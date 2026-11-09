//! US-1804: the entropy-refusal bounded-reboot decision, as a pure core.
//!
//! # What this decides, and why anything has to
//!
//! ADR [`0004`](../docs/adr/0004-fatal-boot-recovery-policy.md) refused a
//! watchdog because it would convert a *legible* park — a signature that
//! names the cause, held until the owner intervenes — into an illegible
//! reboot loop. But the ADR itself wrote the carve-out: *"A watchdog would
//! be in scope for a transient hang mode — one a reset actually clears."*
//! The cold-boot entropy stall is precisely that mode: a settling ring
//! oscillator clears by waiting (the 2026-11-09 decode shows it succeeding
//! at the deadline's tail), and a reboot re-rolls the draw with the settling
//! clock already warm. An immediate park turns a recoverable stall into a
//! brick only the owner's power cycle fixes.
//!
//! So the refusal policy at the two entropy sites becomes: **reboot and
//! re-roll, a bounded number of times, then park legibly.** The bound lives
//! in SRAM retained across `SCB::sys_reset` (a `.retain` NOLOAD section, so
//! the Rust runtime's `.bss` zero-init never wipes it — US-1805/US-1807).
//!
//! # What is pure here
//!
//! The decision arithmetic — magic guard, bound comparison, the bump, the
//! clear — is host-testable here with no hardware types. The device side
//! (`boot.rs::entropy_reboot_or_park`, US-1807) owns the volatile access to
//! the retained static and the two exits: `Action::Reboot` → `sys_reset`,
//! `Action::Park` → `fatal_boot`, the **same** `fatal_boot(reason)` path the
//! sites used before this epic — so a park still emits signature `0011`
//! (`TrngRefused`) or `0100` (`DrbgRefused`) and stays legible. That
//! legibility is a device-side property; what this core guarantees is that
//! the park is only reached after exactly [`MAX_REFUSED_BOOTS`] refused
//! boots.
//!
//! # The magic guard
//!
//! Power-on leaves the retained section's contents **undefined** (it is
//! outside the zero/copy ranges on purpose). The magic word distinguishes
//! "this is our counter from a previous refused boot" from "undefined bytes
//! after power-on": a mismatch is treated as a fresh state — the first
//! observed refusal still reboots rather than parks, because undefined
//! memory must never read as a bound already reached. A genuine
//! `(RETAIN_MAGIC, MAX_REFUSED_BOOTS)` state is indistinguishable in
//! principle from undefined bytes that happen to match both words (1 in
//! 2^64); the accepted failure direction is an unnecessary early park after
//! exactly one refused boot — never an unbounded reboot loop — and ADR 0004's
//! park legibility is preserved either way.

/// The magic word a valid retained counter carries. Arbitrary constant,
/// chosen to be unlikely in undefined power-on SRAM and readable in a hex
/// dump ("RTNR" — retained TRNG counter).
pub const RETAIN_MAGIC: u32 = 0x5254_4E52;

/// The number of consecutive refused boots after which the board parks
/// instead of rebooting again. Worst case is three refused boots — with the
/// 60 s entropy budget each, ~3 minutes of visible blinking — and then a
/// legible park with the same signature the site would have emitted
/// immediately before this epic.
pub const MAX_REFUSED_BOOTS: u32 = 3;

/// What a refusal site does once the whole entropy budget is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Bump the retained counter and reset (`SCB::sys_reset`): re-roll the
    /// draw from the top of boot.
    Reboot,
    /// `fatal_boot` with the site's reason — the same park, same signature,
    /// as before this epic. Unreachable-after discipline unchanged.
    Park,
}

/// The retained counter's layout as it sits in the `.retain` section.
///
/// The device side stores exactly this through a volatile pointer; the
/// `repr(C, align(4))` keeps the two words at fixed offsets so the section's
/// contents are interpretable from a hex dump and the pointer arithmetic in
/// `boot.rs` stays trivial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct Retained {
    /// [`RETAIN_MAGIC`] when valid; anything else after power-on.
    pub magic: u32,
    /// Consecutive refused boots so far, saturating at [`MAX_REFUSED_BOOTS`].
    pub attempts: u32,
}

/// The action a refusal takes given the retained state as read.
///
/// Gherkin (US-1804): a state whose magic does not match — undefined
/// power-on bytes — is a fresh state: **Reboot**. A valid state below the
/// bound: **Reboot**. A valid state at the bound: **Park** — the bound is
/// what keeps ADR 0004's refusal legible when the stall is *not* transient
/// (a hard autocorrelation wedge reboots identically to a settling stall,
/// so only the counter discriminates them).
pub fn decide(magic: u32, attempts: u32) -> Action {
    if magic != RETAIN_MAGIC {
        Action::Reboot
    } else if attempts >= MAX_REFUSED_BOOTS {
        Action::Park
    } else {
        Action::Reboot
    }
}

/// The state a refusal leaves behind when it decides to [`Action::Reboot`].
///
/// A fresh (magic-mismatched) state becomes the first counted refusal;
/// a counted one increments, saturated at the bound so the counter can
/// never wrap past it.
pub fn bumped(magic: u32, attempts: u32) -> Retained {
    if magic != RETAIN_MAGIC {
        Retained { magic: RETAIN_MAGIC, attempts: 1 }
    } else {
        Retained {
            magic: RETAIN_MAGIC,
            attempts: attempts.saturating_add(1).min(MAX_REFUSED_BOOTS),
        }
    }
}

/// The state a successful boot writes: a valid counter at zero, so the next
/// refusal starts from one.
///
/// Written once per boot at the first point *both* entropy sites have
/// succeeded (`after init_drbg returns` — US-1809), not at the boot's very
/// top: a counter bumped by a refused boot must survive until a boot
/// genuinely reaches serving entropy, or a board that refused three times
/// and then succeeded once mid-window would lose its history. Gherkin:
/// "Given retained state (MAGIC, anything) / When the boot reaches serving /
/// Then the state is cleared and the next refusal starts from one."
pub fn cleared() -> Retained {
    Retained { magic: RETAIN_MAGIC, attempts: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gherkin: "Given retained state whose magic does not match / When a
    /// refusal is decided / Then the action is Reboot / And the state
    /// becomes (MAGIC, 1)."
    ///
    /// The fresh state is what a power-on boot reads: the `.retain` section's
    /// contents are undefined, and undefined memory must never read as a
    /// bound already reached.
    #[test]
    fn given_retained_state_whose_magic_does_not_match_when_a_refusal_is_decided_then_reboot_and_state_becomes_magic_1() {
        for garbage in [0u32, 0xFFFF_FFFF, RETAIN_MAGIC ^ 1, 0x1234_5678] {
            assert_eq!(decide(garbage, 7), Action::Reboot, "magic {garbage:#010x}");
            assert_eq!(bumped(garbage, 7), Retained { magic: RETAIN_MAGIC, attempts: 1 });
        }
        // The singular fresh case the Gherkin names — the undefined state the
        // device side represents as zeros before the first write.
        assert_eq!(decide(0, 0), Action::Reboot);
        assert_eq!(bumped(0, 0), Retained { magic: RETAIN_MAGIC, attempts: 1 });
    }

    /// Gherkin: "Given retained state (MAGIC, 1) / When a refusal is decided
    /// / Then the action is Reboot / And the state becomes (MAGIC, 2)."
    #[test]
    fn given_retained_state_magic_1_when_a_refusal_is_decided_then_reboot_and_state_becomes_magic_2() {
        assert_eq!(decide(RETAIN_MAGIC, 1), Action::Reboot);
        assert_eq!(bumped(RETAIN_MAGIC, 1), Retained { magic: RETAIN_MAGIC, attempts: 2 });
        // And the whole run-up: 1 → 2 → 3, each still a Reboot, so the worst
        // case is exactly MAX_REFUSED_BOOTS refused boots before the park.
        assert_eq!(bumped(RETAIN_MAGIC, 2), Retained { magic: RETAIN_MAGIC, attempts: 3 });
        assert_eq!(decide(RETAIN_MAGIC, 2), Action::Reboot);
    }

    /// Gherkin: "Given retained state (MAGIC, MAX_REFUSED_BOOTS) / When a
    /// refusal is decided / Then the action is Park."
    ///
    /// The park is legible *by construction of the device side*: it is the
    /// same `fatal_boot(msg, reason)` call the site made before this epic,
    /// so signature `0011`/`0100` still names the cause. This core's job is
    /// only that the park is reached on exactly the bound-th refusal and not
    /// before — no watchdog, no loop without memory.
    #[test]
    fn given_retained_state_at_the_bound_when_a_refusal_is_decided_then_park() {
        assert_eq!(decide(RETAIN_MAGIC, MAX_REFUSED_BOOTS), Action::Park);
        // Past the bound too (a saturating write raced nothing, but the
        // comparison is `>=` on purpose): still Park, never Reboot again.
        assert_eq!(decide(RETAIN_MAGIC, MAX_REFUSED_BOOTS + 1), Action::Park);
        // And the bump saturates, so a state at the bound cannot grow.
        assert_eq!(
            bumped(RETAIN_MAGIC, MAX_REFUSED_BOOTS),
            Retained { magic: RETAIN_MAGIC, attempts: MAX_REFUSED_BOOTS }
        );
    }

    /// Gherkin: "Given retained state (MAGIC, anything) / When the boot
    /// reaches serving / Then the state is cleared and the next refusal
    /// starts from one."
    #[test]
    fn given_a_successful_boot_when_the_state_is_cleared_then_the_next_refusal_starts_from_one() {
        let state = cleared();
        assert_eq!(state, Retained { magic: RETAIN_MAGIC, attempts: 0 });
        // The boot after a clear reads a valid counter at zero, so its first
        // refusal is attempt 1 of 3 — a full fresh budget, not a residue.
        assert_eq!(decide(state.magic, state.attempts), Action::Reboot);
        assert_eq!(bumped(state.magic, state.attempts), Retained { magic: RETAIN_MAGIC, attempts: 1 });
    }

    /// The bound the EPIC promises, asserted so a re-size cannot happen
    /// silently: the worst case is bounded, visible (each refused boot
    /// blinks for its whole window) and then parks.
    #[test]
    fn the_bound_is_three_refused_boots_and_no_boot_loops_unbounded() {
        assert_eq!(MAX_REFUSED_BOOTS, 3);
        // Walking the state machine from the fresh state: exactly
        // MAX_REFUSED_BOOTS Reboots and then a Park.
        let mut state = Retained { magic: 0, attempts: 0 };
        let mut reboots = 0;
        loop {
            match decide(state.magic, state.attempts) {
                Action::Reboot => {
                    reboots += 1;
                    state = bumped(state.magic, state.attempts);
                }
                Action::Park => break,
            }
            assert!(reboots <= MAX_REFUSED_BOOTS, "the walk exceeded the bound");
        }
        assert_eq!(reboots, MAX_REFUSED_BOOTS);
    }
}
