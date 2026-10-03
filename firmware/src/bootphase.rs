//! **Boot-phase LED ladder** — the pure core of the "where did boot die?"
//! instrument, host-tested; the LED driver that consumes it lives in the
//! device bin (`firmware/src/boot_led.rs`).
//!
//! # The problem this exists for
//!
//! A board that flashes cleanly and then never re-enumerates produces
//! **byte-identical observable behaviour** whether it
//!
//! * parks in one of the pre-USB `fatal_boot` sites (a `defmt::error!` plus
//!   `loop {}`), or
//! * runs the whole boot and then fails to bring USB up.
//!
//! Nothing distinguishes them today: there is no watchdog (one would destroy
//! the evidence), no retained-RAM flag, no flash byte, no post-mortem read
//! channel. `defmt` needs an RTT probe, and `AGENTS.md` forbids attaching one
//! for exactly this failure — a probe makes `OTP_DATA_RAW` read `0xFFFFFFFF`,
//! which `read_otp_key_1()` reads as "no key", and `fatal_boot` fires before
//! USB is ever constructed. The CTAP-HID diagnostic ring
//! ([`fapico2_firmware`'s `boot-timeline` capture](crate)) needs enumeration
//! to drain, which is the thing that failed.
//!
//! The board LED (GPIO25, active-low) is the only channel that survives a
//! board that never enumerates. **It is always there**: no feature, no rebuild,
//! no second image.
//!
//! # The encoding: one short pulse per boundary crossed
//!
//! This is a **progress counter**, not a code. Each of the [`RUNGS`] boot
//! boundaries emits exactly **one** short pulse ([`PULSE_ON_US`] on,
//! [`PULSE_OFF_US`] off) and the LED is then driven **OFF**. A board that
//! freezes after crossing `k` boundaries has therefore shown `k` pulses and
//! then stopped — and the total cost is *linear* in the number of boundaries,
//! which is what makes a 9-rung ladder affordable on every boot.
//!
//! ```text
//!  never blinked            -> froze at or before embassy_rp::init (the LED did not exist yet)
//!  k pulses, then dark      -> froze in the stage AFTER boundary k
//!  9 pulses, then dark      -> every boundary crossed, then it died before the executor ran
//!  9 pulses, then 1 Hz blink-> boot completed; the heartbeat owns the pin and the fault is post-boot
//! ```
//!
//! Two properties make that last line the whole point:
//!
//! * **The count is monotone and injective.** Boundary `k` has signature `k`
//!   pulses and boundary `j` has `j`; no two boundaries encode alike, and
//!   [`rung_where_frozen`] inverts the mapping exactly. A caller that emits
//!   them out of order or twice is refused by [`Ladder::mark`] and produces
//!   *no* pulse, so the count cannot lie about progress.
//! * **The steady heartbeat is unmistakable.** The 1 Hz heartbeat
//!   ([`main.rs`](https://example.invalid)) is 500 ms on / 500 ms off; a
//!   ladder pulse is 25 ms. "parked before USB" and "alive but USB-dead" are
//!   one glance apart, which is the entire question this instrument exists
//!   to answer.
//!
//! # The one ambiguity, stated rather than hidden
//!
//! A board that freezes *inside* a pulse can leave the observer one pulse
//! short or one long — the LED is a physical signal, not a memory. The
//! mitigation is that a pulse is 80 ms while the stages between boundaries are
//! hundreds of milliseconds to seconds, so the probability mass sits far from
//! the boundary. The residual error is exactly one rung, in the direction
//! "died in stage `k`" vs "died in stage `k+1`".
//!
//! # Cost, and why it is on by default
//!
//! [`full_ladder_us`] is the wall-clock the ladder adds to a boot that reaches
//! the last rung. It is paid on **every** boot of **every** unit, which is the
//! price of "the next person must not have to rebuild". If a deployment ever
//! decides that latency is worth more, `FAPICO2_BOOT_LED=0` compiles the whole
//! thing out at the call sites — see `firmware/src/boot_led.rs`.

/// Number of boot boundaries the ladder reports. Boundaries are numbered
/// [`RUNG_HAL`]..=[`RUNG_SERVING`] and are emitted in [`RUNG_ORDER`].
pub const RUNGS: u8 = 9;

/// `embassy_rp::init` returned and the board LED is mounted — the earliest
/// boundary at which a pulse is physically possible at all.
pub const RUNG_HAL: u8 = 0;
/// Entering the TRNG / clock bring-up (driver construction, `TIMER0` proof,
/// boot sanity draw). The first rung that can catch a peripheral-level hang.
pub const RUNG_TRNG: u8 = 1;
/// Entering `boot::derive_boot_store_key` — **the OTP key-row read**, the
/// leading suspect for a post-flash dark boot. Deliberately emitted
/// *immediately before* the read so a freeze inside it is attributable to the
/// read and not to the phase before it.
pub const RUNG_OTP: u8 = 2;
/// The secure store is mounted: slot decided, winning image restored.
pub const RUNG_STORE: u8 = 3;
/// `boot::init_drbg` returned — a DRBG exists.
pub const RUNG_DRBG: u8 = 4;
/// First-boot C→Rust migration finished.
pub const RUNG_MIGRATION: u8 = 5;
/// Every applet constructed into its write-once slot and registered with the
/// dispatcher (the "app statics" milestone).
pub const RUNG_APPS: u8 = 6;
/// `Usb::new` returned and `usb_task` was spawned — the USB milestone.
pub const RUNG_USB: u8 = 7;
/// Every serve-loop task, including the heartbeat, was spawned and `main` is
/// about to park into the executor.
pub const RUNG_SERVING: u8 = 8;

/// One pulse's on-time. Short on purpose: it must not be mistaken for the
/// heartbeat's 500 ms on-time.
pub const PULSE_ON_US: u32 = 25_000;
/// One pulse's off-time (the gap that makes the next pulse countable).
pub const PULSE_OFF_US: u32 = 55_000;

/// Wall-clock one full pulse costs: [`PULSE_ON_US`] + [`PULSE_OFF_US`].
pub const PULSE_US: u32 = PULSE_ON_US + PULSE_OFF_US;

/// The order the call sites in `firmware/src/main.rs` emit the rungs in. It is
/// a `const` rather than prose so a test can hold the *ordering* claim to
/// account — an edit that moves a `mark!` site has to move it here too, or the
/// ladder stops being monotone and the count stops meaning "how far".
///
/// That claim is enforced by [`tests::the_call_sites_in_main_agree_with_this_order`],
/// which reads `main.rs` and checks both halves: every rung is marked exactly
/// once, and the source order of those sites is this order.
pub const RUNG_ORDER: [u8; RUNGS as usize] = [
    RUNG_HAL,
    RUNG_TRNG,
    RUNG_OTP,
    RUNG_STORE,
    RUNG_DRBG,
    RUNG_MIGRATION,
    RUNG_APPS,
    RUNG_USB,
    RUNG_SERVING,
];

/// What the LED pin is parked at between pulses. `On` is **never** a ladder
/// outcome: the touch prompt (GPIO25, `button::set_touch_prompt_led`) lights
/// the pin to mean "touch me", and a ladder that left the pin lit would be
/// indistinguishable from a consent window that never closed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LedLevel {
    Off,
    On,
}

/// The complete, observable signature of one boot boundary: how many short
/// pulses precede the freeze, and the level the pin is parked at once the
/// last pulse ends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature {
    /// Short pulses emitted from a cold board up to and including this rung.
    pub pulses: u8,
    /// The level the pin rests at after the last pulse.
    pub settled: LedLevel,
}

/// The human-readable name of a rung, for diagnostics and tests.
pub fn rung_name(rung: u8) -> Option<&'static str> {
    Some(match rung {
        RUNG_HAL => "hal+led-mounted",
        RUNG_TRNG => "trng-clock",
        RUNG_OTP => "otp-key-row-read",
        RUNG_STORE => "secure-store-mounted",
        RUNG_DRBG => "drbg-live",
        RUNG_MIGRATION => "migration-done",
        RUNG_APPS => "app-statics-registered",
        RUNG_USB => "usb-up",
        RUNG_SERVING => "serving",
        _ => return None,
    })
}

/// The signature boundary `rung` produces. `None` for a rung outside
/// [`RUNGS`] — an out-of-range rung is a programming error, and returning a
/// signature for it would let a typo look like real progress.
pub fn signature(rung: u8) -> Option<Signature> {
    if rung >= RUNGS {
        return None;
    }
    Some(Signature {
        pulses: rung + 1,
        settled: LedLevel::Off,
    })
}

/// The inverse of [`signature`]: given a pulse count observed on a frozen
/// board, which boundary was the last one crossed.
///
/// `None` for a count that no boundary produces — `0` means the board froze
/// before it could cross any boundary at all (in or before `embassy_rp::init`,
/// where the LED does not yet exist).
pub fn rung_where_frozen(pulses: u8) -> Option<u8> {
    if pulses == 0 || pulses > RUNGS {
        return None;
    }
    Some(pulses - 1)
}

/// The wall-clock a boot that reaches every rung pays for the ladder.
///
/// This is the honest cost line for any "should this be on by default?"
/// argument: it is *linear* in [`RUNGS`] because each rung emits one pulse,
/// not `rung`-many pulses. A unary-per-rung encoding was rejected on exactly
/// this arithmetic — it is quadratic, which is what made the pre-existing
/// `dbg::phase_blinks` unsuitable for the default build.
pub fn full_ladder_us() -> u32 {
    RUNGS as u32 * PULSE_US
}

/// What [`Ladder::mark`] decided to do with a call site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mark {
    /// Emit `pulses` short pulses. The pin is left at `settled`.
    Pulse { rung: u8, pulses: u8, settled: LedLevel },
    /// Do not touch the pin at all.
    Silent(Silent),
}

/// Why a call site produced [`Mark::Silent`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Silent {
    /// Out of order, a duplicate, or a rung that is not next. Refused so the
    /// pulse count stays a truthful progress counter.
    OutOfOrder,
    /// The ladder has been released; the pin belongs to the runtime drivers.
    Released,
}

/// The boot-path state machine behind the LED.
///
/// One instance lives in a `static mut` on the pre-task boot path (the same
/// write-once discipline as `boot::LED_OUT`): single core, no preemption, no
/// task runs before [`Ladder::release`]. It holds no hardware handle — the
/// driver does — so all of it is host-testable.
#[derive(Clone, Copy, Debug)]
pub struct Ladder {
    /// The next rung the ladder will accept. `RUNGS` once every rung is in.
    next: u8,
    released: bool,
}

impl Ladder {
    /// A fresh ladder, expecting [`RUNG_HAL`] first.
    pub const fn new() -> Self {
        Self {
            next: 0,
            released: false,
        }
    }

    /// Report that boot crossed boundary `rung`.
    ///
    /// A rung that is not exactly the next one is refused: the counter would
    /// otherwise report progress the board has not made, which is the one
    /// failure mode an instrument like this cannot have.
    pub fn mark(&mut self, rung: u8) -> Mark {
        if self.released {
            return Mark::Silent(Silent::Released);
        }
        if rung != self.next || rung >= RUNGS {
            return Mark::Silent(Silent::OutOfOrder);
        }
        let sig = signature(rung).expect("rung < RUNGS is in range by the guard above");
        self.next += 1;
        Mark::Pulse {
            rung,
            pulses: sig.pulses,
            settled: sig.settled,
        }
    }

    /// Hand the pin to the runtime drivers (heartbeat task, trussed UI, touch
    /// prompt). Idempotent; after it, every [`Ladder::mark`] is
    /// [`Mark::Silent`] and the pin is never driven again by boot-phase code.
    pub fn release(&mut self) {
        self.released = true;
    }

    /// How many boundaries have been crossed so far (== pulses a frozen board
    /// would show).
    pub fn reached(&self) -> u8 {
        self.next
    }

    /// Has the pin been handed over?
    pub fn is_released(&self) -> bool {
        self.released
    }
}

impl Default for Ladder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn rung_order_is_strictly_increasing_and_complete() {
        assert_eq!(RUNG_ORDER.len(), RUNGS as usize);
        for (i, rung) in RUNG_ORDER.iter().enumerate() {
            assert_eq!(*rung as usize, i, "rung {i} is not at position {i}");
        }
        let mut seen = BTreeSet::new();
        for rung in RUNG_ORDER {
            assert!(seen.insert(rung), "rung {rung} appears twice in RUNG_ORDER");
        }
        assert_eq!(seen.len(), RUNGS as usize);
    }

    #[test]
    fn every_rung_is_named_and_names_are_unique() {
        let mut seen = BTreeSet::new();
        for rung in 0..RUNGS {
            let name = rung_name(rung).unwrap_or_else(|| panic!("rung {rung} has no name"));
            assert!(seen.insert(name), "name {name:?} is used twice");
        }
        assert_eq!(rung_name(RUNGS), None);
        assert_eq!(rung_name(200), None);
    }

    /// The load-bearing claim: no two boundaries encode identically, and the
    /// count a frozen board shows maps back to exactly one boundary.
    #[test]
    fn signatures_are_injective_and_reversible() {
        let mut counts = BTreeSet::new();
        for rung in 0..RUNGS {
            let sig = signature(rung).unwrap();
            assert!(
                counts.insert(sig.pulses),
                "rung {rung} collides with another rung at {} pulses",
                sig.pulses
            );
            assert_eq!(
                rung_where_frozen(sig.pulses),
                Some(rung),
                "{} pulses must name rung {rung}",
                sig.pulses
            );
        }
        assert_eq!(counts.len(), RUNGS as usize);
        // Out-of-range in both directions.
        assert_eq!(signature(RUNGS), None);
        assert_eq!(rung_where_frozen(0), None);
        assert_eq!(rung_where_frozen(RUNGS + 1), None);
    }

    /// The touch-LED contract: a ladder pulse must never leave GPIO25 latched
    /// on, because "on" is the user-presence prompt.
    #[test]
    fn no_boundary_pins_the_led_on() {
        for rung in 0..RUNGS {
            assert_eq!(signature(rung).unwrap().settled, LedLevel::Off);
        }
    }

    #[test]
    fn a_clean_boot_crosses_every_rung_once_in_order() {
        let mut ladder = Ladder::new();
        for rung in RUNG_ORDER {
            match ladder.mark(rung) {
                Mark::Pulse { pulses, settled, .. } => {
                    assert_eq!(pulses, rung + 1);
                    assert_eq!(settled, LedLevel::Off);
                }
                other => panic!("rung {rung} should have pulsed, got {other:?}"),
            }
            assert_eq!(ladder.reached(), rung + 1);
        }
        assert_eq!(ladder.reached(), RUNGS);
        assert!(!ladder.is_released());
        // A rung past the end is refused rather than inventing progress.
        assert_eq!(ladder.mark(RUNG_SERVING), Mark::Silent(Silent::OutOfOrder));
        assert_eq!(ladder.reached(), RUNGS);
    }

    #[test]
    fn out_of_order_and_duplicate_marks_never_advance_the_counter() {
        let mut ladder = Ladder::new();
        // Skip ahead.
        assert_eq!(ladder.mark(RUNG_OTP), Mark::Silent(Silent::OutOfOrder));
        assert_eq!(ladder.reached(), 0);
        // A duplicate.
        ladder.mark(RUNG_HAL);
        assert_eq!(ladder.mark(RUNG_HAL), Mark::Silent(Silent::OutOfOrder));
        assert_eq!(ladder.reached(), 1);
        // Backwards.
        assert_eq!(ladder.mark(RUNG_HAL), Mark::Silent(Silent::OutOfOrder));
        // Out of range.
        assert_eq!(ladder.mark(RUNGS + 7), Mark::Silent(Silent::OutOfOrder));
        assert_eq!(ladder.reached(), 1);
        // The ladder is unpoisoned: the next in-order rung still works.
        assert!(matches!(ladder.mark(RUNG_TRNG), Mark::Pulse { .. }));
        assert_eq!(ladder.reached(), 2);
    }

    #[test]
    fn release_silences_the_ladder_and_is_idempotent() {
        let mut ladder = Ladder::new();
        ladder.mark(RUNG_HAL);
        ladder.release();
        assert!(ladder.is_released());
        ladder.release();
        assert!(ladder.is_released());
        for rung in RUNG_ORDER {
            assert_eq!(ladder.mark(rung), Mark::Silent(Silent::Released));
        }
        assert_eq!(ladder.reached(), 1, "release must not count as progress");
    }

    /// The whole point of [`RUNG_ORDER`]: the `mark!` sites in `main.rs` are
    /// exactly these nine rungs, once each, in this order.
    ///
    /// This test exists because [`RUNG_ORDER`] is otherwise a table checked
    /// against itself — `assert_eq!(*rung as usize, i)` is true of any
    /// self-consistent array, so the eight other tests in this module stayed
    /// green with a rung deleted from the shipped binary (verified: deleting
    /// `mark!(RUNG_USB)` from `main.rs` left 93/93 green). `main.rs` is
    /// arm-gated and compiled by no host test, so nothing else in the tree
    /// could see that edit; this reads its source text instead — the same
    /// source-pinning shape `status_table.rs`'s CTAP constant check uses for
    /// `firmware/src/ctap_hid.rs`, and for the same reason.
    ///
    /// `include_str!` rather than a filesystem read: it resolves at compile
    /// time, so a moved or deleted `main.rs` is a build error rather than a
    /// runtime surprise, and it does not depend on the test's working
    /// directory.
    #[test]
    fn the_call_sites_in_main_agree_with_this_order() {
        let main = include_str!("main.rs");
        // Each `mark!(...RUNG_X)` site, in source order. The match is
        // anchored on the constant name after the `mark!(`, so a comment
        // mentioning a rung is not counted as a call.
        let mut marked: Vec<&str> = Vec::new();
        for line in main.lines() {
            let Some((_, args)) = line.split_once("mark!(") else {
                continue;
            };
            let Some((args, close)) = args.split_once(')') else {
                continue;
            };
            // A statement, not an expression: `mark!(RUNG_X);`. Without this
            // a mention inside a larger expression would count as a call.
            if !close.trim_start().starts_with(';') {
                continue;
            }
            let args = args.trim();
            if let Some(name) = args.rsplit("::").next().filter(|n| n.starts_with("RUNG_")) {
                marked.push(name);
            }
        }
        let expected: Vec<&str> = RUNG_ORDER.iter().map(|r| rung_const_name(*r)).collect();
        assert_eq!(
            marked, expected,
            "the `mark!` sites in firmware/src/main.rs must be exactly the nine \
             RUNG_* boundaries, once each, in RUNG_ORDER's sequence.\n  found in \
             main.rs: {marked:?}\n  RUNG_ORDER claims: {expected:?}\nA rung that is \
             missing, duplicated or out of order means the LED's pulse count no \
             longer says how far boot got."
        );
    }

    /// The `RUNG_*` constant name for a rung, so the test above names the same
    /// nine constants `RUNG_ORDER` holds rather than a second hand-written
    /// list that could drift.
    fn rung_const_name(rung: u8) -> &'static str {
        match rung {
            RUNG_HAL => "RUNG_HAL",
            RUNG_TRNG => "RUNG_TRNG",
            RUNG_OTP => "RUNG_OTP",
            RUNG_STORE => "RUNG_STORE",
            RUNG_DRBG => "RUNG_DRBG",
            RUNG_MIGRATION => "RUNG_MIGRATION",
            RUNG_APPS => "RUNG_APPS",
            RUNG_USB => "RUNG_USB",
            RUNG_SERVING => "RUNG_SERVING",
            other => panic!("rung {other} has no RUNG_* constant name"),
        }
    }

    /// The frozen-board readings the docs promise, as an executable table.
    #[test]
    fn the_documented_readings_hold() {
        // Never blinked -> no boundary, no rung (froze in/before HAL init).
        assert_eq!(rung_where_frozen(0), None);
        // k pulses -> froze in the stage AFTER boundary k.
        for rung in 0..RUNGS {
            let pulses = signature(rung).unwrap().pulses;
            let last = rung_where_frozen(pulses).unwrap();
            assert_eq!(last, rung);
        }
        // The full ladder is one pulse per rung: linear, and cheap enough to
        // ship on by default.
        assert_eq!(full_ladder_us(), RUNGS as u32 * 80_000);
        assert!(
            full_ladder_us() < 1_000_000,
            "the ladder must stay under a second of boot latency"
        );
    }
}