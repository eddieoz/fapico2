//! Bounded retry for the boot path's OTP reads.
//!
//! The RP2350's OTP array reads intermittently on some boards in the first
//! seconds after power-on — errata **E16** territory: the array's read voltage
//! comes from an internal regulator whose power-good "isn't sampled outside of
//! the initial power-on reset startup sequence". Measured on hardware
//! (2026-10-11, board with a pico-fido2 history; see
//! `docs/pico-fido2-to-fapico2-migration.md`):
//!
//! - the same boot can pass its key-row read and fail its chipid read
//!   (signature id 1 one week, id 2 the next) — the failing read *migrated
//!   later into boot* across attempts, which is what a slowly settling rail
//!   looks like from a series of fixed read sites;
//! - rows read perfectly through the bootrom within the same power episode,
//!   seconds after firmware's read had failed;
//! - and the recovery is not reliably dwell-driven: 10 s of power-off did not
//!   always clear it, so "wait longer between plugs" is not an operator fix.
//!
//! The response is therefore firmware-side and boring: **read again**. A read
//! that fails is retried on a fixed step until a deadline elapses; only then
//! does the caller do what it did before (degrade, or `fatal_boot` with the
//! same signature it would have emitted immediately). This changes nothing
//! about the fail-closed posture — ADR
//! [`docs/adr/0004-fatal-boot-recovery-policy.md`](../docs/adr/0004-fatal-boot-recovery-policy.md):
//! an escalated or genuinely dead row still parks the device, just ~20 s
//! later, and §22's escalated-lock mode does not recover by retry any more
//! than by dwell.
//!
//! The core is pure over injected closures so the attempt bookkeeping is
//! host-testable; the device wrapper in `boot.rs` supplies the real read and
//! the sleep (the same source [`crate`]'s boot ladder uses — `Timer::after`
//! is not available on the early boot path).
//!
//! Two caller policies share this core. The OTP reads keep the original one:
//! a **silent** window of up to [`DEADLINE_MS`], refusal → immediate park.
//! The two boot-entropy sites (US-1802..1810, EPIC
//! `COLD-BOOT-ENTROPY-WINDOW`) now pass [`ENTROPY_DEADLINE_MS`] and a
//! **blinking** sleep ([`crate::wait_blink`]: 80 ms lit / 170 ms dark, one
//! pair per step), and their refusal reboots boundedly
//! ([`crate::entropy_reset`], ADR 0004 amendment 3) — a 60 s window never
//! reads as a dead board, and a transient settle self-recovers instead of
//! parking.

/// Sleep between attempts, in ms. Small enough to ride out a rail that
/// settles within seconds, coarse enough that the worst case does not turn
/// into a hot read loop against a fuse array.
pub const STEP_MS: u64 = 250;

/// Total sleep budget across retries, in ms. Measured grounding: healthy
/// reads were observed through the bootrom tens of seconds into the same
/// power episode where firmware's early read had failed; 20 s covers that
/// window. On a genuinely unreadable row the device parks after one budget,
/// with the same LED signature it would have emitted immediately.
pub const DEADLINE_MS: u64 = 20_000;

/// Sleep budget for the **boot-entropy** sites (`ensure_boot_entropy`'s
/// record draw, `init_drbg`'s DRBG seed nonce), in ms. Sized on the first
/// hardware measurement of the settling floor: the 2026-11-09 decode
/// ([`docs/audits/2026-11-09-cold-boot-entropy-window.md`]) shows a cold
/// power episode settling at **≥ 20.4 s** — [`DEADLINE_MS`] consumed in
/// full, the draw succeeding on the deadline's final attempts. 60 s is
/// twice that floor with margin, still an exact multiple of [`STEP_MS`].
///
/// The OTP reads deliberately keep [`DEADLINE_MS`]: a fuse rail that fails
/// one read at 19.9 s is the same dead row at 59.9 s (§22's escalated lock
/// recovers by neither retry nor dwell), so their budget stays at the size
/// that already covered its measured window — and their refusal still parks
/// immediately. Only the two entropy sites pass this constant; `retry`
/// takes the deadline as an argument, so nothing else's behaviour moves.
/// These two sites blink while they wait (`crate::wait_blink`) and reboot
/// boundedly on refusal (`crate::entropy_reset`, ADR 0004 amendment 3).
pub const ENTROPY_DEADLINE_MS: u64 = 60_000;

/// Retry `read` on `None`, sleeping `step_ms` between attempts, until it
/// succeeds or `deadline_ms` of sleep has elapsed. The first attempt is
/// immediate: a healthy board pays nothing.
///
/// Pure: `read` and `sleep_ms` are injected, so the attempt/sleep
/// bookkeeping is assertable on the host (see the tests). The device wrapper
/// passes its busy-wait. What the *window* looks like is the caller's
/// policy, and it differs by site since ADR 0004 amendment 3 (US-1802..1810):
/// the OTP reads pass [`DEADLINE_MS`] and a silent sleep — a dark window of
/// up to ~[`DEADLINE_MS`] is documented operator behavior, and a real
/// refusal parks immediately; the two boot-entropy sites pass
/// [`ENTROPY_DEADLINE_MS`] and a blinking sleep ([`crate::wait_blink`]) and
/// their refusal reboots boundedly ([`crate::entropy_reset`]).
pub fn retry<T>(
    mut read: impl FnMut() -> Option<T>,
    mut sleep_ms: impl FnMut(u64),
    step_ms: u64,
    deadline_ms: u64,
) -> Option<T> {
    let mut slept_ms: u64 = 0;
    loop {
        if let Some(value) = read() {
            return Some(value);
        }
        if slept_ms >= deadline_ms {
            return None;
        }
        sleep_ms(step_ms);
        slept_ms += step_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts reads and sleeps without actually sleeping. `fail_first` is
    /// how many leading reads return `None`; everything after succeeds,
    /// handing out ascending values.
    struct Rig {
        reads: core::cell::Cell<u32>,
        sleeps: core::cell::Cell<u32>,
        fail_first: u32,
    }

    impl Rig {
        fn new(fail_first: u32) -> Self {
            Self { reads: core::cell::Cell::new(0), sleeps: core::cell::Cell::new(0), fail_first }
        }
        fn read(&self) -> Option<u32> {
            let n = self.reads.get() + 1;
            self.reads.set(n);
            if n <= self.fail_first { None } else { Some(n) }
        }
        fn sleep(&self, ms: u64) {
            assert_eq!(ms, STEP_MS, "the device wrapper owns the real sleep; the rig asserts the step it is handed");
            self.sleeps.set(self.sleeps.get() + 1);
        }
    }

    #[test]
    fn given_a_healthy_row_when_read_then_one_attempt_and_no_sleep() {
        let rig = Rig::new(0);
        let value = retry(|| rig.read(), |ms| rig.sleep(ms), STEP_MS, DEADLINE_MS);
        assert_eq!(value, Some(1));
        assert_eq!(rig.reads.get(), 1);
        assert_eq!(rig.sleeps.get(), 0);
    }

    #[test]
    fn given_a_row_that_settles_on_the_third_read_when_read_then_two_sleeps_precede_success() {
        // results: 2 of the first 3 reads fail (None), the third succeeds.
        let rig = Rig::new(2);
        let value = retry(|| rig.read(), |ms| rig.sleep(ms), STEP_MS, DEADLINE_MS);
        assert_eq!(value, Some(3));
        assert_eq!(rig.reads.get(), 3);
        assert_eq!(rig.sleeps.get(), 2);
    }

    #[test]
    fn given_a_dead_row_when_read_then_budget_is_exhausted_and_none_is_returned() {
        let rig = Rig::new(u32::MAX);
        let value = retry(|| rig.read(), |ms| rig.sleep(ms), STEP_MS, DEADLINE_MS);
        assert_eq!(value, None);
        // One immediate attempt plus one per step within the budget.
        assert_eq!(rig.reads.get() as u64, 1 + DEADLINE_MS / STEP_MS);
        assert_eq!(rig.sleeps.get() as u64, DEADLINE_MS / STEP_MS);
    }

    #[test]
    fn given_a_zero_deadline_when_read_then_a_single_failure_gives_up_immediately() {
        let rig = Rig::new(u32::MAX);
        let value = retry(|| rig.read(), |ms| rig.sleep(ms), STEP_MS, 0);
        assert_eq!(value, None);
        assert_eq!(rig.reads.get(), 1);
        assert_eq!(rig.sleeps.get(), 0);
    }

    /// US-1802 / EPIC `COLD-BOOT-ENTROPY-WINDOW`. The 2026-11-09 decode
    /// ([`docs/audits/2026-11-09-cold-boot-entropy-window.md`] — sibling
    /// `docs/` at the repo root) measured a cold episode settling at
    /// **≥ 20.4 s**: the 20 s budget was consumed in full and the draw
    /// succeeded on the deadline's final attempts. The entropy draws get
    /// their own budget, sized on that measurement; the OTP reads keep
    /// [`DEADLINE_MS`] and their silent-window policy, unchanged by
    /// construction (`retry` takes the deadline as an argument).
    #[test]
    fn the_entropy_deadline_covers_the_measured_settling_floor_with_margin() {
        // Bigger than the OTP reads' budget — that one sized a fuse rail, not
        // a settling ring oscillator.
        assert!(ENTROPY_DEADLINE_MS > DEADLINE_MS);
        // An exact multiple of the retry step, so the loop spends the whole
        // budget and the final attempt lands at the deadline, not past it.
        assert_eq!(ENTROPY_DEADLINE_MS % STEP_MS, 0);
        // At least twice the measured 20.4 s settling floor — margin, not a
        // guess at the upper bound (which is unmeasured; see the audit).
        assert!(ENTROPY_DEADLINE_MS >= 2 * 20_400);
    }
}
