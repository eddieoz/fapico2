//! US-1803: the entropy-wait blink's *shape*, as a pure function.
//!
//! # What this is, and why it exists
//!
//! The two boot-entropy sites (`ensure_boot_entropy`'s record draw,
//! `init_drbg`'s DRBG seed nonce) can now wait up to
//! [`otp_retry::ENTROPY_DEADLINE_MS`](crate::otp_retry::ENTROPY_DEADLINE_MS)
//! — a 2026-11-09 decode measured a cold episode settling at ≥ 20.4 s, so the
//! budget is sized past it ([`docs/audits/2026-11-09-cold-boot-entropy-window.md`]).
//! A board sitting dark for up to a minute reads as dead to its owner; the
//! owner's decision (2026-11-09) is that the wait must be *visible*: during
//! the wait the pin drives a fast blink between longer dark —
//!
//! ```text
//! .--.--.--.      dots are the blinks (80 ms lit), dashes are the dark
//!                 spaces (170 ms); the pattern repeats for every 250 ms
//!                 retry step of the wait.
//! ```
//!
//! # Why the rhythm is collision-tested
//!
//! GPIO25 is one pin with many drivers, and the diagnosis instrument this
//! tree built (`docs/boot-freeze.md`) works by reading *what the pin does*
//! into one of a fixed table of meanings. The wait-blink is a new entry in
//! that table, so it must be producible by **exactly one** driver: no other
//! driver of the pin may emit an 80 ms on-time or a 250 ms period. The
//! collision test below pins every other driver's timing — the ladders from
//! their constants, the heartbeat and the draw notice by source-pinning the
//! arm-only files that own their literals (`main.rs`, `boot.rs` are compiled
//! by no host test, so a constant here would not see their edits — the same
//! `include_str!` shape [`bootphase`](crate::bootphase)'s call-site test
//! uses).
//!
//! # The split
//!
//! As with [`boot_ladder`](crate::boot_ladder): the level sequence is pure and
//! host-tested here; the device driver (`boot.rs::entropy_wait_sleep`, arm-only)
//! is a thin loop over it that drives the pin and busy-waits. The generator
//! yields whole steps — one step is exactly [`WAIT_BLINK_ON_MS`] lit then
//! [`WAIT_BLINK_OFF_MS`] dark, which is also
//! [`otp_retry::STEP_MS`](crate::otp_retry::STEP_MS), so the blink fills one
//! retry step and the device driver can be handed to `otp_retry::retry` as its
//! `sleep_ms` closure unchanged.

use crate::boot_ladder::Level;

/// The blink's lit duration, in ms — the dots of `.--.--.--.`.
///
/// Chosen so no other driver of GPIO25 emits this on-time (the collision
/// test pins that) and so the step sums to [`otp_retry::STEP_MS`].
pub const WAIT_BLINK_ON_MS: u64 = 80;

/// The blink's dark duration, in ms — the dashes of `.--.--.--.`. The longer
/// half is what makes the pattern read as "fast blink between longer dark".
pub const WAIT_BLINK_OFF_MS: u64 = 170;

/// One full blink step, in ms: [`WAIT_BLINK_ON_MS`] + [`WAIT_BLINK_OFF_MS`].
///
/// Equal to [`otp_retry::STEP_MS`](crate::otp_retry::STEP_MS) by design —
/// the retry loop sleeps one step between attempts, so each sleep drives
/// exactly one dot-dash pair and the window's blink count is the attempt
/// count.
pub const WAIT_BLINK_PERIOD_MS: u64 = WAIT_BLINK_ON_MS + WAIT_BLINK_OFF_MS;

/// The period of the whole pattern, in ms. Named for the collision test's
/// readability; identical to [`WAIT_BLINK_PERIOD_MS`].
pub const fn period() -> u64 {
    WAIT_BLINK_PERIOD_MS
}

/// The level sequence of one blink step: lit, then dark.
///
/// The durations are not part of the sequence — they are the pair of
/// constants the device driver busy-waits over. One step is exactly two
/// levels, and the sequence ends at [`Level::Off`], the pin's resting level,
/// so stepping out of the wait leaves the pin dark for whatever follows.
pub fn step_levels() -> [Level; 2] {
    [Level::On, Level::Off]
}

/// The level sequence of `steps` blink steps: `steps` × (lit, dark).
///
/// What the device driver plays over a whole wait: `retry` sleeps
/// [`otp_retry::STEP_MS`](crate::otp_retry::STEP_MS) per attempt, and each
/// sleep is one call of the driver, which plays one step. A 60 s worst-case
/// window is 240 steps; this generator is per-step so no sequence needs
/// materialising.
pub fn levels_for_steps(steps: u64) -> impl Iterator<Item = Level> {
    (0..steps).flat_map(|_| step_levels())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp_retry;

    /// Gherkin (US-1803): "Given the wait-blink on and off durations / Then
    /// their sum equals the retry step of 250 ms."
    #[test]
    fn the_blink_fills_exactly_one_retry_step() {
        assert_eq!(WAIT_BLINK_ON_MS + WAIT_BLINK_OFF_MS, otp_retry::STEP_MS);
        assert_eq!(period(), otp_retry::STEP_MS);
    }

    /// Gherkin (US-1803): "Given a wait of one 250 ms step / Then the emitted
    /// levels are exactly On(80) then Off(170)."
    #[test]
    fn given_a_wait_of_one_step_then_the_emitted_levels_are_exactly_on_80_then_off_170() {
        let levels: Vec<Level> = levels_for_steps(1).collect();
        assert_eq!(levels, vec![Level::On, Level::Off]);
        // And the durations those two levels are held for:
        assert_eq!(WAIT_BLINK_ON_MS, 80);
        assert_eq!(WAIT_BLINK_OFF_MS, 170);
        // Three steps are the `.--.--.--.` the owner asked for: six levels,
        // ending dark.
        let three: Vec<Level> = levels_for_steps(3).collect();
        assert_eq!(three.len(), 6);
        assert_eq!(*three.last().unwrap(), Level::Off);
    }

    /// Gherkin (US-1803): "Given every duration the pre-release firmware
    /// drives on GPIO25 … Then the wait-blink's 80 ms on-time matches none of
    /// them / And the wait-blink's period matches no other driver's period."
    ///
    /// The table is sourced, not transcribed: the ladders come from their
    /// public constants, the heartbeat and the draw notice are pinned to the
    /// arm-only source that owns their literals, and the signature timings
    /// come from `fatal_sig`. A driver added later with a colliding rhythm
    /// turns this red — which is the point.
    #[test]
    fn the_blink_rhythm_collides_with_no_other_pin_driver() {
        // (driver, on_ms, off_ms)
        let drivers: &[(&str, u64, u64)] = &[
            (
                "linear ladder pulse (bootphase.rs, always-on)",
                u64::from(crate::bootphase::PULSE_ON_US) / 1000,
                u64::from(crate::bootphase::PULSE_OFF_US) / 1000,
            ),
            (
                "cumulative phase ladder (boot_ladder.rs, dbg-log)",
                u64::from(crate::boot_ladder::LADDER_ON_US) / 1000,
                u64::from(crate::boot_ladder::LADDER_OFF_US) / 1000,
            ),
            ("heartbeat", 500, 500),
            ("entropy draw notice", 400, 0),
            ("fatal signature bit", u64::from(crate::fatal_sig::BIT_LIT_US) / 1000, 200),
            ("fatal signature zero gap", 0, u64::from(crate::fatal_sig::ZERO_GAP_US) / 1000),
            ("fatal signature one gap", 0, u64::from(crate::fatal_sig::ONE_GAP_US) / 1000),
            ("fatal signature preamble", u64::from(crate::fatal_sig::PREAMBLE_US) / 1000, 600),
        ];

        for (name, on, off) in drivers {
            assert_ne!(
                WAIT_BLINK_ON_MS, *on,
                "on-time collision with {name}: two drivers could produce an 80 ms lit pulse"
            );
            assert_ne!(
                WAIT_BLINK_PERIOD_MS,
                *on + *off,
                "period collision with {name}: an observer could not tell which driver was running"
            );
        }

        // The heartbeat's 500/500 is a literal in arm-only `main.rs`
        // (~line 1531, the serve loop). Nothing else in the tree could see it
        // change, so the table above would silently rot — this pins the
        // source text, the same shape `bootphase.rs`'s call-site test uses.
        let main = include_str!("main.rs");
        let heartbeat_sites = main.matches("Timer::after_millis(500)").count();
        assert!(
            heartbeat_sites >= 2,
            "the heartbeat's 500 ms literals moved in main.rs — re-check the collision table \
             (an on/off of 500/500 colliding with 80/170 is impossible, but the table's row \
             must still describe the real heartbeat)"
        );

        // The draw notice's 400 ms is likewise an arm-only literal in
        // `boot.rs` (`entropy_draw_notice`'s busy_wait_us).
        let boot = include_str!("boot.rs");
        assert!(
            boot.contains("busy_wait_us(400_000)"),
            "entropy_draw_notice's 400 ms literal moved in boot.rs — re-check the collision table"
        );
    }
}
