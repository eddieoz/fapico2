//! US-1803: the entropy-wait blink's *shape*, as a pure function.
//!
//! # What this is, and why it exists
//!
//! The two boot-entropy sites (`ensure_boot_entropy_blocking`'s record draw,
//! `seed_drbg_blocking`'s DRBG seed nonce) can now wait up to
//! [`otp_retry::ENTROPY_DEADLINE_MS`](crate::otp_retry::ENTROPY_DEADLINE_MS)
//! per budget pass — and since US-1929 a refusal re-arms the pass **forever**
//! (freshness never parks), so the wait can run minutes. A board sitting
//! dark for up to a minute reads as dead to its owner; the owner's decision
//! (2026-11-09) is that the wait must be *visible*: during the wait the pin
//! drives a fast blink between longer dark —
//!
//! ```text
//! .--.--.--.      dots are the blinks (80 ms lit), dashes are the dark
//!                 spaces (170 ms); the pattern repeats for every 250 ms
//!                 retry step of the wait.
//! ```
//!
//! # The progress burst (US-1928)
//!
//! A continuous blink tells a video decoder nothing about *which* site is
//! waiting or *how long* it has waited — the owner's 2026-11-20 direction
//! (O-28, EPIC `FRESH-BOOT-SERVE`). So every 20 failed-attempt steps (one
//! 5-second unit) the waiting site layers a **progress burst** on the blink:
//! K pulses of 450 ms period, K = 5-s-units waited capped at 9, the site
//! named by its on-time (120 ms lit = the record draw, 300 ms lit = the
//! seed). See [`ProgressSite`] and the collision test below — nothing else
//! on GPIO25 can produce either shape.
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

// ---------------------------------------------------------------------------
// US-1928: the progress burst — a wait that lasts seconds tells the video
// decoder *which* site is waiting and *how long*, not merely that it waits.
// ---------------------------------------------------------------------------

/// Which of the two boot-entropy sites is waiting — the identity a burst
/// names by its on-time.
///
/// The two sites are distinguishable on the pin **only** through these
/// constants (the warming blink itself is site-blind by design: both sites
/// play the same `.--.--.--.` while they retry), so the enum is the whole
/// mechanism: the device driver picks the durations from the site it is
/// waiting at, and nothing else on GPIO25 can produce either shape (the
/// collision test pins that).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressSite {
    /// `ensure_boot_entropy_blocking`'s record draw — 120 ms lit pulses.
    Record,
    /// `seed_drbg_blocking`'s DRBG seed — 300 ms lit pulses.
    Seed,
}

/// One burst pulse is emitted after this many failed-attempt steps —
/// 20 × [`otp_retry::STEP_MS`] = 5 s, so a burst's pulse count reads as
/// "5-second units waited at this site".
pub const PROGRESS_BURST_EVERY_STEPS: u64 = 20;

/// The pulse count's cap. Nine 450 ms pulses is ~4 s of burst — long enough
/// to count reliably off a video frame at 30 fps, short enough not to
/// starve the blink itself.
pub const PROGRESS_BURST_MAX_PULSES: u64 = 9;

/// The burst's period, in ms — shared by both sites (the *on-time* is what
/// names the site). 450 ms collides with no other GPIO25 driver's period:
/// the nearest is the signature-bit run's 400 ms, which is the near-miss the
/// collision test exists to keep honest.
pub const PROGRESS_BURST_PERIOD_MS: u64 = 450;

/// The record site's burst: 120 ms lit.
pub const RECORD_BURST_ON_MS: u64 = 120;

/// The record site's burst: 330 ms dark (120 + 330 = 450).
pub const RECORD_BURST_OFF_MS: u64 = 330;

/// The seed site's burst: 300 ms lit.
pub const SEED_BURST_ON_MS: u64 = 300;

/// The seed site's burst: 150 ms dark (300 + 150 = 450).
pub const SEED_BURST_OFF_MS: u64 = 150;

/// How many burst pulses are due after `steps` failed-attempt steps:
/// one per [`PROGRESS_BURST_EVERY_STEPS`] (5-second unit waited), capped at
/// [`PROGRESS_BURST_MAX_PULSES`].
pub fn progress_burst_pulses(steps: u64) -> u64 {
    (steps / PROGRESS_BURST_EVERY_STEPS).min(PROGRESS_BURST_MAX_PULSES)
}

/// The burst's lit duration at `site`, in ms — the site's identity on the
/// pin (120 = record, 300 = seed; both period 450).
pub fn burst_on_ms(site: ProgressSite) -> u64 {
    match site {
        ProgressSite::Record => RECORD_BURST_ON_MS,
        ProgressSite::Seed => SEED_BURST_ON_MS,
    }
}

/// The burst's dark duration at `site`, in ms — the complement that makes
/// the period [`PROGRESS_BURST_PERIOD_MS`] at both sites.
pub fn burst_off_ms(site: ProgressSite) -> u64 {
    match site {
        ProgressSite::Record => RECORD_BURST_OFF_MS,
        ProgressSite::Seed => SEED_BURST_OFF_MS,
    }
}

/// The level sequence of the burst due after `steps` failed-attempt steps at
/// `site`: `progress_burst_pulses(steps)` × (lit, dark), ending at
/// [`Level::Off`], the pin's resting level.
///
/// The `site` argument does not change the *sequence* — every site's burst
/// alternates lit/dark — but it stays in the signature so the device
/// driver's call site names what it is emitting, alongside the duration
/// accessors it reads at the same site ([`burst_on_ms`]/[`burst_off_ms`]).
/// Same split as the blink: the durations are the site's constants the
/// device driver busy-waits over; the generator yields whole pulses. Zero
/// pulses (a healthy draw, or anything short of the first 5-second unit)
/// yields nothing at all.
pub fn progress_burst_levels(_site: ProgressSite, steps: u64) -> impl Iterator<Item = Level> {
    let pulses = progress_burst_pulses(steps);
    (0..pulses).flat_map(|_| step_levels())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp_retry;

    /// Gherkin (US-1928): "Given a draw succeeding without a failed attempt /
    /// Then no sleep runs and no burst is emitted — the boot cost is
    /// unchanged."
    ///
    /// The pure half of that: zero steps (and anything short of the first
    /// 5-second unit) produces no burst at either site. The device half is
    /// structural — the retry loop only calls the sleep between failed
    /// attempts, so a first-attempt success never reaches the burst.
    #[test]
    fn no_burst_on_a_healthy_boot() {
        assert_eq!(progress_burst_pulses(0), 0);
        assert_eq!(progress_burst_pulses(PROGRESS_BURST_EVERY_STEPS - 1), 0);
        assert_eq!(progress_burst_levels(ProgressSite::Record, 0).count(), 0);
        assert_eq!(progress_burst_levels(ProgressSite::Seed, 0).count(), 0);
    }

    /// Gherkin (US-1928): "Given 19 steps of waiting (the blink only runs
    /// between failed attempts) / Then no burst is due / Given 20 steps /
    /// Then one burst of one pulse is due."
    #[test]
    fn the_burst_starts_after_twenty_failed_attempt_steps() {
        assert_eq!(progress_burst_pulses(19), 0);
        assert_eq!(progress_burst_pulses(20), 1);
        assert_eq!(progress_burst_levels(ProgressSite::Record, 20).count(), 2);
    }

    /// Gherkin (US-1928): "Given 40 steps → 2 pulses; 180 steps → 9 pulses
    /// (capped) / Then each pulse names one 5-second unit waited at this
    /// site."
    #[test]
    fn the_burst_count_grows_with_the_wait_and_caps_at_nine() {
        assert_eq!(progress_burst_pulses(40), 2);
        assert_eq!(progress_burst_pulses(180), 9);
        // And the cap holds however long the wait runs.
        assert_eq!(progress_burst_pulses(400), 9);
        // One pulse per 5-second unit: 20 steps x STEP_MS.
        assert_eq!(
            PROGRESS_BURST_EVERY_STEPS * otp_retry::STEP_MS,
            5_000,
            "one burst pulse names one 5-second unit of waiting"
        );
    }

    /// Gherkin (US-1928): "Given the record-draw site waiting / Then the
    /// burst pulses are 120 ms lit / 330 ms dark / Given the DRBG-seed site
    /// waiting / Then the burst pulses are 300 ms lit / 150 ms dark — same
    /// period, different on-time."
    #[test]
    fn the_burst_shape_identifies_the_waiting_site() {
        assert_eq!(burst_on_ms(ProgressSite::Record), 120);
        assert_eq!(burst_off_ms(ProgressSite::Record), 330);
        assert_eq!(burst_on_ms(ProgressSite::Seed), 300);
        assert_eq!(burst_off_ms(ProgressSite::Seed), 150);
        assert_eq!(
            burst_on_ms(ProgressSite::Record) + burst_off_ms(ProgressSite::Record),
            PROGRESS_BURST_PERIOD_MS
        );
        assert_eq!(
            burst_on_ms(ProgressSite::Seed) + burst_off_ms(ProgressSite::Seed),
            PROGRESS_BURST_PERIOD_MS
        );
        // The on-times differ — that difference *is* the site's identity on
        // the pin.
        assert_ne!(
            burst_on_ms(ProgressSite::Record),
            burst_on_ms(ProgressSite::Seed)
        );
    }

    /// Gherkin (US-1928): "Given a burst of K pulses / Then the sequence ends
    /// Off — stepping out leaves the pin dark."
    #[test]
    fn the_burst_ends_at_the_pins_resting_level() {
        for steps in [20, 40, 180, 400] {
            for site in [ProgressSite::Record, ProgressSite::Seed] {
                let levels: Vec<Level> = progress_burst_levels(site, steps).collect();
                assert!(!levels.is_empty(), "a burst is due at {steps} steps");
                assert_eq!(*levels.last().unwrap(), Level::Off);
            }
        }
    }

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
    /// Extended by US-1928: the two progress bursts are two more rows in the
    /// same table, and each burst's on-time (120 / 300) and period (450) is
    /// asserted against every *other* row — the wait-blink included.
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
            (
                "progress burst, record site (US-1928)",
                RECORD_BURST_ON_MS,
                RECORD_BURST_OFF_MS,
            ),
            (
                "progress burst, seed site (US-1928)",
                SEED_BURST_ON_MS,
                SEED_BURST_OFF_MS,
            ),
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

        // US-1928: and each burst is checked the same way against every
        // other row — the wait-blink included. The two bursts share the 450
        // ms period *by design* (the on-time is the site's identity), so the
        // burst's own row (and its sibling's) is the only exclusion.
        let burst_table: &[(&str, u64, u64)] = &[
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
            ("entropy wait-blink", WAIT_BLINK_ON_MS, WAIT_BLINK_OFF_MS),
        ];
        for (site, site_name) in [(ProgressSite::Record, "record"), (ProgressSite::Seed, "seed")] {
            let on = burst_on_ms(site);
            let period = burst_on_ms(site) + burst_off_ms(site);
            for (name, row_on, row_off) in burst_table {
                assert_ne!(
                    on, *row_on,
                    "on-time collision between the {site_name} burst and {name}: \
                     two drivers could produce a {on} ms lit pulse"
                );
                assert_ne!(
                    period, *row_on + *row_off,
                    "period collision between the {site_name} burst and {name}: \
                     an observer could not tell which driver was running"
                );
            }
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
