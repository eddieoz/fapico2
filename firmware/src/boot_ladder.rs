//! US-1304: the boot-phase blink ladder's *shape*, as a pure function.
//!
//! # What is pure here, and why the split exists
//!
//! `dbg::phase_blinks` drives GPIO25 directly: it takes the write-once
//! `boot::LED_OUT` slot through a raw pointer and busy-waits on the RP2350's
//! `TIMERAWL` counter, because at the early boot phases the async executor and
//! its timers are not running yet and a `Timer::after` would never wake. That
//! is the right shape for the device and the wrong shape for a test — none of
//! it runs on a host, and a function that can only be exercised by flashing a
//! board is not a function whose output has been checked.
//!
//! So the *sequence of levels* is expressed here, with no pin and no clock, and
//! `phase_blinks` is reduced to a thin loop over it. The device behaviour is
//! unchanged; what changes is that the arithmetic a human reads off a frozen
//! board is now the output of something the host suite asserts.
//!
//! # Why the count is a transition count, not a light level
//!
//! This is the module's design constraint and it is not incidental. The board
//! LED's polarity is a hardware fact the firmware only assumes (US-1303: on
//! the Pico 2, GPIO25 is **active-high** — the twelve sites that claimed the
//! opposite were corrected there). A ladder read as "the LED was lit N times"
//! would therefore be a reading that a board revision could silently invert.
//!
//! [`phase_levels`] yields levels, and the property that matters is that **every
//! phase leaves the pin at the level it started on** and each blink cycle
//! contributes exactly two transitions. Reading those transitions — rather
//! than counting lit samples — makes the diagnosis identical whichever way
//! the pin is wired. The host suite asserts this by polarity-flipping every
//! fixture and requiring an unchanged verdict, the same way
//! `tests/hardware/test_boot_ladder.py` does for the Python classifier.
//!
//! # Relationship to the host-side classifier
//!
//! `tests/hardware/boot_time_probe.py::classify_ladder` turns a recorded
//! sequence back into a phase id. It is written against this ladder's
//! arithmetic, so the two must agree: phase `n` completes after
//! `1 + 2 + … + n` cycles. `ladder_levels_up_to` here is the same generator the
//! Python tests build their fixtures from.

/// One blink cycle: the pin goes to [`Level::On`] for one half-period and
/// back to [`Level::Off`].
///
/// Named rather than spelled as a bare `bool` because every call site that
/// touches GPIO25 is exactly where the polarity bug of US-1303 lived: a
/// `true`/`false` on a pin is unreadable at the call site, and
/// `led.set_low() // on` was how the wrong polarity survived a code review
/// reading. The *mapping* from these names to pin levels is the one place in
/// the tree allowed to say which is which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The LED's lit level. On this board: drive the pin **high**.
    On,
    /// The LED's unlit level. On this board: drive the pin **low**.
    Off,
}

/// The pin level one phase's ladder must be left at when it finishes.
///
/// Every cycle returns the pin to where it started, so this is the level the
/// pin had before the phase — and therefore the level the next phase starts
/// from. It is a named constant because "the ladder's resting level" is the
/// level a frozen board sits at, and US-1308 reads that resting level as part
/// of the measurement. Encoding it as "the level phase N started at" rather
/// than a literal keeps it correct if the resting level is ever changed.
pub const LADDER_RESTING: Level = Level::Off;

/// The on-level half-period of one blink, in microseconds (40 ms).
///
/// Paired with [`LADDER_OFF_US`], a phase costs `2 × 40 ms × id` — see
/// `dbg::phase_blinks`'s module doc for the ≤1.5 s whole-ladder bound.
pub const LADDER_ON_US: u32 = 40_000;

/// The off-level half-period of one blink, in microseconds (40 ms).
pub const LADDER_OFF_US: u32 = 40_000;

/// The highest phase id the ladder defines (`dbg::P_SERVING`).
pub const MAX_PHASE: u8 = 19;

/// The level sequence for phase `id`: `id` complete blink cycles.
///
/// Phase 0 — and every phase below it — yields an empty sequence, which is
/// what `P_MAIN_ENTERED` relies on: it fires before `embassy_rp::init` and
/// before the `LED_OUT` slot exists, and touching that slot there would write
/// through an uninitialised pointer. Its absence from the LED is the answer
/// for "froze before or during HAL init" (US-1302's `NO_BLINK`).
///
/// Each cycle is [`Level::On`] then [`Level::Off`], so:
///
/// * the sequence is `2 * id` levels long, and
/// * the pin is left at [`LADDER_RESTING`] whatever `id` was.
///
/// The second property is the load-bearing one. Because every phase ends
/// balanced and starts from the same resting level, the *cumulative* level
/// sequence over phases `1..=n` depends only on how many cycles have run — not
/// on where each phase boundary fell — which is what lets a count read off a
/// frozen board name a phase without knowing the pin's polarity.
pub fn phase_levels(id: u8) -> impl Iterator<Item = Level> {
    (0..id).flat_map(|_| [Level::On, Level::Off])
}

/// The cumulative level sequence through phase `id`, starting from
/// [`LADDER_RESTING`].
///
/// This is what the board actually shows, and what the host-side classifier
/// consumes. After phase `n` it holds `2 × (1 + 2 + … + n)` levels — the
/// sparse sequence `0, 2, 6, 12, 20, …`, since the phase boundaries sit at
/// cumulative *cycle* counts `0, 1, 3, 6, 10, …`.
pub fn ladder_levels_up_to(id: u8) -> impl Iterator<Item = Level> {
    (1..=id).flat_map(phase_levels)
}

/// The number of complete blink cycles phase `id` emits — i.e. the transition
/// count a human counts divided by two.
pub fn phase_cycles(id: u8) -> u32 {
    u32::from(id)
}

/// The cumulative cycle count after phase `id` has been emitted: `1 + 2 + … + id`.
pub fn cycles_up_to(id: u8) -> u32 {
    (1..=u32::from(id)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gherkin: "Given the ladder is built with the boot-timeline feature /
    /// When phase 3 is emitted / Then the LED transitions exactly three times
    /// / And the last level left on the pin is the off level."
    #[test]
    fn given_the_ladder_when_phase_3_is_emitted_then_it_transitions_three_times_and_rests_off() {
        let levels: Vec<Level> = phase_levels(3).collect();
        assert_eq!(levels.len(), 6, "three cycles are six level samples");
        assert_eq!(phase_cycles(3), 3);
        assert_eq!(*levels.last().unwrap(), LADDER_RESTING);
        assert_eq!(LADDER_RESTING, Level::Off);
    }

    #[test]
    fn given_phase_zero_when_the_ladder_is_built_then_no_transition_is_emitted() {
        assert_eq!(phase_levels(0).count(), 0);
        assert_eq!(phase_cycles(0), 0);
    }

    #[test]
    fn given_phase_one_when_the_ladder_is_built_then_exactly_one_transition_cycle_is_emitted() {
        let levels: Vec<Level> = phase_levels(1).collect();
        assert_eq!(levels, vec![Level::On, Level::Off]);
        assert_eq!(phase_cycles(1), 1);
    }

    #[test]
    fn given_phase_nineteen_when_the_ladder_is_built_then_exactly_nineteen_cycles_are_emitted() {
        assert_eq!(phase_cycles(MAX_PHASE), 19);
        assert_eq!(phase_levels(MAX_PHASE).count(), 38);
    }

    /// The invariant the whole design rests on: every phase ends balanced and
    /// at the same level, so a phase boundary is legible from a transition
    /// count alone.
    #[test]
    fn given_any_phase_when_the_ladder_is_built_then_it_rests_at_the_resting_level() {
        for id in 0..=MAX_PHASE {
            let levels: Vec<Level> = phase_levels(id).collect();
            let last = levels.last().copied().unwrap_or(LADDER_RESTING);
            assert_eq!(last, LADDER_RESTING, "phase {id} did not rest off");
        }
    }

    /// Phase boundaries are at cumulative cycle counts 0, 1, 3, 6, 10, … — a
    /// *sparse* set. This is why `classify_ladder` can refuse a count that
    /// falls between two boundaries instead of guessing.
    #[test]
    fn given_the_cumulative_ladder_when_phases_are_summed_then_boundaries_are_triangular_numbers() {
        assert_eq!(cycles_up_to(0), 0);
        assert_eq!(cycles_up_to(1), 1);
        assert_eq!(cycles_up_to(2), 3);
        assert_eq!(cycles_up_to(3), 6);
        assert_eq!(cycles_up_to(4), 10);
        assert_eq!(cycles_up_to(MAX_PHASE), 190);
    }

    #[test]
    fn given_the_cumulative_ladder_when_phase_n_is_reached_then_it_has_two_cycles_n_of_transitions() {
        for id in 0..=MAX_PHASE {
            assert_eq!(
                ladder_levels_up_to(id).count() as u32,
                2 * cycles_up_to(id),
                "phase {id} level count"
            );
        }
    }

    /// A level sequence contains no absolute polarity claim: every phase is a
    /// whole number of `On`/`Off` pairs starting from `LADDER_RESTING`. So
    /// flipping the pin inverts the whole sequence without changing any count.
    #[test]
    fn given_the_ladder_when_the_pin_is_inverted_then_every_transition_count_is_unchanged() {
        /// Transitions counted the way the board shows them: the pin starts at
        /// its resting level, so the *first* driven level is itself a
        /// transition. That leading sample is what makes phase 1 read as two
        /// transitions (Off→On→Off) rather than one, and it is why a
        /// cumulative count is always even.
        fn transitions(id: u8, invert: bool) -> u32 {
            let flip = |level: Level| match (level, invert) {
                (Level::On, false) | (Level::Off, true) => Level::On,
                (Level::Off, false) | (Level::On, true) => Level::Off,
            };
            let mut levels = vec![flip(LADDER_RESTING)];
            levels.extend(phase_levels(id).map(flip));
            levels
                .windows(2)
                .filter(|pair| pair[0] != pair[1])
                .count() as u32
        }

        for id in 0..=MAX_PHASE {
            // Reading it the correct way round.
            assert_eq!(transitions(id, false), 2 * phase_cycles(id), "phase {id}");
            // Reading it on a board that wired the LED the other way.
            assert_eq!(transitions(id, true), transitions(id, false), "phase {id}");
        }
    }

    /// The timing arithmetic, asserted rather than restated.
    ///
    /// `dbg::phase_blinks`'s module doc carries two claims that cannot both be
    /// true: "phase N costs 80·N ms and the whole ladder adds **at most 1.5 s**
    /// to a boot that reaches phase 19", and "subtract 80 ms × (the sum of the
    /// phase ids seen)". Phase 19 alone costs 1.52 s; the sum over a full boot
    /// is 80 ms × (1 + … + 19) = 15.2 s. The subtraction formula is the correct
    /// one and the 1.5 s bound is off by a factor of ten — it is phase 19's
    /// own cost, mislabelled as the whole ladder's. US-1304 corrects the doc.
    ///
    /// Both facts are asserted here so neither can drift back.
    #[test]
    fn given_the_whole_ladder_when_it_is_timed_then_the_cost_is_the_triangular_sum_not_phase_nineteen() {
        // One cycle = one on-interval plus one off-interval.
        assert_eq!(u64::from(LADDER_ON_US + LADDER_OFF_US), 80_000);

        // Phase 19 on its own: 19 cycles, 1.52 s. This is the figure the old
        // doc quoted as the whole ladder's cost.
        let phase_19_us = u64::from(phase_cycles(MAX_PHASE)) * 80_000;
        assert_eq!(phase_19_us, 1_520_000);

        // Every phase a full boot passes: the triangular sum, 15.2 s.
        let full_us: u64 = (0..=MAX_PHASE)
            .map(|id| u64::from(phase_cycles(id)) * 80_000)
            .sum();
        assert_eq!(full_us, 15_200_000);
        assert_eq!(full_us, 10 * phase_19_us);
    }
}
