#!/usr/bin/env python3
"""US-1302: the blink-ladder classifier is a pure function of a blink sequence.

The classifier under test is [`boot_time_probe.classify_ladder`]. The
sequences here are **fixtures**, not captures from a board: this story is
host-testable precisely because the classifier does no timing and no USB. A
story that needed the hardware to prove the classifier is a function of an
integer would be testing the wrong thing.

Transition counts, not light levels
-----------------------------------

`firmware/src/dbg.rs` emits its boot ladder so that the count is read as a
**transition count, not a light level**, and the module doc says why in as
many words: the board LED's polarity is a hardware fact the crate only
assumes, so a reading that depended on "on means on" would be a reading that
could be inverted by a board revision.

So every fixture below is a sequence of *levels* (`True`/`False`) and the
classifier counts **level changes**, never "the number of times it was lit".
The fixtures deliberately include the polarity-flipped reading of the same
sequence, and both must classify identically — that is the property the design
claim rests on, and the only way it can be tested without hardware.

Run:
    python3 -m pytest tests/hardware/test_boot_ladder.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from boot_time_probe import classify_ladder  # noqa: E402


def _flip(levels: list[bool]) -> list[bool]:
    """The same blink sequence as read through an inverted LED polarity."""
    return [not level for level in levels]


def _ladder(up_to_phase: int, initial: bool = True) -> list[bool]:
    """A rendered ladder: each phase contributes ``id`` blink cycles.

    ``phase_blinks(id)`` drives the pin low, waits, drives it high, waits --
    ``id`` times. Every cycle ends on the same level it started that cycle
    with, so a full ladder is ``2 * sum(ids)`` levels long and a truncated
    (frozen-mid-phase) tail is one with the last cycle cut short.
    """
    levels = [initial]
    for phase in range(1, up_to_phase + 1):
        for _ in range(phase):
            levels.append(not levels[-1])
            levels.append(not levels[-1])
    return levels


# ---------------------------------------------------------------------------
# Empty and degenerate sequences
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sequence, expected", [
    # No transitions at all: the board never blinked, so it froze inside or
    # before `embassy_rp::init` -- before the LED slot could be driven.
    ([], "NO_BLINK"),
    # A single level is a constant level: also zero transitions.
    ([True], "NO_BLINK"),
    ([False], "NO_BLINK"),
    # Repeated identical levels: observed, but not a transition.
    ([True, True, True, True], "NO_BLINK"),
])
def test_given_a_constant_pin_when_the_sequence_is_counted_then_the_board_never_blinked(
    sequence, expected
):
    assert classify_ladder(sequence) == expected


# ---------------------------------------------------------------------------
# Truncated trailing blink
# ---------------------------------------------------------------------------

def test_given_a_ladder_cut_short_when_classified_then_the_answer_is_unknown():
    """A freeze partway through a phase names no phase, and says so.

    `phase_blinks` emits `id` cycles for phase `id`, so the phase boundaries
    sit at cumulative cycle counts 0, 1, 3, 6, 10 … — a *sparse* set. Every
    count between two boundaries means the device froze partway through a
    phase: 2 cycles is two into phase 2, 5 cycles is five into phase 3, and
    neither distinguishes "froze mid-phase 3" from "froze just after phase 2".

    So the classifier refuses rather than rounding down. Rounding to `PHASE_2`
    from a 5-cycle reading would report a phase boundary the device never
    demonstrably reached, which is the specific failure this epic exists to
    stop — three prior accounts of this signature each guessed past the
    evidence available to them.
    """
    full = _ladder(3)
    assert classify_ladder(full) == "PHASE_3"

    # Truncated by a whole cycle: 6 cycles -> 5, which is inside phase 3.
    assert classify_ladder(full[:-2]) == "UNKNOWN"
    # Truncated mid-cycle: 12 transitions -> 11, an unbalanced pin.
    assert classify_ladder(full[:-1]) == "UNKNOWN"
    # Two whole cycles gone: 6 -> 4, inside phase 3 as well.
    assert classify_ladder(full[:-4]) == "UNKNOWN"
    # Three gone: 6 -> 3 == exactly the phase-2 boundary, so *this* one is
    # readable again -- and it is the only truncation of this ladder that is.
    assert classify_ladder(full[:-6]) == "PHASE_2"


def test_given_every_truncation_of_a_ladder_when_classified_then_only_real_boundaries_are_named():
    """No truncation of a ladder ever names a phase that was not reached.

    Exhausts every prefix of the phase-3 ladder and asserts the classifier
    never returns a `PHASE_n` for `n > 3`. This is the property a human relies
    on when they read a count off a frozen board: a named phase is a boundary
    the firmware demonstrably emitted, not a ceiling inferred from a count.
    """
    full = _ladder(3)
    for cut in range(len(full)):
        verdict = classify_ladder(full[:cut])
        if verdict.startswith("PHASE_"):
            assert int(verdict.removeprefix("PHASE_")) <= 3, verdict


def test_given_a_ladder_with_no_phase_completed_when_classified_then_only_the_first_cycle_counts():
    # A single completed blink, then a freeze: one cycle, so phase 1.
    assert classify_ladder([True, False, True]) == "PHASE_1"


# ---------------------------------------------------------------------------
# Nominal ladder readings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("phase", [1, 2, 3, 5, 8, 13, 19])
def test_given_a_complete_ladder_for_a_phase_when_classified_then_that_phase_is_named(phase):
    assert classify_ladder(_ladder(phase)) == f"PHASE_{phase}"


def test_given_the_full_ladder_when_classified_then_the_last_defined_phase_is_reachable():
    """Phase 19 is the top of the table (`P_SERVING`).

    Reaching it means the device booted, which is the ladder's success state --
    the same thing the probe already calls `SLOW`. The classifier keeps the
    distinction because a board that shows 19 blinks and *still* does not
    enumerate is a different failure from one that never reached phase 19.
    """
    assert classify_ladder(_ladder(19)) == "PHASE_19"


# ---------------------------------------------------------------------------
# The polarity independence the design claim rests on
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("phase", [1, 2, 3, 7, 19])
def test_given_the_same_ladder_read_through_an_inverted_pin_when_classified_then_the_answer_is_identical(
    phase,
):
    """A board revision that inverts the LED must not change the diagnosis.

    This is the property `dbg.rs`'s module doc claims ("N blinks-then-frozen
    names the phase whichever way the pin is wired"), and it is falsifiable
    here without hardware: if the classifier ever counted lit levels instead of
    transitions, the flipped reading would disagree.
    """
    sequence = _ladder(phase)
    assert classify_ladder(sequence) == classify_ladder(_flip(sequence))


# ---------------------------------------------------------------------------
# Unclassifiable readings
# ---------------------------------------------------------------------------

def test_given_an_odd_transition_count_within_a_phase_when_classified_then_the_answer_is_unknown():
    """An odd number of transitions names no completed phase.

    `phase_blinks` always leaves the pin balanced, so the cumulative transition
    count after any number of complete phases is even. An odd count therefore
    came from something this ladder did not produce — a `fatal_boot`
    signature (US-1306) or the heartbeat — and reporting a `PHASE_n` from it
    would be a guess dressed as a measurement.
    """
    assert classify_ladder([True, False, True, False, True]) == "UNKNOWN"


def test_given_more_transitions_than_the_longest_ladder_when_classified_then_the_answer_is_unknown():
    """Past phase 19 there is no phase to name.

    Anything above the defined table is not a reading this firmware can
    produce from the ladder, so it is `UNKNOWN` rather than a phase that does
    not exist.
    """
    assert classify_ladder(_ladder(19) + [False, True, False]) == "UNKNOWN"


def test_given_none_at_all_when_classified_then_the_answer_is_unknown():
    """A missing sequence is not an empty sequence.

    The probe has to be able to say "nobody counted any blinks" as distinct
    from "somebody counted and saw none", because the first means the
    instrument was not watching and the second is a `NO_BLINK` finding.
    """
    assert classify_ladder(None) == "UNKNOWN"
