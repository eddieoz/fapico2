//! The entropy wait's wall clock is a **precondition**, and the wait checks it.
//!
//! # The defect this file exists to catch
//!
//! On 2026-09-29 the branch `feat/rskey-adopt` was flashed to a real Pico 2
//! and came up dark: LED solid, absent from `lsusb`, no CCID reader. The
//! failing path was the entropy probe. `boot::init_drbg` is fatal by design, so
//! a refused seed halts before USB ever enumerates — which is exactly what
//! was observed, and why nothing about the device was diagnosable from the
//! outside.
//!
//! The mechanism *reported* for it was that the entropy wait's wall clock was
//! not running at seed time, so [`MAX_ENTROPY_WAIT`] was unreachable and the
//! wait silently degenerated into the hard poll cap. Whether or not that was
//! the mechanism on this part (the next test file, and D-12, are explicit
//! about what is and is not established), the *shape* of the bug is not in
//! doubt and it is the shape worth closing:
//!
//! > A probe that cannot tell "the peripheral was slow" from "I was never
//! > measuring time" reports both as one opaque `Err`, and the second one is
//! > invisible.
//!
//! A host test cannot see a stopped peripheral timer. It can, however, hand
//! the wait a clock that provably does not advance, and assert that the wait
//! **says so** instead of running out a poll count and reporting a stall that
//! means nothing. That is the assertion below, and it is the one that would
//! have caught this class of bug.
//!
//! # What is and is not established here
//!
//! Established by these tests, on the host:
//!
//! * a wait handed a clock that never advances refuses with
//!   [`TrngError::ClockStalled`], not [`TrngError::Stalled`];
//! * it refuses **fast** — inside [`CLOCK_LIVENESS_SPINS`], not at
//!   [`MAX_ENTROPY_POLLS`];
//! * the three bounds are ordered and each is reachable: liveness
//!   < budget < hard cap;
//! * a wait that succeeds on the very first poll is **not** required to have a
//!   working clock — the clock is a means, the entropy is the goal, and a
//!   dead clock must not be able to refuse entropy that has already arrived;
//! * a clock that *does* advance is never accused of being dead, however few
//!   ticks it reports before it expires the budget.
//!
//! **Not** established by these tests, and stated rather than implied: whether
//! `TIMER0` is counting at the moment `main` seeds the DRBG on real silicon.
//! No board is attached to this tree and none may be assumed. The device half
//! of the answer is a runtime check
//! (`Rp2350Timer::require_advancing`, unreachable from the host build) plus a
//! source-ordering gate (`tests/scripts/check_boot_clock_order.py`). Both are
//! recorded as assumptions in `docs/known-gate-divergences.md` (D-12).

use fapico2_platform::trng::{
    EntropyClock, ProbeStatus, TrngError, TrngProbe, CLOCK_LIVENESS_SPINS, ENTROPY_CLOCK_TICKS_PER_MS,
    MAX_ENTROPY_POLLS, MAX_ENTROPY_WAIT,
};

/// Byte the fake peripheral stamps in, so a test can tell a delivered block
/// from a buffer the wait never wrote to.
const MARKER: u8 = 0xA5;

/// A wall clock whose advance the test scripts, one *status read* at a time.
///
/// `ticks_per_poll: 0` is the shape this whole file is about: a clock that
/// never moves. That is not a contrived input — it is exactly what a stopped
/// or unstarted hardware timer looks like to `ticks()`, and it is the input
/// the old wait could not distinguish from a slow peripheral.
struct FakeClock {
    now: u64,
    ticks_per_poll: u64,
    /// How many times the clock has been read. The fake advances on *reads*,
    /// so a scripted `ticks_per_poll` of 0 with a call count is the only way
    /// to model "moves, but only every Nth read".
    reads: u32,
    /// If non-zero, the clock only moves once every this many reads.
    advance_every: u32,
}

impl FakeClock {
    fn frozen() -> Self {
        Self {
            now: 0,
            ticks_per_poll: 0,
            reads: 0,
            advance_every: 0,
        }
    }

    fn ticking(ticks_per_poll: u64) -> Self {
        Self {
            ticks_per_poll,
            ..Self::frozen()
        }
    }

    /// A clock that is alive but pathologically slow: it advances by
    /// `ticks_per_poll` only once every `advance_every` reads. This is the
    /// shape that reaches the hard poll cap instead of the time budget, and
    /// it is the only shape that can.
    fn slow(ticks_per_poll: u64, advance_every: u32) -> Self {
        Self {
            ticks_per_poll,
            advance_every,
            ..Self::frozen()
        }
    }
}

impl EntropyClock for FakeClock {
    fn ticks(&self) -> u64 {
        self.now
    }
}

/// A probe that lets the test script the peripheral *and* the clock, and
/// counts both.
struct ScriptedProbe {
    status: ProbeStatus,
    /// `Ready` from poll `ready_after + 1` onwards. `u32::MAX` = never.
    ready_after: u32,
    polls: u32,
    clock: FakeClock,
}

impl ScriptedProbe {
    fn new(status: ProbeStatus, clock: FakeClock) -> Self {
        Self {
            status,
            ready_after: u32::MAX,
            polls: 0,
            clock,
        }
    }

    fn ready_after(mut self, n: u32) -> Self {
        self.ready_after = n;
        self
    }
}

impl TrngProbe for ScriptedProbe {
    fn status(&mut self) -> ProbeStatus {
        self.polls += 1;
        self.clock.reads += 1;
        if self.clock.advance_every == 0
            || self.clock.reads.is_multiple_of(self.clock.advance_every)
        {
            self.clock.now += self.clock.ticks_per_poll;
        }
        if self.polls > self.ready_after {
            ProbeStatus::Ready
        } else {
            self.status
        }
    }

    fn read_block(&mut self, block: &mut [u8]) {
        block.fill(MARKER);
    }

    fn read_into(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        if buf.is_empty() {
            return Ok(());
        }
        self.await_ready()?;
        self.read_block(buf);
        Ok(())
    }

    fn source_enable(&mut self) {}

    fn source_disable(&mut self) {}

    fn clock(&mut self) -> &mut dyn EntropyClock {
        &mut self.clock
    }
}

// ---------------------------------------------------------------------------
// (1) THE test. A clock that never advances must be named, not tolerated.
// ---------------------------------------------------------------------------

/// A probe handed a clock that **does not advance** must refuse, and must say
/// that the clock is what it refused on.
///
/// This is the assertion that would have caught the 2026-09-29 dark boot.
/// Before the fix, this wait ran [`MAX_ENTROPY_POLLS`] status reads against a
/// counter frozen at zero, fell out the bottom, and returned a bare
/// `TrngError::Stalled` — a code whose documented meaning is "the peripheral
/// produced nothing within its time budget", which is a statement about the
/// peripheral and a statement that was **not measured**. The caller, and the
/// operator reading the dark device, had nothing to distinguish it from a
/// genuinely slow entropy source.
#[test]
fn a_clock_that_never_advances_is_refused_as_a_clock_failure() {
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy, FakeClock::frozen());
    let mut buf = [0u8; 32];

    assert_eq!(
        probe.probe_bytes(&mut buf),
        Err(TrngError::ClockStalled),
        "a wall clock that never advances must be reported as the failure it \
         is. Returning Stalled claims the peripheral missed a deadline that \
         was never measured, which is how a stopped timer is misread as a \
         dead entropy source."
    );
    assert_eq!(
        buf, [0u8; 32],
        "a refused wait must not hand back a half-written buffer"
    );
}

// ---------------------------------------------------------------------------
// (2) ... and it must refuse *fast*, not after burning the whole poll cap.
// ---------------------------------------------------------------------------

/// The refusal must arrive inside the liveness window, not at the hard cap.
///
/// The reason this is a separate test rather than an extra assertion on (1)
/// is that the two failures are different defects. Returning the right code
/// after half a second of spinning still leaves a boot that hangs before USB
/// enumerates for a measurable time on every power cycle; the whole point of
/// checking the instrument is that the instrument's failure is cheap.
#[test]
fn a_dead_clock_is_refused_inside_the_liveness_window() {
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy, FakeClock::frozen());
    let mut buf = [0u8; 32];

    let _ = probe.probe_bytes(&mut buf);

    assert!(
        probe.polls <= CLOCK_LIVENESS_SPINS + 1,
        "the wait must give up on a dead clock within the liveness window: \
         got {} polls, bound is {}",
        probe.polls,
        CLOCK_LIVENESS_SPINS + 1
    );
    assert!(
        probe.polls < MAX_ENTROPY_POLLS / 8,
        "and that refusal must be dramatically earlier than the hard cap \
         ({} polls) — a refusal that costs most of a second of boot-time \
         spinning is not a check, it is a slower way of not knowing",
        MAX_ENTROPY_POLLS
    );
}

// ---------------------------------------------------------------------------
// (3) The refusal is about the clock, not about the peripheral's status.
// ---------------------------------------------------------------------------

/// Every non-`Ready` peripheral status must produce the same clock-failure
/// code. If `AutocorrErr` still reported `Stalled` while `Busy` reported
/// `ClockStalled`, the code would be describing the peripheral, not the
/// instrument — and would be worth nothing to the reader deciding whether to
/// suspect the ring oscillator or the timer.
#[test]
fn every_peripheral_status_reports_the_clock_failure_identically() {
    for status in [
        ProbeStatus::Busy,
        ProbeStatus::AutocorrErr,
        ProbeStatus::InvalidEhr,
    ] {
        let mut probe = ScriptedProbe::new(status, FakeClock::frozen());
        let mut buf = [0u8; 24];
        assert_eq!(
            probe.probe_bytes(&mut buf),
            Err(TrngError::ClockStalled),
            "status {status:?} against a dead clock must still name the clock"
        );
    }
}

// ---------------------------------------------------------------------------
// (4) A live clock is never accused of being dead.
// ---------------------------------------------------------------------------

/// The mirror of (1): a clock that *is* counting must be trusted, however few
/// ticks it needs to report. A liveness check that could fire on a slow-but-
/// real clock would convert every healthy draw on a slow part into a boot
/// refusal, which is a worse outcome than the one it is fixing.
#[test]
fn a_live_clock_is_never_mistaken_for_a_dead_one() {
    // One tick per read: the slowest clock that still clears the liveness
    // window comfortably (1 tick per read, 256 reads, 256 ticks moved).
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy, FakeClock::ticking(1))
        .ready_after(MAX_ENTROPY_WAIT as u32 - 1);
    let mut buf = [0u8; 32];

    assert_eq!(
        probe.probe_bytes(&mut buf),
        Ok(()),
        "a clock that moves one tick per read is a working clock; refusing it \
         would be the false positive CLOCK_LIVENESS_SPINS is sized to avoid"
    );
    assert_eq!(buf, [MARKER; 32]);
}

// ---------------------------------------------------------------------------
// (5) The goal beats the instrument: entropy in hand is served regardless.
// ---------------------------------------------------------------------------

/// A peripheral that is **already `Ready`** is served even on a dead clock.
///
/// The clock is a means; the entropy is the goal. Refusing a block that has
/// already been validated because a stopwatch is not running would be a
/// strictly worse failure than the one the check exists to catch — it would
/// turn a working device into a brick. The check therefore sits *after* the
/// `Ready` test in the loop, and this test is what pins that ordering.
#[test]
fn entropy_that_has_already_arrived_is_served_on_a_dead_clock() {
    let mut probe = ScriptedProbe::new(ProbeStatus::Ready, FakeClock::frozen());
    let mut buf = [0u8; 32];

    assert_eq!(
        probe.probe_bytes(&mut buf),
        Ok(()),
        "a validated block is a validated block; a dead stopwatch must not \
         refuse entropy the peripheral has already produced"
    );
    assert_eq!(probe.polls, 1);
    assert_eq!(buf, [MARKER; 32]);
}

// ---------------------------------------------------------------------------
// (6) The three bounds are ordered, and each is reachable on its own terms.
// ---------------------------------------------------------------------------

/// The ordering the three bounds depend on, as a **compile-time** assertion.
///
/// `CLOCK_LIVENESS_SPINS` must be far below the hard cap or the liveness check
/// is the cap with a nicer name; and the hard cap must be far above the
/// budget's worst-case iteration count or it pre-empts the budget on a
/// healthy peripheral — which is the `MAX_ENTROPY_POLLS = 64` defect this
/// module was grown to remove, and a boot brick, because a seed refusal is
/// fatal.
const _: () = {
    assert!(
        CLOCK_LIVENESS_SPINS * 64 <= MAX_ENTROPY_POLLS,
        "CLOCK_LIVENESS_SPINS must be at least 64x below MAX_ENTROPY_POLLS, or \
         the liveness check is the hard cap under another name and the \
         'refuse fast' property is gone"
    );
    assert!(
        MAX_ENTROPY_POLLS as u64 > MAX_ENTROPY_WAIT,
        "MAX_ENTROPY_POLLS must exceed MAX_ENTROPY_WAIT by a wide margin. The \
         wait ticks the clock at least once per iteration, so a cap below the \
         budget's tick count would end every wait at the cap on a healthy \
         peripheral — a budget expressed in polls, which is the defect the \
         whole two-bound split exists to remove"
    );
};

/// A clock that is **alive but pathologically slow** — one tick every
/// [`SLOW_EVERY`] reads — reaches the hard cap before it can reach the time
/// budget, and is reported as a plain `Stalled`.
///
/// This is the case the hard cap is actually for, and it is worth keeping
/// reachable by a test: once the liveness check exists, a *dead* clock never
/// gets near the cap, and without this test the cap would silently become an
/// unreachable constant that nobody could tell had stopped meaning anything.
///
/// The band between the two bounds is narrow by construction. The budget is
/// [`MAX_ENTROPY_WAIT`] ticks; the cap is [`MAX_ENTROPY_POLLS`] iterations;
/// the cap binds exactly when a tick takes longer than
/// `MAX_ENTROPY_WAIT / MAX_ENTROPY_POLLS` iterations to arrive. So a clock
/// faster than one tick per that many iterations ends at the budget, and
/// slower ends at the cap.
const SLOW_EVERY: u32 = 100;

#[test]
fn a_live_but_pathologically_slow_clock_ends_at_the_hard_cap() {
    // 20,000 ticks at one per 100 reads needs 2,000,000 polls; the cap is far
    // below that, so the cap must be what ends this wait.
    assert!(
        MAX_ENTROPY_WAIT * SLOW_EVERY as u64 > MAX_ENTROPY_POLLS as u64,
        "this fixture no longer exercises the hard cap: at one tick per \
         {SLOW_EVERY} reads the wall-clock budget would be reached first"
    );

    let mut probe = ScriptedProbe::new(ProbeStatus::Busy, FakeClock::slow(1, SLOW_EVERY));
    let mut buf = [0u8; 32];

    assert_eq!(
        probe.probe_bytes(&mut buf),
        Err(TrngError::Stalled),
        "a clock that IS counting has missed its deadline, which is exactly \
         what Stalled means — the clock failure code would be a lie here"
    );
    assert_eq!(
        probe.polls, MAX_ENTROPY_POLLS,
        "and it must have been the hard cap that ended the wait, having spent \
         all of it: {} polls, cap {}",
        probe.polls,
        MAX_ENTROPY_POLLS
    );
}

/// The other side of that boundary: a clock faster than the band reaches the
/// **budget**, not the cap. Together the two say the bounds are ordered and
/// each is selected by the clock's actual rate, which is the property the
/// band arithmetic above asserts.
#[test]
fn a_live_clock_fast_enough_reaches_the_budget_not_the_cap() {
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy, FakeClock::ticking(1));
    let mut buf = [0u8; 32];

    assert_eq!(probe.probe_bytes(&mut buf), Err(TrngError::Stalled));
    assert_eq!(
        probe.polls as u64, MAX_ENTROPY_WAIT,
        "one tick per read must end the wait at the budget, not the cap"
    );
    assert!(
        MAX_ENTROPY_WAIT < MAX_ENTROPY_POLLS as u64,
        "the budget must be reachable before the cap for the ordering to \
         mean anything"
    );
    // Sanity on the units the whole module rests on, stated where a reader
    // of the constants will trip over it.
    assert_eq!(
        MAX_ENTROPY_WAIT,
        20 * ENTROPY_CLOCK_TICKS_PER_MS,
        "the budget is 20 ms expressed in 1 MHz timer ticks"
    );
}
