//! US-1001 — the TRNG wait is **bounded**, and the bound is testable.
//!
//! `embassy-rp-0.10.0/src/trng.rs:220-243`
//! (`blocking_wait_for_successful_generation`) is an unbounded busy-wait: on
//! `autocorr_err` it soft-resets and re-initialises the peripheral *forever*,
//! and the other invalid-EHR branch is a `panic!()`. The RP2350 TRNG register
//! documentation (`trng.rs:437-438` in the same file) says `AUTOCORR_ERR`
//! "indicates Autocorrelation test failed four times in a row. **When set, RNG
//! ceases functioning until next reset**" — so the retry is not guaranteed to
//! converge.
//!
//! On device that is a hang inside a `no_std` busy-wait with no supervisor, no
//! watchdog kick, and nothing to log. The fix is a **named bound** on the
//! number of polls, after which the wait returns [`TrngError::Stalled`] and
//! the caller can decide what to do (US-1003 owns that decision; US-1005 owns
//! the routing).
//!
//! These tests pin the bound, not merely "an error came back". A test that
//! passes against an unbounded loop — by never returning, or by returning on
//! the first poll — is the failure mode this story exists to prevent, so each
//! test counts the polls and asserts the count against the bound in force.
//! The fake peripheral scripts a poll *sequence* rather than a single status,
//! so the other shape of wrong loop — one that gives up the second time it
//! sees a non-`Ready` status, long before the bound — is covered too.
//!
//! # Two bounds, and both are exercised
//!
//! The wait terminates on whichever expires first:
//!
//! * [`MAX_ENTROPY_WAIT`] — a **wall-clock** budget (20 ms, expressed in
//!   [`EntropyClock`] ticks). This is the meaningful one: it is in units that
//!   mean the same thing regardless of how fast the loop body runs, and it is
//!   sized from the RP2350 datasheet's ~2 ms *average* generation time for
//!   this configuration (RP2350 §12.12.2, quoted in `embassy-rp`'s own
//!   `Config` docs) times a 10x safety factor.
//! * [`MAX_ENTROPY_POLLS`] — a hard cap on status reads that exists so a
//!   broken or absent clock can never turn the budget into an infinite loop.
//!
//! The tests below split cleanly: with the fake clock **frozen**, only the
//! hard cap can terminate the wait, which is what the poll-counting
//! assertions here were written for and what they still check. With the clock
//! **advancing**, the budget is the binding bound — and the pair of tests at
//! the end of the file is the one that catches the error in the direction that
//! matters: a budget set too tight for a healthy peripheral.

use fapico2_platform::trng::{
    EntropyClock, ProbeStatus, TrngError, TrngProbe, CLOCK_LIVENESS_SPINS,
    ENTROPY_CLOCK_TICKS_PER_MS, MAX_ENTROPY_POLLS, MAX_ENTROPY_WAIT, MAX_ENTROPY_WAIT_MS,
};

/// Byte the fake peripheral stamps into the buffer, so a test can tell a
/// delivered block from a buffer the wait loop never touched.
const MARKER: u8 = 0xA5;

/// The RP2350 datasheet's quoted **average** generation time for
/// `embassy-rp`'s default `Config`, in clock ticks: "an average generation
/// time of about 2 milliseconds" (RP2350 §12.12.2, quoted verbatim in
/// `embassy-rp-0.10.0/src/trng.rs:78-83`, where `Config::default()` is
/// sample_count 25 with all three health tests enabled).
///
/// Written as arithmetic on the budget's own tick rate rather than as a
/// literal, so it cannot drift away from the constant it is compared against.
const DATASHEET_AVG_GENERATION_TICKS: u64 = 2 * ENTROPY_CLOCK_TICKS_PER_MS;

/// A fake wall clock whose advance per poll the test controls.
///
/// This is the whole point of the [`EntropyClock`] seam: the budget is
/// arithmetic over this value, so a host test can make a peripheral that is
/// "slow" by any chosen amount without any hardware, and can assert both
/// sides of the deadline — the last instant inside it is served, the first
/// one past it is a stall.
struct FakeClock {
    now: u64,
    /// How many ticks pass between two consecutive status reads. `0` models a
    /// clock that never advances at all, which is also what a broken or
    /// absent clock looks like — and is the case the hard poll cap exists for.
    ticks_per_poll: u64,
}

impl FakeClock {
    fn new(ticks_per_poll: u64) -> Self {
        Self {
            now: 0,
            ticks_per_poll,
        }
    }
}

impl EntropyClock for FakeClock {
    fn ticks(&self) -> u64 {
        self.now
    }
}

/// The bounds are pinned at compile time, not at run time: the failure modes
/// this guards against are a hard cap quietly raised to "effectively infinite"
/// and a budget quietly lowered below one healthy generation — a boot brick,
/// because `boot::init_drbg` is fatal by design. A runtime assertion would
/// fire only after the next `cargo test` and would read as a tautology; these
/// fire the moment a constant is edited.
const _: () = assert!(
    MAX_ENTROPY_POLLS >= 1024 && MAX_ENTROPY_POLLS <= 1 << 24,
    "MAX_ENTROPY_POLLS out of range: it must be finite, and large enough never \
     to pre-empt the wall-clock budget on a healthy peripheral"
);
const _: () = assert!(
    MAX_ENTROPY_WAIT_MS >= 20,
    "MAX_ENTROPY_WAIT_MS must stay at or above 10x the RP2350 datasheet's ~2 ms \
     AVERAGE generation time for embassy-rp's default Config (RP2350 §12.12.2); \
     the datasheet also warns that results 'occasionally take an especially \
     long time to generate'. A budget at or below the average refuses roughly \
     half of all healthy draws, and a seed refusal is fatal at boot."
);

/// Host stand-in for the TRNG peripheral: a scripted poll sequence plus a
/// count of how many polls it was asked for. Lives in the test file (not
/// behind `#[cfg(test)]` in the module) so the device build stays `no_std`-clean
/// and pulls in nothing.
///
/// A *sequence*, not a single fixed status, is the point. A probe that answers
/// the same thing forever cannot tell apart two implementations that both look
/// correct against it: a loop that returns on the **first** non-`Ready` poll
/// and a loop that polls to the full bound behave identically when the status
/// never changes. The interesting case — `Busy` for a while, then `Ready` —
/// is only reachable with a probe that changes its mind.
struct ScriptedProbe {
    /// What `status()` reports on every poll up to and including `ready_after`.
    status: ProbeStatus,
    /// How many polls answer with `status` before the probe reports
    /// [`ProbeStatus::Ready`]. `u32::MAX` means "never", which is the
    /// `ScriptedProbe::new` default: a probe that reports one status forever.
    ready_after: u32,
    /// How many times the wait loop asked for a status, in total.
    polls: u32,
    /// The wall clock the budget is measured against.
    clock: FakeClock,
}

impl ScriptedProbe {
    /// A probe that reports `status` on every poll and never becomes ready,
    /// against a **frozen** clock.
    ///
    /// Frozen is the default so the budget cannot end the wait and every
    /// poll-count assertion below is about the hard cap. `.ticking()` switches
    /// the clock on.
    fn new(status: ProbeStatus) -> Self {
        Self {
            status,
            ready_after: u32::MAX,
            polls: 0,
            clock: FakeClock::new(0),
        }
    }

    /// A probe that reports `status` for the first `n` polls and
    /// [`ProbeStatus::Ready`] from poll `n + 1` onwards. The peripheral is
    /// "waking up" after `n` polls.
    fn ready_after(mut self, n: u32) -> Self {
        self.ready_after = n;
        self
    }

    /// Make the wall clock advance `ticks_per_poll` per status read, so
    /// [`MAX_ENTROPY_WAIT`] — rather than the hard cap — is the bound in play.
    fn ticking(mut self, ticks_per_poll: u64) -> Self {
        self.clock = FakeClock::new(ticks_per_poll);
        self
    }
}

impl TrngProbe for ScriptedProbe {
    fn status(&mut self) -> ProbeStatus {
        self.polls += 1;
        self.clock.now += self.clock.ticks_per_poll;
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

/// (1) The autocorr-failure branch — the one that makes embassy-rp loop
/// forever. A device whose TRNG has wedged must get an *error back*, not a
/// hang, and the error must arrive within the budget.
///
/// The clock here is **live**, so what is under test is the budget and the
/// peripheral, not the instrument. The instrument's own failure has its own
/// file (`trng_clock_precondition.rs`); these two used to share a frozen
/// clock, and once the liveness check landed that silently turned a
/// wedged-peripheral test into a wedged-clock test.
#[test]
fn autocorr_error_returns_stalled_within_the_bound() {
    let mut probe = ScriptedProbe::new(ProbeStatus::AutocorrErr).ticking(1);
    let mut buf = [0u8; 32];

    let result = probe.probe_bytes(&mut buf);

    assert_eq!(
        result,
        Err(TrngError::Stalled),
        "a peripheral stuck on AUTOCORR_ERR must return Stalled, not spin"
    );
    assert!(
        (1..=MAX_ENTROPY_POLLS).contains(&probe.polls),
        "the wait must terminate inside the bound: got {} polls, bound is {}",
        probe.polls,
        MAX_ENTROPY_POLLS
    );
    assert_eq!(
        probe.polls as u64, MAX_ENTROPY_WAIT,
        "the whole bounded budget must be spent before giving up (an early \
         return would mean the bound is not what stops the loop)"
    );
    assert_eq!(
        buf, [0u8; 32],
        "a stalled wait must not hand back a half-written buffer"
    );
}

/// (2) The *other* invalid-EHR branch — `panic!("RNG not busy, but ehr is not
/// valid!")` in embassy-rp. Same treatment: a `no_std` panic with no
/// supervisor is a hang the caller cannot observe either.
#[test]
fn invalid_ehr_returns_stalled_within_the_bound() {
    let mut probe = ScriptedProbe::new(ProbeStatus::InvalidEhr).ticking(1);
    let mut buf = [0u8; 16];

    assert_eq!(probe.probe_bytes(&mut buf), Err(TrngError::Stalled));
    assert!(probe.polls >= 1 && probe.polls <= MAX_ENTROPY_POLLS);
}

/// (3) A peripheral that is merely **slow** — `Busy` for the whole budget less
/// one, then `Ready` on the poll the budget expires on — must still be served.
///
/// This is the test the previous draft of this file was missing: the fake
/// reported one fixed status, `ProbeStatus::Busy` was never constructed
/// anywhere, and so nothing here could distinguish a loop that spends the
/// whole budget from a loop that gives up the *second* time it sees a
/// non-`Ready` status. An implementation of `probe_bytes` that gave up early
/// passed every other test in this file. The bound is a ceiling, not a budget
/// that has to be spent.
///
/// The clock advances 2 ms per poll — the RP2350 datasheet's own quoted
/// **average** generation time for this configuration (RP2350 §12.12.2) — so
/// `Ready` lands on poll 10, which is the poll on which the budget expires.
/// That ordering is deliberate: the `Ready` test runs before the deadline
/// test, so a block arriving exactly on the deadline is served rather than
/// refused, and a budget checked the wrong way round is a brick.
#[test]
fn a_slow_peripheral_that_becomes_ready_is_still_served() {
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy)
        .ticking(2_000)
        .ready_after(9);
    let mut buf = [0u8; 32];

    assert_eq!(
        probe.probe_bytes(&mut buf),
        Ok(()),
        "Ready on the poll the budget expires must be served, not \
         mistaken for a stall"
    );
    assert_eq!(
        probe.polls,
        MAX_ENTROPY_WAIT as u32 / 2_000,
        "the wait used exactly the budget it was allowed and no more"
    );
    assert_eq!(buf, [MARKER; 32], "the whole buffer must be filled");
}

/// (4) The mirror of (3), and what makes (3) a real boundary rather than a
/// coincidence: the same probe woken one poll *later* — `Ready` would arrive
/// on the poll after the budget expires — is a stall, having spent the same
/// elapsed ticks. Together the two say the budget is a deadline on when
/// `Ready` may arrive, and nothing about the statuses that came before it.
#[test]
fn a_peripheral_that_becomes_ready_too_late_is_stalled() {
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy)
        .ticking(2_000)
        .ready_after(10);
    let mut buf = [0u8; 32];

    assert_eq!(probe.probe_bytes(&mut buf), Err(TrngError::Stalled));
    assert_eq!(probe.polls, MAX_ENTROPY_WAIT as u32 / 2_000);
    assert_eq!(
        buf, [0u8; 32],
        "a stalled wait must not hand back a half-written buffer"
    );
}

/// (5) The trivial case, kept separate from (3) so a failure of the scripted
/// sequence is not mistaken for a failure of the wait: a peripheral that is
/// already `Ready` takes exactly one poll.
#[test]
fn a_healthy_peripheral_is_served_on_the_first_ready_poll() {
    let mut probe = ScriptedProbe::new(ProbeStatus::Ready);
    let mut buf = [0u8; 32];

    assert_eq!(probe.probe_bytes(&mut buf), Ok(()));
    assert_eq!(probe.polls, 1, "a ready peripheral takes exactly one poll");
    assert_eq!(buf, [MARKER; 32], "the whole buffer must be filled");
}

/// (6) An empty request is a no-op, matching `Trng::random_bytes`'s
/// contract: asking for zero bytes must not consume the poll budget and must
/// not report a stall for work that was never requested.
#[test]
fn an_empty_request_is_a_no_op() {
    let mut probe = ScriptedProbe::new(ProbeStatus::AutocorrErr);
    let mut buf: [u8; 0] = [];

    assert_eq!(probe.probe_bytes(&mut buf), Ok(()));
    assert_eq!(probe.polls, 0, "an empty request must not poll the peripheral");
}

// ---------------------------------------------------------------------------
// 7. The wall-clock budget — the bound that is in the unit that means something
// ---------------------------------------------------------------------------

/// **The test that catches the error in the direction that matters.** A
/// peripheral that becomes `Ready` on the very last poll *inside* the
/// wall-clock budget must be served.
///
/// This is the half a poll-count budget gets wrong. The RP2350 datasheet
/// quotes ~2 ms as the **average** generation time for this configuration, so
/// a ceiling expressed as a handful of register reads — a few microseconds —
/// is two to three orders of magnitude below one *healthy* generation, and
/// would return `Stalled` on good silicon. Because a seed refusal is fatal
/// at boot, that is not a degraded device, it is a brick. The old
/// `MAX_ENTROPY_POLLS = 64` is exactly that number; this test is written so
/// it would have failed against it, and it fails again the moment anyone
/// lowers `MAX_ENTROPY_WAIT_MS` toward the average.
#[test]
fn a_block_ready_just_inside_the_budget_is_still_served() {
    // One tick per poll. `ready_after(n)` answers `Ready` from poll `n + 1`,
    // so `MAX_ENTROPY_WAIT - 1` puts `Ready` on poll `MAX_ENTROPY_WAIT` — the
    // last instant the deadline permits (the loop breaks on the poll where
    // elapsed ticks reach the budget).
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy)
        .ticking(1)
        .ready_after(MAX_ENTROPY_WAIT as u32 - 1);
    let mut buf = [0u8; 32];

    // The budget must clear the datasheet's ~2 ms AVERAGE generation time for
    // this configuration with room to spare. Stated here as well as in the
    // compile-time assert below, because this test's own `ready_after` scales
    // with the constant: on its own it pins the deadline's *edges* and would
    // happily pass with a budget of one tick. The two assertions together are
    // the guard — this one against a budget that is too small, the edges above
    // against one that is too large or checked at the wrong instant.
    // `const {}` so this is a *compile* failure, not a runtime one: lowering
    // the budget to below the datasheet average then breaks the build rather
    // than waiting to be noticed by a test run.
    const {
        assert!(
            MAX_ENTROPY_WAIT >= 2 * DATASHEET_AVG_GENERATION_TICKS,
            "MAX_ENTROPY_WAIT must stay at or above twice the RP2350 datasheet's \
             ~2 ms AVERAGE generation time (RP2350 §12.12.2, quoted in \
             embassy-rp's own Config docs) — a budget below that refuses a large \
             fraction of healthy draws, and a seed refusal is fatal at boot"
        );
    }
    assert_eq!(
        probe.probe_bytes(&mut buf),
        Ok(()),
        "a block that arrives on the last poll inside the budget must be \
         served; refusing it would refuse roughly half of all healthy draws"
    );
    assert_eq!(buf, [MARKER; 32], "and the whole buffer must be filled");
    // The hard cap was never the binding bound here — the budget was.
    assert!(
        probe.polls as u64 <= MAX_ENTROPY_WAIT + 2,
        "the wall-clock budget should have ended the wait, after {} polls",
        probe.polls
    );
}

/// The mirror: the *same* peripheral woken so that `Ready` arrives one poll
/// — one tick, at 1 tick per poll — past the budget, is a stall. Together the
/// two say the budget is a deadline and not a hint, and that its two edges
/// are exactly where they were meant to be. A budget with no such edge would
/// be a constant that had never been tested.
#[test]
fn a_block_ready_just_past_the_budget_is_stalled() {
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy)
        .ticking(1)
        .ready_after(MAX_ENTROPY_WAIT as u32);
    let mut buf = [0u8; 32];

    assert_eq!(probe.probe_bytes(&mut buf), Err(TrngError::Stalled));
    assert_eq!(
        buf, [0u8; 32],
        "a stalled wait must not hand back a half-written buffer"
    );
}

/// A peripheral that is *one millisecond* per generation — comfortably
/// inside the datasheet's own quoted range and nowhere near the budget —
/// must be served after a few polls, not after a few hundred thousand.
#[test]
fn a_peripheral_generating_at_the_datasheet_average_is_served() {
    // 2 ms of ticks per poll, then `Ready` on the next poll. The wait must
    // end on the *budget*, two polls in.
    let mut probe = ScriptedProbe::new(ProbeStatus::Busy)
        .ticking(2_000)
        .ready_after(1);
    let mut buf = [0u8; 32];

    assert_eq!(probe.probe_bytes(&mut buf), Ok(()));
    assert_eq!(
        probe.polls, 2,
        "a peripheral at the datasheet's ~2 ms average must be served on the \
         second poll, not spun on for the rest of the budget"
    );
}

/// Belt and braces, and the reason *something* still has to end a wait when
/// the clock is not working: a **frozen** clock — the shape a stopped or
/// unstarted hardware timer has on device — must terminate quickly, and it
/// must terminate on the bound that is honest about why.
///
/// This test used to assert that a frozen clock runs the *whole* hard poll
/// cap and reports `Stalled`. That contract was the defect, not the safety
/// net: 2^18 status reads against a counter pinned at zero is ~0.5 s of
/// spinning, and the code it returned claimed a peripheral had missed a
/// deadline that was never measured. The 2026-09-29 dark boot is that shape
/// reached on real hardware. It is now the liveness bound and
/// `ClockStalled`; the hard cap's own reachability is covered in
/// `trng_clock_precondition.rs` by a clock that *is* counting, just far too
/// slowly to reach the budget.
#[test]
fn a_frozen_clock_terminates_on_the_liveness_bound_naming_the_clock() {
    let mut probe = ScriptedProbe::new(ProbeStatus::AutocorrErr); // ticks_per_poll = 0
    let mut buf = [0u8; 32];

    assert_eq!(
        probe.probe_bytes(&mut buf),
        Err(TrngError::ClockStalled),
        "a clock that never advances must be named, not reported as a \
         peripheral that missed an unmeasured deadline"
    );
    assert!(
        probe.polls <= CLOCK_LIVENESS_SPINS + 1,
        "and it must terminate inside the liveness window, not at the hard \
         cap: got {} polls, liveness bound is {}",
        probe.polls,
        CLOCK_LIVENESS_SPINS + 1
    );
}

