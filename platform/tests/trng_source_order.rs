//! US-1005 — the entropy draw's **register-call order** is testable on host.
//!
//! # The defect this file exists to catch
//!
//! On 2026-09-29 a parked unit's register reads gave the answer directly:
//!
//! ```text
//! TRNG.RND_SOURCE_ENABLE  0x400F012C = 0x00000000   <-- the source is off
//! TRNG.TRNG_CONFIG        0x400F010C = 0x00000001   (configured correctly)
//! TRNG.SAMPLE_CNT1        0x400F0130 = 0x00000019   = 25
//! TRNG.TRNG_VALID/EHR     0x400F0110 = 0x00000000   (no block, ever)
//! ```
//!
//! The ring oscillator was never enabled. Everything else was right, which is
//! what made it invisible: a correctly configured, correctly clocked,
//! correctly budgeted wait against a peripheral that was **switched off**.
//! `boot::init_drbg` treats a refused seed as fatal, so the unit halted before
//! USB was ever constructed.
//!
//! # Why a large host suite and a long gate list did not see it
//!
//! Because the ordering lived in `Rp2350Probe::read_into`, inside
//! `#[cfg(all(feature = "device", target_arch = "arm"))]`. No host build ever
//! compiled it. And the host fakes that *did* stand in for it had no source
//! state at all — `status()` answered a scripted `ProbeStatus`, and nothing
//! asked what the peripheral needed before it could answer. A fake with no
//! power switch cannot catch a missing power switch.
//!
//! So the seam is [`draw_blocks`]: `no_std`, not `cfg`-gated, generic over
//! [`TrngProbe`], and the **only** implementation of the sequence in the
//! crate. The device supplies register access; this file supplies a fake
//! that *records the order the operations arrived in* and refuses to produce
//! anything until the source is on. That refusal is not a contrivance — it is
//! the silicon. `RND_SRC_EN` gates the oscillators, so with it clear
//! `TRNG_BUSY` never asserts and `EHR_VALID` never sets, and
//! `Rp2350Probe::status` reports exactly what this fake reports:
//! [`ProbeStatus::InvalidEhr`], forever.
//!
//! Nothing here asserts on a return value alone. The defect is an *ordering*,
//! and an ordering is not visible in a `Result`; the assertions are on the
//! recorded op sequence.

use fapico2_platform::trng::{
    draw_blocks, EntropyClock, ProbeStatus, TrngError, TrngProbe, MAX_ENTROPY_WAIT,
};

/// Base byte the fake stamps into every block, so a test can tell a delivered
/// block from a buffer the wait never wrote to. Each successive block is one
/// higher, so two blocks are never equal.
const MARKER: u8 = 0xA5;

/// One register operation, as the peripheral saw it.
///
/// The timer's reads are deliberately **not** recorded: `await_ready` reads
/// the clock on every iteration and the sequence would bury the three
/// operations that matter under tens of thousands of entries. The clock is
/// the *instrument*; these tests are about what was done to the peripheral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    SourceEnable,
    SourceDisable,
    Status,
    ReadBlock,
}

impl Op {
    fn short(self) -> &'static str {
        match self {
            Op::SourceEnable => "on",
            Op::SourceDisable => "off",
            Op::Status => "poll",
            Op::ReadBlock => "read",
        }
    }
}

/// The fake's wall clock, advanced by the *peripheral* on each status read
/// rather than by `ticks()`. Modelling it that way is what lets a fixture
/// stop the clock part way through a draw, which is the only way to reach the
/// per-block wait with a clock that is not moving.
struct FakeClock {
    now: u64,
}

impl EntropyClock for FakeClock {
    fn ticks(&self) -> u64 {
        self.now
    }
}

/// The host twin of the RP2350 TRNG, with the one property the silicon has
/// and every previous fake lacked: **it is powered**.
///
/// It does not override `read_into`, so `probe_bytes` runs the same
/// [`draw_blocks`] the device runs. Every assertion below is therefore about
/// the function the device executes, not about a copy of it.
struct RecordingProbe {
    /// `RND_SRC_EN`. Off unless a fixture says otherwise.
    enabled: bool,
    /// Ordered record of the register operations performed.
    ops: Vec<Op>,
    /// How many enabled status polls must pass before the peripheral is
    /// willing to report a validated block.
    ready_after_enabled: u32,
    /// How many `Ready` answers the peripheral will give before it goes
    /// silent. `u32::MAX` = unlimited.
    ready_grants: u32,
    /// How many status polls advance the clock; `None` = forever.
    /// `Some(n)` models a timer that stopped part way through the draw.
    clock_stops_after: Option<u32>,
    /// Status polls so far, counted whether or not the source is on.
    ///
    /// Separate from `polls_enabled` because the wall clock does not care
    /// about the TRNG: `TIMER0` is a different peripheral from the ring
    /// oscillators, and a fake that froze its clock whenever the source was
    /// off would make every pre-wait fail as a *clock* failure and quietly
    /// report the wrong defect.
    polls: u32,
    /// Status polls seen while the source was on.
    polls_enabled: u32,
    /// Blocks handed over so far.
    blocks: u32,
    clock: FakeClock,
}

impl RecordingProbe {
    /// The unit as found: powered off, and healthy the moment it is powered.
    /// Its first block arrives on the first poll after the enable — the
    /// fastest a real part can answer, so no test here can be accused of
    /// needing a slow peripheral in order to fail.
    fn parked() -> Self {
        Self::powered_off(u32::MAX, None)
    }

    /// A peripheral that is up and will never produce. Models the wedge.
    fn up_but_silent() -> Self {
        Self {
            enabled: true,
            ..Self::powered_off(0, None)
        }
    }

    /// A peripheral that serves exactly one block and then goes silent: the
    /// shape a 32-byte request (two EHR blocks) dies on, with the *first*
    /// block arriving normally.
    fn serves_one_block() -> Self {
        Self::powered_off(1, None)
    }

    /// Powered off, and a clock that has already stopped. Paired with a
    /// single `Ready` grant so the draw gets past a pre-wait on the block
    /// that is waiting to be produced, and then fails with a clock that is
    /// not moving while it waits for the next one.
    fn clock_dead_after_one_block() -> Self {
        Self {
            enabled: true,
            ..Self::powered_off(1, Some(1))
        }
    }

    fn powered_off(ready_grants: u32, clock_stops_after: Option<u32>) -> Self {
        Self {
            enabled: false,
            ops: Vec::new(),
            ready_after_enabled: 0,
            ready_grants,
            clock_stops_after,
            polls: 0,
            polls_enabled: 0,
            blocks: 0,
            clock: FakeClock { now: 0 },
        }
    }

    fn source_enabled(&self) -> bool {
        self.enabled
    }

    fn count(&self, op: Op) -> usize {
        self.ops.iter().filter(|o| **o == op).count()
    }

    /// A short rendering of the op sequence, for assertion messages: a long
    /// wait produces a long sequence and a wall of `poll poll poll` helps
    /// nobody.
    fn trace(&self) -> String {
        self.ops
            .iter()
            .take(8)
            .map(|o| o.short())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl TrngProbe for RecordingProbe {
    /// The silicon's coupling, exactly. With `RND_SRC_EN` clear there is no
    /// oscillator running, so there is nothing to be busy *with* and nothing
    /// to become valid — not busy, not valid, no error bit set. The device
    /// reports that as `InvalidEhr`, and so does this.
    fn status(&mut self) -> ProbeStatus {
        self.ops.push(Op::Status);
        self.polls += 1;
        let clock_running = match self.clock_stops_after {
            Some(n) => self.polls <= n,
            None => true,
        };
        if clock_running {
            self.clock.now += 1;
        }
        if !self.enabled {
            return ProbeStatus::InvalidEhr;
        }
        self.polls_enabled += 1;
        if self.ready_grants > 0 && self.polls_enabled > self.ready_after_enabled {
            self.ready_grants -= 1;
            ProbeStatus::Ready
        } else {
            ProbeStatus::Busy
        }
    }

    fn source_enable(&mut self) {
        self.ops.push(Op::SourceEnable);
        self.enabled = true;
    }

    fn source_disable(&mut self) {
        self.ops.push(Op::SourceDisable);
        self.enabled = false;
    }

    fn read_block(&mut self, block: &mut [u8]) {
        self.ops.push(Op::ReadBlock);
        let byte = MARKER.wrapping_add(self.blocks as u8);
        block.fill(byte);
        self.blocks += 1;
    }

    fn clock(&mut self) -> &mut dyn EntropyClock {
        &mut self.clock
    }
}

// ---------------------------------------------------------------------------
// (1) THE test. The enable is the first thing, and it is not optional.
// ---------------------------------------------------------------------------

/// The entropy source must be enabled **before the first status read**.
///
/// This is the whole defect, stated as an assertion. A peripheral with its
/// oscillators powered down cannot assert `TRNG_BUSY` or `EHR_VALID`, so a
/// wait issued before `RND_SRC_EN` is set is a wait for a block that cannot
/// exist; it spends the whole budget and reports [`TrngError::Stalled`],
/// which `boot::init_drbg` turns into a refusal to boot on a part whose
/// oscillator has not been switched on.
///
/// Asserted on the recorded *order*, not on the outcome: two different
/// orderings can both end in an error, and only one of them is this bug.
#[test]
fn the_source_is_enabled_before_the_first_status_read() {
    let mut probe = RecordingProbe::parked();
    let mut buf = [0u8; 32];

    // The result is deliberately not the subject of this test; the order is.
    let _ = probe.probe_bytes(&mut buf);

    let enabled_at = probe
        .ops
        .iter()
        .position(|op| *op == Op::SourceEnable)
        .unwrap_or_else(|| {
            panic!(
                "the draw never enabled the entropy source: trace = [{}]. A \
                 peripheral whose RND_SRC_EN was never set cannot assert \
                 TRNG_BUSY or EHR_VALID, so every status read answers \
                 'idle, no error bit' forever.",
                probe.trace()
            )
        });
    let first_status_at = probe
        .ops
        .iter()
        .position(|op| *op == Op::Status)
        .unwrap_or_else(|| {
            panic!(
                "the draw never read the status register: trace = [{}]",
                probe.trace()
            )
        });

    assert!(
        enabled_at < first_status_at,
        "the source was enabled at op {enabled_at} but the status register was \
         first read at op {first_status_at}. A wait issued before the enable is \
         a wait against a peripheral that is switched OFF, not a slow one. \
         Trace: [{}]",
        probe.trace()
    );
    assert_eq!(
        enabled_at, 0,
        "enabling the source is the first thing a draw does, not something it \
         reaches after a round of polling. Trace: [{}]",
        probe.trace()
    );
}

/// The same ordering observed as the symptom an operator sees: a parked but
/// healthy peripheral serves its draw.
///
/// Split from (1) on purpose. (1) says the order is wrong even if the draw
/// somehow succeeded; this says the draw does not succeed. A change that
/// fixed one without the other would still be a defect, and only one of the
/// two assertions would notice.
#[test]
fn a_parked_but_healthy_peripheral_serves_its_draw() {
    let mut probe = RecordingProbe::parked();
    let mut buf = [0u8; 32];

    assert_eq!(
        probe.probe_bytes(&mut buf),
        Ok(()),
        "a peripheral that is off and healthy must be switched on and served. \
         Refusing here is a refusal to boot, before USB enumerates. \
         Trace: [{}]",
        probe.trace()
    );
    assert_eq!(
        &buf[..24],
        &[0xA5; 24],
        "first EHR block"
    );
    assert_eq!(
        &buf[24..],
        &[0xA6; 8],
        "32 bytes is more than one 24-byte EHR block, and the second block \
         must be a *different* block: a peripheral serving the first one \
         twice is handing the caller stale data"
    );
}

// ---------------------------------------------------------------------------
// (2) The sequence, spelled out end to end.
// ---------------------------------------------------------------------------

/// A whole draw, from off to off, with the block between the two switches.
///
/// The full trace, so a change to the *shape* of the sequence (an extra poll,
/// a read before a wait, a second enable) fails here rather than having to be
/// rediscovered by a later session.
#[test]
fn a_successful_draw_is_enable_poll_read_then_disable() {
    let mut probe = RecordingProbe::parked();
    let mut buf = [0u8; 24]; // exactly one EHR block

    assert_eq!(probe.probe_bytes(&mut buf), Ok(()));
    assert_eq!(
        probe.ops,
        vec![Op::SourceEnable, Op::Status, Op::ReadBlock, Op::SourceDisable],
        "one block, one enable, one disable. The wait between the enable and \
         the read is the budget doing its job; a second enable or a second \
         disable is a second way to get the peripheral's power state wrong."
    );
}

/// A 32-byte request crosses two 24-byte blocks, and the source is switched
/// once for the whole draw — not once per block, which is what the old
/// per-block `start()` was one line away from becoming.
#[test]
fn a_multi_block_draw_switches_the_source_once() {
    let mut probe = RecordingProbe::parked();
    let mut buf = [0u8; 32];

    assert_eq!(probe.probe_bytes(&mut buf), Ok(()));
    assert_eq!(
        probe.count(Op::SourceEnable),
        1,
        "the source is on or off for the whole draw. Trace: [{}]",
        probe.trace()
    );
    assert_eq!(
        probe.count(Op::SourceDisable),
        1,
        "and off once, on the way out. Trace: [{}]",
        probe.trace()
    );
    assert_eq!(
        probe.count(Op::ReadBlock),
        2,
        "32 bytes is two EHR blocks"
    );
}

// ---------------------------------------------------------------------------
// (3) The source is off again on every exit, including the refusing ones.
// ---------------------------------------------------------------------------

/// A draw that is refused must leave the peripheral **powered down**.
///
/// The fixture starts *on* — a peripheral left running by an earlier draw, or
/// one that came up in a bad state. A fixture that starts off would make the
/// assertion vacuous, and a fixture that starts off is exactly what every
/// existing host fake had.
#[test]
fn a_refused_draw_leaves_the_source_disabled() {
    let mut probe = RecordingProbe::up_but_silent();
    let mut buf = [0u8; 32];

    assert!(
        probe.probe_bytes(&mut buf).is_err(),
        "this fixture must refuse, or it is not testing a refusal. Trace: [{}]",
        probe.trace()
    );
    assert!(
        !probe.source_enabled(),
        "a refused draw must not leave the ring oscillator running: that is a \
         peripheral left powered, and the next draw would inherit its state. \
         Trace: [{}]",
        probe.trace()
    );
    assert_eq!(
        probe.count(Op::SourceDisable),
        1,
        "and it must have been switched off explicitly, not merely observed to \
         be off afterwards. Trace: [{}]",
        probe.trace()
    );
}

/// The same, on the **mid-draw** refusal: one block lands, the second never
/// arrives. This is the path that used to be invisible — the old code returned
/// `Err` from inside the block loop, and whether the source was left running
/// depended on a hand-written `stop()` being remembered on that one branch.
#[test]
fn a_refusal_part_way_through_a_multi_block_draw_leaves_the_source_disabled() {
    let mut probe = RecordingProbe::serves_one_block();
    let mut buf = [0u8; 32];

    assert!(
        probe.probe_bytes(&mut buf).is_err(),
        "the second block of a 32-byte request must refuse: this fixture only \
         ever produces one. Trace: [{}]",
        probe.trace()
    );
    assert_eq!(
        probe.count(Op::ReadBlock),
        1,
        "only the first block was produced, so only it was read"
    );
    assert!(
        !probe.source_enabled(),
        "a refusal part way through must still power the source down. \
         Trace: [{}]",
        probe.trace()
    );
}

// ---------------------------------------------------------------------------
// (4) The second defect: a dead clock is not a slow peripheral.
// ---------------------------------------------------------------------------

/// `TrngError::ClockStalled` must survive the draw path.
///
/// The old per-block read collapsed every wait failure into
/// `TrngError::Stalled` with `is_err()`, so a wall clock that is not moving
/// arrived at the caller describing the *entropy source* — which is how a
/// timer problem can read as an entropy problem. D-12 is about that
/// indistinguishability, and this is the assertion that the draw path does
/// not reintroduce it.
///
/// The fixture grants exactly one `Ready`, so the block the draw is after
/// arrives and the *next* wait is the one that has to face the dead clock.
/// (A draw that never sees a block is refused by whichever wait comes first,
/// and in the old ordering that was a pre-wait outside the collapse.)
#[test]
fn a_dead_clock_on_the_draw_path_is_named_as_a_clock_failure() {
    let mut probe = RecordingProbe::clock_dead_after_one_block();
    let mut buf = [0u8; 32];

    assert_eq!(
        probe.probe_bytes(&mut buf),
        Err(TrngError::ClockStalled),
        "a clock that is not advancing must reach the caller as itself. \
         Reporting Stalled claims the peripheral missed a deadline that was \
         never measured, which points the reader at the ring oscillator when \
         the timer is what is wrong."
    );
}

/// The mirror, and what makes the assertion above about the peripheral rather
/// than about the code: a **live** clock that runs out of budget is a genuine
/// [`TrngError::Stalled`]. Reporting `ClockStalled` there would be the lie in
/// the other direction.
#[test]
fn a_live_clock_that_misses_the_budget_is_a_peripheral_stall() {
    let mut probe = RecordingProbe::up_but_silent();
    let mut buf = [0u8; 32];

    assert_eq!(probe.probe_bytes(&mut buf), Err(TrngError::Stalled));
}

// ---------------------------------------------------------------------------
// (5) The seam itself: the free function and the trait default are one thing.
// ---------------------------------------------------------------------------

/// `draw_blocks` and `TrngProbe::read_into` are the same sequence.
///
/// `read_into`'s default body *is* `draw_blocks`, and a probe that does not
/// override it is driven by it — that is what stops the device path and the
/// host path from being two implementations that agree today. Driven through
/// each in turn, the two must record identical sequences and fill the buffer
/// identically.
#[test]
fn the_default_read_into_and_the_free_function_are_one_sequence() {
    let mut via_default = RecordingProbe::parked();
    let mut via_free = RecordingProbe::parked();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];

    assert_eq!(via_default.read_into(&mut a), Ok(()));
    assert_eq!(draw_blocks(&mut via_free, &mut b), Ok(()));
    assert_eq!(
        via_default.ops, via_free.ops,
        "the exported seam and the trait default have drifted apart, so the \
         device path and the host path are no longer the same code"
    );
    assert_eq!(a, b, "and they must fill the buffer identically");
}

/// An empty request is a no-op **at the seam**, not only through
/// `probe_bytes`. A caller holding a `TrngProbe` can reach `draw_blocks`
/// directly, and it must not power a peripheral up in order to fill nothing.
#[test]
fn an_empty_request_never_touches_the_peripheral() {
    let mut probe = RecordingProbe::parked();
    let mut buf: [u8; 0] = [];

    assert_eq!(draw_blocks(&mut probe, &mut buf), Ok(()));
    assert!(
        probe.ops.is_empty(),
        "an empty request performed register operations: {:?}",
        probe.ops
    );
    assert!(
        !probe.source_enabled(),
        "and must not leave the source powered"
    );
}

/// A draw must enter the budget **once**.
///
/// The pre-wait this file exists to remove was a second entry into the budget
/// for no information: it waited for a block, discarded the fact that it had
/// one, and then waited for the same block again. Two waits in a row are not
/// visible in a `Result`, so the accounting is asserted against the
/// peripheral's own record — one status read to enter the wait and one to
/// leave it, against a bound the budget's own worst case blows past by four
/// orders of magnitude.
#[test]
fn a_draw_spends_one_budget_and_not_two() {
    let mut probe = RecordingProbe::parked();
    let mut buf = [0u8; 24];

    assert_eq!(probe.probe_bytes(&mut buf), Ok(()));
    assert!(
        probe.count(Op::Status) <= 2,
        "a peripheral that is ready on its first poll costs one status read to \
         enter the wait and one to leave it. Got {} — a wait issued before the \
         source is enabled burns the whole budget first, and a second one \
         after it is the same mistake twice. Trace: [{}]",
        probe.count(Op::Status),
        probe.trace()
    );
    assert!(
        probe.clock.now <= MAX_ENTROPY_WAIT,
        "one block must fit inside one budget: {} ticks of {}",
        probe.clock.now,
        MAX_ENTROPY_WAIT
    );
}
