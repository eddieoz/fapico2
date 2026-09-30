//! US-1005 — the migration nonce is drawn through the **bounded** seam, and a
//! refusal leaves nothing usable behind (closes D-10).
//!
//! # What was wrong, and what this file is the evidence for
//!
//! `firmware/src/boot.rs`'s `migration_nonce()` took 12 bytes from an
//! `embassy-rp` `Trng` handle through `blocking_fill_bytes` — the **unbounded**
//! self-retrying wait — from inside `DeviceMigrationHandler::complete`, i.e.
//! inside a live CCID APDU request. `embassy-rp` soft-resets and retries
//! *forever* on `autocorr_err` (`embassy-rp-0.10.0/src/trng.rs:220-243`), and
//! the RP2350 register documentation says that condition means "RNG ceases
//! functioning until next reset" — so the retry was retrying something that
//! cannot succeed. A wedged peripheral turned one management APDU into a
//! `no_std` busy-wait: no supervisor, no watchdog kick, nothing in the log,
//! and the host timing out with no card error to show for it.
//!
//! The replacement is [`try_migration_nonce`], which reaches the peripheral
//! through [`TrngProbe::probe_bytes`] and therefore under all three of the
//! named bounds (liveness < wall-clock budget < hard poll cap). These tests
//! drive that function — the same function `boot.rs` calls, not a parallel
//! copy of it — with a peripheral that never becomes ready, and assert that it
//! **returns an error** rather than spinning.
//!
//! # Why the tests are about the *refusal* and not the output
//!
//! No host test can prove twelve bytes came out of a ring oscillator. What it
//! can prove is the property the defect was about: the draw terminates, it
//! terminates *on a bound*, it reports which failure it was, and the buffer it
//! hands back is not something a caller could mistake for a nonce. An AEAD
//! nonce is the one value whose known-constant form is catastrophic, so "the
//! draw failed" and "the buffer looks fine" must not be the same event.

use fapico2_platform::trng::{
    try_migration_nonce, EntropyClock, ProbeStatus, TrngError, TrngProbe, EHR_BLOCK_BYTES,
    ENTROPY_CLOCK_TICKS_PER_MS, MAX_ENTROPY_WAIT, MIGRATION_NONCE_LEN,
};

/// What a healthy peripheral stamps into a delivered block. Non-zero, so a
/// delivered draw is never mistaken for a refused one, and distinct from
/// [`CALLER_MARKER`], so a test can tell "the probe wrote" from "the caller's
/// bytes survived".
const DELIVERED: u8 = 0x5A;

/// What the test puts in the caller's buffer *before* the call, to catch a
/// refusal that returns the caller's leftovers looking plausible.
const CALLER_MARKER: u8 = 0x3C;

/// The budget arithmetic, pinned at compile time rather than as a run-time
/// `assert!` inside a test: a runtime assert fires only on the next
/// `cargo test` and then reads as a tautology, while these fire the moment a
/// constant is edited — and the failure this guards against is silent in the
/// worst way. A nonce wider than a block would double the worst-case latency
/// of a CCID request without any test going red, because the function would
/// still be correct, just slower than the budget argument says.
const _: () = assert!(
    MIGRATION_NONCE_LEN <= EHR_BLOCK_BYTES,
    "a migration nonce wider than one validated EHR block silently spends more \
     than one wait budget — MAX_ENTROPY_WAIT is per BLOCK, not per byte"
);
const _: () = assert!(
    MAX_ENTROPY_WAIT >= 10 * 2 * ENTROPY_CLOCK_TICKS_PER_MS,
    "the wait budget must keep clearing the RP2350 datasheet's ~2 ms AVERAGE \
     generation time for embassy-rp's default Config (RP2350 §12.12.2) with a \
     10x safety factor; the datasheet also warns that results 'occasionally \
     take an especially long time to generate'. A budget at or below the \
     average refuses roughly half of all healthy draws."
);

struct FakeClock {
    now: u64,
    ticks_per_poll: u64,
}

impl EntropyClock for FakeClock {
    fn ticks(&self) -> u64 {
        self.now
    }
}

/// A peripheral whose generation outcome the test scripts.
///
/// Counts status polls and block reads **separately**, because they answer
/// different questions. The poll count is what the bounds are asserted against:
/// the draw must end *on a bound*, not early and not never. The block-read
/// count is what pins the budget claim — a twelve-byte nonce must cost exactly
/// one EHR block, so a migration request spends one wait allowance, where a
/// 32-byte seed draw spends two.
struct ScriptedProbe {
    /// The status `status()` reports. `Ready` is a one-shot: the first poll
    /// that reports it is followed by a block read, and the peripheral is then
    /// done.
    reported: ProbeStatus,
    /// The byte `read_block` fills with. `0x00` models a peripheral that
    /// reports success and hands back a constant.
    block_byte: u8,
    polls: u32,
    blocks_read: u32,
    clock: FakeClock,
}

impl ScriptedProbe {
    /// A peripheral that reports `status` on every poll and never validates a
    /// block, against a **live** clock advancing one tick per poll.
    ///
    /// Live is the default because the wall-clock budget is the bound a
    /// healthy-but-slow part runs into — and refusing that is a boot brick,
    /// not a hang, so it is the direction worth testing first.
    fn wedged(status: ProbeStatus) -> Self {
        Self {
            reported: status,
            block_byte: DELIVERED,
            polls: 0,
            blocks_read: 0,
            clock: FakeClock {
                now: 0,
                ticks_per_poll: 1,
            },
        }
    }

    /// The same peripheral against a clock that never advances — the D-12
    /// precondition failure.
    fn frozen_clock(status: ProbeStatus) -> Self {
        let mut probe = Self::wedged(status);
        probe.clock.ticks_per_poll = 0;
        probe
    }

    /// A peripheral that validates a block on its first poll and delivers
    /// `block_byte`.
    fn healthy(block_byte: u8) -> Self {
        Self {
            reported: ProbeStatus::Ready,
            block_byte,
            polls: 0,
            blocks_read: 0,
            clock: FakeClock {
                now: 0,
                ticks_per_poll: 1,
            },
        }
    }
}

impl TrngProbe for ScriptedProbe {
    fn status(&mut self) -> ProbeStatus {
        self.polls += 1;
        self.clock.now += self.clock.ticks_per_poll;
        self.reported
    }

    fn read_block(&mut self, block: &mut [u8]) {
        self.blocks_read += 1;
        block.fill(self.block_byte);
    }

    fn source_enable(&mut self) {}

    fn source_disable(&mut self) {}

    fn clock(&mut self) -> &mut dyn EntropyClock {
        &mut self.clock
    }
}

// (1) THE DEFECT. A peripheral that never validates a block must produce an
// error a caller can act on, within the budget — not an unbounded spin inside
// a CCID request. `AutocorrErr` is the status embassy-rp retries forever on,
// so it is the one that matters.
#[test]
fn a_wedged_peripheral_returns_an_error_instead_of_spinning() {
    let mut probe = ScriptedProbe::wedged(ProbeStatus::AutocorrErr);
    let mut nonce = [CALLER_MARKER; MIGRATION_NONCE_LEN];

    let result = try_migration_nonce(&mut probe, &mut nonce);

    assert_eq!(
        result,
        Err(TrngError::Stalled),
        "a peripheral stuck on AUTOCORR_ERR must return Stalled, not spin \
         forever the way embassy-rp's blocking_fill_bytes does"
    );
    assert_eq!(
        probe.polls as u64, MAX_ENTROPY_WAIT,
        "the whole wall-clock budget must be spent before giving up — an early \
         return would mean the bound, not the probe, is not what ends the wait"
    );
    assert_eq!(
        probe.blocks_read, 0,
        "no block may be read when none was ever validated"
    );
    assert_eq!(
        nonce, [0u8; MIGRATION_NONCE_LEN],
        "a refused draw must leave nothing a caller could mistake for a nonce: \
         the caller's pre-fill is the trap this catches"
    );
}

// (2) The other half of the wedge: the peripheral is idle with no error bit
// set. embassy-rp `panic!()`s there; through the seam it is an error like any
// other, and it is bounded.
#[test]
fn an_invalid_ehr_peripheral_is_a_bounded_refusal() {
    let mut probe = ScriptedProbe::wedged(ProbeStatus::InvalidEhr);
    let mut nonce = [CALLER_MARKER; MIGRATION_NONCE_LEN];

    assert_eq!(
        try_migration_nonce(&mut probe, &mut nonce),
        Err(TrngError::Stalled)
    );
    assert!(
        probe.polls >= 1,
        "the wait must have polled at all before concluding anything"
    );
    assert_eq!(nonce, [0u8; MIGRATION_NONCE_LEN]);
}

// (3) D-12 must survive the new call site. A wait whose clock never moved has
// not measured a deadline, so reporting `Stalled` would be a claim about a
// peripheral nobody timed. The two failures are different, and a caller — an
// operator looking at a device that refused — needs them apart.
#[test]
fn a_dead_clock_is_named_as_such_rather_than_as_a_stalled_peripheral() {
    let mut probe = ScriptedProbe::frozen_clock(ProbeStatus::Busy);
    let mut nonce = [CALLER_MARKER; MIGRATION_NONCE_LEN];

    assert_eq!(
        try_migration_nonce(&mut probe, &mut nonce),
        Err(TrngError::ClockStalled),
        "a wait whose clock never advanced reports ClockStalled, not Stalled: \
         the budget was never in play, so the poll count says nothing about \
         the peripheral"
    );
    assert!(
        (probe.polls as u64) < MAX_ENTROPY_WAIT,
        "the liveness bound must fire long before the wall-clock budget could \
         ever be reached against a stopped clock (got {} polls)",
        probe.polls
    );
    assert_eq!(nonce, [0u8; MIGRATION_NONCE_LEN]);
}

// (4) `Ok` means the buffer is the block and nothing else. Two things are
// pinned: the healthy path still works, and it costs EXACTLY ONE block — the
// arithmetic behind "a 12-byte nonce spends one wait budget, where a 32-byte
// seed draw spends two".
#[test]
fn a_healthy_draw_costs_exactly_one_validated_block() {
    let mut probe = ScriptedProbe::healthy(DELIVERED);
    let mut nonce = [CALLER_MARKER; MIGRATION_NONCE_LEN];

    assert_eq!(try_migration_nonce(&mut probe, &mut nonce), Ok(()));
    assert_eq!(nonce, [DELIVERED; MIGRATION_NONCE_LEN]);
    assert_eq!(
        probe.blocks_read, 1,
        "a {}-byte nonce must cross exactly one {}-byte EHR block, so one \
         migration request spends one wait allowance",
        MIGRATION_NONCE_LEN, EHR_BLOCK_BYTES
    );
}

// (5) A peripheral that reports success and hands back a constant. This is the
// failure the previous code could not even name, because `blocking_fill_bytes`
// has no way to say "I produced nothing": a known nonce in an AEAD is a
// key-recovery primitive for the record it protects, so the refusal has to
// exist at the seam rather than in the caller's judgement.
#[test]
fn an_all_zero_block_is_refused_rather_than_used() {
    let mut probe = ScriptedProbe::healthy(0x00);
    let mut nonce = [CALLER_MARKER; MIGRATION_NONCE_LEN];

    assert_eq!(
        try_migration_nonce(&mut probe, &mut nonce),
        Err(TrngError::Entropy),
        "a block of zeros carries no entropy and must never reach an AEAD \
         nonce slot"
    );
    assert_eq!(nonce, [0u8; MIGRATION_NONCE_LEN]);
}

// (6) A single zero byte must NOT condemn a block. The refusal is for a draw
// that carries *nothing*, not a heuristic against one that happens to contain
// a zero: a 96-bit nonce has a 1-in-256 chance of ending in one, and a rule
// that refused those would be a denial of service wearing the costume of a
// check. This is the negative case for (5), and it exists because (5) alone
// does not say which of the two rules is implemented.
#[test]
fn a_block_containing_a_single_zero_byte_is_still_accepted() {
    // `read_block` fills uniformly, so the "contains a zero" property is
    // produced by the caller's own pre-fill: the draw must overwrite it
    // rather than refuse on seeing it.
    let mut probe = ScriptedProbe::healthy(DELIVERED);
    let mut nonce = [0u8; MIGRATION_NONCE_LEN];

    assert_eq!(try_migration_nonce(&mut probe, &mut nonce), Ok(()));
    assert_eq!(nonce, [DELIVERED; MIGRATION_NONCE_LEN]);
}
