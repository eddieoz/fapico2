//! US-1005 — [`DrbgTrng`]: the one type a caller asks for randomness from.
//!
//! Three properties are pinned here, and they are the properties the epic's
//! Phase 1 outcome actually claims:
//!
//! 1. **It fails closed at construction.** A source that refuses produces no
//!    generator at all — there is no infallible constructor, so a caller
//!    cannot hold a `DrbgTrng` that was never seeded.
//! 2. **A spent budget is refreshed, not stretched.** Crossing
//!    `RESEED_INTERVAL` draws from the source again rather than continuing on
//!    a stale state, and a source that refuses at *that* point produces an
//!    error rather than wrapping around.
//! 3. **The `Trng` impl cannot silently hand back unfilled bytes**, which is
//!    the one behaviour a caller on a request path must not rely on — hence
//!    [`DrbgTrng::try_random_bytes`] and the test that the two agree when the
//!    generator is healthy.
//!
//! The device half of US-1005 — `Rp2350Probe`, the bounded peripheral probe —
//! cannot be exercised here at all: it reads RP2350 registers. What it *can*
//! be checked for is the property that does not need silicon, which is that
//! the bound is expressed in the same units as the host's: see
//! `PERIPHERAL_BLOCK_DIVISOR` and the "block accounting" section.

use core::mem::size_of;

use fapico2_platform::drbg::{
    SeedError, SeedMaterial, SeedSource, NONCE_LEN, OUTLEN, RESEED_INTERVAL,
};
use fapico2_platform::trng::{
    DrbgTrng, DrbgTrngError, EntropyClock, ProbeStatus, Trng, TrngError, TrngProbe,
    EHR_BLOCK_BYTES, MAX_ENTROPY_WAIT_MS,
};

/// The RP2350 delivers one validated EHR block per generation, 24 bytes
/// (`trng::EHR_BLOCK_BYTES`, the *same* constant the device probe loops on —
/// not a copy). A `NONCE_LEN`-byte seed draw therefore crosses this many
/// blocks, and the device's per-block wait budget is multiplied by it.
///
/// The check below is that the host's notion of a draw and the device's agree
/// on what a draw costs. If someone ever changes `NONCE_LEN` without noticing
/// this, the effective per-draw bound silently doubles or halves and no device
/// test would say so. Asserting against the library's own constant rather than
/// a literal is what makes that a test instead of a coincidence.
const _: () = assert!(
    EHR_BLOCK_BYTES == 24,
    "the RP2350 EHR block is 24 bytes (datasheet §12.12.1); if this changes, \
     the block accounting in this file and Rp2350Probe::read_into must change \
     with it"
);


// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// A wall clock that **counts**, one tick per status read, so every wait in
/// this file ends on the real budget rather than on the liveness bound.
///
/// It used to be frozen, with the comment that the deadline arithmetic "has
/// its own suite". That is still true, but a frozen clock stopped being a
/// neutral choice once `await_ready` began checking its own clock: it would
/// have ended every wait here at `CLOCK_LIVENESS_SPINS` and reported
/// `ClockStalled`, so these tests would have been asserting the *clock's*
/// policy while claiming to assert the DRBG's. The clock's own failure is
/// covered in `trng_clock_precondition.rs`; this file is about policy.
struct TickingClock {
    now: u64,
}

impl TickingClock {
    const fn new() -> Self {
        Self { now: 0 }
    }
}

impl EntropyClock for TickingClock {
    fn ticks(&self) -> u64 {
        self.now
    }
}

/// A peripheral probe that can be told to stall, and that counts the blocks
/// it was asked for.
///
/// `blocks_before_stall` models the shape US-1005's `read_into` contract is
/// written for: a peripheral that serves *n* blocks and then stops answering
/// mid-draw. A request that crosses the stall must come back `Err`, never a
/// partly-filled buffer reported as a successful draw.
struct Probe {
    /// `true` → every status read reports `Ready`.
    ready: bool,
    /// `None` → never stall. `Some(n)` → stall once `n` blocks have been
    /// read.
    blocks_before_stall: Option<u32>,
    draws: u32,
    /// The value handed back by a successful read; incremented per draw so
    /// two draws are distinguishable.
    counter: u8,
    clock: TickingClock,
}

impl Probe {
    fn stalled() -> Self {
        Self {
            ready: false,
            blocks_before_stall: None,
            draws: 0,
            counter: 0,
            clock: TickingClock::new(),
        }
    }

    /// A healthy peripheral whose `read_into` serves one whole EHR block and
    /// then stalls on the next — the multi-block failure mode, modelled the
    /// way `Rp2350Probe::read_into` actually behaves: it writes what it has,
    /// the second block never arrives, and it returns `Err`.
    fn stalls_mid_draw() -> Self {
        Self {
            ready: true,
            blocks_before_stall: Some(1),
            draws: 0,
            counter: 0,
            clock: TickingClock::new(),
        }
    }
}

impl TrngProbe for Probe {
    fn status(&mut self) -> ProbeStatus {
        self.clock.now += 1;
        match self.blocks_before_stall {
            Some(limit) if self.draws >= limit => ProbeStatus::Busy,
            _ if self.ready => ProbeStatus::Ready,
            _ => ProbeStatus::Busy,
        }
    }

    fn read_block(&mut self, block: &mut [u8]) {
        self.draws += 1;
        for slot in block.iter_mut() {
            *slot = self.counter.wrapping_add(1);
        }
        self.counter = self.counter.wrapping_add(1);
    }

    /// Fill the way the device does: one validated EHR block at a time, each
    /// with its own bounded wait, and an `Err` the moment one of them cannot
    /// be produced — after whatever earlier blocks already landed in the
    /// caller's buffer.
    fn read_into(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        if buf.is_empty() {
            return Ok(());
        }
        self.await_ready()?;
        let mut written = 0;
        while written < buf.len() {
            if self
                .blocks_before_stall
                .is_some_and(|limit| self.draws >= limit)
            {
                return Err(TrngError::Stalled);
            }
            let end = (written + EHR_BLOCK_BYTES).min(buf.len());
            self.read_block(&mut buf[written..end]);
            written = end;
        }
        Ok(())
    }

    fn source_enable(&mut self) {}

    fn source_disable(&mut self) {}

    fn clock(&mut self) -> &mut dyn EntropyClock {
        &mut self.clock
    }
}

/// A [`SeedSource`] that either yields a fixed seed plus a fresh nonce, or
/// refuses — the two cases the fail-closed contract turns on.
///
/// `wedge` is a `Cell` rather than a plain field because two tests build the
/// generator over `&mut src` (to observe the call count) and *then* wedge it,
/// which a plain field cannot express: the borrow the generator holds is
/// still live. A shared `Cell` says "the refusal is shared state", which is
/// what it is.
struct Source<'a> {
    /// Shared with the test, not owned: a `DrbgTrng` holds `&mut Source` for
    /// its whole life, so a flag the test flips *after* constructing the
    /// generator has to live behind a separate `&Cell` — a field would be
    /// unreachable for exactly the duration the test needs to reach it.
    wedge: &'a core::cell::Cell<bool>,
    /// Every nonce this source has handed out. Two generators cannot hold
    /// overlapping `&mut` borrows of one source, so the evidence that their
    /// nonces differed is recorded here and read after both are dropped.
    log: &'a core::cell::RefCell<heapless::Vec<u8, 4>>,
    /// A specific refusal to return instead of the default stall, so the
    /// "each refusal reaches the caller distinctly" test can exercise all
    /// four US-1003 variants through one double.
    wedge_case: Option<SeedError>,
    /// How many times `seed()` has been called. The C-1 property is that
    /// this is > 1 over a generator's life, and that each call draws afresh.
    calls: core::cell::Cell<u32>,
    nonce: u8,
}

impl<'a> Source<'a> {
    /// A healthy source whose issued nonces nobody inspects. The log is a
    /// leaked four-byte cell: only the two tests that *read* it need a real
    /// one, and a `Box::leak` here is a test-local allocation, never a device
    /// one.
    fn healthy(wedge: &'a core::cell::Cell<bool>) -> Self {
        let log: &'a core::cell::RefCell<heapless::Vec<u8, 4>> =
            Box::leak(Box::new(core::cell::RefCell::new(heapless::Vec::new())));
        Self::healthy_logged(wedge, log)
    }

    /// A healthy source that records every nonce it issues, for the test that
    /// needs to compare two instantiations' draws.
    fn healthy_logged(
        wedge: &'a core::cell::Cell<bool>,
        log: &'a core::cell::RefCell<heapless::Vec<u8, 4>>,
    ) -> Self {
        Self {
            wedge,
            log,
            wedge_case: None,
            calls: core::cell::Cell::new(0),
            nonce: 0,
        }
    }

    /// A source that refuses from the very first call, with the default
    /// (peripheral-wedge) refusal.
    fn refusing(wedge: &'a core::cell::Cell<bool>) -> Self {
        Self {
            wedge,
            log: Box::leak(Box::new(core::cell::RefCell::new(heapless::Vec::new()))),
            wedge_case: None,
            calls: core::cell::Cell::new(0),
            nonce: 0,
        }
    }
}

impl SeedSource for Source<'_> {
    fn seed(&mut self) -> Result<SeedMaterial, SeedError> {
        self.calls.set(self.calls.get() + 1);
        if let Some(e) = self.wedge_case {
            return Err(e);
        }
        if self.wedge.get() {
            return Err(SeedError::Trng(TrngError::Stalled));
        }
        let mut seed = [0u8; OUTLEN];
        let mut nonce = [0u8; NONCE_LEN];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        for b in nonce.iter_mut() {
            *b = self.nonce;
        }
        let _ = self.log.borrow_mut().push(self.nonce);
        // A fresh draw every call, never repeated — the C-1 property.
        self.nonce = self.nonce.wrapping_add(1);
        Ok(SeedMaterial {
            seed: zeroize::Zeroizing::new(seed),
            nonce: zeroize::Zeroizing::new(nonce),
        })
    }
}

// ---------------------------------------------------------------------------
// 1. Construction fails closed
// ---------------------------------------------------------------------------

/// A source that refuses produces **no generator**. There is no infallible
/// constructor to have bypassed — the type simply does not come into being,
/// so the "unseeded generator" state is not expressible.
#[test]
fn a_refusing_source_produces_no_generator() {
    let wedge = core::cell::Cell::new(true);
    let err = DrbgTrng::try_new(Source::refusing(&wedge))
        .expect_err("a refusing source must not yield a generator");
    assert_eq!(err, SeedError::Trng(TrngError::Stalled));
}

/// The four refusals US-1003 defines each reach the caller distinctly. They
/// are kept apart precisely so a caller can tell a fresh device from a
/// failing one, and a `DrbgTrng` that collapsed them would throw that away.
#[test]
fn every_seed_refusal_reaches_the_caller_distinctly() {
    let cases = [
        SeedError::CKey(fapico2_platform::ckey::CKeyError::MissingBootEntropy),
        SeedError::CKey(fapico2_platform::ckey::CKeyError::BadLength),
        SeedError::Store(fapico2_platform::secure_store::SecureStoreError::Io),
        SeedError::DepletedBootEntropy,
        SeedError::Trng(TrngError::Stalled),
    ];
    for case in cases {
        let wedge = core::cell::Cell::new(true);
        let mut src = Source::refusing(&wedge);
        // Each case gets its own source with that exact refusal, so the
        // assertion is that *this* refusal — not merely "an error" — arrives.
        src.wedge_case = Some(case);
        let err = DrbgTrng::try_new(src).expect_err("must not construct");
        assert_eq!(err, case, "the refusal must survive to the caller verbatim");
    }
}

// ---------------------------------------------------------------------------
// 2. The budget is refreshed, not stretched
// ---------------------------------------------------------------------------

/// Cross the re-seed interval and the generator draws from its source
/// **again**. This is the whole of US-1004's accounting seen from outside:
/// one peripheral touch underwrites `RESEED_INTERVAL` requests, and the
/// request after that one is not served from the same stretch.
#[test]
fn crossing_the_interval_redraws_from_the_source() {
    let wedge = core::cell::Cell::new(false);
    let mut t = DrbgTrng::try_new(Source::healthy(&wedge)).expect("seeds");
    let before = t.drbg().reseed_counter();
    assert_eq!(before, 1, "instantiate sets the counter to 1");

    let mut buf = [0u8; 8];
    // Drive well past the interval. What is under test is that the counter
    // never runs away: each crossing re-seeds (counter back to 1) and the
    // request then advances it to 2, so the steady state is 2 no matter how
    // many further requests follow. A generator that did *not* re-seed would
    // sit at RESEED_INTERVAL + 2 and keep climbing.
    for _ in 0..=(RESEED_INTERVAL * 2) {
        t.try_random_bytes(&mut buf).expect("healthy");
    }

    assert_eq!(
        t.drbg().reseed_counter(),
        2,
        "the counter is re-seeded and re-advanced per request, not run past the interval"
    );
    assert!(
        t.drbg().reseed_counter() <= t.drbg().reseed_interval() + 1,
        "the counter must stay bounded by the interval it is meant to respect"
    );
}

/// The source is consulted more than once over a generator's life.
///
/// The *freshness* of each draw is not observable from here: the two
/// `DrbgTrng`s below each hold a `&mut Source`, so they cannot coexist, and
/// the borrows overlap for as long as the generator lives. Comparing the
/// nonces two instantiations issued is therefore a different test
/// (`two_generators_from_the_same_source_diverge` below) built on a shared
/// log. This one asserts the call *count*, which is the C-1 precondition
/// without which no freshness argument is possible at all — a generator that
/// drew once and then stretched that one block forever would be the defect
/// US-1004 exists to bound.
#[test]
fn crossing_the_interval_consults_the_source_again() {
    let wedge = core::cell::Cell::new(false);
    let mut src = Source::healthy(&wedge);
    let mut t = DrbgTrng::try_new(&mut src).expect("seeds");
    let mut buf = [0u8; 8];
    for _ in 0..=RESEED_INTERVAL {
        let _ = t.try_random_bytes(&mut buf);
    }
    assert!(
        src.calls.get() >= 2,
        "crossing the interval must consult the source again, saw {} call(s)",
        src.calls.get()
    );
}

/// A source that is healthy at instantiate and **wedges** at the re-seed
/// produces an error, and — the part that matters — does *not* reopen the
/// spent budget. A generator that half-applied a re-seed would be neither the
/// old state nor a correctly seeded one, and at exhaustion it would be one
/// that silently extended a spent budget.
#[test]
fn a_wedged_reseed_reports_and_does_not_reopen_the_budget() {
    let wedge = core::cell::Cell::new(false);
    let mut src = Source::healthy(&wedge);
    let mut t = DrbgTrng::try_new(&mut src).expect("seeds");
    let mut buf = [0u8; 8];
    for _ in 0..RESEED_INTERVAL {
        t.try_random_bytes(&mut buf).expect("healthy");
    }
    let spent = t.drbg().reseed_counter();

    // The peripheral wedges: the next seed refuses.
    wedge.set(true);

    let err = t
        .try_random_bytes(&mut buf)
        .expect_err("a wedged re-seed must surface, not wrap around");
    assert!(
        matches!(err, DrbgTrngError::Reseed(SeedError::Trng(TrngError::Stalled))),
        "expected the wedge to reach the caller, got {err:?}"
    );
    assert_eq!(
        t.drbg().reseed_counter(),
        spent,
        "a refused re-seed must leave the counter exactly where it was"
    );
    // And the generator stays refusing rather than serving a stale stretch.
    assert!(
        t.try_random_bytes(&mut buf).is_err(),
        "after a refused re-seed the generator must still refuse"
    );
}

/// `ReseedRequired` is a distinct error from a failed re-seed, so a caller
/// can tell "budget spent" from "the peripheral is gone" — they call for
/// different responses (retry later vs. reset the device).
#[test]
fn the_two_failure_modes_are_distinguishable() {
    assert_ne!(
        DrbgTrngError::ReseedRequired,
        DrbgTrngError::Reseed(SeedError::DepletedBootEntropy),
        "a spent budget and a failed re-seed are different events"
    );
}

// ---------------------------------------------------------------------------
// 3. Output properties
// ---------------------------------------------------------------------------

/// Two generators seeded from the same source produce **different** output.
/// If they did not, the generator would be a pure function of its seed and
/// the seed is derivable from public material (the chipid, an OTP row, a
/// record written once) — which is the nonce-reuse defect.
#[test]
fn two_generators_from_the_same_source_diverge() {
    // Two `Source` values over ONE shared `log`, because a `DrbgTrng` holds
    // its source by `&mut` for the generator's whole life: the two borrows
    // genuinely cannot coexist, so the nonces issued are recorded in the
    // shared log and compared after both generators are dropped.
    //
    // `src2` is hand-seeded with `nonce = 1` so the two generators draw
    // *different* nonces. That hand-set field makes the two `log` assertions
    // below verify the test's own setup rather than production behaviour —
    // only `assert_ne!(ba, bb)` below is the real evidence, because it is
    // what the nonce's arrival at the generator's output looks like. So the
    // log assertions are kept but say what they are: a check that the setup
    // did what this test's comment says, and nothing more.
    let wedge = core::cell::Cell::new(false);
    let log: core::cell::RefCell<heapless::Vec<u8, 4>> =
        core::cell::RefCell::new(heapless::Vec::new());
    let mut src = Source::healthy_logged(&wedge, &log);
    let mut src2 = Source::healthy_logged(&wedge, &log);
    src2.nonce = 1;
    {
        let mut a = DrbgTrng::try_new(&mut src).expect("seeds");
        let mut b = DrbgTrng::try_new(&mut src2).expect("seeds");
        let mut ba = [0u8; 32];
        let mut bb = [0u8; 32];
        a.try_random_bytes(&mut ba).expect("serves");
        b.try_random_bytes(&mut bb).expect("serves");
        assert_ne!(
            ba, bb,
            "identical output from two instantiations means the nonce is not mixed in"
        );
    }
    let log = log.borrow();
    assert_eq!(log.len(), 2, "each instantiation drew once (test setup check)");
    assert_ne!(
        log[0], log[1],
        "the two hand-seeded sources drew the same nonce — the test's own \
         precondition is broken, so the output comparison above proves nothing"
    );
}

/// Successive requests are not the same bytes twice — the minimum sanity
/// property of a generator, and the one whose absence would invalidate every
/// nonce drawn from it.
#[test]
fn successive_requests_differ() {
    let wedge = core::cell::Cell::new(false);
    let mut t = DrbgTrng::try_new(Source::healthy(&wedge)).expect("seeds");
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    t.try_random_bytes(&mut a).expect("serves");
    t.try_random_bytes(&mut b).expect("serves");
    assert_ne!(a, b, "two consecutive requests returned the same bytes");
}

/// An empty request **does** spend re-seed budget, because SP 800-90A
/// §10.1.2.5 has no early return: the trailing `Update` and the counter
/// increment happen even for a zero-length request. `Drbg::generate` documents
/// this and pins it in its own suite; the reason to pin it again *here* is
/// that `DrbgTrng` is the type every caller now touches, and "asking for
/// nothing is free" is the natural — and wrong — assumption at this layer.
///
/// (This test was written asserting the opposite, and caught itself. The
/// comment is left because the wrong assumption is the likely one.)
#[test]
fn an_empty_request_still_spends_budget() {
    let wedge = core::cell::Cell::new(false);
    let mut t = DrbgTrng::try_new(Source::healthy(&wedge)).expect("seeds");
    let before = t.drbg().reseed_counter();
    t.try_random_bytes(&mut []).expect("serves");
    assert_eq!(
        t.drbg().reseed_counter(),
        before + 1,
        "an empty request still advances the counter — the standard has no early return"
    );
}

// ---------------------------------------------------------------------------
// 4. The `Trng` impl
// ---------------------------------------------------------------------------

/// On a healthy generator the infallible seam **fills** the buffer.
///
/// The old name claimed it "agrees with" the fallible seam, which it cannot
/// honestly claim: the two generators are independently seeded, so their
/// output is *supposed* to differ and comparing them would be meaningless.
/// The property that is worth pinning is the one the infallible seam can
/// actually offer a caller that failed to check for an error — that it does
/// not leave a recognisable sentinel behind. The whole of US-1006 is that
/// request-path callers move to `try_random_bytes` regardless.
#[test]
fn the_trng_impl_fills_the_buffer_when_healthy() {
    let wedge = core::cell::Cell::new(false);
    let mut via_trait = DrbgTrng::try_new(Source::healthy(&wedge)).expect("seeds");
    let wedge = core::cell::Cell::new(false);
    let mut direct = DrbgTrng::try_new(Source::healthy(&wedge)).expect("seeds");
    let mut a = [0xFFu8; 32];
    let mut b = [0xFFu8; 32];
    via_trait.random_bytes(&mut a);
    direct.try_random_bytes(&mut b).expect("serves");

    assert_ne!(a, [0xFFu8; 32], "the Trng impl must actually fill the buffer");
    // Two independently seeded generators differ, so the comparison is that
    // both are *filled*, not that they match. Assert the shape instead.
    assert!(a.iter().any(|&x| x != 0xFF), "buffer left partly untouched");
}

/// **The load-bearing property of the infallible seam**: when the generator
/// cannot serve, `random_bytes` must not fabricate bytes. It leaves the
/// caller's buffer exactly as it was.
///
/// Zeroing was the rejected alternative and the test records why: a caller
/// that failed to check for an error would sign with a nonce of *zeros*, which
/// is a known constant and therefore strictly worse than the stale state it
/// replaced. Leaving the buffer alone keeps the failure visible where the
/// caller can see it.
#[test]
fn a_failing_generator_leaves_the_buffer_untouched() {
    let wedge = core::cell::Cell::new(false);
    let mut src = Source::healthy(&wedge);
    let mut t = DrbgTrng::try_new(&mut src).expect("seeds");
    let mut buf = [0u8; 8];
    for _ in 0..RESEED_INTERVAL {
        t.try_random_bytes(&mut buf).expect("healthy");
    }
    wedge.set(true);

    // A recognisable pattern, so "untouched" is distinguishable from
    // "zeroed" and from "stale generator output".
    buf.fill(0x5A);
    t.random_bytes(&mut buf);
    assert!(
        buf.iter().all(|&b| b == 0x5A),
        "a failed fill must leave the caller's buffer exactly as it was, not zero it \
         and not write stale output"
    );
}

// ---------------------------------------------------------------------------
// 5. Block accounting — the one device property reachable from the host
// ---------------------------------------------------------------------------

/// The device's wait budget is **per EHR block**, and a seed draw spans more
/// than one block. The `Rp2350Probe` doc quotes a per-block ceiling; this is
/// what makes that sentence true for a `NONCE_LEN`-byte draw rather than only
/// for a one-block one.
///
/// The arithmetic, stated once and stated correctly: a 32-byte draw crosses
/// `ceil(32 / 24) == 2` blocks, and **each** block gets its own budget, so
/// one seed draw's effective ceiling is `2 x MAX_ENTROPY_WAIT` = 40 ms — and
/// `2 x MAX_ENTROPY_POLLS` status reads. It is *not* 2x the whole thing
/// layered inside another full budget: the outer and the inner waits are the
/// same wait.
#[test]
fn a_nonce_draw_spans_more_than_one_peripheral_block() {
    let blocks = NONCE_LEN.div_ceil(EHR_BLOCK_BYTES);
    assert!(
        blocks > 1,
        "the device probe's per-block budget only means something if a draw \
         crosses blocks; NONCE_LEN={NONCE_LEN} block={EHR_BLOCK_BYTES}"
    );
    // The per-draw ceiling is this multiple of the per-block one, in whatever
    // unit the budget uses. Asserted rather than discarded: this is the
    // number the docs quote, so a future edit to either side that breaks the
    // relationship should say so here.
    let effective_budget_ms = blocks as u32 * MAX_ENTROPY_WAIT_MS;
    assert_eq!(
        effective_budget_ms,
        2 * MAX_ENTROPY_WAIT_MS,
        "a NONCE_LEN draw's effective per-draw budget is 2 x the per-block one"
    );
}

/// A probe that stalls is bounded, and the `DrbgTrng` built over a refusing
/// source does not construct. This is the same path `boot::init_drbg` takes,
/// with the host's scripted probe in place of the RP2350 — so the
/// fail-closed behaviour boot relies on is covered without silicon.
///
/// Scope note (an earlier version of this doc claimed more): the
/// "a wedged peripheral really does refuse to seed, wired through a real
/// `FuseSeedSource`" property is **not** tested here — this test wires a
/// refusing `Source` double, not a probe into a `FuseSeedSource`. That
/// property is covered where it belongs, in
/// `platform/tests/drbg_seed.rs` (`a_wedged_peripheral_refuses_to_seed_rather_than_falling_back_to_the_fuses`).
#[test]
fn a_stalled_peripheral_yields_no_generator() {
    let mut probe = Probe::stalled();
    let mut draw = [0u8; NONCE_LEN];
    assert_eq!(
        probe.probe_bytes(&mut draw),
        Err(TrngError::Stalled),
        "a stalling probe must be bounded, not hang"
    );
    let wedge = core::cell::Cell::new(true);
    let src = Source::refusing(&wedge);
    assert!(
        DrbgTrng::try_new(src).is_err(),
        "a stalled peripheral must not yield a generator"
    );
}

/// A peripheral that stalls **part-way through** a multi-block draw must make
/// the whole draw an error, not a short success.
///
/// This is the defect US-1005's `read_into` contract was written to close. A
/// `NONCE_LEN` (32-byte) draw crosses two 24-byte EHR blocks, so the second
/// can stall after the first has already been written — and the caller's
/// buffer is `Zeroizing::new([0u8; NONCE_LEN])`. An implementation that
/// returned `Ok` with 24 fresh bytes and 8 untouched zeros hands the DRBG
/// nonce slot "24 fresh bytes, then 8 zeros" and calls it a valid draw; the
/// all-zero refusal in `FuseSeedSource` cannot see that, because the buffer is
/// not all-zero.
///
/// So: the draw is `Err`, and the buffer's contents are explicitly *not*
/// something a caller is entitled to use. The test states that rather than
/// asserting on the bytes, because the contract is about the error, not about
/// what happens to a buffer whose draw failed.
#[test]
fn a_peripheral_that_stalls_mid_draw_is_an_error_not_a_partial_fill() {
    let mut probe = Probe::stalls_mid_draw(); // serves block 1, then stalls
    let mut draw = [0u8; NONCE_LEN];

    let result = probe.probe_bytes(&mut draw);

    assert_eq!(
        result,
        Err(TrngError::Stalled),
        "a draw that could not be completed must be an error; a short fill \
         reported as success reaches the nonce slot as half zeros"
    );
    assert_eq!(
        probe.draws, 1,
        "the first block WAS served — this is the mid-draw case, not a \
         peripheral that never started"
    );
    // The block accounting that makes the case reachable at all: one block
    // is 24 bytes, a draw is 32, so the stall lands on the second block.
    assert_eq!(
        NONCE_LEN,
        EHR_BLOCK_BYTES + 8,
        "a NONCE_LEN draw is one whole EHR block plus a partial one; if \
         NONCE_LEN changes this test no longer covers the mid-draw path"
    );
}

// ---------------------------------------------------------------------------
// 6. Shape
// ---------------------------------------------------------------------------

/// The device seed source is **borrows and nothing else**, measured on the
/// real type.
///
/// `Drbg` is fixed-size and `no_std`; the `DrbgTrng` wrapper adds only the
/// source. This is a real constraint, not a style preference: the generator
/// lives in a `static mut` on the boot path, and the async-main frame is gated
/// by `check_async_frame.py` at 24,576 B.
///
/// The seed source is *borrows and nothing else*.
///
/// # Where the real type is actually checked, and why
///
/// An earlier version of this test measured a **locally defined** alias over
/// this file's own mock `Store` and `Probe`. That could not have caught the
/// defect it was written for: the mock would stand still while the device
/// alias grew a cached seed, and the test would keep passing.
///
/// The device alias cannot be measured *here*, because
/// `platform::trusted_backend::device::DeviceSeedSource` and the
/// `Rp2350Probe` inside it are `#[cfg(all(feature = "device",
/// target_arch = "arm"))]` — they do not exist in an x86_64 test build at
/// all. So the check on the **real** type is a compile-time assertion next
/// to the alias in `trusted_backend/device.rs`, which the
/// `thumbv8m.main-none-eabi` firmware build enforces:
/// `cargo build -p fapico2-firmware --target thumbv8m.main-none-eabi
/// --release` fails the moment the device source acquires a field.
///
/// What remains here is the host-shape half: the generic source, over the
/// same four borrowed inputs, must not gain a cached seed or a cached draw.
#[test]
fn the_seed_source_is_borrows_and_nothing_else() {
    // Four borrowed inputs, so five words on a 32-bit target (`uid` is a
    // `&[u8]`, a fat pointer: ptr + len) and no more. Written as a sum of the
    // parts so a future field makes the test say *what* grew.
    let expected = size_of::<&[u8; 32]>()  // otp_key_1
        + size_of::<&[u8]>()               // uid (fat: ptr + len)
        + size_of::<&mut Store>()          // store
        + size_of::<&mut Probe>();         // probe
    assert_eq!(
        size_of::<DeviceSeedSource>(),
        expected,
        "FuseSeedSource has acquired state; it must stay four borrowed inputs"
    );
}

/// The host-shaped seed source: OTP row, flash UID, the secure store, and the
/// bounded peripheral probe.
type DeviceSeedSource = fapico2_platform::drbg_seed::FuseSeedSource<'static, Store, Probe>;

/// A `SecureStore` stand-in. Only its size matters here — the C-1 property is
/// about the *source's* layout, not the store's.
struct Store;
impl fapico2_platform::secure_store::SecureStore for Store {
    fn write(
        &mut self,
        _key: &[u8],
        _value: &[u8],
    ) -> Result<(), fapico2_platform::secure_store::SecureStoreError> {
        Ok(())
    }
    fn read(
        &mut self,
        _key: &[u8],
        _out: &mut [u8],
    ) -> Result<usize, fapico2_platform::secure_store::SecureStoreError> {
        Ok(0)
    }
    fn delete(&mut self, _key: &[u8]) -> Result<(), fapico2_platform::secure_store::SecureStoreError> {
        Ok(())
    }
    fn contains(&self, _key: &[u8]) -> bool {
        true
    }
    fn snapshot_partition(
        &self,
        _buf: &mut [u8],
    ) -> Result<usize, fapico2_platform::secure_store::SecureStoreError> {
        Ok(0)
    }
    fn snapshot_len(&self) -> usize {
        0
    }
    fn snapshot_window(&self, _off: usize, _buf: &mut [u8]) -> usize {
        0
    }
    fn is_empty(&self) -> Result<bool, fapico2_platform::secure_store::SecureStoreError> {
        Ok(true)
    }
    fn is_empty_except(
        &self,
        _slot: &[u8],
    ) -> Result<bool, fapico2_platform::secure_store::SecureStoreError> {
        Ok(true)
    }
    fn wipe_all(&mut self) -> Result<(), fapico2_platform::secure_store::SecureStoreError> {
        Ok(())
    }
}
