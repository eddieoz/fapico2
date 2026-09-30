//! Sole source of *entropy* for fapico2 (US-380), amended by US-1002.
//!
//! The EPIC requires that all entropy on the device come from the RP2350
//! hardware TRNG and that no software PRNG ever be the source. This module
//! exposes that requirement as a [`Trng`] trait:
//!
//! * **Device (RP2350)** — [`rp2350::Rp2350Trng`] wraps the `embassy-rp` TRNG
//!   peripheral (the ring-oscillator entropy source, with the CRNGT /
//!   autocorrelation / Von-Neumann post-processing left enabled).
//! * **Host (emulation / tests)** — [`HostTrng`] reads OS entropy. A host has
//!   no hardware TRNG, so the OS CSPRNG is the correct stand-in; this is *not*
//!   a software PRNG.
//!
//! App crates obtain randomness through the free functions
//! [`random_bytes`] / [`random_bytes_into`] (host) rather than reaching for a
//! `rand` RNG directly, so the "single source" boundary is enforced at the
//! platform layer.
//!
//! # Deterministic generation is not a second source (US-1002)
//!
//! US-1002 adds `platform::drbg`, an HMAC-DRBG seeded from this peripheral.
//! That does **not** relax the rule above, and the distinction is the whole
//! point:
//!
//! * A **DRBG is deterministic.** Its output is a function of a seed. It has
//!   no entropy of its own, contributes nothing to the device's entropy
//!   budget, and a fresh one with no seed produces nothing at all — it fails
//!   closed, it does not fall back.
//! * A **TRNG draw is the only thing that adds entropy.** Every byte the
//!   device ever invents originates here.
//!
//! So the arrangement is: entropy enters through [`Trng`], and a DRBG
//! stretches a full-entropy block from it into as much pseudorandom output as
//! a single safe draw can justify. The practical motive is that hardware
//! draws are the scarce, failure-prone resource — a wedged health test is a
//! hard failure, so the fewer operations touch the peripheral, the better.
//!
//! **Routing landed in US-1005 and US-1006.** This paragraph used to end on
//! "nothing routes to a DRBG yet", which was a leftover from before the KATs
//! went green and is false at this tip. On device the firmware builds exactly
//! one generator, in `firmware/src/boot.rs::init_drbg`, and serves the FIDO
//! boot keystore material, both boot RNG pools (FIDO's and OATH's) and the
//! trussed `Rng` backend from it — see [`DrbgTrng`].
//!
//! # Waiting for the peripheral is a separate, bounded decision (US-1001)
//!
//! Getting bytes out of the TRNG is not the same as *waiting* for bytes, and
//! the wait is where the hardware fails. `embassy-rp`'s
//! `blocking_wait_for_successful_generation` is an unbounded busy-wait that
//! retries forever on an autocorrelation failure — a failure the RP2350
//! documentation says never clears on its own. [`TrngProbe::probe_bytes`] is
//! the same wait decision with a ceiling, and the ceiling is a **wall-clock
//! budget** ([`MAX_ENTROPY_WAIT`]), not a count of status reads. There are
//! three named bounds and each is named for the failure it catches:
//!
//! * [`CLOCK_LIVENESS_SPINS`] — the clock is moving at all. The budget is
//!   *conditional* on this, and the wait checks it at the point of use
//!   (D-12), because a budget measured against a stopped counter is not a
//!   loose budget — it is no budget;
//! * [`MAX_ENTROPY_WAIT`] — the meaningful deadline;
//! * [`MAX_ENTROPY_POLLS`] — the last-resort cap behind both.
//!
//! Any one of them terminating is an error rather than a hang, and the
//! clock's is a **different** error, because "the deadline was never
//! measured" and "the peripheral missed the deadline" are different facts
//! and a caller that cannot tell them apart learns nothing from either.
//!
//! # US-1005: every nonce comes from here
//!
//! [`DrbgTrng`] is what the firmware constructs. It is the *only* type a
//! caller outside this module should ask for randomness from, and
//! `tests/scripts/check_rng_path.py` is what keeps it that way — the gate
//! fails on any `blocking_fill_bytes` / `EmbTrng::new` outside this file and
//! the three allowlisted bootstrap sites.
//!
//! Two properties are the reason the gate exists rather than a comment:
//!
//! * **The DRBG is not a second entropy source.** It stretches one validated
//!   peripheral block; the TRNG remains the only thing that adds entropy (see
//!   the section above).
//! * **It fails closed.** A [`DrbgTrng`] that cannot seed is not a
//!   `DrbgTrng` — [`DrbgTrng::try_new`] returns a `Result`, and there is no
//!   constructor that produces a generator without a seed. A generator whose
//!   re-seed budget is spent refuses to generate rather than stretching a
//!   stale state; the error reaches the caller instead of being swallowed.

use core::fmt;

use crate::drbg::{Drbg, DrbgError, SeedError, SeedSource};

/// The size of one validated EHR block: 192 bits (RP2350 datasheet
/// §12.12.1). The peripheral's post-processing delivers 24 bytes at a time, so
/// a 32-byte `NONCE_LEN` draw is **two** blocks — which is why the wait
/// budget below is per-block and not per-request.
///
/// Public and arm-independent so the host tests can state the block accounting
/// (a `NONCE_LEN` draw crossing more than one block) without a board.
pub const EHR_BLOCK_BYTES: usize = 24;

/// Errors a TRNG implementation can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrngError {
    /// The underlying entropy source failed (host-only: `/dev/urandom` unreadable).
    Entropy,
    /// The peripheral never produced a validated block within the wait
    /// budget ([`MAX_ENTROPY_WAIT`]) or the hard poll cap
    /// ([`MAX_ENTROPY_POLLS`]), whichever expired first.
    Stalled,
    /// The wait's own wall clock **did not move at all** while the wait ran.
    ///
    /// # Why this is a separate code, not a flavour of `Stalled`
    ///
    /// [`Stalled`](TrngError::Stalled) says "the peripheral did not produce
    /// in time", which implies the clock was counting and the deadline was
    /// reached. The failure this code names is a *precondition* failure: the
    /// instrument is not measuring, so the deadline was never in play and the
    /// number of polls that went by says nothing whatever about the peripheral.
    ///
    /// It matters because a probe that cannot tell the two apart degrades
    /// silently. A wait budget measured against a clock that is stopped
    /// degenerates into a pure poll count, and the two are then
    /// indistinguishable at the call site: both arrive as one opaque `Err`,
    /// both are fatal at boot, and nothing records that the *timing* was
    /// never the thing in question. Collapsing them is what let the 2026-09-29
    /// dark boot look like an entropy-source problem. See
    /// `docs/known-gate-divergences.md` (D-12).
    ClockStalled,
}

impl fmt::Display for TrngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrngError::Entropy => write!(f, "TRNG entropy source failure"),
            TrngError::Stalled => write!(f, "TRNG stalled: no validated block within the wait budget"),
            TrngError::ClockStalled => write!(
                f,
                "TRNG wait clock stalled: the wall clock did not advance during the \
                 wait, so the time budget was never in play"
            ),
        }
    }
}

/// A monotonic tick source the entropy wait budget is measured against.
///
/// # Why this is a trait
///
/// A budget in *polls* is not a budget in *time*: a poll that finds the
/// peripheral `Busy` costs a poll and a handful of nanoseconds, so 64 of them
/// is about four microseconds — two to three orders of magnitude less than the
/// ~2 ms the RP2350 datasheet quotes for one healthy generation. On good
/// silicon that ceiling returns `Stalled` and, because `init_drbg` treats a
/// seed refusal as fatal, the unit does not boot. That is strictly worse than
/// the hang it replaced, and it is the reason the budget below is expressed in
/// a unit that means the same thing regardless of how fast the loop body runs.
///
/// Injecting the clock also keeps the budget honest *here*: the host tests
/// drive a fake clock and assert the deadline is honoured, which is the only
/// way to catch the error in the direction that matters — a budget set too
/// tight for a healthy peripheral.
pub trait EntropyClock {
    /// A monotonically increasing tick count since an arbitrary fixed origin.
    ///
    /// Only *differences* are meaningful, and the implementation must be
    /// monotonic across the whole run. Wraparound is handled by the caller
    /// (`wrapping_sub`), so a free-running counter is fine.
    fn ticks(&self) -> u64;
}

/// Wall-clock ceiling on **one** wait for a validated EHR block, in
/// milliseconds.
///
/// # Where the number comes from
///
/// `embassy-rp`'s own `Config` documentation quotes RP2350 §12.12.2 verbatim
/// (`embassy-rp-0.10.0/src/trng.rs:78-83`):
///
/// > For acceptable results with an average generation time of about 2
/// > milliseconds, use ROSC chain length settings of 0 or 1 and sample count
/// > settings of 20-25.
///
/// `Config::default()` is exactly that configuration (sample count 25, all
/// three health tests enabled), so **2 ms is the datasheet's average
/// generation time for the config this probe is calibrated against.** The same
/// passage is also the reason for the safety factor:
///
/// > Results occasionally take an especially long time to generate.
///
/// So 2 ms is an *average*, and the datasheet itself warns about the tail. A
/// budget set at the average would refuse roughly half of all healthy draws,
/// which on this device means a boot brick. **20 ms is a 10x safety factor**
/// on that average — generous enough to absorb the tail the datasheet
/// describes, and still bounded.
///
/// # Not measured on silicon
///
/// **No RP2350 board was attached when this value was chosen.** It is derived
/// from a datasheet *average*, not from a measured *maximum*. A silicon part
/// slower than 10x the datasheet average would return
/// [`TrngError::Stalled`] and refuse to seed — and because `init_drbg` is
/// fatal by design, that is a refusal to boot. That is the correct
/// fail-closed direction (a bounded, reportable refusal beats an unbounded
/// hang, and beats a generator fed a constant), but the operator should know
/// it is possible. Recorded as a standing divergence in
/// `docs/known-gate-divergences.md` (D-8) and re-check by US-1007 on
/// hardware.
///
/// # What this value assumes, and who checks it
///
/// It is a **wall-clock** budget, so it is only 20 ms of anything at all if
/// the clock behind it is counting. That used to be an assumption, and a
/// recent one: on 2026-09-29 a device came up dark on a wait whose clock
/// nobody had verified, the budget was therefore unreachable, and the wait
/// reported a peripheral stall for a deadline that had never been measured.
/// It is not an assumption any more — [`TrngProbe::await_ready`] checks the
/// clock at the point of use and returns [`TrngError::ClockStalled`] if it is
/// not moving (see [`CLOCK_LIVENESS_SPINS`] and D-12) — but the *size* of
/// this number remains reasoned, not measured, and that part no host test
/// can reach.
pub const MAX_ENTROPY_WAIT_MS: u32 = 20;

// ---------------------------------------------------------------------------
// The configuration a TRNG soft reset destroys (US-1005 fix).
// ---------------------------------------------------------------------------

/// The two configuration registers `TRNG_SW_RESET` returns to their power-on
/// values — `TRNG_CONFIG.rnd_src_sel` and `SAMPLE_CNT1` — and which a probe
/// therefore has to re-apply every time it re-arms after an
/// autocorrelation error.
///
/// # Why this type exists outside the `device` block
///
/// The registers are on the chip and the *write* is device-only, but the
/// thing worth testing is not the write — it is **which pair of values the
/// budget is calibrated against, and that they are not the reset defaults.**
/// That is a data question with a device-free answer, so the data lives here
/// and the host suite can reach it. `check_rng_path.py` is name-based and
/// cannot see a missing register write inside a device-only module.
///
/// # The numbers, and where they come from
///
/// `embassy-rp-0.10.0/src/trng.rs:110-121`, `Config::default()`:
/// `inverter_chain_length: InverterChainLength::One` (the enum's
/// `One = 1`, `trng.rs:45-51`) and `sample_count: 25`. Both are the values
/// the datasheet's own guidance names — §12.12.2, quoted verbatim in
/// `embassy-rp`'s `Config` docs, asks for "ROSC chain length settings of 0 or
/// 1 and sample count settings of 20-25" to get "an average generation time
/// of about 2 milliseconds", which is the 2 ms [`MAX_ENTROPY_WAIT_MS`] is
/// sized as 10x.
///
/// # The void condition, and why a silent mismatch is expensive
///
/// The budget is only valid *for this configuration*. After a soft reset the
/// power-on defaults are in force instead, and the datasheet's own ordering —
/// "As average generation time increases, result quality increases" — runs
/// the wrong way for a **deadline**: a slower generator needs a *longer*
/// budget than the one calibrated for the faster, correctly-configured part.
/// A probe that re-arms without restoring spends the rest of its life on a
/// deadline that was measured for a different peripheral, and the failure it
/// produces is [`TrngError::Stalled`] on a **healthy** TRNG — which, because
/// `init_drbg` is fatal, is a device that does not boot. That is the same
/// class of void as D-8's assumption (1), reached by a second route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrngConfig {
    /// `TRNG_CONFIG.rnd_src_sel` — the ROSC inverter chain length.
    pub rnd_src_sel: u8,
    /// `SAMPLE_CNT1` — the sample period in system clock ticks.
    pub sample_cnt1: u8,
}

impl Default for TrngConfig {
    /// Exactly `embassy_rp::trng::Config::default()`, which is the
    /// configuration `Rp2350Trng::from_peri` is built with on the boot path
    /// and therefore the one [`MAX_ENTROPY_WAIT_MS`] is calibrated against.
    fn default() -> Self {
        Self {
            rnd_src_sel: 1,  // InverterChainLength::One
            sample_cnt1: 25,
        }
    }
}

impl TrngConfig {
    /// Capture the configuration out of the two raw register words, as read
    /// back from the peripheral. Only `rnd_src_sel` is taken from
    /// `trng_config`; the rest of that word is left alone by the write
    /// path, so widening this to the whole word would discard bits this
    /// module has no business touching.
    pub const fn capture(trng_config: u32, sample_cnt1: u8) -> Self {
        Self {
            rnd_src_sel: (trng_config & 0x3) as u8,
            sample_cnt1,
        }
    }

    /// Whether this configuration is the one the budget assumes.
    ///
    /// Not enforced at runtime today — nothing on the boot path has a
    /// non-nominal configuration to catch, and inventing a refusal for a
    /// state the device cannot currently reach would be a gate against a
    /// bug nobody has. It exists so the property is *named* and testable:
    /// [`tests::a_reset_default_configuration_is_not_the_budgeted_one`]
    /// pins that the power-on values fail it, which is the whole point of
    /// restoring at all.
    pub const fn is_budget_nominal(&self) -> bool {
        // Datasheet-valid generation configurations: chain 0 or 1 (which
        // cannot be made faster by this register), sample count 20-25.
        self.rnd_src_sel <= 1 && self.sample_cnt1 >= 20 && self.sample_cnt1 <= 25
    }
}

#[cfg(test)]
mod tests {
    use super::{TrngConfig, MAX_ENTROPY_WAIT_MS};

    /// The restore is only meaningful because the values it restores are
    /// **not** what a soft reset leaves behind. If a future driver changed
    /// its power-on defaults to the budgeted configuration this test would
    /// start failing for a good reason, and the `soft_reset` write could
    /// then be re-argued rather than simply assumed.
    #[test]
    fn a_reset_default_configuration_is_not_the_budgeted_one() {
        // TRNG_CONFIG power-on default: rnd_src_sel 0. SAMPLE_CNT1 power-on
        // default: 0 (sample every cycle — not a 20-25 sample period).
        let reset_defaults = TrngConfig::capture(0x0000_0000, 0);
        assert!(!reset_defaults.is_budget_nominal());
        assert!(TrngConfig::default().is_budget_nominal());
    }

    /// The restored pair is the driver's documented default, and it survives
    /// a capture round trip through the register words.
    #[test]
    fn capture_round_trips_the_budgeted_configuration() {
        let budgeted = TrngConfig::default();
        // `rnd_src_sel` is bits 1:0 of TRNG_CONFIG; a word with other bits
        // set must not leak them into the captured value.
        let captured = TrngConfig::capture(0xFFFF_FFF9, 25);
        assert_eq!(captured, budgeted);
        assert_eq!(captured.rnd_src_sel, 1);
        assert_eq!(captured.sample_cnt1, 25);
    }

    /// A sample count above the datasheet's recommended band is rejected by
    /// the same predicate — the band is two-sided, not a floor.
    #[test]
    fn a_configuration_outside_the_datasheet_band_is_not_nominal() {
        assert!(!TrngConfig { rnd_src_sel: 1, sample_cnt1: 19 }.is_budget_nominal());
        assert!(!TrngConfig { rnd_src_sel: 1, sample_cnt1: 26 }.is_budget_nominal());
        assert!(!TrngConfig { rnd_src_sel: 2, sample_cnt1: 25 }.is_budget_nominal());
        assert!(TrngConfig { rnd_src_sel: 0, sample_cnt1: 20 }.is_budget_nominal());
    }

    /// The budget is a multiple of the 2 ms average this configuration
    /// produces, and it is not small enough to be the datasheet average
    /// itself — the arithmetic D-8 rests on, pinned so a later edit to
    /// `MAX_ENTROPY_WAIT_MS` cannot quietly make it true.
    #[test]
    fn the_budget_is_the_documented_multiple_of_the_datasheet_average() {
        const DATASHEET_AVERAGE_MS: u32 = 2;
        assert_eq!(MAX_ENTROPY_WAIT_MS, 10 * DATASHEET_AVERAGE_MS);
    }
}

/// Ticks per millisecond [`MAX_ENTROPY_WAIT_MS`] is expressed in.
///
/// The device clock ([`rp2350::Rp2350Timer`]) reads the RP2350 hardware
/// `TIMER`, which runs from `clk_ref`. This is the **1 MHz** convention — the
/// same one `embassy-time` already assumes for every `Duration` this firmware
/// writes, because `embassy-rp`'s time driver returns the raw timer reading
/// and treats it as microseconds. The budget deliberately inherits that
/// assumption rather than inventing a second one: if it is wrong, the
/// firmware's existing timeouts are already wrong by the same factor.
pub const ENTROPY_CLOCK_TICKS_PER_MS: u64 = 1_000;

/// The entropy wait budget, in [`EntropyClock`] ticks: the deadline
/// [`TrngProbe::await_ready`] enforces.
pub const MAX_ENTROPY_WAIT: u64 = MAX_ENTROPY_WAIT_MS as u64 * ENTROPY_CLOCK_TICKS_PER_MS;

/// Consecutive status reads the wall clock is given to demonstrate that it is
/// actually counting, before [`TrngProbe::await_ready`] gives up on it.
///
/// # What this bound is for
///
/// Every other bound in this module assumes the clock works. When it does
/// not, [`MAX_ENTROPY_WAIT`] is unreachable, the wait silently degenerates
/// into a poll count, and the degeneration is invisible: the same opaque
/// `Stalled` arrives whether the peripheral was slow or the clock was dead.
/// So the clock is checked, here, at the point of use — and a clock that has
/// not moved after this many consecutive reads is reported as
/// [`TrngError::ClockStalled`] instead of being allowed to run the wait out
/// to [`MAX_ENTROPY_POLLS`] and report a [`TrngError::Stalled`] that means
/// nothing.
///
/// # Why 256, and why this cannot be a false positive here
///
/// The threshold is a **window in time**, expressed in loop iterations so it
/// needs no working clock to measure itself. At the device's loop cost
/// (see [`MAX_ENTROPY_POLLS`] for the derivation, **1–2 us per iteration**,
/// reasoned and not measured) 256 reads is a **256–512 us** window. The
/// device clock is the RP2350 `TIMER0` tick generator, which embassy-rp
/// configures to **1 MHz** — so a live clock ticks **256–512 times** inside
/// that window, a margin of more than two orders of magnitude.
///
/// A false positive therefore needs a clock ticking slower than ~2 kHz, and
/// the same 2 kHz figure is what would make [`ENTROPY_CLOCK_TICKS_PER_MS`]
/// wrong by a factor of ~500 — at which point the 20 ms budget *is not 20 ms*
/// and every other deadline in this firmware is already wrong by the same
/// factor. There is no clock slow enough to trip this bound for which the
/// remaining arithmetic is still meaningful, so the check cannot cost a
/// healthy draw.
///
/// The cost when it does fire is bounded and small: ~0.5 ms of spinning
/// against ~0.5–1 s for the fallback it short-circuits (D-12).
///
/// # The device path checks the same thing twice, on purpose
///
/// [`Rp2350Timer::require_advancing`](rp2350::Rp2350Timer::require_advancing)
/// runs this check once at boot and hands the result to
/// [`Rp2350Probe::new`](rp2350::Rp2350Probe::new), which *cannot* be
/// constructed without it — that is the compile-time half. This constant is
/// the runtime half, and it lives in the default `await_ready` body so that
/// **no** implementation of [`TrngProbe`], device or host, can reach the
/// budget without passing through it. The device check catches "the clock was
/// never started"; this one catches "the clock stopped", which no
/// construction-time check can see.
pub const CLOCK_LIVENESS_SPINS: u32 = 256;

/// Hard cap on status reads in one wait, **independent of the clock**.
///
/// # What it is for, after the liveness check
///
/// Before [`CLOCK_LIVENESS_SPINS`] existed, this cap was the only thing
/// standing between a dead clock and an infinite loop, and it was sized for
/// that job by arithmetic nobody had checked. It is now the *third* bound,
/// behind the liveness check, and its job is narrower: to stop a clock that
/// **is** counting but so slowly that 20 ms of its ticks would take an
/// unreasonable number of spins. A clock that never moves no longer reaches
/// this constant at all — it is refused at the liveness bound — which is
/// what makes the cap's reachability something that has to be argued rather
/// than assumed, and what makes the derivation below worth writing out.
///
/// # The per-iteration cost, corrected
///
/// **The cost figure this constant was originally justified with was wrong
/// by about an order of magnitude**, and it mattered, because the argument
/// was "the cap is never the binding constraint". The first version of this
/// comment said "2^18 reads at a few tens of nanoseconds each is tens of
/// milliseconds of pure spinning". That counted only the status read. The
/// loop body also calls `self.clock().ticks()` on **every** iteration, and
/// on device that is [`rp2350::Rp2350Timer::ticks`] — a three-register
/// *stable* read of `TIMER0` (high, low, high-again, retry on mismatch), not
/// one load. Three APB peripheral accesses plus a compare and a branch is a
/// few hundred cycles at the **150 MHz** `clk_sys` this firmware boots with
/// (`embassy_rp::init(Default::default())` → `ClockConfig::crystal(12e6)` →
/// PLL sys 12 × 125 / 5 / 2), i.e. **order 1–2 µs per iteration**, not tens
/// of nanoseconds. (The same comment previously said 133 MHz, which is not
/// the clock this firmware configures.)
///
/// # The derivation
///
/// The cap must clear two ceilings, in this order, and the smaller of the two
/// multiples is what sizes it:
///
/// 1. **It must never pre-empt the wall-clock budget.** The wait ticks the
///    clock at least once per iteration, so the budget's worst-case
///    iteration count is `MAX_ENTROPY_WAIT` (20,000) ticks at the *cheapest*
///    plausible loop body (~0.5 µs) and 10,000 at the dearest (~2 µs). A cap
///    below 20,000 would end a wait at the cap on a healthy peripheral, which
///    is the `MAX_ENTROPY_POLLS = 64` defect this module was grown to remove
///    and a boot brick, because a seed refusal is fatal.
/// 2. **It must clear one healthy generation many times over.** ~2 ms
///    (RP2350 §12.12.2, quoted in `embassy-rp`'s own `Config` docs, and the
///    configuration `Config::default()` actually is: sample count 25, chain
///    length 1) is ~1,000–4,000 iterations of this loop.
///
/// `2^19 = 524,288` clears both:
///
/// | against | ratio |
/// |---|---|
/// | the budget's worst-case iteration count (20,000) | **26x** |
/// | one healthy generation (~1,000–4,000) | **130–520x** |
/// | the liveness bound (256) | **2,048x** |
///
/// It was raised from `2^18` (262,144) for this defect fix. At 2^18 the
/// multiple over the budget was only 13x, which is thin for a bound whose
/// per-iteration cost is itself uncertain by a factor of four — and the
/// whole complaint against the old value was that it was too small to serve
/// as the safety net it claimed to be.
///
/// # What it costs, honestly
///
/// `2^19 x 1–2 µs` is **0.5–1.0 s** of spinning. That is the price of a bound
/// that is not a timer, and it is only paid in the case where the clock is
/// alive and slower than one tick per 26 iterations — a condition under
/// which [`ENTROPY_CLOCK_TICKS_PER_MS`] is already wrong by more than an
/// order of magnitude and the 20 ms budget is not 20 ms.
///
/// # The ordering a future edit must preserve
///
/// ```text
/// CLOCK_LIVENESS_SPINS (256)
///   < budget's iteration count (MAX_ENTROPY_WAIT = 20,000)
///     < MAX_ENTROPY_POLLS (2^19)
///       >> one healthy generation (~10^3)
/// ```
///
/// Only the budget and the healthy generation are policy; the other two
/// follow. `platform/tests/trng_clock_precondition.rs` pins all of it, and
/// pins the *reachability* of the cap from both sides — a dead clock lands on
/// the liveness bound, a slow-but-live clock lands on the cap, a normal
/// clock lands on the budget — so this constant cannot quietly become
/// unreachable decoration.
///
/// # Reasoned, not measured
///
/// The ~1–2 µs per iteration is a cycle-count argument over APB register
/// accesses, not a measurement, and no RP2350 board was attached when it was
/// derived. It is an order-of-magnitude correction to a demonstrably wrong
/// figure, not a substitute for one. Same standing caveat as
/// [`MAX_ENTROPY_WAIT_MS`] above; recorded in
/// `docs/known-gate-divergences.md` (D-8, extended by D-12).
pub const MAX_ENTROPY_POLLS: u32 = 1 << 19;


/// Outcome of one TRNG generation attempt, as seen by the wait loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// A validated entropy-health-test-passed block is available to read.
    Ready,
    /// The peripheral is still working on the current block.
    Busy,
    /// The autocorrelation health test failed. `embassy-rp` soft-resets and
    /// retries; the RP2350 documentation says the RNG stays dead until the
    /// next reset, so a retry is not guaranteed to converge.
    AutocorrErr,
    /// The peripheral is idle, the EHR is invalid, and no specific error bit
    /// is set. `embassy-rp` `panic!()`s here.
    InvalidEhr,
}

/// The minimal thing the bounded entropy wait needs from a TRNG peripheral:
/// report the current generation outcome, hand over the bytes once generation
/// has succeeded, and supply the clock the wait budget is measured against.
///
/// This exists to make the *wait decision* host-testable. `embassy-rp`'s
/// public TRNG API exposes only `fill_bytes` / `blocking_fill_bytes` /
/// `blocking_next_u32` / `blocking_next_u64` — the health-test status bits
/// that drive the wedge are not observable through it — so on device the
/// bound cannot be applied to the driver directly. US-1005 decided what to do
/// about that: the device bound is applied through `rp-pac`, in
/// [`rp2350::Rp2350Probe`], and the health-test status bits **are** reachable
/// there. This trait is the seam both halves meet on, and the host tests below
/// are where the budget arithmetic is actually enforced.
pub trait TrngProbe {
    /// Report the current generation outcome.
    ///
    /// An implementation that mirrors `embassy-rp` should soft-reset and
    /// re-initialise the peripheral here, after reporting
    /// [`ProbeStatus::AutocorrErr`]: the wait loop between polls is where a
    /// retry happens, and there is nowhere else in the seam to put it.
    fn status(&mut self) -> ProbeStatus;

    /// Copy the freshly validated entropy into `buf`.
    ///
    /// # Contract
    ///
    /// **Either every byte of `buf` is written, or `Err` is returned and the
    /// contents of `buf` mean nothing.** There is no third outcome. A
    /// peripheral that produces one block and then stalls part-way through a
    /// longer request must return `Err`, not return `Ok` with a short fill: a
    /// caller that hands this straight to a nonce slot cannot tell "24 fresh
    /// bytes then 8 zeros" from "8 fresh bytes then 24 zeros", and a
    /// `Zeroizing::new([0u8; N])` buffer makes the second half look like a
    /// successful draw of half zeros.
    ///
    /// Only called after [`ProbeStatus::Ready`].
    ///
    /// # The default body is the whole draw
    ///
    /// It is [`draw_blocks`], which is the **only** implementation of the
    /// start/wait/read ordering in this crate — device and host alike. The
    /// register-level primitives it sequences are the three methods above it,
    /// and an implementation supplies only those. An implementation that
    /// *overrides* this method owns the ordering outright and is its own
    /// thing to test; the host fakes in the `platform/tests/` tree do exactly
    /// that, which is why the tests that pin the ordering
    /// (`trng_source_order.rs`) use a fake that does not.
    fn read_into(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        draw_blocks(self, buf)
    }

    /// Power the entropy source on.
    ///
    /// # This is not optional, and "why" is the 2026-09-29 dark boot
    ///
    /// The RP2350's ring oscillators are powered by `RND_SRC_EN`. With it
    /// clear, the counters do not run: `TRNG_BUSY` never asserts and
    /// `EHR_VALID` never sets, so a status read reports the peripheral idle
    /// with no error bit set — [`ProbeStatus::InvalidEhr`], forever. A probe
    /// that polls for a validated block before anything has enabled the
    /// source is therefore waiting for a block that **cannot** arrive, and it
    /// returns [`TrngError::Stalled`] for a peripheral that is not broken: it
    /// is switched off. `boot::init_drbg` treats a refused seed as fatal, so
    /// that is a device that does not boot, before USB ever enumerates.
    ///
    /// Required rather than defaulted, for the same reason
    /// [`Rp2350Probe::new`](rp2350::Rp2350Probe::new) demands a
    /// [`ClockReady`](rp2350::ClockReady): an implementation that has to say
    /// what enabling means cannot silently get it wrong by omission, and
    /// there is no "no-op" answer that is correct for a peripheral whose
    /// entropy source is gated by a register.
    fn source_enable(&mut self);

    /// Power the source off, and clear the collected-bit counter.
    ///
    /// Called on **every** exit from [`draw_blocks`], success and refusal
    /// alike: a peripheral left running after a failed draw is a peripheral
    /// left powered, and the next draw would inherit its state rather than
    /// starting clean. Idempotent by construction — it writes two fixed
    /// values rather than toggling — so the unconditional call on the way out
    /// cannot itself be the thing that goes wrong.
    fn source_disable(&mut self);

    /// Copy **one** validated block into `block`.
    ///
    /// `block.len()` is at most [`EHR_BLOCK_BYTES`]. Called only after
    /// [`await_ready`](TrngProbe::await_ready) has returned `Ok`, so the
    /// peripheral is holding a block the health tests passed.
    ///
    /// Reading the last EHR register is what clears the valid bit, so an
    /// implementation must read it on every call — including for a short
    /// final block, or the next draw would be served a stale one.
    fn read_block(&mut self, block: &mut [u8]);

    /// The clock [`await_ready`](TrngProbe::await_ready) measures its
    /// deadline against. An implementation whose peripheral has no readable
    /// clock returns a counter that never advances — which
    /// [`await_ready`](TrngProbe::await_ready) now refuses on, naming the
    /// clock, rather than quietly falling through to a poll count.
    fn clock(&mut self) -> &mut dyn EntropyClock;

    /// The one bounded wait: return once the peripheral reports
    /// [`ProbeStatus::Ready`], or an error when a bound expires.
    ///
    /// Terminates on **whichever comes first**:
    ///
    /// * [`CLOCK_LIVENESS_SPINS`] consecutive status reads across which the
    ///   [`EntropyClock`] has not moved at all — a **precondition** failure,
    ///   [`TrngError::ClockStalled`], reported before the other two bounds get
    ///   a chance to produce a number that means nothing;
    /// * [`MAX_ENTROPY_WAIT`] ticks on this probe's [`EntropyClock`] — the
    ///   budget, and the one that is meaningful, [`TrngError::Stalled`];
    /// * [`MAX_ENTROPY_POLLS`] status reads — the last-resort cap,
    ///   [`TrngError::Stalled`].
    ///
    /// The two are named separately on purpose. Collapsing them into one
    /// "number of tries" is how a poll-count ceiling ends up two orders of
    /// magnitude below one healthy generation.
    ///
    /// # Why the clock check is in here and not at the call sites
    ///
    /// Because a call site is exactly what goes wrong. The 2026-09-29 dark
    /// boot was a call-ordering mistake of this shape: the wait was reached
    /// before anything had guaranteed its clock was counting, the budget was
    /// therefore unreachable, and the wait fell through to the poll cap and
    /// reported a peripheral stall for a condition no one had measured. A
    /// check at each call site would have been the same check in three places,
    /// any one of which a later edit could move. A check *here* is in the
    /// default body of the only method the trait has for waiting, so no
    /// [`TrngProbe`] — device or host, present or future — can reach the
    /// budget without passing through it. See D-12.
    ///
    /// # Ordering: the `Ready` test comes first, deliberately
    ///
    /// A validated block is a validated block. Refusing one because a
    /// stopwatch is not running would turn a working device into a brick,
    /// which is strictly worse than the failure this check exists to make
    /// visible, so the liveness bound is only ever reached on a poll that
    /// found the peripheral still working.
    fn await_ready(&mut self) -> Result<(), TrngError> {
        let start = self.clock().ticks();
        // Latched: once the clock has been seen to move it is a working
        // clock, and a later stretch of equal readings is a slow clock, not a
        // dead one. Re-accusing it would be the false positive
        // `CLOCK_LIVENESS_SPINS` is sized to avoid.
        let mut clock_moved = false;
        let mut frozen_reads: u32 = 0;
        for _ in 0..MAX_ENTROPY_POLLS {
            if self.status() == ProbeStatus::Ready {
                return Ok(());
            }
            let now = self.clock().ticks();
            if now.wrapping_sub(start) >= MAX_ENTROPY_WAIT {
                break;
            }
            if now != start {
                clock_moved = true;
            } else if !clock_moved {
                frozen_reads += 1;
                if frozen_reads >= CLOCK_LIVENESS_SPINS {
                    return Err(TrngError::ClockStalled);
                }
            }
        }
        // Out of the loop without `Ready`. If the clock never moved, the
        // budget was never in play and the poll count says nothing about the
        // peripheral — so name the clock, not the entropy source.
        Err(if clock_moved {
            TrngError::Stalled
        } else {
            TrngError::ClockStalled
        })
    }

    /// Fill `buf` from the peripheral, waiting under both bounds.
    ///
    /// An empty `buf` is a no-op: it returns `Ok(())` without polling, matching
    /// [`Trng::random_bytes`]'s contract — asking for zero bytes must not
    /// consume the budget, and must not report a stall for work never asked
    /// for.
    ///
    /// A read that fills only part of `buf` is an **error** here, not a short
    /// success: see [`TrngProbe::read_into`].
    ///
    /// # There is no wait before the read
    ///
    /// This used to be `self.await_ready()?; self.read_into(buf)`. The
    /// pre-wait bought nothing and cost everything: the source is enabled
    /// *inside* the read path ([`draw_blocks`]), so a wait issued before that
    /// wait is a wait against a peripheral that cannot produce. It was
    /// survivable only because the host fakes' `read_into` was a bare buffer
    /// fill that needed the hand-off, and the device's own `read_into` began
    /// by enabling the source — the two implementations disagreed about who
    /// owns the ordering, and only the device one was shipped. The parked unit
    /// of 2026-09-29 had `RND_SRC_EN` clear and therefore drew nothing at all.
    /// `platform/tests/trng_source_order.rs` is what makes that reachable from
    /// host; dropping this pre-wait is the other half of the fix, because
    /// leaving it in place keeps a second, unreachable wait in front of the
    /// only one that can ever succeed.
    ///
    /// The empty-`buf` guard stays here rather than moving into
    /// [`draw_blocks`] alone because an implementation is free to override
    /// [`read_into`](TrngProbe::read_into), and this contract — no polling for
    /// work never asked for — is the caller's, not the override's.
    fn probe_bytes(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        if buf.is_empty() {
            return Ok(());
        }
        self.read_into(buf)
    }
}

/// The one ordered start/wait/read/stop sequence in this crate.
///
/// `no_std`, not `cfg`-gated, and generic over any [`TrngProbe`], so a host
/// fake can drive it and **record the order** the register operations arrived
/// in. That is the whole point of it: the defect it exists for is a
/// call-ordering defect, and an ordering is not observable from a return
/// value. It used to live in `Rp2350Probe::read_into`, inside a
/// `#[cfg(all(feature = "device", target_arch = "arm"))]` block that never
/// compiles on host — which is how a large host suite and a long gate list
/// could all be green over a device that would not boot.
/// `platform/tests/trng_source_order.rs` drives this function directly.
///
/// # The sequence
///
/// ```text
///   source_enable
///     for each EHR block:
///       await_ready             (bounded: liveness < budget < hard cap)
///       read_block
///   source_disable             (every exit, success and refusal alike)
/// ```
///
/// # Why the enable is first and unconditional
///
/// The RP2350's ring oscillators are gated by `RND_SRC_EN`. With it clear
/// the counters do not run, so `TRNG_BUSY` never asserts and `EHR_VALID`
/// never sets: a status read reports the peripheral idle with no error bit
/// set — [`ProbeStatus::InvalidEhr`] — forever. A wait issued *before* the
/// enable is therefore a wait for a block that cannot arrive, and it ends by
/// reporting [`TrngError::Stalled`]: a claim about the health of a source
/// nobody had switched on. `boot::init_drbg` treats that as fatal, so it is a
/// device that does not boot, before USB enumerates. That is what the parked
/// unit on 2026-09-29 was, and a register readback showed it exactly
/// (`RND_SOURCE_ENABLE = 0`, `SAMPLE_CNT1 = 25`, `TRNG_CONFIG = 1`, EHR
/// never valid).
///
/// The enable is *not* something a status read can be expected to arrange.
/// The one status path that touches the source — the `autocorr_err` branch,
/// which soft-resets and re-arms — is reached only once the wait has already
/// begun, and a soft reset leaves the source **off**: re-arming without
/// re-enabling would leave the wait looking at a peripheral it had just
/// switched off. That is why the enable is a statement here rather than a
/// side effect somewhere else, and why it is first: nothing before it can
/// possibly help.
///
/// # Why there is no wait before the enable
///
/// There used to be one, and it bought nothing. It waited for a block,
/// **discarded the fact that it had one**, and then the read path waited for
/// the same block again — a second entry into the budget for no information,
/// and the reason a peripheral that is off could report a plausible-looking
/// [`TrngError::Stalled`] rather than an obviously-impossible one. It
/// existed because the *host fakes'* `read_into` was a bare buffer fill that
/// needed the hand-off, while the *device's* began by enabling the source:
/// the two implementations disagreed about who owned the ordering, and only
/// the device one was ever compiled. With the ordering in one place there is
/// nothing left to hand off.
///
/// # Why the source is off again on every exit
///
/// The disable is a statement after the per-block half, which is a separate
/// function precisely so that every `?` between the two lands somewhere the
/// disable is still reached. A draw that refuses half way through a
/// multi-block request must still power the oscillator down: a refusal that
/// leaves a peripheral running is a refusal that leaves a powered peripheral
/// for the next draw to inherit. On device `source_disable` also clears
/// `RST_BITS_COUNTER`, and it writes two fixed values rather than toggling,
/// so the unconditional call is a no-op on an already-off source rather than
/// a second way to get the state wrong.
///
/// # Why the two refusals are kept apart
///
/// The `?` on [`await_ready`](TrngProbe::await_ready) propagates **both**
/// codes unchanged, so [`TrngError::ClockStalled`] — a wait whose clock never
/// moved — reaches the caller as itself and not as [`TrngError::Stalled`].
/// The per-block read this replaced collapsed them with `is_err()`, so on
/// every path that draws, a dead wall clock was indistinguishable from a slow
/// peripheral. D-12 is entirely about that indistinguishability, and the
/// draw path is where it bit hardest.
pub fn draw_blocks<P: TrngProbe + ?Sized>(regs: &mut P, buf: &mut [u8]) -> Result<(), TrngError> {
    if buf.is_empty() {
        return Ok(());
    }
    regs.source_enable();
    let outcome = draw_blocks_inner(regs, buf);
    regs.source_disable();
    outcome
}

/// The per-block half of [`draw_blocks`], split out so the disable above is a
/// statement in the same function as the enable and cannot be skipped by an
/// early return added later.
fn draw_blocks_inner<P: TrngProbe + ?Sized>(
    regs: &mut P,
    buf: &mut [u8],
) -> Result<(), TrngError> {
    let mut written = 0;
    while written < buf.len() {
        regs.await_ready()?;
        let end = (written + EHR_BLOCK_BYTES).min(buf.len());
        regs.read_block(&mut buf[written..end]);
        written = end;
    }
    Ok(())
}

/// Length of the migration-completion AEAD nonce, in bytes: the nonce for the
/// class-1 DEK rewrap (`platform::migration::complete_passphrase_class`, US-917).
///
/// The AEAD this feeds is 96-bit-nonce, which is why the length is not
/// negotiable — and why the *failure* modes around it are not symmetric with a
/// protocol nonce's. A repeated nonce under one key is a key-recovery
/// primitive for the record it protects, so "the draw did not happen" has to be
/// a refusal the caller acts on, never a value it uses.
pub const MIGRATION_NONCE_LEN: usize = 12;

/// One migration nonce is **one** validated EHR block, and the block is what
/// [`MAX_ENTROPY_WAIT_MS`] is calibrated against.
///
/// Stated as a compile-time assertion rather than prose because it is a
/// budget claim the gate cannot see: the 20 ms figure is a *per-block*
/// allowance, so a 12-byte draw spends exactly one of them and a 32-byte seed
/// draw spends two. `platform/tests/migration_nonce.rs` states the same
/// arithmetic from the host side; a length that grew past [`EHR_BLOCK_BYTES`]
/// would silently double the worst-case latency of a **CCID request** — which
/// is the property D-10 was about.
const _: () = assert!(
    MIGRATION_NONCE_LEN <= EHR_BLOCK_BYTES,
    "the migration nonce must stay within one validated EHR block, or a single \
     migration request spends more than one wait budget"
);

/// Draw a fresh migration nonce, or refuse — the bounded seam for the AEAD DEK
/// rewrap (US-1005, closing D-10).
///
/// # What this replaces
///
/// The nonce used to come from an `embassy-rp` `Trng` handle inside
/// `DeviceMigrationHandler::complete` — i.e. **inside a live CCID APDU
/// request** — via `blocking_fill_bytes`, the unbounded self-retrying wait
/// that soft-resets and retries *forever* on `autocorr_err` (`D-10`). The
/// RP2350 documents that condition as "RNG ceases functioning until next
/// reset", so the retry was retrying something that cannot succeed: a wedged
/// peripheral turned one management APDU into a `no_std` busy-wait with no
/// supervisor, no watchdog kick, and nothing in the log.
///
/// Through [`TrngProbe::probe_bytes`] the wait carries its three named bounds
/// (liveness < [`MAX_ENTROPY_WAIT`] < [`MAX_ENTROPY_POLLS`]) and the caller
/// gets an `Err` to act on.
///
/// # Why the peripheral and not the DRBG
///
/// The EPIC's Phase 1 outcome is that every nonce comes from a conditioned,
/// reseeded generator, and the natural reading is that this one should too. It
/// cannot, and the reason is ownership rather than principle: the device
/// generator is moved **by value** into the trussed platform
/// (`trusted_backend::take_drbg`) and from there lives inside the client the
/// OpenPGP app owns, so there is no handle left to draw from at the point
/// `complete` needs one. Reaching it would mean reaching through four layers of
/// trussed ownership that this call site does not own.
///
/// What is given up is small and is stated rather than assumed: a
/// [`crate::trng::DrbgTrng`] output is a deterministic function of one
/// validated peripheral block, so for a **one-off, twelve-byte, at-rest**
/// nonce the two routes differ by HMAC and nothing else. The rewrap is not a
/// per-request protocol nonce; it happens once per migrated record.
///
/// Fill `buf` with fresh peripheral entropy through the **bounded** seam.
///
/// This is the whole of "get entropy that cannot wedge the device": one
/// `probe_bytes` call, whose wait carries three named bounds (liveness <
/// [`MAX_ENTROPY_WAIT`] < [`MAX_ENTROPY_POLLS`]), and a *reported* refusal
/// rather than an infinite loop. Every boot-path draw that can be refused
/// goes through here, so there is exactly one place where "fresh" is
/// asserted and exactly one place that scrubs a refusal.
///
/// # Why the all-zero refusal
///
/// A peripheral that reports success and hands back a constant would put a
/// *known* value into whatever consumes it, and a known value is the one
/// input that turns the consumer into an attack on its own key. This is the
/// same condition [`crate::drbg_seed::FuseSeedSource`] refuses, and for the
/// same reason — "fresh" is a claim that has to be asserted, not inferred
/// from an `Ok`.
///
/// # Refusal leaves the buffer scrubbed
///
/// `probe_bytes`'s contract is that a refusal means "the contents of `buf`
/// mean nothing". Here that is not enough to leave them as the caller passed
/// them, because the one thing a reader will mistake a leftover buffer for is
/// usable material — so the refusal path zeroes `buf` before returning. This
/// is deliberately *not* what [`Trng::random_bytes`] does, and the asymmetry
/// is the point: that method cannot report failure, so leaving the buffer
/// alone is the only honest signal it has. This one reports, and a reported
/// refusal can afford to destroy the evidence.
pub fn try_fresh_bytes<P: TrngProbe + ?Sized>(
    probe: &mut P,
    buf: &mut [u8],
) -> Result<(), TrngError> {
    let outcome = match probe.probe_bytes(buf) {
        Ok(()) if buf.iter().all(|&b| b == 0) => Err(TrngError::Entropy),
        other => other,
    };
    if outcome.is_err() {
        // Uniform across every refusal, the all-zero one included: whatever
        // the caller passes back must be unusable, and a single scrub point
        // is a thing a reader can check rather than a rule spread over arms.
        buf.fill(0);
    }
    outcome
}

/// [`try_fresh_bytes`] at the migration nonce's fixed width, kept as its own
/// name because the nonce is the case the reasoning above was written for:
/// `PSO:DECIPHER` returns a raw ECDH shared secret and the *host* derives the
/// KDF (the US-947 revert), so a predictable rewrap nonce is an attack on
/// the migration's own key rather than a cosmetic weakness.
pub fn try_migration_nonce<P: TrngProbe + ?Sized>(
    probe: &mut P,
    out: &mut [u8; MIGRATION_NONCE_LEN],
) -> Result<(), TrngError> {
    try_fresh_bytes(probe, out)
}


/// The platform's sole source of entropy.
///
/// Every byte of randomness on the device MUST flow through a `Trng`
/// implementation backed by the RP2350 hardware TRNG. There is deliberately no
/// seeded / deterministic implementation of this trait.
pub trait Trng {
    /// Fill `buf` with cryptographically-secure random bytes. The whole buffer
    /// is written; an empty buffer is a no-op.
    fn random_bytes(&mut self, buf: &mut [u8]);

    /// Fill `buf` with random bytes, **reporting** a source that cannot
    /// produce any.
    ///
    /// # Why this exists (US-1007 defect fix)
    ///
    /// [`random_bytes`](Trng::random_bytes) has no way to say "I produced
    /// nothing", so an implementation that cannot produce leaves `buf`
    /// untouched and the caller cannot tell a fresh 32 zero bytes from a
    /// refused draw. That ambiguity is what fed the FIDO keygen spin: a
    /// starved draw looked like a successful one, and an unbounded
    /// rejection sampler on top of it looped forever. This is the
    /// trait-level version of the split [`DrbgTrng::try_random_bytes`]
    /// already made at the concrete level — `Trng` reports, this reports the
    /// refusal as an `Err` instead of as silence.
    ///
    /// The default delegates to [`random_bytes`](Trng::random_bytes), so an
    /// implementation that genuinely cannot fail — a peripheral whose draw
    /// has a *bounded* internal wait, D-9's "bounded hang" — stays correct
    /// with no code. It is deliberately **not** the right default for a
    /// source that can silently produce nothing, which is exactly what a
    /// starved [`HostTrng`] and a starved [`DrbgTrng`] do. Both override it.
    fn try_random_bytes(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        self.random_bytes(buf);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Host (emulation / tests): OS entropy.
// ---------------------------------------------------------------------------

/// Host stand-in for the hardware TRNG: reads OS entropy (`/dev/urandom` on
/// Linux). Stateless, so `&mut self` carries no state.
///
/// # The US-1007 starvation seam
///
/// This is the **infallible** funnel: every host draw in the tree that goes
/// through the free functions below ends here, and so does the emulation's
/// own boot-time draw (`emul_main.rs`'s boot-entropy record and
/// `OathApp::boot`). When the seam is active this method **leaves `buf`
/// untouched** rather than filling it — the same choice
/// [`DrbgTrng::random_bytes`] makes on a starved generator, and for the same
/// reason: a filled buffer that is not fresh entropy is a predictable value
/// a caller cannot tell from a real one, whereas an untouched one at least
/// leaves the caller's own contents visible.
///
/// The fallible half of the same condition is
/// [`crate::trusted_backend::host::HostRng::try_fill_bytes`], which returns a
/// real `Err` — that is the path a *request* takes, because `Trng` cannot
/// report a refusal (see D-9 in `docs/known-gate-divergences.md`).
#[cfg(not(target_arch = "arm"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct HostTrng;

#[cfg(not(target_arch = "arm"))]
impl HostTrng {
    pub fn new() -> Self {
        Self
    }
}

/// The US-1007 starvation seam, as a single predicate.
///
/// One consult, shared by [`HostTrng`]'s infallible and fallible draws, so
/// the two cannot disagree about whether the peripheral is producing and so
/// the seam name appears exactly once in this file — `check_rng_path.py`
/// caps it, and a second consult would be a second way to wedge the
/// infallible half. `cfg`-gated at the `mod` declaration in `lib.rs`, so on
/// a device build the seam's name does not resolve at all.
#[cfg(not(target_arch = "arm"))]
fn host_starved() -> bool {
    #[cfg(all(feature = "emulation", not(target_arch = "arm")))]
    {
        crate::entropy_starve::starved()
    }
    #[cfg(not(all(feature = "emulation", not(target_arch = "arm"))))]
    {
        false
    }
}

#[cfg(not(target_arch = "arm"))]
impl Trng for HostTrng {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        use std::io::Read;
        if buf.is_empty() {
            return;
        }
        // US-1007: a starved peripheral produces no block, so neither does
        // this.
        if host_starved() {
            return;
        }
        let file = std::fs::File::open("/dev/urandom")
            .expect("TRNG: open /dev/urandom (host entropy source)");
        let mut reader = std::io::BufReader::new(file);
        reader
            .read_exact(buf)
            .expect("TRNG: read /dev/urandom (host entropy source)");
    }

    /// US-1007: the fallible half of the same condition. Where
    /// [`random_bytes`](Trng::random_bytes) leaves `buf` untouched and says
    /// nothing, this says *no* — which is what stops a starved draw from
    /// being mistaken for 32 fresh zero bytes by a rejection sampler.
    ///
    /// [`TrngError::Stalled`] rather than [`TrngError::Entropy`]: the seam
    /// models a peripheral that has stopped producing, not one whose backing
    /// file became unreadable. The `/dev/urandom` path still `expect`s, so a
    /// genuinely broken entropy *file* is the loud failure it always was and
    /// is not folded into this one.
    fn try_random_bytes(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        if !buf.is_empty() && host_starved() {
            return Err(TrngError::Stalled);
        }
        self.random_bytes(buf);
        Ok(())
    }
}

/// Fill `buf` with platform randomness (host: OS entropy; device: see
/// [`rp2350::Rp2350Trng`]). This is the convenience entry point app crates use
/// instead of touching a `rand` RNG directly.
#[cfg(not(target_arch = "arm"))]
pub fn random_bytes_into(buf: &mut [u8]) {
    let mut trng = HostTrng::new();
    trng.random_bytes(buf);
}

/// [`random_bytes_into`], **fallible** — the free-function half of
/// [`Trng::try_random_bytes`] for host callers that hold no `Trng` value.
///
/// Added by the US-1007 defect fix so the host twin has the same honest
/// refusal the device's `DrbgTrng` already had. Without it a starved host
/// draw is indistinguishable from a draw of 32 zero bytes, which is what let
/// a FIDO keygen spin instead of failing.
#[cfg(not(target_arch = "arm"))]
pub fn try_random_bytes_into(buf: &mut [u8]) -> Result<(), TrngError> {
    let mut trng = HostTrng::new();
    trng.try_random_bytes(buf)
}

/// Fill a fixed-size array with platform randomness (host: OS entropy).
#[cfg(not(target_arch = "arm"))]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    random_bytes_into(&mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Device (RP2350): hardware TRNG via embassy-rp.
// ---------------------------------------------------------------------------

/// RP2350 hardware TRNG. Wraps the `embassy-rp` TRNG driver and is the sole
/// randomness source on the device.
///
/// Construct the underlying `embassy_rp::trng::Trng` in the firmware entry
/// point (it needs the `TRNG` peripheral token and its IRQ binding), then wrap
/// it here so the rest of the codebase only ever sees the [`Trng`] trait:
///
/// ```no_run
/// use embassy_rp::trng::{Config, Trng as EmbTrng};
/// // ... p = embassy_rp::init(...); Irqs from bind_interrupts! ...
/// let trng = fapico2_platform::trng::Rp2350Trng::new(
///     EmbTrng::new(p.TRNG, Irqs, Config::default()),
/// );
/// ```
#[cfg(all(feature = "device", target_arch = "arm"))]
pub mod rp2350 {
    use super::{
        EntropyClock, ProbeStatus, Trng, TrngError, TrngProbe, CLOCK_LIVENESS_SPINS,
    };

    /// Hardware TRNG wrapper. Owns the `embassy-rp` driver by value.
    pub struct Rp2350Trng<'d>(
        pub embassy_rp::trng::Trng<'d, embassy_rp::peripherals::TRNG>,
    );

    impl<'d> Rp2350Trng<'d> {
        pub fn new(inner: embassy_rp::trng::Trng<'d, embassy_rp::peripherals::TRNG>) -> Self {
            Self(inner)
        }

        /// Construct from the peripheral token and the IRQ binding.
        ///
        /// # Why this exists (US-1005)
        ///
        /// It moves the `embassy_rp` driver construction *into this module*
        /// so the firmware no longer names `embassy_rp::trng::Trng::new` at
        /// all. That is not cosmetics: `tests/scripts/check_rng_path.py`
        /// forbids that name outside this file, and a constructor that took a
        /// ready-made driver (the old `new`) could only be called by someone
        /// who had already built one — which is the bypass the gate exists to
        /// catch. With the token and the binding as the arguments, the driver
        /// is unreachable to a caller except through here.
        ///
        /// `TrngIrqs` is a `Copy` ZST produced by `bind_interrupts!`, so any
        /// number of handles may bind the same handler; the duplication
        /// discipline for the underlying `Peri` stays the caller's, exactly
        /// as before.
        pub fn from_peri(
            peri: embassy_rp::Peri<'d, embassy_rp::peripherals::TRNG>,
            irq: impl embassy_rp::interrupt::typelevel::Binding<
                    embassy_rp::interrupt::typelevel::TRNG_IRQ,
                    embassy_rp::trng::InterruptHandler<embassy_rp::peripherals::TRNG>,
                > + 'd,
            config: embassy_rp::trng::Config,
        ) -> Self {
            Self(embassy_rp::trng::Trng::new(peri, irq, config))
        }
    }

    impl<'d> Trng for Rp2350Trng<'d> {
        fn random_bytes(&mut self, buf: &mut [u8]) {
            // `blocking_fill_bytes` draws from the TRNG ring oscillator with the
            // configured post-processing; it is the only entropy path on device.
            self.0.blocking_fill_bytes(buf);
        }
    }

    /// A [`TrngProbe`] over the RP2350 TRNG peripheral (US-1005).
    ///
    /// # Why this type exists at all, given `embassy-rp` has a driver
    ///
    /// Because the *status bits are reachable*, which is the question US-1005
    /// had to answer before it could honestly claim a bound. The answer is
    /// yes — but **not** through `embassy_rp`, and the route matters:
    ///
    /// * `embassy_rp::trng::Trng` exposes no status accessor. Its
    ///   `blocking_wait_for_successful_generation` (trng.rs:220-243 in
    ///   embassy-rp 0.10.0) is private, and it is an unbounded busy-wait: on
    ///   `autocorr_err` it soft-resets and retries **forever**, and on the
    ///   other invalid-EHR branch it `panic!()`s. Neither is reachable from
    ///   outside the crate, so `TrngProbe` was unimplementable against the
    ///   driver's public API alone.
    /// * `embassy_rp::pac` is `pub(crate)` unless the `unstable-pac` feature
    ///   is on (embassy-rp `lib.rs:70-73`), so it is not a door either.
    /// * **`rp_pac` is.** The firmware already depends on `rp-pac` directly
    ///   for exactly this reason (`firmware/Cargo.toml:95-98`: the QSPI-CS
    ///   button read needs registers `embassy_rp::pac` will not expose). It
    ///   publishes `rp_pac::TRNG` — the *same* register block the driver's
    ///   `SealedInstance::regs()` returns — with every field the wait needs
    ///   public: `trng_busy().trng_busy()`, `trng_valid().ehr_valid()`,
    ///   `rng_isr().autocorr_err()`, `ehr_data0()..ehr_data5()`.
    ///
    /// So the peripheral's health-test outcome is observable, and the wait
    /// can carry the ceiling US-1001 specified.
    ///
    /// # What is bounded, precisely
    ///
    /// [`TrngProbe::probe_bytes`] is inherited: the wait terminates on
    /// whichever of three bounds expires first — [`CLOCK_LIVENESS_SPINS`]
    /// consecutive reads with no clock movement at all
    /// ([`TrngError::ClockStalled`], D-12), [`MAX_ENTROPY_WAIT`] (20 ms — a
    /// 10x safety factor on the ~2 ms average generation time the RP2350
    /// datasheet quotes for `embassy-rp`'s default `Config`), or
    /// [`MAX_ENTROPY_POLLS`] (2^19) status reads — and the last two both
    /// answer [`TrngError::Stalled`]. The inherited semantics apply unchanged
    /// on device:
    ///
    /// * `ProbeStatus::AutocorrErr` is reported and the peripheral is
    ///   soft-reset, matching the retry the driver performs. The difference
    ///   is that the retry is *bounded* — the deadline runs across the retries
    ///   rather than being consumed one poll at a time. This is the entire
    ///   point of the type: the RP2350 documents `AUTOCORR_ERR` as "RNG
    ///   ceases functioning until next reset", so the driver's unbounded
    ///   retry is retrying something that cannot succeed. Failing in bounded
    ///   time is the correct outcome, not a workaround.
    /// * An empty `buf` is a no-op, and the budget is per **EHR block**: a
    ///   [`crate::drbg::NONCE_LEN`]-byte seed draw crosses
    ///   `ceil(32 / 24) == 2` blocks, each with its own budget, so one seed
    ///   draw's effective ceiling is 2 x [`MAX_ENTROPY_WAIT`] = 40 ms (and
    ///   2 x [`MAX_ENTROPY_POLLS`] status reads). The constants' own docs say
    ///   the values are per-block, so this is the documented meaning rather
    ///   than a widened one.
    /// * A read that fills only part of `buf` is an **error**, not a short
    ///   success — see [`TrngProbe::read_into`]. The caller is
    ///   `Zeroizing::new([0u8; NONCE_LEN])`, so a partial fill would otherwise
    ///   reach the DRBG nonce slot as "24 fresh bytes followed by 8 zeros" and
    ///   be reported as a successful draw.
    ///
    /// # What is still not bounded — read this before relying on it
    ///
    /// **The budget is an average multiplied by a safety factor, not a
    /// measured maximum.** [`MAX_ENTROPY_WAIT_MS`] is derived from the
    /// datasheet's ~2 ms *average* for this configuration plus a 10x factor;
    /// the datasheet's own wording is that "results occasionally take an
    /// especially long time to generate", and no figure is given for that
    /// tail. No board was attached, so **this has not been measured on
    /// silicon.** A part slower than 10x the datasheet average would return
    /// `Stalled` and, because `boot::init_drbg` treats a seed refusal as
    /// fatal, would refuse to boot. That is the correct fail-closed
    /// direction — a bounded, reportable refusal beats an unbounded hang, and
    /// beats a generator fed a constant — but it is possible, and the
    /// residual is recorded as a standing divergence in
    /// `docs/known-gate-divergences.md` (D-8). US-1007 is where the
    /// hardware leg belongs.
    ///
    /// # No second driver
    ///
    /// This type reads the registers directly and does **not** also hold an
    /// `embassy_rp::trng::Trng`. [`Rp2350Trng`] and [`Rp2350Probe`] are
    /// alternatives over one peripheral, and the boot path constructs both
    /// kinds of handle only through the documented `Peri::clone_unchecked`
    /// duplication, single-core and never concurrently (see `main.rs`).
    /// [`Rp2350Probe`] deliberately does not use the driver's `start_rng` /
    /// `stop_rng` (private, and the driver would have to be constructed
    /// anyway); it writes the same two registers itself, and the one
    /// register it must not get wrong — `trng_debug_control`, which carries
    /// the health-test bypass bits — it does not write at all, leaving that
    /// to `Trng::new`'s `initialize_rng` at construction.
    ///
    /// [`Rp2350Probe::soft_reset`] writes the two it skips *after* the reset,
    /// because that is exactly the window the original omission left open
    /// (see the `TrngConfig` field and D-8's amendment).
    pub struct Rp2350Probe<'d> {
        /// The peripheral token, held for its lifetime only. `Rp2350Probe`
        /// drives registers itself, so there is no driver value to own; what
        /// it owns is the *right* to drive them, which `Peri` is.
        _peri: core::marker::PhantomData<&'d mut embassy_rp::peripherals::TRNG>,
        /// The free-running hardware timer the wait budget is measured
        /// against. A ZST, so it costs the source no RAM.
        timer: Rp2350Timer,
        /// The configuration to re-apply after a soft reset.
        ///
        /// A TRNG soft reset returns `trng_config.rnd_src_sel` and
        /// `sample_cnt1` to their power-on values, so a probe that re-arms
        /// without re-writing them re-arms on a **different peripheral
        /// configuration from the one [`MAX_ENTROPY_WAIT`] is calibrated
        /// against**. That is the second trigger for D-8's void condition
        /// that the first `autocorr_err` opened; the value is captured from
        /// the caller-supplied `Config`, so it is the same configuration
        /// `Trng::new` was built with rather than a second guess at it.
        config: super::TrngConfig,
    }

    /// The wall clock the device entropy wait is measured against: the
    /// RP2350 hardware `TIMER`, read directly through `rp-pac`.
    ///
    /// # Why this and not `embassy_rp`'s timer
    ///
    /// `embassy-rp` 0.10.0 has **no** `timer::CycleCounter` — the crate's
    /// `src/` tree has no `timer` module at all, only `time_driver.rs` (the
    /// `embassy-time` `Driver`) and the RP2040-only `rtc` module. Reaching
    /// through `embassy_time::Instant::now()` instead would put a
    /// link-time driver symbol and a tick-to-duration division inside the
    /// wait loop, and would make the probe unconstructible in any build that
    /// does not link the time driver. The register is already open: `rp-pac`
    /// publishes `rp_pac::TIMER0`, and the only thing needed is a
    /// non-destructive read.
    ///
    /// # It is the counter the firmware already trusts
    ///
    /// `embassy-rp`'s own time driver returns the raw `TIMER` reading and
    /// `embassy-time` reads it as microseconds, so the 1 MHz assumption behind
    /// [`ENTROPY_CLOCK_TICKS_PER_MS`] is the same one every `Duration` in this
    /// firmware already rests on. `TIMER0` is shared with that driver; the
    /// read is non-destructive (the raw counter is not cleared by a read, only
    /// by `timerawc`), so sharing costs nothing and needs no arbitration.
    ///
    /// # `rp_pac::TIMER0` has no enable bit — and this one is not stopped
    ///
    /// The tempting thing to write here, having been handed "the timer is not
    /// running at seed time", is a "make sure the timer is running" call.
    /// On this part there is nothing to call, and that is a fact about the
    /// hardware worth recording rather than a gap:
    ///
    /// * The `TIMER0` register block (`rp-pac` `timer::Timer`) has
    ///   `timehw`/`timelw`/`timehr`/`timelr`/`alarm`/`armed`/`timerawh`/
    ///   `timerawl`/`dbgpause`/`pause`/`locked`/`source`/`intr`/`inte`/
    ///   `intf`/`ints`. **There is no `ENABLE` and no `CLEAR`.** The counter
    ///   cannot be gated or zeroed in software, so there is no "start the
    ///   timer" step to get wrong or to forget.
    /// * What *is* gated is the thing the counter counts. The RP2350's timer
    ///   ticks come from the `TICKS` block, and `TICKS.timer0_ctrl.ENABLE`
    ///   resets to 0. It is enabled — and configured to `clk_ref / 1e6`, i.e.
    ///   exactly 1 MHz — by `embassy_rp::clocks::init`
    ///   (`embassy-rp-0.10.0/src/clocks.rs:1150-1154`), which
    ///   `embassy_rp::init` calls as its second statement
    ///   (`lib.rs:630-634`). `embassy_rp::init` is the second line of
    ///   `main` (`firmware/src/main.rs:197`), so the tick generator is
    ///   running long before the first entropy draw.
    /// * `embassy-rp`'s `time_driver::init()` (the `embassy-time` `Driver`
    ///   setup, `time_driver.rs:154-171`) does **not** start the counter and is
    ///   not lazy about anything relevant: it initialises the alarm state and
    ///   enables `TIMER0_IRQ_0`. It cannot be what "the timer is stopped at
    ///   seed time" refers to.
    ///
    /// So the preconditions for the counter counting are (a) `clocks::init`
    /// having run, and (b) nothing having set `TIMER0.PAUSE` or a debug-pause
    /// bit. Neither is a step this module can perform, and neither is a step
    /// a future edit of `main` can plausibly undo. **What it can do is check
    /// the outcome**, which is what [`Rp2350Timer::require_advancing`] does —
    /// and the outcome is a fact, not a sequencing convention, so checking it
    /// is strictly better than arranging it. See D-12.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct Rp2350Timer;

    impl Rp2350Timer {
        /// Verify `TIMER0` is actually counting, and return the proof.
        ///
        /// The single source of [`ClockReady`], and the reason a
        /// [`Rp2350Probe`] cannot be built without one: the token is a
        /// distinct type with a private field and no public constructor, and
        /// `Rp2350Probe::new` takes it by value. The only way to obtain one
        /// is to have called this and had it succeed, so "a probe exists"
        /// and "the clock was checked" are the same fact to the compiler
        /// rather than two things a code review has to correlate.
        ///
        /// Bounded by [`CLOCK_LIVENESS_SPINS`] raw reads — the same constant,
        /// and for the same reason, that the in-wait check uses: the only
        /// instrument still working when the clock has stopped is the core
        /// executing this loop. On a 1 MHz clock, 256 raw reads is
        /// 256–512 ticks; a live counter cannot miss that, and a stopped one
        /// gives up in well under a millisecond.
        ///
        /// # Why this is `unsafe`-free and cannot touch driver state
        ///
        /// It reads two `TIMER0` registers and compares them. `timerawh` /
        /// `timerawl` are documented "raw read ... (no side effects)" and do
        /// not touch the `armed`/`alarm`/`inte` state that `embassy-rp`'s
        /// `time_driver::init` owns, so this is safe to call on the boot path
        /// before any timer has been armed. It is the *setup* that is not
        /// shareable in general — writing `TIMER0.CLEAR` or `armed` would
        /// trample a driver that had already armed an alarm — which is
        /// another way of saying that reading is the only operation this
        /// module has any business performing on a peripheral another driver
        /// also owns.
        pub fn require_advancing() -> Result<ClockReady, TrngError> {
            Self.verify_advancing(CLOCK_LIVENESS_SPINS)
        }

        /// The check itself, on `&self` so the in-probe path and the
        /// construction-time path cannot drift apart.
        fn verify_advancing(&self, spins: u32) -> Result<ClockReady, TrngError> {
            let start = self.ticks();
            for _ in 0..spins {
                if self.ticks() != start {
                    return Ok(ClockReady { _private: () });
                }
            }
            Err(TrngError::ClockStalled)
        }
    }

    impl EntropyClock for Rp2350Timer {
        fn ticks(&self) -> u64 {
            // The 64-bit reading is two 32-bit registers, so a torn read is
            // possible; re-read the high word and only accept a stable pair.
            // This is the same sequence `embassy-rp`'s `TimerDriver::now` uses
            // (`embassy-rp-0.10.0/src/time_driver.rs:35-43`).
            loop {
                let hi = rp_pac::TIMER0.timerawh().read();
                let lo = rp_pac::TIMER0.timerawl().read();
                if rp_pac::TIMER0.timerawh().read() == hi {
                    return (u64::from(hi) << 32) | u64::from(lo);
                }
            }
        }
    }

    /// Proof that the RP2350 hardware wall clock was observed counting.
    ///
    /// # Unforgeable outside this module, on purpose
    ///
    /// A private field and no public constructor. The value can only be
    /// produced by [`Rp2350Timer::require_advancing`] returning `Ok`, so a
    /// caller cannot construct a [`Rp2350Probe`] without having first watched
    /// the counter move.
    ///
    /// The alternative — a `debug_assert!`, a comment, or a boolean argument
    /// somebody can pass `true` — was rejected because each of them is a
    /// convention, and the 2026-09-29 dark boot was a convention that held on
    /// paper and was not checked. A token the compiler demands is the only
    /// version of "this must happen first" that survives someone reordering
    /// `main` in a later session. The token is zero-sized and consumed, so it
    /// costs no RAM and cannot be replayed.
    #[derive(Debug)]
    pub struct ClockReady {
        _private: (),
    }

    impl<'d> Rp2350Probe<'d> {
        /// Bind to the peripheral — **given that the wall clock was observed
        /// counting**.
        ///
        /// # The second argument is the point
        ///
        /// `clock: ClockReady` is not ceremony. It is the whole reason this
        /// constructor has this shape: the proof is a type the caller cannot
        /// make, so "a probe exists" implies "the clock was checked" to the
        /// compiler, and a future session that moves this call above whatever
        /// it depends on gets a **build failure** rather than a device that
        /// boots dark for a reason nobody can see from the outside.
        ///
        /// The bound being proved is [`MAX_ENTROPY_WAIT`], which is
        /// meaningless without a counting clock. Before this argument existed
        /// that was an assumption stated in a comment three hundred lines
        /// from the call site, on a code path where the seed refusal is fatal
        /// and happens before USB enumerates. That is precisely the shape of
        /// the 2026-09-29 dark boot.
        ///
        /// It is **not** a substitute for the in-wait check. This proves the
        /// clock was counting at one instant during construction; the
        /// [`CLOCK_LIVENESS_SPINS`] check inside
        /// [`TrngProbe::await_ready`] re-asks on every wait, and also covers
        /// the case where the clock is stopped *after* the probe is built —
        /// which no construction-time check can see, and which is a real mode
        /// on a part that can be reset or power-gated underneath a running
        /// task.
        ///
        /// The `Peri` token is the ownership proof, exactly as for
        /// [`Rp2350Trng`].
        ///
        /// `config` is the configuration the peripheral was initialised
        /// with, and it must be the *same* value
        /// [`Rp2350Trng::from_peri`] was given (US-1005 fix). It is not
        /// read back from the registers at construction because the
        /// caller's `Config` is the authoritative statement of intent, and
        /// a value read back from hardware could only ever agree with it or
        /// be wrong — and being wrong here is silent by construction. The
        /// only cost of taking it as an argument is that a caller can pass
        /// something else, which is why the boot path passes the same
        /// `Config::default()` constant it passes to `from_peri`.
        pub fn new(
            peri: embassy_rp::Peri<'d, embassy_rp::peripherals::TRNG>,
            clock: ClockReady,
            config: super::TrngConfig,
        ) -> Self {
            // Both tokens are consumed for their lifetime guarantee; the
            // registers are singletons (`rp_pac::TRNG` is a `const` at
            // `0x400f_0000`) and the clock proof is a ZST, so neither value
            // carries information past the borrow.
            let _ = (peri, clock);
            Self {
                _peri: core::marker::PhantomData,
                timer: Rp2350Timer,
                config,
            }
        }

        /// The soft reset + re-arm the driver performs on `autocorr_err`
        /// (trng.rs:230-235), **including** the `initialize_rng`
        /// configuration re-write.
        ///
        /// # The re-write, and why it is not optional (US-1005 fix)
        ///
        /// The driver re-runs `initialize_rng` after every soft reset
        /// (`embassy-rp-0.10.0/src/trng.rs:233`). That writes **three**
        /// registers: `rng_imr`, `trng_config.rnd_src_sel` and
        /// `sample_cnt1`. The previous version of this function justified
        /// its omission of that call as "the health test is not bypassed by
        /// this type, so there is no configuration to restore" — which is
        /// true only of `trng_debug_control`, the fourth register and the
        /// one the probe has never touched, and silent about the other two.
        ///
        /// So a probe that took the old shape re-armed on `sample_cnt1 = 0`
        /// and `rnd_src_sel = 0` — the power-on defaults, which the
        /// datasheet places *outside* the 20-25 sample band its 2 ms
        /// generation figure is quoted for. The consequence is not a worse
        /// generator; it is a **deadline calibrated for a different
        /// peripheral**, so a healthy part can miss
        /// [`MAX_ENTROPY_WAIT_MS`] and return [`TrngError::Stalled`] — which
        /// `init_drbg` treats as fatal. One autocorrelation error was
        /// enough to turn a booting device into a dark one.
        ///
        /// `rng_imr` is deliberately still not written: it masks the
        /// `EHR_VALID` *interrupt*, and this probe is bounded-poll by
        /// construction, so masking an interrupt nobody enables is a
        /// no-op. The trailing read is the driver's own fixed-delay
        /// substitute and is kept verbatim.
        fn soft_reset(&self) {
            rp_pac::TRNG
                .trng_sw_reset()
                .write(|w| w.set_trng_sw_reset(true));
            // Fixed delay is required after a TRNG soft reset; this read is
            // sufficient (the driver's own comment, trng.rs:232-233).
            rp_pac::TRNG.trng_sw_reset().read();
            self.apply_config();
        }

        /// Re-apply the configuration a soft reset just cleared: the two
        /// fields of [`super::TrngConfig`], written to the two registers
        /// `initialize_rng` writes them to.
        ///
        /// Split out from [`soft_reset`](Self::soft_reset) so the "which
        /// registers" claim is one call site rather than prose, and so the
        /// order — reset, delay read, configure — is visible in one place.
        ///
        /// `TRNG_CONFIG` is a `modify`, not a whole-word write: bits 33:2
        /// are RESERVED and reading them back after a soft reset is how a
        /// future reader would notice if the silicon ever gave them
        /// meaning. The driver uses `.write(...)`, which leaves them at
        /// their reset value; preserving them is a superset of that and
        /// cannot write a bit the driver would not have.
        fn apply_config(&self) {
            rp_pac::TRNG
                .trng_config()
                .modify(|w| w.set_rnd_src_sel(self.config.rnd_src_sel));
            rp_pac::TRNG
                .sample_cnt1()
                .write(|w| *w = self.config.sample_cnt1 as u32);
        }

        /// Soft-reset and re-arm, for the `autocorr_err` branch of
        /// [`TrngProbe::status`].
        ///
        /// The re-arm is the enable that branch owes the peripheral: a TRNG
        /// left reset is a TRNG whose source is off, so a status report that
        /// says "soft-reset, now generating" and then does not switch the
        /// source on would be reporting a state the hardware is not in.
        fn rearm(&mut self) {
            self.soft_reset();
            TrngProbe::source_enable(self);
        }
    }

    impl TrngProbe for Rp2350Probe<'_> {
        fn status(&mut self) -> ProbeStatus {
            // `trng_valid` first: a valid block is the only state in which the
            // driver reports success, and the peripheral clears the bit by
            // reading EHR_DATA5 (datasheet §12.12.3), so this is the same
            // ordering the driver uses.
            if rp_pac::TRNG.trng_valid().read().ehr_valid() {
                return ProbeStatus::Ready;
            }
            if rp_pac::TRNG.rng_isr().read().autocorr_err() {
                self.rearm();
                return ProbeStatus::AutocorrErr;
            }
            if rp_pac::TRNG.trng_busy().read().trng_busy() {
                ProbeStatus::Busy
            } else {
                // Neither busy nor valid nor an autocorrelation error: the
                // driver `panic!()`s here (trng.rs:237). Reporting it as
                // `InvalidEhr` is the same refusal in a form the caller can
                // act on, and it is bounded rather than fatal.
                //
                // This is also the state a source that was never switched on
                // reports, and the two are indistinguishable from here — which
                // is why the *enable* has to be unconditional and first in
                // [`draw_blocks`], rather than something a status read might
                // be expected to arrange.
                ProbeStatus::InvalidEhr
            }
        }

        fn clock(&mut self) -> &mut dyn EntropyClock {
            &mut self.timer
        }

        /// Enable the ring oscillator. Mirrors the driver's private
        /// `start_rng` (`embassy-rp` trng.rs:174-179).
        ///
        /// Writes `RND_SOURCE_ENABLE.RND_SRC_EN`. This single bit is the whole
        /// difference between a peripheral that can produce a block and one
        /// that cannot, and nothing else in this file puts it back — which is
        /// why [`draw_blocks`] calls it first and unconditionally rather than
        /// leaving it to a status read.
        fn source_enable(&mut self) {
            rp_pac::TRNG
                .rnd_source_enable()
                .write(|w| w.set_rnd_src_en(true));
        }

        /// Disable the source and reset the collected-bit counter. Mirrors the
        /// driver's private `stop_rng` (trng.rs:181-187). Called on every exit
        /// from the draw, including the refusal one: leaving the oscillator
        /// running after a refusal would keep a wedged peripheral powered, and
        /// the next draw would inherit its state. Two fixed values rather than
        /// a toggle, so the unconditional call [`draw_blocks`] makes on the way
        /// out is a no-op on an already-off source rather than a second way to
        /// get the state wrong.
        fn source_disable(&mut self) {
            rp_pac::TRNG
                .rnd_source_enable()
                .write(|w| w.set_rnd_src_en(false));
            rp_pac::TRNG
                .rst_bits_counter()
                .write(|w| w.set_rst_bits_counter(true));
        }

        /// Copy one already-validated 24-byte EHR block into the front of
        /// `block`.
        ///
        /// The read of `EHR_DATA5` is what clears the valid bit, so it must
        /// come last — and it is read even for a short (final) block,
        /// otherwise a partial read would leave a stale block marked valid and
        /// the next draw would serve it again.
        ///
        /// `block.len()` is at most [`super::EHR_BLOCK_BYTES`] by construction
        /// in [`draw_blocks`]; the clip here is belt and braces for a caller
        /// that hands it more, not a licence to.
        fn read_block(&mut self, block: &mut [u8]) {
            for (i, reg) in [
                rp_pac::TRNG.ehr_data0(),
                rp_pac::TRNG.ehr_data1(),
                rp_pac::TRNG.ehr_data2(),
                rp_pac::TRNG.ehr_data3(),
                rp_pac::TRNG.ehr_data4(),
                rp_pac::TRNG.ehr_data5(),
            ]
            .iter()
            .enumerate()
            {
                let bytes = reg.read().to_ne_bytes();
                for (j, b) in bytes.iter().enumerate() {
                    let at = i * 4 + j;
                    if at < block.len() {
                        block[at] = *b;
                    }
                }
            }
        }

        // `source_enable` / `source_disable` / `read_into` are all inherited.
        //
        // `read_into` in particular: the per-block wait, the partial-fill
        // refusal and the stop-on-every-exit all live in [`draw_blocks`], one
        // `no_std` function that a host test drives directly. A private copy
        // of that loop here would be the fork this refactor exists to close —
        // the reason the shipped ordering was untestable is that it lived in
        // one of these, inside a `cfg` no host build ever compiles.
        //
        // A partial fill is still an error, and it is worth restating why
        // because nothing in this impl enforces it any more: a 32-byte
        // request spans two 24-byte blocks, the second can stall after the
        // first has already been written, and the caller is
        // `FuseSeedSource`, whose buffer is `Zeroizing::new([0u8; NONCE_LEN])`.
        // Reporting that as success hands the DRBG nonce slot 24 fresh bytes
        // and 8 zeros and calls it a valid draw, which the all-zero check
        // below it cannot see.
    }
}

#[cfg(all(feature = "device", target_arch = "arm"))]
pub use rp2350::{ClockReady, Rp2350Probe, Rp2350Timer, Rp2350Trng};


// ---------------------------------------------------------------------------
// US-1005: the one type a caller asks for randomness from.
// ---------------------------------------------------------------------------

/// Why a [`DrbgTrng`] could not serve bytes.
///
/// Distinct from [`SeedError`], which is *why it could not be seeded*: this
/// is the runtime condition, and it is deliberately not collapsed into a
/// bool so a caller can tell "the generator is spent and nobody re-seeded it"
/// from anything it might add later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrbgTrngError {
    /// The re-seed budget is spent and the generator refused to generate
    /// (`DrbgError::ReseedRequired`). The generator did not wrap around and
    /// did not reset its counter: an un-refreshed stretch of a single
    /// peripheral block is exactly the output the epic's `RESEED_INTERVAL`
    /// exists to bound, and silently continuing would move that bound to
    /// infinity.
    ReseedRequired,
    /// The re-seed itself failed, so there is no fresh state to continue
    /// from. The generator is left untouched — a half-applied re-seed would
    /// be neither the old state nor a correctly seeded one.
    Reseed(SeedError),
}

/// [`DrbgTrngError::ReseedRequired`] as a `rand_core` error code: the re-seed
/// budget is spent and the generator refuses to generate.
///
/// At [`rand_core::Error::CUSTOM_START`], the documented floor for
/// user-defined codes, so it cannot collide with `rand` / `getrandom`'s. The
/// two codes are distinct because a caller — and an operator reading a log —
/// needs to tell "budget spent, retry later" from "the peripheral stopped
/// answering, reset the device".
pub const RNG_ERR_RESEED_REQUIRED: u32 = rand_core::Error::CUSTOM_START;

/// [`DrbgTrngError::Reseed`] as a `rand_core` error code: the re-seed itself
/// was refused because the peripheral produced no validated block.
pub const RNG_ERR_RESEED_REFUSED: u32 = rand_core::Error::CUSTOM_START + 1;

impl fmt::Display for DrbgTrngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DrbgTrngError::ReseedRequired => write!(f, "DRBG re-seed required, budget spent"),
            DrbgTrngError::Reseed(e) => write!(f, "DRBG re-seed refused: {e}"),
        }
    }
}

impl From<DrbgError> for DrbgTrngError {
    fn from(e: DrbgError) -> Self {
        match e {
            DrbgError::ReseedRequired => DrbgTrngError::ReseedRequired,
        }
    }
}

/// The device's randomness source: an HMAC-DRBG seeded from the hardware
/// peripheral (US-1002/US-1003), presented through the [`Trng`] seam the rest
/// of the tree already uses.
///
/// # Why this is the only type a caller should hold
///
/// The EPIC's Phase 1 outcome is that *every* nonce comes from a conditioned,
/// re-seeded generator. That is a statement about the whole tree, and a
/// statement about the whole tree is not enforceable from inside one module —
/// which is why `tests/scripts/check_rng_path.py` exists and why
/// `check_rng_path.py`'s allowlist is a short, commented list rather than a
/// silent exemption. [`Rp2350Trng`] is still public and still implements
/// [`Trng`]: the *bootstrap* draws (the boot-entropy record itself, the two
/// bring-up binaries) legitimately need a peripheral before any generator can
/// exist, and a DRBG cannot be the source of the material that seeds it.
///
/// # The draw count went up, and that is the point
///
/// Before this type, every request that needed randomness touched the
/// peripheral. Now one peripheral touch underwrites
/// [`crate::drbg::RESEED_INTERVAL`] × [`crate::drbg::OUTLEN`] bytes of
/// output, so the *number* of unbounded waits on the request path falls by
/// that factor. It does not fall to zero — see
/// `docs/known-gate-divergences.md` (D-8) for what remains unbounded
/// on the device and why the host tests here cannot close it.
///
/// # Failing closed
///
/// Two failure modes, both surfaced rather than papered over:
///
/// * **Instantiation** — [`DrbgTrng::try_new`] returns
///   `Err(SeedError)`. There is no constructor that hands back an unseeded
///   generator, because an unseeded one produces nothing at all and a
///   caller that ignored the error would be signing with zeros.
/// * **Re-seed exhaustion** — `generate` returns
///   [`DrbgError::ReseedRequired`], and this type turns that into
///   [`DrbgTrngError::ReseedRequired`] rather than re-seeding on its own.
///   Re-seeding needs a peripheral draw, and *this* type holds no peripheral:
///   letting it draw would put a peripheral handle back on the request path,
///   which is the arrangement US-1005 exists to end. The caller owns the
///   re-seed, and US-1006's `Rng` backend is where that happens.
///
/// [`Trng::random_bytes`] cannot express either error — its signature returns
/// `()`. That is a property of the pre-existing seam, not a choice made here,
/// and it is why the fallible surface ([`DrbgTrng::try_random_bytes`]) is the
/// one new code should call. The [`Trng`] impl exists for the callers the
/// trait already had, and its failure behaviour is documented on it.
pub struct DrbgTrng<S: SeedSource> {
    drbg: Drbg,
    source: S,
}

impl<S: SeedSource> DrbgTrng<S> {
    /// Instantiate from `source` on the device's re-seed policy, or refuse.
    ///
    /// There is deliberately no infallible constructor. `SeedError` carries
    /// the four distinct refusals US-1003 defines (missing record, wrong
    /// length, present-but-depleted, wedged peripheral) precisely so a caller
    /// can tell a fresh device from a failing one, and collapsing them into a
    /// `panic!` here would throw away the only thing they are for.
    pub fn try_new(mut source: S) -> Result<Self, SeedError> {
        let drbg = Drbg::seed_from_device(&mut source)?;
        Ok(Self { drbg, source })
    }

    /// Generate `buf.len()` bytes, re-seeding through the source if the
    /// budget is spent.
    ///
    /// The single place the re-seed happens, so the "one peripheral touch
    /// underwrites N requests" accounting has exactly one implementation to
    /// be right about.
    pub fn try_random_bytes(&mut self, buf: &mut [u8]) -> Result<(), DrbgTrngError> {
        match self.drbg.generate(buf) {
            Ok(()) => Ok(()),
            Err(DrbgError::ReseedRequired) => {
                // `reseed_from` is atomic on refusal (US-1004), so a failed
                // re-seed leaves the spent generator spent — it does not
                // reopen the budget with a state that was never refreshed.
                self.drbg
                    .reseed_from(&mut self.source)
                    .map_err(DrbgTrngError::Reseed)?;
                self.drbg.generate(buf)?;
                Ok(())
            }
        }
    }

    /// The generator, for the tests that assert on policy rather than output
    /// (`RESEED_INTERVAL`, the re-seed counter). Not a route to the state:
    /// [`Drbg`]'s own `Debug` is opaque and `k`/`v` are private.
    pub fn drbg(&self) -> &Drbg {
        &self.drbg
    }
}

impl<S: SeedSource> Trng for DrbgTrng<S> {
    /// # This cannot report failure, and that is a real limitation
    ///
    /// [`Trng::random_bytes`] returns `()`, so a re-seed refusal has nowhere
    /// to go. It is **not** swallowed silently: `buf` is left exactly as the
    /// caller passed it (untouched, not zeroed, not filled with a constant)
    /// and the error is logged via `defmt` on device. A caller that needs to
    /// know — which is every caller on a request path, and is the whole of
    /// US-1006 — must call [`DrbgTrng::try_random_bytes`] instead.
    ///
    /// Zeroing the buffer was considered and rejected: a caller that failed to
    /// check for an error would then sign with a nonce of zeros, which is a
    /// *worse* outcome than the pre-refusal state because it is a known
    /// constant rather than merely stale. Leaving it alone keeps the failure
    /// visible in the caller's own buffer.
    ///
    /// # The `debug_assertions` tripwire — read before adding a caller
    ///
    /// Leaving the buffer alone is only safe if a starved generator cannot be
    /// mistaken for output. The concrete sharp end is
    /// `apps/fido/src/device_app.rs`, where `p256::SecretKey::random` reaches
    /// this method through `crypto::TrngAdapter` and would yield an **all-zero
    /// `hkey`** — a persistent device secret — with no error anywhere. So the
    /// refusal trips a `debug_assertions` assert **on device builds only**.
    ///
    /// Why a debug assert and not a `panic!` on device: the *release* profile
    /// here has `debug-assertions = false` (root `Cargo.toml`, `[profile.release]`),
    /// so this is a development-time tripwire and changes no shipped
    /// behaviour. US-1006 exists to remove panics from the **request** path,
    /// and this is the **boot** path, where a loud failure is strictly better
    /// than a stale key — but the boot path is also where `init_drbg` has
    /// already refused fatally if the peripheral is dead, so the case is
    /// practically unreachable in the field and must not be given a new
    /// production panic. `check_rng_path.py` additionally forbids
    /// `.random_bytes(` outside a commented allowlist, so a *new* caller has
    /// to be declared with a reason.
    ///
    /// Why device-only: the host suite *deliberately* starves a generator
    /// through this seam, to prove it leaves the caller's buffer alone
    /// (`platform/tests/drbg_trng.rs::a_failing_generator_leaves_the_buffer_untouched`),
    /// and a universal assert would take that coverage with it. Off-device
    /// there is no persistent secret at stake, so there is nothing for the
    /// assert to protect.
    fn random_bytes(&mut self, buf: &mut [u8]) {
        let outcome = self.try_random_bytes(buf);
        // Device-only, and the reason is that this is the only build where the
        // consequence exists: `apps/fido/src/device_app.rs` persists an
        // all-zero `hkey` through this seam. The host suite deliberately
        // starves a generator to prove the buffer is left alone
        // (`a_failing_generator_leaves_the_buffer_untouched`), and firing
        // there would take that coverage with it. The release profile has
        // `debug-assertions = false`, so this changes no shipped behaviour —
        // it is a development-time tripwire on the path that matters.
        #[cfg(all(feature = "device", target_arch = "arm"))]
        debug_assert!(
            outcome.is_ok(),
            "Trng::random_bytes cannot report failure and left the caller's buffer \
             untouched. A starved generator must never look like output: use \
             DrbgTrng::try_random_bytes (or the trussed Rng backend's \
             try_fill_bytes) at any call site that can act on a refusal."
        );
        #[cfg(all(feature = "device", target_arch = "arm"))]
        if let Err(e) = outcome {
            // Two static strings rather than a `defmt::Format` derive:
            // nothing else in `platform` derives it, and adding it to one
            // error type for the sake of a log line would make the log
            // format part of this type's public surface for no other
            // reason.
            match e {
                DrbgTrngError::ReseedRequired => {
                    defmt::error!("DrbgTrng: re-seed required, budget spent");
                }
                DrbgTrngError::Reseed(_) => {
                    defmt::error!("DrbgTrng: re-seed refused (SeedError)");
                }
            }
        }
        #[cfg(not(all(feature = "device", target_arch = "arm")))]
        let _ = outcome;
    }

    /// US-1007: the generator already had a fallible draw; this is where it
    /// reaches the trait, so a `Trng`-generic caller (the FIDO
    /// `TrngAdapter`, the `crypto` keygen) can be handed this generator and
    /// still *told* when it refuses.
    ///
    /// Both [`DrbgTrngError`] variants map to [`TrngError::Stalled`], and
    /// the collapse is deliberate: `TrngError` is the coarse "this source
    /// could not produce" answer, and the two codes that separate "retry
    /// later" from "the peripheral stopped" are preserved where a caller can
    /// act on them — `DrbgTrng::try_random_bytes` and the trussed `Rng`
    /// backend's `try_fill_bytes`, which is what US-1006 wired. Collapsing
    /// here loses no decision: nobody at the `Trng` level can act on the
    /// difference.
    fn try_random_bytes(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        // Inherent method, not the trait one — named explicitly so the two
        // cannot be confused for each other in a stack trace.
        Self::try_random_bytes(self, buf).map_err(|_| TrngError::Stalled)
    }
}

impl<S: SeedSource> fmt::Debug for DrbgTrng<S> {
    /// Opaque for the same reason [`Drbg`]'s is: the state is the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DrbgTrng")
            .field("drbg", &self.drbg)
            .finish_non_exhaustive()
    }
}
