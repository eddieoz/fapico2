//! US-1004 — the device's re-seed **policy**: how far a single stretch runs
//! before the generator must be re-derived from the fuse seed.
//!
//! US-1002 built the mechanism and pinned its ceiling ([`MAX_RESEED_INTERVAL`],
//! 2^48). This story picks the **operating** value, far below that ceiling,
//! and makes it a named constant with the reasoning attached. What is tested
//! here is therefore not the mechanism — the KATs in `platform::drbg` own
//! that — but the *properties the chosen value is supposed to have*:
//!
//! * it is nowhere near the mechanism's ceiling, so the clamp in
//!   [`Drbg::new`] is a backstop and not the policy;
//! * it bounds how much authenticator output rests on **one touch of a
//!   peripheral that can wedge permanently** — the re-seed draws, so this is
//!   the property that decides the value (see the reasoning on
//!   [`RESEED_INTERVAL`]) — pinned at compile time, because a statement
//!   about a constant should fail when the constant is edited;
//! * the boundary is where SP 800-90A §10.1.2.5 step 1 puts it — served at
//!   the interval, refused at the interval **plus one**;
//! * a refusal spends nothing, so a caller hammering a spent generator
//!   cannot wear the budget down further;
//! * a re-seed re-anchors the window to the **same** size rather than
//!   accumulating, so "keep re-seeding" is not a way to buy more output.
//!
//! That last one is the property the story names as *"the counter must not
//! reset to zero in a way that lets an attacker gain"*, and it is the one an
//! eyeball check would miss: a counter reset to `0` instead of `1` would
//! silently serve **one extra request per seed** and every other test here
//! would still pass.

use fapico2_platform::drbg::{
    Drbg, DrbgError, SeedError, SeedMaterial, SeedSource, MAX_RESEED_INTERVAL, OUTLEN,
    RESEED_INTERVAL,
};

/// A `SeedSource` that cannot seed — enough to name the fused constructor's
/// type without standing up a secure store here.
struct NeverSeeded;

impl SeedSource for NeverSeeded {
    fn seed(&mut self) -> Result<SeedMaterial, SeedError> {
        Err(SeedError::CKey(
            fapico2_platform::ckey::CKeyError::MissingBootEntropy,
        ))
    }
}

/// Arbitrary but fixed instantiate inputs — the policy does not depend on
/// them, and using constants keeps these tests off the host TRNG. On the
/// device path neither half is a constant: see `platform::drbg_seed`, where
/// the `nonce` half is a fresh TRNG draw on every seed. These are the
/// KAT/host inputs, and this file is about the *counter*, not the entropy.
const ENTROPY: [u8; 32] = [0x11u8; 32];
const NONCE: [u8; 8] = [0x22u8; 8];

/// Guard the step-indexed loops below, which have no other bound: an
/// interval far above the shipped one would otherwise spin for hours instead
/// of failing with a sentence that says what is wrong.
///
/// What it returns is simply the interval. That is not a helper worth having
/// as a function — it used to be `requests_per_seed`, an identity that read
/// like it encoded the served-count rule and did not. The rule it pretended
/// to state is actually arithmetic, and it is stated once, in the next
/// comment, where the off-by-one is explained.
fn assert_tractable(interval: u64) -> u64 {
    assert!(
        interval <= SPEND_CAP,
        "a re-seed interval of {interval} serves {interval} requests per seed, \
         over the {SPEND_CAP} this test will run; the device value is meant \
         to be orders of magnitude below the mechanism ceiling"
    );
    interval
}

/// **Requests served between one instantiate and the first refusal: exactly
/// `interval`.** Not a function — it is arithmetic, and it is worth saying
/// out loud once.
///
/// SP 800-90A §10.1.2.5 step 1 refuses when `reseed_counter >
/// reseed_interval`, and instantiate leaves the counter at `1`. The k-th
/// request is therefore answered while `k <= reseed_interval` and refused
/// at `k == reseed_interval + 1`.
///
/// The off-by-one is the whole point of pinning the count rather than the
/// first error. A re-seed that reset the counter to `0` — one past where
/// §10.1.2.4 step 4 puts it — would serve `interval + 1` blocks from every
/// seed it ever took, and no test that only checked "it still generates
/// after a re-seed" would notice.
///
/// A generator on the device policy.
fn device() -> Drbg {
    Drbg::new_device(&ENTROPY, &NONCE)
}

/// Generate one 32-byte block.
fn block() -> [u8; OUTLEN] {
    [0u8; OUTLEN]
}

/// The counting loop gives up here, so a generator that has stopped
/// refusing fails an assertion instead of hanging the suite.
///
/// This is a fixed test constant and **not** derived from
/// [`RESEED_INTERVAL`]: a value under test that is far too large must
/// produce a fast, legible failure, not a loop bounded by the number it was
/// supposed to be small. 16 × the shipped allowance is enough headroom to
/// catch "one extra request per seed" and still finish in milliseconds.
const SPEND_CAP: u64 = 1 << 15;

/// Generate until the generator refuses, and return how many it served.
/// Returns [`SPEND_CAP`] if it never does — which every caller below treats
/// as a failure, since none of them expects a number that large.
fn spend_to_exhaustion(d: &mut Drbg) -> u64 {
    let mut served = 0u64;
    let mut out = block();
    while served < SPEND_CAP {
        if d.generate(&mut out).is_err() {
            return served;
        }
        served += 1;
    }
    served
}

// ---------------------------------------------------------------------------
// (1) The value, and the properties it was chosen for.
// ---------------------------------------------------------------------------
//
// Pinned at **compile time**, in the `trng_wedge.rs` house style: these are
// statements about a constant, so a runtime assertion would only report them
// at the next `cargo test` and read as a tautology. Editing
// `RESEED_INTERVAL` past any of these bounds fails the moment the constant
// is saved, not the moment someone thinks to look.
//
// The value must be nowhere near the mechanism's ceiling. The ceiling is
// 2^48; a caller who passes `u64::MAX` and gets the clamp is a caller
// running a two-million-year budget, and this story exists so the shipped
// default is not that by accident.
const _: () = assert!(
    RESEED_INTERVAL < MAX_RESEED_INTERVAL,
    "the device interval must be chosen, not defaulted to the mechanism ceiling"
);

/// And not merely "below" — far below. The clamp in `Drbg::new` exists to
/// catch a mistake, so the policy has to be nowhere near it.
const _: () = assert!(
    RESEED_INTERVAL * 1024 <= MAX_RESEED_INTERVAL,
    "the device interval must be at least 10 bits below the mechanism ceiling"
);

/// The property the interval actually buys, stated as a bound.
///
/// Every re-seed touches a peripheral that can wedge permanently, so the
/// number that matters is how much authenticator output rests on **one**
/// touch. This pins that to 8 KiB, which is the shipped 2^8 × 32 B. The
/// older 128 KiB figure (the previous value's window, kept in the constant's
/// doc as the subordinate argument) would let a single peripheral touch
/// underwrite sixteen times as much.
///
/// Deliberately *not* the old `RESEED_INTERVAL * OUTLEN <= 128 * 1024`: that
/// gate passed the old value by exactly 32×, so it constrained nothing. This
/// one is tight enough that raising the interval past 2^8 fails to save.
const _: () = assert!(
    RESEED_INTERVAL * (OUTLEN as u64) <= 8 * 1024,
    "one peripheral touch must not underwrite more than 8 KiB of output"
);

/// An interval below 2 refuses the very first request, which is a policy
/// nobody wants by accident.
const _: () = assert!(RESEED_INTERVAL >= 2, "an interval below 2 refuses everything");

/// The runtime half: the shipped defaults are the shipped default, not a
/// convenience a caller has to remember to reach for. This is what makes the
/// constant load-bearing in the API rather than only in the documentation —
/// and it covers the *fused* constructor as well, because that is the one
/// the wiring will call, and it is the one that would otherwise still be
/// handed a caller-chosen interval.
#[test]
fn the_shipped_constructors_run_on_the_device_policy() {
    assert_eq!(device().reseed_interval(), RESEED_INTERVAL);

    // The fused path needs a SecureStore and a fuse row, which is a
    // platform-internal shape; the check that matters here is that
    // `seed_from_device` exists and takes no interval at all, so the
    // policy cannot be passed wrong. A caller that has to supply a number
    // here is a caller who can supply the wrong one.
    let _: fn(&mut NeverSeeded) -> Result<Drbg, SeedError> = Drbg::seed_from_device;
}

// ---------------------------------------------------------------------------
// (2) The boundary.
// ---------------------------------------------------------------------------

/// The brief's boundary test, spelled out: served up to and including
/// `reseed_interval` requests, refused at `reseed_interval + 1`.
#[test]
fn generation_is_served_up_to_the_interval_and_refused_after_it() {
    let mut d = device();
    let expected = assert_tractable(RESEED_INTERVAL);
    let mut out = block();

    for k in 0..expected {
        assert_eq!(
            d.generate(&mut out),
            Ok(()),
            "request {k} of {expected} must be served"
        );
    }
    // `reseed_interval` served. The next one is `reseed_interval + 1` and
    // must be the first refusal — no grace block, no rounding.
    assert_eq!(
        d.generate(&mut out),
        Err(DrbgError::ReseedRequired),
        "the first refusal must land exactly one request past the allowance"
    );
    assert_eq!(d.reseed_counter(), RESEED_INTERVAL + 1);
}

/// The mirror of the boundary test, and what makes it a boundary rather
/// than a coincidence: counted through to the refusal rather than
/// step-indexed, the count is exactly `interval` and not `interval + 1`.
#[test]
fn the_served_count_is_exactly_the_interval() {
    let mut d = device();
    let served = spend_to_exhaustion(&mut d);
    assert_eq!(
        served,
        RESEED_INTERVAL,
        "served {served} requests before refusing, expected {RESEED_INTERVAL}"
    );
}

// ---------------------------------------------------------------------------
// (3) A refusal spends nothing.
// ---------------------------------------------------------------------------

/// A spent generator stays spent, and hammering it does not make it worse.
/// A counter that advanced on the refusal path would let a caller convert
/// one `ReseedRequired` into an unbounded wait for whoever re-seeds next,
/// and — more to the point — would make the "served count" above depend on
/// how often the caller had already been told no.
#[test]
fn a_refusal_consumes_no_budget_and_the_refusal_sticks() {
    let mut d = device();
    spend_to_exhaustion(&mut d);
    let at = d.reseed_counter();
    let mut out = block();

    for _ in 0..16 {
        assert_eq!(d.generate(&mut out), Err(DrbgError::ReseedRequired));
    }
    assert_eq!(
        d.reseed_counter(),
        at,
        "a refused request must not advance the counter"
    );
}

// ---------------------------------------------------------------------------
// (4) The counter survives a re-seed, without accumulating.
// ---------------------------------------------------------------------------

/// A re-seed puts the counter back to **exactly 1** — SP 800-90A §10.1.2.4
/// step 4, and the number the served-count arithmetic above depends on.
/// Resetting to `0` instead would serve `interval + 1` blocks per seed,
/// forever, and would be invisible to every test that only checked "it
/// still generates after a re-seed".
#[test]
fn a_reseed_puts_the_counter_back_to_exactly_one() {
    let mut d = device();
    spend_to_exhaustion(&mut d);
    d.reseed(&ENTROPY);
    assert_eq!(d.reseed_counter(), 1);
}

/// The re-seed re-anchors a window of the **same** size. It does not
/// accumulate: five re-seeds buy five times the original allowance and no
/// more, so an adversary who can force re-seeds cannot compound the budget.
/// A counter that carried over, or that grew on re-seed, would show up here
/// as a rising count.
#[test]
fn repeated_reseeds_re_anchor_the_window_rather_than_accumulating_it() {
    let mut d = device();
    let expected = RESEED_INTERVAL;

    let mut totals = [0u64; 5];
    for slot in totals.iter_mut() {
        *slot = spend_to_exhaustion(&mut d);
        d.reseed(&ENTROPY);
    }

    for (i, served) in totals.iter().enumerate() {
        assert_eq!(
            *served, expected,
            "seed {i} served {served}, expected {expected}: the window must \
             not accumulate across re-seeds"
        );
    }
    // Stated as a total too, because "the same every time" is easier to
    // falsify than it looks: 5 × interval, never 5 × (interval + 1) and
    // never a running total.
    let total: u64 = totals.iter().sum();
    assert_eq!(total, 5 * expected, "five seeds, five equal windows");
}

// ---------------------------------------------------------------------------
// (5) The zero-length request.
// ---------------------------------------------------------------------------

/// §10.1.2.5 has no early return, so an empty request still runs the
/// trailing `Update` and still increments the counter. That is the
/// standard, and US-1002 pins it — but it has a consequence for the policy
/// that is worth pinning here too: a caller looping on zero-length requests
/// reaches the same exhaustion as one asking for real bytes, so "just call
/// it with nothing to be safe" is not a way around the re-seed.
#[test]
fn an_empty_request_spends_budget_at_the_device_interval() {
    let mut d = device();
    let expected = assert_tractable(RESEED_INTERVAL);
    for _ in 0..expected {
        assert_eq!(d.generate(&mut []), Ok(()));
    }
    assert_eq!(
        d.generate(&mut []),
        Err(DrbgError::ReseedRequired),
        "an empty request must not be a free way past the re-seed"
    );
}

// ---------------------------------------------------------------------------
// (6) The unit of the budget: a *request*, not a byte.
// ---------------------------------------------------------------------------
//
// US-1004 justified the interval with "at 2^8 × OUTLEN that is 8 KiB per
// draw", which reads as a per-byte ceiling. The code does not implement one:
// §10.1.2.5 increments `reseed_counter` by 1 per `Generate` call whatever the
// caller asked for, and `generate` takes a slice of any length.
//
// The doc on `RESEED_INTERVAL` now states the request as the unit. These
// tests are what keep that statement honest — they are the measurement the
// old wording never had, and if someone later makes the budget per-byte they
// will have to come here and decide what the new number is, rather than
// inheriting "8 KiB" from a comment.

/// The counter is charged **per call**, and the length of the call does not
/// change it. A 4-byte request and a 4-KiB request each cost one tick.
#[test]
fn the_budget_is_charged_per_request_and_not_per_byte() {
    for len in [1usize, 4, OUTLEN, 64, 512, 4096] {
        let mut d = device();
        let before = d.reseed_counter();
        let mut out = vec![0u8; len];
        d.generate(&mut out).unwrap();
        assert_eq!(
            d.reseed_counter(),
            before + 1,
            "a {len}-byte request must spend exactly one tick, not {}",
            len.div_ceil(OUTLEN).max(1)
        );
    }
}

/// The per-touch output window is `RESEED_INTERVAL × request length`, and
/// the request length is not capped — so **the window is a function of the
/// caller's request size, not a constant**. This is the claim the doc makes
/// and the reason it stopped publishing a byte figure.
///
/// The numbers below are the ones the doc talks around: the 64-byte draw the
/// boot pool fill uses (16 KiB per touch, twice the 8 KiB the old wording
/// implied) and a large single request, which the counter does not notice at
/// all.
#[test]
fn the_per_touch_window_scales_with_the_request_and_is_not_a_constant() {
    let interval = assert_tractable(RESEED_INTERVAL);

    for (label, len) in [("OUTLEN-sized", OUTLEN), ("the 64 B pool chunk", 64)] {
        let mut d = device();
        let mut buf = vec![0u8; len];
        for _ in 0..interval {
            d.generate(&mut buf).unwrap();
        }
        assert_eq!(
            d.generate(&mut buf),
            Err(DrbgError::ReseedRequired),
            "{label}: the budget must be spent after {interval} requests"
        );
        let window = interval as usize * len;
        if len == OUTLEN {
            assert_eq!(
                window, 8 * 1024,
                "8 KiB is what the window evaluates to *only* at OUTLEN-sized requests"
            );
        } else {
            assert_eq!(
                window, 16 * 1024,
                "at the 64 B the boot pool fill actually requests, one touch underwrites \
                 16 KiB — twice the figure the old wording published"
            );
        }
    }

    // And the length itself is unbounded by the budget: a single request far
    // past the whole per-touch window is still served, because the check is
    // made *before* the request runs. This is the reason the doc does not
    // promise a byte ceiling, and the reason per-block accounting was
    // rejected as a "fix" — it would narrow this, not close it.
    let mut d = device();
    let mut huge = vec![0u8; 64 * 1024];
    assert!(
        d.generate(&mut huge).is_ok(),
        "a request larger than the whole per-touch window must still be served; if this now \
         fails the budget has been capped by length, and the doc's 'nothing caps a request' \
         needs updating with whatever the cap is"
    );
}
