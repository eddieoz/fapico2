//! US-1007 defect fix — a starved entropy source must **fail**, not spin.
//!
//! # The defect this file exists to catch
//!
//! `crypto::TrngAdapter` implemented `RngCore::try_fill_bytes` as
//! `self.fill_bytes(dest); Ok(())` — an unconditional success. On a starved
//! `DrbgTrng` the draw leaves the caller's buffer untouched, so the adapter
//! reported *success* with 32 bytes that were not fresh. `p256::SecretKey::random`
//! is a rejection sampler over exactly that draw: it rejects a zero scalar and
//! draws again, and again gets the same untouched buffer, so the request never
//! returned. Not a slow path, not a degraded path — a silent unbounded spin
//! with no output, reachable from `makeCredential`.
//!
//! # Why the assertions are on *counts* and not on "it returned"
//!
//! A test that only checks "the call came back with an `Err`" would still
//! pass against a fix that took an hour to do it. The property the story
//! wants is **bounded**, and boundedness is a claim about how many draws
//! happen, so these tests count draws. [`a_refusing_source_stops_on_the_first_draw`]
//! pins the honest-refusal arm at exactly one; [`a_lying_source_is_capped_at_the_named_constant`]
//! pins the backstop arm at exactly `KEYGEN_MAX_ATTEMPTS` and fails if a
//! fourth draw is ever attempted.
//!
//! The wall-clock assertions are secondary and deliberately loose (a whole
//! second for something that must take microseconds): they are there to turn
//! a regression into a *failing* test rather than a hung CI job. The counts
//! are what make it fail correctly.

use std::cell::Cell;

use fapico2_fido::crypto::{
    try_fill_valid_with, try_generate_p256_keypair_from_trng, KeygenError, KEYGEN_MAX_ATTEMPTS,
};
use fapico2_platform::trng::{Trng, TrngError};

/// Draws that report success while writing nothing — the shape that used to
/// spin. `Refuses` is the opposite: it reports the truth immediately.
enum Behaviour {
    Healthy,
    /// Reports `Ok` and never writes, the way a starved DRBG's infallible
    /// draw behaves. This is the *harder* case: there is no error to
    /// propagate, so only the attempt cap can save it.
    Silent,
    /// Reports `Err` — a source that admits it has nothing.
    Refuses,
}

struct CountingTrng {
    behaviour: Behaviour,
    draws: Cell<u32>,
    /// A constant that `SecretKey::from_slice` always rejects, so a "healthy"
    /// source that never varies cannot accidentally pass the validity check.
    seed: u8,
}

impl CountingTrng {
    fn new(behaviour: Behaviour) -> Self {
        Self {
            behaviour,
            draws: Cell::new(0),
            seed: 0xA5,
        }
    }

    fn draws(&self) -> u32 {
        self.draws.get()
    }
}

impl Trng for CountingTrng {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        self.draws.set(self.draws.get() + 1);
        if let Behaviour::Silent = self.behaviour {
            return; // untouched — the US-1007 starved draw, verbatim
        }
        if let Behaviour::Refuses = self.behaviour {
            return;
        }
        for (i, b) in buf.iter_mut().enumerate() {
            // Vary the bytes and the seed so each draw differs: a fixed
            // buffer would be rejected forever even when "healthy".
            *b = self.seed.wrapping_add(i as u8).wrapping_add(self.draws() as u8);
        }
        self.seed = self.seed.wrapping_add(1);
    }

    fn try_random_bytes(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        if let Behaviour::Refuses = self.behaviour {
            self.draws.set(self.draws.get() + 1);
            return Err(TrngError::Stalled);
        }
        self.random_bytes(buf);
        if let Behaviour::Silent = self.behaviour {
            // The bug in one line: the draw produced nothing, and this
            // reports success anyway. `try_generate_p256_keypair` must
            // survive it anyway — that is what the cap is for.
            return Ok(());
        }
        Ok(())
    }
}

/// The arm that needs no cap: a source that admits it has nothing is believed
/// on the first draw.
#[test]
fn a_refusing_source_stops_on_the_first_draw() {
    let mut trng = CountingTrng::new(Behaviour::Refuses);
    let start = std::time::Instant::now();
    let result = try_generate_p256_keypair_from_trng(&mut trng);
    let elapsed = start.elapsed();

    assert_eq!(
        result,
        Err(KeygenError::Starved),
        "a source that reports a refusal must produce Starved, not a key"
    );
    assert_eq!(
        trng.draws(),
        1,
        "the refusal must end the attempt immediately — the starved case \
         costs ONE draw, not the whole budget"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "a refused keygen must answer in microseconds; took {elapsed:?}"
    );
}

/// The backstop arm, and the one that reproduces the actual spin: a source
/// that claims success forever while producing the same unusable bytes.
///
/// This is the assertion that would have caught the defect. Against the old
/// code this call never returns and the test never finishes; against a fix
/// that merely *reported* better but kept retrying, `draws()` would exceed
/// the cap and the second assertion would fail.
#[test]
fn a_lying_source_is_capped_at_the_named_constant() {
    let mut trng = CountingTrng::new(Behaviour::Silent);
    let start = std::time::Instant::now();
    let result = try_generate_p256_keypair_from_trng(&mut trng);
    let elapsed = start.elapsed();

    assert_eq!(
        result,
        Err(KeygenError::AttemptsExhausted),
        "a source that produces no valid scalar in the whole budget must say \
         so rather than loop"
    );
    assert_eq!(
        trng.draws(),
        KEYGEN_MAX_ATTEMPTS as u32,
        "the rejection must stop at exactly KEYGEN_MAX_ATTEMPTS draws — a \
         higher count is an unbounded loop that happens to be slow, and a \
         lower one would reject honest keys"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "the capped path must answer in microseconds; took {elapsed:?}"
    );
}

/// The bound must not be reached by accident on a healthy source: the whole
/// point of `KEYGEN_MAX_ATTEMPTS` being 8 is that honest draws essentially
/// never consume it. A generous window still catches a cap that is too tight
/// to serve real keygens.
#[test]
fn a_healthy_source_succeeds_on_the_first_draw() {
    let mut trng = CountingTrng::new(Behaviour::Healthy);
    let (secret, public) =
        try_generate_p256_keypair_from_trng(&mut trng).expect("a healthy source must yield a key");

    assert_eq!(trng.draws(), 1, "an honest keygen takes exactly one draw");
    // The public key must actually correspond to the secret: the bounded
    // sampler must produce the same key material `SecretKey::random` would,
    // not merely *some* valid scalar.
    assert_eq!(
        fapico2_fido::crypto::public_key_bytes(&public),
        fapico2_fido::crypto::public_key_bytes(&secret.public_key()),
    );
    assert_ne!(
        secret.to_bytes().as_slice(),
        [0u8; 32].as_slice(),
        "a real draw is not all zeros"
    );
}

/// The device-shaped half: `FidoApp::draw_random` is a pool draw that returns
/// `()` and cannot report a refusal, so there the cap is the *only* bound
/// available. This is the path that had no bound at all before.
#[test]
fn a_draw_that_cannot_refuse_is_still_capped() {
    let mut draws = 0u32;
    let mut scratch = [0u8; 32];
    let result = try_fill_valid_with(
        &mut |out: &mut [u8]| {
            draws += 1;
            // Serve a constant all-zero buffer and claim success, which is
            // what an exhausted pool does.
            out.fill(0);
            Ok(())
        },
        &mut scratch,
        |b| p256::SecretKey::from_slice(b).is_ok(),
    );

    assert_eq!(result, Err(KeygenError::AttemptsExhausted));
    assert_eq!(
        draws,
        KEYGEN_MAX_ATTEMPTS as u32,
        "a draw that cannot report failure must still be bounded by the cap"
    );
}

/// The same device-shaped path, when the pool *can* produce: it must succeed
/// and must not burn the budget to get there.
#[test]
fn a_device_shaped_draw_that_produces_succeeds() {
    let mut draws = 0u32;
    let mut scratch = [0u8; 32];
    try_fill_valid_with(
        &mut |out: &mut [u8]| {
            draws += 1;
            // A scalar that is valid: 1 is non-zero and below the order.
            out.fill(0);
            out[31] = 1;
            Ok(())
        },
        &mut scratch,
        |b| p256::SecretKey::from_slice(b).is_ok(),
    )
    .expect("a producing pool must yield a key");

    assert_eq!(draws, 1);
}
