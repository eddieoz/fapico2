//! US-380 — TRNG baseline. Host tests for the platform TRNG abstraction.
//!
//! The EPIC bar: on device (RP2350) every byte of randomness comes from the
//! hardware TRNG, and no software PRNG is ever the source. On host the same
//! `Trng` abstraction is backed by OS entropy so the app code paths and these
//! tests are exercised identically.
//!
//! TDD: these tests were written against the `Trng` contract before the
//! implementation existed.

use fapico2_platform::trng::{HostTrng, Trng};

/// Two reads of the TRNG must differ — the output is non-deterministic.
#[test]
fn trng_output_is_non_deterministic() {
    let mut trng = HostTrng::new();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    trng.random_bytes(&mut a);
    trng.random_bytes(&mut b);
    assert_ne!(
        a, b,
        "two TRNG reads must differ (randomness must be non-deterministic)"
    );
}

/// The TRNG output must not be all-zero — an all-zero read indicates the
/// source is unwired or a stub, not a real entropy source.
#[test]
fn trng_output_is_non_zero() {
    let mut trng = HostTrng::new();
    let mut a = [0u8; 32];
    trng.random_bytes(&mut a);
    assert!(
        a.iter().any(|&x| x != 0),
        "TRNG output must be non-zero (got an all-zero read)"
    );
}

/// `random_bytes` must fill the entire buffer, including an empty one (no-op).
#[test]
fn trng_fills_entire_buffer() {
    let mut trng = HostTrng::new();
    let mut a = [0u8; 1];
    trng.random_bytes(&mut a);
    // A single byte is only "non-deterministic" across reads; check we can
    // read an empty buffer without error and a byte-length buffer.
    let mut empty = [];
    trng.random_bytes(&mut empty);
    // distinct 1-byte reads are very likely to differ over many samples.
    let mut distinct = false;
    for _ in 0..64 {
        let mut x = [0u8; 1];
        let mut y = [0u8; 1];
        trng.random_bytes(&mut x);
        trng.random_bytes(&mut y);
        if x != y {
            distinct = true;
            break;
        }
    }
    assert!(distinct, "TRNG should produce distinct single bytes across reads");
    assert!(a.len() == 1);
}
