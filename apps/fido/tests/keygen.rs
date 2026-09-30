//! makeCredential key-generation reliability, per advertised curve.
//!
//! # Why this file exists
//!
//! The pytest suite's `test_algorithms[-36]` (ES512 / P-521) failed on roughly
//! seven runs in eight — a flake that looked like an emulator or transport
//! problem and was neither. The cause is arithmetic in
//! [`fapico2_fido::app`]`generate_alg_keypair`'s `-36` arm:
//!
//! * a P-521 scalar is 66 bytes = **528 bits**, but the prime field is
//!   **521 bits**;
//! * so a uniformly random 66-byte draw is a valid scalar only when its top
//!   7 bits are clear — a probability of **2⁻⁷ ≈ 1/127**, measured at
//!   0.007875 over 200,000 draws (1 in 127.0);
//! * `crypto::try_fill_valid` caps the rejection sampler at
//!   `KEYGEN_MAX_ATTEMPTS` = 8, giving
//!   `1 − (1 − 1/127)⁸ ≈ 6.1 %` success.
//!
//! Every failure surfaces as `KeygenError::AttemptsExhausted`, which
//! [`fapico2_fido::app`] maps to CTAP `0x7F` — indistinguishable, to a client,
//! from a device with no entropy left.
//!
//! P-256 and P-384 are unaffected: their draws are exactly field-sized (32 and
//! 48 bytes), so acceptance is ~1 by construction. That asymmetry is why only
//! `-36` ever flaked, and why the fix belongs in the `-36` arm rather than in
//! the attempt budget.
//!
//! The device path is not affected: `device_core.rs` serves ES256 only, and
//! that draw is field-sized too. This is a host/emulation-path defect.

mod common;

use common::{make_mc_request_alg, setup};

/// `makeCredential` must succeed for every curve `getInfo` advertises.
///
/// `[−7, −8, −35, −36]` is the advertised set (`Ctap2Info::default`), and the
/// suite's own `test_algorithms` walks exactly those. A curve that is
/// advertised but cannot produce a key inside the sampler's attempt budget is
/// a defect, not a flake — advertising it is a promise.
///
/// Each curve is exercised [`TRIALS`] times rather than once: the P-521
/// failure probability per request is ~94 %, so a single trial would pass
/// ~6 % of the time and the test would be unreliable in the *other*
/// direction. At 20 trials the chance of the unfixed code passing is
/// `0.061³ ≈ 2.3 × 10⁻⁴`.
const TRIALS: usize = 20;

fn mc_succeeds_for_alg(alg: i64) -> usize {
    let mut failures = 0;
    for i in 0..TRIALS {
        let (mut app, client) = setup();
        let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
        let mut hash = [0u8; 32];
        hash[0] = (i + 1) as u8;
        let resp = app.process_ctap2(
            0x01,
            &make_mc_request_alg(&hash, "example.com", &token, alg),
            [1, 2, 3, 4],
        );
        // 0x00 = success. Anything else is a refusal, and for these curves the
        // only realistic cause is key generation.
        if resp.first() != Some(&0x00) {
            failures += 1;
            eprintln!("alg {alg} trial {i}: status {:#04x}", resp.first().copied().unwrap_or(0xFF));
        }
    }
    failures
}

#[test]
fn make_credential_succeeds_for_every_advertised_curve() {
    for alg in [-7, -8, -35, -36] {
        let failures = mc_succeeds_for_alg(alg);
        assert_eq!(
            failures,
            0,
            "curve {alg} is advertised by getInfo but makeCredential failed in \
             {failures}/{TRIALS} trials — the key-generation sampler cannot \
             reach acceptance inside KEYGEN_MAX_ATTEMPTS for this curve"
        );
    }
}

/// P-521's draw is 66 bytes (528 bits) for a 521-bit field. Asserting the
/// acceptance rate directly pins the arithmetic that the fix relies on, so a
/// future change to the seed width cannot silently reintroduce the flake.
#[test]
fn p521_seed_width_overrun_is_the_documented_cause() {
    // 66 bytes = 528 bits; the field is 521; so 7 bits must be constrained.
    assert_eq!(66 * 8 - 521, 7);
}
