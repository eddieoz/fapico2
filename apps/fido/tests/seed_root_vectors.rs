//! US-1734 — the seed-root known-answer vectors (EPIC FIDO-SEED-ROOT).
//!
//! # The literals are the artifact
//!
//! Every expected value in this file was computed with an **independent**
//! implementation — `python3 -c "import hmac,hashlib; …"` — and pasted in as
//! hex; the Rust side must match them, not generate them. A test that
//! computed its own expectation would be the implementation checking itself
//! against itself, which is exactly the failure mode the EPIC's vectors
//! scenario ("Then it equals HMAC-SHA256(key = S, data = …) **exactly**")
//! forbids.
//!
//! Reproduce the expectations (the EPIC's own command line):
//!
//! ```sh
//! python3 -c "import hmac,hashlib; \
//!   print(hmac.new(bytes.fromhex('42'*32), b'fapico2/fido-root/v1', \
//!                  hashlib.sha256).hexdigest())"
//! ```
//!
//! # What each vector pins
//!
//! 1. `derive_froot` — the one-HMAC root, for three fixed seeds (one of them
//!    all-zero, because a seed of zeroes must still derive *something
//!    deterministic*, not a refusal: the seed's entropy is the operator's
//!    custody problem, not `derive_froot`'s).
//! 2. The seedless arm of the twin accessors — pinned on the device twin in
//!    `seed_root_restore.rs::seedless_froot_is_the_hkey_bytes`
//!    (`froot() == hkey.to_bytes()` byte-for-byte on a twin that never saw a
//!    seed; EPIC §2 C5: the seedless path is frozen; changing the arm by one
//!    bit orphans every deployed passkey). This file pins the pure
//!    `derive_froot` the seeded arm calls.
//! 3. The seedless `derive_resident_scalar` vector — the US-1721 function
//!    keyed by the seedless root, so the guard is explicit that the frozen
//!    derivation survives the root's introduction unchanged (its scenario-3
//!    sibling lives in `resident_key_derivation.rs`; that suite drives the
//!    whole command path, this one pins the pure function).
//!
//! The non-wallet-roles isolation scenario (MSE pubkey, hkey, pinUvAuth-P1
//! ECDH unchanged by a seed install) is US-1734's third BDD scenario and
//! lives in the device-twin suite `seed_root_restore.rs` — it needs the
//! command path, not pure functions.

use fapico2_fido::crypto;

/// The domain string, restated here on purpose: if anyone changes
/// `crypto::FIDO_ROOT_DOMAIN`, these vectors fail *and the failure names the
/// freeze* — the domain string is part of the frozen wire-of-the-wallet
/// (EPIC §2: changing it orphans every restored wallet).
const FIDO_ROOT_DOMAIN: &[u8] = b"fapico2/fido-root/v1";

#[test]
fn froot_vectors_match_the_independent_implementation() {
    // froot(0x42*32) — the EPIC's own example command line.
    assert_eq!(
        hex(crypto::derive_froot(&[0x42u8; 32])),
        "b7d9757d49df0ec9707c32ccbd1113fac17517cf4f98257b8972e20ef432b2be"
    );
    // A second seed, so the test cannot pass on a single coincidence.
    assert_eq!(
        hex(crypto::derive_froot(&[0x77u8; 32])),
        "c8bd2db1ef9910ed0ea3058bb1ee80dc3e3b134b3bbd6482100bdaebc1114497"
    );
    // An all-zero seed: deterministic, not refused. `derive_froot` has no
    // opinion about the seed's entropy.
    assert_eq!(
        hex(crypto::derive_froot(&[0x00u8; 32])),
        "d161e531ee249c929ba34c488923eb921bcc85c45e5b80970620f156685f608c"
    );
}

#[test]
fn the_domain_string_is_the_frozen_one() {
    assert_eq!(crypto::FIDO_ROOT_DOMAIN, FIDO_ROOT_DOMAIN);
}

#[test]
fn seedless_resident_scalar_vector_is_frozen() {
    // The US-1721 first round, keyed by a fixed root and a fixed credential
    // ID: HMAC-SHA256(key = [0x11;32],
    //                 "fapico2/resident-key/v1" ‖ [0..32]).
    // The re-hash rounds are a ~2^-128 event and did not fire for this
    // input; the vector pins the shipped path.
    let root = [0x11u8; 32];
    let cred_id: [u8; 32] = core::array::from_fn(|i| i as u8);
    let scalar = crypto::derive_resident_scalar(&root, &cred_id)
        .expect("this fixed input derives on the first round");
    assert_eq!(
        hex(*scalar),
        "cd108bf6d11991ba6e4dd19b786a10bf590e7415dc275e668164e66307fc5be0"
    );
}

/// Bytes → lowercase hex, for matching the pasted literals.
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
