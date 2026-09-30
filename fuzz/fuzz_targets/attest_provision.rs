#![no_main]
//! US-1053 — `fapico2_fido::attestation::provision`, the per-device
//! attestation identity (US-916).
//!
//! This is the parse-side twin of `tests/scripts/check_attestation_gate.py`.
//! That gate protects the *source* property — the firmware does not ship a
//! static key/cert pair. The property this target protects is the
//! **runtime** one: a store whose identity material is present but corrupt
//! must **fail closed**, never silently regenerate.
//!
//! Why absence of panic proves nothing here: a `provision()` that
//! regenerated on any unreadable slot would return `Ok`, look healthy, boot
//! the device and mint a *new* attestation identity. Every relying party
//! that ever saw a credential signed by the old identity is now looking at
//! an unverifiable signature, and nothing on the device says so. The
//! existing unit test (`provision_is_fresh_then_stable_and_parses`) only
//! covers the happy path, so this is exactly the case a fuzzer is for.
//!
//! The fuzzer seeds the two identity slots — the 32-byte plain scalar and
//! the chunked DER certificate — with attacker bytes in every combination
//! (present/absent/empty, valid- or invalid-scalar, well-formed or
//! truncated certificate) and asserts:
//!
//! 1. **fail closed** — when the scalar slot is present, `provision` either
//!    errors or returns an identity built *from the stored bytes*. A result
//!    whose key differs from the persisted scalar is a silent regeneration.
//! 2. **no silent rewrite** — whenever the scalar slot is present, the
//!    certificate slot is byte-identical afterwards. Provisioning writes are
//!    only ever legitimate on the `NotFound` (fresh-device) path.
//! 3. **the fresh path still works** — with no scalar slot at all, the
//!    applet mints an identity: a valid P-256 key and a DER SEQUENCE. The
//!    target must not be satisfiable by simply refusing everything, which is
//!    why this third assertion exists.
//!
//! # Red-under-mutation (the evidence that these assertions bite)
//!
//! Routing a corrupt scalar or certificate back to the fresh-provision arm
//! instead of `Err(Corrupt)` — i.e. a pre-fail-closed build — turns
//! assertions 1 and 2 red. See `.superpowers/sdd/report-P6.md`.

use std::vec::Vec;

use fapico2_fido::attestation::{
    provision, ATTEST_CERT_MAX, ATTEST_CERT_SLOT, ATTEST_KEY_SLOT, AttestationIdentity,
};
use fapico2_platform::secure_store::{chunked, HostSecureStore, SecureStore};
use fapico2_platform::trng::HostTrng;

/// How the identity slots were seeded for this case.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seed {
    /// Nothing present — the first-boot provisioning path.
    Absent,
    /// Scalar present, no certificate slot at all.
    KeyOnly,
    /// Both present, both attacker bytes.
    Both,
    /// Both present, but the scalar slot holds an empty value (a torn write).
    BothEmpty,
    /// Both present, certificate stored as a plain (non-chunked) entry —
    /// the shape a C-firmware-era or half-migrated store can hold.
    BothPlainCert,
}

/// Read the certificate slot back, whichever framing it was written under.
/// `None` when the slot does not exist or does not decode at all — the
/// distinction matters, so both are returned distinctly.
fn read_cert(store: &mut HostSecureStore) -> CertView {
    let mut buf = [0u8; ATTEST_CERT_MAX];
    match chunked::read_chunked(store, ATTEST_CERT_SLOT, &mut buf) {
        Ok(n) => CertView::Chunked(buf[..n].to_vec()),
        Err(_) => {
            let mut buf = [0u8; ATTEST_CERT_MAX];
            match store.read(ATTEST_CERT_SLOT, &mut buf) {
                Ok(n) => CertView::Plain(buf[..n].to_vec()),
                Err(_) => CertView::Absent,
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
enum CertView {
    Absent,
    Plain(Vec<u8>),
    Chunked(Vec<u8>),
}

/// Read the scalar slot back. `None` = the slot does not exist (the fresh
/// path); `Some(bytes)` = whatever length is stored, including zero.
fn read_key(store: &mut HostSecureStore) -> Option<Vec<u8>> {
    let mut buf = [0u8; 32];
    match store.read(ATTEST_KEY_SLOT, &mut buf) {
        Ok(n) => Some(buf[..n].to_vec()),
        Err(_) => None,
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Bounded: the property is a decision, not a parse of arbitrary size.
    let cert_bytes: Vec<u8> = data.iter().copied().take(192).collect();
    // The scalar is 32 bytes; take whatever the fuzzer offers and pad, so
    // both "wrong length" and "valid length, invalid scalar" are reachable.
    let mut scalar = [0x5Au8; 32];
    for (i, b) in data.iter().take(32).enumerate() {
        scalar[i] = *b;
    }

    let seeds = [
        Seed::Absent,
        Seed::KeyOnly,
        Seed::Both,
        Seed::BothEmpty,
        Seed::BothPlainCert,
    ];
    for seed in seeds {
        let mut store = HostSecureStore::new();
        match seed {
            Seed::Absent => {}
            Seed::KeyOnly => {
                store
                    .write(ATTEST_KEY_SLOT, &scalar)
                    .expect("the store accepts a 32-byte scalar");
            }
            Seed::Both => {
                store
                    .write(ATTEST_KEY_SLOT, &scalar)
                    .expect("the store accepts a 32-byte scalar");
                chunked::write_chunked(&mut store, ATTEST_CERT_SLOT, &cert_bytes)
                    .expect("the store accepts the framed certificate");
            }
            Seed::BothEmpty => {
                store
                    .write(ATTEST_KEY_SLOT, &[])
                    .expect("the store accepts an empty value");
                chunked::write_chunked(&mut store, ATTEST_CERT_SLOT, &cert_bytes)
                    .expect("the store accepts the framed certificate");
            }
            Seed::BothPlainCert => {
                store
                    .write(ATTEST_KEY_SLOT, &scalar)
                    .expect("the store accepts a 32-byte scalar");
                store
                    .write(ATTEST_CERT_SLOT, &cert_bytes)
                    .expect("the store accepts a plain certificate");
            }
        }

        let key_before = read_key(&mut store);
        let cert_before = read_cert(&mut store);

        let mut trng = HostTrng::new();
        let outcome = provision(&mut trng, &mut store);

        let key_after = read_key(&mut store);
        let cert_after = read_cert(&mut store);

        match key_before {
            // -- fresh device: the one path that MAY mint --------------
            None => {
                let identity: AttestationIdentity =
                    outcome.expect("an absent scalar slot must provision a fresh identity");
                assert_eq!(
                    key_after.as_deref(),
                    Some(identity.key().to_bytes().as_slice()),
                    "the freshly minted scalar is not what was persisted",
                );
                let cert = match &cert_after {
                    CertView::Chunked(v) => v.as_slice(),
                    CertView::Plain(v) => v.as_slice(),
                    CertView::Absent => panic!("the minted certificate was not persisted"),
                };
                assert_eq!(
                    cert,
                    identity.cert_bytes(),
                    "the persisted certificate is not the minted one",
                );
                assert_eq!(cert.first(), Some(&0x30), "the minted cert is not a DER SEQUENCE");
                assert!(cert.len() <= ATTEST_CERT_MAX);
            }
            // -- the scalar slot is present: LOAD ONLY, or refuse -------
            Some(stored) => {
                // -- 1. fail closed -------------------------------------
                if let Ok(identity) = &outcome {
                    assert_eq!(
                        identity.key().to_bytes().as_slice(),
                        stored.as_slice(),
                        "provision returned an identity whose key is NOT the persisted \
                         scalar -- the corrupt identity was silently regenerated",
                    );
                    assert_eq!(
                        identity.cert_bytes(),
                        cert_after_view(&cert_after).as_slice(),
                        "provision returned a certificate that is not the stored one",
                    );
                }
                // -- 2. no silent rewrite --------------------------------
                assert_eq!(
                    key_after.as_deref(),
                    Some(stored.as_slice()),
                    "provision rewrote the scalar slot while it was present ({} -> {:?})",
                    stored.len(),
                    key_after.as_ref().map(|k| k.len()),
                );
                assert_eq!(
                    cert_after, cert_before,
                    "provision rewrote the certificate slot while the scalar was present",
                );
                // An empty stored scalar can never be a P-256 key, and a
                // scalar with no certificate is not a provisioned pair.
                if stored.is_empty() {
                    assert!(
                        outcome.is_err(),
                        "an empty scalar slot must fail closed, not regenerate",
                    );
                }
                if stored.len() == 32 && cert_before == CertView::Absent {
                    assert!(
                        outcome.is_err(),
                        "a stored scalar with no certificate is not a provisioned pair \
                         and must fail closed",
                    );
                }
            }
        }
    }
});

/// The certificate bytes as they were found, regardless of framing.
fn cert_after_view(view: &CertView) -> Vec<u8> {
    match view {
        CertView::Absent => Vec::new(),
        CertView::Plain(v) | CertView::Chunked(v) => v.clone(),
    }
}
