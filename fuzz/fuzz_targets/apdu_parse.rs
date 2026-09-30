#![no_main]
//! US-384 — fuzz the APDU parsers.
//!
//! Two untrusted-input APDU parsers, one per transport:
//!   - `iso7816::command::CommandView::try_from` — the ISO7816 command parser
//!     used by the OpenPGP and management apps (`apps/openpgp/src/lib.rs`).
//!   - `fapico2_fido::process_u2f_apdu` — the U2F (CTAP1) APDU parser.
//!
//! A **panic** (not an `Err`) on malformed input is the failure mode under
//! test.

use fapico2_fido::keystore::MemoryKeystore;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // ISO7816 APDU parser (OpenPGP / management path).
    let _ = iso7816::command::CommandView::try_from(data);

    // U2F APDU parser (FIDO path). A fresh in-memory keystore per iteration is
    // cheap and stateless, so every input is parsed in isolation. US-916
    // parity: the parser now takes the user-presence callback and the
    // per-device attestation identity (US-916 test parity:
    // `AttestationIdentity::generate_host`, `|| true` presence).
    let mut keystore = MemoryKeystore::new();
    let attestation = fapico2_fido::attestation::AttestationIdentity::generate_host();
    let _ = fapico2_fido::process_u2f_apdu(data, &mut keystore, || true, &attestation);
});
