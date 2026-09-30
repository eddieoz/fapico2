#![no_main]
//! US-384 — fuzz the CTAP2 CBOR parser.
//!
//! Drives `fapico2_fido::cbor::decode` with arbitrary bytes. This is the
//! untrusted-input entry point for CTAP2 command payloads; a **panic** (not an
//! `Err`) on malformed input is the failure mode we are guarding against.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // `decode` returns `Result`; only a panic is a failure, so ignore the value.
    let _ = fapico2_fido::cbor::decode(data);
});
