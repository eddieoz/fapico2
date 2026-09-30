#![no_main]
//! US-920 — fuzz the CCID bulk-OUT reassembler.
//!
//! Drives `fapico2_firmware::ccid_reasm::CcidReassembler` with arbitrary
//! byte chunks, in serve-loop order (feed → poll-drain, ≤64-byte chunks,
//! clock advancing with the stream). The property under test: **no panic,
//! ever** — and the resync invariant: after any junk (including the wedge
//! attack stream), a fresh complete message assembles and processes
//! untouched.

use fapico2_firmware::ccid_reasm::{CcidReassembler, Reasm, PARTIAL_TIMEOUT_MS};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Serve-loop parity: one bulk-OUT packet (≤64 B) per feed, the state
    // machine polled after every feed, clock advancing with the stream
    // (a 2 KB stream already crosses the 2 s window).
    static NOW_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    NOW_MS.store(0, core::sync::atomic::Ordering::Relaxed);
    let mut reasm = CcidReassembler::new(|| NOW_MS.load(core::sync::atomic::Ordering::Relaxed));

    for chunk in data.chunks(64) {
        NOW_MS.fetch_add(chunk.len() as u64, core::sync::atomic::Ordering::Relaxed);
        let _resync = reasm.feed(chunk);
        loop {
            match reasm.poll() {
                Reasm::Idle | Reasm::Partial => break,
                Reasm::Overflow { .. } | Reasm::TimedOut(_) => break,
                Reasm::Ready(msg) => {
                    // Length invariant: a Ready slice is exactly one
                    // message — 10-byte header + the advertised dwLength.
                    assert!(msg.len() >= 10, "Ready slice shorter than a header");
                    let dw = u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
                    assert_eq!(msg.len(), 10 + dw, "Ready slice inconsistent with dwLength");
                    let len = msg.len();
                    reasm.consume(len);
                }
            }
        }
    }

    // Resync invariant: whatever the junk was, a fresh complete message
    // (GetSlotStatus, seq 0x2A) assembles and processes untouched once the
    // window has elapsed over any stale partial.
    let fresh: [u8; 10] = [0x65, 0, 0, 0, 0, 0, 0x2A, 0, 0, 0];
    NOW_MS.fetch_add(PARTIAL_TIMEOUT_MS, core::sync::atomic::Ordering::Relaxed);
    let _ = reasm.feed(&fresh);
    match reasm.poll() {
        Reasm::Ready(msg) => assert_eq!(msg, &fresh, "fresh message corrupted by junk"),
        other => panic!("fresh message after resync did not process: {other:?}"),
    }
});
