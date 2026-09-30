//! US-933: APDU-level trace of the CCID command path — **capture build only**.
//!
//! Gated behind the `apdu-trace` cargo feature (off by default: the
//! production binary compiles every call site and this module out; the
//! feature is NOT in `default`/`device`/`emulation`, so no ordinary build
//! picks it up). Unlike the US-922 `dbg-log` diagnostic channel, this
//! feature is deliberately **allowed in the release profile** — the failing
//! transport US-933 must capture is a release image (US-929: the dev-profile
//! device build dark-boots pre-main) — so the capture procedure is:
//!
//! 1. build the release image with `--features apdu-trace`
//!    (`cargo build --release --features apdu-trace`),
//! 2. flash it, reproduce the failing `gpg --edit-card` session,
//! 3. drain the trace and **reflash the clean release image** afterwards.
//!
//! ⚠️ The trace records full APDU bytes: the VERIFY / CHANGE REFERENCE DATA
//! commands carry PIN material in the clear inside the trace ring. It is a
//! dedicated capture build, never a shipping configuration.
//!
//! Log surface: the US-922/S-721-2 dbg-ladder RAM ring (`dbg.rs`) — the same
//! 512 × 24 B ring, drained over the CTAP-HID vendor command 0x42. Capture
//! builds pin the drain CID to the fixed `a5 5a a5 5a` (no probe is attached
//! to pull an RTT-printed channel); dbg-log builds keep the per-boot random
//! channel printed to the RTT console only. The HID task and its endpoints
//! are independent of `ccid_task`, so the ring is retrievable after a
//! CCID-side failure.
//!
//! Record format (event codes below; the host-side decoder is
//! `tests/scripts/us933_pull_trace.py`):
//!
//! * `E_APDU_SESS` — emitted once at [`init`]: `a` = per-boot session tag
//!   (4 bytes, BE, TRNG-drawn) that heads the trace dump.
//! * `E_APDU_REQ` — per request APDU: `a` = request length, `b` = per-session
//!   request sequence number. Followed by `ceil(len/8)` `E_APDU_CHUNK`
//!   records carrying the request bytes (8 bytes per record: `a` = bytes
//!   0–4 BE, `b` = bytes 4–8 BE; the trailing partial chunk is padded with
//!   zeros).
//! * `E_APDU_RSP` — per response: `a` = response length (incl. the 2-byte
//!   SW), `b` = status word (`SW1<<8 | SW2`). Followed by the same chunk
//!   records for the full response bytes — for GET DATA 4F this captures the
//!   AID response the epic asks for.

use crate::dbg::{log, E_APDU_CHUNK, E_APDU_REQ, E_APDU_RSP, E_APDU_SESS, T_CCID};

/// Per-boot session tag (BE bytes). `0` until [`init`] runs.
static mut SESSION_TAG: u32 = 0;

/// Per-session APDU sequence counter (wraps at 2^32).
static mut APDU_SEQ: u32 = 0;

/// Install the per-boot session tag and emit the `E_APDU_SESS` header record.
/// `tag` is the already-drawn TRNG value (the caller owns the entropy
/// boundary — see the `init_channel` precedent in `main`).
pub fn init(tag: [u8; 4]) {
    let v = u32::from_be_bytes(tag);
    unsafe {
        SESSION_TAG = v;
    }
    log(T_CCID, E_APDU_SESS, v, 0);
}

/// The active session tag (BE bytes; all-zero until [`init`]).
/// (`allow(dead_code)`: the drain-side consumer is the host decoder; the
/// device only writes the record.)
#[allow(dead_code)]
pub fn session_tag() -> [u8; 4] {
    unsafe { SESSION_TAG.to_be_bytes() }
}

/// Trace one full APDU exchange: the request bytes, then the response bytes
/// (including the SW) — one header record + chunk records per direction.
/// Called from the CCID serve loop's XfrBlock arm after dispatch, before the
/// persist gate. Synchronous (no `.await`) — the same single-writer
/// rationale as `dbg::log`.
pub fn trace_exchange(request: &[u8], response: &[u8]) {
    unsafe {
        let seq = APDU_SEQ;
        APDU_SEQ = APDU_SEQ.wrapping_add(1);
        // Request: header + bytes.
        log(T_CCID, E_APDU_REQ, request.len() as u32, seq);
        trace_bytes(request);
        // Response: header (len, SW) + bytes.
        let sw = if response.len() >= 2 {
            ((response[response.len() - 2] as u32) << 8) | response[response.len() - 1] as u32
        } else {
            0
        };
        log(T_CCID, E_APDU_RSP, response.len() as u32, sw);
        trace_bytes(response);
    }
}

/// Stream `bytes` into the ring as 8-byte chunk records (`a`/`b` are the
/// payload; the record timestamp + monotonic COUNT order the chunks).
fn trace_bytes(bytes: &[u8]) {
    for chunk in bytes.chunks(8) {
        let mut a = [0u8; 4];
        let mut b = [0u8; 4];
        let n = chunk.len().min(4);
        a[..n].copy_from_slice(&chunk[..n]);
        if chunk.len() > 4 {
            let m = (chunk.len() - 4).min(4);
            b[..m].copy_from_slice(&chunk[4..4 + m]);
        }
        log(
            T_CCID,
            E_APDU_CHUNK,
            u32::from_be_bytes(a),
            u32::from_be_bytes(b),
        );
    }
}
