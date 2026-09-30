//! US-920: pure CCID bulk-OUT message reassembly with a park timeout.
//!
//! The device serve loop (`tasks.rs`, device bins only) used to reassemble
//! CCID messages inline with two unbounded awaits: a partial header/payload
//! looped forever on a 10 ms retry, and the reply write parked until the
//! host ACKed. One aborted message therefore wedged the whole transport.
//! This module extracts the reassembly into a HAL-free state machine so the
//! park-timeout + resync behavior is host-testable:
//!
//! - a partial message older than [`PARTIAL_TIMEOUT_MS`] is dropped and the
//!   state resyncs (`feed` drops a stale partial *before* accepting fresh
//!   bytes, so the next SELECT always assembles cleanly — the Given/When/
//!   Then of the EPIC);
//! - an oversized `dwLength` is reported ([`Reasm::Overflow`]) with the
//!   state reset, so the serve loop can answer the CCID `6F 00`-class fail;
//! - complete messages are handed to the caller one at a time
//!   ([`Reasm::Ready`]), including messages pipelined in one bulk-OUT
//!   packet (the remainder survives in the buffer).
//!
//! Clock injection (` HidAssembler ` parity, US-705.1) keeps the module
//! deterministic on the host; the serve loop passes the embassy monotonic
//! clock.

use fapico2_platform::ccid::message::HEADER;

/// Max CCID message on the wire: 10-byte standard CCID header + body
/// (body cap = C `USB_BUFFER_SIZE` parity, 2048 + 16).
pub const MAX_WIRE: usize = 10 + 2048 + 16;

/// A partial message older than this window is dropped and the assembly
/// state resyncs (US-920; the EPIC's "e.g. 2 s").
pub const PARTIAL_TIMEOUT_MS: u64 = 2_000;

/// What a resync dropped: the byte count of the stale partial and, when its
/// 10-byte header had completed, the slot/seq needed to answer it with the
/// CCID aborted-bulk fail (`6F 00`-class DataBlock, seq-matched).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resync {
    /// Bytes of the dropped partial message.
    pub dropped: usize,
    /// bSlot of the dropped partial iff its header had completed.
    pub slot: Option<u8>,
    /// bSeq of the dropped partial iff its header had completed.
    pub seq: Option<u8>,
}

/// One step of the reassembly state machine ([`CcidReassembler::poll`]).
#[derive(Debug, PartialEq, Eq)]
pub enum Reasm<'a> {
    /// Nothing buffered: safe to park on the next bulk-OUT read.
    Idle,
    /// A partial message is buffered and inside the window: keep reading.
    Partial,
    /// One complete message (header + `dwLength` payload). The slice is
    /// valid until [`CcidReassembler::consume`] or the next `feed`.
    Ready(&'a [u8]),
    /// The header advertises more than the buffer can hold; the state was
    /// reset. Answer the `6F 00`-class fail for this (slot, seq).
    Overflow { slot: u8, seq: u8 },
    /// A partial message outlived [`PARTIAL_TIMEOUT_MS`]; the state was
    /// reset. Answer the aborted-bulk fail when the partial's header had
    /// completed.
    TimedOut(Resync),
}

/// CCID bulk-OUT message reassembler (US-920).
///
/// Owns the wire buffer the device serve loop previously kept inline in
/// `ccid_task` (`rx`/`have`), plus the partial-message deadline.
pub struct CcidReassembler {
    buf: [u8; MAX_WIRE],
    have: usize,
    /// Start timestamp of the current partial message (`None` = idle). Invariant:
    /// `have > 0` implies `Some`.
    started_ms: Option<u64>,
    now_ms: fn() -> u64,
}

impl CcidReassembler {
    /// New reassembler with an injected millisecond clock (host-testable).
    pub fn new(now_ms: fn() -> u64) -> Self {
        Self {
            buf: [0u8; MAX_WIRE],
            have: 0,
            started_ms: None,
            now_ms,
        }
    }

    /// Append received bulk-OUT bytes.
    ///
    /// If the buffered partial message is older than [`PARTIAL_TIMEOUT_MS`]
    /// it is dropped FIRST (resync), so `chunk` always assembles as a fresh
    /// message — the aborted message can never desynchronize the following
    /// one. Returns the resync info when a drop happened (the caller
    /// answers the CCID aborted-bulk fail).
    pub fn feed(&mut self, chunk: &[u8]) -> Option<Resync> {
        let resync = if self.is_stale() {
            let r = self.resync_info();
            self.reset();
            Some(r)
        } else {
            None
        };
        if self.have == 0 && !chunk.is_empty() {
            self.started_ms = Some((self.now_ms)());
        }
        // Defensive truncation: unreachable for a ≤ max-packet chunk on any
        // reachable state (complete messages are consumed before the buffer
        // fills), but junk must never panic the device.
        let space = self.buf.len() - self.have;
        let n = chunk.len().min(space);
        self.buf[self.have..self.have + n].copy_from_slice(&chunk[..n]);
        self.have += n;
        resync
    }

    /// Inspect the reassembly state (serve-loop step, before parking on the
    /// next bulk-OUT read).
    ///
    /// [`Reasm::Overflow`] and [`Reasm::TimedOut`] reset the state as a side
    /// effect; [`Reasm::Ready`] keeps the message until [`Self::consume`].
    pub fn poll(&mut self) -> Reasm<'_> {
        if self.have >= HEADER {
            let dw_length =
                u32::from_le_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
            // Checked add: the device target's usize is 32-bit, and a bare
            // `HEADER + dw_length` would wrap for a huge dwLength (release
            // builds compile the overflow away) — an attacker-controlled
            // header must land on the Overflow path, not on UB.
            match dw_length.checked_add(HEADER) {
                Some(total) if total <= self.buf.len() => {
                    if self.have >= total {
                        return Reasm::Ready(&self.buf[..total]);
                    }
                }
                _ => {
                    let slot = self.buf[5];
                    let seq = self.buf[6];
                    self.reset();
                    return Reasm::Overflow { slot, seq };
                }
            }
        }
        if self.is_stale() {
            let r = self.resync_info();
            self.reset();
            return Reasm::TimedOut(r);
        }
        if self.have == 0 {
            Reasm::Idle
        } else {
            Reasm::Partial
        }
    }

    /// Consume the [`Reasm::Ready`] message of length `len`: shift any
    /// pipelined remainder down. A remainder restarts the partial-message
    /// deadline (conservative: a stalled remainder resyncs within the
    /// window of its own start).
    pub fn consume(&mut self, len: usize) {
        debug_assert!(len <= self.have);
        self.buf.copy_within(len..self.have, 0);
        self.have -= len;
        self.started_ms = if self.have > 0 {
            Some((self.now_ms)())
        } else {
            None
        };
    }

    /// Drop the assembly state (resync).
    fn reset(&mut self) {
        self.have = 0;
        self.started_ms = None;
    }

    /// A partial message is buffered and outlived the window.
    fn is_stale(&self) -> bool {
        match self.started_ms {
            Some(t0) => (self.now_ms)().saturating_sub(t0) >= PARTIAL_TIMEOUT_MS,
            None => false,
        }
    }

    /// Metadata about the stale partial (slot/seq only when the 10-byte
    /// header had completed).
    fn resync_info(&self) -> Resync {
        Resync {
            dropped: self.have,
            slot: if self.have >= HEADER {
                Some(self.buf[5])
            } else {
                None
            },
            seq: if self.have >= HEADER {
                Some(self.buf[6])
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};
    use fapico2_platform::ccid::message::{PC_TO_RDR_GET_SLOT_STATUS, PC_TO_RDR_XFR_BLOCK};

    static NOW_MS: AtomicU64 = AtomicU64::new(0);
    fn fake_now() -> u64 {
        NOW_MS.load(Ordering::Relaxed)
    }
    fn advance(ms: u64) {
        NOW_MS.fetch_add(ms, Ordering::Relaxed);
    }

    /// A canonical GetSlotStatus (10-byte header, dwLength 0).
    fn slot_status_msg(seq: u8) -> [u8; HEADER] {
        [PC_TO_RDR_GET_SLOT_STATUS, 0, 0, 0, 0, 0, seq, 0, 0, 0]
    }

    /// An XfrBlock header advertising `dw_length` payload bytes.
    fn xfr_header(slot: u8, seq: u8, dw_length: u32) -> [u8; HEADER] {
        let mut m = [0u8; HEADER];
        m[0] = PC_TO_RDR_XFR_BLOCK;
        m[1..5].copy_from_slice(&dw_length.to_le_bytes());
        m[5] = slot;
        m[6] = seq;
        m
    }

    /// THE Given/When/Then of US-920: a half-header wedge stream, the
    /// window elapsing, and then a fresh SELECT-class message must process.
    #[test]
    fn fresh_message_processes_after_partial_timeout() {
        let mut reasm = CcidReassembler::new(fake_now);

        // Given: a wedged partial — 6 bytes of a header whose payload the
        // host never sends (the executed attack shape).
        let half = [0x6F, 0x64, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(reasm.feed(&half), None, "nothing stale yet");
        assert!(matches!(reasm.poll(), Reasm::Partial));

        // When: the 2 s window elapses with the message still incomplete.
        advance(PARTIAL_TIMEOUT_MS);

        // Then: the next fresh message assembles cleanly — the stale
        // partial is dropped before the new bytes are accepted.
        let fresh = slot_status_msg(0x2A);
        let resync = reasm.feed(&fresh).expect("stale partial must be dropped");
        assert_eq!(resync.dropped, 6);
        // Half header: no slot/seq to answer.
        assert_eq!(resync.slot, None);
        assert_eq!(resync.seq, None);
        match reasm.poll() {
            Reasm::Ready(msg) => assert_eq!(msg, &fresh),
            other => panic!("fresh message after timeout did not process: {other:?}"),
        }
    }

    /// A stale partial whose header DID complete is answered with a
    /// seq-matched aborted-bulk fail: poll reports its slot/seq.
    #[test]
    fn timed_out_partial_with_complete_header_reports_slot_seq() {
        let mut reasm = CcidReassembler::new(fake_now);

        let hdr = xfr_header(0, 0x7B, 100);
        assert_eq!(reasm.feed(&hdr), None);
        assert!(matches!(reasm.poll(), Reasm::Partial));

        advance(PARTIAL_TIMEOUT_MS);
        match reasm.poll() {
            Reasm::TimedOut(r) => {
                assert_eq!(r.dropped, HEADER);
                assert_eq!(r.slot, Some(0));
                assert_eq!(r.seq, Some(0x7B));
            }
            other => panic!("expected TimedOut, got {other:?}"),
        }

        // poll reset the state: the next message processes untouched.
        let fresh = slot_status_msg(0x2A);
        assert_eq!(reasm.feed(&fresh), None);
        match reasm.poll() {
            Reasm::Ready(msg) => assert_eq!(msg, &fresh),
            other => panic!("state not clean after TimedOut resync: {other:?}"),
        }
    }

    /// Inside the window a partial is never dropped — a slow-but-alive
    /// host keeps assembling.
    #[test]
    fn partial_inside_window_is_not_dropped() {
        let mut reasm = CcidReassembler::new(fake_now);

        let msg = slot_status_msg(0x2A);
        assert_eq!(reasm.feed(&msg[..6]), None);
        advance(PARTIAL_TIMEOUT_MS - 1);
        assert_eq!(reasm.feed(&msg[6..]), None);
        match reasm.poll() {
            Reasm::Ready(m) => assert_eq!(m, &msg),
            other => panic!("partial dropped inside the window: {other:?}"),
        }
    }

    /// The window is inclusive: exactly PARTIAL_TIMEOUT_MS stale drops.
    #[test]
    fn window_boundary_is_inclusive() {
        let mut reasm = CcidReassembler::new(fake_now);

        let hdr = xfr_header(0, 0x2A, 1);
        assert_eq!(reasm.feed(&hdr), None);
        advance(PARTIAL_TIMEOUT_MS);
        assert!(matches!(reasm.poll(), Reasm::TimedOut(_)));
    }

    /// An idle reassembler never spuriously resyncs — a long-silent bus
    /// must not drop the next message.
    #[test]
    fn idle_never_times_out() {
        let mut reasm = CcidReassembler::new(fake_now);

        advance(1_000_000_000);
        let fresh = slot_status_msg(0x2A);
        assert_eq!(reasm.feed(&fresh), None);
        match reasm.poll() {
            Reasm::Ready(msg) => assert_eq!(msg, &fresh),
            other => panic!("idle reassembler resynced: {other:?}"),
        }
    }

    /// A message split across bulk-OUT packets assembles; consuming it
    /// returns the reassembler to a clean idle state.
    #[test]
    fn split_message_assembles_and_consumes_clean() {
        let mut reasm = CcidReassembler::new(fake_now);

        let mut apdu = [0u8; HEADER + 3];
        apdu[..HEADER].copy_from_slice(&xfr_header(0, 0x01, 3));
        apdu[HEADER] = 0x00;
        apdu[HEADER + 1] = 0xA4;
        apdu[HEADER + 2] = 0x04;

        assert_eq!(reasm.feed(&apdu[..5]), None);
        assert!(matches!(reasm.poll(), Reasm::Partial));
        assert_eq!(reasm.feed(&apdu[5..]), None);
        match reasm.poll() {
            Reasm::Ready(m) => {
                assert_eq!(m, &apdu);
                let len = m.len();
                reasm.consume(len);
            }
            other => panic!("split message did not assemble: {other:?}"),
        }
        assert!(matches!(reasm.poll(), Reasm::Idle));
    }

    /// Two complete messages pipelined in one bulk-OUT chunk are handed
    /// over one at a time; the remainder survives the first consume.
    #[test]
    fn pipelined_messages_handled_one_at_a_time() {
        let mut reasm = CcidReassembler::new(fake_now);

        let m1 = slot_status_msg(0x2A);
        let m2 = slot_status_msg(0x2B);
        let mut both = [0u8; 2 * HEADER];
        both[..HEADER].copy_from_slice(&m1);
        both[HEADER..].copy_from_slice(&m2);

        assert_eq!(reasm.feed(&both), None);
        match reasm.poll() {
            Reasm::Ready(m) => {
                assert_eq!(m, &m1);
                reasm.consume(HEADER);
            }
            other => panic!("first pipelined message missing: {other:?}"),
        }
        match reasm.poll() {
            Reasm::Ready(m) => {
                assert_eq!(m, &m2);
                reasm.consume(HEADER);
            }
            other => panic!("second pipelined message missing: {other:?}"),
        }
        assert!(matches!(reasm.poll(), Reasm::Idle));
    }

    /// An oversized dwLength overflows: poll reports the header's slot/seq
    /// for the `6F 00` fail and the state resyncs — never parks.
    #[test]
    fn oversize_dw_length_overflows_and_resyncs() {
        let mut reasm = CcidReassembler::new(fake_now);

        let hdr = xfr_header(0, 0x7C, u32::MAX);
        assert_eq!(reasm.feed(&hdr), None);
        match reasm.poll() {
            Reasm::Overflow { slot, seq } => {
                assert_eq!(slot, 0);
                assert_eq!(seq, 0x7C);
            }
            other => panic!("oversize dwLength not detected: {other:?}"),
        }

        // State was reset by the Overflow poll.
        let fresh = slot_status_msg(0x2A);
        assert_eq!(reasm.feed(&fresh), None);
        match reasm.poll() {
            Reasm::Ready(msg) => assert_eq!(msg, &fresh),
            other => panic!("state not clean after Overflow resync: {other:?}"),
        }
    }

    /// Junk flood (incomplete headers filling the buffer) never panics and
    /// never desynchronizes: after it stops, a fresh message processes.
    #[test]
    fn junk_flood_never_panics_and_resyncs() {
        let mut reasm = CcidReassembler::new(fake_now);

        // Junk with an unreachable dwLength: the buffer fills, the chunk
        // feed truncates, and the window eventually drops the stale junk.
        let junk = [0xA5u8; 64];
        for _ in 0..(MAX_WIRE / junk.len() + 4) {
            reasm.feed(&junk);
            let _ = reasm.poll();
            advance(10);
        }
        // Force-drop anything stale, then the fresh message must process.
        advance(PARTIAL_TIMEOUT_MS);
        let fresh = slot_status_msg(0x2A);
        let _ = reasm.feed(&fresh);
        match reasm.poll() {
            Reasm::Ready(msg) => assert_eq!(msg, &fresh),
            other => panic!("junk flood desynchronized the reassembler: {other:?}"),
        }
    }
}
