//! no_std CTAP-HID framing for the device serve loop (US-386).
//!
//! Port of the CTAP-HID layer from `emul_main.rs` (TCP emulation) to the
//! RP2350 build: 64-byte reports, INIT/continuation fragmentation, the 500 ms
//! transaction timeout, keepalives and the INIT handshake. Heapless
//! throughout — the reassembly buffer is a `heapless::Vec<u8, CTAPHID_MAX_MSG>`
//! (the 7609-byte CTAPHID message cap).
//!
//! US-705.1: this module is the pure, host-testable half of the transport —
//! no USB endpoints, and the wall clock is injected as a `fn() -> u64`
//! monotonic millisecond source — so the CID/INIT discipline (channel
//! allocation and the mid-transaction busy rule) carries unit tests.

use heapless::Vec as HeaplessVec;

/// CTAP HID report size.
pub const HID_REPORT_SIZE: usize = 64;
/// Payload capacity of an INIT (first) report: 64 - 7 header bytes.
pub const HID_FIRST_PAYLOAD: usize = HID_REPORT_SIZE - 7;
/// Payload capacity of a continuation report: 64 - 5 header bytes.
pub const HID_CONT_PAYLOAD: usize = HID_REPORT_SIZE - 5;

pub const CTAP_HID_INIT: u8 = 0x06;
pub const CTAP_HID_CBOR: u8 = 0x10;
pub const CTAP_HID_PING: u8 = 0x01;
pub const CTAP_HID_MSG: u8 = 0x03; // U2F (CTAP1) over HID
pub const CTAP_HID_WINK: u8 = 0x08;
pub const CTAP_HID_KEEPALIVE: u8 = 0x3B;
pub const CTAP_HID_ERROR: u8 = 0x3F;
const TYPE_INIT: u8 = 0x80;

// CTAPHID error codes (CTAP spec §11.2.4).
pub const HID_ERR_INVALID_CMD: u8 = 0x01;
pub const HID_ERR_INVALID_SEQ: u8 = 0x04;
pub const HID_ERR_TIMEOUT: u8 = 0x05;
pub const HID_ERR_CHANNEL_BUSY: u8 = 0x06;
pub const HID_ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const HID_ERR_INVALID_LEN: u8 = 0x03;

/// Broadcast channel: only INIT may be issued from it.
pub const HID_CID_BROADCAST: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
/// Reserved channel: no commands accepted from it.
pub const HID_CID_RESERVED: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
/// US-921 review (P0-1): the CCID-bridge channel ([0,0,0,1], the constant
/// `BRIDGE_CHANNEL` in `fapico2_fido::device_app`). The allocator never
/// issues it: an HID channel equal to the bridge channel would alias the
/// bridged FIDO shell's session state.
pub const HID_CID_BRIDGE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
/// US-921 review (P0-1): the first channel of the domain-separated HID
/// presence-tag space (bit 31 set — see
/// `fapico2_fido::presence_tag_from_channel`). The allocator never issues a
/// channel at or above this: those values are presence tags for the HID
/// transport, not CIDs, and must stay disjoint from the CCID presence-tag
/// space (small integers: mgmt 0x1C/0x1E, OATH 0x04/0x03).
pub const HID_CID_DOMAIN_SEPARATED: u32 = 0x8000_0000;

/// Maximum CTAPHID message size per the FIDO spec (7609 bytes).
pub const CTAPHID_MAX_MSG: usize = 7609;
/// Transaction idle timeout before a 0x3F/TIMEOUT error frame is sent.
const TRANSACTION_TIMEOUT_MS: u64 = 500;

/// Reassembles fragmented CTAP-HID frames (heapless).
pub struct HidAssembler {
    channel: [u8; 4],
    cmd: u8,
    total_len: usize,
    received: usize,
    payload: HeaplessVec<u8, CTAPHID_MAX_MSG>,
    expecting_cont: bool,
    seq: u8,
    /// Injected monotonic clock (ms); on device this is the embassy time
    /// driver, in tests a controllable fake.
    now_ms: fn() -> u64,
    last_activity_ms: u64,
}

/// Result of feeding one 64-byte report to the assembler.
#[derive(Debug)]
pub enum HidFeed {
    /// The frame is consumed; more continuation packets are needed (or the
    /// report was a stray continuation, which is dropped).
    NeedMore,
    /// A complete message is ready for dispatch — take it with
    /// [`HidAssembler::payload`]. (The payload stays in the assembler so
    /// this enum stays small on the no_std task stack.)
    Ready(u8),
    /// A framing error was detected; a 0x3F error frame must be sent to the
    /// given channel with the given error code.
    Err([u8; 4], u8),
}

impl HidAssembler {
    pub fn new(now_ms: fn() -> u64) -> Self {
        Self {
            channel: [0; 4],
            cmd: 0,
            total_len: 0,
            received: 0,
            payload: HeaplessVec::new(),
            expecting_cont: false,
            seq: 0,
            now_ms,
            last_activity_ms: now_ms(),
        }
    }

    /// The channel of the in-flight (or last) transaction.
    pub fn channel(&self) -> [u8; 4] {
        self.channel
    }

    /// The payload of the last completed transaction — valid after
    /// [`feed`](Self::feed) returned [`HidFeed::Ready`].
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// If a transaction has been idling awaiting continuations for too
    /// long, emit a TIMEOUT error frame and reset the transaction.
    pub fn check_timeout(&mut self) -> Option<([u8; 4], u8)> {
        if self.expecting_cont && (self.now_ms)() - self.last_activity_ms >= TRANSACTION_TIMEOUT_MS {
            self.expecting_cont = false;
            return Some((self.channel, HID_ERR_TIMEOUT));
        }
        None
    }

    /// Feed a raw HID report.
    pub fn feed(&mut self, frame: &[u8]) -> HidFeed {
        if frame.len() < 5 {
            return HidFeed::NeedMore;
        }

        let channel: [u8; 4] = [frame[0], frame[1], frame[2], frame[3]];
        let cmd_byte = frame[4];

        if cmd_byte & TYPE_INIT != 0 {
            // Init (first) packet
            if frame.len() < 7 {
                return HidFeed::NeedMore;
            }
            let cmd = cmd_byte & 0x7F;
            let total_len = u16::from_be_bytes([frame[5], frame[6]]) as usize;

            if channel == HID_CID_RESERVED
                || (channel == HID_CID_BROADCAST && cmd != CTAP_HID_INIT)
            {
                // Channel 0 is reserved outright; from the broadcast channel
                // only INIT is legal.
                return HidFeed::Err(channel, HID_ERR_INVALID_CHANNEL);
            }

            if self.expecting_cont && channel != self.channel {
                // US-705.1: any INIT-packet-shaped frame from a *different*
                // channel while a transaction is in flight is rejected with
                // CHANNEL_BUSY — a second INIT (broadcast or not) must never
                // silently preempt the in-flight transaction.
                return HidFeed::Err(channel, HID_ERR_CHANNEL_BUSY);
            }
            if self.expecting_cont && channel == self.channel && cmd != CTAP_HID_INIT {
                // New init command on the transaction channel mid-flight.
                self.expecting_cont = false;
                return HidFeed::Err(channel, HID_ERR_INVALID_SEQ);
            }

            if total_len > CTAPHID_MAX_MSG {
                self.expecting_cont = false;
                return HidFeed::Err(channel, HID_ERR_INVALID_LEN);
            }

            let chunk = &frame[7..];
            let take = chunk.len().min(total_len);

            self.channel = channel;
            self.cmd = cmd;
            self.total_len = total_len;
            self.received = take;
            self.payload.clear();
            self.payload
                .extend_from_slice(&chunk[..take])
                .ok();
            self.expecting_cont = true;
            self.seq = 0;
            self.last_activity_ms = (self.now_ms)();

            if self.received >= total_len {
                self.expecting_cont = false;
                return HidFeed::Ready(self.cmd);
            }
            HidFeed::NeedMore
        } else if self.expecting_cont {
            // Continuation packet — must match channel
            if channel != self.channel {
                return HidFeed::NeedMore;
            }
            let seq_byte = frame[4];
            if seq_byte != self.seq {
                self.expecting_cont = false;
                return HidFeed::Err(self.channel, HID_ERR_INVALID_SEQ);
            }
            let chunk = &frame[5..];
            let space_left = self.total_len.saturating_sub(self.received);
            let take = chunk.len().min(space_left);
            self.payload.extend_from_slice(&chunk[..take]).ok();
            self.received += take;
            self.seq = self.seq.wrapping_add(1);
            self.last_activity_ms = (self.now_ms)();

            if self.received >= self.total_len {
                self.expecting_cont = false;
                return HidFeed::Ready(self.cmd);
            }
            HidFeed::NeedMore
        } else {
            // Stray continuation without an init — drop it
            HidFeed::NeedMore
        }
    }
}

/// US-705.1: CTAP-HID channel allocator — the INIT handshake must hand out
/// a fresh channel per INIT instead of the constant `[0, 0, 0, 1]`, so two
/// hosts (or a re-INIT from the same host) can never alias one channel.
///
/// Heapless: allocation is a free-running counter that skips the reserved
/// and broadcast channels, so no CID is reused before the 32-bit wraparound.
/// (The story's alternative — folding the INIT nonce into the derived value —
/// is deliberately declined: a hostile nonce could be steered to collide with
/// an already-issued channel, recreating exactly the silent preemption this
/// story removes. The nonce stays in the signature as the allocation trigger.)
pub struct CidAllocator {
    counter: u32,
}

impl CidAllocator {
    /// Starts above the all-zero reserved channel.
    pub const fn new() -> Self {
        Self { counter: 0 }
    }
}

impl Default for CidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl CidAllocator {
    /// Test-only: place the free-running counter at an arbitrary value
    /// (US-921 review P0-1: lets the wraparound guard be exercised without
    /// 2^31 allocations).
    fn from_counter(counter: u32) -> Self {
        Self { counter }
    }
}

impl CidAllocator {
    /// Allocate the channel to answer one INIT handshake with.
    ///
    /// US-921 review (P0-1): never returns the broadcast, reserved, bridge
    /// ([0,0,0,1]) channels nor anything in the domain-separated high-bit
    /// space (0x8000_0000..=0xFFFFFFFF): those are the presence-tag domains,
    /// not CIDs. When the 31-bit CID space is exhausted the counter wraps
    /// back to the beginning (channel reuse after 2^31 − 3 allocations —
    /// the same free-running reuse story as before, bounded to the safe
    /// space).
    pub fn allocate(&mut self, nonce: &[u8]) -> [u8; 4] {
        let _ = nonce;
        loop {
            self.counter = self.counter.wrapping_add(1);
            if self.counter >= HID_CID_DOMAIN_SEPARATED {
                // The 31-bit CID space is exhausted: wrap to the start
                // (the next increment lands on 1 — the bridge channel,
                // skipped below like every reserved value).
                self.counter = 0;
                continue;
            }
            let cid = self.counter.to_be_bytes();
            if cid != HID_CID_BROADCAST
                && cid != HID_CID_RESERVED
                && cid != HID_CID_BRIDGE
            {
                return cid;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    static NOW_MS: AtomicU64 = AtomicU64::new(0);
    fn fake_now() -> u64 {
        NOW_MS.load(Ordering::Relaxed)
    }

    /// Build a 64-byte INIT-packet report for `channel` announcing
    /// `total_len` payload bytes, with the nonce in the first-report chunk.
    fn init_frame(channel: [u8; 4], nonce: &[u8], total_len: u16) -> [u8; HID_REPORT_SIZE] {
        let mut f = [0u8; HID_REPORT_SIZE];
        f[..4].copy_from_slice(&channel);
        f[4] = CTAP_HID_INIT | TYPE_INIT;
        f[5..7].copy_from_slice(&total_len.to_be_bytes());
        f[7..7 + nonce.len()].copy_from_slice(nonce);
        f
    }

    fn cont_frame(channel: [u8; 4], seq: u8, bytes: &[u8]) -> [u8; HID_REPORT_SIZE] {
        let mut f = [0u8; HID_REPORT_SIZE];
        f[..4].copy_from_slice(&channel);
        f[4] = seq;
        f[5..5 + bytes.len()].copy_from_slice(bytes);
        f
    }

    fn busy_check(alloc: &mut CidAllocator, _asm: &mut HidAssembler, nonce: &[u8]) -> [u8; 4] {
        let cid = alloc.allocate(nonce);
        assert_ne!(cid, HID_CID_BROADCAST, "CID must not be the broadcast channel");
        assert_ne!(cid, HID_CID_RESERVED, "CID must not be the reserved channel");
        cid
    }

    /// US-921 review (P0-1): the allocator never returns a domain-separated
    /// (high-bit) channel nor the CCID-bridge channel [0,0,0,1]. The HID
    /// presence tag space is `presence_tag_from_channel` (bit 31 set); the
    /// CCID consumers' presence tags are small integers (mgmt 0x1C/0x1E,
    /// OATH 0x04/0x03) — an allocated CID equal to any of them would let a
    /// same-tag "join" cross the transport boundary.
    #[test]
    fn allocator_never_returns_bridge_or_domain_separated_cid() {
        // Fresh allocator: the very first allocations skip the bridge
        // channel [0,0,0,1] (the CCID-bridged FIDO shell's constant
        // channel) — 1 is reserved, so counting starts at 2.
        let mut alloc = CidAllocator::new();
        assert_eq!(alloc.allocate(&[]), [0, 0, 0, 2], "bridge CID must be skipped");
        assert_eq!(alloc.allocate(&[]), [0, 0, 0, 3]);

        // Boundary: an allocator running out of the 31-bit CID space wraps
        // instead of entering the domain-separated high-bit space — every
        // returned CID keeps bit 31 clear and stays out of the reserved set.
        let mut alloc = CidAllocator::from_counter(HID_CID_DOMAIN_SEPARATED - 2);
        // Last CID of the safe space…
        let cid = alloc.allocate(&[]);
        assert_eq!(cid, [0x7F, 0xFF, 0xFF, 0xFF], "the last safe CID is issued");
        // …then the counter would step into the high-bit space: it wraps to
        // the start of the safe range instead (bridge channel skipped).
        for expected in 2u32..32 {
            let cid = alloc.allocate(&[]);
            let raw = u32::from_be_bytes(cid);
            assert!(
                raw < HID_CID_DOMAIN_SEPARATED,
                "CID {cid:?} entered the domain-separated presence-tag space"
            );
            assert_ne!(cid, HID_CID_BRIDGE, "bridge CID must never be issued");
            assert_ne!(cid, HID_CID_BROADCAST);
            assert_ne!(cid, HID_CID_RESERVED);
            assert_eq!(raw, expected, "the wrap restarts the safe range in order");
        }
    }

    /// US-705.1: a broadcast INIT is the only thing allocatable, and every
    /// INIT — including a re-INIT with the identical nonce — must get a
    /// distinct channel, never the constant alias `[0, 0, 0, 1]`-style reuse
    /// that let a second INIT silently preempt an in-flight transaction.
    #[test]
    fn init_broadcast_only_allocates_unique_cid() {
        let mut alloc = CidAllocator::new();
        let mut asm = HidAssembler::new(fake_now);

        // The assembler accepts a broadcast INIT (and only INIT).
        assert!(matches!(
            asm.feed(&init_frame(HID_CID_BROADCAST, &[1, 2, 3, 4, 5, 6, 7, 8], 8)),
            HidFeed::Ready(CTAP_HID_INIT)
        ));

        let cid1 = busy_check(&mut alloc, &mut asm, &[1, 2, 3, 4, 5, 6, 7, 8]);
        // Same nonce again (host retry / second probe): a NEW channel.
        let cid2 = busy_check(&mut alloc, &mut asm, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_ne!(cid1, cid2, "two INIT handshakes must not alias one CID");

        // Uniqueness holds over a long run; nothing is ever reserved.
        let mut seen = heapless::Vec::<[u8; 4], 128>::new();
        seen.push(cid1).unwrap();
        seen.push(cid2).unwrap();
        for i in 0u32..100 {
            let nonce = i.to_be_bytes();
            let cid = busy_check(&mut alloc, &mut asm, &nonce);
            assert!(!seen.contains(&cid), "CID {cid:?} reused");
            seen.push(cid).unwrap();
        }
    }

    /// US-705.1: an INIT from another (or the broadcast) channel while a
    /// transaction is in flight is refused with CHANNEL_BUSY and the
    /// in-flight transaction survives.
    #[test]
    fn init_from_other_channel_mid_transaction_is_busy() {
        let mut asm = HidAssembler::new(fake_now);
        let host: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

        // Two-report transaction from `host` (total 100 bytes).
        assert!(matches!(
            asm.feed(&init_frame(host, &[9; 8], 100)),
            HidFeed::NeedMore
        ));
        // A second INIT — broadcast or any other channel — cannot preempt.
        for chan in [HID_CID_BROADCAST, [0x55, 0x66, 0x77, 0x88]] {
            match asm.feed(&init_frame(chan, &[1; 8], 8)) {
                HidFeed::Err(c, code) => {
                    assert_eq!(c, chan);
                    assert_eq!(code, HID_ERR_CHANNEL_BUSY);
                }
                other => panic!("expected CHANNEL_BUSY for {chan:?}, got {other:?}"),
            }
        }
        // The original transaction still completes on its own channel
        // (57 first-report bytes + 43 continuation bytes = the 100 announced).
        match asm.feed(&cont_frame(host, 0, &[0xAA; 43])) {
            HidFeed::Ready(cmd) => {
                assert_eq!(asm.payload().len(), 100);
                assert_eq!(cmd, CTAP_HID_INIT);
            }
            other => panic!("in-flight transaction preempted: {other:?}"),
        }
    }

    /// The injected clock drives the transaction timeout (unchanged
    /// behavior, now host-testable).
    #[test]
    fn idle_transaction_times_out_via_injected_clock() {
        let mut asm = HidAssembler::new(fake_now);
        NOW_MS.store(0, Ordering::Relaxed);
        assert!(matches!(
            asm.feed(&init_frame(HID_CID_BROADCAST, &[9; 8], 200)),
            HidFeed::NeedMore
        ));
        NOW_MS.store(600, Ordering::Relaxed);
        let (chan, code) = asm.check_timeout().expect("timeout after 600 ms idle");
        assert_eq!(chan, HID_CID_BROADCAST);
        assert_eq!(code, HID_ERR_TIMEOUT);
    }
}
