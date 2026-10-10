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

/// US-1505: `CTAPHID_CANCEL` (`0x11`) — CTAPHID §11.2.9, the host's "abandon
/// this request".
///
/// The value is not in dispute: `fido2/hid/__init__.py:79` declares
/// `CANCEL = 0x11` and `fido2/hid/__init__.py:158` puts
/// `TYPE_INIT | CTAPHID.CANCEL` straight into the report it writes, and
/// `pico-keys-sdk/src/usb/hid/ctap_hid.h:90` has
/// `#define CTAPHID_CANCEL (TYPE_INIT | 0x11)`. What §11.2.9 does **not**
/// require is a reply frame, and this firmware deliberately sends none —
/// see [`CTAP2_ERR_KEEPALIVE_CANCEL`] and the note on the dispatch arm in
/// `hid_serve`.
pub const CTAP_HID_CANCEL: u8 = 0x11;

/// `CTAPHID_KEEPALIVE` payload byte 1: PROCESSING (0x01).
///
/// `fido2/ctap.py:37-41` declares `class STATUS(IntEnum): PROCESSING = 1;
/// UPNEEDED = 2` and `fido2/hid/__init__.py:225` does
/// `STATUS(struct.unpack_from(">B", recv)[0])` inside a `try` whose
/// `ValueError` arm raises `ConnectionFailure("Invalid keepalive status")`.
///
/// That is the whole reason there are exactly two constants here and no
/// third: a status byte outside `{0x01, 0x02}` is not "a keepalive the host
/// ignores", it is a **transport failure** in the host, and the connection
/// dies rather than the ceremony.
pub const CTAPHID_KEEPALIVE_PROCESSING: u8 = 0x01;

/// `CTAPHID_KEEPALIVE` payload byte 1: UP_NEEDED (0x02) — the device is
/// waiting for a touch. See [`CTAPHID_KEEPALIVE_PROCESSING`].
pub const CTAPHID_KEEPALIVE_UPNEEDED: u8 = 0x02;

/// US-1505/US-1506: the byte a cancelled or expired CTAP2 consent window
/// answers with — `CTAP2_ERR_KEEPALIVE_CANCEL`, **0x2D**.
///
/// ## Why 0x2D and not this crate's own `Ctap2Response::KeepAliveCancel`
///
/// `fapico2_fido::ctap2::Ctap2Response::KeepAliveCancel` is declared
/// `= 0x2C` (`apps/fido/src/ctap2.rs:69`), and that value is the odd one
/// out. Every implementation and, more to the point, every *client* in
/// this ecosystem puts the code at `0x2D`:
///
/// * `fido2/ctap.py:144-147` (the `fido2` 2.2.1 this repository is built
///   against — AGENTS.md §2) — `UNSUPPORTED_OPTION = 0x2B`,
///   `INVALID_OPTION = 0x2C`, **`KEEPALIVE_CANCEL = 0x2D`**,
///   `NO_CREDENTIALS = 0x2E`;
/// * `pico-fido/src/fido/ctap.h:176` and `pico-fido2/src/fido/ctap.h:176`
///   — `#define CTAP2_ERR_KEEPALIVE_CANCEL 0x2D`;
/// * `RS-Key/crates/rsk-fido/src/error.rs:31` — `KeepAliveCancel = 0x2d`,
///   and its emulator drives that literal byte
///   (`RS-Key/tools/emu/src/hid_tests.rs:207` answers `vec![0x2d]`).
///
/// Reproduce with the installed client:
///
/// ```text
/// $ python -c "import fido2.ctap as c; print(hex(c.CtapError.ERR.KEEPALIVE_CANCEL))"
/// 0x2d
/// ```
///
/// The consequence of emitting `0x2C` is not cosmetic. `fido2` decodes a
/// CTAP2 answer with `status = response[0]; if status != 0x00: raise
/// CtapError(status)` (`fido2/ctap2/base.py:285-287`), so a `0x2C` arrives
/// as `ERR.INVALID_OPTION` and `fido2/client/__init__.py:114-135` maps that
/// to `ClientError.ERR.BAD_REQUEST` — a client-side complaint about the
/// *request* — instead of `ClientError.ERR.TIMEOUT`, which is what
/// `KEEPALIVE_CANCEL` is mapped to at `client/__init__.py:105-110`. The
/// story this byte exists for is "the ceremony was abandoned, not that your
/// request was malformed", and only one of the two spellings says that.
///
/// US-1505/1506 are confined to `firmware/src/`, so the enum is left alone
/// and the corrected byte is stated here. Renumbering
/// `Ctap2Response::KeepAliveCancel` to `0x2D` (which would also leave
/// `0x2D` free of the current `InvalidOption`/`KeepAliveCancel` shift) is
/// the follow-up, and it is safe: `KeepAliveCancel` had no producer anywhere
/// in the tree until this story, so the only thing the old value ever did
/// was mislead a reader.
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;

/// `capFlags` byte of the CTAPHID_INIT reply — **0x05, both bits, on purpose.
///
/// Two incompatible bit assignments for this one byte are live at once, and
/// they disagree about what `0x04` means:
///
/// | bit | CTAP 2.1 spec §11.2.1.1 | pico-keys-sdk / Yubico `fido2` (de facto) |
/// |---|---|---|
/// | `0x01` | **CBOR** | **WINK** |
/// | `0x02` | NMSG | LOCK (unused) |
/// | `0x04` | **WINK** | **CBOR** |
///
/// (Evidence for the right-hand column: `pico-keys-sdk/src/usb/hid/ctap_hid.h`
/// `CAPFLAG_WINK 0x01` / `CAPFLAG_CBOR 0x04`, and `fido2/hid/__init__.py`
/// `class CAPABILITY(IntFlag): WINK = 0x01; CBOR = 0x04`. The C reference sends
/// exactly this pair — `resp->capFlags = CAPFLAG_WINK | CAPFLAG_CBOR` at
/// `pico-keys-sdk/src/usb/hid/hid.c:451`.)
///
/// So `0x04` alone is a trap **under the spec column only**: a spec reader
/// calls it "WINK yes, **CBOR no**" — the device announces it has no CTAP2
/// while serving CTAP2 happily. Under the de-facto column it reads as "CBOR
/// supported", which is the right answer by accident.
///
/// ## How strong that claim is — measured, and weaker than it reads
///
/// An earlier version of this paragraph said flatly that "a spec-reading host
/// never offers the key as a passkey authenticator at all — the US-1507
/// discovery symptom". **That was not established**, and the A/B probe in
/// `docs/webauthn-discovery-ab.md` is what says so:
///
/// * the differing bit is **`0x01`**, and `0x01` is **WINK under every
///   convention verifiable on this machine**. The de-facto column is verified
///   by *executing* `fido2.hid.CAPABILITY`; the spec column could not be
///   verified here at all (the reference fetch was rejected). The whole claim
///   rests on the unverified column;
/// * the CBOR bit **`0x04` is set on both boards**. Our pre-fix board sent
///   `0x04`, the C reference sends `0x05`, and both therefore already read as
///   "CBOR supported" under the de-facto convention — the one every
///   first-party tool actually uses;
/// * so `0x05` is **reference parity, not a demonstrated fix**. The probe
///   proves which bytes differ between two boards. It does not prove which
///   byte a browser acts on, and it did not observe a browser at all.
///
/// The value stays `0x05` because that is what the reference sends and because
/// it is harmless under the convention that *is* verified — not because it has
/// been shown to repair discovery. Do **not** "simplify" this back to a single
/// `0x04` on the strength of the reasoning the earlier draft gave: that byte is
/// the regression this constant exists to prevent, and the argument that
/// actually keeps it is parity with the C reference.
///
/// The device serves both capabilities, which is what makes `0x05` honest
/// rather than merely safe: CBOR on `CTAP_HID_CBOR` and WINK acknowledged on
/// `CTAP_HID_WINK`, both arms in `firmware/src/hid_serve.rs`'s `dispatch`.
/// `init_reply_advertises_cbor_and_wink_under_both_conventions` decodes the
/// reply under each assignment and fails if either reader could conclude
/// "no CTAP2".
pub const CTAPHID_INIT_CAP_FLAGS: u8 = 0x05;

/// Length of the CTAPHID_INIT reply payload: nonce(8) + cid(4) +
/// versionInterface(1) + versionMajor(1) + versionMinor(1) + versionBuild(1) +
/// capFlags(1).
pub const CTAPHID_INIT_REPLY_LEN: usize = 17;

/// The Nostr interface's INIT `capFlags` (US-1661, design §A.8.3 #8): **0x00
/// — a claim of nothing**.
///
/// The `capFlags` conventions disagree on which bit says what (see
/// [`CTAPHID_INIT_CAP_FLAGS`]'s history: the CTAP 2.1 spec reads 0x01 as CBOR,
/// the de-facto `fido2`/pico-keys-sdk reading reads 0x04 as CBOR — which is
/// why the FIDO interface's `0x05` sets both). The disagreement is exactly
/// what this constant exploits: under *either* convention, any nonzero value
/// among 0x01/0x04/0x05 claims CTAP2 or WINK capability. The Nostr interface
/// serves neither — it speaks the CTAPHID **framing** (INIT handshake, CID
/// allocation, PING, sequence packets, CANCEL, error codes) with the Nostr
/// command set in the vendor range 0x40–0x7F, and a generic CTAPHID client
/// must see a **non-CTAP2 vendor device**, not a second authenticator
/// competing with the FIDO interface. `NOSTR_INIT_CAP_FLAGS = 0x00` is the
/// only value that reads as CTAP2-incapable under both conventions at once.
///
/// `nostr_init_reply_claims_only_what_it_serves` decodes the reply under both
/// assignments and fails if either reader could conclude "CTAP2".
pub const NOSTR_INIT_CAP_FLAGS: u8 = 0x00;

/// The Nostr interface's vendor version bytes (US-1661): the **applet's**
/// version, not the YubiKey firmware pair the FIDO interface carries. The
/// FIDO interface reports the management applet's 5.4 pair because yubikit
/// reads INIT bytes 13..15 as `device_version` and gates YubiKey
/// management-protocol work on them; that rationale is FIDO-client-specific
/// and the Nostr interface must not inherit the claim — a yubikit client
/// never opens this interface (it selects on the FIDO usage page), and a
/// generic CTAPHID client should see *fapico2's* applet version. Kept in
/// step with `apps/nostr`'s `APPLET_VERSION` (major, minor) by test:
/// `nostr_init_reply_claims_only_what_it_serves` asserts the pair, so a
/// version bump that leaves this constant behind is a red.
pub const NOSTR_VENDOR_VERSION: (u8, u8, u8) = (0x00, 0x01, 0x00);

/// Build the 17-byte CTAPHID_INIT reply payload.
///
/// US-1507: extracted verbatim from the INIT arm of `dispatch` in
/// `firmware/src/hid_serve.rs` (it was `dispatch_hid_cmd` in
/// `firmware/src/tasks.rs` before the serve loop moved out). The construction
/// is pure stack work with no I/O, so the one byte that decides whether a host
/// discovers this key as a CTAP2 authenticator (see [`CTAPHID_INIT_CAP_FLAGS`])
/// is reachable from this module's unit tests. The firmware builds its reply
/// through *this* function, so the test covers the shipped bytes rather than a
/// copy of them.
///
/// `version_major` / `version_minor` / `version_build` are the **YubiKey**
/// firmware version bytes, not the CTAPHID protocol version: `yubikit` reads
/// INIT bytes 13..15 as `device_version` (`_ManagementCtapBackend`) and gates
/// `read_device_info` on `>= 4.1`. The caller passes the management applet's
/// `VERSION_MAJOR`/`VERSION_MINOR` (the same pair `TAG_VERSION` publishes).
/// `nonce` is truncated to the 8-byte INIT nonce size.
pub fn init_reply(
    nonce: &[u8],
    new_channel: &[u8; 4],
    version_major: u8,
    version_minor: u8,
    version_build: u8,
) -> [u8; CTAPHID_INIT_REPLY_LEN] {
    let mut inner = [0u8; CTAPHID_INIT_REPLY_LEN];
    let n = nonce.len().min(8);
    inner[..n].copy_from_slice(&nonce[..n]);
    inner[8..12].copy_from_slice(new_channel);
    inner[12] = 0x02; // versionInterface (2 = CTAP HID v2)
    inner[13] = version_major;
    inner[14] = version_minor;
    inner[15] = version_build;
    inner[16] = CTAPHID_INIT_CAP_FLAGS;
    inner
}

/// Build the 17-byte CTAPHID_INIT reply payload for the **Nostr** interface
/// (US-1661).
///
/// The framing is the shared CTAPHID v2 one (versionInterface stays 0x02 —
/// that is what the framing is), but the capability claim is
/// [`NOSTR_INIT_CAP_FLAGS`] (0x00 — CTAP2-incapable under both conventions)
/// and the version bytes are [`NOSTR_VENDOR_VERSION`], the applet's own, not
/// the YubiKey firmware pair. The body is a deliberate near-copy of
/// [`init_reply`] rather than a parameterized call: the FIDO reply's
/// capability byte is a *documented decision* ([`CTAPHID_INIT_CAP_FLAGS`])
/// that this interface must not inherit silently, and a `cap_flags`
/// parameter would let a future caller do exactly that.
pub fn nostr_init_reply(nonce: &[u8], new_channel: &[u8; 4]) -> [u8; CTAPHID_INIT_REPLY_LEN] {
    let mut inner = [0u8; CTAPHID_INIT_REPLY_LEN];
    let n = nonce.len().min(8);
    inner[..n].copy_from_slice(&nonce[..n]);
    inner[8..12].copy_from_slice(new_channel);
    inner[12] = 0x02; // versionInterface (2 = CTAP HID v2) — the framing
    inner[13] = NOSTR_VENDOR_VERSION.0;
    inner[14] = NOSTR_VENDOR_VERSION.1;
    inner[15] = NOSTR_VENDOR_VERSION.2;
    inner[16] = NOSTR_INIT_CAP_FLAGS;
    inner
}

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

            if self.expecting_cont && channel != self.channel && cmd != CTAP_HID_INIT {
                // US-705.1: any INIT-packet-shaped frame from a *different*
                // channel while a transaction is in flight is rejected with
                // CHANNEL_BUSY — a second INIT (broadcast or not) must never
                // silently preempt the in-flight transaction.
                //
                // **Except `CTAPHID_INIT` itself**, which the exemption is
                // keyed on. The handshake is the host's resynchronisation
                // primitive: CTAPHID §11.2.1 has it allocate a fresh channel
                // and reset the reassembly state, and the reference does
                // exactly that — `pico-keys-sdk/src/usb/hid/hid.c:403-424`
                // skips the whole busy guard when
                // `ctap_req->init.cmd != CTAPHID_INIT` is false, then
                // `hid.c:455-458` runs `msg_packet.len = msg_packet.current_len = 0`
                // for an INIT. Without the exemption a host whose
                // transaction was abandoned mid-flight has **no way back**:
                // every INIT it sends is answered CHANNEL_BUSY, and the only
                // thing that clears `expecting_cont` is the 500 ms
                // transaction timeout, so `test_ping_abort_from_different_cid`
                // wedges the channel for every later test.
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
    /// The exclusive upper bound this allocator's CIDs stay under — its own
    /// wrap constant. The FIDO interface wraps at [`HID_CID_DOMAIN_SEPARATED`]
    /// (bit 31 is the HID presence-tag domain); the Nostr interface
    /// (US-1659, design §A.8.3a #2) wraps at `0x2000_0000` because its tags
    /// are `0x6000_0000 | CID` (bits 30+29) and OR-folding is not injective:
    /// a free-running cid ≥ 0x2000_0000 would set bit 29 inside the CID
    /// itself, and cid `0x0000_0002`, `0x2000_0002` and `0x6000_0002` would
    /// all fold onto tag `0x6000_0002` — a silent cross-tab grant.
    limit: u32,
}

impl CidAllocator {
    /// Starts above the all-zero reserved channel, in the FIDO interface's
    /// 31-bit space.
    pub const fn new() -> Self {
        Self { counter: 0, limit: HID_CID_DOMAIN_SEPARATED }
    }

    /// A clamped allocator for an interface whose presence tags are
    /// OR-folded onto the CID: the counter may never reach the bits the tag
    /// mask occupies. The Nostr interface's tag domain starts at
    /// `0x6000_0000`, so its CID space is clamped to cid < `0x2000_0000`
    /// (US-1659).
    pub const fn clamped(limit: u32) -> Self {
        Self { counter: 0, limit }
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
        Self { counter, limit: HID_CID_DOMAIN_SEPARATED }
    }

    /// Test-only companion: place the counter under an arbitrary limit,
    /// for the clamped allocator's wrap tests (US-1659).
    fn from_counter_limited(counter: u32, limit: u32) -> Self {
        Self { counter, limit }
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
            if self.counter >= self.limit {
                // This allocator's CID space is exhausted: wrap to the
                // start (the next increment lands on 1 — the bridge
                // channel, skipped below like every reserved value).
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

    /// The same, for an arbitrary CTAPHID command (an INIT-packet whose
    /// command is not `CTAPHID_INIT`) — the shape a second host uses to try
    /// to preempt a transaction in flight.
    fn cmd_init_frame(
        channel: [u8; 4],
        cmd: u8,
        payload: &[u8],
        total_len: u16,
    ) -> [u8; HID_REPORT_SIZE] {
        let mut f = [0u8; HID_REPORT_SIZE];
        f[..4].copy_from_slice(&channel);
        f[4] = cmd | TYPE_INIT;
        f[5..7].copy_from_slice(&total_len.to_be_bytes());
        f[7..7 + payload.len()].copy_from_slice(payload);
        f
    }

    fn cont_frame(channel: [u8; 4], seq: u8, bytes: &[u8]) -> [u8; HID_REPORT_SIZE] {
        let mut f = [0u8; HID_REPORT_SIZE];
        f[..4].copy_from_slice(&channel);
        f[4] = seq;
        f[5..5 + bytes.len()].copy_from_slice(bytes);
        f
    }

    /// US-1659 (design §A.8.3a #2, §2.7.1): the Nostr interface's allocator
    /// is range-clamped to cid < `0x2000_0000` and the interface's tags
    /// (`0x6000_0000 | CID`, `fapico2_nostr::hid_presence_tag`) are injective
    /// over that space and disjoint from the other two domains. OR-folding
    /// is not injective in general: for a free-running cid ≥ 0x2000_0000,
    /// bits 29/30 of the cid fold into the tag mask — cid 0x0000_0002,
    /// 0x2000_0002 and 0x6000_0002 would all yield tag 0x6000_0002 — which
    /// is a silent cross-tab grant: a press armed for one tab consumable by
    /// another.
    #[test]
    #[cfg(feature = "device")]
    fn nostr_cid_allocator_is_clamped_and_tags_injective() {
        use fapico2_nostr::{hid_presence_tag, NOSTR_HID_TAG_DOMAIN, NOSTR_TAG_DOMAIN};

        // The Nostr allocator wraps under its own limit — the clamp is the
        // fix, so it is what the test exercises.
        const NOSTR_CID_LIMIT: u32 = 0x2000_0000;
        let mut alloc = CidAllocator::clamped(NOSTR_CID_LIMIT);
        assert_eq!(alloc.allocate(&[]), [0, 0, 0, 2], "bridge CID skipped, counting from 2");

        // Boundary: at the top of the clamped space the counter wraps back
        // into the safe range instead of stepping into the tag mask's bits —
        // the fold would live exactly here.
        let mut at_edge = CidAllocator::from_counter_limited(NOSTR_CID_LIMIT - 2, NOSTR_CID_LIMIT);
        let last = at_edge.allocate(&[]);
        assert_eq!(last, [0x1F, 0xFF, 0xFF, 0xFF], "the last clamped CID is issued");
        // …then the counter wraps to the start of the safe range (bridge
        // channel skipped), never crossing the clamp.
        assert_eq!(at_edge.allocate(&[]), [0, 0, 0, 2]);
        // Every issued CID keeps the clamp's bits clear — the property the
        // tag injectivity below depends on.
        assert_eq!(u32::from_be_bytes(last) & NOSTR_CID_LIMIT, 0);

        // Injectivity within the Nostr-HID domain: distinct channels yield
        // distinct tags (exercised over the interesting bit patterns — the
        // full space is 2^29, the fold lives at the mask's edges).
        for cid_u32 in [
            0x0000_0002u32,      // the first legal CID
            0x1FFF_FFFFu32,      // the last CID under the clamp
            0x0000_0003u32,      // the one the fold example collides on
            0x0100_0000u32,      // a CID with interior bits set
        ] {
            let cid = cid_u32.to_be_bytes();
            let tag = hid_presence_tag(cid);
            // The mask's bits must be exactly the domain's — a cid under the
            // clamp cannot steal bit 29 or bit 30 or reach bit 31.
            assert_eq!(tag & 0xE000_0000, NOSTR_HID_TAG_DOMAIN);
            assert_eq!(tag & !0xE000_0000, cid_u32 & 0x1FFF_FFFF);
        }

        // Cross-domain disjointness (§A.8.3 #1): the three presence-tag
        // domains never overlap. FIDO HID is `0x8000_0000 | CID`
        // (fapico2_fido::presence_tag_from_channel), the CCID Nostr applet
        // is `0x4000_0000 | idx` (fapico2_nostr::presence_tag), and this
        // interface is `0x6000_0000 | CID`.
        let cid = [0x00, 0x00, 0x00, 0x02];
        let nostr_hid = hid_presence_tag(cid);
        let fido_hid = 0x8000_0000 | u32::from_be_bytes(cid); // the FIDO encoding
        let ccid_nostr = NOSTR_TAG_DOMAIN | 2u32; // the CCID applet's idx-2 tag
        assert_ne!(nostr_hid, fido_hid);
        assert_ne!(nostr_hid, ccid_nostr);
        assert_ne!(fido_hid, ccid_nostr);
        // …and the FIDO domain's bit-31 invariant holds under this one: no
        // Nostr-HID tag can have bit 31 set, so a Nostr press can never arm
        // (or arm-consume) a FIDO window.
        assert_eq!(nostr_hid & 0x8000_0000, 0);
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

    /// US-705.1: an init-packet from another channel while a transaction is
    /// in flight is refused with CHANNEL_BUSY and the in-flight transaction
    /// survives — **unless the command is `CTAPHID_INIT`**, the handshake,
    /// which preempts by design (see `feed`).
    #[test]
    fn init_from_other_channel_mid_transaction_is_busy() {
        let mut asm = HidAssembler::new(fake_now);
        let host: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

        // Two-report transaction from `host` (total 100 bytes).
        assert!(matches!(
            asm.feed(&init_frame(host, &[9; 8], 100)),
            HidFeed::NeedMore
        ));
        // A second INIT *packet* — any other channel — cannot preempt.
        let other: [u8; 4] = [0x55, 0x66, 0x77, 0x88];
        match asm.feed(&cmd_init_frame(other, CTAP_HID_PING, &[1; 4], 4)) {
            HidFeed::Err(c, code) => {
                assert_eq!(c, other);
                assert_eq!(code, HID_ERR_CHANNEL_BUSY);
            }
            other => panic!("expected CHANNEL_BUSY for {other:?}, got {other:?}"),
        }
        // The broadcast channel refuses every non-INIT command outright, and
        // that rule is checked first (it is the channel rule, not the
        // transaction rule) — so this is INVALID_CHANNEL, not CHANNEL_BUSY.
        match asm.feed(&cmd_init_frame(HID_CID_BROADCAST, CTAP_HID_PING, &[1; 4], 4)) {
            HidFeed::Err(c, code) => {
                assert_eq!(c, HID_CID_BROADCAST);
                assert_eq!(code, HID_ERR_INVALID_CHANNEL);
            }
            other => panic!("expected INVALID_CHANNEL on broadcast, got {other:?}"),
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

    /// US-1524: `CTAPHID_INIT` **preempts** an in-flight transaction from
    /// another channel and is answered on the requesting channel — it is the
    /// host's resynchronisation primitive, so it must never be answered
    /// CHANNEL_BUSY.
    ///
    /// Reference: `pico-keys-sdk/src/usb/hid/hid.c:403-424` skips the busy
    /// guard when the incoming command is `CTAPHID_INIT`, and `hid.c:455-458`
    /// clears `msg_packet` for an INIT. CTAPHID §11.2.1 has the handshake
    /// allocate a fresh channel.
    #[test]
    fn ctaphid_init_preempts_an_in_flight_transaction() {
        let mut asm = HidAssembler::new(fake_now);
        let host: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let other: [u8; 4] = [0x55, 0x66, 0x77, 0x88];

        assert!(matches!(
            asm.feed(&init_frame(host, &[9; 8], 100)),
            HidFeed::NeedMore
        ));
        // A handshake on another channel mid-transaction: Ready, on `other`.
        match asm.feed(&init_frame(other, &[1; 8], 8)) {
            HidFeed::Ready(cmd) => {
                assert_eq!(cmd, CTAP_HID_INIT);
                assert_eq!(asm.channel(), other, "the reply goes to the requester's channel");
            }
            other => panic!("CTAPHID_INIT must preempt, got {other:?}"),
        }
        // The aborted transaction no longer holds the assembler: the old
        // channel's continuation is a stray and is dropped, not an error.
        assert!(matches!(
            asm.feed(&cont_frame(host, 0, &[0xAA; 43])),
            HidFeed::NeedMore
        ));
        // …and `other` can still run a fresh transaction.
        assert!(matches!(
            asm.feed(&cmd_init_frame(other, CTAP_HID_PING, &[], 4)),
            HidFeed::Ready(CTAP_HID_PING)
        ));
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

    // The two live `capFlags` decoders, spelled out here so the test carries
    // them itself rather than trusting the constant under test. See
    // `CTAPHID_INIT_CAP_FLAGS` for why both exist.
    //
    // CTAP 2.1 spec §11.2.1.1.
    const SPEC_CBOR: u8 = 0x01;
    const SPEC_WINK: u8 = 0x04;
    // pico-keys-sdk `ctap_hid.h` / Yubico `fido2` `CAPABILITY` (de facto).
    const DEFACTO_CBOR: u8 = 0x04;
    const DEFACTO_WINK: u8 = 0x01;

    /// US-1507: the INIT reply's `capFlags` byte must read as **CBOR + WINK
    /// under both live bit assignments**, because a host that reads it under
    /// the spec assignment concludes the device has no CTAP2 support —
    /// `fido2` 2.2.1 raises `ValueError("Device does not support CTAP2.")`
    /// (`fido2/ctap2/base.py`) and the key is never offered as a passkey
    /// authenticator. That is the discovery symptom this story fixes, so the
    /// test asserts the *decode*, not just the literal: `0x04` would pass a
    /// `== 0x04` check and still fail a spec reader.
    #[test]
    fn init_reply_advertises_cbor_and_wink_under_both_conventions() {
        // Built through the same code path the firmware uses (the INIT
        // handshake's own channel allocation, then `init_reply`, which is
        // what `dispatch_hid_cmd` sends).
        let nonce: [u8; 8] = [0xA0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut alloc = CidAllocator::new();
        let channel = alloc.allocate(&nonce);
        assert_ne!(channel, HID_CID_BROADCAST, "INIT must not answer on the broadcast CID");

        let inner = init_reply(&nonce, &channel, 5, 4, 0);

        // The echoed nonce, the freshly allocated CID, the interface version.
        // (The payload *length* needs no assert: `init_reply` returns
        // `[u8; CTAPHID_INIT_REPLY_LEN]`, so the const is what pins it, and an
        // `inner.len() == 17` check would be comparing the const to itself.)
        assert_eq!(&inner[..8], &nonce[..]);
        assert_eq!(&inner[8..12], &channel[..]);
        assert_eq!(inner[12], 0x02, "versionInterface must be 2 (CTAP HID v2)");

        let cap = inner[16];
        assert_eq!(cap, 0x05, "capFlags must be CBOR|WINK, not a single bit");

        // Decoder 1 — CTAP 2.1 spec §11.2.1.1 (0x01 CBOR, 0x04 WINK).
        assert_ne!(cap & SPEC_CBOR, 0, "spec reader concluded: no CTAP2 support");
        assert_ne!(cap & SPEC_WINK, 0, "spec reader concluded: no WINK");

        // Decoder 2 — pico-keys-sdk / `fido2` CAPABILITY (0x01 WINK, 0x04 CBOR).
        assert_ne!(cap & DEFACTO_CBOR, 0, "de-facto reader concluded: no CTAP2 support");
        assert_ne!(cap & DEFACTO_WINK, 0, "de-facto reader concluded: no WINK");
    }

    /// US-1661 (design §A.8.3 #8, §2.7.1): the Nostr interface's INIT reply
    /// must not read as a CTAP2-capable YubiKey under **either** capFlags
    /// convention, and its version bytes are the applet's, not the YubiKey
    /// firmware pair. A generic CTAPHID client opening the vendor interface
    /// must see a non-CTAP2 vendor device — the claim-vs-honour failure
    /// AGENTS §4 exists to prevent, one interface earlier than the CBOR path.
    #[test]
    fn nostr_init_reply_claims_only_what_it_serves() {
        let nonce: [u8; 8] = [0xB0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mut alloc = CidAllocator::clamped(crate::ctap_hid::HID_CID_DOMAIN_SEPARATED >> 2);
        let channel = alloc.allocate(&nonce);

        let inner = nostr_init_reply(&nonce, &channel);

        // The framing half is still CTAPHID: nonce echo, fresh CID,
        // versionInterface 2.
        assert_eq!(&inner[..8], &nonce[..]);
        assert_eq!(&inner[8..12], &channel[..]);
        assert_eq!(inner[12], 0x02, "versionInterface must be 2 — the framing is CTAPHID v2");

        let cap = inner[16];
        assert_eq!(cap, NOSTR_INIT_CAP_FLAGS);

        // Decoder 1 — CTAP 2.1 spec §11.2.1.1 (0x01 CBOR, 0x04 WINK): neither
        // bit set, so a spec reader cannot conclude CTAP2 (or WINK).
        assert_eq!(cap & SPEC_CBOR, 0, "spec reader concluded: CTAP2 capable");
        assert_eq!(cap & SPEC_WINK, 0, "spec reader concluded: WINK capable");

        // Decoder 2 — pico-keys-sdk / `fido2` CAPABILITY (0x01 WINK, 0x04
        // CBOR): same conclusion, opposite assignment.
        assert_eq!(cap & DEFACTO_CBOR, 0, "de-facto reader concluded: CTAP2 capable");
        assert_eq!(cap & DEFACTO_WINK, 0, "de-facto reader concluded: WINK capable");

        // The version bytes are the vendor's own — not the 5.4 pair the FIDO
        // interface carries for yubikit's device_version gate.
        assert_ne!(
            (inner[13], inner[14], inner[15]),
            (5, 4, 0),
            "the Nostr interface must not claim YubiKey firmware"
        );
        // …and they track the applet's own version pair, so a version bump
        // that leaves the constant behind is a red.
        #[cfg(feature = "device")]
        assert_eq!(
            (inner[13], inner[14]),
            (fapico2_nostr::APPLET_VERSION[0], fapico2_nostr::APPLET_VERSION[1]),
            "NOSTR_VENDOR_VERSION must track apps/nostr's APPLET_VERSION"
        );
    }
}
