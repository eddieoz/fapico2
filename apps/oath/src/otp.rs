//! OTP (Yubikey-compatible slot) applet: SLOT_CONFIGURE / SLOT_SWAP with
//! access-code protection and CRC-validated slot configs.

use fapico2_platform::dispatch::{App, Sw, MAX_RESPONSE};
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
// US-143: the host/test presence fallback, mirroring `OathApp`.
use aes::Aes128;
use fapico2_platform::presence::PresenceService;
// Anonymous trait imports: naming `KeyInit` would make `Hmac::new_from_slice`
// ambiguous with `KeyInit::new_from_slice`.
use aes::cipher::{generic_array::GenericArray, BlockEncrypt as _, KeyInit as _};
// US-131 (PICOForge-COMPAT): the XOR-accumulate comparison moved to `crate::ct`
// so the OATH applet shares this one implementation instead of memcmp-ing a
// response against the expected MAC.
use crate::ct::ct_eq;
use heapless::Vec as HeaplessVec;
use hmac::{Hmac, Mac};
use sha1::Sha1;

const SW_OK: Sw = 0x9000;
const SW_SECURITY_STATUS_NOT_SATISFIED: Sw = 0x6982;
const SW_WRONG_DATA: Sw = 0x6700;
const SW_INCORRECT_P1P2: Sw = 0x6A86;
const SW_INS_NOT_SUPPORTED: Sw = 0x6D00;

const INS_OTP: u8 = 0x01;
const SLOT_CONFIGURE: u8 = 0x01;
const SLOT_CONFIGURE_SLOT2: u8 = 0x03;
const UPDATE_SLOT1: u8 = 0x04;
const UPDATE_SLOT2: u8 = 0x05;
const SLOT_SWAP: u8 = 0x06;
/// US-141 (PICOForge-COMPAT): EXTENDED STATUS (C `otp_status_ext`,
/// `otp.c:550`) — the per-slot `0xB0 + index` TLV stream. Falls through to
/// `SW_INS_NOT_SUPPORTED` before this story; the reference client reaches it
/// on every `read_info` (`picoforge/src/hal/applets/otp.rs:381-407`).
const STATUS_EXT: u8 = 0x14;
// `Calculate` (challenge-response) P1 opcodes. 0x30/0x38 are HMAC-SHA1
// challenge-response; 0x20/0x28 are Yubico AES challenge-response. The slot
// is selected by P1, not P2.
const CALC_HMAC_SLOT1: u8 = 0x30;
const CALC_HMAC_SLOT2: u8 = 0x38;
const CALC_AES_SLOT1: u8 = 0x20;
const CALC_AES_SLOT2: u8 = 0x28;
// otp_config_t flag bits (see pico-fido/src/fido/otp.c).
const CHAL_RESP: u8 = 0x40; // Challenge-response enabled — checked in tkt_flags
const CHAL_HMAC: u8 = 0x22; // HMAC-SHA1 challenge-response mode — in cfg_flags
const CHAL_YUBICO: u8 = 0x20; // Yubico AES challenge-response mode — in cfg_flags
const HMAC_LT64: u8 = 0x04; // Trim trailing equal bytes from a <64B challenge
/// US-143 (PICOForge-COMPAT): C `otp_config_t` cfg_flags CHAL_BTN_TRIG
/// (`pico-fido/src/fido/otp.c:106`) — "challenge-response operation
/// requires button press". The reference client sets it whenever the user
/// ticks "touch" on a challenge-response slot (`build_chalresp`,
/// `picoforge src/hal/applets/otp.rs:190-199`) and reports it back from the
/// EXTENDED STATUS TLV. Until US-143 the bit was absent from this file
/// entirely: a slot programmed with touch read back as a working,
/// touch-less challenge slot, and the user had no way to know the flag had
/// been dropped.
///
/// Honoured by [`OtpApp::user_present`] on the challenge path, under the
/// OTP-only tag [`PRESENCE_TAG_CHAL_BTN_TRIG`].
pub const CHAL_BTN_TRIG: u8 = 0x08;
/// US-143: presence command tag for a touch-gated challenge-response.
///
/// **Domain separation.** The CCID-side tags are otherwise small integers
/// borrowed from the applet's own INS — mgmt WRITE_CONFIG `0x1C` /
/// RESET `0x1E`, OATH RESET `0x04` / SET_CODE-clear `0x03` / CALCULATE
/// `0xA2` / CALC-ALL `0xA4` (`oath_core.rs:185-203`) — and
/// `PresenceRuntime::window_grant` *joins* on an equal tag, so a shared
/// value would let a press meant for one applet arm another's grant. The
/// HID/FIDO side solves the same problem by setting bit 31
/// (`presence_tag_from_channel`, `apps/fido/src/device_app.rs:119-121`);
/// the OTP tag takes the last four bytes of the OTP applet's own AID
/// (`A0 00 00 05 27 20 01` -> `0x0527_2001`) instead. That value is bit-31
/// clear, so it stays out of the HID domain, and it is ~86.6 million CID
/// allocations away from the nearest `CidAllocator` value — far out of
/// reach of the small-integer CCID tags the other applets use.
pub const PRESENCE_TAG_CHAL_BTN_TRIG: u32 = 0x0527_2001;
/// US-143: a touch-gated challenge is refused with the C's
/// SW_CONDITIONS_NOT_SATISFIED (0x6985) — distinct from
/// [`SW_SECURITY_STATUS_NOT_SATISFIED`] (0x6982, a failed access code), so
/// a host can tell "wrong code" from "no touch".
const SW_CONDITIONS_NOT_SATISFIED: Sw = 0x6985;
/// US-142 (PICOForge-COMPAT): the CRC-16/X.25 **residual** of a valid
/// 52-byte config frame. The stored value is `!crc16(&config[..50])`
/// little-endian, so running the same CRC over the *whole* 52 bytes leaves
/// this constant — the C's own check (`check_crc`,
/// `pico-fido/src/fido/otp.c:636-639`) and the reference client's
/// (`crc16(&build_chalresp(..)) == 0xF0B8`, `picoforge
/// src/hal/applets/otp.rs:491-501,550`).
const CRC_RESIDUAL: u16 = 0xF0B8;
/// US-142: the remaining `otp_config_t` offsets, named so the layout is
/// assertable field-by-field instead of as a pile of literals. The C struct
/// (`pico-fido/src/fido/otp.c:110-125`) is
/// `fixed_data[16] ‖ uid[6] ‖ aes_key[16] ‖ acc_code[6] ‖ fixed_size(1) ‖
/// ext_flags(1) ‖ tkt_flags(1) ‖ cfg_flags(1) ‖ rfu[2] ‖ crc(2)`.
//
// `fixed_size`, `ext_flags` and `rfu` are not read on any wire path (US-144
// is the first story to read `fixed_size`; `ext_flags` has no effect on any
// command this applet implements — the C's EXTFLAG_UPDATE_MASK is 0xFF, so
// it passes through untouched). They are named here so the US-142 layout
// test can assert the frame field-by-field against the C struct instead of
// against literals, hence the `dead_code` exemption on those three.
#[allow(dead_code)]
const CFG_FIXED_DATA: usize = 0; // 16 bytes
const CFG_ACC_CODE: usize = 38; // 6 bytes — the slot's own access code
#[allow(dead_code)]
const CFG_FIXED_SIZE: usize = 44; // scancode / public-id length
#[allow(dead_code)]
const CFG_EXT_FLAGS: usize = 45; // ALLOW_UPDATE etc.
const CFG_RFU: usize = 48; // 2 bytes — must be zero
const CFG_CRC: usize = 50; // 2 bytes, little-endian, stored complemented
/// US-144 (PICOForge-COMPAT): C `otp_config_t` cfg_flags STATIC_TICKET — a
/// static-password slot. The response is `fixed_size` HID scancodes packed
/// contiguously across `fixed_data[16] ‖ uid[6] ‖ aes_key[16]`
/// (the reference client's `build_static`,
/// `picoforge src/hal/applets/otp.rs:224-239`).
///
/// **The bit is shared with [`CHAL_YUBICO`] (0x20).** The two never appear
/// in the same configuration — a Yubico-AES challenge slot always sets
/// TKT_CHAL_RESP, a static slot never does — so the 0x20 bit alone cannot
/// discriminate them. [`OtpApp::static_response`] adds `fixed_size != 0` as
/// the second half of the test; the reference client's `build_chalresp`
/// passes `fixed_size = 0`, so a challenge slot can never match.
pub const STATIC_TICKET: u8 = 0x20;
/// The scancode region of a static-password slot: `fixed_data[0..16] ‖
/// uid[6] ‖ aes_key[16]` — 38 bytes, which is the reference client's
/// `build_static` pack length and its 38-character cap.
const STATIC_MAX: usize = 16 + 6 + 16;
/// The C's SW_WRONG_LENGTH, which the pico-keys SDK maps to 0x6700 (the same
/// status word as SW_WRONG_DATA in this SDK — see `cmd_calculate`).
/// US-144: the `[slot1, slot2] ‖ acc[6]` SLOT_SWAP body length (C
/// `2 + ACC_CODE_SIZE`, `otp.c:776`).
const SLOT_SWAP_TAIL: usize = 2 + ACCESS_CODE_SIZE;
/// `otp_config_t` field offsets (packed layout, otp_config_size == 52).
/// tkt_flags (the CHAL_RESP gate), uid, aes_key and cfg_flags are the
/// pre-existing names.
const CFG_TKT_FLAGS: usize = 46;
const CFG_AES_KEY: usize = 22; // 16 bytes
const CFG_UID: usize = 16; // 6 bytes
const CFG_CFG_FLAGS: usize = 47; // cfg_flags — CHAL_HMAC / HMAC_LT64 bits
                                 // C flag-update masks for SLOT_UPDATE (otp.c TKTFLAG/CFGFLAG_UPDATE_MASK; the
                                 // C EXTFLAG_UPDATE_MASK is 0xFF, i.e. ext_flags pass through unchanged).
const TKTFLAG_UPDATE_MASK: u8 = 0x3F;
const CFGFLAG_UPDATE_MASK: u8 = 0x0C;

const OTP_CONFIG_SIZE: usize = 52;
const ACCESS_CODE_SIZE: usize = 6;
/// Number of configurable slots. C parity (`otp_status_ext` loops `i < 4`,
/// and `otp_slot_offset_valid` accepts `p2 <= 3`); the reference client
/// advertises `OtpFeatures.slots = 4` for this firmware
/// (picoforge `src/hal/firmwares/applets.rs:44,86`) and addresses slots 3/4
/// as `(0x01, 0x02)` / `(0x01, 0x03)` for configure and `(0x30, 0x02)` /
/// `(0x30, 0x03)` for challenge.
pub const SLOT_COUNT: usize = 4;
/// Status response: version(3) ‖ pgmSeq(1) ‖ flags(1) ‖ reserved(1).
///
/// **This is not the EXTENDED STATUS body.** The C returns this fixed
/// 6-byte record as the response *body* of a successful CONFIGURE /
/// UPDATE / SWAP (`otp.c::otp_status`, the `res_APDU` fill at
/// `otp.c:595-608`), and the firmware calls it only from those three
/// arms. US-141 adds a *different* thing on a *different* path — the
/// P1 `0x14` per-slot TLV stream ([`OtpApp::status_ext`]) — and leaves
/// this one byte-for-byte as it was, including its volatile
/// program-sequence counter. Do not merge the two.
#[allow(dead_code)]
const STATUS_LEN: usize = 6;

/// The fixed 64-byte payload the YK4 HID frame carries for every command —
/// the client pads, so the real body (52 or 58 bytes) is only recoverable by
/// the C's greater-or-equal length discipline, never by exact match.
const HID_FRAME_PAYLOAD: usize = 64;
/// US-141: the `0xB0 + index` tag of the per-slot EXTENDED STATUS TLV, and
/// the `0xA0` tag each one wraps (C `otp_status_ext`, `otp.c:559-566`).
const STATUS_EXT_TAG_BASE: u8 = 0xB0;
const STATUS_EXT_FLAGS_TAG: u8 = 0xA0;
/// The value inside the `0xA0`: `tkt_flags ‖ cfg_flags` (2 bytes). The
/// reference client reads exactly those two
/// (`picoforge/src/hal/applets/otp.rs:391-392`).
const STATUS_EXT_VALUE_LEN: usize = 2;
/// Outer TLV length: the inner `0xA0 0x02 <tkt> <cfg>` is 4 bytes.
const STATUS_EXT_INNER_LEN: usize = 4;

const FLAG_SLOT1_CONFIGURED: u8 = 0x01;
const FLAG_SLOT2_CONFIGURED: u8 = 0x02;
const FLAG_SLOT3_CONFIGURED: u8 = 0x04;
const FLAG_SLOT4_CONFIGURED: u8 = 0x08;

/// SecureStore slot for the OTP durable state (US-388). Layout: 4 × 52-byte
/// raw slot configs + a presence byte each + the 6-byte access code +
/// presence (fixed, no-heap serialization). The RP2350 secure partition
/// backs the store on device — never plain flash.
///
/// # US-140: the key is versioned, and the old one is never read
///
/// Widening 2 → 4 slots changes `STATE_SIZE` (113 → 219), so a 2-slot blob
/// is not a prefix of a 4-slot one and cannot be widened in place without
/// choosing a meaning for bytes that never meant anything. The codebase
/// already has the rule this story must obey: `store_v3`'s boot policy
/// *"never loaded, never silently re-seeded"* for a record whose bytes do
/// not validate as the current format (`platform/src/store_v3.rs:49-53`).
/// A v1 record does not validate as v2 (wrong length ⇒ wrong shape ⇒ a
/// silent read of `otp.slots.v1` as a 4-slot image would assign v1's
/// `acc-code-presence + 6 acc bytes` to slot 3's `config[0..7]`).
///
/// **Decision: version the key, refuse the old record.** [`STATE_SLOT_V1`]
/// is the retired name; nothing in the firmware reads it, and a device that
/// upgrades with a populated v1 store boots to the factory default (empty
/// slots, no access code) — the same "boot factory-default on a shape we do
/// not recognize" rule [`OtpApp::boot`] already applies to a short or
/// corrupt blob. The cost is that slots 1/2 must be re-programmed once; the
/// alternative (copying v1's two slots into v2's first two) is a re-seed of
/// secret material out of a differently-shaped record, which is exactly what
/// the rule above exists to prevent.
///
/// **What removes the retired record.** Boot does not: a boot is not a
/// wipe, and the record is not this firmware's to interpret. The first
/// *write* of the v2 record does — `OtpApp`'s `App::persist_state` issues
/// `delete(STATE_SLOT_V1)` alongside every `save(STATE_SLOT)`. So the v1
/// blob (two 52-byte slot configs, each a 6-byte uid + a 16-byte AES key,
/// plus the 6-byte device-wide access code) lives at most until the first
/// OTP state persist after the upgrade, and the management factory-reset
/// path (`factory_wipe` → `reset()` → the persist gate) is such a persist —
/// it removes the retired material unconditionally. This delete covers the
/// retired OTP record **only**: the FIDO/OpenPGP/trussed durable state is
/// wiped by [`fapico2_platform::dispatch::App::factory_wipe`] on those apps
/// and by `DeviceFactoryResetHandler` in the firmware, not from here.
const STATE_SLOT: &[u8] = b"otp.slots.v2";
/// The retired 2-slot state key (US-388). Kept as a named constant so the
/// refusal above is checkable rather than folklore; it is **never read**.
/// See [`STATE_SLOT`] for the full decision.
pub const STATE_SLOT_V1: &[u8] = b"otp.slots.v1";
/// Serialized state size: 4 slots × (1 presence + 52 config) + 1 access-code
/// presence + 6 access-code bytes.
const STATE_SIZE: usize = SLOT_COUNT * (1 + OTP_CONFIG_SIZE) + 1 + ACCESS_CODE_SIZE;
/// The retired 2-slot serialized size (US-140). Named for the same reason as
/// [`STATE_SLOT_V1`]: the v1 record is identified, not reinterpreted.
#[allow(dead_code)]
const STATE_SIZE_V1: usize = 2 * (1 + OTP_CONFIG_SIZE) + 1 + ACCESS_CODE_SIZE;

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for value in data {
        crc ^= *value as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Constant-time equality now lives in [`crate::ct::ct_eq`] (US-131): it was
/// originally written here for `VERIFY_PIN` and promoted so the OATH applet
/// authenticates its access code with the same comparison.
pub struct OtpApp {
    slots: [Option<[u8; OTP_CONFIG_SIZE]>; SLOT_COUNT],
    access_code: Option<[u8; ACCESS_CODE_SIZE]>,
    program_sequence: u8,
    /// Device serial string tail used by the Yubico AES challenge-response
    /// (C composes the AES block as challenge[0..6] ‖ `pico_serial_str[0..10]`).
    serial_str: [u8; 10],
    /// Durable state changed since the last persist (US-388).
    dirty: bool,
    /// US-143: user-presence source for a `CFG_CHAL_BTN_TRIG` challenge,
    /// injected via [`OtpApp::with_user_presence`]. `None` resolves to the
    /// build default — fail-closed under the `device` feature, auto-ack on
    /// host/emulation (OathApp parity, `oath_core.rs:606-626`).
    presence: Option<fn() -> bool>,
    /// US-143: the whole grant path (pending-request slot + latch binding)
    /// when the runtime owns the shared presence service (device wiring,
    /// `firmware/src/presence.rs`). Takes precedence over `presence`.
    presence_grant: Option<fn(u32) -> bool>,
}

impl Default for OtpApp {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpApp {
    pub fn new() -> Self {
        Self {
            slots: [None; SLOT_COUNT],
            access_code: None,
            program_sequence: 0,
            // C fallback: a zero board id serializes as ASCII '0' pairs
            // (pico-keys-sdk/src/serial.c), and the Rust firmware carries no
            // board serial — the builder below is the injection seam.
            serial_str: *b"0000000000",
            dirty: false,
            presence: None,
            presence_grant: None,
        }
    }

    /// US-143: attach the user-presence source consulted once per
    /// touch-gated challenge (OathApp `with_user_presence` parity).
    pub fn with_user_presence(mut self, f: fn() -> bool) -> Self {
        self.presence = Some(f);
        self
    }

    /// US-143: attach the shared presence runtime's grant path (device
    /// wiring, `OathApp::set_presence_grant` parity). The runtime owns the
    /// pending-request slot, so a press is granted only to a request made
    /// under [`PRESENCE_TAG_CHAL_BTN_TRIG`] — a touch meant for an OATH
    /// RESET or an OpenPGP PSO:SIGN cannot arm a challenge-response (and
    /// vice versa). Takes precedence over [`OtpApp::with_user_presence`].
    pub fn set_presence_grant(&mut self, g: fn(u32) -> bool) {
        self.presence_grant = Some(g);
    }

    /// Build-dependent presence default (OathApp parity, `oath_core.rs`):
    /// a device build with no injected source denies (fail closed);
    /// emulation/host auto-acks so the existing suites keep working.
    fn default_user_present() -> bool {
        #[cfg(feature = "device")]
        {
            false
        }
        #[cfg(not(feature = "device"))]
        {
            true
        }
    }

    /// US-143: the user-presence grant for a `CFG_CHAL_BTN_TRIG` slot.
    ///
    /// OathApp parity (`oath_core.rs::user_present`): with a grant path
    /// attached the shared runtime IS the grant — the single pending slot
    /// binds the request to [`PRESENCE_TAG_CHAL_BTN_TRIG`], so a press with
    /// no pending request arms nothing. The fallback below is the host/test
    /// path: a per-command [`PresenceService`] fed by the injected
    /// `fn() -> bool` (or the build default).
    fn user_present(&mut self) -> bool {
        const TAG: u32 = PRESENCE_TAG_CHAL_BTN_TRIG;
        if let Some(g) = self.presence_grant {
            return g(TAG);
        }
        let mut svc = PresenceService::new();
        if !svc.begin_request(TAG) {
            return false;
        }
        if match self.presence {
            Some(f) => f(),
            None => Self::default_user_present(),
        } {
            // The OTP applet has no monotonic clock and press->consume is
            // synchronous within this command, so tick 0 is the injected
            // stand-in for the window deadline (OathApp's exact comment).
            svc.observe_press(0);
        }
        let grant = svc.request(TAG, 0).is_some();
        svc.end_request(TAG);
        grant
    }

    /// Override the 10-byte serial string tail used by the Yubico AES
    /// challenge-response (device wiring may derive it from the board id).
    pub fn with_serial_str(mut self, serial_str: [u8; 10]) -> Self {
        self.serial_str = serial_str;
        self
    }

    /// Boot (US-388): load persisted slot contents + access code from the
    /// platform secure store (the RP2350 secure partition on device). A
    /// fresh or corrupt partition boots to the factory-default (empty slots).
    /// The program sequence counter is volatile — fresh at every boot.
    // US-939: `#[inline(never)]` -- async-main frame discipline.
    #[inline(never)]
    pub fn boot(store: &mut dyn SecureStore) -> Self {
        let mut app = Self::new();
        let mut buf = [0u8; STATE_SIZE];
        if let Ok(n) = store.read(STATE_SLOT, &mut buf) {
            if n == STATE_SIZE {
                app.load_state(&buf);
            }
        }
        app
    }

    /// Persist the durable slot state through the secure store
    /// (unconditional write; the [`App::persist`] hook gates this on
    /// dirtiness).
    pub fn save(&self, store: &mut dyn SecureStore) -> Result<(), SecureStoreError> {
        store.write(STATE_SLOT, &self.dump_state())
    }

    /// Whether `slot` (0-based) holds a configuration.
    pub fn slot_configured(&self, slot: usize) -> bool {
        self.slots.get(slot).map(|s| s.is_some()).unwrap_or(false)
    }

    /// US-711: clear the durable slot state (management factory reset).
    /// Marks the app dirty so the emptied state reaches the store through
    /// the app's own persist hook — the same durable wipe path a
    /// reconfigured slot uses.
    pub fn reset(&mut self) {
        self.slots = [None; SLOT_COUNT];
        self.access_code = None;
        self.dirty = true;
    }

    /// The volatile program sequence counter (advances on every STATUS read;
    /// never persisted — it resets on power cycle like the C firmware's).
    pub fn program_sequence(&self) -> u8 {
        self.program_sequence
    }

    /// Serialize the durable state into the fixed-size wire layout.
    fn dump_state(&self) -> heapless::Vec<u8, STATE_SIZE> {
        let mut out = heapless::Vec::<u8, STATE_SIZE>::new();
        for slot in &self.slots {
            out.push(if slot.is_some() { 1 } else { 0 }).ok();
            if let Some(c) = slot {
                out.extend_from_slice(c).ok();
            } else {
                out.extend_from_slice(&[0u8; OTP_CONFIG_SIZE]).ok();
            }
        }
        out.push(u8::from(self.access_code.is_some())).ok();
        out.extend_from_slice(
            self.access_code
                .as_ref()
                .map_or(&[0u8; ACCESS_CODE_SIZE], |a| a),
        )
        .ok();
        out
    }

    /// Restore the durable state from the serialized layout (US-388). A
    /// malformed buffer is ignored (factory defaults).
    fn load_state(&mut self, buf: &[u8]) {
        let mut i = 0usize;
        for slot in &mut self.slots {
            let Some(&present) = buf.get(i) else {
                return;
            };
            i += 1;
            let Some(config) = buf.get(i..i + OTP_CONFIG_SIZE) else {
                return;
            };
            i += OTP_CONFIG_SIZE;
            if present == 1 {
                *slot = Some(config.try_into().expect("fixed OTP_CONFIG_SIZE slice"));
            }
        }
        let Some(&has_access) = buf.get(i) else {
            return;
        };
        i += 1;
        if has_access == 1 {
            if let Some(code) = buf.get(i..i + ACCESS_CODE_SIZE) {
                self.access_code = Some(code.try_into().expect("fixed ACCESS_CODE_SIZE slice"));
            }
        }
    }

    /// US-140: the configured-slot bitmap reported in the 6-byte status
    /// body — bit *i* is slot *i+1*. Bits 0/1 are the C `CONFIG1_VALID` /
    /// `CONFIG2_VALID`; bits 2/3 are the RS-Key extension C carries in the
    /// same byte.
    /// The slot-configured bitmask (`FLAG_SLOTi_CONFIGURED`) — the byte the
    /// Yubico OTP HID idle status report carries at index 5 (yubikit reads
    /// the CONFIG_SLOTS_PROGRAMMED_MASK from it). Public for the firmware's
    /// OTP HID status handler; the CCID status path composes it internally.
    pub fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.slots[0].is_some() {
            flags |= FLAG_SLOT1_CONFIGURED;
        }
        if self.slots[1].is_some() {
            flags |= FLAG_SLOT2_CONFIGURED;
        }
        if self.slots[2].is_some() {
            flags |= FLAG_SLOT3_CONFIGURED;
        }
        if self.slots[3].is_some() {
            flags |= FLAG_SLOT4_CONFIGURED;
        }
        flags
    }

    fn status(&mut self) -> [u8; STATUS_LEN] {
        self.program_sequence = self.program_sequence.wrapping_add(1);
        [0x05, 0x04, 0x00, self.program_sequence, self.flags(), 0x00]
    }

    /// US-141 (PICOForge-COMPAT): EXTENDED STATUS, P1 `0x14` (C
    /// `otp_status_ext`, `otp.c:550-588`).
    ///
    /// One TLV per **configured** slot: `0xB0 + index` whose value is
    /// `0xA0 0x02 <tkt_flags> <cfg_flags>`. An unconfigured slot is
    /// **omitted** — see [`Self::status_ext`] for why emitting a zero-filled
    /// TLV instead would be a bug, not a stricter encoding.
    ///
    /// This is the *other* status: [`OtpApp::status`] (6 fixed bytes,
    /// volatile program-sequence counter) is the body of a successful
    /// configure/update/swap, and is untouched by this story.
    fn status_ext(&self, resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        for (i, slot) in self.slots.iter().enumerate() {
            let Some(cfg) = slot else {
                // US-141: omit, never zero-fill. The reference client's
                // `read_info` walks the TLV stream and pre-fills all four
                // slots with `SlotInfo::empty`; a `0xB0 0x03 0xA0 0x02
                // 0x00 0x00` TLV for a blank slot would parse as
                // `classify(0x00, 0x00) == SlotType::YubicoOtp` — a
                // programmed OTP slot that does not exist. The client
                // pins that classification in its own test
                // (`classify_types`, `otp.rs:576`). Silence is the only
                // encoding that reads back as Empty.
                continue;
            };
            resp.push(STATUS_EXT_TAG_BASE + i as u8).ok();
            resp.push(STATUS_EXT_INNER_LEN as u8).ok();
            resp.push(STATUS_EXT_FLAGS_TAG).ok();
            resp.push(STATUS_EXT_VALUE_LEN as u8).ok();
            resp.push(cfg[CFG_TKT_FLAGS]).ok();
            resp.push(cfg[CFG_CFG_FLAGS]).ok();
        }
    }

    /// Parse the C-harness APDU into (INS, P1, P2, data). The data field is a
    /// borrowed slice into `apdu` (no allocation — US-386 no_std port).
    fn parse_apdu(apdu: &[u8]) -> (u8, u8, u8, &[u8]) {
        // The C harness sends data-less commands as `00 INS P1 P2 00 00`
        // (no Lc field at all), so only trust the extended header when a
        // data field is actually present.
        if apdu.len() >= 7 && apdu[4] == 0x00 && apdu.len() > 7 + 1 {
            let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
            let data = if apdu.len() >= 7 + lc {
                &apdu[7..7 + lc]
            } else {
                &apdu[7..]
            };
            return (apdu[1], apdu[2], apdu[3], data);
        }
        if apdu.len() < 4 {
            return (0, 0, 0, &[]);
        }
        if apdu.len() == 4 {
            // US-132 (PICOForge-COMPAT): ISO 7816-4 case 1 — no Lc, no Le, no
            // data. C parity (`apdu.c::apdu_process`, `buffer_size == 4`).
            // The reference client does not pad its empty-body writes, so
            // this is a frame it really sends. Mirrored into the OATH
            // applet's `oath_core::parse_apdu` in the same story: the two
            // applets must not disagree about what a header is. No test
            // drives a 4-byte frame through this applet — the fix is made
            // for consistency with `oath_core`, not because a known caller
            // needs it.
            return (apdu[1], apdu[2], apdu[3], &[]);
        }
        let lc = apdu[4] as usize;
        let data = if apdu.len() >= 5 + lc {
            &apdu[5..5 + lc]
        } else {
            &apdu[5..]
        };
        (apdu[1], apdu[2], apdu[3], data)
    }

    /// C `otp_slot_offset_valid` (pico-fido/src/fido/otp.c 641-647): the four
    /// opcodes that carry a P2 slot offset accept `p2 <= 3`; every other
    /// opcode requires `p2 == 0`.
    ///
    /// US-140: the two-slot build could only ever see offsets 0/1, and
    /// pinned P2 to 0 on the `0x03`/`0x05`/`0x38`/`0x28` opcodes — which was
    /// already the C rule, just over a two-slot table. This is the rule
    /// verbatim; the four-slot table makes offsets 2 and 3 reachable, which
    /// is what the reference client uses for slots 3 and 4.
    fn slot_offset_valid(p1: u8, p2: u8) -> bool {
        if p1 == SLOT_CONFIGURE
            || p1 == UPDATE_SLOT1
            || p1 == CALC_HMAC_SLOT1
            || p1 == CALC_AES_SLOT1
        {
            p2 < SLOT_COUNT as u8
        } else {
            p2 == 0
        }
    }

    /// SLOT_CONFIGURE (C `cmd_otp`, P1 0x01/0x03). 0x01 targets slot 1 and
    /// takes a P2 slot offset (the C allows offsets up to 3 — US-140 raises
    /// the table to 4 so offsets 2/3 reach slots 3/4), 0x03 targets slot 2
    /// and requires P2 == 0.
    fn cmd_configure(&mut self, p1: u8, p2: u8, data: &[u8]) -> Sw {
        if !Self::slot_offset_valid(p1, p2) {
            return SW_INCORRECT_P1P2;
        }
        // The slot comes from P2; the data is the raw 52-byte config plus,
        // when an access code is involved, its 6 trailing bytes.
        let slot = if p1 == SLOT_CONFIGURE { p2 as usize } else { 1 };
        let body = data;
        // Split off the access code: protected configs are 52+6 bytes; a
        // fresh (unprotected) device accepts the trailing 6 bytes as the new
        // access code.
        let (config, access) = match body.len() {
            n if n == OTP_CONFIG_SIZE => (body, None),
            n if n == OTP_CONFIG_SIZE + ACCESS_CODE_SIZE => {
                (&body[..OTP_CONFIG_SIZE], Some(&body[OTP_CONFIG_SIZE..]))
            }
            // The YK4 HID frame payload is ALWAYS the full 64 bytes — yubikit
            // pads the command unconditionally (`send_and_receive`) and the C
            // reads the access code off the tail of whatever arrived
            // (`otp.c:675`), its length checks being greater-than-or-equal on
            // both transports. A 64-byte body is therefore legal here too:
            // config, then the optional access code, then zero padding.
            n if n == HID_FRAME_PAYLOAD => (
                &body[..OTP_CONFIG_SIZE],
                Some(&body[OTP_CONFIG_SIZE..OTP_CONFIG_SIZE + ACCESS_CODE_SIZE]),
            ),
            _ => return SW_WRONG_DATA,
        };
        let config: [u8; OTP_CONFIG_SIZE] = match config.try_into() {
            Ok(c) => c,
            Err(_) => return SW_WRONG_DATA,
        };
        let all_zero = config.iter().all(|b| *b == 0);
        // The NEW code lives at config[38..44]; the CURRENT code is the
        // 6-byte trailing payload (the reference client's `configure`
        // appends exactly that, `picoforge src/hal/applets/otp.rs:411-422`).
        let trailing_code: Option<[u8; ACCESS_CODE_SIZE]> = access.map(|a| {
            let mut code = [0u8; ACCESS_CODE_SIZE];
            code.copy_from_slice(a);
            code
        });
        let config_code: [u8; ACCESS_CODE_SIZE] = config
            [CFG_ACC_CODE..CFG_ACC_CODE + ACCESS_CODE_SIZE]
            .try_into()
            .expect("fixed 6-byte access-code field");
        // US-144: the code this device is actually protected by. An
        // all-zero code is NOT a code — the reference client models an
        // unprotected device as `current_acc == [0; 6]` and then sends an
        // EMPTY swap body, which the pre-US-144 firmware refused (6982)
        // because it had stored the zeros as a real code.
        let effective = self.access_code.filter(|c| *c != [0u8; ACCESS_CODE_SIZE]);
        // An all-zero config erases the slot. A protected device still has
        // to present its code to erase: the reference client's
        // `delete_slot` appends `current_acc` (zeros when unprotected).
        if all_zero {
            if let Some(existing) = effective {
                let provided = trailing_code.unwrap_or([0u8; ACCESS_CODE_SIZE]);
                if !ct_eq(&provided, &existing) {
                    return SW_SECURITY_STATUS_NOT_SATISFIED;
                }
            }
            self.slots[slot] = None;
            self.dirty = true;
            return SW_OK;
        }
        // C otp.c: a nonzero config with nonzero rfu bytes or a bad CRC
        // returns SW_WRONG_DATA (0x6700 in the pico-keys SDK). US-142: the
        // same check expressed against the C residual, so the accepted set
        // and the reference client's `crc16(frame) == 0xF0B8` cannot drift.
        if config[CFG_RFU] != 0 || config[CFG_RFU + 1] != 0 {
            return SW_WRONG_DATA;
        }
        let stored = u16::from_le_bytes([config[CFG_CRC], config[CFG_CRC + 1]]);
        if crc16(&config[..CFG_CRC]) != !stored || crc16(&config) != CRC_RESIDUAL {
            return SW_WRONG_DATA;
        }
        // US-144: authenticate the CURRENT state, then install the NEW
        // code. The 58-byte form presents the current code in the trailing
        // payload; the 52-byte form re-sends it in the config's own
        // `acc_code` field (the C reads those six bytes off the tail of the
        // frame, `otp.c:675`).
        if let Some(existing) = effective {
            let provided = trailing_code.unwrap_or(config_code);
            if !ct_eq(&provided, &existing) {
                return SW_SECURITY_STATUS_NOT_SATISFIED;
            }
        }
        // The NEW code is the one in the frame — unconditionally, from the
        // `acc_code` FIELD and never from the trailing payload. Pre-US-144
        // the trailing payload won, so a client that appended six zeros
        // for "unprotected" (the reference client's own convention) had
        // its chosen code discarded and an all-zero code installed
        // instead: the device became un-unlockable with the code the user
        // set. A zero new code means "leave the device unprotected",
        // which is what the client means by `NO_ACC`.
        self.access_code = if config_code == [0u8; ACCESS_CODE_SIZE] {
            None
        } else {
            Some(config_code)
        };
        self.slots[slot] = Some(config);
        SW_OK
    }

    /// SLOT_UPDATE (C `cmd_otp`, P1 0x04/0x05). 0x04 targets slot 1 with a
    /// P2 offset (C allows offsets up to 3 — US-140), 0x05 targets slot 2
    /// and requires P2 == 0. A zero rfu and a valid CRC are required up
    /// front; an occupied slot additionally needs its 6-byte access code
    /// (the slot's own `acc_code` field, not the device-level access code)
    /// and is merged under the C flag masks — secret material, `fixed_size`
    /// and, with CHAL_RESP set, `cfg_flags` come from the current config.
    /// An empty slot makes the whole command a no-op success.
    fn cmd_update(&mut self, p1: u8, p2: u8, data: &[u8]) -> Sw {
        if data.len() < OTP_CONFIG_SIZE {
            return SW_WRONG_DATA; // C SW_WRONG_LENGTH (0x6700 in this SDK)
        }
        if !Self::slot_offset_valid(p1, p2) {
            return SW_INCORRECT_P1P2;
        }
        let slot = if p1 == UPDATE_SLOT1 { p2 as usize } else { 1 };
        let mut new_cfg = [0u8; OTP_CONFIG_SIZE];
        new_cfg.copy_from_slice(&data[..OTP_CONFIG_SIZE]);
        if new_cfg[CFG_RFU] != 0 || new_cfg[CFG_RFU + 1] != 0 {
            return SW_WRONG_DATA;
        }
        let stored = u16::from_le_bytes([new_cfg[CFG_CRC], new_cfg[CFG_CRC + 1]]);
        if crc16(&new_cfg[..CFG_CRC]) != !stored || crc16(&new_cfg) != CRC_RESIDUAL {
            return SW_WRONG_DATA;
        }
        if let Some(cur) = self.slots[slot] {
            // Occupied slot: the access code is mandatory and must match the
            // current slot config's acc_code field (C otp.c ct_memcmp).
            if data.len() < OTP_CONFIG_SIZE + ACCESS_CODE_SIZE {
                return SW_WRONG_DATA;
            }
            if !ct_eq(
                &cur[CFG_ACC_CODE..CFG_ACC_CODE + ACCESS_CODE_SIZE],
                &data[OTP_CONFIG_SIZE..OTP_CONFIG_SIZE + ACCESS_CODE_SIZE],
            ) {
                return SW_SECURITY_STATUS_NOT_SATISFIED;
            }
            // C merge (otp.c 768-783): fixed_data+uid+aes_key ([0..38)) and
            // fixed_size ([44]) come from the current config; ext_flags pass
            // through (EXTFLAG_UPDATE_MASK == 0xFF); tkt_flags keeps only the
            // current high bits (TKTFLAG_UPDATE_MASK == 0x3F); cfg_flags are
            // preserved wholesale when the current tkt_flags has CHAL_RESP,
            // otherwise only CFGFLAG_UPDATE_MASK (0x0C) is updateable.
            new_cfg[0..38].copy_from_slice(&cur[0..38]);
            new_cfg[CFG_FIXED_SIZE] = cur[CFG_FIXED_SIZE];
            new_cfg[46] = (cur[46] & !TKTFLAG_UPDATE_MASK) | (new_cfg[46] & TKTFLAG_UPDATE_MASK);
            new_cfg[47] = if cur[46] & CHAL_RESP != 0 {
                cur[47]
            } else {
                (cur[47] & !CFGFLAG_UPDATE_MASK) | (new_cfg[47] & CFGFLAG_UPDATE_MASK)
            };
            self.slots[slot] = Some(new_cfg);
            self.dirty = true;
        }
        SW_OK
    }

    /// SLOT_SWAP (C `cmd_otp`, P1 0x06, `otp.c:752-830`).
    ///
    /// Accepted bodies, exactly the reference client's two shapes
    /// (`picoforge::swap`, `src/hal/applets/otp.rs:435-445`):
    ///
    /// * **empty** — an unprotected device;
    /// * **`[slot1, slot2]`** or **`[slot1, slot2] ‖ acc[6]`** — with
    ///   `slot1` an offset from slot 1 and `slot2` an offset from slot 2.
    ///
    /// The client's `[0, 0]` therefore means the default pair (slot 1 and
    /// slot 2), which is what the C computes too: `slot1 = EF_OTP_SLOT1 +
    /// data[0]`, `slot2 = EF_OTP_SLOT2 + data[1]` (`otp.c:768-769`) — the
    /// two bases are one apart, so an empty body (offsets 0/0 by default)
    /// is exactly slots 1 and 2.
    ///
    /// US-144 divergences from the pre-existing handler, both real:
    ///
    /// * a wrong body length was `SW_INCORRECT_P1P2`; the C answers the
    ///   C's `SW_WRONG_LENGTH` (0x6700 here);
    /// * the offsets were validated and then **thrown away** — the swap
    ///   always exchanged slots 1 and 2, so a client asking to swap 3 and 4
    ///   silently got 1 and 2 back. The C honours the pair (and refuses
    ///   `slot1 == slot2` with 6A86).
    ///
    /// The access code is checked against the **device-wide** code, not the
    /// participating slots' own `acc_code` fields (the C compares the
    /// slots'). See the US-144 report: that is a pre-existing difference
    /// between this applet's Rust-only device-wide code and the C, left
    /// as-is here.
    fn cmd_swap(&mut self, data: &[u8]) -> Sw {
        // C: nc must be 0, 2, or 2 + ACC_CODE_SIZE.
        if !matches!(data.len(), 0 | 2 | SLOT_SWAP_TAIL) {
            return SW_WRONG_DATA; // C SW_WRONG_LENGTH == 0x6700 in this SDK
        }
        let slot1 = if data.is_empty() { 0 } else { data[0] as usize };
        let slot2 = if data.is_empty() {
            1
        } else {
            1 + data[1] as usize
        };
        if slot1 >= SLOT_COUNT || slot2 >= SLOT_COUNT || slot1 == slot2 {
            return SW_INCORRECT_P1P2;
        }
        // An all-zero code is not a code (see `cmd_configure`).
        if let Some(existing) = self.access_code.filter(|c| *c != [0u8; ACCESS_CODE_SIZE]) {
            let presented: [u8; ACCESS_CODE_SIZE] = if data.len() == SLOT_SWAP_TAIL {
                data[2..2 + ACCESS_CODE_SIZE]
                    .try_into()
                    .expect("fixed ACCESS_CODE_SIZE tail")
            } else {
                // An empty / slot-only body carries no code; presenting
                // zeros is the only thing it can present, and it is right
                // only on an unprotected device (C: the same, via a
                // zero-initialized `access_code`).
                [0u8; ACCESS_CODE_SIZE]
            };
            if !ct_eq(&existing, &presented) {
                return SW_SECURITY_STATUS_NOT_SATISFIED;
            }
        }
        self.slots.swap(slot1, slot2);
        SW_OK
    }

    /// US-144: a static-password slot's response — the `fixed_size` HID
    /// scancodes packed contiguously across `fixed_data ‖ uid ‖ aes_key`
    /// (the reference client's `build_static`).
    ///
    /// **No scancode table is needed and none is shipped.** The table the
    /// brief anticipated (modhex -> HID) is a *client*-side concern: the
    /// reference client converts the user's ASCII to scancodes itself
    /// (`ascii_to_scancodes`, `picoforge src/hal/applets/otp.rs:339-347`)
    /// and puts the resulting BYTES in the config frame. The firmware only
    /// ever sees bytes, and a static slot's response is those bytes
    /// verbatim. Flash cost: 0 bytes.
    ///
    /// The discriminator, and why it needs two conditions: STATIC_TICKET
    /// shares bit 0x20 with CHAL_YUBICO, so `cfg_flags & 0x20` alone would
    /// also match a Yubico-AES challenge slot. TKT_CHAL_RESP splits them
    /// (a challenge slot always sets it, a static slot never does), and
    /// `fixed_size` — the number of scancodes, set only by `build_static`
    /// among the reference client's builders — is the tiebreak that keeps a
    /// `cfg_flags = 0x20` slot with no scancodes from being answered as
    /// one.
    fn static_response(cfg: &[u8; OTP_CONFIG_SIZE]) -> Option<&[u8]> {
        if cfg[CFG_TKT_FLAGS] & CHAL_RESP != 0 {
            return None;
        }
        if cfg[CFG_CFG_FLAGS] & STATIC_TICKET == 0 {
            return None;
        }
        let n = (cfg[CFG_FIXED_SIZE] as usize).min(STATIC_MAX);
        if n == 0 {
            return None;
        }
        Some(&cfg[CFG_FIXED_DATA..CFG_FIXED_DATA + n])
    }

    /// `Calculate` challenge-response (C `cmd_otp`, P1 0x30/0x38 HMAC-SHA1,
    /// 0x20/0x28 Yubico AES). The slot is `(0x30/0x20 ? slot 1 : slot 2) +
    /// p2` — the C's expression (`otp.c:891`). US-140: the pre-existing
    /// two-slot table pinned P2 to 0 on every calculate opcode; the C rule
    /// (`slot_offset_valid`) allows `p2 <= 3` on 0x30/0x20, and the reference
    /// client addresses slots 3/4 exactly that way
    /// (`chal_p1p2`, picoforge `src/hal/applets/otp.rs:132-141`).
    /// Returns SW_OK with a 20-byte HMAC-SHA1 or a 16-byte AES-ECB body, or
    /// a status word on validation failure. An unconfigured slot yields
    /// SW_OK with no body (the C app returns early).
    fn cmd_calculate(
        &mut self,
        p1: u8,
        p2: u8,
        data: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        // C `otp_slot_offset_valid` — 0x30/0x20 carry a P2 offset up to 3;
        // 0x38/0x28 require P2 == 0.
        if !Self::slot_offset_valid(p1, p2) {
            return SW_INCORRECT_P1P2;
        }
        // C selects the base slot for P1==0x30/0x20; any other P1 (0x38/0x28)
        // bases on slot 2. The P2 offset then walks forward.
        let base = if p1 == CALC_HMAC_SLOT1 || p1 == CALC_AES_SLOT1 {
            0
        } else {
            1
        };
        // C bounds the result by construction: base is 0 or 1, and only the
        // base-0 opcodes accept p2 < 4, so `base + p2` is always < 4.
        let slot = base + p2 as usize;
        // No config stored -> the C app returns SW_OK with an empty body.
        let cfg = match self.slots[slot] {
            Some(c) => c,
            None => return SW_OK,
        };
        let tkt_flags = cfg[CFG_TKT_FLAGS];
        let cfg_flags = cfg[CFG_CFG_FLAGS];
        // US-144: a static-password slot answers with its scancodes and
        // needs neither CHAL_RESP nor a challenge frame. It is dispatched
        // BEFORE the C's CHAL_RESP gate, which is what would otherwise make
        // every static slot unusable (the C has no static-slot response at
        // all — its CHAL_RESP gate at otp.c:899 comes first and refuses).
        if let Some(scancodes) = Self::static_response(&cfg) {
            if cfg_flags & CHAL_BTN_TRIG != 0 && !self.user_present() {
                return SW_CONDITIONS_NOT_SATISFIED;
            }
            resp.extend_from_slice(scancodes).ok();
            return SW_OK;
        }
        // C gates on the CHAL_RESP bit in tkt_flags before checking the HMAC
        // mode flag in cfg_flags (otp.c cmd_otp: 899 then 924).
        if tkt_flags & CHAL_RESP == 0 {
            return SW_WRONG_DATA;
        }
        // US-143: `CFG_CHAL_BTN_TRIG` — the touch gate. The C sets
        // `status_byte = 0x20` and calls `otp_status`, then
        // **returns SW_CONDITIONS_NOT_SATISFIED when the button WAS
        // pressed** (`otp.c:905-913`): its polarity is inverted on purpose
        // — a press during the prompt is treated as a probe, not consent,
        // so the challenge never completes from a touch-gated slot over
        // this path at all.
        //
        // This firmware uses the *sane* polarity instead: a press during
        // the pending request IS the consent, and no press is refused.
        // That is a deliberate, documented divergence from the C, taken
        // because the inverted polarity would make the feature
        // unconditionally unusable while matching nothing the reference
        // client exercises. The consequence — `picoforge::calculate_hmac`
        // is a single `transceive_full` with no retry, so a touch-gated
        // slot the user programmed through the reference client will be
        // refused — is reported in the story notes, not hidden.
        //
        // The gate runs BEFORE any response byte is produced, and the
        // request is bound to `PRESENCE_TAG_CHAL_BTN_TRIG` so an
        // unrelated touch can never arm it (see that constant).
        if cfg_flags & CHAL_BTN_TRIG != 0 && !self.user_present() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        if p1 == CALC_HMAC_SLOT1 || p1 == CALC_HMAC_SLOT2 {
            // HMAC-SHA1 challenge-response. The key is aes_key(16) ‖ uid(6); the
            // message is the first `chal_len` challenge bytes.
            if data.len() < 64 {
                return SW_WRONG_DATA;
            }
            if cfg_flags & CHAL_HMAC == 0 {
                return SW_WRONG_DATA;
            }
            let mut key = [0u8; 22];
            key[..16].copy_from_slice(&cfg[CFG_AES_KEY..CFG_AES_KEY + 16]);
            key[16..].copy_from_slice(&cfg[CFG_UID..CFG_UID + 6]);
            // A <64-byte challenge has its trailing run of identical bytes
            // trimmed (Yubico HMAC-Challenge semantics).
            let mut chal_len: usize = 64;
            if cfg_flags & HMAC_LT64 != 0 {
                while chal_len > 0 && data[63] == data[chal_len - 1] {
                    chal_len -= 1;
                }
            }
            let mut mac: Hmac<Sha1> = <Hmac<Sha1> as Mac>::new_from_slice(&key)
                .expect("HMAC-SHA1 accepts keys of any length");
            mac.update(&data[..chal_len]);
            for b in mac.finalize().into_bytes() {
                resp.push(b).ok();
            }
            SW_OK
        } else {
            // 0x20/0x28 Yubico AES challenge-response (C otp.c 940-960): the
            // AES-128-ECB block is the first 6 challenge bytes followed by the
            // 10-byte device serial string (`pico_serial_str[0..10]`).
            if data.len() < 6 {
                return SW_WRONG_DATA; // C SW_WRONG_LENGTH (0x6700 in this SDK)
            }
            if cfg_flags & CHAL_YUBICO == 0 {
                return SW_WRONG_DATA;
            }
            let mut block = [0u8; 16];
            block[..6].copy_from_slice(&data[..6]);
            block[6..].copy_from_slice(&self.serial_str);
            let cipher = Aes128::new(GenericArray::from_slice(
                &cfg[CFG_AES_KEY..CFG_AES_KEY + 16],
            ));
            let mut enc = GenericArray::from(block);
            cipher.encrypt_block(&mut enc);
            for b in enc.iter() {
                resp.push(*b).ok();
            }
            SW_OK
        }
    }
}

impl App for OtpApp {
    fn aid(&self) -> &[u8] {
        &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01]
    }

    fn select(&mut self, _internal: bool) -> Sw {
        SW_OK
    }

    /// Yubico OTP AID SELECT carries a 7-byte status body —
    /// `version(3) || pgm_seq || slot_flags || 0 || status` — the same bytes
    /// the C firmware writes in `otp_select` (`otp.c:332-346`,
    /// `otp_status(false)`): `yubikit`'s `YubiOtpSession` over CCID parses the
    /// first three as the OTP applet version and byte 3 as the programming
    /// sequence (`yubikit/yubiotp.py` `YubiOtpSession.__init__`), and an
    /// empty SELECT response made `read_info` throw before any capability
    /// could render — the desktop app's device list degraded to the FIDO
    /// transport alone. Version bytes mirror [`Self::status`] (5.4.0); the
    /// sequence is read WITHOUT the increment (only a configure/update/swap
    /// bumps it, and the client's update detection relies on that).
    fn select_apdu(
        &mut self,
        internal: bool,
        _apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        // `HeaplessVec::extend_from_slice` returns `Result<(), ()>` — the
        // capacity check — and it is `#[must_use]`. A 7-byte body into
        // `MAX_RESPONSE` cannot overflow, so `.ok()` matches the mgmt
        // sibling's `write_version` rather than inventing a new convention.
        resp.extend_from_slice(&[
            0x05,
            0x04,
            0x00,
            self.program_sequence,
            self.flags(),
            0x00,
            0x00,
        ])
        .ok();
        self.select(internal)
    }

    fn deselect(&mut self) {}

    fn process(&mut self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        let (ins, p1, p2, data) = Self::parse_apdu(apdu);
        let sw = if ins != INS_OTP {
            SW_INS_NOT_SUPPORTED
        } else {
            match p1 {
                SLOT_CONFIGURE | SLOT_CONFIGURE_SLOT2 => {
                    let sw = self.cmd_configure(p1, p2, data);
                    if sw == SW_OK {
                        self.dirty = true;
                        // C returns `otp_status(_is_otp)` on configure success
                        // (including the all-zero erase path).
                        resp.extend_from_slice(&self.status()).ok();
                    }
                    sw
                }
                SLOT_SWAP => {
                    let sw = self.cmd_swap(data);
                    if sw == SW_OK {
                        self.dirty = true;
                        resp.extend_from_slice(&self.status()).ok();
                    }
                    sw
                }
                UPDATE_SLOT1 | UPDATE_SLOT2 => {
                    // C returns `otp_status(_is_otp)` on update success (the
                    // empty-slot no-op included); cmd_update marks dirty only
                    // when it actually stored a merged config.
                    let sw = self.cmd_update(p1, p2, data);
                    if sw == SW_OK {
                        resp.extend_from_slice(&self.status()).ok();
                    }
                    sw
                }
                CALC_HMAC_SLOT1 | CALC_HMAC_SLOT2 | CALC_AES_SLOT1 | CALC_AES_SLOT2 => {
                    self.cmd_calculate(p1, p2, data, resp)
                }
                // US-141: EXTENDED STATUS. P1 0x14 carries no P2 offset
                // (C `otp_slot_offset_valid` admits it under none of the
                // offset-carrying opcodes) and no data; the C ignores the
                // body, and so does this.
                STATUS_EXT => {
                    if p2 != 0 {
                        SW_INCORRECT_P1P2
                    } else {
                        self.status_ext(resp);
                        SW_OK
                    }
                }
                _ => SW_INS_NOT_SUPPORTED,
            }
        };
        for b in sw.to_be_bytes() {
            resp.push(b).ok();
        }
    }

    /// US-711: the management RESET hook — clear the slot table, let the
    /// persist gate write the emptied state (see [`OtpApp::reset`]).
    fn factory_wipe(&mut self) {
        self.reset();
    }

    fn persist_state(&mut self, store: &mut dyn SecureStore) -> bool {
        if !self.dirty {
            return false;
        }
        let wrote = self.save(store).is_ok();
        if wrote {
            // US-140 review fix: the retired 2-slot record is never read, so
            // a successful write of the v2 record is proof that this device
            // is on v2 — drop the retired blob in the same durable-before-ack
            // gate rather than leaving two slots' worth of pre-upgrade OTP
            // material (uid + AES key per slot, plus the device-wide access
            // code) sealed in the partition indefinitely. On the management
            // factory-reset path (`factory_wipe` → `reset()` → here) this is
            // the only write that ever removes it. A `NotFound` means it was
            // already gone, which is the desired end state; a real store
            // failure is not a persist failure and must not be reported as
            // one, so the result is deliberately not folded into `wrote`.
            let _ = store.delete(STATE_SLOT_V1);
            self.dirty = false;
        }
        wrote
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    /// Drive one APDU through the app and return (response_body, sw16).
    fn drive(app: &mut OtpApp, apdu: &[u8]) -> (Vec<u8>, u16) {
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        app.process(apdu, &mut resp);
        let bytes: Vec<u8> = resp.as_slice().to_vec();
        let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
        (bytes[..bytes.len() - 2].to_vec(), sw)
    }

    /// Build a valid 52-byte slot config with the given uid, aes_key and the
    /// tkt_flags / cfg_flags bit fields (correct CRC so `cmd_configure` accepts it).
    fn make_config(uid: [u8; 6], aes_key: [u8; 16], tkt_flags: u8, cfg_flags: u8) -> [u8; 52] {
        let mut c = [0u8; 52];
        c[16..22].copy_from_slice(&uid);
        c[22..38].copy_from_slice(&aes_key);
        c[38..44].copy_from_slice(&[0u8; ACCESS_CODE_SIZE]); // acc_code
        c[46] = tkt_flags;
        c[47] = cfg_flags;
        let stored = !crc16(&c[..50]);
        c[50..52].copy_from_slice(&stored.to_le_bytes());
        c
    }

    fn configure(app: &mut OtpApp, slot: usize, config: [u8; 52]) {
        let mut apdu = vec![
            0x00,
            INS_OTP,
            SLOT_CONFIGURE,
            slot as u8,
            config.len() as u8,
        ];
        apdu.extend_from_slice(&config);
        let (_, sw) = drive(app, &apdu);
        assert_eq!(sw, 0x9000);
    }

    fn calculate(app: &mut OtpApp, p1: u8, challenge: &[u8]) -> (Vec<u8>, u16) {
        let mut apdu = vec![0x00, INS_OTP, p1, 0x00, challenge.len() as u8];
        apdu.extend_from_slice(challenge);
        drive(app, &apdu)
    }

    fn hmac_sha1(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut mac: Hmac<Sha1> =
            <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC-SHA1 accepts any key length");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn calculate_hmac_returns_20_byte_digest_over_aes_key_concat_uid() {
        let mut app = OtpApp::new();
        let uid = [1, 2, 3, 4, 5, 6];
        let aes_key = [0xAAu8; 16];
        configure(&mut app, 0, make_config(uid, aes_key, CHAL_RESP, CHAL_HMAC));

        let challenge: Vec<u8> = (0..64).map(|i| (i * 7 + 3) as u8).collect();
        // C builds the HMAC key as aes_key(16) ‖ uid(6).
        let key = [&aes_key[..], &uid[..]].concat();
        let expected = hmac_sha1(&key, &challenge);

        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge);
        assert_eq!(sw, 0x9000);
        assert_eq!(body.len(), 20, "HMAC-SHA1 output is 20 bytes");
        assert_eq!(body, expected);
    }

    #[test]
    fn calculate_requires_chal_resp_flag() {
        let mut app = OtpApp::new();
        // CHAL_RESP cleared in tkt_flags (C's gate), CHAL_HMAC set in cfg_flags.
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], 0, CHAL_HMAC),
        );
        let challenge: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge);
        assert_eq!(sw, SW_WRONG_DATA);
        assert!(body.is_empty());
    }

    #[test]
    fn calculate_rejects_short_challenge() {
        let mut app = OtpApp::new();
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC),
        );
        let challenge: Vec<u8> = (0..10).map(|i| i as u8).collect();
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge);
        assert_eq!(sw, SW_WRONG_DATA); // SDK maps wrong-length to 0x6700
        assert!(body.is_empty());
    }

    #[test]
    fn calculate_trims_trailing_equal_bytes_when_lt64_flag() {
        let mut app = OtpApp::new();
        let aes_key = [0x5Bu8; 16];
        configure(
            &mut app,
            0,
            make_config(
                [9, 8, 7, 6, 5, 4],
                aes_key,
                CHAL_RESP,
                CHAL_HMAC | HMAC_LT64,
            ),
        );
        // First 60 bytes distinct; last 4 identical so the C loop trims to 60.
        let mut challenge = vec![0u8; 64];
        for (i, slot) in challenge.iter_mut().enumerate().take(60) {
            *slot = (i * 11 + 5) as u8;
        }
        challenge[60..].fill(0xCC);
        assert_ne!(challenge[59], 0xCC, "precondition: trim must stop at 60");

        let key = [&aes_key[..], &[9, 8, 7, 6, 5, 4]].concat();
        let expected = hmac_sha1(&key, &challenge[..60]);

        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge);
        assert_eq!(sw, 0x9000);
        assert_eq!(body, expected);
    }

    #[test]
    fn calculate_unconfigured_slot_returns_ok_empty() {
        let mut app = OtpApp::new();
        let challenge: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge);
        assert_eq!(sw, SW_OK);
        assert!(body.is_empty());
    }

    #[test]
    fn calculate_selects_slot_by_p1() {
        let mut app = OtpApp::new();
        // Slot 0 and slot 1 use different key material so the response pins P1.
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC),
        );
        configure(
            &mut app,
            1,
            make_config([6, 5, 4, 3, 2, 1], [0xBB; 16], CHAL_RESP, CHAL_HMAC),
        );
        let challenge: Vec<u8> = (0..64).map(|i| (i * 3 + 1) as u8).collect();

        let key0 = [&[0xAAu8; 16][..], &[1, 2, 3, 4, 5, 6]].concat();
        let key1 = [&[0xBBu8; 16][..], &[6, 5, 4, 3, 2, 1]].concat();
        let exp0 = hmac_sha1(&key0, &challenge);
        let exp1 = hmac_sha1(&key1, &challenge);

        let (b0, sw0) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge);
        assert_eq!(sw0, 0x9000);
        assert_eq!(b0, exp0);
        let (b1, sw1) = calculate(&mut app, CALC_HMAC_SLOT2, &challenge);
        assert_eq!(sw1, 0x9000);
        assert_eq!(b1, exp1);
        assert_ne!(exp0, exp1, "sanity: the two slots must differ");
    }

    #[test]
    fn calculate_rejects_p2_past_the_slot_table() {
        let mut app = OtpApp::new();
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC),
        );
        let challenge: Vec<u8> = (0..64).map(|i| i as u8).collect();
        // US-140: P2 is now a real slot offset on 0x30/0x20, bounded by the
        // C rule `p2 <= 3`. Offset 4 is out of the table -> 6A86.
        let (body, sw) = {
            let mut apdu = vec![0x00, INS_OTP, CALC_HMAC_SLOT1, 0x04, challenge.len() as u8];
            apdu.extend_from_slice(&challenge);
            drive(&mut app, &apdu)
        };
        assert_eq!(sw, SW_INCORRECT_P1P2);
        assert!(body.is_empty());
    }

    // ------------------------------------------------------------------
    // US-712: SLOT_CONFIGURE 0x03 (slot 2), SLOT_UPDATE 0x04/0x05 and
    // Yubico AES challenge-response 0x20/0x28, per the YubiKey slot
    // protocol. The opcode constants come from the module top (in scope
    // via `use super::*`).
    // ------------------------------------------------------------------

    // cfg_flags bit shared by PACING_10MS (ticket mode) and HMAC_LT64
    // (challenge mode): the only cfg bit the C UPDATE mask lets through,
    // which makes the merge observable through challenge trimming.
    const CFG_UPDATE_BIT: u8 = 0x04;

    /// Configure a slot through a raw P1 (0x01 or 0x03), returning (body, sw)
    /// so the C `otp_status` response body can be asserted too.
    fn configure_raw(app: &mut OtpApp, p1: u8, p2: u8, config: [u8; 52]) -> (Vec<u8>, u16) {
        let mut apdu = vec![0x00, INS_OTP, p1, p2, config.len() as u8];
        apdu.extend_from_slice(&config);
        drive(app, &apdu)
    }

    /// 52-byte config with an explicit access-code field at [38..44]
    /// (C `otp_config_t.acc_code`).
    fn make_config_acc(
        uid: [u8; 6],
        aes_key: [u8; 16],
        acc: [u8; ACCESS_CODE_SIZE],
        tkt_flags: u8,
        cfg_flags: u8,
    ) -> [u8; 52] {
        let mut c = make_config(uid, aes_key, tkt_flags, cfg_flags);
        c[38..44].copy_from_slice(&acc);
        let stored = !crc16(&c[..50]);
        c[50..52].copy_from_slice(&stored.to_le_bytes());
        c
    }

    /// Update APDU body: the 52-byte config plus, when the target slot is
    /// occupied, the 6-byte access code (C requires nc >= otp_config_size+6).
    fn update_raw(app: &mut OtpApp, p1: u8, p2: u8, body: &[u8]) -> (Vec<u8>, u16) {
        let mut apdu = vec![0x00, INS_OTP, p1, p2, body.len() as u8];
        apdu.extend_from_slice(body);
        drive(app, &apdu)
    }

    // ---- configure 0x03 (slot 2) ----

    #[test]
    fn configure_slot2_via_0x03_programs_slot_and_returns_status_body() {
        let mut app = OtpApp::new();
        let config = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        let (body, sw) = configure_raw(&mut app, SLOT_CONFIGURE_SLOT2, 0, config);
        assert_eq!(sw, 0x9000);
        // C `cmd_otp` returns `otp_status(_is_otp)` on configure success.
        assert_eq!(body.len(), 6);
        assert!(body[4] & FLAG_SLOT2_CONFIGURED != 0, "slot 2 flag set");
        assert!(body[4] & FLAG_SLOT1_CONFIGURED == 0, "slot 1 untouched");
        assert!(app.slot_configured(1));
    }

    #[test]
    fn configure_0x03_rejects_nonzero_p2() {
        let mut app = OtpApp::new();
        let config = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        let (body, sw) = configure_raw(&mut app, SLOT_CONFIGURE_SLOT2, 1, config);
        assert_eq!(sw, SW_INCORRECT_P1P2);
        assert!(body.is_empty());
        assert!(!app.slot_configured(1));
    }

    #[test]
    fn configure_rejects_bad_crc_with_wrong_data() {
        // C otp.c configure: a nonzero config with a bad CRC (or nonzero rfu)
        // returns SW_WRONG_DATA (0x6700 in the pico-keys SDK).
        let mut app = OtpApp::new();
        let mut config = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        config[51] ^= 0xFF; // corrupt the CRC complement
        let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE_SLOT2, 0, config);
        assert_eq!(sw, SW_WRONG_DATA);
        assert!(!app.slot_configured(1));
    }

    #[test]
    fn configure_rejects_nonzero_rfu_with_wrong_data() {
        let mut app = OtpApp::new();
        let mut config = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        config[48] = 0x01; // rfu[0] must be zero (otp_config_t.rfu)
        let stored = !crc16(&config[..50]);
        config[50..52].copy_from_slice(&stored.to_le_bytes());
        let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE_SLOT2, 0, config);
        assert_eq!(sw, SW_WRONG_DATA);
        assert!(!app.slot_configured(1));
    }

    #[test]
    fn configure_all_zero_via_0x03_deletes_slot_2_only() {
        let mut app = OtpApp::new();
        let config = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        configure(&mut app, 0, config);
        let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE_SLOT2, 0, config);
        assert_eq!(sw, 0x9000);
        assert!(app.slot_configured(1));
        let (body, sw) = configure_raw(&mut app, SLOT_CONFIGURE_SLOT2, 0, [0u8; 52]);
        assert_eq!(sw, 0x9000);
        assert!(!app.slot_configured(1));
        assert!(app.slot_configured(0), "slot 1 must survive the 0x03 erase");
        assert_eq!(body.len(), 6);
        assert!(body[4] & FLAG_SLOT2_CONFIGURED == 0);
    }

    // ---- update 0x04 / 0x05 ----

    #[test]
    fn update_0x04_preserves_secret_material_and_merges_flag_masks() {
        let mut app = OtpApp::new();
        let uid = [1, 2, 3, 4, 5, 6];
        let aes_key = [0xAAu8; 16];
        let acc = [0x11u8; 6];
        configure(
            &mut app,
            0,
            make_config_acc(uid, aes_key, acc, CHAL_RESP, CHAL_HMAC),
        );

        // Update config: different aes_key / uid region, new flag fields.
        // C merge: fixed_data+uid+key ([0..38)) and fixed_size come from the
        // CURRENT config; ext_flags from the new one (mask 0xFF); tkt_flags
        // keeps only the current high bits (mask 0x3F updateable); cfg_flags
        // are preserved entirely when the current tkt_flags has CHAL_RESP.
        let mut cfg_b = [0u8; 52];
        cfg_b[16..22].copy_from_slice(&[9, 9, 9, 9, 9, 9]); // new uid — ignored
        cfg_b[22..38].copy_from_slice(&[0xBB; 16]); // new key — ignored
        cfg_b[38..44].copy_from_slice(&acc); // access code authenticates
        cfg_b[44] = 9; // fixed_size — replaced by the current one
        cfg_b[45] = 0x20; // ext_flags: ALLOW_UPDATE (mask 0xFF passes it)
        cfg_b[46] = 0x3F; // tkt_flags low bits
        cfg_b[47] = 0x04; // cfg_flags PACING_10MS — dropped (CHAL_RESP set)
        let stored = !crc16(&cfg_b[..50]);
        cfg_b[50..52].copy_from_slice(&stored.to_le_bytes());

        let mut body58 = cfg_b.to_vec();
        body58.extend_from_slice(&acc);
        let (resp, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &body58);
        assert_eq!(sw, 0x9000);
        assert_eq!(resp.len(), 6, "C returns the otp_status body on update");
        assert!(resp[4] & FLAG_SLOT1_CONFIGURED != 0);

        // Direct view of the merged slot config (tests share the module).
        let merged = app.slots[0].expect("slot stays configured");
        assert_eq!(&merged[22..38], &[0xAAu8; 16], "aes_key preserved");
        assert_eq!(&merged[16..22], &[1, 2, 3, 4, 5, 6], "uid preserved");
        assert_eq!(merged[44], 0, "fixed_size taken from the current config");
        assert_eq!(merged[45], 0x20, "ext_flags taken from the new config");
        assert_eq!(merged[46], 0x7F, "tkt_flags: current 0x40 | new 0x3F");
        assert_eq!(merged[47], CHAL_HMAC, "cfg_flags preserved (CHAL_RESP)");

        // The merged slot must still answer calculate with the ORIGINAL
        // key material (key/uid preserved) and original cfg_flags
        // (CHAL_HMAC preserved because CHAL_RESP was set).
        let challenge: Vec<u8> = (0..64).map(|i| (i * 5 + 2) as u8).collect();
        let (b, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge);
        assert_eq!(sw, 0x9000, "CHAL_RESP + CHAL_HMAC must survive update");
        let expected = hmac_sha1(&[&aes_key[..], &uid[..]].concat(), &challenge);
        assert_eq!(b, expected);
    }

    #[test]
    fn update_0x04_cfg_flags_take_only_masked_bits_when_no_chal_resp() {
        let mut app = OtpApp::new();
        let acc = [0x11u8; 6];
        // Current config: no CHAL_RESP -> the cfg_flags update mask (0x0C)
        // applies. Note the merged tkt_flags loses CHAL_RESP (current has no
        // high bits, the mask 0x3F cannot set it), so the merge is asserted
        // on the stored state rather than through `calculate`.
        configure(
            &mut app,
            0,
            make_config_acc([1, 2, 3, 4, 5, 6], [0xAA; 16], acc, 0, CHAL_HMAC),
        );
        let mut cfg_b = [0u8; 52];
        cfg_b[38..44].copy_from_slice(&acc);
        cfg_b[45] = 0x20; // ext_flags: ALLOW_UPDATE (mask 0xFF passes it)
        cfg_b[47] = CFG_UPDATE_BIT; // PACING_10MS == HMAC_LT64 bit
        let stored = !crc16(&cfg_b[..50]);
        cfg_b[50..52].copy_from_slice(&stored.to_le_bytes());
        let mut body58 = cfg_b.to_vec();
        body58.extend_from_slice(&acc);
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &body58);
        assert_eq!(sw, 0x9000);
        let merged = app.slots[0].expect("slot stays configured");
        // tkt_flags: (current & 0xC0) | (new & 0x3F) = 0 — CHAL_RESP gone.
        assert_eq!(merged[46], 0);
        // cfg_flags: (CHAL_HMAC 0x22 & !0x0C) | PACING_10MS == 0x26.
        assert_eq!(merged[47], 0x26);
        // ext_flags pass through unchanged (EXTFLAG_UPDATE_MASK == 0xFF).
        assert_eq!(merged[45], 0x20);
        // The secret material region is still the current one.
        assert_eq!(&merged[22..38], &[0xAAu8; 16]);
    }

    #[test]
    fn update_requires_access_code_when_slot_occupied() {
        let mut app = OtpApp::new();
        let acc = [0x11u8; 6];
        configure(
            &mut app,
            0,
            make_config_acc([1, 2, 3, 4, 5, 6], [0xAA; 16], acc, CHAL_RESP, CHAL_HMAC),
        );
        // 52 bytes only: C requires nc >= otp_config_size + 6 for an
        // occupied slot -> SW_WRONG_LENGTH (0x6700 in the pico-keys SDK).
        let config = make_config_acc([1, 2, 3, 4, 5, 6], [0xAA; 16], acc, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &config);
        assert_eq!(sw, SW_WRONG_DATA);
    }

    #[test]
    fn update_rejects_wrong_access_code() {
        let mut app = OtpApp::new();
        configure(
            &mut app,
            0,
            make_config_acc(
                [1, 2, 3, 4, 5, 6],
                [0xAA; 16],
                [0x11; 6],
                CHAL_RESP,
                CHAL_HMAC,
            ),
        );
        let mut cfg_b = [0u8; 52];
        cfg_b[38..44].copy_from_slice(&[0x11; 6]);
        let stored = !crc16(&cfg_b[..50]);
        cfg_b[50..52].copy_from_slice(&stored.to_le_bytes());
        let mut body58 = cfg_b.to_vec();
        body58.extend_from_slice(&[0x99; 6]); // wrong access code
        let (body, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &body58);
        assert_eq!(sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        assert!(body.is_empty());
    }

    #[test]
    fn update_on_empty_slot_is_a_noop_success() {
        let mut app = OtpApp::new();
        let mut cfg_b = [0u8; 52];
        cfg_b[38..44].copy_from_slice(&[0x11; 6]);
        cfg_b[47] = CFG_UPDATE_BIT;
        let stored = !crc16(&cfg_b[..50]);
        cfg_b[50..52].copy_from_slice(&stored.to_le_bytes());
        // C: an empty slot skips the merge entirely — no access code needed.
        let (body, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &cfg_b);
        assert_eq!(sw, 0x9000);
        assert_eq!(body.len(), 6, "status body still returned");
        assert!(body[4] & FLAG_SLOT1_CONFIGURED == 0, "slot stays empty");
        assert!(!app.slot_configured(0));
    }

    #[test]
    fn update_rejects_bad_crc_even_on_empty_slot() {
        let mut app = OtpApp::new();
        let mut cfg_b = [0u8; 52];
        cfg_b[38..44].copy_from_slice(&[0x11; 6]);
        cfg_b[51] ^= 0xFF;
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &cfg_b);
        assert_eq!(sw, SW_WRONG_DATA);
    }

    #[test]
    fn update_rejects_short_body() {
        let mut app = OtpApp::new();
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &[0u8; 51]);
        assert_eq!(sw, SW_WRONG_DATA);
    }

    #[test]
    fn update_0x04_targets_slot_1_and_0x05_targets_slot_2() {
        let mut app = OtpApp::new();
        // Only slot 2 is configured (via 0x03), with access code [1;6].
        configure(
            &mut app,
            1,
            make_config_acc([6, 5, 4, 3, 2, 1], [0xBB; 16], [1; 6], CHAL_RESP, CHAL_HMAC),
        );
        // 0x05 targets slot 2: the wrong access code is checked and fails.
        let mut cfg_b = [0u8; 52];
        cfg_b[38..44].copy_from_slice(&[1; 6]);
        let stored = !crc16(&cfg_b[..50]);
        cfg_b[50..52].copy_from_slice(&stored.to_le_bytes());
        let mut wrong = cfg_b.to_vec();
        wrong.extend_from_slice(&[0x99; 6]);
        let (body, sw) = update_raw(&mut app, UPDATE_SLOT2, 0, &wrong);
        assert_eq!(sw, SW_SECURITY_STATUS_NOT_SATISFIED, "0x05 checks slot 2");
        assert!(body.is_empty());
        // 0x04 targets slot 1, which is empty: no access check, noop success.
        let (body, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &cfg_b);
        assert_eq!(sw, 0x9000, "0x04 on an empty slot 1 is a noop success");
        assert!(body[4] & FLAG_SLOT1_CONFIGURED == 0);
    }

    #[test]
    fn update_rejects_nonzero_p2_for_slot_2_opcodes() {
        let mut app = OtpApp::new();
        let mut cfg_b = [0u8; 52];
        cfg_b[38..44].copy_from_slice(&[1; 6]);
        let stored = !crc16(&cfg_b[..50]);
        cfg_b[50..52].copy_from_slice(&stored.to_le_bytes());
        // 0x05 is the "slot 2" opcode: it carries no P2 offset (C
        // `otp_slot_offset_valid`), so any nonzero P2 is 6A86.
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT2, 1, &cfg_b);
        assert_eq!(sw, SW_INCORRECT_P1P2);
        // US-140: 0x04 *does* carry a P2 offset, bounded by the 4-slot
        // table. Offset 4 is past the end.
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT1, 4, &cfg_b);
        assert_eq!(sw, SW_INCORRECT_P1P2, "the C rule caps P2 offsets at 3");
    }

    // ---- Yubico AES challenge-response 0x20 / 0x28 ----

    /// The default 10-byte serial-string tail (C `pico_serial_str[0..10]`):
    /// the C zero-ID fallback serializes as ASCII '0' hex pairs.
    const DEFAULT_SERIAL_STR: [u8; 10] = *b"0000000000";

    fn aes_ecb_encrypt(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        use aes::cipher::{generic_array::GenericArray, BlockEncrypt as _, KeyInit as _};
        use aes::Aes128;
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let mut out = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut out);
        out.into()
    }

    #[test]
    fn calculate_aes_0x20_returns_ecb_of_challenge_plus_serial() {
        let mut app = OtpApp::new();
        let aes_key = [0xC0u8; 16];
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], aes_key, CHAL_RESP, CHAL_YUBICO),
        );
        let challenge = [0x0Fu8; 6];
        let mut block = [0u8; 16];
        block[..6].copy_from_slice(&challenge);
        block[6..].copy_from_slice(&DEFAULT_SERIAL_STR);
        let expected = aes_ecb_encrypt(&aes_key, &block);

        let (body, sw) = calculate(&mut app, CALC_AES_SLOT1, &challenge);
        assert_eq!(sw, 0x9000);
        assert_eq!(body.len(), 16, "AES-ECB response is a full block");
        assert_eq!(body, expected);
    }

    #[test]
    fn calculate_aes_0x28_uses_slot_2_key() {
        let mut app = OtpApp::new();
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_YUBICO),
        );
        let key2 = [0x5Eu8; 16];
        configure(
            &mut app,
            1,
            make_config([6, 5, 4, 3, 2, 1], key2, CHAL_RESP, CHAL_YUBICO),
        );
        let challenge = [0x42u8; 6];
        let mut block = [0u8; 16];
        block[..6].copy_from_slice(&challenge);
        block[6..].copy_from_slice(&DEFAULT_SERIAL_STR);
        let expected = aes_ecb_encrypt(&key2, &block);
        let (body, sw) = calculate(&mut app, CALC_AES_SLOT2, &challenge);
        assert_eq!(sw, 0x9000);
        assert_eq!(body, expected);
    }

    #[test]
    fn calculate_aes_uses_injected_serial_string() {
        let mut app = OtpApp::new().with_serial_str(*b"DEADBEEF01");
        let aes_key = [0xC0u8; 16];
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], aes_key, CHAL_RESP, CHAL_YUBICO),
        );
        let challenge = [0x0Fu8; 6];
        let mut block = [0u8; 16];
        block[..6].copy_from_slice(&challenge);
        block[6..].copy_from_slice(b"DEADBEEF01");
        let expected = aes_ecb_encrypt(&aes_key, &block);
        let (body, sw) = calculate(&mut app, CALC_AES_SLOT1, &challenge);
        assert_eq!(sw, 0x9000);
        assert_eq!(body, expected);
    }

    #[test]
    fn calculate_aes_requires_chal_yubico_flag() {
        let mut app = OtpApp::new();
        // C quirk (otp.c): CHAL_HMAC == 0x22 *includes* the CHAL_YUBICO bit
        // (0x20), so the AES gate only rejects configs without bit 0x20 —
        // e.g. the bare HMAC sub-bit 0x02.
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, 0x02),
        );
        let (body, sw) = calculate(&mut app, CALC_AES_SLOT1, &[0u8; 6]);
        assert_eq!(sw, SW_WRONG_DATA);
        assert!(body.is_empty());
    }

    #[test]
    fn calculate_aes_passes_gate_for_hmac_flag_config_like_c() {
        // CHAL_HMAC (0x22) contains the CHAL_YUBICO bit, so the C AES branch
        // accepts it; the response is the AES block, same as for a Yubico
        // config. Pin this loose gate as exact C parity.
        let mut app = OtpApp::new();
        let aes_key = [0xC0u8; 16];
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], aes_key, CHAL_RESP, CHAL_HMAC),
        );
        let challenge = [0x2Au8; 6];
        let mut block = [0u8; 16];
        block[..6].copy_from_slice(&challenge);
        block[6..].copy_from_slice(&DEFAULT_SERIAL_STR);
        let expected = aes_ecb_encrypt(&aes_key, &block);
        let (body, sw) = calculate(&mut app, CALC_AES_SLOT1, &challenge);
        assert_eq!(sw, 0x9000);
        assert_eq!(body, expected);
    }

    #[test]
    fn calculate_aes_requires_chal_resp_flag() {
        let mut app = OtpApp::new();
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], 0, CHAL_YUBICO),
        );
        let (body, sw) = calculate(&mut app, CALC_AES_SLOT1, &[0u8; 6]);
        assert_eq!(sw, SW_WRONG_DATA);
        assert!(body.is_empty());
    }

    #[test]
    fn calculate_aes_rejects_short_challenge() {
        let mut app = OtpApp::new();
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_YUBICO),
        );
        let (body, sw) = calculate(&mut app, CALC_AES_SLOT1, &[0u8; 5]);
        assert_eq!(sw, SW_WRONG_DATA); // C SW_WRONG_LENGTH == 0x6700 here
        assert!(body.is_empty());
    }

    #[test]
    fn calculate_aes_unconfigured_slot_returns_ok_empty() {
        let mut app = OtpApp::new();
        let (body, sw) = calculate(&mut app, CALC_AES_SLOT1, &[0u8; 6]);
        assert_eq!(sw, SW_OK);
        assert!(body.is_empty());
    }

    // ==================================================================
    // US-140 (PICOForge-COMPAT): four-slot addressing.
    //
    // The reference client addresses the table with the C's own rule
    // (`otp_slot_offset_valid`, pico-fido/src/fido/otp.c:641):
    //
    //   configure  slot1 (0x01,0x00)  slot2 (0x03,0x00)
    //              slot3 (0x01,0x02)  slot4 (0x01,0x03)
    //   challenge  slot1 (0x30,0x00)  slot2 (0x38,0x00)
    //              slot3 (0x30,0x02)  slot4 (0x30,0x03)
    //
    // (picoforge `config_p1p2` / `chal_p1p2`,
    //  `src/hal/applets/otp.rs:124-141`.) These tests drive those exact
    //  pairs; a firmware that answers 6A86 for one of them is a firmware
    //  the client cannot program.
    // ==================================================================

    /// Configure a slot through the reference client's `(P1, P2)` pair.
    /// Mirrors picoforge `configure`: the 52-byte frame followed by the
    /// 6-byte *current* access code.
    fn configure_as_client(
        app: &mut OtpApp,
        p1: u8,
        p2: u8,
        cfg: &[u8; 52],
        acc: &[u8; 6],
    ) -> (Vec<u8>, u16) {
        let mut body = cfg.to_vec();
        body.extend_from_slice(acc);
        let mut apdu = vec![0x00, INS_OTP, p1, p2, body.len() as u8];
        apdu.extend_from_slice(&body);
        drive(app, &apdu)
    }

    /// Challenge a slot through the reference client's `(P1, P2)` pair with
    /// the fixed 64-byte frame (picoforge `calculate_hmac`).
    fn challenge_as_client(app: &mut OtpApp, p1: u8, p2: u8, frame: &[u8]) -> (Vec<u8>, u16) {
        let mut apdu = vec![0x00, INS_OTP, p1, p2, frame.len() as u8];
        apdu.extend_from_slice(frame);
        drive(app, &apdu)
    }

    const NO_ACC: [u8; 6] = [0; 6];
    /// A 64-byte challenge frame with distinct bytes (no LT64 trim).
    fn challenge_frame() -> [u8; 64] {
        let mut f = [0u8; 64];
        for (i, b) in f.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        f
    }

    /// US-140 RED/GREEN: every one of the reference client's eight
    /// (P1, P2) address pairs reaches its own slot, and each slot answers
    /// with its OWN key material.
    #[test]
    fn slot3_and_slot4_are_addressable() {
        // Distinct key material per slot, so a mis-addressed challenge
        // cannot pass by accident.
        let keys: [[u8; 16]; 4] = [[0xA0u8; 16], [0xB0u8; 16], [0xC0u8; 16], [0xD0u8; 16]];
        let uids: [[u8; 6]; 4] = [
            [1, 1, 1, 1, 1, 1],
            [2, 2, 2, 2, 2, 2],
            [3, 3, 3, 3, 3, 3],
            [4, 4, 4, 4, 4, 4],
        ];
        // The (P1, P2) pair the client uses for each 1-based slot, for
        // configure and for challenge.
        let config_p1p2 = [
            (SLOT_CONFIGURE, 0u8),
            (SLOT_CONFIGURE_SLOT2, 0),
            (SLOT_CONFIGURE, 2),
            (SLOT_CONFIGURE, 3),
        ];
        let chal_p1p2 = [
            (CALC_HMAC_SLOT1, 0u8),
            (CALC_HMAC_SLOT2, 0),
            (CALC_HMAC_SLOT1, 2),
            (CALC_HMAC_SLOT1, 3),
        ];

        let mut app = OtpApp::new();
        for slot in 0..4 {
            let cfg = make_config(uids[slot], keys[slot], CHAL_RESP, CHAL_HMAC);
            let (body, sw) = configure_as_client(
                &mut app,
                config_p1p2[slot].0,
                config_p1p2[slot].1,
                &cfg,
                &NO_ACC,
            );
            assert_eq!(sw, SW_OK, "configure slot {} rejected", slot + 1);
            assert!(body.is_empty() || body.len() == 6, "unexpected body shape");
            assert!(
                app.slot_configured(slot),
                "slot {} not programmed",
                slot + 1
            );
        }

        let frame = challenge_frame();
        for slot in 0..4 {
            let (body, sw) =
                challenge_as_client(&mut app, chal_p1p2[slot].0, chal_p1p2[slot].1, &frame);
            assert_eq!(sw, SW_OK, "challenge slot {} rejected", slot + 1);
            let expected = hmac_sha1(&[&keys[slot][..], &uids[slot][..]].concat(), &frame);
            assert_eq!(
                body,
                expected,
                "slot {} answered with another slot's key",
                slot + 1
            );
        }
    }

    /// The C addressing rule in full: `p2 <= 3` on 0x01/0x04/0x20/0x30,
    /// `p2 == 0` on every other opcode.
    #[test]
    fn slot_offset_validity_matches_the_c_rule() {
        let cfg = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        let mut app = OtpApp::new();
        for p1 in [
            SLOT_CONFIGURE,
            UPDATE_SLOT1,
            CALC_HMAC_SLOT1,
            CALC_AES_SLOT1,
        ] {
            for p2 in 0..=3u8 {
                assert!(
                    OtpApp::slot_offset_valid(p1, p2),
                    "{p1:#04x}/{p2} must be valid"
                );
            }
            assert!(
                !OtpApp::slot_offset_valid(p1, 4),
                "{p1:#04x}/4 must be invalid"
            );
        }
        for p1 in [
            SLOT_CONFIGURE_SLOT2,
            UPDATE_SLOT2,
            CALC_HMAC_SLOT2,
            CALC_AES_SLOT2,
            SLOT_SWAP,
        ] {
            assert!(
                OtpApp::slot_offset_valid(p1, 0),
                "{p1:#04x}/0 must be valid"
            );
            assert!(
                !OtpApp::slot_offset_valid(p1, 1),
                "{p1:#04x}/1 must be invalid"
            );
        }
        // And the two configure spellings of slot 2 are distinct slots.
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 1, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK, "(0x01,0x01) is the C's slot 2 spelling");
        assert!(app.slot_configured(1));
        assert!(
            !app.slot_configured(0),
            "(0x01,0x01) must not have touched slot 1"
        );
    }

    /// US-140 persistence decision: a device holding a **2-slot** state blob
    /// under the retired `otp.slots.v1` key boots to the factory default.
    /// The v1 record is never read, so its bytes can never be re-interpreted
    /// as v2 slots (the `store_v3` "never loaded, never silently re-seeded"
    /// rule, `platform/src/store_v3.rs:49-53`).
    #[test]
    fn a_legacy_two_slot_state_blob_is_refused_not_reinterpreted() {
        use fapico2_platform::secure_store::HostSecureStore;

        let mut store = HostSecureStore::new();
        // Build a genuine 119-byte v1 record: two configured slots plus a
        // device access code.
        let mut legacy = heapless::Vec::<u8, STATE_SIZE_V1>::new();
        for slot in 0..2 {
            legacy.push(1).ok();
            legacy
                .extend_from_slice(&make_config(
                    [slot as u8 + 1; 6],
                    [0x5Au8; 16],
                    CHAL_RESP,
                    CHAL_HMAC,
                ))
                .ok();
        }
        legacy.push(1).ok(); // access-code present
        legacy.extend_from_slice(&[0x77u8; 6]).ok();
        assert_eq!(
            legacy.len(),
            STATE_SIZE_V1,
            "the v1 record really is 119 bytes"
        );
        assert_ne!(
            legacy.len(),
            STATE_SIZE,
            "the two layouts must differ, else the refusal is vacuous"
        );
        store
            .write(STATE_SLOT_V1, &legacy)
            .expect("seed the legacy record");

        let app = OtpApp::boot(&mut store);
        for slot in 0..SLOT_COUNT {
            assert!(
                !app.slot_configured(slot),
                "slot {} must not be re-seeded",
                slot + 1
            );
        }
        // The v1 record is left untouched — boot is not a wipe.
        assert!(
            store.contains(STATE_SLOT_V1),
            "boot must not delete the legacy record"
        );
        assert!(
            !store.contains(STATE_SLOT),
            "boot must not invent a v2 record"
        );
    }

    /// US-140 review fix: boot leaves the retired record alone (above), but
    /// the first *write* of the v2 record purges it. The management
    /// factory-reset path is such a write, so a reset removes the retired
    /// pre-upgrade OTP material (two slots' uid + AES keys and the
    /// device-wide access code) instead of sealing it in the partition
    /// forever.
    #[test]
    fn a_persist_purges_the_retired_v1_record() {
        use fapico2_platform::secure_store::HostSecureStore;

        let mut store = HostSecureStore::new();
        store
            .write(STATE_SLOT_V1, &[0x5Au8; STATE_SIZE_V1])
            .expect("seed the legacy record");
        assert!(
            store.contains(STATE_SLOT_V1),
            "precondition: the retired record is present"
        );

        let mut app = OtpApp::boot(&mut store);
        app.factory_wipe();
        assert!(
            app.persist_state(&mut store),
            "the emptied v2 record is persisted"
        );
        assert!(
            !store.contains(STATE_SLOT_V1),
            "a factory reset must remove the retired v1 record, not leave it sealed"
        );
        // And it is gone for good, not merely hidden: a reboot cannot bring
        // it back, because nothing ever read it.
        let rebooted = OtpApp::boot(&mut store);
        assert!(!rebooted.slot_configured(0) && !rebooted.slot_configured(1));
    }

    /// The 4-slot state round-trips through the secure store: every slot and
    /// the access code survive a reboot, and the record is written under the
    /// new (versioned) key at the new size.
    #[test]
    fn four_slot_state_round_trips_through_the_store() {
        use fapico2_platform::secure_store::HostSecureStore;

        let mut store = HostSecureStore::new();
        let mut app = OtpApp::boot(&mut store);
        for slot in 0..4 {
            let cfg = make_config(
                [slot as u8; 6],
                [0x11 * (slot as u8 + 1); 16],
                CHAL_RESP,
                CHAL_HMAC,
            );
            let (p1, p2) = match slot {
                0 => (SLOT_CONFIGURE, 0),
                1 => (SLOT_CONFIGURE_SLOT2, 0),
                2 => (SLOT_CONFIGURE, 2),
                _ => (SLOT_CONFIGURE, 3),
            };
            let (_, sw) = configure_as_client(&mut app, p1, p2, &cfg, &NO_ACC);
            assert_eq!(sw, SW_OK, "configure slot {} rejected", slot + 1);
        }
        app.save(&mut store).expect("persist");

        let mut probe = [0u8; STATE_SIZE];
        assert_eq!(
            store.read(STATE_SLOT, &mut probe).expect("read v2"),
            STATE_SIZE,
            "the v2 record is {} bytes",
            STATE_SIZE
        );

        let mut rebooted = OtpApp::boot(&mut store);
        for slot in 0..4 {
            assert!(
                rebooted.slot_configured(slot),
                "slot {} lost across reboot",
                slot + 1
            );
        }
        // Secret material really came back, not just the presence bits.
        let frame = challenge_frame();
        let (body, sw) = challenge_as_client(&mut rebooted, CALC_HMAC_SLOT1, 3, &frame);
        assert_eq!(sw, SW_OK);
        let expected = hmac_sha1(&[&[0x11 * 4u8; 16][..], &[3u8; 6][..]].concat(), &frame);
        assert_eq!(body, expected, "slot 4's key must survive the reboot");
    }

    /// The factory-reset path empties all four slots, not just the first two.
    #[test]
    fn factory_reset_empties_all_four_slots() {
        let mut app = OtpApp::new();
        for (p1, p2) in [
            (SLOT_CONFIGURE, 0u8),
            (SLOT_CONFIGURE_SLOT2, 0),
            (SLOT_CONFIGURE, 2),
            (SLOT_CONFIGURE, 3),
        ] {
            let cfg = make_config([9, 9, 9, 9, 9, 9], [0x33; 16], CHAL_RESP, CHAL_HMAC);
            let (_, sw) = configure_as_client(&mut app, p1, p2, &cfg, &NO_ACC);
            assert_eq!(sw, SW_OK);
        }
        for slot in 0..4 {
            assert!(app.slot_configured(slot));
        }
        app.reset();
        for slot in 0..4 {
            assert!(
                !app.slot_configured(slot),
                "slot {} survived the reset",
                slot + 1
            );
        }
    }

    /// The 6-byte post-configure status body's configured-bitmap now spans
    /// four slots.
    #[test]
    fn status_body_flags_cover_all_four_slots() {
        let mut app = OtpApp::new();
        let cfg = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        let (body, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 2, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        assert_eq!(body.len(), STATUS_LEN);
        assert_eq!(body[4] & FLAG_SLOT3_CONFIGURED, FLAG_SLOT3_CONFIGURED);
        assert_eq!(body[4] & FLAG_SLOT1_CONFIGURED, 0);
        assert_eq!(body[4] & FLAG_SLOT4_CONFIGURED, 0);
    }

    // ==================================================================
    // US-141 (PICOForge-COMPAT): per-slot STATUS TLVs (P1 0x14).
    // ==================================================================

    /// A faithful re-implementation of the reference client's
    /// `classify` (picoforge `src/hal/applets/otp.rs:108-120`), so the
    /// assertions below read the answer the *client* computes rather than
    /// the firmware's opinion of it.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    enum ClientSlotType {
        Empty,
        YubicoOtp,
        StaticPassword,
        OathHotp,
        ChallengeResponse,
    }

    fn client_classify(tkt: u8, cfg: u8) -> ClientSlotType {
        const TKT_CHAL_RESP: u8 = 0x40;
        const CFG_CHAL_YUBICO: u8 = 0x20;
        const CFG_STATIC_TICKET: u8 = 0x20;
        const CFG_SHORT_TICKET: u8 = 0x02;
        if tkt & TKT_CHAL_RESP != 0 {
            if cfg & CFG_CHAL_YUBICO != 0 {
                ClientSlotType::ChallengeResponse
            } else {
                ClientSlotType::OathHotp
            }
        } else if cfg & (CFG_STATIC_TICKET | CFG_SHORT_TICKET) != 0 {
            ClientSlotType::StaticPassword
        } else {
            ClientSlotType::YubicoOtp
        }
    }

    /// A faithful re-implementation of the reference client's `read_info`
    /// TLV walk (picoforge `src/hal/applets/otp.rs:381-407`): a real
    /// single-byte-length TLV sequence, and only tags `0xB0..=0xB3` whose
    /// value contains an `0xA0` of at least 2 bytes overwrite the
    /// pre-filled Empty entries.
    fn client_read_info(resp: &[u8]) -> [ClientSlotType; 4] {
        fn find(value: &[u8], tag: u8) -> Option<&[u8]> {
            let mut i = 0;
            while i + 2 <= value.len() {
                if value[i] == tag {
                    let len = value[i + 1] as usize;
                    if i + 2 + len <= value.len() {
                        return Some(&value[i + 2..i + 2 + len]);
                    }
                    return None;
                }
                i += 2 + value[i + 1] as usize;
            }
            None
        }
        let mut slots = [ClientSlotType::Empty; 4];
        let mut i = 0;
        while i + 2 <= resp.len() {
            let tag = resp[i];
            let len = resp[i + 1] as usize;
            assert!(i + 2 + len <= resp.len(), "truncated TLV 0x{tag:02X}");
            let value = &resp[i + 2..i + 2 + len];
            if (0xB0..=0xB3).contains(&tag) {
                if let Some(flags) = find(value, 0xA0) {
                    if flags.len() >= 2 {
                        slots[(tag - 0xB0) as usize] = client_classify(flags[0], flags[1]);
                    }
                }
            }
            i += 2 + len;
        }
        slots
    }

    /// Read EXTENDED STATUS the way the reference client does: a
    /// data-less APDU, body = whatever comes back.
    fn read_info(app: &mut OtpApp) -> (Vec<u8>, u16) {
        // `00 01 14 00 00` — ISO 7816-4 case 1 (no Lc, no Le).
        drive(app, &[0x00, INS_OTP, STATUS_EXT, 0x00, 0x00])
    }

    /// US-141 RED/GREEN: every configured slot appears as exactly one
    /// `0xB0 + index` TLV wrapping `0xA0 0x02 <tkt> <cfg>`, in slot order,
    /// carrying the slot's real flag bytes.
    #[test]
    fn status_reports_per_slot_tlvs() {
        let mut app = OtpApp::new();
        // Two challenge-response slots (distinct flag bytes each) plus one
        // static-shaped slot, so a swapped or mis-indexed TLV is visible.
        let slot1 = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        let slot3 = make_config([3, 3, 3, 3, 3, 3], [0xCC; 16], CHAL_RESP, CHAL_HMAC | 0x04);
        for (p1, p2, cfg) in [(SLOT_CONFIGURE, 0u8, &slot1), (SLOT_CONFIGURE, 2, &slot3)] {
            let (_, sw) = configure_as_client(&mut app, p1, p2, cfg, &NO_ACC);
            assert_eq!(sw, SW_OK);
        }

        let (body, sw) = read_info(&mut app);
        assert_eq!(sw, SW_OK);
        // Two configured slots -> two TLVs, nothing else. Slot 2 and 4 are
        // absent from the stream entirely.
        assert_eq!(
            body,
            vec![
                0xB0,
                0x04,
                0xA0,
                0x02,
                CHAL_RESP,
                CHAL_HMAC, // slot 1
                0xB2,
                0x04,
                0xA0,
                0x02,
                CHAL_RESP,
                CHAL_HMAC | 0x04, // slot 3
            ],
            "one TLV per configured slot, tagged 0xB0 + index"
        );
        assert_eq!(
            client_read_info(&body),
            [
                // CHAL_HMAC (0x22) carries the CHAL_YUBICO bit (0x20), so
                // the client classifies an HMAC slot as ChallengeResponse —
                // the reference client's own `classify(0x40, 0x26)`.
                ClientSlotType::ChallengeResponse,
                ClientSlotType::Empty,
                ClientSlotType::ChallengeResponse,
                ClientSlotType::Empty,
            ],
            "the client's own parser must agree"
        );
    }

    /// US-141: an unconfigured slot is **omitted**, and that omission — not
    /// a zero-filled TLV — is what makes the client read it as Empty.
    #[test]
    fn absent_slot_tlv_reads_as_empty() {
        let mut app = OtpApp::new();
        // A completely blank device: no TLVs at all.
        let (body, sw) = read_info(&mut app);
        assert_eq!(sw, SW_OK);
        assert!(
            body.is_empty(),
            "a blank device must emit no TLVs, got {body:02X?}"
        );
        assert_eq!(
            client_read_info(&body),
            [ClientSlotType::Empty; 4],
            "all four slots read Empty"
        );

        // Program one slot, wipe it, and confirm it disappears from the
        // stream again — and that the disappearance, not a zero TLV, is
        // what the client sees.
        let cfg = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, _) = read_info(&mut app);
        assert_eq!(body.len(), 6, "exactly one TLV while slot 1 is programmed");

        // All-zero write erases the slot (C parity).
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &[0u8; 52], &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = read_info(&mut app);
        assert_eq!(sw, SW_OK);
        assert!(
            body.is_empty(),
            "the wiped slot's TLV must be omitted, got {body:02X?}"
        );

        // The counterfactual: a zero-filled TLV for that slot would read
        // back as a *programmed* Yubico-OTP slot, which is exactly the bug
        // the omission avoids.
        assert_eq!(client_classify(0x00, 0x00), ClientSlotType::YubicoOtp);
        let zero_filled = [0xB0u8, 0x04, 0xA0, 0x02, 0x00, 0x00];
        assert_eq!(
            client_read_info(&zero_filled)[0],
            ClientSlotType::YubicoOtp,
            "zero-filling would fabricate a slot — the client's classify(0,0) is YubicoOtp"
        );
    }

    /// A wiped slot must not read back as YubicoOtp end to end: program,
    /// wipe, re-read, and assert the client's own classification.
    #[test]
    fn wiped_slot_does_not_read_back_as_yubico_otp() {
        let mut app = OtpApp::new();
        for (p1, p2) in [
            (SLOT_CONFIGURE, 0u8),
            (SLOT_CONFIGURE_SLOT2, 0),
            (SLOT_CONFIGURE, 2),
            (SLOT_CONFIGURE, 3),
        ] {
            // A Yubico-OTP-shaped slot (tkt = 0, cfg = 0) — the one shape
            // the client classifies as YubicoOtp.
            let mut cfg = make_config([7; 6], [0x77; 16], 0, 0);
            cfg[44] = 6; // fixed_size: a public id is present
            let stored = !crc16(&cfg[..50]);
            cfg[50..52].copy_from_slice(&stored.to_le_bytes());
            let (_, sw) = configure_as_client(&mut app, p1, p2, &cfg, &NO_ACC);
            assert_eq!(sw, SW_OK);
        }
        let (body, _) = read_info(&mut app);
        assert_eq!(
            client_read_info(&body),
            [ClientSlotType::YubicoOtp; 4],
            "all four really were programmed as Yubico-OTP slots"
        );

        // Wipe slot 3 only.
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 2, &[0u8; 52], &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = read_info(&mut app);
        assert_eq!(sw, SW_OK);
        let seen = client_read_info(&body);
        assert_eq!(
            seen[2],
            ClientSlotType::Empty,
            "the wiped slot must read Empty"
        );
        assert_ne!(
            seen[2],
            ClientSlotType::YubicoOtp,
            "a wiped slot must never read back as YubicoOtp"
        );
        for i in [0usize, 1, 3] {
            assert_eq!(
                seen[i],
                ClientSlotType::YubicoOtp,
                "slot {} survived",
                i + 1
            );
        }
    }

    /// The TLV stream reflects the *stored* slot, so a per-slot
    /// configuration change shows up immediately.
    #[test]
    fn status_tlvs_track_the_flag_update_merge() {
        let mut app = OtpApp::new();
        let acc = [0x11u8; 6];
        let app_cfg = make_config_acc([1, 2, 3, 4, 5, 6], [0xAA; 16], acc, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &app_cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, _) = read_info(&mut app);
        assert_eq!(
            client_read_info(&body)[0],
            ClientSlotType::ChallengeResponse
        );

        // A SLOT_UPDATE that asks for a different cfg_flags. The C merge
        // preserves cfg_flags wholesale whenever the *current* tkt_flags
        // has CHAL_RESP, so the 0x04 request is dropped — and the TLV
        // must show the stored bytes, not the requested ones.
        let mut upd = [0u8; 52];
        upd[38..44].copy_from_slice(&acc);
        upd[45] = 0x20; // ext_flags: ALLOW_UPDATE
        upd[47] = CFG_UPDATE_BIT; // 0x04 — the only cfg bit the C mask lets through
        let stored = !crc16(&upd[..50]);
        upd[50..52].copy_from_slice(&stored.to_le_bytes());
        let mut body58 = upd.to_vec();
        body58.extend_from_slice(&acc);
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &body58);
        assert_eq!(sw, SW_OK);
        // cfg_flags is now 0x26 (CHAL_HMAC 0x22 | 0x04) and tkt_flags lost
        // CHAL_RESP — the client's classification follows the stored bytes.
        let merged = app.slots[0].expect("slot stays configured");
        let (body, _) = read_info(&mut app);
        assert_eq!(
            body,
            vec![0xB0u8, 0x04, 0xA0, 0x02, merged[46], merged[47]],
            "the TLV carries the merged flag bytes"
        );
        // The C merge dropped the 0x04 request (current CHAL_RESP set) and
        // kept CHAL_RESP in tkt_flags; the TLV reports exactly that.
        assert_eq!(
            merged[47], CHAL_HMAC,
            "cfg_flags preserved wholesale under CHAL_RESP"
        );
        assert_eq!(merged[46], CHAL_RESP, "tkt_flags keeps its high bits");
        assert_eq!(body[4], CHAL_RESP);
        assert_eq!(body[5], CHAL_HMAC);
    }

    /// P1 0x14 carries no slot offset: a nonzero P2 is 6A86, not a slot
    /// selector.
    #[test]
    fn status_ext_rejects_nonzero_p2() {
        let mut app = OtpApp::new();
        let cfg = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = drive(&mut app, &[0x00, INS_OTP, STATUS_EXT, 0x02, 0x00]);
        assert_eq!(sw, SW_INCORRECT_P1P2);
        assert!(body.is_empty());
    }

    // ==================================================================
    // US-142 (PICOForge-COMPAT): the 52-byte config frame + CRC-16/X.25.
    //
    // **Already implemented and enforced** (configure and update, both
    // since US-712). This story is the conformance PIN: it asserts the
    // exact field layout, the residual the reference client asserts, and
    // that the two enforcement paths actually reject a corrupt frame. It
    // is expected to be green on the first run — that is the point.
    // ==================================================================

    /// A fully-populated 52-byte config: every field carries a distinct,
    /// non-zero value so a misplaced offset cannot pass unnoticed.
    fn full_config() -> [u8; 52] {
        let mut c = [0u8; 52];
        for (i, b) in c[CFG_FIXED_DATA..CFG_FIXED_DATA + 16]
            .iter_mut()
            .enumerate()
        {
            *b = 0xA0 | i as u8;
        }
        c[CFG_UID..CFG_UID + 6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        for (i, b) in c[CFG_AES_KEY..CFG_AES_KEY + 16].iter_mut().enumerate() {
            *b = 0xB0 | i as u8;
        }
        c[CFG_ACC_CODE..CFG_ACC_CODE + 6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        c[CFG_FIXED_SIZE] = 16;
        c[CFG_EXT_FLAGS] = 0x20;
        c[CFG_TKT_FLAGS] = CHAL_RESP;
        c[CFG_CFG_FLAGS] = CHAL_HMAC;
        let stored = !crc16(&c[..CFG_CRC]);
        c[CFG_CRC..].copy_from_slice(&stored.to_le_bytes());
        c
    }

    /// US-142: the whole story in one test — layout, residual, single-byte
    /// rejection everywhere in the frame, rfu-must-be-zero, and both
    /// enforcement paths.
    #[test]
    fn config_crc_residual_is_f0b8() {
        let cfg = full_config();

        // ---- 1. the field layout, field by field ----
        assert_eq!(OTP_CONFIG_SIZE, 52, "otp_config_size");
        let expect_fixed: Vec<u8> = (0..16u8).map(|i| 0xA0 | i).collect();
        let expect_key: Vec<u8> = (0..16u8).map(|i| 0xB0 | i).collect();
        assert_eq!(&cfg[CFG_FIXED_DATA..CFG_FIXED_DATA + 16], &expect_fixed[..]);
        assert_eq!(
            &cfg[CFG_UID..CFG_UID + 6],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
        assert_eq!(&cfg[CFG_AES_KEY..CFG_AES_KEY + 16], &expect_key[..]);
        assert_eq!(&cfg[CFG_ACC_CODE..CFG_ACC_CODE + 6], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(cfg[CFG_FIXED_SIZE], 16);
        assert_eq!(cfg[CFG_EXT_FLAGS], 0x20);
        assert_eq!(cfg[CFG_TKT_FLAGS], 0x40);
        assert_eq!(cfg[CFG_CFG_FLAGS], 0x22);
        assert_eq!(&cfg[CFG_RFU..CFG_RFU + 2], &[0, 0], "rfu must be zero");
        // The stored CRC is the *complement*, little-endian.
        assert_eq!(
            &cfg[CFG_CRC..CFG_CRC + 2],
            (!crc16(&cfg[..CFG_CRC])).to_le_bytes()
        );

        // ---- 2. the residual over the WHOLE 52-byte frame ----
        assert_eq!(crc16(&cfg), CRC_RESIDUAL, "X.25 residual 0xF0B8");
        assert_eq!(crc16(&cfg), 0xF0B8);
        // Every reference-client builder shape lands on the same residual.
        assert_eq!(
            crc16(&make_config([0x11; 6], [0x22; 16], CHAL_RESP, CHAL_HMAC)),
            0xF0B8
        );
        assert_eq!(crc16(&make_config([0; 6], [0; 16], 0, 0)), 0xF0B8);
        // The CRC parameters themselves: init 0xFFFF, reflected poly
        // 0x8408, and NO final XOR (the complement is stored, not folded
        // into the running value — hence the separate `!`).
        assert_eq!(crc16(&[]), 0xFFFF);

        // ---- 3. the frame is accepted, byte for byte, by CONFIGURE ----
        let mut app = OtpApp::new();
        let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE, 0, cfg);
        assert_eq!(sw, SW_OK, "a residual-0xF0B8 frame must configure");
        assert_eq!(app.slots[0].expect("stored"), cfg, "stored verbatim");

        // ---- 4. ONE flipped byte anywhere is rejected ----
        // Every offset, not a sample, and on both enforcement paths.
        for offset in 0..OTP_CONFIG_SIZE {
            let mut bad = cfg;
            bad[offset] ^= 0x01;
            let mut app = OtpApp::new();
            let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE, 0, bad);
            assert_eq!(
                sw, SW_WRONG_DATA,
                "configure accepted a frame with byte {offset} flipped"
            );
            assert!(!app.slot_configured(0));

            let mut bad = cfg;
            bad[offset] ^= 0x80;
            let mut app = OtpApp::new();
            let (_, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &bad);
            assert_eq!(sw, SW_WRONG_DATA, "update accepted byte {offset} flipped");
        }

        // ---- 5. the rfu bytes must be zero even with a valid CRC ----
        for rfu in [CFG_RFU, CFG_RFU + 1] {
            let mut bad = cfg;
            bad[rfu] = 0x01;
            // Recompute the CRC so only the rfu rule can reject it.
            let stored = !crc16(&bad[..CFG_CRC]);
            bad[CFG_CRC..].copy_from_slice(&stored.to_le_bytes());
            assert_eq!(crc16(&bad), CRC_RESIDUAL, "precondition: the CRC is valid");
            let mut app = OtpApp::new();
            let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE, 0, bad);
            assert_eq!(sw, SW_WRONG_DATA, "rfu byte {rfu} was not enforced");
            let (_, sw) = update_raw(&mut app, UPDATE_SLOT1, 0, &bad);
            assert_eq!(sw, SW_WRONG_DATA, "update ignored rfu byte {rfu}");
        }
    }

    /// US-142 probe, **rewritten by US-144** to assert the FIXED contract.
    ///
    /// US-142 characterized the pre-US-144 behavior: a 58-byte configure
    /// authenticated only the TRAILING bytes and installed the trailing
    /// code, so (a) a client could make the device-wide code and a slot's
    /// own `acc_code` field disagree, and (b) a first program that appended
    /// six zeros for "unprotected" installed an all-zero code and ignored
    /// the one in the frame. Both assertions were true of the old code and
    /// are now **false** — which is the point of US-144. This test now
    /// pins the corrected behavior:
    ///
    /// * the TRAILING payload authenticates the CURRENT state and is
    ///   never installed;
    /// * the code in `config[38..44]` is the NEW device-wide code,
    ///   unconditionally;
    /// * so the device-wide code and the slot just written can no longer
    ///   disagree — the residual divergence (older slots keeping their own
    ///   field) is characterized at the end.
    #[test]
    fn probe_device_wide_access_code_tracks_the_written_slot() {
        let new_a = [0x11u8; 6];
        let new_b = [0x22u8; 6];
        let mut app = OtpApp::new();

        // 1. The reference client's FIRST program: `build_chalresp(..,
        //    new_acc)` embeds the new code and `configure(.., NO_ACC)`
        //    appends six zeros.
        let cfg1 = make_config_acc([1, 2, 3, 4, 5, 6], [0xAA; 16], new_a, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg1, &NO_ACC);
        assert_eq!(sw, SW_OK);
        assert_eq!(
            app.access_code,
            Some(new_a),
            "US-144: the code in the FRAME is installed, not the trailing zeros"
        );
        // The new code unlocks the next write; the zeros do not.
        let cfg2 = make_config([6, 5, 4, 3, 2, 1], [0xBB; 16], CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &cfg2, &NO_ACC);
        assert_eq!(
            sw, SW_SECURITY_STATUS_NOT_SATISFIED,
            "an unprotected write is refused"
        );
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &cfg2, &new_a);
        assert_eq!(sw, SW_OK, "the real code opens the device");

        // 2. Re-programming slot 1 with a DIFFERENT code rotates the
        //    device-wide code to it. The old code no longer opens anything.
        let cfg3 = make_config_acc([9, 9, 9, 9, 9, 9], [0xCC; 16], new_b, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg3, &new_a);
        assert_eq!(sw, SW_OK, "the trailing CURRENT code authenticated");
        assert_eq!(
            app.access_code,
            Some(new_b),
            "the frame's code is now the device code"
        );
        assert_eq!(
            &app.slots[0].expect("slot 1")[CFG_ACC_CODE..CFG_ACC_CODE + 6],
            &new_b,
            "slot 1's own field agrees with the device code -- no divergence"
        );
        let cfg4 = make_config([4, 4, 4, 4, 4, 4], [0xDD; 16], CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 2, &cfg4, &new_a);
        assert_eq!(
            sw, SW_SECURITY_STATUS_NOT_SATISFIED,
            "the superseded code is dead"
        );

        // 3. The RESIDUAL divergence US-144 does not fix, pinned: a slot
        //    keeps its OWN acc_code field, and UPDATE authenticates against
        //    THAT (C parity, otp.c:675/724) rather than against the
        //    device-wide code. Slot 2 was written in step 1 with a
        //    zero-acc_code config, so its field is all zeros -- and the
        //    device code has since rotated to new_b. UPDATE on slot 2
        //    therefore opens with the slot's zeros, NOT with the device's
        //    new_b.
        assert_eq!(
            &app.slots[1].expect("slot 2")[CFG_ACC_CODE..CFG_ACC_CODE + 6],
            &[0u8; 6],
            "precondition: slot 2's own field is zeros, the device code is new_b"
        );
        let mut upd = [0u8; 52];
        upd[CFG_EXT_FLAGS] = 0x20;
        let stored = !crc16(&upd[..CFG_CRC]);
        upd[CFG_CRC..].copy_from_slice(&stored.to_le_bytes());
        let mut with_device_code = upd.to_vec();
        with_device_code.extend_from_slice(&new_b);
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT2, 0, &with_device_code);
        assert_eq!(
            sw, SW_SECURITY_STATUS_NOT_SATISFIED,
            "the DEVICE code does not open an UPDATE"
        );
        let mut body58 = upd.to_vec();
        body58.extend_from_slice(&[0u8; 6]);
        let (_, sw) = update_raw(&mut app, UPDATE_SLOT2, 0, &body58);
        assert_eq!(
            sw, SW_OK,
            "RESIDUAL (C parity): UPDATE authenticates against the SLOT's field"
        );
        // ...and the merge then REPLACES that field with the update body's
        // six zeros, so the slot's own code is not even stable.
        assert_eq!(
            &app.slots[1].expect("slot 2")[CFG_ACC_CODE..CFG_ACC_CODE + 6],
            &[0u8; 6],
            "the C merge takes [38..44] from the incoming frame"
        );
        // 4. Boot restores the device-wide code and changes no slot field.
        use fapico2_platform::secure_store::HostSecureStore;
        let mut store = HostSecureStore::new();
        app.save(&mut store).expect("persist");
        let rebooted = OtpApp::boot(&mut store);
        assert_eq!(
            rebooted.access_code,
            Some(new_b),
            "boot restores the device code"
        );
    }

    /// US-142 probe, **rewritten by US-144**: the trailing-payload-wins bug
    /// is fixed, and a zero code now means "leave the device unprotected"
    /// (which is what the reference client means by `NO_ACC`) rather than
    /// "install a code of six zeros".
    #[test]
    fn probe_a_zero_new_code_leaves_the_device_unprotected() {
        let new_code = [0x3Cu8; 6];
        let mut app = OtpApp::new();
        let cfg = make_config_acc(
            [1, 2, 3, 4, 5, 6],
            [0xAA; 16],
            new_code,
            CHAL_RESP,
            CHAL_HMAC,
        );
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        assert_eq!(
            app.access_code,
            Some(new_code),
            "US-144: the frame's code is installed"
        );

        // Re-program with a zero acc_code field and the CURRENT code
        // trailing: the device is returned to the unprotected state.
        let plain = make_config([2, 2, 2, 2, 2, 2], [0xCC; 16], CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &plain, &new_code);
        assert_eq!(sw, SW_OK, "the current code authenticated the write");
        assert_eq!(
            app.access_code, None,
            "a zero new code leaves the device unprotected"
        );

        // ...and an unprotected device then takes a write with no code.
        let plain2 = make_config([3, 3, 3, 3, 3, 3], [0xDD; 16], CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 2, &plain2, &NO_ACC);
        assert_eq!(sw, SW_OK, "unprotected again");
        // The old code is dead, and a protected write needs a code.
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 3, &plain2, &new_code);
        assert_eq!(sw, SW_OK, "still unprotected: nothing to authenticate");
    }

    // ==================================================================
    // US-143 (PICOForge-COMPAT): the 64-byte challenge frame and the
    // touch gate.
    // ==================================================================

    /// The reference client's frame size (picoforge
    /// `CHALLENGE_FRAME`, `src/hal/applets/otp.rs:37`). A shorter
    /// challenge is padded, never truncated; a longer one is rejected by
    /// the client before it ever reaches the wire.
    const CHALLENGE_FRAME: usize = 64;
    /// The default pad byte (picoforge `pad_challenge`).
    const PAD: u8 = 0x7F;

    /// A verbatim port of the reference client's `pad_challenge`
    /// (picoforge `src/hal/applets/otp.rs:452-469`), included so the
    /// round-trip below is proved against the CLIENT's padding and not
    /// against a re-derivation of it.
    fn client_pad_challenge(challenge: &[u8]) -> [u8; CHALLENGE_FRAME] {
        let mut frame = [0u8; CHALLENGE_FRAME];
        frame[..challenge.len()].copy_from_slice(challenge);
        if challenge.len() < CHALLENGE_FRAME {
            // The firmware recovers the message by trimming trailing bytes
            // equal to the frame's LAST byte, so the pad must differ from
            // it or the tail of the challenge would be eaten.
            let pad = if *challenge.last().expect("non-empty") == PAD {
                0x00
            } else {
                PAD
            };
            frame[challenge.len()..].fill(pad);
        }
        frame
    }

    /// A verbatim port of the firmware's HMAC-LT64 trim (C
    /// `otp.c:934-938`): strip the trailing run of bytes equal to the
    /// frame's final byte. Used to prove the client's padding is fully
    /// undone by the firmware.
    fn firmware_trim(frame: &[u8; CHALLENGE_FRAME]) -> &[u8] {
        let last = frame[CHALLENGE_FRAME - 1];
        let mut n = CHALLENGE_FRAME;
        while n > 0 && frame[n - 1] == last {
            n -= 1;
        }
        &frame[..n]
    }

    /// US-143 RED/GREEN: the slot takes a fixed 64-byte challenge. A
    /// shorter frame is the C's SW_WRONG_LENGTH, which this SDK maps to
    /// 0x6700 (`otp.c:922-925`, the SDK's own wrong-length mapping), and
    /// no response byte is produced.
    #[test]
    fn short_challenge_returns_6700() {
        let mut app = OtpApp::new();
        configure(
            &mut app,
            0,
            make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], CHAL_RESP, CHAL_HMAC),
        );
        // Every length from 0 to 63 is short; 64 is the boundary.
        for len in [0usize, 1, 6, 10, 32, 62, 63] {
            let chal: Vec<u8> = (0..len).map(|i| (i * 5 + 1) as u8).collect();
            let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &chal);
            assert_eq!(sw, 0x6700, "a {len}-byte challenge must be rejected");
            assert!(body.is_empty(), "a {len}-byte challenge produced a body");
        }
        // The boundary: exactly 64 is accepted.
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge_frame());
        assert_eq!(sw, SW_OK);
        assert_eq!(body.len(), 20);
        // And one byte more is the client's problem, not the firmware's:
        // the frame is truncated to the first 64 bytes by the length gate
        // (data.len() < 64 is the only rejection), which is the C's shape.
        let longer: Vec<u8> = (0..65).map(|i| (i * 3 + 2) as u8).collect();
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &longer);
        assert_eq!(sw, SW_OK, "the C only rejects nc < 64");
        assert_eq!(body.len(), 20);
    }

    /// US-143 RED/GREEN: a short challenge, padded by the client into the
    /// 64-byte frame, comes back as the HMAC of the ORIGINAL challenge —
    /// the pad byte is trimmed by the LT64 rule, and the alternate fill
    /// (0x00 when the challenge already ends in 0x7F) is handled.
    #[test]
    fn pads_short_challenge_to_64() {
        let mut app = OtpApp::new();
        let uid = [1, 2, 3, 4, 5, 6];
        let aes_key = [0xAAu8; 16];
        // HMAC_LT64 is what makes the trim happen at all; the reference
        // client's `build_chalresp` always sets it.
        configure(
            &mut app,
            0,
            make_config(uid, aes_key, CHAL_RESP, CHAL_HMAC | HMAC_LT64),
        );
        let key = [&aes_key[..], &uid[..]].concat();

        // The three shapes the client's `pad_challenge` distinguishes.
        let cases: [&[u8]; 3] = [
            &[1, 2, 3, 4, 5, 6, 7, 8], // normal
            &[0xAA, 0x7F],             // ends in the default pad -> 0x00 fill
            &[0x7F],                   // single byte, already the pad
        ];
        for challenge in cases {
            let frame = client_pad_challenge(challenge);
            assert_eq!(
                frame.len(),
                CHALLENGE_FRAME,
                "the client always sends 64 bytes"
            );
            // Precondition: the firmware's trim recovers the challenge.
            assert_eq!(
                firmware_trim(&frame),
                challenge,
                "client padding must round-trip: challenge {challenge:02X?}"
            );
            // Precondition: the pad differs from the challenge's last byte.
            if challenge.len() < CHALLENGE_FRAME {
                assert_ne!(
                    frame[CHALLENGE_FRAME - 1],
                    challenge[challenge.len() - 1],
                    "the pad must not collide with the challenge's last byte"
                );
            }
            let expected = hmac_sha1(&key, challenge);
            let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &frame);
            assert_eq!(sw, SW_OK, "challenge {challenge:02X?}");
            assert_eq!(
                body, expected,
                "the response must be the HMAC of the ORIGINAL challenge, not the padded frame"
            );
        }

        // A C quirk worth pinning explicitly: the trim loop's FIRST
        // comparison is `data[63] == data[63]`, which is always true, so
        // an HMAC-LT64 slot always drops AT LEAST the final byte. A
        // full-width 64-byte challenge is therefore HMACed over 63 bytes.
        // (The client's own `firmware_trim` mirror trims identically, so
        // this is agreed behaviour, not a divergence — but it does mean a
        // 64-byte challenge is not answered over 64 bytes.)
        let full = challenge_frame();
        assert_ne!(full[62], full[63], "precondition: the trim stops at 63");
        assert_eq!(firmware_trim(&full).len(), 63);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &full);
        assert_eq!(sw, SW_OK);
        assert_eq!(body, hmac_sha1(&key, &full[..63]));

        // The same full frame on a slot WITHOUT HMAC_LT64 is HMACed whole.
        let mut app2 = OtpApp::new();
        configure(
            &mut app2,
            0,
            make_config(uid, aes_key, CHAL_RESP, CHAL_HMAC),
        );
        let (body, sw) = calculate(&mut app2, CALC_HMAC_SLOT1, &full);
        assert_eq!(sw, SW_OK);
        assert_eq!(body, hmac_sha1(&key, &full));
    }

    /// US-143: without HMAC_LT64 the trim does NOT happen, so a padded
    /// frame is HMACed as 64 bytes. This is the asymmetry the pad byte
    /// exists to work around, and it is worth pinning.
    #[test]
    fn without_lt64_the_pad_is_part_of_the_message() {
        let mut app = OtpApp::new();
        let uid = [1, 2, 3, 4, 5, 6];
        let aes_key = [0xAAu8; 16];
        configure(&mut app, 0, make_config(uid, aes_key, CHAL_RESP, CHAL_HMAC));
        let challenge: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let frame = client_pad_challenge(challenge);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &frame);
        assert_eq!(sw, SW_OK);
        assert_eq!(body, hmac_sha1(&[&aes_key[..], &uid[..]].concat(), &frame));
        assert_ne!(
            body,
            hmac_sha1(&[&aes_key[..], &uid[..]].concat(), challenge)
        );
    }

    // ---- the touch gate ----

    /// A challenge slot programmed with `touch` is gated on a user-presence
    /// grant; without it, the slot refuses with 6985 and emits no body.
    #[test]
    fn chal_btn_trig_requires_a_presence_grant() {
        static GRANT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        fn granting(_tag: u32) -> bool {
            GRANT.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn refusing(_tag: u32) -> bool {
            false
        }

        let mut app = OtpApp::new().with_user_presence(|| true);
        // The reference client's `build_chalresp(secret, touch = true, ..)`
        // sets exactly this bit (0x22 | 0x04 | 0x08).
        let cfg = make_config(
            [1, 2, 3, 4, 5, 6],
            [0xAA; 16],
            CHAL_RESP,
            CHAL_HMAC | HMAC_LT64 | CHAL_BTN_TRIG,
        );
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let frame = challenge_frame();

        // No grant path -> the build default (host auto-ack) stands in.
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &frame);
        assert_eq!(sw, SW_OK, "host default auto-acks");
        assert_eq!(body.len(), 20);

        // An explicit refusing grant path gates it.
        app.set_presence_grant(refusing);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &frame);
        assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED, "0x6985 without a touch");
        assert!(body.is_empty(), "a refused touch must emit no response");

        // A granting path lets it through — and is handed the OTP tag.
        GRANT.store(true, std::sync::atomic::Ordering::SeqCst);
        app.set_presence_grant(granting);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &frame);
        assert_eq!(sw, SW_OK, "a granted touch opens the slot");
        assert_eq!(body.len(), 20);
        GRANT.store(false, std::sync::atomic::Ordering::SeqCst);

        // A slot WITHOUT the bit is never gated, even on the same app.
        let plain = make_config([2, 2, 2, 2, 2, 2], [0xBB; 16], CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &plain, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT2, &frame);
        assert_eq!(sw, SW_OK, "a slot without CHAL_BTN_TRIG is never gated");
        assert_eq!(body.len(), 20);
    }

    /// US-143: the grant is requested under a tag that belongs to the OTP
    /// applet ALONE — a press armed for OATH RESET, OATH CALCULATE, mgmt
    /// WRITE_CONFIG or FIDO cannot open a challenge-response grant, and an
    /// OTP touch cannot open theirs.
    #[test]
    fn the_otp_presence_tag_cannot_be_confused_with_another_apple() {
        use crate::oath_core::{PRESENCE_TAG_CALCULATE, PRESENCE_TAG_CALC_ALL};
        use crate::oath_core::{PRESENCE_TAG_RESET, PRESENCE_TAG_SET_CODE_CLEAR};

        // The OTP tag is distinct from every CCID tag in the workspace.
        for other in [
            PRESENCE_TAG_RESET,
            PRESENCE_TAG_SET_CODE_CLEAR,
            PRESENCE_TAG_CALCULATE,
            PRESENCE_TAG_CALC_ALL,
            0x1C,        // mgmt WRITE_CONFIG
            0x1E,        // mgmt RESET
            0x2A_9E9A,   // OpenPGP PSO:SIGN
            0x2A_8086,   // OpenPGP PSO:DECIPHER
            0x0088_0000, // OpenPGP INT-AUTH
        ] {
            assert_ne!(
                PRESENCE_TAG_CHAL_BTN_TRIG, other,
                "the OTP presence tag must not collide with {other:#x}"
            );
        }
        // ...and it is out of the HID/FIDO tag domain (bit 31 set), which
        // is how FIDO carves its own space out
        // (`presence_tag_from_channel`, apps/fido/src/device_app.rs:119).
        assert_eq!(
            PRESENCE_TAG_CHAL_BTN_TRIG & 0x8000_0000,
            0,
            "the OTP tag must stay out of the HID presence domain"
        );
        // ...while a FIDO tag built the FIDO way is inside it: the same
        // expression `presence_tag_from_channel` evaluates.
        fn fido_tag(channel: [u8; 4]) -> u32 {
            0x8000_0000 | u32::from_be_bytes(channel)
        }
        assert_ne!(
            fido_tag([0x00, 0x00, 0x00, 0x01]),
            PRESENCE_TAG_CHAL_BTN_TRIG
        );
        assert_eq!(
            fido_tag([0x00, 0x00, 0x00, 0x01]) & 0x8000_0000,
            0x8000_0000
        );
    }

    /// US-143: the touch bit is reported back through EXTENDED STATUS, so a
    /// client can tell that the flag was honoured rather than dropped.
    ///
    /// The expected bytes are **literals**, not the constants: the client's
    /// `build_chalresp(secret, touch = true, ..)` writes
    /// `0x22 | 0x04 | 0x08` and it reads `touch: cfg & 0x08` back
    /// (picoforge src/hal/applets/otp.rs:190-199, 400-401). Spelling the
    /// literals here is what makes a wrong CHAL_BTN_TRIG value a test
    /// failure rather than a silent pass.
    #[test]
    fn the_touch_bit_is_reported_in_the_status_tlv() {
        let mut app = OtpApp::new();
        // 0x22 CHAL_HMAC | 0x04 HMAC_LT64 | 0x08 CHAL_BTN_TRIG — literals.
        let cfg = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], 0x40, 0x22 | 0x04 | 0x08);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = read_info(&mut app);
        assert_eq!(sw, SW_OK);
        assert_eq!(body, vec![0xB0, 0x04, 0xA0, 0x02, 0x40, 0x22 | 0x04 | 0x08]);
        // The bit the client masks on:
        assert_eq!(body[5] & 0x08, 0x08, "the client reads touch as cfg & 0x08");
        // ...and the constant must be that same bit, or a slot programmed
        // with touch would be gated on a bit the client never sets.
        assert_eq!(
            CHAL_BTN_TRIG, 0x08,
            "CFG_CHAL_BTN_TRIG is otp_config_t's 0x08"
        );
    }

    /// US-143: a slot the client programmed with a LITERAL touch byte is
    /// gated, and one without is not — the gate tracks the wire byte, not
    /// some derived value.
    #[test]
    fn the_gate_follows_the_wire_cfg_byte() {
        fn refuse(_tag: u32) -> bool {
            false
        }
        let mut app = OtpApp::new();
        app.set_presence_grant(refuse);
        let frame = challenge_frame();

        // 0x22 | 0x04 | 0x08 — exactly what picoforge writes for touch=true.
        let touched = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], 0x40, 0x22 | 0x04 | 0x08);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &touched, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &frame);
        assert_eq!(sw, 0x6985, "the literal touch byte must gate the challenge");
        assert!(body.is_empty());

        // 0x22 | 0x04 — touch=false.
        let plain = make_config([2, 2, 2, 2, 2, 2], [0xBB; 16], 0x40, 0x22 | 0x04);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &plain, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT2, &frame);
        assert_eq!(
            sw, SW_OK,
            "without the touch byte the challenge is never gated"
        );
        assert_eq!(body.len(), 20);
    }

    // ==================================================================
    // US-144 (PICOForge-COMPAT): the access-code write contract, static
    // slots and SWAP.
    // ==================================================================

    /// US-144 RED/GREEN: the 58-byte write contract the reference client
    /// uses — the NEW code in `config[38..44]`, the CURRENT code appended —
    /// in both directions, and the rejection paths.
    #[test]
    fn access_code_write_accepts_trailing_current_code() {
        let old = [0x31u8; 6];
        let new = [0x42u8; 6];
        let mut app = OtpApp::new();

        // 1. First program on a virgin device. The client appends six zeros
        //    ("no current code"); the frame carries the new code.
        let c1 = make_config_acc([1, 2, 3, 4, 5, 6], [0xAA; 16], new, CHAL_RESP, CHAL_HMAC);
        let (body, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &c1, &NO_ACC);
        assert_eq!(sw, SW_OK);
        assert_eq!(
            app.access_code,
            Some(new),
            "the frame's code is the device code"
        );
        assert_eq!(
            body.len(),
            STATUS_LEN,
            "the C returns the 6-byte status body"
        );

        // 2. A protected write presenting the WRONG current code is 6982
        //    and changes nothing.
        let c2 = make_config_acc([2, 2, 2, 2, 2, 2], [0xBB; 16], new, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &c2, &[0x99; 6]);
        assert_eq!(sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        assert!(
            !app.slot_configured(1),
            "a refused write must not program the slot"
        );

        // 3. The RIGHT current code is accepted and ROTATES the device code
        //    to the one in the new frame.
        let c3 = make_config_acc([3, 3, 3, 3, 3, 3], [0xCC; 16], old, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &c3, &new);
        assert_eq!(sw, SW_OK);
        assert_eq!(
            app.access_code,
            Some(old),
            "the new frame's code is installed"
        );
        assert_eq!(
            app.slots[1].expect("slot 2")[CFG_ACC_CODE..CFG_ACC_CODE + 6],
            old
        );
        // The superseded code no longer opens anything.
        let c4 = make_config_acc([4, 4, 4, 4, 4, 4], [0xDD; 16], new, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 2, &c4, &new);
        assert_eq!(sw, SW_SECURITY_STATUS_NOT_SATISFIED, "the old code is dead");

        // 4. The trailing code NEVER becomes the device code. Presenting
        //    the device's own code while embedding a different one installs
        //    the embedded one.
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 3, &c4, &old);
        assert_eq!(sw, SW_OK);
        assert_eq!(
            app.access_code,
            Some(new),
            "the FIELD wins, not the trailing payload"
        );

        // 5. The 52-byte form: no trailing code, the frame's own field is
        //    both the current code and the new one (a no-op re-write).
        let same = make_config_acc([5, 5, 5, 5, 5, 5], [0xEE; 16], new, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE, 0, same);
        assert_eq!(
            sw, SW_OK,
            "a 52-byte write re-sending the current code is accepted"
        );
        // ...but a 52-byte write carrying a DIFFERENT code is not: with no
        // trailing payload the field is read as the current code.
        let other = make_config_acc([6, 6, 6, 6, 6, 6], [0xFF; 16], old, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE, 0, other);
        assert_eq!(sw, SW_SECURITY_STATUS_NOT_SATISFIED);

        // 6. Deleting a protected slot needs the code; deleting an
        //    unprotected one does not. The client's `delete_slot` appends
        //    `current_acc` (zeros when unprotected) in both cases.
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &[0u8; 52], &[0x77; 6]);
        assert_eq!(
            sw, SW_SECURITY_STATUS_NOT_SATISFIED,
            "a protected erase needs the code"
        );
        assert!(
            app.slot_configured(0),
            "the slot must survive a refused erase"
        );
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &[0u8; 52], &new);
        assert_eq!(sw, SW_OK);
        assert!(!app.slot_configured(0), "the slot is erased");
        // Re-programming with a zero acc_code field and the current code
        // trailing returns the device to the unprotected state...
        let c5 = make_config([7, 7, 7, 7, 7, 7], [0x11; 16], CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 2, &c5, &new);
        assert_eq!(sw, SW_OK, "the current code authenticated the write");
        assert_eq!(
            app.access_code, None,
            "a zero acc_code leaves the device unprotected"
        );
        // ...after which an unprotected erase needs no code at all.
        let (_, sw) = configure_raw(&mut app, SLOT_CONFIGURE, 2, [0u8; 52]);
        assert_eq!(sw, SW_OK, "an unprotected erase needs no code");
        // And a plain unprotected configure needs no trailing code.
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 3, &c5, &NO_ACC);
        assert_eq!(sw, SW_OK);
    }

    // ---- static-password slots ----

    /// A verbatim port of the reference client's `build_static`
    /// (`picoforge src/hal/applets/otp.rs:224-239`): the scancodes are
    /// packed contiguously across `fixed_data ‖ uid ‖ aes_key`, truncated
    /// at 38, with `fixed_size` holding the count and cfg_flags = 0x20.
    fn client_build_static(scancodes: &[u8], append_cr: bool, new_acc: &[u8; 6]) -> [u8; 52] {
        let mut buf = [0u8; 38];
        let n = scancodes.len().min(38);
        buf[..n].copy_from_slice(&scancodes[..n]);
        let mut fixed = [0u8; 16];
        fixed.copy_from_slice(&buf[..16]);
        let mut uid = [0u8; 6];
        uid.copy_from_slice(&buf[16..22]);
        let mut key = [0u8; 16];
        key.copy_from_slice(&buf[22..38]);
        let tkt = if append_cr { 0x20 } else { 0x00 };
        make_config_acc(uid, key, *new_acc, tkt, 0x20).tap_with(|c| {
            c[CFG_FIXED_DATA..CFG_FIXED_DATA + 16].copy_from_slice(&fixed);
            c[CFG_FIXED_SIZE] = n as u8;
            let stored = !crc16(&c[..CFG_CRC]);
            c[CFG_CRC..].copy_from_slice(&stored.to_le_bytes());
        })
    }

    /// Tiny test-only builder combinator (no `tap` in this toolchain's
    /// stable surface); keeps the port above readable.
    trait Tap: Sized {
        fn tap_with(self, f: impl FnOnce(&mut Self)) -> Self {
            let mut me = self;
            f(&mut me);
            me
        }
    }
    impl Tap for [u8; 52] {}

    /// US-144: a static-password slot is USABLE. The response is the stored
    /// scancode run, verbatim — no table, no modhex, nothing derived.
    #[test]
    fn static_slot_responds_with_its_packed_scancodes() {
        // "Passw0rd!" as US-keyboard HID scancodes (shift bit 0x80), the
        // exact bytes the client would send after `ascii_to_scancodes`.
        let scancodes: [u8; 9] = [0x19, 0x18, 0x0C, 0x13, 0xB0, 0x33, 0x27, 0x0F, 0x2D];
        let acc = [0x5Au8; 6];
        let mut app = OtpApp::new();
        let cfg = client_build_static(&scancodes, false, &acc);
        // The port produced what the client produces.
        assert_eq!(cfg[CFG_CFG_FLAGS], 0x20);
        assert_eq!(cfg[CFG_FIXED_SIZE], 9);
        assert_eq!(&cfg[..9], &scancodes);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);

        // The challenge now answers with those bytes.
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge_frame());
        assert_eq!(sw, SW_OK, "a static slot must not be gated by CHAL_RESP");
        assert_eq!(
            body,
            scancodes.to_vec(),
            "the response is the scancode run verbatim"
        );

        // The client classifies it as a static-password slot.
        let (info, sw) = read_info(&mut app);
        assert_eq!(sw, SW_OK);
        assert_eq!(info, vec![0xB0, 0x04, 0xA0, 0x02, 0x00, 0x20]);
        assert_eq!(client_read_info(&info)[0], ClientSlotType::StaticPassword);
    }

    /// The discriminator that lets a static slot be told apart from a
    /// Yubico-AES challenge slot, which shares cfg bit 0x20.
    #[test]
    fn static_and_challenge_slots_are_not_confused() {
        let mut app = OtpApp::new();
        // A Yubico-AES challenge slot: cfg 0x20, tkt 0x40, fixed_size 0.
        let chal = make_config([1, 2, 3, 4, 5, 6], [0xC0; 16], CHAL_RESP, CHAL_YUBICO);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &chal, &NO_ACC);
        assert_eq!(sw, SW_OK);
        // A static slot: cfg 0x20, tkt 0x00, fixed_size 3.
        let stat = client_build_static(&[0x04, 0x05, 0x06], false, &NO_ACC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &stat, &NO_ACC);
        assert_eq!(sw, SW_OK);
        assert_eq!(
            stat[CFG_CFG_FLAGS] & 0x20,
            chal[CFG_CFG_FLAGS] & 0x20,
            "the bit really is shared"
        );

        // Each answers with its own thing. The Yubico-AES slot is only
        // reachable through the AES opcodes (0x20/0x28).
        let (body, sw) = calculate(&mut app, CALC_AES_SLOT1, &challenge_frame()[..6]);
        assert_eq!(sw, SW_OK);
        assert_eq!(
            body.len(),
            16,
            "the AES slot returns a block, not scancodes"
        );
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT2, &challenge_frame());
        assert_eq!(sw, SW_OK);
        assert_eq!(
            body,
            vec![0x04, 0x05, 0x06],
            "the static slot returns its scancodes"
        );
    }

    /// A cfg-0x20 slot with NO scancodes (`fixed_size == 0`) is not a static
    /// slot and must not answer with an empty body as one — it falls
    /// through to the C's CHAL_RESP gate and is refused.
    #[test]
    fn a_static_ticket_bit_without_scancodes_is_not_a_static_slot() {
        let mut app = OtpApp::new();
        let cfg = make_config([1, 2, 3, 4, 5, 6], [0xAA; 16], 0x00, 0x20);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge_frame());
        assert_eq!(
            sw, SW_WRONG_DATA,
            "no scancodes and no CHAL_RESP -> the C's 6700"
        );
        assert!(body.is_empty());
    }

    /// A static slot's response is capped at the 38-byte scancode region,
    /// even if `fixed_size` claims more.
    #[test]
    fn static_response_is_capped_at_the_scancode_region() {
        let mut app = OtpApp::new();
        let scancodes: Vec<u8> = (0..38u8).map(|i| i.wrapping_add(1)).collect();
        let mut cfg = client_build_static(&scancodes, false, &NO_ACC);
        assert_eq!(cfg[CFG_FIXED_SIZE], 38);
        // Forge an over-long fixed_size (38 -> 200) and recompute the CRC.
        cfg[CFG_FIXED_SIZE] = 200;
        let stored = !crc16(&cfg[..CFG_CRC]);
        cfg[CFG_CRC..].copy_from_slice(&stored.to_le_bytes());
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge_frame());
        assert_eq!(sw, SW_OK);
        assert_eq!(
            body.len(),
            38,
            "capped at the scancode region, never past [0..38)"
        );
        assert_eq!(body, scancodes);
    }

    /// A touch-gated static slot is gated, exactly like a touch-gated
    /// challenge slot.
    #[test]
    fn a_touch_gated_static_slot_is_gated() {
        fn refuse(_tag: u32) -> bool {
            false
        }
        let mut app = OtpApp::new();
        app.set_presence_grant(refuse);
        let mut cfg = client_build_static(&[0x04, 0x05], false, &NO_ACC);
        cfg[CFG_CFG_FLAGS] |= CHAL_BTN_TRIG;
        let stored = !crc16(&cfg[..CFG_CRC]);
        cfg[CFG_CRC..].copy_from_slice(&stored.to_le_bytes());
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &cfg, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (body, sw) = calculate(&mut app, CALC_HMAC_SLOT1, &challenge_frame());
        assert_eq!(
            sw, SW_CONDITIONS_NOT_SATISFIED,
            "a password is never typed without a touch"
        );
        assert!(body.is_empty());
    }

    // ---- SWAP ----

    fn swap_as_client(app: &mut OtpApp, body: &[u8]) -> (Vec<u8>, u16) {
        let mut apdu = vec![0x00, INS_OTP, SLOT_SWAP, 0x00];
        if body.is_empty() {
            // `Apdu::read(.., &[])` on the client: no Lc, no Le.
            apdu.push(0x00);
        } else {
            apdu.push(body.len() as u8);
            apdu.extend_from_slice(body);
        }
        drive(app, &apdu)
    }

    /// US-144: the SWAP bodies the reference client actually sends —
    /// empty (unprotected) and `[0, 0] ‖ acc[6]` (protected).
    #[test]
    fn swap_accepts_the_clients_two_body_shapes() {
        let acc = [0x7Eu8; 6];
        let mut app = OtpApp::new();

        // Unprotected, distinct key material per slot.
        let k0 = [0xA0u8; 16];
        let k1 = [0xB0u8; 16];
        let c0 = make_config([1; 6], k0, CHAL_RESP, CHAL_HMAC);
        let c1 = make_config([2; 6], k1, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 0, &c0, &NO_ACC);
        assert_eq!(sw, SW_OK);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE_SLOT2, 0, &c1, &NO_ACC);
        assert_eq!(sw, SW_OK);
        // A zero acc_code leaves the device unprotected.
        assert_eq!(app.access_code, None);

        let frame = challenge_frame();
        // EMPTY body on an unprotected device: the shape `picoforge::swap`
        // sends when `current_acc` is all zeros. Pre-US-144 this returned
        // 6982 (a stored all-zero code was treated as a real one).
        let (body, sw) = swap_as_client(&mut app, &[]);
        assert_eq!(
            sw, SW_OK,
            "an empty-body swap on an unprotected device must succeed"
        );
        assert_eq!(
            body.len(),
            STATUS_LEN,
            "the C returns the 6-byte status body"
        );
        // The swap really happened.
        let (r, _) = calculate(&mut app, CALC_HMAC_SLOT1, &frame);
        assert_eq!(r, hmac_sha1(&[&k1[..], &[2u8; 6][..]].concat(), &frame));
        let (r, _) = calculate(&mut app, CALC_HMAC_SLOT2, &frame);
        assert_eq!(r, hmac_sha1(&[&k0[..], &[1u8; 6][..]].concat(), &frame));
        // Swapping back is a no-op-equivalent second swap.
        assert_eq!(swap_as_client(&mut app, &[]).1, SW_OK);

        // Protect the device, then the `[0, 0] ‖ acc[6]` body.
        let pc = make_config_acc([3; 6], [0xC0; 16], acc, CHAL_RESP, CHAL_HMAC);
        let (_, sw) = configure_as_client(&mut app, SLOT_CONFIGURE, 2, &pc, &NO_ACC);
        assert_eq!(sw, SW_OK);
        assert_eq!(app.access_code, Some(acc));

        let mut wrong = vec![0u8, 0u8];
        wrong.extend_from_slice(&[0x00; 6]);
        let (_, sw) = swap_as_client(&mut app, &wrong);
        assert_eq!(
            sw, SW_SECURITY_STATUS_NOT_SATISFIED,
            "the wrong code is refused"
        );

        // An empty body on a PROTECTED device is refused too (C parity:
        // the zero-initialized `access_code` cannot match).
        let (_, sw) = swap_as_client(&mut app, &[]);
        assert_eq!(sw, SW_SECURITY_STATUS_NOT_SATISFIED);

        // The client's protected shape.
        let mut good = vec![0u8, 0u8];
        good.extend_from_slice(&acc);
        let (body, sw) = swap_as_client(&mut app, &good);
        assert_eq!(sw, SW_OK);
        assert_eq!(body.len(), STATUS_LEN);
    }

    /// US-144: the slot-pair offsets in the body are HONOURED. Pre-US-144
    /// they were validated and thrown away and the swap always exchanged
    /// slots 1 and 2.
    #[test]
    fn swap_honours_the_slot_pair_in_the_body() {
        let mut app = OtpApp::new();
        let keys = [[0xA0u8; 16], [0xB0; 16], [0xC0; 16], [0xD0; 16]];
        for (slot, (p1, p2)) in [
            (0usize, (SLOT_CONFIGURE, 0u8)),
            (1, (SLOT_CONFIGURE_SLOT2, 0)),
            (2, (SLOT_CONFIGURE, 2)),
            (3, (SLOT_CONFIGURE, 3)),
        ] {
            let cfg = make_config([slot as u8; 6], keys[slot], CHAL_RESP, CHAL_HMAC);
            let (_, sw) = configure_as_client(&mut app, p1, p2, &cfg, &NO_ACC);
            assert_eq!(sw, SW_OK);
        }
        let frame = challenge_frame();
        let key_of = |app: &mut OtpApp, p1: u8, p2: u8| -> Vec<u8> {
            let (b, _) = challenge_as_client(app, p1, p2, &frame);
            b
        };

        // `[2, 2]` = slot1+2 (= slot 3) with slot2+2 (= slot 4).
        let (body, sw) = swap_as_client(&mut app, &[2, 2]);
        assert_eq!(sw, SW_OK);
        assert_eq!(body.len(), STATUS_LEN);
        // Slot 3 and 4 exchanged their key material.
        let b3 = key_of(&mut app, CALC_HMAC_SLOT1, 2);
        assert_eq!(
            b3,
            hmac_sha1(&[&keys[3][..], &[3u8; 6][..]].concat(), &frame)
        );
        let b4 = key_of(&mut app, CALC_HMAC_SLOT1, 3);
        assert_eq!(
            b4,
            hmac_sha1(&[&keys[2][..], &[2u8; 6][..]].concat(), &frame)
        );
        // Slots 1 and 2 were NOT touched.
        let b1 = key_of(&mut app, CALC_HMAC_SLOT1, 0);
        assert_eq!(
            b1,
            hmac_sha1(&[&keys[0][..], &[0u8; 6][..]].concat(), &frame)
        );

        // `[0, 0]` is the default pair (slots 1 and 2), which is what the
        // client sends.
        let (_, sw) = swap_as_client(&mut app, &[0, 0]);
        assert_eq!(sw, SW_OK);
        let b1 = key_of(&mut app, CALC_HMAC_SLOT1, 0);
        assert_eq!(
            b1,
            hmac_sha1(&[&keys[1][..], &[1u8; 6][..]].concat(), &frame)
        );

        // The same slot twice is 6A86 (C parity).
        let (_, sw) = swap_as_client(&mut app, &[1, 0]); // slot1+1 == slot2+0
        assert_eq!(sw, SW_INCORRECT_P1P2, "swapping a slot with itself");
        // Out of the table is 6A86.
        let (_, sw) = swap_as_client(&mut app, &[0, 3]);
        assert_eq!(sw, SW_INCORRECT_P1P2);
        // A body length the C rejects (1, 3..7, 9+) is 0x6700, not 0x6A86.
        for len in [1usize, 3, 4, 7, 9, 64] {
            let b = vec![0u8; len];
            let (_, sw) = swap_as_client(&mut app, &b);
            assert_eq!(sw, SW_WRONG_DATA, "a {len}-byte swap body must be 0x6700");
        }
        // The C's `[slot1, slot2]` (2-byte) form is accepted: `[1, 1]`
        // is slot1+1 (= slot 2) with slot2+1 (= slot 3).
        let (body, sw) = swap_as_client(&mut app, &[1, 1]);
        assert_eq!(sw, SW_OK);
        assert_eq!(body.len(), STATUS_LEN);
    }
}
