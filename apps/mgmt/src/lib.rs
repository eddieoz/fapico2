//! Management applet (US-351 / US-352).
//!
//! Reports the compiled-in capability mask and firmware version on SELECT, and
//! serves three commands:
//! * `READ_CONFIG` (0x1D) — emit the `man_get_config` TLV blob.
//! * `WRITE_CONFIG` (0x1C) — store the device-configuration blob (requires a
//!   user-presence grant; granted in emulation).
//! * `RESET` (0x1E) — full factory reset: with a user-presence grant, the
//!   device-supplied
//!   [`FactoryResetHandler`] wipes device-wide durable state (FIDO
//!   keystore + hkey, OATH credential table, OTP slots) and this applet
//!   clears its config blob and the sticky config lock. Without a hook
//!   (host/emulation default) only the management config is cleared.
//!
//! The capability bits are **feature-gated**, not a hardcoded constant. The OTP
//! bit is compiled in only when the `otp` feature is enabled, mirroring the C
//! firmware's `ENABLE_OTP_APP` gate (C US-212 / RUST US-351). US-104
//! (PICOForge-COMPAT) adds the same treatment for PIV behind a `piv` feature:
//! the device registers only the AIDs in
//! `fapico2_apps::registry::CCID_AIDS` (Management, OATH, OTP, OpenPGP, and
//! since US-160 the vendor LED applet), so a device build must not advertise
//! the PIV applet it does not carry, while the host emulation binary — which
//! really does register `PivApp` — must. A trimmed build therefore cannot
//! silently advertise an applet it does not answer for. (`apps/tests/caps.rs`
//! holds the capability word and the AID set together and proves the pairing
//! both ways; that file also explains why a capability bit cannot be invented
//! for an applet the client does not decode.)
//!
//! **US-386 device port.** The stored `EF_DEV_CONF` blob is bounded by a
//! `heapless::Vec` (no heap) and the version string is emitted without `std`'s
//! `format!`, so the same implementation compiles for the host/emulation build
//! (`host` feature, std) and the RP2350 device build (`device` feature,
//! `no_std`).

#![cfg_attr(not(feature = "host"), no_std)]

use fapico2_platform::dispatch::{App, MAX_RESPONSE, Sw, SW_INS_NOT_SUPPORTED, SW_OK, SW_WRONG_LENGTH};
use fapico2_platform::presence::PresenceService;
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use heapless::Vec as HeaplessVec;

/// Management AID (matches `management.c` `man_aid`).
pub const MANAGEMENT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Firmware version reported on SELECT, mirroring `man_select`'s
/// `"PICO_FIDO_VERSION_MAJOR.PICO_FIDO_VERSION_MINOR.0"`.
///
/// The version is a **client-compatibility contract**, not a changelog. yubikit
/// gates its management `read_device_info` on `>= 4.1` — below that the
/// desktop app degrades to legacy applet scanning and can never learn FIDO2
/// or the serial (`yubikit/support.py` `_read_info_ccid`). 5.4 is a real
/// YubiKey 5 firmware version, matching the YubiKey 5 PID this build
/// enumerates as, and stays distinct from the RS-Key SDK major (8, rescue
/// SELECT byte 2) whose separation the rescue protocol test pins.
pub const VERSION_MAJOR: u8 = 5;
pub const VERSION_MINOR: u8 = 4;

/// Fixed emulation chipid — host/emulation builds have no OTP row, so a
/// fixed stand-in (ASCII `"fapico2"` + `0x00`) keeps the derived serial
/// deterministic, the same convention as the fixed emulation store key
/// (`store_v3::emulation_store_key`). Device builds must inject the real
/// chipid through [`ManagementApp::with_chipid`] instead.
///
/// US-103 (PICOForge-COMPAT): now
/// [`fapico2_platform::usb_ident::EMULATION_CHIPID`], so the emulated USB
/// serial and this applet's emulated `TAG_SERIAL` are derived from the same
/// stand-in chipid and therefore agree. Same value as before; only the owner
/// moved.
pub const EMULATION_CHIPID: u64 = fapico2_platform::usb_ident::EMULATION_CHIPID;

/// R12: the 4-byte `TAG_SERIAL` value derived from the device chipid —
/// `SHA-256(chipid BE)[..4]`, the codebase's existing device-bound
/// derivation style (`ckey::serial_hash` is SHA-256 over the flash UID).
/// Distinct per device, so hosts cannot fingerprint the fleet by the
/// constant serial the C firmware answered with (`pico_serial.id` on
/// every unit). The response shape is unchanged: same tag (0x02), same
/// 4-byte length, with the C "8-digit serial" mask still applied at
/// emit time.
///
/// US-103 (PICOForge-COMPAT): delegates to
/// [`fapico2_platform::usb_ident::serial_hash4`], the crate-wide single
/// source of truth, so this applet's `TAG_SERIAL` and the USB
/// `iSerialNumber` (which renders the *same* 4 hash bytes as 8 decimal
/// digits) are the same hash of the same chipid by construction, not by two
/// matching copies. Behaviour is byte-identical to the inline hashing this
/// replaced — the applet keeps its 4-byte TLV encoding and the USB descriptor
/// its 8-digit ASCII one; only the ownership of the derivation moved.
pub fn serial_from_chipid(chipid: u64) -> [u8; 4] {
    fapico2_platform::usb_ident::serial_hash4(chipid)
}

// Capability bits (matches `management.h` / `test_app_switching.py` `CAP_*`).
//
// `pub` since US-104 (PICOForge-COMPAT): `apps/tests/caps.rs` builds the
// *expected* word out of these constants. Spelled as literals there they would
// be a second copy that could drift from the ones `caps()` actually uses.
pub const CAP_OTP: u16 = 0x01;
pub const CAP_U2F: u16 = 0x02;
pub const CAP_OPENPGP: u16 = 0x08;
/// PIV. **Never advertised by a device build** — see [`caps`].
pub const CAP_PIV: u16 = 0x10;
pub const CAP_OATH: u16 = 0x20;
pub const CAP_FIDO2: u16 = 0x200;

/// The capability bits advertised in *every* build: the two HID applets
/// (FIDO2/U2F are not AID-dispatched, so they are unconditional) plus the two
/// CCID applets no Cargo feature gates (OATH, OpenPGP).
///
/// US-104: this replaces the old `CAPS_SIX`, a single "all six bits" constant.
/// That name was a lie in two ways — the word is feature-gated so no one
/// constant can describe it, and PIV is not advertised at all on the device
/// path. A feature-independent "always on" mask is the only shape that stays
/// true in every configuration; the feature-dependent bits are spelled where
/// they are gated.
pub const CAPS_BASE: u16 = CAP_FIDO2 | CAP_U2F | CAP_OATH | CAP_OPENPGP;

/// Capability word reported by `READ_CONFIG`. This is the single source of truth
/// for "what is compiled in", so a trimmed build cannot silently advertise an
/// applet it does not carry.
///
/// Two bits are feature-gated, each for the same reason — the applet is
/// genuinely absent from that build's AID dispatcher:
///
/// * `otp` — mirrors the C firmware's `ENABLE_OTP_APP` gate (C US-212 / RUST
///   US-351). Every shipped build enables it, so they all advertise `0x22B`.
/// * `piv` — US-104 (PICOForge-COMPAT). The device path registers only the AIDs
///   of `fapico2_apps::registry::CCID_AIDS` (Management, OATH, OTP, OpenPGP,
///   and since US-160 the RS-Key vendor LED applet), so a device build must
///   report `0x22B` and must **not** set `CAP_PIV`: advertising an applet that
///   cannot answer leaves the desktop client offering a PIV screen that is a
///   dead end. The host emulation binary is the one build that *does* register
///   `PivApp` as a sixth CCID app (`firmware/src/emul_main.rs`), so it — and
///   only it — enables `piv` and reports `0x23B`, which keeps the PIV screen
///   visible where PIV works.
///
/// `apps/tests/caps.rs` holds this word and the AID set together; that file also
/// explains why the check cannot live in this crate.
pub fn caps() -> u16 {
    let mut c = CAPS_BASE;
    #[cfg(feature = "otp")]
    {
        c |= CAP_OTP;
    }
    #[cfg(feature = "piv")]
    {
        c |= CAP_PIV;
    }
    c
}

// TLV tags emitted by `man_get_config` (matches `management.h`).
const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_VERSION: u8 = 0x05;
const TAG_DEVICE_FLAGS: u8 = 0x08;
const TAG_CONFIG_LOCK: u8 = 0x0A;

// Command INS bytes (matches `management.c`).
const INS_READ_CONFIG: u8 = 0x1D;
const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_RESET: u8 = 0x1E;
/// US-413 S-413-6: interactive C-data migration (passphrase-gated classes).
/// `P1` selects the class (0 = FIDO keydev PIN, 1 = OpenPGP PW1); data =
/// raw passphrase. Response data = one status byte (`ClassStatus`).
const INS_MIGRATION: u8 = 0x1F;

/// Device-supplied completion hook: runs one passphrase-gated migration
/// class against the C data partition and the secure store
/// (`fapico2_platform::migration::complete_passphrase_class`). Kept behind
/// a trait so the app stays device-agnostic (host tests inject a fixture
/// handler backed by the same platform function).
pub trait MigrationHandler {
    /// Write the one-byte `ClassStatus` into `out`; return the SW.
    fn complete(&mut self, class: u8, passphrase: &[u8], out: &mut HeaplessVec<u8, MAX_RESPONSE>) -> Sw;
}

/// US-711 device-supplied factory-reset hook: wipes device-wide state
/// beyond this applet's own config — the FIDO keystore + hkey, the OATH
/// credential table, the OTP slots, and every remaining secure-store entry
/// (C `cmd_factory_reset` → `cbor_reset()`, `management.c:209`).
/// Kept behind a trait so the app stays device-agnostic; the firmware
/// injects the real handler (`DeviceFactoryResetHandler`), host tests a
/// fixture backed by the same reset primitives.
pub trait FactoryResetHandler {
    /// Wipe device-wide durable state. Returns the SW the RESET APDU must
    /// answer: on a failure SW this applet aborts the reset without
    /// clearing its own config — the hook owns recovering or surfacing any
    /// partial wipe of the state it manages beyond this applet.
    fn factory_reset(&mut self) -> Sw;
}

// ISO 7816-4 status words.
const SW_WRONG_DATA: Sw = 0x6700;
const SW_CONDITIONS_NOT_SATISFIED: Sw = 0x6985;
const SW_CLA_NOT_SUPPORTED: Sw = 0x6E00;

/// Maximum stored `EF_DEV_CONF` blob. A short-APDU `WRITE_CONFIG` carries at
/// most 255 data bytes (minus the leading length byte), so 256 covers every
/// legal payload.
const MAX_CONFIG: usize = 256;

/// SecureStore slot for the durable `EF_DEV_CONF` blob (US-388). The RP2350
/// secure partition backs the store on device — never plain flash.
const CONFIG_SLOT: &[u8] = b"mgmt.conf.v1";

/// US-702: device user-presence source, injected by the firmware
/// (`with_user_presence`). The C firmware gates `WRITE_CONFIG` on a
/// physical button press; the emulation/host default auto-acks, while a
/// device build without an injected source **denies** (fail closed).
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

pub struct ManagementApp {
    /// Stored `EF_DEV_CONF` contents. `None` == factory default, so
    /// `READ_CONFIG` emits the full caps/flags blob; `Some(..)` returns the
    /// stored bytes verbatim (matching C `file_has_data(ef)`). Bounded
    /// heapless buffer — no heap on the device (US-386).
    config: Option<HeaplessVec<u8, MAX_CONFIG>>,
    /// Durable state changed since the last persist (US-388).
    dirty: bool,
    /// S-413-6 migration completion hook (device only; `None` ⇒
    /// INS_MIGRATION answers SW_INS_NOT_SUPPORTED).
    migration: Option<&'static mut dyn MigrationHandler>,
    /// US-711 device-wide factory-reset hook (device only; `None` ⇒ RESET
    /// clears this applet's config only — the host/emulation default).
    reset: Option<&'static mut dyn FactoryResetHandler>,
    /// US-702: user-presence source (board button on device). `None` uses
    /// the build default (auto-ack host/emulation, deny on device).
    presence: Option<fn() -> bool>,
    /// US-921: the whole grant path (pending request + latch binding) when
    /// the runtime owns the shared presence service (device wiring). Takes
    /// precedence over `presence` — the shared runtime IS the grant path.
    presence_grant: Option<fn(u32) -> bool>,
    /// US-702: config lock (C `config_lock`): a stored config carrying
    /// TAG_CONFIG_LOCK = 0x01 refuses further WRITE_CONFIG until RESET.
    /// Derived from the stored blob so the durable format is unchanged.
    locked: bool,
    /// R12: the 4-byte `TAG_SERIAL` value — derived from the chipid
    /// (default: the fixed emulation chipid; device wiring overrides it
    /// through [`ManagementApp::with_chipid`]).
    serial: [u8; 4],
}

/// US-702: does the stored `EF_DEV_CONF` blob carry the config-lock byte?
fn blob_is_locked(blob: &[u8]) -> bool {
    blob.windows(3).any(|w| w == [TAG_CONFIG_LOCK, 1, 0x01])
}

impl ManagementApp {
    pub fn new() -> Self {
        Self {
            config: None,
            dirty: false,
            migration: None,
            reset: None,
            presence: None,
            presence_grant: None,
            locked: false,
            serial: serial_from_chipid(EMULATION_CHIPID),
        }
    }

    /// R12 device wiring: derive the `TAG_SERIAL` value from the real OTP
    /// chipid (`embassy_rp::otp::get_chipid()`), so each device presents a
    /// distinct serial. Device builds call this at boot; the host/emulation
    /// default derives from the fixed emulation chipid (deterministic e2e).
    pub fn with_chipid(mut self, chipid: u64) -> Self {
        self.serial = serial_from_chipid(chipid);
        self
    }

    /// Attach the S-413-6 migration completion hook (device wiring).
    pub fn with_migration_handler(mut self, h: &'static mut dyn MigrationHandler) -> Self {
        self.migration = Some(h);
        self
    }

    /// US-711: attach the device-wide factory-reset hook (device wiring).
    pub fn with_factory_reset(mut self, h: &'static mut dyn FactoryResetHandler) -> Self {
        self.reset = Some(h);
        self
    }

    /// US-702: attach the user-presence source (the board button poll on
    /// the device build).
    pub fn with_user_presence(mut self, f: fn() -> bool) -> Self {
        self.presence = Some(f);
        self
    }

    /// US-921: attach the shared presence runtime's grant path (device
    /// wiring) — the runtime owns the pending-request slot and the button
    /// latch binding, so destructive commands are granted only by a press
    /// that lands while *this* command's request is pending.
    pub fn with_presence_grant(mut self, g: fn(u32) -> bool) -> Self {
        self.presence_grant = Some(g);
        self
    }

    /// US-702: whether the stored config carries the config lock.
    pub fn is_config_locked(&self) -> bool {
        self.locked
    }

    /// Boot (US-388): load the persisted `EF_DEV_CONF` from the platform
    /// secure store (the RP2350 secure partition on device). A fresh or
    /// corrupt partition boots to the factory-default configuration. There
    /// is no persistent auth session — a rebooted device is unauthenticated
    /// (ISO 7816-4 security state resets with power).
    // US-939: `#[inline(never)]` -- async-main frame discipline.
    #[inline(never)]
    pub fn boot(store: &mut dyn SecureStore) -> Self {
        let mut app = Self::new();
        let mut buf = [0u8; MAX_CONFIG];
        if let Ok(n) = store.read(CONFIG_SLOT, &mut buf) {
            if let Ok(blob) = HeaplessVec::<u8, MAX_CONFIG>::from_slice(&buf[..n]) {
                app.locked = blob_is_locked(&blob);
                app.config = Some(blob);
            }
        }
        app
    }

    /// Persist the durable `EF_DEV_CONF` blob through the secure store
    /// (unconditional write; the [`App::persist`] hook gates this on
    /// dirtiness).
    pub fn save(&self, store: &mut dyn SecureStore) -> Result<(), SecureStoreError> {
        match &self.config {
            Some(blob) => store.write(CONFIG_SLOT, blob),
            // Factory default: the persisted blob (if any) is removed.
            None => match store.contains(CONFIG_SLOT) {
                true => store.delete(CONFIG_SLOT),
                false => Ok(()),
            },
        }
    }

    /// Whether a user-supplied configuration has been written (C:
    /// `file_has_data(EF_DEV_CONF)`).
    pub fn has_config(&self) -> bool {
        self.config.is_some()
    }

    /// Emit the `man_select` version string ("MAJOR.MINOR.0") without `std`.
    /// Single-digit major/minor (the shipped build reports 5.4.0).
    fn write_version(out: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        let buf = [
            b'0' + VERSION_MAJOR,
            b'.',
            b'0' + VERSION_MINOR,
            b'.',
            b'0',
        ];
        out.extend_from_slice(&buf).ok();
    }

    /// Build the `man_get_config` response into `out`. When no config is stored
    /// this emits the full caps/serial/form-factor/version/device-flags/
    /// config-lock blob; otherwise it returns the stored bytes verbatim.
    fn read_config(&self, out: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        match &self.config {
            None => default_config_tlv(self.serial, out),
            Some(stored) => {
                out.push(stored.len() as u8).ok();
                out.extend_from_slice(stored).ok();
            }
        }
    }
}

/// Emit the default `man_get_config` TLV blob for `serial` into `out`.
///
/// Public because the same blob is also served over the FIDO CTAPHID
/// interface as `CTAP_READ_CONFIG` (`0x42`) — yubikit's `_read_info_ctap`
/// reads device info that way when a client enumerates the key through its
/// FIDO interface rather than CCID. One implementation, so the two paths
/// cannot drift.
pub fn default_config_tlv(serial: [u8; 4], out: &mut HeaplessVec<u8, MAX_RESPONSE>) {
    let caps = caps();
    // Overall length placeholder at [0], filled at the end.
    out.push(0).ok();
    // TAG_USB_SUPPORTED (which capabilities are compiled in).
    out.extend_from_slice(&[TAG_USB_SUPPORTED, 2, (caps >> 8) as u8, (caps & 0xFF) as u8]).ok();
    // TAG_SERIAL — chipid-derived (R12); same tag/length shape as the C
    // constant serial, so clients see no protocol change.
    let mut serial = serial;
    serial[0] &= !0xFC; // force 8-digit serial, per C
    out.extend_from_slice(&[TAG_SERIAL, 4, serial[0], serial[1], serial[2], serial[3]]).ok();
    // TAG_FORM_FACTOR = 1 (YubiKey 5 form factor).
    out.extend_from_slice(&[TAG_FORM_FACTOR, 1, 0x01]).ok();
    // TAG_VERSION = major.minor.0.
    out.extend_from_slice(&[TAG_VERSION, 3, VERSION_MAJOR, VERSION_MINOR, 0x00]).ok();
    // TAG_USB_ENABLED (feature-gated; same as supported here).
    out.extend_from_slice(&[TAG_USB_ENABLED, 2, (caps >> 8) as u8, (caps & 0xFF) as u8]).ok();
    // TAG_DEVICE_FLAGS = FLAG_EJECT.
    out.extend_from_slice(&[TAG_DEVICE_FLAGS, 1, 0x80]).ok();
    // TAG_CONFIG_LOCK = unlocked.
    out.extend_from_slice(&[TAG_CONFIG_LOCK, 1, 0x00]).ok();
    if !out.is_empty() {
        let total = out.len();
        out[0] = (total - 1) as u8;
    }
}

impl Default for ManagementApp {
    fn default() -> Self {
        Self::new()
    }
}

impl App for ManagementApp {
    fn aid(&self) -> &[u8] {
        MANAGEMENT_AID
    }

    fn select(&mut self, _internal: bool) -> Sw {
        SW_OK
    }

    fn deselect(&mut self) {}

    fn select_apdu(
        &mut self,
        _internal: bool,
        _apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        // man_select returns "MAJOR.MINOR.0" as the SELECT response data.
        Self::write_version(resp);
        SW_OK
    }

    fn process(&mut self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        // US-701: reject APDUs shorter than the 4-byte header outright — a
        // 1-byte APDU `[0x00]` passes the CLA gate but must not be indexed.
        if apdu.len() < 4 {
            write_sw(resp, SW_WRONG_LENGTH);
            return;
        }
        let cla = apdu.first();
        if cla != Some(&0x00) {
            write_sw(resp, SW_CLA_NOT_SUPPORTED);
            return;
        }
        let ins = apdu[1];
        let data = parse_data(apdu);
        let sw = match ins {
            INS_READ_CONFIG => {
                self.read_config(resp);
                SW_OK
            }
            INS_WRITE_CONFIG => self.cmd_write_config(data),
            INS_RESET => self.cmd_reset(),
            INS_MIGRATION => match &mut self.migration {
                Some(h) => {
                    if data.is_empty() {
                        write_sw(resp, SW_WRONG_LENGTH);
                        return;
                    }
                    h.complete(apdu[2], &data[1..], resp)
                }
                None => SW_INS_NOT_SUPPORTED,
            },
            _ => SW_INS_NOT_SUPPORTED,
        };
        write_sw(resp, sw);
    }

    fn persist_state(&mut self, store: &mut dyn SecureStore) -> bool {
        if !self.dirty {
            return false;
        }
        let wrote = self.save(store).is_ok();
        if wrote {
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

/// Extract the APDU data field as a borrowed slice (no allocation). Both the
/// short and the C-harness extended `00 Hi Lo` Lc encodings are accepted
/// (cf. oath.rs).
fn parse_data(apdu: &[u8]) -> &[u8] {
    if apdu.len() >= 7 && apdu[4] == 0x00 {
        let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
        return apdu.get(7..7 + lc).unwrap_or(&[]);
    }
    if apdu.len() < 5 {
        return &[];
    }
    let lc = apdu[4] as usize;
    apdu.get(5..5 + lc).unwrap_or(&[])
}

fn write_sw(resp: &mut HeaplessVec<u8, MAX_RESPONSE>, sw: Sw) {
    resp.extend_from_slice(&sw.to_be_bytes()).ok();
}

impl ManagementApp {
    /// US-906: the user-presence grant for destructive/config commands —
    /// routed through the platform presence service (bound, timed,
    /// single-use). The command declares itself pending under its INS tag,
    /// one press poll may arm a grant for *that* tag, and the grant is
    /// consumed exactly once.
    ///
    /// US-921 device wiring: with `with_presence_grant` attached, the whole
    /// grant path IS the runtime's shared presence service (one instance for
    /// the whole firmware — pending slot + button-latch binding + clock), so
    /// a press with no pending request never arms anything. The fallback
    /// below stays the host/test path: a per-command service fed by the
    /// injected `fn() -> bool` poll (or the build default — fail-closed on
    /// device, auto-ack on host/emulation so the existing suites stay
    /// green); press→consume is synchronous within the command there, so
    /// tick 0 stands in for the clock.
    fn user_present(&mut self, tag: u32) -> bool {
        if let Some(g) = self.presence_grant {
            return g(tag);
        }
        let mut svc = PresenceService::new();
        if !svc.begin_request(tag) {
            return false;
        }
        if match self.presence {
            Some(f) => f(),
            None => default_user_present(),
        } {
            // mgmt has no monotonic clock and press→consume is synchronous
            // within this command, so the 10 s window is moot here; tick 0
            // is the injected stand-in (US-921 wires the real clock).
            svc.observe_press(0);
        }
        let grant = svc.request(tag, 0).is_some();
        svc.end_request(tag);
        grant
    }

    /// WRITE_CONFIG: data = [len, config...]; the first byte must equal the
    /// length of the remaining bytes (C `apdu.data[0] == apdu.nc - 1`), and a
    /// user-presence grant is required.
    fn cmd_write_config(&mut self, data: &[u8]) -> Sw {
        if data.is_empty() || data[0] as usize != data.len() - 1 {
            return SW_WRONG_DATA;
        }
        // US-702: a locked config refuses further writes (C `config_lock`),
        // even with a fresh presence grant — the lock byte is sticky until
        // RESET.
        if self.locked {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        if !self.user_present(INS_WRITE_CONFIG as u32) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        match HeaplessVec::<u8, MAX_CONFIG>::from_slice(&data[1..]) {
            Ok(blob) => {
                self.locked = blob_is_locked(&blob);
                self.config = Some(blob);
                self.dirty = true;
                SW_OK
            }
            Err(_) => SW_WRONG_DATA,
        }
    }

    /// RESET (0x1E): the C factory reset (`cmd_factory_reset` →
    /// `cbor_reset()`). US-702: a user-presence grant is required — a
    /// refused reset wipes nothing. With the grant, the device-supplied
    /// hook (US-711 [`FactoryResetHandler`]) wipes device-wide durable
    /// state (FIDO keystore + hkey, OATH credential table, OTP slots);
    /// a hook failure aborts closed. This applet then clears its own
    /// config blob and the sticky config lock (US-702); the emptied state
    /// reaches the store through the transport's persist gate.
    fn cmd_reset(&mut self) -> Sw {
        if !self.user_present(INS_RESET as u32) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        if let Some(h) = &mut self.reset {
            let sw = h.factory_reset();
            if sw != SW_OK {
                return sw;
            }
        }
        self.config = None;
        // US-702: factory state clears the config lock too.
        self.locked = false;
        self.dirty = true;
        SW_OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fapico2_platform::dispatch::{App, SW_OK};

    #[cfg(not(target_arch = "arm"))]
    use fapico2_platform::secure_store::HostSecureStore;

    /// Drive one APDU through the app and return (response_bytes, sw).
    fn drive(app: &mut ManagementApp, apdu: &[u8]) -> (Vec<u8>, Sw) {
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        app.process(apdu, &mut resp);
        let bytes: Vec<u8> = resp.as_slice().to_vec();
        let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
        (bytes[..bytes.len() - 2].to_vec(), sw)
    }

    /// SELECT carries the "MAJOR.MINOR.0" version string (man_select).
    #[test]
    fn select_returns_version_string() {
        let mut app = ManagementApp::new();
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        let mut sel = vec![0x00, 0xA4, 0x04, 0x00, MANAGEMENT_AID.len() as u8];
        sel.extend_from_slice(MANAGEMENT_AID);
        let sw = app.select_apdu(false, &sel, &mut resp);
        assert_eq!(sw, SW_OK);
        assert_eq!(&resp.as_slice(), b"5.4.0");
    }

    /// The advertised capability word tracks the feature gates at compile time
    /// (US-212 / US-351 for `otp`, US-104 for `piv`): a device build — the
    /// default `otp` and no `piv` — advertises `0x22B`; dropping `otp` gives
    /// `0x22A`; adding `piv` (the host emulation binary, which registers
    /// `PivApp`) gives `0x23B`.
    #[test]
    fn caps_reflects_feature_gates() {
        let expected = CAPS_BASE
            | if cfg!(feature = "otp") { CAP_OTP } else { 0 }
            | if cfg!(feature = "piv") { CAP_PIV } else { 0 };
        assert_eq!(caps(), expected);
        // …and the same expectation pinned to the literal bytes that go on the
        // wire (0x22A base + 0x01 for OTP + 0x10 for PIV), so a change to a
        // `CAP_*` value cannot silently move a value the host suite and the
        // desktop client compare against.
        let wire = 0x22Au16
            | if cfg!(feature = "otp") { 0x01 } else { 0 }
            | if cfg!(feature = "piv") { 0x10 } else { 0 };
        assert_eq!(caps(), wire, "wire caps word must be 0x{wire:04X}");
        // The four ungated bits are always present.
        assert_eq!(caps() & CAPS_BASE, CAPS_BASE);
    }

    /// READ_CONFIG with no user config emits the caps TLV first, after the
    /// leading overall-length byte (this is what the merged suite parses).
    #[test]
    fn read_config_default_emits_caps_tlv() {
        let mut app = ManagementApp::new();
        let (data, sw) = drive(&mut app, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        assert!(!data.is_empty());
        // data[0] = overall length; first TLV starts at [1].
        assert_eq!(data[1], TAG_USB_SUPPORTED);
        assert_eq!(data[2], 2);
        let word = u16::from_be_bytes([data[3], data[4]]);
        assert_eq!(word, caps());
        // The ungated caps are always present (the OTP/PIV bits are
        // feature-gated, so a trimmed build legitimately omits them — check the
        // other four).
        assert_eq!(word & CAPS_BASE, CAPS_BASE);
    }

    /// R12: two different chipids derive two different serials, and the
    /// derived value is never the old C fleet constant ("1234") — every
    /// device presents a distinct serial, so hosts cannot fingerprint
    /// the fleet.
    #[test]
    fn serial_distinct_per_chipid() {
        let a = serial_from_chipid(0x0102_0304_0506_0708);
        let b = serial_from_chipid(0x0102_0304_0506_0709);
        assert_ne!(a, b);
        assert_ne!(a, [0x31, 0x32, 0x33, 0x34]);
        assert_ne!(b, [0x31, 0x32, 0x33, 0x34]);
    }

    /// R12: the same chipid derives the same serial on every call — the
    /// serial is a stable device identity, not a per-boot value.
    #[test]
    fn serial_stable_for_same_chipid() {
        let a = serial_from_chipid(0xDEAD_BEEF_CAFE_0001);
        let b = serial_from_chipid(0xDEAD_BEEF_CAFE_0001);
        assert_eq!(a, b);
    }

    /// R12: the default READ_CONFIG blob still carries TAG_SERIAL (0x02)
    /// with the same 4-byte shape — the value is now the chipid-derived
    /// serial (emulation chipid on host builds), so clients see no
    /// protocol change.
    #[test]
    fn read_config_serial_tlv_shape_unchanged() {
        let mut app = ManagementApp::new();
        let (data, sw) = drive(&mut app, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        // Walk the TLV chain after the leading overall-length byte.
        let mut pos = 1;
        while pos + 1 < data.len() {
            let tag = data[pos];
            let len = data[pos + 1] as usize;
            if tag == TAG_SERIAL {
                assert_eq!(len, 4, "TAG_SERIAL must keep its 4-byte shape");
                let mut expected = serial_from_chipid(EMULATION_CHIPID);
                expected[0] &= !0xFC; // the C 8-digit mask, applied at emit
                assert_eq!(&data[pos + 2..pos + 2 + 4], &expected[..]);
                return;
            }
            pos += 2 + len;
        }
        panic!("TAG_SERIAL missing from the default READ_CONFIG blob");
    }

    /// R12 device wiring: `with_chipid` overrides the emitted serial with
    /// the real chipid's derivation.
    #[test]
    fn with_chipid_overrides_emitted_serial() {
        let chipid = 0x0102_0304_0506_0708;
        let mut app = ManagementApp::new().with_chipid(chipid);
        let (data, _) = drive(&mut app, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
        let mut pos = 1;
        while pos + 1 < data.len() {
            let tag = data[pos];
            let len = data[pos + 1] as usize;
            if tag == TAG_SERIAL {
                let mut expected = serial_from_chipid(chipid);
                expected[0] &= !0xFC;
                assert_eq!(&data[pos + 2..pos + 2 + 4], &expected[..]);
                assert_ne!(&data[pos + 2..pos + 2 + 4], &[0x31, 0x32, 0x33, 0x34]);
                return;
            }
            pos += 2 + len;
        }
        panic!("TAG_SERIAL missing from the default READ_CONFIG blob");
    }

    /// WRITE_CONFIG stores the blob; a subsequent READ_CONFIG returns it
    /// verbatim (C `file_has_data(EF_DEV_CONF)` → echo stored bytes).
    #[test]
    fn write_then_read_roundtrip() {
        let mut app = ManagementApp::new();
        let config = vec![0xAB, 0xCD, 0xEF];
        // APDU: [CLA, INS, P1, P2, Lc, data...] with data = [len, ...config].
        let mut data = vec![0x00, INS_WRITE_CONFIG, 0x00, 0x00, (1 + config.len()) as u8, config.len() as u8];
        data.extend_from_slice(&config);
        let (_, sw) = drive(&mut app, &data);
        assert_eq!(sw, SW_OK);
        assert!(app.has_config());

        let (resp, sw) = drive(&mut app, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        // Stored path: [overall_len = config_len] + config bytes (C writes the
        // length placeholder at [0] before memcpy-ing config to [1..]).
        let mut expected = vec![config.len() as u8];
        expected.extend_from_slice(&config);
        assert_eq!(&resp[..], &expected[..]);
    }

    /// RESET returns the app to the default (no-config) state.
    #[test]
    fn reset_clears_config() {
        let mut app = ManagementApp::new();
        // WRITE_CONFIG a single-byte config: data = [1, 0x00].
        let apdu = [0x00, INS_WRITE_CONFIG, 0x00, 0x00, 2, 1, 0x00];
        drive(&mut app, &apdu);
        assert!(app.has_config());

        let (_, sw) = drive(&mut app, &[0x00, INS_RESET, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        assert!(!app.has_config());

        // READ_CONFIG now emits the default caps blob again.
        let (data, _) = drive(&mut app, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
        assert_eq!(data[1], TAG_USB_SUPPORTED);
    }

    /// WRITE_CONFIG rejects a length field that does not match the payload.
    #[test]
    fn write_config_rejects_bad_length() {
        let mut app = ManagementApp::new();
        // Lc=3, data=[0x05, 0x01, 0x02]: data[0]=5 but only 2 bytes follow.
        let apdu = [0x00, INS_WRITE_CONFIG, 0x00, 0x00, 3, 0x05, 0x01, 0x02];
        let (_, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, SW_WRONG_DATA);
    }

    /// A non-zero CLA is rejected (C `man_process_apdu` gate).
    #[test]
    fn cla_must_be_zero() {
        let mut app = ManagementApp::new();
        let (_, sw) = drive(&mut app, &[0x80, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_CLA_NOT_SUPPORTED);
    }

    // US-391 boot fix: the firmware constructed the app with `new()`, which
    // silently drops the persisted `EF_DEV_CONF` on every reboot. `boot` is
    // the durable path.

    /// A persisted `EF_DEV_CONF` survives the reboot seam: `boot` reloads it
    /// from the secure store.
    #[test]
    fn boot_loads_persisted_config() {
        use fapico2_platform::secure_store::HostSecureStore;

        let mut app = ManagementApp::new();
        let apdu = [0x00, INS_WRITE_CONFIG, 0x00, 0x00, 2, 1, 0x00];
        drive(&mut app, &apdu);
        assert!(app.has_config());
        let mut store = HostSecureStore::new();
        assert!(app.persist_state(&mut store), "WRITE_CONFIG dirtied the app");

        // Reboot: a fresh app instance boots from the same store.
        let mut app2 = ManagementApp::boot(&mut store);
        assert!(app2.has_config(), "boot must reload the persisted EF_DEV_CONF");
        let (data, sw) = drive(&mut app2, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        assert_eq!(data, vec![1, 0x00]);
    }

    /// `boot` on a fresh (empty) partition starts at the factory-default
    /// configuration.
    #[test]
    fn boot_on_fresh_partition_is_default() {
        use fapico2_platform::secure_store::HostSecureStore;

        let mut store = HostSecureStore::new();
        let mut app = ManagementApp::boot(&mut store);
        assert!(!app.has_config());
        let (data, _) = drive(&mut app, &[0x00, INS_READ_CONFIG, 0x00, 0x00, 0x00]);
        assert_eq!(data[1], TAG_USB_SUPPORTED);
    }

    /// S-413-6: fixture handler delegating to the real platform completion
    /// over a synthetic C partition holding the 61-byte PIN-wrapped keydev
    /// KAT (platform::migration tests own the full fixture; here we verify
    /// the APDU surface: class byte, passphrase routing, status encoding).
    struct FixtureHandler {
        store: HostSecureStore,
        done: bool,
    }

    impl FixtureHandler {
        fn new() -> Self {
            Self { store: HostSecureStore::new(), done: false }
        }
    }

    impl MigrationHandler for FixtureHandler {
        fn complete(
            &mut self,
            class: u8,
            passphrase: &[u8],
            out: &mut HeaplessVec<u8, MAX_RESPONSE>,
        ) -> Sw {
            // Real platform path over the synthetic C partition.
            use fapico2_platform::cflash::DataPartition;
            use fapico2_platform::cfs::{CFlashSource, PoolBounds};
            use fapico2_platform::migration::{
                complete_passphrase_class, MigrationBuffers,
            };
            const FLASH_XIP_BASE: u32 = 0x1000_0000;
            const PART_START: u32 = FLASH_XIP_BASE + 0x102_000;
            const PART_END: u32 = PART_START + 3064 * 1024;
            const OTP_HEX: &str =
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
            const UID_HEX: &str = "0102030405060708";
            const KD61_HEX: &str =
                "02505152535455565758595a5bfb1a04be0af704eac566d0ca8675a75949d584b8779399972bcc27a3b906d1d672203288b3aaa3f9bac2bf0e1534ba63";

            let mut img = vec![0xFFu8; (PART_END - PART_START) as usize];
            let part = DataPartition { start: PART_START, end: PART_END };
            let b = PoolBounds::from_partition(part);
            let (end_rom, data_end) = (b.end_rom_pool, b.data_end);
            // One record: the 61-byte PIN-wrapped keydev, at the pool end.
            let rec_len = 12 + 2 + 61u32;
            let base = data_end - rec_len;
            let w = |img: &mut std::vec::Vec<u8>, addr: u32, bytes: &[u8]| {
                let o = (addr - PART_START) as usize;
                img[o..o + bytes.len()].copy_from_slice(bytes);
            };
            w(&mut img, base, &0u32.to_le_bytes()); // next = 0 (only record)
            w(&mut img, base + 4, &0u32.to_le_bytes());
            w(&mut img, base + 8, &0xCC00u16.to_le_bytes());
            w(&mut img, base + 10, &61u16.to_le_bytes());
            w(&mut img, base + 12, &hex(KD61_HEX));
            // hard-init: head = base, sentinels zeroed.
            w(&mut img, data_end, &base.to_le_bytes());
            w(&mut img, end_rom, &0u32.to_le_bytes());
            w(&mut img, end_rom + 4, &0u32.to_le_bytes());

            struct Flash { img: std::vec::Vec<u8> }
            impl CFlashSource for Flash {
                fn read(&self, addr: u32, buf: &mut [u8]) {
                    let o = (addr - PART_START) as usize;
                    buf.copy_from_slice(&self.img[o..o + buf.len()]);
                }
            }
            let f = Flash { img };
            let mut bufs = MigrationBuffers::new();
            let otp: [u8; 32] = hex(OTP_HEX).try_into().unwrap();
            let uid = hex(UID_HEX);
            // US-918 signature: the AEAD nonce — only the class-1 DEK rewrap
            // consumes it (class 0 persists the raw keydev value), so a fixed
            // zero nonce keeps these APDU-surface tests deterministic.
            const NONCE: [u8; 12] = [0u8; 12];
            match complete_passphrase_class(
                &f, part, &mut self.store, &otp, &uid, &mut bufs, class, &NONCE, passphrase,
            ) {
                Ok(status) => {
                    self.done = status == fapico2_platform::migration::ClassStatus::Migrated;
                    out.push(status.to_byte()).ok();
                    SW_OK
                }
                Err(_) => {
                    out.push(fapico2_platform::migration::ClassStatus::Error.to_byte())
                        .ok();
                    SW_OK
                }
            }
        }
    }

    fn hex(s: &str) -> std::vec::Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Malformed migration APDU (no class/passphrase data) ⇒ SW_WRONG_LENGTH.
    #[test]
    fn migration_apdu_malformed_is_wrong_length() {
        static mut HANDLER: Option<FixtureHandler> = None;
        let handler = unsafe {
            let h = core::ptr::addr_of_mut!(HANDLER);
            *h = Some(FixtureHandler::new());
            (*h).as_mut().unwrap()
        };
        let mut app = ManagementApp::new().with_migration_handler(handler);
        let (_, sw) = drive(&mut app, &[0x00, INS_MIGRATION, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_WRONG_LENGTH);
    }

    /// Without a handler (host builds), INS_MIGRATION is not supported.
    #[test]
    fn migration_apdu_without_handler_not_supported() {
        let mut app = ManagementApp::new();
        let (_, sw) = drive(&mut app, &[0x00, INS_MIGRATION, 0x00, 0x00, 0x02, 0x00, b'6']);
        assert_eq!(sw, SW_INS_NOT_SUPPORTED);
    }

    /// Correct PIN: class 0 completes over the real platform path — status
    /// 0 (MIGRATED) and the keystore slot updated in the fixture store.
    #[test]
    fn migration_apdu_correct_pin_migrates() {
        static mut HANDLER: Option<FixtureHandler> = None;
        let handler = unsafe {
            let h = core::ptr::addr_of_mut!(HANDLER);
            *h = Some(FixtureHandler::new());
            (*h).as_mut().unwrap()
        };
        let mut app = ManagementApp::new().with_migration_handler(handler);
        let mut apdu = vec![0x00, INS_MIGRATION, 0x00, 0x00, 0x07, 0x00];
        apdu.extend_from_slice(b"123456");
        let (resp, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, SW_OK);
        assert_eq!(resp, vec![0x00]); // MIGRATED
    }

    /// Wrong PIN: status 1 (NEEDS_PASSPHRASE), constant behavior.
    #[test]
    fn migration_apdu_wrong_pin_needs_passphrase() {
        static mut HANDLER: Option<FixtureHandler> = None;
        let handler = unsafe {
            let h = core::ptr::addr_of_mut!(HANDLER);
            *h = Some(FixtureHandler::new());
            (*h).as_mut().unwrap()
        };
        let mut app = ManagementApp::new().with_migration_handler(handler);
        let mut apdu = vec![0x00, INS_MIGRATION, 0x00, 0x00, 0x07, 0x00];
        apdu.extend_from_slice(b"999999");
        let (resp, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, SW_OK);
        assert_eq!(resp, vec![0x01]); // NEEDS_PASSPHRASE
    }
}
