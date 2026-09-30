//! PIV applet (Rust migration Phase 4, US-371..US-378).
//!
//! Rust port of `pico-openpgp/src/openpgp/piv.c` (GPLv3), scoped by ADR 0001
//! (ECC-only: P-256/P-384 ECDSA + ECDH; RSA is out of scope for this merge).
//!
//! The AID dispatcher (`fapico2_platform::dispatch`) selects this app on the
//! PIV AID `A0 00 00 03 08`. Like the C reference, PIV commands are dispatched
//! on INS only (no CLA gate).
//!
//! * US-371 — skeleton: SELECT (FCI blob + 9000), GET VERSION (0xFD), GET
//!   SERIAL (0xF8).
//! * US-372 — authentication: VERIFY PIN (0x20), CHANGE REFERENCE (0x24),
//!   RESET RETRY (0x2C), management-key AUTHENTICATE (0x87/0x9b, single +
//!   mutual challenge), SET MGM KEY (0xFF), SET RETRIES (0xFA), RESET (0xFB).
//!
//! Later stories add data objects (US-373), key import/generation (US-374)
//! and ECC sign/ECDH (US-375).

pub mod crypto;
#[cfg(not(target_arch = "arm"))]
pub mod keystore;

use fapico2_platform::apdu_chain::{ChainAssembler, Step};
use fapico2_platform::dispatch::{
    App, MAX_RESPONSE, Sw, SW_FILE_NOT_FOUND, SW_INS_NOT_SUPPORTED, SW_OK, SW_WRONG_LENGTH,
};
use fapico2_platform::trng;
use heapless::Vec as HeaplessVec;

/// PIV application AID (C `piv_aid`).
pub const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

/// Version reported by GET VERSION (C `version.h`: `PIV_VERSION 0x0507` →
/// "5.7.0" as printed by `yubico-piv-tool -a status`).
pub const PIV_VERSION_MAJOR: u8 = 5;
pub const PIV_VERSION_MINOR: u8 = 7;

/// Fixed dev serial, matching the C `get_serial()` dev build (0x31323334).
const SERIAL: u32 = 0x31323334;

// Command INS bytes (C command table in `piv.c`).
const INS_VERSION: u8 = 0xFD;
const INS_YK_SERIAL: u8 = 0xF8;
const INS_SELECT: u8 = 0xA4;
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_PIN: u8 = 0x24;
const INS_RESET_RETRY: u8 = 0x2C;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_SET_MGMKEY: u8 = 0xFF;
const INS_SET_RETRIES: u8 = 0xFA;
const INS_RESET: u8 = 0xFB;
const INS_GET_DATA: u8 = 0xCB;
const INS_PUT_DATA: u8 = 0xDB;

/// C `OPENPGP_MAX_OBJECT_SIZE` — PUT DATA rejects larger 53 payloads.
const MAX_OBJECT_SIZE: usize = 2048;

// Status words (C `apdu.h`).
const SW_WRONG_P1P2: Sw = 0x6B00;
const SW_WRONG_DATA: Sw = 0x6700;
const SW_MEMORY_FAILURE: Sw = 0x6581;
const SW_EXEC_ERROR: Sw = 0x6400;
const SW_FUNC_NOT_SUPPORTED: Sw = 0x6A81;
const SW_INCORRECT_PARAMS: Sw = 0x6A80;
const SW_INCORRECT_P1P2: Sw = 0x6A86;
const SW_REFERENCE_NOT_FOUND: Sw = 0x6A88;
const SW_PIN_BLOCKED: Sw = 0x6983;
const SW_DATA_INVALID: Sw = 0x6984;
// Data-object format errors (US-373+); part of the C `apdu.h` SW set.
#[allow(dead_code)]
const SW_CONDITIONS_NOT_SATISFIED: Sw = 0x6985;
const SW_SECURITY_STATUS_NOT_SATISFIED: Sw = 0x6982;

// PIV algorithm ids (C `piv.c` — note the pico numbering: AES128 = 0x08,
// AES192 = 0x0A, AES256 = 0x0C).
pub const PIV_ALGO_3DES: u8 = 0x03;
pub const PIV_ALGO_AES128: u8 = 0x08;
pub const PIV_ALGO_AES192: u8 = 0x0A;
pub const PIV_ALGO_AES256: u8 = 0x0C;
/// ECC slots (US-374/US-375, ADR 0001).
pub const PIV_ALGO_ECCP256: u8 = 0x11;
pub const PIV_ALGO_ECCP384: u8 = 0x14;

/// CARD-MGM key slot (C `EF_PIV_KEY_CARDMGM`).
const KEY_CARDMGM: u8 = 0x9B;
/// PIV reference wire size (C `PIV_PIN_WIRE_SIZE`): 8 bytes, 0xFF-padded.
const PIN_WIRE_SIZE: usize = 8;

// Touch policy values (C `piv.c`).
const TOUCHPOLICY_NEVER: u8 = 1;
const TOUCHPOLICY_ALWAYS: u8 = 2;

// Default reference data (C `scan_files_piv` / `cmd_set_retries`).
const DEFAULT_PIN: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
const DEFAULT_PUK: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];

// Management-key challenge state (C `mgm_challenge_kind`).
const MGM_CHALLENGE_NONE: u8 = 0;
const MGM_CHALLENGE_MUTUAL: u8 = 1;
const MGM_CHALLENGE_SINGLE: u8 = 2;

/// FCI response emitted on SELECT (C `select_piv_aid`). The C card returns
/// 61xx and requires a follow-up GET RESPONSE; ykpiv also accepts the data
/// directly with 9000, which is what this port emits (the dispatcher writes
/// the SW itself, so the handler only contributes the data bytes).
fn select_fci() -> [u8; 44] {
    [
        0x4F, 0x02, 0x01, 0x00,
        0x79, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00,
        // 0x50 application label, length = strlen("Pico Keys PIV") = 13 (0x0D),
        // exactly as C `select_piv_aid` emits it.
        0x50, 0x0D, b'P', b'i', b'c', b'o', b' ', b'K', b'e', b'y', b's', b' ', b'P', b'I', b'V',
        0xAC, 0x0C, 0x80, 0x07, 0x07, 0x08, 0x0A, 0x0C, 0x11, 0x14, 0x2E,
        0x06, 0x01, 0x00,
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Pin,
    Puk,
}

/// PIV persistent + session state.
///
/// Persistent half (US-372): PIN/PUK verifiers (C `EF_PIV_PIN`/`EF_PIV_PUK`,
/// 34-byte `[len, format, verifier]` files), retry counters (C
/// `EF_PW_PRIV[7..9]` / `EF_PW_RETRIES[4..6]`), management key (C
/// `EF_PIV_KEY_CARDMGM`) and its metadata triple (algo, pin policy, touch
/// policy — C `meta_add`). US-373: data objects (C 0xC1xx file table —
/// certs, CHUID, CCC, GP DOs) keyed by file id.
///
/// Session half (C `has_pwpiv` / `has_mgm` / `mgm_challenge*`): volatile,
/// cleared on every SELECT/deselect (C `init_piv` / `piv_unload`) and on
/// keystore load.
#[derive(Debug)]
#[cfg_attr(not(target_arch = "arm"), derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct PivState {
    pin: Option<[u8; 32]>,
    puk: Option<[u8; 32]>,
    pin_retries: u8,
    puk_retries: u8,
    pin_total: u8,
    puk_total: u8,
    mgm_key: [u8; 32],
    mgm_key_len: u8,
    mgm_algo: u8,
    mgm_pin_policy: u8,
    mgm_touch: u8,
    /// Data objects (C 0xC1xx EFs), file id → content.
    objects: std::collections::BTreeMap<u16, Vec<u8>>,
    // Session state.
    has_pwpiv: bool,
    has_mgm: bool,
    mgm_challenge: [u8; 16],
    mgm_challenge_kind: u8,
    mgm_challenge_algo: u8,
}

impl Default for PivState {
    fn default() -> Self {
        let mut mgm_key = [0u8; 32];
        mgm_key[..24].copy_from_slice(&DEFAULT_MGM_KEY);
        Self {
            // C `scan_files_piv`: default PIN "123456\xff\xff", PUK "12345678".
            pin: Some(crypto::pin_derive_verifier(&DEFAULT_PIN)),
            puk: Some(crypto::pin_derive_verifier(&DEFAULT_PUK)),
            pin_retries: 3,
            puk_retries: 3,
            pin_total: 3,
            puk_total: 3,
            // C `scan_files_piv`: 24-byte 0x01..0x08 ×3 key, AES-192, touch
            // ALWAYS, pin policy DEFAULT.
            mgm_key,
            mgm_key_len: 24,
            mgm_algo: PIV_ALGO_AES192,
            mgm_pin_policy: 0,
            mgm_touch: TOUCHPOLICY_ALWAYS,
            objects: std::collections::BTreeMap::new(),
            has_pwpiv: false,
            has_mgm: false,
            mgm_challenge: [0; 16],
            mgm_challenge_kind: MGM_CHALLENGE_NONE,
            mgm_challenge_algo: 0,
        }
    }
}

/// Default 24-byte management key (C `piv_management_key_default`).
const DEFAULT_MGM_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// PIV application.
#[derive(Default)]
pub struct PivApp {
    st: PivState,
    /// US-181 (PICOForge-COMPAT): receive-side ISO 7816-4 command chaining.
    ///
    /// Like the C reference and unlike the three applets that *do* gate on
    /// CLA, PIV dispatches on INS only (the module docs say so, and
    /// `process` below has no CLA comparison), so a `cla|0x10` fragment used
    /// to reach `parse_data` as an ordinary APDU and then die on the
    /// bounds-check in `tlv_iter` — a 6A80 on every long `PUT DATA`.
    ///
    /// The field is `Default` so the `#[derive(Default)]` above still holds;
    /// the on-device `bss` cost is the same `MAX_CHAINED_APDU` the OpenPGP
    /// applet pays, and the same reasoning applies — see
    /// `platform::apdu_chain` for why it is a static buffer and not a heap.
    chain: ChainAssembler,
    /// Host/emulation persistence (C `flash_commit` stand-in). Device
    /// wiring is future work; `new()` is the in-memory form used by tests.
    #[cfg(not(target_arch = "arm"))]
    keystore: Option<keystore::PivKeystore>,
}

impl PivApp {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load (or create) the secure-store snapshot and start from it.
    #[cfg(not(target_arch = "arm"))]
    pub fn with_keystore(
        path: std::path::PathBuf,
    ) -> Result<Self, keystore::PivKeystoreError> {
        let (st, keystore) = keystore::PivKeystore::load_or_create(path)?;
        Ok(Self {
            st,
            // US-181: a freshly-loaded app has no chain in progress. Named
            // rather than `..Default::default()` so that adding a field later
            // is a compile error here instead of a silently-defaulted one.
            chain: ChainAssembler::new(),
            keystore: Some(keystore),
        })
    }

    /// C `flash_commit()`: persist the persistent half of the state.
    fn persist(&self) {
        #[cfg(not(target_arch = "arm"))]
        if let Some(ks) = &self.keystore {
            if let Err(e) = ks.persist(&self.st) {
                eprintln!("fapico2-piv: keystore persist failed: {e:?}");
            }
        }
    }

    /// C `init_piv` / `piv_unload`: SELECT and deselect both clear the
    /// session (PIN auth, mgm auth, pending mgm challenge). ykpiv relies on
    /// this ("do not select the applet here, as it resets the challenge
    /// state").
    fn reset_session(&mut self) {
        self.st.has_pwpiv = false;
        self.st.has_mgm = false;
        self.st.mgm_challenge = [0; 16];
        self.st.mgm_challenge_kind = MGM_CHALLENGE_NONE;
        self.st.mgm_challenge_algo = 0;
        // US-181: a SELECT or deselect also drops a half-received command
        // chain. Both already funnel through here, so this is the one place
        // to put it — and it is load-bearing, not tidiness: without it a
        // client that abandoned a chain mid-stream would have its bytes
        // prepended to the first command after the re-select.
        self.chain.reset();
    }

    fn clear_mgm_challenge(&mut self) {
        self.st.mgm_challenge = [0; 16];
        self.st.mgm_challenge_kind = MGM_CHALLENGE_NONE;
        self.st.mgm_challenge_algo = 0;
    }

    /// C `pin_check_verifier` + `pin_spend_retry` + `pin_reset_retries`:
    /// spend one retry BEFORE comparing (C order), reset on success.
    fn check_reference(&mut self, which: Which, pin: &[u8]) -> Sw {
        let (verifier, retries) = match which {
            Which::Pin => match self.st.pin {
                Some(v) => (v, self.st.pin_retries),
                None => return SW_FILE_NOT_FOUND,
            },
            Which::Puk => match self.st.puk {
                Some(v) => (v, self.st.puk_retries),
                None => return SW_FILE_NOT_FOUND,
            },
        };
        if retries == 0 {
            return SW_PIN_BLOCKED;
        }
        let remaining = retries - 1;
        match which {
            Which::Pin => self.st.pin_retries = remaining,
            Which::Puk => self.st.puk_retries = remaining,
        }
        let expected = crypto::pin_derive_verifier(pin);
        if !crypto::ct_eq(&expected, &verifier) {
            return if remaining == 0 {
                SW_PIN_BLOCKED
            } else {
                0x63C0 | remaining as u16
            };
        }
        match which {
            Which::Pin => self.st.pin_retries = self.st.pin_total,
            Which::Puk => self.st.puk_retries = self.st.puk_total,
        }
        SW_OK
    }

    /// C `dhash[0]=8; dhash[1]=1; pin_derive_verifier(...)` — store a
    /// reference (PIN/PUK) from its 8-byte wire form.
    fn set_reference(&mut self, which: Which, pin: &[u8]) {
        let v = crypto::pin_derive_verifier(pin);
        match which {
            Which::Pin => self.st.pin = Some(v),
            Which::Puk => self.st.puk = Some(v),
        }
    }

    fn which_ok(which: Which, st: &PivState) -> bool {
        match which {
            Which::Pin => st.pin.is_some(),
            Which::Puk => st.puk.is_some(),
        }
    }
}

impl App for PivApp {
    fn aid(&self) -> &[u8] {
        PIV_AID
    }

    fn select(&mut self, _internal: bool) -> Sw {
        self.reset_session();
        SW_OK
    }

    fn deselect(&mut self) {
        self.reset_session();
    }

    fn select_apdu(
        &mut self,
        _internal: bool,
        _apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        // Host-issued SELECT (dispatcher-routed, `00 A4 04 00`): emit the FCI
        // blob, then 9000 (C `select_piv_aid` minus the 61xx/GET RESPONSE dance).
        self.reset_session();
        push_slice(resp, &select_fci());
        SW_OK
    }

    fn process(&mut self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        // C has no CLA gate: `piv_process_apdu` matches on INS only.
        //
        // US-181 (PICOForge-COMPAT): the chain is resolved here, at the one
        // entry point, rather than inside `cmd_put_data`. Two reasons, and the
        // second is the one that decides it:
        //
        // 1. PicoForge chains `PUT DATA` **and** `IMPORT`
        //    (`picoforge/src/hal/applets/piv.rs:592` and `:673`), and
        //    `IMPORT` is `INS 0xFE` — an INS this applet does not implement
        //    yet, so a `cmd_put_data`-only hook would leave the next chained
        //    command to be wired twice.
        // 2. Resolving per-INS means every new INS re-derives the same
        //    three-way `Step` match, and only one of the copies would be
        //    covered by the `platform::apdu_chain` tests.
        //
        // `Pass` is the important one: an ordinary command with no chain in
        // progress leaves the accumulator having been read but not parsed and
        // not copied, so the code below is exactly what it always was —
        // including the status a malformed body gets, which routing it
        // through the chain parser would have quietly rewritten. `Buffered`
        // dispatches nothing and answers `9000`, because PicoForge hard-fails
        // on any other status (`picoforge/src/hal/transport/ccid.rs:129-131`).
        // `Broken` answers the error; the accumulated bytes are already gone
        // by then.
        //
        // `Complete` needs `take_apdu` rather than `apdu()`: every arm below
        // takes `&mut self`, so a borrow of `self.chain` could not survive the
        // call. The hand-off is a move, and it only happens on a resolved
        // chain — once per long `PUT DATA`.
        let rendered = match self.chain.push(apdu) {
            Step::Pass => None,
            Step::Buffered => {
                write_sw(resp, SW_OK);
                return;
            }
            Step::Complete => Some(self.chain.take_apdu()),
            Step::Broken(err) => {
                write_sw(resp, err.status());
                return;
            }
        };
        let apdu = rendered.as_deref().unwrap_or(apdu);
        let sw = match apdu.get(1) {
            Some(&INS_VERSION) => {
                push_slice(resp, &[PIV_VERSION_MAJOR, PIV_VERSION_MINOR, 0x00]);
                SW_OK
            }
            Some(&INS_YK_SERIAL) => {
                push_slice(resp, &SERIAL.to_be_bytes());
                SW_OK
            }
            Some(&INS_SELECT) => self.cmd_select(apdu, resp),
            Some(&INS_VERIFY) => self.cmd_verify(apdu),
            Some(&INS_CHANGE_PIN) => self.cmd_change_reference(apdu),
            Some(&INS_RESET_RETRY) => self.cmd_reset_retry(apdu),
            Some(&INS_AUTHENTICATE) => self.cmd_authenticate(apdu, resp),
            Some(&INS_SET_MGMKEY) => self.cmd_set_mgmkey(apdu),
            Some(&INS_SET_RETRIES) => self.cmd_set_retries(apdu),
            Some(&INS_RESET) => self.cmd_reset(apdu),
            Some(&INS_GET_DATA) => self.cmd_get_data(apdu, resp),
            Some(&INS_PUT_DATA) => self.cmd_put_data(apdu),
            _ => SW_INS_NOT_SUPPORTED,
        };
        write_sw(resp, sw);
    }
}

impl PivApp {
    /// `00 A4 04 01` select variant (C `cmd_piv_select`): P2 must be 0x01; when
    /// the data is the 5-byte PIV AID the FCI blob is re-emitted. C returns 9000
    /// either way once P2 is right.
    fn cmd_select(&self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) -> Sw {
        if apdu.get(3) != Some(&0x01) {
            return SW_WRONG_P1P2;
        }
        let data = parse_data(apdu);
        if data.get(..PIV_AID.len()) == Some(PIV_AID) {
            push_slice(resp, &select_fci());
        }
        SW_OK
    }

    /// C `cmd_piv_verify` (0x20): P1 0x00 verify / 0xFF logout, P2 0x80 (PIN
    /// only). No data → report 63C<retries> (or 9000 while authenticated).
    fn cmd_verify(&mut self, apdu: &[u8]) -> Sw {
        let p1 = *apdu.get(2).unwrap_or(&0x00);
        let p2 = *apdu.get(3).unwrap_or(&0x00);
        if (p1 != 0x00 && p1 != 0xFF) || p2 != 0x80 {
            return SW_INCORRECT_PARAMS;
        }
        if self.st.pin.is_none() {
            return SW_REFERENCE_NOT_FOUND;
        }
        let data = parse_data(apdu);
        if p1 == 0xFF {
            if !data.is_empty() {
                return SW_INCORRECT_PARAMS;
            }
            self.st.has_pwpiv = false;
            return SW_OK;
        }
        if !data.is_empty() && data.len() != PIN_WIRE_SIZE {
            self.st.has_pwpiv = false;
            return SW_INCORRECT_PARAMS;
        }
        if !data.is_empty() {
            self.st.has_pwpiv = false;
            let sw = self.check_reference(Which::Pin, &data);
            if sw == SW_OK {
                self.st.has_pwpiv = true;
            }
            self.persist(); // C: pin_spend_retry commits the counter
            return sw;
        }
        if self.st.pin_retries == 0 {
            return SW_PIN_BLOCKED;
        }
        if self.st.has_pwpiv {
            return SW_OK;
        }
        0x63C0 | self.st.pin_retries as u16
    }

    /// C `cmd_piv_change_pin` (0x24): P1 0x00, P2 0x80 (PIN) / 0x81 (PUK),
    /// data = old(8) || new(8). Verifying the old reference spends a retry.
    fn cmd_change_reference(&mut self, apdu: &[u8]) -> Sw {
        let p1 = *apdu.get(2).unwrap_or(&0x00);
        let p2 = *apdu.get(3).unwrap_or(&0x00);
        let which = match p2 {
            0x80 => Which::Pin,
            0x81 => Which::Puk,
            _ => return SW_REFERENCE_NOT_FOUND,
        };
        if p1 != 0x00 {
            return SW_REFERENCE_NOT_FOUND;
        }
        let data = parse_data(apdu);
        if data.len() != PIN_WIRE_SIZE * 2 {
            return SW_INCORRECT_PARAMS;
        }
        if !Self::which_ok(which, &self.st) {
            return SW_MEMORY_FAILURE;
        }
        // The old-reference check spends a retry either way (C commits the
        // counter before the outcome is known).
        let sw = self.check_reference(which, &data[..PIN_WIRE_SIZE]);
        self.persist();
        if sw != SW_OK {
            return sw;
        }
        self.set_reference(which, &data[PIN_WIRE_SIZE..]);
        self.persist();
        SW_OK
    }

    /// C `cmd_piv_reset_retry` (0x2C): P1 0x00 P2 0x80, data = puk(8) ||
    /// new_pin(8). Verifies the PUK, then unblocks + re-keys the PIN.
    fn cmd_reset_retry(&mut self, apdu: &[u8]) -> Sw {
        let p1 = *apdu.get(2).unwrap_or(&0x00);
        let p2 = *apdu.get(3).unwrap_or(&0x00);
        if p1 != 0x00 || p2 != 0x80 {
            return SW_REFERENCE_NOT_FOUND;
        }
        let data = parse_data(apdu);
        if data.len() != PIN_WIRE_SIZE * 2 {
            return SW_INCORRECT_PARAMS;
        }
        if self.st.puk.is_none() {
            return SW_MEMORY_FAILURE;
        }
        // The PUK check spends a retry either way.
        let sw = self.check_reference(Which::Puk, &data[..PIN_WIRE_SIZE]);
        self.persist();
        if sw != SW_OK {
            return sw;
        }
        self.set_reference(Which::Pin, &data[PIN_WIRE_SIZE..]);
        // C `pin_reset_retries(ef, true)` — force: works even while blocked.
        self.st.pin_retries = self.st.pin_total;
        self.persist();
        SW_OK
    }

    /// C `cmd_authenticate` (0x87), CARD-MGM (P2 0x9b) path. Slot-key
    /// authentication (9a/9c/9d/9e) arrives with US-374/US-375.
    fn cmd_authenticate(
        &mut self,
        apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        let algo = *apdu.get(2).unwrap_or(&0x00);
        let key_ref = *apdu.get(3).unwrap_or(&0x00);
        let data = parse_data(apdu);
        if data.is_empty() || data[0] != 0x7C {
            return SW_INCORRECT_PARAMS;
        }
        if key_ref != KEY_CARDMGM {
            return SW_FUNC_NOT_SUPPORTED;
        }
        if self.st.mgm_key_len == 0 {
            return SW_MEMORY_FAILURE;
        }
        if !matches!(
            algo,
            PIV_ALGO_3DES | PIV_ALGO_AES128 | PIV_ALGO_AES192 | PIV_ALGO_AES256
        ) {
            return SW_INCORRECT_PARAMS;
        }
        let want_len = match algo {
            PIV_ALGO_AES128 => 16,
            PIV_ALGO_AES192 => 24,
            PIV_ALGO_AES256 => 32,
            _ => 24, // 3DES
        };
        if self.st.mgm_key_len as usize != want_len {
            return SW_INCORRECT_PARAMS;
        }
        // C: chal_len = 3DES ? sizeof(mgm_challenge)/2 : sizeof(mgm_challenge)
        // with `mgm_challenge[16]`.
        let chal_len = if algo == PIV_ALGO_3DES { 8 } else { 16 };

        let t7c = match find_tag(&data, 0x7C) {
            Some(v) if !v.is_empty() => v,
            _ => return SW_INCORRECT_PARAMS,
        };
        let op = match first_auth_operation(t7c) {
            Some(o) => o,
            None => return SW_INCORRECT_PARAMS,
        };
        let challenge_response = matches!(op.0, 0x80 | 0x82) && !op.1.is_empty();
        let pending = self.st.mgm_challenge_kind != MGM_CHALLENGE_NONE;
        // C: stored meta algo must match, except while answering a pending
        // challenge. (Touch check is `#ifndef ENABLE_EMULATION` in C.)
        if self.st.mgm_algo != algo && !(pending && challenge_response) {
            return SW_INCORRECT_PARAMS;
        }
        let a81 = find_tag(t7c, 0x81);
        let a82 = find_tag(t7c, 0x82);
        match op.0 {
            0x80 => self.mgm_auth_op(algo, chal_len, Some(op.1), a81, None, resp),
            0x81 if op.1.is_empty() => self.mgm_auth_op(algo, chal_len, None, Some(b""), None, resp),
            0x82 => self.mgm_auth_op(algo, chal_len, None, None, a82, resp),
            _ => SW_INCORRECT_PARAMS,
        }
    }

    /// C `authenticate_mgm`: a80/a81/a82 are the 0x80/0x81/0x82 TLV values
    /// present in the 7C template (empty slice == tag present with length 0).
    fn mgm_auth_op(
        &mut self,
        algo: u8,
        chal_len: usize,
        a80: Option<&[u8]>,
        a81: Option<&[u8]>,
        a82: Option<&[u8]>,
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        // Copy the key out before touching session state: the crypt calls
        // below interleave with `clear_mgm_challenge()` (mutable borrow).
        let key_len = self.st.mgm_key_len as usize;
        let mut key_buf = [0u8; 32];
        key_buf[..key_len].copy_from_slice(&self.st.mgm_key[..key_len]);
        let key = &key_buf[..key_len];

        // Mutual challenge: `7C .. 80 00` → card issues an encrypted
        // challenge.
        if let Some(c80) = a80 {
            if c80.is_empty() {
                if a81.is_some() || a82.is_some() {
                    self.clear_mgm_challenge();
                    return SW_INCORRECT_PARAMS;
                }
                let fresh = trng::random_bytes::<16>();
                let mut ch = [0u8; 16];
                ch[..chal_len].copy_from_slice(&fresh[..chal_len]);
                self.st.mgm_challenge = ch;
                self.st.mgm_challenge_kind = MGM_CHALLENGE_MUTUAL;
                self.st.mgm_challenge_algo = algo;
                let enc = match crypto::mgm_crypt(algo, key, &ch[..chal_len], true) {
                    Some(e) => e,
                    None => {
                        self.clear_mgm_challenge();
                        return SW_EXEC_ERROR;
                    }
                };
                push_slice(resp, &[0x7C, (chal_len + 2) as u8, 0x80, chal_len as u8]);
                push_slice(resp, &enc);
                self.st.has_mgm = false;
                return SW_OK;
            }
            // Mutual completion: `7C .. 80 <witness> 81 <host random>`.
            let host_random = match a81 {
                Some(h) => h,
                None => {
                    self.clear_mgm_challenge();
                    return SW_INCORRECT_PARAMS;
                }
            };
            let valid_state = self.st.mgm_challenge_kind == MGM_CHALLENGE_MUTUAL
                && self.st.mgm_challenge_algo == algo
                && c80.len() == chal_len
                && host_random.len() == chal_len
                && a82.is_none();
            let witness_matches =
                valid_state && crypto::ct_eq(c80, &self.st.mgm_challenge[..chal_len]);
            self.clear_mgm_challenge();
            if !witness_matches {
                return SW_DATA_INVALID;
            }
            let enc = match crypto::mgm_crypt(algo, key, host_random, true) {
                Some(e) => e,
                None => return SW_EXEC_ERROR,
            };
            push_slice(resp, &[0x7C, (chal_len + 2) as u8, 0x82, chal_len as u8]);
            push_slice(resp, &enc);
            self.st.has_mgm = true;
            return SW_OK;
        }

        // Single challenge: `7C .. 81 00` → card issues a plaintext challenge.
        if let Some(c81) = a81 {
            if c81.is_empty() {
                if a82.is_some() {
                    self.clear_mgm_challenge();
                    return SW_INCORRECT_PARAMS;
                }
                let fresh = trng::random_bytes::<16>();
                let mut ch = [0u8; 16];
                ch[..chal_len].copy_from_slice(&fresh[..chal_len]);
                self.st.mgm_challenge = ch;
                self.st.mgm_challenge_kind = MGM_CHALLENGE_SINGLE;
                self.st.mgm_challenge_algo = algo;
                push_slice(resp, &[0x7C, (chal_len + 2) as u8, 0x81, chal_len as u8]);
                push_slice(resp, &ch[..chal_len]);
                self.st.has_mgm = false;
                return SW_OK;
            }
            // 0x81 with data is not a management operation (signing uses it
            // for slot keys, US-375).
            self.clear_mgm_challenge();
            return SW_INCORRECT_PARAMS;
        }

        // Single completion: `7C .. 82 <response>` → card decrypts and
        // compares against the issued challenge.
        if let Some(c82) = a82 {
            if !c82.is_empty() {
                let valid_state = self.st.mgm_challenge_kind == MGM_CHALLENGE_SINGLE
                    && self.st.mgm_challenge_algo == algo
                    && c82.len() == chal_len;
                let decrypted = if valid_state {
                    crypto::mgm_crypt(algo, key, c82, false)
                } else {
                    None
                };
                let response_matches = match &decrypted {
                    Some(d) => crypto::ct_eq(d, &self.st.mgm_challenge[..chal_len]),
                    None => false,
                };
                self.clear_mgm_challenge();
                if decrypted.is_none() && valid_state {
                    return SW_EXEC_ERROR;
                }
                if !response_matches {
                    return SW_DATA_INVALID;
                }
                self.st.has_mgm = true;
                return SW_OK;
            }
        }

        self.clear_mgm_challenge();
        SW_INCORRECT_PARAMS
    }

    /// C `cmd_set_mgmkey` (0xFF): P1 0xFF, P2 0xFF (touch never) / 0xFE
    /// (touch always), data = [algo, 0x9b, key_len, key...]. Requires an
    /// authenticated management session.
    fn cmd_set_mgmkey(&mut self, apdu: &[u8]) -> Sw {
        let p1 = *apdu.get(2).unwrap_or(&0x00);
        let p2 = *apdu.get(3).unwrap_or(&0x00);
        if p1 != 0xFF {
            return SW_WRONG_P1P2;
        }
        let data = parse_data(apdu);
        if data.len() < 5 {
            return SW_WRONG_LENGTH;
        }
        if !self.st.has_mgm {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let touch = match p2 {
            0xFF => TOUCHPOLICY_NEVER,
            0xFE => TOUCHPOLICY_ALWAYS,
            _ => return SW_WRONG_P1P2,
        };
        let (algo, key_ref, pinlen) = (data[0], data[1], data[2] as usize);
        let combo_ok = key_ref == KEY_CARDMGM
            && match algo {
                PIV_ALGO_AES128 => pinlen == 16,
                PIV_ALGO_AES192 => pinlen == 24,
                PIV_ALGO_AES256 => pinlen == 32,
                PIV_ALGO_3DES => pinlen == 24,
                _ => false,
            };
        if !combo_ok {
            return SW_WRONG_DATA;
        }
        if data.len() != pinlen + 3 {
            return SW_WRONG_LENGTH;
        }
        let mut key = [0u8; 32];
        key[..pinlen].copy_from_slice(&data[3..3 + pinlen]);
        self.st.mgm_key = key;
        self.st.mgm_key_len = pinlen as u8;
        // C `meta_add`: (algo, MGM_PIN_POLICY, touch).
        self.st.mgm_algo = algo;
        self.st.mgm_pin_policy = 0;
        self.st.mgm_touch = touch;
        self.persist();
        SW_OK
    }

    /// C `cmd_set_retries` (0xFA): P1/P2 = new PIN/PUK retry totals. Requires
    /// both mgm and PIN authentication; also resets PIN+PUK to factory
    /// defaults.
    fn cmd_set_retries(&mut self, apdu: &[u8]) -> Sw {
        if !self.st.has_mgm || !self.st.has_pwpiv {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let p1 = *apdu.get(2).unwrap_or(&0x00);
        let p2 = *apdu.get(3).unwrap_or(&0x00);
        self.st.pin_total = p1;
        self.st.puk_total = p2;
        self.set_reference(Which::Pin, &DEFAULT_PIN);
        self.st.pin_retries = self.st.pin_total;
        self.set_reference(Which::Puk, &DEFAULT_PUK);
        self.st.puk_retries = self.st.puk_total;
        self.persist();
        SW_OK
    }

    /// C `cmd_reset` (0xFB): factory reset, allowed only when BOTH PIN and
    /// PUK are blocked (retries exhausted).
    fn cmd_reset(&mut self, apdu: &[u8]) -> Sw {
        let p1 = *apdu.get(2).unwrap_or(&0x00);
        let p2 = *apdu.get(3).unwrap_or(&0x00);
        if p1 != 0x00 || p2 != 0x00 {
            return SW_INCORRECT_P1P2;
        }
        if self.st.pin_retries != 0 || self.st.puk_retries != 0 {
            return SW_INCORRECT_PARAMS;
        }
        self.st = PivState::default();
        self.persist();
        SW_OK
    }

    /// C `cmd_piv_get_data` (0xCB, P1 0x3F P2 0xFF): data =
    /// `5C <len> 5F C1 <fid>` (1..3 id bytes); response `53 <len> <contents>`
    /// with the C `tlv_format_len` length form. Empty/absent → 6A82.
    fn cmd_get_data(
        &mut self,
        apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        let p1 = *apdu.get(2).unwrap_or(&0x00);
        let p2 = *apdu.get(3).unwrap_or(&0x00);
        if p1 != 0x3F || p2 != 0xFF {
            return SW_INCORRECT_P1P2;
        }
        let data = parse_data(apdu);
        if data.len() < 3 {
            return SW_WRONG_LENGTH;
        }
        if data[0] != 0x5C || (data[1] & 0x80) != 0 || data[1] == 0 || data[1] >= 4 {
            return SW_WRONG_DATA;
        }
        if data.len() != data[1] as usize + 2 {
            return SW_WRONG_LENGTH;
        }
        let mut fid: u32 = 0;
        for b in &data[2..2 + data[1] as usize] {
            fid = (fid << 8) | *b as u32;
        }
        // C allows only the 5F C1 xx object space here (the BITGT/DISCOVERY/
        // admin/attestation function files have no equivalent in the merged
        // tree, so they answer 6A82 as well).
        if (fid & 0xFFFF00) != 0x5FC100 {
            return SW_FILE_NOT_FOUND;
        }
        let obj_fid = fid as u16;
        match self.st.objects.get(&obj_fid) {
            Some(bytes) if !bytes.is_empty() => {
                resp.push(0x53).ok();
                push_tlv_len(resp, bytes.len());
                push_slice(resp, bytes);
                SW_OK
            }
            _ => SW_FILE_NOT_FOUND,
        }
    }

    /// C `cmd_piv_put_data` (0xDB, P1 0x3F P2 0xFF): requires the mgm
    /// session; the body carries TOP-LEVEL `5C 03 5F C1 <fid>` + `53 <len>
    /// <data>` (the flat form yubikit sends; a 7E/7F leading byte is also
    /// admitted by C). An empty 53 clears the object (C
    /// `flash_clear_file`).
    fn cmd_put_data(&mut self, apdu: &[u8]) -> Sw {
        let p1 = *apdu.get(2).unwrap_or(&0x00);
        let p2 = *apdu.get(3).unwrap_or(&0x00);
        if p1 != 0x3F || p2 != 0xFF {
            return SW_INCORRECT_P1P2;
        }
        if !self.st.has_mgm {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let data = parse_data(apdu);
        if data.is_empty() {
            return SW_WRONG_LENGTH;
        }
        // C walks the body FLAT from byte 0 (tlv_find_tag), so 5C/53 are
        // found only at top level.
        let a5c = find_tag(&data, 0x5C);
        let a53 = find_tag(&data, 0x53);
        if data[0] != 0x7E && data[0] != 0x7F && (a5c.is_none() || a53.is_none()) {
            return SW_WRONG_DATA;
        }
        if let (Some(c), Some(v)) = (a5c, a53) {
            if c.len() != 3 || c[0] != 0x5F || c[1] != 0xC1 {
                return SW_WRONG_DATA;
            }
            let fid = (c[1] as u16) << 8 | c[2] as u16;
            if !known_object_fid(fid) {
                // C: file_search_by_fid returns NULL → SW_MEMORY_FAILURE.
                return SW_MEMORY_FAILURE;
            }
            if v.len() > MAX_OBJECT_SIZE {
                return SW_WRONG_LENGTH;
            }
            if v.is_empty() {
                self.st.objects.remove(&fid);
            } else {
                self.st.objects.insert(fid, v.to_vec());
            }
            self.persist();
        }
        SW_OK
    }
}

/// The 0xC1xx PIV file table (C `files.h`) — object ids PUT DATA accepts.
fn known_object_fid(fid: u16) -> bool {
    matches!(
        fid,
        0xC101 | 0xC102 | 0xC103 | 0xC105 | 0xC106 | 0xC107 | 0xC108 | 0xC109
            | 0xC10A | 0xC10B | 0xC10C
            | 0xC10D..=0xC11E
            | 0xC121 | 0xC122 | 0xC123
    )
}

fn parse_data(apdu: &[u8]) -> Vec<u8> {
    // Raw APDU: [CLA, INS, P1, P2, Lc?, data...]. Accepts the short form and
    // the harness extended `00 Hi Lo` Lc encoding (cf. mgmt's parse_data).
    if apdu.len() >= 7 && apdu[4] == 0x00 {
        let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
        return apdu.get(7..7 + lc).unwrap_or(&[]).to_vec();
    }
    if apdu.len() < 5 {
        return Vec::new();
    }
    let lc = apdu[4] as usize;
    apdu.get(5..5 + lc).unwrap_or(&[]).to_vec()
}

fn push_slice(resp: &mut HeaplessVec<u8, MAX_RESPONSE>, bytes: &[u8]) {
    for b in bytes {
        resp.push(*b).ok();
    }
}

/// C `tlv_format_len`: <128 one byte, <256 `81 xx`, else `82 hi lo`.
fn push_tlv_len(resp: &mut HeaplessVec<u8, MAX_RESPONSE>, len: usize) {
    if len < 128 {
        resp.push(len as u8).ok();
    } else if len < 256 {
        resp.push(0x81).ok();
        resp.push(len as u8).ok();
    } else {
        resp.push(0x82).ok();
        resp.push((len >> 8) as u8).ok();
        resp.push(len as u8).ok();
    }
}

fn write_sw(resp: &mut HeaplessVec<u8, MAX_RESPONSE>, sw: Sw) {
    for b in sw.to_be_bytes() {
        resp.push(b).ok();
    }
}

// ---------------------------------------------------------------------
// TLV walking (flat, C `tlv_walk` semantics) — auth templates + PUT DATA.
// ---------------------------------------------------------------------

/// C `tlv_walk`: 1-byte tags, lengths in the short form or the `81 xx` /
/// `82 hi lo` long forms; a tag at the end of the buffer with no length
/// byte is a zero-length marker (C OATH quirk); an overlong value stops
/// the walk.
fn tlv_iter(buf: &[u8]) -> impl Iterator<Item = (u8, &[u8])> + '_ {
    let mut p = 0;
    std::iter::from_fn(move || {
        if p >= buf.len() {
            return None;
        }
        let tag = buf[p];
        p += 1;
        let len = if p >= buf.len() {
            0
        } else {
            let l = buf[p];
            p += 1;
            match l {
                0x81 if p < buf.len() => {
                    let v = buf[p] as usize;
                    p += 1;
                    v
                }
                0x82 if buf.len() - p >= 2 => {
                    let v = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
                    p += 2;
                    v
                }
                _ => l as usize,
            }
        };
        if len > buf.len() - p {
            return None;
        }
        let value = &buf[p..p + len];
        p += len;
        Some((tag, value))
    })
}

fn find_tag(buf: &[u8], tag: u8) -> Option<&[u8]> {
    tlv_iter(buf).find(|(t, _)| *t == tag).map(|(_, v)| v)
}

/// C `piv_first_auth_operation`: first 0x80/0x81/0x82/0x85 TLV in the
/// template, skipping an empty 0x82 (the legacy empty response tag that
/// ykpiv prepends to signing APDUs).
fn first_auth_operation(buf: &[u8]) -> Option<(u8, &[u8])> {
    for (tag, value) in tlv_iter(buf) {
        if tag == 0x82 && value.is_empty() {
            continue;
        }
        if matches!(tag, 0x80 | 0x81 | 0x82 | 0x85) {
            return Some((tag, value));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use fapico2_platform::dispatch::App;

    /// Drive one APDU through the app and return (response_bytes, sw).
    fn drive(app: &mut PivApp, apdu: &[u8]) -> (Vec<u8>, Sw) {
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        app.process(apdu, &mut resp);
        let bytes: Vec<u8> = resp.as_slice().to_vec();
        let sw = u16::from_be_bytes([bytes[bytes.len() - 2], bytes[bytes.len() - 1]]);
        (bytes[..bytes.len() - 2].to_vec(), sw)
    }

    fn select_apdu(app: &mut PivApp) -> (Vec<u8>, Sw) {
        let mut resp = HeaplessVec::<u8, MAX_RESPONSE>::new();
        let mut sel = vec![0x00, INS_SELECT, 0x04, 0x00, PIV_AID.len() as u8];
        sel.extend_from_slice(PIV_AID);
        let sw = app.select_apdu(false, &sel, &mut resp);
        (resp.as_slice().to_vec(), sw)
    }

    // ---------------- US-371: skeleton ----------------

    /// SELECT via the dispatcher path (P1=04 P2=00) emits the FCI blob with
    /// 9000 — the ykpiv `_ykpiv_ensure_application_selected` shape.
    #[test]
    fn select_apdu_returns_fci() {
        let mut app = PivApp::new();
        let (data, sw) = select_apdu(&mut app);
        assert_eq!(sw, SW_OK);
        assert_eq!(data.len(), 44);
        // First TLV: 0x4F (application) wrapping the 0x79 PIV AID DO.
        assert_eq!(&data[0..4], &[0x4F, 0x02, 0x01, 0x00]);
        assert_eq!(&data[4..6], &[0x79, 0x09]);
        assert_eq!(&data[6..11], PIV_AID);
        // 0x50 application label, length = strlen("Pico Keys PIV") = 13 (0x0D).
        assert!(data.windows(2).any(|w| w == [0x50, 0x0D]));
        assert!(data
            .windows(15)
            .any(|w| w.starts_with(&[0x50, 0x0D]) && &w[2..] == b"Pico Keys PIV"));
        // 0xAC (proprietary) wrapping the algorithm capabilities DO.
        assert!(data.windows(14).any(|w| w.starts_with(&[0xAC, 0x0C, 0x80, 0x07])));
    }

    /// GET VERSION (0xFD) → "5.7.0" bytes (C `version.h` PIV_VERSION 0x0507).
    #[test]
    fn get_version_returns_5_7_0() {
        let mut app = PivApp::new();
        let (data, sw) = drive(&mut app, &[0x00, INS_VERSION, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        assert_eq!(data, [PIV_VERSION_MAJOR, PIV_VERSION_MINOR, 0x00]);
        assert_eq!(data, [5, 7, 0]);
    }

    /// GET SERIAL (0xF8) → 4-byte big-endian dev serial (C `cmd_get_serial`).
    #[test]
    fn get_serial_returns_dev_serial() {
        let mut app = PivApp::new();
        let (data, sw) = drive(&mut app, &[0x00, INS_YK_SERIAL, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        assert_eq!(data, SERIAL.to_be_bytes());
        assert_eq!(data, [0x31, 0x32, 0x33, 0x34]);
    }

    /// The C `00 A4 04 01` select variant (P2=01 + AID data) re-emits the FCI.
    #[test]
    fn select_p2_1_with_aid_returns_fci() {
        let mut app = PivApp::new();
        let mut apdu = vec![0x00, INS_SELECT, 0x04, 0x01, PIV_AID.len() as u8];
        apdu.extend_from_slice(PIV_AID);
        let (data, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, SW_OK);
        assert_eq!(data.len(), 44);
        assert_eq!(&data[6..11], PIV_AID);
    }

    /// `00 A4 04 01` with the wrong P2 is rejected (C `SW_WRONG_P1P2` 6B00).
    #[test]
    fn select_wrong_p2_rejected() {
        let mut app = PivApp::new();
        let mut apdu = vec![0x00, INS_SELECT, 0x04, 0x02, PIV_AID.len() as u8];
        apdu.extend_from_slice(PIV_AID);
        let (_, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, SW_WRONG_P1P2);
    }

    /// Unknown INS → 6D00 (C default case in `piv_process_apdu`).
    #[test]
    fn unknown_ins_rejected() {
        let mut app = PivApp::new();
        let (_, sw) = drive(&mut app, &[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_INS_NOT_SUPPORTED);
    }

    // ---------------- US-372: authentication ----------------

    /// 8-byte PIV wire encoding (ASCII, 0xFF-padded) — C `PIV_PIN_WIRE_SIZE`.
    fn wire(pin: &str) -> [u8; 8] {
        let mut w = [0xFFu8; 8];
        let b = pin.as_bytes();
        let n = b.len().min(8);
        w[..n].copy_from_slice(&b[..n]);
        w
    }

    fn verify_pin(app: &mut PivApp, pin: &str) -> Sw {
        let w = wire(pin);
        drive(app, &[0x00, INS_VERIFY, 0x00, 0x80, 8, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]).1
    }

    fn verify_query(app: &mut PivApp) -> Sw {
        drive(app, &[0x00, INS_VERIFY, 0x00, 0x80]).1
    }

    /// Complete a single-challenge mgm authentication with `key` (AES-192,
    /// the default); returns the SW of the response APDU.
    fn mgm_single_auth(app: &mut PivApp, key: &[u8; 24]) -> Sw {
        let (data, sw) = drive(app, &[0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 4, 0x7C, 0x02, 0x81, 0x00]);
        assert_eq!(sw, SW_OK, "challenge issue must succeed");
        assert_eq!(&data[0..4], &[0x7C, 0x12, 0x81, 0x10], "challenge TLV shape");
        let enc = crate::crypto::mgm_crypt(PIV_ALGO_AES192, key, &data[4..20], true).unwrap();
        let mut apdu = vec![0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 20, 0x7C, 0x12, 0x82, 0x10];
        apdu.extend_from_slice(&enc);
        drive(app, &apdu).1
    }

    #[test]
    fn verify_pin_default_ok() {
        let mut app = PivApp::new();
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
    }

    #[test]
    fn verify_query_reports_retries() {
        let mut app = PivApp::new();
        // Fresh state: 3 attempts remaining (yk piv `status` "PIN tries left").
        assert_eq!(verify_query(&mut app), 0x63C3);
    }

    #[test]
    fn verify_pin_wrong_decrements_then_resets() {
        let mut app = PivApp::new();
        assert_eq!(verify_pin(&mut app, "000000"), 0x63C2);
        assert_eq!(verify_query(&mut app), 0x63C2);
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
        // Success resets the counter (C `pin_reset_retries` on match).
        assert_eq!(verify_query(&mut app), SW_OK); // still authenticated
        let (_, sw) = drive(&mut app, &[0x00, INS_VERIFY, 0xFF, 0x80]); // logout
        assert_eq!(sw, SW_OK);
        assert_eq!(verify_query(&mut app), 0x63C3);
    }

    #[test]
    fn verify_pin_correct_on_last_attempt_succeeds() {
        let mut app = PivApp::new();
        assert_eq!(verify_pin(&mut app, "000000"), 0x63C2);
        assert_eq!(verify_pin(&mut app, "000000"), 0x63C1);
        // C spends the last retry, then the match resets the counter —
        // a correct PIN on the final attempt succeeds.
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
        assert_eq!(verify_query(&mut app), SW_OK);
    }

    #[test]
    fn verify_pin_third_wrong_blocks() {
        let mut app = PivApp::new();
        assert_eq!(verify_pin(&mut app, "000000"), 0x63C2);
        assert_eq!(verify_pin(&mut app, "000000"), 0x63C1);
        // Third wrong attempt spends the last retry → blocked.
        assert_eq!(verify_pin(&mut app, "000000"), SW_PIN_BLOCKED);
        // While blocked, even the CORRECT pin is rejected (C
        // `pin_spend_retry` returns BLOCKED before the compare).
        assert_eq!(verify_pin(&mut app, "123456"), SW_PIN_BLOCKED);
        assert_eq!(verify_query(&mut app), SW_PIN_BLOCKED);
    }

    #[test]
    fn verify_pin_logout() {
        let mut app = PivApp::new();
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
        let w = wire("123456");
        // Logout with data is rejected.
        let (_, sw) = drive(&mut app, &[0x00, INS_VERIFY, 0xFF, 0x80, 8, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]);
        assert_eq!(sw, SW_INCORRECT_PARAMS);
        let (_, sw) = drive(&mut app, &[0x00, INS_VERIFY, 0xFF, 0x80]);
        assert_eq!(sw, SW_OK);
        assert_eq!(verify_query(&mut app), 0x63C3);
    }

    #[test]
    fn verify_pin_rejects_bad_p1_p2_and_length() {
        let mut app = PivApp::new();
        let w = wire("123456");
        // P2 must be 0x80 (C returns SW_INCORRECT_PARAMS 6A80).
        let (_, sw) = drive(&mut app, &[0x00, INS_VERIFY, 0x00, 0x81]);
        assert_eq!(sw, SW_INCORRECT_PARAMS);
        let (_, sw) = drive(&mut app, &[0x00, INS_VERIFY, 0x01, 0x80]);
        assert_eq!(sw, SW_INCORRECT_PARAMS);
        // Wire size must be exactly 8.
        let apdu = vec![0x00, INS_VERIFY, 0x00, 0x80, 6, w[0], w[1], w[2], w[3], w[4], w[5]];
        let (_, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, SW_INCORRECT_PARAMS);
    }

    #[test]
    fn change_pin_roundtrip() {
        let mut app = PivApp::new();
        let mut apdu = vec![0x00, INS_CHANGE_PIN, 0x00, 0x80, 16];
        apdu.extend_from_slice(&wire("123456"));
        apdu.extend_from_slice(&wire("654321"));
        assert_eq!(drive(&mut app, &apdu).1, SW_OK);
        assert_eq!(verify_pin(&mut app, "654321"), SW_OK);
        assert_eq!(verify_pin(&mut app, "123456"), 0x63C2);
    }

    #[test]
    fn change_pin_wrong_old_pin_spends_retry() {
        let mut app = PivApp::new();
        let mut apdu = vec![0x00, INS_CHANGE_PIN, 0x00, 0x80, 16];
        apdu.extend_from_slice(&wire("000000"));
        apdu.extend_from_slice(&wire("654321"));
        assert_eq!(drive(&mut app, &apdu).1, 0x63C2);
        // Old PIN still works (change was rejected).
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
    }

    #[test]
    fn change_puk_roundtrip() {
        let mut app = PivApp::new();
        let mut apdu = vec![0x00, INS_CHANGE_PIN, 0x00, 0x81, 16];
        apdu.extend_from_slice(&wire("12345678"));
        apdu.extend_from_slice(&wire("87654321"));
        assert_eq!(drive(&mut app, &apdu).1, SW_OK);
        // The old PUK no longer verifies.
        let mut apdu = vec![0x00, INS_CHANGE_PIN, 0x00, 0x81, 16];
        apdu.extend_from_slice(&wire("12345678"));
        apdu.extend_from_slice(&wire("99999999"));
        assert_eq!(drive(&mut app, &apdu).1, 0x63C2);
        // Restore with the new PUK.
        let mut apdu = vec![0x00, INS_CHANGE_PIN, 0x00, 0x81, 16];
        apdu.extend_from_slice(&wire("87654321"));
        apdu.extend_from_slice(&wire("12345678"));
        assert_eq!(drive(&mut app, &apdu).1, SW_OK);
    }

    #[test]
    fn unblock_pin_after_block() {
        let mut app = PivApp::new();
        for _ in 0..3 {
            verify_pin(&mut app, "000000");
        }
        assert_eq!(verify_query(&mut app), SW_PIN_BLOCKED);
        // PUK + new PIN unblocks and re-keys the PIN (C `cmd_piv_reset_retry`).
        let mut apdu = vec![0x00, INS_RESET_RETRY, 0x00, 0x80, 16];
        apdu.extend_from_slice(&wire("12345678"));
        apdu.extend_from_slice(&wire("135790"));
        assert_eq!(drive(&mut app, &apdu).1, SW_OK);
        assert_eq!(verify_pin(&mut app, "135790"), SW_OK);
        assert_eq!(verify_query(&mut app), SW_OK);
        // PIN counter was reset to the total.
        let (_, sw) = drive(&mut app, &[0x00, INS_VERIFY, 0xFF, 0x80]);
        assert_eq!(sw, SW_OK);
        assert_eq!(verify_query(&mut app), 0x63C3);
    }

    #[test]
    fn unblock_pin_wrong_puk() {
        let mut app = PivApp::new();
        let mut apdu = vec![0x00, INS_RESET_RETRY, 0x00, 0x80, 16];
        apdu.extend_from_slice(&wire("00000000"));
        apdu.extend_from_slice(&wire("135790"));
        assert_eq!(drive(&mut app, &apdu).1, 0x63C2); // PUK retry spent
        // PIN untouched.
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
    }

    #[test]
    fn mgm_single_auth_default_key() {
        let mut app = PivApp::new();
        assert_eq!(mgm_single_auth(&mut app, &DEFAULT_MGM_KEY), SW_OK);
    }

    #[test]
    fn mgm_single_auth_wrong_key() {
        let mut app = PivApp::new();
        assert_eq!(mgm_single_auth(&mut app, &[0u8; 24]), SW_DATA_INVALID);
    }

    #[test]
    fn mgm_mutual_roundtrip() {
        let mut app = PivApp::new();
        // Issue mutual challenge: `7C 02 80 00`.
        let (data, sw) = drive(&mut app, &[0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 4, 0x7C, 0x02, 0x80, 0x00]);
        assert_eq!(sw, SW_OK);
        assert_eq!(&data[0..4], &[0x7C, 0x12, 0x80, 0x10], "mutual challenge TLV");
        let chal = crate::crypto::mgm_crypt(PIV_ALGO_AES192, &DEFAULT_MGM_KEY, &data[4..20], false).unwrap();
        // Complete: witness + host random. 7C wraps 18+18 = 36 (0x24) bytes,
        // so Lc = 2 + 36 = 38.
        let host_random = [0x42u8; 16];
        let mut apdu = vec![0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 38, 0x7C, 0x24, 0x80, 0x10];
        apdu.extend_from_slice(&chal);
        apdu.extend_from_slice(&[0x81, 0x10]);
        apdu.extend_from_slice(&host_random);
        let (data, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, SW_OK);
        // Card answers with the encrypted host random: 7C 12 82 10 <16>.
        let enc = crate::crypto::mgm_crypt(PIV_ALGO_AES192, &DEFAULT_MGM_KEY, &host_random, true).unwrap();
        assert_eq!(&data[0..4], &[0x7C, 0x12, 0x82, 0x10]);
        assert_eq!(&data[4..], &enc[..]);
    }

    #[test]
    fn mgm_mutual_wrong_witness() {
        let mut app = PivApp::new();
        let (_, sw) = drive(&mut app, &[0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 4, 0x7C, 0x02, 0x80, 0x00]);
        assert_eq!(sw, SW_OK);
        // Wrong witness (garbage) + host random. Same TLV shape as the
        // roundtrip: 7C 24 wrapping 18+18, Lc 38.
        let mut apdu = vec![0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 38, 0x7C, 0x24, 0x80, 0x10];
        apdu.extend_from_slice(&[0xA5u8; 16]);
        apdu.extend_from_slice(&[0x81, 0x10]);
        apdu.extend_from_slice(&[0x42u8; 16]);
        let (_, sw) = drive(&mut app, &apdu);
        assert_eq!(sw, SW_DATA_INVALID);
    }

    #[test]
    fn mgm_algo_mismatch_rejected() {
        let mut app = PivApp::new();
        // Stored meta algo is AES-192 (0x0A); AES-128 (0x08) must be rejected
        // when no challenge is pending (C `meta[0] != algo`).
        let (_, sw) = drive(&mut app, &[0x00, INS_AUTHENTICATE, PIV_ALGO_AES128, 0x9B, 4, 0x7C, 0x02, 0x81, 0x00]);
        assert_eq!(sw, SW_INCORRECT_PARAMS);
    }

    #[test]
    fn mgm_auth_requires_7c_template() {
        let mut app = PivApp::new();
        let (_, sw) = drive(&mut app, &[0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 0x00]);
        assert_eq!(sw, SW_INCORRECT_PARAMS);
        let (_, sw) = drive(&mut app, &[0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 4, 0x7D, 0x02, 0x81, 0x00]);
        assert_eq!(sw, SW_INCORRECT_PARAMS);
    }

    #[test]
    fn set_mgmkey_roundtrip() {
        let mut app = PivApp::new();
        assert_eq!(mgm_single_auth(&mut app, &DEFAULT_MGM_KEY), SW_OK);
        let new_key = [0xABu8; 24];
        // P1 = 0xFF (C), P2 = touch, data = [algo, 0x9b, keylen, key...].
        let mut apdu = vec![0x00, INS_SET_MGMKEY, 0xFF, 0xFE, 27, PIV_ALGO_AES192, 0x9B, 24];
        apdu.extend_from_slice(&new_key);
        assert_eq!(drive(&mut app, &apdu).1, SW_OK);
        assert_eq!(mgm_single_auth(&mut app, &new_key), SW_OK);
        // The old key no longer works.
        assert_eq!(mgm_single_auth(&mut app, &DEFAULT_MGM_KEY), SW_DATA_INVALID);
    }

    #[test]
    fn set_mgmkey_requires_mgm_auth() {
        let mut app = PivApp::new();
        // Well-formed APDU (P1=0xFF, valid key) but no mgm session.
        let mut apdu = vec![0x00, INS_SET_MGMKEY, 0xFF, 0xFE, 27, PIV_ALGO_AES192, 0x9B, 24];
        apdu.extend_from_slice(&[0u8; 24]);
        assert_eq!(drive(&mut app, &apdu).1, SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn set_mgmkey_rejects_bad_params() {
        let mut app = PivApp::new();
        assert_eq!(mgm_single_auth(&mut app, &DEFAULT_MGM_KEY), SW_OK);
        // P1 must be 0xFF.
        let mut apdu = vec![0x00, INS_SET_MGMKEY, 0x00, 0xFE, 27, PIV_ALGO_AES192, 0x9B, 24];
        apdu.extend_from_slice(&[0u8; 24]);
        assert_eq!(drive(&mut app, &apdu).1, SW_WRONG_P1P2);
        // P2 must be 0xFF or 0xFE.
        let mut apdu = vec![0x00, INS_SET_MGMKEY, 0xFF, 0x00, 27, PIV_ALGO_AES192, 0x9B, 24];
        apdu.extend_from_slice(&[0u8; 24]);
        assert_eq!(drive(&mut app, &apdu).1, SW_WRONG_P1P2);
        // Key length must match the algorithm (AES-192 needs 24).
        let mut apdu = vec![0x00, INS_SET_MGMKEY, 0xFF, 0xFE, 27, PIV_ALGO_AES192, 0x9B, 16];
        apdu.extend_from_slice(&[0u8; 24]);
        assert_eq!(drive(&mut app, &apdu).1, SW_WRONG_DATA);
    }

    #[test]
    fn set_retries_resets_totals_and_defaults() {
        let mut app = PivApp::new();
        assert_eq!(mgm_single_auth(&mut app, &DEFAULT_MGM_KEY), SW_OK);
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
        // SET RETRIES: P1 = PIN total (5), P2 = PUK total (2).
        let (_, sw) = drive(&mut app, &[0x00, INS_SET_RETRIES, 5, 2]);
        assert_eq!(sw, SW_OK);
        // Logout, then the query reports the new total (PIN reset to default).
        let (_, sw) = drive(&mut app, &[0x00, INS_VERIFY, 0xFF, 0x80]);
        assert_eq!(sw, SW_OK);
        assert_eq!(verify_query(&mut app), 0x63C5);
    }

    #[test]
    fn set_retries_requires_pin_and_mgm() {
        let mut app = PivApp::new();
        // No mgm auth.
        assert_eq!(drive(&mut app, &[0x00, INS_SET_RETRIES, 3, 3]).1, SW_SECURITY_STATUS_NOT_SATISFIED);
        // Mgm auth but no PIN.
        assert_eq!(mgm_single_auth(&mut app, &DEFAULT_MGM_KEY), SW_OK);
        assert_eq!(drive(&mut app, &[0x00, INS_SET_RETRIES, 3, 3]).1, SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn reset_requires_both_blocked() {
        let mut app = PivApp::new();
        // Fresh state: neither blocked → 6A80 (C SW_INCORRECT_PARAMS).
        assert_eq!(drive(&mut app, &[0x00, INS_RESET, 0x00, 0x00]).1, SW_INCORRECT_PARAMS);
        assert_eq!(drive(&mut app, &[0x00, INS_RESET, 0x01, 0x00]).1, SW_INCORRECT_P1P2);
    }

    #[test]
    fn reset_factory_after_block() {
        let mut app = PivApp::new();
        // Block the PIN (3 wrong) and the PUK (3 wrong change attempts).
        for _ in 0..3 {
            verify_pin(&mut app, "000000");
        }
        for _ in 0..3 {
            let mut apdu = vec![0x00, INS_CHANGE_PIN, 0x00, 0x81, 16];
            apdu.extend_from_slice(&wire("00000000"));
            apdu.extend_from_slice(&wire("00000000"));
            drive(&mut app, &apdu);
        }
        let (_, sw) = drive(&mut app, &[0x00, INS_RESET, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        // Factory defaults restored.
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
        assert_eq!(mgm_single_auth(&mut app, &DEFAULT_MGM_KEY), SW_OK);
    }

    #[test]
    fn select_resets_session() {
        let mut app = PivApp::new();
        assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
        // Issue a mgm challenge, then SELECT (clears the session per C
        // init_piv / ykpiv "select resets the challenge state").
        let (data, sw) = drive(&mut app, &[0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 4, 0x7C, 0x02, 0x81, 0x00]);
        assert_eq!(sw, SW_OK);
        let (_, sw) = select_apdu(&mut app);
        assert_eq!(sw, SW_OK);
        // PIN session cleared.
        assert_eq!(verify_query(&mut app), 0x63C3);
        // Pending challenge cleared: completing with the old response fails.
        let enc = crate::crypto::mgm_crypt(PIV_ALGO_AES192, &DEFAULT_MGM_KEY, &data[4..20], true).unwrap();
        let mut apdu = vec![0x00, INS_AUTHENTICATE, PIV_ALGO_AES192, 0x9B, 20, 0x7C, 0x12, 0x82, 0x10];
        apdu.extend_from_slice(&enc);
        assert_eq!(drive(&mut app, &apdu).1, SW_DATA_INVALID);
    }

    // ---------------- US-373: data objects (GET/PUT DATA) ----------------

    /// GET DATA object id: `5C 03 5F C1 <fid>` (C `cmd_piv_get_data`).
    fn object_id(fid: u8) -> Vec<u8> {
        vec![0x5C, 0x03, 0x5F, 0xC1, fid]
    }

    /// TLV length form (C `tlv_format_len`): <128 short, <256 `81 xx`,
    /// else `82 hi lo`.
    fn tlv_len_form(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, len as u8]
        }
    }

    /// PUT DATA body, yubikit's flat form: `5C 03 5F C1 <fid> 53 <len> <data>`.
    fn put_body(fid: u8, data: &[u8]) -> Vec<u8> {
        let mut body = vec![0x5C, 0x03, 0x5F, 0xC1, fid, 0x53];
        body.extend(tlv_len_form(data.len()));
        body.extend_from_slice(data);
        body
    }

    fn get_object(app: &mut PivApp, fid: u8) -> (Vec<u8>, Sw) {
        let body = object_id(fid);
        let mut apdu = vec![0x00, INS_GET_DATA, 0x3F, 0xFF, body.len() as u8];
        apdu.extend_from_slice(&body);
        drive(app, &apdu)
    }

    fn put_object(app: &mut PivApp, fid: u8, data: &[u8]) -> Sw {
        let body = put_body(fid, data);
        // Extended Lc form for bodies over 255, as on the wire (yubikit).
        let mut apdu = vec![0x00, INS_PUT_DATA, 0x3F, 0xFF];
        if body.len() > 255 {
            apdu.push(0x00);
            apdu.extend_from_slice(&(body.len() as u16).to_be_bytes());
        } else {
            apdu.push(body.len() as u8);
        }
        apdu.extend_from_slice(&body);
        drive(app, &apdu).1
    }

    fn mgm_auth(app: &mut PivApp) {
        assert_eq!(mgm_single_auth(app, &DEFAULT_MGM_KEY), SW_OK);
    }

    /// Fresh state has no objects: GET CHUID → 6A82 (C: empty file).
    #[test]
    fn get_object_missing_returns_file_not_found() {
        let mut app = PivApp::new();
        let (data, sw) = get_object(&mut app, 0x02);
        assert_eq!(sw, SW_FILE_NOT_FOUND);
        assert!(data.is_empty());
    }

    /// PUT (mgm) then GET: the card answers `53 <len> <data>` with 9000.
    #[test]
    fn put_get_object_roundtrip() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        let value = [0x30, 0x03, b'P', b'I', b'V'];
        assert_eq!(put_object(&mut app, 0x02, &value), SW_OK);
        let (data, sw) = get_object(&mut app, 0x02);
        assert_eq!(sw, SW_OK);
        assert_eq!(data, vec![0x53, 0x05, 0x30, 0x03, b'P', b'I', b'V']);
    }

    /// C checks has_mgm before parsing the body.
    #[test]
    fn put_object_requires_mgm() {
        let mut app = PivApp::new();
        assert_eq!(put_object(&mut app, 0x02, b"test"), SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn put_get_reject_bad_p1_p2() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        let body = put_body(0x02, b"test");
        let mut apdu = vec![0x00, INS_PUT_DATA, 0x00, 0xFF, body.len() as u8];
        apdu.extend_from_slice(&body);
        assert_eq!(drive(&mut app, &apdu).1, SW_INCORRECT_P1P2);
        let (data, sw) = drive(&mut app, &[0x00, INS_GET_DATA, 0x00, 0xFF, 5, 0x5C, 0x03, 0x5F, 0xC1, 0x02]);
        assert_eq!(sw, SW_INCORRECT_P1P2);
        assert!(data.is_empty());
    }

    /// Body must carry top-level 5C + 53 (or start with 7E/7F).
    #[test]
    fn put_object_bad_prefix_rejected() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        // 54 prefix, no 5C/53 → 6700 (C SW_WRONG_DATA).
        let mut apdu = vec![0x00, INS_PUT_DATA, 0x3F, 0xFF, 6];
        apdu.extend_from_slice(&[0x54, 0x04, 0x5F, 0xC1, 0x02, 0x00]);
        assert_eq!(drive(&mut app, &apdu).1, SW_WRONG_DATA);
        // Empty body → 6700 (C SW_WRONG_LENGTH).
        assert_eq!(drive(&mut app, &[0x00, INS_PUT_DATA, 0x3F, 0xFF, 0x00]).1, SW_WRONG_LENGTH);
    }

    /// 0xC104 has no file in the C table → 6581 (C SW_MEMORY_FAILURE).
    #[test]
    fn put_object_unknown_fid_rejected() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        assert_eq!(put_object(&mut app, 0x04, b"test"), SW_MEMORY_FAILURE);
    }

    /// Empty 53 clears the object (C `flash_clear_file`).
    #[test]
    fn put_object_empty_clears() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        assert_eq!(put_object(&mut app, 0x03, b"ccc"), SW_OK);
        assert_eq!(put_object(&mut app, 0x03, b""), SW_OK);
        let (_, sw) = get_object(&mut app, 0x03);
        assert_eq!(sw, SW_FILE_NOT_FOUND);
    }

    /// 53 payload over 2048 (C OPENPGP_MAX_OBJECT_SIZE) → 6700.
    #[test]
    fn put_object_oversized_rejected() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        let big = [0x5Au8; MAX_OBJECT_SIZE + 1];
        assert_eq!(put_object(&mut app, 0x02, &big), SW_WRONG_LENGTH);
        assert_eq!(put_object(&mut app, 0x02, &[0x5Au8; MAX_OBJECT_SIZE]), SW_OK);
        let (data, sw) = get_object(&mut app, 0x02);
        assert_eq!(sw, SW_OK);
        // 2048 → 82 08 00 long-form length.
        assert_eq!(&data[0..4], &[0x53, 0x82, 0x08, 0x00]);
        assert_eq!(data.len(), 4 + MAX_OBJECT_SIZE);
    }

    /// 128..255 → `81 xx` length form (C `tlv_format_len`).
    #[test]
    fn get_object_mid_length_form() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        let value = [0x5Au8; 200];
        assert_eq!(put_object(&mut app, 0x02, &value), SW_OK);
        let (data, sw) = get_object(&mut app, 0x02);
        assert_eq!(sw, SW_OK);
        assert_eq!(&data[0..3], &[0x53, 0x81, 200]);
        assert_eq!(data.len(), 3 + 200);
    }

    /// Every certificate slot object the C file table serves (9A/9C/9D/9E,
    /// retired 1, CCC).
    #[test]
    fn put_get_all_cert_slots() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        for fid in [0x01u8, 0x03, 0x05, 0x0A, 0x0B, 0x0D] {
            let value = [fid; 8];
            assert_eq!(put_object(&mut app, fid, &value), SW_OK);
            let (data, sw) = get_object(&mut app, fid);
            assert_eq!(sw, SW_OK, "slot {fid:02X}");
            assert_eq!(data, vec![0x53, 0x08, value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7]]);
        }
    }

    /// GET DATA shape checks (C order: P1P2, length, 5C form, nc match).
    #[test]
    fn get_object_rejects_malformed_ids() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        assert_eq!(put_object(&mut app, 0x02, b"abc"), SW_OK);
        // nc != inner len + 2.
        assert_eq!(drive(&mut app, &[0x00, INS_GET_DATA, 0x3F, 0xFF, 4, 0x5C, 0x03, 0x5F, 0xC1]).1, SW_WRONG_LENGTH);
        // Wrong outer tag.
        assert_eq!(drive(&mut app, &[0x00, INS_GET_DATA, 0x3F, 0xFF, 5, 0x5D, 0x03, 0x5F, 0xC1, 0x02]).1, SW_WRONG_DATA);
        // 2-byte id (5C 02 ...) is outside the 5F C1 xx space → 6A82.
        assert_eq!(drive(&mut app, &[0x00, INS_GET_DATA, 0x3F, 0xFF, 4, 0x5C, 0x02, 0x5F, 0xC1]).1, SW_FILE_NOT_FOUND);
        // Inner len with the high bit set → 6700.
        assert_eq!(drive(&mut app, &[0x00, INS_GET_DATA, 0x3F, 0xFF, 5, 0x5C, 0x83, 0x5F, 0xC1, 0x02]).1, SW_WRONG_DATA);
        // Too short.
        assert_eq!(drive(&mut app, &[0x00, INS_GET_DATA, 0x3F, 0xFF, 2, 0x5C, 0x03]).1, SW_WRONG_LENGTH);
        // Stored object still intact.
        let (_, sw) = get_object(&mut app, 0x02);
        assert_eq!(sw, SW_OK);
    }

    /// US-373 "in keystore": objects + US-372 auth state survive a reload of
    /// the host secure-store snapshot.
    #[test]
    fn piv_keystore_persists_objects_and_pin() {
        #[cfg(not(target_arch = "arm"))]
        {
            let dir = std::env::temp_dir().join(format!("fapico2_piv_ks_{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("piv_keystore.cbor");
            let _ = std::fs::remove_file(&path);

            {
                let mut app = PivApp::with_keystore(path.clone()).unwrap();
                assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
                assert_eq!(verify_pin(&mut app, "000000"), 0x63C2); // spend a retry
                mgm_auth(&mut app);
                assert_eq!(put_object(&mut app, 0x02, b"persistent"), SW_OK);
            } // dropped → snapshot on disk

            let mut app = PivApp::with_keystore(path.clone()).unwrap();
            // Object persisted ("persistent" = 10 bytes → 53 0A).
            let (data, sw) = get_object(&mut app, 0x02);
            assert_eq!(sw, SW_OK);
            assert_eq!(
                data,
                vec![0x53, 0x0A, b'p', b'e', b'r', b's', b'i', b's', b't', b'e', b'n', b't']
            );
            // PIN retry counter persisted (1 spent before reload).
            assert_eq!(verify_query(&mut app), 0x63C2);
            assert_eq!(verify_pin(&mut app, "123456"), SW_OK);
            // mgm session did NOT persist (session state).
            assert_eq!(
                drive(&mut app, &[0x00, INS_SET_RETRIES, 3, 3]).1,
                SW_SECURITY_STATUS_NOT_SATISFIED
            );
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(&dir);
        }
    }

    #[test]
    fn slot_key_auth_is_not_yet_supported() {
        // 0x87 to a key slot (9a) lands with US-374/375; until then the
        // function is unsupported (C has it fully implemented).
        let mut app = PivApp::new();
        let apdu = vec![0x00, INS_AUTHENTICATE, PIV_ALGO_ECCP256, 0x9A, 8, 0x7C, 0x06, 0x81, 0x04, 0, 1, 2, 3];
        assert_eq!(drive(&mut app, &apdu).1, SW_FUNC_NOT_SUPPORTED);
    }

    // ---------------- US-181 (PICOForge-COMPAT): command chaining ----------------

    /// `PUT DATA` sent the way PicoForge's `send_chained` sends it
    /// (`picoforge/src/hal/transport/ccid.rs:115-144`): 255-byte `cla|0x10`
    /// fragments, each of which the client requires `9000` from
    /// (`:129-131`), then the remainder as an ordinary APDU.
    fn put_object_chained(app: &mut PivApp, fid: u8, data: &[u8]) -> Vec<Sw> {
        let body = put_body(fid, data);
        let mut sws = Vec::new();
        let mut i = 0;
        while body.len() - i > 255 {
            let mut apdu = vec![0x10, INS_PUT_DATA, 0x3F, 0xFF, 255];
            apdu.extend_from_slice(&body[i..i + 255]);
            sws.push(drive(app, &apdu).1);
            i += 255;
        }
        // The tail may itself exceed 255 bytes, and then the client sends it
        // with an **extended Lc** (`00 hi lo`) — `Apdu` picks the encoding by
        // length and `send_chained` hands the tail straight to
        // `transceive_full` (`picoforge/src/hal/transport/ccid.rs:135-142`).
        // The trap: the `while` loop peels 255 bytes at a time, so a body of
        // 809 goes out as 255 / 255 / 299, and a helper that always writes a
        // one-byte Lc would truncate that last 299 to 10.
        let rest = &body[i..];
        let mut tail = vec![0x00, INS_PUT_DATA, 0x3F, 0xFF];
        if rest.len() > 255 {
            tail.push(0x00);
            tail.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        } else {
            tail.push(rest.len() as u8);
        }
        tail.extend_from_slice(rest);
        sws.push(drive(app, &tail).1);
        sws
    }

    /// A 512-byte object over the wire in three APDUs writes and reads back
    /// byte-for-byte. Without the chain hook every fragment reached
    /// `cmd_put_data` as an ordinary APDU and was refused `6A80`
    /// (`tlv_iter` bounds-checks the `53` length against the 255 bytes it
    /// actually has), so this is the test that the PIV half of US-181 works.
    #[test]
    fn put_object_chained_roundtrips_a_large_object() {
        // Two sizes on purpose. 512 makes the body 521 bytes → 255 / 255 / 11,
        // so the tail fits a one-byte Lc. 800 makes it 809 → 255 / 255 / 299,
        // so the tail needs an **extended Lc**, which is the shape PicoForge
        // actually sends and the one a naive fragment loop gets wrong.
        for len in [512usize, 800] {
            let mut app = PivApp::new();
            mgm_auth(&mut app);
            let data: Vec<u8> = (0..len as u32).map(|i| (i % 251) as u8).collect();
            let sws = put_object_chained(&mut app, 0x02, &data);
            assert!(
                sws.iter().all(|s| *s == SW_OK),
                "len {len}: every fragment must answer 9000 or the client \
                 abandons the write, got {:?}",
                sws.iter().map(|s| format!("{s:04X}")).collect::<Vec<_>>()
            );
            let (got, sw) = get_object(&mut app, 0x02);
            assert_eq!(sw, SW_OK, "len {len}");
            assert_eq!(
                got,
                [vec![0x53], tlv_len_form(len), data].concat(),
                "len {len}: the object did not round-trip"
            );
        }
    }

    /// The chained form and the single extended-Lc form must be
    /// indistinguishable. This is the compatibility claim in full: PicoForge
    /// picks the form by length, so a card that answers them differently
    /// would break one client or the other.
    #[test]
    fn a_chained_put_data_matches_the_single_extended_lc_form() {
        let data: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let mut chained = PivApp::new();
        mgm_auth(&mut chained);
        assert!(put_object_chained(&mut chained, 0x02, &data).iter().all(|s| *s == SW_OK));

        let mut single = PivApp::new();
        mgm_auth(&mut single);
        assert_eq!(put_object(&mut single, 0x02, &data), SW_OK);

        assert_eq!(get_object(&mut chained, 0x02), get_object(&mut single, 0x02));
    }

    /// An abandoned chain must not reach the next *different* command. The
    /// fragment goes in, then a `GET DATA`: which must see its own (absent)
    /// object, not the abandoned fragment's bytes prepended to a body it never
    /// had.
    ///
    /// "Different" is load-bearing, and it is not an implementation choice.
    /// ISO 7816-4 terminates a chain with the first command whose CLA b4 is
    /// clear, and gives no way to say "this one is not really the terminator".
    /// A PUT DATA with the *same* INS/P1/P2 after an abandoned chain is
    /// therefore the terminator by the standard's own definition — see
    /// `an_abandoned_chain_followed_by_the_same_command_is_refused_not_stored`
    /// for what happens then.
    #[test]
    fn an_abandoned_chain_does_not_contaminate_a_different_command() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        let big: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let body = put_body(0x02, &big);
        let mut frag = vec![0x10, INS_PUT_DATA, 0x3F, 0xFF, 255];
        frag.extend_from_slice(&body[..255]);
        assert_eq!(drive(&mut app, &frag).1, SW_OK, "a fragment still answers 9000");

        // A GET DATA for the object the chain was aimed at: the chain is
        // dropped, so the object was never written.
        assert_eq!(get_object(&mut app, 0x02).1, SW_FILE_NOT_FOUND);
        // And an ordinary write is unaffected by the dropped chain.
        assert_eq!(put_object(&mut app, 0x03, b"clean"), SW_OK);
        assert_eq!(
            get_object(&mut app, 0x03).0,
            vec![0x53, 0x05, b'c', b'l', b'e', b'a', b'n'],
            "the abandoned chain's bytes were merged into this write"
        );
    }

    /// **The ISO limit, and what it costs.** There is no way to tell "the
    /// terminator of the chain I started" from "an unrelated command that
    /// happens to have the same INS/P1/P2", because CLA b4 clear *is* the
    /// definition of a terminator. So a PUT DATA arriving after an abandoned
    /// PUT DATA chain is treated as the terminator and the two bodies are
    /// concatenated.
    ///
    /// What matters is that the merged result is **refused, not stored**: the
    /// `5C` tag resolves but the `53` that follows declares 512 bytes over a
    /// buffer that has ~261, so `tlv_iter` bounds-checks it away and
    /// `cmd_put_data` answers `SW_WRONG_DATA` (6A80 — this applet spells
    /// "wrong data" 6700, `apps/piv/src/lib.rs:60`). Pinned because the
    /// alternative failure — storing the merge — is silent corruption, and
    /// because a reader would otherwise assume the header check can tell the
    /// two cases apart. It cannot, and `platform::apdu_chain` says so at the
    /// point where the decision is made.
    #[test]
    fn an_abandoned_chain_followed_by_the_same_command_is_refused_not_stored() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        let big: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let body = put_body(0x02, &big);
        let mut frag = vec![0x10, INS_PUT_DATA, 0x3F, 0xFF, 255];
        frag.extend_from_slice(&body[..255]);
        assert_eq!(drive(&mut app, &frag).1, SW_OK);

        // Same INS / P1 / P2: the standard calls this the terminator.
        assert_eq!(put_object(&mut app, 0x03, b"clean"), SW_WRONG_DATA);
        // Nothing was written, under either fid.
        assert_eq!(get_object(&mut app, 0x02).1, SW_FILE_NOT_FOUND);
        assert_eq!(get_object(&mut app, 0x03).1, SW_FILE_NOT_FOUND);
    }

    /// A SELECT mid-chain discards it — the rule that closes the gap between
    /// "abandoned" and "resynchronised".
    #[test]
    fn a_select_mid_chain_discards_it() {
        let mut app = PivApp::new();
        mgm_auth(&mut app);
        let big: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let body = put_body(0x02, &big);
        let mut frag = vec![0x10, INS_PUT_DATA, 0x3F, 0xFF, 255];
        frag.extend_from_slice(&body[..255]);
        assert_eq!(drive(&mut app, &frag).1, SW_OK);
        assert_eq!(select_apdu(&mut app).1, SW_OK);
        // The mgm session is gone with the SELECT, and the chain with it: the
        // tail now fails on the session gate, not by being merged.
        let rest = &body[255..];
        let mut tail = vec![0x00, INS_PUT_DATA, 0x3F, 0xFF, 0x00];
        tail[4] = 0x00;
        tail.truncate(5);
        tail.push(0x00);
        tail.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        tail.extend_from_slice(rest);
        assert_eq!(drive(&mut app, &tail).1, SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    /// **The pre-fix failure mode, asserted on the mechanism rather than on a
    /// reverted build.** This is why PIV was a hard break rather than a
    /// corruption: a 255-byte fragment reaches `cmd_put_data`, and
    /// `find_tag(.., 0x53)` returns `None` because `tlv_iter` bounds-checks
    /// the declared length against the bytes actually present
    /// (`apps/piv/src/lib.rs`, `tlv_iter`'s `if len > buf.len() - p { return
    /// None }`), so `cmd_put_data` answers `SW_WRONG_DATA`.
    ///
    /// The trap a reader would otherwise believe: **OpenPGP does not behave
    /// this way.** opcard's `PUT DATA` takes the object from P1/P2
    /// (`Tag::from((command.p1, command.p2))`,
    /// `vendor/opcard/src/types.rs:604`) and stores `ctx.data` verbatim, so a
    /// truncated body there is stored as-is and answered `9000`. The two
    /// applets fail in opposite directions, and the PIV one is the safe one.
    #[test]
    fn a_truncated_piv_body_is_refused_by_the_tlv_walker() {
        let big: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        let body = put_body(0x02, &big);
        // Whole body: both tags resolve.
        assert!(find_tag(&body, 0x5C).is_some());
        assert_eq!(find_tag(&body, 0x53).map(<[u8]>::len), Some(512));
        // First 255-byte fragment: the `5C` is complete, the `53` is not.
        let frag = &body[..255];
        assert!(find_tag(frag, 0x5C).is_some());
        assert!(
            find_tag(frag, 0x53).is_none(),
            "the fragment's 53 declared 512 bytes and carries fewer; a walker \
             that did not bounds-check would hand back a short slice"
        );
    }
}
