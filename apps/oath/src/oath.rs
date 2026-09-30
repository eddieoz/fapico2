//! OATH applet: PUT/DELETE/LIST/CALCULATE/CALC_ALL/VALIDATE/SET_CODE/RENAME
//! plus the OTP PIN lifecycle (SET/VERIFY/CHANGE PIN) and RESET.

use crate::ct::ct_eq;
use fapico2_platform::dispatch::{App, Sw, MAX_RESPONSE};
use fapico2_platform::presence::PresenceService;
use heapless::Vec as HeaplessVec;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

// ISO 7816 status words (mirroring the C firmware's apdu.h).
const SW_OK: Sw = 0x9000;
const SW_WRONG_DATA: Sw = 0x6700;
const SW_SECURITY_STATUS_NOT_SATISFIED: Sw = 0x6982;
const SW_DATA_INVALID: Sw = 0x6984;
const SW_CONDITIONS_NOT_SATISFIED: Sw = 0x6985;
const SW_INCORRECT_PARAMS: Sw = 0x6A80;
#[allow(dead_code)]
const SW_FILE_NOT_FOUND: Sw = 0x6A82;
const SW_INCORRECT_P1P2: Sw = 0x6A86;
const SW_INS_NOT_SUPPORTED: Sw = 0x6D00;

// TLV tags.
const TAG_NAME: u8 = 0x71;
const TAG_NAME_LIST: u8 = 0x72;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_RESPONSE: u8 = 0x75;
#[allow(dead_code)]
const TAG_T_RESPONSE: u8 = 0x76;
const TAG_NO_RESPONSE: u8 = 0x77;
#[allow(dead_code)]
const TAG_PROPERTY: u8 = 0x78;
const TAG_VERSION: u8 = 0x79;
const TAG_IMF: u8 = 0x7A;
const TAG_PASSWORD: u8 = 0x80;
const TAG_NEW_PASSWORD: u8 = 0x81;

// Key algorithm/type masks.
const TYPE_MASK: u8 = 0xF0;
const TYPE_HOTP: u8 = 0x10;
#[allow(dead_code)]
const TYPE_TOTP: u8 = 0x20;
const ALG_MASK: u8 = 0x0F;
const ALG_SHA1: u8 = 0x01;
const ALG_SHA256: u8 = 0x02;
const ALG_SHA512: u8 = 0x03;

// Commands.
const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RESET: u8 = 0x04;
const INS_RENAME: u8 = 0x05;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_VALIDATE: u8 = 0xA3;
const INS_CALC_ALL: u8 = 0xA4;
const INS_VERIFY_CODE: u8 = 0xB1;
const INS_VERIFY_PIN: u8 = 0xB2;
const INS_CHANGE_PIN: u8 = 0xB3;
const INS_SET_PIN: u8 = 0xB4;

/// US-921/US-903: presence command tag for RESET (INS 0x04) — mgmt parity,
/// the command's own INS. The tag binds a pending presence request to
/// exactly the command that declared it (mirror of
/// `oath_core.rs::PRESENCE_TAG_RESET`).
pub const PRESENCE_TAG_RESET: u32 = 0x04;
/// US-905/US-921: presence command tag for SET_CODE with empty data
/// clearing a present access code (INS 0x03) — RESET-parity presence
/// consumer (mirror of `oath_core.rs::PRESENCE_TAG_SET_CODE_CLEAR`).
pub const PRESENCE_TAG_SET_CODE_CLEAR: u32 = 0x03;
// Tie the tags to the INS constants they mirror (const `From` is not
// stable, hence the literals above).
const _: () = assert!(PRESENCE_TAG_RESET as u8 == INS_RESET);
const _: () = assert!(PRESENCE_TAG_SET_CODE_CLEAR as u8 == INS_SET_CODE);

/// OTP PIN retry budget (C: MAX_OTP_COUNTER); each check decrements it and a
/// successful verify rewrites the record, resetting the budget.
const MAX_OTP_COUNTER: u8 = 3;

struct OathCred {
    name: Vec<u8>,
    /// Stored key TLV value: [alg|type, digits, secret...].
    key: Vec<u8>,
    /// HOTP moving factor (8 bytes, big-endian); None for TOTP.
    imf: Option<u64>,
}

/// A parsed TLV (tag, value) from an APDU data field.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn parse_tlvs(data: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= data.len() {
        let tag = data[i];
        let len = data[i + 1] as usize;
        if i + 2 + len > data.len() {
            break;
        }
        out.push(Tlv {
            tag,
            value: &data[i + 2..i + 2 + len],
        });
        i += 2 + len;
    }
    out
}

fn find_tlv<'a>(tlvs: &'a [Tlv<'a>], tag: u8) -> Option<&'a [u8]> {
    tlvs.iter().find(|t| t.tag == tag).map(|t| t.value)
}

fn hmac_digest(alg: u8, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let bits = alg & ALG_MASK;
    let out: Vec<u8> = match bits {
        ALG_SHA1 => {
            let mut mac = HmacSha1::new_from_slice(key).ok()?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        ALG_SHA256 => {
            let mut mac = HmacSha256::new_from_slice(key).ok()?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        ALG_SHA512 => {
            let mut mac = HmacSha512::new_from_slice(key).ok()?;
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        _ => return None,
    };
    Some(out)
}

fn digest_size(alg: u8) -> usize {
    match alg & ALG_MASK {
        ALG_SHA1 => 20,
        ALG_SHA256 => 32,
        ALG_SHA512 => 64,
        _ => 0,
    }
}

/// Legacy verifier domain separator (the pre-US-904 unsalted form).
const PIN_LEGACY_DOMAIN: &[u8] = b"fapico2-otp-pin";

/// US-904 (SEC-HARDEN): the OTP-PIN record — salted, device-bound verifier
/// (mirror of `oath_core.rs::PinRecord`; the host mirror keeps no durable
/// stream, so `legacy` only exists to keep the verification paths identical).
#[derive(Clone, Copy)]
struct PinRecord {
    counter: u8,
    salt: [u8; 16],
    verifier: [u8; 32],
    legacy: bool,
}

/// US-904 salted PIN verifier: `SHA256(salt || pin)`.
fn pin_verifier(pin: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin);
    h.finalize().into()
}

/// The pre-US-904 unsalted form, used only to verify a legacy record.
fn legacy_pin_verifier(pin: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PIN_LEGACY_DOMAIN);
    h.update(pin);
    h.finalize().into()
}

/// US-903 (SEC-HARDEN): build-dependent presence default — a device build
/// without an injected source denies (fail closed); emulation/host
/// auto-acks (mgmt parity).
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

pub struct OathApp {
    /// Storage slots in creation order; deleted slots are None and are
    /// reused by the next PUT (C free-slot bitmap parity).
    creds: Vec<Option<OathCred>>,
    /// OATH access code (validate secret): [alg, secret...].
    /// Residual (US-901 → US-904): the salted OTP-PIN verifier removed the
    /// PIN residual, but the raw access code stays persisted unencrypted —
    /// VALIDATE needs it for the response HMAC — until store encryption
    /// (US-917) lands.
    access_code: Option<Vec<u8>>,
    /// Challenge issued by the last SELECT (validate binds to it).
    challenge: [u8; 8],
    validated: bool,
    /// US-903 (SEC-HARDEN): user-presence source (the board button on
    /// device), injected via [`with_user_presence`]. `None` resolves to the
    /// build default: fail-closed (`false`) under the `device` feature,
    /// auto-ack otherwise (emulation/host).
    presence: Option<fn() -> bool>,
    /// US-921: the whole grant path (pending request + latch binding) when
    /// the runtime owns the shared presence service (device wiring). Takes
    /// precedence over `presence` — the shared runtime IS the grant path.
    presence_grant: Option<fn(u32) -> bool>,
    /// OTP PIN record (US-904): salted verifier — see [`PinRecord`].
    pin: Option<PinRecord>,
}

impl Default for OathApp {
    fn default() -> Self {
        Self::new()
    }
}

impl OathApp {
    /// US-901 (SEC-HARDEN): recompute the session grant — the virgin
    /// auto-validate rule (mirrors `oath_core.rs`). A session is granted only
    /// while the app is completely virgin: no access code, no OTP PIN, no
    /// credentials.
    fn refresh_session_grant(&mut self) {
        self.validated = self.access_code.is_none()
            && self.pin.is_none()
            && self.creds.iter().all(|c| c.is_none());
    }

    pub fn new() -> Self {
        let mut challenge = [0u8; 8];
        fapico2_platform::trng::random_bytes_into(&mut challenge);
        let mut app = Self {
            creds: Vec::new(),
            access_code: None,
            challenge,
            validated: false,
            pin: None,
            presence: None,
            presence_grant: None,
        };
        app.refresh_session_grant();
        app
    }

    /// US-903 (SEC-HARDEN): attach the user-presence source (mirrors
    /// `oath_core.rs` / mgmt). Consulted exactly once per RESET.
    pub fn with_user_presence(mut self, f: fn() -> bool) -> Self {
        self.presence = Some(f);
        self
    }

    /// US-921: attach the shared presence runtime's grant path (device
    /// wiring) — the runtime owns the pending-request slot and the button
    /// latch binding, so destructive commands are granted only by a press
    /// that lands while *this* command's request (its
    /// [`PRESENCE_TAG_RESET`] / [`PRESENCE_TAG_SET_CODE_CLEAR`] tag) is
    /// pending. Takes precedence over `with_user_presence`.
    pub fn with_presence_grant(mut self, g: fn(u32) -> bool) -> Self {
        self.presence_grant = Some(g);
        self
    }

    /// US-904 (SEC-HARDEN): test/diagnostic accessor for the OTP-PIN record
    /// — `(counter, salt, verifier)`. Reveals only salted material; kept
    /// off the [`App`] trait (mirror of `oath_core.rs::otp_pin_record`).
    #[doc(hidden)]
    pub fn otp_pin_record(&self) -> Option<(u8, [u8; 16], [u8; 32])> {
        self.pin.map(|p| (p.counter, p.salt, p.verifier))
    }

    /// US-903/US-905 (SEC-HARDEN): the user-presence grant — consulted by
    /// RESET and by empty-data SET_CODE clearing a present access code
    /// (mirrors `oath_core.rs` / mgmt).
    ///
    /// US-921 device wiring (mgmt parity): with `with_presence_grant`
    /// attached, the whole grant path IS the shared presence service — a
    /// press with no pending request never arms anything. The fallback
    /// below stays the host/test path: a per-command service fed by the
    /// injected `fn() -> bool` poll (or the build default — fail-closed on
    /// device, auto-ack on host/emulation); press→consume is synchronous
    /// within the command there, so tick 0 stands in for the clock.
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
            // OATH has no monotonic clock and press→consume is synchronous
            // within this command, so the 10 s window is moot here; tick 0
            // is the injected stand-in (US-921 wires the real clock).
            svc.observe_press(0);
        }
        let grant = svc.request(tag, 0).is_some();
        svc.end_request(tag);
        grant
    }

    fn reset_state(&mut self) {
        self.creds.clear();
        self.access_code = None;
        self.pin = None;
        self.refresh_session_grant();
    }

    /// Parse the C-harness APDU: `00 INS P1 P2 00 LH LL data... LE...`.
    fn parse_apdu(apdu: &[u8]) -> (u8, u8, u8, Vec<u8>) {
        // The C harness sends data-less commands as `00 INS P1 P2 00 00`
        // (no Lc field at all), so only trust the extended header when a
        // data field is actually present.
        if apdu.len() >= 7 && apdu[4] == 0x00 && apdu.len() > 7 + 1 {
            let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
            let data = if apdu.len() >= 7 + lc {
                apdu[7..7 + lc].to_vec()
            } else {
                apdu[7..].to_vec()
            };
            return (apdu[1], apdu[2], apdu[3], data);
        }
        if apdu.len() < 4 {
            return (0, 0, 0, Vec::new());
        }
        if apdu.len() == 4 {
            // US-132 (PICOForge-COMPAT): ISO 7816-4 case 1 — no Lc, no Le, no
            // data. C parity (`apdu.c::apdu_process`, `buffer_size == 4`),
            // and the form picoforge's `Apdu::encode` produces for an
            // empty-body write. Mirrors `oath_core::parse_apdu`.
            return (apdu[1], apdu[2], apdu[3], Vec::new());
        }
        let lc = apdu[4] as usize;
        let data = if apdu.len() >= 5 + lc {
            apdu[5..5 + lc].to_vec()
        } else {
            apdu[5..].to_vec()
        };
        (apdu[1], apdu[2], apdu[3], data)
    }

    fn find_cred(&self, name: &[u8]) -> Option<usize> {
        self.creds
            .iter()
            .position(|c| c.as_ref().map(|c| &c.name).is_some_and(|n| n == name))
    }

    /// Compute the OATH response body for a credential (digits + hmac or the
    /// truncated form).
    fn calculate(&mut self, truncate: bool, cred_key: &[u8], chal: &[u8]) -> Option<Vec<u8>> {
        if cred_key.len() < 2 {
            return None;
        }
        let alg = cred_key[0];
        let digits = cred_key[1];
        let mac = hmac_digest(alg, &cred_key[2..], chal)?;
        let size = digest_size(alg);
        let mut out = Vec::new();
        if truncate {
            out.push(5u8);
            out.push(digits);
            let offset = mac[size - 1] as usize & 0x0F;
            out.push(mac[offset] & 0x7F);
            out.extend_from_slice(&mac[offset + 1..offset + 4]);
        } else {
            out.push((size + 1) as u8);
            out.push(digits);
            out.extend_from_slice(&mac);
        }
        Some(out)
    }
}

impl App for OathApp {
    fn aid(&self) -> &[u8] {
        &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
    }

    fn select(&mut self, internal: bool) -> Sw {
        if !internal {
            // Host-issued SELECT resets the security state (ISO 7816-4): the
            // grant is recomputed by the virgin rule (US-901), never
            // self-granted.
            self.refresh_session_grant();
            fapico2_platform::trng::random_bytes_into(&mut self.challenge);
        }
        SW_OK
    }

    fn select_apdu(
        &mut self,
        internal: bool,
        _apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        let sw = self.select(internal);
        if sw == SW_OK {
            let mut data = Vec::new();
            data.extend_from_slice(&[TAG_VERSION, 3, 4, 3, 0]);
            data.extend_from_slice(&[TAG_NAME, 8, b'f', b'a', b'p', b'i', b'c', b'o', b'2', b'!']);
            if self.access_code.is_some() {
                data.extend_from_slice(&[TAG_CHALLENGE, 8]);
                data.extend_from_slice(&self.challenge);
            }
            for b in data {
                resp.push(b).ok();
            }
        }
        sw
    }

    fn deselect(&mut self) {}

    fn process(&mut self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        let (ins, p1, p2, data) = Self::parse_apdu(apdu);
        let sw = self.handle(ins, p1, p2, data, resp);
        for b in sw.to_be_bytes() {
            resp.push(b).ok();
        }
    }
}

impl OathApp {
    fn handle(
        &mut self,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Vec<u8>,
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        match ins {
            INS_PUT => self.cmd_put(data),
            INS_DELETE => self.cmd_delete(data),
            INS_SET_CODE => self.cmd_set_code(data),
            INS_RESET => self.cmd_reset(p1, p2),
            INS_RENAME => self.cmd_rename(data),
            INS_LIST => self.cmd_list(data, resp),
            INS_CALCULATE => self.cmd_calculate(p2, data, resp),
            INS_VALIDATE => self.cmd_validate(data, resp),
            INS_CALC_ALL => self.cmd_calculate_all(p2, data, resp),
            INS_VERIFY_CODE => {
                if !self.validated {
                    return SW_SECURITY_STATUS_NOT_SATISFIED;
                }
                SW_OK
            }
            INS_SET_PIN => self.cmd_set_pin(data),
            INS_CHANGE_PIN => self.cmd_change_pin(data),
            INS_VERIFY_PIN => self.cmd_verify_pin(data),
            _ => SW_INS_NOT_SUPPORTED,
        }
    }

    fn cmd_put(&mut self, data: Vec<u8>) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let tlvs = parse_tlvs(&data);
        let key = match find_tlv(&tlvs, TAG_KEY) {
            Some(k) if k.len() >= 2 => k.to_vec(),
            Some(_) => return SW_WRONG_DATA,
            None => return SW_INCORRECT_PARAMS,
        };
        let name = match find_tlv(&tlvs, TAG_NAME) {
            Some(n) => n.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        // HOTP credentials carry a moving factor: an explicit TAG_IMF is
        // left-padded to 8 bytes; a missing one is stored as zero (C parity).
        let imf = if key[0] & TYPE_MASK == TYPE_HOTP {
            Some(match find_tlv(&tlvs, TAG_IMF) {
                Some(v) => {
                    let mut be = [0u8; 8];
                    let src = v;
                    let start = 8usize.saturating_sub(src.len());
                    let take = src.len().min(8);
                    be[start..start + take].copy_from_slice(&src[..take]);
                    u64::from_be_bytes(be)
                }
                None => 0,
            })
        } else {
            None
        };
        let cred = OathCred { name, key, imf };
        match self.find_cred(&cred.name) {
            Some(idx) => self.creds[idx] = Some(cred),
            None => match self.creds.iter().position(|c| c.is_none()) {
                Some(free) => self.creds[free] = Some(cred),
                None => self.creds.push(Some(cred)),
            },
        }
        SW_OK
    }

    fn cmd_delete(&mut self, data: Vec<u8>) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let tlvs = parse_tlvs(&data);
        let name = match find_tlv(&tlvs, TAG_NAME) {
            Some(n) => n.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        match self.find_cred(&name) {
            Some(idx) => {
                self.creds[idx] = None;
                SW_OK
            }
            None => SW_DATA_INVALID,
        }
    }

    fn cmd_rename(&mut self, data: Vec<u8>) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let tlvs = parse_tlvs(&data);
        let mut names = tlvs.iter().filter(|t| t.tag == TAG_NAME);
        let old = match names.next() {
            Some(t) => t.value.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        let new = match names.next() {
            Some(t) => t.value.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        match self.find_cred(&old) {
            Some(idx) => {
                self.creds[idx].as_mut().unwrap().name = new;
                SW_OK
            }
            None => SW_DATA_INVALID,
        }
    }

    fn cmd_set_code(&mut self, data: Vec<u8>) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        if data.is_empty() {
            // US-905 (SEC-HARDEN): clearing a present access code is as hard
            // as setting it — it consumes a user-presence grant (RESET
            // parity). With no code on file it stays a plain no-op success
            // (nothing to clear, no consent needed — C parity).
            if self.access_code.is_some() && !self.user_present(PRESENCE_TAG_SET_CODE_CLEAR) {
                return SW_CONDITIONS_NOT_SATISFIED;
            }
            self.access_code = None;
            // Removing the code does not re-grant a non-virgin app (US-901).
            self.refresh_session_grant();
            return SW_OK;
        }
        let tlvs = parse_tlvs(&data);
        let key = match find_tlv(&tlvs, TAG_KEY) {
            Some(k) => k.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        if key.len() == 1 {
            return SW_WRONG_DATA;
        }
        let chal = match find_tlv(&tlvs, TAG_CHALLENGE) {
            Some(c) => c.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        let resp_tag = match find_tlv(&tlvs, TAG_RESPONSE) {
            Some(r) => r.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        let Some(mac) = hmac_digest(key[0], &key[1..], &chal) else {
            return SW_INCORRECT_PARAMS;
        };
        if resp_tag.len() != digest_size(key[0]) || !ct_eq(&mac, &resp_tag) {
            return SW_DATA_INVALID;
        }
        self.access_code = Some(key);
        fapico2_platform::trng::random_bytes_into(&mut self.challenge);
        self.validated = false;
        SW_OK
    }

    fn cmd_validate(&mut self, data: Vec<u8>, resp: &mut HeaplessVec<u8, MAX_RESPONSE>) -> Sw {
        let tlvs = parse_tlvs(&data);
        let chal = match find_tlv(&tlvs, TAG_CHALLENGE) {
            Some(c) => c.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        let resp_tag = match find_tlv(&tlvs, TAG_RESPONSE) {
            Some(r) => r.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        let Some(code) = &self.access_code else {
            // US-902 (deliberate C-parity break): with no access code on file
            // VALIDATE can never check anything, so it must not grant — the
            // session state (and the grant) is left untouched.
            return SW_CONDITIONS_NOT_SATISFIED;
        };
        let Some(mac) = hmac_digest(code[0], &code[1..], &self.challenge) else {
            return SW_INCORRECT_PARAMS;
        };
        if resp_tag.len() != mac.len() || !ct_eq(&mac, &resp_tag) {
            return SW_DATA_INVALID;
        }
        let Some(out) = hmac_digest(code[0], &code[1..], &chal) else {
            return SW_INCORRECT_PARAMS;
        };
        self.validated = true;
        let mut body = vec![TAG_RESPONSE, out.len() as u8];
        body.extend_from_slice(&out);
        for b in body {
            resp.push(b).ok();
        }
        SW_OK
    }

    fn cmd_calculate(
        &mut self,
        p2: u8,
        data: Vec<u8>,
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        if p2 != 0 && p2 != 1 {
            return SW_INCORRECT_P1P2;
        }
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let tlvs = parse_tlvs(&data);
        let name = match find_tlv(&tlvs, TAG_NAME) {
            Some(n) => n.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        let idx = match self.find_cred(&name) {
            Some(i) => i,
            None => return SW_DATA_INVALID,
        };
        let is_hotp = self.creds[idx].as_ref().unwrap().key[0] & TYPE_MASK == TYPE_HOTP;
        // HOTP uses the stored moving factor; TOTP the request challenge.
        let chal: Vec<u8> = if is_hotp {
            match self.creds[idx].as_ref().unwrap().imf {
                Some(v) => v.to_be_bytes().to_vec(),
                None => return SW_INCORRECT_PARAMS,
            }
        } else {
            match find_tlv(&tlvs, TAG_CHALLENGE) {
                Some(c) => c.to_vec(),
                None => return SW_INCORRECT_PARAMS,
            }
        };
        let key = self.creds[idx].as_ref().unwrap().key.clone();
        let Some(mut out) = self.calculate(p2 == 1, &key, &chal) else {
            return SW_INCORRECT_PARAMS;
        };
        out.insert(0, TAG_RESPONSE + p2);
        for b in out {
            resp.push(b).ok();
        }
        if is_hotp {
            if let Some(v) = self.creds[idx].as_mut().unwrap().imf {
                self.creds[idx].as_mut().unwrap().imf = Some(v.wrapping_add(1));
            }
        }
        SW_OK
    }

    fn cmd_calculate_all(
        &mut self,
        p2: u8,
        data: Vec<u8>,
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        if p2 != 0 && p2 != 1 {
            return SW_INCORRECT_P1P2;
        }
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let tlvs = parse_tlvs(&data);
        let chal = match find_tlv(&tlvs, TAG_CHALLENGE) {
            Some(c) => c.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        for idx in 0..self.creds.len() {
            let Some(ref cred) = self.creds[idx] else {
                continue;
            };
            let (name, key) = (cred.name.clone(), cred.key.clone());
            resp.push(TAG_NAME).ok();
            resp.push(name.len() as u8).ok();
            for b in &name {
                resp.push(*b).ok();
            }
            let is_hotp = key[0] & TYPE_MASK == TYPE_HOTP;
            if is_hotp {
                if p2 == 1 {
                    // Truncation requested but HOTP has no client challenge:
                    // report "no response" with the digit count.
                    resp.extend_from_slice(&[TAG_NO_RESPONSE, 1, key[1]]).ok();
                    continue;
                }
                let counter = match self.creds[idx].as_ref().and_then(|c| c.imf) {
                    Some(v) => v,
                    None => continue,
                };
                let Some(out) = self.calculate(false, &key, &counter.to_be_bytes()) else {
                    continue;
                };
                for b in out {
                    resp.push(b).ok();
                }
                self.creds[idx].as_mut().unwrap().imf = Some(counter.wrapping_add(1));
            } else {
                let Some(mut out) = self.calculate(p2 == 1, &key, &chal) else {
                    continue;
                };
                out.insert(0, TAG_RESPONSE + p2);
                for b in out {
                    resp.push(b).ok();
                }
            }
        }
        SW_OK
    }

    fn cmd_list(&mut self, data: Vec<u8>, resp: &mut HeaplessVec<u8, MAX_RESPONSE>) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let _ext = data == [0x01];
        for cred in self.creds.iter().flatten() {
            let mut entry = vec![TAG_NAME_LIST, (cred.name.len() + 1) as u8, cred.key[0]];
            entry.extend_from_slice(&cred.name);
            for b in entry {
                resp.push(b).ok();
            }
        }
        SW_OK
    }

    fn cmd_reset(&mut self, p1: u8, p2: u8) -> Sw {
        if p1 != 0xDE || p2 != 0xAD {
            return SW_INCORRECT_P1P2;
        }
        // US-132 (PICOForge-COMPAT): the US-903 session gate is REMOVED here
        // exactly as it is in `oath_core.rs::cmd_reset` — same decision, same
        // two surviving gates, same trade (see
        // `docs/tasks/us132-oath-reset-picocompat.md`). This host back end
        // must not answer RESET differently from the device back end: two
        // `OathApp`s with different security gates is a trap, and the only
        // thing that makes this back end safe to keep is that it is kept in
        // step. The device and the emulation binary both run `oath_core`;
        // this one exists for the host dispatcher/registry tests and must
        // mirror it.
        //
        // US-903 (SEC-HARDEN) still applies in full: the APDU path alone
        // cannot erase the credential table. US-921: the grant is bound to
        // the RESET tag (PRESENCE_TAG_RESET) and consumed from the shared
        // presence runtime — a discarded press (no pending request) never
        // arms it.
        if !self.user_present(PRESENCE_TAG_RESET) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        self.reset_state();
        SW_OK
    }

    fn cmd_set_pin(&mut self, data: Vec<u8>) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        if self.pin.is_some() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        let tlvs = parse_tlvs(&data);
        let pw = match find_tlv(&tlvs, TAG_PASSWORD) {
            Some(p) => p,
            None => return SW_INCORRECT_PARAMS,
        };
        // US-904: the record is salted from the platform TRNG (host parity
        // with `oath_core.rs::cmd_set_pin`).
        let mut salt = [0u8; 16];
        fapico2_platform::trng::random_bytes_into(&mut salt);
        self.pin = Some(PinRecord {
            counter: MAX_OTP_COUNTER,
            salt,
            verifier: pin_verifier(pw, &salt),
            legacy: false,
        });
        SW_OK
    }

    /// Check a PIN against the salted record (mirror of
    /// `oath_core.rs::check_pin`; every check burns one retry, a successful
    /// verify resets the budget and upgrades a legacy record in place).
    fn check_pin(&mut self, pw: &[u8]) -> Result<(), Sw> {
        let Some(mut rec) = self.pin else {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        };
        if rec.counter == 0 {
            return Err(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        let verified = if rec.legacy {
            legacy_pin_verifier(pw) == rec.verifier
        } else {
            pin_verifier(pw, &rec.salt) == rec.verifier
        };
        if verified {
            if rec.legacy {
                // US-904 legacy migration: fresh salt, verifier re-derived
                // from the just-verified PIN, upgraded in place.
                let mut salt = [0u8; 16];
                fapico2_platform::trng::random_bytes_into(&mut salt);
                self.pin = Some(PinRecord {
                    counter: MAX_OTP_COUNTER,
                    salt,
                    verifier: pin_verifier(pw, &salt),
                    legacy: false,
                });
            } else {
                rec.counter = MAX_OTP_COUNTER;
                self.pin = Some(rec);
            }
            Ok(())
        } else {
            rec.counter -= 1;
            self.pin = Some(rec);
            Err(SW_SECURITY_STATUS_NOT_SATISFIED)
        }
    }

    fn cmd_change_pin(&mut self, data: Vec<u8>) -> Sw {
        let tlvs = parse_tlvs(&data);
        let pw = match find_tlv(&tlvs, TAG_PASSWORD) {
            Some(p) => p.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        let new_pw = match find_tlv(&tlvs, TAG_NEW_PASSWORD) {
            Some(p) => p,
            None => return SW_INCORRECT_PARAMS,
        };
        if self.pin.is_none() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        if let Err(sw) = self.check_pin(&pw) {
            return sw;
        }
        // US-904: CHANGE_PIN re-salts the record (host parity).
        let mut salt = [0u8; 16];
        fapico2_platform::trng::random_bytes_into(&mut salt);
        self.pin = Some(PinRecord {
            counter: MAX_OTP_COUNTER,
            salt,
            verifier: pin_verifier(new_pw, &salt),
            legacy: false,
        });
        SW_OK
    }

    fn cmd_verify_pin(&mut self, data: Vec<u8>) -> Sw {
        let tlvs = parse_tlvs(&data);
        let pw = match find_tlv(&tlvs, TAG_PASSWORD) {
            Some(p) => p.to_vec(),
            None => return SW_INCORRECT_PARAMS,
        };
        if self.pin.is_none() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        if let Err(sw) = self.check_pin(&pw) {
            return sw;
        }
        self.validated = true;
        SW_OK
    }
}
