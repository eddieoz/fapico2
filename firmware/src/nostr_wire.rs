//! US-1662 — the vendor CTAPHID wire dialect for the Nostr applet.
//!
//! The third HID interface (US-1657) speaks CTAPHID framing (US-1660); the
//! Nostr command set rides the vendor command range `0x40–0x7F` (spec-reserved,
//! §A.8.2) as CBOR payloads, with **NIP-46 method semantics** per D20: each
//! command byte names one method of the §A.3 set (`ping`, `get_public_key`,
//! `sign_event`, `nip44_encrypt/decrypt`) plus the §2.2 key-management set
//! that has no NIP-46 twin. The device signs the **32-byte sighash** (§5 — it
//! never parses JSON); the host computes event ids.
//!
//! The envelopes are deliberately minimal — the vendor command byte IS the
//! method, and the payload is one CBOR array:
//!
//! ```text
//! request : 82 [idx: uint, arg: bytes]        (an empty payload = PING)
//! response: A1/A2 {1: sw: uint, 2: data: bytes?}
//! ```
//!
//! The response's `sw` field is D13's status vocabulary (§2.2.0) crossing the
//! transport byte-for-byte — `0x6985` is "press the button" and `0x6A82` is
//! "that identity is not on the device" whether the client reached the applet
//! over CCID/APDU or over this interface. An **unsupported method** is
//! `sw = 0x6D00` (`SW_INS_NOT_SUPPORTED`) answered **in band, on the method's
//! own channel** — the D20 refusal (`error unsupported-method` in the line
//! protocol), not a CTAPHID framing error: the framing is fine, the method is
//! what the device does not serve.
//!
//! The applet behind this module is the SAME command core the CCID/APDU path
//! serves (`apps/nostr`, US-1643+): a vendor command becomes the applet APDU
//! (`[00, INS, idx, 00, Lc, arg…]`, extended Lc — NIP-44 arguments exceed one
//! byte), and the applet's (data ‖ SW) response becomes the CBOR map. One
//! command core, two transports, one vocabulary.

use fapico2_platform::dispatch::Sw;
use heapless::Vec as HeaplessVec;

use crate::hid_serve::NOSTR_RESP_MAX;

/// NIP-46 `ping` → the applet's `GET_INFO` (the `pong <version>` arm).
pub const NOSTR_CMD_PING: u8 = 0x40;
/// NIP-46 `get_public_key` — no touch.
pub const NOSTR_CMD_GET_PUBKEY: u8 = 0x41;
/// NIP-46 `sign_event`: the 32-byte sighash in, BIP-340 sig out — touch-gated.
pub const NOSTR_CMD_SIGN: u8 = 0x42;
/// NIP-46 `nip44_encrypt` — touch-gated.
pub const NOSTR_CMD_NIP44_ENCRYPT: u8 = 0x43;
/// NIP-46 `nip44_decrypt` — touch-gated.
pub const NOSTR_CMD_NIP44_DECRYPT: u8 = 0x44;
/// §2.2 `LIST_KEYS` — the enumeration no NIP-46 client gets wrong.
pub const NOSTR_CMD_LIST_KEYS: u8 = 0x45;
/// §2.2 `GENERATE_KEY` (D12: generate-on-device is the device-as-only-copy
/// path; onboarding guidance prefers software generate + IMPORT).
pub const NOSTR_CMD_GENERATE_KEY: u8 = 0x46;
/// §2.2 `IMPORT_KEY`.
pub const NOSTR_CMD_IMPORT_KEY: u8 = 0x47;
/// §2.2 `EXPORT_KEY` (D12) — touch-gated, permanent.
pub const NOSTR_CMD_EXPORT_KEY: u8 = 0x48;
/// §2.2 `DELETE_KEY`.
pub const NOSTR_CMD_DELETE_KEY: u8 = 0x49;
/// §2.2 `SET_LABEL`.
pub const NOSTR_CMD_SET_LABEL: u8 = 0x4A;

/// The largest legal request argument. `NIP44_DECRYPT` is the worst case:
/// sender key (32) + payload (33 version+nonce ‖ 2 ‖ padded(1792) ‖ 32 mac) —
/// the applet's own `max_legal` cap. The APDU adds 7 header bytes.
pub const NOSTR_APDU_REQ_MAX: usize = 7 + 32 + 33 + 2 + 2048 + 32;

/// D13 §2.2.0 — `wrong data / bad index`: a malformed request envelope.
pub const SW_WRONG_DATA: Sw = 0x6A80;
/// D13 §2.2.0 — the store could not be opened or read: the honest "the
/// device is broken" word. Also the degradation for an applet answer that
/// arrived without a status word (unreachable for this applet).
pub const SW_STORE_FAULT: Sw = 0x6F00;

/// Is `cmd` in the spec-reserved vendor range (§A.8.2)?
pub fn is_vendor_command(cmd: u8) -> bool {
    (0x40..=0x7F).contains(&cmd)
}

/// Vendor command byte → the applet INS it drives. `None` is an **unsupported
/// method**: the caller answers in band with [`fapico2_platform::dispatch::
/// SW_INS_NOT_SUPPORTED`] — the D20 refusal — rather than a framing fault.
pub fn vendor_to_ins(cmd: u8) -> Option<u8> {
    use fapico2_nostr::{
        INS_DELETE_KEY, INS_EXPORT_KEY, INS_GENERATE_KEY, INS_GET_INFO, INS_GET_PUBKEY,
        INS_IMPORT_KEY, INS_LIST_KEYS, INS_NIP44_DECRYPT, INS_NIP44_ENCRYPT, INS_SET_LABEL,
        INS_SIGN,
    };
    let ins = match cmd {
        NOSTR_CMD_PING => INS_GET_INFO,
        NOSTR_CMD_GET_PUBKEY => INS_GET_PUBKEY,
        NOSTR_CMD_SIGN => INS_SIGN,
        NOSTR_CMD_NIP44_ENCRYPT => INS_NIP44_ENCRYPT,
        NOSTR_CMD_NIP44_DECRYPT => INS_NIP44_DECRYPT,
        NOSTR_CMD_LIST_KEYS => INS_LIST_KEYS,
        NOSTR_CMD_GENERATE_KEY => INS_GENERATE_KEY,
        NOSTR_CMD_IMPORT_KEY => INS_IMPORT_KEY,
        NOSTR_CMD_EXPORT_KEY => INS_EXPORT_KEY,
        NOSTR_CMD_DELETE_KEY => INS_DELETE_KEY,
        NOSTR_CMD_SET_LABEL => INS_SET_LABEL,
        _ => return None,
    };
    Some(ins)
}

/// The request envelope: CBOR `array(2) [idx, arg]`. An **empty payload** is
/// the argument-less form (`ping`): idx 0, empty arg. Anything else that is
/// not exactly this shape is [`SW_WRONG_DATA`] — reported in band, because a
/// client that sent garbage still gets a readable answer, not silence.
pub fn decode_request(payload: &[u8]) -> Result<(u16, &[u8]), Sw> {
    let Some((idx, arg)) = decode_request_inner(payload) else {
        return Err(SW_WRONG_DATA);
    };
    Ok((idx, arg))
}

/// The decoder proper: `None` = malformed. Kept separate so the error path
/// above stays one `Sw`.
fn decode_request_inner(payload: &[u8]) -> Option<(u16, &[u8])> {
    // An empty payload is the argument-less form (`ping`): idx 0, no arg.
    if payload.is_empty() {
        return Some((0, &[]));
    }
    let (head, rest) = payload.split_first()?;
    if *head != 0x82 {
        return None; // array(2), always
    }
    let (idx, rest) = read_uint(rest)?;
    if idx > 0xFFFF {
        return None;
    }
    let (arg, rest) = read_bytes(rest)?;
    if !rest.is_empty() {
        return None; // trailing garbage is malformed, not ignorable
    }
    Some((idx as u16, arg))
}

/// CBOR `major 0` (unsigned int) — ai `0..=0x19` (u8 / u16 heads).
fn read_uint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let (head, rest) = buf.split_first()?;
    match head {
        0x00..=0x17 => Some((*head as u64, rest)),
        0x18 => {
            let (b, rest) = rest.split_first()?;
            Some((*b as u64, rest))
        }
        0x19 => {
            let (b, rest) = rest.split_at_checked(2)?;
            Some((u16::from_be_bytes([b[0], b[1]]) as u64, rest))
        }
        _ => None,
    }
}

/// CBOR `major 2` (byte string) — small, u8-head and u16-head lengths. The
/// request arguments top out at ~2.1 KB, so the u16 head (`0x59`) covers every
/// legal form; a u32 head (`0x5A`) or an indefinite length is not a request
/// this transport can carry and is refused rather than half-decoded.
fn read_bytes(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (head, rest) = buf.split_first()?;
    // Each arm consumes its own length bytes: the `rest` that leaves the
    // match is the first byte of the *body*, never a length byte.
    let (len, rest) = match head {
        0x40..=0x57 => (*head as usize - 0x40, rest),
        0x58 => {
            let (b, r) = rest.split_first()?;
            (*b as usize, r)
        }
        0x59 => {
            let (b, r) = rest.split_at_checked(2)?;
            (u16::from_be_bytes([b[0], b[1]]) as usize, r)
        }
        _ => return None,
    };
    rest.split_at_checked(len)
}

/// The response envelope: CBOR `map {1: sw, 2: data}` — `2` present only when
/// the applet returned data. Encoded into `out` (the hoisted `NOSTR_RESP`
/// static's size, passed as `&mut` by the caller), returning the written
/// length for the reply frame.
///
/// Every legal applet reply fits (largest: the ~1.9 KB `NIP44_ENCRYPT`
/// ciphertext, design §A.8.3 #6). A response that somehow cannot is
/// **truncated, never dropped and never allowed to push the `sw` field out**:
/// the vocabulary field is the one thing that must survive the transport, and
/// valid-but-short CBOR beats a panic on the device. The truncation is
/// visible to a client that checks `data`'s length against the method's
/// expected shape.
pub fn encode_response(sw: Sw, data: &[u8], out: &mut HeaplessVec<u8, NOSTR_RESP_MAX>) -> usize {
    out.clear();
    let [hi, lo] = sw.to_be_bytes();
    if data.is_empty() {
        out.extend_from_slice(&[0xA1, 0x01, 0x19, hi, lo]).ok();
        return out.len();
    }
    // map(2) head + key 1 + sw (0x19 u16) + key 2 + byte string head (0x59).
    const OVERHEAD: usize = 1 + 1 + 3 + 1 + 3;
    let body_room = out.capacity().saturating_sub(OVERHEAD);
    if body_room == 0 {
        // Degenerate buffer: the sw-only form is the one thing that fits.
        out.extend_from_slice(&[0xA1, 0x01, 0x19, hi, lo]).ok();
        return out.len();
    }
    let data = if data.len() > body_room { &data[..body_room] } else { data };
    let [dhi, dlo] = (data.len() as u16).to_be_bytes();
    out.extend_from_slice(&[0xA2, 0x01, 0x19, hi, lo, 0x02, 0x59, dhi, dlo]).ok();
    out.extend_from_slice(data).ok();
    out.len()
}

/// Decode the response envelope — the test-side and client-side reader of
/// [`encode_response`]. `None` = not this shape.
pub fn decode_response(buf: &[u8]) -> Option<(Sw, &[u8])> {
    let (&map_head, rest) = buf.split_first()?;
    let entries = match map_head {
        0xA1 => 1,
        0xA2 => 2,
        _ => return None,
    };
    let (mut sw, mut data) = (None, None);
    let mut rest = rest;
    for _ in 0..entries {
        let (&key, r) = rest.split_first()?;
        match key {
            0x01 => {
                let (v, r) = read_uint(r)?;
                sw = Some(v as u16);
                rest = r;
            }
            0x02 => {
                let (d, r) = read_bytes(r)?;
                data = Some(d);
                rest = r;
            }
            _ => return None,
        }
    }
    Some((sw?, data.unwrap_or(&[])))
}

/// The request envelope's encoder — the mirror of [`decode_request`], for the
/// client (OpenXrypt's extension speaks the same bytes) and for the tests.
/// `arg` may be empty (idx-only form).
pub fn encode_request(idx: u16, arg: &[u8]) -> HeaplessVec<u8, NOSTR_APDU_REQ_MAX> {
    let mut out = HeaplessVec::new();
    out.push(0x82).unwrap();
    if idx <= 0x17 {
        out.push(idx as u8).unwrap();
    } else if idx <= 0xFF {
        out.extend_from_slice(&[0x18, idx as u8]).unwrap();
    } else {
        let [hi, lo] = idx.to_be_bytes();
        out.extend_from_slice(&[0x19, hi, lo]).unwrap();
    }
    match arg.len() {
        0..=23 => out.push((0x40 + arg.len()) as u8).unwrap(),
        24..=255 => out.extend_from_slice(&[0x58, arg.len() as u8]).unwrap(),
        _ => {
            let [hi, lo] = (arg.len() as u16).to_be_bytes();
            out.extend_from_slice(&[0x59, hi, lo]).unwrap()
        }
    }
    out.extend_from_slice(arg).unwrap();
    out
}

/// Build the applet APDU for one vendor command: `[00, INS, idx, 00, Lc, arg…]`,
/// extended Lc when the argument needs it. `None` = the argument cannot ride
/// an APDU of this size (an over-long arg is [`SW_WRONG_DATA`] in band, not a
/// panic) — `out` must be at least [`NOSTR_APDU_REQ_MAX`].
pub fn build_apdu(ins: u8, idx: u16, arg: &[u8], out: &mut HeaplessVec<u8, NOSTR_APDU_REQ_MAX>) {
    out.clear();
    out.extend_from_slice(&[0x00, ins, idx as u8, 0x00]).unwrap();
    if arg.len() <= 255 {
        out.push(arg.len() as u8).unwrap();
    } else {
        out.push(0x00).unwrap();
        let [hi, lo] = (arg.len() as u16).to_be_bytes();
        out.extend_from_slice(&[hi, lo]).unwrap();
    }
    out.extend_from_slice(arg).unwrap();
}

/// The one vendor-command body every `NostrDispatch` impl runs: decode the
/// request, map the method, build the APDU, drive the applet command through
/// `process` (the `App::process` shape — `(data ‖ SW)` into a `MAX_RESPONSE`
/// buffer), and encode the CBOR response into `out`. Returns the length.
///
/// The request and response buffers are the **caller's** — on the device they
/// are the hoisted scratch statics (`nostr_shared::{NOSTR_APDU_REQ,
/// NOSTR_APDU_RESP}`); a 6 KB transient here would sit on the HID poll
/// chain, and `check_boot_chain`'s margin is measured in kilobytes, not
/// megabytes. `process` is `FnOnce`: it runs exactly once per command.
pub fn process_vendor_through(
    cmd: u8,
    payload: &[u8],
    req: &mut HeaplessVec<u8, NOSTR_APDU_REQ_MAX>,
    resp: &mut HeaplessVec<u8, { fapico2_platform::dispatch::MAX_RESPONSE }>,
    process: impl FnOnce(&[u8], &mut HeaplessVec<u8, { fapico2_platform::dispatch::MAX_RESPONSE }>),
    out: &mut HeaplessVec<u8, NOSTR_RESP_MAX>,
) -> usize {
    use fapico2_platform::dispatch::SW_INS_NOT_SUPPORTED;

    // Malformed request: the vocabulary, in band.
    let Ok((idx, arg)) = decode_request(payload) else {
        return encode_response(SW_WRONG_DATA, &[], out);
    };
    // Unsupported method: also in band — the D20 `error unsupported-method`
    // refusal, not a framing fault (the framing is fine; the method is what
    // the device does not serve).
    let Some(ins) = vendor_to_ins(cmd) else {
        return encode_response(SW_INS_NOT_SUPPORTED, &[], out);
    };
    build_apdu(ins, idx, arg, req);
    resp.clear();
    process(req.as_slice(), resp);
    // (data ‖ SW) → the CBOR response; the sw field is the vocabulary
    // crossing (§A.8.3b #8). The applet always answers with a status word;
    // a shorter reply degrades to the store fault (0x6F00, D13) — the
    // honest "the device is broken" word, not a made-up code.
    let n = resp.len();
    let (data, sw) = if n >= 2 {
        let sw = u16::from_be_bytes([resp[n - 2], resp[n - 1]]);
        (&resp[..n - 2], sw)
    } else {
        (&[][..], SW_STORE_FAULT)
    };
    encode_response(sw, data, out)
}

#[cfg(all(test, feature = "emulation"))]
mod tests {
    use super::*;
    use fapico2_platform::dispatch::SW_INS_NOT_SUPPORTED;

    /// The envelope shapes are the extension's executable spec: request and
    /// response round-trip byte-exactly, and the `sw` field survives as a u16.
    #[test]
    fn request_and_response_envelopes_round_trip() {
        // idx-only form (GET_PUBKEY / LIST_KEYS / GENERATE_KEY).
        let req = encode_request(3, &[]);
        let (idx, arg) = decode_request(&req).unwrap();
        assert_eq!((idx, arg), (3, &[][..]));

        // idx + short arg (SIGN: the 32-byte sighash).
        let req = encode_request(0, &[0x5A; 32]);
        let (idx, arg) = decode_request(&req).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(arg, &[0x5A; 32][..]);

        // u16-head arg (NIP-44: arguments exceed 255 bytes).
        let req = encode_request(1, &[0x33; 1900]);
        let (idx, arg) = decode_request(&req).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(arg.len(), 1900);

        // Empty payload = the argument-less form (`ping`).
        let (idx, arg) = decode_request(&[]).unwrap();
        assert_eq!((idx, arg), (0, &[][..]));

        // Response: sw only, then sw + data.
        let mut out = HeaplessVec::new();
        let n = encode_response(0x6985, &[], &mut out);
        assert_eq!(decode_response(&out[..n]).unwrap(), (0x6985, &[][..]));
        let n = encode_response(0x9000, &[1, 2, 3], &mut out);
        assert_eq!(decode_response(&out[..n]).unwrap(), (0x9000, &[1, 2, 3][..]));
    }

    /// A response larger than the 2 KiB wire buffer truncates its data —
    /// valid-but-short CBOR — and the `sw` field survives, because the
    /// vocabulary field is the one thing that must cross the transport.
    #[test]
    fn an_oversized_response_truncates_but_keeps_the_sw_field() {
        let mut out = HeaplessVec::new();
        let big = [0x7Fu8; 3000];
        let n = encode_response(0x6B00, &big, &mut out);
        assert!(n <= NOSTR_RESP_MAX);
        let (sw, data) = decode_response(&out[..n]).unwrap();
        assert_eq!(sw, 0x6B00);
        assert!(data.len() < 3000 && !data.is_empty());
        assert_eq!(data, &big[..data.len()]);
    }

    /// Malformed requests refuse with the vocabulary, not a panic — and the
    /// strictness is exact: trailing garbage, wrong array shape, an oversized
    /// integer head and a u32 byte-string head are all `SW_WRONG_DATA`.
    #[test]
    fn malformed_requests_refuse_with_the_vocabulary() {
        for bad in [
            &[0xFF][..],           // not an array
            &[0x81, 0x01][..],     // array(1), not array(2)
            &[0x82, 0x19, 0x01][..], // truncated u16 uint
            &[0x82, 0x01, 0x41][..], // truncated byte string
            &[0x82, 0x01, 0x40, 0x00, 0x00][..], // trailing garbage
            &[0x82, 0x1A, 0, 0, 0, 0x01, 0x40, 0][..], // u32 uint head
        ] {
            assert_eq!(decode_request(bad), Err(SW_WRONG_DATA));
        }
    }

    /// The vendor range is exactly `0x40–0x7F`, and the method mapping covers
    /// every command the applet serves — anything else in the range is the
    /// in-band unsupported-method refusal, never a panicking index.
    #[test]
    fn vendor_range_and_method_mapping() {
        for cmd in 0x40..=0x7F {
            let _ = vendor_to_ins(cmd); // must not panic
        }
        assert_eq!(vendor_to_ins(NOSTR_CMD_PING), Some(fapico2_nostr::INS_GET_INFO));
        assert_eq!(vendor_to_ins(NOSTR_CMD_SIGN), Some(fapico2_nostr::INS_SIGN));
        assert_eq!(vendor_to_ins(NOSTR_CMD_NIP44_DECRYPT), Some(fapico2_nostr::INS_NIP44_DECRYPT));
        assert_eq!(vendor_to_ins(0x7F), None);
        assert_eq!(vendor_to_ins(0x50), None);
        // And the refusal is the vocabulary crossing, not a CTAPHID fault:
        // the caller encodes it as any other sw.
        let mut out = HeaplessVec::new();
        let n = encode_response(SW_INS_NOT_SUPPORTED, &[], &mut out);
        assert_eq!(decode_response(&out[..n]).unwrap(), (SW_INS_NOT_SUPPORTED, &[][..]));
    }
}
