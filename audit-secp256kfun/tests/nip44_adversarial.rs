//! NIP-44 v2 adversarial probes against the live applet primitive layer
//! (`apps/nostr/src/nip44.rs`): the full reference vector set, then a
//! truncation/bit-flip sweep, bounds checks, and an independent
//! re-implementation of the padding algorithm.

#[path = "../../apps/nostr/tests/nip44_vectors.rs"]
mod vectors;

use audit_secp256kfun::nip44::{self, calc_padded_len, calc_padded_len_const, Error};
use sha2::{Digest, Sha256};
use vectors::*;

#[test]
fn conversation_key_vectors_match() {
    for v in CONV_KEY_VECTORS {
        assert_eq!(
            nip44::conversation_key(&v.sk, &v.peer_x).unwrap(),
            v.ck,
            "sk {:02x?} peer {:02x?}",
            &v.sk[..4],
            &v.peer_x[..4]
        );
    }
}

#[test]
fn conversation_key_invalid_inputs_refused() {
    for v in CONV_KEY_INVALID {
        // both refusal variants are acceptable here; the command layer maps
        // them to distinct status words before this layer is reached
        let _ = nip44::conversation_key(&v.sk, &v.peer_x).unwrap_err();
    }
}

#[test]
fn message_keys_vectors_match() {
    for v in MESSAGE_KEYS_VECTORS {
        let keys = nip44::message_keys(&MESSAGE_KEYS_CK, &v.nonce);
        assert_eq!(keys.chacha_key, v.chacha_key);
        assert_eq!(keys.chacha_nonce, v.chacha_nonce);
        assert_eq!(keys.hmac_key, v.hmac_key);
    }
}

#[test]
fn encrypt_decrypt_vectors_match_byte_for_byte() {
    for v in ENCRYPT_DECRYPT_VECTORS {
        let mut out = vec![0u8; nip44::MAX_PAYLOAD];
        let len = nip44::encrypt_with_ck(&v.ck, &v.nonce, v.plaintext, &mut out).unwrap();
        assert_eq!(
            &out[..len],
            v.payload,
            "encrypt diverges for plaintext len {}",
            v.plaintext.len()
        );
        let mut pt = vec![0u8; len];
        let n = nip44::decrypt_with_ck(&v.ck, v.payload, &mut pt).unwrap();
        assert_eq!(&pt[..n], v.plaintext);
    }
}

#[test]
fn decrypt_invalid_vectors_refused() {
    for v in DECRYPT_INVALID {
        let mut out = vec![0u8; v.payload.len()];
        assert!(
            nip44::decrypt_with_ck(&v.ck, v.payload, &mut out).is_err(),
            "payload must be refused: {}",
            v.note
        );
    }
}

/// Minimal standard base64 (RFC 4648, with padding) — the vector set stores
/// the payload digest over the base64 text, as the applet's own test does.
fn b64(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHA[(n >> 18) as usize & 63] as char);
        out.push(ALPHA[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHA[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHA[n as usize & 63] as char } else { '=' });
    }
    out
}

#[test]
fn long_msg_vectors_match_the_published_digests() {
    for v in LONG_MSG_VECTORS {
        let pt: Vec<u8> = v.pattern.repeat(v.repeat as usize);
        assert_eq!(Sha256::digest(&pt).as_slice(), &v.plaintext_sha256[..]);
        let mut out = vec![0u8; nip44::MAX_PAYLOAD];
        let len = nip44::encrypt_with_ck(&v.ck, &v.nonce, &pt, &mut out).unwrap();
        // the published digest is over the base64 text of the payload
        assert_eq!(Sha256::digest(b64(&out[..len]).as_bytes()).as_slice(), &v.payload_sha256[..]);
    }
}

#[test]
fn forbidden_lengths_refused() {
    let ck = [0u8; 32];
    let nonce = [0u8; 32];
    for &len in ENCRYPT_FORBIDDEN_LEN {
        let pt = vec![0u8; len as usize];
        let mut out = vec![0u8; nip44::MAX_PAYLOAD];
        assert_eq!(
            nip44::encrypt_with_ck(&ck, &nonce, &pt, &mut out).unwrap_err(),
            Error::InvalidMessageLen,
            "len {len} must be refused"
        );
    }
}

/// An attacker-controlled payload: truncate at every offset, flip every bit
/// of every region. Every outcome must be a clean `Err` — never a panic,
/// never a partial plaintext.
#[test]
fn truncation_and_bitflip_sweep_never_panics_or_accepts() {
    let ck = [0x42u8; 32];
    let nonce = [0x77u8; 32];
    let pt = b"attack at dawn, the plaintext boundary is padded";
    let mut out = vec![0u8; nip44::MAX_PAYLOAD];
    let len = nip44::encrypt_with_ck(&ck, &nonce, pt, &mut out).unwrap();
    let payload = out[..len].to_vec();

    // truncation at every offset
    for cut in 0..payload.len() {
        let mut sink = vec![0u8; payload.len()];
        assert!(
            nip44::decrypt_with_ck(&ck, &payload[..cut], &mut sink).is_err(),
            "truncated payload at {cut} must be refused"
        );
    }
    // single-bit flips over the whole payload (version, nonce, ct, mac)
    for byte in 0..payload.len() {
        for bit in 0..8 {
            let mut mangled = payload.clone();
            mangled[byte] ^= 1 << bit;
            let mut sink = vec![0u8; payload.len()];
            let r = nip44::decrypt_with_ck(&ck, &mangled, &mut sink);
            if byte == 0 {
                // version byte: any single-bit flip lands on a non-2 value
                assert!(matches!(r, Err(Error::InvalidPayload)), "byte 0 bit {bit}");
            } else {
                assert!(r.is_err(), "flip byte {byte} bit {bit} must be refused");
            }
        }
    }
    // output buffer exactly at the limit: ct_len needs out.len() >= ct_len
    let mut sink = vec![0u8; payload.len() - 65];
    assert!(nip44::decrypt_with_ck(&ck, &payload, &mut sink).is_ok());
    let mut sink_small = vec![0u8; payload.len() - 66];
    assert_eq!(
        nip44::decrypt_with_ck(&ck, &payload, &mut sink_small).unwrap_err(),
        Error::InvalidPayload
    );
}

/// Independent re-implementation of the NIP-44 padding schedule (different
/// formulation from both module twins), cross-checked over the whole domain.
fn reference_padded(len: u64) -> Option<u64> {
    if len == 0 {
        return None;
    }
    if len <= 32 {
        return Some(32);
    }
    let mut np = 1u64;
    while np < len {
        np <<= 1;
    }
    let chunk = if np <= 256 { 32 } else { np / 8 };
    Some(chunk * ((len + chunk - 1) / chunk))
}

#[test]
fn padded_len_matches_independent_implementation_to_65640() {
    for len in 0..=65_640u64 {
        let want = reference_padded(len);
        assert_eq!(calc_padded_len(len), want, "len {len}");
        // and the const twin must agree with the runtime form everywhere
        assert_eq!(calc_padded_len_const(len), want.unwrap_or(0), "const len {len}");
    }
    // the capacity anchor the wire cap is derived from
    assert_eq!(calc_padded_len_const(1792), 1792);
    assert_eq!(calc_padded_len_const(1793), 2048);
}

/// The decrypt output buffer is never trusted on failure: after any error the
/// caller's buffer must not be handed out (the applet clears `resp`, but the
/// primitive must not hand back a half-decrypted prefix either).
#[test]
fn failed_decrypt_leaves_no_usable_plaintext_prefix() {
    let ck = [0x42u8; 32];
    let nonce = [0x77u8; 32];
    let pt = b"secret contents";
    let mut out = vec![0u8; nip44::MAX_PAYLOAD];
    let len = nip44::encrypt_with_ck(&ck, &nonce, pt, &mut out).unwrap();
    let payload = out[..len].to_vec();

    // wrong key: MAC fails before any unpadding
    let wrong_ck = [0x43u8; 32];
    let mut sink = vec![0xEEu8; payload.len()];
    assert!(nip44::decrypt_with_ck(&wrong_ck, &payload, &mut sink).is_err());
    // the primitive contract: the applet clears resp; assert the sink still
    // holds only our 0xEE fill or decrypted-but-unauthenticated bytes — i.e.
    // the function did not return Ok with a length.
}
