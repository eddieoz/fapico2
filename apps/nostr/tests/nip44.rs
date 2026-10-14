//! US-1653 — `calc_padded_len` and its `len == 1` edge; US-1654 — the NIP-44
//! v2 reference vectors through the applet's primitive layer.
//!
//! The vectors are the ones NIP-44 itself publishes
//! (`vectors/nip44.vectors.json`, sha256 269ed0f6…, carried verbatim from the
//! spike), so a passing suite is agreement with the reference implementation,
//! not self-consistency (design §2.7).
//!
//! The spike's proven pins ride along: the conversation key is HMAC over the
//! **unhashed** x of `a·B` (§2.5), and `calc_padded_len(0)` is `None` — the
//! expression is never evaluated there, because the release profile is
//! `panic = "abort"` and a one-byte plaintext would otherwise reboot the
//! device (§2.2.2).

#[allow(dead_code, non_upper_case_globals)]
mod vectors {
    include!("nip44_vectors.rs");
}

use fapico2_nostr::nip44::{
    calc_padded_len, conversation_key, decrypt_with_ck, encrypt_with_ck, message_keys, Error,
    MAX_PAYLOAD, MIN_PAYLOAD,
};
use sha2::{Digest, Sha256};
use vectors::*;

fn buf() -> Vec<u8> {
    vec![0u8; MAX_PAYLOAD]
}

/// US-1653's named test. The reference pairs come from the generated
/// vectors; the edges are stated here because the spec's pseudocode is
/// undefined at `len == 1` (`log2(0)`) and the release profile is
/// `panic = "abort"` — a literal transcription reboots the device on a
/// one-byte plaintext.
#[test]
fn calc_padded_len_edges() {
    for (a, b) in CALC_PADDED_LEN_VECTORS {
        assert_eq!(calc_padded_len(*a), Some(*b), "calc_padded_len({a})");
    }
    // The edges the story names: a one-byte plaintext pads to 32, a
    // 32-byte one does not grow — and nothing at all is evaluated at 0,
    // stated by `None` rather than by a panic or an overflow.
    assert_eq!(calc_padded_len(1), Some(32));
    assert_eq!(calc_padded_len(32), Some(32));
    assert_eq!(calc_padded_len(0), None);
}

/// The §2.5 pin, stated as a test: the shared-point x that reaches the HMAC
/// is the raw coordinate. The valid vectors passing IS that proof — some
/// libraries hash this leg, and any change to it fails here.
#[test]
fn conversation_key_vectors() {
    for v in CONV_KEY_VECTORS {
        assert_eq!(conversation_key(&v.sk, &v.peer_x).unwrap(), v.ck);
    }
}

#[test]
fn conversation_key_invalid_refused() {
    for v in CONV_KEY_INVALID {
        assert_eq!(
            conversation_key(&v.sk, &v.peer_x),
            Err(Error::InvalidPeerX),
            "{}",
            v.note
        );
    }
}

#[test]
fn message_keys_vectors() {
    for v in MESSAGE_KEYS_VECTORS {
        let k = message_keys(&MESSAGE_KEYS_CK, &v.nonce);
        assert_eq!(k.chacha_key, v.chacha_key);
        assert_eq!(k.chacha_nonce, v.chacha_nonce);
        assert_eq!(k.hmac_key, v.hmac_key);
    }
}

/// US-1654: the reference payloads reproduce byte-for-byte given the
/// vector's nonce — encrypt, round-trip, and the payload the reference
/// implementation produced.
#[test]
fn encrypt_matches_reference_payloads() {
    for v in ENCRYPT_DECRYPT_VECTORS {
        // The ECDH leg agrees first.
        assert_eq!(conversation_key(&v.sk, &v.peer_x).unwrap(), v.ck);
        let mut out = buf();
        let n = encrypt_with_ck(&v.ck, &v.nonce, v.plaintext, &mut out).unwrap();
        assert_eq!(&out[..n], v.payload, "payload mismatch");
        let mut pt = buf();
        let m = decrypt_with_ck(&v.ck, &out[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], v.plaintext);
    }
}

/// US-1654: the forbidden lengths are refused at the primitive — 0 below
/// the floor, ≥ 65536 above the ceiling.
#[test]
fn encrypt_forbidden_lengths_refused() {
    for len in ENCRYPT_FORBIDDEN_LEN {
        let mut out = buf();
        let plaintext = vec![0x61u8; *len as usize];
        assert_eq!(
            encrypt_with_ck(&CONV_KEY_VECTORS[0].ck, &[0u8; 32], &plaintext, &mut out),
            Err(Error::InvalidMessageLen),
            "len {len} must be refused"
        );
    }
}

#[test]
fn decrypt_invalid_refused() {
    let mut out = buf();
    for v in DECRYPT_INVALID {
        assert!(
            decrypt_with_ck(&v.ck, v.payload, &mut out).is_err(),
            "{}",
            v.note
        );
    }
}

/// The official long-message anchors are over the COMPRESSED (base64)
/// payload a NIP-44 client transmits, not the raw bytes — base64 the raw
/// payload before hashing (the same `b64` shape the spike used).
fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        s.push(T[(b[0] >> 2) as usize] as char);
        s.push(T[(((b[0] & 3) << 4) | (b[1] >> 4)) as usize] as char);
        s.push(if c.len() > 1 {
            T[(((b[1] & 15) << 2) | (b[2] >> 6)) as usize] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[(b[2] & 63) as usize] as char
        } else {
            '='
        });
    }
    s
}

#[test]
fn long_msg_vectors() {
    for v in LONG_MSG_VECTORS {
        let mut plaintext = Vec::with_capacity(v.pattern.len() * v.repeat as usize);
        for _ in 0..v.repeat {
            plaintext.extend_from_slice(v.pattern);
        }
        assert_eq!(Sha256::digest(&plaintext)[..], v.plaintext_sha256[..]);
        let mut out = buf();
        let n = encrypt_with_ck(&v.ck, &v.nonce, &plaintext, &mut out).unwrap();
        assert_eq!(
            Sha256::digest(b64(&out[..n]).as_bytes())[..],
            v.payload_sha256[..],
        );
        let mut pt = buf();
        let m = decrypt_with_ck(&v.ck, &out[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], &plaintext[..]);
    }
}

/// US-1654: the payload floor the spec states — 99 bytes for the smallest
/// legal plaintext — is enforced at the primitive, and the story's
/// "decoded payload under the 99-byte floor is rejected" rides it.
#[test]
fn payload_bounds_enforced() {
    assert_eq!(MIN_PAYLOAD, 99);
    let ck = CONV_KEY_VECTORS[0].ck;
    let mut out = buf();
    let n = encrypt_with_ck(&ck, &[0u8; 32], b"a", &mut out).unwrap();
    // Truncate below the floor: every short payload is refused, not parsed.
    for short in 0..99.min(n) {
        let mut pt = buf();
        assert!(decrypt_with_ck(&ck, &out[..short], &mut pt).is_err());
    }
    // And the honest payload decrypts.
    let mut pt = buf();
    assert_eq!(decrypt_with_ck(&ck, &out[..n], &mut pt).unwrap(), 1);
}
