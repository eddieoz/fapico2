//! US-1633: the reference vectors run through the spike's host implementation.
//!
//! Passing `CONV_KEY_VECTORS` through [`nostr_secp_spike::conversation_key`] is
//! also the §2.5 pin: NIP-44 needs the **unhashed** x of the shared point
//! `a·B`, and these vectors prove `secp256kfun`'s
//! `op::scalar_mul_point(..).normalize().coordinates().0` yields exactly that —
//! the raw coordinate, never a hash of it.

use nostr_secp_spike::{
    bip340_sign, bip340_verify, calc_padded_len, conversation_key, decrypt_with_ck,
    encrypt_with_ck, message_keys, vectors_gen::*, xonly_pubkey, Error,
};
use sha2::{Digest, Sha256};

fn buf() -> Vec<u8> {
    vec![0u8; 65_603]
}

/// Minimal RFC 4648 base64 (standard alphabet, padded) for the long-msg
/// anchors, which the official vectors take over the compressed payload.
fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        s.push(T[(b[0] >> 2) as usize] as char);
        s.push(T[(((b[0] & 3) << 4) | (b[1] >> 4)) as usize] as char);
        s.push(if c.len() > 1 { T[(((b[1] & 15) << 2) | (b[2] >> 6)) as usize] as char } else { '=' });
        s.push(if c.len() > 2 { T[(b[2] & 63) as usize] as char } else { '=' });
    }
    s
}

#[test]
fn bip340_reference_vectors() {
    for v in BIP340_VECTORS {
        // Derive the x-only key whenever the row's public key is absent
        // (the verification-failure rows carry an implicit key).
        let pk = match v.pk {
            Some(pk) => pk,
            None => xonly_pubkey(v.sk.as_ref().unwrap()).unwrap(),
        };
        if let (Some(sk), Some(sig)) = (v.sk, v.sig) {
            let got = bip340_sign(&sk, v.msg, &v.aux.unwrap())
                .unwrap_or_else(|e| panic!("vector {} sign failed: {e:?}", v.index));
            assert_eq!(got, sig, "vector {} signature mismatch", v.index);
        }
        if let Some(expected) = v.verify_ok {
            let sig = v.sig.expect("verify rows carry a signature");
            match bip340_verify(&pk, v.msg, &sig) {
                Ok(actual) => assert_eq!(actual, expected, "vector {} verify mismatch", v.index),
                // The refusal rows include public keys that are not on the
                // curve (rows 5 and 14); lifting them fails, which is the
                // "did not verify" reading those rows demand.
                Err(_) => assert!(!expected, "vector {} must not verify", v.index),
            }
        }
    }
}

#[test]
fn nip44_conversation_key_vectors() {
    for v in CONV_KEY_VECTORS {
        assert_eq!(
            conversation_key(&v.sk, &v.peer_x).unwrap(),
            v.ck,
            "conversation key mismatch"
        );
    }
}

/// The §2.5 pin, stated as a test: the shared-point x that reaches the HMAC is
/// the raw coordinate. If a future `secp256kfun` changed `coordinates()` (or
/// someone swapped it for a hashing accessor) the valid vectors fail here.
#[test]
fn conversation_key_uses_unhashed_shared_x() {
    // Proven by every CONV_KEY_VECTORS row passing; the loop below is the
    // explicit statement of that proof.
    assert!(!CONV_KEY_VECTORS.is_empty());
    for v in CONV_KEY_VECTORS {
        let ck = conversation_key(&v.sk, &v.peer_x).expect("valid vector");
        assert_eq!(ck, v.ck);
    }
}

#[test]
fn nip44_conversation_key_invalid_refused() {
    for v in CONV_KEY_INVALID {
        let r = conversation_key(&v.sk, &v.peer_x);
        assert_eq!(r, Err(Error::InvalidPeerX), "note: {}", v.note);
    }
}

#[test]
fn nip44_message_keys_vectors() {
    for v in MESSAGE_KEYS_VECTORS {
        let k = message_keys(&MESSAGE_KEYS_CK, &v.nonce);
        assert_eq!(k.chacha_key, v.chacha_key);
        assert_eq!(k.chacha_nonce, v.chacha_nonce);
        assert_eq!(k.hmac_key, v.hmac_key);
    }
}

/// US-1653's `calc_padded_len_edges` at the primitive layer: the reference
/// pairs, plus the `len == 1` edge (`log2(0)` must never be evaluated) and
/// `len == 0` returning `None`.
#[test]
fn calc_padded_len_edges() {
    for (a, b) in CALC_PADDED_LEN_VECTORS {
        assert_eq!(calc_padded_len(*a), Some(*b), "calc_padded_len({a})");
    }
    assert_eq!(calc_padded_len(1), Some(32));
    assert_eq!(calc_padded_len(32), Some(32));
    assert_eq!(calc_padded_len(0), None);
}

#[test]
fn nip44_encrypt_matches_reference_payloads() {
    for v in ENCRYPT_DECRYPT_VECTORS {
        // The ECDH leg agrees first.
        assert_eq!(
            conversation_key(&v.sk, &v.peer_x).unwrap(),
            v.ck,
            "conversation key cross-check"
        );
        let mut out = buf();
        let n = encrypt_with_ck(&v.ck, &v.nonce, v.plaintext, &mut out).unwrap();
        assert_eq!(&out[..n], v.payload, "payload mismatch");
        // Round-trip.
        let mut pt = buf();
        let m = decrypt_with_ck(&v.ck, &out[..n], &mut pt).unwrap();
        assert_eq!(&pt[..m], v.plaintext);
    }
}

#[test]
fn nip44_decrypt_invalid_refused() {
    let mut out = buf();
    for v in DECRYPT_INVALID {
        assert!(
            decrypt_with_ck(&v.ck, v.payload, &mut out).is_err(),
            "note: {}",
            v.note
        );
    }
}

#[test]
fn nip44_long_msg_vectors() {
    for v in LONG_MSG_VECTORS {
        let mut plaintext = Vec::with_capacity(v.pattern.len() * v.repeat as usize);
        for _ in 0..v.repeat {
            plaintext.extend_from_slice(v.pattern);
        }
        assert_eq!(Sha256::digest(&plaintext)[..], v.plaintext_sha256[..]);
        let mut out = buf();
        let n = encrypt_with_ck(&v.ck, &v.nonce, &plaintext, &mut out).unwrap();
        // The official anchors are over the COMPRESSED (base64) payload —
        // the same form a NIP-44 client transmits — not the raw bytes.
        assert_eq!(
            Sha256::digest(b64(&out[..n]).as_bytes())[..],
            v.payload_sha256[..]
        );
    }
}

#[test]
fn nip44_encrypt_forbidden_lengths_refused() {
    let mut out = buf();
    for n in ENCRYPT_FORBIDDEN_LEN {
        let n = *n as usize;
        let plaintext = vec![b'x'; n];
        assert_eq!(
            encrypt_with_ck(&[0u8; 32], &[1u8; 32], &plaintext, &mut out),
            Err(Error::InvalidMessageLen),
            "length {n} must be refused"
        );
    }
}
