//! Vendor vault protocol (CTAPHID vendor 0x41 / 0x05 subcommands).
//!
//! Wire contract (tests/pico-fido/test_080_vault.py):
//! - status:        `{1: vault_id or b""}`
//! - enroll begin:  `{1: device_public(X448, 56), 2: challenge(32)}`
//! - enroll finish: packet = cert_len(BE16) ‖ cert ‖ nonce(12) ‖ AESGCM ct,
//!   plain = kvault(32) ‖ label_len ‖ label; success `{1: vault_id}`
//! - unenroll: clears the vault.

#[cfg(feature = "host")]
use crate::cbor::{self, Value};
use crate::crypto;
use aes_gcm::aead::generic_array::GenericArray;
#[cfg(feature = "host")]
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Digest;

pub const VAULT_ID_DOMAIN: &[u8] = b"PicoKeys Vault ID v1";
pub const ENROLL_INFO: &[u8] = b"PicoKeys Vault enrollment v1";
pub const VAULT_ID_BYTES: usize = 32;
pub const ENROLL_CHALLENGE_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;

/// Derive the stable 256-bit vault identifier from the raw vault key.
pub fn vault_id(kvault: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(VAULT_ID_DOMAIN);
    h.update(kvault);
    h.finalize().into()
}

/// Session key for the enrollment packet:
/// HKDF-SHA256(salt=None, info=ENROLL_INFO ‖ challenge ‖ cert_public ‖ device_public).
pub fn enrollment_session_key(
    shared: &[u8],
    challenge: &[u8],
    cert_public: &[u8],
    device_public: &[u8],
) -> [u8; 32] {
    let hk = Hkdf::<sha2::Sha256>::new(None, shared);
    // fapico2 no_std patch: bounded heapless info buffer (16 + 32 + 56 + 56).
    let mut info = heapless::Vec::<u8, 192>::new();
    let _ = info.extend_from_slice(ENROLL_INFO);
    let _ = info.extend_from_slice(challenge);
    let _ = info.extend_from_slice(cert_public);
    let _ = info.extend_from_slice(device_public);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("32-byte OKM always fits");
    okm
}

/// Decrypt the enrollment packet body **in place** (no-heap device path,
/// S-701-5). `body` = ciphertext || tag; on success the plaintext (kvault ||
/// label_len || label) replaces it and its length is returned.
pub fn decrypt_enrollment_packet_in_place(
    session_key: &[u8; 32],
    nonce: &[u8; 12],
    body: &mut heapless::Vec<u8, 128>,
    aad: &[u8],
) -> Option<usize> {
    use aes_gcm::aead::AeadInPlace;
    let cipher = Aes256Gcm::new_from_slice(session_key).ok()?;
    let ct_len = body.len() - 16;
    let (ct, tag) = body.split_at_mut(ct_len);
    let tag_arr = GenericArray::from_slice(tag);
    let nonce_arr = GenericArray::from_slice(nonce);
    cipher
        .decrypt_in_place_detached(nonce_arr, aad, ct, tag_arr)
        .ok()?;
    Some(ct_len)
}

/// Decrypt the enrollment packet body. Returns (kvault, label).
#[cfg(feature = "host")]
pub fn decrypt_enrollment_packet(
    session_key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(session_key).ok()?;
    if ciphertext.len() < 16 {
        return None;
    }
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            &mut buf,
            GenericArray::from_slice(tag),
        )
        .ok()?;
    let plain = &buf[..];
    if plain.len() < VAULT_ID_BYTES + 1 {
        return None;
    }
    let kvault = plain[..VAULT_ID_BYTES].to_vec();
    let label_len = plain[VAULT_ID_BYTES] as usize;
    if plain.len() < VAULT_ID_BYTES + 1 + label_len {
        return None;
    }
    let label = plain[VAULT_ID_BYTES + 1..VAULT_ID_BYTES + 1 + label_len].to_vec();
    Some((kvault, label))
}

/// Heuristic SubjectPublicKeyInfo extraction: find the last BIT STRING
/// carrying a 56-byte (X448) public key in a DER certificate.
pub fn x448_public_from_cert(cert: &[u8]) -> Option<[u8; 56]> {
    let mut found = None;
    let mut i = 0;
    while i + 2 <= cert.len() {
        if cert[i] == 0x03 {
            // BIT STRING: short or long-form length.
            let (len, hdr) = match cert[i + 1] {
                l if l & 0x80 == 0 => (l as usize, 2),
                0x81 => {
                    if i + 3 > cert.len() {
                        break;
                    }
                    (cert[i + 2] as usize, 3)
                }
                0x82 => {
                    if i + 4 > cert.len() {
                        break;
                    }
                    (u16::from_be_bytes([cert[i + 2], cert[i + 3]]) as usize, 4)
                }
                _ => break,
            };
            if i + hdr + len <= cert.len() && len == 57 && cert[i + hdr] == 0 {
                let mut key = [0u8; 56];
                key.copy_from_slice(&cert[i + hdr + 1..i + hdr + 57]);
                found = Some(key);
            }
            i += hdr + len;
        } else {
            i += 1;
        }
    }
    found
}

/// Encode a successful vendor response: status byte 0 plus the CBOR map.
#[cfg(feature = "host")]
pub fn ok_response(map: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&cbor::encode(&Value::M(map)));
    out
}

/// The pinUvAuth message for vault vendor commands:
/// 0xff*32 ‖ 0x0d ‖ subcommand ‖ raw_params.
#[cfg(feature = "host")]
pub fn auth_message(subcommand: u8, raw_params: &[u8]) -> Vec<u8> {
    let mut msg = vec![0xffu8; 32];
    msg.push(0x0d);
    msg.push(subcommand);
    msg.extend_from_slice(raw_params);
    msg
}

/// SHA-256 helper re-exported for callers without sha2 in scope.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    crypto::sha256(data)
}
