//! PIV crypto primitives.
//!
//! Ported from `pico-keys-sdk/src/crypto_utils.c` (PIN derivation chain) and
//! `pico-openpgp/src/openpgp/piv.c` (`mgm_crypt`), both GPLv3.
//!
//! The HKDF argument order mirrors the C `mbedtls_hkdf(md, salt, salt_len,
//! ikm, ikm_len, info, info_len, okm, okm_len)` calls exactly, including the
//! byte lengths the C source passes for the info strings (`"DEVICE/ROOT"` is
//! passed as 12 bytes, i.e. NUL-terminated; `"PIN/VERIFY"`/`"PIN/TOKEN"` as
//! 10/9 bytes without NUL).

use aes::{Aes128, Aes192, Aes256};
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};
use des::TdesEde3;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{PIV_ALGO_3DES, PIV_ALGO_AES128, PIV_ALGO_AES192, PIV_ALGO_AES256};

type HmacSha256 = Hmac<Sha256>;

/// 8-byte emulation serial ID: the top four bytes are the dev serial
/// `0x31323334` reported by GET SERIAL (0xF8); the C host build derives the
/// equivalent from the board/DMI ID, the device build will use the RP2350
/// board ID. It is the root of the PIN derivation chain.
pub const SERIAL_ID: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00, 0x00];

/// C `derive_kbase` (no-OTP branch):
/// HKDF-SHA256(salt="NO-OTP", ikm=SHA256(serial_id), info="DEVICE/ROOT\0", 32).
fn derive_kbase() -> [u8; 32] {
    hkdf_expand(Some(b"NO-OTP"), &Sha256::digest(SERIAL_ID), b"DEVICE/ROOT\0")
}

fn hkdf_expand(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut okm)
        .expect("hkdf: output length 32 is valid");
    okm
}

/// C `pin_derive_verifier`:
/// kver = HMAC-SHA256(kbase, pin);
/// verifier = HKDF(salt=SHA256(serial_id), ikm=kver, info="PIN/VERIFY", 32).
pub fn pin_derive_verifier(pin: &[u8]) -> [u8; 32] {
    let kver = derive_kver(pin);
    hkdf_expand(Some(&Sha256::digest(SERIAL_ID)), &kver, b"PIN/VERIFY")
}

/// C `pin_derive_session` (same chain, info="PIN/TOKEN").
pub fn pin_derive_session(pin: &[u8]) -> [u8; 32] {
    let kver = derive_kver(pin);
    hkdf_expand(Some(&Sha256::digest(SERIAL_ID)), &kver, b"PIN/TOKEN")
}

fn derive_kver(pin: &[u8]) -> [u8; 32] {
    // `KeyInit` and `Mac` both provide `new_from_slice`; be explicit.
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&derive_kbase()).expect("hmac: 32-byte key");
    mac.update(pin);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// C `mgm_crypt`: AES-128/192/256 or 3-key 3DES, single-block ECB.
/// `None` when the key length does not fit the algorithm or the input is not
/// one block (C returns a non-zero error in that case).
pub fn mgm_crypt(algo: u8, key: &[u8], input: &[u8], encrypt: bool) -> Option<Vec<u8>> {
    match algo {
        PIV_ALGO_3DES => block_crypt::<TdesEde3>(key, input, encrypt, 8),
        PIV_ALGO_AES128 => block_crypt::<Aes128>(key, input, encrypt, 16),
        PIV_ALGO_AES192 => block_crypt::<Aes192>(key, input, encrypt, 16),
        PIV_ALGO_AES256 => block_crypt::<Aes256>(key, input, encrypt, 16),
        _ => None,
    }
}

/// Single-block ECB encrypt/decrypt for one of the mgm key ciphers.
fn block_crypt<C: BlockEncryptMut + BlockDecryptMut + KeyInit>(
    key: &[u8],
    input: &[u8],
    encrypt: bool,
    block_len: usize,
) -> Option<Vec<u8>> {
    if input.len() != block_len {
        return None;
    }
    let mut cipher = C::new_from_slice(key).ok()?;
    // `from_slice` borrows `input`; take an owned block (u8 arrays are Copy).
    let mut block = Block::<C>::from_slice(input).clone();
    if encrypt {
        cipher.encrypt_block_mut(&mut block);
    } else {
        cipher.decrypt_block_mut(&mut block);
    }
    Some(block.to_vec())
}

/// Constant-time equality (C `mbedtls_ct_memcmp`).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin8(s: &str) -> [u8; 8] {
        let mut w = [0xFFu8; 8];
        let b = s.as_bytes();
        let n = b.len().min(8);
        w[..n].copy_from_slice(&b[..n]);
        w
    }

    /// AES-192 ECB single-block reference vector (key 000102...17), verified
    /// against both `openssl enc -aes-192-ecb -nopad` and Python
    /// `cryptography`.
    #[test]
    fn aes192_ecb_reference_vector() {
        let key: [u8; 24] = (0u8..24).collect::<Vec<u8>>().try_into().unwrap();
        let pt = hex("00112233445566778899aabbccddeeff");
        let ct = hex("dda97ca4864cdfe06eaf70a0ec0d7191");
        let enc = mgm_crypt(PIV_ALGO_AES192, &key, &pt, true).unwrap();
        assert_eq!(enc, ct);
        let dec = mgm_crypt(PIV_ALGO_AES192, &key, &enc, false).unwrap();
        assert_eq!(dec, pt);
    }

    /// AES-128/256 and 3DES round-trip, plus wrong-size rejection.
    #[test]
    fn mgm_crypt_roundtrips_and_rejects() {
        let k16: [u8; 16] = (1u8..=16).collect::<Vec<u8>>().try_into().unwrap();
        let k32: [u8; 32] = (1u8..=32).collect::<Vec<u8>>().try_into().unwrap();
        let k24: [u8; 24] = (1u8..=24).collect::<Vec<u8>>().try_into().unwrap();
        let block16 = [0x5Au8; 16];
        let block8 = [0x5Au8; 8];

        for (algo, key, block) in [
            (PIV_ALGO_AES128, &k16[..], &block16[..]),
            (PIV_ALGO_AES192, &k24[..], &block16[..]),
            (PIV_ALGO_AES256, &k32[..], &block16[..]),
            (PIV_ALGO_3DES, &k24[..], &block8[..]),
        ] {
            let enc = mgm_crypt(algo, key, block, true).unwrap();
            assert_ne!(enc, block.to_vec(), "{algo}: ciphertext equals plaintext");
            assert_eq!(mgm_crypt(algo, key, &enc, false).unwrap(), block.to_vec());
        }
        // 3DES is 8-byte blocks, AES is 16.
        assert!(mgm_crypt(PIV_ALGO_3DES, &k24, &block16, true).is_none());
        assert!(mgm_crypt(PIV_ALGO_AES192, &k24, &block8, true).is_none());
        // 16-byte key must not satisfy AES-192.
        assert!(mgm_crypt(PIV_ALGO_AES192, &k16, &block16, true).is_none());
        // Unknown algo.
        assert!(mgm_crypt(0x11, &k24, &block16, true).is_none());
    }

    /// C-chain golden values (computed against the `crypto_utils.c` formulas
    /// for the emulation serial ID and default PIN/PUK):
    ///   verifier = HKDF(serial_hash, HMAC(kbase, pin), "PIN/VERIFY").
    #[test]
    fn pin_verifier_matches_c_chain() {
        assert_eq!(
            pin_derive_verifier(&pin8("123456")).to_vec(),
            hex("37927510f5e7f2b0c05329b1a66d99cfab5dffd1020f932297471d383229777b")
        );
        assert_eq!(
            pin_derive_session(&pin8("123456")).to_vec(),
            hex("3f87ec917398b5f20a7d14792bb0942161639e845db525081c98c966e4f48ea0")
        );
        assert_eq!(
            pin_derive_verifier(&pin8("12345678")).to_vec(),
            hex("fbee51a8b41c361c45ceab0ff2d7111a3b841686b159a8f8e6debe80e91268f2")
        );
        // A different PIN yields a different verifier.
        assert_ne!(pin_derive_verifier(&pin8("000000")), pin_derive_verifier(&pin8("123456")));
    }

    #[test]
    fn ct_eq_detects_difference() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
