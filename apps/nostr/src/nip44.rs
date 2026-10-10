//! NIP-44 v2 (design §2.5, §2.2.2) — ported from the spike's measured
//! implementation (`spike-secp256kfun/src/lib.rs`, US-1632/US-1633) with the
//! vectors that prove it (`vectors/nip44.vectors.json`, the checksum NIP-44
//! itself publishes). Byte shapes follow `vectors/reference-nip44.ts` exactly.
//!
//! The module is the **primitive layer**: bounds are the spec's
//! (1..=65535), the callers are the tests and the command arms in `lib.rs`.
//! The command layer applies the applet's own cap (`MAX_PLAINTEXT`,
//! §2.2.1) on top — the primitive must stay spec-faithful so the reference
//! vectors run unmodified, and the applet's cap is a *wire* decision, not a
//! crypto one.

#![allow(non_snake_case)]

use hmac::{Hmac, Mac};
use secp256kfun::{
    marker::{EvenY, NonZero, Public, Secret},
    op, Point, Scalar,
};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Every refusal the primitives can produce. The statuses the applet maps
/// these to (§2.2.0) live in the command arms, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Secret key is zero or ≥ curve order.
    InvalidSecretKey,
    /// Peer x is not a valid non-zero curve point.
    InvalidPeerX,
    /// Plaintext length outside 1..=65535.
    InvalidMessageLen,
    /// Payload malformed: bad version, bad length, bad prefix, bad padding.
    InvalidPayload,
    /// MAC mismatch or unpad mismatch after MAC — decryption failed.
    DecryptionFailed,
}

/// NIP-44 v2 bounds (`u.minPlaintextSize` / `u.maxPlaintextSize`).
pub const MIN_PLAINTEXT: u64 = 1;
pub const MAX_PLAINTEXT: u64 = 65_535;
/// `version(1) + nonce(32) + ct(2 + 65536) + mac(32)` — the largest payload.
pub const MAX_PAYLOAD: usize = 65_603;
/// `version(1) + nonce(32) + ct(2 + 32) + mac(32)` — the smallest payload.
pub const MIN_PAYLOAD: usize = 99;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HKDF-Expand (RFC 5869) into `okm`; `okm.len() ≤ 255 * 32`.
fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) {
    let mut t = [0u8; 32];
    let mut first = true;
    for (counter, chunk) in (1u8..).zip(okm.chunks_mut(32)) {
        let mut mac = HmacSha256::new_from_slice(prk).expect("hmac accepts any key length");
        if !first {
            mac.update(&t);
        }
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().into();
        chunk.copy_from_slice(&t[..chunk.len()]);
        first = false;
    }
}

fn mul_norm<S1, T2, S2>(
    s: &Scalar<S1, NonZero>,
    p: &Point<T2, S2, NonZero>,
) -> Option<Point<secp256kfun::marker::Normal, Public, NonZero>> {
    op::scalar_mul_point(s, p).normalize().non_zero()
}

/// Lift an x-only key to the EvenY point it names — the **validation**
/// US-1656 demands before any scalar multiplication. `None` for zero and
/// for an x that is not on the curve; secp256k1 is cofactor 1, so there is
/// no low-order point *between* those two and the identity (which has no
/// x-coordinate) — lifting is the whole check.
pub fn lift_xonly(x: &[u8; 32]) -> Option<Point<EvenY, Public, NonZero>> {
    Point::<EvenY, Public, NonZero>::from_xonly_bytes(*x)
}

/// NIP-44 v2 conversation key: `HMAC-SHA256(key = x(a·B), msg = "nip44-v2")`,
/// `a·B` lifted from the **x-only** peer key with y assumed even. The x fed to
/// the HMAC is the **raw coordinate** of the shared point — the §2.5 pin.
pub fn conversation_key(sk: &[u8; 32], peer_x: &[u8; 32]) -> Result<[u8; 32], Error> {
    let B = lift_xonly(peer_x).ok_or(Error::InvalidPeerX)?;
    let a = Scalar::<Secret, NonZero>::from_bytes(*sk).ok_or(Error::InvalidSecretKey)?;
    // a·B ≠ ∞ for a ≠ 0 and B on the curve, but the marker makes us say so.
    let shared = mul_norm(&a, &B).ok_or(Error::InvalidPeerX)?;
    // The raw, unhashed x coordinate — verified against the vectors: some
    // libraries hash this leg, secp256kfun's `coordinates()` does not.
    let x = shared.coordinates().0;
    Ok(hmac_sha256(b"nip44-v2", &x))
}

/// The three derived keys from NIP-44 v2 `getMessageKeys`:
/// `HKDF-expand(SHA256, prk = ck, info = nonce, L = 76)`.
#[derive(Clone, Copy)]
pub struct MessageKeys {
    pub chacha_key: [u8; 32],
    pub chacha_nonce: [u8; 12],
    pub hmac_key: [u8; 32],
}

pub fn message_keys(ck: &[u8; 32], nonce: &[u8; 32]) -> MessageKeys {
    let mut okm = [0u8; 76];
    hkdf_expand(ck, nonce, &mut okm);
    let mut chacha_key = [0u8; 32];
    chacha_key.copy_from_slice(&okm[..32]);
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce.copy_from_slice(&okm[32..44]);
    let mut hmac_key = [0u8; 32];
    hmac_key.copy_from_slice(&okm[44..76]);
    MessageKeys {
        chacha_key,
        chacha_nonce,
        hmac_key,
    }
}

/// NIP-44 v2 `calcPaddedLen`. `None` at `len == 0` — the input is invalid
/// there, and the expression must not be evaluated (`log2(0)`; the release
/// profile is `panic = "abort"`, so a literal transcription would reboot
/// the device on a one-byte plaintext — US-1653).
pub fn calc_padded_len(len: u64) -> Option<u64> {
    if len == 0 {
        // Never evaluated: the release profile is panic = "abort", and a
        // one-byte plaintext must not reboot the device (US-1653).
        return None;
    }
    if len <= 32 {
        return Some(32);
    }
    let v = len - 1; // ≥ 32 here, so the log2 below is well-defined
    let next_power = 1u64 << (63 - v.leading_zeros() + 1);
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    Some(chunk * ((len - 1) / chunk + 1))
}

/// NIP-44 v2 encrypt with the conversation key given directly:
/// `0x02 ‖ nonce(32) ‖ ciphertext ‖ mac(32)` written into `out`.
/// Returns the payload length. `out` needs [`MAX_PAYLOAD`] bytes for the
/// largest legal plaintext.
pub fn encrypt_with_ck(
    ck: &[u8; 32],
    nonce: &[u8; 32],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = plaintext.len() as u64;
    if !(MIN_PLAINTEXT..=MAX_PLAINTEXT).contains(&n) {
        return Err(Error::InvalidMessageLen);
    }
    let padded_len = calc_padded_len(n).ok_or(Error::InvalidMessageLen)? as usize;
    // The reference's `pad()` returns prefix ‖ plaintext ‖ suffix, and the
    // WHOLE of it is the ciphertext: ct_len = 2 + calc_padded_len(n).
    let ct_len = 2 + padded_len;
    let total = 33 + ct_len + 32;
    if out.len() < total {
        return Err(Error::InvalidMessageLen);
    }
    let keys = message_keys(ck, nonce);

    out[0] = 0x02;
    out[1..33].copy_from_slice(nonce);
    // padded plaintext: 2-byte BE unpadded length ‖ plaintext ‖ zero suffix.
    let (n_hi, n_lo) = (((n >> 8) & 0xff) as u8, (n & 0xff) as u8);
    out[33] = n_hi;
    out[34] = n_lo;
    out[35..35 + plaintext.len()].copy_from_slice(plaintext);
    let zeros_start = 35 + plaintext.len();
    let padded_end = 33 + ct_len;
    if zeros_start < padded_end {
        for b in &mut out[zeros_start..padded_end] {
            *b = 0;
        }
    }
    // ChaCha20 in place over prefix ‖ plaintext ‖ suffix.
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    let mut cipher =
        chacha20::ChaCha20::new(&keys.chacha_key.into(), &keys.chacha_nonce.into());
    cipher.apply_keystream(&mut out[33..33 + ct_len]);

    // mac = HMAC-SHA256(hmac_key, nonce ‖ ciphertext) — the AAD is the nonce.
    let mut mac = HmacSha256::new_from_slice(&keys.hmac_key).expect("hmac accepts any key length");
    mac.update(nonce);
    mac.update(&out[33..33 + ct_len]);
    out[33 + ct_len..total].copy_from_slice(&mac.finalize().into_bytes());
    Ok(total)
}

/// NIP-44 v2 decrypt with the conversation key given directly: `payload` is
/// `0x02 ‖ nonce(32) ‖ ciphertext ‖ mac(32)`; the unpadded plaintext is
/// written at the start of `out` and its length returned. The MAC is checked
/// **constant-time** (`verify_slice`, never `==`) before any unpadding.
pub fn decrypt_with_ck(
    ck: &[u8; 32],
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if payload.len() < MIN_PAYLOAD || payload.len() > MAX_PAYLOAD {
        return Err(Error::InvalidPayload);
    }
    if payload[0] != 0x02 {
        // Every non-2 version byte is refused explicitly — a payload whose
        // first bytes are zero is never mis-parsed as a longer form.
        return Err(Error::InvalidPayload);
    }
    let nonce: [u8; 32] = payload[1..33].try_into().expect("32-byte nonce slice");
    let ct_len = payload.len() - 65;
    let keys = message_keys(ck, &nonce);

    // MAC first, constant-time (`hmac::Mac::verify_slice`), before any
    // length/padding parsing — the step the spec's vectors cannot police.
    let mut mac = HmacSha256::new_from_slice(&keys.hmac_key).expect("hmac accepts any key length");
    mac.update(&nonce);
    mac.update(&payload[33..33 + ct_len]);
    if mac.verify_slice(&payload[33 + ct_len..]).is_err() {
        return Err(Error::DecryptionFailed);
    }

    if out.len() < ct_len {
        return Err(Error::InvalidPayload);
    }
    out[..ct_len].copy_from_slice(&payload[33..33 + ct_len]);
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    let mut cipher =
        chacha20::ChaCha20::new(&keys.chacha_key.into(), &keys.chacha_nonce.into());
    cipher.apply_keystream(&mut out[..ct_len]);

    // Unpad validation before any slicing: the 2-byte BE prefix is the only
    // length form — a first byte pair of 00 00 reads unpadded_len == 0 and is
    // rejected below; the 6-byte (u32) prefix form is unreachable under the
    // applet's wire cap and is refused as a plain length mismatch here.
    let unpadded_len = ((out[0] as usize) << 8) | out[1] as usize;
    if !(MIN_PLAINTEXT as usize..=MAX_PLAINTEXT as usize).contains(&unpadded_len) {
        return Err(Error::InvalidPayload);
    }
    let expected = calc_padded_len(unpadded_len as u64).ok_or(Error::InvalidPayload)? as usize;
    if ct_len != 2 + expected {
        return Err(Error::InvalidPayload);
    }
    // The unpadded plaintext is promised at the start of `out`; it sits at
    // offset 2 inside the decrypted padded region — move it forward.
    out.copy_within(2..2 + unpadded_len, 0);
    Ok(unpadded_len)
}
