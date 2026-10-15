//! BIP-340 signing on secp256k1 (design §2.5) — ported from the spike's
//! measured implementation (`spike-secp256kfun/src/lib.rs`, US-1633/US-1634):
//! the same ops, the same no-alloc shape, `no_std` throughout.
//!
//! The two transcription traps the spike recorded are load-bearing here too:
//! **the aux is tag-hashed before the XOR** with the (parity-fixed) scalar,
//! and `d` is negated to even-y *before* the nonce derivation. The vector
//! suite (`tests/keymgmt.rs`) runs the reference rows through the APDU path,
//! so either regression fails the build rather than the user.
//!
//! The spike's `#![allow(non_snake_case)]` rides along: BIP-340's reference
//! names its points `P`/`R` and the port keeps the prose and the code in step.

#![allow(non_snake_case)]

use secp256kfun::{
    marker::{NonZero, Public, Secret, Zero},
    op, G, Point, Scalar,
};
use sha2::{Digest, Sha256};

/// `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data…)` — the BIP-340 tag hash.
fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The PIN verifier: `SHA256(salt ‖ pin)` — the OATH `PinRecord`
/// derivation (`oath_core.rs:823-828`), salt first, exactly the same byte
/// order. One derivation in one place: the applet's SET/CHANGE/VERIFY all
/// go through this, so a byte-order mistake is one mistake, not three.
pub fn pin_verifier(pin: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin);
    h.finalize().into()
}

fn mul_norm<S1, T2, S2>(
    s: &Scalar<S1, NonZero>,
    p: &Point<T2, S2, NonZero>,
) -> Option<Point<secp256kfun::marker::Normal, Public, NonZero>> {
    op::scalar_mul_point(s, p).normalize().non_zero()
}

/// A non-zero secret scalar below the curve order — the BIP-340 bounds on
/// `d'` for free: `from_bytes` rejects zero and `≥ n` alike. [`IMPORT_KEY`]
/// (`crate::INS_IMPORT_KEY`) applies this before anything is stored.
pub fn scalar_valid(scalar: &[u8; 32]) -> bool {
    Scalar::<Secret, NonZero>::from_bytes(*scalar).is_some()
}

/// The x-only public key of `d·G` — the BIP-340 `x()` (and the bytes an
/// `npub` encodes). `None` only for an invalid scalar; a valid `d` never
/// yields the identity.
pub fn xonly_pubkey(sk: &[u8; 32]) -> Option<[u8; 32]> {
    let d = Scalar::<Secret, NonZero>::from_bytes(*sk)?;
    Some(mul_norm(&d, G)?.coordinates().0)
}

/// BIP-340 signing: the 64-byte `(R.x ‖ s)` signature over the message (the
/// applet always passes the 32-byte sighash). `aux` is the randomness input;
/// the command path draws it from the applet's RNG source, the tests pin it
/// to the vector's `aux_rand`.
///
/// `None` on an invalid secret key, or on the spec's `k' = 0` refusal
/// (probability ~2⁻²⁵⁶).
pub fn bip340_sign(sk: &[u8; 32], msg: &[u8], aux: &[u8; 32]) -> Option<[u8; 64]> {
    // `from_bytes` returns None for 0 and for ≥ n — exactly BIP-340's bounds on d'.
    let d_orig = Scalar::<Secret, NonZero>::from_bytes(*sk)?;
    let P0 = mul_norm(&d_orig, G).expect("d·G is never the identity for d ≠ 0");
    // BIP-340: d = d' if has_even_y(d'·G), else n − d'. The x-only encoding
    // of P is the same either way, so px comes from P0.
    let mut d = d_orig;
    d.conditional_negate(!P0.is_y_even());
    let px = P0.coordinates().0;

    // t = bytes(d) ⊕ hashBIP0340/aux(aux), bytes(d) of the *negated* scalar.
    let d_bytes = d.to_bytes();
    let aux_t = tagged_hash(b"BIP0340/aux", &[aux]);
    let mut t = [0u8; 32];
    for i in 0..32 {
        t[i] = d_bytes[i] ^ aux_t[i];
    }
    let rand = tagged_hash(b"BIP0340/nonce", &[&t, &px, msg]);
    let k0 = Scalar::<Secret, Zero>::from_bytes_mod_order(rand);
    if k0.is_zero() {
        return None;
    }
    // Re-type the zero-checked scalar as NonZero (canonical bytes, k0 ≠ 0).
    let mut k = Scalar::<Secret, NonZero>::from_bytes(k0.to_bytes())?;
    let R = mul_norm(&k, G).expect("k·G is never the identity for k ≠ 0");
    k.conditional_negate(!R.is_y_even());

    let e_bytes = tagged_hash(b"BIP0340/challenge", &[&R.coordinates().0, &px, msg]);
    let e = Scalar::<Secret, Zero>::from_bytes_mod_order(e_bytes).set_secrecy::<Public>();
    let sig_s = secp256kfun::s!(k + e * d);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&R.coordinates().0);
    sig[32..].copy_from_slice(&sig_s.to_bytes());
    Some(sig)
}
