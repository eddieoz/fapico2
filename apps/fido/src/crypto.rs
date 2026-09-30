//! Cryptographic primitives for fapico2-fido.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
#[cfg(feature = "host")]
use cbc::cipher::block_padding::NoPadding;
// The RFC 8439 AEAD, non-optional: unlike the host-gated primitives below it
// the device's `0x41` channel needs it, so it is not behind a feature. Only
// `KeyInit` is pulled in at the top level — `AeadInPlace` is imported inside
// the three functions that use it, so the two names sit next to the call they
// belong to rather than in a prelude nobody reads.
use chacha20poly1305::KeyInit;
use fapico2_platform::trng::{Trng, RNG_ERR_RESEED_REFUSED};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    PublicKey, SecretKey,
};

/// The `rand_core` error a refused entropy draw reports, as
/// [`RNG_ERR_RESEED_REFUSED`].
///
/// `rand_core::Error` has no public `from_code`; the documented constructor
/// in the 0.6 line is the `From<NonZeroU32>` impl, which is what
/// `platform::trusted_backend::device` does for the same two codes. The
/// `expect` is unreachable: the constant is `CUSTOM_START`, non-zero by
/// construction, and it is a `const`, not a runtime value.
fn _refused_err() -> rand_core::Error {
    rand_core::Error::from(
        core::num::NonZeroU32::new(RNG_ERR_RESEED_REFUSED)
            .expect("CUSTOM_START is non-zero by construction"),
    )
}

type HmacSha256 = Hmac<Sha256>;

/// Bridge exposing the platform TRNG as a `rand_core` RNG so the curve crates'
/// `::random(&mut rng)` constructors keep working while every byte of entropy
/// still comes from the platform TRNG (US-380) — never a software PRNG.
/// `rand_core` is the traits-only crate; it carries no RNG implementation.
/// Host-only: on device the [`TrngAdapter`] wraps the handed-in [`Trng`].
#[cfg(feature = "host")]
#[derive(Debug, Default, Clone, Copy)]
pub struct TrngRng;

#[cfg(feature = "host")]
impl rand_core::RngCore for TrngRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(fapico2_platform::trng::random_bytes::<4>())
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(fapico2_platform::trng::random_bytes::<8>())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fapico2_platform::trng::random_bytes_into(dest);
    }
    /// US-1007: mirrors [`TrngAdapter::try_fill_bytes`] — this was
    /// `Ok(())` unconditionally, which reported a starved draw as fresh
    /// bytes. It is the host half of the same defect, and the reason the
    /// twin's FIDO leg was reproducible at all. The host twin's boot path
    /// (`FidoApp::with_keystore`) still calls
    /// [`generate_p256_keypair`], which uses the infallible sampler; the
    /// request path uses [`try_generate_p256_keypair`] and is bounded.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fapico2_platform::trng::try_random_bytes_into(dest)
            .map_err(|_| _refused_err())
    }
}
#[cfg(feature = "host")]
impl rand_core::CryptoRng for TrngRng {}

/// Derive a key using HKDF-SHA256.
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info, okm).expect("HKDF expand failed");
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Generate random bytes from the platform TRNG (US-380). The sole randomness
/// source: RP2350 hardware TRNG on device, OS entropy on host. Host-only
/// convenience (device hands the [`Trng`] in explicitly).
#[cfg(feature = "host")]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    fapico2_platform::trng::random_bytes::<N>()
}

#[cfg(feature = "host")]
/// Generate a vector of random bytes from the platform TRNG (US-380).
pub fn random_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    fapico2_platform::trng::random_bytes_into(&mut buf);
    buf
}

#[cfg(feature = "host")]
/// AES-256-CBC encrypt with NoPadding (data must be block-aligned).
pub fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    let mut buf = data.to_vec();
    let ct = Aes256CbcEnc::new_from_slices(key, iv).expect("key/iv length");
    ct.encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
        .expect("NoPadding encrypt (data must be block-aligned)");
    buf
}

#[cfg(feature = "host")]
/// AES-256-CBC decrypt with NoPadding (data must be block-aligned).
pub fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    let mut buf = data.to_vec();
    let ct = Aes256CbcDec::new_from_slices(key, iv).expect("key/iv length");
    ct.decrypt_padded_mut::<NoPadding>(&mut buf).ok()?;
    Some(buf)
}

#[cfg(feature = "host")]
/// Derive the AES-256-CBC encrypt/decrypt with PKCS7 padding (legacy, still used
/// by non-PIN code paths). Kept for backward compatibility.
pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    let mut buf = data.to_vec();
    let ct = Aes256CbcEnc::new_from_slices(key, iv).expect("key/iv length");
    ct.encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf, data.len())
        .expect("PKCS7 encrypt");
    buf
}

#[cfg(feature = "host")]
/// AES-256-CBC decrypt with PKCS7 padding (legacy).
pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    let mut buf = data.to_vec();
    let ct = Aes256CbcDec::new_from_slices(key, iv).expect("key/iv length");
    ct.decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf).ok()?;
    Some(buf)
}

/// Generate a P-256 key pair from the platform TRNG (US-380). The sole
/// randomness source: `SecretKey::random` draws through [`TrngRng`].
///
/// # This one cannot fail, and a caller that needs to know must not use it
///
/// `SecretKey::random` is a *rejection sampler* over an [`RngCore`] it cannot
/// make fail: it draws 32 bytes and retries while the scalar is zero or
/// at or above n. Paired with an RNG whose `try_fill_bytes` always returns
/// `Ok`, a source that has stopped producing turns that into an **unbounded
/// loop** —
/// every draw is the same untouched buffer, so the rejection never resolves
/// and the request never returns. That is the US-1007 defect, and it is not
/// theoretical: it is what a starved `hkey` derivation did.
///
/// So this constructor is for the *boot/construction* paths only, and even
/// there it is a hazard rather than a design. **Any path a request can
/// reach must use [`try_generate_p256_keypair`]**, which bounds the rejection
/// and can report exhaustion.
#[cfg(feature = "host")]
pub fn generate_p256_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretKey::random(&mut TrngRng);
    let public = secret.public_key();
    (secret, public)
}

/// The most rejection attempts [`try_generate_p256_keypair`] will make before
/// giving up.
///
/// # Why a cap, and why 8
///
/// The cap is the load-bearing half of the fix, and it is what makes the
/// function *terminate* rather than merely fail more precisely. Even with an
/// honest `try_fill_bytes`, an `RngCore` is a trait: some future
/// implementation may still report `Ok` forever, and then a refusal is only
/// reported after `KEYGEN_MAX_ATTEMPTS` draws instead of never. A bound that
/// depends on the callee behaving is not a bound.
///
/// The number is deliberately far above the honest cost. A P-256 scalar is
/// rejected only if it is zero or >= the group order, so the probability that
/// any single draw is rejected is about 2^-128 for a real source and
/// effectively zero in practice; 8 attempts makes the *exhaustion* branch
/// reachable only by a source that is not producing fresh bytes. It is not
/// tuned for a false-positive rate — it is tuned to be short enough that a
/// request cannot sit in it, and long enough that no healthy source ever
/// approaches it.
pub const KEYGEN_MAX_ATTEMPTS: usize = 8;

/// Why a P-256 key could not be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeygenError {
    /// The entropy source **reported** that it produced nothing. Nothing was
    /// fabricated and no attempt was made to interpret a stale buffer: the
    /// draw failed, and the failure is the answer.
    Starved,
    /// The source reported success on every one of [`KEYGEN_MAX_ATTEMPTS`]
    /// draws, yet no draw was a valid scalar. This is the backstop arm — a
    /// generator that lies about succeeding rather than one that admits it
    /// cannot. It terminates, which is the whole point.
    AttemptsExhausted,
}

impl core::fmt::Display for KeygenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeygenError::Starved => write!(f, "entropy source reported no output"),
            KeygenError::AttemptsExhausted => {
                write!(f, "no valid P-256 scalar in {KEYGEN_MAX_ATTEMPTS} draws")
            }
        }
    }
}

/// Bounded rejection sampling over an **explicit draw**, the primitive
/// [`try_fill_valid`] is written in terms of.
///
/// This is the shape the device's request path needs. `FidoApp::draw_random`
/// serves bytes out of a boot-seeded pool and returns `()`, so there is no
/// `RngCore` to hand and no refusal to observe — the *cap* is the only bound
/// available there, which is precisely why the cap is the load-bearing half
/// of this fix rather than the error type.
///
/// # Errors
///
/// [`KeygenError::Starved`] propagated from `draw` on the first refusal.
/// [`KeygenError::AttemptsExhausted`] if no one of at most
/// [`KEYGEN_MAX_ATTEMPTS`] draws satisfied `accept` — the case a pool draw
/// that always "succeeds" with a constant buffer lands in, and the one that
/// used to be an infinite loop.
pub fn try_fill_valid_with<D, F>(
    draw: &mut D,
    out: &mut [u8],
    mut accept: F,
) -> Result<(), KeygenError>
where
    D: FnMut(&mut [u8]) -> Result<(), KeygenError>,
    F: FnMut(&[u8]) -> bool,
{
    for _ in 0..KEYGEN_MAX_ATTEMPTS {
        draw(out)?;
        if accept(out) {
            return Ok(());
        }
    }
    Err(KeygenError::AttemptsExhausted)
}

/// Fill `out` with `out.len()` fresh bytes, retrying a rejected draw at most
/// [`KEYGEN_MAX_ATTEMPTS`] times. The general form of what every curve
/// crate's `::random(&mut rng)` does internally, with the "forever" replaced
/// by a ceiling and a refusal surfaced instead of absorbed.
///
/// This exists because the four curves `makeCredential` accepts (P-256,
/// Ed25519, P-384, P-521) each carry their **own** copy of the same
/// unbounded rejection loop, and fixing only P-256 would leave three arms of
/// the same request still able to spin. One bounded sampler, four curves.
///
/// `accept` is the curve's own validity predicate — pass the crate's
/// `from_slice` and the accepted key set is exactly the one the curve's own
/// sampler would have produced. Drawing through `try_fill_bytes` means a
/// source that admits it has nothing stops the loop on the first attempt
/// instead of spending the whole budget rejecting the same untouched buffer.
///
/// # Errors
///
/// See [`try_fill_valid_with`].
pub fn try_fill_valid<R, F>(rng: &mut R, out: &mut [u8], accept: F) -> Result<(), KeygenError>
where
    R: rand_core::RngCore + ?Sized,
    F: FnMut(&[u8]) -> bool,
{
    try_fill_valid_with(
        &mut |b: &mut [u8]| rng.try_fill_bytes(b).map_err(|_| KeygenError::Starved),
        out,
        accept,
    )
}

/// Generate a P-256 key pair, **fallibly and within a bounded number of
/// attempts**.
///
/// This is the only P-256 keygen a request path may call. It replaces
/// `SecretKey::random`'s unbounded rejection sampler with the same sampler
/// under an explicit ceiling, via [`try_fill_valid`].
///
/// `SecretKey::from_slice` is the validity rule `SecretKey::random` applies,
/// so a key produced here is one `SecretKey::random` would have produced. It
/// is spelled out rather than delegated because delegating *is* the bug: the
/// whole reason this function exists is that we cannot bound the loop inside
/// `p256`.
///
/// # Errors
///
/// See [`try_fill_valid`].
pub fn try_generate_p256_keypair<R: rand_core::RngCore + ?Sized>(
    rng: &mut R,
) -> Result<(SecretKey, PublicKey), KeygenError> {
    let mut bytes = [0u8; 32];
    try_fill_valid(rng, &mut bytes, |b| SecretKey::from_slice(b).is_ok())?;
    let secret =
        SecretKey::from_slice(&bytes).map_err(|_| KeygenError::AttemptsExhausted)?;
    let public = secret.public_key();
    Ok((secret, public))
}

/// [`try_generate_p256_keypair`] over a platform [`Trng`], the seam the
/// device and the host both feed.
///
/// The [`TrngAdapter`] is what makes the `Trng`'s *fallible* draw visible to
/// `RngCore::try_fill_bytes`; without the adapter the trait method would be
/// unreachable from the sampler.
pub fn try_generate_p256_keypair_from_trng<R: Trng>(
    trng: &mut R,
) -> Result<(SecretKey, PublicKey), KeygenError> {
    try_generate_p256_keypair(&mut TrngAdapter(trng))
}

/// Sign data with P-256 ECDSA.
pub fn p256_sign(secret: &SecretKey, data: &[u8]) -> Signature {
    let signing_key = SigningKey::from(secret);
    signing_key.sign(data)
}

/// Get the encoded public key bytes (uncompressed, 65 bytes).
pub fn public_key_bytes(public: &PublicKey) -> [u8; 65] {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = public.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(point.as_bytes());
    out
}

/// Parse an uncompressed public key.
pub fn parse_public_key(bytes: &[u8]) -> Option<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).ok()
}

#[cfg(feature = "host")]
/// Parse a COSE EC2 P-256 public key (x || y coordinates) into a `PublicKey`.
pub fn parse_cose_ec2_p256(x: &[u8], y: &[u8]) -> Option<PublicKey> {
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut point_bytes = Vec::with_capacity(65);
    point_bytes.push(0x04);
    point_bytes.extend_from_slice(x);
    point_bytes.extend_from_slice(y);
    PublicKey::from_sec1_bytes(&point_bytes).ok()
}

/// ECDH key agreement: derive the raw shared secret (X coordinate, 32 bytes).
pub fn ecdh_shared_secret(secret: &SecretKey, peer_public: &PublicKey) -> [u8; 32] {
    use p256::elliptic_curve::ecdh::diffie_hellman;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer_public.as_affine());
    let bytes = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

/// SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sha256_into(data, &mut out);
    out
}

/// SHA-256 into a caller-provided buffer (S-701-1 no-heap core).
pub fn sha256_into(data: &[u8], out: &mut [u8; 32]) {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    out.copy_from_slice(&hasher.finalize());
}

/// HMAC-SHA256 into a caller-provided buffer (S-701-1 no-heap core).
pub fn hmac_sha256_into(key: &[u8], data: &[u8], out: &mut [u8; 32]) {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    out.copy_from_slice(&bytes);
}

/// AES-256-CBC encrypt in place with NoPadding (S-701-1 no-heap core; `buf`
/// length must be a multiple of 16).
#[allow(clippy::result_unit_err)] // single failure mode: malformed input/block length
pub fn aes256_cbc_encrypt_into(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) -> Result<(), ()> {
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    let mut ct = Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| ())?;
    for b in buf.as_chunks_mut::<16>().0 {
        ct.encrypt_block_mut(b.into());
    }
    Ok(())
}

/// AES-256-CBC decrypt in place with NoPadding (S-701-1 no-heap core).
#[allow(clippy::result_unit_err)] // single failure mode: malformed input/block length
pub fn aes256_cbc_decrypt_into(key: &[u8; 32], iv: &[u8; 16], buf: &mut [u8]) -> Result<(), ()> {
    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    let mut ct = Aes256CbcDec::new_from_slices(key, iv).map_err(|_| ())?;
    for b in buf.as_chunks_mut::<16>().0 {
        ct.decrypt_block_mut(b.into());
    }
    Ok(())
}

// ------------------------------------------------------------------
// ChaCha20-Poly1305 (RFC 8439) — the RS-Key `0x41` channel's AEAD
// ------------------------------------------------------------------

/// ChaCha20-Poly1305 nonce width (RFC 8439 §2.8).
pub const CHACHA_NONCE_LEN: usize = 12;

/// Poly1305 tag width (RFC 8439 §2.8).
pub const CHACHA_TAG_LEN: usize = 16;

/// Why a ChaCha20-Poly1305 seal or open refused.
///
/// Deliberately *not* a CTAP2 status: this module is the primitive layer and
/// knows nothing of `0x41`, and each of the three callers maps these onto the
/// status its own sub-command is specified to return. Keeping the two apart is
/// what lets one AEAD serve three arms that disagree about what "wrong" means —
/// `vendor_backup::load` answers `0x3D` (integrity failure), while the soft-lock
/// and org-attestation paths answer `0x27` (operation denied) for the identical
/// cryptographic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// The output buffer could not hold the result, or a length that the AEAD
    /// itself requires did not hold (a `nonce(12) ‖ ct ‖ tag(16)` blob whose
    /// ciphertext is not exactly the caller's `out` length).
    ///
    /// A capacity problem, never a failed authentication: it is decided from
    /// lengths alone, before any key is touched.
    Length,
    /// The tag did not verify. Nothing was written to the caller's buffer.
    Integrity,
}

/// Seal `plaintext` under ChaCha20-Poly1305 as `ct ‖ tag(16)` — the nonce is
/// **not** prepended; the caller frames it.
///
/// `out` is **cleared** first: this is a "write this" function, not an append,
/// and a caller that pre-framed the nonce into the same buffer would have it
/// erased. The only bound is the output buffer's capacity, reported as
/// [`AeadError::Length`] — a `Result`, not a panic and not a truncation, because
/// a silently short ciphertext authenticates over the wrong length.
///
/// The `‖ tag` order (rather than the `tag ‖ ct` that `ring`'s
/// `seal_in_place_append_tag` and RustCrypto's `encrypt` both produce) is
/// dictated by the client: `wrap_secret` and `chacha_seal` return
/// `nonce ‖ buf` with the tag already on the tail
/// (`picoforge/src/hal/fido/backup.rs:61-78`). That wire format is fixed and
/// this function is the only place it is produced.
pub fn chacha20poly1305_seal<const N: usize>(
    key: &[u8; 32],
    nonce: &[u8; CHACHA_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut heapless::Vec<u8, N>,
) -> Result<(), AeadError> {
    // Capacity is decided from lengths before a single byte of plaintext is
    // written, so the `Err` path leaves nothing behind.
    if plaintext.len() + CHACHA_TAG_LEN > N {
        return Err(AeadError::Length);
    }
    out.clear();
    // `extend_from_slice` on a `heapless::Vec` is all-or-nothing, and having
    // just checked the capacity it cannot fail; the `map_err` is there so that
    // stays true if the bound above is ever edited.
    out.extend_from_slice(plaintext).map_err(|_| AeadError::Length)?;
    let tag = {
        use chacha20poly1305::aead::AeadInPlace;
        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| AeadError::Length)?;
        cipher
            .encrypt_in_place_detached(nonce.into(), aad, out.as_mut_slice())
            .map_err(|_| AeadError::Length)?
    };
    out.extend_from_slice(tag.as_slice()).map_err(|_| AeadError::Length)?;
    debug_assert_eq!(out.len(), plaintext.len() + CHACHA_TAG_LEN);
    Ok(())
}

/// Open `ct ‖ tag(16)` under ChaCha20-Poly1305, **appending** the plaintext to
/// `out`.
///
/// Fails closed with `out` left exactly as it was found: on a tag mismatch the
/// returned `Err` is [`AeadError::Integrity`] and the append is rolled back, so
/// a caller that ignores the error still holds no attacker-chosen bytes. (The
/// underlying `decrypt_in_place_detached` authenticates *before* touching the
/// buffer; the rollback is what makes "untouched" true of the caller's view.)
///
/// `ct_and_tag` shorter than [`CHACHA_TAG_LEN`] is a framing error rather than
/// a failed authentication, and is reported as one.
pub fn chacha20poly1305_open<const N: usize>(
    key: &[u8; 32],
    nonce: &[u8; CHACHA_NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
    out: &mut heapless::Vec<u8, N>,
) -> Result<(), AeadError> {
    if ct_and_tag.len() < CHACHA_TAG_LEN {
        return Err(AeadError::Length);
    }
    let split = ct_and_tag.len() - CHACHA_TAG_LEN;
    let (ct, tag) = ct_and_tag.split_at(split);
    let start = out.len();
    if start + ct.len() > N {
        return Err(AeadError::Length);
    }
    out.extend_from_slice(ct).map_err(|_| AeadError::Length)?;
    {
        use chacha20poly1305::aead::AeadInPlace;
        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| AeadError::Length)?;
        if cipher
            .decrypt_in_place_detached(nonce.into(), aad, &mut out[start..], tag.into())
            .is_err()
        {
            // Roll back: the caller must never see a partial plaintext, and
            // "the buffer is as it was" is a stronger and simpler promise to
            // make to all three callers than "the caller must not look".
            out.truncate(start);
            return Err(AeadError::Integrity);
        }
    }
    Ok(())
}

/// Open a `nonce(12) ‖ ct ‖ tag(16)` blob into `out`, which must be exactly the
/// ciphertext's length.
///
/// The blob framing is the client's (`picoforge/src/hal/fido/backup.rs:61-78`)
/// and is shared verbatim by the seed-export, soft-lock and org-attestation
/// paths. It lives here rather than in each of those modules so that the split
/// cannot be performed two different ways by two different arms: the tag is on
/// the **tail**, which is *not* what `chacha20poly1305`'s `encrypt` returns,
/// and getting that backwards yields a blob that fails to open rather than one
/// that opens to garbage.
pub fn chacha20poly1305_open_blob(
    key: &[u8; 32],
    aad: &[u8],
    blob: &[u8],
    out: &mut [u8],
) -> Result<(), AeadError> {
    if blob.len() < CHACHA_NONCE_LEN + CHACHA_TAG_LEN {
        return Err(AeadError::Length);
    }
    let nonce: &[u8; CHACHA_NONCE_LEN] =
        blob[..CHACHA_NONCE_LEN].try_into().expect("sliced to the nonce length");
    let body = &blob[CHACHA_NONCE_LEN..];
    let split = body.len() - CHACHA_TAG_LEN;
    let (ct, tag) = body.split_at(split);
    if ct.len() != out.len() {
        // A blob whose plaintext is not the caller's expected length is not one
        // this protocol produced. Decided on lengths, before the key is used.
        return Err(AeadError::Length);
    }
    out.copy_from_slice(ct);
    use chacha20poly1305::aead::AeadInPlace;
    let cipher =
        chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::Length)?;
    cipher
        .decrypt_in_place_detached(nonce.into(), aad, out, tag.into())
        .map_err(|_| {
            // The ciphertext was copied into `out` before the keystream was
            // XORed into it, so on a tag failure `out` still holds the
            // *ciphertext*. Restore the caller's zeros rather than leaving
            // attacker-chosen bytes in a buffer the caller may log or reuse.
            out.fill(0);
            AeadError::Integrity
        })
}

/// `rand_core` adapter over a platform [`Trng`] reference, so the curve
/// crates' `::random(&mut rng)` constructors consume TRNG bytes directly on
/// host **and** device (S-701-1: one shared crypto seam; the device hands
/// the TRNG in at construction instead of the host free functions).
pub struct TrngAdapter<'a, R: Trng>(pub &'a mut R);

impl<R: Trng> rand_core::RngCore for TrngAdapter<'_, R> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.random_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.random_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.random_bytes(dest);
    }

    /// US-1007: this used to be `self.fill_bytes(dest); Ok(())` — an
    /// unconditional success that reported a refused draw as fresh bytes,
    /// which is the half of the FIDO keygen spin that made the loop
    /// *unbounded* rather than merely wrong. It now forwards to the `Trng`'s
    /// fallible draw, so a source that cannot produce is visible here as an
    /// `Err` and the caller can stop.
    ///
    /// `RNG_ERR_RESEED_REFUSED` and not `RNG_ERR_RESEED_REQUIRED`: both
    /// `Trng` implementations collapse to [`fapico2_platform::trng::TrngError`]
    /// `::Stalled`, and a source that has stopped producing is the "peripheral
    /// produced no validated block" case, not the "budget is spent, retry
    /// later" one.
    ///
    /// `fill_bytes` above is deliberately left as the infallible draw: it is
    /// what `RngCore` requires every implementor to provide, and the callers
    /// that can act on a refusal must go through `try_fill_bytes` or
    /// [`try_generate_p256_keypair`]. A `fill_bytes` caller that needs to
    /// know is the same mistake as a `Trng::random_bytes` caller, and
    /// `check_rng_path.py` is what keeps the set of them visible.
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_random_bytes(dest).map_err(|_| _refused_err())
    }
}

impl<R: Trng> rand_core::CryptoRng for TrngAdapter<'_, R> {}

// ------------------------------------------------------------------
// PIN protocol v1 / v2 shared-secret derivation
// ------------------------------------------------------------------

/// PIN protocol v1: shared secret = SHA256(ecdh_raw) → 32 bytes.
/// Both hmac_key and enc_key are the same 32 bytes.
pub fn derive_shared_secret_v1(ecdh_raw: &[u8; 32]) -> [u8; 32] {
    sha256(ecdh_raw)
}

/// PIN protocol v2: derive 64-byte shared secret = hmac_key(32) || enc_key(32)
/// via HKDF with the standard CTAP2 info strings.
pub fn derive_shared_secret_v2(ecdh_raw: &[u8; 32]) -> [u8; 64] {
    let mut shared = [0u8; 64];
    hkdf_sha256(
        None,
        ecdh_raw,
        b"CTAP2 HMAC key",
        &mut shared[..32],
    );
    hkdf_sha256(
        None,
        ecdh_raw,
        b"CTAP2 AES key",
        &mut shared[32..],
    );
    shared
}

/// Extract the HMAC key (first 32 bytes) from a v2 shared secret.
pub fn hmac_key_from_v2(shared: &[u8; 64]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&shared[..32]);
    k
}

/// Extract the encryption key (last 32 bytes) from a v2 shared secret.
pub fn enc_key_from_v2(shared: &[u8; 64]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&shared[32..]);
    k
}

// ------------------------------------------------------------------
// PIN encrypt / decrypt for each protocol version
// ------------------------------------------------------------------

#[cfg(feature = "host")]
/// Encrypt for PIN protocol v1: AES-CBC with IV=0, no padding.
pub fn pin_encrypt_v1(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let iv = [0u8; 16];
    aes_cbc_encrypt(key, &iv, plaintext)
}

#[cfg(feature = "host")]
/// Decrypt for PIN protocol v1: AES-CBC with IV=0, no padding.
pub fn pin_decrypt_v1(key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let iv = [0u8; 16];
    aes_cbc_decrypt(key, &iv, ciphertext)
}

#[cfg(feature = "host")]
/// Encrypt for PIN protocol v2: IV(16 random) || AES-CBC-NoPad(enc_key).
pub fn pin_encrypt_v2(enc_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let iv = random_bytes::<16>();
    let ct = aes_cbc_encrypt(enc_key, &iv, plaintext);
    let mut result = iv.to_vec();
    result.extend(ct);
    result
}

#[cfg(feature = "host")]
/// Decrypt for PIN protocol v2: strip 16-byte IV, AES-CBC-NoPad decrypt.
pub fn pin_decrypt_v2(enc_key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 32 {
        // Need at least IV(16) + one block(16)
        return None;
    }
    let iv: [u8; 16] = data[..16].try_into().ok()?;
    aes_cbc_decrypt(enc_key, &iv, &data[16..])
}

#[cfg(feature = "host")]
/// Encrypt PIN data according to the negotiated protocol version.
/// v1: IV=0, no padding.  v2: random IV prepended, no padding.
pub fn pin_encrypt(protocol: u8, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    if protocol == 1 {
        pin_encrypt_v1(key, plaintext)
    } else {
        pin_encrypt_v2(key, plaintext)
    }
}

#[cfg(feature = "host")]
/// Decrypt PIN data according to the negotiated protocol version.
pub fn pin_decrypt(protocol: u8, key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if protocol == 1 {
        pin_decrypt_v1(key, ciphertext)
    } else {
        pin_decrypt_v2(key, ciphertext)
    }
}

// ------------------------------------------------------------------
// PIN auth verification (pinUvAuthParam)
// ------------------------------------------------------------------

#[cfg(feature = "host")]
/// Compute pinUvAuthParam: HMAC-SHA256(hmac_key, data) truncated to
/// 16 bytes for v1, 32 bytes for v2.
pub fn pin_uv_auth_param(protocol: u8, hmac_key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mac = hmac_sha256(hmac_key, data);
    if protocol == 1 {
        mac[..16].to_vec()
    } else {
        mac.to_vec()
    }
}

/// Constant-time comparison of two byte slices: XOR-accumulates every byte
/// difference, so the work performed never depends on where (or whether)
/// the inputs diverge. Returns true only if the slices are equal-length and
/// identical (US-703).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a pinUvAuthParam against the computed HMAC (no-heap: the expected
/// HMAC lives in a fixed 32-byte buffer).
pub fn pin_verify_auth(protocol: u8, hmac_key: &[u8; 32], data: &[u8], param: &[u8]) -> bool {
    let expected_len = if protocol == 1 { 16 } else { 32 };
    if param.len() != expected_len {
        return false;
    }
    let mut mac = [0u8; 32];
    hmac_sha256_into(hmac_key, data, &mut mac);
    // Constant-time comparison
    ct_eq(&mac[..expected_len], param)
}

// ------------------------------------------------------------------
// Legacy PIN helpers (kept for compatibility)
// ------------------------------------------------------------------

/// PIN hash: SHA-256 of PIN, truncated to 16 bytes.
pub fn pin_hash(pin: &[u8]) -> [u8; 16] {
    let hash = sha256(pin);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

// ------------------------------------------------------------------
// US-910: salted, stretched PIN verifier
// ------------------------------------------------------------------

/// Iteration count for the stretched PIN verifier (US-910). Device-measured
/// budget: 4096 iterated SHA-256 rounds target well under 200 ms per
/// verification on the RP2350 (Cortex-M33). Both host and device use this
/// same constant — host tests can afford it.
pub const PIN_VERIFIER_ROUNDS: u32 = 4096;

/// Verifier format stamp (US-910): `0` = legacy unsalted
/// `SHA256(PIN)[..16]`, `1` = salted stretched (see
/// [`pin_verifier_stretched`]). Persisted next to the verifier bytes.
pub const PIN_VERIFIER_FORMAT_STRETCHED: u8 = 1;

/// Domain separator for the stretched PIN verifier (US-910). Binds the
/// derivation to this exact purpose so the same (salt, PIN) pair cannot be
/// replayed as a KDF output anywhere else.
const PIN_VERIFIER_DOMAIN: &[u8] = b"fapico2.fido.pin-verifier.v1";

/// US-910 stretched PIN verifier: `SHA256` iterated `rounds` times over
/// `DOMAIN || salt || SHA256(PIN)[..16]`, truncated to 16 bytes.
///
/// The input is the CTAP2 16-byte PIN-hash candidate (the client sends
/// `SHA256(PIN)[..16]` over the pinUv shared secret — the raw PIN never
/// reaches the authenticator in the getPinToken path), so the verifier is a
/// function of the client-visible candidate. The per-device TRNG salt plus
/// the iteration count remove the shared offline-table weakness of the
/// legacy form: an attacker with the snapshot must redo `rounds` hashes per
/// PIN guess, per device.
pub fn pin_verifier_stretched(pin_hash: &[u8; 16], salt: &[u8; 16], rounds: u32) -> [u8; 16] {
    let mut input = [0u8; PIN_VERIFIER_DOMAIN.len() + 16 + 16];
    input[..PIN_VERIFIER_DOMAIN.len()].copy_from_slice(PIN_VERIFIER_DOMAIN);
    let mut off = PIN_VERIFIER_DOMAIN.len();
    input[off..off + 16].copy_from_slice(salt);
    off += 16;
    input[off..off + 16].copy_from_slice(pin_hash);

    let mut h = sha256(&input);
    for _ in 1..rounds.max(1) {
        h = sha256(&h);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}

/// Verify a PIN-hash candidate against the stored verifier in either
/// format (US-910). `format` is the persisted `pin_verifier_format` value;
/// legacy (`0`) records compare the candidate directly, stretched (`1`)
/// records re-derive with the stored salt and iteration count. Comparison
/// is constant-time in both cases.
pub fn pin_verifier_matches(
    stored: &[u8; 16],
    format: u8,
    salt: Option<&[u8; 16]>,
    iter: u32,
    candidate: &[u8; 16],
) -> bool {
    match (format, salt) {
        (PIN_VERIFIER_FORMAT_STRETCHED, Some(salt)) => {
            let derived = pin_verifier_stretched(candidate, salt, iter);
            ct_eq(&derived, stored)
        }
        // Legacy record (or malformed stretched record without salt):
        // compare the candidate directly, never guess-verify.
        _ => ct_eq(candidate, stored),
    }
}

/// US-910: derive the stretched verifier and iteration count from a
/// just-verified PIN-hash candidate and a caller-supplied TRNG salt — the
/// migration step for legacy records and the emission path for
/// set/change-PIN. The salt source is the platform TRNG seam: host builds
/// use `crypto::random_bytes` (OS entropy), the device command path draws
/// from its boot-time TRNG pool (`draw_random`).
pub fn pin_verifier_upgrade(candidate: &[u8; 16], salt: &[u8; 16]) -> ([u8; 16], u32) {
    (
        pin_verifier_stretched(candidate, salt, PIN_VERIFIER_ROUNDS),
        PIN_VERIFIER_ROUNDS,
    )
}


#[cfg(feature = "host")]
/// Encrypt pinHash for PIN protocol (v1 style, IV=0).
pub fn pin_hash_enc(shared_secret: &[u8; 32], pin_hash: &[u8; 16]) -> [u8; 16] {
    let iv = [0u8; 16];
    let encrypted = aes256_cbc_encrypt(shared_secret, &iv, pin_hash);
    let mut out = [0u8; 16];
    out.copy_from_slice(&encrypted[..16]);
    out
}

#[cfg(feature = "host")]
/// Sign data with P-256 ECDSA, returning the ASN.1 DER-encoded signature.
///
/// CTAP2 / python-fido2's ES256 verifier (backed by ``cryptography``) expects
/// the signature in DER form, matching the C firmware which uses
/// ``mbedtls_ecdsa_write_signature``.
pub fn p256_sign_bytes(secret: &SecretKey, data: &[u8]) -> Vec<u8> {
    let sig = p256_sign(secret, data);
    sig.to_der().as_bytes().to_vec()
}

/// Reconstruct a `SecretKey` from its 32-byte scalar representation.
pub fn secret_key_from_bytes(bytes: &[u8]) -> Option<SecretKey> {
    if bytes.len() != 32 {
        return None;
    }
    SecretKey::from_slice(bytes).ok()
}

/// Sign with P-256 ECDSA and DER-encode into a fixed buffer (S-701-4: the
/// device command path cannot allocate; python-fido2's ES256 verifier expects
/// the ASN.1 DER form).
pub fn p256_sign_der_into(
    secret: &SecretKey,
    data: &[u8],
    out: &mut heapless::Vec<u8, 72>,
) -> Option<()> {
    use p256::ecdsa::signature::Signer;
    let signing_key = SigningKey::from(secret);
    let sig: Signature = signing_key.sign(data);
    out.clear();
    // DER: SEQUENCE { INTEGER r, INTEGER s } — minimal-length integers with
    // a leading 0x00 when the high bit is set.
    let r = sig.r().to_bytes();
    let s = sig.s().to_bytes();
    let int_len = |v: &[u8]| -> usize {
        let mut i = 0;
        while i < 31 && v[i] == 0 {
            i += 1;
        }
        let n = 32 - i;
        n + if v[i] & 0x80 != 0 { 1 } else { 0 }
    };
    let rl = int_len(&r);
    let sl = int_len(&s);
    let body = 2 + rl + 2 + sl;
    out.push(0x30).ok()?;
    out.push(body as u8).ok()?;
    for v in [r.as_slice(), s.as_slice()] {
        let mut i = 0;
        while i < 31 && v[i] == 0 {
            i += 1;
        }
        let n = 32 - i;
        out.push(0x02).ok()?;
        let padded = v[i] & 0x80 != 0;
        out.push((n + if padded { 1 } else { 0 }) as u8).ok()?;
        if padded {
            out.push(0x00).ok()?;
        }
        out.extend_from_slice(&v[i..]).ok()?;
    }
    Some(())
}

/// Parse a COSE EC2 P-256 public key from raw x||y halves without allocating.
pub fn parse_cose_ec2_p256_bytes(x: &[u8], y: &[u8]) -> Option<PublicKey> {
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(x);
    point[33..65].copy_from_slice(y);
    PublicKey::from_sec1_bytes(&point).ok()
}

/// AES-256-CBC encrypt with a zero IV into a fixed buffer (PIN protocol v1
/// framing; `buf` length must be a multiple of 16).
#[allow(clippy::result_unit_err)]
pub fn pin_cbc_encrypt_zero_iv(key: &[u8; 32], buf: &mut [u8]) -> Result<(), ()> {
    let iv = [0u8; 16];
    aes256_cbc_encrypt_into(key, &iv, buf)
}

/// AES-256-CBC decrypt with a zero IV in place (PIN protocol v1 framing).
#[allow(clippy::result_unit_err)]
pub fn pin_cbc_decrypt_zero_iv(key: &[u8; 32], buf: &mut [u8]) -> Result<(), ()> {
    let iv = [0u8; 16];
    aes256_cbc_decrypt_into(key, &iv, buf)
}

#[cfg(test)]
mod der_tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    #[test]
    fn der_signature_roundtrip() {
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let data = b"hello world";
        let mut out = heapless::Vec::<u8, 72>::new();
        p256_sign_der_into(&sk, data, &mut out).unwrap();
        let vk = VerifyingKey::from(&sk.public_key());
        let sig = Signature::from_der(out.as_slice()).expect("valid DER");
        vk.verify(data, &sig).expect("signature verifies");
    }
}
