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
// US-910 salted, stretched PIN verifier; US-1570 raises the floor on the
// RP2350 SHA-256 accelerator (US-1569)
// ------------------------------------------------------------------

// ===========================================================================
// US-1570 — the cost model
// ===========================================================================
//
// **This is arithmetic over four published constants, not a measurement, and
// the difference matters.** There is no RP2350 in this repository's loop
// (`platform/src/sha256_accel.rs`, "What is measured and what is not": the
// register layer is unreviewed-by-execution, only its padding and
// block-assembly logic are tested). So nothing below may be quoted as "the
// verification latency is N ms on hardware". What it *is* is the derivation
// that says which constant to pick, plus a compile-time assertion that the
// chosen count fits the budget **under the pessimistic per-round figure**.
//
// The four constants, and where each comes from:
//
// | symbol | value | source |
// |---|---|---|
// | [`RP2350_CLK_SYS_HZ`] | 150 MHz | the RP2350's stock `clk_sys`; what `embassy-rp` 0.10.0's `rp235xa` `Config::default()` programs (`clk_sys: Def::new(150_000_000)`) |
// | [`PIN_VERIFY_BUDGET_MS`] | 200 ms | the budget the pre-US-1570 comment already claimed for the whole verification; carried forward unchanged so the *new* number is comparable with the old one rather than a redefinition |
// | [`SHA256_BLOCK_DIGEST_CYCLES`] | 57 | the RP2350 datasheet, carried on the register itself in `rp-pac`'s SVD text for `CSR.WDATA_RDY`: *"After writing 16 words, this flag will go low for 57 cycles whilst the core completes its digest."* One 512-bit compression. |
// | [`PIN_VERIFIER_CYCLES_PER_ROUND_POLLED`] | 384 | **ours, and the only genuinely estimated figure.** See below. |
//
// The 384 is the load-bearing number and it is deliberately pessimistic. Per
// accelerated round the CPU pays, on top of the block's own 57 cycles:
//
// * `hash_into`'s block assembly — one 64-byte `Block` copy per push;
// * `BlockSink::begin` — a `RESETS.RESET_DONE` read and a read-modify-write on
//   `CSR` (clear `ERR_WDATA_NOT_RDY`, set `BSWAP`/`DMA_SIZE`, strobe `START`);
// * 16 stores to `WDATA`, each budgeted at **4 cycles** rather than the 1 an
//   idealised store would take, because the driver assembles each word from
//   four byte loads (`u32::from_le_bytes(block.0[i*4..])`,
//   `sha256_accel.rs:668-674`) and `WDATA` is on the peripheral bus;
// * `BlockSink::finish` — poll `SUM_VLD` and read eight `SUM` registers.
//
// Summed honestly that is nearer 200 cycles; 384 is roughly a 1:3 host:digest
// ratio on the block's *own* figure, chosen so the assertion below still holds
// if the compiler generates the byte-assembly as written rather than folding
// it into one aligned load. **The `sum` of the four bullets, and the poll-loop
// trip counts, are the part that needs hardware.** The block's 57 cycles and
// the 150 MHz clock are datasheet figures; the multiplication is arithmetic.
//
// Consequence, which is the honest headline: **100,000 rounds does not fit
// this budget on the polled path** — 100,000 x 384 = 38.4 M cycles = 256 ms.
// It *would* fit the DMA path ([`PIN_VERIFIER_CYCLES_PER_ROUND_DMA`], where
// sixteen CPU stores become one channel trigger: 100,000 x 128 = 12.8 M
// cycles = 85 ms), but the DMA register path is the part `sha256_accel` most
// explicitly declines to claim has been executed, so the count chosen below is
// the one the *pessimistic, polled* derivation supports. Raising it to 100k is
// a one-constant edit once a board can measure it.

/// Wall-clock budget for **one** PIN verification on the RP2350.
///
/// Carried forward verbatim from the pre-US-1570 `PIN_VERIFIER_ROUNDS` comment
/// ("target well under 200 ms per verification"). Changing the budget and the
/// round count together would make the round count unfalsifiable: nothing
/// downstream could tell a KDF that got 32x stronger from one that merely got
/// a laxer deadline.
pub const PIN_VERIFY_BUDGET_MS: u64 = 200;

/// The RP2350's stock `clk_sys`. `embassy-rp` 0.10.0's RP2350 `Config::default()`
/// programs this (`clk_sys: Def::new(150_000_000)`), and nothing in this
/// firmware overrides it — there is no clock-`set` call anywhere in
/// `firmware/src/`. If a board is clocked differently this constant is wrong
/// in the *optimistic* direction, which is why
/// [`PIN_VERIFIER_CYCLES_PER_ROUND_POLLED`] carries a 3x margin rather than
/// being a tight estimate.
pub const RP2350_CLK_SYS_HZ: u64 = 150_000_000;

/// Cycles the RP2350 SHA-256 block spends on **one** 512-bit compression.
///
/// Datasheet figure, quoted from the register description `rp-pac` carries
/// from `svd/rp235x.svd` for `CSR.WDATA_RDY` (see the module docs of
/// `platform::sha256_accel`, "The register names in the story brief are
/// RP2040's, not RP2350's"): after the sixteenth word is written the flag goes
/// low "for 57 cycles whilst the core completes its digest".
///
/// It is 57 cycles for the *compression*, not for the whole round — the word
/// writes and the begin/finish bookkeeping are the CPU's, and are budgeted in
/// [`PIN_VERIFIER_CYCLES_PER_ROUND_POLLED`] instead.
pub const SHA256_BLOCK_DIGEST_CYCLES: u32 = 57;

/// CPU cycles per accelerated verification round, **polled** driver — the
/// pessimistic figure the round count is chosen against. See the module
/// section above for how 384 is built from the four costs.
///
/// Deliberately a round number and deliberately pessimistic: the point of the
/// constant is to be an upper bound a reader can check by adding four small
/// numbers, not a measurement.
pub const PIN_VERIFIER_CYCLES_PER_ROUND_POLLED: u32 = 384;

/// CPU cycles per accelerated verification round on the **DMA** driver, for
/// comparison only. Sixteen `WDATA` stores collapse into one
/// `CTRL_TRIG.EN` trigger plus the transfer, and `push_dma` waits on
/// `CTRL.BUSY` instead of `WDATA_RDY` per word
/// (`sha256_accel.rs:686-702`). Budgeted at roughly 2x the block's own figure
/// for the two DMA waits and the address writes.
///
/// **Not used by the round count.** The DMA path is the one `sha256_accel` is
/// least willing to claim works, and a KDF whose affordable round count
/// depends on it would be a claim about unexecuted code.
pub const PIN_VERIFIER_CYCLES_PER_ROUND_DMA: u32 = 128;

/// [`PIN_VERIFY_BUDGET_MS`] expressed in `clk_sys` cycles. The division is
/// exact at these values (30 MHz-cycles per millisecond), so no rounding
/// stands between the budget and the assertion below.
pub const PIN_VERIFY_BUDGET_CYCLES: u64 = PIN_VERIFY_BUDGET_MS * RP2350_CLK_SYS_HZ / 1_000;

/// Iteration count for the stretched PIN verifier (US-910), raised by US-1570
/// from 4096 to **65,536** — a 16x increase, and the largest power of two
/// whose *pessimistic polled* derivation still fits [`PIN_VERIFY_BUDGET_CYCLES`]:
///
/// ```text
///   65,536 x 384 cycles = 25,165,824 cycles
///                     / 150,000,000 Hz = 167.8 ms   (budget: 200 ms, 16% margin)
/// ```
///
/// Rounds are whole SHA-256 **evaluations** of the running 32-byte digest, and
/// a 32-byte message is exactly one 512-bit block, so the block count is
/// `rounds + 1`: the extra block is round 0's input, which is
/// `DOMAIN || salt || SHA256(PIN)[..16]` — 60 bytes, and 60 > 55, so FIPS 180-4
/// §5.1.1 pads it across **two** blocks (`sha256_accel::SHA256_MAX_TAIL_BLOCKS`).
/// That double block is inside the figure above: 65,537 blocks, of which 65,536
/// are one-block messages.
///
/// The security argument is the reason for the change and it is worth stating
/// plainly, because 4096 was never a strong number: **every one of the four
/// reference implementations spends three to five hash operations per PIN
/// guess** (`pico-fido2/src/fido/crypto_utils.c:44-56`; RS-Key
/// `src/pico_crypt/kdf.rs:92-106`; see `docs/secure-storage-comparison.md`
/// §5.2). 65,536 is 14 orders of magnitude more work per guess than 3, and the
/// increment is only affordable because the work moved from the Cortex-M33's
/// software SHA-256 onto the block that all five references ignore.
///
/// Both host and device use this same constant — host tests can afford it, and
/// a build that tested a different number than it ships would test nothing.
pub const PIN_VERIFIER_ROUNDS: u32 = 65_536;

/// The budget assertion, as a **build failure**.
///
/// The two numbers that must agree — the round count and the decode ceiling
/// that refuses anything above it — live in different modules on purpose (the
/// ceiling is a parse rule in `device_keystore.rs`/`keystore.rs`, the count is
/// a cost decision here), and for the life of US-910 they were two independent
/// literals that nothing in the type system checked. This is the check that a
/// future edit to either one cannot silently break the other's promise: raising
/// the count past the budget, or lowering the budget past the count, fails the
/// build with the arithmetic in the message.
const _: () = {
    assert!(
        (PIN_VERIFIER_ROUNDS as u64) * (PIN_VERIFIER_CYCLES_PER_ROUND_POLLED as u64)
            <= PIN_VERIFY_BUDGET_CYCLES,
        "PIN_VERIFIER_ROUNDS does not fit PIN_VERIFY_BUDGET_MS at \
         PIN_VERIFIER_CYCLES_PER_ROUND_POLLED: the PIN verification would \
         overrun its budget. Either lower the round count, or re-derive \
         PIN_VERIFIER_CYCLES_PER_ROUND_POLLED against a measured board."
    );
};

/// Verifier format stamp (US-910): `0` = legacy unsalted
/// `SHA256(PIN)[..16]`, `1` = salted stretched (see
/// [`pin_verifier_stretched`]). Persisted next to the verifier bytes.
pub const PIN_VERIFIER_FORMAT_STRETCHED: u8 = 1;

/// Domain separator for the stretched PIN verifier (US-910). Binds the
/// derivation to this exact purpose so the same (salt, PIN) pair cannot be
/// replayed as a KDF output anywhere else.
const PIN_VERIFIER_DOMAIN: &[u8] = b"fapico2.fido.pin-verifier.v1";

/// `DOMAIN || salt || SHA256(PIN)[..16]` — 60 bytes, and therefore **two**
/// padded SHA-256 blocks, not one (60 > 55, FIPS 180-4 §5.1.1). Named so the
/// "rounds + 1 block" arithmetic in [`PIN_VERIFIER_ROUNDS`] is checkable
/// rather than remembered.
pub const PIN_VERIFIER_INPUT_LEN: usize = PIN_VERIFIER_DOMAIN.len() + 16 + 16;

/// Bytes the first evaluation of the verifier hashes, as a compile-time
/// constant so [`sha256_fixed_via`] can derive the bit length without an
/// overflow check: a fixed-size array's length cannot reach 2^61 bytes.
const _: () = assert!(
    (PIN_VERIFIER_INPUT_LEN as u64) * 8 < (1u64 << 61),
    "SHA-256's length field counts bits; a fixed-size input must stay under \
     2^61 bytes or `msg.len() * 8` wraps into a different message's digest"
);

// ===========================================================================
// US-1570 — the migration window for legacy-format verifiers
// ===========================================================================

/// The first release index at which a **legacy-format** (`format == 0`) PIN
/// verifier stops being admitted (the window is **open** while
/// [`PIN_VERIFIER_RELEASE_INDEX`] is strictly below it). Release `0` is the one
/// that first shipped
/// [`PIN_VERIFIER_ROUNDS`] at its current value with the window open, so the
/// first release that may refuse legacy records is `1` — hence `1` here.
///
/// # Why a release window and not a counter
///
/// The migration is triggered by the only event that can migrate a record
/// safely — a *successful* PIN verification (`pin_verifier_upgrade`, reached
/// from `PinProtocol::migrate_legacy_pin_verifier` and the device twin's
/// success arm; a wrong PIN never reaches it and therefore never migrates).
/// A failed attempt leaves no trace of having happened, so a record cannot
/// count its own window: any per-record counter would have to live in a new
/// snapshot key, and there is nowhere honest to put one that a torn write could
/// not roll back (US-1571 measures exactly that rollback, and finds the rollback
/// *restores* a count — a window counter living there would be a window an
/// attacker could rewind).
///
/// So the window is measured in the only unit that survives a failed attempt:
/// **firmware releases**. It has a real cost and it should be stated here
/// rather than discovered in the field: closing it refuses the PIN outright for
/// a device whose owner has not typed the PIN since the upgrade. That is the
/// intended outcome — such a device is running an unsalted `SHA256(PIN)[..16]`
/// and the KDF this story exists to strengthen has not reached it — but it is a
/// user-visible lockout and belongs behind a deliberate, announced bump of this
/// constant, not a refactor.
pub const PIN_VERIFIER_LEGACY_GRACE_RELEASE: u32 = 1;

/// This build's index in the migration window. Below
/// [`PIN_VERIFIER_LEGACY_GRACE_RELEASE`] today, so the window is **open**:
/// legacy records still verify and still migrate. The release process bumps
/// it; nothing else may.
///
/// Strictly `<` and not `<=`, so that "this build is release 0, the minimum"
/// is a statement about the *window* rather than a tautology about `u32`:
/// `clippy::absurd_extreme_comparisons` rejects `<=` here for exactly that
/// reason, and a comparison that is always true is not one that can be
/// reasoned about when the release index moves.
pub const PIN_VERIFIER_RELEASE_INDEX: u32 = 0;

/// Whether this build still admits a legacy-format verifier — the single
/// place the window is decided, so the admission check and the migration
/// trigger cannot be changed in two files that disagree about whether the
/// window is open.
pub const PIN_VERIFIER_LEGACY_WINDOW_OPEN: bool =
    PIN_VERIFIER_RELEASE_INDEX < PIN_VERIFIER_LEGACY_GRACE_RELEASE;

/// The build-time half of the legacy window: release 1 is the first build
/// that refuses legacy verifiers. Asserting the comparison *and* spelling out
/// what it would take to close the window is the point — a reader who wants
/// to close it has to edit two constants and re-derive this.
const _: () = assert!(
    PIN_VERIFIER_LEGACY_GRACE_RELEASE >= 1,
    "release 0 shipped with the raised PIN_VERIFIER_ROUNDS and admitted \
     legacy verifiers, so grace cannot be revoked from it: a legacy record \
     on such a device has already had its migration opportunity"
);

/// Why a stored PIN verifier was refused **before** any PIN guess was spent.
///
/// This is a separate step from [`pin_verifier_matches`] on purpose. The
/// comparison is where a wrong PIN is detected and costs a retry; admission is
/// where a *record* is found not to be one this build is willing to verify
/// against at all, and answering it must not cost the user anything — there is
/// no guess involved and there is nothing to learn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinVerifierRefusal {
    /// The record is in the pre-US-910 format (bare `SHA256(PIN)[..16]`,
    /// unsalted, unstretched) and the migration window is closed. The PIN is
    /// not refused because it is wrong — it is refused because the record no
    /// longer describes a verifier this build will run. The owner's remedy is
    /// a `setPIN`, which requires no old PIN (`CTAP2_ERR_NOT_ALLOWED` only
    /// applies when one is already set, and the recovery is the factory-reset
    /// path).
    LegacyWindowClosed,
    /// The record claims more rounds than [`PIN_VERIFIER_ROUNDS`].
    ///
    /// **This is a defence in depth, not the first line.** Both snapshot
    /// decoders already refuse such a record at parse time — a non-zero exit,
    /// not a clamp — in `device_keystore.rs` (`Item::U(u) if
    /// u <= crypto::PIN_VERIFIER_ROUNDS`, "corrupt input is refused, never
    /// truncated") and in `keystore.rs` (`if i > crypto::PIN_VERIFIER_ROUNDS
    /// as u64 { return None }`). They are the right place for it: an
    /// attacker-crafted iteration count is a *parse* hazard (FX-440), and a
    /// parse-time refusal cannot be reached by any code path at all.
    ///
    /// Repeating the check here is cheap and is stated as what it is. The
    /// reason it is not redundant is that it is the copy that moves when the
    /// constant moves: US-1570 raises `PIN_VERIFIER_ROUNDS` 16x, and the two
    /// decoders read that constant rather than hard-coding 4096, so there is
    /// no second number to forget. What this adds is that a caller which
    /// assembles a verifier **without** going through a snapshot decoder — a
    /// restored backup, a vendor `0x41` import, a future migration path —
    /// still gets the refusal.
    IterationsOverBudget {
        /// The count the record asked for.
        claimed: u32,
    },
    /// The record claims the stretched format but carries no salt. Unverifiable
    /// by construction: `pin_verifier_matches` has no salt to re-derive with,
    /// and its fallback arm compares the candidate directly, which is the
    /// legacy comparison wearing a stretched flag — a record that would verify
    /// a bare PIN hash. Refused here so that fallback can only ever be reached
    /// by a record that says it is legacy.
    Malformed,
}

/// Decide whether this build will verify against a stored PIN verifier at all,
/// from the record's own fields.
///
/// This is the admission gate US-1570 adds on top of US-910's parse-time
/// ceilings, and it is the expression of the two clauses of the story that the
/// decoders cannot express:
///
/// * **"the snapshot-decode ceiling refuses any iteration count the new budget
///   cannot serve"** — the decoders refuse at *parse* time; this refuses the
///   same condition for a verifier that did not arrive through a snapshot, and
///   it refuses it with a **distinguishable** value rather than a `bool`, so a
///   caller can answer the client with a different status for "this record is
///   not verifiable" than for "this PIN is wrong". Collapsing the two is what
///   lets an attacker spend nothing while probing which records exist.
/// * **"legacy-format verifiers are refused after the migration window"** —
///   the window itself ([`PIN_VERIFIER_LEGACY_WINDOW_OPEN`]), which is the one
///   half of the migration story the snapshot format has nowhere to record.
///
/// `format == 0` with the window open is admitted and must be migrated on the
/// next successful verification; every other shape is either accepted or
/// refused here, never "accepted and quietly verified some other way".
pub fn pin_verifier_admission(
    format: u8,
    pin_iter: u32,
    salt: Option<&[u8; 16]>,
) -> Result<(), PinVerifierRefusal> {
    if format == PIN_VERIFIER_FORMAT_STRETCHED {
        // Order matters: a stretched record with no salt is corrupt whatever
        // its count says, and reporting the count first would tell an attacker
        // crafting records which of their two defects the decoder noticed.
        if salt.is_none() {
            return Err(PinVerifierRefusal::Malformed);
        }
        if pin_iter > PIN_VERIFIER_ROUNDS {
            return Err(PinVerifierRefusal::IterationsOverBudget { claimed: pin_iter });
        }
        return Ok(());
    }
    // Any non-`1` format byte is a legacy record. There is no third value to
    // handle separately, and inventing one here would be inventing a format
    // no encoder emits.
    if !PIN_VERIFIER_LEGACY_WINDOW_OPEN {
        return Err(PinVerifierRefusal::LegacyWindowClosed);
    }
    Ok(())
}

/// SHA-256 of a **fixed-size** message, through `sink`.
///
/// The fixed size is not a style choice, it is the point: it makes the bit
/// length a compile-time constant, so there is no runtime `len * 8` to
/// overflow. SHA-256's length field counts **bits**, so the largest encodable
/// message is 2^61 − 1 bytes and a runtime `len * 8` silently wraps into a
/// well-formed digest of a *different* message — the failure
/// `platform::sha256_accel` refuses to wrap (its `Sha256Error::TooLong`, an
/// arm-only type, hence prose rather than a link).
///
/// The multiply below is therefore total rather than checked: `N` is a `usize`
/// and Rust caps a slice's length at `isize::MAX` bytes on every target this
/// firmware builds for, which is far below the 2^61 that would wrap a `u64`.
/// A PIN verifier's inputs are 60 bytes and 32 bytes; making that structural
/// means the check cannot be dropped in a later edit without the type changing
/// with it, and the `debug_assert` keeps the bound visible to a reader rather
/// than leaving it to be remembered.
fn sha256_fixed_via<const N: usize, S: fapico2_platform::sha256_accel::BlockSink>(
    msg: &[u8; N],
    sink: &mut S,
) -> Result<[u8; 32], S::Error> {
    // `1 << 61` rather than a bare 0: `absurd_extreme_comparisons` aside, the
    // named bound is the one the SHA-256 length field imposes, and this is the
    // line a reader checks it against.
    debug_assert!(N <= (1usize << 61), "SHA-256 cannot encode a 2^61-byte message");
    fapico2_platform::sha256_accel::hash_into(msg, (N as u64) * 8, sink)
}

/// US-1570: the stretched verifier's round loop, routed through a
/// [`BlockSink`](fapico2_platform::sha256_accel::BlockSink).
///
/// # Why the loop and not the sink are the portable part
///
/// The RP2350 SHA-256 block is a **compression-function** accelerator: it takes
/// 512-bit blocks, maintains the chaining state internally, and does not know
/// what a message is (`sha256_accel` module docs, quoting `WDATA`: *"Software
/// is responsible for ensuring the data is correctly padded and terminated"*).
/// It cannot therefore absorb an iterated hash the way a streaming hasher
/// would. Each round here is a fresh one-shot SHA-256 whose 32-byte output is
/// the next round's input, so the loop lives on this side of the seam and the
/// sink only ever sees single-block messages.
///
/// That is also why the block count is exactly `rounds + 1` and not `rounds`:
/// round 0's message is the 60-byte domain-separated input, and 60 > 55 forces
/// two padded blocks.
///
/// # Errors
///
/// Whatever `sink` reports. On the device that is the arm-only
/// `platform::sha256_accel::Sha256Error` and, per that module's rule, every
/// variant is a *detectable* failure — never a digest the caller cannot
/// distinguish from a real one. [`pin_verifier_stretched`] turns any of them
/// into the software path rather than into a verifier value.
pub fn pin_verifier_stretched_via<S: fapico2_platform::sha256_accel::BlockSink>(
    pin_hash: &[u8; 16],
    salt: &[u8; 16],
    rounds: u32,
    sink: &mut S,
) -> Result<[u8; 16], S::Error> {
    let mut input = [0u8; PIN_VERIFIER_INPUT_LEN];
    input[..PIN_VERIFIER_DOMAIN.len()].copy_from_slice(PIN_VERIFIER_DOMAIN);
    let mut off = PIN_VERIFIER_DOMAIN.len();
    input[off..off + 16].copy_from_slice(salt);
    off += 16;
    input[off..off + 16].copy_from_slice(pin_hash);

    let mut h = sha256_fixed_via(&input, sink)?;
    // `rounds.max(1)`, matching US-910's `for _ in 1..rounds.max(1)`: the
    // count is a total of SHA-256 evaluations, so round 0 above is the first
    // of them rather than one in addition to them. `max(1)` also keeps a
    // corrupt zero from degenerating into "hash nothing and return the domain
    // separator's digest" — the same refusal-not-truncation rule the snapshot
    // decoders apply to the count on the way in.
    for _ in 1..rounds.max(1) {
        h = sha256_fixed_via(&h, sink)?;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    Ok(out)
}

/// US-910 stretched PIN verifier in **software**: `SHA256` iterated `rounds`
/// times over `DOMAIN || salt || SHA256(PIN)[..16]`, truncated to 16 bytes.
///
/// This is US-910's loop, unchanged, and it is the definition of the digest
/// that every other path must reproduce.
///
/// # Why it is not routed through a `BlockSink`
///
/// It is tempting to give the software path a `BlockSink` over stock `sha2`
/// and run both paths through the same loop, so that "same digest" is
/// structural rather than tested. That does not work, and the reason is worth
/// recording because it is a trap any future sink implementation walks into.
///
/// [`fapico2_platform::sha256_accel::hash_into`] hands a sink blocks that are
/// **already padded** — `padding_blocks` runs before the first `push`. The
/// high-level `sha2::Digest` API is a *message* API: `update(block)` buffers and
/// `finalize()` appends `0x80`, the zeroes and the length field itself. Feeding
/// it a padded block and finalising therefore computes
/// `SHA256(padded_block)` — a 64-byte **message** with its own padding — and
/// not the compression of that block onto the chaining state. The digest is
/// well-formed and wrong, which is the worst shape a wrong answer can have:
/// nothing refuses it.
///
/// The high-level API exposes no way to say "this block is final, compress it
/// now", so a software sink would have to be the compression function itself.
/// Keeping the software path as an ordinary `sha256` call is the boring answer,
/// and it is also the faster one — no block copy per round. The equivalence
/// between this function and the accelerated one is therefore *tested*, not
/// assumed: `apps/fido/tests/pin_kdf_budget.rs` drives
/// [`pin_verifier_stretched_via`] through an independent raw-compression sink
/// and requires the same 16 bytes.
pub fn pin_verifier_stretched_software(
    pin_hash: &[u8; 16],
    salt: &[u8; 16],
    rounds: u32,
) -> [u8; 16] {
    let mut input = [0u8; PIN_VERIFIER_INPUT_LEN];
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
///
/// # US-1570: on the RP2350 this runs on the hardware block, not in software
///
/// The accelerated path is the **default** on a device build, and it is the
/// only reason [`PIN_VERIFIER_ROUNDS`] can be 65,536 rather than 4096: 65,536
/// software SHA-256 evaluations on a Cortex-M33 is minutes, not the
/// [`PIN_VERIFY_BUDGET_MS`] budget.
///
/// **The fallback is to software, not to an error, and the reason is
/// specific.** `sha256_accel` insists that a broken accelerator produce "a
/// distinguishable failure, never a plausible-looking hash", and that is
/// right for anything whose output is compared against an attacker-visible
/// MAC — there, a wrong digest is a forgery. Here the fallback is not a
/// different answer, it is *the same answer computed elsewhere*, because the
/// block is specified to be SHA-256 and its block assembly is differentially
/// tested against stock `sha2`
/// (`platform/tests/sha256_accel.rs`). So an `Err` from the accelerator means
/// "this board's block did not do the thing", and the correct response to that
/// is the slow path, not a refusal: refusing would turn a performance fault
/// into a bricked PIN, and letting the value through unclamped would be the
/// actual bug. `tests/pin_kdf_budget.rs::an_accelerator_that_stops_working_falls_back_rather_than_lying`
/// pins the fallback against a sink that fails mid-verification.
///
/// The signature is unchanged from US-910, so every existing caller
/// (`PinProtocol`, the device twin's `client_pin_inner`) gets the accelerated
/// path without a call-site edit.
pub fn pin_verifier_stretched(pin_hash: &[u8; 16], salt: &[u8; 16], rounds: u32) -> [u8; 16] {
    #[cfg(all(feature = "device", target_arch = "arm"))]
    {
        // `polled`, deliberately: `Sha256Accel::with_dma` needs a channel index
        // this crate cannot prove it owns (the RP2350 `PERIORS` arbitration is
        // not published by `rp-pac`, `sha256_accel`'s module docs), and
        // `PIN_VERIFIER_CYCLES_PER_ROUND_POLLED` is the figure the round count
        // was derived against — so this is both the safer driver and the one
        // the cost model describes.
        let mut accel = fapico2_platform::sha256_accel::Sha256Accel::polled();
        if let Ok(v) = pin_verifier_stretched_via(pin_hash, salt, rounds, &mut accel) {
            return v;
        }
    }
    pin_verifier_stretched_software(pin_hash, salt, rounds)
}


/// Verify a PIN-hash candidate against the stored verifier in either
/// format (US-910). `format` is the persisted `pin_verifier_format` value;
/// legacy (`0`) records compare the candidate directly, stretched (`1`)
/// records re-derive with the stored salt and iteration count. Comparison
/// is constant-time in both cases.
///
/// # US-1570: this does **not** include the admission check
///
/// [`pin_verifier_admission`] is a separate, prior step and it is not folded
/// in here, for a reason worth being explicit about: this function's contract
/// is "is this candidate the right one", and its answer is a `bool` that the
/// caller turns into a *spent retry*. Admission is "will this build verify
/// against this record at all", and folding it in would mean a record the
/// device has declined to verify reports the same thing as a wrong PIN —
/// which is both a wrong error status on the wire and an invitation to treat a
/// refusal as a guess.
///
/// The `_ => ct_eq(candidate, stored)` arm below is the reason that separation
/// matters: a stretched record with no salt lands there and is compared
/// *directly*, i.e. as a legacy record. That is correct for a record that
/// says it is legacy and a hole for one that says otherwise, so admission is
/// what refuses the latter before this is reached. A caller on a new code path
/// must call it.
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
///
/// # US-1570: this is also the round count's single emitter
///
/// The returned count is [`PIN_VERIFIER_ROUNDS`] and the returned verifier is
/// exactly that many rounds over the same salt — so a record written through
/// this function is by construction one the snapshot decoders accept, with no
/// gap between "the strongest verifier this build can produce" and "the
/// strongest verifier this build will read". `tests/pin_kdf_budget.rs`
/// asserts the two numbers are equal rather than merely close, because the
/// failure mode that would matter is a mismatch in the *other* direction:
/// writing a record the decoder later refuses is an unrecoverable PIN.
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
