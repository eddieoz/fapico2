//! AEAD sealing of sensitive keystore-snapshot fields (US-911).
//!
//! The `fido.keystore.v1` snapshot (host [`crate::keystore`] and no-heap
//! [`crate::device_keystore`] share the CBOR map format) used to carry the
//! credential private keys, hmac-secret / largeBlob values and the
//! `device_random` master as cleartext CBOR bstrs. This module seals those
//! fields with AES-256-GCM while every metadata field (rpId, user id,
//! credProtect flags, counters, ...) stays plaintext so credential
//! enumeration keeps working.
//!
//! # Key derivation (outside the snapshot — the circularity guard)
//!
//! The snapshot bytes cannot hold their own key (`device_random` sits IN the
//! snapshot), so the field key derives from material OUTSIDE the snapshot:
//! the [`fapico2_platform::secure_store::SecureStore::store_key`] AEAD key
//! (US-915). Field subkey:
//! `HKDF-SHA256(ikm = store_key, info = "fapico2 fido snapshot fields v1")`
//! — one subkey per store key, so a store-key rotation re-keys every field.
//!
//! Where the store key comes from:
//! * **Device** — [`fapico2_platform::secure_store::rp2350::
//!   Rp2350SecureStore::store_key`]: the boot-derived OTP+chipid key. An
//!   unkeyed store (pre-US-915 shape, host-test-only) keeps the legacy
//!   plaintext snapshot format — an unsealed store's serialization is
//!   unsealed end to end.
//! * **Host emulation / tests** — `HostSecureStore::store_key` returns the
//!   fixed [`fapico2_platform::store_v3::emulation_store_key`].
//! * **Host file keystore** — [`file_snapshot_store_key`]: the
//!   [`fapico2_platform::secure_store::FileSecureStore`] has no key of its
//!   own (a plain file stands in for the secure partition and holds no real
//!   secrets), but it must not carry plaintext credential keys either, so
//!   the file keystore uses this fixed documented key.
//!
//! # Wire format of one sealed field
//!
//! `[nonce 12B][ct = pt_len][tag 16B]` (`ct` is the GCM ciphertext, same
//! length as the plaintext — 28 bytes of overhead per field). The nonce is
//! **deterministic**: `SHA-256(field_key ‖ SHA-256(aad ‖ plaintext))[..12]`
//! — the same mirror-image rule format v3 uses for whole images. The same
//! snapshot content re-persists byte-identically (the persist gate's
//! compare-then-write stays quiet) and no `(key, nonce)` pair ever encrypts
//! two different plaintexts (the nonce digests the full content).
//!
//! # AAD (field identity)
//!
//! Every field's AAD binds the snapshot slot name, the field's scope tag and
//! — for credential fields — the credential ID: a value cannot be replayed
//! into another credential, another field or another slot.
//!
//! # Failure semantics (US-911 refusal contract)
//!
//! * A credential field that fails to open kills the **entry**: the codec
//!   keeps the plaintext metadata, zeroes the secret fields and marks the
//!   credential `revoked` — never silently zeroed away, never usable.
//! * An auth-level field (`device_random`, large-blob array, vault state)
//!   that fails to open fails the **whole snapshot** (`None` = Corrupt,
//!   fatal per FX-409/FX-440) — the stateless master is never garbage.
//!
//! # Snapshot format marker
//!
//! The top-level snapshot map carries `{2: 2}` when its sensitive fields are
//! sealed (the map previously held only the extensibility key `{1: [...]}`).
//! Parsing dispatches on the marker, so legacy plaintext snapshots keep
//! loading (and are re-persisted sealed on the next mutation).

use crate::cbor::no_heap::CborError;
use crate::crypto;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use heapless::Vec as HeaplessVec;

/// `info` for the field-subkey HKDF (see the module docs).
pub const FIELD_KEY_INFO: &[u8] = b"fapico2 fido snapshot fields v1";

/// AAD domain-separation prefix (every field AAD starts with it).
const AAD_PREFIX: &[u8] = b"fapico2 fido snapshot field v1";

/// Snapshot top-level map key holding the sealed-format marker...
/// ...and its value. `{2: 2}` = sensitive fields are AEAD-sealed.
pub const SEALED_MARKER_KEY: u64 = 2;
pub const SEALED_MARKER_VALUE: u64 = 2;

/// GCM nonce length.
pub const NONCE_LEN: usize = 12;
/// GCM auth tag length.
pub const TAG_LEN: usize = 16;
/// Per-field framing overhead: nonce(12) + tag(16) — ciphertext is
/// plaintext-length.
pub const FIELD_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Largest sensitive field plaintext (the device large-blob array bound).
/// Host fields are heap-sized and unbounded by this.
pub const MAX_FIELD_PT: usize = 1024;

/// Which snapshot field a sealed value belongs to (the AAD scope tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldScope {
    /// `StoredCredential.private_key` (snapshot key 3).
    CredentialPrivateKey,
    /// `StoredCredential.cred_blob` (snapshot key 17).
    CredentialBlob,
    /// `StoredCredential.large_blob_key` (snapshot key 18).
    CredentialLargeBlobKey,
    /// `StoredCredential.hmac_secret` (snapshot key 19).
    CredentialHmacSecret,
    /// `AuthState.large_blob_array` (snapshot auth key 3).
    AuthLargeBlobArray,
    /// `AuthState.vault_state` (snapshot auth key 4).
    AuthVaultState,
    /// `AuthState.device_random` (snapshot auth key 5) — the stateless
    /// master.
    AuthDeviceRandom,
    /// `VendorState.secret` (snapshot auth key 7) — the RS-Key `0x41` key
    /// material: the master seed, the sealed soft-lock key, the org
    /// attestation scalar and the audit checkpoint key. US-176.
    ///
    /// A **new** tag rather than a reuse of `AuthDeviceRandom`, even though
    /// both are "the wallet's secret": `device_random` leaves the token inside
    /// `getInfo`'s `encState` (`device_core.rs:1873-1875`), so it is a bearer
    /// value for the stateless-U2F path and not a secret at all. Binding two
    /// fields of different lifetimes to one AAD would let a value written as
    /// one be replayed as the other.
    AuthVendorSecret,
}

impl FieldScope {
    /// Stable scope tag bound into the AAD. Never rename — the AAD is part
    /// of the authenticated data and renaming breaks every stored snapshot.
    pub fn tag(&self) -> &'static str {
        match self {
            FieldScope::CredentialPrivateKey => "private-key",
            FieldScope::CredentialBlob => "cred-blob",
            FieldScope::CredentialLargeBlobKey => "large-blob-key",
            FieldScope::CredentialHmacSecret => "hmac-secret",
            FieldScope::AuthLargeBlobArray => "large-blob-array",
            FieldScope::AuthVaultState => "vault-state",
            FieldScope::AuthDeviceRandom => "device-random",
            // US-176. Named in `vendor_state`'s module docs as the tag of the
            // snapshot auth-key-7 field; it is a wire constant of the stored
            // snapshot format, so it is spelled out here rather than referred
            // to — a `SECRET_SCOPE_TAG` constant elsewhere would be a second
            // place for the two to disagree, and this `match` is where the
            // AAD is actually built.
            FieldScope::AuthVendorSecret => "vendor-secret",
        }
    }
}

/// The field AAD: `AAD_PREFIX ‖ 0 ‖ slot ‖ 0 ‖ scope_tag ‖ 0 ‖ cred_id`.
/// Fixed-size (the no-heap device codec builds it on the stack); the slot is
/// a `fido.keystore.v1` slot name and the credential ID the device bound is
/// ≤ [`crate::device_keystore::ID_MAX`]-shaped — 176 bytes covers the static
/// bounds with headroom.
#[derive(Clone, Copy)]
pub struct FieldAad {
    buf: [u8; 176],
    len: usize,
}

impl FieldAad {
    /// Build the AAD for one field. `slot` is the snapshot slot name
    /// (`fido.keystore.v1`), `cred_id` the raw credential-ID bytes (empty
    /// for auth-level fields).
    ///
    /// # Panics (host) / compile-time-bound (device)
    /// The inputs are static bounds (slot name ≤ 48 store-key bytes, scope
    /// tag ≤ 17, credential ID ≤ 64 on device); exceeding the fixed AAD
    /// buffer is a programming error, not a runtime condition, so it asserts.
    pub fn new(slot: &[u8], scope: FieldScope, cred_id: &[u8]) -> Self {
        let mut aad = Self { buf: [0u8; 176], len: 0 };
        aad.push(AAD_PREFIX);
        aad.push_byte(0);
        aad.push(slot);
        aad.push_byte(0);
        aad.push(scope.tag().as_bytes());
        aad.push_byte(0);
        aad.push(cred_id);
        aad
    }

    /// The AAD bytes (pass to [`seal_field`] / [`open_field`]).
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn push(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        assert!(end <= self.buf.len(), "field AAD bound exceeded");
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    fn push_byte(&mut self, b: u8) {
        self.push(&[b]);
    }
}

/// `HKDF-SHA256(ikm = store_key, info = "fapico2 fido snapshot fields v1")`
/// — the 32-byte AES-256-GCM subkey that seals every sensitive snapshot
/// field. Derived OUTSIDE the snapshot (the store key never appears in the
/// snapshot bytes), so sealing is not circular.
pub fn field_key(store_key: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    crypto::hkdf_sha256(None, store_key, FIELD_KEY_INFO, &mut out);
    out
}

/// The fixed store key for the host **file** keystore (the
/// [`fapico2_platform::secure_store::FileSecureStore`] backing file is the
/// secure-partition stand-in and holds no real secrets, but the snapshot it
/// carries must not hold plaintext credential keys either). Mirrors
/// `store_v3::emulation_store_key`: HKDF over fixed, public material, then
/// the ordinary [`field_key`] derivation on top.
pub fn file_snapshot_store_key() -> [u8; 32] {
    let mut out = [0u8; 32];
    crypto::hkdf_sha256(
        None,
        b"fapico2 host file keystore store key (no secrets)",
        b"store",
        &mut out,
    );
    out
}

/// Deterministic field nonce: `SHA-256(key ‖ SHA-256(aad ‖ pt))[..12]`.
/// Pure function of `(key, aad, plaintext)` — the same field re-seals to the
/// same bytes (compare-then-write stays quiet) and no `(key, nonce)` pair
/// ever encrypts two different plaintexts.
fn field_nonce(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> [u8; NONCE_LEN] {
    use sha2::Digest;
    let inner = {
        let mut h = sha2::Sha256::new();
        h.update(aad);
        h.update(pt);
        h.finalize()
    };
    let mut h = sha2::Sha256::new();
    h.update(key);
    h.update(inner);
    let out = h.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&out[..NONCE_LEN]);
    nonce
}

/// Seal one sensitive field into `out` as `[nonce][ct][tag]`.
/// `out` must be exactly `pt.len() + FIELD_OVERHEAD` bytes (the caller sizes
/// the CBOR bstr). Deterministic — see [`field_nonce`].
pub fn seal_field(key: &[u8; 32], aad: &[u8], pt: &[u8], out: &mut [u8]) -> Result<(), CborError> {
    // `out` is caller-sized (host heap / device stack scratch bounded by
    // MAX_FIELD_PT); its exact length is the caller's CBOR bstr contract.
    if out.len() != pt.len().saturating_add(FIELD_OVERHEAD) {
        return Err(CborError::BufferFull);
    }
    let nonce = field_nonce(key, aad, pt);
    out[..NONCE_LEN].copy_from_slice(&nonce);
    out[NONCE_LEN..NONCE_LEN + pt.len()].copy_from_slice(pt);
    let tag = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CborError::BufferFull)?
        .encrypt_in_place_detached(
            (&nonce).into(),
            aad,
            &mut out[NONCE_LEN..NONCE_LEN + pt.len()],
        )
        .map_err(|_| CborError::BufferFull)?;
    out[NONCE_LEN + pt.len()..].copy_from_slice(tag.as_slice());
    Ok(())
}

/// Open one sealed field (`blob` = `[nonce][ct][tag]`) into `out`;
/// returns the plaintext length. Fails closed on a tag mismatch (callers
/// apply the US-911 refusal semantics — entry killed or snapshot corrupt).
pub fn open_field(
    key: &[u8; 32],
    aad: &[u8],
    blob: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if blob.len() < FIELD_OVERHEAD {
        return None;
    }
    let pt_len = blob.len() - FIELD_OVERHEAD;
    if pt_len > out.len() {
        return None;
    }
    let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN].try_into().ok()?;
    let tag: [u8; TAG_LEN] = blob[blob.len() - TAG_LEN..].try_into().ok()?;
    out[..pt_len].copy_from_slice(&blob[NONCE_LEN..blob.len() - TAG_LEN]);
    Aes256Gcm::new_from_slice(key)
        .ok()?
        .decrypt_in_place_detached((&nonce).into(), aad, &mut out[..pt_len], (&tag).into())
        .ok()?;
    Some(pt_len)
}

/// Open one sealed field on the host (heap form of [`open_field`]).
#[cfg(feature = "host")]
pub fn open_field_vec(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Option<std::vec::Vec<u8>> {
    let mut out = std::vec![0u8; blob.len().saturating_sub(FIELD_OVERHEAD)];
    let n = open_field(key, aad, blob, &mut out)?;
    out.truncate(n);
    Some(out)
}

/// Build the field AAD into a heapless buffer (the no-heap device codec's
/// form — falls through to [`FieldAad`] bounds).
pub(crate) fn field_aad_heapless<const N: usize>(
    slot: &[u8],
    scope: FieldScope,
    cred_id: &[u8],
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), CborError> {
    out.clear();
    out.extend_from_slice(AAD_PREFIX).map_err(|_| CborError::BufferFull)?;
    out.push(0).map_err(|_| CborError::BufferFull)?;
    out.extend_from_slice(slot).map_err(|_| CborError::BufferFull)?;
    out.push(0).map_err(|_| CborError::BufferFull)?;
    out.extend_from_slice(scope.tag().as_bytes())
        .map_err(|_| CborError::BufferFull)?;
    out.push(0).map_err(|_| CborError::BufferFull)?;
    out.extend_from_slice(cred_id).map_err(|_| CborError::BufferFull)?;
    Ok(())
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn field_seal_open_round_trip() {
        let aad = FieldAad::new(b"fido.keystore.v1", FieldScope::CredentialPrivateKey, b"cred-1");
        let pt = [0x77u8; 32];
        let mut blob = [0u8; 32 + FIELD_OVERHEAD];
        seal_field(&KEY, aad.bytes(), &pt, &mut blob).unwrap();
        assert_ne!(&blob[NONCE_LEN..NONCE_LEN + 32], &pt, "ciphertext must differ from plaintext");
        let mut out = [0u8; 32];
        assert_eq!(open_field(&KEY, aad.bytes(), &blob, &mut out), Some(32));
        assert_eq!(out, pt);
    }

    #[test]
    fn field_seal_is_deterministic() {
        let aad = FieldAad::new(b"fido.keystore.v1", FieldScope::AuthDeviceRandom, &[]);
        let pt = [0x11u8; 32];
        let mut a = [0u8; 32 + FIELD_OVERHEAD];
        let mut b = [0u8; 32 + FIELD_OVERHEAD];
        seal_field(&KEY, aad.bytes(), &pt, &mut a).unwrap();
        seal_field(&KEY, aad.bytes(), &pt, &mut b).unwrap();
        assert_eq!(a, b, "the same (key, aad, pt) must re-seal byte-identically");
    }

    #[test]
    fn field_open_binds_aad() {
        let pt = [0x33u8; 32];
        let aad = FieldAad::new(b"fido.keystore.v1", FieldScope::CredentialHmacSecret, b"cred-9");
        let mut blob = [0u8; 32 + FIELD_OVERHEAD];
        seal_field(&KEY, aad.bytes(), &pt, &mut blob).unwrap();
        // A different credential ID / scope / slot must not open the value.
        let other_cred = FieldAad::new(b"fido.keystore.v1", FieldScope::CredentialHmacSecret, b"cred-8");
        let other_scope = FieldAad::new(b"fido.keystore.v1", FieldScope::CredentialPrivateKey, b"cred-9");
        let other_slot = FieldAad::new(b"other.slot.v1", FieldScope::CredentialHmacSecret, b"cred-9");
        let mut out = [0u8; 32];
        assert!(open_field(&KEY, other_cred.bytes(), &blob, &mut out).is_none());
        assert!(open_field(&KEY, other_scope.bytes(), &blob, &mut out).is_none());
        assert!(open_field(&KEY, other_slot.bytes(), &blob, &mut out).is_none());
    }

    #[test]
    fn field_open_fails_closed_on_bit_flip_and_wrong_key() {
        let pt = [0x55u8; 40];
        let aad = FieldAad::new(b"fido.keystore.v1", FieldScope::CredentialBlob, b"c");
        let mut blob = [0u8; 40 + FIELD_OVERHEAD];
        seal_field(&KEY, aad.bytes(), &pt, &mut blob).unwrap();
        let mut out = [0u8; 40];
        blob[7] ^= 0x01;
        assert!(open_field(&KEY, aad.bytes(), &blob, &mut out).is_none());
        blob[7] ^= 0x01;
        blob[NONCE_LEN] ^= 0x80; // flip one ciphertext byte (tag must catch it)
        assert!(open_field(&KEY, aad.bytes(), &blob, &mut out).is_none());
        blob[NONCE_LEN] ^= 0x80;
        let wrong_key = [0x43u8; 32];
        assert!(open_field(&wrong_key, aad.bytes(), &blob, &mut out).is_none());
        assert_eq!(open_field(&KEY, aad.bytes(), &blob, &mut out), Some(40));
        assert_eq!(out[..40], pt);
    }

    #[test]
    fn field_key_differs_per_store_key() {
        let k1 = field_key(&[1u8; 32]);
        let k2 = field_key(&[2u8; 32]);
        assert_ne!(k1, k2);
        assert_eq!(field_key(&[1u8; 32]), k1, "field key is a pure function");
    }
}
