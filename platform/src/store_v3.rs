//! Secure-partition image format v3 — encrypt-then-MAC (US-915, EPIC
//! SEC-HARDENING Phase D).
//!
//! The red team forged a valid format-v2 slot (`redteam/store_forge.py`):
//! v2 is `[PS2F][count][entries][crc32]` — plaintext entries guarded by an
//! unkeyed CRC-32 any attacker can recompute. Format v3 closes R6: every
//! entry's key/value is encrypted and the image is authenticated under an
//! AES-256-GCM key that never lives in the image — a flash dump (T4)
//! yields no usable secrets and a forged slot fails its tags.
//!
//! Wire format (all little-endian):
//!
//! ```text
//! [magic u32 = "PS3F"][count u32][nonce 12B]
//! per entry i:  [kl u32][vl u32][ct: kl+vl bytes][tag 16B]
//! [crc32 u32 over every byte before it]
//! ```
//!
//! * **Entry AEAD** — AES-256-GCM over `key ‖ value` (encrypted in place);
//!   entry nonce `i` = `nonce[0..8] ‖ (i as u32 LE)`; the AAD binds the
//!   whole image shape: `magic ‖ count ‖ i ‖ kl ‖ vl` — so the entry
//!   count, lengths and order are authenticated too (swapping, recounting
//!   or truncating entries breaks tags).
//! * **Determinism** —
//!   `nonce = SHA-256(store_key ‖ SHA-256(entries))[..12]`: the sealed
//!   image is a pure function of `(logical content, store key)`. This is
//!   load-bearing for the persist gate's compare-then-write (US-423
//!   canonical-image comparisons): the same store content re-seals to the
//!   same bytes, so unchanged stores do not reprogram flash. Distinct
//!   plaintexts derive distinct nonces (the nonce hashes the full
//!   content), so no `(key, nonce)` pair ever encrypts two different
//!   plaintexts — the GCM nonce-reuse hazard does not arise.
//! * **CRC kept** — the trailing CRC-32 stays the cheap torn-write
//!   detector (a truncated program fails the walk before the tags), while
//!   the tags catch what the CRC cannot: recomputed-CRC forgeries.
//! * **Key derivation** — [`derive_store_key`]:
//!   `HKDF-SHA256(ikm = otp_key_1 ‖ chipid, salt = "PS3F", info = "store")`.
//!   The OTP row (`boot.rs` `read_otp_key_1`) is the C-firmware key row;
//!   binding the chipid means a leaked store image does not decrypt on
//!   another device, and a leaked OTP row alone does not open this
//!   device's store. US-918 hardens further (boot-entropy record in the
//!   image header).
//!
//! **Boot policy** ([`boot_decision_sealed`]): a slot loads only as v3
//! (tags verified). A **CRC-valid v2 image** is the pre-update device
//! signature and is migrated exactly once into v3 — and only when **both**
//! slots hold valid v2 (the persist discipline always programs both, so a
//! successfully-persisted pre-update device shows valid v2 in both; a lone
//! v2 slot is a forgery or a torn write and is refused). The red-team
//! attack (forge the primary slot with a recomputed CRC) fails: v3 beats
//! v2, and a lone v2 slot with an erased or v3 shadow is refused — never
//! loaded, never silently re-seeded.
//!
//! On host (emulation / tests) the store key is the fixed
//! [`emulation_store_key`] — the emulator's secure-partition stand-in
//! holds no real secrets; its format is the real one so the host paths
//! exercise the exact on-flash layout.

use crate::secure_store::{
    crc32_update, read_exact_window, ImageReader, SecureStoreError, MAX_KEY_LEN,
};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Secure-partition image magic, format v3 — LE bytes `"PS3F"`.
pub const PARTITION_IMAGE_MAGIC_V3: u32 = 0x4633_5350;

/// GCM nonce length (the `Aes256Gcm` standard 12-byte nonce).
pub const V3_NONCE_LEN: usize = 12;
/// GCM auth tag length.
pub const V3_TAG_LEN: usize = 16;
/// v3 image header: magic(4) + count(4) + nonce(12).
pub const V3_HEADER_LEN: usize = 8 + V3_NONCE_LEN;
/// Per-entry framing overhead: kl(4) + vl(4) + tag(16) — the ciphertext is
/// plaintext-length (GCM is a stream cipher). The sealed image length is
/// `logical_len + 12 + 16 × entry_count`.
pub const V3_ENTRY_OVERHEAD: usize = 4 + 4 + V3_TAG_LEN;
/// Trailing CRC-32.
pub const V3_CRC_LEN: usize = 4;

/// The largest single-entry ciphertext the no_std streaming paths handle:
/// the device store's value bound (512) plus [`MAX_KEY_LEN`]. Host paths
/// use heap buffers and the full host value bound instead.
const STREAM_ENTRY_MAX: usize = MAX_KEY_LEN + 512;

type AeadResult<T> = core::result::Result<T, SecureStoreError>;

/// `HKDF-SHA256(ikm = otp_key_1 ‖ chipid, salt = "PS3F", info = "store")`
/// — the v3 store AEAD key (US-915). The OTP row is read by the firmware
/// (`read_otp_key_1`, `boot.rs`); the chipid binds the key to the physical
/// board, so a leaked store image does not decrypt on another device and a
/// leaked OTP row alone does not open this device's store. An all-zero OTP
/// row (factory part / never-initialized C firmware) derives a valid but
/// weaker key — acceptable for a fresh (empty) store; US-918 mixes the
/// boot-entropy record in.
pub fn derive_store_key(otp_key_1: &[u8; 32], chipid: &[u8; 8]) -> [u8; 32] {
    let mut ikm = [0u8; 40];
    ikm[..32].copy_from_slice(otp_key_1);
    ikm[32..].copy_from_slice(chipid);
    let hk = Hkdf::<Sha256>::new(Some(b"PS3F"), &ikm);
    let mut out = [0u8; 32];
    hk.expand(b"store", &mut out).expect("32 okm");
    out
}

/// The fixed host/emulation store key — HKDF over fixed, public material.
/// The emulation secure partition stands in for the RP2350 secure region
/// in tests and the emulator and holds no real secrets; its format is the
/// real one so the host paths exercise the exact on-flash layout.
pub fn emulation_store_key() -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"PS3F"), b"fapico2 emulation store key (no secrets)");
    let mut out = [0u8; 32];
    hk.expand(b"store", &mut out).expect("32 okm");
    out
}

/// The plaintext digest that seeds [`nonce_for`].
///
/// **Framed, not concatenated.** Each entry contributes
/// `index ‖ key_len ‖ key ‖ val_len ‖ val`, every scalar little-endian, so
/// the encoding is injective over the entry list. A bare `key ‖ val` does
/// not have that property — `("ab","c")` and `("a","bc")` produce the same
/// hash input — and a collision here would seal two different images under
/// one `(key, nonce)` pair, which is the GCM nonce-reuse hazard this module
/// documents as not arising.
///
/// Both sealing paths (the device's windowed emission in
/// [`crate::secure_store`] and the heap [`seal_image`]) call this, so the
/// canonical-image property [`nonce_for`] relies on cannot drift between
/// them.
pub fn entries_digest<'a, I>(entries: I) -> [u8; 32]
where
    I: IntoIterator<Item = (u32, u32, &'a [u8], u32, &'a [u8])>,
{
    let mut hasher = Sha256::new();
    for (i, kl, k, vl, v) in entries {
        hasher.update(i.to_le_bytes());
        hasher.update(kl.to_le_bytes());
        hasher.update(k);
        hasher.update(vl.to_le_bytes());
        hasher.update(v);
    }
    hasher.finalize().into()
}

/// Deterministic image nonce: `SHA-256(store_key ‖ SHA-256(entries))[..12]`.
/// A pure function of the sealed content + key — the same store content
/// re-seals byte-identically (compare-then-write stays quiet). `pub` for
/// the store implementations' own windowed emissions.
pub fn nonce_for(key: &[u8; 32], entries_digest: &[u8; 32]) -> [u8; V3_NONCE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(entries_digest);
    let out = hasher.finalize();
    let mut nonce = [0u8; V3_NONCE_LEN];
    nonce.copy_from_slice(&out[..V3_NONCE_LEN]);
    nonce
}

/// Per-entry nonce: the image nonce's first 8 bytes + the entry index
/// (little-endian). Distinct entries of one image never share a nonce.
fn entry_nonce(image_nonce: &[u8; V3_NONCE_LEN], index: usize) -> [u8; V3_NONCE_LEN] {
    let mut n = [0u8; V3_NONCE_LEN];
    n[..8].copy_from_slice(&image_nonce[..8]);
    n[8..].copy_from_slice(&(index as u32).to_le_bytes());
    n
}

/// Per-entry AAD: `magic ‖ count ‖ index ‖ kl ‖ vl ‖ image_nonce` — the
/// image shape is authenticated with every entry's tag, and the nonce binds
/// each tag to its own image (US-915 review: without it, a same-key
/// same-layout entry transplant from another image with a matching
/// nonce-prefix would decrypt).
fn entry_aad(
    image_nonce: &[u8; V3_NONCE_LEN],
    count: usize,
    index: usize,
    kl: usize,
    vl: usize,
) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[0..4].copy_from_slice(&PARTITION_IMAGE_MAGIC_V3.to_le_bytes());
    aad[4..8].copy_from_slice(&(count as u32).to_le_bytes());
    aad[8..12].copy_from_slice(&(index as u32).to_le_bytes());
    aad[12..16].copy_from_slice(&(kl as u32).to_le_bytes());
    aad[16..20].copy_from_slice(&(vl as u32).to_le_bytes());
    aad[20..32].copy_from_slice(image_nonce);
    aad
}

fn cipher(key: &[u8; 32]) -> AeadResult<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| SecureStoreError::Corrupt)
}

/// Encrypt one entry in place: `pt` (`key ‖ value`) becomes the ciphertext;
/// returns the 16-byte tag.
pub fn seal_entry(
    key: &[u8; 32],
    image_nonce: &[u8; V3_NONCE_LEN],
    count: usize,
    index: usize,
    kl: usize,
    vl: usize,
    pt: &mut [u8],
) -> AeadResult<[u8; V3_TAG_LEN]> {
    if pt.len() != kl + vl {
        return Err(SecureStoreError::Corrupt);
    }
    let nonce = entry_nonce(image_nonce, index);
    let tag = cipher(key)?
        .encrypt_in_place_detached((&nonce).into(), &entry_aad(image_nonce, count, index, kl, vl), pt)
        .map_err(|_| SecureStoreError::Corrupt)?;
    let mut out = [0u8; V3_TAG_LEN];
    out.copy_from_slice(tag.as_slice());
    Ok(out)
}

/// Decrypt one entry in place (the no_std streaming form — `ct` transits a
/// bounded stack window). Fails closed on a tag mismatch.
#[allow(clippy::too_many_arguments)] // streaming AEAD plumbing: every arg is a distinct bound
pub fn open_entry(
    key: &[u8; 32],
    image_nonce: &[u8; V3_NONCE_LEN],
    count: usize,
    index: usize,
    kl: usize,
    vl: usize,
    ct: &mut [u8],
    tag: &[u8; V3_TAG_LEN],
) -> AeadResult<()> {
    if ct.len() != kl + vl {
        return Err(SecureStoreError::Corrupt);
    }
    let nonce = entry_nonce(image_nonce, index);
    cipher(key)?
        .decrypt_in_place_detached(
            (&nonce).into(),
            &entry_aad(image_nonce, count, index, kl, vl),
            ct,
            tag.into(),
        )
        .map_err(|_| SecureStoreError::Corrupt)
}

// ---------------------------------------------------------------------------
// Host (heap) whole-image seal / unseal — the emulation and test shape.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "arm"))]
pub mod heap {
    use super::*;
    use crate::secure_store::{crc32, MAX_VALUE_LEN, PARTITION_IMAGE_MAGIC};
    use std::vec::Vec;

    /// The exact serialized length of the format-v3 image at the start of
    /// `v3` (host slice form, values up to [`MAX_VALUE_LEN`]). A structural
    /// walk plus the trailing CRC over the recovered prefix — the CRC binds
    /// the length, so erased 0xFF padding after the image (a fixed-size
    /// slot window) recovers the same length; tags are verified by
    /// [`unseal_image`] afterwards. `None` on any structural failure or
    /// CRC mismatch.
    pub fn sealed_image_len(v3: &[u8]) -> Option<usize> {
        if v3.len() < V3_HEADER_LEN + V3_CRC_LEN {
            return None;
        }
        if u32::from_le_bytes([v3[0], v3[1], v3[2], v3[3]]) != PARTITION_IMAGE_MAGIC_V3 {
            return None;
        }
        let count = u32::from_le_bytes([v3[4], v3[5], v3[6], v3[7]]) as usize;
        if count > 1024 {
            return None;
        }
        let mut i = V3_HEADER_LEN;
        for _ in 0..count {
            let lens: [u8; 8] = v3.get(i..i + 8)?.try_into().ok()?;
            let kl = u32::from_le_bytes(lens[0..4].try_into().ok()?) as usize;
            let vl = u32::from_le_bytes(lens[4..8].try_into().ok()?) as usize;
            if kl > MAX_KEY_LEN || vl > MAX_VALUE_LEN {
                return None;
            }
            let entry = 8usize
                .checked_add(kl)?
                .checked_add(vl)?
                .checked_add(V3_TAG_LEN)?;
            i = i.checked_add(entry)?;
            if i > v3.len() {
                return None;
            }
        }
        let tail: [u8; V3_CRC_LEN] = v3.get(i..i + V3_CRC_LEN)?.try_into().ok()?;
        let stored = u32::from_le_bytes(tail);
        (crc32(&v3[..i]) == stored).then_some(i + V3_CRC_LEN)
    }

    /// One logical entry: (key, value) plaintext.
    type Entry = (Vec<u8>, Vec<u8>);

    /// Seal a **logical format-v2 image** (the store's own serialization —
    /// `partition_image()` bytes) into a format-v3 image. `Err(Corrupt)`
    /// when the input is not a valid v2 image.
    pub fn seal_image(v2: &[u8], key: &[u8; 32]) -> AeadResult<Vec<u8>> {
        let entries = parse_v2_entries(v2)?;
        let count = entries.len();
        // Digest the plaintext entries for the deterministic nonce.
        let digest = entries_digest(entries.iter().enumerate().map(|(i, (k, v))| {
            (i as u32, k.len() as u32, k.as_slice(), v.len() as u32, v.as_slice())
        }));
        let image_nonce = nonce_for(key, &digest);

        let mut out = Vec::new();
        out.extend_from_slice(&PARTITION_IMAGE_MAGIC_V3.to_le_bytes());
        out.extend_from_slice(&(count as u32).to_le_bytes());
        out.extend_from_slice(&image_nonce);
        for (i, (k, v)) in entries.iter().enumerate() {
            let (kl, vl) = (k.len(), v.len());
            out.extend_from_slice(&(kl as u32).to_le_bytes());
            out.extend_from_slice(&(vl as u32).to_le_bytes());
            let mut pt = Vec::with_capacity(kl + vl);
            pt.extend_from_slice(k);
            pt.extend_from_slice(v);
            let tag = seal_entry(key, &image_nonce, count, i, kl, vl, &mut pt)?;
            out.extend_from_slice(&pt);
            out.extend_from_slice(&tag);
        }
        let crc = crc32(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    /// Unseal a format-v3 image back into the **logical format-v2 image**
    /// bytes (what `HostSecureStore::from_partition_image` restores from).
    /// `Err(Corrupt)` on any structural failure, tag mismatch or CRC
    /// mismatch — a forged or torn v3 image never yields entries.
    pub fn unseal_image(v3: &[u8], key: &[u8; 32]) -> AeadResult<Vec<u8>> {
        let entries = parse_v3_entries(v3, key, MAX_VALUE_LEN)?;
        rebuild_v2(&entries)
    }

    /// The v2→v3 migration (US-915 boot rule): seal a CRC-valid v2 image
    /// into v3. Refuses anything that does not validate as v2 — a forged
    /// slot never re-seeds into the new format.
    pub fn migrate_v2_image(v2: &[u8], key: &[u8; 32]) -> AeadResult<Vec<u8>> {
        crate::secure_store::partition_image_len(v2).ok_or(SecureStoreError::Corrupt)?;
        seal_image(v2, key)
    }

    /// Rebuild the logical v2 image bytes from plaintext entries.
    fn rebuild_v2(entries: &[(Vec<u8>, Vec<u8>)]) -> AeadResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&PARTITION_IMAGE_MAGIC.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (k, v) in entries {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k);
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v);
        }
        let crc = crc32(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    fn parse_v2_entries(img: &[u8]) -> AeadResult<Vec<Entry>> {
        let end = crate::secure_store::partition_image_len(img)
            .ok_or(SecureStoreError::Corrupt)?;
        let count = u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize;
        let mut i = 8;
        let mut entries = Vec::with_capacity(count);
        while i + 4 <= end - 4 {
            let kl = u32::from_le_bytes(img[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            let k = img[i..i + kl].to_vec();
            i += kl;
            let vl = u32::from_le_bytes(img[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            let v = img[i..i + vl].to_vec();
            i += vl;
            entries.push((k, v));
        }
        Ok(entries)
    }

    fn parse_v3_entries(
        img: &[u8],
        key: &[u8; 32],
        vl_cap: usize,
    ) -> AeadResult<Vec<Entry>> {
        if img.len() < V3_HEADER_LEN + V3_CRC_LEN {
            return Err(SecureStoreError::Corrupt);
        }
        if u32::from_le_bytes([img[0], img[1], img[2], img[3]]) != PARTITION_IMAGE_MAGIC_V3 {
            return Err(SecureStoreError::Corrupt);
        }
        let count = u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize;
        if count > 1024 {
            return Err(SecureStoreError::Corrupt);
        }
        // Trailing CRC first (the cheap torn-write gate).
        let crc_stored = u32::from_le_bytes(img[img.len() - 4..].try_into().unwrap());
        if crc32(&img[..img.len() - 4]) != crc_stored {
            return Err(SecureStoreError::Corrupt);
        }
        let mut image_nonce = [0u8; V3_NONCE_LEN];
        image_nonce.copy_from_slice(&img[8..8 + V3_NONCE_LEN]);

        let body_end = img.len() - V3_CRC_LEN;
        let mut i = V3_HEADER_LEN;
        let mut entries = Vec::with_capacity(count.min(64));
        for idx in 0..count {
            if i + 8 > body_end {
                return Err(SecureStoreError::Corrupt);
            }
            let kl = u32::from_le_bytes(img[i..i + 4].try_into().unwrap()) as usize;
            let vl = u32::from_le_bytes(img[i + 4..i + 8].try_into().unwrap()) as usize;
            i += 8;
            if kl > MAX_KEY_LEN || vl > vl_cap || i + kl + vl + V3_TAG_LEN > body_end {
                return Err(SecureStoreError::Corrupt);
            }
            let mut ct = img[i..i + kl + vl].to_vec();
            i += kl + vl;
            let tag: [u8; V3_TAG_LEN] = img[i..i + V3_TAG_LEN].try_into().unwrap();
            i += V3_TAG_LEN;
            open_entry(key, &image_nonce, count, idx, kl, vl, &mut ct, &tag)?;
            entries.push((ct[..kl].to_vec(), ct[kl..].to_vec()));
        }
        if i != body_end {
            return Err(SecureStoreError::Corrupt);
        }
        Ok(entries)
    }
}

#[cfg(not(target_arch = "arm"))]
pub use heap::{migrate_v2_image, seal_image, sealed_image_len, unseal_image};

// ---------------------------------------------------------------------------
// no_std streaming validation + restore (the device boot shape).
// ---------------------------------------------------------------------------

/// The exact serialized length of the format-v3 image at the start of the
/// medium, verifying every entry tag and the trailing CRC on the way — the
/// boot-time slot validator (windowed; no whole-image buffer exists).
/// `None` on any structural failure, tag mismatch or CRC mismatch.
pub fn sealed_image_len_reader(reader: &mut dyn ImageReader, key: &[u8; 32]) -> Option<usize> {
    let mut crc = 0xFFFF_FFFF_u32;
    let mut hdr = [0u8; V3_HEADER_LEN];
    read_exact_window(reader, 0, &mut hdr)?;
    crc = crc32_update(crc, &hdr);
    if u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) != PARTITION_IMAGE_MAGIC_V3 {
        return None;
    }
    let count = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    if count > 1024 {
        return None;
    }
    let mut image_nonce = [0u8; V3_NONCE_LEN];
    image_nonce.copy_from_slice(&hdr[8..]);

    let mut i = V3_HEADER_LEN;
    for idx in 0..count {
        let mut lens = [0u8; 8];
        read_exact_window(reader, i, &mut lens)?;
        crc = crc32_update(crc, &lens);
        let kl = u32::from_le_bytes([lens[0], lens[1], lens[2], lens[3]]) as usize;
        let vl = u32::from_le_bytes([lens[4], lens[5], lens[6], lens[7]]) as usize;
        i += 8;
        // US-915 (review): bound `vl` before the add — a near-u32::MAX `vl`
        // would wrap `vl + kl` on a 32-bit target and slip past this check
        // (the heap path bounds `vl` first for the same reason).
        if kl > MAX_KEY_LEN || vl > STREAM_ENTRY_MAX || kl + vl > STREAM_ENTRY_MAX {
            return None;
        }
        // ct + tag through one bounded stack window (the device boot stack
        // discipline: small fixed windows, never a whole image).
        let mut win = [0u8; STREAM_ENTRY_MAX];
        let ct_len = kl + vl;
        read_exact_window(reader, i, &mut win[..ct_len])?;
        crc = crc32_update(crc, &win[..ct_len]);
        i += ct_len;
        let mut tag = [0u8; V3_TAG_LEN];
        read_exact_window(reader, i, &mut tag)?;
        crc = crc32_update(crc, &tag);
        i += V3_TAG_LEN;
        open_entry(key, &image_nonce, count, idx, kl, vl, &mut win[..ct_len], &tag).ok()?;
    }
    let mut tail = [0u8; V3_CRC_LEN];
    read_exact_window(reader, i, &mut tail)?;
    let stored = u32::from_le_bytes(tail);
    (!crc == stored).then_some(i + V3_CRC_LEN)
}

/// [`sealed_image_len_reader`] as a plain predicate.
pub fn sealed_image_is_valid_reader(reader: &mut dyn ImageReader, key: &[u8; 32]) -> bool {
    sealed_image_len_reader(reader, key).is_some()
}

/// Slice twin of [`sealed_image_is_valid_reader`] (host tests / emulator).
#[cfg(not(target_arch = "arm"))]
pub fn sealed_image_is_valid(img: &[u8], key: &[u8; 32]) -> bool {
    use crate::secure_store::SliceReader;
    let mut r = SliceReader::new(img);
    sealed_image_len_reader(&mut r, key).is_some()
}

/// Read the next v3 entry at `off` through `reader`, decrypting key and
/// value into `kbuf` / `vbuf` (bounded by [`MAX_KEY_LEN`] and
/// [`STREAM_ENTRY_MAX`] − [`MAX_KEY_LEN`]). Returns `(kl, vl, next_off)`,
/// or `None` on any structural failure / tag mismatch. The caller
/// validates the WHOLE image first (all-or-nothing).
#[allow(clippy::too_many_arguments)] // streaming AEAD plumbing: every arg is a distinct bound
pub fn sealed_next_entry(
    reader: &mut dyn ImageReader,
    key: &[u8; 32],
    image_nonce: &[u8; V3_NONCE_LEN],
    count: usize,
    index: usize,
    off: usize,
    kbuf: &mut [u8; MAX_KEY_LEN],
    vbuf: &mut [u8],
) -> Option<(usize, usize, usize)> {
    let mut lens = [0u8; 8];
    read_exact_window(reader, off, &mut lens)?;
    let kl = u32::from_le_bytes([lens[0], lens[1], lens[2], lens[3]]) as usize;
    let vl = u32::from_le_bytes([lens[4], lens[5], lens[6], lens[7]]) as usize;
    if kl > MAX_KEY_LEN || vl > vbuf.len() || kl + vl > STREAM_ENTRY_MAX {
        return None;
    }
    let ct_len = kl + vl;
    let mut win = [0u8; STREAM_ENTRY_MAX];
    read_exact_window(reader, off + 8, &mut win[..ct_len])?;
    let mut tag = [0u8; V3_TAG_LEN];
    read_exact_window(reader, off + 8 + ct_len, &mut tag)?;
    open_entry(key, image_nonce, count, index, kl, vl, &mut win[..ct_len], &tag).ok()?;
    kbuf[..kl].copy_from_slice(&win[..kl]);
    vbuf[..vl].copy_from_slice(&win[kl..ct_len]);
    Some((kl, vl, off + 8 + ct_len + V3_TAG_LEN))
}

/// The sealed boot decision (US-915 boot rule — the v2-era four-way
/// decision's load semantics, replaced):
///
/// * `LoadPrimary` / `LoadShadow` — a **tag-verified v3** slot; load it.
/// * `MigratePrimary` — **both** slots hold CRC-valid format-v2 images
///   (the pre-update device signature: the persist discipline programs
///   both slots, so a successfully-persisted v2 device shows valid v2 in
///   both). The caller restores the primary's v2 image and immediately
///   re-seals — the boot persist gate's "slot bytes ≠ store
///   serialization" repair path is exactly that, so the migration needs
///   no new persist machinery.
/// * `Fresh` — both slots erased; first boot, empty store.
/// * `Refuse` — content is present but nothing validates: a lone v2 slot
///   (forgery or torn write — the red-team attack shape), a bad-tag v3,
///   or corrupt content. Never loaded, never silently re-seeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedBootDecision {
    /// The primary slot holds a valid v3 image; load it.
    LoadPrimary,
    /// The primary is invalid but the shadow holds a valid v3 image.
    LoadShadow,
    /// Both slots hold valid format-v2 images: restore the primary's and
    /// migrate (re-seal) once.
    MigratePrimary,
    /// Both slots erased; first boot, empty store.
    Fresh,
    /// Content present but nothing validates; refuse to boot.
    Refuse,
}

/// Reader form — the device boot path (US-715 windowed discipline).
/// `erased_window` is the byte window the erased check walks on each slot
/// (the device passes its whole slot size; a whole-slot all-`0xFF` read is
/// the erased-flash signature).
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn boot_decision_sealed_reader(
    primary: &mut dyn ImageReader,
    shadow: &mut dyn ImageReader,
    key: &[u8; 32],
    erased_window: usize,
) -> SealedBootDecision {
    if sealed_image_is_valid_reader(primary, key) {
        return SealedBootDecision::LoadPrimary;
    }
    if sealed_image_is_valid_reader(shadow, key) {
        return SealedBootDecision::LoadShadow;
    }
    if crate::secure_store::slot_is_erased_reader(primary, erased_window)
        && crate::secure_store::slot_is_erased_reader(shadow, erased_window)
    {
        return SealedBootDecision::Fresh;
    }
    // The pre-update device signature: both slots CRC-valid format-v2.
    if crate::secure_store::partition_image_is_valid_reader(primary)
        && crate::secure_store::partition_image_is_valid_reader(shadow)
    {
        return SealedBootDecision::MigratePrimary;
    }
    SealedBootDecision::Refuse
}

/// Slice twin — the host/emulator boot path (whole images in memory).
/// Each slice's own length is its erased-check window (an empty slice is
/// the erased shape, matching the emulator's absent shadow slot).
#[cfg(not(target_arch = "arm"))]
pub fn boot_decision_sealed(
    primary: &[u8],
    shadow: &[u8],
    key: &[u8; 32],
) -> SealedBootDecision {
    use crate::secure_store::{SliceReader, slot_is_erased_reader};
    use crate::secure_store::partition_image_is_valid;
    let primary_valid = {
        let mut p = SliceReader::new(primary);
        sealed_image_is_valid_reader(&mut p, key)
    };
    if primary_valid {
        return SealedBootDecision::LoadPrimary;
    }
    let shadow_valid = {
        let mut s = SliceReader::new(shadow);
        sealed_image_is_valid_reader(&mut s, key)
    };
    if shadow_valid {
        return SealedBootDecision::LoadShadow;
    }
    // An erased slot is all-0xFF or empty (the emulation shape); each
    // slice's own length is its erased-check window.
    let primary_erased =
        slot_is_erased_reader(&mut SliceReader::new(primary), primary.len());
    let shadow_erased =
        slot_is_erased_reader(&mut SliceReader::new(shadow), shadow.len());
    if primary_erased && shadow_erased {
        return SealedBootDecision::Fresh;
    }
    // The pre-update device signature: both slots CRC-valid format-v2.
    if partition_image_is_valid(primary) && partition_image_is_valid(shadow) {
        return SealedBootDecision::MigratePrimary;
    }
    SealedBootDecision::Refuse
}
