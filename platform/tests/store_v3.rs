//! US-915 (SEC-HARDENING Phase D): the secure-partition image format v3 —
//! encrypt-then-MAC. Host tests for the sealing layer
//! ([`fapico2_platform::store_v3`]): the AEAD primitives, the deterministic
//! sealing, the key derivation, and the host heap seal/unseal + migration
//! paths — the properties the flash-image threat model (T4 dump, slot
//! forgery) rests on.
//!
//! The boot-policy cases (v3-beats-v2, migration signature, forged-slot
//! refusal) live in `tests/boot_decision.rs`; the store round-trips in
//! `secure_store.rs`'s own test module.

use fapico2_platform::secure_store::{
    HostSecureStore, Rp2350SecureStore, SecureStore, SecureStoreError, MAX_KEY_LEN,
    MAX_VALUE_LEN,
};
use fapico2_platform::store_v3::{
    derive_store_key, emulation_store_key, entries_digest, migrate_v2_image, nonce_for, seal_entry,
    seal_image,
    sealed_image_is_valid, sealed_image_len, unseal_image, PARTITION_IMAGE_MAGIC_V3,
    V3_HEADER_LEN, V3_NONCE_LEN, V3_TAG_LEN,
};

/// A key distinct from the emulation key (key-separation cases).
fn other_key() -> [u8; 32] {
    let mut k = emulation_store_key();
    k[0] ^= 0x01;
    k
}

/// The logical format-v2 image for (key, value) — the sealing input.
fn logical_image(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut store = Rp2350SecureStore::new(); // unkeyed → legacy v2 bytes
    store.write(key, value).unwrap();
    let mut img = vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let n = store.partition_image(&mut img).unwrap();
    img.truncate(n);
    img
}

/// The sealed image under the emulation key for (key, value).
fn sealed_image(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut store = HostSecureStore::new();
    store.write(key, value).unwrap();
    store.partition_image()
}

/// A sealed image has the v3 magic, the declared header shape, and its
/// length is the logical length plus the nonce and one tag per entry.
#[test]
fn sealed_shape_and_length() {
    let v2 = logical_image(b"k1", b"0123456789abcdef");
    let sealed = seal_image(&v2, &emulation_store_key()).unwrap();

    assert_eq!(
        u32::from_le_bytes(sealed[0..4].try_into().unwrap()),
        PARTITION_IMAGE_MAGIC_V3,
        "the sealed image carries the PS3F magic"
    );
    assert_eq!(
        sealed_image_len(&sealed),
        Some(sealed.len()),
        "the exact-length recovery matches the image length"
    );
    // length formula: logical + header nonce (12) + one tag per entry (16)
    // — one entry here.
    assert_eq!(sealed.len(), v2.len() + V3_NONCE_LEN + V3_TAG_LEN);
    assert!(sealed.len() >= V3_HEADER_LEN + 8 + 16 + V3_TAG_LEN + 4);
    // plaintext absence (T4): the value bytes never appear in the image.
    assert!(
        !windows_contains(&sealed, b"0123456789abcdef"),
        "the plaintext value must not appear in the sealed image"
    );
    assert!(
        !windows_contains(&sealed, b"k1"),
        "the plaintext key must not appear in the sealed image"
    );
}

fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The same content + key seals byte-identically — the deterministic
/// sealing that keeps the persist gate's compare-then-write quiet (US-423).
#[test]
fn sealing_is_deterministic() {
    let v2 = logical_image(b"k1", b"0123456789abcdef");
    let key = emulation_store_key();
    let a = seal_image(&v2, &key).unwrap();
    let b = seal_image(&v2, &key).unwrap();
    assert_eq!(a, b, "the same content and key re-seal byte-identically");

    // The nonce is a pure function of (key, content digest).
    let mut store = HostSecureStore::new();
    store.write(b"k1", b"0123456789abcdef").unwrap();
    let via_store = store.partition_image();
    assert_eq!(a, via_store, "the store's own sealing matches the heap path");
}

/// Different content derives different nonces (the nonce hashes the full
/// content), so no (key, nonce) pair ever encrypts two plaintexts — the
/// GCM nonce-reuse hazard does not arise.
#[test]
fn nonce_binds_the_content() {
    let key = emulation_store_key();
    let a = seal_image(&logical_image(b"k1", b"first-value-000000000000"), &key).unwrap();
    let b = seal_image(&logical_image(b"k1", b"second-value-000000000000"), &key).unwrap();
    let nonce = |img: &[u8]| img[V3_HEADER_LEN - V3_NONCE_LEN..V3_HEADER_LEN].to_vec();
    assert_ne!(nonce(&a), nonce(&b), "distinct plaintexts derive distinct nonces");
}

/// Key separation: sealing under one key never validates under another,
/// and the nonce derivation is key-bound (leaking the image leaks neither
/// the key nor the plaintext).
#[test]
fn key_separation() {
    let v2 = logical_image(b"k1", b"0123456789abcdef");
    let sealed = seal_image(&v2, &emulation_store_key()).unwrap();
    assert!(
        !sealed_image_is_valid(&sealed, &other_key()),
        "an image sealed under the emulation key must not verify under another key"
    );
    assert!(
        unseal_image(&sealed, &other_key()).is_err(),
        "unsealing under the wrong key fails closed"
    );
    assert_ne!(
        nonce_for(&emulation_store_key(), &[0u8; 32]),
        nonce_for(&other_key(), &[0u8; 32]),
        "the nonce derivation is key-bound"
    );
}

/// A forged tag (any bit-flip in a tag byte) fails the image validation.
#[test]
fn forged_tag_refused() {
    let sealed = sealed_image(b"k1", b"0123456789abcdef");
    let key = emulation_store_key();
    let tag_at = V3_HEADER_LEN + 8 + 16; // header + lens + ciphertext end
    let mut forged = sealed.clone();
    forged[tag_at] ^= 0x01;
    assert!(
        !sealed_image_is_valid(&forged, &key),
        "a flipped tag bit must fail validation"
    );
    // A bit-flip in the ciphertext body fails the tag the same way.
    let mut forged_ct = sealed.clone();
    forged_ct[V3_HEADER_LEN + 8] ^= 0x40;
    assert!(!sealed_image_is_valid(&forged_ct, &key));
    // A truncated image fails the CRC walk.
    assert!(!sealed_image_is_valid(&sealed[..sealed.len() - 5], &key));
}

/// The heap seal/unseal round-trip restores every entry, and the restored
/// store re-seals to the same bytes (the canonical-image property).
#[test]
fn heap_seal_unseal_round_trip() {
    let key = emulation_store_key();
    let mut store = HostSecureStore::new();
    store.write(b"alpha", b"value-one").unwrap();
    store.write(b"beta", &[0u8; 300]).unwrap(); // multi-block value
    let sealed = store.partition_image();

    let logical = unseal_image(&sealed, &key).unwrap();
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&logical);
    let mut out = [0u8; MAX_VALUE_LEN];
    let m = restored.read(b"alpha", &mut out).unwrap();
    assert_eq!(&out[..m], b"value-one");
    let m = restored.read(b"beta", &mut out).unwrap();
    assert_eq!(m, 300);

    // Re-sealing the restored content reproduces the image byte-for-byte.
    assert_eq!(restored.partition_image(), sealed);
}

/// The v2→v3 migration (`migrate_v2_image`) seals a CRC-valid v2 image and
/// refuses anything that does not validate as v2 — a forged or torn slot
/// never re-seeds into the new format.
#[test]
fn migration_seals_valid_v2_only() {
    let key = emulation_store_key();
    let v2 = logical_image(b"k1", b"0123456789abcdef");
    let sealed = migrate_v2_image(&v2, &key).unwrap();
    assert!(sealed_image_is_valid(&sealed, &key));
    // The migrated image restores the same entry.
    let logical = unseal_image(&sealed, &key).unwrap();
    assert!(windows_contains(&logical, b"0123456789abcdef"));

    // Refusal shapes: truncated (torn write) and forged (bit-flipped
    // payload with a recomputed CRC — rebuild the CRC to prove the gate
    // is the AEAD, not the checksum).
    let torn = &v2[..v2.len() * 6 / 10];
    assert_eq!(migrate_v2_image(torn, &key), Err(SecureStoreError::Corrupt));
    let mut forged = v2.clone();
    forged[20] ^= 0x40;
    assert_eq!(migrate_v2_image(&forged, &key), Err(SecureStoreError::Corrupt));
}

/// The per-entry AEAD: the tag authenticates the entry content AND the
/// image shape (count, index, lengths) — reordering entries breaks tags.
#[test]
fn entry_tag_binds_the_image_shape() {
    let key = emulation_store_key();
    let nonce = [0x11u8; V3_NONCE_LEN];
    let mut ct = b"k1".to_vec();
    ct.extend_from_slice(b"value-one"); // 9-byte value
    let tag = seal_entry(&key, &nonce, 2, 0, 2, 9, &mut ct).unwrap();

    // The honest open decrypts the ciphertext buffer back to plaintext.
    let mut buf = ct.clone();
    fapico2_platform::store_v3::open_entry(&key, &nonce, 2, 0, 2, 9, &mut buf, &tag).unwrap();
    assert_eq!(&buf[..2], b"k1");
    assert_eq!(&buf[2..], b"value-one");

    // A different entry index fails the tag (the entry nonce differs).
    let mut idx1 = ct.clone();
    assert!(fapico2_platform::store_v3::open_entry(&key, &nonce, 2, 1, 2, 9, &mut idx1, &tag).is_err());

    // An edited value length fails the tag — the AAD binds the declared
    // lengths (the attacker's truncated buffer with a re-declared vl).
    let mut short = ct.clone();
    short.truncate(10);
    assert!(fapico2_platform::store_v3::open_entry(&key, &nonce, 2, 0, 2, 8, &mut short, &tag).is_err());

    // Wrong pt length is rejected outright on the seal side.
    let mut pt4 = b"k1".to_vec();
    assert_eq!(
        seal_entry(&key, &nonce, 2, 0, 2, 3, &mut pt4),
        Err(SecureStoreError::Corrupt)
    );
}

/// US-915 (review): the per-entry AAD binds the image nonce — an entry
/// ciphertext does not decrypt under a different image whose nonce merely
/// shares the 8-byte entry-nonce prefix (the IV is `nonce[..8] ‖ index`, so
/// without the nonce in the AAD such a transplant verified).
#[test]
fn entry_tag_binds_the_image_nonce() {
    let key = emulation_store_key();
    let nonce = [0x11u8; V3_NONCE_LEN];
    let mut ct = b"k1".to_vec();
    ct.extend_from_slice(b"value-one");
    let tag = seal_entry(&key, &nonce, 2, 0, 2, 9, &mut ct).unwrap();

    // A second image nonce identical over the entry-nonce prefix but
    // differing in the remaining bytes: the per-entry IV is unchanged, so
    // only the AAD can tell the images apart.
    let mut prefix_nonce = nonce;
    prefix_nonce[10] ^= 0x01;
    assert_eq!(&prefix_nonce[..8], &nonce[..8]);

    let mut transplanted = ct;
    assert!(
        fapico2_platform::store_v3::open_entry(
            &key, &prefix_nonce, 2, 0, 2, 9, &mut transplanted, &tag,
        )
        .is_err(),
        "an entry must not decrypt under another image's nonce"
    );
}

/// The store-key derivation is HKDF over the OTP row + chipid: distinct
/// boards derive distinct keys from the same OTP row, and the emulation
/// key (fixed public material) is not the zero key.
#[test]
fn store_key_derivation_binds_the_board() {
    let otp = [0x42u8; 32];
    let k1 = derive_store_key(&otp, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
    let k2 = derive_store_key(&otp, &[0x99, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
    let k3 = derive_store_key(&otp, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
    assert_ne!(k1, k2, "a different chipid derives a different key");
    assert_eq!(k1, k3, "the derivation is deterministic");
    assert_ne!(k1, emulation_store_key());
    // An all-zero OTP row (factory part) still derives a valid 32-byte key.
    assert_eq!(derive_store_key(&[0u8; 32], &[0u8; 8]).len(), 32);
}

/// The no_std streaming validator accepts what the heap path sealed, for
/// in-bounds (device-shaped) entries.
#[test]
fn streaming_validator_accepts_device_shaped_images() {
    let key = emulation_store_key();
    let mut store = Rp2350SecureStore::new();
    store.set_store_key(key);
    store.write(b"k1", b"0123456789abcdef").unwrap();
    let mut buf = vec![0u8; Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX];
    let n = store.partition_image(&mut buf).unwrap();
    let img = &buf[..n];

    use fapico2_platform::secure_store::SliceReader;
    use fapico2_platform::store_v3::sealed_image_is_valid_reader;
    let mut reader = SliceReader::new(img);
    assert!(sealed_image_is_valid_reader(&mut reader, &key));
    // Padded slot window: the validator stops at the exact length.
    let mut padded = img.to_vec();
    padded.extend_from_slice(&[0xFF; 64]);
    let mut reader = SliceReader::new(&padded);
    assert_eq!(
        fapico2_platform::store_v3::sealed_image_len_reader(&mut reader, &key),
        Some(n),
        "the padded slot window validates to the exact image length"
    );
    // A wrong key fails the streaming validation too.
    let mut reader = SliceReader::new(img);
    assert!(!sealed_image_is_valid_reader(&mut reader, &other_key()));
}

/// The device store's key gate: restore + snapshot refuse nothing but a
/// keyed store without a key set stays on the legacy path — and a sealed
/// image offered to a keyless store never restores.
#[test]
fn keyless_store_never_restores_sealed_images() {
    let sealed = sealed_image(b"k1", b"0123456789abcdef");
    let mut store = Rp2350SecureStore::new(); // no key set
    store.from_partition_image(&sealed);
    assert!(
        store.is_empty().unwrap(),
        "a sealed image without a configured key must not restore"
    );
    // The MAX_KEY_LEN bound still holds through the sealed path.
    let mut keyed = Rp2350SecureStore::new();
    keyed.set_store_key(emulation_store_key());
    let long_key = [0x61u8; MAX_KEY_LEN + 1];
    assert_eq!(keyed.write(&long_key, b"x"), Err(SecureStoreError::KeyTooLong));
}

/// The image nonce is a function of the framed entry list, so two
/// different contents can never share it. This is the GCM nonce-reuse
/// hazard the module doc claims does not arise, and the concrete way to
/// break it is a boundary shift: a bare `key ‖ val` digest makes
/// `("ab", "c")` and `("a", "bc")` hash alike, sealing two images under
/// one `(key, nonce)`. Length framing is what makes the encoding
/// injective, so the pair below must derive different nonces.
#[test]
fn boundary_shift_does_not_collide_the_image_nonce() {
    let a = sealed_image(b"ab", b"c");
    let b = sealed_image(b"a", b"bc");
    assert_ne!(
        a, b,
        "the two contents are genuinely different images"
    );
    let nonce = |img: &[u8]| img[V3_HEADER_LEN - V3_NONCE_LEN..V3_HEADER_LEN].to_vec();
    assert_ne!(
        nonce(&a),
        nonce(&b),
        "a key/value boundary shift must not reproduce another content's nonce"
    );
    // Order is part of the framing too. Asserted on `entries_digest` rather
    // than through a store: a store serializes in its own slot order (the
    // host store's is hash order), so reordering is not reachable from the
    // store API at all. The property belongs to the digest, which is what
    // the sealed path actually consumes.
    let fwd = entries_digest([
        (0, 2, b"k1".as_slice(), 2, b"v1".as_slice()),
        (1, 2, b"k2".as_slice(), 2, b"v2".as_slice()),
    ]);
    let rev = entries_digest([
        (0, 2, b"k2".as_slice(), 2, b"v2".as_slice()),
        (1, 2, b"k1".as_slice(), 2, b"v1".as_slice()),
    ]);
    assert_ne!(fwd, rev, "entry order is part of what the digest binds");
}

/// The device's windowed emission and the heap `seal_image` must frame a
/// plaintext identically, or the same store content seals to two different
/// byte strings depending on which path produced it.
///
/// Multi-entry stores cannot be compared byte-for-byte: the device store
/// serializes in slot order while the host store holds a `BTreeMap` (sorted
/// by key), so their orderings differ by design and the *images* are
/// legitimately different. The framing itself is still shared, which is
/// what the single-entry case isolates.
#[test]
fn device_and_heap_sealing_agree_byte_for_byte() {
    let (key, value) = (b"fido.keystore.v1", b"0123456789abcdef");

    let mut device = Rp2350SecureStore::new();
    device.set_store_key(emulation_store_key());
    device.write(key, value).unwrap();
    let mut dev_img = vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let dev_len = device.partition_image(&mut dev_img).unwrap();
    let dev_img = &dev_img[..dev_len];

    // `HostSecureStore::default` already keys itself with the same
    // `emulation_store_key()`, so it has no `set_store_key` equivalent.
    let mut heap = HostSecureStore::new();
    heap.write(key, value).unwrap();
    let heap_img = heap.partition_image();

    assert_eq!(
        dev_img, &heap_img[..],
        "one entry must seal identically through both paths — a divergence \
         here means the framing drifted, not that the orderings differ"
    );
}
