//! US-919 host tests: the pure foreign-image boot-admission decision
//! matrix, the streaming manifest hash, and the `SecureStore::wipe_all`
//! primitive across the host-reachable store implementations.
//!
//! Policy reference: EPIC `security-hardening` US-919, finding R9 (BOOTSEL
//! accepts unsigned reflash; nothing detects an implanted firmware and the
//! store loads from any valid image). The decision is deliberately
//! data-loss-over-implant: a manifest mismatch wipes the secure partition
//! BEFORE any app loads.

use fapico2_platform::fw_manifest::{
    foreign_image_decision, hash_region, parse_manifest_hex, ForeignImageDecision,
    EMUL_FAKE_FW_MANIFEST, SLOT_FW_MANIFEST,
};
use fapico2_platform::secure_store::{
    HostSecureStore, ImageReader, Rp2350SecureStore, SecureStore, SharedStore, SliceReader,
};

fn h(n: u8) -> [u8; 32] {
    let mut out = [n; 32];
    out[..16].copy_from_slice(&[n; 16]);
    out
}

/// US-919: an absent manifest slot (first boot / pre-policy device) loads —
/// the caller stamps the current hash and continues; the wipe arm must
/// never trigger on the virgin store.
#[test]
fn absent_slot_loads_and_stamps() {
    assert_eq!(foreign_image_decision(None, h(1)), ForeignImageDecision::Load);
    // Absent is absent regardless of the current image's bytes.
    assert_eq!(foreign_image_decision(None, [0u8; 32]), ForeignImageDecision::Load);
    assert_eq!(
        foreign_image_decision(None, [0xFF; 32]),
        ForeignImageDecision::Load
    );
}

/// US-919: the running image matching the last-known-good hash loads.
#[test]
fn equal_hash_loads() {
    let cur = h(7);
    assert_eq!(
        foreign_image_decision(Some(cur), cur),
        ForeignImageDecision::Load
    );
}

/// US-919 (R9): a stored hash differing from the running image's hash is a
/// foreign image → [`ForeignImageDecision::WipeAndFresh`]. Constant-time
/// fold sanity: the outcome must not depend on WHERE the bytes diverge —
/// the earliest byte, the latest byte, one byte, every byte.
#[test]
fn differing_hash_wipes() {
    let cur = h(9);
    // Divergence in the last byte only (the ct fold must catch it).
    let mut last_byte = cur;
    last_byte[31] ^= 0x01;
    assert_eq!(
        foreign_image_decision(Some(last_byte), cur),
        ForeignImageDecision::WipeAndFresh
    );
    // Divergence in the first byte only.
    let mut first_byte = cur;
    first_byte[0] ^= 0x80;
    assert_eq!(
        foreign_image_decision(Some(first_byte), cur),
        ForeignImageDecision::WipeAndFresh
    );
    // Divergence in every byte, and the reverse comparison (the policy is
    // directional: the STORED hash defines last-known-good).
    assert_eq!(
        foreign_image_decision(Some(h(0)), cur),
        ForeignImageDecision::WipeAndFresh
    );
    assert_eq!(
        foreign_image_decision(Some(cur), h(0)),
        ForeignImageDecision::WipeAndFresh
    );
}

/// US-919: the streaming manifest hash is plain SHA-256 over the region —
/// window sizes and chunk boundaries are invisible in the result.
#[test]
fn hash_region_matches_direct_sha256() {
    use sha2::{Digest as _, Sha256};

    // 300 bytes: two full IMAGE_WINDOW (128) chunks + a partial tail.
    let region: Vec<u8> = (0..300).map(|i| (i * 13 + 5) as u8).collect();
    let mut reader = SliceReader::new(&region);
    let streamed = hash_region(&mut reader, region.len());
    let direct: [u8; 32] = Sha256::digest(&region).into();
    assert_eq!(streamed, direct, "streamed windows must fold to the direct digest");

    // A region at exactly one window boundary, and a shorter region of the
    // same buffer (the bound drives the coverage, not the medium length).
    let mut reader = SliceReader::new(&region);
    let d: [u8; 32] = Sha256::digest(&region[..128]).into();
    assert_eq!(hash_region(&mut reader, 128), d);
    let mut reader = SliceReader::new(&region);
    let e: [u8; 32] = Sha256::digest(&b""[..]).into();
    assert_eq!(hash_region(&mut reader, 0), e);
}

/// US-919: the emulation stand-in hash constant + the hex parser round-trip
/// and its rejection of malformed input (a malformed FAPICO2_FW_HASH must
/// not silently steer the wipe policy).
#[test]
fn emulation_fake_manifest_and_hex_parser() {
    assert_eq!(parse_manifest_hex(&hex(EMUL_FAKE_FW_MANIFEST)), Some(EMUL_FAKE_FW_MANIFEST));
    assert_eq!(parse_manifest_hex(""), None);
    assert_eq!(parse_manifest_hex("zz"), None);
    assert_eq!(parse_manifest_hex(&"ab".repeat(31)), None);
    assert_eq!(parse_manifest_hex(&"ab".repeat(65)), None);
}

fn hex(b: [u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// US-919: the wipe-all primitive empties EVERY slot (no known-name
/// enumeration) — host in-memory store.
#[test]
fn wipe_all_host_store() {
    let mut store = HostSecureStore::new();
    store.write(SLOT_FW_MANIFEST, &h(1)).unwrap();
    store.write(b"some.app.slot", b"secret").unwrap();
    assert!(!store.is_empty().unwrap());
    store.wipe_all().unwrap();
    assert!(store.is_empty().unwrap());
    assert!(!store.contains(SLOT_FW_MANIFEST));
    assert!(!store.contains(b"some.app.slot"));
    // Idempotent: wiping an empty store stays Ok.
    store.wipe_all().unwrap();
    assert!(store.is_empty().unwrap());
}

/// US-919: the wipe-all primitive on the device store (pure static memory,
/// host-runnable) — every slot goes and the backing bytes are zeroized
/// (US-704).
#[test]
fn wipe_all_rp2350_store() {
    let mut store = Rp2350SecureStore::new();
    store.write(b"slot.one", &[7u8; 64]).unwrap();
    store.write(b"slot.two", &[9u8; 64]).unwrap();
    assert!(!store.is_empty().unwrap());
    store.wipe_all().unwrap();
    assert!(store.is_empty().unwrap());
    assert!(!store.contains(b"slot.one"));
    // US-704: no stale secret bytes in the freed slot backing.
    for (key, val) in store.slot_bytes_dump() {
        assert!(key.iter().all(|&b| b == 0));
        assert!(val.iter().all(|&b| b == 0));
    }
    // The store still accepts writes after the wipe (fresh semantics).
    store.write(b"fresh", b"v").unwrap();
    let mut out = [0u8; 8];
    assert_eq!(store.read(b"fresh", &mut out).unwrap(), 1);
}

/// US-919: the wipe-all primitive forwards through the shared-handle
/// wrapper (the device boots through a `SharedStore`).
#[test]
fn wipe_all_shared_store_forwards() {
    let cell = core::cell::RefCell::new(HostSecureStore::new());
    let mut shared: SharedStore<'_, HostSecureStore> = SharedStore::new(&cell);
    shared.write(SLOT_FW_MANIFEST, &h(2)).unwrap();
    assert!(!shared.is_empty().unwrap());
    shared.wipe_all().unwrap();
    assert!(shared.is_empty().unwrap());
}

/// US-919: the file-backed host store wipes by removing its backing file
/// (the file IS the secure-partition stand-in).
#[test]
fn wipe_all_file_store() {
    let path = std::env::temp_dir().join(format!("fapico2_fw_manifest_test_{}", std::process::id()));
    let mut store = fapico2_platform::secure_store::FileSecureStore::new(path.clone());
    store.write(b"ks", b"payload").unwrap();
    assert!(!store.is_empty().unwrap());
    store.wipe_all().unwrap();
    assert!(store.is_empty().unwrap());
    assert!(!path.exists());
    // Idempotent: wiping an already-empty (missing file) store stays Ok.
    store.wipe_all().unwrap();
}

/// US-919: the slot-const contract — the manifest record rides the sealed
/// v3 store image (the deviation rationale shared with US-918's
/// `boot.entropy.v1`), so a store carrying only the manifest slot is
/// "virgin except" for the migration budget.
#[test]
fn manifest_slot_roundtrips_partition_image() {
    let mut store = Rp2350SecureStore::new();
    store.set_store_key([9u8; 32]);
    store.write(SLOT_FW_MANIFEST, &h(3)).unwrap();
    assert!(store.is_empty_except(SLOT_FW_MANIFEST).unwrap());

    let mut img = [0u8; Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX];
    let n = store.partition_image(&mut img).unwrap();
    let mut restored = Rp2350SecureStore::new();
    restored.set_store_key([9u8; 32]);
    restored.from_partition_image(&img[..n]);
    let mut out = [0u8; 32];
    assert_eq!(restored.read(SLOT_FW_MANIFEST, &mut out).unwrap(), 32);
    assert_eq!(out, h(3));
}

/// Compile-time use of the reader trait import (the hash tests exercise
/// [`ImageReader`] through [`SliceReader`]); keeps the import honest.
#[test]
fn reader_is_object_safe_over_windows() {
    let region = [1u8; 200];
    let mut reader: Box<dyn ImageReader> = Box::new(SliceReader::new(&region));
    let mut win = [0u8; 64];
    assert_eq!(reader.read_window(160, &mut win), 40, "short-fill at the medium end");
}
