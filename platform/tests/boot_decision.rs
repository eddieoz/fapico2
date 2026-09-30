//! US-427 (SECURE-PERSIST Phase C) torn-write / corrupt-image boot
//! semantics, host-proven — carried forward into the US-915 sealed boot
//! policy ([`boot_decision_sealed`], format v3, encrypt-then-MAC).
//!
//! [`boot_decision_sealed`] is the five-way decision the device boot makes
//! from the two raw on-flash slot contents (primary/shadow) and the store
//! key, and the emulation boot makes from the partition file (primary)
//! against an erased shadow:
//!
//! * primary holds a **tag-verified v3** image → `LoadPrimary`;
//! * else shadow holds a tag-verified v3 image → `LoadShadow`;
//! * else both slots erased (all-0xFF or empty) → `Fresh` (first boot);
//! * else both slots hold **CRC-valid v2** images → `MigratePrimary`
//!   (the pre-update device signature: persist always programs both
//!   slots, so a successfully-persisted v2 device shows valid v2 in both
//!   — the migration is the one-time re-seal);
//! * else → `Refuse` — content is present but nothing validates. The
//!   device parks in `fatal_boot`, the emulator exits 2. A silent re-seed
//!   over a corrupt or forged image is forbidden (EPIC SECURE-PERSIST,
//!   US-915).
//!
//! The US-427 scenarios below are the minimum set: torn prefixes,
//! bit-flips (payload, magic, CRC field), the torn-primary /
//! valid-shadow fallback, both-corrupt, primary-wins, and the two Fresh
//! shapes — now proven against the sealed format, where the GCM tag
//! catches what the CRC cannot (recomputed-CRC forgeries). The US-915
//! red-team cases close out the story: a forged lone-v2 slot (attack
//! #17), a forged v3 with a wrong tag, the genuine both-v2 migration
//! signature, and key separation (an image sealed under another key
//! refuses).
//!
//! Slot model: on the device a slot is the fixed-size flash window (the
//! image + erased 0xFF padding — the image is self-delimiting, so the
//! padding does not invalidate it); in emulation the "primary slot" is
//! the whole partition-file content and the shadow is empty. `slot_window`
//! builds the padded-window shape for the valid-image scenarios.

use fapico2_platform::secure_store::{HostSecureStore, Rp2350SecureStore, SecureStore};
use fapico2_platform::store_v3::{boot_decision_sealed, emulation_store_key, SealedBootDecision};

/// The host store's sealed (format-v3) partition image holding exactly one
/// entry — the emulation-keyed store's own serialization.
fn sealed_image(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut store = HostSecureStore::new();
    store.write(key, value).unwrap();
    store.partition_image()
}

/// Build a legacy format-v2 image holding exactly one entry — the unkeyed
/// device store's serialization (the pre-US-915 device shape).
fn v2_image(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut store = Rp2350SecureStore::new();
    store.write(key, value).unwrap();
    let mut img = vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
    let n = store.partition_image(&mut img).unwrap();
    img.truncate(n);
    img
}

/// The on-flash slot shape for a valid image: the image followed by erased
/// (0xFF) padding out to `window` — what `boot_decision_sealed` actually
/// sees on the device (whole-slot reads).
fn slot_window(img: &[u8], window: usize) -> Vec<u8> {
    let mut slot = vec![0xFFu8; window];
    slot[..img.len()].copy_from_slice(img);
    slot
}

const ERASED_SLOT: [u8; 64] = [0xFF; 64];

/// (a) A truncated sealed primary (a valid image cut to ~60 % — the classic
/// torn write) with an erased shadow must be refused, not silently emptied.
#[test]
fn truncated_primary_erased_shadow_refuses() {
    let img = sealed_image(b"k1", b"0123456789abcdef");
    let torn = &img[..img.len() * 6 / 10]; // ~60 % prefix
    assert!(
        !fapico2_platform::store_v3::sealed_image_is_valid(torn, &emulation_store_key()),
        "sanity: the torn prefix itself must not validate"
    );
    assert_eq!(
        boot_decision_sealed(torn, &ERASED_SLOT[..], &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// (b) A bit-flip inside the sealed primary's payload (one byte of a
/// ciphertext) with an erased shadow must be refused — the entry tag
/// catches what a recomputed CRC would let through.
#[test]
fn payload_bitflip_primary_erased_shadow_refuses() {
    let img = sealed_image(b"k1", b"0123456789abcdef");
    let mut flipped = img.clone();
    // Sealed layout: magic(4) count(4) nonce(12) kl(4) vl(4) ct(16..) —
    // index 24 is inside the 16-byte ciphertext.
    flipped[24] ^= 0x40;
    assert_eq!(
        boot_decision_sealed(&flipped, &ERASED_SLOT[..], &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// (c1) A bit-flip in the primary's header (the magic) must be refused.
#[test]
fn magic_bitflip_primary_erased_shadow_refuses() {
    let img = sealed_image(b"k1", b"0123456789abcdef");
    let mut flipped = img.clone();
    flipped[0] ^= 0x01;
    assert_eq!(
        boot_decision_sealed(&flipped, &ERASED_SLOT[..], &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// (c2) A bit-flip in the primary's CRC field (last byte of the image) must
/// be refused — the stored CRC no longer matches its prefix.
#[test]
fn crc_bitflip_primary_erased_shadow_refuses() {
    let img = sealed_image(b"k1", b"0123456789abcdef");
    let mut flipped = img.clone();
    *flipped.last_mut().unwrap() ^= 0x80;
    assert_eq!(
        boot_decision_sealed(&flipped, &ERASED_SLOT[..], &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// (d) The US-391 durability pair working as designed: the primary holds a
/// programming prefix of a (newer) sealed image — a power loss landed
/// mid-write — while the shadow still holds a different valid sealed image.
/// Boot falls back to the shadow; at most the slot being written is lost.
#[test]
fn torn_primary_valid_shadow_loads_shadow() {
    let torn_source = sealed_image(b"new.key", b"brand-new-state-0123456789");
    let torn = &torn_source[..torn_source.len() * 4 / 10]; // first 40 %
    let shadow = slot_window(&sealed_image(b"old.key", b"previous-good-state"), 128);
    assert_eq!(
        boot_decision_sealed(torn, &shadow, &emulation_store_key()),
        SealedBootDecision::LoadShadow
    );
}

/// (e) Both slots corrupt (different corruptions) must be refused — there is
/// no valid image anywhere to load, and neither slot is erased.
#[test]
fn both_slots_corrupt_refuses() {
    let primary = sealed_image(b"k1", b"0123456789abcdef");
    let shadow_source = sealed_image(b"k2", b"fedcba9876543210");
    let truncated_primary = &primary[..primary.len() * 6 / 10];
    let mut flipped_shadow = shadow_source;
    flipped_shadow[12] ^= 0xFF;
    assert_eq!(
        boot_decision_sealed(truncated_primary, &flipped_shadow, &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// (f) Primary valid, shadow corrupt → the primary wins (a stale/corrupt
/// shadow must never shadow a good primary). Also: the valid primary is seen
/// in its on-flash slot shape — image + erased padding — which must not
/// invalidate it (self-delimiting image).
#[test]
fn valid_primary_corrupt_shadow_loads_primary() {
    let primary = slot_window(&sealed_image(b"k1", b"0123456789abcdef"), 128);
    let mut shadow = sealed_image(b"k2", b"fedcba9876543210");
    shadow[24] ^= 0x40;
    assert_eq!(
        boot_decision_sealed(&primary, &shadow, &emulation_store_key()),
        SealedBootDecision::LoadPrimary
    );
}

/// A valid sealed primary beats a valid sealed shadow: primary-first is the
/// codified slot precedence (persist programs primary then shadow, boot
/// reads primary first).
#[test]
fn valid_primary_beats_valid_shadow() {
    let primary = slot_window(&sealed_image(b"k1", b"0123456789abcdef"), 128);
    let shadow = slot_window(&sealed_image(b"k2", b"fedcba9876543210"), 128);
    assert_eq!(
        boot_decision_sealed(&primary, &shadow, &emulation_store_key()),
        SealedBootDecision::LoadPrimary
    );
}

/// (g) Both slots all-0xFF (fresh board, or the region never programmed) is
/// the legal first-boot path: start with an empty store.
#[test]
fn both_slots_erased_is_fresh() {
    assert_eq!(
        boot_decision_sealed(&ERASED_SLOT[..], &[0xFFu8; 128], &emulation_store_key()),
        SealedBootDecision::Fresh
    );
}

/// (h) Both slots empty (the emulation shape: no partition file, no shadow)
/// is Fresh too — "erased" includes the empty slice.
#[test]
fn both_slots_empty_is_fresh() {
    assert_eq!(
        boot_decision_sealed(&[], &[], &emulation_store_key()),
        SealedBootDecision::Fresh
    );
}

// ---------------------------------------------------------------------------
// US-915 boot policy: the v2→v3 migration rule and the red-team cases.
// ---------------------------------------------------------------------------

/// US-915 TDD (a): the genuine pre-update device signature — **both** slots
/// holding CRC-valid format-v2 images — is the one-time `MigratePrimary`
/// migration trigger. A lone v2 slot never migrates (next test).
#[test]
fn both_slots_valid_v2_is_the_migration_signature() {
    let v2 = v2_image(b"k1", b"0123456789abcdef");
    assert_eq!(
        boot_decision_sealed(&v2, &v2, &emulation_store_key()),
        SealedBootDecision::MigratePrimary
    );
    // The migration signature is slot-order agnostic (persist programs
    // primary then shadow; either being the fresher one does not matter).
    assert_eq!(
        boot_decision_sealed(&v2, &ERASED_SLOT[..], &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// US-915 TDD (a) / red-team attack #17: a forged lone-v2 slot (recomputed
/// CRC, attacker-controlled entries) with an erased shadow is **refused** —
/// never loaded, never silently re-seeded into the sealed format. This is
/// the shape `redteam/store_forge.py` produced.
#[test]
fn forged_lone_v2_slot_refuses() {
    let v2 = v2_image(b"fido.hkey", b"attacker-chosen-hkey-0000000000");
    assert!(
        fapico2_platform::secure_store::partition_image_is_valid(&v2),
        "sanity: the forged slot passes the CRC validator"
    );
    // v2 + erased shadow → Refuse.
    assert_eq!(
        boot_decision_sealed(&v2, &ERASED_SLOT[..], &emulation_store_key()),
        SealedBootDecision::Refuse
    );
    // v2 + torn v2 shadow (a second forged shape) → Refuse.
    let torn = &v2[..v2.len() * 6 / 10];
    assert_eq!(
        boot_decision_sealed(&v2, torn, &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// US-915 TDD (b): a forged sealed image — a valid v3 image with the entry
/// tag replaced — must be refused (the tag authenticates the entry and the
/// image shape).
#[test]
fn forged_v3_wrong_tag_refuses() {
    let img = sealed_image(b"k1", b"0123456789abcdef");
    let mut forged = img.clone();
    // Flip the first byte of the entry tag (right after the ciphertext:
    // 20 header + 8 lens + 16 ct).
    forged[20 + 8 + 16] ^= 0x01;
    assert_eq!(
        boot_decision_sealed(&forged, &ERASED_SLOT[..], &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// US-915 TDD (c): the v2→v3 migration round-trip — a keyed store restores
/// the legacy v2 image (the migration's load step), re-seals it (the boot
/// persist gate's repair program), and every entry survives; the sealed
/// result is a LoadPrimary on the next boot.
#[test]
fn v2_to_v3_migration_round_trip_preserves_entries() {
    let key = emulation_store_key();
    let v2 = v2_image(b"k1", b"0123456789abcdef");

    // Migration step 1: restore the legacy image into the keyed store.
    let mut store = Rp2350SecureStore::new();
    store.set_store_key(key);
    store.from_partition_image(&v2);
    let mut out = [0u8; 512];
    let m = store.read(b"k1", &mut out).unwrap();
    assert_eq!(&out[..m], b"0123456789abcdef");

    // Migration step 2: the store's serialization is now sealed (v3).
    let mut sealed = vec![0u8; Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX];
    let n = store.partition_image(&mut sealed).unwrap();
    assert_eq!(
        u32::from_le_bytes(sealed[0..4].try_into().unwrap()),
        fapico2_platform::store_v3::PARTITION_IMAGE_MAGIC_V3,
        "the migrated store's image is format v3"
    );

    // Migration step 3: the next boot loads it, and the entries are intact.
    assert_eq!(
        boot_decision_sealed(&sealed[..n], &ERASED_SLOT[..], &key),
        SealedBootDecision::LoadPrimary
    );
    let mut rebooted = Rp2350SecureStore::new();
    rebooted.set_store_key(key);
    rebooted.from_partition_image(&sealed[..n]);
    let m = rebooted.read(b"k1", &mut out).unwrap();
    assert_eq!(&out[..m], b"0123456789abcdef");
}

/// Key separation (US-915): an image sealed under one key never validates
/// under another — the flash image alone is useless on another device
/// (and the emulation key is not the device key).
#[test]
fn sealed_image_is_key_bound() {
    let img = sealed_image(b"k1", b"0123456789abcdef");
    let mut other = emulation_store_key();
    other[0] ^= 0x01;
    assert_eq!(
        boot_decision_sealed(&img, &ERASED_SLOT[..], &other),
        SealedBootDecision::Refuse
    );
}

/// A pre-update v2 primary with a valid v3 shadow boots from the shadow —
/// the sealed image is authenticated, so it is trusted over the legacy
/// content (and the forged-v2-primary attack falls through to refusal when
/// the shadow is not a genuine sealed image).
#[test]
fn v2_primary_valid_v3_shadow_loads_shadow() {
    let v2 = v2_image(b"k1", b"legacy-content-00000000000000");
    let shadow = slot_window(&sealed_image(b"k1", b"sealed-content-000000000"), 128);
    assert_eq!(
        boot_decision_sealed(&v2, &shadow, &emulation_store_key()),
        SealedBootDecision::LoadShadow
    );
}

/// US-915 (review): the per-entry AAD binds the image nonce, so a same-key,
/// same-layout entry transplant between two differently-sealed images
/// fails the tag — a stolen entry ciphertext cannot be replayed into
/// another image that happens to share its nonce prefix. The transplanted
/// image is made CRC-valid first (the attacker controls the CRC field), so
/// the refusal provably comes from the AEAD tag, not the torn-write gate.
#[test]
fn cross_image_entry_transplant_refuses() {
    // Same key, same entry layout (kl=2, vl=26, count=1), different
    // plaintext → different entries digest → a different image nonce.
    let make = |tag: &[u8]| {
        let mut v = tag.to_vec();
        v.resize(26, b'0');
        v
    };
    let victim = sealed_image(b"k1", &make(b"victim-entry"));
    let attacker = sealed_image(b"k1", &make(b"attacker-entry"));
    assert_eq!(victim.len(), attacker.len(), "same-layout images");

    // Sanity: the local CRC-32 mirrors the format's trailing field.
    let stored = u32::from_le_bytes(victim[victim.len() - 4..].try_into().unwrap());
    assert_eq!(crc32_ieee(&victim[..victim.len() - 4]), stored);

    // Splice the attacker image's entry (ct + tag) over the victim's; the
    // images share the layout, so the spliced image is byte-for-byte a
    // plausible v3 image once the CRC is re-fixed.
    const ENTRY_OFF: usize = 20 + 8; // v3 header + the one lens field
    let entry_len = victim.len() - ENTRY_OFF - 4;
    let mut transplanted = victim.clone();
    transplanted[ENTRY_OFF..ENTRY_OFF + entry_len]
        .copy_from_slice(&attacker[ENTRY_OFF..ENTRY_OFF + entry_len]);
    let fixed = crc32_ieee(&transplanted[..transplanted.len() - 4]);
    let tail = transplanted.len() - 4;
    transplanted[tail..].copy_from_slice(&fixed.to_le_bytes());

    // The transplant must be refused by the AEAD tag (which now binds the
    // image nonce), never yielding the attacker's entry as store content.
    assert!(
        fapico2_platform::store_v3::unseal_image(&transplanted, &emulation_store_key()).is_err(),
        "a cross-image entry transplant must fail the entry tag"
    );
    assert_eq!(
        boot_decision_sealed(&transplanted, &ERASED_SLOT[..], &emulation_store_key()),
        SealedBootDecision::Refuse
    );
}

/// IEEE CRC-32 (reflected, poly 0xEDB88320) — the test-local twin of the
/// format's trailing CRC, so the transplant above can present a CRC-valid
/// image and prove the AEAD tag is what refuses.
fn crc32_ieee(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}
