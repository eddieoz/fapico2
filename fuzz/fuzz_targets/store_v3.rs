#![no_main]
//! US-1050 — the format-v3 secure-partition image (`fapico2_platform::store_v3`).
//!
//! The v3 sealer derives its GCM **image nonce** as a pure function of
//! `(store key, SHA-256(entries))` and leans on that twice:
//!
//! * *compare-then-write* — the same logical store must re-seal byte-identically,
//!   or every persist would erase a slot that did not need erasing; and
//! * *nonce uniqueness* — two different plaintexts must never land under one
//!   image nonce, because a repeated `(key, nonce)` pair under AES-256-GCM is
//!   catastrophic (keystream reuse → the XOR of the two plaintexts, and the
//!   authentication subkey).
//!
//! Absence-of-panic would prove nothing here: a sealer that returned a
//! **constant** nonce still round-trips perfectly and still refuses a forged
//! tag. So this target asserts three properties, each of which the other two
//! do not imply:
//!
//! 1. **Round-trip identity** — `unseal(seal(m)) == m` for every well-formed
//!    logical (format-v2) image, and `seal` is deterministic.
//! 2. **Image-nonce uniqueness** — two plaintexts that differ in *any* entry
//!    byte seal to different image nonces. This is the invariant the
//!    nonce-construction regression would break. It is deliberately checked
//!    on the **image nonce as it appears on the wire** (bytes 8..20), not on
//!    a re-derivation, so it cannot pass by calling the same function twice.
//! 3. **Fail-closed on damage** — every proper prefix of a sealed image, and
//!    every single-bit mutation of one, is refused; and the boot decision
//!    over a damaged slot is `Refuse`, never `LoadPrimary` / `LoadShadow` /
//!    `Fresh`.
//!
//! The fuzzer supplies the *entries*; the target builds two distinct
//! well-formed logical images from them and runs all three properties.
//!
//! # Red-under-mutation (the evidence that these assertions bite)
//!
//! Replacing `store_v3::nonce_for` with a constant (the shape a
//! nonce-construction regression takes) turns assertion 2 red while 1 and 3
//! stay green — see `.superpowers/sdd/report-P6.md`.

use std::vec::Vec;

use fapico2_platform::secure_store::{partition_image_is_valid, PARTITION_IMAGE_MAGIC};
use fapico2_platform::store_v3::{
    boot_decision_sealed, emulation_store_key, seal_image, sealed_image_len, unseal_image,
    SealedBootDecision, V3_HEADER_LEN,
};

/// Bound on the number of entries one input expands to. The truncation /
/// mutation sweeps are quadratic in the sealed length, and this target runs
/// in a 15-minute CI smoke, so the input is deliberately kept small: the
/// property under test is not "how large an image survives", it is "what the
/// sealer *decides* for every distinct input".
const MAX_ENTRIES: usize = 4;
/// Bound on the plaintext bytes one input contributes to the entries.
const MAX_PLAINTEXT: usize = 96;

/// The platform's CRC-32 (IEEE 802.3, reflected, poly `0xEDB8_8320`,
/// tableless), mirrored here because `secure_store::crc32` is `pub(crate)`.
/// `partition_image_is_valid` — which uses the platform's own copy — is
/// asserted on every image this builds, so a drift in this mirror fails the
/// target instead of silently weakening it.
fn crc32(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Build the store's own **logical** serialization (format v2) — the sealing
/// input of `seal_image`, i.e. what `HostSecureStore::logical_image` emits.
fn logical_image(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
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
    out
}

/// Expand the fuzz input into a bounded list of `(key, value)` entries. Keys
/// are derived from the entry index so two entries never collide in the
/// digest-by-concatenation sense; values carry the input bytes.
fn entries_from(data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut budget = MAX_PLAINTEXT;
    for (i, chunk) in data.chunks(8).take(MAX_ENTRIES).enumerate() {
        if budget == 0 {
            break;
        }
        let take = chunk.len().min(budget);
        budget -= take;
        let key = vec![b'k', b0(i)];
        out.push((key, chunk[..take].to_vec()));
    }
    out
}

/// A per-entry key byte that keeps generated keys distinct and short.
fn b0(i: usize) -> u8 {
    b"ABCDEFGH"[i & 7]
}

/// A plaintext that differs from `entries` in exactly one entry's last value
/// byte — the minimal possible distinct-plaintext pair, which is the hardest
/// case for nonce uniqueness (a construction that hashed only the first
/// entry, or a counter instead of a digest, would collide here).
fn variant(entries: &[(Vec<u8>, Vec<u8>)]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = entries.to_vec();
    for (_, v) in out.iter_mut().rev() {
        if let Some(last) = v.last_mut() {
            *last ^= 0x01;
            return Some(out);
        }
    }
    // No entry carries a byte to flip: append a fresh single-byte entry,
    // which is still a distinct plaintext.
    if out.len() < MAX_ENTRIES {
        out.push((vec![b'k', b'Z'], vec![0u8]));
        return Some(out);
    }
    None
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let key = emulation_store_key();
    let entries = entries_from(data);
    let plain_a = logical_image(&entries);
    assert!(
        partition_image_is_valid(&plain_a),
        "harness: the logical image it built is not valid to the platform's own CRC/length walk",
    );
    let sealed_a = seal_image(&plain_a, &key).expect("a structurally valid v2 image always seals");

    // -- 1. round-trip identity, and determinism ----------------------------
    assert_eq!(
        unseal_image(&sealed_a, &key).expect("a freshly sealed image always opens"),
        plain_a,
        "seal/unseal is not the identity on the logical image",
    );
    assert_eq!(
        seal_image(&plain_a, &key).expect("re-seal"),
        sealed_a,
        "seal is not deterministic -- compare-then-write would erase a slot that did not change",
    );
    assert_eq!(
        sealed_image_len(&sealed_a),
        Some(sealed_a.len()),
        "the self-delimiting length walk disagrees with the sealed length",
    );

    // -- 2. image-nonce uniqueness across distinct plaintexts --------------
    // Read the nonce off the wire (header offset `V3_HEADER_LEN - 12` == 8),
    // so this cannot be satisfied by two calls into the same derivation.
    let nonce_of = |sealed: &[u8]| -> [u8; 12] {
        sealed[8..8 + 12].try_into().expect("header carries the image nonce")
    };
    assert!(sealed_a.len() >= V3_HEADER_LEN, "header does not fit");
    if let Some(entries_b) = variant(&entries) {
        let plain_b = logical_image(&entries_b);
        assert_ne!(plain_b, plain_a, "the variant is not a distinct plaintext");
        let sealed_b = seal_image(&plain_b, &key).expect("the variant also seals");
        assert_eq!(
            unseal_image(&sealed_b, &key).expect("the variant opens"),
            plain_b,
            "the variant does not round-trip",
        );
        assert_ne!(
            nonce_of(&sealed_b),
            nonce_of(&sealed_a),
            "two distinct plaintexts share an image nonce -- AES-256-GCM keystream reuse",
        );
    }

    // -- 3. fail-closed on truncation and on any single-bit mutation -------
    for cut in 0..sealed_a.len() {
        assert!(
            unseal_image(&sealed_a[..cut], &key).is_err(),
            "a truncated image was accepted (cut at {cut} of {})",
            sealed_a.len(),
        );
    }
    for byte in 0..sealed_a.len() {
        for bit in 0..8 {
            let mut damaged = sealed_a.clone();
            damaged[byte] ^= 1 << bit;
            assert!(
                unseal_image(&damaged, &key).is_err(),
                "a forged image was accepted (bit {bit} of byte {byte} flipped)",
            );
        }
    }

    // The boot decision must agree, over a whole-slot window with erased
    // padding after the self-delimiting image (the real on-flash shape).
    let mut slot = vec![0xFFu8; sealed_a.len() + 64];
    slot[..sealed_a.len()].copy_from_slice(&sealed_a);
    assert_eq!(
        boot_decision_sealed(&slot, &slot, &key),
        SealedBootDecision::LoadPrimary,
        "a good sealed image does not load",
    );
    let mut damaged_slot = slot.clone();
    damaged_slot[sealed_a.len() / 2] ^= 0x01;
    assert_eq!(
        boot_decision_sealed(&damaged_slot, &slot, &key),
        SealedBootDecision::LoadShadow,
        "a damaged primary must fall through to the shadow, not be silently re-seeded",
    );
    assert_eq!(
        boot_decision_sealed(&damaged_slot, &[0xFFu8; 16], &key),
        SealedBootDecision::Refuse,
        "content that is present but validates as nothing must refuse, never re-seed",
    );
});
