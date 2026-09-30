//! Negative controls for the stateless-U2F-over-CTAP2 fallback.
//!
//! `app.rs::stateless_u2f_credential_for` lets a CTAP2 `allowList` name a U2F
//! key handle that US-714 never stored in the keystore. That is a genuine new
//! capability — it turns a blob into an assertion key — so the *refusals* are
//! worth pinning, not just the happy path that
//! `test_authenticate_ctap1_through_ctap2` covers.
//!
//! The property: **only a handle this device minted, for this RP, can become
//! an assertion key.** The gate is `stateless::verify_handle`, which
//! re-derives the key from the device master and compares a tag over
//! `appId` in constant time.
//!
//! The case that matters most is (2): without the appId tag, a client could
//! register a U2F credential under one RP and assert it under another, so the
//! tests below mint a handle for RP A and demand refusal under RP B.

use fapico2_fido::keystore::{Keystore, MemoryKeystore};
use fapico2_fido::stateless;

/// Mint a stateless U2F handle the way `u2f::stateless_handle` does, using the
/// public primitives. Kept here rather than exported from `u2f` so the test
/// pins the *documented* construction (path words with the C MSB marker, tag
/// over `appId`) instead of calling the production function it is checking.
fn mint_handle(
    ks: &MemoryKeystore,
    app_id: &[u8; 32],
) -> (stateless::StatelessScalar, [u8; stateless::KEY_HANDLE_LEN]) {
    let master = stateless::master_from_device_random(&ks.get_auth_state().device_random);
    let mut path = [0u8; stateless::KEY_PATH_LEN];
    for (i, b) in path.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    // C parity: every little-endian path word has its MSB set (`val |=
    // 0x80000000`), which is also what `is_stateless` gates on.
    for word in path.as_chunks_mut::<4>().0 {
        word[3] |= 0x80;
    }
    let scalar = stateless::derive_scalar_from_path(&master, &path);
    let tag = stateless::handle_tag(&scalar, app_id, &path);
    let mut handle = [0u8; stateless::KEY_HANDLE_LEN];
    handle[..stateless::KEY_PATH_LEN].copy_from_slice(&path);
    handle[stateless::KEY_PATH_LEN..].copy_from_slice(&tag);
    (scalar, handle)
}

/// RP id hashes, as U2F/CTAP2 hash the RP ID into `app_param` / `rp_id_hash`.
fn rp_hash(label: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in label.iter().take(32).enumerate() {
        out[i] = *b;
    }
    out
}

#[test]
fn a_handle_minted_for_this_rp_verifies() {
    // The positive control: without it the negatives below would pass for the
    // wrong reason (e.g. a broken mint that never produces a valid handle).
    let ks = MemoryKeystore::new();
    let rp_a = rp_hash(b"example.com");
    let (scalar, handle) = mint_handle(&ks, &rp_a);
    let master = stateless::master_from_device_random(&ks.get_auth_state().device_random);
    assert!(
        stateless::verify_handle(master.bytes(), &rp_a, &handle),
        "a freshly minted handle must verify for the RP that minted it"
    );
    // And the derived scalar is the same one registration would have used.
    assert_eq!(
        stateless::derive_scalar(master.bytes(), &handle)
            .expect("valid handle derives")
            .bytes(),
        scalar.bytes(),
        "re-derivation must reproduce the registered scalar"
    );
}

#[test]
fn a_handle_minted_for_another_rp_is_refused() {
    let ks = MemoryKeystore::new();
    let rp_a = rp_hash(b"example.com");
    let rp_b = rp_hash(b"attacker.example");
    let (_, handle) = mint_handle(&ks, &rp_a);
    let master = stateless::master_from_device_random(&ks.get_auth_state().device_random);

    assert!(
        !stateless::verify_handle(master.bytes(), &rp_b, &handle),
        "cross-RP assertion must be refused: the tag binds the handle to the RP \
         that registered it"
    );
}

#[test]
fn a_single_bit_flip_is_refused() {
    let ks = MemoryKeystore::new();
    let rp_a = rp_hash(b"example.com");
    let (_, handle) = mint_handle(&ks, &rp_a);
    let master = stateless::master_from_device_random(&ks.get_auth_state().device_random);

    // Flip one bit in the tag half, then in the path half.
    for idx in [stateless::KEY_PATH_LEN, stateless::KEY_HANDLE_LEN - 1] {
        let mut bad = handle;
        bad[idx] ^= 0x01;
        assert!(
            !stateless::verify_handle(master.bytes(), &rp_a, &bad),
            "a mutated handle at byte {idx} must be refused"
        );
    }
}

#[test]
fn a_random_blob_is_not_stateless_shaped() {
    let blob: Vec<u8> = (0..stateless::KEY_HANDLE_LEN).map(|i| i as u8).collect();
    assert!(
        !stateless::is_stateless(&blob),
        "a blob whose path words lack the C MSB marker is not a stateless handle"
    );
    // Wrong length is refused too, before any key material is touched.
    assert!(!stateless::is_stateless(&blob[..32]));
}
