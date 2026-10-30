//! US-1721 — resident credential keys are a function of (device, rp, user).
//!
//! EPIC `FIDO-RESIDENT-DRIFT`. US-1719 proved the defect: resident credential
//! IDs are deterministic from `(rp_id, user.id)` while keys are fresh TRNG, so
//! a re-registration is shadowed by the oldest same-ID record whose key then
//! signs (`docs/audits/2026-10-30-wrong-key-assertion-drift.md`, §7 the
//! silent foreign-key signature). This story makes the resident **key**
//! deterministic from the resident **ID** — true C parity with pico-fido
//! (`cbor_make_credential.c:521-526` sets `key_seed = cred_idr` for
//! `options.rk == ptrue` and `:672` loads the key from that seed; the C
//! derivation is keyed by the device master key inside `derive_key`
//! (`fido.c:325`), which is the shape ours repeats with `hkey`) — so a
//! duplicate record is harmless: either record signs with the same key.
//!
//! # The three scenarios
//!
//! 1. `same_inputs_derive_the_same_key` — the RED. Two resident makeCredentials
//!    for the same (rp, user.id) on one twin must attest the *same* public
//!    key, valid on P-256 every time, and that key must actually sign a pinned
//!    assertion. Today the two keys are independent TRNG draws and this fails.
//!    It is **not** `#[ignore]`d: it goes red→green inside this story.
//! 2. `the_key_is_not_derivable_from_public_data` — two twins whose device
//!    secrets differ (separate boots ⇒ separate `hkey`s, `device_app.rs` boot),
//!    same (rp, user.id): the credential ID is public-data-derived and equal,
//!    but the keys must differ — the device secret is what stops the key being
//!    forgeable from `(rp, user)` alone. Green by construction today; written
//!    anyway because it guards the fix (a derivation that dropped `hkey`
//!    would turn it red).
//! 3. `non_resident_credentials_keep_their_trng_keys` — rk false twice for the
//!    same (rp, user.id): different keys *and* different (random) credential
//!    IDs. The derivation is the resident branch only; this pins the
//!    compat invariant that non-resident keygen is untouched.
//!
//! # Compat invariants this suite sits next to
//!
//! The snapshot load path and the record format are untouched: existing
//! random-key records keep loading and signing (their key is *in* the record;
//! the derivation only affects new MCs) — the full suite proves that, and
//! US-1719's green exclude scenario re-proves it on the region path.

mod region_boot;

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use region_boot::*;
use std::sync::MutexGuard;

/// The RP every scenario registers under (US-1719's fixture value; the
/// specific string is irrelevant, only its stability matters).
const RP: &str = "localhost";

/// A fixed `user.id`, byte-identical across every registration — the
/// precondition that makes the derived resident ID collide.
const USER_ID: &[u8] = b"us1721-derive-user";

const PIN: &[u8] = b"123456";

/// The fixture's constant challenge (region_boot's `make_cred`/`get_assertion`
/// both use `[0xCC; 32]`), so an assertion signature is over
/// `authData ‖ CHALLENGE`.
const CHALLENGE: [u8; 32] = [0xCCu8; 32];

/// The serialisation guard: the region provider is a process-global, so every
/// test holds [`lock`] for its whole body (`region_boot`'s module docs).
type Guard = MutexGuard<'static, ()>;

/// The frozen resident-ID derivation, restated from the client's side.
///
/// `device_core.rs` computes
/// `SHA-256("fapico2-resident-id" ‖ SHA-256(rp_id) ‖ user_handle)` — the same
/// independent restatement `resident_reregister.rs` carries, so this suite
/// breaks loudly if the ID derivation drifts while the key derivation is being
/// wired in (the reordering hazard the story names).
fn derived_resident_id() -> Vec<u8> {
    let rp_hash = fapico2_fido::crypto::sha256(RP.as_bytes());
    let mut buf = Vec::new();
    buf.extend_from_slice(b"fapico2-resident-id");
    buf.extend_from_slice(&rp_hash);
    buf.extend_from_slice(USER_ID);
    fapico2_fido::crypto::sha256(&buf).to_vec()
}

/// Boot a PIN-set, presence-granted, region-backed twin.
///
/// The same discipline `resident_reregister.rs::boot_pinned_device` uses, minus
/// what its scenarios need and ours does not (no credMgmt, so no metadata
/// assertions): the region provider must be installed *before* the first
/// command, and the backend assertion is there because a snapshot-backed run
/// would test the wrong keystore.
fn boot(tag: &str) -> (InstalledRegion, Device) {
    let region = install(tag);
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(PIN);
    assert!(device.persist(), "the PIN write must reach the secure store");
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed — the shipped path"
    );
    (region, device)
}

/// One resident registration through the shipped command path.
///
/// Returns the credential ID and the attested key, asserting the frozen ID
/// derivation every time — the precondition both key scenarios rest on.
fn register(device: &mut Device) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let (status, cbor) = device.make_cred(RP, USER_ID);
    assert_eq!(status, 0x00, "resident makeCredential must succeed");
    let (cred_id, x, y) = mc_parts(&cbor);
    assert_eq!(
        cred_id,
        derived_resident_id(),
        "resident ID derivation drifted from the frozen \
         SHA-256(\"fapico2-resident-id\" ‖ SHA-256(rp_id) ‖ user.id)"
    );
    (cred_id, x, y)
}

/// One **non-resident** registration: the same (rp, user.id) as [`register`],
/// but with no `rk` option (`resident = req.rk == Some(true)`), built locally
/// on the same pair numbering `pam_region_repro.rs::make_cred_nonresident`
/// documents: clientDataHash(1), rp(2), user(3), pubKeyCredParams(4),
/// pinUvAuthParam(8), pinUvAuthProtocol(9).
fn register_nonresident(device: &mut Device) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let mut r: heapless::Vec<u8, 512> = heapless::Vec::new();
    nh::push_map_header(&mut r, 6).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &CHALLENGE).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, RP).unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, USER_ID).unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap();
    nh::push_uint(&mut r, 8).unwrap();
    nh::push_bstr(&mut r, &device.pin_auth(&CHALLENGE)).unwrap();
    nh::push_uint(&mut r, 9).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    let (status, cbor) = device.call(0x01, r.as_slice());
    assert_eq!(status, 0x00, "non-resident makeCredential must succeed");
    mc_parts(&cbor)
}

/// The credential ID and the attested P-256 key (x, y) out of a makeCredential
/// response.
///
/// The attestedCredentialData offsets every sibling parser uses:
/// rpIdHash 0-31, flags 32, signCount 33-36, aaguid 37-52, credIdLen 53-54,
/// credId 55.., then the COSE key — walked with the same `no_heap::Parser` the
/// applet itself encodes with.
fn mc_parts(cbor: &[u8]) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let ad = bstr_at(cbor, 2).expect("makeCredential reply carries authData");
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad[55..55 + id_len].to_vec();
    let cose = &ad[55 + id_len..];
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let mut p = Parser::new(cose);
    let Item::Map(n) = p.next().unwrap() else { panic!("COSE key is a map") };
    for _ in 0..n {
        let key = match p.next().unwrap() {
            Item::U(u) => u as i64,
            Item::N(n) => n,
            other => panic!("COSE label {other:?}"),
        };
        match key {
            -2 => match p.next().unwrap() {
                Item::B(b) => x.copy_from_slice(b),
                other => panic!("x is bytes, got {other:?}"),
            },
            -3 => match p.next().unwrap() {
                Item::B(b) => y.copy_from_slice(b),
                other => panic!("y is bytes, got {other:?}"),
            },
            _ => p.skip().unwrap(),
        }
    }
    (cred_id, x, y)
}

/// Does `signed` verify under the P-256 key `(x, y)`?
///
/// Total, not panicking, for the same reason `resident_reregister.rs`'s copy
/// is: the caller wants the answer, and a panic inside the helper would name
/// the wrong line.
fn verifies_under(x: [u8; 32], y: [u8; 32], signed: &[u8], sig_der: &[u8]) -> bool {
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&x);
    point[33..65].copy_from_slice(&y);
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&point) else {
        return false;
    };
    let Ok(sig) = Signature::from_der(sig_der) else {
        return false;
    };
    vk.verify(signed, &sig).is_ok()
}

/// Is `(x, y)` a valid P-256 public key? The gherkin's "the derived scalar is
/// valid for P-256 every time", checked from the wire: a point the curve
/// rejects could never have come from a usable scalar.
fn is_valid_p256_point(x: [u8; 32], y: [u8; 32]) -> bool {
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&x);
    point[33..65].copy_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&point).is_ok()
}

/// **Scenario 1 — the RED.** Same inputs derive the same key.
///
/// One twin, two resident makeCredentials for the same (rp, user.id): both
/// registrations must attest the *same* public key, the key must be a valid
/// P-256 point every time, and a getAssertion pinned to the shared ID must
/// actually verify under it — a key equal in the response but unable to sign
/// would be the shadowing defect wearing a new coat.
#[test]
fn same_inputs_derive_the_same_key() {
    let _guard: Guard = lock();
    let (_region, mut device) = boot("us1721-same-key");

    let (cred_id1, x1, y1) = register(&mut device);
    let (cred_id2, x2, y2) = register(&mut device);

    assert_eq!(
        cred_id1, cred_id2,
        "same (rp, user.id) must derive the same resident ID — the precondition"
    );
    assert!(
        is_valid_p256_point(x1, y1) && is_valid_p256_point(x2, y2),
        "both attested keys must be valid P-256 points"
    );
    assert_eq!(
        (x1, y1),
        (x2, y2),
        "RED (US-1721): two resident registrations for the same (rp, user.id) \
         attested DIFFERENT public keys — the key is still a fresh TRNG draw \
         instead of a function of the resident ID, so a re-registered \
         credential is shadowed by the oldest same-ID record whose key then \
         signs (US-1719, analysis §7: the silent foreign-key signature)"
    );

    // End-to-end: the shared key is not just advertised, it signs. The pinned
    // assertion (allowList naming the shared ID) must verify under it.
    let (status, cbor) = device.get_assertion(RP, Some(&cred_id1));
    assert_eq!(status, 0x00, "the pinned assertion must be served: {cbor:02x?}");
    let auth_data = bstr_at(&cbor, 2).expect("getAssertion reply carries authData");
    let sig_der = bstr_at(&cbor, 3).expect("getAssertion reply carries a signature");
    let mut signed = auth_data;
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(x1, y1, &signed, &sig_der),
        "the pinned assertion must verify under the (shared) registered key"
    );
}

/// **Scenario 2** — the key is not derivable from public data.
///
/// Two twins whose device secrets differ (each `Device::boot(keyed_store())`
/// draws a fresh `hkey`), same (rp, user.id): the credential ID is
/// public-data-derived and therefore *equal* across the twins, but the keys
/// must differ — `hkey` is the secret that makes the derivation
/// unforgeable from `(rp, user)` alone.
#[test]
fn the_key_is_not_derivable_from_public_data() {
    let _guard: Guard = lock();

    let (region_a, mut device_a) = boot("us1721-twin-a");
    let (id_a, x_a, y_a) = register(&mut device_a);
    drop(device_a); // never used after the provider is repointed below

    let (region_b, mut device_b) = boot("us1721-twin-b");
    let (id_b, x_b, y_b) = register(&mut device_b);

    // Both region files must outlive their device's writes.
    drop(region_a);
    drop(region_b);

    assert_eq!(
        id_a, id_b,
        "same public inputs → the same resident ID on both twins (the ID is \
         exactly what is public knowledge)"
    );
    assert_ne!(
        (x_a, y_a),
        (x_b, y_b),
        "two twins with different device secrets must derive DIFFERENT keys for \
         the same (rp, user.id) — a derivation that ignored hkey would make the \
         key forgeable from public data alone"
    );
}

/// **Scenario 3** — non-resident credentials keep their TRNG keys.
///
/// The derivation is the resident branch only. Two rk-absent makeCredentials
/// for the same (rp, user.id) must differ in *both* the key and the (random)
/// credential ID — unchanged from before this story.
#[test]
fn non_resident_credentials_keep_their_trng_keys() {
    let _guard: Guard = lock();
    let (_region, mut device) = boot("us1721-nonresident");

    let (id1, x1, y1) = register_nonresident(&mut device);
    let (id2, x2, y2) = register_nonresident(&mut device);

    assert_ne!(
        id1, id2,
        "non-resident credential IDs stay random (unchanged)"
    );
    assert_ne!(
        (x1, y1),
        (x2, y2),
        "non-resident keys stay TRNG (unchanged) — the derivation must never \
         reach the non-resident branch"
    );
}
