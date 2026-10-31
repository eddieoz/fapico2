//! US-1732 — the RED device-twin suite for seed-governed wallet restore
//! (EPIC FIDO-SEED-ROOT).
//!
//! # The field report this file pins as code
//!
//! The 2026-10-31 diagnosis: a seed exported from board A and imported into
//! board B, then re-registering the same passkey, produced a **different
//! wallet** on B — while delete-and-recreate on B reproduces B's key
//! consistently, so the identity is deterministic and the *root* is what
//! differs. The settled chain (EPIC §1): the resident credential ID is
//! device-independent, but the signing scalar is
//! `HMAC-SHA256(hkey_bytes, "fapico2/resident-key/v1" ‖ cred_id)` and
//! `hkey` is a TRNG-random per-device P-256 scalar — and the backup master
//! seed that EXPORT/LOAD move between devices is inert: it has no consumer
//! outside the vendor transport and its snapshot slot. Custody without
//! authority.
//!
//! # Why the device twin on the region path
//!
//! `AGENTS.md` §1: there are two `FidoApp`s and the shipped one is
//! `device_app::FidoApp`. The wallet lives in the keyregion on hardware, so
//! every scenario here boots the twin over a `Rp2350SecureStore` + installed
//! key region through the shared [`region_boot`] fixture and drives
//! `process_ctap2_with_store` — the shipped path — asserting
//! `backend() == KeyRegion` before anything else, because a snapshot-backed
//! run would prove nothing about the wallet.
//!
//! # The scenarios
//!
//! US-1732's three:
//!
//! 1. **Same seed, same wallet** — `#[ignore]`d RED: on today's code the
//!    seed is inert, so two boards that `seed_master` the same 32 bytes still
//!    draw different TRNG `hkey`s and attest under different keys. US-1734
//!    (the `froot` accessor) and US-1735 (MC keyed by `froot`) flip this.
//! 2. **Different seeds, different keys** — green today and green after the
//!    fix: on today's code different `hkey`s already give different keys;
//!    afterwards different `froot`s do. This is the defect restated in the
//!    affirmative, and it guards the *negative* direction of the fix — the
//!    seed must separate wallets too, not only unify them.
//! 3. **Seedless board behaves exactly as v0.3.3** — the back-compat guard
//!    (EPIC §2 C5), un-ignored and green on today's code: the twin exposes
//!    its `hkey()`, so the suite can derive the expected US-1721 scalar
//!    independently and assert the attested key matches, byte for byte.
//!    When US-1734 landed, this scenario kept running unchanged — the
//!    seedless arm of `froot` *is* `hkey.to_bytes()`, so any deviation is a
//!    break here first. (The EPIC's Step-2 note expected this scenario to be
//!    RED until US-1734 exposed a `froot` accessor; the twin's existing
//!    `hkey()` accessor makes the independent assertion expressible today,
//!    so it runs as a live guard from this story on instead of being parked.)
//!
//! US-1734's two, landed with the accessor:
//!
//! 4. **Seedless `froot` is the `hkey` bytes** — the root itself, pinned
//!    byte-for-byte, plus the seeded arm against the vectors suite's KAT.
//! 5. **A seed install touches nothing but the root** — `hkey` and the
//!    clientPIN `getKeyAgreement` device key (the pinUvAuth-P1 ECDH role)
//!    are byte-identical across a `seed_master` (EPIC §2: "`hkey` keeps
//!    every non-wallet role").

mod region_boot;

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use fapico2_fido::crypto;
use heapless::Vec as HV;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use region_boot::*;

/// The RP and user both boards register — the identity that must collapse to
/// one key once the seed governs (EPIC US-1732's BDD).
const RP: &str = "example.com";
const USER_ID: &[u8] = b"us1732-user";

/// The fixture's PIN — the device is PIN-set, so MC/GA ride a token the
/// fixture mints (`region_boot::Device::set_pin`).
const PIN: &[u8] = b"123456";

/// Board A's seed, board B's different seed. Byte patterns, not entropy: the
/// values do not matter, only that they are 32 bytes and unequal.
const SEED_S: [u8; 32] = [0x42u8; 32];
const SEED_T: [u8; 32] = [0x77u8; 32];

/// The fixture's constant challenge — the clientDataHash tail of every
/// verified signature here, same discipline as `resident_reregister.rs`.
const CHALLENGE: [u8; 32] = [0xCCu8; 32];

/// Boot one region-backed device twin, PIN-set, seeded with `seed`
/// (`None` = seedless), and register `RP`/`USER_ID`.
///
/// Returns the credential ID and the attested key's `(x, y)`. The region and
/// the device are dropped here — the caller only needs the identity, and the
/// region provider is a process global so exactly one is installed at a time
/// (`region_boot`'s module docs).
fn register_on(tag: &str, seed: Option<[u8; 32]>) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let region = install(tag);
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(PIN);
    if let Some(s) = seed {
        device.seed_master(s);
    }
    assert_eq!(
        device.master_seed(),
        seed,
        "the fixture's seed did not land where the device core will read it"
    );
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed — a snapshot-backed run replaces by ID and masks drift"
    );
    let (status, cbor) = device.make_cred(RP, USER_ID);
    assert_eq!(status, 0x00, "resident makeCredential must succeed");
    let (_ad, cred_id, x, y) = mc_parts(&cbor);
    drop(device);
    drop(region);
    (cred_id, x, y)
}

/// The credential ID, and the attested P-256 key `(x, y)`, out of a
/// makeCredential reply — the same walk `resident_reregister.rs::mc_parts`
/// uses: the COSE key lives inside `authData`'s attestedCredentialData tail,
/// rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId COSE.
fn mc_parts(cbor: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
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
    (ad.to_vec(), cred_id, x, y)
}

/// The authData and DER signature out of a getAssertion response.
fn ga_parts(cbor: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (
        bstr_at(cbor, 2).expect("getAssertion reply carries authData"),
        bstr_at(cbor, 3).expect("getAssertion reply carries a signature"),
    )
}

/// Does `sig_der` verify over `signed` under the P-256 key `(x, y)`?
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

/// US-1732 scenario 1 — flipped green by US-1735 (the MC branch keys its
/// derivation by `froot`): the same seed reproduces the same wallet.
#[test]
fn two_boards_with_the_same_seed_derive_the_same_credential_key() {
    let _guard = lock();

    let (cred_a, xa, ya) = register_on("us1732-same-a", Some(SEED_S));
    let (cred_b, xb, yb) = register_on("us1732-same-b", Some(SEED_S));

    assert_eq!(
        cred_a, cred_b,
        "the resident ID is device-independent — the EPIC's settled fact 1"
    );
    assert_eq!(
        (xa, ya),
        (xb, yb),
        "the same seed must reproduce the same passkey private key for the \
         same (rp, user) — the settled end-state this epic exists to land"
    );
}

/// US-1732 scenario 2 — the defect restated in the affirmative; green today
/// and green after the fix.
#[test]
fn two_boards_with_different_seeds_derive_different_keys() {
    let _guard = lock();

    let (cred_a, xa, ya) = register_on("us1732-diff-a", Some(SEED_S));
    let (cred_b, xb, yb) = register_on("us1732-diff-b", Some(SEED_T));

    assert_eq!(cred_a, cred_b, "same identity ⇒ same credential ID, any root");
    assert_ne!(
        (xa, ya),
        (xb, yb),
        "different roots must derive different keys — the seed separates \
         wallets as surely as it unifies them"
    );
}

/// US-1734 scenario (seedless-froot guard): on a twin that never saw a
/// seed, the `froot` accessor returns the `hkey` bytes **byte-for-byte** —
/// the frozen seedless arm (EPIC §2 C5). US-1732's scenario 3 pins the
/// derivation's *output* through the command path; this pins the root
/// itself, so a change to the accessor fails here before anything signs.
#[test]
fn seedless_froot_is_the_hkey_bytes() {
    let _guard = lock();
    let _region = install("us1734-seedless-froot");
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    assert_eq!(device.master_seed(), None);

    let hkey_bytes = device.hkey().to_bytes();
    assert_eq!(device.froot(), hkey_bytes.as_slice(), "seedless froot must be the hkey bytes");

    // And installing a seed moves the root off the hkey bytes — the
    // seed-governed arm, against the same fixed KAT the vectors suite pins
    // for `derive_froot` (independently computed; see seed_root_vectors.rs).
    device.seed_master(SEED_S);
    assert_eq!(
        device.froot(),
        crypto::derive_froot(&SEED_S),
        "seeded froot must be the domain-separated function of the seed"
    );
    assert_ne!(device.froot(), hkey_bytes.as_slice(), "a seed must move the root off hkey");
}

/// US-1734 scenario (the seed does not touch the non-wallet roles): a seed
/// install leaves `hkey` itself, and every consumer keyed by it, unchanged
/// (EPIC §2's "`hkey` keeps every non-wallet role").
///
/// The observable is the clientPIN `getKeyAgreement` response — it is a pure
/// function of `self.hkey` on the device path (`device_core.rs` 0x02 arm,
/// and the same `hkey` keys the pinUvAuth-P1 ECDH at `derive_shared`), so a
/// byte-identical response before and after `seed_master` proves the ECDH
/// role did not move. `hkey()`'s accessor is the direct half of the same
/// proof.
#[test]
fn a_seed_install_does_not_touch_the_non_wallet_roles() {
    let _guard = lock();
    let _region = install("us1734-roles");
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();

    let hkey_before = device.hkey();
    let ka_before = key_agreement_bytes(&mut device);

    device.seed_master(SEED_S);

    assert_eq!(
        device.hkey().to_bytes(),
        hkey_before.to_bytes(),
        "the seed install must not rotate hkey"
    );
    assert_eq!(
        key_agreement_bytes(&mut device),
        ka_before,
        "the clientPIN getKeyAgreement device key must be unchanged — a seed \
         LOAD must not break a PIN handshake mid-life"
    );
}

/// US-1735 scenario (largeBlobKey follows the same root): two seeded twins
/// with the same seed return the **same** largeBlobKey for the same identity.
#[test]
fn large_blob_key_follows_the_same_root() {
    let _guard = lock();

    let region_a = install("us1735-lbk-a");
    let mut a = Device::boot(keyed_store());
    a.grant_presence_always();
    a.set_pin(PIN);
    a.seed_master(SEED_S);

    let region_b = install("us1735-lbk-b");
    let mut b = Device::boot(keyed_store());
    b.grant_presence_always();
    b.set_pin(PIN);
    b.seed_master(SEED_S);

    let (sa, cbor_a) = a.make_cred_lbk(RP, USER_ID);
    let (sb, cbor_b) = b.make_cred_lbk(RP, USER_ID);
    assert_eq!(sa, 0x00, "MC with largeBlobKey must succeed on board A");
    assert_eq!(sb, 0x00, "MC with largeBlobKey must succeed on board B");
    let lbk_a = bstr_at(&cbor_a, 5).expect("MC response carries largeBlobKey at key 5");
    let lbk_b = bstr_at(&cbor_b, 5).expect("MC response carries largeBlobKey at key 5");
    assert_eq!(lbk_a, lbk_b, "the same seed must reproduce the same largeBlobKey");
    drop(a);
    drop(b);
    drop(region_a);
    drop(region_b);
}

/// US-1735 scenario (US-1721 preserved): a re-registration on a seeded board
/// is idempotent — same credential ID attests under the same key, and the
/// drift epic's overwrite leaves exactly one record for the identity.
#[test]
fn reregistration_on_a_seeded_board_stays_idempotent() {
    let _guard = lock();
    let _region = install("us1735-idempotent");
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(PIN);
    device.seed_master(SEED_S);

    let (s1, c1) = device.make_cred(RP, USER_ID);
    let (_, cred_id, x1, y1) = mc_parts(&c1);
    let (s2, c2) = device.make_cred(RP, USER_ID);
    let (_, cred_id_2, x2, y2) = mc_parts(&c2);
    assert_eq!((s1, s2), (0x00, 0x00));
    assert_eq!(cred_id, cred_id_2, "the resident ID derivation is frozen");
    assert_eq!((x1, y1), (x2, y2), "the key is a function of (froot, cred_id) — idempotent");

    // Exactly one record for the identity: credMgmt metadata's resident
    // count is the applet's own answer (the drift epic's overwrite holds).
    let (cm_status, cm_cbor) = device.cm_get_metadata();
    assert_eq!(cm_status, 0x00, "credMgmt metadata must answer on a token'd twin");
    assert_eq!(
        uint_at(&cm_cbor, 1),
        Some(1),
        "exactly one resident record for the identity after re-registration"
    );
}

/// The raw clientPIN `getKeyAgreement` (0x06 sub 0x02) response body — the
/// device COSE key, byte-exact.
fn key_agreement_bytes(device: &mut Device) -> Vec<u8> {
    let mut req: HV<u8, 32> = HV::new();
    nh::push_map_header(&mut req, 2).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 2).unwrap();
    nh::push_uint(&mut req, 2).unwrap();
    let (status, cbor) = device.call(0x06, req.as_slice());
    assert_eq!(status, 0x00, "getKeyAgreement must succeed");
    cbor
}

/// Plant one resident record directly into a twin's key region — the shape a
/// future record-transfer or migration leg would produce: the registered
/// public key is whatever the caller says, the stored scalar is deliberately
/// **not** the derivation's answer (`[0x66; 32]`), so a GA that trusted the
/// stored scalar would sign under the wrong key and fail every verification
/// here.
///
/// The record goes through the applet's own codec and key derivation
/// (`region_keys`, `RegionCredentials::put`), so it is sealed exactly as a
/// device-written record would be — `region_boot::enroll_directly`'s
/// discipline, with the identity under test's fields.
fn plant_record(
    device: &mut Device,
    region_file: &InstalledRegion,
    cred_id: &[u8],
    x: [u8; 32],
    y: [u8; 32],
) {
    let keys = device.with_store(|store| {
        let ks = DeviceKeystore::load(store).expect("readable").expect("snapshot present");
        region_keys(store, &ks)
    });
    let mut cred = DeviceCredential {
        credential_id: HV::new(),
        public_key: DeviceCoseKey::es256(x, y),
        private_key: PrivateScalar::from_bytes([0x66u8; 32]),
        rp_id_hash: crypto::sha256(RP.as_bytes()),
        rp_id: HV::new(),
        user_handle: HV::new(),
        user_name: HV::new(),
        user_display_name: HV::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: HV::new(),
        cred_blob: HV::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: 0,
        revoked: false,
        expires_at: None,
    };
    cred.credential_id.extend_from_slice(cred_id).unwrap();
    cred.rp_id.extend_from_slice(RP.as_bytes()).unwrap();
    cred.user_handle.extend_from_slice(USER_ID).unwrap();
    region_file.with(|region| {
        let mut creds = RegionCredentials::new(region, &keys);
        creds.put(&nonce(7), &cred).expect("the planted record writes");
    });
}

/// US-1736 scenario: a restored board signs a restored identity **without a
/// usable stored key**. Board A registers under seed S (key K); board B —
/// same seed — holds only a planted record for the same credential ID with
/// the same public key and a junk stored scalar. The derivation at sign time
/// reconstructs K and the signature verifies under it.
#[test]
fn a_restored_board_signs_without_a_usable_stored_key() {
    let _guard = lock();

    // Board A registers the identity under seed S.
    let (cred_id, kx, ky) = register_on("us1736-a", Some(SEED_S));

    // Board B: same seed, planted record, no usable stored scalar.
    let region_b = install("us1736-b");
    let mut b = Device::boot(keyed_store());
    b.grant_presence_always();
    b.set_pin(PIN);
    b.seed_master(SEED_S);
    plant_record(&mut b, &region_b, &cred_id, kx, ky);

    let (status, cbor) = b.get_assertion(RP, None);
    assert_eq!(status, 0x00, "the restored board must serve the planted identity");
    let (ad, sig) = ga_parts(&cbor);
    let mut signed = ad;
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(kx, ky, &signed, &sig),
        "the signature must verify under board A's key K — derived from the \
         seed at sign time, not read from the record"
    );
}

/// US-1736 scenario (the orphan gate, EPIC §2 C3): a resident record whose
/// stored public key disagrees with the derivation never signs, and the
/// answer is `CTAP2_ERR_NO_CREDENTIALS` — absence, not fault.
#[test]
fn a_record_whose_stored_key_disagrees_with_the_derivation_never_signs() {
    let _guard = lock();
    let region = install("us1736-orphan");
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(PIN);
    device.seed_master(SEED_S);

    // The identity's credential ID is device-independent, so the ID is the
    // real one; the registered public key is unrelated to anything the
    // seed could derive.
    let cred_id = derived_resident_id();
    plant_record(&mut device, &region, &cred_id, [0xAAu8; 32], [0xBBu8; 32]);

    let (status, cbor) = device.get_assertion(RP, None);
    assert_eq!(
        status, 0x2E,
        "a disagreeing record answers NO_CREDENTIALS — never a guess, never a signature"
    );
    assert!(cbor.is_empty(), "the refusal carries no body");

    // The allowList shape of the same request: same refusal.
    let (status_allow, _cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(status_allow, 0x2E, "the orphan gate does not depend on the request shape");
}

/// The frozen resident-ID derivation, restated from the client's side (the
/// same independent recomputation `resident_reregister.rs` pins): the record
/// the orphan gate judges carries the real identity's ID.
fn derived_resident_id() -> Vec<u8> {
    use sha2::Digest;
    let rp_hash = crypto::sha256(RP.as_bytes());
    let mut h = sha2::Sha256::new();
    h.update(b"fapico2-resident-id");
    h.update(&rp_hash);
    h.update(USER_ID);
    h.finalize().to_vec()
}


/// US-1732 scenario 3 — the seedless back-compat guard (EPIC §2 C5), a live
/// regression guard from this story on (see the module docs for why it runs
/// un-ignored rather than parked RED).
#[test]
fn a_seedless_board_behaves_exactly_as_v0_3_3() {
    let _guard = lock();

    let _region = install("us1732-seedless");
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(PIN);
    assert_eq!(device.master_seed(), None, "a stock device has no master seed");
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed"
    );

    let (status, cbor) = device.make_cred(RP, USER_ID);
    assert_eq!(status, 0x00);
    let (_ad, cred_id, x, y) = mc_parts(&cbor);

    // The independent US-1721 derivation, keyed by the board's own hkey —
    // what v0.3.3 shipped. The frozen rule: derive_resident_scalar's output
    // for a given (hkey, cred_id) must not change by one bit (EPIC §2).
    let hkey_bytes = device.hkey().to_bytes();
    let derived = crypto::derive_resident_scalar(hkey_bytes.as_slice(), &cred_id)
        .expect("the seedless derivation is never exhausted (US-1721)");
    let sk = p256::SecretKey::from_slice(&*derived).expect("a validated scalar");
    let pub_bytes = crypto::public_key_bytes(&sk.public_key());
    let mut ex = [0u8; 32];
    let mut ey = [0u8; 32];
    ex.copy_from_slice(&pub_bytes[1..33]);
    ey.copy_from_slice(&pub_bytes[33..65]);
    assert_eq!((x, y), (ex, ey), "the attested key must be the hkey-keyed US-1721 derivation");

    // And getAssertion signs under that same key, over authData ‖
    // clientDataHash.
    let (ga_status, ga_cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(ga_status, 0x00, "seedless getAssertion must serve the record");
    let (ad, sig) = ga_parts(&ga_cbor);
    let mut signed = ad;
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(x, y, &signed, &sig),
        "the seedless assertion must sign under the record's registered key"
    );
}
