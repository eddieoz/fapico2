//! US-1722 — CTAP 2.1 §6.1.3 overwrite: makeCredential replaces the same-ID
//! record (EPIC FIDO-RESIDENT-DRIFT).
//!
//! US-1721 made resident keys deterministic, so the duplicate records a
//! re-registration leaves behind are harmless *signature-wise* — but they
//! still accumulate (one slot lost per re-registration, of 844) and credMgmt
//! still enumerates them. This story implements the spec-default that closes
//! it: **a makeCredential for a discoverable credential REPLACES the existing
//! same-ID record** (CTAP 2.1 §6.1.3). The overwrite must run strictly after
//! the existing exclude/UP/UV/token gates — it inherits them — and it must
//! RECLAIM the replaced record's slot, never leak one (`AGENTS.md` §5:
//! capacity is a security property).
//!
//! # The counter trap this file pins
//!
//! The replaced record's signature counter is part of its identity to the RP:
//! the client has seen `C0 … Cn` signed for this ID, and the surviving record
//! must sign `Cn+1` next. Both replace-by-ID backends (snapshot
//! `device_keystore.rs::store_credential`, host twin `keystore.rs`) reset the
//! counter to the applet's fresh global one on replace — and a naive region
//! overwrite would too. The region path has a second half the other two do
//! not: the batched counter window (`CounterWindow`, 32 bumps) holds values
//! the RP has already seen that are not durable yet, so the carry must read
//! the *effective* (pending-aware) counter and the window must be made
//! durable before the record it describes is removed. This file pins the
//! wire-observable contract: the first assertion after the overwrite signs
//! `Cn+1`, and the makeCredential response itself reports the carried counter
//! — a signCount that drops below values already signed for this ID is the
//! clone-detection signal the RP acts on.
//!
//! # Harness
//!
//! `region_boot`'s device twin — the shipped path (`AGENTS.md` §1: the host
//! twin in `app.rs` replaces by ID already, so a host-twin suite would pass
//! forever while hardware drifts). Every scenario asserts
//! `CredentialBackend::KeyRegion` and holds `region_boot::lock()` for its
//! whole body (the provider is a process-global).
//!
//! Signed-message shape: the fixture's constant challenge `[0xCC; 32]` is the
//! clientDataHash of every MC and GA here, so every ES256 signature verifies
//! over `authData ‖ [0xCC; 32]`. GA responses carry no key, so each
//! registration's key is tracked from its own makeCredential response's
//! attestedCredentialData COSE key.

mod region_boot;

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use fapico2_fido::crypto;
use fapico2_platform::keyregion::KeyRegion as _;
use heapless::Vec as HV;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use region_boot::*;

/// The RP every scenario registers against.
const RP: &str = "us1722.example";

/// A fixed `user.id`, byte-identical across the registrations of each
/// scenario — the precondition that makes the derived resident ID collide.
const USER_ID: &[u8] = b"us1722-user";

const PIN: &[u8] = b"123456";
/// The fixture's constant challenge — the clientDataHash for every MC and GA.
const CHALLENGE: [u8; 32] = [0xCCu8; 32];

/// CTAP2_ERR_CREDENTIAL_EXCLUDED.
const ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;

/// The frozen resident-ID derivation, restated from the client's side:
/// `SHA-256("fapico2-resident-id" ‖ SHA-256(rp_id) ‖ user_handle)`
/// (`device_core.rs`, the US-1721 block). Recomputed here so the scenarios
/// assert the wire ID against an independent derivation rather than against
/// itself.
fn derived_resident_id() -> Vec<u8> {
    let rp_hash = crypto::sha256(RP.as_bytes());
    let mut buf = Vec::new();
    buf.extend_from_slice(b"fapico2-resident-id");
    buf.extend_from_slice(&rp_hash);
    buf.extend_from_slice(USER_ID);
    crypto::sha256(&buf).to_vec()
}

/// The authData, credential ID and attested P-256 key (x, y) out of a
/// makeCredential response. The COSE key lives inside `authData`, a nested
/// map inside a byte string — the one shape `bstr_at` cannot reach alone.
fn mc_parts(cbor: &[u8]) -> (Vec<u8> /* authData */, Vec<u8> /* cred id */, [u8; 32], [u8; 32]) {
    let ad = bstr_at(cbor, 2).expect("makeCredential reply carries authData");
    // attestedCredentialData: rpIdHash(32) flags(1) signCount(4) aaguid(16)
    // credIdLen(2) credId COSE-key.
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

/// The authData and DER signature out of a getAssertion response (keys 2, 3).
fn ga_parts(cbor: &[u8]) -> (Vec<u8> /* authData */, Vec<u8> /* DER sig */) {
    (
        bstr_at(cbor, 2).expect("getAssertion reply carries authData"),
        bstr_at(cbor, 3).expect("getAssertion reply carries a signature"),
    )
}

/// The signCount out of authData: bytes 33..37, big-endian — rpIdHash(32) +
/// flags(1) precede it.
fn sign_count_of(auth_data: &[u8]) -> u32 {
    u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]])
}

/// Does `signed` verify under the P-256 key `(x, y)`?
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

/// One resident registration through the shipped command path, asserting the
/// deterministic derivation (the US-1721 precondition every scenario rests on).
fn register(device: &mut Device) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let (status, cbor) = device.make_cred(RP, USER_ID);
    assert_eq!(status, 0x00, "resident makeCredential must succeed: {cbor:02x?}");
    let (_ad, cred_id, x, y) = mc_parts(&cbor);
    assert_eq!(
        cred_id,
        derived_resident_id(),
        "resident ID derivation drifted from the frozen \
         SHA-256(\"fapico2-resident-id\" ‖ SHA-256(rp_id) ‖ user.id)"
    );
    (cred_id, x, y)
}

/// A non-resident makeCredential for the same (rp, user.id): no `rk` option —
/// the builder `pam_region_repro.rs::make_cred_nonresident` established for
/// the rk:false shape on this fixture.
fn make_cred_nonresident(device: &mut Device, user: &[u8]) -> (u8, Vec<u8>) {
    let mut r: HV<u8, 512> = HV::new();
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
    nh::push_bstr(&mut r, user).unwrap();
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
    device.call(0x01, r.as_slice())
}

/// A resident makeCredential whose excludeList names `exclude_id` — the same
/// builder `resident_reregister.rs::make_cred_excluding` documents (the
/// exclude entry is a `{type, id}` map; a bare bstr would be discarded by the
/// parser and the refusal would never fire).
fn make_cred_excluding(device: &mut Device, exclude_id: &[u8]) -> (u8, Vec<u8>) {
    let mut r: HV<u8, 512> = HV::new();
    nh::push_map_header(&mut r, 8).unwrap();
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
    nh::push_uint(&mut r, 5).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, exclude_id).unwrap();
    nh::push_uint(&mut r, 7).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "rk").unwrap();
    nh::push_bool(&mut r, true).unwrap();
    nh::push_uint(&mut r, 8).unwrap();
    nh::push_bstr(&mut r, &device.pin_auth(&CHALLENGE)).unwrap();
    nh::push_uint(&mut r, 9).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    device.call(0x01, r.as_slice())
}

/// Boot the region-backed twin the way every scenario needs it: a fresh
/// region file, a PIN-set snapshot persisted, presence granted, token minted.
/// The lock guard and the region file must outlive the device.
fn boot_device(tag: &str) -> (MutexGuardOf, InstalledRegion, Device) {
    let guard = lock();
    let region_file = install(tag);
    let mut device = Device::boot(keyed_store());
    device.grant_presence_always();
    device.set_pin(PIN);
    assert!(device.persist(), "the PIN write must reach the secure store");
    assert_eq!(
        device.backend(),
        fapico2_fido::device_keystore::CredentialBackend::KeyRegion,
        "the fixture must be region-backed — a snapshot-backed run replaces by ID \
         and masks the overwrite defect by construction"
    );
    (guard, region_file, device)
}

/// The serialisation guard's type, named once (the guard must be bound, not
/// dropped, for the whole test body).
type MutexGuardOf = std::sync::MutexGuard<'static, ()>;

/// How many FIDO slots are physically free, counted the way the allocator
/// counts them: `[FIDO_FIRST_SLOT, FIDO_SLOT_LIMIT)`, a slot is free iff its
/// image is pristine (`is_erased` — the `RecordOccupancy` rule: occupied
/// unless pristine). A tombstone left by an uncompacted delete occupies its
/// slot and is NOT free here, which is what makes this the honest
/// "did the overwrite reclaim the slot" measure — the index-based
/// `remaining` cannot see an uncompacted tombstone.
fn free_fido_slots(region_file: &InstalledRegion) -> u32 {
    region_file.with(|region| {
        let mut free = 0u32;
        for i in FIDO_FIRST_SLOT..FIDO_SLOT_LIMIT {
            let slot = Slot::new(i as u16).expect("FIDO slot index is inside the region");
            if let Ok(img) = region.read_slot(slot) {
                if is_erased(&img) {
                    free += 1;
                }
            }
        }
        free
    })
}

/// credMgmt `enumerateCredsBegin` totalCredentials (PicoForge key 9 — the
/// dialect is binding, `AGENTS.md` §2) for [`RP`].
fn cm_total_for_rp(device: &mut Device) -> u64 {
    let (status, cbor) = device.cm_enumerate_creds(RP);
    assert_eq!(status, 0x00, "enumerateCredsBegin must succeed: {cbor:02x?}");
    uint_at(&cbor, 9).expect("totalCredentials at PicoForge key 9")
}

/// credMgmt `getCredsMetadata` maxPossibleRemainingResidentCredentialsCount
/// (key 2 in both dialects).
fn cm_remaining(device: &mut Device) -> u64 {
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata must succeed: {cbor:02x?}");
    uint_at(&cbor, 2).expect("maxPossibleRemainingResidentCredentialsCount at key 2")
}

/// **US-1722 scenario 1 — overwrite collapses the duplicate set.**
///
/// One live resident credential, then makeCredential for the same (rp,
/// user.id) with rk:true and no excludeCredentials → exactly one record for
/// that ID remains (credMgmt totalCredentials == 1), the surviving record
/// signs the pinned assertion, and the allocator reports the same free-slot
/// count as before the re-registration — the replaced record's slot is
/// RECLAIMED, not leaked (`AGENTS.md` §5).
///
/// RED today: the region `put` appends without dedup, so credMgmt lists two
/// and the re-registration burns one of 844 slots.
#[test]
fn overwrite_collapses_the_duplicate_set() {
    let (_guard, region_file, mut device) = boot_device("us1722-overwrite");

    let (cred_id, _k1x, _k1y) = register(&mut device);
    let free_before = free_fido_slots(&region_file);
    let remaining_before = cm_remaining(&mut device);

    // The overwrite: same (rp, user.id), rk: true, no exclude list.
    let (id2, k2x, k2y) = register(&mut device);
    assert_eq!(id2, cred_id, "the deterministic derivation must produce the same ID twice");

    // Exactly one record for the RP.
    let total = cm_total_for_rp(&mut device);
    assert_eq!(
        total, 1,
        "credMgmt must list exactly 1 credential for the RP after the overwrite; found {total} \
         — the re-registration appended a duplicate instead of replacing the same-ID record \
         (CTAP 2.1 §6.1.3)"
    );

    // The surviving record carries the new registration's attested key: the
    // pinned assertion verifies under K2.
    let (status, cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(status, 0x00, "the pinned assertion must be served: {cbor:02x?}");
    let (auth_data, sig_der) = ga_parts(&cbor);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(k2x, k2y, &signed, &sig_der),
        "the surviving record must sign under the new registration's key"
    );

    // Capacity: the overwrite reclaimed the replaced record's slot — the
    // allocator's physical free count is unchanged, and the wire claim
    // (`getCredsMetadata` remaining) with it.
    let free_after = free_fido_slots(&region_file);
    assert_eq!(
        free_after, free_before,
        "the overwrite must reclaim the replaced record's slot, never leak one: free slots \
         went {free_before} -> {free_after} (AGENTS.md §5: capacity is a security property)"
    );
    let remaining_after = cm_remaining(&mut device);
    assert_eq!(
        remaining_after, remaining_before,
        "the wire capacity claim must be unchanged across an overwrite: \
         {remaining_before} -> {remaining_after}"
    );
}

/// **US-1722 scenario 2 — the counter never regresses for the surviving ID.**
///
/// First registration → first assertion counter C0; several assertions
/// advance it to C_last; overwrite re-registration; one more assertion →
/// signCount == C_last + 1 — never the applet's fresh global counter, and
/// never a value below what the RP has already seen for this ID.
///
/// The makeCredential response's own signCount is part of the same contract:
/// it must report the CARRIED counter. A response reporting the fresh global
/// counter while the record carries C_last makes the RP observe signCount
/// drop from the values it has already accepted — the clone-detection signal
/// — on the very operation that was supposed to fix the duplicate.
#[test]
fn the_counter_never_regresses_for_the_surviving_id() {
    let (_guard, _region, mut device) = boot_device("us1722-counter");

    let (cred_id, _k1x, _k1y) = register(&mut device);

    // First assertion: C0.
    let (status, cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(status, 0x00, "the first assertion must be served: {cbor:02x?}");
    let (ad, _) = ga_parts(&cbor);
    let c0 = sign_count_of(&ad);
    assert!(c0 > 0, "the first signed counter must be positive, got {c0}");

    // Several assertions advance the counter (batched in the region's
    // CounterWindow — which is exactly the state a naive overwrite loses).
    let mut last = c0;
    for _ in 0..3 {
        let (status, cbor) = device.get_assertion(RP, Some(&cred_id));
        assert_eq!(status, 0x00, "the assertion must be served: {cbor:02x?}");
        let (ad, _) = ga_parts(&cbor);
        let c = sign_count_of(&ad);
        assert!(c > last, "the counter must advance monotonically: {last} -> {c}");
        last = c;
    }

    // The overwrite re-registration.
    let (status, cbor) = device.make_cred(RP, USER_ID);
    assert_eq!(status, 0x00, "the overwrite makeCredential must succeed: {cbor:02x?}");
    let (mc_ad, mc_id, _k2x, _k2y) = mc_parts(&cbor);
    assert_eq!(mc_id, cred_id, "the overwrite targets the same derived ID");
    let mc_count = sign_count_of(&mc_ad);
    assert_eq!(
        mc_count, last,
        "the makeCredential response must report the carried counter ({last}), not the \
         applet's fresh global counter ({mc_count}) — a signCount below values already \
         signed for this ID is the clone-detection signal (CTAP 2.1 §6.1.3 overwrite \
         carries the counter)"
    );

    // One more assertion: C_last + 1.
    let (status, cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(status, 0x00, "the post-overwrite assertion must be served: {cbor:02x?}");
    let (ad, _) = ga_parts(&cbor);
    let final_count = sign_count_of(&ad);
    let expected = last + 1;
    assert_eq!(
        final_count, expected,
        "the first assertion after the overwrite must sign C_last + 1 = {expected}; signed \
         {final_count} — the surviving record's counter must never reset to the applet's \
         fresh counter"
    );
}

/// **US-1722 scenario 3 — exclude list wins over overwrite.**
///
/// The live credential's ID in excludeCredentials → CTAP2_ERR_CREDENTIAL_EXCLUDED
/// (0x19), nothing replaced: the count stays 1 and the record still signs
/// under its own key. The overwrite sits strictly AFTER the exclude gate, so
/// this passes today and must keep passing — the gates precede the overwrite
/// by construction, and reordering them is the hazard the brief names.
#[test]
fn exclude_list_wins_over_overwrite() {
    let (_guard, _region, mut device) = boot_device("us1722-exclude");

    let (cred_id, k1x, k1y) = register(&mut device);

    let (status, body) = make_cred_excluding(&mut device, &cred_id);
    assert_eq!(
        status, ERR_CREDENTIAL_EXCLUDED,
        "MC with excludeCredentials naming the live credential must be refused \
         CTAP2_ERR_CREDENTIAL_EXCLUDED: {body:02x?}"
    );

    // Nothing replaced: still exactly one record.
    let total = cm_total_for_rp(&mut device);
    assert_eq!(total, 1, "the refused re-registration must not have replaced anything");

    // And the stored credential is unharmed: it still signs, under K1.
    let (status, cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(status, 0x00, "the stored credential must still serve: {cbor:02x?}");
    let (auth_data, sig_der) = ga_parts(&cbor);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(k1x, k1y, &signed, &sig_der),
        "the stored credential must still sign under K1 after the refused re-registration"
    );
}

/// **US-1722 scenario 4 — non-discoverable credentials never overwrite.**
///
/// A live resident credential, then an rk:false makeCredential for the same
/// (rp, user.id) → a second, RANDOM-ID credential is created (stateless
/// keyhandles have no identity to overwrite: CTAP 2.1 §6.1.3's replacement
/// rule is scoped to discoverable credentials), and the resident record is
/// untouched — it still enumerates and still asserts under K1.
///
/// Passes today (the random ID cannot collide with the derived one); must
/// keep passing through the overwrite work.
#[test]
fn non_discoverable_credentials_never_overwrite() {
    let (_guard, _region, mut device) = boot_device("us1722-nonresident");

    let (cred_id, k1x, k1y) = register(&mut device);

    // rk: false, same (rp, user.id).
    let (status, cbor) = make_cred_nonresident(&mut device, USER_ID);
    assert_eq!(status, 0x00, "the non-resident makeCredential must succeed: {cbor:02x?}");
    let (_ad, random_id, k2x, k2y) = mc_parts(&cbor);
    assert_ne!(
        random_id, cred_id,
        "a non-discoverable credential gets a random ID — it must never collide with \
         the derived resident ID"
    );

    // The resident record is untouched: still the only discoverable
    // credential for the RP, and still signing under K1.
    let total = cm_total_for_rp(&mut device);
    assert_eq!(
        total, 1,
        "the resident record must still be the only discoverable credential for the RP"
    );
    let (status, cbor) = device.get_assertion(RP, Some(&cred_id));
    assert_eq!(status, 0x00, "the resident record must still serve: {cbor:02x?}");
    let (auth_data, sig_der) = ga_parts(&cbor);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(k1x, k1y, &signed, &sig_der),
        "the resident record must still sign under K1"
    );

    // And the second credential exists: it is servable by its own ID.
    let (status, cbor) = device.get_assertion(RP, Some(&random_id));
    assert_eq!(status, 0x00, "the non-resident credential must be servable: {cbor:02x?}");
    let (auth_data, sig_der) = ga_parts(&cbor);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(k2x, k2y, &signed, &sig_der),
        "the non-resident credential must sign under its own key"
    );
}

// ---------------------------------------------------------------------------
// The host twin (AGENTS.md §1: there are two FidoApps, and they must not
// drift on this story's behaviour)
// ---------------------------------------------------------------------------

use fapico2_fido::app::FidoApp;
use fapico2_fido::keystore::MemoryKeystore;

/// A resident (rk: true) or non-resident makeCredential for the host twin,
/// PIN-less — the twin answers `makeCredUvNotRqd: true` without a PIN, so no
/// pinUvAuthParam is needed. Numbering as the device twin's builder documents:
/// clientDataHash(1), rp(2), user(3), pubKeyCredParams(4), options(7).
fn twin_make_cred(rp: &str, user: &[u8], rk: bool) -> Vec<u8> {
    let mut r: HV<u8, 512> = HV::new();
    nh::push_map_header(&mut r, if rk { 5 } else { 4 }).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &CHALLENGE).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, rp).unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, user).unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap();
    if rk {
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "rk").unwrap();
        nh::push_bool(&mut r, true).unwrap();
    }
    r.as_slice().to_vec()
}

/// A getAssertion with an allowList entry for the host twin — rpId(1),
/// clientDataHash(2), allowList(3) (`app.rs::parse_ga_request`'s numbering,
/// the reverse of makeCredential's).
fn twin_get_assertion(rp: &str, id: &[u8]) -> Vec<u8> {
    let mut r: HV<u8, 512> = HV::new();
    nh::push_map_header(&mut r, 3).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, rp).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_bstr(&mut r, &CHALLENGE).unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, id).unwrap();
    r.as_slice().to_vec()
}

/// **US-1722 — the twin-proof: the host twin carries the counter too.**
///
/// AGENTS.md §1's rule is that the twins answer identically, and US-1722's
/// response half is no exception: the host twin's `MemoryKeystore` replaces
/// by ID in place (the same counter carry the device twins got), and its
/// makeCredential response must report the CARRIED counter — not the fresh
/// global one — so a client on the twin never observes signCount drop below
/// values it already accepted for the ID. The device twin scenario above
/// pins the same contract on the region path; this one pins it on the twin
/// the emulator runs (`app.rs`), including across its own GA bumps.
///
/// No PIN, no region: the twin's snapshot keystore is the whole story here —
/// a PIN-less twin answers `makeCredUvNotRqd: true`, so a resident
/// makeCredential needs no pinUvAuthParam, and the default presence source
/// grants.
#[test]
fn the_host_twin_also_carries_the_counter_on_a_resident_replace() {
    let mut twin = FidoApp::with_keystore(MemoryKeystore::new());

    // First registration: response signCount is the fresh global counter.
    let first = twin.process_ctap2(0x01, &twin_make_cred(RP, USER_ID, true), [0, 0, 0, 1]);
    assert_eq!(
        first[0], 0x00,
        "host-twin resident makeCredential must succeed: {:02x?}",
        &first[..first.len().min(24)]
    );
    let (ad1, cred_id, _k1x, _k1y) = mc_parts(&first[1..]);
    let s1 = sign_count_of(&ad1);

    // Two assertions advance the record's counter (the twin bumps in RAM).
    let mut last = s1;
    for _ in 0..2 {
        let ga = twin.process_ctap2(0x02, &twin_get_assertion(RP, &cred_id), [0, 0, 0, 1]);
        assert_eq!(
            ga[0], 0x00,
            "host-twin getAssertion must be served: {:02x?}",
            &ga[..ga.len().min(24)]
        );
        let (ad, _) = ga_parts(&ga[1..]);
        let c = sign_count_of(&ad);
        assert!(c > last, "twin counter must advance monotonically: {last} -> {c}");
        last = c;
    }

    // The replace registration: response signCount must be the CARRIED
    // counter, not the fresh global one (which is 1 here — one MC has
    // happened — while the record the replace supersedes already signed
    // `last`).
    let second = twin.process_ctap2(0x01, &twin_make_cred(RP, USER_ID, true), [0, 0, 0, 1]);
    assert_eq!(
        second[0], 0x00,
        "host-twin replace makeCredential must succeed: {:02x?}",
        &second[..second.len().min(24)]
    );
    let (ad2, id2, _k2x, _k2y) = mc_parts(&second[1..]);
    assert_eq!(id2, cred_id, "the twin derives the same resident ID twice");
    let mc_count = sign_count_of(&ad2);
    assert_eq!(
        mc_count, last,
        "the host twin's makeCredential response must report the carried counter ({last}), \
         not the fresh global one ({mc_count}) — a signCount below values already signed \
         for this ID is the clone-detection signal (CTAP 2.1 §6.1.3; the device twin \
         patches the same bytes)"
    );

    // The surviving record continues: the next assertion signs carried + 1.
    let ga = twin.process_ctap2(0x02, &twin_get_assertion(RP, &cred_id), [0, 0, 0, 1]);
    assert_eq!(
        ga[0], 0x00,
        "post-replace host-twin assertion must be served: {:02x?}",
        &ga[..ga.len().min(24)]
    );
    let (ad, _) = ga_parts(&ga[1..]);
    let expected = last + 1;
    assert_eq!(
        sign_count_of(&ad),
        expected,
        "the first host-twin assertion after the replace must sign C_last + 1 = {expected}"
    );
}
