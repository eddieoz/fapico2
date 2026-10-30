//! US-1726 — credMgmt deleteCredential removes every same-ID record
//! (EPIC FIDO-RESIDENT-DRIFT).
//!
//! credMgmt `deleteCredential` used to kill exactly ONE record per request:
//! `RegionCredentials::delete` resolves one slot (`find_slot`, newest-first
//! since US-1724) and tombstones it. On a **legacy duplicate set** — the
//! pre-epic state where the same credential ID occupies several records with
//! different keys and counters — the newest duplicate died and the rest kept
//! shadowing: the RP still enumerated the credential, a pinned getAssertion
//! still served the survivor, and one of the freed slots stayed leaked until
//! some later operation happened to touch it. US-1722 built
//! `FidoApp::delete_all_by_id` — the one "delete this credential" primitive,
//! flush-first and loop-to-exhaustion — for makeCredential's overwrite; this
//! story routes the credMgmt arm through the same helper so MC overwrite and
//! credMgmt can never diverge on what "delete this credential" means.
//!
//! # The counter-window wedge this retires (found in US-1722's review)
//!
//! The old arm tombstoned WITHOUT flushing the `CounterWindow` first. A
//! getAssertion that had batched a counter bump for the deleted slot left a
//! pending entry that outlived its record — and `flush_counters` drops entries
//! one at a time on success, so the stale entry (pointing at a tombstone or,
//! after compaction, an erased slot) failed every later flush at that entry:
//! all counter persistence wedged, or — had the slot been re-allocated — the
//! stale value would have been written into the slot's next tenant.
//! `delete_all_by_id` flushes FIRST, so no pending entry outlives its record.
//! `the_deleted_slot_leaves_no_stale_pending_counter_entry` pins the wedge
//! observable end to end: a delete with a batched counter outstanding must not
//! break the NEXT flush consumer (a makeCredential overwrite).
//!
//! # Harness
//!
//! `region_boot`'s device twin — the shipped path (`AGENTS.md` §1). The
//! duplicate fixture is written through the region API directly
//! ([`region_boot::credential`] + `RegionCredentials::put`): two records, same
//! credential ID and RP, different keys and counters — a legacy board's state.
//! The distinct credential of the survivor scenario goes through
//! makeCredential, so it is command-path-real. Every scenario asserts
//! `CredentialBackend::KeyRegion` and holds `region_boot::lock()` for its whole
//! body (the provider is a process-global).
//!
//! The deleteCredential request is the **PicoForge dialect** (`AGENTS.md` §2):
//! `authenticatorCredentialManagement` 0x0A, sub-command 0x06, params
//! `{2: {type, id}}` under the request's key 2, and the pinUvAuth message is
//! `subCommand ‖ CBOR(subCommandParams)` — byte-exact, as
//! `tests/device_full_set.rs::picoforge_cred_mgmt` documents. Success answers
//! an empty body in both dialects; that wire shape is frozen here.

mod region_boot;

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use fapico2_fido::crypto;
use fapico2_platform::keyregion::host::Faults;
use fapico2_platform::keyregion::KeyRegion as _;
use heapless::Vec as HV;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use region_boot::*;

/// The RP every fixture and command in this file runs against.
const RP: &str = "us1726.example";

const PIN: &[u8] = b"123456";

const OK: u8 = 0x00;
/// `CTAP2_ERR_NO_CREDENTIALS` — the total-miss answer, kept from today.
const NO_CREDENTIALS: u8 = 0x2E;
/// `CTAP2_ERR_KEY_STORE_FULL` — the internal-fault answer (fail closed).
const KEY_STORE_FULL: u8 = 0x28;

/// The duplicate set's ID: [`credential_id`]'s fixture 1, carried by BOTH
/// fixture records (the second one has it forced on).
fn dup_id() -> [u8; 32] {
    credential_id(1)
}

/// SHA-256 through the applet's own `crypto`, so the RP-hash assertions are
/// not asserting a second derivation.
fn rp_of(s: &str) -> [u8; 32] {
    crypto::sha256(s.as_bytes())
}

/// Boot the region-backed twin: a fresh region file, a PIN-set snapshot
/// persisted, presence granted. The lock guard and the region file must
/// outlive the device.
fn boot_device(tag: &str) -> (std::sync::MutexGuard<'static, ()>, InstalledRegion, Device) {
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
         in an array and cannot hold a duplicate set at all"
    );
    (guard, region_file, device)
}

/// The region keys the applet derives from the durable snapshot.
fn keys_of(device: &mut Device) -> RegionKeys {
    device.with_store(|store| {
        let ks = DeviceKeystore::load(store).expect("readable").expect("snapshot present");
        region_keys(store, &ks)
    })
}

/// Write one resident fixture credential straight into the region.
///
/// [`credential`](region_boot::credential)'s fixture gives every credential its
/// own RP and its own ID; this overrides both to the scenario's RP, and — when
/// `force_id` is given — stamps the duplicate ID on, so two records with
/// different keys ([`credential`] derives them from `n`) and different counters
/// carry ONE identity. That is the pre-epic legacy board's state: US-1721 made
/// new registrations derive the ID, but boards registered before the epic hold
/// whatever duplicates their pre-derivation re-registrations appended.
fn write_fixture(device: &mut Device, region_file: &InstalledRegion, n: u32, force_id: Option<&[u8; 32]>) {
    let keys = keys_of(device);
    let mut cred = credential(n, true);
    cred.rp_id_hash = rp_of(RP);
    cred.rp_id.clear();
    cred.rp_id.extend_from_slice(RP.as_bytes()).unwrap();
    if let Some(id) = force_id {
        cred.credential_id.clear();
        cred.credential_id.extend_from_slice(id).unwrap();
    }
    region_file.with(|region| {
        let mut creds = RegionCredentials::new(region, &keys);
        creds
            .put(&nonce(100 + n), &cred)
            .expect("the fixture must enrol (unique per-write nonce, lowest free slot)");
    });
}

/// How many FIDO slots are physically free, counted the way the allocator
/// counts them: `[FIDO_FIRST_SLOT, FIDO_SLOT_LIMIT)`, a slot is free iff its
/// image is pristine (`is_erased` — the `RecordOccupancy` rule). A tombstone
/// left by an uncompacted delete occupies its slot and is NOT free here, which
/// makes this the honest "did the delete return the slots" measure — the
/// index-based `remaining` cannot see an uncompacted tombstone.
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

/// credMgmt `deleteCredential` (0x06), **PicoForge dialect**: params
/// `{2: {type: "public-key", id: bstr}}` under the request's key 2, pinUvAuth
/// protocol 1, and the MAC over `subCommand ‖ CBOR(subCommandParams)` — the
/// params map byte-exact as sent (`device_full_set.rs::picoforge_cred_mgmt`
/// is the reference for the signing scope).
fn cm_delete_cred(device: &mut Device, id: &[u8]) -> (u8, Vec<u8>) {
    let mut params: HV<u8, 128> = HV::new();
    nh::push_map_header(&mut params, 1).unwrap();
    nh::push_uint(&mut params, 2).unwrap();
    nh::push_map_header(&mut params, 2).unwrap();
    nh::push_tstr(&mut params, "id").unwrap();
    nh::push_bstr(&mut params, id).unwrap();
    nh::push_tstr(&mut params, "type").unwrap();
    nh::push_tstr(&mut params, "public-key").unwrap();

    let mut auth_msg: Vec<u8> = vec![0x06];
    auth_msg.extend_from_slice(params.as_slice());
    let mac = crypto::hmac_sha256(&device.pin_token().expect("a minted pinUvAuthToken"), &auth_msg);

    let mut r: HV<u8, 256> = HV::new();
    nh::push_map_header(&mut r, 4).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_uint(&mut r, 0x06).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    r.extend_from_slice(params.as_slice()).ok();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_bstr(&mut r, &mac[..16]).unwrap();
    device.call(0x0A, r.as_slice())
}

/// credMgmt `enumerateCredsBegin` totalCredentials (PicoForge key 9) for [`RP`].
fn cm_total_for_rp(device: &mut Device) -> u64 {
    let (status, cbor) = device.cm_enumerate_creds(RP);
    assert_eq!(
        status, OK,
        "enumerateCredsBegin must succeed while the RP has credentials: {cbor:02x?}"
    );
    uint_at(&cbor, 9).expect("totalCredentials at PicoForge key 9")
}

// ---------------------------------------------------------------------------
// makeCredential/getAssertion response helpers
// ---------------------------------------------------------------------------
// Copied per-test-crate (`mc_overwrite.rs` documents the shapes): each
// integration test compiles `region_boot` separately, and these read wire
// bytes the device twin's responses carry.

/// The authData, credential ID and attested P-256 key (x, y) out of a
/// makeCredential response.
fn mc_parts(cbor: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
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
    (ad, cred_id, x, y)
}

/// The authData and DER signature out of a getAssertion response (keys 2, 3).
fn ga_parts(cbor: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (
        bstr_at(cbor, 2).expect("getAssertion reply carries authData"),
        bstr_at(cbor, 3).expect("getAssertion reply carries a signature"),
    )
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

/// The fixture's constant challenge — the clientDataHash of every GA here, so
/// a signature verifies over `authData ‖ [0xCC; 32]`.
const CHALLENGE: [u8; 32] = [0xCCu8; 32];

// ---------------------------------------------------------------------------
// Scenario 1 — a legacy duplicate set is removed wholesale
// ---------------------------------------------------------------------------

/// **US-1726 scenario 1 — deleting the ID deletes the credential.**
///
/// Two same-ID records (different keys, different counters — the pre-epic
/// legacy shape), then credMgmt deleteCredential for that ID → **zero**
/// credentials for the RP: enumeration answers CTAP2_ERR_NO_CREDENTIALS (the
/// RP is gone), metadata counts zero, a pinned getAssertion answers
/// CTAP2_ERR_NO_CREDENTIALS, and BOTH freed slots return to the allocator.
///
/// RED today: the arm's single `creds.delete` kills only the newest
/// index-order match (US-1724 made the by-ID walk newest-first), so the older
/// duplicate survives — the RP still enumerates, the pinned assertion still
/// serves, and one slot stays leaked.
#[test]
fn a_legacy_duplicate_set_is_removed_wholesale() {
    let (_guard, region_file, mut device) = boot_device("us1726-wholesale");
    let id = dup_id();

    // The legacy fixture: two same-ID records with different keys/counters.
    write_fixture(&mut device, &region_file, 1, None);
    write_fixture(&mut device, &region_file, 2, Some(&id));

    // Fixture sanity: the set is live — enumerated twice, served by GA.
    let total = cm_total_for_rp(&mut device);
    assert_eq!(total, 2, "the fixture's two same-ID records must both enumerate");
    let (status, cbor) = device.get_assertion(RP, Some(&id));
    assert_eq!(status, OK, "the duplicate set must be servable before the delete: {cbor:02x?}");
    let free_before = free_fido_slots(&region_file);

    // When: credMgmt deleteCredential for the set's ID.
    let (status, body) = cm_delete_cred(&mut device, &id);
    assert_eq!(status, OK, "deleteCredential must succeed: {body:02x?}");

    // Then: enumeration reports zero credentials for the RP — the Begin arm
    // answers NO_CREDENTIALS once the RP has nothing left.
    let (status, body) = device.cm_enumerate_creds(RP);
    assert_eq!(
        status, NO_CREDENTIALS,
        "enumerateCredsBegin must answer 0x2E once every same-ID record is gone; got {status:#04x} \
         — a surviving duplicate keeps the RP alive ({body:02x?})"
    );
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, OK, "getCredsMetadata must still succeed: {cbor:02x?}");
    let existing = uint_at(&cbor, 1).expect("existingResidentCredentialsCount at key 1");
    assert_eq!(
        existing, 0,
        "existingResidentCredentialsCount must be 0 after the wholesale delete; found {existing}"
    );

    // And a pinned getAssertion answers NO_CREDENTIALS.
    let (status, body) = device.get_assertion(RP, Some(&id));
    assert_eq!(
        status, NO_CREDENTIALS,
        "a pinned getAssertion must answer 0x2E after the delete; got {status:#04x} — a \
         surviving duplicate still serves the credential ({body:02x?})"
    );

    // Capacity: BOTH freed slots return to the allocator (AGENTS.md §5:
    // capacity is a security property). The physical count — `is_erased` per
    // FIDO slot, the allocator's own occupancy rule — is the honest measure.
    let free_after = free_fido_slots(&region_file);
    assert_eq!(
        free_after,
        free_before + 2,
        "both duplicates' slots must return to the allocator: free went {free_before} -> \
         {free_after}, expected +2"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2 — other credentials survive
// ---------------------------------------------------------------------------

/// **US-1726 scenario 2 — the delete spares everything it does not name.**
///
/// The duplicate set plus ONE distinct-ID credential — created through
/// makeCredential, so it is command-path-real (real keypair, real response) —
/// then deleteCredential for the duplicate set's ID: the distinct credential
/// still enumerates and still asserts, and the assertion verifies under the
/// key the makeCredential response attested.
///
/// GREEN already (the single delete targets only the named ID; the distinct
/// credential was never a match for it) and kept un-ignored: it is the guard
/// that routing the arm through the shared helper — whose loop removes every
/// same-ID record — does not overreach.
#[test]
fn other_credentials_survive() {
    let (_guard, region_file, mut device) = boot_device("us1726-survivor");
    let id = dup_id();

    write_fixture(&mut device, &region_file, 1, None);
    write_fixture(&mut device, &region_file, 2, Some(&id));

    // The distinct credential, through the shipped command path.
    let (status, cbor) = device.make_cred(RP, b"us1726-distinct-user");
    assert_eq!(status, OK, "the distinct makeCredential must succeed: {cbor:02x?}");
    let (_ad, distinct_id, dx, dy) = mc_parts(&cbor);
    assert_ne!(
        distinct_id, id,
        "the derived resident ID must not collide with the fixture duplicate's ID"
    );

    // Fixture sanity: three credentials enumerate for the RP.
    let total = cm_total_for_rp(&mut device);
    assert_eq!(total, 3, "two duplicates + one distinct credential");

    // When: the duplicate set is deleted.
    let (status, body) = cm_delete_cred(&mut device, &id);
    assert_eq!(status, OK, "deleteCredential must succeed: {body:02x?}");

    // Then: the distinct credential still enumerates.
    let (status, cbor) = device.cm_enumerate_creds(RP);
    assert_eq!(
        status, OK,
        "the RP must still enumerate after the duplicate set is deleted: {cbor:02x?}"
    );
    let remaining = uint_at(&cbor, 9).expect("totalCredentials at PicoForge key 9");
    assert!(
        remaining >= 1,
        "the distinct credential must still enumerate; totalCredentials = {remaining}"
    );

    // … and still asserts, under the key its makeCredential attested.
    let (status, cbor) = device.get_assertion(RP, Some(&distinct_id));
    assert_eq!(status, OK, "the distinct credential must still be served: {cbor:02x?}");
    let (auth_data, sig_der) = ga_parts(&cbor);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&CHALLENGE);
    assert!(
        verifies_under(dx, dy, &signed, &sig_der),
        "the distinct credential must sign under its own makeCredential key"
    );
}

// ---------------------------------------------------------------------------
// The counter-window wedge (found in US-1722's review; retired here)
// ---------------------------------------------------------------------------

/// **A deleteCredential with a batched counter outstanding must not wedge the
/// next flush consumer.**
///
/// The wedge, end to end: a getAssertion batches a counter bump for the
/// credential's slot (`CounterWindow`, 32 bumps); deleteCredential tombstones
/// that slot. The old arm flushed nothing first, so the pending entry
/// outlived its record — and because `flush_counters` drops entries one at a
/// time on success, the stale entry (pointing at the tombstone, or at the
/// slot compaction erased) failed every later flush at that entry. The first
/// flush consumer to come along was makeCredential's overwrite: its
/// `delete_all_by_id` flushes FIRST, so the re-registration failed
/// CTAP2_ERR_KEY_STORE_FULL on a perfectly healthy region.
///
/// RED today: the MC overwrite after the delete fails 0x28. GREEN once the
/// arm routes through `delete_all_by_id` — the flush makes the batched
/// counter durable BEFORE the tombstone commits, no pending entry outlives
/// its record, and the overwrite's own flush finds an empty window.
#[test]
fn the_deleted_slot_leaves_no_stale_pending_counter_entry() {
    let (_guard, region_file, mut device) = boot_device("us1726-wedge");
    let id = dup_id();

    // The doomed credential (direct fixture) and a survivor (command path).
    write_fixture(&mut device, &region_file, 1, None);
    let (status, cbor) = device.make_cred(RP, b"us1726-wedge-user");
    assert_eq!(status, OK, "the survivor makeCredential must succeed: {cbor:02x?}");
    let (_ad, survivor_id, _sx, _sy) = mc_parts(&cbor);

    // Batch a counter bump for the doomed slot. **Two assertions, on purpose:**
    // the first assertion after a boot flushes immediately (US-1012's restore
    // slack — a restored session must make its first signed counter durable),
    // so it is the flush itself; the SECOND is the batched bump whose pending
    // entry the wedge needs. The durable counter after it proves the bump is
    // still pending, not persisted.
    let (status, cbor) = device.get_assertion(RP, Some(&id));
    assert_eq!(status, OK, "the flushing assertion must be served: {cbor:02x?}");
    let flushed_at = {
        let keys = keys_of(&mut device);
        region_file.with(|region| {
            let mut creds = RegionCredentials::new(region, &keys);
            let mut w = fapico2_platform::keyregion::on_demand::CredentialWindow::new();
            let slot = match creds.load_by_id_at(Some(&rp_of(RP)), &id, &mut w) {
                fapico2_platform::keyregion::SlotRead::Present(s) => s,
                _ => panic!("the doomed credential must be in the region"),
            };
            creds.durable_counter(slot).expect("the record must read")
        })
    };
    let (status, cbor) = device.get_assertion(RP, Some(&id));
    assert_eq!(status, OK, "the batching assertion must be served: {cbor:02x?}");
    let still_durable = {
        let keys = keys_of(&mut device);
        region_file.with(|region| {
            let mut creds = RegionCredentials::new(region, &keys);
            let mut w = fapico2_platform::keyregion::on_demand::CredentialWindow::new();
            let slot = match creds.load_by_id_at(Some(&rp_of(RP)), &id, &mut w) {
                fapico2_platform::keyregion::SlotRead::Present(s) => s,
                _ => panic!("the doomed credential must be in the region"),
            };
            creds.durable_counter(slot).expect("the record must read")
        })
    };
    assert_eq!(
        still_durable, flushed_at,
        "the second assertion's bump must be BATCHED (durable counter unchanged) — the wedge \
         precondition is a pending entry for the doomed slot"
    );

    // Delete the credential that owns the pending entry.
    let (status, body) = cm_delete_cred(&mut device, &id);
    assert_eq!(status, OK, "deleteCredential must succeed: {body:02x?}");

    // The NEXT flush consumer: a makeCredential overwrite (US-1722) flushes
    // the window first. It must succeed — on the wedged code it answers
    // CTAP2_ERR_KEY_STORE_FULL because the flush dies on the deleted slot's
    // stale pending entry.
    let (status, cbor) = device.make_cred(RP, b"us1726-wedge-user");
    assert_eq!(
        status, OK,
        "the overwrite makeCredential must succeed after a deleteCredential; got {status:#04x} \
         — a pending counter entry for the deleted slot outlived its record and wedged the \
         overwrite's flush-first ({cbor:02x?})"
    );

    // And the re-registered credential is real: it enumerates and serves.
    let total = cm_total_for_rp(&mut device);
    assert_eq!(total, 1, "the overwrite left exactly the re-registered credential");
    let (status, _) = device.get_assertion(RP, Some(&survivor_id));
    assert_eq!(status, OK, "the re-registered credential must serve after the overwrite");
}

// ---------------------------------------------------------------------------
// The helper's failure paths, through the wire
// ---------------------------------------------------------------------------

/// **A flush failure inside the shared helper fails the delete CLEANLY.**
///
/// `delete_all_by_id` flushes the `CounterWindow` before it touches a record,
/// so a region that refuses programs fails the delete BEFORE any tombstone
/// commits: the client gets a fail-closed status, nothing is half-deleted
/// (the credential still enumerates and still serves), and — once the region
/// recovers — the same delete succeeds. Every pending entry still points at a
/// live record, so the retry's flush is a plain retry, not a wedge.
///
/// The fail-closed status is `CTAP2_ERR_KEY_STORE_FULL` (0x28), the helper's
/// own consumers' answer — honest storage-trouble, not the "no such
/// credential" (0x2E) the old arm collapsed every failure into. A total miss
/// (no live same-ID record) keeps 0x2E, unchanged.
#[test]
fn a_failed_flush_fails_the_delete_cleanly() {
    let (_guard, region_file, mut device) = boot_device("us1726-cleanfail");
    let id = dup_id();
    write_fixture(&mut device, &region_file, 1, None);

    // The region refuses every program — the flush inside the helper cannot
    // write, and the delete must not proceed.
    region_file.with(|r| r.inject_faults(Faults { programs: true, ..Faults::default() }));

    let (status, body) = cm_delete_cred(&mut device, &id);
    assert_eq!(
        status, KEY_STORE_FULL,
        "a delete whose flush failed must answer CTAP2_ERR_KEY_STORE_FULL (fail closed); got \
         {status:#04x} ({body:02x?})"
    );

    // Nothing half-deleted: the credential is still enumerated and served.
    // (The GA's own counter bump is batched — no program needed — so it
    // serves with the write path sick.)
    let total = cm_total_for_rp(&mut device);
    assert_eq!(total, 1, "the failed delete must not have removed anything");
    let (status, cbor) = device.get_assertion(RP, Some(&id));
    assert_eq!(status, OK, "the credential must still serve after the failed delete: {cbor:02x?}");

    // The region recovers; the same delete now succeeds — the flush's pending
    // entries were never left pointing at anything but live records.
    region_file.with(|r| r.inject_faults(Faults::default()));
    let (status, body) = cm_delete_cred(&mut device, &id);
    assert_eq!(status, OK, "the retried deleteCredential must succeed: {body:02x?}");
    let (status, _) = device.cm_enumerate_creds(RP);
    assert_eq!(status, NO_CREDENTIALS, "the RP must be gone after the successful delete");
}
