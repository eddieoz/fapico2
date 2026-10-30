//! US-1727 — "migration collision copies instead of destroying".
//!
//! ```gherkin
//! Feature: Snapshot-to-region migration never loses a credential
//!   Scenario: An already-migrated credential is retired idempotently
//!     Given a snapshot credential whose identical copy already lives in the region
//!     When migration runs
//!     Then the snapshot copy is retired and the region record is untouched
//!   Scenario: A colliding-but-different record is migrated, not discarded
//!     Given a snapshot credential whose ID exists in the region bound to a DIFFERENT key
//!     When migration runs
//!     Then the region record is replaced by the snapshot credential
//!     And no record was retired without a copy
//! ```
//!
//! # Why this is its own file
//!
//! [`migrate_snapshot_to_region`]'s collision probe
//! ([`RegionCredentials::contains_credential`]) answers a question about an
//! **ID**, and US-1725 made it RP-qualified. But "a record with this ID is
//! durable" is two different situations wearing one answer:
//!
//! * the idempotence case — the identical copy a previous, interrupted run
//!   already made durable. Retiring the snapshot copy is correct, and is what
//!   has always happened.
//! * the drift case (`docs/audits/2026-10-30-wrong-key-assertion-drift.md`
//!   §5.3) — the credential ID is deterministic but the region's record was
//!   sealed under a **different** random key, so the snapshot credential has
//!   never been copied. Retiring it without copying destroys the only copy the
//!   user has. That is the catastrophic half, and it is what the pre-fix code
//!   did: the probe's `already_present` answer covered both cases, and the
//!   drift one died silently.
//!
//! The distinction is the credential's **private key**, and the tests here pin
//! both sides of it. Both fixtures seed the region directly
//! ([`RegionCredentials::put`], the same primitive the migration writes
//! through) so the record under test is byte-for-byte one the device would
//! have written — the discipline `snapshot_migration.rs` states for its own
//! fixtures.
//!
//! Both tests use the [`migration`-driving `attempt`] shape of
//! `snapshot_migration.rs`: the free function, over a real
//! [`FileKeyRegion`], so the medium's actual commit semantics are in the loop.

mod region_boot;

use fapico2_fido::device_keystore::{
    credential_from_record_body, migrate_snapshot_to_region, DeviceCoseKey, DeviceCredential,
    DeviceKeystore, MigrationOutcome, PrivateScalar, RegionCredentials, RegionKeys,
};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::{KeyRegion, Slot, SlotRead};
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use heapless::Vec as HV;
use region_boot::*;

/// The private scalar `region_boot::credential` builds with — the snapshot
/// credential's key in both fixtures. Restated as a constant for the same
/// reason `region_boot::INDEX_FIRST_SLOT` restates `index::INDEX_FIRST_SLOT`:
/// the assertions read the key's *bytes*, and a literal here keeps that
/// visible next to the assertion that consumes it.
const SNAPSHOT_KEY: [u8; 32] = [0x66; 32];

/// The drift record's key — deliberately different from [`SNAPSHOT_KEY`]. Same
/// ID, same RP, same user handle, different scalar: exactly the pre-epic
/// shape, where the ID was deterministic and the key was freshly random per
/// registration.
const DRIFT_KEY: [u8; 32] = [0x77; 32];

/// One migration attempt over a region, against the real entry point.
///
/// The same driver `snapshot_migration.rs::attempt` uses — copied, not
/// shared, because `region_boot` is compiled once per test binary and the
/// driver is three lines of it.
fn attempt(
    ks: &mut DeviceKeystore,
    region: &mut dyn KeyRegion,
    store: &mut Rp2350SecureStore,
) -> MigrationOutcome {
    let keys = region_keys(store, ks);
    let mut n = 0u32;
    let mut nonce = move || {
        n += 1;
        nonce(n)
    };
    migrate_snapshot_to_region(region, &keys, &mut nonce, ks, Some(store))
}

/// A store seeded with the one snapshot credential [`credential`] builds.
fn seeded_store() -> Rp2350SecureStore {
    let mut store = keyed_store();
    let ks = populated_keystore(1);
    ks.persist(&mut store).expect("seed the snapshot");
    store
}

/// The region record holding `credential_id(0)`, decoded.
///
/// Through [`RegionCredentials::load_by_id_at`] — the same single-walk
/// composition the migration's discrimination uses — so what the test reads
/// back is what the device's own resolution would serve, not a second
/// definition of "the record under this ID".
fn stored_credential(region: &mut dyn KeyRegion, keys: &RegionKeys) -> (DeviceCredential, Slot) {
    let mut creds = RegionCredentials::new(region, keys);
    let mut window = CredentialWindow::new();
    let slot = expect_present(
        creds.load_by_id_at(Some(&rp_hash(0)), &credential_id(0), &mut window),
        "the credential is in the region",
    );
    let cred = credential_from_record_body(window.as_slice())
        .expect("a live record decodes as a credential");
    (cred, slot)
}

/// How many live records the index leads to for `credential_id(0)`.
///
/// The no-duplicate half of "no record was retired without a copy": the
/// replace must leave one record naming this ID, not two (a second one is the
/// enumerate-twice failure US-1558's probe exists to prevent).
fn records_for_id(region: &mut dyn KeyRegion, keys: &RegionKeys) -> usize {
    let mut creds = RegionCredentials::new(region, keys);
    let total = creds.used().expect("a readable index");
    let mut window = CredentialWindow::new();
    let mut found = 0;
    for i in 0..total {
        let Some(slot) = creds.nth_entry_slot(i) else { break };
        if !matches!(creds.load_slot(slot, &mut window), SlotRead::Present(())) {
            continue;
        }
        if let Some(cred) = credential_from_record_body(window.as_slice()) {
            if cred.credential_id.as_slice() == credential_id(0) {
                found += 1;
            }
        }
    }
    found
}

/// The pre-epic drift shape: the ID, RP and user handle of [`credential`] with
/// a different key — a record the collision probe would find, and the one the
/// snapshot credential must not be retired for.
fn drift_credential() -> DeviceCredential {
    let mut cred = DeviceCredential {
        credential_id: HV::new(),
        public_key: DeviceCoseKey::es256([0x81; 32], [0x82; 32]),
        private_key: PrivateScalar::from_bytes(DRIFT_KEY),
        rp_id_hash: rp_hash(0),
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
        // Above the snapshot credential's **effective** counter — `credential`
        // builds with 0 durable and `DeviceKeystore::load` adds US-1011's
        // restore slack (32 on this mode) — so the carry rule's region half is
        // the arm the assertion exercises: the surviving record signs from the
        // drift record's counter only because it is the larger.
        counter: 40,
        revoked: false,
        expires_at: None,
    };
    cred.credential_id.extend_from_slice(&credential_id(0)).unwrap();
    cred.rp_id.extend_from_slice(b"example.test").unwrap();
    cred.user_handle.extend_from_slice(&[0u8; 8]).unwrap();
    cred.user_name.extend_from_slice(b"user").unwrap();
    cred
}

// ---------------------------------------------------------------------------
// Scenario: an already-migrated credential is retired idempotently
// ---------------------------------------------------------------------------

/// The re-run case, kept exactly as it has always behaved: the region holds
/// the identical copy, migration retires the snapshot copy, and the region
/// record is **untouched** — not rewritten, not re-sealed, its slot's bytes
/// identical before and after.
#[test]
fn an_already_migrated_credential_is_retired_idempotently() {
    let _lock = lock();
    let region_file = install("mig-col-idem");
    let mut store = seeded_store();
    let mut ks = DeviceKeystore::load(&mut store).expect("readable").expect("present");
    let keys = region_keys(&store, &ks);

    // The region already holds the identical copy of the snapshot's credential
    // — the durable record of an interrupted-then-completed earlier run.
    let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
    {
        let mut creds = RegionCredentials::new(&mut region, &keys);
        creds
            .put(&nonce(100), &credential(0, true))
            .expect("seed the already-migrated copy");
    }

    // The record before, at the slot level: this is what "untouched" means
    // here. A rewrite that re-sealed the same plaintext under a fresh nonce
    // would decode identically and pass a field-wise assertion, so the
    // comparison is the raw slot image — the only level at which "did the
    // migration touch it" has a definite answer.
    let (_, slot) = stored_credential(&mut region, &keys);
    let before = region.read_slot(slot).expect("read the slot before");

    assert_eq!(
        attempt(&mut ks, &mut region, &mut store),
        MigrationOutcome::Retired { migrated: 0, already_present: 1, retired: 1 },
        "the identical copy counts as already present, and nothing is re-written",
    );
    assert_eq!(ks.credentials.len(), 0, "the snapshot copy is retired");

    let after = region.read_slot(slot).expect("read the slot after");
    assert_eq!(
        before[..],
        after[..],
        "the region record must be untouched: the migration recognised its own \
         earlier work and wrote nothing",
    );
    assert_eq!(records_for_id(&mut region, &keys), 1, "one record, as before");
}

// ---------------------------------------------------------------------------
// Scenario: a colliding-but-different record is migrated, not discarded
// ---------------------------------------------------------------------------

/// The drift case — the pre-fix code's casualty. The region holds a record
/// with the snapshot credential's ID bound to a different key, so the probe's
/// `already_present` answer was a false "already migrated": the snapshot copy
/// was retired **without ever being copied**, and the user's passkey (the only
/// copy of its key was in the snapshot) was destroyed.
///
/// The fix discriminates by the key: different ⇒ the snapshot record never
/// made it ⇒ copy-with-replace. After the run, the region record carries the
/// **snapshot's** key — the snapshot is the pre-region source of truth and
/// newest-wins is the epic's rule — and the counter the surviving record signs
/// next never regresses (US-1722's carry rule, taken over the one field the
/// region record may legitimately contribute).
#[test]
fn a_colliding_but_different_record_is_migrated_not_discarded() {
    let _lock = lock();
    let region_file = install("mig-col-drift");
    let mut store = seeded_store();
    let mut ks = DeviceKeystore::load(&mut store).expect("readable").expect("present");
    let keys = region_keys(&store, &ks);

    // Seed the drift record: same ID, same RP, same user handle, DIFFERENT key.
    let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
    {
        let mut creds = RegionCredentials::new(&mut region, &keys);
        creds.put(&nonce(100), &drift_credential()).expect("seed the drift record");
    }
    let (pre, _) = stored_credential(&mut region, &keys);
    assert_eq!(
        pre.private_key,
        PrivateScalar::from_bytes(DRIFT_KEY),
        "fixture sanity: the region starts with the drift key, not the snapshot's",
    );
    // The snapshot credential's effective counter, captured before the run:
    // `DeviceKeystore::load` has added US-1011's restore slack to the durable
    // 0, and the carry rule compares against what the snapshot side would
    // actually sign from.
    let snapshot_counter = ks.credentials[0].counter;

    assert_eq!(
        attempt(&mut ks, &mut region, &mut store),
        MigrationOutcome::Retired { migrated: 1, already_present: 0, retired: 1 },
        "a colliding-but-different record was NOT already migrated: the snapshot \
         credential had to be written for the retirement to be honest",
    );
    assert_eq!(ks.credentials.len(), 0, "the snapshot is retired");

    // **The snapshot credential's content is in the region.** The snapshot is
    // empty now, so this assertion is the whole story: before the fix the
    // region still held the drift key here, and the snapshot's key existed
    // nowhere — the passkey was destroyed by the very run that claimed to
    // have preserved it.
    let (post, _) = stored_credential(&mut region, &keys);
    assert_eq!(
        post.private_key,
        PrivateScalar::from_bytes(SNAPSHOT_KEY),
        "the region record must carry the SNAPSHOT's key: the drift record was \
         the artifact, and newest-wins means the snapshot wins",
    );
    assert_eq!(post.public_key, credential(0, true).public_key, "the matching public key");

    // US-1722's carry rule, on the one field the region record contributes:
    // the surviving ID must never sign a counter lower than any record it
    // superseded signed. The drift record carried 40, above the snapshot's
    // effective counter — so the surviving record carries 40.
    assert_eq!(
        post.counter,
        snapshot_counter.max(40),
        "the surviving record's counter is max(snapshot, region): monotonic \
         whatever sequence the RP last accepted",
    );
    assert_eq!(
        post.user_handle.as_slice(),
        &[0u8; 8],
        "same credential, same user handle",
    );

    // The replace, not an append: exactly one record still names this ID.
    assert_eq!(
        records_for_id(&mut region, &keys),
        1,
        "the replace must not leave the drift record behind as a second copy — \
         a credential enumerating twice is the failure US-1558's probe exists to \
         prevent",
    );
}
