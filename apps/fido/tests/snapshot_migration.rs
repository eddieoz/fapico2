//! US-1558 — "a provisioned device upgrades without losing keys".
//!
//! ```gherkin
//! Scenario: a provisioned device upgrades without losing keys
//!   Given a store holding a populated fido.keystore.v1 snapshot
//!   When the new firmware first touches the applet after RUNG_USB
//!   Then every credential is written as an individual record
//!   And each snapshot slot is retired only after every record is durable
//!   And an interrupted migration leaves the snapshot intact and re-runs next time
//!   And a device whose OTP row is unavailable still enumerates
//! ```
//!
//! # The clauses, and what pins each
//!
//! | clause | test |
//! |---|---|
//! | every credential is an individual record | [`every_snapshot_credential_becomes_its_own_record`] |
//! | the snapshot is retired **only after** the last record is durable | [`the_snapshot_is_retired_only_after_the_last_record`], [`a_region_that_refuses_from_the_first_byte_retires_nothing`] |
//! | an interrupted migration re-runs, and does not duplicate | [`an_interrupted_migration_leaves_the_snapshot_intact_and_re_runs`] |
//! | a second boot does not re-migrate | [`a_second_boot_after_a_completed_migration_writes_nothing`] |
//! | the boot path does not touch the region (S8/S9) | [`the_boot_path_leaves_the_region_untouched`] |
//! | the first applet use is what migrates (S12) | [`the_first_command_after_rung_usb_is_what_migrates`] |
//! | a cold OTP row still enumerates | [`a_device_whose_otp_row_is_unavailable_still_enumerates`] |
//! | the wire counts follow the region, not the snapshot | [`a_migrated_device_reports_the_regions_capacity`] |
//!
//! # Why the unit tests call the free function and the device tests call a
//! command
//!
//! `migrate_snapshot_to_region` is a free function precisely so its three
//! outcomes can be produced on demand: a region that refuses its *first* byte,
//! and one that refuses *mid-write*, are not reachable through
//! `process_ctap2_with_store`. The last four tests go the other way — through
//! the real command entry point — because the brief's requirement is about
//! **when** the migration runs, and "when" is a property of the call site, not
//! of the function.
//!
//! # Why the snapshot is the marker
//!
//! There is no `migrated: bool` anywhere, and that is the design rather than an
//! omission. The durable credential array being empty *is* the marker, and both
//! hard properties follow from ordering: nothing writes the store until every
//! `put` has returned, so "retired" implies "durable", and a half-applied state
//! is not expressible. `migrate_snapshot_to_region`'s docs carry the argument;
//! these tests exist to refuse to let it be wrong.

mod region_boot;

use fapico2_fido::device_keystore::{
    credential_from_record_body, migrate_snapshot_to_region, CredentialIdProbe, DeviceKeystore,
    MigrationOutcome, RegionCredentials, RegionKeys, SNAPSHOT_MAX_CREDS,
};
use fapico2_platform::keyregion::fido_store::FidoRecordStore;
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::index::index_capacity;
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::{KeyRegion, SlotRead, FIDO_CAPACITY};
use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;
use heapless::Vec as HV;
use region_boot::*;


/// Credentials in the fixture snapshot.
///
/// **Four**, and the number is not decorative. The snapshot codec's bound is
/// [`SNAPSHOT_MAX_CREDS`] (12) while a `Rp2350SecureStore` holds
/// `2 × chunked::MAX_PARTS = 24` physical entries, so a snapshot of twelve
/// credentials cannot be written into the store the board actually has
/// (`key_store_ceiling.rs` measures the real ceiling). Four is the most this
/// store can hold *and* enough for "interrupted part-way" to be a real
/// interruption.
const CREDS: u32 = 4;

/// One migration attempt over a region, against the real applet entry point.
///
/// `store` is `&mut` because the retirement writes through it; everything else
/// is borrowed for the duration of the call.
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

/// Every credential ID the region's index leads to, opened and read out.
///
/// Walks `nth_entry_slot` + `load_slot` — the same two seams credMgmt's
/// enumeration uses — so a count here and a count on the wire come from **one**
/// definition of "a credential this device holds".
fn indexed_credential_ids(region: &mut dyn KeyRegion, keys: &RegionKeys) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    let mut creds = RegionCredentials::new(region, keys);
    let total = creds.used().expect("a readable index");
    let mut window = CredentialWindow::new();
    for n in 0..total {
        let Some(slot) = creds.nth_entry_slot(n) else { break };
        if !matches!(creds.load_slot(slot, &mut window), SlotRead::Present(())) {
            continue;
        }
        if let Some(cred) = credential_from_record_body(window.as_slice()) {
            let mut id = [0u8; 32];
            id.copy_from_slice(&cred.credential_id[..32]);
            out.push(id);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// A store seeded with `count` credentials in `fido.keystore.v1`.
fn seeded_store(count: u32) -> Rp2350SecureStore {
    let mut store = keyed_store();
    let ks = populated_keystore(count);
    ks.persist(&mut store).expect("seed the snapshot");
    store
}

// ---------------------------------------------------------------------------
// Then every credential is written as an individual record
// ---------------------------------------------------------------------------

#[test]
fn every_snapshot_credential_becomes_its_own_record() {
    let _lock = lock();
    let region_file = install("mig-all");
    let mut store = seeded_store(CREDS);
    let mut ks = DeviceKeystore::load(&mut store).expect("readable").expect("present");
    let keys = region_keys(&store, &ks);

    let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
    assert!(
        indexed_credential_ids(&mut region, &keys).is_empty(),
        "the region starts empty — this is the loss the story exists to prevent",
    );

    assert_eq!(
        attempt(&mut ks, &mut region, &mut store),
        MigrationOutcome::Retired { migrated: CREDS, already_present: 0, retired: CREDS },
        "a clean migration writes every credential and retires the snapshot",
    );

    // Every credential is findable through the index, as its own record.
    let ids = indexed_credential_ids(&mut region, &keys);
    assert_eq!(ids.len(), CREDS as usize, "one record per snapshot credential");
    for n in 0..CREDS {
        assert!(ids.contains(&credential_id(n)), "credential {n} did not migrate");
    }

    // **Each credential got its own slot.** That is what "one record per
    // credential" means on the medium, and it is the property the whole-snapshot
    // design could not have: `FidoAllocator::alloc` is lowest-free-slot, so two
    // credentials sharing a slot would mean one overwrote the other.
    let mut store_view = FidoRecordStore::new(&mut region);
    store_view.recover().expect("nothing staged");
    let mut seen = HV::<u16, 8>::new();
    for n in 0..CREDS {
        let mut window = CredentialWindow::new();
        let hit = store_view.load_by_credential_id(
            &keys.payload,
            &keys.index,
            None,
            &credential_id(n),
            &CredentialIdProbe { credential_id: &credential_id(n) },
            &mut window,
        );
        let slot = expect_present(hit, "the migrated credential is findable").slot();
        assert!(seen.push(slot.index()).is_ok(), "two credentials share one slot");
    }
    assert_eq!(seen.len(), CREDS as usize);
}

// ---------------------------------------------------------------------------
// And the snapshot is retired only after every record is durable
// ---------------------------------------------------------------------------

#[test]
fn the_snapshot_is_retired_only_after_the_last_record() {
    let _lock = lock();
    let region_file = install("mig-order");
    let mut store = seeded_store(CREDS);
    let mut ks = DeviceKeystore::load(&mut store).expect("readable").expect("present");

    // A budget of two `program` calls — far short of four credentials. The
    // migration must stop, and the snapshot must still be holding every
    // credential it started with, because *nothing* in
    // `migrate_snapshot_to_region` touches the store until the last record is
    // durable.
    let mut region = CappedRegion::new(
        FileKeyRegion::open(region_file.path()).expect("the region"),
        2,
    );
    let outcome = attempt(&mut ks, &mut region, &mut store);
    assert!(
        matches!(outcome, MigrationOutcome::Deferred(_)),
        "a region that stops accepting writes must defer, got {outcome:?}",
    );

    // Re-read the snapshot from the store — a power cut's view of the world. If
    // the retirement had been attempted before the last record, this array would
    // be short.
    let after = DeviceKeystore::load(&mut store).expect("readable").expect("present");
    assert_eq!(
        after.credentials.len(),
        CREDS as usize,
        "the durable snapshot must still hold every credential: the retirement \
         runs only after the last record is durable",
    );
}

#[test]
fn a_region_that_refuses_from_the_first_byte_retires_nothing() {
    let _lock = lock();
    let region_file = install("mig-nobyte");
    let mut store = seeded_store(CREDS);
    let mut ks = DeviceKeystore::load(&mut store).expect("readable").expect("present");

    let mut region =
        CappedRegion::new(FileKeyRegion::open(region_file.path()).expect("the region"), 0);
    let outcome = attempt(&mut ks, &mut region, &mut store);
    assert!(
        matches!(outcome, MigrationOutcome::Deferred(_)),
        "not one byte writable must defer, got {outcome:?}",
    );
    assert_eq!(region.programs(), 0, "the budget was already spent");

    let after = DeviceKeystore::load(&mut store).expect("readable").expect("present");
    assert_eq!(
        after.credentials.len(),
        CREDS as usize,
        "a migration that wrote nothing must leave the snapshot exactly as it was",
    );
}

// ---------------------------------------------------------------------------
// And an interrupted migration leaves the snapshot intact and re-runs
// ---------------------------------------------------------------------------

#[test]
fn an_interrupted_migration_leaves_the_snapshot_intact_and_re_runs() {
    let _lock = lock();
    let region_file = install("mig-resume");
    let mut store = seeded_store(CREDS);
    let mut ks = DeviceKeystore::load(&mut store).expect("readable").expect("present");
    let keys = region_keys(&store, &ks);

    // ---- first power cycle: the region dies part-way --------------------
    // The budget is deliberately **not** a multiple of a credential: a `put` is
    // a sector commit plus an index rewrite, and the cut lands in the middle of
    // one. "Interrupted" in the gherkin is not obliged to be tidy.
    let partial = {
        let mut region = CappedRegion::new(
            FileKeyRegion::open(region_file.path()).expect("the region"),
            6,
        );
        let outcome = attempt(&mut ks, &mut region, &mut store);
        assert!(
            matches!(outcome, MigrationOutcome::Deferred(_)),
            "the cut must land as Deferred, got {outcome:?}",
        );
        // Measured *through the index*, so this counts records a client could
        // actually find rather than bytes that reached the medium.
        indexed_credential_ids(&mut region, &keys).len()
    };
    assert!(
        partial < CREDS as usize,
        "the run must not have finished: {partial} of {CREDS} are findable",
    );

    // **A restart.** The keystore is re-read from the store, exactly as
    // `FidoApp::boot` does on the next power cycle. "Re-runs next time" has to
    // survive the object being rebuilt, not merely the object being re-asked.
    let mut ks = DeviceKeystore::load(&mut store).expect("readable").expect("present");
    assert_eq!(
        ks.credentials.len(),
        CREDS as usize,
        "the snapshot is intact — it is what the device still answers from",
    );

    // ---- second power cycle: the region works ---------------------------
    let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
    match attempt(&mut ks, &mut region, &mut store) {
        MigrationOutcome::Retired { migrated, already_present, retired } => {
            assert_eq!(retired, CREDS, "every credential is retired");
            assert_eq!(
                migrated + already_present,
                CREDS,
                "the re-run covers all four, splitting them between 'just written' \
                 and 'already durable'",
            );
            assert_eq!(
                already_present, partial as u32,
                "what the interrupted run made durable must be recognised, not \
                 rewritten — that recognition is what stops a duplicate",
            );
        }
        other => panic!("a resumed migration must complete, got {other:?}"),
    }

    // **No duplicates.** Two records naming one credential would make the
    // passkey enumerate twice and assert against either copy, which is the
    // failure the whole "look before you write" step exists to prevent.
    let ids = indexed_credential_ids(&mut region, &keys);
    assert_eq!(ids.len(), CREDS as usize, "one record per credential, not two");
    for n in 0..CREDS {
        assert_eq!(
            ids.iter().filter(|id| **id == credential_id(n)).count(),
            1,
            "credential {n} was written more than once by the re-run",
        );
    }
}

// ---------------------------------------------------------------------------
// And a second boot does not re-migrate
// ---------------------------------------------------------------------------

#[test]
fn a_second_boot_after_a_completed_migration_writes_nothing() {
    let _lock = lock();
    let region_file = install("mig-idempotent");
    let mut store = seeded_store(CREDS);
    {
        let mut ks = DeviceKeystore::load(&mut store).expect("readable").expect("present");
        let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
        assert!(
            matches!(attempt(&mut ks, &mut region, &mut store), MigrationOutcome::Retired { .. })
        );
    }

    // A second power cycle: restore the snapshot, ask again.
    let mut ks2 = DeviceKeystore::load(&mut store).expect("readable").expect("present");
    assert_eq!(
        ks2.credentials.len(),
        0,
        "the snapshot's array is empty — that empty array is the marker",
    );

    let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
    region.reset_stats();
    assert_eq!(
        attempt(&mut ks2, &mut region, &mut store),
        MigrationOutcome::AlreadyMigrated,
        "an empty credential array is the steady state",
    );
    let stats = region.stats();
    assert_eq!(
        (stats.slot_reads, stats.programs, stats.sector_erases),
        (0, 0, 0),
        "the steady-state path must not even *read* the region: it checks one \
         resident length and returns, because every command on every device \
         past this story pays that check",
    );
}

// ---------------------------------------------------------------------------
// S8/S9 — the boot path does not touch the region
// ---------------------------------------------------------------------------

#[test]
fn the_boot_path_leaves_the_region_untouched() {
    let _lock = lock();
    let region_file = install("mig-bootpath");
    let store = seeded_store(CREDS);

    // Booting is `FidoApp::boot` and nothing else — which is exactly what the
    // device does, and what S8/S9 forbid from reaching the region.
    let mut device = Device::boot(store);
    let stats = region_file.with(|r| r.stats());
    assert_eq!(
        (stats.slot_reads, stats.programs, stats.sector_erases),
        (0, 0, 0),
        "booting must not touch the region at all. The migration is S12's 'after \
         RUNG_USB, at first applet use'; a boot-path read is the thing S8/S9 \
         exist to prevent",
    );

    let after = device.with_store(|s| DeviceKeystore::load(s)).expect("readable").expect("present");
    assert_eq!(
        after.credentials.len(),
        CREDS as usize,
        "and the boot itself migrated nothing",
    );
}

// ---------------------------------------------------------------------------
// S12 — the first applet use after RUNG_USB is what migrates
// ---------------------------------------------------------------------------

#[test]
fn the_first_command_after_rung_usb_is_what_migrates() {
    let _lock = lock();
    let region_file = install("mig-firstcmd");
    let store = seeded_store(CREDS);
    let mut device = Device::boot(store);
    assert_eq!(region_file.with(|r| r.stats().programs), 0, "boot wrote nothing");

    // `getInfo` is the cheapest command there is, and it is enough — the
    // migration is not tied to a credential operation.
    let (status, _) = device.get_info();
    assert_eq!(status, 0x00, "getInfo");
    assert!(
        region_file.with(|r| r.stats().programs) > 0,
        "the first applet use must migrate",
    );

    // Every credential is a record and the snapshot no longer holds them.
    let keys = device.with_store(|s| {
        let ks = DeviceKeystore::load(s).expect("readable").expect("present");
        assert_eq!(ks.credentials.len(), 0, "the snapshot's array is retired");
        region_keys(s, &ks)
    });
    let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
    assert_eq!(
        indexed_credential_ids(&mut region, &keys).len(),
        CREDS as usize,
        "every credential is a record after one command",
    );

    // …and a second command adds nothing, because the array is now empty.
    let before = region.stats();
    let (status, _) = device.get_info();
    assert_eq!(status, 0x00, "getInfo again");
    let after = region.stats();
    assert_eq!(
        (after.programs, after.sector_erases, after.slot_reads),
        (before.programs, before.sector_erases, before.slot_reads),
        "the second command is the steady state",
    );
}

#[test]
fn a_ctap1_only_device_migrates_on_its_first_u2f_command() {
    // The same obligation on the **other** applet surface. `U2F AUTHENTICATE`
    // takes the region path whenever a region is reachable
    // (`device_core.rs::u2f_authenticate` → `region_keys_for`), so a device
    // whose only traffic is CTAP1 would otherwise read an empty region and
    // answer "wrong data" for every legacy key — the loss this story exists to
    // prevent, reached by a different door.
    //
    // The command sent is a CTAP1 REGISTER for a handle the snapshot does not
    // hold. It is refused either way; what matters is that the migration ran,
    // which is what the region statistics and the snapshot say afterwards.
    let _lock = lock();
    let region_file = install("mig-u2f");
    let store = seeded_store(CREDS);
    let mut device = Device::boot(store);

    let mut apdu: Vec<u8> = vec![0x00, 0x01, 0x03, 0x00, 65 + 8];
    apdu.extend_from_slice(&[0x11u8; 32]); // challenge
    apdu.extend_from_slice(&[0x22u8; 32]); // application
    apdu.push(8); // key handle length
    apdu.extend_from_slice(b"no-such");
    let resp = device.u2f(&apdu);
    assert!(!resp.is_empty(), "the applet answered the APDU rather than parking");

    assert!(
        region_file.with(|r| r.stats().programs) > 0,
        "the first U2F command must migrate too — CTAP1 is an applet surface, \
         not a separate device",
    );
    let keys = device.with_store(|s| {
        let ks = DeviceKeystore::load(s).expect("readable").expect("present");
        assert_eq!(ks.credentials.len(), 0, "and the snapshot's array is retired");
        region_keys(s, &ks)
    });
    let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
    assert_eq!(
        indexed_credential_ids(&mut region, &keys).len(),
        CREDS as usize,
        "every credential is a record after one CTAP1 command",
    );
}

// ---------------------------------------------------------------------------
// And a device whose OTP row is unavailable still enumerates
// ---------------------------------------------------------------------------

#[test]
fn a_device_whose_otp_row_is_unavailable_still_enumerates() {
    let _lock = lock();
    // The region **is** installed and reachable, so the only thing missing is
    // the keys. That is precisely the "OTP row unavailable" shape the EPIC
    // records: injected at the key source rather than at `read_otp_key_1`,
    // because a cold OTP array halts the board before `RUNG_USB` for four
    // pre-existing reasons (`derive_boot_store_key`, `init_drbg`,
    // `derive_oath_seal`, the migration authority) that are not this epic's to
    // relax. What this story owes is the *applet layer*: degrade, never halt.
    let region_file = install("mig-coldotp");
    let mut store = cold_otp_store();
    let ks = populated_keystore(CREDS);
    ks.persist(&mut store).expect("seed the snapshot");

    let mut device = Device::boot(store);
    device.set_pin(b"123456");

    // The migration cannot run — there is no root to derive keys from — and it
    // does not try to. getInfo still succeeds.
    let (status, _) = device.get_info();
    assert_eq!(status, 0x00, "getInfo must succeed with no keys");

    // **It still enumerates.** With no keys `region_keys_for` answers `None`, so
    // the snapshot — untouched, because nothing ever retired it — is the store.
    // This is the gherkin's last clause, and it is the difference between an
    // authenticator with no passkeys and an authenticator whose passkeys are
    // still there.
    let (status, cbor) = device.cm_enumerate_rps();
    assert_eq!(status, 0x00, "enumerateRpsBegin must succeed: {cbor:02x?}");

    // **And nothing was migrated.** The region is untouched, so a device whose
    // keys come back finds the whole snapshot waiting.
    let stats = region_file.with(|r| r.stats());
    assert_eq!(
        (stats.programs, stats.sector_erases),
        (0, 0),
        "without keys the migration must not write anything",
    );
    let after = device.with_store(|s| DeviceKeystore::load(s)).expect("readable").expect("present");
    assert_eq!(
        after.credentials.len(),
        CREDS as usize,
        "the snapshot must be intact for the day the keys come back",
    );

    // The enumeration actually **named** the RP. An empty reply would also have
    // been "a clean CTAP error" and would have proved nothing — and it is the
    // specific failure US-1573 warns about: answering "you have no passkeys"
    // for storage that was never looked at.
    assert_eq!(
        enumerate_rps_id(&cbor).as_deref(),
        Some(&b"example.test"[..]),
        "the RP the snapshot holds must come back out of enumerateRpsBegin",
    );
    assert_eq!(
        uint_at(&cbor, 5),
        Some(CREDS as u64),
        "and totalRps agrees — PicoForge's key 5 (AGENTS.md §2: the dialect is \
         binding). Four, not one: the fixture gives each credential its own RP \
         hash, so the snapshot holds four distinct relying parties and all four \
         came back out of an enumeration that had no keys to read.",
    );
}

// ---------------------------------------------------------------------------
// The wire claims follow the region, not the snapshot
// ---------------------------------------------------------------------------

#[test]
fn a_migrated_device_reports_the_regions_capacity() {
    let _lock = lock();
    let _region_file = install("mig-capacity");
    let store = seeded_store(CREDS);
    let mut device = Device::boot(store);
    device.set_pin(b"123456"); // this call is what triggers the migration here

    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata: {cbor:02x?}");
    assert_eq!(
        uint_at(&cbor, 1),
        Some(CREDS as u64),
        "existingResidentCredentialsCount is the migrated count",
    );
    assert_eq!(
        uint_at(&cbor, 2),
        Some((FIDO_CAPACITY - CREDS) as u64),
        "maxPossibleRemainingResidentCredentialsCount is the derived region \
         capacity less what the migration put there — not the snapshot's twelve",
    );
    assert_eq!(
        uint_at(&cbor, 3),
        Some(FIDO_CAPACITY as u64),
        "the PicoForge total-capacity extension (AGENTS.md §2: the dialect is binding)",
    );
}

/// The index must be able to hold what the snapshot could hold.
///
/// A capacity check rather than a migration one, but it is the assumption
/// `every_snapshot_credential_becomes_its_own_record` makes when it asserts the
/// index led to every credential: a whole snapshot has to fit in the index or
/// the last credentials migrated are unfindable.
#[test]
fn the_index_can_hold_a_whole_snapshot() {
    assert!(
        index_capacity() >= SNAPSHOT_MAX_CREDS as u32,
        "the region holds {FIDO_CAPACITY} FIDO credentials and its index \
         {cap} entries; a full snapshot would not fit in the index",
        cap = index_capacity(),
    );
}

/// `expect_present` is the only unwrapper these tests use, and it names
/// `Absent` and `Fault` separately — a helper that collapsed both into a panic
/// would let a degraded region read as a healthy one, which is the whole hazard
/// `SlotRead` was given three states to prevent (US-1573).
#[test]
fn a_tombstoned_record_is_not_reported_as_a_credential() {
    let _lock = lock();
    let region_file = install("mig-tombstone");
    let mut store = keyed_store();
    let ks = populated_keystore(1);
    ks.persist(&mut store).expect("seed the snapshot");
    let keys = region_keys(&store, &ks);

    let mut region = FileKeyRegion::open(region_file.path()).expect("the region");
    let mut creds = RegionCredentials::new(&mut region, &keys);
    creds.put(&nonce(1), &credential(0, true)).expect("one record");
    let window = {
        let mut w = CredentialWindow::new();
        assert!(matches!(creds.load_slot(fapico2_platform::keyregion::Slot::new(
            fapico2_platform::keyregion::FIDO_FIRST_SLOT as u16
        )
        .unwrap(), &mut w), SlotRead::Present(())));
        w.as_slice().to_vec()
    };
    assert!(
        credential_from_record_body(&window).is_some(),
        "a live record decodes as a credential",
    );

    // A tombstone opens cleanly and is *not* a credential. If migration read it
    // as present, a deleted credential would be skipped forever and the
    // snapshot's copy stranded; if it read it as absent, migration would put a
    // second copy of the same passkey in a new slot.
    assert!(
        credential_from_record_body(&[0xFF]).is_none(),
        "a tombstone decodes as no credential at all",
    );
}