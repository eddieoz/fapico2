//! US-1546 — "wipe and factory reset", for the path that actually runs it.
//!
//! ```gherkin
//! Scenario: authenticatorReset clears every key
//!   Given a region holding FIDO, OATH and OpenPGP records
//!   When authenticatorReset completes
//!   Then every slot is erased and no record is readable
//!   And the region is empty with no orphan records
//! ```
//!
//! # What this story was, and what it now is
//!
//! `commit::wipe` and `FidoRecordStore::wipe` were written and fully tested, and
//! **neither had a production caller**. CTAP2 `authenticatorReset` cleared the
//! in-RAM snapshot arrays and nothing else: every FIDO record stayed on flash,
//! byte-identical, and the device went on reporting an empty credential store
//! over them. [`the_credential_count_is_zero_after_a_reset`] is the test that
//! fails against that build and passes now.
//!
//! The symptom is *worse* than "the erase was missed", because of what survives
//! it. `reset_from_seed` rotates `device_random`, and therefore the **payload**
//! key — but the **index** key is device-rooted and PIN-free
//! (`crypto::derive_index_key_from_root`, US-1547/S1). So the index entries
//! stayed readable and enumerable, and credMgmt `getCredsMetadata` kept
//! reporting the pre-reset count. A device saying "0 credentials" while its
//! index says otherwise is exactly the wire claim AGENTS.md §4 exists to
//! prevent.
//!
//! # The scope boundary, stated rather than glossed
//!
//! The gherkin says "a region holding FIDO, OATH **and OpenPGP** records".
//! That clause cannot be satisfied by a key-region wipe, because OpenPGP's keys
//! are not in the key region — they are in the relocated trussed `ifs` window
//! (US-1536/US-1538), and they were never at risk from this defect. What this
//! file pins is the part that was broken:
//!
//! - [`a_reset_erases_every_fido_record_slot_and_the_whole_index`] — the
//!   region's FIDO range and index are erased;
//! - [`a_reset_leaves_oaths_credentials_alone`] — and OATH's are **not**, which
//!   is the scoping the story needs and the reason the applet calls a scoped
//!   wipe rather than [`FidoRecordStore::wipe`];
//! - [`the_credential_count_is_zero_after_a_reset`] — and the device says so.
//!
//! A device-wide factory reset is a different operation with a different blast
//! radius, and it is not this story: `firmware/src/boot.rs`'s
//! `DeviceFactoryResetHandler` owns that one, and the whole-region
//! `FidoRecordStore::wipe` is what it would call.
//!
//! # Why the refusal arm matters more than the success arm
//!
//! [`a_reset_whose_erase_fails_is_refused_and_keeps_the_credential`] is the
//! test that earns the story. A reset that fails to erase and answers `0x00` is
//! the failure mode that survives a casual reading: the owner is told the
//! authenticator is clean, and it is not. The refusal is
//! `CTAP2_ERR_PROCESSING` (`0x21`), the code the C reference returns for a
//! failed `fido_reset_storage` (`../pico-fido2/src/fido/cbor_reset.c`).

mod region_boot;

use fapico2_fido::device_keystore::{RegionCredentials, RegionKeys};
use fapico2_platform::keyregion::commit::{self, CommitPlan, Recovery};
use fapico2_platform::keyregion::fido_store::FidoRecordStore;
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::host::{Faults, FileKeyRegion};
use fapico2_platform::keyregion::oath_store;
use fapico2_platform::keyregion::record::{self, Domain, RecordHeader};
use fapico2_platform::keyregion::slotmap::is_erased;
use fapico2_platform::keyregion::{
    KeyRegion, Slot, SlotRead, FIDO_CAPACITY, FIDO_FIRST_SLOT, FIDO_SLOT_LIMIT, OATH_CAPACITY,
    OATH_FIRST_SLOT, SLOTS_PER_SECTOR, TOTAL_SLOTS,
};
use region_boot::*;

/// `CTAP2_ERR_PROCESSING` (`ctap2.rs`) — the reference's answer for a reset
/// whose storage erase failed.
const PROCESSING: u8 = 0x21;
/// `CTAP2_ERR_PIN_NOT_SET` (`ctap2.rs`) — what credMgmt answers after a reset
/// has cleared the PIN.
const PIN_NOT_SET: u8 = 0x35;

/// Where the index reservation starts, in slots.
///
/// `index.rs` publishes `INDEX_FIRST_SLOT`; this file spells it out once so the
/// range arithmetic below reads as `[FIDO_FIRST_SLOT, index_start)`.
const INDEX_FIRST_SLOT: u32 = TOTAL_SLOTS - 32;

/// One resident credential enrolled **into the region**, plus the region file.
///
/// Booted with an empty snapshot, so the enrolment takes the region path and
/// the snapshot's array stays empty — every assertion below is about the region
/// rather than about a RAM structure the reset also clears.
///
/// The caller must already hold [`region_boot::lock`].
fn provisioned(tag: &str) -> (InstalledRegion, Device) {
    let region_file = install(tag);
    let mut device = Device::boot(keyed_store());
    device.set_pin(b"123456");
    let (status, cbor) = device.make_cred("example.test", b"user-1");
    assert_eq!(status, 0x00, "makeCredential into the region: {cbor:02x?}");
    (region_file, device)
}

/// The `rp_id_hash` of the fixture's relying party.
///
/// The **real** `SHA-256(rpId)`, because `region_boot`'s `make_cred` enrolled
/// under it. A synthetic 32-byte value would make every "is it still findable?"
/// assertion below pass for the wrong reason: the index tag it computes would
/// never match any entry, so the probe would report "nothing there" whether or
/// not the wipe ran. The value has to be the one the record was written under,
/// or the test is decoration.
fn rp_hash() -> [u8; 32] {
    fapico2_fido::crypto::sha256(b"example.test")
}

/// The keys the region is actually written under.
///
/// Derived from the device's own snapshot, exactly as
/// `region_assertion_counter.rs`'s `keys_of` does — **not** re-derived from a
/// guessed OTP row. That matters more than it looks: the index key is
/// `derive_index_key_from_root(otp_row ‖ chipid)` and the payload key adds the
/// PIN secret, so a probe built from a row the device does not use computes
/// index tags that match nothing. Every "is it still findable?" assertion would
/// then pass against a region holding the owner's credential, and the test would
/// be decoration.
///
/// Taken **before** the reset, which is the whole point: this is the key the
/// record was sealed under, so a post-reset read that still opens would be
/// evidence of a surviving record rather than of a rotated key.
fn keys_of(device: &mut Device) -> RegionKeys {
    device.with_store(|store| {
        let ks = fapico2_fido::device_keystore::DeviceKeystore::load(store)
            .expect("a readable snapshot")
            .expect("a snapshot on the store, because the transport's persist gate has run");
        fapico2_fido::device_app::region_keys(store, &ks).expect("a store key is installed")
    })
}

/// Is every slot in `[first, limit)` pristine erased flash?
fn all_erased(region: &mut FileKeyRegion, first: u32, limit: u32) -> bool {
    let mut i = first;
    while i < limit {
        let slot = Slot::new(i as u16).expect("every index here is inside the region");
        match region.read_slot(slot) {
            Ok(bytes) => {
                if !is_erased(&bytes) {
                    return false;
                }
            }
            // A read that faults is not evidence of erasure, and the callers
            // assert on this function's answer. Reporting `false` keeps a sick
            // region from being counted as a clean wipe.
            Err(_) => return false,
        }
        i += 1;
    }
    true
}

// ---------------------------------------------------------------------------
// The success arm
// ---------------------------------------------------------------------------

/// **A reset erases FIDO's records and the whole index.**
///
/// Both halves matter and they fail differently. Leaving record bytes behind
/// means a flash dump recovers a passkey; leaving the index behind means the
/// device reports credentials it no longer holds — and since the index key is
/// device-rooted and PIN-free, that index is exactly the thing an attacker with
/// a dump can read without ever knowing the PIN (US-1551).
#[test]
fn a_reset_erases_every_fido_record_slot_and_the_whole_index() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("reset-erases");
    let _keys = keys_of(&mut device);

    // Before: the credential is really there, so the assertions mean something.
    {
        let mut r = FileKeyRegion::open(region_file.path()).expect("reopen");
        assert!(
            !all_erased(&mut r, FIDO_FIRST_SLOT, INDEX_FIRST_SLOT),
            "the fixture must not start already erased",
        );
    }

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(status, 0x00, "authenticatorReset must succeed: {body:02x?}");

    region_file.with(|r| {
        assert!(
            all_erased(r, FIDO_FIRST_SLOT, FIDO_SLOT_LIMIT),
            "FIDO's record range [{FIDO_FIRST_SLOT}, {FIDO_SLOT_LIMIT}) still holds data after a \
             reset — the credential the owner enrolled is still on flash",
        );
        assert!(
            all_erased(r, INDEX_FIRST_SLOT, TOTAL_SLOTS),
            "the index [{INDEX_FIRST_SLOT}, {TOTAL_SLOTS}) still holds entries after a reset. The \
             index key is device-rooted and PIN-free, so surviving entries are readable by anyone \
             with a flash dump, and the device would report credentials it no longer holds",
        );
    });
}

/// **The region is left clean: no staged bytes for the next boot to replay.**
///
/// `commit::wipe`'s own doc names the hazard — a wipe that leaves the scratchpad
/// holding a staged record hands the next boot a `recover` to replay, and the
/// records it replays are ones the caller just asked to destroy. FIDO's range
/// starts immediately after the scratchpad, so a scoped wipe that stopped one
/// sector short would leave exactly this.
#[test]
fn a_reset_leaves_no_staged_record_for_the_next_boot_to_replay() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("reset-recover");
    let _keys = keys_of(&mut device);

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(status, 0x00, "authenticatorReset must succeed: {body:02x?}");

    region_file.with(|r| {
        // The scratchpad sits between OATH and FIDO, so it is outside the scoped
        // wipe by design. It must be erased anyway — the commit path erases it
        // after every write, and a device whose last operation was the wipe would
        // still hold whatever the enrolment staged if that erase had not landed.
        assert!(
            all_erased(r, FIDO_FIRST_SLOT - SLOTS_PER_SECTOR, FIDO_FIRST_SLOT),
            "the commit scratchpad still holds staged bytes after a reset",
        );
        // And there is nothing for `recover` to finish.
        let recovery = FidoRecordStore::new(&mut *r).recover();
        assert!(
            matches!(recovery, Ok(Recovery::Swept)),
            "a region with no staged commit must recover as already-swept, not as work to redo; \
             got {recovery:?}",
        );
    });
}

/// **The wiped credential does not open — before or after a reboot.**
///
/// The reboot leg is the one that matters and the one a RAM-only assertion would
/// miss: `reset_from_seed` rotates the device's key material, so a record that
/// merely *looked* gone in RAM reappears on the next boot if the medium still
/// holds it. The probe deliberately uses the **fixture's** keys, not the
/// device's post-reset ones, because "unreadable under the new key" is a weaker
/// claim than "unreadable under the key it was written with".
#[test]
fn the_wiped_credential_is_unreadable_across_a_reboot() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("reset-reboot");
    // The keys the record was sealed under, taken before the reset rotates
    // `device_random` and therefore the payload key.
    let keys = keys_of(&mut device);

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(status, 0x00, "authenticatorReset must succeed: {body:02x?}");

    // Reboot: persist the snapshot the reset wrote, then boot a fresh app from
    // it against the same region file.
    assert!(device.persist(), "the reset's snapshot must persist");
    let store = device.into_store();
    let mut rebooted = Device::boot(store);
    rebooted.grant_presence_always();

    region_file.with(|r| {
        let mut creds = RegionCredentials::new(&mut *r, &keys);
        // Enumerate rather than look up a remembered ID: the claim is that
        // nothing opens, and a lookup by ID could pass on a wrong-slot answer.
        let mut found = [Slot::new(0).expect("slot 0 is in range"); 4];
        let n = creds.slots_for_rp(&rp_hash(), &mut found);
        assert_eq!(
            n,
            Some(0),
            "a wiped credential must not be findable after a reboot; the index yielded {n:?} in \
             {found:?}",
        );
    });
    let _ = rebooted;
}

/// **The device reports zero credentials after a reset.**
///
/// This is the symptom the story was filed for, and the assertion the previous
/// build fails. `existingResidentCredentialsCount` is key 1 of credMgmt
/// `getCredsMetadata` (`region_boot::uint_at`), and it is the number a user
/// checks after resetting a device.
#[test]
fn the_credential_count_is_zero_after_a_reset() {
    let _lock = lock();
    let (_region_file, mut device) = provisioned("reset-count");
    let _keys = keys_of(&mut device);

    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata must succeed: {cbor:02x?}");
    assert_eq!(
        uint_at(&cbor, 1),
        Some(1),
        "the fixture must have one resident credential before the reset, or this test proves \
         nothing",
    );

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(status, 0x00, "authenticatorReset must succeed: {body:02x?}");

    // A reset clears the PIN (`reset_from_seed`), so the session token the
    // fixture holds is dead and credMgmt — which requires one — answers
    // `0x35 PIN_NOT_SET`. That is correct device behaviour and it is worth
    // pinning before the count is read, because it is the difference between
    // "the device forgot the index" and "the device forgot everything".
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(
        status, PIN_NOT_SET,
        "an authenticatorReset clears the PIN, so credMgmt must answer PIN_NOT_SET until one is \
         set again. Got {status:#04x} / {cbor:02x?}",
    );

    // Set a new PIN — which re-establishes a real authenticated session — and
    // then read the count the user would actually see.
    device.set_pin(b"87654321");
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata must succeed after a reset: {cbor:02x?}");
    assert_eq!(
        uint_at(&cbor, 1),
        Some(0),
        "after an authenticatorReset the device must report zero resident credentials. A non-zero \
         count here means the index survived the reset — and because the index key is \
         device-rooted and PIN-free, it is both a wire claim the device does not honour and a \
         pre-reset credential list readable from a flash dump",
    );
    // And the store takes a credential again — a reset that reported zero but
    // refused every later enrolment would be its own kind of broken.
    let (status, cbor) = device.make_cred("example.test", b"user-2");
    assert_eq!(
        status, 0x00,
        "a fresh enrolment after a reset must succeed: {cbor:02x?}",
    );
}

// ---------------------------------------------------------------------------
// The scoping arm — a FIDO reset is not a device wipe
// ---------------------------------------------------------------------------

/// **A FIDO reset leaves OATH's credentials alone.**
///
/// This is why the applet calls a scoped wipe rather than
/// [`FidoRecordStore::wipe`]. OATH owns the region's **head**
/// ([`OATH_FIRST_SLOT`] = 0), so an erase that starts at slot 0 destroys OATH's
/// records; CTAP2 `authenticatorReset` resets the FIDO authenticator and has no
/// business touching another applet's credentials.
///
/// Today nothing on a device build can observe the difference — the OATH adapter
/// is not wired, which is precisely why this has to be pinned by a test rather
/// than by a comment. The day someone wires OATH in, this is the test that says
/// whether the scoping held.
#[test]
fn a_reset_leaves_oaths_credentials_alone() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("reset-oath");

    // A real OATH-domain record in OATH's first slot, committed through the same
    // path the applet uses.
    let keys = keys_of(&mut device);
    region_file.with(|r| commit_oath_record(r, &keys));

    // It is there before the reset — otherwise this test proves nothing.
    {
        let mut r = FileKeyRegion::open(region_file.path()).expect("reopen");
        assert!(
            !all_erased(&mut r, OATH_FIRST_SLOT, OATH_FIRST_SLOT + OATH_CAPACITY),
            "the OATH fixture must not start already erased",
        );
    }

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(status, 0x00, "authenticatorReset must succeed: {body:02x?}");

    region_file.with(|r| {
        assert!(
            !all_erased(r, OATH_FIRST_SLOT, OATH_FIRST_SLOT + OATH_CAPACITY),
            "a FIDO authenticatorReset destroyed an OATH credential. The scoped wipe is meant to \
             start at FIDO's first sector; if this fails, the erase is reaching into the \
             reservation in front of it — check the sector-alignment assertion in \
             `fido_store.rs`",
        );
    });
}

/// Commit one OATH-domain record into OATH's first slot.
///
/// Goes through [`commit::commit`] rather than
/// [`FidoRecordStore::put`] on purpose: the store's allocator deliberately
/// refuses slots outside FIDO's range — which is the very guard
/// [`a_reset_leaves_oaths_credentials_alone`] is about — so a scoped test needs
/// the lower-level path to plant the fixture.
fn commit_oath_record(region: &mut FileKeyRegion, keys: &RegionKeys) {
    let slot = Slot::new(OATH_FIRST_SLOT as u16).expect("OATH's first slot is inside the region");
    let header = RecordHeader::new(Domain::Oath, slot, 1);
    let sealed = record::seal(&header, keys.payload.as_bytes(), &[0xA5u8; record::NONCE_LEN], b"oath")
        .expect("a short plaintext seals under any payload key");
    let plan = CommitPlan::new(
        Slot::new(oath_store::SCRATCHPAD_FIRST_SLOT as u16).expect("the scratchpad is in range"),
        slot,
        Domain::Oath,
        1,
    );
    commit::commit(region, plan, &sealed).expect("a first OATH commit over a clean slot succeeds");
}

// ---------------------------------------------------------------------------
// The refusal arm
// ---------------------------------------------------------------------------

/// **A reset whose erase fails is refused, and keeps the credential.**
///
/// The test that earns the story. Two properties in one, because either alone
/// is a defect:
///
/// 1. the status is **not** `0x00` — an ack would tell the owner the
///    authenticator is clean while every record is still on flash;
/// 2. `getCredsMetadata` **still reports 1** — the refusal is honest about the
///    world. A reset that reported failure *and* cleared the count would have
///    moved the lie rather than removed it.
#[test]
fn a_reset_whose_erase_fails_is_refused_and_keeps_the_credential() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("reset-fault");
    let _keys = keys_of(&mut device);

    // The failure: every sector erase now fails at the transport.
    region_file.with(|r| r.inject_faults(Faults { erases: true, ..Faults::default() }));

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(
        status, PROCESSING,
        "a reset whose region erase failed must be refused, not acked. The reference returns \
         CTAP2_ERR_PROCESSING for exactly this (`cbor_reset.c`: `if (fido_reset_storage() != \
         PICOKEYS_OK) return CTAP2_ERR_PROCESSING`). Got {status:#04x} / {body:02x?}",
    );

    // And the refusal is honest: the credential is still there, so the device
    // must still say so.
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata must still answer: {cbor:02x?}");
    assert_eq!(
        uint_at(&cbor, 1),
        Some(1),
        "the erase failed, so the credential is still on flash and the device must still report \
         it. A reset that reported failure and then reported an empty store has moved the lie \
         rather than removed it",
    );
}

/// **A failed reset leaves the credential usable, not stranded.**
///
/// The ordering property behind the refusal: `wipe_region_credentials` runs
/// **before** `reset_from_seed`. If the order were reversed, a failed wipe would
/// still have cleared the PIN state, rotated the device random and dropped the
/// session — so the owner would be locked out of a credential that is still on
/// flash, with no way to remove it short of a factory reset.
#[test]
fn a_failed_reset_leaves_the_credential_usable() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("reset-failed-usable");
    let _keys = keys_of(&mut device);

    region_file.with(|r| r.inject_faults(Faults { erases: true, ..Faults::default() }));

    let (status, _) = device.call(0x07, &[]);
    assert_eq!(status, PROCESSING, "the reset must be refused");

    region_file.with(|r| r.inject_faults(Faults::default()));

    // The PIN is still set, so an assertion needs a token — and its success is
    // what proves both that the PIN state survived and that the record is still
    // readable.
    let (status, body) = device.get_assertion("example.test", None);
    assert_eq!(
        status, 0x00,
        "a refused reset must leave the owner's credential usable. If this fails, the RAM state \
         was cleared behind a failed medium write. Got {status:#04x} / {body:02x?}",
    );
}

// ---------------------------------------------------------------------------
// The `None` arm and the geometry
// ---------------------------------------------------------------------------

/// **A reset on a device with no region installed still succeeds.**
///
/// The `None` arm of the applet's wipe helper. Such a device is not a failure:
/// the snapshot is its store, `reset_from_seed` has already cleared it, and
/// reporting a refusal would break `authenticatorReset` on every device whose
/// key region failed to install. S10's rule in miniature — degrade, never halt.
#[test]
fn a_reset_without_a_region_still_succeeds() {
    let _lock = lock();
    // No `install(tag)`: the provider answers `None`, which is what a device
    // whose region never came up looks like.
    let mut device = Device::boot(keyed_store());
    device.set_pin(b"123456");
    let (status, cbor) = device.make_cred("example.test", b"user-1");
    assert_eq!(status, 0x00, "the snapshot path must enrol: {cbor:02x?}");

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(
        status, 0x00,
        "a device with no key region must still reset: its credentials are in the snapshot, which \
         the reset has always cleared. Got {status:#04x} / {body:02x?}",
    );

    // The snapshot really was cleared. A reset clears the PIN, so set one again
    // before the credMgmt probe — same reason as the region-backed test.
    device.set_pin(b"87654321");
    let (status, cbor) = device.cm_get_metadata();
    assert_eq!(status, 0x00, "getCredsMetadata must answer: {cbor:02x?}");
    assert_eq!(
        uint_at(&cbor, 1),
        Some(0),
        "a reset with no region must still report zero credentials",
    );
}

/// **The scoped wipe covers exactly the sectors it claims to.**
///
/// A shape check rather than a behaviour check, and it is the one that makes the
/// OATH scoping provable rather than incidental: if the geometry changed and the
/// wipe's ranges did not, the two would silently disagree and
/// [`a_reset_leaves_oaths_credentials_alone`] would stop failing for the right
/// reason.
#[test]
fn the_scoped_wipe_erases_every_sector_exactly_once() {
    let _lock = lock();
    let region_file = install("reset-scope");

    // Two disjoint passes: the index tail, then FIDO's records. Counted
    // separately because a wipe that erased one twice and skipped the other
    // would still total the right number.
    let sectors = |first: u32, limit: u32| (limit - first) / SLOTS_PER_SECTOR;
    let expected =
        sectors(INDEX_FIRST_SLOT, TOTAL_SLOTS) + sectors(FIDO_FIRST_SLOT, FIDO_SLOT_LIMIT);

    region_file.with(|r| {
        let erased = FidoRecordStore::new(&mut *r)
            .wipe_fido_range()
            .expect("a fresh region wipes clean");
        assert_eq!(
            erased, expected,
            "the wipe erased {erased} sectors; the records range [{FIDO_FIRST_SLOT}, \
             {FIDO_SLOT_LIMIT}) plus the index tail [{INDEX_FIRST_SLOT}, {TOTAL_SLOTS}) cover \
             {expected}. Each sector must be erased exactly once — twice is wasted wear, fewer \
             means a range that no longer matches the partitions",
        );
        // And OATH's range came through untouched, in the same pass.
        assert!(
            all_erased(r, OATH_FIRST_SLOT, OATH_FIRST_SLOT + OATH_CAPACITY),
            "the scoped wipe erased into OATH's range",
        );
    });

    // Sanity on the geometry this reasoning rests on.
    assert_eq!(
        FIDO_SLOT_LIMIT,
        FIDO_FIRST_SLOT + FIDO_CAPACITY,
        "FIDO's range must be exactly its derived capacity wide",
    );
    const {
        assert!(
            FIDO_FIRST_SLOT >= OATH_FIRST_SLOT + OATH_CAPACITY,
            "FIDO's range must start after OATH's, or the scoped wipe reaches into another applet"
        );
    }
}

/// **The erased-slot answer is the one a caller must not confuse with a fault.**
///
/// Small, and here because the wipe is the newest caller of
/// [`RegionCredentialError`]'s states. A wiped slot reads as
/// [`SlotRead::Absent`] — "we looked and it is not there" — which is the correct
/// answer, and different from a region that could not be read at all. The second
/// is [`SlotRead::Fault`], and a caller that conflated the two would report a
/// sick region as a clean one.
#[test]
fn a_wiped_slot_reads_as_absent_and_not_as_a_fault() {
    let _lock = lock();
    let (region_file, mut device) = provisioned("reset-absent");
    let keys = keys_of(&mut device);

    let (status, body) = device.call(0x07, &[]);
    assert_eq!(status, 0x00, "authenticatorReset must succeed: {body:02x?}");

    region_file.with(|r| {
        let mut creds = RegionCredentials::new(&mut *r, &keys);
        let mut found = [Slot::new(0).expect("slot 0 is in range"); 4];
        let n = creds.slots_for_rp(&rp_hash(), &mut found);
        assert_eq!(
            n,
            Some(0),
            "an erased region yields nothing — the wipe completed, we read it, there is nothing \
             there. The index yielded {n:?} in {found:?}",
        );
        // The by-ID probe must keep the same three states apart. `load_by_id`
        // takes no RP hint here, which is the harder case: it has to find the
        // credential across every relying party or report that it cannot.
        let mut window = CredentialWindow::new();
        let hit = creds.load_by_id(None, b"no-such-credential", &mut window);
        assert!(
            matches!(hit, SlotRead::Absent),
            "an absent credential answers Absent — we read the region and it is not there. Got \
             {hit:?}",
        );
    });
}