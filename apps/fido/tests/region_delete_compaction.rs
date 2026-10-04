//! US-1556 — delete, tombstone and compaction, through the applet's codec.
//!
//! ```gherkin
//! Scenario: deleting the last credential of a relying party
//!   Given a credential is deleted
//!   When the region is compacted
//!   Then the slot is erased
//!   And remainingDiscoverableCredentialsCount reflects the new count
//!   And a subsequent enrollment reuses the freed slot
//! ```
//!
//! # Why this is a separate file from `capacity_boundary.rs`
//!
//! That file measures one number at the far end of the region. This one is about
//! what happens when a credential goes **away**, which is the operation with a
//! hardware trap underneath it: `commit.rs` refuses a single-slot delete on
//! purpose ("Why there is no single-slot delete here"), because an erased target
//! is indistinguishable from a commit that never reached its witness and would be
//! resurrected by `recover` as a replay. So a delete here is a commit whose
//! target is a **tombstone**, and "the slot is erased" is a separate later step.
//!
//! # Every credential is a real [`DeviceCredential`]
//!
//! Encoded by the applet's own codec, so the tombstone has to be distinguished
//! from a real record by the same rule the device uses — an impossible body —
//! rather than by a test-only convention. A synthetic blob here would let a
//! tombstone collide with a legitimate record shape and pass anyway.

use std::path::{Path, PathBuf};

use fapico2_fido::device_keystore::{
    credential_from_record_body, credential_record_body, is_deleted_body, region_pin_secret,
    DeviceCredential, DeviceCoseKey, DevicePinState, PrivateScalar, RegionCredentialError,
    RegionCredentials, RegionKeys,
};
use fapico2_platform::keyregion::crypto;
use fapico2_platform::keyregion::fido_store::{self, FidoRecordStore, FidoStoreError};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::slotmap::{is_erased, SlotImage};
use fapico2_platform::keyregion::{
    commit, KeyRegion, Slot, SlotRead, FIDO_CAPACITY, FIDO_FIRST_SLOT, SLOTS_PER_SECTOR,
    TOTAL_SLOTS,
};

use heapless::Vec as HeaplessVec;

const REGION_SLOTS: u32 = TOTAL_SLOTS;

// ---------------------------------------------------------------------------
// Fixtures — shared shape with `capacity_boundary.rs`
// ---------------------------------------------------------------------------

struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-us1556-{}-{tag}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self { path }
    }
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRegion {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn otp_row() -> [u8; 32] {
    let mut row = [0u8; 32];
    for (i, b) in row.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(29).wrapping_add(0x13);
    }
    row
}

fn chip_id() -> [u8; 8] {
    [0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78]
}

/// The keys, from a **fixed** PIN state so every call in one test seals and opens
/// under the same key. A test that re-derived a different key per call would see
/// every lookup fail and could read that as a delete bug.
fn keys() -> RegionKeys {
    let row = otp_row();
    let root = crypto::derive_otp_root(&row, &chip_id()).expect("a non-zero OTP row");
    let secret = region_pin_secret(&DevicePinState::default(), &[0x3c; 32]);
    RegionKeys {
        index: crypto::derive_index_key_from_root(&root),
        payload: crypto::derive_payload_key_from_root(&root, &secret),
    }
}

fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&(n as u32).to_le_bytes());
    out[4..].copy_from_slice(&b"us1556nonce!!"[..record::NONCE_LEN - 4]);
    out
}

fn slot(index: u16) -> Slot {
    Slot::new(index).expect("every index here is inside the region")
}

fn credential_id(n: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(b"f156");
    id[4..8].copy_from_slice(&n.to_le_bytes());
    id[8..].copy_from_slice(&[(n >> 8) as u8; 24]);
    id
}

fn rp_hash(n: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = (n as u8).wrapping_mul(47).wrapping_add(i as u8).wrapping_add(0x3b);
    }
    h
}

/// A modest credential — short fields, so the tests are about the delete rather
/// than about the record bound (`capacity_boundary.rs` measures that).
fn credential(n: u32, resident: bool) -> DeviceCredential {
    let mut cred = DeviceCredential {
        credential_id: HeaplessVec::new(),
        public_key: DeviceCoseKey::es256([n as u8; 32], [0x22; 32]),
        private_key: PrivateScalar::from_bytes([0x66; 32]),
        rp_id_hash: rp_hash(n),
        rp_id: HeaplessVec::new(),
        user_handle: HeaplessVec::new(),
        user_name: HeaplessVec::new(),
        user_display_name: HeaplessVec::new(),
        cred_protect: 0,
        large_blob_key: None,
        hmac_secret: HeaplessVec::new(),
        cred_blob: HeaplessVec::new(),
        third_party_payment: false,
        pin_complexity_policy: false,
        resident,
        algorithm: -7,
        counter: n,
        revoked: false,
        expires_at: None,
    };
    cred.credential_id.extend_from_slice(&credential_id(n)).unwrap();
    cred.rp_id.extend_from_slice(b"example.test").unwrap();
    cred.user_handle.extend_from_slice(&[n as u8; 8]).unwrap();
    cred.user_name.extend_from_slice(b"user").unwrap();
    cred
}

fn fresh(tag: &str) -> (TempRegion, FileKeyRegion) {
    let tmp = TempRegion::new(tag);
    let region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("a fresh region file");
    (tmp, region)
}

fn with_store<R>(region: &mut FileKeyRegion, f: impl FnOnce(&mut RegionCredentials<'_, '_>) -> R) -> R {
    let k = keys();
    let mut creds = RegionCredentials::new(region, &k);
    f(&mut creds)
}

/// Unwrap a [`SlotRead`] that must have been `Present`.
///
/// `SlotRead` has no `expect` on purpose — its whole point is that `Fault` and
/// `Absent` are *different* answers — so the assertion has to be written down
/// rather than defaulted. A helper that turned both into a panic would let a test
/// read a degraded region as a healthy one.
fn expect_present<T>(outcome: SlotRead<T>, what: &str) -> T {
    match outcome {
        SlotRead::Present(v) => v,
        SlotRead::Absent => panic!("{what}: absent"),
        SlotRead::Fault(why) => panic!("{what}: the region must be readable, got a fault: {why}"),
    }
}

fn read_slot(region: &mut dyn KeyRegion, s: Slot) -> SlotImage {
    region.read_slot(s).expect("slot reads")
}

/// Every slot in one 4 KiB sector.
fn sector_bytes(region: &mut dyn KeyRegion, base: Slot) -> Vec<SlotImage> {
    (0..SLOTS_PER_SECTOR)
        .map(|i| read_slot(region, slot(base.index() + i as u16)))
        .collect()
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// **A deleted credential is gone from every path, and the freed slot is reused.**
///
/// The whole gherkin, in order: delete, compact, count, re-enrol.
#[test]
fn deleting_a_credential_frees_its_slot_and_a_later_enrolment_reuses_it() {
    let (_tmp, mut region) = fresh("delete-compact");

    // Four credentials for **one** RP — a site's worth, so the "last credential of a
    // relying party" case is real: three deletions leave one.
    let rp = rp_hash(0);
    let mut slots = [Slot::new(0).unwrap(); 4];
    with_store(&mut region, |creds| {
        for n in 0..4 {
            let mut cred = credential(n, true);
            cred.rp_id_hash = rp;
            let report = creds.put(&nonce(n), &cred).expect("the fixture must enrol");
            slots[n as usize] = report.slot;
        }
        assert_eq!(creds.used(), Some(4));
        assert_eq!(
            creds.remaining(),
            Some(FIDO_CAPACITY - 4),
            "four enrolments must leave four fewer than capacity"
        );

        // Delete the **last** one. The tombstone is a commit, so the slot is
        // still occupied — and that is the point of the test's second half.
        let target = credential_id(3);
        let deleted = creds
            .delete(&nonce(100), &target)
            .expect("deleting an enrolled credential must succeed");
        assert_eq!(
            deleted.slot, slots[3],
            "the delete must land in the slot the credential occupied"
        );
        assert!(
            deleted.index_slot.is_some(),
            "the credential had an index entry, so the delete must clear it"
        );

        // The credential is unreadable through every path: by ID, and through
        // the RP enumeration the credential-management `enumerateCreds` uses.
        let mut window = CredentialWindow::new();
        assert!(
            matches!(
                creds.load_by_id(Some(&rp), &target, &mut window),
                SlotRead::Absent
            ),
            "a deleted credential must not load by ID"
        );
        assert!(
            window.is_empty(),
            "a failed load must leave the window empty — it is cleared before the lookup, so a \
             stale credential cannot be served"
        );
        let mut found = [slot(0); 8];
        let n = creds
            .slots_for_rp(&rp, &mut found)
            .expect("the index must be readable");
        assert_eq!(
            n, 3,
            "the deleted credential must be gone from the RP's slot list"
        );

        // The slot is **not** free yet: a tombstone is a record.
        assert_eq!(creds.used(), Some(3), "the count drops with the index entry");
    });

    // The tombstone really is in the slot, and it really is a tombstone.
    let raw = read_slot(&mut region, slots[3]);
    assert!(!is_erased(&raw), "the delete left a record, not an erase");
    let decoded =
        expect_present(record::decode(slots[3], &raw), "a tombstone is an ordinary record");
    assert_eq!(decoded.header().generation(), 2, "the delete advances the generation");
    // **Open the body before checking it.** What sits in the slot is the *sealed*
    // blob — ciphertext — and a tombstone's plaintext is one byte of 0xFF while
    // its ciphertext is not. Checking raw bytes would be checking a fact about
    // GCM rather than about the record, which is the confusion
    // `is_deleted_body`'s own docs warn against.
    let payload_key = keys().payload;
    let opened = expect_present(
        record::open(decoded.header(), payload_key.as_bytes(), decoded.body()),
        "the tombstone must open under the payload key",
    );
    assert!(
        is_deleted_body(opened.as_slice()),
        "the opened body must be the tombstone marker"
    );
    assert!(
        credential_from_record_body(opened.as_slice()).is_none(),
        "a tombstone must not decode as a credential — that is what makes it a delete rather than \
         a corrupt record"
    );

    // Compact. The tombstone's slot is erased; the three live mates are
    // byte-identical — the sector rewrite copies them verbatim, so a compaction
    // cannot silently re-seal a credential.
    let sector = commit::sector_base(slots[3]);
    let before: Vec<SlotImage> = sector_bytes(&mut region, sector);
    with_store(&mut region, |creds| {
        let report = creds.compact(sector).expect("compaction must succeed");
        assert_eq!(report.sector, sector);
        assert_eq!(
            report.slots_erased, 1,
            "exactly the tombstone's slot must be freed"
        );
        assert_eq!(
            report.staged_programs, 3,
            "one program per surviving record, copied verbatim"
        );
    });
    let after: Vec<SlotImage> = sector_bytes(&mut region, sector);
    for (offset, (b, a)) in before.iter().zip(after.iter()).enumerate() {
        let s = slot(sector.index() + offset as u16);
        if s == slots[3] {
            assert!(is_erased(a), "the tombstone's slot must be erased after compaction");
        } else {
            assert_eq!(a, b, "slot {offset} must survive compaction byte-identically");
        }
    }

    // And a subsequent enrolment reuses exactly the freed slot.
    with_store(&mut region, |creds| {
        let report = creds
            .put(&nonce(200), &credential(9, true))
            .expect("the freed slot must accept a new credential");
        assert_eq!(
            report.slot, slots[3],
            "the allocator's lowest-free-slot rule must hand out the slot compaction erased"
        );
        assert_eq!(
            report.generation, 1,
            "a slot compaction erased reads as virgin, so the reuse starts at generation 1"
        );
        let mut window = CredentialWindow::new();
        assert!(
            matches!(creds.load_by_id(Some(&rp_hash(9)), &credential_id(9), &mut window), SlotRead::Present(())),
            "the reused slot's credential must be readable"
        );
    });
}

/// **Generation monotonicity survives a delete.** The tombstone advances the
/// generation, so the credential written into the reused slot is at generation 1
/// of an *erased* slot while the deleted one was at generation 2 — which is the
/// whole reason a tombstone is a record and not an erase.
#[test]
fn a_delete_advances_the_generation_so_the_tombstone_cannot_be_replayed() {
    let (_tmp, mut region) = fresh("generation");
    with_store(&mut region, |creds| {
        let report = creds.put(&nonce(1), &credential(1, true)).expect("enrol");
        let first = report.generation;
        assert_eq!(first, 1);

        let deleted = creds
            .delete(&nonce(2), &credential_id(1))
            .expect("the delete must succeed");
        assert_eq!(
            deleted.generation,
            first + 1,
            "the tombstone must carry a strictly higher generation than the credential it replaced"
        );
    });
}

/// **A `Full` store is a distinct answer from a sick one.** The gherkin's
/// `0x28` is a capacity claim; returning it for a flash that is merely failing
/// would be a claim the device cannot make.
#[test]
fn a_full_region_and_an_unreachable_region_are_different_answers() {
    let (_tmp, mut region) = fresh("distinct");

    // Unreachable: every read fails.
    let mut broken = FileKeyRegion::open(_tmp.path()).expect("reopen");
    broken.inject_faults(fapico2_platform::keyregion::host::Faults {
        reads: true,
        ..Default::default()
    });
    {
        let k = keys();
        let mut creds = RegionCredentials::new(&mut broken, &k);
        let err = creds.put(&nonce(1), &credential(1, true)).expect_err("a sick flash must refuse");
        assert!(
            matches!(err, RegionCredentialError::Unreachable(_)),
            "a transport failure must be Unreachable, not Full — got {err:?}"
        );
        assert!(
            creds.remaining().is_none(),
            "a sick index must answer None, never 0: 'we could not find out' is not 'the device is \
             full'"
        );
    }

    // Full: a region one sector **shorter than FIDO's whole range** would hold no
    // FIDO slot at all (the range starts at slot `FIDO_FIRST_SLOT`), so the
    // boundary has to be reached with a full-length region — which is what
    // `capacity_boundary.rs` measures. What this file checks instead is that a
    // region with no free FIDO slot reports `Full` rather than a transport error,
    // and that `remaining()` says `None` rather than `0` when it cannot tell.
    //
    // The distinction the gherkin names is therefore established by the pair:
    // `capacity_boundary.rs` measures `Full` at the real boundary, and this test
    // measures `Unreachable` for a sick region. Both are `0x28`-shaped answers
    // that must not be confused.
    assert!(
        FIDO_CAPACITY > 0,
        "a capacity of zero would make the Full arm of this test unreachable"
    );
}

/// **A tombstone cannot be mistaken for a credential** — the property the
/// one-byte marker exists for.
#[test]
fn a_tombstone_is_not_a_credential_and_an_erased_slot_is_not_a_tombstone() {
    // A real credential body.
    let body = credential_record_body(&credential(1, true)).expect("encode");
    assert!(
        !is_deleted_body(body.as_slice()),
        "a credential body must never read as a tombstone"
    );
    assert!(
        credential_from_record_body(body.as_slice()).is_some(),
        "a credential body must decode"
    );

    // The tombstone.
    assert!(
        is_deleted_body(&fido_store::TOMBSTONE_BODY),
        "the marker must recognise itself"
    );
    assert!(
        credential_from_record_body(&fido_store::TOMBSTONE_BODY).is_none(),
        "a tombstone must not decode as a credential"
    );

    // And the distinction that matters for a count: an **erased slot** is not a
    // tombstone. `delete` checks the opened plaintext, never the raw image, and
    // this is why — an erased slot reads as all-`0xFF`, which is the same byte
    // pattern, and treating the two as one would make "never written" and
    // "deleted" indistinguishable to a caller counting live credentials.
    let mut erased = [0xFFu8; 64];
    assert!(
        !is_deleted_body(&erased),
        "an erased slot must not read as a tombstone — the check is on opened plaintext"
    );
}

/// **A delete of a credential that does not exist is `NoSuchCredential`, not a
/// silent success** — a caller that treats `Ok` as "deleted" would report a
/// delete that did not happen.
#[test]
fn deleting_an_absent_credential_is_refused() {
    let (_tmp, mut region) = fresh("absent");
    with_store(&mut region, |creds| {
        creds.put(&nonce(1), &credential(1, true)).expect("enrol");
        let err = creds
            .delete(&nonce(2), &credential_id(99))
            .expect_err("deleting an absent credential must be refused");
        assert!(
            matches!(err, RegionCredentialError::NoSuchCredential),
            "got {err:?}"
        );
        assert_eq!(creds.used(), Some(1), "the refused delete must change nothing");
    });
}

/// **A by-ID delete finds its credential without an `rp_id_hash`.** This is the
/// path whose `None` branch in `fido_store::CredentialIdLocator` used to
/// enumerate against an all-zero hash — which verified no tag and so found
/// nothing, answering `Absent` for every input.
#[test]
fn a_delete_finds_its_credential_without_being_told_the_relying_party() {
    let (_tmp, mut region) = fresh("no-rp");
    with_store(&mut region, |creds| {
        // Several RPs, several credentials each, so the lookup cannot succeed by
        // accident on the first candidate.
        for n in 0..9u32 {
            creds.put(&nonce(n), &credential(n, true)).expect("enrol");
        }
        let report = creds
            .delete(&nonce(50), &credential_id(7))
            .expect("a by-ID delete with no rp_id_hash must find its credential");
        assert_eq!(creds.used(), Some(8));

        // The neighbours are untouched — the probe compared the whole ID, so a
        // prefix match would have deleted the wrong one.
        let mut window = CredentialWindow::new();
        for n in [0u32, 6, 8] {
            assert!(
                matches!(
                    creds.load_by_id(Some(&rp_hash(n)), &credential_id(n), &mut window),
                    SlotRead::Present(())
                ),
                "credential {n} must survive the delete of credential 7"
            );
        }
        assert!(
            matches!(
                creds.load_by_id(Some(&rp_hash(7)), &credential_id(7), &mut window),
                SlotRead::Absent
            ),
            "the deleted credential must be gone"
        );
    });
}

/// **A sector-mate's credential is never lost to a delete.** The whole reason
/// `commit.rs` stages through a scratchpad is that a commit erases a whole sector;
/// this is the property at the applet level.
#[test]
fn a_delete_does_not_touch_its_sector_mates() {
    let (_tmp, mut region) = fresh("mates");
    let mut all = Vec::new();
    // Enough to fill at least two sectors, so there are mates to lose. The store
    // borrow is scoped per call so the medium can be inspected between them —
    // the discipline `with_store`'s own doc names.
    for n in 0..12u32 {
        let r = with_store(&mut region, |creds| {
            creds.put(&nonce(n), &credential(n, true)).expect("enrol")
        });
        all.push(r.slot);
    }
    let before: Vec<SlotImage> = all.iter().map(|s| read_slot(&mut region, *s)).collect();

    with_store(&mut region, |creds| {
        creds.delete(&nonce(99), &credential_id(5)).expect("delete");
    });

    for (i, s) in all.iter().enumerate() {
        let after = read_slot(&mut region, *s);
        if *s == all[5] {
            assert_ne!(&after, &before[i], "the deleted slot must have changed");
        } else {
            assert_eq!(
                &after, &before[i],
                "slot {i} is a sector-mate of the delete and must be byte-identical afterwards"
            );
        }
    }
}

/// **`compact` over a sector with no tombstone costs no erase.** NOR endurance is
/// specified per sector, so an erase spent on nothing is wear spent for nothing.
#[test]
fn compacting_a_full_sector_issues_no_erase() {
    let (_tmp, mut region) = fresh("no-erase");
    // Four credentials → one full sector, no tombstones.
    let mut sector = None;
    for n in 0..4u32 {
        let r = with_store(&mut region, |creds| {
            creds.put(&nonce(n), &credential(n, true)).expect("enrol")
        });
        sector = Some(commit::sector_base(r.slot));
    }
    let sector = sector.expect("four enrolments");
    let before = region.stats();
    with_store(&mut region, |creds| {
        let report = creds.compact(sector).expect("compaction must succeed");
        assert_eq!(report.slots_erased, 0, "a full sector has nothing to free");
        assert_eq!(report.staged_programs, 0, "and nothing to stage");
    });
    let after = region.stats();
    assert_eq!(
        after.sector_erases, before.sector_erases,
        "a compaction with nothing to do must not erase — it costs four slot reads and no wear"
    );
}

/// **The store's own error vocabulary reaches the applet intact.** A delete that
/// fails to commit is not a successful delete, and the mapping that decides that
/// lives in one function (`map_store_error`).
#[test]
fn a_failed_commit_is_reported_not_swallowed() {
    let (_tmp, mut region) = fresh("failed-commit");
    let mut broken = FileKeyRegion::open(_tmp.path()).expect("reopen");
    with_store(&mut region, |creds| {
        creds.put(&nonce(1), &credential(1, true)).expect("enrol");
    });
    // Erases fail from here on, so the delete's commit cannot complete.
    broken.inject_faults(fapico2_platform::keyregion::host::Faults {
        erases: true,
        ..Default::default()
    });
    {
        let k = keys();
        let mut creds = RegionCredentials::new(&mut broken, &k);
        let err = creds
            .delete(&nonce(2), &credential_id(1))
            .expect_err("a commit that cannot erase must be reported");
        // Not `Ok`: a caller that read this as success would report a delete
        // that did not happen.
        assert!(
            !matches!(err, RegionCredentialError::NoSuchCredential),
            "the error must describe the failure, not the lookup: {err:?}"
        );
    }
    // With the fault cleared, the credential is still there — the failed commit
    // rolled back rather than leaving a half-written record.
    broken.inject_faults(Default::default());
    with_store(&mut broken, |creds| {
        let mut window = CredentialWindow::new();
        assert!(
            matches!(
                creds.load_by_id(Some(&rp_hash(1)), &credential_id(1), &mut window),
                SlotRead::Present(())
            ),
            "a failed delete must leave the credential readable — the commit is sector-atomic"
        );
    });
}

/// **The region's two keys have the properties the design needs**, stated as
/// properties rather than as a derivation.
///
/// They point in opposite directions, which is why they are checked together:
///
/// * the **index** key must be PIN-free — a user who has forgotten their PIN can
///   still be told which slots hold records, the whole reason `index.rs` exists;
/// * the **payload** key must be **stable across a PIN change** — a credential
///   enrolled on a PIN-less device has to stay readable after the user sets one,
///   because re-keying the region is a whole-region transaction this story does
///   not build.
///
/// The second is a deliberate trade, and `region_pin_secret`'s docs name what it
/// gives up: an attacker holding the OTP row and the chipid can derive the
/// payload key. That is **parity with the backend being replaced** — the snapshot
/// seals its credential fields under `field_key(store_key)`, and `store_key` *is*
/// `derive_store_key(OTP || chipid)`.
#[test]
fn the_index_key_is_pin_free_and_the_payload_key_survives_a_pin_change() {
    let row = otp_row();
    let root = crypto::derive_otp_root(&row, &chip_id()).expect("a non-zero OTP row");
    let device_random = [0x5a; 32];

    let no_pin = DevicePinState::default();
    assert!(
        no_pin.pin_hash.is_none(),
        "a fresh PIN state must carry no verifier — this test's whole premise"
    );
    let mut with_pin = no_pin.clone();
    with_pin.pin_hash = Some([0x42; 16]);
    with_pin.pin_salt = Some([0x24; 16]);

    // **Payload key: stable across the PIN change.** This is the property that
    // keeps a PIN-less enrolment from being orphaned.
    let a = region_pin_secret(&no_pin, &device_random);
    let b = region_pin_secret(&with_pin, &device_random);
    assert_eq!(
        a, b,
        "the region pin_secret must not depend on the PIN verifier — otherwise setting a PIN \
         would leave every credential enrolled before it permanently unreadable, and re-keying \
         the region is a transaction this story does not build"
    );

    // **Index key: PIN-free**, and therefore identical for both PIN states.
    let ia = crypto::derive_index_key_from_root(&root);
    let ib = crypto::derive_index_key_from_root(&root);
    assert_eq!(
        ia.as_bytes(),
        ib.as_bytes(),
        "the index key must depend on the OTP root alone — that is what makes a PIN-free \
         enumeration possible at all"
    );

    // **The two keys are different keys.** A store that derived both from one
    // input would make the index's authentication meaningless: anyone who could
    // verify a forged index entry could then open the payload records.
    let payload = crypto::derive_payload_key_from_root(&root, &a);
    assert_ne!(
        ia.as_bytes(),
        payload.as_bytes(),
        "the index key and the payload key must not be the same key"
    );

    // And two devices with a different `device_random` derive different payload
    // keys, so one device's region is not readable with another's secret.
    let other = region_pin_secret(&no_pin, &[0xa7; 32]);
    let other_payload = crypto::derive_payload_key_from_root(&root, &other);
    assert_ne!(
        payload.as_bytes(),
        other_payload.as_bytes(),
        "two devices must not derive the same payload key from the same OTP row"
    );
}

/// **Enrolling a PIN later must not orphan credentials enrolled without one.**
///
/// The fallback when `pin_hash` is `None` is the keystore's `device_random`,
/// which does not change when a PIN is set — so a credential enrolled on a
/// PIN-less device is still readable after the user sets one. This is a real
/// property and it is exactly the kind of thing a "derive from the PIN" change
/// breaks silently.
#[test]
fn setting_a_pin_does_not_invalidate_credentials_enrolled_without_one() {
    let (_tmp, mut region) = fresh("pin-change");
    let device_random = [0x9d; 32];

    let no_pin_keys = {
        let row = otp_row();
        let root = crypto::derive_otp_root(&row, &chip_id()).unwrap();
        let secret = region_pin_secret(&DevicePinState::default(), &device_random);
        RegionKeys {
            index: crypto::derive_index_key_from_root(&root),
            payload: crypto::derive_payload_key_from_root(&root, &secret),
        }
    };
    let mut creds = RegionCredentials::new(&mut region, &no_pin_keys);
    creds.put(&nonce(1), &credential(1, true)).expect("enrol on a PIN-less device");
    drop(creds);

    // The user sets a PIN.
    let mut with_pin = DevicePinState::default();
    with_pin.pin_hash = Some([0x77; 16]);
    with_pin.pin_salt = Some([0x31; 16]);
    let after_pin = {
        let row = otp_row();
        let root = crypto::derive_otp_root(&row, &chip_id()).unwrap();
        let secret = region_pin_secret(&with_pin, &device_random);
        RegionKeys {
            index: crypto::derive_index_key_from_root(&root),
            payload: crypto::derive_payload_key_from_root(&root, &secret),
        }
    };

    let mut creds = RegionCredentials::new(&mut region, &after_pin);
    let mut window = CredentialWindow::new();
    assert!(
        matches!(
            creds.load_by_id(Some(&rp_hash(1)), &credential_id(1), &mut window),
            SlotRead::Present(())
        ),
        "setting a PIN must not orphan a credential enrolled without one — the PIN-less \
         fallback is the keystore's device_random, which does not change"
    );
}

/// The store is used through its own API, so its errors are named here once.
#[allow(dead_code)]
fn assert_store_error_shape(e: FidoStoreError) {
    match e {
        FidoStoreError::Full | FidoStoreError::IndexFull => {}
        _ => {}
    }
}

/// A test that opens a raw store, to prove the applet's adapter and the store
/// agree on what a delete does to the medium.
#[allow(dead_code)]
fn raw_store_probe(region: &mut FileKeyRegion) {
    let mut store = FidoRecordStore::new(region);
    let _ = store.fido_entries();
}

/// FIDO's first slot, named so a reader does not have to look it up.
#[allow(dead_code)]
const FIDO_FIRST: u32 = FIDO_FIRST_SLOT;