//! The FIDO/OATH slot partition is enforced by the store's own guard, not only
//! by allocator discipline.
//!
//! The partition itself is a fact of `keyregion::mod` (OATH `[0, 68)`,
//! scratchpad `[68, 72)`, FIDO `[72, 928)`, index the tail) and both
//! allocators honour it. But `FidoRecordStore::{delete, update, compact}` take
//! a caller-supplied [`Slot`], and before the partition move FIDO sat at the
//! region's head — so the guard only tested the upper bound. After the move
//! that guard admitted every OATH slot and the whole scratchpad: a FIDO
//! tombstone committed over an OATH credential erases OATH's sector and
//! destroys the credential. This file pins the two-sided refusal so the
//! predicate cannot drift back the way its own comment did.

use std::path::{Path, PathBuf};

use fapico2_platform::ckey;
use fapico2_platform::keyregion::crypto::{self, IndexKey, PayloadKey};
use fapico2_platform::keyregion::fido_store::{is_fido_slot, FidoRecordStore, FidoStoreError};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::index::RpIdHash;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::{Slot, FIDO_FIRST_SLOT, OATH_CAPACITY};

/// The whole region, for the same reason `key_region_one_record.rs` gives: a
/// short stand-in would move what the allocator can reach.
const REGION_SLOTS: u32 = fapico2_platform::keyregion::TOTAL_SLOTS;

struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-slotguard-{}-{tag}.bin", std::process::id()));
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
        *b = (i as u8).wrapping_mul(13).wrapping_add(0x23);
    }
    row
}

fn chip_id() -> [u8; 8] {
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
}

/// A PIN-derived secret, made the way an applet makes one — the same key
/// hierarchy the device would use, per `key_region_counter_budget.rs`'s fixture.
fn pin_secret() -> [u8; 32] {
    let row = otp_row();
    let serial = ckey::serial_hash(b"fapico2 keyregion slot partition test");
    let kbase = ckey::derive_kbase(&row, &serial, 0x0BAD_F00D, Some(&[0x5a; 32]))
        .expect("a provisioned OTP row derives a kbase");
    let kver = ckey::derive_kver(&kbase, b"123456");
    ckey::pin_session(&serial, &kver)
}

fn payload_key() -> PayloadKey {
    crypto::derive_payload_key(&otp_row(), &chip_id(), &pin_secret())
        .expect("a provisioned OTP row derives a payload key")
}

fn index_key() -> IndexKey {
    crypto::derive_index_key(&otp_row(), &chip_id())
        .expect("a provisioned OTP row derives an index key")
}

fn rp_hash() -> RpIdHash {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(0x41);
    }
    RpIdHash::from_bytes(h)
}

fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"slot guard!"[..record::NONCE_LEN - 4]);
    out
}

fn body(n: u32) -> Vec<u8> {
    let mut v = vec![0u8; 128];
    v[..4].copy_from_slice(&n.to_le_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(4) {
        *b = (i as u8).wrapping_mul(5).wrapping_add(n as u8);
    }
    v
}

fn slot(index: u32) -> Slot {
    Slot::new(index as u16).expect("every index named here is inside the region")
}

/// **The predicate is two-sided.** The head of the region belongs to OATH and
/// the scratchpad follows it; only `[FIDO_FIRST_SLOT, FIDO_SLOT_LIMIT)` is
/// FIDO's. A regression to the one-sided upper bound is the bug this file
/// exists for, so the predicate itself is pinned at both ends.
#[test]
fn the_fido_predicate_refuses_oath_scratchpad_and_index_slots() {
    assert!(
        !is_fido_slot(slot(0)),
        "slot 0 is OATH's head — the pre-partition guard admitted it"
    );
    assert!(!is_fido_slot(slot(OATH_CAPACITY - 1)), "OATH's last slot is OATH's");
    assert!(
        !is_fido_slot(slot(FIDO_FIRST_SLOT - 1)),
        "the scratchpad's last slot is the commit's, not FIDO's"
    );
    assert!(is_fido_slot(slot(FIDO_FIRST_SLOT)), "FIDO's first slot is FIDO's");
    assert!(
        !is_fido_slot(slot(fapico2_platform::keyregion::FIDO_SLOT_LIMIT)),
        "the scratchpad behind FIDO's range is not FIDO's"
    );
    assert!(
        !is_fido_slot(slot(fapico2_platform::keyregion::TOTAL_SLOTS - 1)),
        "the index owns the tail"
    );
}

/// **A FIDO delete cannot name an OATH slot.** The concrete failure the
/// one-sided guard allowed: `delete(Slot::new(0))` read OATH's credential
/// generation, erased OATH's sector, and committed a FIDO tombstone into
/// OATH's slot 0.
#[test]
fn a_fido_delete_refuses_an_oath_slot() {
    let tmp = TempRegion::new("delete-oath");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let mut store = FidoRecordStore::new(&mut region);
    let err = store
        .delete(&payload_key(), slot(0), &nonce(1))
        .expect_err("an OATH slot must be refused, not tombstoned");
    assert!(
        matches!(err, FidoStoreError::RegionUnreadable(_)),
        "got {err:?}"
    );
}

/// **A FIDO update cannot name an OATH slot** — same hole, write-shaped.
#[test]
fn a_fido_update_refuses_an_oath_slot() {
    let tmp = TempRegion::new("update-oath");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let mut store = FidoRecordStore::new(&mut region);
    let err = store
        .update(&payload_key(), &index_key(), slot(0), &nonce(1), &rp_hash(), &body(1))
        .expect_err("an OATH slot must be refused, not overwritten");
    assert!(
        matches!(err, FidoStoreError::RegionUnreadable(_)),
        "got {err:?}"
    );
}

/// **The refusal is not a broken store**: the same key set still enrols and
/// deletes inside FIDO's own range, so the guard only refuses across the
/// partition and never the partition's own side.
#[test]
fn the_guard_refuses_only_across_the_partition() {
    let tmp = TempRegion::new("control");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");
    let mut store = FidoRecordStore::new(&mut region);
    let report = store
        .put(&payload_key(), &index_key(), &nonce(1), &rp_hash(), &body(1))
        .expect("a FIDO enrolment into FIDO's own range succeeds");
    assert!(
        is_fido_slot(report.slot),
        "the allocator must only issue FIDO slots"
    );
    store
        .delete(&payload_key(), report.slot, &nonce(2))
        .expect("a FIDO delete inside FIDO's own range succeeds");
}

// ---------------------------------------------------------------------------
// The scratchpad guard — the same partition, on the commit path
// ---------------------------------------------------------------------------

/// **A commit cannot stage through the index.**
///
/// `commit::CommitPlan::validate` is the last line of defence for a hazard no
/// other check sees: a scratchpad pointing into the **index** would not fail —
/// it would *succeed*, and erase the index sector on every commit from then on.
/// The commit returns `Ok`, the credential is written, and the entry naming it
/// is gone. No error is reported at any point.
///
/// The index is the one sector no domain owns — both the FIDO and OATH stores
/// write into it — which is what justifies singling it out. Demanding the
/// region's *own* scratchpad instead would be stricter and wrong: `commit` takes
/// the scratchpad as a caller's argument, and `key_region_commit.rs` runs a
/// three-sector region that legitimately stages through slot 4. The comment on
/// the guard records that reasoning.
///
/// This lives here rather than in `key_region_commit.rs` because that file's
/// three-sector fixture cannot express the hazard at all: its region ends at
/// slot 12, and the index starts at 928.
#[test]
fn a_commit_refuses_a_reserved_slot_as_its_scratchpad() {
    use fapico2_platform::keyregion::commit::{self, CommitError, CommitPlan};
    use fapico2_platform::keyregion::index::INDEX_FIRST_SLOT;
    use fapico2_platform::keyregion::record::Domain;
    use fapico2_platform::keyregion::{is_reserved_slot, SCRATCHPAD_FIRST_SLOT};

    let tmp = TempRegion::new("scratchpad-guard");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("create");

    // Seed a real index entry, so "the index survived" is a claim and not a
    // tautology about an empty region.
    {
        let mut store = FidoRecordStore::new(&mut region);
        store
            .put(&payload_key(), &index_key(), &nonce(1), &rp_hash(), &body(1))
            .expect("a FIDO enrolment must seed the index");
    }

    // A sealed body to hand the plan. `validate` refuses before anything is
    // staged, so its contents do not matter — but the call must be well-formed
    // enough to reach the guard rather than fail earlier for want of a body.
    let sealed = {
        let header =
            record::RecordHeader::new(record::Domain::Fido, slot(FIDO_FIRST_SLOT), 1);
        record::seal(
            &header,
            payload_key().as_bytes(),
            &nonce(1),
            &body(1),
        )
        .expect("a 128-byte body seals under the fixture's payload key")
    };

    for (why, scratch) in [
        ("the first index slot", slot(INDEX_FIRST_SLOT)),
        ("a later index slot", slot(INDEX_FIRST_SLOT + 8)),
    ] {
        let plan = CommitPlan::new(scratch, slot(FIDO_FIRST_SLOT), Domain::Fido, 1);
        let outcome = commit::commit(&mut region, plan, &sealed);
        assert!(
            matches!(outcome, Err(CommitError::Plan { .. })),
            "{why} must be refused as a scratchpad, got {outcome:?}",
        );
    }

    // The index is intact, and a legitimate commit still works — the guard
    // refuses reserved slots, not commits.
    let mut store = FidoRecordStore::new(&mut region);
    assert!(
        store.put(&payload_key(), &index_key(), &nonce(2), &rp_hash(), &body(2)).is_ok(),
        "a FIDO enrolment through the region's own scratchpad must still succeed",
    );
    // The exemption in the guard is load-bearing and this is its other half:
    // the region's own scratchpad **is** reserved, which is exactly why the
    // check has to exempt it rather than simply refusing every reserved slot.
    assert!(
        is_reserved_slot(slot(SCRATCHPAD_FIRST_SLOT)),
        "the region's own scratchpad is a reserved slot, so the guard must exempt it by name — \
         a predicate that refused all reserved slots would refuse every commit",
    );
}
