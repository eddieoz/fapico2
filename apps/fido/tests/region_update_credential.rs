//! US-1555 — credMgmt's `updateUserInformation` is a rename **in the slot the
//! credential already occupies**.
//!
//! ```gherkin
//! Scenario: renaming a resident credential
//!   Given a resident credential for one RP
//!   When updateUserInformation changes its user name
//!   Then the store still holds exactly that credential
//!   And enumerating the RP answers the new name and the same counter
//! ```
//!
//! # Why this file exists
//!
//! The region arm of `updateUserInformation` reached for
//! [`RegionCredentials::put`], which allocates a **new** slot and appends a new
//! index entry: the renamed passkey enumerated twice, the two copies' counters
//! diverged, and [`FIDO_CAPACITY`] lost one slot per rename. The fix is
//! [`RegionCredentials::update_credential`] — the slot-addressed primitive the
//! counter bump already uses — and these tests pin the property that would have
//! caught the defect: **a rename changes no counts**.

use std::path::{Path, PathBuf};

use fapico2_fido::device_keystore::{
    credential_from_record_body, region_pin_secret, DeviceCredential, DevicePinState, PrivateScalar,
    RegionCredentialError, RegionCredentials, RegionKeys,
};
use fapico2_platform::keyregion::crypto;
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::{SlotRead, TOTAL_SLOTS};

use heapless::Vec as HeaplessVec;

const REGION_SLOTS: u32 = TOTAL_SLOTS;

struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-us1555-{}-{tag}.bin", std::process::id()));
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

/// The keys, from a **fixed** PIN state so every call in one test seals and
/// opens under the same key.
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
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"us1555nonce!!"[..record::NONCE_LEN - 4]);
    out
}

fn credential_id(n: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(b"u155");
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

/// A modest credential — short fields, so the tests are about the rename rather
/// than about the record bound.
fn credential(n: u32, resident: bool) -> DeviceCredential {
    let mut cred = DeviceCredential {
        credential_id: HeaplessVec::new(),
        public_key: fapico2_fido::device_keystore::DeviceCoseKey::es256([n as u8; 32], [0x22; 32]),
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

fn expect_present<T>(outcome: SlotRead<T>, what: &str) -> T {
    match outcome {
        SlotRead::Present(v) => v,
        SlotRead::Absent => panic!("{what}: absent"),
        SlotRead::Fault(why) => panic!("{what}: the region must be readable, got a fault: {why}"),
    }
}

fn load_credential(
    creds: &mut RegionCredentials<'_, '_>,
    rp: &[u8; 32],
    id: &[u8; 32],
) -> Option<DeviceCredential> {
    let mut window = CredentialWindow::new();
    match creds.load_by_id(Some(rp), id, &mut window) {
        SlotRead::Present(()) => credential_from_record_body(window.as_slice()),
        SlotRead::Absent => None,
        SlotRead::Fault(why) => panic!("the region must be readable, got a fault: {why}"),
    }
}

/// **A rename lands in the slot the credential already occupies.** The
/// property the `put`-based defect violated three ways at once: the count does
/// not grow, the old record is gone, and the new name is the only name.
#[test]
fn an_update_renames_the_credential_in_its_own_slot() {
    let (_tmp, mut region) = fresh("rename");
    let rp = rp_hash(1);

    let _updated_slot = with_store(&mut region, |creds| {
        creds.put(&nonce(1), &credential(1, true)).expect("enrol the first");
        creds.put(&nonce(2), &credential(2, true)).expect("enrol a neighbour");
        assert_eq!(creds.used(), Some(2), "two enrolments, two credentials");

        // The lookup the command performs — one walk, the slot it names.
        let mut window = CredentialWindow::new();
        let slot = expect_present(
            creds.load_by_id_at(Some(&rp), &credential_id(1), &mut window),
            "the credential must be findable before the rename",
        );
        let mut cred =
            credential_from_record_body(window.as_slice()).expect("the record decodes");

        // The rename: user name and display name, exactly what
        // `updateUserInformation` is allowed to touch.
        cred.user_name.clear();
        cred.user_name.extend_from_slice(b"renamed").unwrap();
        cred.user_display_name.clear();
        cred.user_display_name.extend_from_slice(b"Renamed User").unwrap();

        creds
            .update_credential(&nonce(3), slot, &cred)
            .expect("a rename into the slot the lookup named succeeds");
        slot
    });

    with_store(&mut region, |creds| {
        // The count is the whole bug: `put` answered `3` here.
        assert_eq!(
            creds.used(),
            Some(2),
            "a rename must not grow the store — the pre-fix path allocated a second slot"
        );

        // The new name, under the same ID and the same slot.
        let reloaded = load_credential(creds, &rp, &credential_id(1))
            .expect("the renamed credential is still findable");
        assert_eq!(reloaded.user_name.as_slice(), b"renamed");
        assert_eq!(reloaded.user_display_name.as_slice(), b"Renamed User");
        assert_eq!(reloaded.counter, 1, "the rename must not disturb the counter");

        // The neighbour is untouched — a second index entry for the renamed
        // credential would have shifted the enumeration this credential sits in.
        let neighbour = load_credential(creds, &rp_hash(2), &credential_id(2))
            .expect("the neighbour survives the rename");
        assert_eq!(neighbour.user_name.as_slice(), b"user");
    });
}

/// **An update cannot resurrect a deleted credential.** After the delete and
/// the compaction the slot is erased, and an erased slot is
/// [`RegionCredentialError::Unreachable`] to an update — the store's deliberate
/// answer (`FidoRecordStore::update`'s step 2: an erased slot is "an enrolment
/// is the operation for that"), because committing over nothing is
/// indistinguishable from an enrolment and must not be spelled "update". The
/// deleted credential stays gone.
#[test]
fn an_update_cannot_resurrect_a_tombstone() {
    let (_tmp, mut region) = fresh("tombstone");
    let rp = rp_hash(1);

    with_store(&mut region, |creds| {
        creds.put(&nonce(1), &credential(1, true)).expect("enrol");
        let mut window = CredentialWindow::new();
        let slot = expect_present(
            creds.load_by_id_at(Some(&rp), &credential_id(1), &mut window),
            "the credential must be findable before the delete",
        );

        creds.delete(&nonce(2), &credential_id(1)).expect("delete");
        creds
            .compact(fapico2_platform::keyregion::commit::sector_base(slot))
            .expect("compaction frees the tombstoned slot");
        assert_eq!(creds.used(), Some(0), "the delete must have emptied the store");

        let mut renamed = credential(1, true);
        renamed.user_name.clear();
        renamed.user_name.extend_from_slice(b"renamed").unwrap();
        let err = creds
            .update_credential(&nonce(3), slot, &renamed)
            .expect_err("an update over an erased slot must be refused");
        assert!(
            matches!(err, RegionCredentialError::Unreachable(_)),
            "an erased slot is 'no record', not a credential to update — got {err:?}"
        );
        assert!(
            load_credential(creds, &rp, &credential_id(1)).is_none(),
            "the deleted credential stays deleted"
        );
    });
}
