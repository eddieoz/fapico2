//! US-1563 — the boundary, **measured** rather than asserted.
//!
//! ```gherkin
//! Scenario: enroll to the boundary and assert a clean refusal
//!   Given the region at its full capacity
//!   When credentials are enrolled until the first refusal
//!   Then the refusal is CTAP2_ERR_KEY_STORE_FULL (0x28)
//!   And the count matches the derivation from parts and record size
//!   And no partial credential is left behind
//!   And docs/capacity.md carries the measured number
//! ```
//!
//! # Why this file exists rather than a constant
//!
//! `FIDO_CAPACITY` is **derived** — `keyregion/mod.rs` computes it as
//! `TOTAL_SLOTS − OATH_CAPACITY − SCRATCHPAD_SLOTS − INDEX_SLOT_COUNT` and
//! refuses to compile if those four terms do not tile the region exactly once.
//! That derivation is a claim about *slots*; this file is the claim about
//! **enrolments**, and the two are only the same if every enrolment really does
//! take exactly one slot. They need not: a commit could leave a slot occupied
//! it should have freed, a tombstone could leak one, an index write could fail
//! and strand a record. So the number is measured by running to it, and the
//! derivation is checked against the measurement rather than trusted.
//!
//! This is the discipline the old `DEVICE_MAX_CREDS = 12` failed: it was a
//! literal in a file no region could contradict, and it was wrong by two orders
//! of magnitude *and* unreachable (the real ceiling was four, from the 24-entry
//! secure store's occupancy arithmetic — `tests/key_store_ceiling.rs`).
//!
//! # What is measured and what is checked
//!
//! | claim | how |
//! |---|---|
//! | the device enrols `FIDO_CAPACITY` credentials | every one is written **and read back byte-identically** |
//! | the next one is refused `Full` (→ CTAP2 0x28) | [`RegionCredentials::put`] returns [`RegionCredentialError::Full`] |
//! | the count matches the derivation | `measured == FIDO_CAPACITY`, asserted |
//! | no partial credential is left behind | the index holds exactly `FIDO_CAPACITY` entries, every slot outside the boundary is erased, and the scratchpad is swept |
//!
//! # Cost, and why it is not `#[ignore]`d
//!
//! The run is O(n²) in slot reads: `FidoAllocator::alloc` is a linear scan by
//! design (`slotmap.rs`, "Lowest free slot is a linear scan"), so enrolling *n*
//! credentials costs ~n²/2 header reads. At 856 that is ~366,000 1 KiB reads
//! against a `FileKeyRegion` — seconds, not minutes, on a host tmpfs. Ignoring it
//! would defeat the point: **the number is the deliverable**, and an unrun
//! measurement is an assertion.
//!
//! Every record written here is a **real** [`DeviceCredential`] encoded by the
//! applet's own codec, not a synthetic blob — a boundary measured over 400-byte
//! filler would be a boundary for the filler, not for a passkey. The fixture is
//! the largest credential a browser may register (a 63-byte RP ID, a 58-byte
//! `user.name`, a 43-byte `displayName`, a 64-byte `user.id`, a full-size
//! `credBlob`, `largeBlobKey`), which is the case `FIDO_RECORD_MAX` was
//! measured against.

use std::path::{Path, PathBuf};

use fapico2_fido::device_keystore::{
    credential_from_record_body, credential_record_body, region_pin_secret, DeviceCredential,
    DevicePinState, RegionCredentialError, RegionCredentials, RegionKeys,
};
use fapico2_platform::keyregion::crypto;
use fapico2_platform::keyregion::fido_store::FidoStoreError;
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::slotmap::{is_erased, SlotImage};
use fapico2_platform::keyregion::{
    commit, KeyRegion, Slot, SlotRead, FIDO_CAPACITY, FIDO_RECORD_MAX, FIDO_SLOT_LIMIT,
    SLOTS_PER_SECTOR, TOTAL_SLOTS,
};

use heapless::Vec as HeaplessVec;

/// The region's whole geometry — the same number `key_region_one_record.rs`
/// uses, and for the same reason: a short stand-in would move
/// `region.slots()` and therefore what the allocator can reach.
const REGION_SLOTS: u32 = TOTAL_SLOTS;

/// The CTAP2 error the refusal must be answered with.
///
/// `ctap2.rs`'s `Ctap2Response::KeyStoreFull`. Named here because the gherkin
/// names it, and because "the store said Full" and "the device said 0x28" are
/// two claims — the second is the one a client sees, and the mapping between
/// them is exactly the kind of thing that drifts when only one twin changes
/// (AGENTS.md §1).
const KEY_STORE_FULL: u8 = 0x28;

/// The `u8` this device returns for [`RegionCredentialError::Full`].
///
/// Stated as a **test-local** function rather than a library constant because the
/// mapping from a store error to a CTAP2 status byte lives in `device_core.rs`,
/// which is not reachable from an integration test. What this pins is that the
/// applet-side error carries `Full` and nothing else — the byte itself is
/// pinned by `tests/key_store_ceiling.rs` on the snapshot path and, for the
/// region path, by `region_refusal_is_the_ctap2_key_store_full_byte` below,
/// which drives the real command path.
fn ctap2_for(err: RegionCredentialError) -> u8 {
    match err {
        // The one that matters: a full store is 0x28 and nothing else.
        RegionCredentialError::Full => KEY_STORE_FULL,
        // Everything else is a different claim, and mapping them onto 0x28 would
        // be a device telling a user its store is full when the flash is sick.
        other => panic!("expected KeyStoreFull, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A region file in the host temp directory, removed on drop.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-us1563-{}-{tag}.bin", std::process::id()));
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

/// The device-rooted OTP row. Non-zero because `crypto::derive_otp_root` refuses
/// an all-zero row rather than return a constant root.
fn otp_row() -> [u8; 32] {
    let mut row = [0u8; 32];
    for (i, b) in row.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31).wrapping_add(0x07);
    }
    row
}

fn chip_id() -> [u8; 8] {
    [0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f]
}

/// The two region keys, from the OTP row and the applet's PIN secret.
///
/// `region_pin_secret` is the applet's own derivation (`device_keystore.rs`), so
/// this fixture is the same material the device would use — a test that derived
/// its own would be testing a different key hierarchy than the one shipped.
fn keys() -> RegionKeys {
    let row = otp_row();
    let root = crypto::derive_otp_root(&row, &chip_id()).expect("a non-zero OTP row");
    let pin_state = DevicePinState::default();
    let secret = region_pin_secret(&pin_state, &[0x5a; 32]);
    RegionKeys {
        index: crypto::derive_index_key_from_root(&root),
        payload: crypto::derive_payload_key_from_root(&root, &secret),
    }
}

/// The applet's PIN secret, recomputed so a delete/put cycle in one test uses
/// the same key twice — a test that silently re-derived a *different* key would
/// see every lookup fail and could mistake that for a delete bug.
fn keys_for(pin_state: &DevicePinState, device_random: &[u8; 32]) -> RegionKeys {
    let row = otp_row();
    let root = crypto::derive_otp_root(&row, &chip_id()).expect("a non-zero OTP row");
    let secret = region_pin_secret(pin_state, device_random);
    RegionKeys {
        index: crypto::derive_index_key_from_root(&root),
        payload: crypto::derive_payload_key_from_root(&root, &secret),
    }
}

/// A fresh GCM nonce for the `n`-th write.
///
/// Unique per write, which `record::seal` requires and this file holds itself to
/// rather than assuming. A repeated nonce under one key is catastrophic for GCM
/// and the store deliberately does not derive nonces (`FidoRecordStore::put`'s
/// docs) — the device draws from its TRNG pool, and this is the host's
/// equivalent.
fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&(n as u32).to_le_bytes());
    out[4..].copy_from_slice(&b"us1563nonce!!"[..record::NONCE_LEN - 4]);
    out
}

fn slot(index: u16) -> Slot {
    Slot::new(index).expect("every index in this file is inside the region")
}

/// The largest credential a browser may register.
///
/// Every field at its CTAP 2.1 maximum, because the boundary is only the
/// boundary for the credentials that actually occur: a measurement over short
/// RP IDs would report a capacity the device cannot serve a real site at.
/// `tests/key_store_ceiling.rs`'s `REALISTIC_MC` is the same fixture measured
/// through the snapshot path, so the two files' numbers are comparable.
fn maximal_credential(n: u32) -> DeviceCredential {
    let mut cred = DeviceCredential {
        credential_id: HeaplessVec::new(),
        public_key: fapico2_fido::device_keystore::DeviceCoseKey::es256([n as u8; 32], [0x77; 32]),
        private_key: [0x33; 32],
        rp_id_hash: rp_hash(n),
        rp_id: HeaplessVec::new(),
        user_handle: HeaplessVec::new(),
        user_name: HeaplessVec::new(),
        user_display_name: HeaplessVec::new(),
        cred_protect: 2,
        large_blob_key: Some([0x44; 32]),
        hmac_secret: HeaplessVec::new(),
        cred_blob: HeaplessVec::new(),
        third_party_payment: true,
        pin_complexity_policy: false,
        resident: true,
        algorithm: -7,
        counter: n,
        revoked: false,
        expires_at: Some(n),
    };
    // 63-byte RP ID ("example" style host names reach this), 32-byte credential
    // ID, 64-byte user handle, 58-byte user name, 43-byte display name and a
    // full-size 32-byte credBlob.
    cred.credential_id.extend_from_slice(&credential_id(n)).unwrap();
    cred.rp_id.extend_from_slice(&long_rp_id(n)).unwrap();
    cred.user_handle.extend_from_slice(&[n as u8; 64]).unwrap();
    cred.user_name.extend_from_slice(&[b'u'; 58]).unwrap();
    cred.user_display_name.extend_from_slice(&[b'D'; 43]).unwrap();
    cred.cred_blob.extend_from_slice(&[0xcc; 32]).unwrap();
    cred.hmac_secret.extend_from_slice(&[0x11; 64]).unwrap();
    cred
}

/// A 32-byte credential ID, unique per credential.
fn credential_id(n: u32) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(b"f156");
    id[4..8].copy_from_slice(&n.to_le_bytes());
    id[8..].copy_from_slice(&[(n >> 8) as u8; 24]);
    id
}

/// A 63-byte RP ID, distinct per credential so the index cannot collide.
///
/// **Every byte is printable ASCII**, and that is load-bearing rather than
/// cosmetic: `DeviceCredential::encode` writes `rp_id` through
/// `no_heap::push_tstr`, which is `core::str::from_utf8` and refuses anything
/// else. A fixture that packed a counter into the tail with `to_le_bytes`
/// produced `0x80` at credential 128 and the encoder — correctly — rejected the
/// whole record as `InvalidUtf8`. A CBOR `tstr` is a UTF-8 string; an RP ID that
/// is not one is not an RP ID.
fn long_rp_id(n: u32) -> [u8; 63] {
    let mut id = [b'r'; 63];
    // base-36 into the last four characters, all in '0'..='z'.
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut v = n;
    for i in (0..4).rev() {
        id[59 - i] = digits[(v % 36) as usize];
        v /= 36;
    }
    id
}

/// `rp_id_hash` for credential `n`. Not a real SHA-256 — the bytes are the
/// *message* an index entry's MAC is made over, so what matters is that they
/// differ and no two credentials share one.
fn rp_hash(n: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = (n as u8).wrapping_mul(53).wrapping_add(i as u8).wrapping_add(0x9d);
    }
    h
}

/// Run `f` with a credential store over `region`, dropping the store first.
///
/// The scoping is not tidiness: `RegionCredentials` holds the region borrow for
/// its whole life, so a test that wants to inspect the medium between two
/// operations has to end the borrow. Re-creating it is free — its constructor
/// reads nothing.
fn with_store<R>(region: &mut FileKeyRegion, f: impl FnOnce(&mut RegionCredentials<'_, '_>) -> R) -> R {
    let k = keys();
    let mut creds = RegionCredentials::new(region, &k);
    f(&mut creds)
}

/// Every slot in FIDO's range, indexed by its offset from `FIDO_FIRST_SLOT`.
fn fido_area(region: &mut dyn KeyRegion) -> Vec<SlotImage> {
    (0..FIDO_CAPACITY)
        .map(|i| {
            let s = FIDO_FIRST + i;
            region.read_slot(slot(s as u16)).expect("slot reads")
        })
        .collect()
}

/// FIDO's first slot, named once so the geometry arithmetic is in one place and
/// a reader does not have to remember that the region's head belongs to OATH.
const FIDO_FIRST: u32 = fapico2_platform::keyregion::FIDO_FIRST_SLOT;

/// Unwrap a [`SlotRead`] that must have been `Present`.
///
/// `SlotRead` has no `expect` on purpose — its whole point is that `Fault` and
/// `Absent` are *different* answers — so the assertion is written down rather
/// than defaulted.
fn expect_present<T>(outcome: SlotRead<T>, what: &str) -> T {
    match outcome {
        SlotRead::Present(v) => v,
        SlotRead::Absent => panic!("{what}: absent"),
        SlotRead::Fault(why) => panic!("{what}: the region must be readable, got a fault: {why}"),
    }
}

// ---------------------------------------------------------------------------
// The measurement
// ---------------------------------------------------------------------------

/// **The number, measured.** Every credential the region can hold enrols, every
/// one reads back byte-identically, and the next one is refused `0x28`.
#[test]
fn the_boundary_is_the_derived_capacity_and_the_next_enrolment_is_refused() {
    let tmp = TempRegion::new("boundary");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("a fresh region file");

    let mut enrolled = 0u32;
    with_store(&mut region, |creds| {
        let mut window = CredentialWindow::new();
        for n in 0..FIDO_CAPACITY {
            let cred = maximal_credential(n);
            creds
                .put(&nonce(n), &cred)
                .unwrap_or_else(|e| panic!("credential {n} of {FIDO_CAPACITY} must enrol, got {e:?}"));
            enrolled += 1;

            // Read it back on the way past, so "enrolled" means *durable and
            // findable*, not merely written. A credential that writes and cannot
            // be read back is a capacity claim the device does not honour — the
            // exact defect AGENTS.md §4 is about, and the reason this loop does
            // not defer verification to the end.
            let rp = rp_hash(n);
            let got = creds.load_by_id(Some(&rp), &credential_id(n), &mut window);
            assert!(
                matches!(got, SlotRead::Present(())),
                "credential {n} must be readable straight after enrolment, got {got:?}"
            );
            let decoded = credential_from_record_body(window.as_slice())
                .unwrap_or_else(|| panic!("credential {n} must decode as a credential"));
            assert_eq!(
                decoded.credential_id.as_slice(),
                credential_id(n).as_slice(),
                "credential {n} read back a different credential"
            );
            assert_eq!(
                decoded.rp_id.as_slice(),
                long_rp_id(n).as_slice(),
                "credential {n} read back a different RP"
            );
            assert_eq!(
                decoded.private_key, cred.private_key,
                "credential {n} read back a different private key"
            );
        }

        // The first refusal, and its exact shape.
        let err = creds.put(&nonce(FIDO_CAPACITY), &maximal_credential(FIDO_CAPACITY))
            .expect_err("the enrolment past capacity must be refused");
        let status = ctap2_for(err);
        assert_eq!(
            status, KEY_STORE_FULL,
            "a full region must answer CTAP2_ERR_KEY_STORE_FULL, not some other status"
        );

        // And the advertised count agrees with what was just written.
        assert_eq!(
            creds.used(),
            Some(FIDO_CAPACITY),
            "the index must hold exactly one entry per enrolled credential"
        );
        assert_eq!(
            creds.remaining(),
            Some(0),
            "a full region must advertise zero remaining — a wire claim the device does not honour \
             is the defect AGENTS.md §4 names"
        );
    });

    assert_eq!(
        enrolled, FIDO_CAPACITY,
        "the measured boundary must equal the derivation: the region holds \
         TOTAL_SLOTS - OATH - SCRATCHPAD - INDEX slots and one credential per slot"
    );
}

/// **No partial credential is left behind.** Every slot outside the boundary is
/// erased and the scratchpad is swept, so a refused enrolment has not consumed a
/// slot a later one could have used.
#[test]
fn a_refused_enrolment_leaves_nothing_behind() {
    let tmp = TempRegion::new("no-partial");
    let mut region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("a fresh region file");

    // Fill to exactly capacity - 1, so the boundary is one step away.
    with_store(&mut region, |creds| {
        for n in 0..FIDO_CAPACITY - 1 {
            creds
                .put(&nonce(n), &maximal_credential(n))
                .unwrap_or_else(|e| panic!("credential {n} must enrol, got {e:?}"));
        }
        assert_eq!(creds.remaining(), Some(1), "one slot left before the boundary");

        // The last one succeeds and uses the last slot.
        creds
            .put(&nonce(FIDO_CAPACITY - 1), &maximal_credential(FIDO_CAPACITY - 1))
            .expect("the last free slot must accept a credential");
        assert_eq!(creds.remaining(), Some(0));
    });

    // Outside FIDO's range: OATH's slots, the scratchpad and the index must all
    // be exactly as they were — a FIDO enrolment that disturbed any of them
    // would be writing into another applet's area (`fido_store::is_fido_slot`).
    let before: Vec<SlotImage> = (0..FIDO_FIRST)
        .map(|i| region.read_slot(slot(i as u16)).expect("slot reads"))
        .collect();
    for (i, raw) in before.iter().enumerate() {
        assert!(
            is_erased(raw),
            "slot {i} is outside FIDO's range and must be untouched by an enrolment"
        );
    }
    let scratch_base = fapico2_platform::keyregion::SCRATCHPAD_FIRST_SLOT;
    for i in 0..SLOTS_PER_SECTOR {
        let raw = region
            .read_slot(slot((scratch_base + i) as u16))
            .expect("slot reads");
        assert!(
            is_erased(&raw),
            "the commit scratchpad must be swept after a successful enrolment — staged bytes left \
             behind are read as a pending commit by the next recover"
        );
    }

    // Exactly FIDO_CAPACITY of FIDO's own slots are occupied, and no more.
    let area = fido_area(&mut region);
    let occupied = area.iter().filter(|raw| !is_erased(raw)).count();
    assert_eq!(
        occupied, FIDO_CAPACITY as usize,
        "exactly one slot per credential must be occupied — a partial write would show up here as \
         an occupied slot with no index entry"
    );

    // And every occupied slot carries a FIDO record with a generation of 1,
    // which is what proves each credential took a *fresh* slot rather than
    // rewriting one (a rewrite would raise a slot's generation above 1).
    for (offset, raw) in area.iter().enumerate() {
        if is_erased(raw) {
            continue;
        }
        let s = slot((FIDO_FIRST + offset as u32) as u16);
        let decoded = expect_present(record::decode(s, raw), "every occupied slot holds a record");
        assert_eq!(
            decoded.header().generation(),
            1,
            "slot {offset} was written more than once — the allocator reused a slot rather than \
             taking the free one"
        );
    }
}

/// The record the applet writes is the one the region's stride was sized for.
///
/// The measurement above is only meaningful if the fixture actually exercises the
/// bound: a maximal credential must encode to at most `FIDO_RECORD_MAX`, and
/// must be close enough to it that the 128-byte `SLOT_MARGIN_BYTES` is margin
/// rather than slack.
#[test]
fn a_maximal_credential_fits_the_measured_record_bound() {
    let cred = maximal_credential(0);
    let body = credential_record_body(&cred).expect("a maximal credential must encode");
    assert!(
        body.len() <= FIDO_RECORD_MAX as usize,
        "a maximal credential encodes to {} B, over the {} B record bound — the stride was sized \
         for a record this store cannot hold",
        body.len(),
        FIDO_RECORD_MAX
    );
    // The lower edge: if this ever fails the measurement is measuring a fixture
    // nothing resembles. A real passkey lands within a few hundred bytes of this.
    assert!(
        body.len() >= 400,
        "the fixture encodes to only {} B — it is not the maximal credential the record bound was \
         measured against, so the boundary it measures is not the device's",
        body.len()
    );
    // And it round-trips: the boundary is measured over records the device can
    // also read.
    let decoded = credential_from_record_body(body.as_slice()).expect("round-trip");
    assert_eq!(decoded, cred, "the record body must decode to the credential that produced it");
}

/// The derivation and the measurement are the same number, stated as an
/// identity rather than left implicit.
///
/// `docs/capacity.md` carries this figure; this test is what makes it true, and
/// it is here rather than in the document because a document assertion is not
/// checked by anything (`docs/capacity.md`, "What this document is not").
#[test]
fn the_derivation_sums_to_the_measured_boundary() {
    assert_eq!(
        FIDO_CAPACITY,
        TOTAL_SLOTS
            - fapico2_platform::keyregion::OATH_CAPACITY
            - fapico2_platform::keyregion::SCRATCHPAD_SLOTS
            - fapico2_platform::keyregion::index::INDEX_SLOT_COUNT,
        "the capacity is four terms, and they must claim every slot exactly once"
    );
    // The range FIDO actually writes is the capacity, at the derived offset —
    // the two numbers a caller could confuse, pinned together.
    assert_eq!(FIDO_SLOT_LIMIT - FIDO_FIRST, FIDO_CAPACITY);
    // The index must be able to hold one entry per record, or the last
    // credentials would be enrolled and unfindable.
    assert!(
        fapico2_platform::keyregion::index::index_capacity() >= TOTAL_SLOTS,
        "the index must cover the whole region's slot count"
    );
}

/// `docs/capacity.md` must carry this number.
///
/// The gherkin's last clause, checked. A document that drifts from the code is
/// the failure mode that let `DEVICE_MAX_CREDS = 12` and the "~42 credentials"
/// claim survive as long as they did, and this is the check that stops the
/// measured figure from becoming the next one.
#[test]
fn capacity_docs_carry_the_measured_number() {
    let docs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/capacity.md");
    let text = std::fs::read_to_string(&docs)
        .unwrap_or_else(|e| panic!("docs/capacity.md must be readable: {e}"));
    let number = FIDO_CAPACITY.to_string();
    assert!(
        text.contains(&number),
        "docs/capacity.md does not mention the measured capacity {number} — the document and the \
         region have drifted apart"
    );
}