//! US-1724: **by-ID credential resolution prefers the newest record** — one
//! ordering rule for discovery, overwrite and the by-ID locator.
//!
//! ```gherkin
//! Feature: Duplicate-ID resolution prefers the newest record, like discovery and like overwrite
//!   Scenario: The last-written match wins
//!     Given a region fixture with two same-ID records, old then new in index order
//!     When the by-ID locator resolves the ID
//!     Then it returns the newer record's slot (index-order last match)
//!   Scenario: Uniqueness is unchanged when no duplicates exist
//!     Given a fixture with distinct IDs
//!     When the locator resolves each ID
//!     Then every resolution equals the pre-change behavior
//! ```
//!
//! # Why the ordering rule lives here
//!
//! `CredentialIdLocator::locate` walked its candidates in index order and
//! returned on the **first** probe hit — which, for a legacy board carrying two
//! same-ID records, is the **oldest** copy. Discovery enumerates both and
//! overwrite (US-1722) replaces the newest, so the by-ID probe was the one
//! reader left disagreeing about which record *is* the credential. After
//! US-1723 the app-level match step signs what discovery found; this story
//! makes the locator itself agree: the walk continues past a hit and the
//! **last** hit — index-order last, which on a fresh region is the newest
//! written — is returned. Post-US-1722 no new duplicates accumulate; this rule
//! governs legacy boards mid-upgrade (see the comment at the walk).
//!
//! # What the fault tests pin
//!
//! The last-match walk changes which candidates are *reached* — a candidate
//! after the first hit is probed only after this story. Two tests pin the fault
//! semantics the walk keeps, decided from the code's error model and
//! documented at the implementation:
//!
//! * [`a_hit_survives_a_later_candidate_fault`] — a hit is a **proven** fact
//!   (that record was opened and its ID matched), so a later unreadable
//!   candidate cannot retroactively unprove it; the walk aborts there and
//!   returns the hit in hand rather than `Fault`. `Located::Fault` means "the
//!   search could not be completed and nothing was decided"; discarding a
//!   proven answer would turn one sick slot into a failed lookup for a
//!   credential the device verifiably holds.
//! * [`a_fault_before_any_hit_is_still_a_fault`] — today's meaning, preserved:
//!   a fault on a candidate with no hit yet propagates as [`SlotRead::Fault`]
//!   (US-1573: a faulted read must never memoize as "absent").
//!
//! # Fixture premise, asserted not assumed
//!
//! "Old then new in index order" is a claim about two orderings agreeing —
//! allocation (lowest free slot) and index placement (first free cell) — so the
//! duplicate test asserts the candidate list `index::lookup_all` returns really
//! is `[old, decoy, new]` before asserting which of them the locator picks. A
//! fixture whose premise failed silently would make the RED/GREEN story
//! meaningless.

use std::path::{Path, PathBuf};

use fapico2_platform::ckey;
use fapico2_platform::keyregion::crypto::{self, IndexKey, KeyDomain, PayloadKey};
use fapico2_platform::keyregion::fido_store::{CredentialProbe, FidoRecordStore};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::index::{self, RpIdHash};
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::slotmap::SlotImage;
use fapico2_platform::keyregion::{KeyRegion, Slot, SlotRead, TOTAL_SLOTS};

// ---------------------------------------------------------------------------
// Fixtures — the region-file + keys + put pattern of key_region_counter_budget
// ---------------------------------------------------------------------------

/// A region file in the host temp directory, removed on drop.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-us1724-{}-{tag}.bin", std::process::id()));
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

/// The device-rooted OTP row. Non-zero, because `crypto::derive_otp_root`
/// refuses an all-zero row rather than return a constant root.
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

/// A PIN-derived secret, made the way an applet makes one, so the fixture is
/// the same key hierarchy the device would use.
fn pin_secret() -> [u8; 32] {
    let row = otp_row();
    let serial = ckey::serial_hash(b"fapico2 us1724 locator order test");
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

/// One RP for the whole file: the duplicate story is about IDs colliding under
/// one RP, which is the shape a legacy board's deterministic-ID re-registration
/// produced.
fn rp_hash() -> RpIdHash {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(0x41);
    }
    RpIdHash::from_bytes(h)
}

/// A fresh GCM nonce for the `n`-th write — unique per write, which
/// `record::seal` requires.
fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"us1724 nonce!"[..record::NONCE_LEN - 4]);
    out
}

/// A record body the probe can identify: the credential ID followed by one
/// distinguishing byte. The trailing byte is what makes two same-ID records
/// ("old" and "new") distinguishable plaintexts, standing in for the key and
/// counter that differ between a legacy board's two copies — the body is
/// opaque to the store, so a marker byte is the honest stand-in for them.
fn body(id: &[u8], marker: u8) -> Vec<u8> {
    let mut v = id.to_vec();
    v.push(marker);
    v
}

/// Two-byte IDs: distinct, and neither a prefix of another, so the probe's
/// whole-ID comparison cannot alias across credentials.
const ID_DUP: &[u8] = &[0xD0, 0x0D];
const ID_DECOY: &[u8] = &[0xE0, 0x0E];
const ID_UNIQUE_A: &[u8] = &[0xA0, 0x01];
const ID_UNIQUE_B: &[u8] = &[0xB0, 0x02];
const ID_UNIQUE_C: &[u8] = &[0xC0, 0x03];

/// The probe the locator is handed: the plaintext **is** the credential when it
/// starts with the whole wanted ID and carries at least one byte after it. The
/// length guard is the whole-ID claim `CredentialProbe::matches` documents — a
/// record whose body *is* the ID alone must not match.
struct IdProbe;

impl CredentialProbe for IdProbe {
    fn matches(&self, plaintext: &[u8], credential_id: &[u8]) -> bool {
        plaintext.len() > credential_id.len() && plaintext.starts_with(credential_id)
    }
}

/// A [`FileKeyRegion`] with one slot poisoned for **reads** — the transport
/// fault a locator walk has to survive or report, injected per slot so the rest
/// of the fixture keeps working.
struct PoisonedReader {
    inner: FileKeyRegion,
    poison: Option<u16>,
}

impl PoisonedReader {
    fn new(path: &Path) -> Self {
        PoisonedReader {
            inner: FileKeyRegion::create(path, TOTAL_SLOTS)
                .expect("the temp region file is creatable"),
            poison: None,
        }
    }

    /// Arm (or disarm) the poison. Off during setup, so writes and the
    /// allocator's scans are unaffected; on for the lookup under test.
    fn poison(&mut self, slot_index: Option<u16>) {
        self.poison = slot_index;
    }
}

impl KeyRegion for PoisonedReader {
    fn read_slot(&mut self, slot: Slot) -> Result<SlotImage, &'static str> {
        if self.poison == Some(slot.index()) {
            return Err("us1724: poisoned slot");
        }
        self.inner.read_slot(slot)
    }

    fn erase_sector(&mut self, slot: Slot) -> Result<(), &'static str> {
        self.inner.erase_sector(slot)
    }

    fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        self.inner.program(slot, offset, data)
    }

    fn slots(&self) -> u32 {
        self.inner.slots()
    }
}

/// Enrol one credential and answer with its slot.
fn put(store: &mut FidoRecordStore<'_>, id: &[u8], marker: u8, n: u32) -> Slot {
    store
        .put(&payload_key(), &index_key(), &nonce(n), &rp_hash(), &body(id, marker))
        .unwrap_or_else(|e| panic!("credential {id:?} must enrol: {e}"))
        .slot
}

/// The RP-qualified candidate list, in index order — the fixture-premise
/// instrument. `store` borrows the region the records were written to, so the
/// list is the walk the locator itself starts from.
fn candidates_for(store: &mut FidoRecordStore<'_>) -> Vec<Slot> {
    let mut out = [Slot::new(0).expect("slot 0 exists"); 16];
    match index::lookup_all(
        &index_key(),
        store.region(),
        KeyDomain::Fido,
        &rp_hash(),
        &mut out,
    ) {
        SlotRead::Present(n) => out[..n].to_vec(),
        other => panic!("the fixture's index is readable: {other:?}"),
    }
}

/// Resolve one ID through the store's by-ID load and answer the slot it
/// selected together with the plaintext now in the window.
fn resolve(
    store: &mut FidoRecordStore<'_>,
    rp: Option<&RpIdHash>,
    id: &[u8],
    window: &mut CredentialWindow,
) -> SlotRead<(Slot, Vec<u8>)> {
    match store.load_by_credential_id(&payload_key(), &index_key(), rp, id, &IdProbe, window) {
        SlotRead::Present(hit) => SlotRead::Present((hit.slot(), window.as_slice().to_vec())),
        SlotRead::Absent => SlotRead::Absent,
        SlotRead::Fault(why) => SlotRead::Fault(why),
    }
}

// ---------------------------------------------------------------------------
// Scenario 1 — the last-written match wins (RED before US-1724)
// ---------------------------------------------------------------------------

/// Two same-ID records, old then new in index order, with a different-ID decoy
/// between them: the locator resolves the ID to the **newer** record's slot,
/// through both the RP-qualified walk and the RP-less structural walk.
#[test]
fn the_last_written_match_wins() {
    let tmp = TempRegion::new("last-wins");
    let mut region = PoisonedReader::new(tmp.path());
    let (old_slot, decoy_slot, new_slot) = {
        let mut store = FidoRecordStore::new(&mut region);
        // Old duplicate, then a different-ID decoy, then the newer duplicate —
        // so the winning walk really has to keep going past a non-matching
        // candidate rather than merely falling off the end of the list.
        let old = put(&mut store, ID_DUP, 0x01, 1);
        let decoy = put(&mut store, ID_DECOY, 0x02, 2);
        let new = put(&mut store, ID_DUP, 0x03, 3);
        (old, decoy, new)
    };

    // Premise: allocation (lowest free slot) and index placement (first free
    // cell) agree, so the candidate list is `[old, decoy, new]` — the premise
    // the gherkin's "old then new in index order" rests on.
    let mut store = FidoRecordStore::new(&mut region);
    assert!(
        old_slot.index() < new_slot.index(),
        "the fixture premise broke: allocation is lowest-free-slot, so the older put must own the \
         lower slot ({old_slot:?} vs {new_slot:?})"
    );
    assert_eq!(
        candidates_for(&mut store),
        vec![old_slot, decoy_slot, new_slot],
        "the fixture premise broke: index::lookup_all must list the records old-then-new for the \
         ordering rule to be tested at all"
    );

    let mut window = CredentialWindow::new();

    // The RP-qualified branch.
    match resolve(&mut store, Some(&rp_hash()), ID_DUP, &mut window) {
        SlotRead::Present((slot, plaintext)) => {
            assert_eq!(
                slot, new_slot,
                "a by-ID probe must resolve a duplicate ID to the newest record (index-order last), \
                 not the oldest copy the first-match walk returned"
            );
            assert_eq!(
                plaintext,
                body(ID_DUP, 0x03),
                "the record loaded must be the newer copy — the marker byte distinguishes the two \
                 same-ID records"
            );
        }
        other => panic!("the duplicate ID must resolve, got {other:?}"),
    }

    // The structural (RP-less) branch — the same rule, its own walk.
    match resolve(&mut store, None, ID_DUP, &mut window) {
        SlotRead::Present((slot, plaintext)) => {
            assert_eq!(
                slot, new_slot,
                "the RP-less structural walk must answer with the newest same-ID record too — one \
                 ordering rule for both locator branches"
            );
            assert_eq!(plaintext, body(ID_DUP, 0x03));
        }
        other => panic!("the duplicate ID must resolve without an RP, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Scenario 2 — uniqueness is unchanged when no duplicates exist
// ---------------------------------------------------------------------------

/// Distinct IDs each resolve to their own record, through both walks — the
/// behavior before and after the ordering change is identical when there is
/// nothing to order.
#[test]
fn uniqueness_is_unchanged_when_no_duplicates_exist() {
    let tmp = TempRegion::new("unique");
    let mut region = PoisonedReader::new(tmp.path());
    let mut store = FidoRecordStore::new(&mut region);
    let slot_a = put(&mut store, ID_UNIQUE_A, 0x11, 1);
    let slot_b = put(&mut store, ID_UNIQUE_B, 0x22, 2);
    let slot_c = put(&mut store, ID_UNIQUE_C, 0x33, 3);

    // Premise: three records, three distinct index candidates, in write order.
    assert_eq!(
        candidates_for(&mut store),
        vec![slot_a, slot_b, slot_c],
        "the no-duplicates fixture must hold exactly the three records it enrolled"
    );

    let expected = [
        (ID_UNIQUE_A, slot_a, 0x11u8),
        (ID_UNIQUE_B, slot_b, 0x22),
        (ID_UNIQUE_C, slot_c, 0x33),
    ];
    let mut window = CredentialWindow::new();
    for (id, slot, marker) in expected {
        for rp in [Some(&rp_hash()), None] {
            match resolve(&mut store, rp, id, &mut window) {
                SlotRead::Present((found, plaintext)) => {
                    assert_eq!(
                        found, slot,
                        "ID {id:?} must resolve to its own record (through {} walk) — distinct IDs \
                         have exactly one answer and the ordering rule may not move it",
                        if rp.is_some() { "the RP-qualified" } else { "the structural" }
                    );
                    assert_eq!(
                        plaintext,
                        body(id, marker),
                        "ID {id:?} must load its own body, not a sibling's"
                    );
                }
                other => panic!("ID {id:?} must resolve ({rp:?} walk), got {other:?}"),
            }
        }
    }

    // An ID nobody issued is absent through both walks — unchanged too.
    for rp in [Some(&rp_hash()), None] {
        assert_eq!(
            resolve(&mut store, rp, ID_DUP, &mut window),
            SlotRead::Absent,
            "an unknown ID stays absent ({} walk)",
            if rp.is_some() { "RP-qualified" } else { "structural" }
        );
    }
}

// ---------------------------------------------------------------------------
// Fault semantics the last-match walk keeps (documented at the walk)
// ---------------------------------------------------------------------------

/// A hit followed by a later unreadable candidate returns the **hit in hand**,
/// not a fault: the hit is a proven fact, and the walk aborts at the fault
/// rather than keep probing a region whose transport just lied.
///
/// Passes before this story too (the first-match walk never reached the poisoned
/// candidate); it pins the choice the last-match walk had to make explicit.
#[test]
fn a_hit_survives_a_later_candidate_fault() {
    let tmp = TempRegion::new("hit-then-fault");
    let mut region = PoisonedReader::new(tmp.path());
    let (old_slot, decoy_slot, _new_slot) = {
        let mut store = FidoRecordStore::new(&mut region);
        let old = put(&mut store, ID_DUP, 0x01, 1);
        let decoy = put(&mut store, ID_DECOY, 0x02, 2);
        let new = put(&mut store, ID_DUP, 0x03, 3);
        (old, decoy, new)
    };

    // Arm the poison before the store borrows the region.
    region.poison(Some(decoy_slot.index()));
    let mut store = FidoRecordStore::new(&mut region);

    let mut window = CredentialWindow::new();
    match resolve(&mut store, Some(&rp_hash()), ID_DUP, &mut window) {
        SlotRead::Present((slot, plaintext)) => {
            assert_eq!(
                slot, old_slot,
                "with the walk aborting at the faulted candidate, the answer is the newest hit \
                 reached before it — the older duplicate, not a fault"
            );
            assert_eq!(plaintext, body(ID_DUP, 0x01));
        }
        other => panic!(
            "a proven hit must not be discarded because a LATER candidate faulted: {other:?}"
        ),
    }
}

/// A fault on a candidate with **no hit yet** is still a fault — today's
/// meaning, preserved (US-1573: a faulted read must never memoize as "absent").
///
/// Passes before and after; it guards the rewritten walk against quietly
/// turning the fault into `Absent` while reordering it.
#[test]
fn a_fault_before_any_hit_is_still_a_fault() {
    let tmp = TempRegion::new("fault-no-hit");
    let mut region = PoisonedReader::new(tmp.path());
    let (old_slot, _decoy_slot, _new_slot) = {
        let mut store = FidoRecordStore::new(&mut region);
        let old = put(&mut store, ID_DUP, 0x01, 1);
        let decoy = put(&mut store, ID_DECOY, 0x02, 2);
        let new = put(&mut store, ID_DUP, 0x03, 3);
        (old, decoy, new)
    };

    // Poison the FIRST candidate: the walk faults before any hit exists. Arm
    // the poison before the store borrows the region.
    region.poison(Some(old_slot.index()));
    let mut store = FidoRecordStore::new(&mut region);

    let mut window = CredentialWindow::new();
    match resolve(&mut store, Some(&rp_hash()), ID_DUP, &mut window) {
        SlotRead::Fault(_) => {}
        other => panic!(
            "a fault before any hit must propagate as Fault, never degrade to absent or a guess: \
             {other:?}"
        ),
    }
}
