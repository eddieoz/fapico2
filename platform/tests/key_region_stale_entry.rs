//! US-1729: **an index entry only names a record it was written for** — every
//! locator compares the entry's stored generation with the record header's
//! generation before serving the slot.
//!
//! ```gherkin
//! Feature: An index entry only names a record it was written for
//!   Scenario: A torn commit's recycled slot is not served through its stale entry
//!     Given a slot that served generation N and lost its header (torn commit)
//!     And its index entry still authenticates (device-rooted, PIN-free)
//!     When the slot is re-allocated at generation 1 for a new credential
//!     Then RP discovery lists the new credential exactly once (via its own entry, not the stale one)
//!     And a by-ID probe for the OLD credential answers absent
//!   Scenario: Live entries are unaffected
//!     Given an intact region
//!     When discovery and by-ID lookups run
//!     Then every result equals the pre-change behavior
//! ```
//!
//! # The torn-state mechanics the fixture builds
//!
//! The state is the one `fido_store.rs`'s allocator docs document ("This
//! allocator is stateless, so it cannot remember a generation for a slot whose
//! header no longer parses"): a slot served generation *N* and lost its header
//! to a torn commit, and its index entry — MAC-bound over the entry's *own*
//! `(domain, slot, generation)` — still authenticates, because entry
//! authentication is device-rooted and PIN-free and never consults the record.
//! The fixture builds it with the store's own operations: enrol (gen 1), a
//! counter-style `update` (gen 2, entry rewritten in place to gen 2), then the
//! header destroyed by programming zeros over it — the NOR-legal half of a torn
//! commit. The allocator now sees an unoccupied slot and re-issues it at
//! generation 1 for a *new* credential, whose entry lands in a fresh cell.
//! The index then holds two authentic entries for one RP: a stale one
//! claiming gen 2 and the live one claiming gen 1 — and before US-1729 nothing
//! compared either against the header ("Named honestly: nothing currently
//! compares the two", `fido_store.rs`).
//!
//! # What the stale entry did before the fix (observed RED)
//!
//! RP discovery (`slots_for_rp`) listed the recycled slot **twice** — once
//! through the stale entry and once through its own. The by-ID probe for the
//! old credential answered `Absent` already (the probe opens the record and
//! compares IDs, and the ID is gone); the pin stays so the fix cannot turn that
//! absence into a `Fault` (US-1573: a stale entry is absence, not a fault).
//!
//! # What the fix does not change
//!
//! The entry's own authentication is untouched (`index.rs`, `IndexEntry::verify`
//! — device-rooted, PIN-free). The generation comparison is a second, semantic
//! check made *after* the slot opens, and it lives in the locators, not in
//! US-1724's last-match walk: this story decides **whether a candidate counts**,
//! not which match wins.

use std::path::{Path, PathBuf};

use fapico2_platform::ckey;
use fapico2_platform::keyregion::crypto::{self, IndexKey, PayloadKey};
use fapico2_platform::keyregion::fido_store::{CredentialProbe, FidoRecordStore};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::index::RpIdHash;
use fapico2_platform::keyregion::on_demand::CredentialWindow;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::{KeyRegion, Slot, SlotRead, TOTAL_SLOTS};

// ---------------------------------------------------------------------------
// Fixtures — the region-file + keys + put pattern of key_region_fido_locator
// ---------------------------------------------------------------------------

/// A region file in the host temp directory, removed on drop.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-us1729-{}-{tag}.bin", std::process::id()));
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
    let serial = ckey::serial_hash(b"fapico2 us1729 stale entry test");
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

/// A deterministic `rp_id_hash` stand-in, one per id.
fn rp_hash(id: u8) -> RpIdHash {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = id.wrapping_mul(31).wrapping_add(i as u8);
    }
    RpIdHash::from_bytes(h)
}

/// A fresh GCM nonce for the `n`-th write — unique per write, which
/// `record::seal` requires.
fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"us1729 nonce!"[..record::NONCE_LEN - 4]);
    out
}

/// A record body the probe can identify: the credential ID followed by one
/// distinguishing byte. The body is opaque to the store, so a marker byte is
/// the honest stand-in for the key and counter that differ between two
/// credentials.
fn body(id: &[u8], marker: u8) -> Vec<u8> {
    let mut v = id.to_vec();
    v.push(marker);
    v
}

/// Two-byte IDs: distinct, and neither a prefix of another, so the probe's
/// whole-ID comparison cannot alias across credentials.
const ID_OLD: &[u8] = &[0x0B, 0x0E];
const ID_NEW: &[u8] = &[0x0F, 0x0E];
const ID_LIVE_A: &[u8] = &[0xA0, 0x01];
const ID_LIVE_B: &[u8] = &[0xB0, 0x02];

/// The probe the locator is handed: the plaintext **is** the credential when it
/// starts with the whole wanted ID and carries at least one byte after it — the
/// same whole-ID claim `key_region_fido_locator.rs`'s probe makes.
struct IdProbe;

impl CredentialProbe for IdProbe {
    fn matches(&self, plaintext: &[u8], credential_id: &[u8]) -> bool {
        plaintext.len() > credential_id.len() && plaintext.starts_with(credential_id)
    }
}

/// Enrol one credential and answer with its slot.
fn put(
    store: &mut FidoRecordStore<'_>,
    rp: &RpIdHash,
    id: &[u8],
    marker: u8,
    n: u32,
) -> Slot {
    store
        .put(&payload_key(), &index_key(), &nonce(n), rp, &body(id, marker))
        .unwrap_or_else(|e| panic!("credential {id:?} must enrol: {e}"))
        .slot
}

/// Resolve one ID through the store's by-ID load and answer the slot it
/// selected together with the plaintext now in the window.
fn resolve(
    store: &mut FidoRecordStore<'_>,
    rp: &RpIdHash,
    id: &[u8],
    window: &mut CredentialWindow,
) -> SlotRead<(Slot, Vec<u8>)> {
    match store.load_by_credential_id(&payload_key(), &index_key(), Some(rp), id, &IdProbe, window)
    {
        SlotRead::Present(hit) => SlotRead::Present((hit.slot(), window.as_slice().to_vec())),
        SlotRead::Absent => SlotRead::Absent,
        SlotRead::Fault(why) => SlotRead::Fault(why),
    }
}

/// Destroy a record header the way a torn commit does: program zeros over the
/// page that carries it. NOR-legal (only bits clear), and `RecordHeader::parse`
/// refuses the result, so occupancy and `record::decode` both read the slot as
/// empty — exactly the state the allocator's torn-path paragraph describes.
fn tear_header(region: &mut FileKeyRegion, slot: Slot) {
    region
        .program(slot, 0, &[0u8; fapico2_platform::keyregion::host::PAGE_BYTES])
        .expect("programming zeros over the header page is NOR-legal");
}

// ---------------------------------------------------------------------------
// Scenario 1 — the recycled slot is not served through its stale entry
// ---------------------------------------------------------------------------

/// The torn-commit state: a stale entry claiming generation 2 and a live entry
/// claiming generation 1, both authentic, both naming the same slot.
///
/// Discovery must list the new credential **once** — through its own entry —
/// and the old credential must be *absent*, never faulted.
#[test]
fn a_torn_commits_recycled_slot_is_not_served_through_its_stale_entry() {
    let tmp = TempRegion::new("torn");
    let mut region = FileKeyRegion::create(tmp.path(), TOTAL_SLOTS)
        .expect("the temp region file is creatable");
    let rp = rp_hash(1);

    let torn_slot = {
        let mut store = FidoRecordStore::new(&mut region);
        let slot = put(&mut store, &rp, ID_OLD, 0x01, 1);
        // Advance the slot to generation 2 the way a durable counter write
        // does — the entry is rewritten in place to gen 2, so after the tear
        // the stale entry claims a generation the new record cannot carry.
        let rep = store
            .update(&payload_key(), &index_key(), slot, &nonce(2), &rp, &body(ID_OLD, 0x02))
            .expect("the update must commit");
        assert_eq!(rep.generation, 2, "premise: the update advanced the record to generation 2");
        slot
    };

    // The torn commit: the header is gone, the entry survives.
    tear_header(&mut region, torn_slot);

    let mut store = FidoRecordStore::new(&mut region);
    assert_eq!(
        store.record_generation(torn_slot).expect("the region reads"),
        0,
        "premise: the header is destroyed — the slot reads as empty"
    );

    // The slot is re-allocated at generation 1 for a NEW credential, whose own
    // entry lands in a fresh cell.
    let rep = store
        .put(&payload_key(), &index_key(), &nonce(3), &rp, &body(ID_NEW, 0x03))
        .expect("the new credential must enrol");
    assert_eq!(
        rep.slot, torn_slot,
        "premise: the allocator recycles the torn slot (lowest free slot)"
    );
    assert_eq!(
        rep.generation, 1,
        "premise: the recycled slot is re-allocated at generation 1"
    );

    // Premise: two entries for this RP now authenticate — the stale one (gen 2)
    // and the live one (gen 1). This is the hazard: both pass the index's own
    // tag check, which binds the entry's *own* generation. Read through the
    // raw `index::lookup_all`, which reports authenticated entries without the
    // US-1729 comparison — the instrument, not the behaviour under test.
    let mut probe = [Slot::new(0).expect("slot 0 exists"); 16];
    let before = match fapico2_platform::keyregion::index::lookup_all(
        &index_key(),
        store.region(),
        fapico2_platform::keyregion::crypto::KeyDomain::Fido,
        &rp,
        &mut probe,
    ) {
        SlotRead::Present(n) => n,
        other => panic!("the fixture's index is readable: {other:?}"),
    };
    assert_eq!(
        before, 2,
        "premise: the index holds both the stale and the live entry for this RP"
    );

    // **The fix under test**: discovery lists the new credential exactly once,
    // via its own entry — the stale entry names a record that no longer exists
    // in that slot and is skipped (Absent), never faulted.
    let mut slots = [Slot::new(0).expect("slot 0 exists"); 16];
    match store.slots_for_rp(&index_key(), &rp, &mut slots) {
        SlotRead::Present(n) => {
            assert_eq!(
                n, 1,
                "RP discovery must list the recycled credential exactly once — the stale entry is \
                 not a second credential"
            );
            assert_eq!(
                &slots[..n],
                &[torn_slot],
                "the one listed slot is the recycled slot, via its own (generation-matched) entry"
            );
        }
        other => panic!("discovery must succeed on a region with one stale entry: {other:?}"),
    }

    // A by-ID probe for the OLD credential answers absent — **Absent, not
    // Fault** (US-1573: a stale entry is absence, not a fault).
    let mut window = CredentialWindow::new();
    match resolve(&mut store, &rp, ID_OLD, &mut window) {
        SlotRead::Absent => {}
        SlotRead::Fault(why) => {
            panic!("a stale entry is absence, not a fault (US-1573): {why}")
        }
        SlotRead::Present((slot, _)) => {
            panic!(
                "the old credential's record no longer exists; the stale entry must not serve \
                 slot {slot:?} for it"
            )
        }
    }

    // And the new credential is still served: through by-ID, and through
    // `load_by_rp`, which must reach it past the stale first entry.
    match resolve(&mut store, &rp, ID_NEW, &mut window) {
        SlotRead::Present((slot, plaintext)) => {
            assert_eq!(slot, torn_slot, "the new credential lives in the recycled slot");
            assert_eq!(plaintext, body(ID_NEW, 0x03), "the record served is the new one");
        }
        other => panic!("the new credential must resolve: {other:?}"),
    }
    match store.load_by_rp(&payload_key(), &index_key(), &rp, &mut window) {
        SlotRead::Present(_) => {
            assert_eq!(
                window.as_slice(),
                &body(ID_NEW, 0x03)[..],
                "load_by_rp must serve the new credential, not fail or serve nothing, because the \
                 first entry in index order is the stale one"
            );
        }
        other => panic!("load_by_rp must reach the live entry past the stale one: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Scenario 2 — live entries are unaffected
// ---------------------------------------------------------------------------

/// An intact region behaves exactly as before the change: discovery lists each
/// credential once, by-ID resolves each, `load_by_rp` serves, and a *live*
/// entry whose generation advanced with its record (the `update` path) still
/// matches — the comparison is against the header, and a live rewrite moves
/// both together.
#[test]
fn live_entries_are_unaffected() {
    let tmp = TempRegion::new("live");
    let mut region = FileKeyRegion::create(tmp.path(), TOTAL_SLOTS)
        .expect("the temp region file is creatable");
    let rp = rp_hash(7);
    let other = rp_hash(8);

    let (slot_a, slot_b, slot_other) = {
        let mut store = FidoRecordStore::new(&mut region);
        let a = put(&mut store, &rp, ID_LIVE_A, 0x0A, 1);
        let b = put(&mut store, &rp, ID_LIVE_B, 0x0B, 2);
        let o = put(&mut store, &other, ID_OLD, 0x0C, 3);
        // A live generation advance: entry and record move together.
        let rep = store
            .update(&payload_key(), &index_key(), a, &nonce(4), &rp, &body(ID_LIVE_A, 0x0D))
            .expect("the update must commit");
        assert_eq!(rep.generation, 2, "premise: the update advanced the record to generation 2");
        (a, b, o)
    };

    let mut store = FidoRecordStore::new(&mut region);

    // Discovery: each RP's credentials, once each.
    let mut slots = [Slot::new(0).expect("slot 0 exists"); 16];
    match store.slots_for_rp(&index_key(), &rp, &mut slots) {
        SlotRead::Present(n) => {
            assert_eq!(n, 2, "two live credentials of one RP, listed once each");
            let mut listed = slots[..2].to_vec();
            listed.sort_by_key(|s| s.index());
            assert_eq!(listed, vec![slot_a, slot_b]);
        }
        other => panic!("discovery must succeed: {other:?}"),
    }
    let mut slots = [Slot::new(0).expect("slot 0 exists"); 16];
    match store.slots_for_rp(&index_key(), &other, &mut slots) {
        SlotRead::Present(n) => {
            assert_eq!(n, 1, "the other RP's credential, once");
            assert_eq!(slots[0], slot_other);
        }
        other => panic!("discovery must succeed: {other:?}"),
    }

    // By-ID: every credential resolves to its own slot and plaintext, including
    // the one whose generation advanced to 2 under a matching entry.
    let mut window = CredentialWindow::new();
    for (slot, id, marker) in
        [(slot_a, ID_LIVE_A, 0x0D), (slot_b, ID_LIVE_B, 0x0B), (slot_other, ID_OLD, 0x0C)]
    {
        let rp = if id == ID_OLD { &other } else { &rp };
        match resolve(&mut store, rp, id, &mut window) {
            SlotRead::Present((found, plaintext)) => {
                assert_eq!(found, slot, "credential {id:?} resolves to its own slot");
                assert_eq!(plaintext, body(id, marker), "credential {id:?} serves its own body");
            }
            other => panic!("credential {id:?} must resolve: {other:?}"),
        }
    }

    // load_by_rp: served, once per RP.
    for (rp, id, marker) in
        [(&rp, ID_LIVE_A, 0x0D), (&rp, ID_LIVE_B, 0x0B), (&other, ID_OLD, 0x0C)]
    {
        match store.load_by_rp(&payload_key(), &index_key(), rp, &mut window) {
            SlotRead::Present(_) => {}
            other => panic!("load_by_rp must serve {id:?}: {other:?}"),
        }
        let _ = marker;
    }
}
