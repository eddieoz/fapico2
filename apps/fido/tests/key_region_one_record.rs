//! US-1552 — "enrolling touches one record", against the per-record key region.
//!
//! ```gherkin
//! Scenario: enrolling touches one record
//!   Given a region holding four credentials
//!   When a fifth is enrolled
//!   Then exactly one slot is erased and programmed
//!   And the other four are untouched
//!   And the operation commits or rolls back cleanly, never latching dirty state
//! ```
//!
//! # Which path this exercises, and which it deliberately does not
//!
//! Everything here drives `fapico2_platform::keyregion::fido_store` over a
//! [`FileKeyRegion`], which models NOR honestly: `program` ANDs into what is
//! there and **refuses** a 0 → 1 transition, `erase_sector` clears a whole
//! 4 KiB sector, and neither is a `Vec` assignment (`host.rs`, "Why a stand-in
//! that lies is worse than no stand-in"). A byte pattern a real part could not
//! hold would fail here rather than pass.
//!
//! It does **not** drive `device_core.rs`. The device command path cannot reach
//! this store yet: the only `KeyRegion` implementation in the tree is the host
//! file region, and a QSPI-backed one would have to be constructed from
//! `firmware/src/boot.rs`'s `FLASH_DEV` static — a file this story does not own.
//! The applet-side wiring (the on-demand read path through `get_credential`,
//! `getAssertion`'s candidate list and the credMgmt enumeration) is US-1554's
//! follow-through, and `apps/fido/tests/key_store_ceiling.rs` is deliberately
//! left asserting what the *snapshot* backend still does.
//!
//! # What each gherkin clause is pinned by
//!
//! | clause | test |
//! |---|---|
//! | a fifth credential enrols | [`a_fifth_credential_enrolls_where_the_snapshot_backend_refused_it`] |
//! | exactly one slot erased and programmed | [`enrolling_erases_one_live_sector`] |
//! | the other four untouched | [`the_other_four_credentials_are_byte_identical_afterwards`] |
//! | commits or rolls back cleanly | [`a_failed_commit_rolls_back_and_leaves_no_staged_bytes`] |
//! | never latching dirty state | [`a_failed_put_latches_nothing_and_the_store_still_works`] |
//!
//! Plus the two constraints the brief made non-negotiable: an unreadable region
//! **degrades** ([`an_unreadable_region_degrades_and_never_reads_as_empty`]) and
//! the **boot path does not touch the region**
//! ([`constructing_a_store_reads_nothing`]).

use std::path::{Path, PathBuf};

use fapico2_platform::keyregion::crypto::{self, IndexKey, PayloadKey};

/// How many credentials the enrolling tests have already written before the
/// one under test. Written as a constant rather than repeated as `4` because
/// the slot number is now relative to FIDO's range: a bare 4 here would be
/// slot 4 of the region, which is OATH's.
const ENROLLED_BEFORE: u32 = 4;
use fapico2_platform::keyregion::fido_store::{
    self, CredentialProbe, FidoRecordStore, FidoStoreError, SCRATCHPAD_FIRST_SLOT,
};
use fapico2_platform::keyregion::host::{Faults, FileKeyRegion};
use fapico2_platform::keyregion::index::{self, RpIdHash};
use fapico2_platform::keyregion::on_demand::{self, CredentialWindow, OnDemandHit};
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::slotmap::{is_erased, SlotImage};
use fapico2_platform::keyregion::{
    KeyRegion, Slot, SlotRead, FIDO_CAPACITY, FIDO_RECORD_MAX, SLOTS_PER_SECTOR, TOTAL_SLOTS,
};

/// The region's whole geometry.
///
/// Every test uses the **full** region, not a short stand-in, because two of the
/// assertions are about capacity and the index reservation: a short file would
/// move `region.slots()` and therefore what the allocator can reach
/// (`slotmap::scan_bound_for`, "Why the bound is `TOTAL_SLOTS`").
const REGION_SLOTS: u32 = TOTAL_SLOTS;

/// The four the reported defect reached, and the fifth it refused.
const FOUR: u8 = 4;
const FIVE: u8 = 5;

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
            std::env::temp_dir().join(format!("fapico2-us1552-{}-{tag}.bin", std::process::id()));
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

/// The device-rooted OTP row the region's two keys descend from.
///
/// Not a secret in this file — it is the fixture's identity. What matters is
/// that it is **not** all zeros, because `crypto::derive_otp_root` returns `None`
/// for a zero row rather than a constant root ("`None` on an all-zero OTP row
/// and on nothing else"), and a zero-row fixture would be testing a function
/// that refuses to answer.
fn otp_row() -> [u8; 32] {
    let mut row = [0u8; 32];
    for (i, b) in row.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(0x11);
    }
    row
}

fn chip_id() -> [u8; 8] {
    [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
}

/// The PIN-derived secret mixed into the payload key.
///
/// `crypto::derive_payload_key` takes already-derived material, not a PIN, on
/// purpose ("Why the root is not a substitute for the PIN secret"), so this
/// stands in for whatever the applet's verifier produced.
fn pin_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(0x5a);
    }
    s
}

fn keys() -> (IndexKey, PayloadKey) {
    let row = otp_row();
    let index_key = crypto::derive_index_key(&row, &chip_id()).expect("a non-zero OTP row");
    let payload_key =
        crypto::derive_payload_key(&row, &chip_id(), &pin_secret()).expect("a non-zero OTP row");
    (index_key, payload_key)
}

/// An RP hash for credential `n`, distinct per credential.
///
/// The bytes need not be a real `SHA-256` here: they are the *message* an index
/// entry's MAC is made over, so what matters is that they differ and that no two
/// credentials share one — which is what would make an enumeration ambiguous.
fn rp_hash(n: u8) -> RpIdHash {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = n.wrapping_mul(37).wrapping_add(i as u8).wrapping_add(3);
    }
    RpIdHash::from_bytes(h)
}

/// A GCM nonce for the `n`-th write.
///
/// Unique per put, which is what [`record::seal`] requires and what this file
/// holds itself to rather than assuming. A repeated nonce under one key is
/// catastrophic for GCM, and the store deliberately does not derive nonces —
/// `FidoRecordStore::put`'s docs say why.
fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"us1552nonce!!"[..record::NONCE_LEN - 4]);
    out
}

/// The plaintext standing in for one credential record.
///
/// Shaped like the real thing — an opaque blob, because what the store seals is
/// whatever CBOR map `device_keystore.rs` produced and the store must have no
/// opinion about its layout (`fido_store.rs`, `CredentialProbe`'s docs). Its
/// length sits well under [`FIDO_RECORD_MAX`], so a capacity failure here would
/// be a store bug rather than an oversized fixture.
fn credential_plaintext(n: u8) -> Vec<u8> {
    let mut v = vec![0u8; 400];
    for (i, b) in v.iter_mut().enumerate() {
        *b = n.wrapping_mul(11).wrapping_add(i as u8);
    }
    // A recognisable prefix, so a by-ID lookup can say *which* record it found.
    v[..9].copy_from_slice(b"CRED-ID--");
    v[8] = n;
    v
}

/// A probe that recognises this file's fixture records by their 9-byte prefix.
struct PrefixProbe;

impl CredentialProbe for PrefixProbe {
    fn matches(&self, plaintext: &[u8], credential_id: &[u8]) -> bool {
        plaintext.len() >= 9 && plaintext.starts_with(credential_id)
    }
}

fn slot(index: u16) -> Slot {
    Slot::new(index).expect("every index in this file is inside the region")
}

/// Enrol credential `n` and return where it landed.
fn enroll(
    store: &mut FidoRecordStore<'_>,
    index_key: &IndexKey,
    payload_key: &PayloadKey,
    n: u8,
) -> fido_store::PutReport {
    store
        .put(payload_key, index_key, &nonce(n as u32), &rp_hash(n), &credential_plaintext(n))
        .unwrap_or_else(|e| panic!("credential {n} must enrol: {e}"))
}

/// Every FIDO slot's bytes, indexed by slot number — the "are the other four
/// untouched" fixture.
///
/// Taken over FIDO's whole range rather than over the four records, so a test
/// can assert that **nothing** outside the written slot changed, including slots
/// that were never allocated.
fn fido_area(region: &mut dyn KeyRegion) -> Vec<SlotImage> {
    (0..FIDO_CAPACITY)
        .map(|i| region.read_slot(slot(i as u16)).expect("slot reads"))
        .collect()
}

/// The scratchpad sector's four slots, for "no staged bytes survive".
fn scratchpad_bytes(region: &mut dyn KeyRegion) -> Vec<SlotImage> {
    (0..SLOTS_PER_SECTOR)
        .map(|i| {
            region
                .read_slot(slot((SCRATCHPAD_FIRST_SLOT + i) as u16))
                .expect("slot reads")
        })
        .collect()
}

/// A fresh region file plus an opened handle.
fn fresh_region(tag: &str) -> (TempRegion, FileKeyRegion) {
    let tmp = TempRegion::new(tag);
    let region = FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("a fresh region file");
    (tmp, region)
}

/// Run `f` with a store over `region`, and drop the store before returning.
///
/// The scoping is not tidiness. [`FidoRecordStore`] holds the region borrow for
/// its whole life — that is what makes "one borrow and nothing else" its size —
/// so a test that wants to inject a fault or snapshot the medium between two
/// operations has to end the borrow first. Re-creating the store is free: it
/// reads nothing (`constructing_a_store_reads_nothing`), so the per-operation
/// cost is identical either way.
fn with_store<R>(region: &mut FileKeyRegion, f: impl FnOnce(&mut FidoRecordStore<'_>) -> R) -> R {
    let mut store = FidoRecordStore::new(region);
    f(&mut store)
}

/// Unwrap a load that must have succeeded.
///
/// [`SlotRead`] has no `unwrap` on purpose: its whole point is that `Fault` and
/// `Absent` are *different* answers, and a helper that turned both into a panic
/// would let a test read a degraded store as a good one. So the assertion has to
/// be written down rather than defaulted.
fn expect_hit(outcome: SlotRead<OnDemandHit>) -> OnDemandHit {
    expect_present(outcome, "the credential must be present")
}

/// The same, for the store's other reads.
fn expect_present<T>(outcome: SlotRead<T>, missing: &str) -> T {
    match outcome {
        SlotRead::Present(value) => value,
        SlotRead::Absent => panic!("{missing}"),
        SlotRead::Fault(why) => panic!("the region must be readable, got a fault: {why}"),
    }
}

/// Assert every one of `n`'s credentials is findable and byte-identical.
fn assert_all_read_back(
    store: &mut FidoRecordStore<'_>,
    index_key: &IndexKey,
    payload_key: &PayloadKey,
    up_to: u8,
) {
    let mut window = CredentialWindow::new();
    for n in 0..up_to {
        expect_hit(store.load_by_rp(payload_key, index_key, &rp_hash(n), &mut window));
        assert_eq!(
            window.as_slice(),
            credential_plaintext(n).as_slice(),
            "credential {n} must read back byte-identical"
        );
    }
}

// ---------------------------------------------------------------------------
// The capacity win
// ---------------------------------------------------------------------------

/// **The reported defect, gone.** A fifth credential enrols, and the store says
/// why it can.
///
/// `key_store_ceiling.rs` shows the snapshot backend refusing this with
/// `KeyStoreFull` (0x28) because `other_slots + old_parts + new_parts > 24` in
/// the 24-entry secure partition. Here the fifth write is one record in one
/// sector of a 960-slot region, and the capacity it is measured against is
/// derived rather than asserted.
#[test]
fn a_fifth_credential_enrolls_where_the_snapshot_backend_refused_it() {
    let (_tmp, mut region) = fresh_region("fifth");
    let (index_key, payload_key) = keys();
    with_store(&mut region, |store| {
        for n in 0..FIVE {
            enroll(store, &index_key, &payload_key, n);
        }
        assert_all_read_back(store, &index_key, &payload_key, FIVE);
    });

    assert_eq!(
        FidoRecordStore::capacity(),
        FIDO_CAPACITY,
        "capacity() must be the region's derived FIDO capacity, not a literal"
    );
    assert!(
        FidoRecordStore::capacity() > u32::from(FOUR) * 10,
        "the win is not marginal: {} against the four a soak board held",
        FidoRecordStore::capacity()
    );
}

/// Every credential is retrievable by credential ID, not only by RP — which is
/// what `getAssertion`'s `allowList` and the exclude list actually ask for.
///
/// The cost is `candidates + 1` AEAD operations rather than one
/// (`CredentialIdLocator`'s docs), so the assertion here is that the extra pass
/// returns the *right* record rather than the index's first match.
#[test]
fn a_credential_is_found_by_its_credential_id_among_its_rp_siblings() {
    let (_tmp, mut region) = fresh_region("byid");
    let (index_key, payload_key) = keys();
    with_store(&mut region, |store| {
        // Five credentials under **one** RP, so the by-ID lookup really has to
        // choose rather than take the first match.
        for n in 0..FIVE {
            store
                .put(
                    &payload_key,
                    &index_key,
                    &nonce(n as u32),
                    &rp_hash(0),
                    &credential_plaintext(n),
                )
                .unwrap_or_else(|e| panic!("credential {n} must enrol: {e}"));
        }

        let mut window = CredentialWindow::new();
        for n in 0..FIVE {
            let wanted: Vec<u8> = credential_plaintext(n)[..9].to_vec();
            expect_hit(store.load_by_credential_id(
                &payload_key,
                &index_key,
                Some(&rp_hash(0)),
                &wanted,
                &PrefixProbe,
                &mut window,
            ));
            assert_eq!(
                window.as_slice(),
                credential_plaintext(n).as_slice(),
                "credential {n} must be the record its ID names"
            );
        }

        // A credential ID nobody issued is absent — not a fault, and not a guess.
        let missing = b"CRED-ID-\xff".to_vec();
        assert_eq!(
            store.load_by_credential_id(
                &payload_key,
                &index_key,
                Some(&rp_hash(0)),
                &missing,
                &PrefixProbe,
                &mut window,
            ),
            SlotRead::Absent
        );
    });
}

// ---------------------------------------------------------------------------
// The gherkin's middle clause
// ---------------------------------------------------------------------------

/// **"Exactly one slot is erased and programmed"** — read as the sector, because
/// the sector is the erase unit on this part (`mod.rs`, "Slots per NOR
/// sector").
///
/// Counted from the region's own instrument rather than asserted in a comment,
/// and split into the numbers the criterion means: `live_erases` is the
/// credential write's own cost, and the two scratchpad erases buy the brown-out
/// guarantee while destroying nothing the owner holds (`commit.rs`,
/// `CommitReport`). The four programs are the sector's four slots — the target
/// plus its three mates, copied verbatim.
#[test]
fn enrolling_erases_one_live_sector() {
    let (_tmp, mut region) = fresh_region("one-sector");
    let (index_key, payload_key) = keys();
    let report = with_store(&mut region, |store| {
        for n in 0..FOUR {
            enroll(store, &index_key, &payload_key, n);
        }
        enroll(store, &index_key, &payload_key, 4)
    });
    assert_eq!(
        report.commit.live_erases, 1,
        "one live sector erase is the whole of 'one slot erased'"
    );
    assert_eq!(
        report.commit.scratchpad_erases, 2,
        "the scratchpad's prepare and retire — charged to no credential"
    );
    // **One programmed slot, exactly** — and the arithmetic behind it is worth
    // stating because it is not obvious. Allocation is lowest-free, so the
    // target is the lowest unoccupied slot in the region; every other slot in
    // its sector therefore has a *higher* index and has never been written, so
    // it is erased and skipped rather than copied. `commit::stage` counts only
    // the non-empty slots (`if !erased(&live)`), so both counts are 1.
    //
    // That is the strongest form of the gherkin clause available on this
    // hardware: the *sector* is erased (NOR cannot do less), but exactly one
    // slot of it carries bytes, and the three mates are erased-to-nothing and
    // programmed back as nothing.
    assert_eq!(
        report.commit.staged_programs, 1,
        "exactly one slot programmed into the scratchpad"
    );
    assert_eq!(
        report.commit.live_programs, 1,
        "and exactly one slot programmed into the live sector"
    );

    // The record went to the lowest free slot, in its own sector.
    // **Re-based when the partition moved.** This asserted slot 4, because
    // FIDO's range used to start at the region's head. It now starts after
    // OATH's reservation and the commit scratchpad, so "lowest free slot" means
    // the lowest free slot *of FIDO's* — which is the whole point of the
    // partition, and the reason the number is written relative to
    // `FIDO_FIRST_SLOT` rather than as a literal.
    assert_eq!(
        report.slot.index() as u32,
        fido_store::FIDO_FIRST_SLOT + ENROLLED_BEFORE,
        "the lowest free slot of FIDO's range, after the credentials already enrolled"
    );
    assert_eq!(report.generation, 1, "a virgin slot's first write is generation 1");
    assert!(fido_store::is_fido_slot(report.slot), "and it is inside FIDO's range");
    assert!(
        report.commit.live_erases + report.commit.scratchpad_erases < SLOTS_PER_SECTOR,
        "the credential write touched three sectors at most, not one per credential"
    );
}

/// **"The other four are untouched."** Byte-identical, over the whole FIDO area,
/// not merely "still present".
///
/// A snapshot of FIDO's entire range before and after the fifth write, compared
/// slot by slot: every slot except the one written must be **bit for bit**
/// identical. That is the strongest form of preservation available — the mates
/// in the written sector are *copied*, not re-derived (`commit.rs`, "Why
/// sector-mates are copied verbatim, not re-sealed").
#[test]
fn the_other_four_credentials_are_byte_identical_afterwards() {
    let (_tmp, mut region) = fresh_region("untouched");
    let (index_key, payload_key) = keys();
    with_store(&mut region, |store| {
        for n in 0..FOUR {
            enroll(store, &index_key, &payload_key, n);
        }
    });
    let before = fido_area(&mut region);

    let report = with_store(&mut region, |store| enroll(store, &index_key, &payload_key, 4));
    let after = fido_area(&mut region);

    assert_eq!(before.len(), after.len(), "the FIDO area must not have changed shape");
    let changed: Vec<u16> = (0..before.len())
        .filter(|i| before[*i] != after[*i])
        .map(|i| i as u16)
        .collect();
    assert_eq!(
        changed,
        vec![report.slot.index()],
        "exactly one slot changed — the one written — got {changed:?}"
    );

    // Which is the substantive half: the four records still *decode* as the
    // four records, not merely as unchanged bytes.
    with_store(&mut region, |store| {
        assert_all_read_back(store, &index_key, &payload_key, FIVE)
    });
}

// ---------------------------------------------------------------------------
// Rollback, and "never latching dirty state"
// ---------------------------------------------------------------------------

/// **"The operation commits or rolls back cleanly."** A refused erase leaves the
/// four records exactly as they were.
///
/// The fault is injected on **erases**, so the fifth write dies before the point
/// of no return — the state `commit.rs` calls phase 1, where "generation N is
/// still there and still readable" is the guarantee.
#[test]
fn a_failed_commit_rolls_back_and_leaves_no_staged_bytes() {
    let (_tmp, mut region) = fresh_region("rollback");
    let (index_key, payload_key) = keys();
    with_store(&mut region, |store| {
        for n in 0..FOUR {
            enroll(store, &index_key, &payload_key, n);
        }
    });
    let before = fido_area(&mut region);

    region.inject_faults(Faults { erases: true, ..Faults::default() });
    let outcome = with_store(&mut region, |store| {
        store.put(
            &payload_key,
            &index_key,
            &nonce(4),
            &rp_hash(4),
            &credential_plaintext(4),
        )
    });
    region.inject_faults(Faults::default());

    assert!(
        outcome.is_err(),
        "a refused erase is reported, not swallowed: {outcome:?}"
    );
    assert_eq!(before, fido_area(&mut region), "a refused write changes no byte of any record");
    assert!(
        scratchpad_bytes(&mut region).iter().all(is_erased),
        "no staged bytes survive a refused commit — commit.rs's self-cleaning pass"
    );
    let read_back = |store: &mut FidoRecordStore<'_>| {
        assert_all_read_back(store, &index_key, &payload_key, FOUR)
    };
    with_store(&mut region, read_back);

    // And the store still works: a refusal is not a latch. This is the
    // difference between "this write failed" and "this device is full", and it
    // is exactly the distinction SOAK-FINDING-1's wedge turned into a dark
    // board.
    let report = with_store(&mut region, |store| enroll(store, &index_key, &payload_key, 4));
    assert_eq!(
        report.slot.index() as u32,
        fido_store::FIDO_FIRST_SLOT + ENROLLED_BEFORE,
        "the next FIDO slot is still free after the refusal — a refusal is not a latch"
    );
}

/// **"Never latching dirty state."** A failed put leaves nothing in RAM, and the
/// store answers for the records that exist and not for the one that does not.
///
/// The reason this is testable at all is that [`FidoRecordStore`] holds one
/// field — the region borrow. There is no `dirty: bool` to clear and no
/// `stored: bool` whose invariant could go stale, so the assertion is the shape
/// itself plus its behavioural consequence.
///
/// The fault is on **reads**, which lands in the index write *after* the record
/// commit has already succeeded: the record is there and the entry is not, so
/// the credential is **unfindable** rather than corrupt, and nothing is
/// overwritten. That asymmetry is the ordering decision `fido_store.rs`'s
/// `put` documents.
#[test]
fn a_failed_put_latches_nothing_and_the_store_still_works() {
    let (_tmp, mut region) = fresh_region("nolatch");
    let (index_key, payload_key) = keys();
    with_store(&mut region, |store| {
        for n in 0..FOUR {
            enroll(store, &index_key, &payload_key, n);
        }
    });

    region.inject_faults(Faults { reads: true, ..Faults::default() });
    let outcome = with_store(&mut region, |store| {
        store.put(
            &payload_key,
            &index_key,
            &nonce(4),
            &rp_hash(4),
            &credential_plaintext(4),
        )
    });
    region.inject_faults(Faults::default());
    assert!(outcome.is_err(), "an index that cannot be read is a reported failure");

    with_store(&mut region, |store| {
        assert_all_read_back(store, &index_key, &payload_key, FOUR);
        let mut window = CredentialWindow::new();
        assert_eq!(
            store.load_by_rp(&payload_key, &index_key, &rp_hash(4), &mut window),
            SlotRead::Absent,
            "the refused credential is not addressable"
        );
    });

    // And the store accepts a retry, which is the operational meaning of "no
    // latch": the device is not wedged.
    with_store(&mut region, |store| enroll(store, &index_key, &payload_key, 4));
}

// ---------------------------------------------------------------------------
// "Degrade, never halt"
// ---------------------------------------------------------------------------

/// An unreadable region yields `Fault`, **never** `Absent`, and never a panic or
/// an empty-store answer.
///
/// This is US-1573's hazard in the form that would be most expensive here: a
/// faulted read memoized as "no credentials" makes the next enrolment build a
/// second identity on top of the owner's. The three-way [`SlotRead`] /
/// [`FidoStoreError`] split exists so that mistake is a state a caller is
/// expected to match, and this asserts the three paths answer differently.
#[test]
fn an_unreadable_region_degrades_and_never_reads_as_empty() {
    let (_tmp, mut region) = fresh_region("unreadable");
    let (index_key, payload_key) = keys();
    with_store(&mut region, |store| {
        for n in 0..FOUR {
            enroll(store, &index_key, &payload_key, n);
        }
    });

    region.inject_faults(Faults { reads: true, ..Faults::default() });

    with_store(&mut region, |store| {
        // A lookup: `Fault`, not `Absent`.
        let mut window = CredentialWindow::new();
        let hit = store.load_by_rp(&payload_key, &index_key, &rp_hash(0), &mut window);
        assert!(
            hit.is_fault(),
            "an unreadable region must read as a fault, not as 'no such credential': {hit:?}"
        );
        assert!(
            window.is_empty(),
            "and the window must hold nothing — a faulted lookup serves no credential"
        );

        // An enumeration: `Fault`, not "zero credentials".
        let mut slots = [slot(0); 4];
        assert!(
            store.slots_for_rp(&index_key, &rp_hash(0), &mut slots).is_fault(),
            "an index that cannot be read is a fault, not an empty result"
        );
        assert!(
            store.inspect_index().is_fault(),
            "the structural index pass reports a fault rather than a clean report"
        );

        // A write: refused as *unreadable*, not as *full*. The two answer
        // different questions and only one is true, so collapsing them would
        // tell the owner their key is full when the flash is sick.
        let outcome = store.put(
            &payload_key,
            &index_key,
            &nonce(4),
            &rp_hash(4),
            &credential_plaintext(4),
        );
        assert!(
            matches!(outcome, Err(FidoStoreError::RegionUnreadable(_))),
            "an unreadable region is a transport refusal, not a capacity one: {outcome:?}"
        );
    });

    region.inject_faults(Faults::default());

    // Recovered: the four are still there, so nothing was lost to the fault.
    let read_back = |store: &mut FidoRecordStore<'_>| {
        assert_all_read_back(store, &index_key, &payload_key, FOUR)
    };
    with_store(&mut region, read_back);
}

/// A region that refuses every **write** reports a transport or commit failure —
/// never a panic, and never a `Full` it cannot justify.
#[test]
fn a_region_that_refuses_writes_does_not_panic_and_does_not_claim_full() {
    let (_tmp, mut region) = fresh_region("nowrite");
    let (index_key, payload_key) = keys();
    region.inject_faults(Faults { programs: true, ..Faults::default() });
    let outcome = with_store(&mut region, |store| {
        store.put(
            &payload_key,
            &index_key,
            &nonce(0),
            &rp_hash(0),
            &credential_plaintext(0),
        )
    });
    region.inject_faults(Faults::default());

    match outcome {
        Err(FidoStoreError::RegionUnreadable(_)) | Err(FidoStoreError::Commit(_)) => {}
        other => panic!("a refused program must be reported as such, got {other:?}"),
    }

    // Unfaulted, the same write succeeds: the refusal did not latch.
    with_store(&mut region, |store| enroll(store, &index_key, &payload_key, 0));
}

// ---------------------------------------------------------------------------
// The boot-path constraint (S8/S9)
// ---------------------------------------------------------------------------

/// **Constructing a store reads nothing.** The boot path must not touch the key
/// region, and a constructor is exactly the sort of thing a boot path calls.
///
/// Asserted on the region's own instruction counter, which is the only way to
/// make it checkable rather than asserted in a comment: `FileKeyRegion::create`
/// erases through the file, not through `erase_sector`, so a virgin region's
/// counters are zero before anything else happens, and they must still be zero
/// after `FidoRecordStore::new` returns and after the store is dropped.
#[test]
fn constructing_a_store_reads_nothing() {
    let (_tmp, mut region) = fresh_region("bootpath");
    assert_eq!(
        region.stats().slot_reads, 0,
        "a virgin region has served no reads; otherwise this test proves nothing"
    );

    // Ending the borrow is the whole assertion: `FidoRecordStore` holds only the
    // borrow, so going out of scope touches nothing. A `drop` call would be a
    // lie about that — there is no destructor to run.
    with_store(&mut region, |_store| {});

    let stats = region.stats();
    assert_eq!(stats.slot_reads, 0, "FidoRecordStore::new must not read the region");
    assert_eq!(stats.sector_erases, 0, "and must not erase");
    assert_eq!(stats.programs, 0, "and must not program");
}

/// The **first** read is the applet's first operation, not the store's
/// construction: `recover` on a pristine scratchpad costs four slot reads and
/// **no erase**.
///
/// That is `commit::recover`'s "Nothing staged at all" arm, and it is worth
/// pinning separately from the constructor test because it is what the first
/// real enrolment does — and an enrolment that erased the scratchpad
/// unconditionally would spend a sector's worth of NOR endurance on every write.
#[test]
fn the_first_operation_reads_but_does_not_erase() {
    let (_tmp, mut region) = fresh_region("firstop");
    region.reset_stats();
    with_store(&mut region, |store| {
        store.recover().expect("a pristine scratchpad recovers immediately")
    });

    let stats = region.stats();
    assert_eq!(stats.slot_reads, SLOTS_PER_SECTOR, "four slot reads, no more");
    assert_eq!(stats.sector_erases, 0, "a virgin scratchpad is swept by doing nothing");
    assert_eq!(stats.programs, 0);
}

// ---------------------------------------------------------------------------
// Resident cost, and the properties the module claims
// ---------------------------------------------------------------------------

/// The store's own resident cost is one field — the region borrow.
///
/// Pinned rather than asserted in a comment, because the whole RAM argument
/// (`fido_store.rs`, "Why the whole array had to go") is a number: 856 resident
/// `DeviceCredential`s would be 616,320 bytes of `.bss` against 532,480 bytes of
/// RAM, and `FidoRecordStore` is what makes that false.
#[test]
fn the_store_holds_no_resident_credential_state() {
    use core::mem::size_of;
    assert_eq!(
        size_of::<FidoRecordStore<'static>>(),
        size_of::<&'static mut dyn KeyRegion>(),
        "the store is one borrow and nothing else — no cache, no pending-write marker"
    );
    // And the payload side is the bounded window, not a set of credentials.
    assert_eq!(
        size_of::<CredentialWindow>(),
        838,
        "838 B: the 836-byte bound plus a u16 length"
    );
}

/// One RP lookup opens exactly one record.
///
/// The property `on_demand.rs`'s module docs rest the whole design on: locating a
/// credential must not open any payload, so the AEAD count is bounded at one by
/// the [`on_demand::SlotLocator`] signature rather than by a loop someone
/// reviewed. Counted with `on_demand`'s own thread-local witness, over eight
/// credentials under eight RPs so a search that opened payloads would show it.
#[test]
fn an_rp_lookup_opens_exactly_one_record() {
    let (_tmp, mut region) = fresh_region("one-aead");
    let (index_key, payload_key) = keys();
    with_store(&mut region, |store| {
        for n in 0..8u8 {
            enroll(store, &index_key, &payload_key, n);
        }
    });

    let mut window = CredentialWindow::new();
    on_demand::testing::clear();
    with_store(&mut region, |store| {
        expect_hit(store.load_by_rp(&payload_key, &index_key, &rp_hash(3), &mut window));
    });
    assert_eq!(
        on_demand::testing::unseal_attempts(),
        1,
        "exactly one record is opened to find one credential"
    );
}

/// The window is cleared before every load and on drop, so a failed lookup can
/// never serve the previous operation's credential.
#[test]
fn the_window_never_carries_a_credential_across_a_failed_lookup() {
    let (_tmp, mut region) = fresh_region("window");
    let (index_key, payload_key) = keys();
    let mut window = CredentialWindow::new();
    with_store(&mut region, |store| {
        for n in 0..3u8 {
            enroll(store, &index_key, &payload_key, n);
        }
        expect_hit(store.load_by_rp(&payload_key, &index_key, &rp_hash(0), &mut window));
        assert!(!window.is_empty(), "the window holds credential 0");

        let miss = store.load_by_rp(&payload_key, &index_key, &rp_hash(200), &mut window);
        assert_eq!(miss, SlotRead::Absent);
    });
    assert!(
        window.is_empty(),
        "a failed lookup must not leave the previous credential in the window"
    );
}

/// Every index entry authenticates under the device-rooted key, and the
/// verification opens no payload.
#[test]
fn every_index_entry_authenticates_under_the_device_rooted_key() {
    let (_tmp, mut region) = fresh_region("verify");
    let (index_key, payload_key) = keys();
    let mut hashes = Vec::new();
    for n in 0..6u8 {
        hashes.push(rp_hash(n));
        with_store(&mut region, |store| enroll(store, &index_key, &payload_key, n));
    }

    with_store(&mut region, |store| {
        let report = expect_present(store.inspect_index(), "the index must read");
        assert_eq!(report.present, 6, "one entry per credential, no orphans");
        assert_eq!(report.malformed, 0, "and no malformed entry");

        let v = expect_present(store.verify_index(&index_key, &hashes), "the index must verify");
        assert_eq!(v.present, 6);
        assert_eq!(v.authenticated, 6, "every entry authenticates its own rp_id_hash");
        assert_eq!(v.rejected, 0);

        // A hash nobody enrolled cannot be made to authenticate an entry: the
        // tag binds `(domain, slot, generation, rp_id_hash)`, so editing the
        // index to answer for it recomputes a different expected tag.
        let wrong = [rp_hash(200), rp_hash(201)];
        let v = expect_present(store.verify_index(&index_key, &wrong), "the index must still read");
        assert_eq!(v.authenticated, 0, "no entry answers a hash it was not made for");
        assert_eq!(v.rejected, 6);
    });
}

/// The allocator lands inside FIDO's range and never in the reservations.
///
/// The bound is asserted by construction in `fido_store.rs`'s `const _` block;
/// this checks the *runtime* consequence, and specifically that an enrolment
/// does not consume an index slot or an OATH slot — which is how `index.rs` says
/// an index gets destroyed.
#[test]
fn an_enrolment_never_lands_in_a_reservation() {
    let (_tmp, mut region) = fresh_region("bound");
    let (index_key, payload_key) = keys();
    let report = with_store(&mut region, |store| enroll(store, &index_key, &payload_key, 0));
    assert!(fido_store::is_fido_slot(report.slot), "inside FIDO's range");
    assert!(!index::is_index_slot(report.slot), "never an index slot");
    assert!(
        (report.slot.index() as u32) != SCRATCHPAD_FIRST_SLOT,
        "never the commit scratchpad"
    );
    // **Rewritten.** This said the slot must be *below* the scratchpad, which
    // held while FIDO's range was at the region's head. The shared partition
    // is OATH, scratchpad, FIDO, index — so the property is now that the slot is
    // inside FIDO's range and outside every reservation, which is what
    // `is_fido_slot` plus the two negative assertions above already say.
    assert!(
        (report.slot.index() as u32) >= SCRATCHPAD_FIRST_SLOT + SLOTS_PER_SECTOR,
        "FIDO's range begins past the scratchpad"
    );
    assert!(
        (report.slot.index() as u32) < index::INDEX_FIRST_SLOT,
        "and ends before the index"
    );
}

/// A credential too large for a record is refused as a *credential* problem, not
/// as a capacity problem and not by truncating.
#[test]
fn an_oversized_credential_is_refused_rather_than_truncated() {
    let (_tmp, mut region) = fresh_region("oversize");
    let (index_key, payload_key) = keys();
    let too_big = vec![0xaau8; FIDO_RECORD_MAX as usize + 1];
    with_store(&mut region, |store| {
        let outcome = store.put(&payload_key, &index_key, &nonce(0), &rp_hash(0), &too_big);
        assert!(
            matches!(outcome, Err(FidoStoreError::CredentialTooLarge { .. })),
            "an oversized credential is refused as such, got {outcome:?}"
        );
    });

    // And the refusal consumed nothing: the next credential takes slot 0.
    with_store(&mut region, |store| enroll(store, &index_key, &payload_key, 0));
}