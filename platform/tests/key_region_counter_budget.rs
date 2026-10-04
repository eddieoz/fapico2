//! US-1561, US-1562: the erase budget of the **per-record** counter write.
//!
//! ```gherkin
//! Scenario: the budget reflects the new write pattern
//!   Given the per-record write amplification
//!   When the budget is recomputed
//!   Then docs/erase-budget.md states the new per-sector cycle count
//!   And check_erase_budget.py reads the constants from source and fails on disagreement
//! ```
//!
//! # What this file measures, and what it deliberately does not
//!
//! `docs/erase-budget.md`'s existing measurement is of `FlashSlotSink` — the
//! **whole-snapshot** persist, eight sector erases on eight distinct sectors.
//! That path is still real (the migration, the PIN state, the vendor state and
//! the OATH stream all still persist through it) and its figures are still
//! gated. What it stopped being is the cost of a **FIDO signature-counter
//! bump**, because credentials moved to the key region and a counter bump is
//! now a record commit.
//!
//! So this file measures the new thing, and the arithmetic lives on
//! [`FidoRecordStore::update`] rather than here:
//!
//! | what | who publishes it |
//! |---|---|
//! | sector erases one `commit::commit` issues | [`commit::SECTOR_ERASES_PER_COMMIT`] |
//! | sector erases one index-entry write issues | [`fido_store::INDEX_SECTOR_ERASES_PER_ENTRY_WRITE`] |
//! | sector erases one durable counter write issues | [`fido_store::SECTOR_ERASES_PER_COUNTER_WRITE`] |
//! | slots a commit reprograms | [`SLOTS_PER_SECTOR`] |
//!
//! **This file's job is to make sure those constants are not lies.** A constant
//! in a source file that nothing checks is a comment; a constant checked
//! against a measurement is a fact. `erase_budget_figures` drives the **real**
//! [`FidoRecordStore::update`] over a [`FileKeyRegion`] — NOR semantics, a
//! `program` that refuses a 0 → 1 transition — and prints what actually
//! happened. `check_erase_budget.py` parses those figures, compares them with
//! the constants read out of the source by regex, and fails on disagreement in
//! either direction.
//!
//! # The two controls that make the measurement able to fail
//!
//! An instrument that cannot fail measures nothing. These are the arms that
//! would move:
//!
//! * `unchanged_sector_erases` — a **read** must cost zero erases. This is the
//!   per-record analogue of the snapshot document's `unchanged_erase_calls = 0`:
//!   it is what says "there is a path that touches no medium at all", and a
//!   commit path that had lost its `recover`-is-a-no-op property would move it.
//! * `second_update_sector_erases` — a **second** counter write over the same
//!   record must cost the same as the first, not more and not fewer. A protocol
//!   that grew a fifth erase would show here; one that started skipping a phase
//!   would show here too.
//!
//! # What is NOT measured here
//!
//! **`cycles_per_sector`.** The 100,000 the lifetime is derived from is a
//! **literature** NOR-endurance figure, not a measurement of the part fitted to
//! a Pico 2, and this file does not pretend otherwise: it measures the
//! *distribution* (how many erases land on the busiest single sector), which is
//! the half that is this project's to establish. The endurance half is named as
//! literature in `docs/erase-budget.md` §4c and in the gate script, which
//! checks that the document keeps saying so.
//!
//! The device path is not counted either, for the reason §2.3 of that document
//! gives: there is no vendor counter channel, and the honest answer is that the
//! hardware leg is outstanding rather than approximated.

use std::path::{Path, PathBuf};

use fapico2_platform::ckey;
use fapico2_platform::keyregion::commit;
use fapico2_platform::keyregion::crypto::{self, IndexKey, PayloadKey};
use fapico2_platform::keyregion::fido_store::{self, FidoRecordStore};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::index::RpIdHash;
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::slotmap::SlotImage;
use fapico2_platform::keyregion::{KeyRegion, Slot, SLOTS_PER_SECTOR, TOTAL_SLOTS};

/// The region's whole geometry.
///
/// **The full region, not a short stand-in.** `FidoAllocator::alloc` scans
/// `FIDO_SLOT_LIMIT` slots and the index lives at the tail, so a short file
/// would change what the allocator can reach and what the index write touches.
/// The budget is only the shipping budget if the shipping geometry is what was
/// measured.
const REGION_SLOTS: u32 = TOTAL_SLOTS;

/// Durable writes in the measured run, so a per-write figure is a rate rather
/// than a single sample. Three is enough to see a protocol change and small
/// enough that the instrument stays a test rather than a benchmark.
const WRITES: u32 = 3;

/// Credentials seeded into the region **before** the measured run.
///
/// Four, and that number is the point rather than a convenience:
/// [`SLOTS_PER_SECTOR`] is 4, so four credentials fill the first FIDO sector
/// completely. A commit then has three sector-mates to copy and reprograms the
/// whole sector, which is the **worst case** for the program count and the
/// **typical** case for any device past its first few registrations — a sector
/// with one record in it is the geometry a brand-new device has and nothing
/// else. Measuring the sparse case would under-report the wear, and the budget's
/// divisor is a per-sector figure.
///
/// The measured record is the **first** of them, so it is a sector-mate-free
/// position (offset 0 of its sector) rather than one buried under three others
/// — a commit's cost does not depend on the target's offset, only on how many
/// of its sector-mates are occupied, and this file says so rather than letting
/// the reader assume it.
const SEEDED: u32 = SLOTS_PER_SECTOR;

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
            std::env::temp_dir().join(format!("fapico2-us1562-{}-{tag}.bin", std::process::id()));
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
    let serial = ckey::serial_hash(b"fapico2 keyregion counter budget test");
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

/// A fresh GCM nonce for the `n`-th write.
///
/// Unique per write, which `record::seal` requires and this file holds itself
/// to rather than assuming.
fn nonce(n: u32) -> [u8; record::NONCE_LEN] {
    let mut out = [0u8; record::NONCE_LEN];
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..].copy_from_slice(&b"us1562 nonce!"[..record::NONCE_LEN - 4]);
    out
}

/// The plaintext body a durable write programs. A changing tag byte, so every
/// write is a real record change rather than a rewrite of identical bytes.
fn body(n: u32) -> Vec<u8> {
    let mut v = vec![0u8; 128];
    v[..4].copy_from_slice(&n.to_le_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(4) {
        *b = (i as u8).wrapping_mul(5).wrapping_add(n as u8);
    }
    v
}

// ---------------------------------------------------------------------------
// The counting region
// ---------------------------------------------------------------------------

/// A [`KeyRegion`] that records **which sector** each erase and program landed
/// on.
///
/// Per-sector and not per-call, because the whole lifetime argument is a
/// per-sector argument: `docs/erase-budget.md`'s withdrawn 12,500 was exactly
/// the mistake of dividing a per-sector budget by a per-persist *operation*
/// count, and an instrument that only counted calls cannot see that mistake a
/// second time. This is `persist_sink.rs`'s `sector_erase_profile_since`
/// applied to the region rather than the slot sink — the same question, asked of
/// the code that now answers it.
struct CountingRegion {
    inner: FileKeyRegion,
    /// Sector erases per sector index since the last [`Self::reset_log`].
    erase_log: Vec<u32>,
    /// Slot programs per sector index since the last [`Self::reset_log`].
    program_log: Vec<u32>,
}

impl CountingRegion {
    fn new(path: &Path) -> Self {
        CountingRegion {
            inner: FileKeyRegion::create(path, REGION_SLOTS)
                .expect("the temp region file is creatable"),
            erase_log: Vec::new(),
            program_log: Vec::new(),
        }
    }

    /// Forget the per-sector log. `FileKeyRegion::stats` is left alone: the
    /// erase log subsumes it and two counters for one fact is one more way for
    /// them to disagree.
    fn reset_log(&mut self) {
        self.erase_log.clear();
        self.program_log.clear();
    }

    /// Total sector erases logged.
    fn erases(&self) -> u32 {
        self.erase_log.iter().sum()
    }

    /// Total slot programs logged.
    fn programs(&self) -> u32 {
        self.program_log.iter().sum()
    }

    /// How many **distinct** sectors were erased.
    fn distinct_erased(&self) -> u32 {
        self.erase_log.iter().filter(|&&n| n > 0).count() as u32
    }

    /// The busiest single sector's erase count.
    fn busiest(&self) -> u32 {
        self.erase_log.iter().copied().max().unwrap_or(0)
    }

    /// Every sector that was erased, as `(sector index, erase count)`, busiest
    /// first.
    ///
    /// **Sorted by count, not by address**, because the number the budget is
    /// derived from is the busiest one and the address it sits at is
    /// incidental. Sorting makes the printed profile directly comparable with
    /// the divisor the document publishes.
    fn erase_profile(&self) -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> = self
            .erase_log
            .iter()
            .enumerate()
            .filter(|(_, &n)| n > 0)
            .map(|(i, &n)| (i as u32, n))
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }

    /// Sector erases that landed on one sector index.
    fn erases_on(&self, slot: Slot) -> u32 {
        self.erase_log.get(slot.index() as usize / SLOTS_PER_SECTOR as usize).copied().unwrap_or(0)
    }

    /// Slot programs that landed on one sector index.
    fn programs_on(&self, slot: Slot) -> u32 {
        self.program_log.get(slot.index() as usize / SLOTS_PER_SECTOR as usize).copied().unwrap_or(0)
    }

    fn bump(log: &mut Vec<u32>, slot: Slot) {
        let at = slot.index() as usize / SLOTS_PER_SECTOR as usize;
        if at >= log.len() {
            log.resize(at + 1, 0);
        }
        log[at] += 1;
    }
}

impl KeyRegion for CountingRegion {
    fn read_slot(&mut self, slot: Slot) -> Result<SlotImage, &'static str> {
        self.inner.read_slot(slot)
    }

    fn erase_sector(&mut self, slot: Slot) -> Result<(), &'static str> {
        let out = self.inner.erase_sector(slot);
        // Logged **after** the inner call and whether it succeeded or failed, so
        // the log answers "what did the protocol *attempt*", which is the wear
        // question — a refused erase may or may not have consumed a cycle, and
        // no interface says which.
        Self::bump(&mut self.erase_log, slot);
        out
    }

    fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        Self::bump(&mut self.program_log, slot);
        self.inner.program(slot, offset, data)
    }

    fn slots(&self) -> u32 {
        self.inner.slots()
    }
}

// ---------------------------------------------------------------------------
// The instrument
// ---------------------------------------------------------------------------

/// US-1562: measure what one durable per-record counter write costs, and print
/// it in the form `check_erase_budget.py` parses.
///
/// `ERASE_BUDGET_RECORD <key>=<n>` — a **separate prefix** from the snapshot
/// instrument's `ERASE_BUDGET`, and deliberately so: the two measurements are
/// of different code paths over different media, and merging them into one
/// figure set would produce a document that could describe either.
#[test]
fn erase_budget_record_figures() {
    let tmp = TempRegion::new("budget");
    let mut region = CountingRegion::new(tmp.path());
    let mut writes = 0u32;

    // Seed: one credential, so `update` has a record and an index entry to work
    // on. Its own erases are not counted — they are the `put` path, and the
    // `put` path's cost is `FidoRecordStore::put`'s story.
    let target = {
        let mut store = FidoRecordStore::new(&mut region);
        let mut first = None;
        for n in 0..SEEDED {
            let report = store
                .put(&payload_key(), &index_key(), &nonce(n), &rp_hash(), &body(n))
                .expect("a fresh credential enrols");
            if n == 0 {
                first = Some(report.slot);
            }
        }
        first.expect("the seed enrolled at least one credential")
    };

    // The measured run: `WRITES` durable counter writes over the same record.
    // Each one is exactly the operation a FIDO signature-counter batch
    // flush performs, so this is the shipping wear pattern and not a proxy.
    let mut total_erases = 0u32;
    let mut total_programs = 0u32;
    let mut per_write_erases = Vec::new();
    let mut live_erases_first = 0u32;
    let mut live_programs_first = 0u32;
    let mut distinct_first = 0u32;
    let mut busiest_first = 0u32;
    // The full per-sector erase profile of the first durable write, so the
    // document can publish the **distribution** and not only its maximum. The
    // snapshot instrument could not need this — its erases were uniform, one
    // per sector, which is the best case a two-slot layout can produce — and
    // here it is not uniform at all: one sector takes four of the six.
    let mut profile_first: Vec<(u32, u32)> = Vec::new();
    for n in 1..=WRITES {
        region.reset_log();
        let mut store = FidoRecordStore::new(&mut region);
        store
            .update(&payload_key(), &index_key(), target, &nonce(n), &rp_hash(), &body(n))
            .expect("a counter write over a live record succeeds");
        writes += 1;
        let erases = region.erases();
        let programs = region.programs();
        if n == 1 {
            live_erases_first = region.erases_on(target);
            live_programs_first = region.programs_on(target);
            distinct_first = region.distinct_erased();
            busiest_first = region.busiest();
            profile_first = region.erase_profile();
        }
        per_write_erases.push(erases);
        total_erases += erases;
        total_programs += programs;
    }

    // Uniformity. `busiest % WRITES` rather than an average, for the reason
    // `persist_sink.rs` uses it: an average over an uneven run publishes a rate
    // that never happened.
    for erases in &per_write_erases {
        assert_eq!(
            *erases, per_write_erases[0],
            "every durable counter write must cost the same erases; the budget's divisor is a \
             per-write figure and an uneven run would publish a rate that never occurred"
        );
    }
    assert_eq!(writes, WRITES);

    // Control 1 — a read costs nothing. The per-record analogue of the snapshot
    // document's `unchanged_erase_calls = 0`.
    region.reset_log();
    {
        let mut store = FidoRecordStore::new(&mut region);
        // The seed enrolled at generation 1 and each of the `WRITES` durable
        // writes advanced it by one, so the record now carries `1 + WRITES`.
        // Read here to prove the writes really landed rather than being
        // short-circuited — an instrument that counted erases against a store
        // that silently did nothing would report the same numbers.
        assert_eq!(store.record_generation(target), Ok(1 + WRITES));
    }
    let unchanged_sector_erases = region.erases();

    // Control 2 — the second write costs the same as the first. Stated by
    // re-reading `per_write_erases[0]` rather than by a second scenario: a
    // protocol that grew a phase would make `per_write_erases` non-uniform and
    // the loop above would already have failed.
    let second_update_sector_erases = per_write_erases
        .get(1)
        .copied()
        .expect("WRITES is at least 2, so a second write was measured");

    println!("ERASE_BUDGET_RECORD slots_per_sector={SLOTS_PER_SECTOR}");
    println!(
        "ERASE_BUDGET_RECORD sector_erases_per_record_commit={}",
        commit::SECTOR_ERASES_PER_COMMIT
    );
    println!(
        "ERASE_BUDGET_RECORD scratchpad_erases_per_record_commit={}",
        commit::SCRATCHPAD_ERASES_PER_COMMIT
    );
    println!(
        "ERASE_BUDGET_RECORD live_erases_per_record_commit={}",
        commit::LIVE_ERASES_PER_COMMIT
    );
    println!(
        "ERASE_BUDGET_RECORD sector_erases_per_index_entry_write={}",
        fido_store::INDEX_SECTOR_ERASES_PER_ENTRY_WRITE
    );
    println!(
        "ERASE_BUDGET_RECORD sector_erases_per_counter_write={}",
        fido_store::SECTOR_ERASES_PER_COUNTER_WRITE
    );
    println!(
        "ERASE_BUDGET_RECORD measured_sector_erases_per_counter_write={}",
        total_erases / writes
    );
    println!(
        "ERASE_BUDGET_RECORD live_sector_erases_per_counter_write={live_erases_first}"
    );
    println!(
        "ERASE_BUDGET_RECORD live_slot_programs_per_counter_write={live_programs_first}"
    );
    println!("ERASE_BUDGET_RECORD distinct_sectors_erased_per_counter_write={distinct_first}");
    println!("ERASE_BUDGET_RECORD max_erases_per_sector_per_counter_write={busiest_first}");
    // The distribution itself, comma-joined as `sector:erases`. Not a
    // `key=value` line the figure parser would pick up: it is a shape, and a
    // parser that could read one number out of it would be tempted to use it as
    // the divisor, which is precisely the mistake §3.4 of the document withdrew.
    let profile = profile_first
        .iter()
        .map(|(i, n)| format!("{i}:{n}"))
        .collect::<Vec<_>>()
        .join(",");
    println!("ERASE_BUDGET_RECORD erase_profile_per_counter_write={profile}");
    println!("ERASE_BUDGET_RECORD unchanged_sector_erases={unchanged_sector_erases}");
    println!("ERASE_BUDGET_RECORD second_update_sector_erases={second_update_sector_erases}");
    println!(
        "ERASE_BUDGET_RECORD measured_slot_programs_per_counter_write={}",
        total_programs / writes
    );

    // --- what the measured figures must equal -----------------------------
    //
    // The constants are the document's inputs; this is what makes them facts.
    // A failure here means the protocol changed and the budget in
    // `docs/erase-budget.md` §4c — and `check_erase_budget.py`, which reads the
    // same constants out of the source — is now a stale document rather than a
    // live measurement.
    assert_eq!(
        total_erases / writes,
        fido_store::SECTOR_ERASES_PER_COUNTER_WRITE,
        "one durable counter write does not cost SECTOR_ERASES_PER_COUNTER_WRITE sector erases — \
         docs/erase-budget.md §4c and keyregion/fido_store.rs are both now wrong"
    );
    assert_eq!(
        live_erases_first,
        commit::LIVE_ERASES_PER_COMMIT,
        "the acceptance criterion counts ONE live-sector erase, and the protocol issues {}",
        live_erases_first
    );
    assert_eq!(
        live_programs_first,
        commit::LIVE_PROGRAMS_PER_COMMIT,
        "'one program' means one SECTOR reprogram: {} slot programs into the live sector",
        live_programs_first
    );
    assert_eq!(
        distinct_first,
        3,
        "a counter write must touch exactly three sectors — the record's, the index's and the \
         scratchpad's — or the per-sector divisor in the budget is derived from a distribution \
         nobody has measured"
    );
    // **Four, not two, and this is the number the lifetime is divided by.** The
    // record commit and the index rewrite are separate three-phase writes that
    // stage through the **same** scratchpad sector, so that one sector collects
    // two erases from each — four of the six erases a durable counter write
    // issues land on a single 4 KiB sector. It is the wear bottleneck of the
    // whole per-record path, and it is not visible from either half's arithmetic
    // in isolation.
    assert_eq!(
        busiest_first, 4,
        "the busiest single sector is the commit scratchpad, which both the record commit and \
         the index rewrite stage through: two erases each, four in total"
    );
    // **The add-up check, done for this distribution rather than the snapshot's.**
    // `persist_sink.rs` can assert `max x distinct == total` because its eight
    // erases are uniform — one per sector. This one cannot: four of the six land
    // on the scratchpad and one each on the other two, so the honest check is
    // that the profile **sums** to the total and that its maximum is the divisor
    // the document publishes. Asserting `max x distinct == total` here would be
    // asserting that the wear is uniform, which is false and which is the whole
    // reason this path's budget is smaller than the snapshot path's.
    let profile_total: u32 = profile_first.iter().map(|(_, n)| *n).sum();
    assert_eq!(
        profile_total, total_erases / writes,
        "the per-sector erase profile does not sum to the per-write total"
    );
    assert_eq!(
        profile_first.first().map(|(_, n)| *n),
        Some(busiest_first),
        "the profile's own maximum must be the figure the budget divides by"
    );
    assert_eq!(
        unchanged_sector_erases, 0,
        "reading a record must not erase anything — this is the control that says there is a \
         path that touches no medium"
    );
    assert_eq!(
        second_update_sector_erases,
        total_erases / writes,
        "a second durable counter write must cost the same as the first"
    );
}

/// US-1561: the batched window costs **no** medium for the assertions inside it.
///
/// The other half of the story's gherkin, at the platform's level: US-1562's
/// instrument counts what a durable write costs, and this asserts that a write
/// is what happens *once per batch* rather than once per assertion.
///
/// It drives the store directly — the applet-side window is
/// `apps/fido/tests/region_counter_batching.rs`'s subject — so what is pinned
/// here is the cheap half: N-1 record rewrites of the same slot would each cost
/// [`fido_store::SECTOR_ERASES_PER_COUNTER_WRITE`] erases, and a caller that
/// performed them would learn it the hard way.
#[test]
fn a_durable_counter_write_is_the_only_thing_that_costs_a_sector() {
    let tmp = TempRegion::new("no-free-erase");
    let mut region = CountingRegion::new(tmp.path());
    let target = {
        let mut store = FidoRecordStore::new(&mut region);
        let mut first = None;
        for n in 0..SEEDED {
            let report = store
                .put(&payload_key(), &index_key(), &nonce(n), &rp_hash(), &body(n))
                .expect("a fresh credential enrols");
            if n == 0 {
                first = Some(report.slot);
            }
        }
        first.expect("the seed enrolled at least one credential")
    };

    // A read, and then a second read: the state every assertion inside a batch
    // window is in. Zero erases, and that is the whole of "no erase occurs for
    // 31 assertions" as far as the medium is concerned.
    region.reset_log();
    for _ in 0..31 {
        let mut store = FidoRecordStore::new(&mut region);
        assert!(matches!(store.record_generation(target), Ok(1)));
    }
    assert_eq!(
        region.erases(),
        0,
        "reading a record inside a batch window must erase nothing — if a credential update had \
         become eager, this is the assertion that would have failed"
    );

    // And the one durable write in the window does erase. A test that asserted
    // only the zero above would pass against a store that never wrote at all.
    region.reset_log();
    {
        let mut store = FidoRecordStore::new(&mut region);
        store
            .update(&payload_key(), &index_key(), target, &nonce(1), &rp_hash(), &body(1))
            .expect("the window-closing write succeeds");
    }
    assert_eq!(
        region.erases(),
        fido_store::SECTOR_ERASES_PER_COUNTER_WRITE,
        "the window-closing durable write is where the wear is, and its cost is the constant the \
         budget is derived from"
    );
}