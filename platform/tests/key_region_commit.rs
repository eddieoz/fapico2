//! US-1544, US-1545, US-1546: sector-atomic commits, the self-cleaning failure
//! pass, and the factory wipe.
//!
//! # The two things these tests have to get right, or they prove nothing
//!
//! **1. A real NOR stand-in.** Every assertion here runs against a
//! [`FileKeyRegion`], whose `program` ANDs into what is already there and
//! **refuses** a 0 → 1 transition (`host.rs:373-379`) and whose `erase_sector`
//! clears a whole 4 KiB sector (`host.rs:317-335`). That refusal is what makes
//! the program ordering load-bearing rather than decorative: a commit that
//! reprogrammed a byte over a programmed one would fail with `E_NOR_SET_BIT`
//! rather than quietly producing an image the part could never hold.
//!
//! **2. A real power cut, and a real returned failure.** These are different
//! states and the difference is the story:
//!
//! * a **returned failure** ([`Fault::FailAt`]) unwinds normally out of
//!   `commit`, so the commit's own cleanup runs;
//! * a **power cut** ([`Fault::CutAt`]) performs the flash operation and then
//!   **panics** — caught outside `commit` — so `commit`'s frame is unwound
//!   *without* its cleanup, exactly as a reset vector would leave it. The file
//!   on disk then holds precisely the bytes the flash would hold, and the test
//!   reopens the region through [`FileKeyRegion::open`] and drives
//!   [`commit::recover`] as a boot would.
//!
//! A power-cut test that instead returned `Err` would be testing US-1545 twice
//! and would silently pass a commit path with no recovery at all. Every cut
//! point from the first flash operation to the last is exercised, and each one
//! asserts a *whole-sector* outcome — never a mixture.
//!
//! # The region under test
//!
//! Twelve slots — three sectors — because [`SLOTS_PER_SECTOR`] is 4 and a
//! region must hold whole sectors (`host.rs:168-173`). Sector 0 is the live
//! sector, sector 1 the scratchpad, sector 2 a neighbour. Three is the smallest
//! geometry in which "a sector-mate's record survived", "the neighbouring
//! sector was never erased" and "the scratchpad is not where I keep records"
//! are three distinguishable assertions rather than the same statement.

use std::path::{Path, PathBuf};

use fapico2_platform::keyregion::commit::{self, CommitError, CommitPlan, Recovery, SCRATCHPAD_SLOTS};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::record::{self, Domain};
use fapico2_platform::keyregion::slotmap::{SlotAllocator, SlotImage};
use fapico2_platform::keyregion::{KeyRegion, Sealed, Slot, SlotRead, SLOTS_PER_SECTOR};

/// Three sectors: 0..4 is the live sector, 4..8 the scratchpad, 8..12 a
/// neighbour whose record a commit into sector 0 must never touch.
const REGION_SLOTS: u32 = 12;

const LIVE_SECTOR: u16 = 0;
const SCRATCHPAD_SECTOR: u16 = 4;
const NEIGHBOUR_SECTOR: u16 = 8;

const ERASED: u8 = 0xFF;

/// The update every commit test performs: slot 1 of the live sector, OATH,
/// generation 2.
const TARGET: u16 = 1;

/// The injected transport error, distinct from the region's own strings so a
/// test that swallows it cannot be mistaken for a real refusal.
const E_INJECTED: &str = "key_region_commit test: injected write failure";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn slot(index: u16) -> Slot {
    Slot::new(index).expect("every index in this file is inside the region")
}

fn scratchpad() -> Slot {
    slot(SCRATCHPAD_SECTOR)
}

/// A region file in the host temp directory, removed on drop.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("fapico2-commit-{}-{tag}.bin", std::process::id()));
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

/// A sealed body whose bytes identify it, so a test can tell records apart.
///
/// Not a real AEAD output: [`record::testing`] exists precisely so a test can
/// mint a `Sealed` without a key (`record.rs:1064-1075`). Commit never opens a
/// body — it moves bytes — so a well-framed blob is all the commit path needs.
fn body(tag: u8) -> Sealed {
    record::testing::sealed_from_bytes(vec![tag; 48])
}

/// The plan for the standard update.
fn update_plan() -> CommitPlan {
    CommitPlan::new(scratchpad(), slot(TARGET), Domain::Oath, 2)
}

/// A plan writing `body` into `target` at `generation`.
fn plan(target: u16, domain: Domain, generation: u32) -> CommitPlan {
    CommitPlan::new(scratchpad(), slot(target), domain, generation)
}

/// Commit over a plain region (no fault injection, no logging).
fn commit_ok(
    region: &mut FileKeyRegion,
    target: u16,
    domain: Domain,
    generation: u32,
    tag: u8,
) -> commit::CommitReport {
    commit::commit(region, plan(target, domain, generation), &body(tag))
        .expect("an unfaulted commit succeeds")
}

/// A region holding four records in the live sector: slots 0 and 2 FIDO, slots 1
/// and 3 OATH, so a commit has to preserve records from **both** key domains
/// that it did not write. Plus one in the neighbouring sector.
fn seed(region: &mut FileKeyRegion) {
    commit_ok(region, 0, Domain::Fido, 1, 0xA0);
    commit_ok(region, TARGET, Domain::Oath, 1, 0xB0);
    commit_ok(region, 2, Domain::Fido, 1, 0xC0);
    commit_ok(region, 3, Domain::Oath, 1, 0xD0);
    commit_ok(region, NEIGHBOUR_SECTOR, Domain::Fido, 1, 0xE0);
}

/// Re-establish the generation-1 state from scratch.
///
/// Seeding is a series of commits, so re-running it on an already-seeded region
/// would be a generation regression. Truncating and pre-erasing through
/// `create` is what makes each iteration independent, and it is the same
/// pre-erase a virgin part has.
fn seed_fresh(tmp: &TempRegion) {
    FileKeyRegion::create(tmp.path(), REGION_SLOTS).expect("a fresh region file");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
    seed(&mut region);
}

/// A region file that exists and is already seeded.
fn seeded_file(tag: &str) -> TempRegion {
    let tmp = TempRegion::new(tag);
    seed_fresh(&tmp);
    tmp
}

/// The four live-sector slot images.
fn live_bytes(region: &mut FileKeyRegion) -> Vec<SlotImage> {
    (0..SLOTS_PER_SECTOR)
        .map(|i| region.read_slot(slot(LIVE_SECTOR + i as u16)).expect("slot reads"))
        .collect()
}

/// The four scratchpad slot images.
fn scratchpad_bytes(region: &mut FileKeyRegion) -> Vec<SlotImage> {
    (0..SLOTS_PER_SECTOR)
        .map(|i| region.read_slot(slot(SCRATCHPAD_SECTOR + i as u16)).expect("slot reads"))
        .collect()
}

/// Whether every byte of every image is erased.
fn all_erased(images: &[SlotImage]) -> bool {
    images.iter().all(|img| img.iter().all(|b| *b == ERASED))
}

/// The record `target` currently reads back as, or `None` when it is absent.
fn read_record(region: &mut FileKeyRegion, target: u16) -> Option<(u32, Vec<u8>)> {
    let s = slot(target);
    let raw = region.read_slot(s).expect("slot reads");
    match record::decode(s, &raw) {
        SlotRead::Present(decoded) => {
            Some((decoded.header().generation(), decoded.body().as_bytes().to_vec()))
        }
        SlotRead::Absent | SlotRead::Fault(_) => None,
    }
}

/// The live sector's contents at generation 1, before the update.
fn live_sector_at_generation_1() -> Vec<(u16, u32, u8)> {
    vec![(0, 1, 0xA0), (TARGET, 1, 0xB0), (2, 1, 0xC0), (3, 1, 0xD0)]
}

/// The live sector's contents after the update commits.
fn live_sector_at_generation_2() -> Vec<(u16, u32, u8)> {
    vec![(0, 1, 0xA0), (TARGET, 2, 0xB1), (2, 1, 0xC0), (3, 1, 0xD0)]
}

/// Assert the live sector reads back as `expected`: `(slot, generation, tag)`.
fn assert_live_sector(region: &mut FileKeyRegion, expected: &[(u16, u32, u8)]) {
    for offset in 0..SLOTS_PER_SECTOR {
        let index = LIVE_SECTOR + offset as u16;
        let want = expected.iter().find(|(s, _, _)| *s == index).copied();
        let got = read_record(region, index);
        match want {
            None => {
                assert_eq!(got, None, "slot {index} should be absent, but it reads back as a record")
            }
            Some((_, generation, tag)) => {
                let (got_generation, bytes) = got.unwrap_or_else(|| {
                    panic!("slot {index} should hold generation {generation}, but it is absent")
                });
                assert_eq!(got_generation, generation, "slot {index} has the wrong generation");
                assert_eq!(bytes, vec![tag; 48], "slot {index} has the wrong body");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The fault-injecting wrapper (US-1545)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Erase,
    Program,
}

/// What the wrapper does at one flash operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    /// Nothing.
    None,
    /// The n-th mutating operation **fails**: it does nothing and returns
    /// [`E_INJECTED`]. `commit` sees an ordinary failure and unwinds normally,
    /// so its own cleanup runs. This is US-1545's "the failure returns".
    FailAt(u32),
    /// The n-th mutating operation **completes and then the process is cut**:
    /// the wrapper performs the operation and then panics, and the panic is
    /// caught outside `commit`. The bytes are on the medium; the commit's
    /// cleanup never ran. This is US-1544's "a power loss before the marker".
    CutAt(u32),
}

impl Fault {
    fn fires_at(self, index: u32) -> bool {
        match self {
            Fault::None => false,
            Fault::FailAt(n) | Fault::CutAt(n) => index == n,
        }
    }

    fn is_cut(self) -> bool {
        matches!(self, Fault::CutAt(_))
    }
}

/// A [`KeyRegion`] that logs every operation and can fail or cut at one.
///
/// A wrapper rather than a hook on [`FileKeyRegion`] because that file is
/// another story's, and because the trait is the right seam: the commit path
/// sees nothing but `KeyRegion`, so a wrapper proves the behaviour is a
/// property of the commit discipline and not of the host model's internals.
///
/// Only **mutating** operations are numbered. Reads do not change the medium,
/// so a power cut at a read is the same state as a power cut at the operation
/// before it — numbering them would have made the cut points non-distinct and
/// the sweep over them vacuous.
struct Harness<'a> {
    inner: &'a mut FileKeyRegion,
    /// `(operation, slot, 1-based mutating-operation index)`.
    log: Vec<(Op, u16, u32)>,
    mut_ops: u32,
    fault: Fault,
}

impl<'a> Harness<'a> {
    fn new(inner: &'a mut FileKeyRegion) -> Self {
        Harness { inner, log: Vec::new(), mut_ops: 0, fault: Fault::None }
    }

    fn with_fault(inner: &'a mut FileKeyRegion, fault: Fault) -> Self {
        Harness { inner, log: Vec::new(), mut_ops: 0, fault }
    }

    /// The mutating operations, in order, as `(operation, slot)`.
    fn ops(&self) -> Vec<(Op, u16)> {
        self.log.iter().map(|(op, slot, _)| (*op, *slot)).collect()
    }

    /// How many mutating operations the commit issued.
    fn op_count(&self) -> u32 {
        self.mut_ops
    }

    /// The 1-based index of the first operation of `kind` on `target`.
    fn index_of(&self, kind: Op, target: u16) -> u32 {
        self.log
            .iter()
            .find(|(op, slot, _)| *op == kind && *slot == target)
            .map(|(_, _, n)| *n)
            .unwrap_or_else(|| panic!("no {kind:?} on slot {target} was logged: {:?}", self.ops()))
    }
}

/// The panic a [`Fault::CutAt`] raises, and which must never be caught inside
/// the commit frame — if it were, the cut would be modelled as an ordinary
/// failure and US-1545 would be tested twice.
const CUT: &str = "key_region_commit test: power cut";

impl KeyRegion for Harness<'_> {
    fn read_slot(&mut self, target: Slot) -> Result<SlotImage, &'static str> {
        self.inner.read_slot(target)
    }

    fn erase_sector(&mut self, target: Slot) -> Result<(), &'static str> {
        self.mut_ops += 1;
        let index = self.mut_ops;
        self.log.push((Op::Erase, target.index(), index));
        if self.fault.fires_at(index) && !self.fault.is_cut() {
            return Err(E_INJECTED);
        }
        self.inner.erase_sector(target)?;
        if self.fault.fires_at(index) {
            panic!("{CUT} after erasing the sector of slot {}", target.index());
        }
        Ok(())
    }

    fn program(&mut self, target: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        self.mut_ops += 1;
        let index = self.mut_ops;
        self.log.push((Op::Program, target.index(), index));
        if self.fault.fires_at(index) && !self.fault.is_cut() {
            return Err(E_INJECTED);
        }
        self.inner.program(target, offset, data)?;
        if self.fault.fires_at(index) {
            panic!("{CUT} after programming slot {}", target.index());
        }
        Ok(())
    }

    fn slots(&self) -> u32 {
        self.inner.slots()
    }
}

/// Run `f` with panics silenced, and require that it ended in one.
///
/// If `f` returns normally the "power cut" did not happen and the test is
/// vacuous, so this fails loudly rather than quietly passing.
fn power_cut<T: std::fmt::Debug>(f: impl FnOnce() -> T) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(previous);
    let payload = outcome.expect_err("the commit finished; the power cut was never injected");
    // `panic!("{CUT} after ...")` formats, so the payload is a `String`; a bare
    // `panic!(CUT)` would be a `&str`. Accept either, and require the message to
    // be the cut marker so a panic from anywhere else cannot pass for one.
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or_default();
    assert!(
        message.starts_with(CUT),
        "the unwind came from somewhere other than the injected cut: {message:?}"
    );
}

/// The flash-op indices of one uninterrupted commit, measured on a region of its
/// own so that measuring them does not change the state under test.
struct Flash {
    /// The index of the witness program — the commit marker.
    marker: u32,
    /// The index of the live-sector erase: the point of no return.
    live_erase: u32,
    /// Every mutating operation the commit issues.
    total: u32,
}

fn measure(tag: &str) -> Flash {
    let tmp = seeded_file(&format!("{tag}-probe"));
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
    let mut harness = Harness::new(&mut region);
    commit::commit(&mut harness, update_plan(), &body(0xB1)).expect("probe commit");
    let flash = Flash {
        marker: harness.index_of(Op::Program, SCRATCHPAD_SECTOR + TARGET),
        live_erase: harness.index_of(Op::Erase, TARGET),
        total: harness.op_count(),
    };
    assert!(
        flash.marker < flash.live_erase,
        "the commit marker is written before the live erase, never after"
    );
    drop(harness);
    drop(region);
    flash
}

// ---------------------------------------------------------------------------
// US-1544 — an update is all-or-nothing
// ---------------------------------------------------------------------------

#[test]
fn an_update_erases_exactly_one_sector_and_writes_the_commit_marker_last() {
    let tmp = seeded_file("order");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
    let before = live_bytes(&mut region);

    let mut harness = Harness::new(&mut region);
    let report = commit::commit(&mut harness, update_plan(), &body(0xB1)).expect("commit succeeds");
    let ops = harness.ops();
    let live_erase = harness.index_of(Op::Erase, TARGET);
    let marker = harness.index_of(Op::Program, SCRATCHPAD_SECTOR + TARGET);
    drop(harness);

    // Exactly one erase of a sector that holds live records. The two scratchpad
    // erases are counted separately by the report, and they are the whole
    // reason "exactly one erase" is true of the *data* sector and not of the
    // medium: the erase that matters is the one that can destroy a credential.
    assert_eq!(report.live_erases, 1, "one erase of the live sector");
    assert_eq!(report.scratchpad_erases, 2, "prepare + retire");
    let live_erases: Vec<_> =
        ops.iter().filter(|(op, s)| *op == Op::Erase && *s < SCRATCHPAD_SECTOR).copied().collect();
    assert_eq!(
        live_erases,
        vec![(Op::Erase, TARGET)],
        "exactly one erase touched the live sector: {ops:?}"
    );

    // The commit marker is written last within the staging phase: it is the
    // final program before the live sector is erased.
    let last_before_erase = ops[..(live_erase - 1) as usize]
        .iter()
        .rev()
        .find(|(op, _)| *op == Op::Program)
        .copied()
        .expect("the witness was programmed");
    assert_eq!(last_before_erase, (Op::Program, SCRATCHPAD_SECTOR + TARGET));
    assert_eq!(marker, live_erase - 1, "the witness is the last program before the erase");

    // And the whole sector was programmed — the erase cleared three mates that
    // hold live records, so they have to be back.
    assert_eq!(report.staged_programs, SLOTS_PER_SECTOR);
    assert_eq!(report.live_programs, SLOTS_PER_SECTOR);

    assert_ne!(before, live_bytes(&mut region), "the target really did change");
    assert_live_sector(&mut region, &live_sector_at_generation_2());
}

#[test]
fn a_power_loss_before_the_commit_marker_leaves_generation_n_readable() {
    let tmp = TempRegion::new("cut-before-marker");
    let flash = measure("cut-before-marker");

    // Every operation from the first up to — but not including — the live erase.
    // The marker is the last of them, so this range is exactly "a power loss
    // before the marker", plus the one operation immediately after it.
    for cut in 1..flash.live_erase {
        seed_fresh(&tmp);
        let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
        let before = live_bytes(&mut region);
        drop(region);

        let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
        let mut harness = Harness::with_fault(&mut region, Fault::CutAt(cut));
        power_cut(|| {
            let _ = commit::commit(&mut harness, update_plan(), &body(0xB1));
        });
        drop(harness);

        let mut after = FileKeyRegion::open(tmp.path()).expect("region reopens");
        assert_eq!(
            live_bytes(&mut after),
            before,
            "cut at operation {cut} (marker is {}, erase is {}) must leave generation N \
             byte-for-byte intact",
            flash.marker,
            flash.live_erase
        );
        assert_live_sector(&mut after, &live_sector_at_generation_1());

        // The scratchpad is swept by recovery, so nothing partial survives for
        // a later boot to misread as a staged set.
        assert_eq!(
            commit::recover(&mut after, scratchpad()).expect("recover runs"),
            Recovery::Swept,
            "cut at operation {cut} left a complete staged set, which cannot be: the witness is \
             operation {}",
            flash.marker
        );
        assert!(all_erased(&scratchpad_bytes(&mut after)), "the scratchpad was swept");
    }
}

#[test]
fn a_power_loss_after_the_erase_completes_on_recover() {
    let tmp = TempRegion::new("cut-after-erase");
    let flash = measure("cut-after-erase");

    // The end state an uninterrupted commit produces, taken from a region of its
    // own so the comparison is against the real thing rather than a restatement
    // of what the commit is supposed to do.
    let reference_file = seeded_file("cut-after-erase-reference");
    let mut reference = FileKeyRegion::open(reference_file.path()).expect("region opens");
    commit::commit(&mut reference, update_plan(), &body(0xB1)).expect("reference commit");
    let expected_after = live_bytes(&mut reference);
    drop(reference);

    for cut in flash.live_erase..=flash.total {
        seed_fresh(&tmp);

        let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
        let mut harness = Harness::with_fault(&mut region, Fault::CutAt(cut));
        power_cut(|| {
            let _ = commit::commit(&mut harness, update_plan(), &body(0xB1));
        });
        drop(harness);

        let mut after = FileKeyRegion::open(tmp.path()).expect("region reopens");
        let recovery = commit::recover(&mut after, scratchpad()).expect("recover runs");

        // All-or-nothing: the whole sector is the new generation, never a mix.
        assert_eq!(
            live_bytes(&mut after),
            expected_after,
            "cut at operation {cut} did not converge on the committed generation"
        );
        assert_live_sector(&mut after, &live_sector_at_generation_2());
        assert!(all_erased(&scratchpad_bytes(&mut after)), "the scratchpad is clean after recover");
        // What recovery does depends on how much of the copy reached the live
        // sector, and all three answers are whole states:
        //
        // * the last live program is the witness, so a cut there leaves the
        //   live sector byte-identical to the scratchpad — nothing to replay;
        // * the last operation is the retire erase, after which the scratchpad
        //   is empty — nothing staged at all;
        // * anything earlier left the live sector missing bytes it needs back.
        if cut == flash.total {
            assert_eq!(recovery, Recovery::Swept, "cut after the retire erase: nothing staged");
        } else if cut == flash.total - 1 {
            assert!(
                matches!(recovery, Recovery::AlreadyCurrent { .. }),
                "the live sector already equals the staged set, so recovery must not rewrite it: \
                 {recovery:?}"
            );
        } else {
            assert!(
                matches!(recovery, Recovery::Replayed { .. }),
                "cut at operation {cut} should have replayed the staged set, got {recovery:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// US-1545 — a failed commit is self-cleaning
// ---------------------------------------------------------------------------

#[test]
fn a_failure_before_the_erase_removes_this_calls_records_and_keeps_generation_n() {
    let tmp = TempRegion::new("fail-before-erase");
    let flash = measure("fail-before-erase");

    for fail in 1..flash.live_erase {
        seed_fresh(&tmp);
        let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
        let before = live_bytes(&mut region);
        drop(region);

        let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
        let mut harness = Harness::with_fault(&mut region, Fault::FailAt(fail));
        let outcome = commit::commit(&mut harness, update_plan(), &body(0xB1));
        assert!(
            matches!(outcome, Err(CommitError::Flash { reason: E_INJECTED })),
            "operation {fail} is before the point of no return, so this is an ordinary failure: \
             {outcome:?}"
        );
        drop(harness);

        let mut after = FileKeyRegion::open(tmp.path()).expect("region reopens");

        // The previous complete generation is still readable.
        assert_eq!(
            live_bytes(&mut after),
            before,
            "a failure at operation {fail} must leave generation N byte-for-byte intact"
        );
        assert_live_sector(&mut after, &live_sector_at_generation_1());

        // The records written by *this* call are gone.
        assert!(
            all_erased(&scratchpad_bytes(&mut after)),
            "a failure at operation {fail} left this call's staged records behind"
        );

        // And the region is not left permanently unwritable.
        let report = commit_ok(&mut after, TARGET, Domain::Oath, 2, 0xB1);
        assert_eq!(report.live_erases, 1);
        assert_live_sector(&mut after, &live_sector_at_generation_2());
    }
}

#[test]
fn a_failure_after_the_erase_is_repaired_and_the_region_stays_writable() {
    let tmp = TempRegion::new("fail-after-erase");
    let flash = measure("fail-after-erase");

    // The retire erase is excluded here: it is best-effort by design, and it is
    // the subject of `a_failed_retire_still_reports_the_commit_as_successful`.
    for fail in flash.live_erase..flash.total - 1 {
        seed_fresh(&tmp);

        let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
        let mut harness = Harness::with_fault(&mut region, Fault::FailAt(fail));
        let outcome = commit::commit(&mut harness, update_plan(), &body(0xB1));
        assert!(
            matches!(outcome, Err(CommitError::Incomplete { .. })),
            "operation {fail} is at or after the point of no return, so the commit must say so and \
             must not claim a plain failure its cleanup could have handled: {outcome:?}"
        );
        drop(harness);

        let mut after = FileKeyRegion::open(tmp.path()).expect("region reopens");
        let recovery = commit::recover(&mut after, scratchpad()).expect("recover runs");
        assert!(all_erased(&scratchpad_bytes(&mut after)), "the scratchpad is clean after recover");

        // The one thing this state must never be is a sector holding a mixture.
        // Which whole state recovery lands on depends on whether the erase ran,
        // and the refused erase is genuinely distinguishable from the performed
        // one — the staged set is an *upgrade* to the live sector, and applying
        // it over a live record is exactly what the replacement test refuses.
        if fail == flash.live_erase {
            assert_eq!(
                recovery,
                Recovery::Swept,
                "the live erase was refused, so the commit was abandoned rather than replayed"
            );
            assert_live_sector(&mut after, &live_sector_at_generation_1());

            // Not left permanently unwritable: the same write lands on the retry.
            let report = commit_ok(&mut after, TARGET, Domain::Oath, 2, 0xB1);
            assert_eq!(report.live_erases, 1);
            assert_live_sector(&mut after, &live_sector_at_generation_2());
        } else {
            assert!(
                matches!(recovery, Recovery::Replayed { .. }),
                "the erase ran, so the staged set is the only copy and must be replayed: \
                 {recovery:?}"
            );
            assert_live_sector(&mut after, &live_sector_at_generation_2());

            // Not left permanently unwritable: the next write lands, at the next
            // generation, with every mate intact.
            let report = commit_ok(&mut after, 2, Domain::Fido, 2, 0xC1);
            assert_eq!(report.live_erases, 1);
            assert_live_sector(
                &mut after,
                &[(0, 1, 0xA0), (TARGET, 2, 0xB1), (2, 2, 0xC1), (3, 1, 0xD0)],
            );
        }
    }
}

#[test]
fn a_failed_retire_still_reports_the_commit_as_successful() {
    let tmp = TempRegion::new("retire-fault");
    let flash = measure("retire-fault");
    seed_fresh(&tmp);

    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
    let mut harness = Harness::with_fault(&mut region, Fault::FailAt(flash.total));
    let outcome = commit::commit(&mut harness, update_plan(), &body(0xB1));
    drop(harness);

    // The live sector already holds generation N+1 in full. Reporting `Err`
    // here would be lying: a caller that saw a failure would reasonably treat
    // the write as not having happened and try again.
    assert!(
        outcome.is_ok(),
        "the retire erase is best-effort and must not turn a completed commit into a failure: \
         {outcome:?}"
    );
    assert_live_sector(&mut region, &live_sector_at_generation_2());

    // The stale staged set it left is swept by the next boot, not replayed.
    let recovery = commit::recover(&mut region, scratchpad()).expect("recover runs");
    assert!(
        matches!(recovery, Recovery::AlreadyCurrent { .. }),
        "a stale staged set must be recognised, not replayed: {recovery:?}"
    );
    assert!(all_erased(&scratchpad_bytes(&mut region)));
    assert_live_sector(&mut region, &live_sector_at_generation_2());
}

#[test]
fn a_commit_refuses_a_generation_that_does_not_advance() {
    let tmp = seeded_file("generation");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
    let before = live_bytes(&mut region);

    let mut harness = Harness::new(&mut region);
    let outcome = commit::commit(&mut harness, plan(TARGET, Domain::Oath, 1), &body(0xB1));
    assert_eq!(
        outcome,
        Err(CommitError::Generation { target: slot(TARGET), current: 1, offered: 1 }),
        "rewriting generation 1 over generation 1 is a replay by another name"
    );
    // Refused before the scratchpad is even erased: nothing was written.
    assert!(harness.log.is_empty(), "a refused generation must not touch the medium");
    drop(harness);
    assert_eq!(live_bytes(&mut region), before);
}

/// A [`KeyRegion`] that fails one read of one slot, once.
struct FailOnce<'a, 'b> {
    inner: &'a mut FileKeyRegion,
    armed: &'b std::cell::Cell<bool>,
    slot: u16,
}

impl KeyRegion for FailOnce<'_, '_> {
    fn read_slot(&mut self, s: Slot) -> Result<SlotImage, &'static str> {
        if self.armed.get() && s.index() == self.slot {
            self.armed.set(false);
            return Err(E_INJECTED);
        }
        self.inner.read_slot(s)
    }

    fn erase_sector(&mut self, s: Slot) -> Result<(), &'static str> {
        self.inner.erase_sector(s)
    }

    fn program(&mut self, s: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        self.inner.program(s, offset, data)
    }

    fn slots(&self) -> u32 {
        self.inner.slots()
    }
}

#[test]
fn a_commit_refuses_when_a_slot_cannot_be_read() {
    let tmp = seeded_file("read-fault");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
    let before = live_bytes(&mut region);

    // Fail the read the commit makes of its target slot. Treating an unreadable
    // slot as "empty" is US-1573's hazard in its most expensive form: the commit
    // would erase a credential and never report the loss.
    let armed = std::cell::Cell::new(true);
    let mut failer = FailOnce { inner: &mut region, armed: &armed, slot: TARGET };
    let outcome = commit::commit(&mut failer, update_plan(), &body(0xB1));

    assert!(!armed.get(), "the read fault was never injected, so the test is vacuous");
    assert_eq!(outcome, Err(CommitError::Read { slot: slot(TARGET), reason: E_INJECTED }));
    assert_eq!(live_bytes(&mut region), before, "a slot that could not be read must not be erased");
}

// ---------------------------------------------------------------------------
// Sector-mate preservation
// ---------------------------------------------------------------------------

#[test]
fn a_sector_mates_live_record_survives_its_neighbours_update() {
    let tmp = seeded_file("mates");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
    let before = live_bytes(&mut region);

    commit::commit(&mut region, update_plan(), &body(0xB1)).expect("commit succeeds");
    let after = live_bytes(&mut region);

    // Three records the commit did not write, in two key domains, survive
    // byte-for-byte — preserved, not re-derived.
    for index in [0u16, 2, 3] {
        assert_eq!(
            before[index as usize], after[index as usize],
            "slot {index} is a sector-mate and must be carried across the erase unchanged"
        );
    }
    assert_ne!(before[TARGET as usize], after[TARGET as usize], "the target did change");

    assert_live_sector(&mut region, &live_sector_at_generation_2());
    assert_eq!(
        read_record(&mut region, NEIGHBOUR_SECTOR),
        Some((1, vec![0xE0; 48])),
        "the neighbouring sector's record is untouched"
    );
}

#[test]
fn no_commit_erases_a_sector_other_than_its_own() {
    let tmp = seeded_file("no-stray-erase");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");

    let mut harness = Harness::new(&mut region);
    commit::commit(&mut harness, update_plan(), &body(0xB1)).expect("commit succeeds");
    let scratch_end = SCRATCHPAD_SECTOR + SLOTS_PER_SECTOR as u16;
    let stray: Vec<_> =
        harness.ops().into_iter().filter(|(op, s)| *op == Op::Erase && *s >= scratch_end).collect();
    assert_eq!(
        stray,
        Vec::new(),
        "a commit erased a sector that was neither its own nor the scratchpad"
    );
    assert_eq!(SCRATCHPAD_SLOTS, SLOTS_PER_SECTOR, "the scratchpad is exactly one sector");
    drop(harness);
}

// ---------------------------------------------------------------------------
// US-1546 — wipe and factory reset
// ---------------------------------------------------------------------------

#[test]
fn wipe_leaves_the_region_fully_erased_and_re_allocatable() {
    let tmp = seeded_file("wipe");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");
    // A second record in the neighbour sector, so "every key" is more than one.
    commit_ok(&mut region, NEIGHBOUR_SECTOR + 1, Domain::Oath, 1, 0xF0);
    assert!(read_record(&mut region, 0).is_some());
    assert!(read_record(&mut region, NEIGHBOUR_SECTOR + 1).is_some());

    let sectors = commit::wipe(&mut region).expect("wipe runs");
    assert_eq!(sectors, REGION_SLOTS / SLOTS_PER_SECTOR, "every sector was erased");

    // Every slot erased, and no record readable — from either key domain, and
    // whether or not the record could ever have been opened.
    for index in 0..REGION_SLOTS {
        let s = slot(index as u16);
        let raw = region.read_slot(s).expect("slot reads");
        assert!(raw.iter().all(|b| *b == ERASED), "slot {index} is not erased after wipe");
        assert_eq!(read_record(&mut region, index as u16), None, "slot {index} still reads a record");
    }

    // No orphan records: the scratchpad holds nothing a later boot could mistake
    // for a staged set.
    assert_eq!(commit::recover(&mut region, scratchpad()).expect("recover runs"), Recovery::Swept);

    // Re-allocatable: every slot is free, and a write lands.
    let rule = record::RecordOccupancy;
    let mut allocator =
        SlotAllocator::new(&mut region, &rule).expect("the discovery scan reads every slot");
    let allocation = allocator.alloc().expect("a wiped region has room");
    assert_eq!(allocation.slot, slot(0));
    assert_eq!(allocation.generation, 1, "a wiped region restarts at generation 1");
    drop(allocator);

    let report = commit_ok(&mut region, 0, Domain::Fido, 1, 0x11);
    assert_eq!(report.live_erases, 1);
    assert_eq!(read_record(&mut region, 0), Some((1, vec![0x11; 48])));
}

#[test]
fn wipe_is_idempotent() {
    let tmp = seeded_file("wipe-idempotent");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");

    assert_eq!(commit::wipe(&mut region).expect("first wipe"), REGION_SLOTS / SLOTS_PER_SECTOR);
    assert_eq!(commit::wipe(&mut region).expect("second wipe"), REGION_SLOTS / SLOTS_PER_SECTOR);
    for index in 0..REGION_SLOTS {
        assert!(read_record(&mut region, index as u16).is_none());
    }
}

/// A [`KeyRegion`] that fails the n-th erase.
struct FailErase<'a, 'b> {
    inner: &'a mut FileKeyRegion,
    erases: &'b std::cell::Cell<u32>,
}

impl KeyRegion for FailErase<'_, '_> {
    fn read_slot(&mut self, s: Slot) -> Result<SlotImage, &'static str> {
        self.inner.read_slot(s)
    }

    fn erase_sector(&mut self, s: Slot) -> Result<(), &'static str> {
        self.erases.set(self.erases.get() + 1);
        if self.erases.get() == 2 {
            return Err(E_INJECTED);
        }
        self.inner.erase_sector(s)
    }

    fn program(&mut self, s: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        self.inner.program(s, offset, data)
    }

    fn slots(&self) -> u32 {
        self.inner.slots()
    }
}

#[test]
fn wipe_reports_a_failed_erase_rather_than_counting_it() {
    let tmp = TempRegion::new("wipe-fault");
    seed_fresh(&tmp);
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");

    // Fail the second erase: a factory reset that reports success having wiped
    // nothing is worse than one that reports failure. The house precedent is
    // `wipe_internal_fs` returning `bool` (`trusted_backend/device.rs:1092`).
    let erases = std::cell::Cell::new(0u32);
    let region_ref = &mut region;
    let mut failer = FailErase { inner: region_ref, erases: &erases };
    let outcome = commit::wipe(&mut failer);

    assert_eq!(outcome, Err(E_INJECTED), "a refused erase is not an erased sector");
    assert_eq!(erases.get(), 2, "the second erase is the one that was refused");
}

// ---------------------------------------------------------------------------
// The plan is validated before the medium is touched
// ---------------------------------------------------------------------------

#[test]
fn an_invalid_plan_is_refused_without_a_single_flash_operation() {
    let tmp = seeded_file("plan");
    let mut region = FileKeyRegion::open(tmp.path()).expect("region opens");

    let cases: [(&str, CommitPlan); 4] = [
        (
            "target outside the region",
            CommitPlan::new(scratchpad(), slot(REGION_SLOTS as u16 + 8), Domain::Fido, 1),
        ),
        (
            "scratchpad is the sector being written",
            CommitPlan::new(slot(LIVE_SECTOR), slot(2), Domain::Fido, 1),
        ),
        (
            "scratchpad sector is past the region",
            CommitPlan::new(slot(REGION_SLOTS as u16), slot(2), Domain::Fido, 1),
        ),
        ("generation 0", CommitPlan::new(scratchpad(), slot(2), Domain::Fido, 0)),
    ];

    for (why, plan) in cases {
        let mut harness = Harness::new(&mut region);
        let outcome = commit::commit(&mut harness, plan, &body(0x01));
        assert!(matches!(outcome, Err(CommitError::Plan { .. })), "{why}: {outcome:?}");
        assert!(harness.log.is_empty(), "{why}: the medium was touched");
    }
}