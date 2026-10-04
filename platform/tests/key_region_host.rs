//! US-1541 + US-1543: the key region over a host file, and the slot
//! allocator over it.
//!
//! Two stories share this file because they share the thing under test: a
//! [`FileKeyRegion`] is only interesting because [`SlotAllocator`] drives it,
//! and an allocator is only trustworthy because the region underneath it
//! refuses the writes the hardware would refuse. A `Vec<u8>` stand-in would let
//! both pass on a part where neither write is possible.
//!
//! # The record rule in this file is a test double, not a proposal
//!
//! `slotmap` defines what "occupied" has to mean ([`Occupancy`]) without owning
//! the record format, which is US-1542's. The codec now supplies its own rule,
//! `record::RecordOccupancy`; this file still carries [`TestProbe`], over a
//! **provisional** 8-byte header (a 4-byte magic then a little-endian
//! generation), for two reasons:
//!
//! * these tests must not depend on `record.rs`'s byte layout, so a codec
//!   revision cannot turn an allocator assertion into a codec failure — and
//! * `record::RecordOccupancy` answers "occupied" from the header *including
//!   its CRC*, while `TestProbe` answers from the magic alone. The two rules
//!   disagree on a truncated record, and the tests below must be pinned against
//!   a rule the allocator cannot choose.
//!
//! What [`TestProbe`] does **not** model, and must not be mistaken for: a CRC.
//! It calls a truncated record occupied where the codec calls it free. That is
//! the conservative direction, and no assertion here depends on the difference.
//!
//! # Why the region is behind a mutex
//!
//! [`SlotAllocator`] holds `&mut dyn KeyRegion`, which the borrow checker then
//! denies the test — and the test is exactly what needs to count reads and
//! inject a fault. So the region is shared through an `Arc<Mutex<…>>` and the
//! test keeps a second handle to it. The alternative (an allocator that took
//! `&mut dyn KeyRegion` per call) would move a call-site decision — "am I
//! writing or just looking?" — into every caller, which is the kind of
//! complexity AGENTS.md §5 asks to avoid.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use fapico2_platform::flashmap::BLOCK_SIZE;
use fapico2_platform::keyregion::host::{
    self, E_IO, E_NOR_SET_BIT, E_PAGE_ALIGN, E_PAST_SLOT, E_SHORT_READ, E_SLOT_OUT_OF_REGION,
    Faults, FileKeyRegion, Stats,
};
use fapico2_platform::keyregion::slotmap::{self, AllocError, Occupancy, SlotAllocator, SlotImage};
use fapico2_platform::keyregion::{
    FIDO_SLOT_BYTES, KeyRegion, Slot, SlotRead, SLOTS_PER_SECTOR, TOTAL_SLOTS,
};

/// A slot image with every cell erased.
fn erased_slot() -> SlotImage {
    [0xFF; FIDO_SLOT_BYTES as usize]
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A region file in the host temp directory, removed on drop.
///
/// Named with the process id and a per-test tag so the tests can run in
/// parallel without colliding, and so a leftover file from a killed run is
/// identifiable rather than silently reused.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-keyregion-{}-{tag}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// A fresh, pre-erased region of `slots` slots, plus a handle onto it.
    fn create(&self, slots: u32) -> (Region, Handle) {
        Region::new(FileKeyRegion::create(&self.path, slots).expect("temp region file"))
    }

    /// Re-open the same file, as a "power cycle" would.
    fn open(&self) -> (Region, Handle) {
        Region::new(FileKeyRegion::open(&self.path).expect("temp region file"))
    }
}

impl Drop for TempRegion {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Lock the shared region.
///
/// Poisoning is recovered from rather than propagated: a test that panicked
/// while holding the lock has already failed, and propagating the poison would
/// turn one failure into an unrelated-looking one in the next test.
fn lock(m: &Mutex<FileKeyRegion>) -> MutexGuard<'_, FileKeyRegion> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The region as the allocator sees it.
#[derive(Clone)]
struct Region(Arc<Mutex<FileKeyRegion>>);

/// A second handle onto the same region, for the things only the test does.
#[derive(Clone)]
struct Handle(Arc<Mutex<FileKeyRegion>>);

impl Region {
    fn new(file: FileKeyRegion) -> (Self, Handle) {
        let shared = Arc::new(Mutex::new(file));
        (Self(Arc::clone(&shared)), Handle(shared))
    }
}

impl KeyRegion for Region {
    fn read_slot(&mut self, slot: Slot) -> Result<SlotImage, &'static str> {
        lock(&self.0).read_slot(slot)
    }
    fn erase_sector(&mut self, slot: Slot) -> Result<(), &'static str> {
        lock(&self.0).erase_sector(slot)
    }
    fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), &'static str> {
        lock(&self.0).program(slot, offset, data)
    }
    fn slots(&self) -> u32 {
        lock(&self.0).slots()
    }
}

impl Handle {
    fn stats(&self) -> Stats {
        lock(&self.0).stats()
    }
    fn inject_faults(&self, faults: Faults) {
        lock(&self.0).inject_faults(faults);
    }
    fn reset_stats(&self) {
        lock(&self.0).reset_stats();
    }
}

/// The provisional record header — see the module docs.
///
/// Four pages of one record: the header page plus three body pages, which is
/// what a real codec would program to fill a 1 KiB slot. Every page starts at
/// `0xFF` and only clears bits, because that is how NOR is programmed; a
/// fixture that started at `0x00` would hide the model.
const MAGIC: [u8; 4] = *b"KR01";
const PAGE: usize = host::PAGE_BYTES;
const PAGES_PER_SLOT: usize = FIDO_SLOT_BYTES as usize / PAGE;

/// A header page carrying `generation` and a one-byte `tag`.
fn header_page(generation: u32, tag: u8) -> [u8; PAGE] {
    let mut page = [0xFFu8; PAGE];
    page[0..4].copy_from_slice(&MAGIC);
    page[4..8].copy_from_slice(&generation.to_le_bytes());
    page[8] = tag;
    page
}

/// A body page of deterministic bytes — no randomness, so a failure is
/// reproducible from the diff.
fn body_page(seed: u8) -> [u8; PAGE] {
    let mut page = [0xFFu8; PAGE];
    for (i, b) in page.iter_mut().enumerate() {
        *b = seed ^ (i as u8);
    }
    page
}

/// Program one whole record into `slot` and return the exact image the slot
/// now holds — every page, including the untouched `0xFF` tail of the last.
fn program_record(
    region: &mut dyn KeyRegion,
    slot: Slot,
    generation: u32,
    tag: u8,
) -> [u8; FIDO_SLOT_BYTES as usize] {
    let mut image = erased_slot();
    for page_index in 0..PAGES_PER_SLOT {
        let page: [u8; PAGE] = if page_index == 0 {
            header_page(generation, tag)
        } else {
            body_page(tag.wrapping_add(page_index as u8))
        };
        region
            .program(slot, (page_index * PAGE) as u32, &page)
            .expect("program a whole page");
        let at = page_index * PAGE;
        image[at..at + PAGE].copy_from_slice(&page);
    }
    image
}

/// A test-local occupancy rule over the provisional header.
///
/// The production rule is `record::RecordOccupancy`; this one exists so the
/// allocator's tests are pinned against *a* rule the allocator does not own,
/// and so they keep working if that rule's format changes.
struct TestProbe;

impl Occupancy for TestProbe {
    fn occupied(&self, raw: &SlotImage) -> bool {
        raw[0..4] == MAGIC
    }

    fn generation(&self, raw: &SlotImage) -> Option<u32> {
        if raw[0..4] != MAGIC {
            return None;
        }
        Some(u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]))
    }
}

/// Allocate from `alloc` and immediately store a record, so the next
/// allocation sees the slot occupied. Returns the allocation.
fn store(alloc: &mut SlotAllocator<'_, '_>, tag: u8) -> slotmap::Allocation {
    let a = alloc.alloc().expect("a free slot");
    program_record(alloc.region_mut(), a.slot, a.generation, tag);
    a
}

// ---------------------------------------------------------------------------
// US-1541 — "Given a FileKeyRegion over a host file / When records are written
// and read back / Then they are byte-identical"
// ---------------------------------------------------------------------------

#[test]
fn records_written_and_read_back_are_byte_identical() {
    let tmp = TempRegion::new("roundtrip");
    let (mut region, _handle) = tmp.create(8);

    let mut written: Vec<(Slot, [u8; FIDO_SLOT_BYTES as usize])> = Vec::new();
    for i in 0..8u16 {
        let slot = Slot::new(i).expect("8 slots");
        let image = program_record(&mut region, slot, i as u32 + 1, i as u8);
        written.push((slot, image));
    }

    for (slot, image) in &written {
        assert_eq!(
            region.read_slot(*slot).expect("the slot is inside the region"),
            *image,
            "slot {slot:?} must read back byte-for-byte as programmed"
        );
    }

    // Re-opening the same file — the host's "power cycle" — must see the same
    // bytes. A region that only ever agreed with itself in RAM would pass the
    // loop above and be useless on the next boot.
    drop(region);
    let (mut reopened, _) = tmp.open();
    for (slot, image) in &written {
        assert_eq!(
            reopened.read_slot(*slot).expect("reopened"),
            *image,
            "slot {slot:?} must survive a re-open"
        );
    }
}

#[test]
fn an_untouched_slot_reads_as_erased() {
    let tmp = TempRegion::new("erased");
    let (mut region, _) = tmp.create(4);
    assert_eq!(
        region.read_slot(Slot::new(0).unwrap()).unwrap(),
        erased_slot(),
        "a virgin region must be 0xFF everywhere — a zero-filled stand-in would accept \
         records a real part cannot hold"
    );
}

// ---------------------------------------------------------------------------
// US-1541 — "And the region reports the device's capacity"
// ---------------------------------------------------------------------------

#[test]
fn the_region_reports_the_devices_capacity() {
    let full = TempRegion::new("cap-full");
    let (region, _) = full.create(TOTAL_SLOTS);
    assert_eq!(
        region.slots(),
        TOTAL_SLOTS,
        "a region built at the device geometry must report exactly TOTAL_SLOTS"
    );
    drop(region);
    assert_eq!(
        full.open().0.slots(),
        TOTAL_SLOTS,
        "the capacity must be derived from the file, not remembered from construction"
    );

    // The other half of the contract, from `KeyRegion::slots`'s own doc: a short
    // file reports its own capacity. That is the whole reason `slots()` is a
    // method rather than `TOTAL_SLOTS`.
    let small = TempRegion::new("cap-small");
    let (region, _) = small.create(SLOTS_PER_SECTOR * 2);
    assert_eq!(region.slots(), SLOTS_PER_SECTOR * 2);
    assert!(
        region.slots() < TOTAL_SLOTS,
        "a short file must report a smaller region, not the device constant"
    );
    drop(region);

    // And a slot the device geometry allows but this region does not hold is an
    // **error**, not a panic and not a silent read of somebody else's bytes.
    let (mut region, _) = small.open();
    assert_eq!(
        region
            .read_slot(Slot::new((TOTAL_SLOTS - 1) as u16).unwrap())
            .unwrap_err(),
        E_SLOT_OUT_OF_REGION
    );
    assert_eq!(
        region
            .program(Slot::new((TOTAL_SLOTS - 1) as u16).unwrap(), 0, &[0u8; PAGE])
            .unwrap_err(),
        E_SLOT_OUT_OF_REGION
    );
    // A slot the geometry does not allow does not exist at all.
    assert!(Slot::new(TOTAL_SLOTS as u16).is_none());
}

#[test]
fn a_region_that_is_not_whole_sectors_is_refused() {
    // A partial slot cannot be erased without touching its neighbour, and a
    // partial sector has no commit unit (`keyregion/mod.rs:118-132`).
    let tmp = TempRegion::new("ragged");
    assert!(FileKeyRegion::create(tmp.path(), 3).is_err(), "3 slots is not a whole sector");
    assert!(FileKeyRegion::create(tmp.path(), 0).is_err(), "a zero-slot region is not a region");
    assert!(
        FileKeyRegion::create(tmp.path(), TOTAL_SLOTS + SLOTS_PER_SECTOR).is_err(),
        "a region cannot hold more than TOTAL_SLOTS slots"
    );

    std::fs::write(tmp.path(), vec![0xFFu8; BLOCK_SIZE + 1]).expect("write a ragged file");
    let err = match FileKeyRegion::open(tmp.path()) {
        Ok(_) => panic!("a ragged region must be refused"),
        Err(e) => e,
    };
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "a layout violation must be reported as itself, not as a generic I/O error"
    );
}

// ---------------------------------------------------------------------------
// US-1541 — the NOR model
// ---------------------------------------------------------------------------

#[test]
fn a_program_that_would_set_a_bit_is_refused() {
    let tmp = TempRegion::new("nor");
    let (mut region, _) = tmp.create(4);
    let slot = Slot::new(0).unwrap();

    // Cleared bits are legal: programming 0x00 over erased 0xFF is exactly what
    // a record write is.
    region.program(slot, 0, &[0x00; PAGE]).expect("clearing bits are legal");
    assert_eq!(&region.read_slot(slot).unwrap()[..PAGE], &[0x00; PAGE][..]);

    // Setting a bit back is not.
    assert_eq!(
        region.program(slot, 0, &[0xFF; PAGE]).unwrap_err(),
        E_NOR_SET_BIT,
        "programming 0xFF over a programmed 0x00 page must be refused — the part cannot do it"
    );

    // One bit, in one byte, in a window that otherwise *clears* bits: still
    // refused, and refused **wholesale**.
    //
    // The page is first programmed to 0xF0, so it has both 1s (a set bit would
    // clear) and 0s (a set bit would have to go 0 -> 1). A window over a
    // pristine 0xFF page could not demonstrate this at all: every bit there is
    // already clearable, so nothing in it is ever an illegal write.
    region
        .program(slot, PAGE as u32, &[0xF0; PAGE])
        .expect("0xF0 over erased 0xFF only clears bits");
    let mut mixed = [0xF0u8; PAGE];
    mixed[0] = 0x01; // 0 -> 1 against byte 0: illegal
    mixed[1] = 0x00; // 1 -> 0 against byte 1: legal, and must not happen
    assert_eq!(
        region.program(slot, PAGE as u32, &mixed).unwrap_err(),
        E_NOR_SET_BIT
    );
    let back = region.read_slot(slot).unwrap();
    assert_eq!(
        back[PAGE + 1],
        0xF0,
        "a refused program must not partially apply: a real part programs a page atomically, \
         so byte 1 must still hold its 0xF0"
    );
    assert_eq!(
        back[PAGE],
        0xF0,
        "…and byte 0 must not have been written either"
    );

    // Re-programming identical bytes is legal (no bit changes), which is what
    // makes an idempotent commit possible at all.
    region.program(slot, 0, &[0x00; PAGE]).expect("rewriting identical bytes is legal");
}

#[test]
fn erase_restores_the_sector_to_ff() {
    let tmp = TempRegion::new("erase");
    // Two sectors, so the erase's reach is observable rather than "everything".
    let (mut region, handle) = tmp.create(SLOTS_PER_SECTOR * 2);
    let mut images = Vec::new();
    for i in 0..SLOTS_PER_SECTOR * 2 {
        let slot = Slot::new(i as u16).unwrap();
        images.push(program_record(&mut region, slot, i + 1, i as u8));
    }
    handle.reset_stats();

    // The sector is the erase unit, so erasing one of its four slots clears all
    // four — that is `keyregion/mod.rs:118-132`, and a host stand-in that
    // erased only the named slot would let a commit design that cannot work on
    // the part pass here.
    region
        .erase_sector(Slot::new(0).unwrap())
        .expect("erase the first sector");
    assert_eq!(handle.stats().sector_erases, 1, "one sector erased");
    for i in 0..SLOTS_PER_SECTOR {
        let slot = Slot::new(i as u16).unwrap();
        assert_eq!(
            region.read_slot(slot).unwrap(),
            erased_slot(),
            "slot {slot:?} shares the erased sector and must read 0xFF"
        );
    }
    // The second sector is untouched.
    for i in SLOTS_PER_SECTOR..SLOTS_PER_SECTOR * 2 {
        let slot = Slot::new(i as u16).unwrap();
        assert_eq!(
            region.read_slot(slot).unwrap(),
            images[i as usize],
            "slot {slot:?} is in another sector and must be untouched"
        );
    }
}

#[test]
fn a_program_must_be_whole_page_aligned_windows() {
    let tmp = TempRegion::new("pages");
    let (mut region, _) = tmp.create(4);
    let slot = Slot::new(0).unwrap();
    assert_eq!(
        region.program(slot, 0, &[0x00; PAGE - 1]).unwrap_err(),
        E_PAGE_ALIGN,
        "a partial page is not a program the part accepts"
    );
    assert_eq!(
        region.program(slot, 1, &[0x00; PAGE]).unwrap_err(),
        E_PAGE_ALIGN,
        "an unaligned start address is not a page program"
    );
    assert_eq!(
        region.program(slot, FIDO_SLOT_BYTES, &[0x00; PAGE]).unwrap_err(),
        E_PAST_SLOT,
        "a window that would run past the slot must be refused, not clipped — a clipped \
         write stores a record shorter than the codec thinks it stored"
    );
    // The whole slot is the legal window, and it is legal.
    region
        .program(slot, 0, &[0x00; FIDO_SLOT_BYTES as usize])
        .expect("a whole-slot program is four whole pages");
}

// ---------------------------------------------------------------------------
// US-1541 — the error channel
// ---------------------------------------------------------------------------

#[test]
fn a_truncated_region_reads_as_a_fault_not_an_erased_slot() {
    let tmp = TempRegion::new("trunc");
    let (mut region, _) = tmp.create(8);
    program_record(&mut region, Slot::new(0).unwrap(), 1, 0x11);

    // A real I/O failure, not an injected one: the file is truncated behind the
    // open region so slot 3 no longer exists. Returning the `0xFF` the read
    // buffer was initialised with would report the fault as an erased slot —
    // the memoization US-1573 exists to prevent.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(tmp.path())
        .expect("a second handle on the region file");
    f.set_len(3 * 1024 + 7)
        .expect("truncate mid-slot");

    assert_eq!(
        region.read_slot(Slot::new(3).unwrap()).unwrap_err(),
        E_SHORT_READ,
        "a truncated region is a transport failure, not an erased slot"
    );
    assert_eq!(
        region
            .program(Slot::new(3).unwrap(), 0, &[0x00; PAGE])
            .unwrap_err(),
        E_SHORT_READ
    );
    // Slots that still exist are unaffected.
    assert!(region.read_slot(Slot::new(0).unwrap()).is_ok());
}

#[test]
fn injected_faults_reach_the_key_region_error_channel() {
    let tmp = TempRegion::new("inject");
    let (mut region, handle) = tmp.create(4);
    let slot = Slot::new(0).unwrap();

    handle.inject_faults(Faults {
        reads: true,
        erases: true,
        programs: true,
    });
    assert_eq!(region.read_slot(slot).unwrap_err(), E_IO);
    assert_eq!(region.erase_sector(slot).unwrap_err(), E_IO);
    assert_eq!(region.program(slot, 0, &[0x00; PAGE]).unwrap_err(), E_IO);

    handle.inject_faults(Faults::default());
    assert!(region.read_slot(slot).is_ok());
}

// ---------------------------------------------------------------------------
// US-1543 — "When a credential is stored / Then it takes the lowest free slot"
// ---------------------------------------------------------------------------

#[test]
fn allocation_takes_the_lowest_free_slot() {
    let tmp = TempRegion::new("lowest");
    let (mut region, _) = tmp.create(SLOTS_PER_SECTOR * 2);
    let probe = TestProbe;
    let mut alloc = SlotAllocator::new(&mut region, &probe).expect("allocator");

    for expected in 0..SLOTS_PER_SECTOR * 2 {
        let a = store(&mut alloc, expected as u8);
        assert_eq!(
            a.slot,
            Slot::new(expected as u16).unwrap(),
            "allocations must fill from the bottom of the region"
        );
        assert_eq!(
            a.generation, 1,
            "each slot is new, so each starts at generation 1"
        );
    }
    assert_eq!(
        alloc.alloc().unwrap_err(),
        AllocError::Full,
        "a region with no free slot must report Full, not loop"
    );

    // Free the *upper* sector and re-allocate: the lowest free slot is 4, not 5,
    // and not "the first one that was freed most recently".
    alloc
        .region_mut()
        .erase_sector(Slot::new(SLOTS_PER_SECTOR as u16).unwrap())
        .expect("free the second sector");
    let a = alloc.alloc().expect("the second sector is free");
    assert_eq!(a.slot, Slot::new(SLOTS_PER_SECTOR as u16).unwrap());
    assert_eq!(
        a.generation, 2,
        "that slot is at its own generation 1, so its next is 2 — generations are per slot"
    );

    // Freeing the *lower* sector must win, even though the upper one still has
    // room. That is what "lowest" means.
    alloc
        .region_mut()
        .erase_sector(Slot::new(0).unwrap())
        .expect("free the first sector");
    assert_eq!(
        alloc.alloc().expect("slot 0 is free").slot,
        Slot::new(0).unwrap()
    );
}

// ---------------------------------------------------------------------------
// US-1543 — "And its generation is one higher than any generation previously
// seen in that slot"
// ---------------------------------------------------------------------------

#[test]
fn deleting_a_slot_and_reallocating_yields_a_strictly_higher_generation() {
    // One sector, so deleting is a single sector erase and every slot in it
    // goes at once.
    let tmp = TempRegion::new("generation");
    let (mut region, _) = tmp.create(SLOTS_PER_SECTOR);
    let probe = TestProbe;
    let mut alloc = SlotAllocator::new(&mut region, &probe).expect("allocator");

    let mut last = 0u32;
    for round in 0..5u32 {
        let a = alloc.alloc().expect("the region is empty after the erase");
        assert_eq!(
            a.slot,
            Slot::new(0).unwrap(),
            "the freed slot is the lowest free slot"
        );
        assert!(
            a.generation > last,
            "round {round}: generation {} must be strictly higher than the {last} previously \
             seen in this slot",
            a.generation
        );
        assert_eq!(
            a.generation,
            last + 1,
            "it must be exactly one higher, not merely higher"
        );
        last = a.generation;
        program_record(alloc.region_mut(), a.slot, a.generation, round as u8);

        // "Deleted": the sector erase that physically destroys the record, and
        // with it the only durable trace of the generation.
        alloc.region_mut().erase_sector(a.slot).expect("delete the record");
    }
    assert_eq!(last, 5, "five write/delete rounds");

    // The high-water mark is what remembers the erased generations; the region
    // cannot, because the erase removed them.
    assert_eq!(alloc.high_water(Slot::new(0).unwrap()), Some(5));
}

#[test]
fn the_discovery_scan_seeds_the_high_water_from_the_regions_generations() {
    // What lifts the guarantee across a power cycle: a *fresh* allocator over a
    // region that still holds a record reads that record's generation and
    // starts above it. This is the seam `Occupancy::generation` exists for —
    // `TestProbe` fills it provisionally, and the codec fills it for real.
    let tmp = TempRegion::new("seed");
    let (mut region, _) = tmp.create(SLOTS_PER_SECTOR);
    let probe = TestProbe;
    {
        let mut first = SlotAllocator::new(&mut region, &probe).expect("allocator");
        for _ in 0..3 {
            store(&mut first, 0x20);
            first
                .region_mut()
                .erase_sector(Slot::new(0).unwrap())
                .expect("erase");
        }
        // Slot 0 is erased, so the *region* remembers nothing about it. The
        // allocator still does; a fresh one will not. That is the documented
        // limit, stated as an assertion so it cannot drift silently.
        assert_eq!(first.high_water(Slot::new(0).unwrap()), Some(3));
    }
    drop(region);

    // A fresh allocator over the erased region: nothing in flash to seed from.
    let (mut region, _) = tmp.open();
    {
        let mut second = SlotAllocator::new(&mut region, &probe).expect("allocator after reset");
        assert_eq!(second.high_water(Slot::new(0).unwrap()), Some(0));
        let a = second.alloc().expect("slot 0 is free");
        assert_eq!(a.generation, 1);
        // Write a record at a high generation so the region itself holds the
        // floor the next allocator has to clear.
        program_record(second.region_mut(), a.slot, 7, 0x33);
    }
    drop(region);

    let (mut region, _) = tmp.open();
    let mut third = SlotAllocator::new(&mut region, &probe).expect("allocator after reset");
    assert_eq!(
        third.high_water(Slot::new(0).unwrap()),
        Some(7),
        "a fresh allocator must read the generation out of the region, not assume 0"
    );
    // Slot 0 is occupied — by the region's own record, which is what makes it
    // so — so the remaining three fill in order and the region then reports
    // Full.
    let mut taken = Vec::new();
    while let Ok(a) = third.alloc() {
        program_record(third.region_mut(), a.slot, a.generation, 0x44);
        taken.push(a.slot.index());
    }
    assert_eq!(
        taken,
        vec![1, 2, 3],
        "slot 0 must be skipped: the record the discovery scan read is what occupies it"
    );
    assert_eq!(third.alloc().unwrap_err(), AllocError::Full);
}

#[test]
fn a_generation_counter_that_cannot_advance_refuses_rather_than_wrapping() {
    // 2^32 rewrites of one slot is unreachable, and the point is what the code
    // does when it is: `wrapping_add` would turn it into generation 0, which is
    // the replay this module exists to prevent.
    let tmp = TempRegion::new("exhaust");
    let (mut region, _) = tmp.create(SLOTS_PER_SECTOR);
    let probe = TestProbe;
    let mut alloc = SlotAllocator::new(&mut region, &probe).expect("allocator");
    alloc.observe(Slot::new(0).unwrap(), u32::MAX);
    assert_eq!(
        alloc.alloc().unwrap_err(),
        AllocError::GenerationExhausted {
            slot: Slot::new(0).unwrap()
        }
    );
}

#[test]
fn observe_only_ever_raises_a_high_water_mark() {
    let tmp = TempRegion::new("observe");
    let (mut region, _) = tmp.create(SLOTS_PER_SECTOR);
    let probe = TestProbe;
    let mut alloc = SlotAllocator::new(&mut region, &probe).expect("allocator");
    let slot = Slot::new(2).unwrap();
    alloc.observe(slot, 40);
    alloc.observe(slot, 12);
    assert_eq!(
        alloc.high_water(slot),
        Some(40),
        "a lower generation must not lower the mark"
    );
    assert_eq!(alloc.high_water(Slot::new(3).unwrap()), Some(0));
}

// ---------------------------------------------------------------------------
// US-1543 — "And the scan is bounded by the compile-time slot count"
// ---------------------------------------------------------------------------

/// A region that reports a capacity it does not have.
///
/// The hostile case for the bound: `slots()` is a method, so a wrong answer is
/// representable, and `Slot` is a `u16` — an unclamped loop over `u32::MAX`
/// would wrap the index and re-read slots 0..959 until the heat death of the
/// universe. This double refuses every slot at or past `TOTAL_SLOTS` so that
/// losing the clamp is a hard failure rather than a slow one.
struct LyingRegion {
    reported: u32,
    reads: Arc<AtomicU32>,
    /// Slots `program` has been called on, so a fill loop makes progress.
    /// A region that never recorded anything would read as erased forever and
    /// `alloc` would hand out slot 0 for ever — a livelock the test below has
    /// to be able to rule out, not sit inside.
    written: BTreeSet<u16>,
}

impl LyingRegion {
    /// The region, plus an independent witness to how many reads it served.
    /// An `Arc<AtomicU32>` rather than a field the test cannot reach: the
    /// allocator holds `&mut`, so the counter has to be shared to be observed
    /// at all.
    fn new(reported: u32) -> (Self, Arc<AtomicU32>) {
        let reads = Arc::new(AtomicU32::new(0));
        (
            Self {
                reported,
                reads: Arc::clone(&reads),
                written: BTreeSet::new(),
            },
            reads,
        )
    }
}

impl KeyRegion for LyingRegion {
    fn read_slot(&mut self, slot: Slot) -> Result<SlotImage, &'static str> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if slot.index() as u32 >= TOTAL_SLOTS {
            return Err("lying region: slot past TOTAL_SLOTS");
        }
        Ok(if self.written.contains(&slot.index()) {
            // Non-erased, and carrying the provisional header so `TestProbe`
            // calls it occupied. The NOR physics are the file region's job and
            // are pinned by the other tests here; this double only has to
            // occupy the slots it is told to occupy.
            let mut raw = erased_slot();
            raw[0..4].copy_from_slice(&MAGIC);
            raw
        } else {
            erased_slot()
        })
    }

    fn erase_sector(&mut self, _slot: Slot) -> Result<(), &'static str> {
        Ok(())
    }

    fn program(&mut self, slot: Slot, _offset: u32, _data: &[u8]) -> Result<(), &'static str> {
        self.written.insert(slot.index());
        Ok(())
    }

    fn slots(&self) -> u32 {
        self.reported
    }
}

#[test]
fn the_scan_is_bounded_by_the_compile_time_slot_count() {
    // The bound is a named constant that is the region's geometry, not a tuning
    // knob: if `TOTAL_SLOTS` moves and this does not, the module documents a
    // ceiling that does not exist.
    assert_eq!(
        SlotAllocator::scan_bound(),
        TOTAL_SLOTS,
        "the allocator's bound must be the compile-time slot count"
    );
    assert_eq!(slotmap::SCAN_BOUND, TOTAL_SLOTS);
    assert_eq!(
        slotmap::scan_bound_for(u32::MAX),
        TOTAL_SLOTS,
        "a region claiming an impossible capacity must be clamped to the bound"
    );
    assert_eq!(slotmap::scan_bound_for(8), 8, "a smaller region is bounded by itself");
    assert_eq!(
        slotmap::scan_bound_for(TOTAL_SLOTS),
        TOTAL_SLOTS,
        "a region at exactly the bound is not clamped away"
    );

    // And the clamp is load-bearing, not decorative: with it, construction over
    // a lying region performs exactly TOTAL_SLOTS reads. Without it this test
    // walks four billion of them — or trips the `debug_assert` in `slot_at`,
    // which is the better of the two failures.
    let (mut liar, reads) = LyingRegion::new(u32::MAX);
    let probe = TestProbe;
    let mut alloc = SlotAllocator::new(&mut liar, &probe).expect("a bounded scan cannot fault");
    assert_eq!(alloc.bound(), TOTAL_SLOTS);
    assert_eq!(
        reads.load(Ordering::Relaxed),
        TOTAL_SLOTS,
        "the discovery scan must read each slot in the bound exactly once — no more"
    );
    assert_eq!(alloc.slot_reads(), TOTAL_SLOTS);
    assert_eq!(alloc.scans(), 0, "construction is not an allocation scan");

    let a = alloc.alloc().expect("every slot reads as erased");
    assert_eq!(a.slot, Slot::new(0).unwrap());
    assert_eq!(a.generation, 1);
    program_record(alloc.region_mut(), a.slot, a.generation, 0x00);
    assert_eq!(alloc.scans(), 1);
    assert_eq!(
        reads.load(Ordering::Relaxed),
        TOTAL_SLOTS + 1,
        "one more read: the allocation scan stopped at the first free slot, and the \
         bound held even though the region claimed otherwise"
    );

    // Filling the whole region through the same lie terminates, hands out every
    // slot inside the bound exactly once, and then reports `Full` rather than
    // wrapping. The loop is capped as well as terminated: a cap is what makes
    // "bounded" an assertion about this run and not just about the code.
    let mut used = 1u32;
    while used < TOTAL_SLOTS {
        let a = alloc.alloc().expect("the region is not full yet");
        assert_eq!(
            a.slot.index() as u32,
            used,
            "allocation {used} must be slot {used} — no slot outside the bound, and none twice"
        );
        program_record(alloc.region_mut(), a.slot, a.generation, 0x00);
        used += 1;
    }
    assert_eq!(used, TOTAL_SLOTS);
    assert_eq!(
        alloc.alloc().unwrap_err(),
        AllocError::Full,
        "a bounded scan over a full region terminates instead of wrapping the u16 index"
    );
}

#[test]
fn a_real_region_scan_is_bounded_by_its_own_capacity() {
    let tmp = TempRegion::new("scanbound");
    let (mut region, handle) = tmp.create(SLOTS_PER_SECTOR * 2);
    let probe = TestProbe;
    let mut alloc = SlotAllocator::new(&mut region, &probe).expect("allocator");
    assert_eq!(
        alloc.bound(),
        SLOTS_PER_SECTOR * 2,
        "the scan bound is the region's own capacity, below SCAN_BOUND"
    );
    assert_eq!(handle.stats().slot_reads, SLOTS_PER_SECTOR * 2);
    let reads_before = handle.stats().slot_reads;
    alloc.alloc().expect("slot 0 is free");
    assert_eq!(
        handle.stats().slot_reads,
        reads_before + 1,
        "an allocation into an empty region stops at the first slot"
    );
}

// ---------------------------------------------------------------------------
// US-1573 — a fault is never absence
// ---------------------------------------------------------------------------

#[test]
fn a_region_fault_surfaces_as_fault_not_absent() {
    let tmp = TempRegion::new("fault");
    let (mut region, handle) = tmp.create(SLOTS_PER_SECTOR);
    let probe = TestProbe;

    // Build the allocator over a healthy region, then break the transport: the
    // allocator exists and is holding state, so the fault arrives through the
    // paths a real boot-time fault would arrive through.
    let mut alloc = SlotAllocator::new(&mut region, &probe).expect("allocator");
    // Store through the allocator, so slot 0's generation is one the allocator
    // issued and its high-water is one the allocator holds.
    let first = store(&mut alloc, 0x44);
    assert_eq!(first.slot, Slot::new(0).unwrap());
    assert_eq!(first.generation, 1);
    handle.inject_faults(Faults {
        reads: true,
        ..Faults::default()
    });

    // `read` classifies it as a fault. `present()` is `None` for both fault and
    // absence (`keyregion/mod.rs:404-411`) — which is exactly why the variant
    // exists to be matched on.
    let outcome = alloc.read(Slot::new(1).unwrap());
    assert!(
        outcome.is_fault(),
        "a transport error must not read as an absent record"
    );
    assert!(
        !matches!(outcome, SlotRead::Absent),
        "US-1573: a fault memoized as absence is how the next enrollment builds a second \
         identity on top of the owner's"
    );
    assert_eq!(outcome.present(), None);

    // And `alloc` refuses rather than skipping the unreadable slot. This is the
    // expensive form of the same bug: slot 0 holds a real record, and an
    // allocator that treated "could not read" as "free" would hand slot 0 out
    // and destroy it.
    match alloc.alloc() {
        Err(AllocError::Fault { slot, .. }) => assert_eq!(slot, Slot::new(0).unwrap()),
        Ok(a) => panic!("a faulted read must abort the allocation, got slot {:?}", a.slot),
        Err(e) => panic!("a faulted read must abort the allocation, got {e:?}"),
    }
    assert_eq!(
        alloc.high_water(Slot::new(0).unwrap()),
        Some(1),
        "an allocation aborted by a fault must not have moved the high-water mark"
    );

    // Recovery: the same allocator, once the transport works, sees the record it
    // could not read before and moves on.
    handle.inject_faults(Faults::default());
    let a = alloc.alloc().expect("the region reads again");
    assert_eq!(a.slot, Slot::new(1).unwrap());
    assert_eq!(a.generation, 1);
    assert!(!alloc.read(Slot::new(0).unwrap()).is_fault());
    assert_eq!(
        alloc.high_water(Slot::new(0).unwrap()),
        Some(1),
        "a record the allocator could not read must not have had its generation reset"
    );
}

#[test]
fn an_unreadable_region_cannot_produce_an_allocator_at_all() {
    // A half-seeded allocator is indistinguishable from a fresh one: every
    // unknown high-water reads as 0, which is generation 1 waiting to be issued
    // into a slot that has been at 900. So the discovery scan's fault aborts
    // construction.
    let tmp = TempRegion::new("faultnew");
    let (mut region, handle) = tmp.create(SLOTS_PER_SECTOR);
    handle.inject_faults(Faults {
        reads: true,
        ..Faults::default()
    });
    let probe = TestProbe;
    match SlotAllocator::new(&mut region, &probe) {
        Err(AllocError::Fault { slot, .. }) => assert_eq!(slot, Slot::new(0).unwrap()),
        Ok(_) => panic!(
            "construction must fail rather than return an allocator with no generations in it"
        ),
        Err(e) => panic!("construction must fail with a fault, got {e:?}"),
    }
}