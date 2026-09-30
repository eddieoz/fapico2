//! US-422 (SECURE-PERSIST Phase A): the flash-slot `ImageSink`.
//!
//! `FlashSlotSink` is the behavior-identical port of the old
//! `persist_secure_partition`/`secure_slot_matches` pair (deleted from
//! `firmware/src/main.rs`): primary-then-shadow, compare-then-write, a
//! read failure forces a reprogram (the safe side). These host tests pin the
//! byte-exact behavior through a NOR-model fake flash, driven by the REAL
//! gate (`persist_apps`) plus direct `FlashSlotSink::program`-shaped
//! inspection of the slot bytes.
//!
//! Slot offsets mirror the device constants: `primary = 0`,
//! `shadow = SLOT`, `SLOT = 12288` (the device's `SECURE_SLOT_BYTES`:
//! `PARTITION_IMAGE_MAX` = 9,100 B rounded up to 3 × 4 KiB NOR sectors).

use fapico2_platform::dispatch::{App, MAX_RESPONSE, SW_OK};
use fapico2_platform::persist::persist_apps;
use fapico2_platform::persist_sink::{FlashSlotSink, SlotFlash};
use fapico2_platform::secure_store::{
    HostSecureStore, Rp2350SecureStore, SecureStore, SecureStoreError,
};
use fapico2_platform::store_v3::{emulation_store_key, sealed_image_is_valid};
use heapless::Vec as HeaplessVec;
use std::collections::BTreeMap;

/// Test flash geometry (mirrors the device slot constants, see module docs).
const FLASH_SIZE: usize = 64 * 1024;
const PRIMARY: u32 = 0;
const SLOT: u32 = 12288;
const SHADOW: u32 = SLOT;

/// One logged flash operation (US-427 slot-order pin; the compare reads are
/// traffic, not slot writes, and are not logged).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Erase,
    Write,
}

/// NOR model over a `Vec`: erased bytes are 0xFF; `write` may only clear
/// bits; `erase(from..to)` fills 0xFF. Counters + forced failure injection.
struct FakeFlash {
    /// The whole "flash" (64 KiB), starts erased (0xFF).
    mem: Vec<u8>,
    erase_count: usize,
    write_count: usize,
    read_count: usize,
    /// `(from, to)` of every erase — which slot region was touched.
    erase_ranges: Vec<(u32, u32)>,
    /// `(addr, len)` of every write.
    write_addrs: Vec<(u32, usize)>,
    /// US-427: every erase/write in program order (`op, addr, len`).
    ops: Vec<(Op, u32, usize)>,
    fail_reads: bool,
    /// When true, writes to the shadow slot fail (the US-391 durability pair's
    /// failure mode: a power loss after the primary landed). Erases always
    /// succeed.
    fail_writes: bool,
}

impl FakeFlash {
    fn new(size: usize) -> Self {
        Self {
            mem: vec![0xFF; size],
            erase_count: 0,
            write_count: 0,
            read_count: 0,
            erase_ranges: Vec::new(),
            write_addrs: Vec::new(),
            ops: Vec::new(),
            fail_reads: false,
            fail_writes: false,
        }
    }
}

impl SlotFlash for FakeFlash {
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), SecureStoreError> {
        self.read_count += 1;
        if self.fail_reads {
            return Err(SecureStoreError::Flash);
        }
        let start = addr as usize;
        buf.copy_from_slice(&self.mem[start..start + buf.len()]);
        Ok(())
    }
    fn erase(&mut self, from: u32, to: u32) -> Result<(), SecureStoreError> {
        self.erase_count += 1;
        self.erase_ranges.push((from, to));
        self.ops.push((Op::Erase, from, (to - from) as usize));
        self.mem[from as usize..to as usize].fill(0xFF);
        Ok(())
    }
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), SecureStoreError> {
        self.write_count += 1;
        self.write_addrs.push((addr, data.len()));
        self.ops.push((Op::Write, addr, data.len()));
        if self.fail_writes && addr >= SHADOW {
            return Err(SecureStoreError::Flash);
        }
        // NOR: a program may only clear bits (1 → 0).
        let dst = &mut self.mem[addr as usize..addr as usize + data.len()];
        for (d, b) in dst.iter_mut().zip(data) {
            *d &= b;
        }
        Ok(())
    }
}

/// Stub dispatcher app with an explicit dirty flag (pattern:
/// `tests/persist_gate.rs`): writes a known value when dirty, clears dirty
/// only when the store write succeeds.
///
/// US-1010: the value is owned rather than `'static` so
/// [`StubApp::bump_value`] can change it between persists — the shape of the
/// FIDO sign-count bump, where the sealed image is *different* every time and
/// the sink's compare-then-write can never short-circuit.
struct StubApp {
    aid: &'static [u8],
    dirty: bool,
    value: HeaplessVec<u8, 64>,
}

impl StubApp {
    fn new(aid: &'static [u8]) -> Self {
        let mut value = HeaplessVec::new();
        value.extend_from_slice(b"stub-state-v1").expect("fixture fits");
        Self {
            aid,
            dirty: false,
            value,
        }
    }

    /// US-1010: one FIDO-sign-count-shaped mutation of the persisted state —
    /// the value changes, so the next persist's image differs from the one
    /// already in both slots.
    fn bump_value(&mut self) {
        let last = self.value.len() - 1;
        self.value[last] = self.value[last].wrapping_add(1);
    }
}

impl App for StubApp {
    fn aid(&self) -> &[u8] {
        self.aid
    }

    fn select(&mut self, _internal: bool) -> u16 {
        SW_OK
    }

    fn deselect(&mut self) {}

    fn process(&mut self, _apdu: &[u8], _resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {}

    fn persist_state(&mut self, store: &mut dyn SecureStore) -> bool {
        if !self.dirty {
            return false;
        }
        let wrote = store.write(b"stub.state", &self.value).is_ok();
        if wrote {
            self.dirty = false;
        }
        wrote
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }
}

/// Run the gate once with a dirty app; returns the sink's flash after the run.
fn run_gate(
    app: &mut StubApp,
    store: &mut HostSecureStore,
    sink: &mut FlashSlotSink<FakeFlash>,
) -> bool {
    app.dirty = true;
    persist_apps(&mut [app], store, sink)
}

/// US-715: the sink walks the image in 256-byte windows, so the write log is
/// a chunk sequence — assert every program run covers exactly
/// `[base, base+len)` in order, each chunk ≤ 256 B, no gap or overshoot.
/// (A slot may be programmed more than once across the test: each run
/// restarts at the slot base.)
fn assert_write_chunks(f: &FakeFlash, base: u32, len: usize) {
    let mut at: Option<usize> = None; // None = between runs
    let mut runs = 0usize;
    for (addr, n) in f
        .write_addrs
        .iter()
        .filter(|(a, _)| (*a as usize) >= base as usize && (*a as usize) < base as usize + len)
    {
        let (a, n) = (*addr as usize, *n);
        assert!(n <= 256, "the windowed program writes in ≤256-byte chunks");
        match at {
            Some(at_) => assert_eq!(a, at_, "chunks must be contiguous within a run"),
            None => {
                assert_eq!(a, base as usize, "each run must start at the slot base");
                runs += 1;
            }
        }
        at = Some(a + n);
        if at == Some(base as usize + len) {
            at = None; // the run covered the image exactly
        }
    }
    assert!(at.is_none(), "the last run must cover the image exactly");
    assert!(runs >= 1, "at least one complete program run must be logged");
}

/// The number of ≤256-byte windowed writes one slot program takes.
fn write_chunks(len: usize) -> usize {
    len.div_ceil(256)
}

#[test]
fn first_persist_programs_both_slots() {
    let mut app = StubApp::new(&[0xA0, 0x00]);
    let mut store = HostSecureStore::new();
    let mut sink = FlashSlotSink::new(FakeFlash::new(FLASH_SIZE), PRIMARY, SHADOW, SLOT as usize);

    assert!(run_gate(&mut app, &mut store, &mut sink));
    assert!(!app.dirty, "a successful persist must clear the app's dirty flag");

    let f = sink.flash_mut();
    assert_eq!(f.erase_count, 2, "both slots must be erased");
    let mem = f.mem.clone();

    // Each slot region contains the EXACT image: validate it (US-915: a
    // sealed image — tag-verified under the emulation store key),
    // byte-compare against the store's image, and reload into a fresh
    // `HostSecureStore` — the value must be present in BOTH slots.
    let expected = store.partition_image();
    let key = emulation_store_key();
    assert_eq!(
        f.write_count,
        2 * write_chunks(expected.len()),
        "both slots programmed (US-715: as ≤256-byte windowed writes)"
    );

    // US-427 (scenario i): the full program-order interleaving, pinned in
    // sequence — the primary slot is COMPLETELY handled (erase, then
    // program) before the shadow slot is touched at all. A power loss
    // mid-program therefore destroys at most the slot being written; at
    // every other instant the other slot still holds a valid image, and
    // boot's primary→shadow precedence follows this order. US-715: the
    // program step is a run of ≤256-byte windowed writes covering the
    // image exactly (the erase granularity and slot order are unchanged).
    assert_eq!(f.erase_ranges[0], (PRIMARY, PRIMARY + SLOT), "the primary slot is erased first");
    assert_eq!(
        f.erase_ranges[1],
        (SHADOW, SHADOW + SLOT),
        "then the shadow slot (US-427: the full primary-then-shadow
        erase/program interleaving — a torn write destroys at most the
        slot being written, and boot's slot precedence follows this order)"
    );
    let shadow_erase = f
        .ops
        .iter()
        .position(|(op, a, _)| *op == Op::Erase && *a == SHADOW)
        .expect("the shadow erase must be logged");
    let last_primary_write = f
        .ops
        .iter()
        .rposition(|(op, a, _)| *op == Op::Write && (PRIMARY..SHADOW).contains(a))
        .expect("the primary writes must be logged");
    assert!(
        last_primary_write < shadow_erase,
        "the primary slot is completely handled (erase + every write chunk) before the shadow erase"
    );
    assert_write_chunks(f, PRIMARY, expected.len());
    assert_write_chunks(f, SHADOW, expected.len());
    for base in [PRIMARY, SHADOW] {
        let region = &mem[base as usize..(base + SLOT) as usize];
        assert!(
            sealed_image_is_valid(region, &key),
            "the slot must hold a valid (tag-verified) sealed partition image"
        );
        assert_eq!(
            region[..expected.len()],
            expected[..],
            "the slot bytes must be the exact image"
        );
        let mut restored = HostSecureStore::new();
        restored.from_partition_image(region);
        assert!(
            restored.contains(b"stub.state"),
            "the app's value must be present in the slot"
        );
    }
}

#[test]
fn identical_second_persist_programs_nothing() {
    let mut app = StubApp::new(&[0xA0, 0x00]);
    let mut store = HostSecureStore::new();
    let mut sink = FlashSlotSink::new(FakeFlash::new(FLASH_SIZE), PRIMARY, SHADOW, SLOT as usize);

    assert!(run_gate(&mut app, &mut store, &mut sink));
    let reads_after_run1 = sink.flash_mut().read_count;

    // Re-dirty the SAME app with the SAME value: the compare must
    // short-circuit both slots (0 new erases / 0 new writes).
    assert!(run_gate(&mut app, &mut store, &mut sink));

    let f = sink.flash_mut();
    assert_eq!(f.erase_count, 2, "an unchanged image must not erase any slot (2 total after two runs)");
    assert_eq!(
        f.write_count,
        2 * write_chunks(store.partition_image().len()),
        "an unchanged image must not program any slot (2 total after two runs)"
    );
    assert!(
        f.read_count > reads_after_run1,
        "the compare reads the slot contents on the second run"
    );
    assert!(!app.dirty);
}

#[test]
fn stale_shadow_slot_is_reprogrammed_alone() {
    let mut app = StubApp::new(&[0xA0, 0x00]);
    let mut store = HostSecureStore::new();
    let mut sink = FlashSlotSink::new(FakeFlash::new(FLASH_SIZE), PRIMARY, SHADOW, SLOT as usize);

    assert!(run_gate(&mut app, &mut store, &mut sink));
    let primary_after_run1 = sink
        .flash_mut()
        .mem[PRIMARY as usize..(PRIMARY + SLOT) as usize]
        .to_vec();

    // Corrupt one byte inside the shadow image (bit rot / power loss — within
    // the image's own bounds, so the compare can see it).
    sink.flash_mut().mem[(SHADOW + 12) as usize] ^= 0xFF;

    assert!(run_gate(&mut app, &mut store, &mut sink));

    let f = sink.flash_mut();
    assert_eq!(f.erase_count, 3, "exactly one erase added (the stale shadow)");
    let expected = store.partition_image();
    assert!(
        sealed_image_is_valid(&f.mem[PRIMARY as usize..(PRIMARY + SLOT) as usize], &emulation_store_key()),
        "the primary must still hold a valid image"
    );
    assert_eq!(
        f.write_count,
        3 * write_chunks(expected.len()),
        "exactly one slot's worth of windowed writes added (the stale shadow)"
    );
    assert_eq!(
        f.erase_ranges[2],
        (SHADOW, SHADOW + SLOT),
        "the erased slot must be the shadow"
    );
    assert_write_chunks(f, SHADOW, expected.len());
    assert_eq!(
        &f.mem[PRIMARY as usize..(PRIMARY + SLOT) as usize],
        &primary_after_run1,
        "the primary region must be byte-identical to after run 1"
    );
    // The shadow holds the fresh image again.
    assert!(
        sealed_image_is_valid(&f.mem[SHADOW as usize..(SHADOW + SLOT) as usize], &emulation_store_key()),
        "the reprogrammed shadow must hold a valid image"
    );
    assert_eq!(
        &f.mem[SHADOW as usize..SHADOW as usize + expected.len()],
        &expected[..]
    );
}

#[test]
fn read_failure_forces_reprogram() {
    let mut app = StubApp::new(&[0xA0, 0x00]);
    let mut store = HostSecureStore::new();
    let mut sink = FlashSlotSink::new(FakeFlash::new(FLASH_SIZE), PRIMARY, SHADOW, SLOT as usize);

    assert!(run_gate(&mut app, &mut store, &mut sink));
    sink.flash_mut().fail_reads = true;

    // Contents still match, but an unreadable slot must be reprogrammed
    // (the safe side): both slots are erased + written again.
    assert!(run_gate(&mut app, &mut store, &mut sink));

    let f = sink.flash_mut();
    assert_eq!(f.erase_count, 4, "both slots reprogrammed despite matching content");
    let expected = store.partition_image();
    assert_eq!(
        f.write_count,
        4 * write_chunks(expected.len()),
        "both slots reprogrammed despite matching content"
    );
    let mem = f.mem.clone();
    for base in [PRIMARY, SHADOW] {
        assert!(
            sealed_image_is_valid(&mem[base as usize..(base + SLOT) as usize], &emulation_store_key()),
            "the reprogrammed slot must hold a valid image"
        );
        assert_eq!(&mem[base as usize..base as usize + expected.len()], &expected[..]);
    }
}

#[test]
fn failing_sink_keeps_apps_dirty_and_gate_false() {
    let mut app = StubApp::new(&[0xA0, 0x00]);
    let mut store = HostSecureStore::new();
    let mut sink = FlashSlotSink::new(FakeFlash::new(FLASH_SIZE), PRIMARY, SHADOW, SLOT as usize);
    sink.flash_mut().fail_writes = true;

    app.dirty = true;
    assert!(
        !persist_apps(&mut [&mut app], &mut store, &mut sink),
        "a failing sink must return false (no success reply may go out)"
    );
    assert!(
        app.dirty,
        "the app must STILL be dirty after a sink failure (retry next command)"
    );
    // The failing run: primary erase + full windowed program landed, then
    // the shadow's first write chunk failed (after its erase).
    let f = sink.flash_mut();
    assert_eq!(f.erase_count, 2, "both slots erased before the shadow write failed");
    let mem = f.mem.clone();
    let expected = store.partition_image();
    let c = write_chunks(expected.len());
    assert_eq!(
        f.write_count,
        c + 1,
        "the primary's full chunk run landed, then the shadow's first chunk failed"
    );
    assert!(
        sealed_image_is_valid(&mem[PRIMARY as usize..(PRIMARY + SLOT) as usize], &emulation_store_key()),
        "the primary must hold the image after the failed run"
    );

    // Recovery: the flag clears; the gate's re-dirtied app retries. The
    // primary now matches → the compare skips it; only the shadow is
    // programmed (+1 erase, + its chunk run).
    sink.flash_mut().fail_writes = false;
    assert!(persist_apps(&mut [&mut app], &mut store, &mut sink));
    assert!(!app.dirty, "a successful retry must clear the app's dirty flag");
    let f = sink.flash_mut();
    assert_eq!(f.erase_count, 3, "the retry adds exactly one erase (primary skipped)");
    assert_eq!(
        f.write_count,
        2 * c + 1,
        "the retry adds exactly the shadow's chunk run (primary skipped)"
    );
    assert_eq!(f.erase_ranges[2], (SHADOW, SHADOW + SLOT), "the retried slot is the shadow");
    assert_write_chunks(f, SHADOW, expected.len());
}

// ---------------------------------------------------------------------------
// US-1010 (EPIC `RS-KEY-ADOPT` Phase 2) — the erase-budget measurement.
//
// This block is an INSTRUMENT, not a second copy of the gate. It measures
// what `FlashSlotSink::program` actually asks the flash driver to erase and
// prints the figures as `ERASE_BUDGET key=value` lines;
// `tests/scripts/check_erase_budget.py` parses that output, compares it with
// `docs/erase-budget.md`, and holds the absolute expectations. The asserts
// here are only the self-consistency relations that must hold by
// construction — a genuinely broken sink fails them rather than publishing a
// number that is merely self-consistent.
//
// Why the device geometry and not the `SLOT = 12288` the tests above use: the
// wear question is about the *shipping* layout, which is sized from the
// SEALED (format-v3) image bound, not the legacy v2 one.
// ---------------------------------------------------------------------------

/// NOR erase granularity the RP2350 flash driver programs with — the device's
/// `FLASH_ERASE_SIZE` (`firmware/src/boot.rs:192`).
const NOR_ERASE_GRANULARITY: usize = 4096;

/// The **device** slot size, restating `firmware/src/boot.rs:47-48`:
///
/// ```text
/// SECURE_SLOT_BYTES = SECURE_PARTITION_SIZE.div_ceil(FLASH_ERASE_SIZE) * FLASH_ERASE_SIZE
/// SECURE_PARTITION_SIZE = Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX
/// ```
///
/// `boot.rs` is arm-only (it names the embassy flash driver), so the formula
/// is re-evaluated here against the host-visible sealed-image bound.
/// `device_slot_geometry_is_the_figure_the_budget_publishes` pins the result,
/// so a drift on either side is a failing test rather than a silently
/// republished number.
const DEVICE_SLOT_BYTES: usize = Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX
    .div_ceil(NOR_ERASE_GRANULARITY)
    * NOR_ERASE_GRANULARITY;

/// The device's primary/shadow slot bases (`firmware/src/boot.rs:58-59`),
/// rebased to 0 — only the *relative* geometry matters to the sink, and a
/// 0-based fake keeps the NOR model inside a 64 KiB `Vec`.
const DEVICE_PRIMARY: u32 = 0;
const DEVICE_SHADOW: u32 = DEVICE_SLOT_BYTES as u32;

/// US-1010: how many 4 KiB NOR sectors the erase calls logged since `mark`
/// cover. This is the "sector-erase count" half of the measurement: what the
/// sink asks to be erased, expressed in the unit the part's endurance
/// datasheet is quoted in. Alignment is asserted, not assumed — the HAL
/// refuses an unaligned range in `check_erase` before touching silicon.
fn sector_erasures_since(f: &FakeFlash, mark: usize) -> usize {
    f.erase_ranges[mark..]
        .iter()
        .map(|(from, to)| {
            let g = NOR_ERASE_GRANULARITY as u32;
            assert_eq!(
                from % g,
                0,
                "an erase range must be sector-aligned or the HAL refuses it \
                 (embedded_storage::nor_flash::check_erase)"
            );
            assert_eq!(to % g, 0, "an erase range must be sector-aligned");
            assert!(
                *from == DEVICE_PRIMARY || *from == DEVICE_SHADOW,
                "the sink erases a slot window, never a sub-range of one"
            );
            ((to - from) / g) as usize
        })
        .sum()
}

/// US-1010 (lifetime correction): how the sector erasures are **distributed**.
///
/// `sector_erasures_since` counts erase *operations*. This counts, per
/// sector, how many of them landed on **that** sector, and returns
/// `(sectors touched, busiest sector's count)`.
///
/// This is the whole lifetime question, and it is a different question.
/// NOR endurance is specified per sector, so what bounds the product is
/// the rate at which the busiest single sector is erased — not the number
/// of erases issued in a persist. The two differ by a factor of
/// `sectors touched` whenever the erases land on distinct sectors, which is
/// exactly the confusion that produced the first published ceiling of
/// 12,500. The instrument measures the distribution rather than assuming
/// it, so the document's arithmetic rests on a figure that can disagree
/// with it.
///
/// The first element is a **footprint**, not a count over time: a persist
/// erases the same sectors every time, so the number of distinct sectors in
/// the whole run is the number a single persist touches. The second is a
/// total over the run and must be divided by the run length to become a
/// rate; the caller asserts divisibility before dividing.
fn sector_erase_profile_since(f: &FakeFlash, mark: usize) -> (usize, usize) {
    let g = NOR_ERASE_GRANULARITY as u32;
    let mut per_sector: BTreeMap<u32, usize> = BTreeMap::new();
    for (from, to) in &f.erase_ranges[mark..] {
        let mut addr = *from;
        while addr < *to {
            assert_eq!(addr % g, 0, "an erase range must be sector-aligned");
            *per_sector.entry(addr / g).or_insert(0) += 1;
            addr += g;
        }
    }
    (
        per_sector.len(),
        per_sector.values().copied().max().unwrap_or(0),
    )
}

/// US-1010: the measurement `docs/erase-budget.md` publishes.
#[test]
fn erase_budget_figures() {
    /// Persists in the changed-image run. > 1 so a per-persist figure is a
    /// rate, not a single sample.
    const PERSISTS: usize = 8;

    let mut app = StubApp::new(&[0xA0, 0x00]);
    let mut store = HostSecureStore::new();
    let mut sink = FlashSlotSink::new(
        FakeFlash::new(FLASH_SIZE),
        DEVICE_PRIMARY,
        DEVICE_SHADOW,
        DEVICE_SLOT_BYTES,
    );

    // (1) The defect as it ships: a FIDO sign-count bump changes the sealed
    // image on every `getAssertion`, so `slot_matches` can never short-circuit
    // and every persist erases both slot windows in full.
    let mark = sink.flash_mut().erase_count;
    for _ in 0..PERSISTS {
        app.bump_value();
        assert!(run_gate(&mut app, &mut store, &mut sink));
    }
    let f = sink.flash_mut();
    let changed_calls = f.erase_count - mark;
    let changed_sectors = sector_erasures_since(f, mark);
    assert_eq!(
        changed_sectors,
        changed_calls * (DEVICE_SLOT_BYTES / NOR_ERASE_GRANULARITY),
        "each erase call must cover exactly one whole slot window"
    );
    // The distribution, not just the total. `busiest % PERSISTS == 0` is
    // asserted rather than rounded: a per-persist rate published by integer
    // division of an uneven count would quietly understate the wear.
    let (distinct_sectors, busiest) = sector_erase_profile_since(f, mark);
    assert_eq!(
        busiest % PERSISTS,
        0,
        "the per-sector erase count must be uniform across the run, or the \
         per-persist rate below is not the rate"
    );
    let mark = sink.flash_mut().erase_count;

    // (2) Control — the one that makes the measurement able to FAIL. An
    // unchanged image must erase nothing at all. A sink that stopped
    // comparing (i.e. the pre-compare-then-write behaviour) would show a
    // non-zero count here, and `check_erase_budget.py` would go red.
    assert!(run_gate(&mut app, &mut store, &mut sink));
    let unchanged_calls = sink.flash_mut().erase_count - mark;
    let unchanged_sectors = sector_erasures_since(sink.flash_mut(), mark);

    // (3) Control — one stale slot is repaired on its own; the untouched slot
    // is not worn again.
    sink.flash_mut().mem[(DEVICE_SHADOW + 12) as usize] ^= 0xFF;
    let mark = sink.flash_mut().erase_count;
    assert!(run_gate(&mut app, &mut store, &mut sink));
    let partial_calls = sink.flash_mut().erase_count - mark;

    let sectors_per_slot = DEVICE_SLOT_BYTES / NOR_ERASE_GRANULARITY;
    println!("ERASE_BUDGET sector_granularity_bytes={NOR_ERASE_GRANULARITY}");
    println!("ERASE_BUDGET slots=2");
    println!("ERASE_BUDGET slot_bytes={DEVICE_SLOT_BYTES}");
    println!("ERASE_BUDGET sectors_per_slot={sectors_per_slot}");
    println!(
        "ERASE_BUDGET changed_erase_calls_per_persist={}",
        changed_calls / PERSISTS
    );
    println!(
        "ERASE_BUDGET changed_sector_erasures_per_persist={}",
        changed_sectors / PERSISTS
    );
    // The lifetime figures. `distinct == total` is the load-bearing one: it
    // says the persist's erases land on 8 *different* sectors, so no sector
    // collects more than one of them, and `max == 1` is the per-sector rate
    // the ceiling is actually derived from.
    println!(
        "ERASE_BUDGET changed_distinct_sectors_erased_per_persist={distinct_sectors}"
    );
    println!(
        "ERASE_BUDGET changed_max_erases_per_sector_per_persist={}",
        busiest / PERSISTS
    );
    println!("ERASE_BUDGET unchanged_erase_calls={unchanged_calls}");
    println!("ERASE_BUDGET unchanged_sector_erasures={unchanged_sectors}");
    println!("ERASE_BUDGET partial_erase_calls={partial_calls}");
    println!(
        "ERASE_BUDGET partial_sector_erasures={}",
        partial_calls * sectors_per_slot
    );
}

/// US-1010: the slot geometry this file's measurement rests on is the figure
/// `docs/erase-budget.md` publishes. If either the sealed-image bound or the
/// erase granularity moves, this fails here rather than the gate silently
/// re-deriving a different budget.
#[test]
fn device_slot_geometry_is_the_figure_the_budget_publishes() {
    assert_eq!(
        DEVICE_SLOT_BYTES, 16_384,
        "US-1010 publishes a 16,384-byte slot (4 x 4 KiB sectors); \
         SEALED_PARTITION_IMAGE_MAX or the granularity moved — \
         re-measure and update docs/erase-budget.md"
    );
    assert_eq!(
        DEVICE_SLOT_BYTES + DEVICE_SLOT_BYTES,
        32_768,
        "two slots must still fit the 64 KiB SECURE region \
         (the platform/src/secure_store.rs sizing gate)"
    );
}
