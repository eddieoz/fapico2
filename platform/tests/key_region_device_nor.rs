//! US-1541, device half: **the device's NOR rules and the host's must agree**.
//!
//! # The gap this file closes
//!
//! [`FileKeyRegion`] is the region every codec test in this tree is calibrated
//! against, because it is the only one that can be executed without a board. It
//! models NOR honestly: erased is `0xFF`, `program` ANDs into what is there and
//! **refuses** any byte needing a 0 → 1 transition, and `erase_sector` restores
//! `0xFF` over a whole 4 KiB sector (`keyregion/host.rs:317-384`).
//!
//! `device_region.rs` now has a second copy of those rules — in
//! [`nor`], the pure core the QSPI-backed [`DeviceKeyRegion`] calls. Two copies
//! is a defect waiting to happen: `host.rs` could be corrected to match the
//! part while `nor` kept the old rule (or the reverse), every host test would
//! stay green, and the part would refuse a write the suite had approved. This
//! file drives both over the **same operation script** and requires them to
//! accept, refuse and land on byte-identical contents.
//!
//! So the device region is tested here as far as it can be without a board:
//! every rule that does not need flash hardware, differentially. What is left
//! — that `blocking_read`/`blocking_write`/`blocking_erase` do what the driver
//! documents — is the driver's claim, not this story's.
//!
//! # Why the comparison is on the *message*, not just on `Err`
//!
//! `FileKeyRegion` and `nor` name the same four rules with the same wording
//! behind different transport prefixes (`"file key region: …"` vs
//! `"device key region: …"`). Asserting only that both refuse would pass if the
//! device refused a *different* rule than the host did — a refusal for
//! misalignment where the host refused for a bit transition is a different bug
//! and would show up as a mysterious write refusal on hardware. So each refusal
//! is compared modulo the prefix, and a script step whose two sides disagree
//! reports both messages verbatim.
//!
//! The one deliberate divergence is the sector-truncation message: the host
//! region's is about a *file* and the device region's about a *region*, so the
//! suffix differs. Erase refusals are therefore compared accept/refuse only, and
//! this file says so at the comparison site rather than leaving it as a trap.
//!
//! # About the `[u8]` image the device side is driven through
//!
//! [`nor`] is deliberately transport-free, so the "device" here is a byte array
//! plus three of its own calls: geometry, bits, AND-apply. That is the whole of
//! `DeviceKeyRegion`'s decision logic; the QSPI calls around it do no deciding.
//! The array is the *device's* image and the temp file is the *host's*, and the
//! assertions are about the two arriving at the same state.

use std::path::{Path, PathBuf};

use fapico2_platform::flashmap::BLOCK_SIZE;
use fapico2_platform::keyregion::device_region::nor::{self, EraseRefusal, ProgramRefusal};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::{
    FIDO_SLOT_BYTES, KeyRegion, Slot, SLOTS_PER_SECTOR,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The transport prefix [`nor`] puts in front of every refusal it reports.
///
/// The only thing allowed to differ between the two models' messages; the rule
/// wording after it is the physics and is compared.
const DEVICE_PREFIX: &str = "device key region: ";

/// Slots in the differential region: two whole sectors, which is the smallest
/// shape that can show a sector erase taking its neighbours with it.
const SLOTS: u32 = SLOTS_PER_SECTOR * 2;

/// A region file in the host temp directory, removed on drop.
///
/// Named with the process id and a per-test tag so the tests run in parallel
/// without colliding, and so a leftover file from a killed run is identifiable
/// rather than silently reused — the convention `key_region_host.rs:60-71`
/// established.
struct TempRegion {
    path: PathBuf,
}

impl TempRegion {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("fapico2-keyregion-dev-{}-{tag}.bin", std::process::id()));
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

/// The **device**'s image of the region, driven only through [`nor`].
///
/// The three steps below are, in order, what `DeviceKeyRegion::program` does
/// (`keyregion/device_region.rs`, `impl KeyRegion for DeviceKeyRegion`): decide
/// the window is legal, decide the program is performable over what is there,
/// then AND. Nothing else in the device path can change a verdict.
struct DeviceImage {
    bytes: Vec<u8>,
}

impl DeviceImage {
    fn erased() -> Self {
        Self {
            bytes: vec![nor::ERASED_BYTE; SLOTS as usize * FIDO_SLOT_BYTES as usize],
        }
    }

    fn program(&mut self, slot: Slot, offset: u32, data: &[u8]) -> Result<(), ProgramRefusal> {
        nor::check_program_geometry(slot, SLOTS, offset, data)?;
        let at = slot.index() as usize * FIDO_SLOT_BYTES as usize + offset as usize;
        let mut existing = self.bytes[at..at + data.len()].to_vec();
        nor::apply_program(&mut existing, data)?;
        self.bytes[at..at + data.len()].copy_from_slice(&existing);
        Ok(())
    }

    fn erase_sector(&mut self, slot: Slot) -> Result<(), EraseRefusal> {
        let (from, to) = nor::erase_span(slot, SLOTS)?;
        // `erase_span` answers in flash space; the image is region-relative, so
        // the key region's base is removed here rather than in `nor` — that is
        // the one line of the device path that is addressing, not deciding.
        let base = (from - fapico2_platform::flashmap::KEY_REGION_OFFSET) as usize;
        let span = (to - from) as usize;
        debug_assert_eq!(span, BLOCK_SIZE);
        self.bytes[base..base + span].fill(nor::ERASED_BYTE);
        Ok(())
    }

    fn read_slot(&self, slot: Slot) -> Vec<u8> {
        let at = slot.index() as usize * FIDO_SLOT_BYTES as usize;
        self.bytes[at..at + FIDO_SLOT_BYTES as usize].to_vec()
    }
}

/// The two regions driven side by side.
struct Pair {
    device: DeviceImage,
    host: FileKeyRegion,
    _temp: TempRegion,
}

impl Pair {
    fn new(tag: &str) -> Self {
        let temp = TempRegion::new(tag);
        let host = FileKeyRegion::create(temp.path(), SLOTS).expect("temp region file");
        Self {
            device: DeviceImage::erased(),
            host,
            _temp: temp,
        }
    }

    /// Run one program on both, requiring the same verdict.
    ///
    /// `same_prefix` is the transport prefix each side puts in front of the
    /// shared rule wording.
    fn program(&mut self, slot: Slot, offset: u32, data: &[u8], step: &str) {
        let device = self.device.program(slot, offset, data);
        let host = self.host.program(slot, offset, data);
        match (&device, &host) {
            (Ok(()), Ok(())) => {}
            (Err(d), Err(h)) => {
                // The transport prefix is the only thing allowed to differ: the
                // rule wording after it is the physics, and is compared.
                let rule = d.reason().strip_prefix(DEVICE_PREFIX).unwrap_or(d.reason());
                assert!(
                    h.ends_with(rule),
                    "{step}: the two regions refused for different reasons.\n  device: {}\n  \
                     host:   {h}\nBoth name the same four rules; if the wording has genuinely \
                     diverged, one of them is wrong about the part.",
                    d.reason()
                );
            }
            _ => panic!(
                "{step}: the two regions disagreed.\n  device: {device:?}\n  host:   {host:?}\n\
                 A window one model accepts and the other refuses is the exact failure this \
                 file exists to prevent: a codec that passes on the host would fail on the part."
            ),
        }
    }

    /// Run one sector erase on both, requiring the same accept/refuse verdict.
    ///
    /// **Message not compared**, unlike [`Self::program`]: the truncation rule is
    /// the one whose wording legitimately differs (the host's is about a file,
    /// the device's about a region), so requiring the strings to match would be
    /// asserting a copy edit rather than a physics.
    fn erase(&mut self, slot: Slot, step: &str) {
        let device = self.device.erase_sector(slot).is_ok();
        let host = self.host.erase_sector(slot).is_ok();
        assert_eq!(
            device, host,
            "{step}: the two regions disagree about whether sector {slot:?} can be erased.\n  \
             device: {device}\n  host:   {host}"
        );
    }

    /// The two images must be byte-identical.
    fn assert_identical(&mut self, step: &str) {
        for i in 0..SLOTS {
            let slot = Slot::new(i as u16).expect("i < SLOTS <= TOTAL_SLOTS");
            let device = self.device.read_slot(slot);
            let host = self.host.read_slot(slot).expect("a slot inside the region reads");
            assert_eq!(
                device, host,
                "{step}: slot {i} differs between the device's NOR core and the host's file model."
            );
        }
    }
}

fn slot(i: u16) -> Slot {
    Slot::new(i).expect("test slots stay inside TOTAL_SLOTS")
}

/// A byte block, deterministic given `seed`.
fn block(seed: u32, len: usize) -> Vec<u8> {
    // xorshift32: a fixed seed keeps a failure reproducible, which a wall-clock
    // or hash-order source would not.
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x & 0xFF) as u8
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A virgin region is `0xFF` in every slot, on both sides.
#[test]
fn a_fresh_region_is_erased_on_both_sides() {
    let mut pair = Pair::new("fresh");
    for i in 0..SLOTS {
        let s = slot(i as u16);
        assert!(
            pair.device.read_slot(s).iter().all(|b| *b == nor::ERASED_BYTE),
            "the device image must start erased"
        );
        assert!(
            pair.host
                .read_slot(s)
                .expect("a slot inside the region reads")
                .iter()
                .all(|b| *b == nor::ERASED_BYTE),
            "FileKeyRegion::create pre-erases to 0xFF (keyregion/host.rs:183-187); a region \
             whose virgin state is 0x00 would accept records a real part cannot hold"
        );
    }
    pair.assert_identical("fresh");
}

/// The whole accepted-program space, in one run: legal windows land identically,
/// and an idempotent re-program of the same bytes is accepted by both (it is
/// `d & !cur == 0`, not "bytes differ").
#[test]
fn accepted_programs_land_identically() {
    let mut pair = Pair::new("accept");
    for i in 0..SLOTS {
        let s = slot(i as u16);
        for offset in [0u32, 256, 768] {
            let len = FIDO_SLOT_BYTES as usize - offset as usize;
            let data = block(0xC0DE + i * 31 + offset, len);
            pair.program(s, offset, &data, "first program");
            // Re-programming the same bytes changes nothing and is not a
            // refusal: NOR reads `d & !cur == 0`, and identical bytes clear no
            // bits that are already clear.
            pair.program(s, offset, &data, "idempotent re-program");
        }
    }
    pair.assert_identical("accepted programs");
}

/// A program that needs a bit set from 0 to 1 is refused by both, **with the
/// same rule** — and refused before anything is written.
#[test]
fn a_bit_transition_is_refused_by_both_and_writes_nothing() {
    let mut pair = Pair::new("setbit");
    let s = slot(0);
    let data = block(0x1111, 256);
    pair.program(s, 0, &data, "seed");

    // Same block, with one byte rewritten so it needs at least one bit set
    // back. `wrapping_add(1)` on a byte that is not already `0xFF` always turns
    // at least one clear bit on (the carry), which is exactly the transition
    // NOR cannot perform — picking the byte by search keeps that guaranteed
    // rather than a property of the seed.
    let pos = data
        .iter()
        .position(|b| *b != 0xFF)
        .expect("a random 256-byte block has a byte with room to set a bit");
    let mut rewrite = data.clone();
    rewrite[pos] = data[pos].wrapping_add(1);
    pair.program(s, 0, &rewrite, "bit transition");

    let d = nor::check_bits(&pair.device.read_slot(s)[..256], &rewrite);
    assert_eq!(
        d,
        Err(ProgramRefusal::SetBit),
        "the device's own core must classify a 0 -> 1 transition as SetBit"
    );
    assert_eq!(
        pair.device.read_slot(s)[..256],
        data[..],
        "a refused program must leave the medium untouched — the device applies the AND only \
         after the rule says yes, so there is nothing to roll back"
    );
    pair.assert_identical("after a refused program");
}

/// Every geometric refusal fires on both sides, in the same order.
#[test]
fn geometric_refusals_fire_on_both_sides() {
    let mut pair = Pair::new("geometry");

    // Not page-aligned.
    pair.program(slot(0), 1, &block(1, 256), "unaligned offset");
    // Not a whole number of pages.
    pair.program(slot(0), 0, &block(1, 100), "ragged length");
    // Empty.
    pair.program(slot(0), 0, &[], "empty window");
    // Past the end of the slot.
    pair.program(slot(0), 768, &block(1, 512), "past the slot end");
    // Outside the region — a slot valid for the *device* geometry but past a
    // short region. `Slot::new` accepts it; `check_program_geometry` must not.
    let beyond = Slot::new(SLOTS as u16).expect("SLOTS is well inside TOTAL_SLOTS");
    pair.program(beyond, 0, &block(1, 256), "slot past the region");

    pair.assert_identical("geometric refusals");
}

/// A sector erase takes its whole 4 KiB — [`SLOTS_PER_SECTOR`] slots — and the
/// two regions agree on exactly which ones.
#[test]
fn a_sector_erase_takes_its_mates_on_both_sides() {
    let mut pair = Pair::new("erase");
    // Fill every slot so the erase has something to take away.
    for i in 0..SLOTS {
        let s = slot(i as u16);
        pair.program(s, 0, &block(0x5A5A + i, FIDO_SLOT_BYTES as usize), "fill");
    }
    pair.assert_identical("before the erase");

    // Slot 5 lives in the second sector; erasing it must not touch sector 1.
    pair.erase(slot(5), "erase the second sector");
    let erased_base = nor::sector_first_slot(slot(5));
    for i in 0..SLOTS_PER_SECTOR {
        let s = Slot::new(erased_base as u16 + i as u16).expect("inside the region");
        assert!(
            pair.device
                .read_slot(s)
                .iter()
                .all(|b| *b == nor::ERASED_BYTE),
            "slot {} shares sector 5 and must have gone with it",
            s.index()
        );
    }
    for i in 0..SLOTS_PER_SECTOR as u16 {
        let s = slot(i);
        assert!(
            pair.device
                .read_slot(s)
                .iter()
                .any(|b| *b != nor::ERASED_BYTE),
            "slot {i} is in the *other* sector and must have survived an erase of slot 5 — an \
             erase that reached across the sector boundary would destroy a live credential"
        );
    }
    pair.assert_identical("after the erase");
}

/// The region boundary is refused by both, on both sides of it.
///
/// The device region is always a whole number of sectors, so on the part the
/// "past the end" arm is unreachable; it is here because `KeyRegion::
/// erase_sector` accepts any `Slot` the *device* geometry allows, and a stand-in
/// that quietly truncated the sector would hide the rule from the codec — the
/// same reason `keyregion/host.rs:326-332` keeps its own check.
#[test]
fn the_region_boundary_is_refused_by_both() {
    let temp = TempRegion::new("truncated");
    let mut region =
        FileKeyRegion::create(temp.path(), SLOTS_PER_SECTOR).expect("temp region file");

    let last = Slot::new(SLOTS_PER_SECTOR as u16 - 1).expect("well inside TOTAL_SLOTS");
    assert!(
        region.erase_sector(last).is_ok(),
        "the last slot of a whole-sector region must be erasable — refusing it would strand the \
         region's own last sector"
    );

    let past = Slot::new(SLOTS_PER_SECTOR as u16).expect("well inside TOTAL_SLOTS");
    assert!(
        region.erase_sector(past).is_err(),
        "a slot past a whole-sector region must be refused, not truncated: an erase that ran off \
         the end would clear flash the firmware never addresses"
    );
    assert_eq!(
        nor::erase_span(past, SLOTS_PER_SECTOR),
        Err(EraseRefusal::SlotOutOfRegion),
        "the device core must agree with the host model at the region boundary"
    );
    assert!(
        nor::erase_span(last, SLOTS_PER_SECTOR).is_ok(),
        "…and must agree that the last slot inside it is fine"
    );

    // The other arm, `SectorTruncated`, is only reachable from a capacity that
    // is *not* a whole number of sectors. `FileKeyRegion::create` refuses to
    // build one (`keyregion/host.rs:168-173`) and the device region is the
    // whole window, so the device core is checked here on its own — which is
    // the point: it is the arm that would erase across a boundary if a future
    // board ever produced a region whose size did not tile.
    let ragged = SLOTS_PER_SECTOR - 1;
    assert_eq!(
        nor::erase_span(Slot::new(ragged as u16).unwrap(), ragged),
        Err(EraseRefusal::SectorTruncated),
        "a region that ends inside a sector has no valid last sector, and erasing it would take \
         records that have no slot of their own"
    );
}

/// A mixed script — programs, refusals and erases interleaved — must leave the
/// two regions byte-identical.
///
/// This is the one that would catch a drift the single-purpose tests miss: it
/// drives the transitions that make the NOR rule non-trivial (program → refuse
/// → erase → program again over the *same* bytes, which must become legal
/// precisely because the erase restored `0xFF`).
#[test]
fn a_mixed_script_leaves_both_regions_identical() {
    let mut pair = Pair::new("mixed");
    let mut x = 0x9E37_79B9u32;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };

    for step in 0..64u32 {
        let i = (next() % SLOTS) as u16;
        let s = slot(i);
        match next() % 4 {
            0 | 1 => {
                let offset = (next() % 4) * 256;
                let len = FIDO_SLOT_BYTES as usize - offset as usize;
                pair.program(s, offset, &block(next(), len), &format!("mixed program {step}"));
            }
            2 => {
                // Deliberately the same block as an earlier step, so the
                // outcome depends on what is already programmed.
                pair.program(s, 0, &block(7, 256), &format!("mixed rewrite {step}"));
            }
            _ => pair.erase(s, &format!("mixed erase {step}")),
        }
        pair.assert_identical(&format!("after mixed step {step}"));
    }
}

/// The device core's sector arithmetic is the host model's, slot for slot.
#[test]
fn sector_first_slot_agrees_across_the_whole_region() {
    for i in 0..SLOTS {
        let s = slot(i as u16);
        assert_eq!(
            nor::sector_first_slot(s),
            (i / SLOTS_PER_SECTOR) * SLOTS_PER_SECTOR,
            "slot {i}: the sector base is arithmetic, and `keyregion/mod.rs:303-307` asserts at \
             compile time that the division is exact — this is the runtime echo of that"
        );
        let (from, to) = nor::erase_span(s, SLOTS).expect("a slot inside the region");
        assert_eq!(
            to - from,
            BLOCK_SIZE as u32,
            "an erase span is exactly one NOR sector; anything else either under-erases (a \
             record that survives) or over-erases (a neighbouring credential)"
        );
        assert_eq!(
            from % BLOCK_SIZE as u32,
            0,
            "the sector base must be 4 KiB-aligned: `blocking_erase` refuses a misaligned range, \
             so an unaligned base would make every erase in the region fail"
        );
    }
}