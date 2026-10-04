//! US-1540: the capacities are derived from the region, and the region and the
//! constants cannot disagree.
//!
//! # The defect this installs a discipline against
//!
//! `DEVICE_MAX_CREDS = 12` sat in `apps/fido/src/device_keystore.rs` with a doc
//! comment claiming twelve credentials "fits the chunked slot's 5,952-B payload
//! capacity". It never did. The real bound was the **24-entry store occupancy**:
//! a chunked rewrite holds both generations live, so
//! `other_slots + old_parts + new_parts <= 24`, and on a soak board
//! `other_slots` is 12. Measured result: four credentials, then
//! `KeyStoreFull` — which is what `apps/fido/tests/key_store_ceiling.rs`
//! reproduces.
//!
//! A constant that no region can contradict is not a capacity, it is a wish.
//! These tests are the rest of that discipline: they recompute the capacities
//! from the region and refuse a disagreement.
//!
//! # What the erase granularity forces
//!
//! The epic's original stride analysis picked 1 KiB slots and 256 FIDO / 68
//! OATH in a 960 KiB region. That is right about the stride and silent about
//! the hardware: RP2350 QSPI flash erases in 4 KiB sectors and NOR cannot
//! rewrite programmed bytes, so a 1 KiB slot cannot be erased on its own.
//!
//! The design here keeps the 1 KiB slot as the unit of **identity** — the
//! address a record is found at — and makes the **sector** the unit of erasure
//! and of commit. One credential update therefore erases one sector and
//! programs four slots, three of which carry unchanged records. US-1544 and
//! US-1545 have to make that sector atomic, and neither may assume a one-slot
//! erase, because the flash cannot do it.

use fapico2_platform::flashmap::{BLOCK_SIZE, KEY_REGION_BYTES, KEY_REGION_OFFSET};
use fapico2_platform::keyregion as kr;

/// Recompute the FIDO capacity the way the module claims to derive it.
///
/// Written out rather than imported, so the test states the rule instead of
/// restating the module's own arithmetic — a test that calls the same
/// expression is a test that cannot fail for a different reason than the code.
const fn derive_fido_capacity() -> u32 {
    (KEY_REGION_BYTES / kr::FIDO_SLOT_BYTES) - kr::OATH_CAPACITY
}

#[test]
fn the_capacities_are_the_region_arithmetic() {
    assert_eq!(kr::FIDO_CAPACITY, derive_fido_capacity());
    assert_eq!(kr::TOTAL_SLOTS, KEY_REGION_BYTES / kr::FIDO_SLOT_BYTES);
    assert_eq!(kr::FIDO_CAPACITY + kr::OATH_CAPACITY, kr::TOTAL_SLOTS);
}

#[test]
fn the_region_holds_far_more_than_the_reported_ceiling() {
    // The reported defect: four credentials, with `DEVICE_MAX_CREDS` claiming
    // twelve. The floor the acceptance criteria name is 256.
    assert!(
        kr::FIDO_CAPACITY >= 256,
        "FIDO capacity {} is below the 256 floor",
        kr::FIDO_CAPACITY
    );
    assert!(
        kr::OATH_CAPACITY >= 68,
        "OATH capacity {} is below the 68 floor",
        kr::OATH_CAPACITY
    );
    // …and the improvement over the reported ceiling is the point of the
    // whole epic, so it is asserted as a ratio rather than left implied.
    assert!(
        kr::FIDO_CAPACITY >= 64 * 4,
        "capacity {} is not a meaningful improvement on the measured four-credential ceiling",
        kr::FIDO_CAPACITY
    );
}

#[test]
fn a_slot_cannot_straddle_a_nor_sector() {
    // The constraint the epic's stride analysis missed. If this fails, a record
    // can span two sectors and erasing one destroys the other — which is a
    // credential lost with no error reported.
    assert_eq!(BLOCK_SIZE as u32 % kr::FIDO_SLOT_BYTES, 0);
    assert_eq!(BLOCK_SIZE as u32 / kr::FIDO_SLOT_BYTES, kr::SLOTS_PER_SECTOR);
    assert_eq!(
        kr::FIDO_SLOT_BYTES % kr::OATH_SLOT_BYTES,
        0,
        "the FIDO grid must be a whole number of OATH slots, or the two domains cannot share \
         one region"
    );
}

#[test]
fn the_strides_hold_their_domains_largest_record() {
    for (name, stride, record_max) in [
        ("FIDO", kr::FIDO_SLOT_BYTES, kr::FIDO_RECORD_MAX),
        ("OATH", kr::OATH_SLOT_BYTES, kr::OATH_RECORD_MAX),
    ] {
        assert!(
            stride >= record_max + kr::RECORD_HEADER_BYTES,
            "the {name} stride {stride} cannot hold a {record_max}-byte record plus a \
             {}-byte header; a record that does not fit is truncated, not stored",
            kr::RECORD_HEADER_BYTES
        );
        // The margin is what lets a future record with a longer field widen one
        // constant instead of re-deriving the region's layout.
        assert!(
            stride - (record_max + kr::RECORD_HEADER_BYTES) >= 128,
            "the {name} stride leaves {} B of growth room, less than the 128 B the design \
             claims; a longer field would then change the region's layout rather than a \
             constant",
            stride - (record_max + kr::RECORD_HEADER_BYTES)
        );
    }
}

#[test]
fn the_slots_tile_the_region_exactly() {
    assert_eq!(
        KEY_REGION_BYTES % kr::FIDO_SLOT_BYTES,
        0,
        "a partial last slot is a slot that cannot be erased without touching the one before it"
    );
    let used = (kr::FIDO_CAPACITY + kr::OATH_CAPACITY) * kr::FIDO_SLOT_BYTES;
    assert!(used <= KEY_REGION_BYTES);
    // OATH records are shorter, so they occupy one FIDO-sized slot each rather
    // than packing four to a sector. That is the deliberate trade: packing would
    // raise the FIDO count, at the cost of a record update having to rewrite
    // records belonging to the same sector — the complexity AGENTS.md §5 says to
    // take only when the attack it stops can be named. None can be named here.
    assert_eq!(
        kr::OATH_CAPACITY * kr::OATH_SLOT_BYTES,
        68 * 512,
        "OATH's declared area changed shape"
    );
}

#[test]
fn the_region_is_where_the_linker_script_says_it_is() {
    // US-1539 declared KEYREGION in the generated `memory.x` from a different
    // derivation. The region the firmware links around and the region the
    // firmware programs have to be the same one, so this is where the two
    // derivations meet.
    assert_eq!(KEY_REGION_OFFSET, 0x30_0000);
    assert_eq!(KEY_REGION_BYTES, 960 * 1024);
    assert_eq!(
        KEY_REGION_BYTES % BLOCK_SIZE as u32,
        0,
        "the region must be a whole number of NOR sectors; the commit unit is the sector"
    );
}