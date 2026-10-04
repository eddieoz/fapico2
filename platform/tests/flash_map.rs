//! US-1536: the flash layout, and the budget that must not reach it.
//!
//! # The defect this pins
//!
//! Before this story the trussed internal filesystem started at `0x102_000`
//! (1,032 KiB) while the CI flash-budget ratchet admitted images up to
//! `FIRMWARE_FLASH_BUDGET_KIB = 1536` (1,536 KiB). The ratchet sat **504 KiB
//! above** the start of a region full of OpenPGP and PIV keys, so an image the
//! gate accepted could link over the front of that filesystem.
//!
//! Nothing in the tree related the two numbers. `check_size_report.py` compared
//! the image against the budget; the anonymous `const _` block in
//! `trusted_backend::device` compared the window against the C data partition
//! and the secure slots. Neither read the other, because there was nothing to
//! read — and that is the whole shape of the bug: two correct assertions with
//! no third assertion joining them.
//!
//! # What is here instead
//!
//! The fix is geometric: the window now starts above
//! `flashmap::FIRMWARE_GROWTH_END`, so a budget at or below the budget line
//! cannot reach it even in principle, and `platform/src/flashmap.rs` asserts
//! that at compile time. These tests are the runtime restatement — they exist
//! so the layout is *visible in test output* and so the regression is named
//! rather than remembered.
//!
//! `tests/scripts/check_flash_budget.py` (US-1534) closes the remaining half:
//! the budget is also stated in `ci.yml`, and a workflow file cannot import a
//! Rust constant, so that gate compares the two numbers.

use fapico2_platform::board;
use fapico2_platform::flashmap;

/// The budget's end offset. The invariant is stated as a comparison of
/// *offsets*, because "the budget must not reach the data" is a statement about
/// where the budget stops, not about how many bytes the image happens to be.
fn budget_end() -> u32 {
    flashmap::FIRMWARE_FLASH_BUDGET_BYTES
}

/// Every persistent region, as `(name, start, end)`.
fn data_regions() -> Vec<(&'static str, u32, u32)> {
    vec![
        ("trussed internal FS", flashmap::TRUSSED_FS_OFFSET, flashmap::TRUSSED_FS_END),
        (
            "per-record key store",
            flashmap::KEY_REGION_OFFSET,
            flashmap::KEY_REGION_OFFSET + flashmap::KEY_REGION_BYTES,
        ),
    ]
}

#[test]
fn the_flash_budget_cannot_reach_any_data_region() {
    let end = budget_end();
    for (name, start, _stop) in data_regions() {
        assert!(
            end <= start,
            "the CI flash budget ends at {end:#x} but the {name} starts at {start:#x}: an \
             image the ratchet accepts could link over it. Raise \
             FIRMWARE_FLASH_BUDGET_KIB only up to flashmap::FIRMWARE_GROWTH_END, and if that \
             is not enough, move the data regions in platform/src/flashmap.rs deliberately — \
             an already-provisioned unit's keys are in the region being moved"
        );
    }
}

#[test]
fn the_former_layout_would_have_failed() {
    // The regression, stated as arithmetic rather than as a story. 1536 KiB is
    // 0x180_000; the old window started at 0x102_000. This test cannot fail
    // unless someone changes the old offset constant to stop documenting the
    // bug, which is the point of pinning it.
    assert_eq!(
        budget_end(),
        0x180_000,
        "the ratchet moved; the regression this test names needs its arithmetic rewritten"
    );
    assert!(
        budget_end() > flashmap::LEGACY_TRUSSED_FS_OFFSET,
        "the legacy window used to start at {:#x}, INSIDE the budget. If this now fails, the \
         legacy offset no longer describes the geometry that was broken, and this test is \
         naming a bug that no longer exists in the form it describes",
        flashmap::LEGACY_TRUSSED_FS_OFFSET
    );
}

#[test]
fn the_trussed_window_sits_in_the_headroom_not_the_firmware_budget() {
    // The margin is the whole point: 512 KiB of headroom between the budget
    // and the first data byte. If this ever collapses to zero, the layout has
    // been re-derived and the ratchet is back to one bump away from a wipe.
    let margin = flashmap::TRUSSED_FS_OFFSET - budget_end();
    assert_eq!(
        margin, 0x80_000,
        "the gap between the flash budget and the trussed window is {margin:#x}, not 512 KiB"
    );
}

#[test]
fn every_region_is_disjoint_from_its_neighbours() {
    let regions = data_regions();

    // Firmware may reach the budget; the budget may reach nothing below.
    assert!(budget_end() <= flashmap::TRUSSED_FS_OFFSET);

    // Regions do not overlap each other.
    for pair in regions.windows(2) {
        let (_, _, a_end) = pair[0];
        let (b_name, b_start, _) = pair[1];
        assert!(
            a_end <= b_start,
            "{} ends at {a_end:#x} but {} starts at {b_start:#x}: the regions overlap",
            pair[0].0,
            b_name
        );
    }

    // And the last one stops below the secure partition, whose address is a
    // provisioned unit's keystore — an overlap there is not a link error, it is
    // an unreadable store discovered at BOOTSEL.
    let (_, _, last_end) = regions[regions.len() - 1];
    assert!(
        last_end <= board::SECURE_PARTITION_OFFSET,
        "the last data region ends at {last_end:#x}, past the secure partition at {:#x}",
        board::SECURE_PARTITION_OFFSET
    );
}

#[test]
fn the_window_is_exactly_one_mebibyte_of_whole_nor_sectors() {
    // littlefs2 addresses in 4 KiB blocks and embassy-rp programs in 256 B
    // pages, so an offset or length that is not a whole number of sectors
    // would put the last sector of the window outside it.
    assert_eq!(flashmap::BLOCK_SIZE, 4096);
    let window = flashmap::TRUSSED_FS_END - flashmap::TRUSSED_FS_OFFSET;
    assert_eq!(window, 1024 * 1024);
    assert_eq!(window % flashmap::BLOCK_SIZE as u32, 0);
    assert_eq!(flashmap::TRUSSED_FS_OFFSET % flashmap::BLOCK_SIZE as u32, 0);
}

#[test]
fn the_window_fits_the_board() {
    // Board-derived, not board-assumed: the window has to sit inside the part
    // this build was configured for. A larger board would have a different
    // secure-partition offset, and the window would still be legal — this is
    // the check that would notice if it were not.
    assert!(
        flashmap::TRUSSED_FS_END <= board::FLASH_SIZE_BYTES as u32,
        "the trussed window ends at {:#x}, past the top of this board's flash ({:#x})",
        flashmap::TRUSSED_FS_END,
        board::FLASH_SIZE_BYTES
    );
}

#[test]
fn the_key_store_is_what_is_left_between_the_window_and_the_keystore() {
    // US-1539. 960 KiB on the shipping part: 0x300_000..0x3F0_000, abutting the
    // trussed window on one side and the secure partition on the other. Both
    // adjacencies are the point — a hole on either side is flash nothing can
    // use, and an overlap is a keystore something can be linked over.
    assert_eq!(flashmap::KEY_REGION_OFFSET, 0x30_0000);
    assert_eq!(flashmap::KEY_REGION_BYTES, 960 * 1024);
    assert_eq!(
        flashmap::KEY_REGION_OFFSET + flashmap::KEY_REGION_BYTES,
        board::SECURE_PARTITION_OFFSET,
        "the key store must end exactly at the secure partition: {:#x} + {:#x} != {:#x}",
        flashmap::KEY_REGION_OFFSET,
        flashmap::KEY_REGION_BYTES,
        board::SECURE_PARTITION_OFFSET
    );
    // Whole NOR sectors, so the record stride US-1540 derives can divide it
    // without leaving a sector nobody can erase.
    assert_eq!(flashmap::KEY_REGION_BYTES % flashmap::BLOCK_SIZE as u32, 0);
    // Whole 1 KiB record slots is US-1540's business; what this pins is that
    // the region is not an odd size that no stride could tile cleanly.
    assert_eq!(flashmap::KEY_REGION_BYTES % 1024, 0);
}