//! The flash map: one owner for every persistent region's offset.
//!
//! Every offset here is **flash-relative** — measured from `board::FLASH_ORIGIN`
//! (`0x1000_0000`), which is what `embassy-rp`'s `blocking_read`/`write`/`erase`
//! take. Nothing in this module is absolute, and nothing in this module is a
//! magic number written twice.
//!
//! ```text
//! 0x000_000 .. 0x180_000   firmware image                  1,536 KiB — the CI ratchet
//! 0x180_000 .. 0x200_000   firmware growth headroom          512 KiB — unreferenced, on purpose
//! 0x200_000 .. 0x300_000   trussed window                   1,024 KiB
//!                         ├ 0x200_000 .. 0x2C0_000   ifs     768 KiB — OpenPGP + PIV
//!                         └ 0x2C0_000 .. 0x300_000   efs     256 KiB — Location::External
//! 0x300_000 .. 0x3F0_000   per-record key store               960 KiB
//! 0x3F0_000 .. 0x400_000   secure partition (small secrets)     64 KiB — board::SECURE_PARTITION_OFFSET
//! ```
//!
//! # The trussed window is split, and `ifs` keeps the front (US-1538)
//!
//! [`TRUSSED_FS_OFFSET`]/[`TRUSSED_FS_BLOCKS`] describe the whole 1 MiB window,
//! which is what the linker reserves and what `board::KEY_REGION_BYTES` is
//! derived from — neither of them moved. The **window** is now two littlefs2
//! filesystems: [`TRUSSED_IFS_BLOCKS`] at the front for `ifs`, and
//! [`TRUSSED_EFS_BLOCKS`] at the tail for `efs`.
//!
//! The order is not cosmetic. littlefs2 stores `block_count` in the volume
//! superblock and refuses to mount a volume whose geometry does not match the
//! driver's (`lfs.c:4523-4531`: `Invalid block count`, `LFS_ERR_INVAL`). A
//! legacy volume copied byte-for-byte into the *tail* window would therefore
//! refuse to mount, and the boot path's `is_mountable` → `format` fall-through
//! would erase every OpenPGP key on the unit. Keeping `ifs` at the front means
//! the relocated bytes land at the same block indices they were written at, and
//! [`crate::trusted_backend::device`]'s migration reads them there.
//!
//! # Why this module exists (US-1536)
//!
//! The trussed window used to sit at `0x102_000`, **inside** the region the CI
//! flash-budget ratchet is free to grow into. The ratchet allows a firmware
//! image up to [`FIRMWARE_FLASH_BUDGET_BYTES`] (1,621 KiB) and the window began
//! at 1,032 KiB, so the geometry was wrong by 504 KiB before this epic touched
//! it: a firmware image the gate *accepted* could link over the front of the
//! trussed filesystem, and every OpenPGP and PIV key past that offset would go
//! with it.
//!
//! Nothing in the tree related the two numbers. `tests/scripts/check_size_report.py`
//! checked the image against the budget; the anonymous `const _` block in
//! `trusted_backend::device` checked the window against the C data partition and
//! the secure slots. Neither read the other, because there was nothing to read.
//!
//! The fix is geometric rather than documentary: the window now starts **above**
//! [`FIRMWARE_GROWTH_END`], so a budget at or below the budget line cannot reach
//! it even in principle. [`FIRMWARE_FLASH_BUDGET_BYTES`] is stated once, here,
//! and `tests/scripts/check_flash_budget.py` asserts that `ci.yml`'s
//! `FIRMWARE_FLASH_BUDGET_KIB` still agrees with it (US-1534) — two independent
//! numbers that cannot drift because a gate compares them.
//!
//! # The budget is a ratchet, not a ceiling
//!
//! [`FIRMWARE_FLASH_BUDGET_BYTES`] is the value CI refuses to exceed, and it is
//! deliberately allowed to be below [`FIRMWARE_GROWTH_END`]: 512 KiB of
//! headroom is what makes raising it a deliberate act with a recorded reason
//! rather than an accident. Raising the budget is safe **up to the growth
//! boundary**. Past it, this module stops compiling — which is the correct
//! outcome, because past it the firmware would be growing into a filesystem
//! full of someone's keys.

use crate::board;
use crate::cflash;

/// The firmware flash budget in bytes — the ratchet `ci.yml` enforces against
/// the shipping UF2 (`FIRMWARE_FLASH_BUDGET_KIB`, 1,621 KiB).
///
/// Raised 1536 → 1621 on 2026-10-06 (docs/size-report.md, that date's entry):
/// the shipping image had already grown past 1,536 KiB across the US-15xx
/// epics while the boot-chain gate hid the ratchet's red; this entry's image
/// is 3,242 blocks = 1,659,904 B = 1,621 KiB exactly — zero headroom,
/// deliberately, so the next 512 B trips it.
///
/// This is the number that used to be 504 KiB *above* the trussed window's
/// start. It is the only place it is written down in Rust; `ci.yml` carries the
/// same value in KiB because a workflow file cannot import a Rust constant, and
/// `tests/scripts/check_flash_budget.py` fails the build if the two disagree.
pub const FIRMWARE_FLASH_BUDGET_BYTES: u32 = 1621 * 1024;

/// The end of the region the firmware may grow into without a layout change:
/// 512 KiB of unreferenced headroom above the budget.
pub const FIRMWARE_GROWTH_END: u32 = 0x20_0000;

/// NOR erase granularity (RP2350 QSPI flash).
pub const BLOCK_SIZE: usize = 4096;

/// The trussed window's size in KiB — restated here as a KiB quantity because
/// [`crate::board::KEY_REGION_BYTES`] is derived from it in KiB terms.
pub const TRUSSED_FS_KB: u32 = (TRUSSED_FS_BLOCKS * BLOCK_SIZE) as u32 / 1024;

/// Start of the trussed internal-FS window, flash-relative.
///
/// OpenPGP and PIV live here. It sits immediately above
/// [`FIRMWARE_GROWTH_END`], which is what makes Finding 2 of `FIDO-SECURE-STORE`
/// structurally impossible rather than merely documented.
pub const TRUSSED_FS_OFFSET: u32 = FIRMWARE_GROWTH_END;

/// Blocks in the trussed internal-FS window: 256 × 4 KiB = 1 MiB.
pub const TRUSSED_FS_BLOCKS: usize = 256;

/// The trussed window's first byte past its end.
pub const TRUSSED_FS_END: u32 = TRUSSED_FS_OFFSET + (TRUSSED_FS_BLOCKS * BLOCK_SIZE) as u32;

/// Blocks of the trussed window given to the **internal** FS (`ifs`): 192 ×
/// 4 KiB = 768 KiB.
///
/// `ifs` sits at [`TRUSSED_FS_OFFSET`] — the front of the window, which is
/// where the relocated legacy volume's blocks land. See the module docs for why
/// the order matters.
///
/// # Why 768 KiB and not the whole window
///
/// The window is shared now because there is no free flash left to give
/// `efs` its own: the data partition is tiled to the top of the part
/// (`KEY_REGION_BYTES` is board-derived from the window's size, so shrinking
/// the window would silently shrink the key store, and enlarging it would
/// move `board::SECURE_PARTITION_OFFSET`).
///
/// 768 KiB is **27× the measured cost of what `ifs` carries**.
///
/// That measurement is
/// `platform/tests/fs_store_backing.rs::the_split_leaves_ifs_room_for_what_it_carries`,
/// which writes a whole OpenPGP card's worth of payload — three RSA-4096
/// private keys at the 7–10 KB of DER the epic cites
/// (`docs/tasks/EPIC-secure-storage.md` §2), plus the state files beside them —
/// into a real littlefs2 volume and reads back what the volume *cost*, CTZ
/// skip-lists and metadata included: **28,672 B**. (The epic's own "roughly
/// 254 KB used, ~770 KB spare" for the same window is a transcription nobody
/// measured; this is the number with littlefs2's overhead in it.)
pub const TRUSSED_IFS_BLOCKS: usize = 192;

/// Blocks of the trussed window given to the **external** FS (`efs`): 64 ×
/// 4 KiB = 256 KiB, at [`TRUSSED_EFS_OFFSET`].
///
/// This is what makes `Location::External` flash-backed (US-1538). It used to
/// be an 8-block RAM buffer that `mount_ram_fs` reformatted on every boot,
/// while `vendor/opcard/src/card.rs:569` makes `External` the opcard default —
/// so a key written at the default location survived exactly until the next
/// power cycle, with no error at any point.
///
/// 256 KiB is sized against the payload `efs` exists to hold: one OpenPGP key
/// set is three RSA-4096 private keys at 7–10 KB of DER each, so this holds
/// on the order of ten key sets with littlefs2's metadata overhead, against
/// the one the tree has ever needed. Anything larger would be taken from an
/// `ifs` that has to hold both OpenPGP and PIV, for no applet that exists.
pub const TRUSSED_EFS_BLOCKS: usize = TRUSSED_FS_BLOCKS - TRUSSED_IFS_BLOCKS;

/// Start of the `efs` window — the **tail** of the trussed window, immediately
/// after `ifs`.
///
/// Tail, not front, for the reason in the module docs: `ifs` must keep the
/// window's low block indices so the relocated legacy volume's superblock pair
/// (blocks 0 and 1) stays inside `ifs` and every CTZ pointer stays valid.
pub const TRUSSED_EFS_OFFSET: u32 =
    TRUSSED_FS_OFFSET + (TRUSSED_IFS_BLOCKS * BLOCK_SIZE) as u32;

/// Where the trussed window lived before US-1536, retained only as the source
/// of a one-shot relocation.
///
/// `0x102_000 .. 0x202_000` — the front of the C data partition. It is
/// **read** by [`crate::trusted_backend::device`]'s migration and never
/// written, which is what makes the migration idempotent and retryable: an
/// interrupted copy leaves the source intact, the partial destination is erased,
/// and the next boot tries again.
pub const LEGACY_TRUSSED_FS_OFFSET: u32 = 0x102_000;

/// Start of the per-record key store, flash-relative (US-1539).
///
/// This is where FIDO and OATH credentials move to. It begins exactly where
/// the trussed window ends, so the two cannot overlap by construction.
pub const KEY_REGION_OFFSET: u32 = TRUSSED_FS_END;

/// The key store's size: everything between the end of the trussed window and
/// the secure partition.
///
/// **Board-derived, not a constant.** On the shipping 4 MiB `pico2` part that is
/// 960 KiB; a larger part gets a larger key store, which is the right answer
/// because the spare flash is capacity — it is what US-1540 derives the
/// credential ceilings from. The linker script derives the same number
/// independently (`platform/board_def.rs::Board::key_region_kb`); the two are
/// asserted equal by `platform/tests/flash_map.rs`, because a region the
/// firmware links around and a region the firmware programs have to be the
/// same one.
pub const KEY_REGION_BYTES: u32 = board::KEY_REGION_BYTES;

/// Compile-time layout invariants (US-1536).
///
/// Anonymous so there is no dead-code name surface; the asserts are evaluated at
/// compile time either way — an unused named const with a failing assert still
/// fails the build with E0080, because rustc const-checks all const items.
///
/// The first two are the ones that close Finding 2. The third is the boundary
/// check that already existed in `device.rs`, restated here so that every region
/// in the map is checked against its neighbours in one place rather than in
/// whichever file happened to be written first.
const _: () = {
    assert!(
        FIRMWARE_FLASH_BUDGET_BYTES <= FIRMWARE_GROWTH_END,
        "the CI flash budget has grown past the firmware growth boundary: an image the \
         ratchet accepts would link into the trussed filesystem window. Lower the budget, \
         or move the data regions in platform/src/flashmap.rs — deliberately, with the \
         already-provisioned units in mind"
    );
    assert!(
        FIRMWARE_GROWTH_END <= TRUSSED_FS_OFFSET,
        "the trussed filesystem must start at or above the firmware growth boundary"
    );
    assert!(
        TRUSSED_FS_OFFSET >= cflash::PT_JSON_DATA_START,
        "trussed FS window starts before the C data partition"
    );
    assert!(
        TRUSSED_FS_END <= cflash::PT_JSON_DATA_START + cflash::PT_JSON_DATA_SIZE,
        "trussed FS window exceeds the C data partition"
    );
    assert!(
        TRUSSED_FS_END <= board::SECURE_PARTITION_OFFSET,
        "trussed FS window overlaps the secure image-slot window"
    );
    // US-1539: the key store is what is left between the trussed window and
    // the secure partition, so it abuts both. The linker reserves it
    // independently (`Board::key_region_kb`), and these two assertions are what
    // make "the region the firmware links around" and "the region the firmware
    // programs" the same region rather than two constants that agree today.
    assert!(
        KEY_REGION_OFFSET == TRUSSED_FS_END,
        "the key store must start where the trussed window ends"
    );
    assert!(
        KEY_REGION_OFFSET + KEY_REGION_BYTES == board::SECURE_PARTITION_OFFSET,
        "the key store must end where the secure partition begins: an overlap is a keystore \
         the firmware can be linked over, and a gap is flash nothing can use"
    );
    // Stated as an exact-multiple identity rather than `% == 0`: same meaning,
    // and it is the form that compiles here — CI runs clippy with `-D warnings`
    // and `manual_is_multiple_of` rejects the `%` form.
    assert!(
        KEY_REGION_BYTES == (KEY_REGION_BYTES / BLOCK_SIZE as u32) * BLOCK_SIZE as u32,
        "the key region must be a whole number of NOR sectors; the record stride US-1540 \
         derives divides it, and a remainder would leave a partial sector nobody can erase"
    );
    // US-1538: the two halves of the trussed window. These are the assertions
    // that make "the window is split" a geometric fact rather than two
    // constants that happen to sum today: `ifs` and `efs` must tile the window
    // exactly, with no gap (flash nothing can use) and no overlap (two
    // littlefs2 filesystems claiming the same 4 KiB sector — which does not
    // fail at link time, it destroys one of them at run time).
    assert!(
        TRUSSED_IFS_BLOCKS > 0 && TRUSSED_EFS_BLOCKS > 0,
        "the trussed window must hold both a non-empty ifs and a non-empty efs"
    );
    assert!(
        TRUSSED_IFS_BLOCKS + TRUSSED_EFS_BLOCKS == TRUSSED_FS_BLOCKS,
        "ifs and efs must tile the trussed window exactly: a gap is flash no filesystem \
         can reach, an overlap is two filesystems erasing each other's blocks"
    );
    assert!(
        TRUSSED_EFS_OFFSET == TRUSSED_FS_OFFSET + (TRUSSED_IFS_BLOCKS * BLOCK_SIZE) as u32,
        "the external filesystem must begin exactly where the internal one ends"
    );
    assert!(
        TRUSSED_EFS_OFFSET + (TRUSSED_EFS_BLOCKS * BLOCK_SIZE) as u32 == TRUSSED_FS_END,
        "the external filesystem must end where the trussed window ends — and therefore \
         before the key region, which is not this module's flash to hand out"
    );
};