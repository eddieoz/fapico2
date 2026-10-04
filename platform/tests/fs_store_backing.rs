//! US-1537 / S13, platform half: **what a trussed `Location` is actually
//! backed by**.
//!
//! The sibling gate, `apps/openpgp/tests/key_storage_location.rs`, answers
//! *which* `Location` each applet key asks for. This file answers the other
//! half — what that `Location` turns into — and the split is not cosmetic:
//! the original defect was `Location::External` resolving to RAM, so a check
//! that only reads the enum value passes straight over the thing that broke.
//! EPIC US-1537's own wording is "External resolves to a flash-backed
//! filesystem", and that second clause is this file.
//!
//! # Why the split (and why it is the platform that gets the second half)
//!
//! `DeviceFsStore` — the three `&'static dyn DynFilesystem` handles an
//! RP2350 applet's `Location` resolves through — lives in
//! `platform/src/trusted_backend/device.rs`, is `cfg`-gated to
//! `target_arch = "arm"`, and is therefore **not reachable from any host
//! test**. US-1538, the story that moves `External` onto flash, edits that
//! file. Putting the gate here means the person landing US-1538 has the
//! failing assertion in the same directory as the code they are changing,
//! and the `#[ignore]` waiting for them carries the reason.
//!
//! # About the citations
//!
//! This file is deliberately written against **symbols**, not line numbers.
//! `device.rs` is under active refactor — US-1536 is moving the trussed
//! window's offset/length into `platform/src/flashmap.rs` — so a gate whose
//! failure message carried a hard-coded `device.rs:427` would be wrong the
//! next morning for reasons that have nothing to do with key storage. Every
//! assertion below names the item it is looking at
//! (`static mut EFS_STORAGE: …`, `DeviceFsStore::boot`, `mount_ram_fs`) and
//! resolves the *live* line number at failure time via [`cite`], so the
//! report is accurate when it is produced rather than when it was typed.
//!
//! # What is asserted live, and what is not
//!
//! | test | today | why |
//! |---|---|---|
//! | [`a_location_resolves_to_the_filesystem_it_is_named_after`] | pass | the trussed mapping, executed |
//! | [`the_internal_filesystem_is_flash_backed_on_the_device`] | pass | `ifs` = `DevFlashStorage` over the QSPI window |
//! | [`the_volatile_filesystem_is_ram_on_the_device`] | pass | `vfs` = `RamFsStorage`, and that is *correct* |
//! | [`external_resolves_to_flash_on_the_device`] | pass | `efs` = `DevEfsStorage` over the QSPI window |
//! | [`a_legacy_volume_will_not_mount_in_the_split_window`] | pass | why the migration is a **file** copy |
//! | [`the_split_keeps_ifs_and_efs_disjoint_and_whole`] | pass | the carve tiles the window |
//! | [`the_split_leaves_ifs_room_for_what_it_carries`] | pass | measured, not asserted |
//!
//! # What cannot be asserted from here, and why
//!
//! `DeviceFsStore::boot` and `migrate_legacy_window` are `cfg`-gated to
//! `target_arch = "arm"` and cannot be linked into an x86_64 test, so the first
//! four rows read `device.rs` as text and the last three **execute the real
//! littlefs2 C library** over the same geometries the device uses. That
//! covers the part that is easy to get wrong and silent — littlefs2's refusal
//! to mount a volume whose geometry does not match its driver — but it is a
//! model of the migration, not the migration itself. Running it needs a board.

use std::path::{Path, PathBuf};

use littlefs2::driver::Storage;
use littlefs2::fs::Filesystem;
use littlefs2::io::OpenSeekFrom;
use littlefs2::path::{Path as LfsPath, PathBuf as LfsPathBuf};
use trussed::store::{DynFilesystem, Store};
use trussed_core::types::Location;

use fapico2_platform::trusted_backend::host::{leak_buf, mount_fs, HostStore};
use fapico2_platform::flashmap::{BLOCK_SIZE, TRUSSED_EFS_BLOCKS};

/// The external window's size, read from the carve rather than restated.
const TRUSSED_EFS_BYTES: usize = TRUSSED_EFS_BLOCKS * BLOCK_SIZE;

/// The device store this file is about. `cfg(target_arch = "arm")`, so it is
/// read, never linked — see the module docs.
const DEVICE_RS: &str = "platform/src/trusted_backend/device.rs";

/// 4 KiB blocks. Only has to be large enough for littlefs2 to mount over the
/// leaked buffer; nothing in this file writes more than nothing.
const BLOCKS: usize = 256;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the platform crate is not at the workspace root")
        .to_path_buf()
}

/// The device store source, read fresh on every call.
///
/// Fresh matters: `device.rs` is being refactored in parallel with this
/// story (US-1536), and a cached copy would be asserting about a tree that
/// no longer exists.
fn device_src() -> String {
    let path = workspace_root().join(DEVICE_RS);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{DEVICE_RS} could not be read ({e}); this gate is about it"))
}

/// `path:line` for the first line of `src` containing `needle`.
///
/// Used only in failure messages. A test that quoted a fixed line number
/// would go stale silently; this one is wrong only when it fires.
fn cite(src: &str, needle: &str) -> String {
    match src.lines().position(|l| l.contains(needle)) {
        Some(i) => format!("{DEVICE_RS}:{}", i + 1),
        None => format!("{DEVICE_RS} (no line matching {needle:?})"),
    }
}

/// The body of a brace-balanced block starting at the first line containing
/// `anchor`, from that line to the line the block closes on.
///
/// Brace counting is crude but adequate here: the blocks are `fn` bodies and
/// `impl` items in a file that is not full of braces inside string literals
/// in the regions of interest, and a mis-count produces a loud failure
/// ("block not found") rather than a quiet wrong answer.
fn block(src: &str, anchor: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.contains(anchor))
        .unwrap_or_else(|| {
            panic!("{DEVICE_RS}: no block starting at {anchor:?}; the shape this gate assumes has changed")
        });
    let mut depth = 0i32;
    let mut seen_open = false;
    let mut out = String::new();
    for line in &lines[start..] {
        depth += line.chars().filter(|c| *c == '{').count() as i32;
        depth -= line.chars().filter(|c| *c == '}').count() as i32;
        if line.contains('{') {
            seen_open = true;
        }
        out.push_str(line);
        out.push('\n');
        if seen_open && depth == 0 {
            return out;
        }
    }
    panic!("{DEVICE_RS}: the block at {anchor:?} never closes")
}

/// The declared storage type of one of the three `(storage, allocation,
/// filesystem)` statics in `DeviceFsStore`.
///
/// Each triple is declared as `static mut <FS>_STORAGE: MaybeUninit<Backing>`
/// — `IFS_STORAGE` is the QSPI-backed one, `EFS_STORAGE`/`VFS_STORAGE` the
/// RAM ones. Reading the *declaration* rather than the `mount_ram_fs` call
/// site is what lets this survive US-1538: the move changes what
/// `EFS_STORAGE` holds and nothing else.
///
/// Returns the type argument as written, e.g. `DevFlashStorage`.
fn backing_type(src: &str, fs: &str) -> String {
    let decl = format!("static mut {fs}_STORAGE:");
    let (line_no, _) = src
        .lines()
        .enumerate()
        .find(|(_, l)| l.trim_start().starts_with(&decl))
        .unwrap_or_else(|| {
            panic!(
                "{DEVICE_RS} no longer declares `static mut {fs}_STORAGE: …` — the three-store \
                 shape this gate assumes is gone, so it cannot say whether `{fs}` is flash"
            )
        });
    // The declaration may wrap onto a continuation line; take everything up
    // to the `;` either way, then pull the *single generic argument* out of
    // the `core::mem::MaybeUninit<…>` wrapper by matching angle brackets.
    // Matching the brackets rather than trimming text is the point: the
    // wrapper was introduced by US-951 (to keep 64 KiB of erase-value
    // storage out of `.data`), and a substring/trim of the declaration
    // yields `DevFlashStorage> = …::uninit()` rather than the backing type.
    let start_of_decl = src
        .lines()
        .take(line_no)
        .map(|l| l.len() + 1)
        .sum::<usize>();
    let after = &src[start_of_decl..];
    let end = after
        .find(';')
        .unwrap_or_else(|| panic!("{DEVICE_RS}:{}: `{decl} …` has no terminating `;`", line_no + 1));
    let init = &after[..end];
    let open = init
        .find('<')
        .unwrap_or_else(|| panic!("{DEVICE_RS}:{}: `{decl}` does not name a MaybeUninit<…>", line_no + 1));
    let mut depth = 0i32;
    let mut inner = String::new();
    for c in init[open + 1..].chars() {
        match c {
            '<' => {
                depth += 1;
                inner.push(c);
            }
            '>' if depth == 0 => break,
            '>' => {
                depth -= 1;
                inner.push(c);
            }
            _ => inner.push(c),
        }
    }
    inner.trim().to_string()
}

/// Three genuinely distinct filesystems, so "the same one" becomes a claim
/// about object identity rather than about a type.
///
/// `HostStore::fresh()` would also give three, but these are sized here so
/// the test states what it needs.
fn three_distinct_filesystems() -> (
    &'static dyn DynFilesystem,
    &'static dyn DynFilesystem,
    &'static dyn DynFilesystem,
) {
    let mk = || mount_fs::<BLOCKS>(leak_buf(BLOCKS * 4096));
    (mk(), mk(), mk())
}

/// # The gherkin's mapping, part one
///
/// `Location` is a three-variant enum (`Volatile | Internal | External`,
/// `trussed-core-0.2.2/src/types.rs:326-331`) and `Store::fs` is the only
/// thing that turns one into a filesystem
/// (`trussed-0.2.0/src/store.rs:135-141`):
///
/// ```text
/// Internal => self.ifs(),  External => self.efs(),  Volatile => self.vfs(),
/// ```
///
/// That mapping lives in a dependency, so it is **executed** rather than
/// grepped: three distinct filesystems are handed to a `Store` and each
/// `Location` is asked for its filesystem by identity. If upstream ever
/// renumbers the variants or reorders the arms, this goes red instead of
/// quietly sending `External` somewhere else — and both halves of US-1537
/// rest on this row.
#[test]
fn a_location_resolves_to_the_filesystem_it_is_named_after() {
    let (ifs, efs, vfs) = three_distinct_filesystems();
    let store = HostStore::new(ifs, efs, vfs);

    // The three handles really are distinct objects, so a mapping assertion
    // that compared a value with itself could not pass here.
    assert!(
        !std::ptr::eq(store.ifs(), store.efs()) && !std::ptr::eq(store.ifs(), store.vfs()),
        "the fixtures must be three different filesystems, or this test proves nothing"
    );

    // Pointer identity is the assertion: `fs(Location::X)` must return *the
    // same filesystem object* `HostStore` was handed for X, not merely one
    // of the same type.
    assert!(
        std::ptr::eq(store.fs(Location::Internal), store.ifs()),
        "Location::Internal must resolve to the store's `ifs` (trussed-0.2.0/src/store.rs:137)"
    );
    assert!(
        std::ptr::eq(store.fs(Location::External), store.efs()),
        "Location::External must resolve to the store's `efs` (trussed-0.2.0/src/store.rs:138)"
    );
    assert!(
        std::ptr::eq(store.fs(Location::Volatile), store.vfs()),
        "Location::Volatile must resolve to the store's `vfs` (trussed-0.2.0/src/store.rs:139)"
    );
}

/// # The gherkin's second clause, part two: `Internal` is flash
///
/// This is the one that actually holds the card's state today.
/// `apps/openpgp/src/device_shell.rs:123` sets
/// `options.storage = Location::Internal`, so the OpenPGP card state is
/// `ifs`, and `ifs` is the only one of the three that is not RAM.
///
/// What is asserted is the *property*, not the spelling, because US-1536 is
/// concurrently rewriting the window's geometry:
///
/// * `IFS_STORAGE` is a `DevFlashStorage` — littlefs2 storage over the
///   embassy-rp blocking **QSPI** `Flash` driver, not a RAM buffer that
///   happens to share the name.
/// * That driver is *confined to a flash window*: it carries an `offset`
///   set to the trussed window's start, and every `read`/`write` adds it, so
///   the bytes land in QSPI flash rather than wherever the struct happens to
///   sit. A type rename that pointed the driver at RAM would pass the first
///   assertion and fail this one.
/// * `DeviceFsStore::boot` publishes the QSPI-mounted `IFS` as the store's
///   `ifs:` field, and does so by mounting `IFS_STORAGE` itself rather than
///   through the RAM helper. That distinction survives US-1538: moving
///   `External` to flash changes what `efs` is, not how `ifs` is mounted.
#[test]
fn the_internal_filesystem_is_flash_backed_on_the_device() {
    let src = device_src();

    let ifs = backing_type(&src, "IFS");
    assert_ne!(
        ifs, "RamFsStorage",
        "IFS_STORAGE is declared `MaybeUninit<{ifs}>` at {} — `Location::Internal` is where the \
         OpenPGP card state lives, and a RAM backing there is exactly the defect shape this \
         gate exists for (a non-volatile `Location` resolving to a volatile filesystem).",
        cite(&src, "static mut IFS_STORAGE:")
    );
    assert_eq!(
        ifs, "DevFlashStorage",
        "IFS_STORAGE must remain the QSPI-backed storage type; it is now `{ifs}`. A new backing \
         type is fine, but it must be flash — rename the constant and this message with it."
    );

    // The name is not the proof: `DevFlashStorage` must actually address the
    // QSPI window, and both `read` and `write` must add the window's offset.
    //
    // **This assertion was rewritten**, and the reason is worth keeping. It
    // originally required the offset to arrive through a `self.offset` *field*,
    // which is how the relocation addressed two windows from one handle. That
    // field cost 8 bytes of `.bss` (IFS_STORAGE went 2 -> 8) on a board with 4
    // bytes of unallocated SRAM in total, where DARK-BOOT-1 established that
    // bss growth moves MSPLIM and shrinks the main stack. The relocation now
    // probes the legacy window through a stack-only `LegacyWindow` that borrows
    // the flash, so `DevFlashStorage` is back to one field and its offset is
    // the constant.
    //
    // The property this gate protects is unchanged, and is what the assertion
    // now states: the driver adds the trussed window's offset, from wherever it
    // comes. A renamed driver pointing at RAM still fails here.
    let dev = block(&src, "impl Storage for DevFlashStorage");
    for arm in ["fn read(", "fn write("] {
        assert!(
            dev.contains(arm),
            "DevFlashStorage no longer has a `{arm}` arm ({}) — the QSPI-window check below \
             cannot be made, so this gate would be passing vacuously.",
            cite(&src, "impl Storage for DevFlashStorage")
        );
    }
    assert!(
        dev.contains("TRUSSED_FS_OFFSET + off as u32"),
        "DevFlashStorage's read/write must add the trussed window's offset ({}) — through a \
         field or through the constant, either is fine. Without it, `DevFlashStorage` is a \
         name, not a location, and a renamed driver pointing at RAM would sail through the \
         assertion above.",
        cite(&src, "impl Storage for DevFlashStorage")
    );
    // The offset has to come from the one place it is written down. It used to
    // be a field set by the constructor; it is now the constant itself, so the
    // thing worth gating moved up a level: `device.rs` must not restate the
    // window's offset, or there are two numbers again and this is exactly the
    // drift US-1536 removed.
    assert!(
        src.contains("pub use crate::flashmap::"),
        "device.rs must take TRUSSED_FS_OFFSET from crate::flashmap ({}) rather than \
         restating it. The flash map owns every persistent region's offset; a second literal \
         here is the defect US-1536 closed.",
        cite(&src, "pub use crate::flashmap")
    );

    // …and `ifs` is the QSPI-mounted triple, not the RAM helper's product.
    let boot = block(&src, "fn boot(flash: DevFlash)");
    assert!(
        boot.contains("ifs: &*(*core::ptr::addr_of!(IFS)).as_ptr()"),
        "DeviceFsStore::boot must publish the QSPI-mounted IFS as the store's `ifs:` field ({})",
        cite(&src, "fn boot(flash: DevFlash)")
    );
    assert!(
        !boot.contains("ifs = mount_ram_fs(") && !boot.contains("let ifs = mount_ram_fs("),
        "DeviceFsStore::boot builds `ifs` through `mount_ram_fs` ({}), which formats RAM — the \
         internal filesystem would then be volatile.",
        cite(&src, "fn boot(flash: DevFlash)")
    );
}

/// The definition of `Volatile`, asserted so the other two clauses have
/// something to be different *from*.
///
/// `vfs` is RAM and that is correct — a volatile filesystem is one whose
/// contents a power cycle is supposed to take away. If this goes red,
/// `Location::Volatile` has stopped meaning "RAM" and the gate story needs
/// rethinking, not just this line.
#[test]
fn the_volatile_filesystem_is_ram_on_the_device() {
    let src = device_src();
    let vfs = backing_type(&src, "VFS");
    assert_eq!(
        vfs, "RamFsStorage",
        "VFS_STORAGE is declared `MaybeUninit<{vfs}>` at {} — the volatile store must be RAM. \
         `Location::Volatile` means 'a power cycle takes this away'; backing it with anything \
         else makes the name a lie in the other direction.",
        cite(&src, "static mut VFS_STORAGE:")
    );
}

/// # US-1538's second clause: `External` is flash
///
/// `Location::External` resolves to `efs` (asserted live, above), and on the
/// RP2350 `efs` is a `RamFsStorage` built by `mount_ram_fs`, which calls
/// `Filesystem::format` on every boot. So the upstream opcard default —
/// `Options::default().storage = Location::External`
/// (`vendor/opcard/src/card.rs:569`) — is a *RAM* filesystem, reformatted on
/// every power-up. An applet that trusted the default would lose its key on
/// reboot and would see no error at the time: the write succeeded, into
/// something that was about to be erased.
///
/// The firmware does not hit it, because the one production site overrides
/// the default to `Location::Internal`
/// (`apps/openpgp/src/device_shell.rs:123`, gated by
/// `apps/openpgp/tests/key_storage_location.rs`). That override is
/// load-bearing and US-1537 exists so the next refactor of `device_shell.rs`
/// cannot drop it. US-1538 removes the trap rather than guarding against
/// stepping on it.
#[test]
fn external_resolves_to_flash_on_the_device() {
    let src = device_src();
    let efs = backing_type(&src, "EFS");

    assert_ne!(
        efs, "RamFsStorage",
        "EFS_STORAGE is declared `MaybeUninit<{efs}>` at {}. `Location::External` resolves to \
         `efs` (trussed-0.2.0/src/store.rs:138) and `vendor/opcard/src/card.rs:569` makes \
         `External` the opcard default — so an applet that trusts the default keeps its keys in \
         RAM, in a filesystem `mount_ram_fs` reformats on every boot. This is the defect US-1537 \
         was filed for and US-1538 fixes.",
        cite(&src, "static mut EFS_STORAGE:")
    );

    // Second half, and deliberately negative: `mount_ram_fs` must no longer
    // build the external store. Counting call sites inside `boot` rather
    // than naming a replacement type means this passes whichever flash
    // backing US-1538 chooses, and fails if the RAM helper was merely
    // re-pointed instead of removed.
    let boot = block(&src, "fn boot(flash: DevFlash)");
    let ram_calls = boot.matches("mount_ram_fs(").count();
    assert_eq!(
        ram_calls, 1,
        "DeviceFsStore::boot calls `mount_ram_fs` {ram_calls} time(s) ({}); only the volatile \
         store may still be built that way. `efs` is the external store and must be flash-backed.",
        cite(&src, "fn boot(flash: DevFlash)")
    );

    // …and the new type must actually address a flash window, not be another
    // name. This is the `ifs` row's "the name is not the proof" argument,
    // applied to `efs`: a renamed driver that pointed at RAM would sail
    // through the two assertions above.
    let efs_impl = block(&src, "impl Storage for DevEfsStorage");
    assert!(
        efs_impl.contains("TRUSSED_EFS_OFFSET + off as u32"),
        "DevEfsStorage's read/write must add the external window's offset ({}). Without it \
         `DevEfsStorage` is a name, not a location, and a driver pointing at RAM passes the \
         assertions above. The offset must also come from `crate::flashmap`, not a literal here \
         — the same rule the `ifs` row enforces.",
        cite(&src, "impl Storage for DevEfsStorage")
    );
    assert!(
        efs_impl.contains("const BLOCK_COUNT: usize = TRUSSED_EFS_BLOCKS;"),
        "DevEfsStorage must declare the external window's block count from flashmap ({}); a \
         block count larger than the window is a second filesystem erasing the first one's \
         blocks.",
        cite(&src, "impl Storage for DevEfsStorage")
    );

    // A flash-backed `efs` that is still *formatted on every boot* would be
    // the same defect wearing a different hat, so the format has to be
    // guarded by a mountability probe.
    let flash_mount = block(&src, "unsafe fn mount_flash_fs");
    assert!(
        flash_mount.contains("if !Filesystem::is_mountable("),
        "mount_flash_fs ({}) formats unconditionally. It is reached by the external store, whose \
         whole purpose is to survive a power cycle; formatting a flash volume on every boot is \
         `mount_ram_fs`'s defect with a slower disk behind it.",
        cite(&src, "unsafe fn mount_flash_fs")
    );
    let ram_mount = block(&src, "fn mount_ram_fs");
    assert!(
        !ram_mount.contains("is_mountable"),
        "mount_ram_fs ({}) is now reached by the volatile store only, where an unconditional \
         format is correct and expected.",
        cite(&src, "fn mount_ram_fs")
    );
}

/// # The fact the whole migration design rests on
///
/// Executed against the **real** littlefs2 C library, not asserted from a
/// comment.
///
/// littlefs2 writes `block_count` into the volume superblock and compares it
/// against the driver's on mount: `lfs.c:4523-4531`, `Invalid block count` →
/// `LFS_ERR_INVAL`. So a volume formatted at one geometry is **not** a volume
/// with a truncated tail at a smaller geometry — it is an unmountable one.
///
/// That is the whole reason `migrate_legacy_window` copies files rather than
/// blocks. The byte-copy relocation US-1536 shipped was correct then, because
/// the window had one geometry; US-1538's split makes `ifs` narrower, and the
/// same code would erase every OpenPGP key on every provisioned unit at the
/// `is_mountable` → `format` fall-through.
///
/// If this test ever goes red, littlefs2 has learned to mount a volume across
/// a geometry change, and the migration can be simplified back to a block copy.
/// Until then it is load-bearing.
#[test]
fn a_legacy_volume_will_not_mount_in_the_split_window() {
    const LEGACY_BLOCKS: usize = 256; // the pre-split window, in full

    // A volume written at the legacy geometry, with a file in it.
    let legacy_buf = leak_buf(LEGACY_BLOCKS * 4096);
    {
        let fs = mount_fs::<LEGACY_BLOCKS>(legacy_buf);
        fs.create_dir_all(littlefs2::path!("/opcard"))
            .expect("the legacy volume must accept a directory");
        fs.write(littlefs2::path!("/opcard/key"), &[0xA7u8; 3000])
            .expect("the legacy volume must accept a file");
    }

    // The relocation's byte copy, unchanged: erase the destination **window**
    // and stream the source's bytes into it. The window is still 256 blocks
    // after the split — the split partitions it, it does not shorten it — so
    // the copy is byte-for-byte identical to what US-1536 shipped.
    let split_buf = leak_buf(LEGACY_BLOCKS * 4096);
    copy_erased(legacy_buf, split_buf);

    // And then the device declares a driver over the front of that window: the
    // `ifs` half. 224 is what the 768 KiB / 256 KiB carve in `flashmap.rs`
    // yields; the test is written against the *ratio* so it keeps its meaning if
    // the carve moves.
    const SPLIT_BLOCKS: usize = LEGACY_BLOCKS - (LEGACY_BLOCKS / 8);

    // …and the device's own probe, run against the copy.
    let storage: &'static mut LeakedStorage<SPLIT_BLOCKS> =
        Box::leak(Box::new(LeakedStorage::new(split_buf)));
    assert!(
        !Filesystem::is_mountable(&mut *storage),
        "a volume copied byte-for-byte out of a {LEGACY_BLOCKS}-block window mounted in a \
         {SPLIT_BLOCKS}-block one. littlefs2 pins block_count in the superblock \
         (lfs.c:4523-4531), so it must refuse — and while it refuses, \
         `migrate_legacy_window` has to re-create the volume at the new geometry and copy the \
         *files* across, because the byte copy `DeviceFsStore::boot` would otherwise fall \
         through to `Filesystem::format` destroys every key on the unit."
    );
}

/// The migration's strategy, executed: re-creating the volume at the smaller
/// geometry and replaying its contents preserves them.
///
/// This is a **model** of `migrate_legacy_window` (which is arm-gated and
/// cannot be linked here), written against the same littlefs2 the device
/// uses, so the copy it performs is the copy the device performs. What it
/// cannot prove is that `device.rs` performs it — that needs a board.
#[test]
fn the_file_level_migration_preserves_a_populated_legacy_volume() {
    const LEGACY_BLOCKS: usize = 64;
    const SPLIT_BLOCKS: usize = 48;

    /// One realistic OpenPGP-shaped payload: a key blob, a sub-key blob and a
    /// small state file, in a nested directory — the shape trussed writes.
    fn populate(fs: &dyn DynFilesystem) {
        // littlefs2's `write` does not create parents; trussed creates them
        // first (`trussed-0.2.0/src/store.rs:189-190`, `create_directories`),
        // and so does the migration, which is why the copy can nest.
        fs.create_dir_all(littlefs2::path!("/opcard/0x9f"))
            .expect("create dir");
        fs.write(
            littlefs2::path!("/opcard/0x9f/key-1"),
            &[0x11u8; 4096],
        )
        .expect("key");
        fs.write(
            littlefs2::path!("/opcard/0x9f/key-2"),
            &[0x22u8; 1500],
        )
        .expect("subkey");
        fs.write(
            littlefs2::path!("/opcard/0x9f/state"),
            b"pw1-valid\x00\x03",
        )
        .expect("state");
        // A zero-length file: the case a chunked copy that only writes on read
        // would silently drop.
        fs.write(littlefs2::path!("/opcard/0x9f/empty"), &[])
            .expect("empty");
    }

    let legacy_buf = leak_buf(LEGACY_BLOCKS * 4096);
    populate(mount_fs::<LEGACY_BLOCKS>(legacy_buf));

    // …format the destination at the new geometry and copy the tree into it.
    let split_buf = leak_buf(SPLIT_BLOCKS * 4096);
    let destination = mount_fs::<SPLIT_BLOCKS>(split_buf);
    let source = mount_fs::<LEGACY_BLOCKS>(legacy_buf);
    migrate_for_test(source, destination);

    // Read it back through a *fresh* mount of the destination — a remount, not
    // the live handle — because "the copy returned Ok" is not the same claim
    // as "the bytes are in flash".
    let reopened = mount_fs::<SPLIT_BLOCKS>(split_buf);
    for (path, expect) in [
        (
            littlefs2::path!("/opcard/0x9f/key-1"),
            Some(vec![0x11u8; 4096]),
        ),
        (
            littlefs2::path!("/opcard/0x9f/key-2"),
            Some(vec![0x22u8; 1500]),
        ),
        (
            littlefs2::path!("/opcard/0x9f/state"),
            Some(b"pw1-valid\x00\x03".to_vec()),
        ),
        // Present, and empty — the assertion is `exists`, not "reads back".
        (littlefs2::path!("/opcard/0x9f/empty"), None),
    ] {
        assert!(
            reopened.exists(path),
            "{path:?} did not survive the migration into the smaller volume. The destination is \
             a fresh mount, so this is about the bytes, not about a cached handle."
        );
        if let Some(expect) = expect {
            let got = read_all(reopened, path);
            assert_eq!(
                got.len(),
                expect.len(),
                "{path:?} came back {len} bytes, not the {want} it was written with",
                len = got.len(),
                want = expect.len()
            );
            assert!(got == expect, "{path:?} came back with different bytes");
        }
    }

    // And the source is untouched: a migration that consumed its input would
    // make a retry after a power cut impossible, which is the property the
    // read-only `LegacyWindow` storage exists to provide.
    let still_there = mount_fs::<LEGACY_BLOCKS>(legacy_buf);
    assert!(
        still_there.exists(littlefs2::path!("/opcard/0x9f/key-1")),
        "the legacy volume lost a file during the migration. It must stay readable after a \
         power cut mid-copy, or the retry has nothing to copy from."
    );
}

/// The carve is a split, not a relocation: `ifs` and `efs` must tile the
/// window exactly, and both must be non-empty.
///
/// Read from `flashmap.rs` rather than re-stated, so the numbers the test
/// checks are the numbers the firmware compiles against. `flashmap.rs` asserts
/// the same identities at compile time; this one exists because a reader
/// arriving at `fs_store_backing.rs` should not have to go and find that.
#[test]
fn the_split_keeps_ifs_and_efs_disjoint_and_whole() {
    let map = std::fs::read_to_string(workspace_root().join("platform/src/flashmap.rs"))
        .expect("platform/src/flashmap.rs");
    // `TRUSSED_EFS_BLOCKS` is written as the *difference* of two other
    // constants, which is the point: the window is single-source and the carve
    // is an expression of it. So the reader resolves identifiers rather than
    // transcribing numbers, and a carve written as a literal still reads.
    fn usize_const(map: &str, name: &str) -> usize {
        let expr = map
            .lines()
            .find_map(|l| {
                let rest = l.trim().strip_prefix(&format!("pub const {name}: usize = "))?;
                rest.split(';').next().map(str::trim)
            })
            .unwrap_or_else(|| panic!("flashmap.rs no longer declares `pub const {name}: usize`"));
        match expr.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                let (lhs, rhs) = expr
                    .split_once(" - ")
                    .unwrap_or_else(|| panic!("flashmap.rs: cannot read {name} = {expr:?}"));
                usize_const(map, lhs.trim()) - usize_const(map, rhs.trim())
            }
        }
    }
    let window = usize_const(&map, "TRUSSED_FS_BLOCKS");
    let ifs = usize_const(&map, "TRUSSED_IFS_BLOCKS");
    let efs = usize_const(&map, "TRUSSED_EFS_BLOCKS");

    assert!(ifs > 0, "ifs must not be empty — it is where the OpenPGP keys live");
    assert!(efs > 0, "efs must not be empty — it is where `Location::External` now lives");
    assert_eq!(
        ifs + efs,
        window,
        "ifs ({ifs}) + efs ({efs}) must tile the {window}-block window exactly: a gap is flash \
         nothing can use, an overlap is two littlefs2 filesystems erasing each other's blocks"
    );
    // The order is load-bearing, so assert it rather than assume it: `ifs` is
    // the front of the window and `efs` the tail. littlefs2 pins `block_count`
    // in the superblock, so a relocated volume's blocks 0 and 1 (its superblock
    // pair) must land inside `ifs` — if the carve moved `efs` to the front, the
    // byte copy would put the metadata pair in the wrong filesystem and
    // `migrate_legacy_window` would have nothing to mount.
    assert!(
        map.contains("pub const TRUSSED_EFS_OFFSET: u32 =\n    TRUSSED_FS_OFFSET + (TRUSSED_IFS_BLOCKS * BLOCK_SIZE) as u32;")
            || map.contains("TRUSSED_EFS_OFFSET: u32 = TRUSSED_FS_OFFSET + (TRUSSED_IFS_BLOCKS * BLOCK_SIZE) as u32"),
        "flashmap.rs no longer places the external window immediately after the internal one at \
         the window's base. `efs` must be the *tail*: the relocated legacy volume's superblock \
         pair lives at blocks 0 and 1, and littlefs2 refuses a volume whose geometry does not \
         match its driver, so those blocks have to stay inside `ifs`."
    );
}

/// # The capacity half of the carve, measured rather than asserted
///
/// `docs/capacity.md` opens by insisting that a number here says where it came
/// from, and `docs/tasks/EPIC-secure-storage.md` §2 records `ifs` as holding
/// OpenPGP + PIV with "~770 KB spare" in the 1 MiB window. That is a figure
/// about keys, not about a filesystem, and the carve in `flashmap.rs` is
/// justified against it.
///
/// This writes a realistic `ifs` payload — one OpenPGP card's worth of key
/// blobs, at the DER sizes the epic cites (three RSA-4096 private keys, 7–10 KB
/// each) plus a little state — into a real littlefs2 volume, and reports what
/// the volume *costs*, metadata and CTZ overhead included. That is the number
/// the 768 KiB `ifs` has to clear, and it is measured rather than transcribed.
#[test]
fn the_split_leaves_ifs_room_for_what_it_carries() {
    const BLOCKS: usize = 256; // the window the payload is sized against
    const BLOCK: usize = 4096;

    let buf = leak_buf(BLOCKS * BLOCK);
    let fs = mount_fs::<BLOCKS>(buf);
    fs.create_dir_all(littlefs2::path!("/opcard"))
        .expect("the volume must accept a directory");
    let before = fs.available_space().expect("a mounted volume reports its free space");

    // Three RSA-4096 private keys at the DER sizes the epic cites, plus the
    // state files a card keeps beside them.
    for (path, len) in [
        (littlefs2::path!("/opcard/key-0"), 10_000usize),
        (littlefs2::path!("/opcard/key-1"), 8_000),
        (littlefs2::path!("/opcard/key-2"), 7_000),
    ] {
        fs.write(path, &vec![0x5Au8; len])
            .expect("the volume must accept a maximal key");
    }
    fs.write(littlefs2::path!("/opcard/state"), &[0u8; 256])
        .expect("state");

    let after = fs.available_space().expect("free space after the write");
    let used = before - after;
    // Visible with `--nocapture`; the number is the point of the test, so it is
    // printed rather than only asserted against.
    println!(
        "ifs payload: {used} B for 3 RSA-4096 keys (25 KB of DER) + state, littlefs2 \
         overhead included; carve gives ifs {} B ({}x) and efs {} B",
        768 * 1024,
        (768 * 1024) / used,
        256 * 1024
    );

    // 768 KiB is what `flashmap.rs` gives `ifs`. Assert the carve against the
    // measured cost with the epic's own multiple rather than a round number, so
    // a regression in either the payload or the carve shows up here.
    const IFS_BYTES: usize = 768 * 1024;
    assert!(
        used * 3 < IFS_BYTES,
        "one OpenPGP card's key set costs {used} B of littlefs2 volume, so three card's worth \
         ({triple} B) no longer fit `ifs`'s {IFS_BYTES} B. Either the carve is too small or the \
         payload model above is wrong; both are findings, and the first is a flash decision, not \
         a test to relax.",
        triple = used * 3
    );
    // …and the whole point of the carve was that `efs` gets real flash too. This
    // is stated against `efs`'s **own** window rather than as a second clause of the
    // assertion above: `ifs` is 768 KiB and `efs` 256 KiB, so a conjunct repeating
    // the `ifs` bound would be subsumed by it and would only look like a second
    // check. Read the carve rather than restating 256 KiB, so a future re-split
    // has to re-answer the question instead of passing on a stale literal.
    let efs_bytes = TRUSSED_EFS_BYTES;
    assert!(
        used * 3 < efs_bytes,
        "the external window ({efs_bytes} B) cannot hold three card's worth of keys either \
         ({used} B each); the carve is sized for one card in `ifs` and a handful in `efs`, not \
         for an unbounded number of applet keysets"
    );
}

// ---------------------------------------------------------------------------
// littlefs2 helpers for the tests above
// ---------------------------------------------------------------------------

/// littlefs2 `Storage` over a leaked host buffer at a *fixed* block count.
///
/// `mount_fs` is parameterized and leaks everything; these tests need the same
/// thing but also need to name the block count in a type position (to stand in
/// for `DevFlashStorage` / `LegacyWindow`, whose geometries differ). Mirrors
/// `fapico2_platform::trusted_backend::host::BufStorage`, which is not public.
pub struct LeakedStorage<const BLOCKS: usize> {
    buf: *mut [u8],
}

impl<const BLOCKS: usize> LeakedStorage<BLOCKS> {
    fn new(buf: *mut [u8]) -> Self {
        Self { buf }
    }

    fn buf(&mut self) -> &mut [u8] {
        // SAFETY: the buffer is leaked for the process lifetime and `&mut self`
        // admits at most one in-flight driver call, exactly as `BufStorage` in
        // `trusted_backend::host` does.
        unsafe { &mut *self.buf }
    }
}

impl<const BLOCKS: usize> Storage for LeakedStorage<BLOCKS> {
    const READ_SIZE: usize = 256;
    const WRITE_SIZE: usize = 256;
    const BLOCK_SIZE: usize = 4096;
    const BLOCK_COUNT: usize = BLOCKS;
    const BLOCK_CYCLES: isize = -1;
    type CACHE_SIZE = littlefs2::consts::U256;
    type LOOKAHEAD_SIZE = littlefs2::consts::U8;

    fn read(&mut self, off: usize, buf: &mut [u8]) -> littlefs2::io::Result<usize> {
        let s = self.buf();
        buf.copy_from_slice(&s[off..off + buf.len()]);
        Ok(buf.len())
    }

    fn write(&mut self, off: usize, data: &[u8]) -> littlefs2::io::Result<usize> {
        let s = self.buf();
        s[off..off + data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    fn erase(&mut self, off: usize, len: usize) -> littlefs2::io::Result<usize> {
        let s = self.buf();
        s[off..off + len].fill(0xFF);
        Ok(len)
    }
}

/// The relocation's old behaviour, reduced to its essence: erase the
/// destination and stream the source's bytes into it.
///
/// Deliberately **not** littlefs2 — it is the raw flash move, which is what
/// `relocate_copy` used to do on top of the same erase.
fn copy_erased(src: *mut [u8], dst: *mut [u8]) {
    // SAFETY: both buffers are leaked for the process lifetime and the host
    // tests are single-threaded, so the two slices are never live at once.
    let (src, dst) = unsafe { (&*src, &mut *dst) };
    dst.fill(0xFF);
    dst.copy_from_slice(src);
}

/// Read a file's whole contents out of a mounted volume.
fn read_all(fs: &dyn DynFilesystem, path: &LfsPath) -> Vec<u8> {
    let mut out = Vec::new();
    fs.open_file_and_then(path, &mut |file| {
        let mut buf = [0u8; 1024];
        loop {
            match file.read(&mut buf) {
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .expect("the migrated file must open");
    out
}

/// The migration [`migrate_legacy_window`] performs, on the host.
///
/// Deliberately the same shape as the device code — walk the tree, recreate the
/// directories, stream each file across in chunks — so a change to one that is
/// not made to the other shows up as a disagreement rather than as a surprise
/// on hardware. It is a *model*: what this proves is that the strategy works
/// against the real littlefs2, not that `device.rs` runs it.
fn migrate_for_test(src: &dyn DynFilesystem, dst: &dyn DynFilesystem) {
    let root = LfsPathBuf::try_from("/").expect("root path");
    copy_dir_for_test(src, dst, root.as_path(), 0)
}

fn copy_dir_for_test(src: &dyn DynFilesystem, dst: &dyn DynFilesystem, path: &LfsPath, depth: usize) {
    assert!(depth <= 3, "migration depth cap at {path:?}");
    let entries: Vec<_> = src
        .read_dir_and_then(path, &mut |it| {
            let mut v = Vec::new();
            for e in it {
                v.push(e.expect("a readable directory entry"));
            }
            Ok(v)
        })
        .expect("the source directory must list");
    for entry in entries {
        // `.` and `..` are real entries here too, and `DirEntry::path()` is
        // `parent + "/" + name` (littlefs2-0.8.1/src/fs.rs:1020), so recursing
        // into `.` walks forever. The device migration skips them for the same
        // reason; see `copy_dir` in `trusted_backend/device.rs`.
        let name = entry.file_name().as_ref();
        if name == "." || name == ".." {
            continue;
        }
        match entry.file_type() {
            littlefs2::fs::FileType::Dir => {
                dst.create_dir_all(entry.path()).expect("create dir");
                copy_dir_for_test(src, dst, entry.path(), depth + 1);
            }
            littlefs2::fs::FileType::File => {
                dst.write(entry.path(), &[]).expect("create file");
                let size = entry.metadata().len();
                let mut pos = 0usize;
                src.open_file_and_then(entry.path(), &mut |file| {
                    let mut buf = [0u8; 256];
                    while pos < size {
                        let n = match file.read(&mut buf) {
                            Ok(0) | Err(_) => return Ok(()),
                            Ok(n) => n,
                        };
                        dst.write_chunk(
                            entry.path(),
                            &buf[..n],
                            OpenSeekFrom::Start(pos as u32),
                        )
                        .expect("write chunk");
                        pos += n;
                    }
                    Ok(())
                })
                .expect("the source file must open");
            }
        }
    }
}
