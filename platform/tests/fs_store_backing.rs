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
//! | [`external_resolves_to_flash_on_the_device`] | **RED, `#[ignore]`d** | `efs` is still `RamFsStorage` — US-1538 |

use std::path::{Path, PathBuf};

use trussed::store::{DynFilesystem, Store};
use trussed_core::types::Location;

use fapico2_platform::trusted_backend::host::{leak_buf, mount_fs, HostStore};

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

/// # US-1537's red, parked until US-1538
///
/// **This is the whole reason the story was filed**, and it fails today.
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
/// cannot drop it.
///
/// US-1538 moves `efs` onto flash. When it does, remove the `#[ignore]`
/// below; nothing else in this file needs to change.
///
/// To watch it fail today:
///
/// ```text
/// cargo test -p fapico2-platform --test fs_store_backing -- --ignored
/// ```
#[test]
#[ignore = "RED until US-1538 moves `efs` off `RamFsStorage` onto flash; see the module docs"]
fn external_resolves_to_flash_on_the_device() {
    let src = device_src();
    let efs = backing_type(&src, "EFS");

    assert_ne!(
        efs, "RamFsStorage",
        "EFS_STORAGE is declared `MaybeUninit<{efs}>` at {}. `Location::External` resolves to \
         `efs` (trussed-0.2.0/src/store.rs:138) and `vendor/opcard/src/card.rs:569` makes \
         `External` the opcard default — so today an applet that trusted the default keeps its \
         keys in RAM, in a filesystem `mount_ram_fs` reformats on every boot. This is the \
         defect US-1537 was filed for and US-1538 fixes.",
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
}
