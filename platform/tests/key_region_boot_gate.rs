//! US-1559: **the boot path must not read the key region, and it must be able
//! not to.** A source-level gate on the ordering claim.
//!
//! # Why a source-parsing test at all
//!
//! S8/S9 say the boot path does not touch the per-record key store. That is a
//! claim about *order* in a file, so it is checked against the file: this
//! reads `firmware/src/main.rs` and `firmware/src/boot.rs` fresh and asserts
//! where the region's three lifecycle calls sit relative to
//! `mark!(RUNG_USB)`. The convention is `platform/tests/fs_store_backing.rs` —
//! assertions written against **symbols**, resolving the live line number at
//! failure time via [`cite`], because a gate that quotes a fixed line number is
//! wrong the next morning for reasons that have nothing to do with the property.
//!
//! # What the runtime gate already covers, and what only this covers
//!
//! `boot::key_region()` answers `None` until `release_key_region()` has run, so
//! a boot-path caller that arrived early gets a clean empty key set rather than
//! a handle. That is the strong half, and it is **runtime** — it holds even if
//! somebody writes a new pre-`RUNG_USB` call site tomorrow.
//!
//! This file is the other half: it says the release is *after* `RUNG_USB`, that
//! nothing earlier in the boot even *asks*, and that the ladder still has
//! exactly nine marks. A runtime gate alone would pass if the release were moved
//! above `RUNG_USB` and nothing called the accessor — the region would be
//! reachable during boot with nothing observing it. Two gates, each covering the
//! other's blind spot.
//!
//! # What is deliberately **not** asserted
//!
//! That the constructor reads nothing. That is asserted where it is true and
//! where it is mechanical — the `DeviceKeyRegion::new` body, below — because
//! "does this call touch flash" is not decidable by reading a line of a diff; it
//! is decidable by reading a body whose entire contents are one field
//! assignment.

use std::path::{Path, PathBuf};

const MAIN_RS: &str = "firmware/src/main.rs";
const BOOT_RS: &str = "firmware/src/boot.rs";
const REGION_RS: &str = "platform/src/keyregion/device_region.rs";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the platform crate is not at the workspace root")
        .to_path_buf()
}

/// Read a source file fresh on every call.
///
/// Fresh matters: these files are under active work, and a cached copy would be
/// asserting about a tree that no longer exists — the reason
/// `fs_store_backing.rs:67-76` states at its own `device_src`.
fn src(rel: &str) -> String {
    let path = workspace_root().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{rel} could not be read ({e}); this gate is about it"))
}

/// The byte offset of the first line containing `needle`, or a loud failure.
fn at(text: &str, needle: &str) -> usize {
    text.find(needle).unwrap_or_else(|| {
        panic!(
            "no `{needle}` in the file this gate reads. The shape it assumes has changed; the \
             gate cannot be re-derived by guessing — re-state the property against the new shape."
        )
    })
}

/// `path:line` for the first line containing `needle`. Failure messages only.
fn cite(rel: &str, text: &str, needle: &str) -> String {
    // `text` is the whole file, so counting the newlines before the match gives
    // the 1-based line number. `at` panics rather than returning a placeholder:
    // a citation for a symbol that is gone is worse than no citation.
    let i = at(text, needle);
    format!("{rel}:{}", text[..i].lines().count())
}

/// Every line in `rel` that mentions `needle`.
fn all_lines(text: &str, needle: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.contains(needle))
        .map(|(i, l)| (i + 1, l.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// The ladder is still nine marks
// ---------------------------------------------------------------------------

/// US-1559 added boot-path code around the ladder and must not have added a
/// rung.
///
/// `bootphase::RUNGS` is 9 and `bootphase.rs`'s own test holds the call sites to
/// `RUNG_ORDER`; this is the same claim seen from the side that would break it
/// — a `mark!` site that is not one of the nine would make the pulse count lie
/// about progress, which is the one failure mode an instrument like that cannot
/// have.
#[test]
fn the_ladder_still_has_exactly_nine_marks() {
    let main = src(MAIN_RS);
    let marks = all_lines(&main, "mark!(fapico2_firmware::bootphase::RUNG_");
    assert_eq!(
        marks.len(),
        9,
        "`main.rs` has {} `mark!(…RUNG_…)` call sites ({}); the ladder is defined as exactly nine \
         (`bootphase::RUNGS`), and a tenth would make the pulse count report a boundary the boot \
         does not have.",
        marks.len(),
        marks
            .iter()
            .map(|(n, _)| format!("{MAIN_RS}:{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    // The full call, not the bare symbol: the prose around this story's own
    // wiring legitimately names `RUNG_USB` in a comment, and counting those
    // would make this gate red for a reason that is not a defect.
    let usb_sites = all_lines(&main, "mark!(fapico2_firmware::bootphase::RUNG_USB);");
    assert_eq!(
        usb_sites.len(),
        1,
        "there must be exactly one `mark!(…RUNG_USB);` site ({}), found {} — this gate anchors \
         every ordering claim on it, and a second one would leave 'which' ambiguous",
        usb_sites
            .iter()
            .map(|(n, _)| format!("{MAIN_RS}:{n}"))
            .collect::<Vec<_>>()
            .join(", "),
        usb_sites.len()
    );
}

// ---------------------------------------------------------------------------
// S8/S9: nothing reads the region before RUNG_USB
// ---------------------------------------------------------------------------

/// The release is **after** `RUNG_USB`. This is the load-bearing assertion.
#[test]
fn the_region_is_released_after_rung_usb() {
    let main = src(MAIN_RS);
    let usb = at(&main, "mark!(fapico2_firmware::bootphase::RUNG_USB)");
    let release = at(&main, "boot::release_key_region()");
    assert!(
        release > usb,
        "the release must come after the marker, not before ({} vs {})",
        cite(MAIN_RS, &main, "boot::release_key_region()"),
        cite(MAIN_RS, &main, "mark!(fapico2_firmware::bootphase::RUNG_USB)")
    );
}

/// Nothing before `RUNG_USB` even *asks* for the region.
///
/// The runtime gate would make an early request harmless, but "harmless" is not
/// the property S8/S9 state: they say the boot path does not touch the region at
/// all, and a request that is merely ignored is still a request.
#[test]
fn no_boot_path_call_site_reaches_the_accessor_before_rung_usb() {
    let main = src(MAIN_RS);
    let usb = at(&main, "mark!(fapico2_firmware::bootphase::RUNG_USB");
    let before = &main[..usb];
    for needle in ["boot::key_region", "read_slot", "erase_sector", "FidoRecordStore", "OathRecordStore"] {
        assert!(
            !before.contains(needle),
            "`{needle}` appears at {} — before `RUNG_USB` ({}). S8/S9 forbid the boot path from \
             touching the key region at all; a call that is merely ignored by the runtime gate is \
             still a call, and one that is not ignored is a flash read on the boot path.",
            cite(MAIN_RS, before, needle),
            cite(MAIN_RS, &main, "mark!(fapico2_firmware::bootphase::RUNG_USB")
        );
    }
}

/// The one pre-`RUNG_USB` thing that *is* allowed: constructing the handle.
///
/// A `Flash` cannot be built without a `Peri`, and `p.FLASH` is consumed two
/// lines below the other two `Flash::new_blocking` calls, so the handle has to be
/// made there. What matters is that this is the **whole** of what happens: one
/// construction call, and no other region symbol in that neighbourhood.
#[test]
fn the_only_pre_usb_region_mention_is_the_handle_construction() {
    let main = src(MAIN_RS);
    let usb = at(&main, "mark!(fapico2_firmware::bootphase::RUNG_USB");
    let before = &main[..usb];
    let inits = all_lines(before, "boot::init_key_region(");
    assert_eq!(
        inits.len(),
        1,
        "expected exactly one `boot::init_key_region(` before `RUNG_USB` ({}), found {}",
        cite(MAIN_RS, before, "boot::init_key_region("),
        inits.len()
    );
    let names = all_lines(before, "KeyRegionHandle");
    assert_eq!(
        names.len(),
        1,
        "the pre-USB block must name `KeyRegionHandle` exactly once — the construction \
         expression itself. More mentions would mean the boot path is doing something with the \
         region beyond parking a handle: {}",
        names
            .iter()
            .map(|(n, _)| format!("{MAIN_RS}:{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

// ---------------------------------------------------------------------------
// boot.rs: the guard is a guard, not a comment
// ---------------------------------------------------------------------------

/// `key_region()` checks readiness **before** it takes the reference.
///
/// Without this the runtime half of S8/S9 is a claim about a comment: the flag
/// would be written and never read, and the accessor would hand out a
/// `&'static mut` to a possibly-uninitialized slot.
#[test]
fn the_accessor_refuses_before_the_release() {
    let boot = src(BOOT_RS);
    let guard = at(&boot, "KEY_REGION_READY.load");
    let take = at(&boot, "assume_init_mut()");
    assert!(
        guard < take,
        "the readiness load must precede the reference being minted: `boot.rs` writes the slot in \
         `init_key_region` and only sets the flag in `release_key_region`, so an accessor that \
         takes the reference first is an `&mut` to an uninitialized slot whenever anything asks \
         too early ({} vs {})",
        cite(BOOT_RS, &boot, "KEY_REGION_READY.load"),
        cite(BOOT_RS, &boot, "assume_init_mut()")
    );
    assert!(
        boot.contains("pub fn key_region() -> Option<&'static mut KeyRegionHandle>"),
        "`boot::key_region` must keep its `Option` return ({}). A panic or an assert here would \
         be a halt on the boot path (S10): an unreachable key store is an empty key set and a \
         clean CTAP error, not a brick.",
        cite(BOOT_RS, &boot, "pub fn key_region()")
    );
}

/// The release writes the flag and nothing else — it cannot fail, because a boot
/// path that reached `RUNG_USB` and then could not release the region would have
/// to choose between halting and serving a key store it cannot read (S10).
#[test]
fn the_release_cannot_fail() {
    let boot = src(BOOT_RS);
    let start = at(&boot, "pub fn release_key_region()");
    let body_start = at(&boot[start..], "{") + start;
    let end = at(&boot[body_start..], "\n}") + body_start;
    let body = &boot[body_start..end];
    assert!(
        body.contains("KEY_REGION_READY.store(true"),
        "`release_key_region` must set the flag ({})\n\n{body}",
        cite(BOOT_RS, &boot, "pub fn release_key_region()")
    );
    for forbidden in ["unwrap(", "expect(", "assert", "panic!", "fatal_boot"] {
        assert!(
            !body.contains(forbidden),
            "`release_key_region` contains `{forbidden}` ({}). It runs on the boot path after \
             `RUNG_USB`, where anything that can fail has to be a log line and a flag — a halt \
             there is a device that enumerates and then never answers a CTAP request.\n\n{body}",
            cite(BOOT_RS, &boot, "pub fn release_key_region()")
        );
    }
}

// ---------------------------------------------------------------------------
// The device region itself
// ---------------------------------------------------------------------------

/// `DeviceKeyRegion::new` reads nothing.
///
/// S8/S9 are enforced in two places — the accessor gate above and the
/// constructor's own emptiness — and this is the mechanical proof of the
/// second. The body is one field assignment; anything else would be a flash
/// access reachable from a constructor, and a constructor is exactly what a boot
/// path calls.
#[test]
fn the_device_region_constructor_reads_nothing() {
    let region = src(REGION_RS);
    let start = at(&region, "pub fn new(flash: DevFlash) -> Self {");
    let end = at(&region[start..], "\n        }") + start + "\n        }".len();
    let body = &region[start..end];
    assert_eq!(
        body.trim(),
        "pub fn new(flash: DevFlash) -> Self {\n            Self { flash }\n        }",
        "the constructor is no longer inert ({}):\n\n{body}\n\nS8/S9 say the boot path does not \
         touch the key region, and this is the call it would go through. Anything that reads, \
         scans or mounts here has to move to the first applet operation instead.",
        cite(REGION_RS, &region, "pub fn new(flash: DevFlash) -> Self {")
    );
}

/// Every `KeyRegion` method on the device is fallible, and none of them halts.
///
/// S10: "degrade, never halt". The device region is the one component whose
/// failure mode the boot path cannot absorb, so the checks are here rather than
/// in the applets that would have to catch them.
#[test]
fn the_device_region_never_halts() {
    let region = src(REGION_RS);
    let impl_start = at(&region, "impl KeyRegion for DeviceKeyRegion {");
    let body = &region[impl_start..];
    for forbidden in ["unwrap()", ".expect(", "panic!", "unreachable!"] {
        assert!(
            !body.contains(forbidden),
            "`impl KeyRegion for DeviceKeyRegion` contains `{forbidden}` ({}). The device profile \
             is `panic = \"abort\"`, so a panic in a region operation is an unreachable device with \
             no unwinding, no rollback and no CTAP error — the whole S10 contract is that this \
             returns `Err` instead.",
            cite(REGION_RS, &region, "impl KeyRegion for DeviceKeyRegion {")
        );
    }
    for method in ["fn read_slot(", "fn erase_sector(", "fn program(", "fn slots("] {
        assert!(
            body.contains(method),
            "`impl KeyRegion for DeviceKeyRegion` has no `{method}` arm ({}). One of the trait's \
             methods is missing, so this gate would be passing vacuously for it.",
            cite(REGION_RS, &region, "impl KeyRegion for DeviceKeyRegion {")
        );
    }
}