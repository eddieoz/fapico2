//! US-1537 / S13: **every applet key's storage location is asserted**.
//!
//! ```gherkin
//! Scenario: no applet key lands on a volatile filesystem
//!   Given each applet that generates or imports a key
//!   When its storage location is resolved
//!   Then it is Internal or External
//!   And External resolves to a flash-backed filesystem
//!   And a test fails if any applet's default becomes Volatile
//! ```
//!
//! # This is a gate, not a bug fix
//!
//! The keys survive today. That is the point of the story: it is the gate
//! that keeps them surviving when `apps/openpgp/src/device_shell.rs` is next
//! refactored, and it must cover opcard's `options.storage` **default**
//! because that default is the value that caused the hazard in the first
//! place. A test that only asserted "whatever `device_shell.rs` currently
//! sets" would be a mirror: drop the override and it would faithfully report
//! `External`, which is the defect.
//!
//! The scenario's two clauses land in two files, because they are two
//! different claims about two different pieces of code:
//!
//! | clause | where it is asserted | how |
//! |---|---|---|
//! | "it is Internal or External" | **this file** | the `Location` value |
//! | "External resolves to a flash-backed filesystem" | `platform/tests/fs_store_backing.rs` | the backing store |
//!
//! Splitting them is the substance of the story, not bookkeeping. The
//! original defect was `Location::External` *resolving to RAM* — an enum
//! value that reads persistently and is not. Either clause alone passes
//! straight over it: the enum alone never sees the backing store, and the
//! backing store alone never sees which location the applet asked for.
//!
//! # What this file asserts
//!
//! | test | today | what it catches |
//! |---|---|---|
//! | [`the_opcard_default_storage_is_never_volatile`] | pass | the default becoming `Volatile` |
//! | [`no_production_site_puts_card_state_on_the_volatile_filesystem`] | pass | any production `options.storage = …Volatile` |
//! | [`the_shipped_card_still_overrides_storage_to_internal`] | pass | the `device_shell.rs:123` override being dropped or changed |
//! | [`the_built_card_writes_its_state_to_the_internal_filesystem`] | pass | the override being dropped, observed rather than read |
//! | [`every_options_construction_site_is_accounted_for`] | pass | a **new** site appearing silently |
//! | [`the_only_excluded_file_is_this_one`] | pass | the enumeration's own exclusion list growing |
//! | [`the_generated_private_key_follows_the_card_location`] | **RED, `#[ignore]`d** | opcard `gen.rs` — reported, not fixed |
//!
//! # Why the last one is red
//!
//! `vendor/opcard/src/command/gen.rs:171` and `:217` hardcode
//! `set_persistence(Location::Volatile)` when **generating** the private
//! key, while `:183` and `:229` stamp `ctx.options.storage` on the derived
//! public key and on the keyref that `State::set_key` writes into the
//! persistent state file. The import path has the same shape
//! (`private_key_template.rs:269`, `:363`). The state file therefore holds a
//! **keyref to a key that was created in the volatile filesystem** — after a
//! reboot the ref dangles and the key is gone, with no error at any point:
//! the write succeeded, into something a power cycle takes away.
//!
//! That is a real latent bug and it is **not this story's to fix** — US-1537
//! adds tests only. It is parked the same way the `External`-is-RAM
//! assertion is parked in the platform file: `#[ignore]`d, runnable, and
//! failing today with the citations in the message. Whether opcard is
//! patched or the divergence is accepted is US-1537's report to make, not
//! its test's to decide silently.

use std::path::{Path, PathBuf};

use trussed_core::types::{Location, PathBuf as TrussedPathBuf};

use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::{
    dispatch::{Dispatcher, MAX_RESPONSE},
    trusted_backend::{
        dispatch::OpcardDispatch,
        host::{HostPlatform, HostStore},
        runner::with_backend,
    },
};

/// The only *production* site that sets `options.storage`. Asserted by name
/// in [`the_shipped_card_still_overrides_storage_to_internal`]; kept here so
/// the two tests cannot drift onto different files.
const DEVICE_SHELL: &str = "apps/openpgp/src/device_shell.rs";

/// opcard's state file, relative to whatever `Location` the card was built
/// with. `vendor/opcard/src/state.rs:813` names the leaf; the `opcard/dat/`
/// prefix is the client's own path root.
///
/// Read rather than hard-coded as a guess: if the prefix or the leaf moves,
/// the point of the test is still "the state file is in `ifs` and not in
/// `efs`/`vfs`", and this keeps that check from becoming a second thing to
/// update.
fn state_path() -> TrussedPathBuf {
    TrussedPathBuf::try_from("opcard/dat/persistent-state.cbor")
        .expect("the opcard state path is a valid trussed PathBuf")
}

// ---------------------------------------------------------------------------
// 1. The default
// ---------------------------------------------------------------------------

/// **Requirement S13, first clause**: an applet's default storage location
/// must never be `Location::Volatile`.
///
/// `opcard::Options::default()` sets `storage: Location::External`
/// (`vendor/opcard/src/card.rs:569`) — the field is declared at `:494` and
/// the `Default` impl at `:559`. `Location` is a three-variant enum
/// (`trussed-core-0.2.2/src/types.rs:326-331`: `Volatile | Internal |
/// External`), and `Volatile` maps to `vfs` (`trussed-0.2.0/src/store.rs:140`),
/// which on the RP2350 is a `RamFsStorage` **formatted on every boot**
/// (`platform/src/trusted_backend/device.rs`, `mount_ram_fs`). A default of
/// `Volatile` would mean every future `Options::default()` — every new applet,
/// every new test fixture, every new call site that forgets to override — put
/// its key in a filesystem whose entire purpose is to forget.
///
/// Asserted two ways on purpose. `!= Volatile` is the requirement; `==
/// External` pins *which* surviving value it is, so the day it changes to
/// `Internal` this test says so by name instead of reporting a green nobody
/// read.
#[test]
fn the_opcard_default_storage_is_never_volatile() {
    let default = opcard::Options::default().storage;

    assert_ne!(
        default,
        Location::Volatile,
        "opcard::Options::default().storage is Location::Volatile \
         (vendor/opcard/src/card.rs:569). A default of Volatile puts every applet key that \
         trusts the default into `vfs`, which is RAM formatted on every boot — the keys do \
         not survive a power cycle, and nothing reports an error at the time. S13 requires \
         Internal or External."
    );
    assert_eq!(
        default,
        Location::External,
        "opcard's default storage moved from Location::External to {default:?} \
         (vendor/opcard/src/card.rs:569). That is allowed by S13 only if the new value is \
         still backed by a non-volatile filesystem — re-check \
         `platform/tests/fs_store_backing.rs`, which is the half of this gate that looks at \
         the backing store rather than the enum."
    );
}

// ---------------------------------------------------------------------------
// 2. No production site opts *into* volatile
// ---------------------------------------------------------------------------

/// **Requirement S13, the "any applet's default becomes Volatile" clause**,
/// applied to explicit assignments rather than to the `Default` impl.
///
/// `apps/openpgp/src/device_shell.rs:123` is currently the *only* production
/// site in the tree that assigns `options.storage` (a scan of `apps/*/src`,
/// `firmware/src`, `platform/src`, `emu-harness/src` for `.rs` files finds
/// exactly one). It assigns `Location::Internal`. This asserts that stays
/// true, and that no second site appears pointing at `Volatile`.
///
/// Test trees are excluded, and deliberately so. A test that assigns
/// `options.storage` is not a hazard — it is this file, describing the rule
/// — and including them would make the gate fire on its own prose and train
/// whoever reads the next failure to add an exemption. Test sites are not
/// dropped, though: [`every_options_construction_site_is_accounted_for`]
/// enumerates production *and* tests together and fails on `Volatile` in
/// either.
///
/// Source-scanning rather than only checking the enum, because a *new*
/// production site has no runtime handle from a host test — the RP2350 build
/// is `no_std` and `arm`-only. This is the accepted convention here; see
/// `apps/fido/tests/status_table.rs::the_ctaphid_command_table_matches_the_reference`
/// and `platform/tests/no_signing_key.rs`, both of which read their own
/// tree.
#[test]
fn no_production_site_puts_card_state_on_the_volatile_filesystem() {
    let root = workspace_root();
    let mut sites = Vec::new();
    let mut scanned = 0usize;
    for file in production_rs_files(&root) {
        let src = std::fs::read_to_string(&file).unwrap_or_default();
        for (i, line) in src.lines().enumerate() {
            let line = strip_comment(line);
            // `.storage = <something>Volatile` — the only spelling a
            // production override can take. `Options` is `#[non_exhaustive]`
            // (`vendor/opcard/src/card.rs:479`), so `options.storage = …` is
            // the *only* way to set it from outside the crate; there is no
            // struct-literal form to miss.
            if line.contains(".storage =") {
                scanned += 1;
                if line.contains("Volatile") {
                    sites.push(format!("{}:{}: {}", rel(&root, &file), i + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        sites.is_empty(),
        "a production site assigns `options.storage` to Location::Volatile:\n  {}\n\
         Volatile is `vfs` — RAM, formatted on every boot. No applet key may be written there.",
        sites.join("\n  ")
    );
    // The scan is only a gate if it is looking at something. One assignment
    // is the expected count today (`device_shell.rs:123`); zero would mean
    // the walk or the matcher broke, and the assertion above would then be
    // reporting success because it found nothing.
    assert!(
        scanned >= 1,
        "no production `.storage =` assignment was found at all. The override this gate exists \
         to protect (`apps/openpgp/src/device_shell.rs:123`) should be one of them — if it is \
         gone, that is the failure this file exists for, not a green result."
    );
}

// ---------------------------------------------------------------------------
// 3. The override is still there
// ---------------------------------------------------------------------------

/// **The override must survive.** `apps/openpgp/src/device_shell.rs:123`
/// stamps `options.storage = Location::Internal` immediately after
/// `Options::default()`; the doc comment above it (`:106-108`) states why:
/// the card state lives in the trussed internal filesystem — the 1 MiB
/// QSPI-flash window on device, load-bearing for S-721-4 persistence — and
/// *not* the RAM volatile store.
///
/// Dropping the override would not fail any other test in this repository.
/// It would resolve to `Options::default().storage` = `External`, which *is*
/// non-volatile by the enum and *is* RAM by the backing store — so
/// [`the_opcard_default_storage_is_never_volatile`] would stay green and
/// the platform half would only complain once US-1538 lands. This test is
/// what makes the drop loud on the day it happens.
#[test]
fn the_shipped_card_still_overrides_storage_to_internal() {
    let src = std::fs::read_to_string(workspace_root().join(DEVICE_SHELL))
        .unwrap_or_else(|e| panic!("{DEVICE_SHELL} must be readable from this test's crate: {e}"));

    let line = src
        .lines()
        .find(|l| strip_comment(l).contains("options.storage"))
        .unwrap_or_else(|| {
            panic!(
                "{DEVICE_SHELL} no longer assigns `options.storage` at all. The build falls back \
                 to `opcard::Options::default().storage` (vendor/opcard/src/card.rs:569), which \
                 is Location::External — non-volatile by the enum, RAM by the backing store on \
                 the RP2350. Restore the override, or land US-1538 first."
            )
        });
    assert!(
        line.contains("Location::Internal"),
        "{DEVICE_SHELL}: the `options.storage` override is now `{line}`. It must be \
         Location::Internal: that is the trussed internal filesystem, the 1 MiB QSPI-flash \
         window on device (platform/src/trusted_backend/device.rs `IFS_STORAGE`, a \
         DevFlashStorage), which is what makes S-721-4 persistence work. Any other non-volatile \
         value is fine only if its backing store is flash — see \
         `platform/tests/fs_store_backing.rs`."
    );

    // The doc comment is part of the constraint, not decoration: it is what
    // the next person reads before changing the line, and it is the only
    // place the "1 MiB QSPI-flash window" claim is written down.
    assert!(
        src.contains("QSPI-flash window"),
        "{DEVICE_SHELL}: the `new()` doc comment must keep saying *why* the override is \
         Location::Internal (the QSPI-flash window). A comment that has rotted into 'set the \
         storage location' is how the next refactor drops it."
    );
}

// ---------------------------------------------------------------------------
// 4. …and the built card really lands there (observed, not read)
// ---------------------------------------------------------------------------

/// The same claim as [`the_shipped_card_still_overrides_storage_to_internal`],
/// **executed** rather than read.
///
/// `HostStore::fresh()` hands out three genuinely distinct filesystems. Boot
/// the real `OpenPgpApp` over them, drive one command that makes opcard
/// *write* its persistent state, and then ask **which of the three** the
/// state file landed in. `Internal` → `ifs`, `External` → `efs`, `Volatile` →
/// `vfs` (`trussed-0.2.0/src/store.rs:135-141`, executed for real by
/// `platform/tests/fs_store_backing.rs::a_location_resolves_to_the_filesystem_it_is_named_after`).
///
/// This is the half that cannot be fooled by a source edit: it does not read
/// `device_shell.rs` at all. It boots the app that ships, has it write, and
/// looks at the bytes.
///
/// **A write, not just a read.** A fresh card's `SELECT` + `GET DATA` load
/// the state but do not save it — opcard only writes on a change (see
/// `vendor/opcard/src/state.rs:1291`, where the save is gated on the
/// US-912 `pw*_changed` flags being absent, which they are not on a factory
/// card). Testing a read would then pass whether or not anything was ever
/// written, which is the failure this whole story is about. So the sequence
/// is the same one `tests/pw_status_resume.rs` uses to prove durability:
/// VERIFY PW3, then PUT DATA `0xC4` to relax PW-status, which takes the
/// `State::save` path at `vendor/opcard/src/command.rs:585`.
#[test]
fn the_built_card_writes_its_state_to_the_internal_filesystem() {
    let store = HostStore::fresh();
    let path = state_path();

    with_backend(
        HostPlatform::with_store(store),
        OpcardDispatch::new(),
        "opcard",
        |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            command(&mut dispatcher, 0xa4, 4, 0, OPENPGP_AID, 0x9000);
            // The factory PW3 (OpenPGP 3.4 §4.4.3.9) — the same value
            // `pw_status_resume.rs` verifies against.
            command(&mut dispatcher, 0x20, 0, 0x83, b"12345678", 0x9000);
            // PW-status payload: flag byte plus the three maximum-length
            // bytes the card requires unchanged.
            command(&mut dispatcher, 0xda, 0, 0xc4, &[0x01, 0x7f, 0x7f, 0x7f], 0x9000);
        },
    );

    assert!(
        store.ifs.exists(&path),
        "the card's state file is not in `ifs` (the internal filesystem). \
         `OpenPgpApp::new` sets options.storage = Location::Internal \
         (apps/openpgp/src/device_shell.rs:123) and Internal resolves to `ifs`."
    );
    assert!(
        !store.efs.exists(&path),
        "the card's state file is in `efs` — the EXTERNAL filesystem. On the RP2350 `efs` is a \
         RamFsStorage formatted on every boot, so the card's key state would not survive a \
         power cycle even though `Location::External` reads as persistent."
    );
    assert!(
        !store.vfs.exists(&path),
        "the card's state file is in `vfs` — the VOLATILE filesystem. This is the failure S13 \
         exists to prevent, observed on a live app rather than read from a source file."
    );
}

/// Minimal APDU round-trip: `[CLA, INS, P1, P2, Lc?, data, Le]`, asserted on
/// the trailing status word so a wrong answer cannot pass unnoticed.
fn command(
    dispatcher: &mut Dispatcher<'_, 1>,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    sw: u16,
) -> Vec<u8> {
    let mut apdu = vec![0, ins, p1, p2];
    if !data.is_empty() {
        apdu.push(u8::try_from(data.len()).unwrap());
        apdu.extend_from_slice(data);
    }
    apdu.push(0);
    let mut response = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(&apdu, &mut response);
    assert!(response.len() >= 2, "empty response to INS={ins:02x}");
    let body_len = response.len() - 2;
    assert_eq!(
        u16::from_be_bytes(response[body_len..].try_into().unwrap()),
        sw,
        "INS={ins:02x} P1={p1:02x} P2={p2:02x}"
    );
    response[..body_len].to_vec()
}

// ---------------------------------------------------------------------------
// 5. The enumeration: a new site cannot appear silently
// ---------------------------------------------------------------------------

/// Every `opcard::Options` construction site in the tree — production **and**
/// tests — enumerated, with the storage each one resolves to, and with
/// `file:line` in the failure message.
///
/// The point is the *inventory*, not the assertion. S13's failure mode is a
/// site nobody reviewed: a new applet, a new test fixture, a new helper that
/// builds `Options::default()` and forgets the override. Each such site is
/// individually harmless (it gets `External`, which is non-volatile by the
/// enum) and collectively they are how a key reaches `Volatile`. Pinning the
/// inventory means adding a site is a *deliberate* act — the test names it
/// and the author has to decide its location out loud.
///
/// Sites are classified by resolving the assignment that follows the
/// construction within the same statement block:
///
/// * `Inherited` — no `options.storage = …` after the `default()` call, so
///   the site resolves to [`the_opcard_default_storage_is_never_volatile`]'s
///   value.
/// * `Internal` / `External` / `Volatile` — set explicitly.
/// * `Unresolved` — a `default()` call with something written after it that
///   this scanner could not classify. Reported rather than guessed: a site
///   this test cannot read is a site this test cannot vouch for.
#[test]
fn every_options_construction_site_is_accounted_for() {
    let root = workspace_root();
    let excluded = excluded_paths();
    let mut inventory: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();

    for file in all_rs_files(&root) {
        let rel_path = rel(&root, &file);
        // This file quotes `opcard::Options::default()` in its own failure
        // messages, so a scanner that reads prose as code reports sites that
        // are not there. The exclusion is not a bare skip —
        // [`the_only_excluded_file_is_this_one`] is the gate on it, and
        // `excluded_paths()` is the single definition both read.
        if excluded.contains(&rel_path) {
            continue;
        }
        let src = std::fs::read_to_string(&file).unwrap_or_default();
        let inside_opcard = rel_path.starts_with("vendor/opcard/");
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let code = strip_comment(line);
            if !is_opcard_options_default(code, &src, inside_opcard) {
                continue;
            }
            let where_ = format!("{}:{}", rel(&root, &file), i + 1);
            // Resolve by reading forward over the next few *code* lines. The
            // override is always immediately after (`let mut options = …;
            // options.storage = …;`), so a short window is enough; a longer
            // one would start attributing one site's assignment to another.
            let window: Vec<&str> = lines[i..]
                .iter()
                .take(6)
                .map(|l| strip_comment(l))
                .collect();
            let assignment = window.iter().find(|l| l.contains(".storage ="));
            let resolved = match assignment {
                None => "Inherited",
                Some(a) if a.contains("Volatile") => "Volatile",
                Some(a) if a.contains("Internal") => "Internal",
                Some(a) if a.contains("External") => "External",
                Some(a) => {
                    unresolved.push(format!("{where_}: `{}`", a.trim()));
                    continue;
                }
            };
            inventory.push(format!("{where_}: {resolved}"));
        }
    }

    inventory.sort();
    unresolved.sort();

    assert!(
        unresolved.is_empty(),
        "these `opcard::Options` construction sites set `.storage` to something this gate cannot \
         classify. A site the gate cannot read is a site it cannot vouch for — spell the \
         location out:\n  {}",
        unresolved.join("\n  ")
    );
    assert!(
        !inventory.is_empty(),
        "the scan found no `Options::default()` site at all. Either the walk is broken (it \
         should find at least apps/openpgp/src/device_shell.rs) or opcard's API changed shape, \
         and a gate that has silently stopped looking is worse than no gate."
    );
    assert!(
        !inventory.iter().any(|s| s.ends_with(": Volatile")),
        "an `opcard::Options` construction site resolves to Location::Volatile:\n  {}\n\
         Volatile is `vfs` — RAM, formatted on every boot. S13 forbids it for every applet key, \
         production or test.",
        inventory.join("\n  ")
    );

    // The inventory itself, printed on success too. A gate whose output is
    // only visible when it fires is a gate nobody maintains: this is the
    // list a reviewer reads to confirm no site arrived unremarked.
    eprintln!("US-1537 opcard::Options construction sites:\n  {}", inventory.join("\n  "));
}

// ---------------------------------------------------------------------------
// 6. The private key (parked — reported, not fixed)
// ---------------------------------------------------------------------------

/// # A real latent bug, recorded rather than closed
///
/// `vendor/opcard/src/command/gen.rs` generates the private key with
/// `set_persistence(Location::Volatile)` at `:171` (RSA) and `:217` (EC),
/// while the derived **public** key at `:183`/`:229` and the keyref that
/// `State::set_key` writes into the persistent state file both use
/// `ctx.options.storage`. The import path has the same shape
/// (`private_key_template.rs:269`, `:363`).
///
/// So: a generated key lives in the RAM filesystem, and a reference to it
/// lives in the flash filesystem. After a reboot the reference dangles —
/// `GET PUBLIC KEY` returns nothing usable, `PSO:CDS` cannot find the key,
/// and the card reports it in the ordinary way a missing key is reported
/// rather than as a storage fault.
///
/// **This story does not fix it.** US-1537 is "assert every key's storage
/// location", and `vendor/opcard` is run deliberately unmodified apart from
/// two named review patches (US-912, US-914 — see the `device_shell.rs`
/// `new()` doc comment). Patching `gen.rs` is a different decision, with a
/// different blast radius, and it is not one this test gets to make silently.
///
/// The assertion is therefore `#[ignore]`d rather than deleted: it states
/// the policy S13 asks for, fails today, and is runnable
///
/// ```text
/// cargo test -p fapico2-openpgp --test key_storage_location -- --ignored
/// ```
///
/// so whoever takes the fix can see exactly what turns green.
#[test]
#[ignore = "RED: vendor/opcard/src/command/gen.rs generates the private key at \
            Location::Volatile while the public key and the persistent keyref use \
            ctx.options.storage. Not fixed by US-1537 — see the module docs."]
fn the_generated_private_key_follows_the_card_location() {
    let root = workspace_root();
    let gen = root.join("vendor/opcard/src/command/gen.rs");
    let src = std::fs::read_to_string(&gen).expect("vendor/opcard/src/command/gen.rs must exist");

    let offenders: Vec<String> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("set_persistence(Location::Volatile)"))
        .map(|(i, l)| format!("{}:{}: {}", rel(&root, &gen), i + 1, l.trim()))
        .collect();

    assert!(
        offenders.is_empty(),
        "opcard generates the card's PRIVATE key with `Location::Volatile` while the public key \
         and the persistent keyref both use `ctx.options.storage`:\n  {}\n\
         A key in `vfs` and a reference to it in the persistent state file means the reference \
         dangles on the next power cycle — the card loses its key with no error at write time. \
         The import path (`vendor/opcard/src/command/private_key_template.rs`) has the same \
         shape.",
        offenders.join("\n  ")
    );

    // Control: the *public* key and the keyref already follow the card's
    // location, so this test's demand is not "stop using Volatile anywhere in
    // opcard" — it is "make the private key agree with the public one". If
    // this assertion ever fails too, the scan above is reading the wrong
    // lines and the failure above would be meaningless.
    assert!(
        src.contains("set_persistence(ctx.options.storage)"),
        "gen.rs no longer stamps `ctx.options.storage` on the public key; the Volatile scan \
         above is not measuring what it claims to measure."
    );
}

// ---------------------------------------------------------------------------
// Source-walk helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("apps/openpgp is two levels below the workspace root")
        .to_path_buf()
}

/// Directories walked for the enumeration: everything that can name
/// `opcard::Options`, tests included.
///
/// `vendor/opcard/src` is here because opcard's own `#[cfg(test)] mod tests`
/// constructs `Options::default()` (`card.rs:669`) — a site S13 covers even
/// though it never ships. Every other `vendor/` tree is excluded: those are
/// third-party crates whose `Options` types are unrelated, and walking them
/// would put this gate at the mercy of a dependency's internals.
const WALK_ROOTS: &[&str] = &[
    "apps",
    "firmware",
    "platform",
    "emu-harness",
    "vendor/opcard/src",
];

/// As [`WALK_ROOTS`], but `src/` only — what "production" means for the
/// purpose of a key-storage rule.
///
/// Deliberately expressed as a suffix rule (`…/src`) rather than a
/// blocklist of test directories. A blocklist has to be updated when someone
/// adds a new kind of test directory, and the day it is missed the gate goes
/// blind without saying so; the suffix is a property of the layout itself.
const PRODUCTION_ROOTS: &[&str] = &["apps", "firmware", "platform", "emu-harness"];

/// Skip these: build output, VCS metadata, and third-party virtualenvs.
/// Mirrors `platform/tests/no_signing_key.rs::SKIP_DIRS` — a gate that
/// could be walked around by choosing a directory is not a gate, so the
/// list is short and named rather than pattern-matched.
const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    ".test-venv",
    "secrets",
    "3dprint",
];

fn all_rs_files(root: &Path) -> Vec<PathBuf> {
    collect(root, WALK_ROOTS, |_| true)
}

fn production_rs_files(root: &Path) -> Vec<PathBuf> {
    // The predicate is about the file's **parent** directory, which is where
    // `src` lives — a `…/src/foo.rs` keeps because its parent is named `src`,
    // and nothing else does.
    collect(root, PRODUCTION_ROOTS, |path| {
        path.parent().and_then(Path::file_name).is_some_and(|n| n == "src")
    })
}

fn collect(root: &Path, roots: &[&str], keep: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for r in roots {
        walk(&root.join(r), &mut out, &keep);
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, keep: &impl Fn(&Path) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(&path, out, keep);
        } else if keep(&path) && path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn rel(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .into_owned()
}

/// Strip a trailing `//` comment, so a match in a doc comment is never
/// mistaken for code.
///
/// Load-bearing here: `device_shell.rs:19` and `:106` both *mention*
/// `Options::storage = Location::Internal` in prose, and the enumeration
/// would otherwise report the prose as an assignment. Every match in the two
/// gates above is therefore a statement, not a comment about one.
fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Is this line a construction of **opcard's** `Options`?
///
/// `Options::default()` on its own is far too loose a needle in this tree:
/// `apps/fido/src/app.rs` builds `McOptions::default()` and
/// `GaOptions::default()` (`:3477`, `:3693`), which have nothing to do with a
/// trussed `Location`. Two conditions, both necessary:
///
/// * the type is **qualified** — `opcard::Options::default()`, or unqualified
///   `Options::default()` in a file that brings opcard's `Options` into scope
///   (by `use`, or by being opcard's own crate). A suffixed name like
///   `McOptions::default()` leaves `Mc` immediately before `Options` and is
///   rejected by the prefix test below.
/// * the line is not a **doc comment**, which `strip_comment` has already
///   removed. That is the whole of the literal problem: this file quotes the
///   expression in prose, every mention is inside `///` or inside a
///   `panic!` whose preceding line is a doc comment or a `//`, and a real
///   construction never appears inside a string.
///
/// `inside_opcard` is passed by the caller from the *path*, not guessed from
/// the file's text, so `vendor/opcard/src/card.rs`'s own `#[cfg(test)]`
/// construction (`:669`, reached through `use super::*`) is counted.
fn is_opcard_options_default(code: &str, whole_file: &str, inside_opcard: bool) -> bool {
    let at = match code.find("Options::default()") {
        Some(i) => i,
        None => return false,
    };
    let before = &code[..at];
    // The qualifier must end exactly here. `opcard::Options::…` satisfies it
    // directly; the bare form needs the preceding character to be one that
    // can end an expression, which `Mc` in `McOptions::default()` is not.
    let qualified = before.ends_with("opcard::")
        || before.is_empty()
        || before.ends_with(|c: char| c.is_whitespace() || "=(,{&".contains(c));
    if !qualified {
        return false;
    }
    // Explicitly qualified (`opcard::Options::default()`) is self-evidently
    // opcard's. The bare form is only opcard's if this file brought that
    // name into scope — otherwise it is some other crate's `Options`.
    before.ends_with("opcard::") || inside_opcard || imports_opcard_options(whole_file)
}

/// Does this file bring opcard's `Options` into scope by name?
///
/// Covers `use opcard::…;` and `use opcard::{Options, …};`. Scanned over
/// non-comment lines only, so a mention in a doc comment does not count.
fn imports_opcard_options(src: &str) -> bool {
    src.lines().any(|l| {
        let l = strip_comment(l).trim_start();
        l.starts_with("use opcard::")
    })
}

/// This file, repo-relative — the one path
/// [`every_options_construction_site_is_accounted_for`] skips.
const SELF_REL: &str = "apps/openpgp/tests/key_storage_location.rs";

/// # The gate on the skip
///
/// [`every_options_construction_site_is_accounted_for`] skips exactly one
/// path — this file — because it quotes `opcard::Options::default()` in its
/// failure messages. A skip is a hole, and a hole with a good comment
/// attached is still a hole, so the skip is checked here rather than
/// trusted.
///
/// Two things can go wrong and both are caught:
///
/// * the exclusion **grows** — someone adds a second skipped path (a vendor
///   patch, a generated file) and the inventory quietly stops covering it;
/// * the exclusion **stops matching** — this file is renamed or moved, the
///   skip misses, and the inventory starts reporting its own prose again.
///   That is the same class of defect as `platform/tests/no_signing_key.rs`
///   exempting itself by name and then needing
///   `signing_key_is_git_ignored` to prove the exemption still meant
///   something.
#[test]
fn the_only_excluded_file_is_this_one() {
    let root = workspace_root();

    // 1. The skip still points at a file that exists. If `SELF_REL` were
    //    stale, the skip would be dead code and this file's own mentions
    //    would reappear in the inventory.
    assert!(
        root.join(SELF_REL).is_file(),
        "{SELF_REL} does not exist, so the enumeration's exclusion of it is dead code — the \
         inventory would now report this file's own quoted expressions as construction sites."
    );

    // 2. The exclusion is a single named path, not a pattern. If it ever
    //    becomes a prefix or a glob, this is where it shows.
    assert_eq!(
        excluded_paths(),
        vec![SELF_REL.to_string()],
        "the enumeration skips more than itself. Every skipped path is a place an \
         `opcard::Options` site can hide from S13's inventory."
    );
}

/// The paths [`every_options_construction_site_is_accounted_for`] skips.
///
/// A function rather than an inline literal so the exclusion and the gate on
/// it cannot drift apart: there is exactly one definition, and this test
/// reads it.
fn excluded_paths() -> Vec<String> {
    vec![SELF_REL.to_string()]
}
