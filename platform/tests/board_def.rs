//! US-1080: the board-definition tests. **This is the red the story asks for.**
//!
//! # The test that used to be here
//!
//! `platform/src/lib.rs` carried
//!
//! ```text
//! assert_eq!(LED_PIN, 25, "LED pin must track C PICO_DEFAULT_LED_PIN (GPIO25)");
//! ```
//!
//! next to `pub const LED_PIN: u8 = 25;`. It could not fail. The only thing
//! that could make it fail was editing the constant it was asserting, and
//! anyone who did that would edit the test in the same commit — at which point
//! it was a comment. Two literals, two tests, zero information.
//!
//! # What is here instead
//!
//! * [`selected_board_file_parity`] — the **live** check. It re-reads the exact
//!   file this build was configured from (`platform::board::BOARD_FILE`, an
//!   absolute path the build script published) and requires every compiled
//!   constant to equal what the file says. It fails when the board file
//!   changes without a rebuild, when the build script resolves a different file
//!   than the test reads, and when a value in the file is silently dropped.
//! * [`a_second_board_needs_no_rust_edit`] — the **story's red**. A second
//!   board definition, differing in `led_pin` and `flash_size_kb`, changes both
//!   the resolved pin and the generated `memory.x` partition, with no `.rs`
//!   source in the path.
//! * [`pico2_partition_is_unchanged_from_the_hand_written_memory_x`] — the
//!   safety property. The generated script for the board that ships must be
//!   partition-identical to the `memory.x` that used to be checked in, or every
//!   already-provisioned unit's keystore (two slots at `0x103F0000`, which a
//!   `.uf2` reflash does not clear) would become unreadable.
//! * [`the_parser_refuses_rather_than_defaulting`] — the no-silent-default
//!   property, one case per way a board file can be wrong.
//!
//! # Why the parser is `include!`d and not imported
//!
//! `platform/board_def.rs` is a non-`mod` file shared with the two build
//! scripts, which cannot depend on this crate. Including it here rather than
//! duplicating it is what makes the test check the *same* parser the build
//! used; a copy in the test would be free to drift and would then be testing
//! itself. Its module docs carry the design.

include!("../board_def.rs");

use std::path::Path;

/// A second board, as a **fixture inside this test** rather than a second file
/// in `firmware/boards/`.
///
/// EPIC US-1080 is explicit that this is not a board zoo: one board exists, so
/// one file ships, and "the point is that the *second* board is a data change".
/// Shipping a preset nobody flashes would be untested configuration — the
/// reason the EPIC rules it out. So the second board is text this test
/// supplies, and the proof is that the *pipeline* turns it into a different
/// pin and a different partition.
///
/// What a real second board is: a copy of `pico2.toml` with a different name,
/// pins and flash size, dropped into `firmware/boards/` and selected with
/// `FAPICO2_BOARD=<name>`. Nothing else. `FAPICO2_BOARD_PATH` does the same
/// for a file outside the repository.
const SECOND_BOARD: &str = r#"
[board]
name = "pico2-8m"
led_pin = 13
button_pin = 2
flash_size_kb = 8192

[usb]
vidpid = "0x1234:0x5678"
product = "fapico2-large"
manufacturer = "Example"
"#;

/// A board with the **minimum** flash the parser accepts, so its derived
/// secure origin lands somewhere the old hard-coded literal does not.
///
/// US-1010: this fixture is the point. `firmware/src/boot.rs` held
/// `SECURE_ORIGIN: usize = 0x103F_0000` as a literal beside a board-derived
/// `SECURE_PRIMARY_OFFSET`, and the two agreed only because the shipped part
/// happens to be 4 MiB. A 2 MiB board — which `MIN_FLASH_SIZE_KB` (2,048)
/// still accepts — puts its secure region at `0x101F0000`, and the manifest
/// hash would have stopped 1 MiB past the end of the region, hashing the
/// keystore it exists to protect. No test covered that, because a test that
/// compares a literal with a literal cannot fail.
const SMALLER_BOARD: &str = r#"
[board]
name = "pico2-2m"
led_pin = 25
button_pin = 1
flash_size_kb = 2048

[usb]
vidpid = "0x1234:0x5678"
product = "fapico2-small"
manufacturer = "Example"
"#;

/// The board file this build was compiled from, re-read.
///
/// `BOARD_FILE` is the absolute path `platform/build.rs` published, so this
/// cannot drift onto a different file than the one the constants came from —
/// which is the failure a name-based lookup would have.
fn selected() -> Board {
    let path = fapico2_platform::board::BOARD_FILE;
    let src = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("board file {path} could not be read: {e}"));
    parse(path, &src).unwrap_or_else(|e| panic!("selected board file does not parse: {e}"))
}

#[test]
fn selected_board_file_parity() {
    let b = selected();

    assert_eq!(
        fapico2_platform::board::BOARD_NAME,
        b.name,
        "PK_BOARD_NAME must be the selected file's [board] name"
    );
    assert_eq!(
        fapico2_platform::board::LED_PIN,
        b.led_pin,
        "LED_PIN must be the selected board file's led_pin"
    );
    assert_eq!(
        fapico2_platform::board::BUTTON_PIN,
        b.button_pin,
        "BUTTON_PIN must be the selected board file's button_pin"
    );
    assert_eq!(
        fapico2_platform::board::FLASH_SIZE_KB,
        b.flash_size_kb,
        "FLASH_SIZE_KB must be the selected board file's flash_size_kb"
    );
    assert_eq!(
        fapico2_platform::board::APP_FLASH_KB,
        b.app_flash_kb(),
        "the app region is total flash minus the 64 KiB secure reservation"
    );
    assert_eq!(
        fapico2_platform::board::SECURE_PARTITION_OFFSET,
        b.secure_offset(),
        "the secure region is anchored at the TOP of flash, not above the app region"
    );
    // US-1010: the XIP base the firmware measures every flash address from.
    // It is a silicon constant rather than a board key, so it is *the same*
    // for every board — but it is still published from `board_def.rs` rather
    // than written down in three places, and this is the check that it is.
    assert_eq!(
        fapico2_platform::board::FLASH_ORIGIN,
        FLASH_ORIGIN,
        "PK_FLASH_ORIGIN must be board_def.rs's FLASH_ORIGIN, the same value memory.x renders"
    );

    // The identity half: `identity`'s "default" is now the board's declaration.
    let id = fapico2_platform::identity::usb_ident();
    assert_eq!(id.product, b.product, "USB iProduct must come from the board file");
    assert_eq!(
        id.manufacturer, b.manufacturer,
        "USB iManufacturer must come from the board file"
    );
    assert_eq!(
        (id.vid, id.pid),
        (b.vid, b.pid),
        "USB VID:PID must come from the board file"
    );
    // A const assert, not a runtime one: the property is about what the build
    // resolved, so a `const` block turns a violation into a compile failure
    // rather than a test failure — which is the stronger statement, and the
    // one that survives a test binary nobody re-runs.
    const _: () = assert!(
        fapico2_platform::identity::DEFAULT_BUILD,
        "an unoverridden build is a DEFAULT build even though its identity came from a file"
    );
}

/// The story's red: a second board file, a different pin, a different
/// partition, and **no `.rs` source anywhere in the path**.
#[test]
fn a_second_board_needs_no_rust_edit() {
    let a = selected();
    let b = parse("<fixture:second board>", SECOND_BOARD).expect("the second board must parse");

    // The two boards really are different on the two axes the story names.
    assert_ne!(a.led_pin, b.led_pin, "the fixture must differ in led_pin");
    assert_ne!(a.flash_size_kb, b.flash_size_kb, "the fixture must differ in flash_size_kb");

    // 1. The pin follows the file.
    assert_eq!(b.led_pin, 13);
    assert_eq!(b.button_pin, 2);
    // …and the device-visible constant is a *pure function of the file*, so
    // the compiled `LED_PIN` for board B is 13 without anything being edited.
    // The function is `platform::board::u8_from_env`, the same const fn the
    // build script feeds; naming it here is what ties the two together.
    assert_eq!(fapico2_platform::board::u8_from_env("13"), b.led_pin);
    assert_ne!(fapico2_platform::board::u8_from_env("25"), b.led_pin);

    // 2. The partition follows the file.
    let mx_a = render_memory_x(&a);
    let mx_b = render_memory_x(&b);
    assert_ne!(mx_a, mx_b, "two boards must generate two different memory.x scripts");
    assert!(mx_b.contains("LENGTH = 8128K"), "8 MiB board: app region must be 8192-64");
    assert!(mx_b.contains("ORIGIN = 0x107f0000"), "8 MiB board: secure region at the top");
    assert!(mx_a.contains("LENGTH = 4032K"), "4 MiB board: app region must be 4096-64");
    assert!(mx_a.contains("ORIGIN = 0x103f0000"), "4 MiB board: secure region at the top");
    assert_eq!(b.secure_offset(), 8128 * 1024);
}

/// The generated script for the board that ships must be **partition-identical**
/// to the `memory.x` that used to be checked in.
///
/// This is the assertion that makes US-1080 safe rather than merely tidy. The
/// two hand-written lines were:
///
/// ```text
/// FLASH  : ORIGIN = 0x10000000, LENGTH = 4032K
/// SECURE (r) : ORIGIN = 0x103F0000, LENGTH = 64K
/// ```
///
/// A provisioned unit's two secure image slots live at `0x103F0000`, and a
/// `.uf2` reflash does **not** clear them — the store is NOR flash, not RAM, so
/// a reflash leaves an intact store behind. If the generated script moved that
/// region, every such unit would boot to an empty store, re-derive its hkey
/// and orphan every enrolled credential. There is no error: it looks exactly
/// like a factory-fresh device.
#[test]
fn pico2_partition_is_unchanged_from_the_hand_written_memory_x() {
    let b = selected();
    assert_eq!(b.flash_size_kb, 4096, "the shipped board is the 4 MiB Pico 2");
    assert_eq!(b.app_flash_kb(), 4032);
    assert_eq!(b.secure_origin(), 0x103F_0000);
    assert_eq!(b.flash_size_bytes(), 4 * 1024 * 1024);

    let mx = render_memory_x(&b);
    // Spacing is normalised so the assertion is about the *values*, not about
    // how the generator chose to lay the line out.
    let flat: String = mx.split_whitespace().collect::<Vec<_>>().join(" ");
    for expected in [
        "FLASH : ORIGIN = 0x10000000, LENGTH = 4032K",
        "SECURE (r) : ORIGIN = 0x103f0000, LENGTH = 64K",
        "RAM : ORIGIN = 0x20000000, LENGTH = 520K",
        "PROVIDE(_stext = ORIGIN(FLASH) + 0x200);",
    ] {
        assert!(flat.contains(expected), "generated memory.x lost {expected:?}:\n{mx}");
    }
    // The US-391 anchor must survive generation: the bootrom only scans the
    // first 4 KiB for the IMAGE_DEF, and the 256-byte UF2 blocks must not
    // straddle it.
    assert!(
        mx.contains("INSERT AFTER .vector_table;"),
        "the IMAGE_DEF placement workaround (US-391) must survive generation"
    );
}

/// Every way a board file can be wrong is a hard refusal, never a default.
///
/// The failure this exists to prevent: a misspelled key, a board that does not
/// exist, a flash size the shipping image does not fit in — each of which would
/// otherwise produce a *plausible* board that is not the board anyone meant.
#[test]
fn the_parser_refuses_rather_than_defaulting() {
    let cases: &[(&str, &str)] = &[
        (
            "unknown key",
            "[board]\nname = \"x\"\nled_pin = 1\nbutton_pin = 2\nflash_size_kb = 4096\nmcu = \"rp2350\"\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\nmanufacturer = \"m\"\n",
        ),
        (
            "unknown section",
            "[board]\nname = \"x\"\nled_pin = 1\nbutton_pin = 2\nflash_size_kb = 4096\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\nmanufacturer = \"m\"\n[power]\nvolts = 3.3\n",
        ),
        (
            "missing key",
            "[board]\nname = \"x\"\nled_pin = 1\nbutton_pin = 2\nflash_size_kb = 4096\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\n",
        ),
        (
            "duplicate key",
            "[board]\nname = \"x\"\nled_pin = 1\nled_pin = 2\nbutton_pin = 2\nflash_size_kb = 4096\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\nmanufacturer = \"m\"\n",
        ),
        (
            "pin above GPIO29",
            "[board]\nname = \"x\"\nled_pin = 30\nbutton_pin = 2\nflash_size_kb = 4096\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\nmanufacturer = \"m\"\n",
        ),
        (
            "flash below the floor",
            "[board]\nname = \"x\"\nled_pin = 1\nbutton_pin = 2\nflash_size_kb = 512\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\nmanufacturer = \"m\"\n",
        ),
        (
            "identity string too long for the descriptor",
            "[board]\nname = \"x\"\nled_pin = 1\nbutton_pin = 2\nflash_size_kb = 4096\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nmanufacturer = \"m\"\n",
        ),
        (
            "key before any section",
            "name = \"x\"\n[board]\nled_pin = 1\n",
        ),
        (
            "integer with a sign",
            "[board]\nname = \"x\"\nled_pin = 1\nbutton_pin = 2\nflash_size_kb = -4096\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\nmanufacturer = \"m\"\n",
        ),
        (
            "unquoted string",
            "[board]\nname = x\nled_pin = 1\nbutton_pin = 2\nflash_size_kb = 4096\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\nmanufacturer = \"m\"\n",
        ),
        (
            "vidpid without a colon",
            "[board]\nname = \"x\"\nled_pin = 1\nbutton_pin = 2\nflash_size_kb = 4096\n\
             [usb]\nvidpid = \"0001\"\nproduct = \"p\"\nmanufacturer = \"m\"\n",
        ),
        (
            "trailing junk after a value",
            "[board]\nname = \"x\"\nled_pin = 1 25\nbutton_pin = 2\nflash_size_kb = 4096\n\
             [usb]\nvidpid = \"0001:0002\"\nproduct = \"p\"\nmanufacturer = \"m\"\n",
        ),
    ];
    for (what, src) in cases {
        let got = parse("<refusal case>", src);
        assert!(got.is_err(), "the parser accepted a board file it must refuse: {what}");
    }
}

/// **The decisive end-to-end check**: the *compiled* pin is a function of the
/// board file, not a literal that happens to agree with it.
///
/// # Why this test had to exist
///
/// Every other test in this file has a hole, and it is worth being precise
/// about it. `selected_board_file_parity` compares `LED_PIN` against the file.
/// With the shipped `pico2` board — `led_pin = 25` — that comparison also
/// passes for `pub const LED_PIN: u8 = 25`, which is the *pre-US-1080 source*.
/// Restoring the old constant turns this file's other five tests green, because
/// none of them can tell "resolved from the file" from "written down, and the
/// file happens to say the same thing".
///
/// That is the same defect the story is about, one level up: a test that
/// cannot fail. So the only honest fix is to make the build resolve a board
/// whose `led_pin` is *not* 25 and observe the compiled value change. That
/// means a real second `cargo build` — which is affordable here precisely
/// because the dependency graph is already warm: the build script re-runs and
/// `fapico2-platform`'s lib recompiles in well under a second.
///
/// # What it does and does not prove
///
/// **Proves:** `platform::board::LED_PIN` / `FLASH_SIZE_KB` / `BOARD_NAME` and
/// `identity::usb_ident()` are computed from whichever board file the build
/// selected; the two selection variables both trigger a re-run; and a board
/// name with a `-` still yields a usable `cfg` token.
///
/// **Does not prove:** anything about the linker. `memory.x` is generated by
/// `firmware/build.rs` (the *other* build script, in the other crate) and is
/// not built here; its arithmetic is covered in-process by
/// [`a_second_board_needs_no_rust_edit`] and by
/// [`pico2_partition_is_unchanged_from_the_hand_written_memory_x`], and the
/// real two-board device build is recorded in the US-1080 report. This test
/// also leaves the tree built for whichever board ran last, so it restores the
/// shipped board before returning; a panic mid-test would leave it on the
/// fixture, which the next plain `cargo build` self-heals (both selection
/// variables are `rerun-if-env-changed`).
#[test]
fn the_compiled_pin_follows_the_board_file_end_to_end() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the platform crate is not at the workspace root")
        .to_path_buf();
    let dir = std::env::temp_dir().join("fapico2-board-def-probe");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let probe = dir.join("probe-board.toml");
    std::fs::write(&probe, SECOND_BOARD).expect("write the probe board");

    // Read what the build script **published**, by running the very binary
    // cargo ran and reading its stdout.
    //
    // Two other approaches were tried first and both are wrong here, for
    // reasons worth recording:
    //
    // * scanning `build/` for `fapico2-platform-*/output` and taking the newest
    //   — the workspace target dir holds one directory per (feature set,
    //   target, profile) unit, several stale, and this repository's target dir
    //   is on a bind mount whose `modified()` does not order the way `ls`
    //   shows it. The test read an output file from the day before.
    // * `cargo build -v` and reading that run's `output` file — `-v` names the
    //   build script's *compile* unit, while the `output` file belongs to a
    //   differently-hashed *run* unit that cargo does not print.
    //
    // `cargo build -v` does reliably name the executable, and the build
    // script's contract is that everything it publishes is on stdout, so
    // executing that executable with the same environment reproduces exactly
    // what cargo saw. No filesystem guessing, no JSON.
    //
    // The build is still driven through cargo first: that is what recompiles
    // the script when `board_def.rs` changes, and it is the step that proves
    // the selection variable *invalidated* the build (cargo re-runs the script
    // rather than reporting it `Fresh`).
    let published = |env: Option<&std::path::Path>| -> String {
        let mut cmd = std::process::Command::new("cargo");
        cmd.args(["build", "-v", "--lib", "-p", "fapico2-platform", "--target"])
            .arg(fapico2_platform::identity::HOST_BUILD_TARGET)
            .current_dir(&root);
        match env {
            // `FAPICO2_BOARD_PATH` is *removed* rather than set-empty for the
            // default build: the build scripts treat "unset" and "set" as two
            // different states (a set-but-empty board name is a hard error,
            // not a request for the default).
            None => {
                cmd.env_remove("FAPICO2_BOARD_PATH");
                cmd.env_remove("FAPICO2_BOARD");
            }
            Some(p) => {
                cmd.env("FAPICO2_BOARD_PATH", p);
            }
        }
        let out = cmd.output().expect("cargo must be runnable from a test");
        let log = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "cargo build failed for board {env:?}:\n{log}");
        let script = log
            .lines()
            .filter_map(|l| l.split("Running `").nth(1))
            .filter_map(|l| l.split('`').next())
            .find(|p| p.ends_with("build-script-build"))
            .unwrap_or_else(|| {
                panic!(
                    "cargo did not re-run the build script (no `Running` line). Both selection \
                     variables are `rerun-if-env-changed`, so a `Fresh` here means that \
                     declaration is gone — which is the bug this test exists to catch:\n{log}"
                )
            });

        // Re-run the script by hand and take its stdout, which is the same
        // `cargo:` directive stream cargo itself consumed.
        let mut run = std::process::Command::new(script);
        run.env("CARGO_MANIFEST_DIR", root.join("platform"))
            .env("HOST", fapico2_platform::identity::HOST_BUILD_TARGET)
            .env("TARGET", fapico2_platform::identity::HOST_BUILD_TARGET)
            .env("PROFILE", "debug")
            .env("OUT_DIR", std::env::temp_dir().join("fapico2-board-def-out"));
        std::fs::create_dir_all(std::env::temp_dir().join("fapico2-board-def-out"))
            .expect("OUT_DIR must exist");
        match env {
            None => {
                run.env_remove("FAPICO2_BOARD_PATH");
                run.env_remove("FAPICO2_BOARD");
            }
            Some(p) => {
                run.env("FAPICO2_BOARD_PATH", p);
            }
        }
        let r = run.output().expect("the build script must be executable");
        assert!(
            r.status.success(),
            "the build script refused board {env:?}:\n{}",
            String::from_utf8_lossy(&r.stderr)
        );
        String::from_utf8_lossy(&r.stdout).into_owned()
    };

    let second = published(Some(&probe));
    assert!(
        second.contains("cargo:rustc-env=PK_LED_PIN=13"),
        "a build for a board with led_pin=13 must publish PK_LED_PIN=13, not the shipped \
         board's 25. Build script said:\n{second}"
    );
    assert!(second.contains("cargo:rustc-env=PK_BUTTON_PIN=2"), "{second}");
    assert!(second.contains("cargo:rustc-env=PK_FLASH_SIZE_KB=8192"), "{second}");
    // US-1010: the XIP base has to be *published*, not re-derived by each
    // consumer. `firmware/src/boot.rs` reads it; a consumer that fell back to
    // a literal would still build, and the wrong manifest exclusion would be
    // invisible until a non-4-MiB board was flashed.
    assert!(
        second.contains(&format!("cargo:rustc-env=PK_FLASH_ORIGIN={FLASH_ORIGIN}")),
        "the XIP base must be published for firmware/src/boot.rs to derive SECURE_ORIGIN from: \
         {second}"
    );
    assert!(second.contains("cargo:rustc-env=PK_BOARD_NAME=pico2-8m"), "{second}");
    assert!(
        second.contains("cargo:rustc-cfg=board_pico2_8m"),
        "a `-` in a board name must become `_` in the cfg token, or rustc rejects the build: \
         {second}"
    );
    assert!(second.contains("cargo:rustc-env=PK_BOARD_PRODUCT=fapico2-large"), "{second}");
    assert!(second.contains("cargo:rustc-env=PK_BOARD_VID_PID=1234:5678"), "{second}");

    // **This is the half that cannot be faked.** Everything above checks what
    // the build script *published*; a `pub const LED_PIN: u8 = 25;` sitting in
    // `platform/src/board.rs` would publish all of it correctly and still
    // compile GPIO25. So the parity test is re-run **as a test binary built
    // for the fixture board**: with `BOARD_FILE` pointing at the fixture, it
    // compares the compiled `LED_PIN` against `led_pin = 13` and fails if the
    // constant is anything else.
    //
    // `--exact` on one test name keeps the recursion bounded — the
    // end-to-end test is filtered out of its own nested run.
    let parity = |env: Option<&std::path::Path>| -> bool {
        let mut cmd = std::process::Command::new("cargo");
        cmd.args([
            "test",
            "-p",
            "fapico2-platform",
            "--test",
            "board_def",
            "--target",
            fapico2_platform::identity::HOST_BUILD_TARGET,
            "--",
            "--exact",
            "selected_board_file_parity",
        ])
        .current_dir(&root);
        match env {
            None => {
                cmd.env_remove("FAPICO2_BOARD_PATH");
                cmd.env_remove("FAPICO2_BOARD");
            }
            Some(p) => {
                cmd.env("FAPICO2_BOARD_PATH", p);
            }
        }
        let out = cmd.output().expect("cargo must be runnable from a test");
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "the nested parity run failed for board {env:?}:\n{log}");
        assert!(
            log.contains("1 passed"),
            "the nested run must execute exactly the one filtered test:\n{log}"
        );
        true
    };
    assert!(
        parity(Some(&probe)),
        "selected_board_file_parity, compiled against the fixture board, must pass"
    );

    // Back to the shipped board, and prove the switch is reversible — which is
    // also what leaves the tree in a sane state.
    let first = published(None);
    assert!(
        first.contains("cargo:rustc-env=PK_LED_PIN=25"),
        "unsetting the selection must go back to firmware/boards/pico2.toml. Build script said:\n{first}"
    );
    assert!(first.contains("cargo:rustc-env=PK_BOARD_NAME=pico2"), "{first}");
    assert!(first.contains("cargo:rustc-env=PK_BOARD_PRODUCT=fapico2"), "{first}");
    assert!(first.contains("cargo:rustc-cfg=board_pico2"), "{first}");
    assert!(parity(None), "selected_board_file_parity must pass again on the shipped board");

    let _ = std::fs::remove_file(&probe);
}

/// US-1010: the secure region's **absolute** origin is arithmetic on the XIP
/// base and the board's offset — not a literal.
///
/// `firmware/src/boot.rs` derived `SECURE_PRIMARY_OFFSET` from the board (US-1080)
/// and then computed `SECURE_ORIGIN` for the manifest-hash exclusion from a
/// hard-coded `0x103F_0000` two lines away. Both were right for the 4 MiB part
/// and only the first stayed right for any other.
///
/// This test states the property the code has to have: change the board's flash
/// size and the region moves. It fails for a `pub const SECURE_ORIGIN: usize =
/// 0x103F_0000` — which is the pre-fix source — because that value is not a
/// function of anything.
#[test]
fn the_absolute_secure_origin_is_arithmetic_not_a_literal() {
    let big = selected();
    let small = parse("<fixture:2m board>", SMALLER_BOARD)
        .expect("a 2 MiB board is the parser's documented floor and must parse");

    // The derivation the firmware now performs, written out here so the test
    // states the rule rather than restating a constant.
    let derive = |b: &Board| FLASH_ORIGIN + b.secure_offset();

    assert_eq!(
        derive(&big),
        big.secure_origin(),
        "the absolute secure origin must be the XIP base plus the board's offset"
    );
    assert_eq!(
        derive(&small),
        small.secure_origin(),
        "…and that must hold for a board with different flash, not just the shipped one"
    );

    // The two boards really do land in different places.
    assert_ne!(derive(&big), derive(&small), "a smaller board must move the secure region");
    assert_eq!(derive(&big), 0x103F_0000, "4 MiB: the address provisioned units already use");
    assert_eq!(derive(&small), 0x101F_0000, "2 MiB: 1 MiB lower, where the old literal was not");

    // …and the published constants, which is what `boot.rs` actually reads.
    assert_eq!(
        fapico2_platform::board::FLASH_ORIGIN + small.app_flash_kb() * 1024,
        derive(&small),
        "FLASH_ORIGIN + SECURE_PARTITION_OFFSET must reproduce the region for any board"
    );
    assert_eq!(
        derive(&small) + SECURE_RESERVE_KB * 1024,
        FLASH_ORIGIN + small.flash_size_bytes(),
        "the region must be top-anchored: it ends at the top of flash"
    );
}

/// The shipped file parses, and the shipped file is where the build says it is.
#[test]
fn the_shipped_board_is_the_one_that_built_this() {
    let path = fapico2_platform::board::BOARD_FILE;
    assert!(
        Path::new(path).is_absolute(),
        "PK_BOARD_FILE must be absolute, got {path:?}; a relative path would make the parity \
         test depend on the test's working directory"
    );
    let name = Path::new(path).file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    assert_eq!(
        name,
        fapico2_platform::board::BOARD_NAME,
        "the file this build read must be the file the board is named after"
    );
    // Tests run with the *package* directory as CWD, not the workspace root,
    // so the tree is located from `CARGO_MANIFEST_DIR` (`<root>/platform`)
    // rather than from a relative path that would depend on how the test was
    // invoked.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the platform crate is not at the workspace root")
        .to_path_buf();
    let boards_dir = root.join("firmware").join("boards");
    let canonical = std::fs::canonicalize(boards_dir.join("pico2.toml"))
        .expect("the default board file must exist in the tree");
    let default_boards: Vec<String> = std::fs::read_dir(&boards_dir)
        .expect("firmware/boards must exist")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".toml"))
        .collect();
    // A default build resolves the shipped board; a `FAPICO2_BOARD` build
    // legitimately does not, so the assertion is conditional on the name.
    if fapico2_platform::board::BOARD_NAME == "pico2" {
        assert_eq!(
            std::fs::canonicalize(path).unwrap(),
            canonical,
            "a build named `pico2` must have read firmware/boards/pico2.toml"
        );
    }
    // Not a board zoo. One board exists; the second is a data change, and a
    // test is the only place a second definition belongs until one is flashed.
    assert!(
        default_boards.len() == 1,
        "EPIC US-1080 ships exactly one board file; found {default_boards:?}. A preset nobody \
         flashes is untested configuration — add it when the board exists."
    );
}

/// The two copies of `MAX_IDENTITY_STRING` — the board parser's and the
/// platform's — must agree.
///
/// The parser is compiled without the `platform` crate, so it cannot import
/// the constant and restates it. That restatement is exactly the kind of
/// duplication that rots: a raised ceiling on the descriptor side would leave
/// the board side refusing names the firmware could carry, or the reverse.
#[test]
fn the_identity_string_ceilings_agree() {
    assert_eq!(
        MAX_IDENTITY_STRING,
        fapico2_platform::identity::MAX_IDENTITY_STRING,
        "board_def.rs and identity.rs must bound USB identity strings identically"
    );
}
