//! Build script: resolve the board and **generate `memory.x`** (US-1080).
//!
//! # What it does, in order
//!
//! 1. Resolves the selected `firmware/boards/<board>.toml` — the same file and
//!    the same parser `platform/build.rs` uses, so there is exactly one
//!    definition of "the board" and one definition of how to read it.
//! 2. Writes the linker script into `OUT_DIR` and puts `OUT_DIR` on the linker
//!    search path, so `cortex-m-rt`'s `link.x` finds it via its
//!    `INCLUDE memory.x`.
//!
//! That is the whole job. It publishes **no** `PK_*` values of its own, and
//! [`write_memory_x`] documents why that is deliberate rather than an
//! oversight.
//!
//! # Why `memory.x` is generated and not checked in
//!
//! It used to be a hand-written file with `LENGTH = 4032K` and
//! `SECURE ORIGIN = 0x103F0000` — the partition maths of one specific 4 MiB
//! part, written down rather than derived. A board with 8 MiB of flash would
//! have kept 4 MiB of partition and put its secure region at the same address,
//! and nothing would have said so. Now the two numbers are arithmetic on
//! `flash_size_kb`, and the file that carries them is a build artefact.
//!
//! The arithmetic is the *same* arithmetic, and that is the safety property:
//! for the shipping 4 MiB `pico2` board the generated script is partition-
//! identical to the hand-written one (`4032K` at `0x10000000`, `SECURE` at
//! `0x103F0000`), so a provisioned unit's two secure image slots — which live
//! at `0x103F0000` and survive a `.uf2` reflash, because the store is NOR flash
//! and not RAM — remain readable. `firmware/src/boot.rs` now computes
//! `SECURE_PRIMARY_OFFSET` from `fapico2_platform::board::SECURE_PARTITION_
//! OFFSET`, the same `Board` value this script rendered the script from, so the
//! linker and the store cannot disagree.
//!
//! # The E10 erratum, and what this script must not break
//!
//! Erratum RP2350-E10: the RP2350 will not boot a UF2-flashed Arm image unless
//! the file opens with picotool's "absolute block" — an ABSOLUTE-family
//! (0xe48bff57) block of 0xEF bytes carrying the `RP2_IGNORE_BLOCK` extension
//! flag, which `firmware/uf2gen.py` emits. Two consequences for a
//! board-parameterised build:
//!
//! * The absolute block's **address is a constant**, not a function of the
//!   flash size: picotool's `gen_abs_block()` default is `0x10FFFF00` on every
//!   part, and `RP2_IGNORE_BLOCK` is what makes the write a no-op "on any flash
//!   size". Deriving it from `flash_size_kb` would *break* compatibility with
//!   the C reference image, so `uf2gen.py` keeps it as written.
//! * The **payload** must still fit: the bootrom's 4 KiB erase-sector
//!   accounting walks consecutive 256-byte pages, and an image whose partition
//!   ran past the board's real flash would be silently truncated. That is now
//!   bounded from two sides at once — the generated `FLASH` `LENGTH` is
//!   `flash_size_kb - 64K`, and `check_size_report.py` measures the ELF.
//!
//! # The linker search path
//!
//! Only `OUT_DIR` is published. `cortex-m-rt` publishes its own `OUT_DIR` (for
//! `link.x`) and the two are searched in that order, so `link.x` resolves
//! first and the `INCLUDE memory.x` inside it resolves to the generated file.
//! Publishing `CARGO_MANIFEST_DIR` as well would re-introduce a second
//! candidate named `memory.x` and make the winner depend on search order — the
//! exact kind of "it worked on my build" failure US-1080 is removing.

// US-1080: the dependency-free board-file parser + `memory.x` renderer. The
// same file `platform/build.rs` includes; see its module docs for why it is
// `include!`d rather than imported. Relative to *this* file, i.e. one level up
// out of `firmware/` and into the platform crate that owns it.
include!("../platform/board_def.rs");

/// Generate this crate's `memory.x` from the resolved board.
///
/// # Why this publishes no `PK_*` values of its own
///
/// An earlier draft of this script published `PK_BOARD`, `PK_FLASH_SIZE_KB`,
/// `PK_SECURE_PARTITION_OFFSET` and four more, on the reasoning that "two
/// build scripts in two crates cannot share published env vars" and that the
/// firmware therefore has to resolve the board itself. Both halves of that
/// reasoning are false, and the conclusion was seven `cargo:rustc-env` lines
/// that **no source file in the tree reads** (`grep -rn 'env!("PK_'` finds
/// every one of them in `platform/src`, none here).
///
/// * They *can* be shared, and are: `firmware/src/boot.rs` takes its constants
///   from `fapico2_platform::board::SECURE_PARTITION_OFFSET`, an ordinary
///   cross-crate `const`. Cargo resolves that dependency in the crate graph
///   before anything compiles, so there is no build-order question — the
///   concern was about a mechanism the code does not use.
/// * Publishing them *here* would have been actively worse than not
///   publishing them. `flash_size_kb` would then be stated twice, by two build
///   scripts, with nothing holding the two statements together — a second
///   source for the one fact the story exists to make single. The linker script
///   is a **build artefact**, so the only honest way to keep them in step is to
///   generate both from the same `Board` value in the same function, which is
///   what happens below.
///
/// The real cross-check that the two crates agree is `platform/tests/
/// board_def.rs`, which re-derives the partition from the selected file and
/// compares it with the compiled constants.
fn write_memory_x(board: &Board, out_dir: &str) {
    let script = render_memory_x(board);
    let path = std::path::Path::new(out_dir).join("memory.x");
    std::fs::write(&path, &script)
        .unwrap_or_else(|e| panic!("could not write {}: {e}", path.display()));
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../platform/board_def.rs");
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("Cargo always sets OUT_DIR");
    // US-922: publish the cargo profile as a cfg so the crate can hard-refuse
    // the `dbg-log` diagnostic feature under `--release` (there is no stable
    // `cfg(release)`; `debug_assertions` can be force-enabled in release and
    // is not equivalent). The guard itself lives in `src/lib.rs`, and
    // `tests/scripts/check_dbg_release_gate.py` is what keeps it there.
    // Unrelated to the board work above; kept on the same script because this
    // is the crate's only build script.
    println!("cargo:rustc-check-cfg=cfg(release_profile)");
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        println!("cargo:rustc-cfg=release_profile");
    }
    // US-919: the foreign-image wipe is a BUILD PARAMETER, not a cargo
    // feature. `FAPICO2_FOREIGN_IMAGE_WIPE=1` compiles it in, `=0` compiles
    // it out, and unset falls back to the target's default:
    //
    //   device build   -> OFF. Flashing new firmware must not be a
    //                     credential-destroying event. This is an
    //                     open-source project whose users build and flash
    //                     their own images, so "I flashed a build with a
    //                     fix and lost every passkey" is the ORDINARY case,
    //                     not an edge case — and it is the one that ends
    //                     someone's use of the project. Both reference
    //                     products make the same call: RS-Key lays its KV
    //                     store out to survive a reflash by design
    //                     (`firmware/memory.x:22-27`,
    //                     `tests/01_flash_persistence.py:12`) and pico-fido2
    //                     has no image check at all, so neither destroys a
    //                     keystore when the operator updates.
    //                     The strict data-loss-over-implant posture is
    //                     still one variable away, for whoever wants it.
    //   emulation/host -> ON.  A host build is what the e2e suites that
    //                     PROVE the wipe arm (US-923, the D7 leg of
    //                     `redteam_hw_bdd.py`) run against. Defaulting it
    //                     off there would silently flip those tests to the
    //                     log-only path, where they keep passing while
    //                     proving nothing — the same failure shape as a gate
    //                     that measures the wrong artefact.
    //
    // The two axes are not in tension, and conflating them is how this
    // comment was wrong once already. Secure boot is a property of the
    // DEVICE: burning the RP2350's one-way `CRIT1.secure_boot_enable` fuse
    // makes the bootrom refuse a foreign image before any firmware runs,
    // which is the actual answer to an implant — and it is irreversible.
    // This parameter is a property of the BUILD: it decides what firmware
    // does when it finds an image it does not recognise. A deployment that
    // has burned the fuse wants this ON; an operator updating a personal
    // token every few weeks does not. The firmware wipe was previously ON
    // for everyone, which made the second group lose their keys on every
    // update, to defend the first group against an attack they can close
    // properly at the ROM.
    //
    // The default keys off the `device` FEATURE, not the cargo profile: a
    // debug-profile device build is still a device build, and keying off
    // `release` would hand it the host default — the same mistake US-922's
    // `release_profile` cfg exists to warn about, one feature over.
    //
    // Why an env var and not a feature: a cargo feature is additive, and
    // "off by default" would be an omission from `default` that nobody
    // reads. An env var is an explicit line in a build script, and
    // `tests/scripts/check_foreign_image_wipe.py` pins how it resolves.
    println!("cargo:rustc-check-cfg=cfg(FAPICO2_FOREIGN_IMAGE_WIPE)");
    println!("cargo:rerun-if-env-changed=FAPICO2_FOREIGN_IMAGE_WIPE");
    let is_device_build = std::env::var_os("CARGO_FEATURE_DEVICE").is_some();
    let wipe = match std::env::var("FAPICO2_FOREIGN_IMAGE_WIPE").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") => true,
        Ok("0") | Ok("false") | Ok("no") | Ok("") => false,
        Ok(other) => panic!(
            "FAPICO2_FOREIGN_IMAGE_WIPE={other:?} is not a yes/no value; use 1/0 \
             (true/false and yes/no are also accepted).\n\
             This variable decides whether a firmware-image mismatch DESTROYS \
             every credential on the device, so it is not read with a permissive \
             default: an unrecognised value stops the build rather than picking a \
             side on the operator's behalf."
        ),
        Err(std::env::VarError::NotPresent) => !is_device_build,
        Err(e) => panic!("reading FAPICO2_FOREIGN_IMAGE_WIPE failed: {e}"),
    };
    if wipe {
        println!("cargo:rustc-cfg=FAPICO2_FOREIGN_IMAGE_WIPE");
    }

    // The **boot-phase LED ladder** (`firmware/src/boot_led.rs` driving the
    // pure `fapico2_firmware::bootphase` core). ON by default, in every
    // profile, with no feature to remember: the failure it diagnoses — a
    // board that flashes cleanly and then never re-enumerates — has no other
    // read channel. No watchdog (one resets the board and destroys the
    // evidence), no retained-RAM flag, no ring (the CTAP-HID ring needs the
    // enumeration that failed), no `defmt` (a probe makes `OTP_DATA_RAW` read
    // `0xFFFFFFFF`, which `read_otp_key_1()` reads as "no key", so the probe
    // manufactures the very `fatal_boot` it would be there to localise). The
    // whole cost is `bootphase::full_ladder_us()` — under a second, once per
    // boot.
    //
    // An env var and not a feature, for the same reason
    // `FAPICO2_FOREIGN_IMAGE_WIPE` is one: features are additive, so "in
    // `default`" is a line in a manifest nobody reads at 2am with a dead
    // board in front of them, and a feature can only be switched off by not
    // passing it. Same yes/no parsing, and the same refusal to guess.
    println!("cargo:rustc-check-cfg=cfg(FAPICO2_BOOT_LED)");
    println!("cargo:rerun-if-env-changed=FAPICO2_BOOT_LED");
    let boot_led = match std::env::var("FAPICO2_BOOT_LED").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") => true,
        Ok("0") | Ok("false") | Ok("no") | Ok("") => false,
        Ok(other) => panic!(
            "FAPICO2_BOOT_LED={other:?} is not a yes/no value; use 1/0 \
             (true/false and yes/no are also accepted).\n\
             This variable decides whether a device that hangs during boot can \
             be diagnosed in the field by watching its LED, so it is not read \
             with a permissive default."
        ),
        Err(std::env::VarError::NotPresent) => true,
        Err(e) => panic!("reading FAPICO2_BOOT_LED failed: {e}"),
    };
    if boot_led {
        println!("cargo:rustc-cfg=FAPICO2_BOOT_LED");
    }

    // Selection rules are duplicated from `platform/build.rs` rather than
    // imported, for the same reason `include!` cannot reach into another
    // crate's `main`: neither build script can call the other. Both must
    // resolve `FAPICO2_BOARD` / `FAPICO2_BOARD_PATH` to the *same file*, or the
    // constants this crate compiles from and the linker script this crate
    // generates would describe two different boards — a partition that does
    // not match the store offsets, which is a corrupt keystore rather than a
    // build error. The two must agree on the *rule*, not merely on each
    // variable; `the_shipped_board_is_the_one_that_built_this` in
    // `platform/tests/board_def.rs` pins the shipped case (the file this
    // build read is `firmware/boards/<BOARD_NAME>.toml`), and the end-to-end
    // test there drives a real second board through both crates.
    for var in ["FAPICO2_BOARD", "FAPICO2_BOARD_PATH"] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("Cargo always sets it");
    let path = match std::env::var("FAPICO2_BOARD_PATH") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => {
            let name =
                std::env::var("FAPICO2_BOARD").unwrap_or_else(|_| "pico2".to_string());
            if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
                panic!(
                    "FAPICO2_BOARD={name:?} is not a bare board name; select one of the files in \
                     firmware/boards/, or point FAPICO2_BOARD_PATH at a path"
                );
            }
            // This manifest dir is `<root>/firmware`, so the boards directory is
            // a sibling rather than a child.
            std::path::Path::new(&manifest_dir)
                .join("boards")
                .join(format!("{name}.toml"))
        }
    };
    let path = std::fs::canonicalize(&path).unwrap_or_else(|e| {
        panic!(
            "board file {} could not be read: {e}. The board that ships is \
             firmware/boards/pico2.toml.",
            path.display()
        )
    });
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("board file {} could not be read: {e}", path.display()));
    let board = parse(&path.display().to_string(), &src).unwrap_or_else(|e| panic!("{e}"));
    println!("cargo:rerun-if-changed={}", path.display());

    write_memory_x(&board, &out_dir);

    // `link.x` (from `cortex-m-rt`) does `INCLUDE memory.x`; this is where the
    // generated script has to be found. Emitted **before** anything else so
    // the generated file is the only `memory.x` on the search path.
    println!("cargo:rustc-link-search={out_dir}");
}
