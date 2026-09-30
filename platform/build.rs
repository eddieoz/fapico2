//! Build script for `fapico2-platform` — the **board** and the **device
//! identity block**.
//!
//! Two jobs, in that order, because one feeds the other.
//!
//! # 1. Resolve the board (US-1080)
//!
//! `firmware/boards/<board>.toml` declares the pins, the flash size and the USB
//! identity. This script parses the selected one and publishes `PK_*` values
//! that `src/board.rs` compiles into constants, plus the board's identity
//! strings as the *defaults* `src/identity.rs` resolves against.
//!
//! | variable | what it selects | default |
//! |---|---|---|
//! | `FAPICO2_BOARD` | a file name under `firmware/boards/`, no extension | `pico2` |
//! | `FAPICO2_BOARD_PATH` | a path to a board file; **wins** over the above | unset |
//!
//! The parser is `platform/board_def.rs`, `include!`d rather than imported: a
//! build script cannot depend on the crate it builds, and putting the parser in
//! a module would pull `String` and the whole thing into the `no_std` device
//! image for a function the device never calls.
//!
//! # 2. Resolve the identity overrides
//!
//! The handful of values that decide *which product this firmware claims to be
//! on top of the board's*, published to the crate as `cargo:rustc-env` pairs
//! read back in `src/identity.rs` with `const fn` resolution. Same shape the
//! `fapico2-fido` build script established for the AAGUID (US-101).
//!
//! | variable | what it sets | default |
//! |---|---|---|
//! | `FAPICO2_AAGUID_HEX` | CTAP2.1 getInfo key `0x03`, 32 hex chars | see [`identity::DEFAULT_AAGUID`] |
//! | `FAPICO2_MANUFACTURER` | USB iManufacturer string | the board file's `usb.manufacturer` |
//! | `FAPICO2_PRODUCT` | USB iProduct string | the board file's `usb.product` |
//! | `FAPICO2_VID_PID` | USB VID:PID, `VVVV:PPPP` or `0xVVVV:0xPPPP` | the board file's `usb.vidpid` |
//!
//! ```text
//! FAPICO2_BOARD=pico2w FAPICO2_PRODUCT="Acme Token" cargo build -p fapico2-firmware
//! ```
//!
//! # Precedence, and why it is that way
//!
//! **board file → identity default → env override.** The board is the
//! *declaration* of what a physical thing is, so it is the floor that cannot be
//! forgotten. An env override is a *one-build experiment* — a name a developer
//! is testing before it goes in a file — so it sits on top and costs nothing
//! when unset. The AAGUID is not a board key: it is a product-level constant
//! with a documented derivation and a one-way history (see `identity.rs`), and
//! putting it in a per-board file would let a board quietly re-identify every
//! passkey already enrolled.
//!
//! # Every override is all-or-nothing
//!
//! A malformed or wrong-length value is a **hard build failure**, never a
//! silent fallback, for every variable in the table — and for every key in a
//! board file. These are identity constants: a typo that quietly fell back
//! would ship a product claiming a name and a USB id nobody asked for, and the
//! failure would surface to a *user* as "this device is mis-branded" rather
//! than to the build. The AAGUID half of that rule is US-101's and is kept
//! verbatim; the string and VID/PID halves extend it to the rest of the block.
//!
//! The validation lives here so the message can quote the offending value, and
//! the cfg emitted below turns it into a `compile_error!` in
//! `src/identity.rs` (so the failure names the constant, not just the build
//! script — rustc cannot attribute a const-eval panic back here).

// US-1080: the dependency-free board-file parser + `memory.x` renderer, shared
// with `firmware/build.rs` and `platform/tests/board_def.rs`. Not a module.
include!("board_def.rs");

/// The board file to resolve, by name under `firmware/boards/`.
const BOARD_ENV: &str = "FAPICO2_BOARD";
/// The board file to resolve, by explicit path. Wins over [`BOARD_ENV`].
const BOARD_PATH_ENV: &str = "FAPICO2_BOARD_PATH";
/// The board that ships. One board exists, so one file is checked in — EPIC
/// US-1080 is explicit that this is "not a board zoo" and that the point is
/// that the *second* board is a data change.
const DEFAULT_BOARD: &str = "pico2";
/// Where the checked-in board files live, relative to the **workspace** root.
/// This build script's `CARGO_MANIFEST_DIR` is `<root>/platform`, so the path is
/// joined from the manifest dir's parent rather than from the CWD, which cargo
/// does not guarantee to be the workspace root.
const BOARDS_DIR: &str = "firmware/boards";

/// The AAGUID override (documented on `identity::AAGUID`).
const AAGUID_ENV: &str = "FAPICO2_AAGUID_HEX";
/// The USB manufacturer string override.
const MANUFACTURER_ENV: &str = "FAPICO2_MANUFACTURER";
/// The USB product string override.
const PRODUCT_ENV: &str = "FAPICO2_PRODUCT";
/// The USB VID:PID override.
const VID_PID_ENV: &str = "FAPICO2_VID_PID";

/// The cfg `src/identity.rs` turns into a `compile_error!` when an override is
/// present but malformed. One cfg for the whole block rather than one per
/// variable: a build has at most one identity, and the error text already
/// names which variable failed, so a per-variable cfg would add surface and
/// buy no information.
const INVALID_CFG: &str = "fapico2_identity_invalid";

/// Env var carrying Cargo's `HOST` triple (see `main`). Read back in
/// `src/identity.rs` as `identity::HOST_BUILD_TARGET`.
const HOST_TARGET_ENV: &str = "FAPICO2_PLATFORM_HOST_TARGET";

/// An AAGUID is 16 bytes, i.e. 32 hex characters.
const AAGUID_HEX_LEN: usize = 32;

/// A USB string descriptor field, as the 32-byte ceiling the PHY TLV codec
/// imposes on `0x09`/`0x0F` (a UTF-8 name plus its NUL). Matching the
/// descriptor and the TLV to one bound means an identity cannot be accepted
/// on the USB path and then be un-writable through the config path.
const MAX_IDENTITY_STRING_LEN: usize = 32;

/// Returns `Ok(())` when `s` is exactly 32 ASCII hex characters.
///
/// ASCII-only on purpose: a multi-byte UTF-8 character would make a
/// `char_indices`-based parser mis-count byte offsets, and a non-hex byte
/// must be a build error rather than a skipped character.
fn validate_aaguid(s: &str) -> Result<(), String> {
    // The gate is on `s.len()`, i.e. BYTES, so the message reports bytes.
    // (Reporting `chars().count()` would mix units: for a multi-byte UTF-8
    // input the two numbers differ, and quoting the wrong one sends the
    // reader hunting for a length that is not what was checked.)
    if s.len() != AAGUID_HEX_LEN {
        return Err(format!(
            "expected {AAGUID_HEX_LEN} bytes (16-byte AAGUID as 32 hex characters, no \
             separators, no `0x` prefix), got {} byte(s): {s:?}",
            s.len(),
        ));
    }
    if let Some(bad) = s.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!(
            "contains the non-hex character {bad:?}; only 0-9 a-f A-F are accepted: {s:?}"
        ));
    }
    Ok(())
}

/// Returns `Ok(())` when `s` is usable as a USB identity string.
///
/// Three rules, each for a reason the descriptor layer will not catch:
///
/// 1. **ASCII.** A USB string descriptor is UTF-16 on the wire, and a device
///    that advertises non-ASCII here is at the mercy of whatever the host's
///    descriptor parser does with it. The build is the only place to catch it.
/// 2. **No interior NUL.** `0x0C` is a line separator; a string containing one
///    splits in half in every log line, tool, and JSON dump that renders the
///    device's name. A *trailing* NUL is fine and is how a name is stored in
///    the PHY TLV — that is a different question, asked at encode time.
/// 3. **Length.** Bounded by the same 32 bytes the PHY TLV codec imposes, so
///    one identity works on both the descriptor path and the config path.
fn validate_identity_string(var: &str, s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err(format!("{var} is empty; unset it to take the default, or give it a name"));
    }
    if let Some(bad) = s.chars().find(|c| !c.is_ascii()) {
        return Err(format!(
            "{var} contains the non-ASCII character {bad:?}; USB string descriptors are \
             UTF-16 and non-ASCII names do not survive every host's parser: {s:?}"
        ));
    }
    if s.contains('\0') {
        return Err(format!(
            "{var} contains an interior NUL, which splits the name in half in every log \
             line that renders it: {s:?}"
        ));
    }
    // +1 for the NUL the descriptor carries, matching the TLV's own ceiling.
    if s.len() + 1 > MAX_IDENTITY_STRING_LEN {
        return Err(format!(
            "{var} is {} bytes; the limit is {} including the trailing NUL that both the \
             USB descriptor and the PHY TLV tag carry: {s:?}",
            s.len() + 1,
            MAX_IDENTITY_STRING_LEN
        ));
    }
    Ok(())
}

/// Returns `Ok(())` when `s` is `VVVV:PPPP` or `0xVVVV:0xPPPP`, uppercase or
/// lowercase hex, no separators inside a half.
///
/// The `0x` prefix is accepted per-half, so both `FA20:0002` and
/// `0xfa20:0x0002` work — a person copying from `lsusb` writes the first, a
/// person copying from a C header writes the second, and neither should have
/// to remember which this build accepts.
fn validate_vid_pid(s: &str) -> Result<(), String> {
    let halves: Vec<&str> = s.split(':').collect();
    if halves.len() != 2 {
        return Err(format!(
            "expected VID:PID with exactly one colon, got {} part(s): {s:?}",
            halves.len()
        ));
    }
    for half in halves {
        let digits = half.strip_prefix("0x").or_else(|| half.strip_prefix("0X")).unwrap_or(half);
        if digits.len() != 4 {
            return Err(format!(
                "each half must be exactly 4 hex digits, got {digits:?} in {half:?}"
            ));
        }
        if let Some(bad) = digits.chars().find(|c| !c.is_ascii_hexdigit()) {
            return Err(format!("{half:?} contains the non-hex character {bad:?}"));
        }
    }
    Ok(())
}

/// The shared reporting tail: publish the (possibly bad) value verbatim so the
/// error text can quote it, and flip the cfg that makes the reason surface.
fn report(var: &str, raw: &str, reason: &str) {
    println!("cargo:rustc-cfg={INVALID_CFG}");
    println!("cargo:rustc-env={var}={raw}");
    println!("cargo:rustc-env={var}_ERROR={reason}");
}

/// Resolve the selected board file and publish its `PK_*` values.
///
/// Returns the resolved [`Board`] so `main` can feed its USB identity into the
/// override slots below. A board file that does not exist or does not parse is
/// a **hard build failure**: there is no such thing as a default board on an
/// error path, because "the build silently fell back to `pico2`" is precisely
/// the class of failure US-1080 exists to remove — a device built for a 2 MiB
/// part that got 4 MiB of partition, or a fork's LED pin that silently became
/// GPIO25.
fn resolve_board() -> Board {
    // **Both** variables are declared on **every** run, before either is read.
    // Cargo derives the re-run fingerprint from what the *previous* run
    // printed, so a `rerun-if-env-changed` emitted only inside the branch that
    // consumes it is a variable cargo does not yet know about — and the first
    // run that sets it is the one that gets missed. That failure is silent and
    // nasty: the build succeeds, the linker script comes from the old board,
    // and the identity in the image disagrees with the file. Declaring both up
    // front is the only arrangement where either variable is always tracked.
    for var in [BOARD_ENV, BOARD_PATH_ENV] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("Cargo always sets it");
    // `<root>/platform` -> `<root>`; the boards live in a *sibling* crate's
    // directory, which is deliberate — the firmware crate is the one that links
    // the generated memory.x, so the file sits with the thing it describes.
    let root = std::path::Path::new(&manifest_dir)
        .parent()
        .expect("the platform crate is not at the workspace root")
        .to_path_buf();
    let path = match std::env::var(BOARD_PATH_ENV) {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => {
            let name = std::env::var(BOARD_ENV).unwrap_or_else(|_| DEFAULT_BOARD.to_string());
            // Reject a name that is not a bare file name. `FAPICO2_BOARD`
            // selects *within* `firmware/boards/`; anything with a separator
            // is `FAPICO2_BOARD_PATH`'s job, and quietly honouring a
            // traversal here would let a build read a board file from
            // anywhere in the filesystem under a name that looks checked-in.
            if name.is_empty()
                || name.contains('/')
                || name.contains('\\')
                || name.contains("..")
            {
                panic!(
                    "{BOARD_ENV}={name:?} is not a bare board name. Select one of the files in \
                     {BOARDS_DIR}/, or point {BOARD_PATH_ENV} at a path."
                );
            }
            root.join(BOARDS_DIR).join(format!("{name}.toml"))
        }
    };
    let path = std::fs::canonicalize(&path).unwrap_or_else(|e| {
        panic!(
            "board file {} could not be read: {e}. The board that ships is {BOARDS_DIR}/{DEFAULT_BOARD}.toml; \
             set {BOARD_ENV} to a name in that directory, or {BOARD_PATH_ENV} to a path.",
            path.display()
        )
    });
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("board file {} could not be read: {e}", path.display()));
    let label = path.display().to_string();
    let board = parse(&label, &src).unwrap_or_else(|e| panic!("invalid board file: {e}"));

    println!("cargo:rerun-if-changed={}", path.display());
    println!("cargo:rustc-env=PK_BOARD_NAME={}", board.name);
    println!("cargo:rustc-env=PK_BOARD_FILE={label}");
    println!("cargo:rustc-env=PK_LED_PIN={}", board.led_pin);
    println!("cargo:rustc-env=PK_BUTTON_PIN={}", board.button_pin);
    println!("cargo:rustc-env=PK_FLASH_SIZE_KB={}", board.flash_size_kb);
    // US-1010: the QSPI XIP base, published for the same reason as the numbers
    // above. `firmware/src/boot.rs` carried `FLASH_ORIGIN` and `SECURE_ORIGIN`
    // as literals (`0x1000_0000` / `0x103F_0000`) beside a board-derived
    // `SECURE_PRIMARY_OFFSET`, with nothing linking them: correct for a 4 MiB
    // board, silently wrong for a smaller one. `memory.x` renders `FLASH
    // ORIGIN` from this same `board_def::FLASH_ORIGIN`, so publishing it keeps
    // the linker script, the store's keystore address and the manifest-hash
    // exclusion on one number instead of three that agree only by coincidence.
    // Published **decimal**, because `platform::board::FLASH_ORIGIN` reads it
    // through the same `u32_from_env` the other `PK_*` numbers use, and that
    // const fn rejects a non-digit rather than guessing at a radix.
    println!("cargo:rustc-env=PK_FLASH_ORIGIN={FLASH_ORIGIN}");
    // A per-board `cfg`, so a downstream crate can branch on the board without
    // parsing a name. `board_pico2` is the only one that exists.
    //
    // The board's *name* and the cfg *token* are not the same string: a cfg is
    // an identifier, so a board called `pico2-8m` becomes `board_pico2_8m`. The
    // mapping is documented on `platform::board::BOARD_CFG` and is a total
    // function of the name, so `BOARD_NAME` and the cfg can never disagree
    // about which board this is. (Getting this wrong is not a warning: rustc
    // rejects `--cfg board_pico2-8m` outright, which is a *fine* failure mode —
    // loud, at build time, on the board that caused it.)
    let cfg = format!("board_{}", board.name.replace(['-', '.'], "_"));
    assert!(
        cfg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "board name {:?} does not map to a usable cfg token {cfg:?}",
        board.name
    );
    println!("cargo:rustc-check-cfg=cfg({cfg})");
    println!("cargo:rustc-cfg={cfg}");
    board
}

/// Publishes `var` when unset (as the empty string) or well-formed, and
/// reports it as malformed otherwise.
///
/// Unset still publishes the empty string, so the read-back in
/// `src/identity.rs` is a plain `env!` on every path rather than a cfg fork.
/// The **board's** identity is published separately as `PK_BOARD_*` and is what
/// `identity.rs` uses as the default; that separation is what keeps
/// `identity::DEFAULT_BUILD` meaning what it says — "no *override* is in
/// effect" — for a build whose identity came from a board file rather than from
/// four literals in this crate's source.
fn publish(var: &str, validate: impl Fn(&str) -> Result<(), String>) {
    match std::env::var(var) {
        // Unset (the normal `cargo build` / `cargo test` path): publish
        // nothing usable and let `src/identity.rs` take the default. We still
        // publish the var — as the empty string — so the read-back there is
        // a plain `env!` on every path rather than a cfg fork.
        Err(_) => println!("cargo:rustc-env={var}="),
        Ok(raw) => match validate(&raw) {
            // NOTE on where a malformed override is reported: rustc has no
            // way to attribute a const-eval panic back to the build script, so
            // a bad value surfaces as an `error[E0080]: evaluation panicked`
            // pointing at the *use sites* in `src/identity.rs`, not at
            // anything in this file. Do not go hunting here when you see that
            // panic: the offending value and the reason are in the second
            // error, and the fix belongs to the environment variable.
            //
            // The cfg-gated `compile_error!` in `src/identity.rs` is what
            // guarantees the reason text reaches the compiler either way.
            Ok(()) => println!("cargo:rustc-env={var}={raw}"),
            Err(reason) => report(var, &raw, &reason),
        },
    }
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg({INVALID_CFG})");
    // Re-run when any override changes, or when the rules themselves change.
    for var in [AAGUID_ENV, MANUFACTURER_ENV, PRODUCT_ENV, VID_PID_ENV] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=board_def.rs");

    // Cargo sets `HOST` to the triple the build-script *executable* runs on
    // and `TARGET` to the triple the crate is being *compiled* for; the two
    // differ under cross-compilation. The end-to-end override test shells out
    // to a real `cargo build` and needs to name a host triple, so this must be
    // `HOST` — reading `TARGET` would hand a cross-compiling build (e.g.
    // `thumbv8m.main-none-eabi`) the wrong triple. Both vars are always set by
    // Cargo, so this is unconditional and the `env!` in `identity.rs` cannot
    // fail to resolve.
    println!(
        "cargo:rustc-env={}={}",
        HOST_TARGET_ENV,
        std::env::var("HOST").expect("Cargo always sets HOST for build scripts")
    );

    let board = resolve_board();

    // The board's USB identity — the *defaults* `src/identity.rs` resolves
    // against. Published separately from the `FAPICO2_*` override slots above
    // so that a default build (identity from a file, no override) is still
    // `identity::DEFAULT_BUILD`, and so that a build log shows both the board
    // and the deviation from it.
    println!("cargo:rustc-env=PK_BOARD_MANUFACTURER={}", board.manufacturer);
    println!("cargo:rustc-env=PK_BOARD_PRODUCT={}", board.product);
    println!(
        "cargo:rustc-env=PK_BOARD_VID_PID={:04X}:{:04X}",
        board.vid, board.pid
    );

    publish(AAGUID_ENV, validate_aaguid);
    publish(MANUFACTURER_ENV, |s| validate_identity_string(MANUFACTURER_ENV, s));
    publish(PRODUCT_ENV, |s| validate_identity_string(PRODUCT_ENV, s));
    publish(VID_PID_ENV, validate_vid_pid);
}
