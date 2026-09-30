//! US-101 (EPIC `PICOForge-COMPAT`): the AAGUID override is proven
//! **end to end**, through a real Cargo build.
//!
//! `tests/aaguid.rs` proves the parsing/selection logic in isolation. It
//! cannot, however, catch the regression that matters most: `build.rs`
//! publishing an empty value unconditionally, or ignoring `FAPICO2_AAGUID_HEX`
//! entirely. In that world every in-crate test still passes while the override
//! is dead in every real build — the constant silently stays RS-Key no matter
//! what the operator sets.
//!
//! This file closes that gap the honest way: it shells out to a real
//! `cargo build` with `FAPICO2_AAGUID_HEX` set and inspects the artifact that
//! build produces. It builds twice — once with the override, once without —
//! and asserts the AAGUID bytes in the compiled rlib *track the environment*.
//! One-sided "the override bytes are present" would not be enough, because a
//! crate that somehow always contained both would also pass; the two-sided
//! check is what makes it a real assertion.
//!
//! # Why this is not `#[ignore]`d
//!
//! A test whose entire reason for existing is catching a plumbing regression
//! guards nothing if it is excluded from the default path. It is cheap enough
//! to keep in: ~2 s warm, and the expensive part is a one-time cold build of
//! the probe target directory, which persists across runs. It writes to its
//! own `CARGO_TARGET_DIR`, so it cannot disturb the enclosing run's artifacts
//! or contend for its target lock.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The **published default** — fapico2's own AAGUID, the ASCII bytes of
/// `fapico2` plus a version word. What a build with no override must contain.
const FAPICO2_DEFAULT: [u8; 16] = [
    0x66, 0x61, 0x70, 0x69, 0x63, 0x6F, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02,
];

/// The borrowed RS-Key value, kept as the **override probe**: a development
/// build aimed at a PicoForge that has not yet added fapico2's AAGUID to its
/// profile table sets `FAPICO2_AAGUID_HEX` to exactly this. So the override
/// build below is a real configuration, not an arbitrary hex string.
const RSKEY: [u8; 16] = [
    0x24, 0x79, 0xC7, 0xBF, 0x6B, 0x30, 0x56, 0x83, 0x9E, 0xC8, 0x0E, 0x81, 0x71, 0xA9, 0x18,
    0xB7,
];

/// The hex spelling of [`RSKEY`], which is the documented development
/// override: 32 upper-case hex characters, no separators, no `0x` prefix.
const RSKEY_HEX: &str = "2479C7BF6B3056839EC80E8171A918B7";

/// A dedicated target directory, so the probe never invalidates the artifacts
/// the enclosing test run is using and never contends for its target lock.
fn probe_target_dir() -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps/fido must live inside the workspace")
        .to_path_buf();
    workspace.join("target").join("aaguid-build-probe")
}

/// Run a real `cargo build -p fapico2-fido` with (or without) the override set,
/// and return the bytes of the rlib it produced.
fn build_with_override(override_hex: Option<&str>) -> Vec<u8> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let target_dir = probe_target_dir();

    let mut cmd = Command::new(&cargo);
    cmd.args([
        "build",
        "--quiet",
        "-p",
        "fapico2-fido",
        // The workspace `.cargo/config.toml` pins the default target to
        // `thumbv8m.main-none-eabi`, where the crate's default `host` feature
        // cannot build. Target the host explicitly, using the triple build.rs
        // published for us.
        "--target",
        fapico2_fido::HOST_BUILD_TARGET,
    ])
    .env("CARGO_TARGET_DIR", &target_dir);
    // Never inherit an override from the ambient environment: the
    // no-override case must be genuinely unset.
    cmd.env_remove("FAPICO2_AAGUID_HEX");
    if let Some(hex) = override_hex {
        cmd.env("FAPICO2_AAGUID_HEX", hex);
    }

    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn `{cargo} build`: {e}"));
    assert!(
        out.status.success(),
        "cargo build (override={override_hex:?}) must succeed\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rlib = target_dir
        .join(fapico2_fido::HOST_BUILD_TARGET)
        .join("debug")
        .join("libfapico2_fido.rlib");
    std::fs::read(&rlib).unwrap_or_else(|e| {
        panic!(
            "expected the probe build to produce {}: {e}\n\
             (the rlib path differs if the cargo profile is not `dev`)",
            rlib.display()
        )
    })
}

/// How many times `needle` occurs in `haystack`.
fn count(haystack: &[u8], needle: &[u8; 16]) -> usize {
    haystack
        .windows(16)
        .filter(|w| **w == needle[..])
        .count()
}

#[test]
fn aaguid_build_tracks_the_fapico2_aaguid_hex_environment_variable() {
    // --- Build 1: no override. The RS-Key default must be compiled in and
    //     the override value must not be. ---
    let default_build = build_with_override(None);
    assert!(
        count(&default_build, &FAPICO2_DEFAULT) > 0,
        "a build with FAPICO2_AAGUID_HEX unset must compile fapico2's own default \
         (66 61 70 69 63 6F 32 00 ... 02 — ASCII \"fapico2\") into the artifact"
    );
    assert_eq!(
        count(&default_build, &RSKEY), 0,
        "a default build must NOT carry the borrowed RS-Key identity: two byte \
         sequences in one artifact would make the default unverifiable from the \
         outside, which is what the RS-Key probe is for"
    );
    // --- Build 2: override set. The override must be compiled in. This is
    //     the assertion that fails if build.rs stops honouring the env var:
    //     without it the bytes would be absent and RS-Key would be present
    //     instead. ---
    let override_build = build_with_override(Some(RSKEY_HEX));
    assert!(
        count(&override_build, &RSKEY) > 0,
        "a build with FAPICO2_AAGUID_HEX={RSKEY_HEX} must compile THAT value into \
         the artifact, not fapico2's own default — this is the exact build a \
         developer ships to stay classifiable on a client that has not yet \
         added our AAGUID to its profile table"
    );
    assert_eq!(
        count(&override_build, &FAPICO2_DEFAULT), 0,
        "an override build must not also carry the published default: the AAGUID \
         is an identity, and two identities in one artifact is one too many"
    );

    // --- The two artifacts must actually differ. Without this, a hypothetical
    //     crate carrying both byte sequences in the same places would satisfy
    //     the assertions above while the override did nothing. ---
    assert_ne!(
        default_build, override_build,
        "flipping FAPICO2_AAGUID_HEX must change the compiled artifact; the two \
         probe builds are byte-identical, so the override had no effect"
    );
}
