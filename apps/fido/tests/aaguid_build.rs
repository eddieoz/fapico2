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
//! # US-1517: the third build, the one that must not happen
//!
//! The drift this story found was not a broken `build.rs`. It was a script that
//! set `FAPICO2_AAGUID_HEX` on its own — git-ignored, so present in one
//! developer's checkout only — which made the same repository produce two
//! AAGUIDs while every assertion in this file stayed green, because an
//! override build *is* a supported configuration.
//!
//! Two tests here close that:
//!
//! * [`aaguid_override_without_an_explicit_acknowledgement_fails_the_build`]
//!   pins the second-variable requirement: an override on its own must not
//!   build at all.
//! * [`no_tracked_build_script_overrides_the_identity`] pins the other half —
//!   that no script in version control assigns an identity variable, so the
//!   override cannot be smuggled in through a checked-in `build.sh` either.
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
use std::process::{Command, Output};

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

/// US-1517: the acknowledgement an identity override now also requires.
const ACK_VAR: &str = "FAPICO2_IDENTITY_OVERRIDE_ACK";

/// Every identity variable, so a probe build can guarantee none of them — nor
/// the acknowledgement — leaked in from the ambient environment.
const IDENTITY_VARS: [&str; 5] = [
    "FAPICO2_AAGUID_HEX",
    "FAPICO2_MANUFACTURER",
    "FAPICO2_PRODUCT",
    "FAPICO2_VID_PID",
    ACK_VAR,
];

/// A dedicated target directory, so the probe never invalidates the artifacts
/// the enclosing test run is using and never contends for its target lock.
fn probe_target_dir() -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps/fido must live inside the workspace")
        .to_path_buf();
    workspace.join("target").join("aaguid-build-probe")
}

/// Run one probe `cargo build` and return its exit status and stderr. Does
/// **not** assert on success and does **not** read the rlib — the two callers
/// below want opposite things from the outcome (one builds an artifact, the
/// other requires the build to fail), and a helper that decided for them would
/// make the failing case unrepresentable.
///
/// `acknowledge` is a separate parameter from `override_hex` for the same
/// reason: the *absence* of the acknowledgement is precisely what US-1517 needs
/// tested, so it has to be a value this function accepts rather than something
/// it infers.
fn probe_build(override_hex: Option<&str>, acknowledge: bool) -> Output {
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
    // Never inherit an identity variable from the ambient environment: the
    // no-override case must be genuinely unset, and a developer's own
    // acknowledged override in their shell would otherwise decide the outcome
    // of every assertion below.
    for var in IDENTITY_VARS {
        cmd.env_remove(var);
    }
    if let Some(hex) = override_hex {
        cmd.env("FAPICO2_AAGUID_HEX", hex);
    }
    if acknowledge {
        cmd.env(ACK_VAR, "1");
    }

    cmd.output().unwrap_or_else(|e| panic!("failed to spawn `{cargo} build`: {e}"))
}

/// Run a probe build that is expected to succeed, and return the bytes of the
/// rlib it produced.
fn build_with_override(override_hex: Option<&str>) -> Vec<u8> {
    let out = probe_build(override_hex, override_hex.is_some());
    assert!(
        out.status.success(),
        "cargo build (override={override_hex:?}, acknowledged={}) must succeed\nstderr:\n{}",
        override_hex.is_some(),
        String::from_utf8_lossy(&out.stderr)
    );

    let rlib = probe_target_dir()
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

/// Drop every single- and double-quoted region from a shell line.
///
/// A shell assignment's *value* may be quoted (`FAPICO2_PRODUCT="Acme Token"`)
/// while the name is not, so this removes the quoted bytes and leaves the word
/// `FAPICO2_PRODUCT=` — still an assignment, still caught. A variable
/// mentioned only inside quotes is a read, not a write, and is exactly what
/// this removes.
fn strip_quoted(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            // Backslash escapes inside a double-quoted region only; a lone
            // backslash in single quotes is a literal backslash, and treating
            // it as an escape could run the region on past its real end.
            Some('"') if c == '\\' => continue,
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => quote = Some(c),
            None => out.push(c),
        }
    }
    out
}

/// US-1517: an identity override on its own must **fail the build**.
///
/// This is the test that would have caught the drift. `build-custom.sh` set
/// `FAPICO2_AAGUID_HEX=89FB94B7…` and nothing else, and because setting that
/// one variable has always been a *supported* configuration, every other
/// assertion in this file passed while the repository produced two AAGUIDs. A
/// rule that only says "an override is allowed" cannot catch that; the rule has
/// to say "an override is a decision, and an undecided one stops the build".
///
/// So the second variable is the mechanism, and this is the mechanism's test.
/// It is a test that **fails without** the build-script change: before it,
/// `probe_build(Some(RSKEY_HEX), false)` was an ordinary successful override
/// build.
#[test]
fn aaguid_override_without_an_explicit_acknowledgement_fails_the_build() {
    let out = probe_build(Some(RSKEY_HEX), false);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an identity override with no {ACK_VAR} must not build: the AAGUID is \
         the leading 16 bytes of every attested credential blob, so an override \
         that arrives by accident ships a device sharing no passkeys with \
         every other build from this checkout.\nstderr:\n{stderr}"
    );
    // The failure has to *name the remedy*, or it is just an obstacle. Assert
    // on the variable rather than on the message shape: a rewording of the
    // prose should not turn this red, but losing the variable's name should.
    assert!(
        stderr.contains(ACK_VAR),
        "the build failure must name {ACK_VAR} — an operator who cannot see \
         what to type next is stuck, and a stuck operator works around the \
         check instead of setting the variable.\nstderr:\n{stderr}"
    );

    // ...and the mirror: with the acknowledgement, the very same override
    // builds. Without this leg the test above would also pass if the build had
    // simply stopped accepting overrides altogether, which is the opposite of
    // what US-101 wanted and would break PicoForge development.
    let acked = probe_build(Some(RSKEY_HEX), true);
    assert!(
        acked.status.success(),
        "the same override WITH {ACK_VAR}=1 must still build — the escape hatch \
         is the point of the mechanism.\nstderr:\n{}",
        String::from_utf8_lossy(&acked.stderr)
    );
}

/// US-1517: no build script **in version control** may set an identity
/// variable.
///
/// The other half of "one source of truth", and the half that would have caught
/// `build-custom.sh` had it been tracked: the acknowledgement gate makes an
/// override deliberate, but a deliberate override inside `build.sh` is exactly
/// the drift again — it is just deliberate now, and the next person to read
/// `build.sh` has no way to know the shipped AAGUID moved.
///
/// So the claim is made about *files*: `build.sh` (the developer path),
/// `build-signed.sh` (the release path, and therefore the one that decides
/// what is published) and `build-timeline.sh` set no identity variable between
/// them, and the published defaults in `platform/src/identity.rs` are what
/// every image built from this repository serves.
///
/// `build-custom.sh` is git-ignored and so cannot be seen here — which is the
/// finding rather than a gap in the check: an identity that only one machine
/// can produce is not a configuration, it is a local habit, and it is the
/// reason this rule is expressed over tracked files at all.
///
/// Only the *code* of each script is read. A comment naming
/// `FAPICO2_AAGUID_HEX` is documentation, and this file's own docs discuss the
/// variable at length; requiring a blank line before every mention would make
/// the rule about prose instead of about builds.
#[test]
fn no_tracked_build_script_overrides_the_identity() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("apps/fido must live two levels below the workspace root");

    for script in ["build.sh", "build-signed.sh", "build-timeline.sh"] {
        let path = workspace.join(script);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));

        for (lineno, line) in text.lines().enumerate() {
            // Strip a trailing shell comment and every quoted region. The
            // quotes matter: `echo "AAGUID: ${FAPICO2_AAGUID_HEX}"` mentions
            // the variable but assigns nothing, and `build.sh` says exactly
            // that while it is building. Without this the check would report a
            // false positive on the very script it is protecting — and a rule
            // whose own home fails it gets disabled rather than obeyed.
            let code = strip_quoted(line);
            let code = code.split('#').next().unwrap_or("");
            for var in IDENTITY_VARS {
                // A shell *word* that is `VAR=…`, with an optional `export`
                // prefix. A bare mention — `$FAPICO2_PRODUCT`,
                // `${FAPICO2_PRODUCT}` — reads a variable rather than setting
                // one, and is deliberately not caught: a script may
                // legitimately forward an operator's acknowledged override
                // (and must, or the documented escape hatch would not work
                // through `./build.sh`).
                let assigned = code.split_whitespace().any(|word| {
                    word.strip_prefix("export")
                        .unwrap_or(word)
                        .strip_prefix(var)
                        .is_some_and(|rest| rest.starts_with('='))
                });
                assert!(
                    !assigned,
                    "{}:{} assigns {var}, so the image this script produces does \
                     not serve the published default identity. The single \
                     source of truth is DEFAULT_AAGUID / DEFAULT_MANUFACTURER / \
                     DEFAULT_PRODUCT / DEFAULT_VID:PID in \
                     platform/src/identity.rs; if this build genuinely needs a \
                     different one, it is a development experiment and belongs \
                     in the command line (with {ACK_VAR}=1), not in a script \
                     every release runs.",
                    path.display(),
                    lineno + 1,
                );
            }
        }
    }
}
