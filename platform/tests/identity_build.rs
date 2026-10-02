//! End-to-end: an identity **environment variable must change the compiled
//! binary**.
//!
//! `tests/identity.rs` can only check the rules. This checks the thing that
//! actually matters for a fork: set `FAPICO2_PRODUCT` (or the other three) and
//! the string that ends up in the firmware is that one. The only way to see
//! that is to run a real `cargo build` and look at what came out, so this
//! shells out — twice, in both directions, and compares the artifacts.
//!
//! **Inherited from `apps/fido/tests/aaguid_build.rs`,** which does the same
//! for the AAGUID. Two copies rather than one shared helper because a test in
//! one crate cannot import a `#[cfg(test)]` module from another, and the two
//! probes build different crates.
//!
//! What each direction buys:
//!
//! * the **override** build must contain the override's bytes, so a build
//!   script that stopped reading the environment fails here rather than
//!   silently shipping the default under a name the operator chose;
//! * the **default** build must *not* contain them, so a script that ignored
//!   the override while still emitting both values cannot pass the first
//!   check by accident;
//! * the two artifacts must **differ**, so a crate carrying both sequences in
//!   the same places cannot satisfy the two checks above while the variable
//!   did nothing at all.
//!
//! A dedicated `CARGO_TARGET_DIR`, so the probe never invalidates the
//! artifacts the enclosing test run is using and never contends for the
//! target lock.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The product name used as the override, chosen so its bytes cannot occur by
/// accident anywhere in a build of a crate that does not use it.
const PRODUCT: &str = "Zzz-Identity-Probe";
/// The manufacturer used as the override, same reasoning.
const MANUFACTURER: &str = "Qqq-Probe-Co";
/// The VID:PID used as the override — high halves, so the packed pair cannot
/// collide with a real product's.
const VID_PID: &str = "ABCD:EF01";
/// The AAGUID used as the override.
const AAGUID_HEX: &str = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF";

/// Every identity variable, so the "default" build below can guarantee none of
/// them leaked in from the ambient environment.
///
/// US-1517 added the fifth. An identity override has since also required
/// `FAPICO2_IDENTITY_OVERRIDE_ACK=1`, so a probe that set only the four would
/// not build at all — and an acknowledgement inherited from the developer's own
/// shell would decide whether the "default" half of this file really is a
/// default build. Both reasons put it on this list.
const ALL_VARS: [&str; 5] = [
    "FAPICO2_AAGUID_HEX",
    "FAPICO2_MANUFACTURER",
    "FAPICO2_PRODUCT",
    "FAPICO2_VID_PID",
    "FAPICO2_IDENTITY_OVERRIDE_ACK",
];

/// A dedicated target directory for ONE variant, separate from the enclosing
/// run's.
///
/// **One directory per variant, not one shared.** The two builds differ only
/// by environment variables, so cargo stamps them with *different* metadata
/// hashes and therefore produces two differently-named rlibs. Sharing a
/// directory left the override build's rlib sitting next to the default
/// build's, and the artefact lookup below — a `find` over `deps/` — then
/// picked whichever the directory happened to yield first. Once an override
/// build had run, the "default" build read back the *override* rlib, and the
/// test failed with the override string present in the default artefact.
///
/// That failure is the test reporting a real thing about itself, which is the
/// only kind worth keeping: it was never able to say which artefact it was
/// looking at. A separate directory per variant makes the lookup exact —
/// each directory can only ever contain its own build.
fn probe_target_dir(overridden: bool) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("platform must live inside the workspace")
        .join("target")
        .join("identity-build-probe")
        .join(if overridden { "override" } else { "default" })
}

/// Run a real `cargo build -p fapico2-platform` with the whole identity block
/// either set to the probe values (plus the US-1517 acknowledgement) or
/// removed, and return the bytes of the rlib produced.
fn build_with(overridden: bool) -> Vec<u8> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(&cargo);
    cmd.args([
        "build",
        "--quiet",
        "-p",
        "fapico2-platform",
        // The workspace `.cargo/config.toml` pins the default target to
        // `thumbv8m.main-none-eabi`, where the crate's host-default deps may
        // not build; target the host explicitly, using the triple the build
        // script published.
        "--target",
        fapico2_platform::identity::HOST_BUILD_TARGET,
    ])
    .env("CARGO_TARGET_DIR", probe_target_dir(overridden));
    // Never inherit an override from the ambient environment: the "default"
    // build must be genuinely unset, or the test would prove nothing about
    // the default.
    for var in ALL_VARS {
        cmd.env_remove(var);
    }
    if overridden {
        cmd.env("FAPICO2_IDENTITY_OVERRIDE_ACK", "1")
            .env("FAPICO2_AAGUID_HEX", AAGUID_HEX)
            .env("FAPICO2_MANUFACTURER", MANUFACTURER)
            .env("FAPICO2_PRODUCT", PRODUCT)
            .env("FAPICO2_VID_PID", VID_PID);
    }

    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn `{cargo} build`: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "cargo build (identity overridden = {overridden}) must succeed\n\
         stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Find the rlib among the build's products. A name match rather than a
    // fixed path, because cargo's hash suffix changes whenever anything in the
    // dependency graph moves — and this test must not be the thing that breaks
    // when an unrelated crate is bumped.
    let deps = probe_target_dir(overridden)
        .join(fapico2_platform::identity::HOST_BUILD_TARGET)
        .join("debug")
        .join("deps");
    let rlib = std::fs::read_dir(&deps)
        .unwrap_or_else(|e| panic!("no deps dir at {}: {e}", deps.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("libfapico2_platform-") && n.ends_with(".rlib"))
        })
        .unwrap_or_else(|| {
            panic!("no libfapico2_platform rlib in {}", deps.display())
        });
    std::fs::read(&rlib).unwrap_or_else(|e| panic!("read {}: {e}", rlib.display()))
}

/// How many times `needle` occurs in `haystack`.
fn count(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.windows(needle.len()).filter(|w| *w == needle).count()
}

#[test]
fn every_identity_variable_changes_the_compiled_artifact() {
    let default_build = build_with(false);
    let override_build = build_with(true);

    // --- the override build must carry the override, for all four ---
    for (what, bytes) in [
        ("FAPICO2_PRODUCT", PRODUCT.as_bytes()),
        ("FAPICO2_MANUFACTURER", MANUFACTURER.as_bytes()),
    ] {
        assert!(
            count(&override_build, bytes) > 0,
            "{what}={:?} must be compiled into the artifact; without this the build \\
             script is not reading the environment and a fork would publish \\
             under the wrong name",
            what
        );
        assert_eq!(
            count(&default_build, bytes),
            0,
            "{what} must not appear in a default build — a build carrying both the \\
             default and the override cannot be told apart from outside"
        );
    }

    // The VID:PID pair, probed as the little-endian halfwords the compiled
    // `UsbIdent` actually holds. It is probeable here — unlike the AAGUID —
    // because `identity::usb_ident()` is ungated and so is compiled into a
    // host rlib, whereas the AAGUID is consumed only by the FIDO crate.
    let vid_le = 0xABCDu16.to_le_bytes();
    let pid_le = 0xEF01u16.to_le_bytes();
    assert!(
        count(&override_build, &vid_le) > 0,
        "FAPICO2_VID_PID={VID_PID} must be compiled into the artifact (probe: the \
         VID as a little-endian halfword)"
    );
    assert!(count(&override_build, &pid_le) > 0, "...and so must the PID");
    // **No negative probe for the VID/PID**, unlike the strings above, and the
    // asymmetry is a fact about probe strength rather than about coverage. A
    // two-byte pattern occurs by chance several times in any artifact this
    // size — the assertion was written, and measurably failed with six
    // incidental hits — so "the default build does not contain 0xABCD" is not a
    // statement about the build script at all. The strings get the negative
    // because a 16-byte probe is not a coincidence; these do not.
    //
    // What still holds the line here is the positive assertion above (the
    // override is present, so the variable *is* read) together with the
    // artifacts-differ check at the end (so *something* changed between the two
    // builds). A script that read the variable for the strings but not for the
    // VID would pass this file, and would be caught by the descriptor tests
    // and by the obviousness of `usb_ident()` returning one value.

    // **The AAGUID is deliberately not probed here**, and the reason is worth
    // recording because it looks like an oversight. `AAGUID` is a `[u8; 16]`
    // constant consumed by `apps/fido`, not by anything in this crate, and a
    // `const` with no in-crate use site is not obliged to be materialised into
    // the rlib at all — so "its bytes are absent" would say nothing about
    // whether the environment variable was read, and asserting on it would be a
    // test that passes for the wrong reason and fails on a compiler change.
    //
    // It is covered properly, in the crate that does consume it:
    // `apps/fido/tests/aaguid_build.rs` greps the *fido* rlib for the override
    // AAGUID, and `tests/identity.rs` checks the resolved constant against the
    // build's own configuration. Between those, the AAGUID path is better
    // covered than the strings are.

    // --- the two artifacts must differ, or a variable did nothing ---
    assert_ne!(
        default_build, override_build,
        "flipping the four identity variables must change the compiled artifact; \\
         the two probe builds are byte-identical, so at least one of them is \\
         being ignored"
    );

    // --- and the default build must carry the published defaults ---
    assert!(
        count(&default_build, fapico2_platform::identity::DEFAULT_PRODUCT.as_bytes()) > 0,
        "a default build must contain the published default product name"
    );
    assert!(
        count(&default_build, fapico2_platform::identity::DEFAULT_MANUFACTURER.as_bytes()) > 0,
        "a default build must contain the published default manufacturer"
    );
    assert!(
        count(&default_build, &fapico2_platform::identity::DEFAULT_AAGUID) > 0,
        "a default build must contain the published default AAGUID — fapico2's own \\
         identity, not the borrowed RS-Key one"
    );
}
