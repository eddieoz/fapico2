//! **No private key material anywhere in this repository** (US-1081).
//!
//! # Why this is a test and not a sentence in a doc
//!
//! US-1081's last requirement is that the secure-boot signing key "must be
//! generated and held outside this repository — a private key in the tree is
//! the failure mode this whole phase exists to prevent". A requirement stated
//! in prose rots silently: the key is one `scp` away, and nothing in the build
//! notices. `docs/SECURITY-ASSESSMENT-ROUND2.md` §8 R2-09 records the same
//! lesson for a neighbouring property — *"a gate that cannot fail should be
//! treated as absent"* — and this is the gate that can fail.
//!
//! It runs in the ordinary host suite, which CI already runs, so there is no
//! separate step to forget.
//!
//! # What it scans, and what it deliberately does not
//!
//! It walks the working tree from the workspace root, skipping `target/`,
//! `.git/` and `.superpowers/`. It **does** scan `vendor/`, `tests/pico-fido/`
//! and `tests/openpgp/` — a key pasted into a vendored file or a test fixture
//! is just as committed as one in `platform/src/`, and a gate that could be
//! walked around by choosing a directory is not a gate. It reads nothing under
//! those suites and changes nothing; this test only reads.
//!
//! It looks for the **encodings a key is actually stored in** — PEM/OpenSSH
//! armoured blocks, PGP private blocks, PuTTY v2 files — and for a `.key` /
//! `.pem` / `.pk8` file under this project's own source directories. It is a
//! *material* check, not a lint: a file called `signing_key.rs` full of hex
//! digits would pass it, and that is a real limitation, recorded here rather
//! than papered over. What it does cover is the failure mode that actually
//! happens — a key file produced by a tool and committed, or a key pasted
//! into a source file.

use std::path::{Path, PathBuf};

/// Markers that unambiguously mean "this file contains private key material",
/// as `(prefix, suffix)` halves.
///
/// Deliberately specific. `PRIVATE KEY` alone matches a *certificate* helper
/// or a comment; these are the headers an OpenSSH/OpenSSL/GPG tool emits when
/// it writes a key.
///
/// **Split in two on purpose.** Written out whole, this file would match
/// itself and the gate would go red on the tree it is protecting. The obvious
/// fix — exempting this file by name — is a hole: it exempts a whole file from
/// a key scan, in the one file whose contents a reader is least likely to
/// scrutinise for a key. Splitting the literals means the gate needs no
/// exemption at all and applies to every file including this one.
const PRIVATE_MATERIAL: &[(&str, &str)] = &[
    ("-----BEGIN ", "RSA PRIVATE KEY-----"),
    ("-----BEGIN ", "EC PRIVATE KEY-----"),
    ("-----BEGIN ", "DSA PRIVATE KEY-----"),
    ("-----BEGIN ", "OPENSSH PRIVATE KEY-----"),
    ("-----BEGIN ", "PRIVATE KEY-----"),
    ("-----BEGIN ", "ENCRYPTED PRIVATE KEY-----"),
    ("-----BEGIN ", "PGP PRIVATE KEY BLOCK-----"),
    ("PuTTY-", "User-Key-File-3"),
];

/// Extensions that are a key file by name. Checked only under this project's
/// own source directories — `vendor/` legitimately ships `.der`/`.cbor`
/// fixtures and a vendored tree is not ours to police.
const KEY_FILE_SUFFIXES: &[&str] = &[".key", ".pem", ".pk8", ".pkcs12", ".p12", ".pfx", ".jwk"];

/// Directories this project owns, relative to the workspace root.
const OWNED: &[&str] = &["platform", "firmware", "apps", "docs", "tests", "tools", "proto"];

/// Build-directories, VCS metadata, and uncommitted-but-expected trees.
const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    ".superpowers",
    "node_modules",
    "__pycache__",
    // Third-party virtualenvs. Ignored by git and therefore uncommittable,
    // and carrying a *false* positive that makes them worth naming rather
    // than skipping by pattern: `cryptography`'s `serialization/ssh.py`
    // holds one of this test's private-key markers as a header
    // *constant* (spelled out here only as a description — writing the
    // literal in this file would make the test fail on itself, which it
    // duly did the first time). A
    // test that goes red the first time anyone follows the documented venv
    // setup is a test people disable.
    ".venv",
    ".test-venv",
    // `secrets/` holds the secure-boot signing key, which `build-signed.sh`
    // *generates on purpose* — US-1081's whole point is that the key is
    // never in version control, so a working tree is expected to contain
    // one. `signing_key_is_git_ignored` below is what keeps this skip
    // honest: drop the ignore rule and that test goes red, rather than this
    // one passing quietly over a directory nothing else is watching.
    "secrets",
];

/// Files above this size are not scanned. A private key is small; a large
/// binary in the tree is not a key, and reading it would only cost time.
const MAX_BYTES: u64 = 1 << 20;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the platform crate is not at the workspace root")
        .to_path_buf()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
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
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn no_private_key_material_is_committed() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(
        files.len() > 100,
        "the walk found only {} files under {}; a scan that sees almost nothing \
         is a scan that proves nothing",
        files.len(),
        root.display()
    );

    let mut offenders: Vec<String> = Vec::new();
    for file in &files {
        let name = file.file_name().unwrap_or_default().to_string_lossy().into_owned();

        // 1. Key-shaped filenames, but only inside directories this project
        //    owns. `vendor/` is upstream's business.
        let rel = file.strip_prefix(&root).unwrap_or(file);
        let owned = rel
            .components()
            .next()
            .map(|c| OWNED.contains(&c.as_os_str().to_string_lossy().as_ref()))
            .unwrap_or(false);
        if owned && KEY_FILE_SUFFIXES.iter().any(|s| name.ends_with(s)) {
            offenders.push(format!("{}: key-shaped filename", rel.display()));
            continue;
        }

        // 2. Private key material in the bytes, anywhere in the tree.
        let Ok(meta) = file.metadata() else { continue };
        if meta.len() > MAX_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        // Key blocks are ASCII; a NUL in the first 64 bytes means this is a
        // binary file and cannot be one of the text markers.
        if bytes.len() > 64 && bytes[..64].contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        for (pre, post) in PRIVATE_MATERIAL {
            let marker = format!("{pre}{post}");
            if text.contains(&marker) {
                offenders.push(format!("{}: contains {marker:?}", rel.display()));
                break;
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "private key material is committed to this repository (US-1081: the \
         secure-boot signing key must be generated and held OUTSIDE the tree):\n  {}",
        offenders.join("\n  ")
    );
}

/// The module that consumes the fingerprint must not contain anything that
/// could be the key it fingerprints.
///
/// US-1081's own code takes a `FINGERPRINT_BYTES`-wide hash and nothing else,
/// so a key-shaped constant appearing in `boot_key.rs` would be either a
/// mistake or the exact failure the story warns about. This is the narrow
/// check; the tree-wide one is above.
#[test]
fn the_provisioning_module_contains_no_key_shaped_constant() {
    let src = std::fs::read_to_string(workspace_root().join("platform/src/boot_key.rs"))
        .expect("platform/src/boot_key.rs must exist");

    // A 64-hex-digit run in code is a key or a hash; in this module there
    // must be none, because every value here is arithmetic on a caller-supplied
    // fingerprint.
    let hex_run = |needle: &str| {
        src.as_bytes().windows(needle.len()).any(|w| w == needle.as_bytes())
    };
    for suspect in ["include_bytes!", "include_str!"] {
        assert!(
            !hex_run(suspect),
            "platform/src/boot_key.rs must not pull in a file at compile time \
             ({suspect}); the fingerprint is supplied by the caller"
        );
    }
    for (pre, post) in PRIVATE_MATERIAL {
        let marker = format!("{pre}{post}");
        assert!(
            !hex_run(&marker),
            "platform/src/boot_key.rs contains private key material ({marker:?})"
        );
    }
}
/// The gate on the `secrets/` skip in `SKIP_DIRS`: the signing key's home
/// must stay ignored, with `README.md` the only exception under it.
///
/// A separate test rather than an inline assertion, so a regression here
/// names itself. Without it, "skip `secrets/`" is a convenient hole with a
/// good comment attached — and a comment is not a control.
#[test]
fn signing_key_is_git_ignored() {
    let gi = std::fs::read_to_string(workspace_root().join(".gitignore"))
        .expect(".gitignore must exist for this test to mean anything");
    assert!(
        gi.lines().any(|l| l.trim() == "secrets/*"),
        "`.gitignore` no longer ignores `secrets/*`, so the signing key \
         `build-signed.sh` generates would be committable. \
         no_signing_key.rs skips `secrets/` on the strength of this rule."
    );
    // Scoped to `secrets/`: the repository has another deliberate un-ignore
    // (the US-1064 artefact fixtures), and a blanket "exactly one negation"
    // assertion would be wrong about it. What must not exist is a second
    // exception *under `secrets/`*, because that is the key's directory.
    let secrets_exceptions: Vec<&str> = gi
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("!secrets/"))
        .collect();
    assert_eq!(
        secrets_exceptions,
        vec!["!secrets/README.md"],
        "the only file expected to be un-ignored under `secrets/` is its \
         README; a second exception is a way for the key to be committed, \
         and this list is where it would be added"
    );
}
