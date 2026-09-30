//! US-1007 — the **emulation-only entropy-starvation injection seam**.
//!
//! # The problem this exists to solve
//!
//! The epic's US-1007 asks for a device whose TRNG autocorrelation test is
//! forced to fail, and then wants four things observed on that *one live
//! device*: a clean error from a request that needs randomness, the device
//! still enumerable over **both** transports, and a successful request after
//! the peripheral recovers. On a host that sequence is **inexpressible**
//! without a seam, because the host entropy source reads `/dev/urandom` —
//! which is correct, and *unkillable*.
//!
//! The naive seam (an env var read at process start) cannot express the
//! second half either: "starve, then recover" is a transition of a **running**
//! process, and a process-start variable has exactly one value for its whole
//! life.
//!
//! # The mechanism: a control file the entropy path polls
//!
//! The path of the control file is read **once**, at first use, from
//! `FAPICO2_ENTROPY_STARVE_FILE`. The file's **existence** is the live
//! state:
//!
//! * absent → entropy is healthy;
//! * present → entropy is starved, and *every* draw refuses;
//! * removed → entropy recovers, with no restart.
//!
//! Chosen over the alternative (a new command on the CCID or HID socket)
//! deliberately. A socket command would put a vendor opcode into a
//! *protocol-visible* surface — the transports the shipping device answers —
//! and "it must not exist in a production build" is then a claim about a
//! dispatcher table rather than about a `cfg`. A file polled by the entropy
//! path is reachable from outside the process while it runs, needs no
//! protocol change, and its reachability is entirely a `cfg` question.
//!
//! # Why it cannot be reached in a shipping build
//!
//! Two independent conditions, both required:
//!
//! * `feature = "emulation"` — the platform crate's `emulation` feature, the
//!   one `fapico2-firmware`'s `emulation` feature turns on, and which the
//!   device build (`--features device`, target `thumbv8m.main-none-eabi`)
//!   does not;
//! * `not(target_arch = "arm")` — belt and braces, and the same guard every
//!   other host-only seam in this crate already carries (`HostTrng`,
//!   `trusted_backend::host`, `usb_ident`'s host arms).
//!
//! `tests/scripts/check_rng_path.py` enforces both, and enforces them as
//! *two different checks*: a name-forgiveness check (no code outside the
//! declared allowlist may name the accessor) and a structural check (the
//! `mod` declaration must sit under exactly that `cfg` attribute). The second
//! is the one that matters — moving the `mod` line out from under the `cfg`
//! is the only edit that could put this in a device build, and it goes red.
//!
//! # What it does and does not reach — stated, not implied
//!
//! The seam sits at the **peripheral** layer, which is the layer that can
//! wedge on silicon. It reaches:
//!
//! * `HostTrng::random_bytes` — every host draw in the tree funnels here, so
//!   the FIDO `TrngRng`, the trussed `HostRng`, and the emulation's own
//!   boot-time draws (`emul_main.rs`'s boot-entropy record and
//!   `OathApp::boot`) are all covered;
//! * `HostRng::try_fill_bytes` — the *fallible* half, which is the one
//!   trussed actually calls, and the only way a request can learn that
//!   entropy is gone instead of silently getting an untouched buffer.
//!
//! It does **not** reach the DRBG. The emulation builds no generator
//! (`firmware/src/boot.rs::init_drbg` is device-only, and `emul_main.rs`
//! never calls it), so there is no instantiate or reseed draw here to starve.
//! That layer is covered on the host by `platform/tests/drbg_trng.rs` and
//! `platform/tests/trng_wedge.rs`, and its request-path consequence by
//! `apps/openpgp/tests/rng_stall.rs`. US-1007's twin does not duplicate any
//! of them; it drives the live process.
//!
//! # Fail direction
//!
//! `starved()` returns `false` for anything it cannot read — an unset env
//! var, a missing file, a path it cannot stat. That is deliberate: a test
//! hook that could wedge a device when it *malfunctions* would be a denial
//! of service, which is the whole reason this module is `cfg`-gated rather
//! than merely discouraged. The hook can only ever be *inert* by default.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The environment variable naming the control file. Read once, at first
/// use — the *path* is fixed for the life of the process (it is
/// configuration), while the file's existence is the live switch.
pub const STARVE_FILE_ENV: &str = "FAPICO2_ENTROPY_STARVE_FILE";

/// The resolved control-file path, or `None` when the seam is not configured
/// at all. `None` is the default and costs one `OnceLock` read per draw and
/// **no syscall at all**.
static CONTROL_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

fn control_path() -> Option<&'static Path> {
    CONTROL_PATH
        .get_or_init(|| match std::env::var(STARVE_FILE_ENV) {
            Ok(p) if !p.is_empty() => Some(PathBuf::from(p)),
            _ => None,
        })
        .as_deref()
}

/// Whether entropy is currently being forced to starve.
///
/// `true` only when the seam is configured **and** the control file exists.
/// Every other case — unconfigured, absent, unstattable — is `false`.
pub fn starved() -> bool {
    match control_path() {
        Some(p) => p.exists(),
        None => false,
    }
}
