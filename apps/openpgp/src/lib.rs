//! fapico2 OpenPGP 3.4 app (US-331+).
//!
//! Wraps the vendored `opcard` implementation (OpenPGP card spec v3.4) over
//! the `fapico2_platform` AID dispatcher. One generic app,
//! [`OpenPgpApp`] (S-721-2), runs the real card logic on both:
//!
//! * the **device** build (`device` feature): the S-721-1 no_std trussed
//!   platform client (`fapico2_platform::trusted_backend::device` — TRNG
//!   entropy, QSPI-flash littlefs2, LED UI; the client is taken by value
//!   with `trusted_backend::device::take_client()` and owned by the app);
//! * the **host** builds (`device` feature, non-arm targets): the same
//!   `SyscallRunner` client on the host backend
//!   (`trusted_backend::host::with_host_backend`).
//!
//! The `virt` feature additionally re-exports `with_ram_client` — the
//! trussed-virt (RAM) client seam the pre-S-721-2 tests use.
//!
//! `vendor/opcard` runs unmodified apart from the review patches
//! (US-912 factory-default gate; US-914 post-authorization presence
//! seam — see `docs/tasks/opcard-integration-notes.md`).
#![cfg_attr(not(any(feature = "std", feature = "virt")), no_std)]

/// Run `f` with a trussed-virt client backed by RAM storage (the
/// pre-S-721-2 seam; the real card logic now runs over the S-721-1
/// `SyscallRunner` client — see [`OpenPgpApp`]). The returned client (and
/// any app built from it) must not escape the closure.
#[cfg(feature = "virt")]
pub fn with_ram_client<R>(
    client_id: &str,
    f: impl FnOnce(opcard::virt::VirtClient<'_>) -> R,
) -> R {
    opcard::virt::with_ram_client(client_id, f)
}

// The OpenPGP app over a trussed client (S-721-2): device + host builds
// share this one generic implementation (see device_shell.rs).
#[cfg(feature = "device")]
pub mod device_shell;
#[cfg(feature = "device")]
pub use device_shell::{
    OpenPgpApp, OPENPGP_AID, PRESENCE_TAG_INT_AUTH, PRESENCE_TAG_PSO_DECIPHER,
    PRESENCE_TAG_PSO_SIGN,
};
