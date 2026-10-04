//! OATH (YkOath-compatible) and OTP (Yubikey slot) applications over CCID.
//!
//! Command semantics follow the Yubico YKOATH and YubiKey-slot protocols;
//! validated against `tests/pico-fido/test_070_oath.py` and `test_071_otp.py`.
//!
//! **Device split.** The OTP applet (`otp.rs`) is a single `no_std`
//! implementation that compiles for both the host and the device. The OATH
//! applet has two backends: the heapless core (`oath_core.rs`) — full INS
//! set plus `boot`/`persist_state` over the `oath.keystore.v1` migration
//! stream (S-711-1, US-353) — which the device **and** the emulation binary
//! both run (S-711-2, US-354), and the legacy `std` implementation
//! (`oath.rs`, `host` feature), retained for host-only dispatcher/registry
//! tests.

#![cfg_attr(not(feature = "host"), no_std)]

// US-1553: `OathApp` owns a boxed key-region handle for the length of its
// session, so the applet needs the allocator. It is **not** used before
// `platform::rsa_heap::init()` — the handle is constructed at first applet use,
// after `RUNG_USB` and therefore after boot — so the US-961 heap gate
// (`tests/scripts/check_heap_gate.py`) is unaffected. The alternative was a
// second key held in the applet's static, and `ckey.rs` already holds
// `OathSeal` there for the same reason.
extern crate alloc;

pub mod oath_core;
pub mod otp;

// US-131 (PICOForge-COMPAT): the shared constant-time comparison, promoted out
// of `otp.rs` so the OATH applet's access-code authentications use the same
// implementation as `VERIFY_PIN` instead of a `memcmp`.
pub(crate) mod ct;

#[cfg(feature = "host")]
pub mod oath;
#[cfg(feature = "host")]
pub use oath::OathApp;

#[cfg(all(feature = "device", target_arch = "arm"))]
pub use oath_core::{OathApp, OATH_AID};

// US-1030: the credential-key seal context. Re-exported because it is a
// **required** argument of `oath_core::OathApp::{new, boot, new_in_place,
// boot_in_place}` — a caller that cannot name the type cannot supply it,
// and an `Option` would put "the keys are not sealed" one keystroke away
// from a fully green build. It is `oath_core`'s own dependency's type; the
// re-export is a naming convenience, not a second definition.
pub use fapico2_platform::ckey::OathSeal;
// US-1030: the store slot the per-key monotonic seal generation lives in.
pub use oath_core::SLOT_OATH_SEAL_GENERATION;

pub use otp::OtpApp;
