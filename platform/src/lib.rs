//! Platform crate: USB/CCID/HID transport, emulation, and AID dispatcher.
//!
//! EPIC `RUST-MIGRATION` — Phase 0 foundation.
//!
//! * Device path: `usb.rs` wraps `embassy-usb` composite CCID+HID.
//! * Emulation path: `emulation.rs` wraps TCP sockets mirroring C `emulation.c`.
//! * Dispatch: `dispatch.rs` routes AID-based SELECT to registered apps.
//! * Board: [`board`] resolves the pin map and flash layout from
//!   `firmware/boards/<board>.toml` at build time.

#![cfg_attr(not(feature = "emulation"), no_std)]

// The crate is `no_std`, but the host (emulation / test) paths need `std`:
// OS-entropy TRNG and the file-backed secure store. Opt back in only for host
// targets; device (arm) builds stay fully `no_std`.
#[cfg(not(target_arch = "arm"))]
extern crate std;

// Device (embassy) USB transport. Embassy crates are arm-only dependencies, so
// this module is excluded from host (x86_64) builds/tests even though the
// `device` feature stays default-on there.
#[cfg(all(feature = "device", target_arch = "arm"))]
pub mod usb;

#[cfg(feature = "emulation")]
pub mod emulation;

pub mod dispatch;

/// ISO 7816-4 **command chaining** on the receive side (US-181,
/// `PICOForge-COMPAT`): reassembles a `cla|0x10` fragment run into one
/// complete command APDU, bounded and fail-closed. `iso7816` 0.2.0 resolves
/// chains on the send side only, and `opcard::Card::handle` says so in its own
/// docs ("chained commands must be resolved by the caller") — the receive
/// side is the caller's job, and two applets need it. See the module docs for
/// the derivation of the bound and for the status-word choice.
pub mod apdu_chain;

/// Platform presence service (US-906): bound, timed, single-use user-presence
/// grants over an injected [`presence::PresenceSource`].
pub mod presence;

/// S-724: arm-only static heap behind the software-RSA backend (`rsa-backend`
/// feature). Host builds never see it (std allocator applies).
#[cfg(all(feature = "rsa-backend", target_arch = "arm"))]
pub mod rsa_heap;

/// Platform persist gate (US-421): the one persist→snapshot→program sequence
/// every transport calls (durable-before-ack).
pub mod persist;

/// Flash-slot [`persist::ImageSink`] (US-422): programs the partition image
/// into the reserved on-flash slots (primary + shadow), compare-then-write.
pub mod persist_sink;

/// CCID message framing (length-prefixed, per C `ccid.py` harness).
pub mod ccid;

/// HID class-control decisions + CCID class descriptor (US-391 E7).
pub mod hid_control;

// Yubico OTP HID transport (frame protocol + descriptors). Host-testable
// like `hid_control`; the `usb.rs` glue wires it onto the control endpoint.
pub mod otp_hid;

/// RS-Key / pico-fido PHY record TLV codec (US-116, built by US-114 for the
/// `0x41` `CONFIG_READ` response). `no_std`, no-alloc; the twelve tags are
/// [`phy_tlv::PhyTag`] and the framing is one-byte tag + one-byte length.
/// Ungated and target-agnostic so it is host-testable here rather than only
/// from the FIDO crate that first needed it.
pub mod phy_tlv;

/// USB identity: the stable 8-digit `iSerialNumber` derived from the OTP
/// chipid (US-103 PICOForge-COMPAT). Ungated so it is host-testable while
/// [`usb`] stays arm-only; see the module docs for the digit rule, its
/// collision budget, and the write-once `'static str` bridge.
pub mod usb_ident;

/// The **device identity block** — AAGUID, USB manufacturer, USB product and
/// USB VID:PID, each a published default with a build-time override
/// (PICOForge-COMPAT follow-up). Lives here rather than in an app crate
/// because `platform` is the only crate every participant depends on: the USB
/// descriptor is built in [`usb`] and `fapico2-fido` re-exports
/// [`identity::AAGUID`] for the CTAP2 layer, and a device whose descriptor and
/// whose getInfo disagreed on a name would be a worse bug than either being
/// hardcoded. Ungated and target-agnostic so the whole block is host-testable.
pub mod identity;

/// Sole source of *entropy* (US-380). Host: OS entropy; device: RP2350
/// TRNG. Deterministic generation (`drbg` below) stretches a draw from here
/// and is not itself a second source — see that module's docs.
pub mod trng;

/// US-1007's entropy-starvation injection seam: makes a **running** host
/// process behave as though the peripheral had wedged, so the "starve,
/// observe a clean error, recover, observe success" sequence is expressible
/// without a board.
///
/// **Emulation-only, and the `cfg` is the whole argument.** Two independent
/// conditions — the platform's `emulation` feature and a non-`arm` target —
/// which the device build (`--features device`, `thumbv8m.main-none-eabi`)
/// satisfies neither of. `tests/scripts/check_rng_path.py` enforces both: a
/// name-forgiveness check over the accessor, and a structural check that this
/// `mod` line still sits under exactly that attribute. Do not move it out.
///
/// Inert unless `FAPICO2_ENTROPY_STARVE_FILE` names a control file, and even
/// then only while that file exists — see the module docs.
#[cfg(all(feature = "emulation", not(target_arch = "arm")))]
pub mod entropy_starve;

/// HMAC-DRBG over HMAC-SHA-256 (US-1002): the deterministic generator the
/// TRNG above feeds. `no_std`, no alloc, KAT-verified against NIST's
/// published HMAC_DRBG example vectors.
///
/// **Wired (US-1005/US-1006) — this module is not dead code.** On device the
/// firmware builds exactly one generator, in
/// `firmware/src/boot.rs::init_drbg`, and serves from it: the FIDO boot
/// keystore material, the FIDO and OATH boot RNG pools, and the trussed
/// `Rng` backend the request path draws through. Callers reach it as
/// [`trng::DrbgTrng`], whose only constructor is the fallible `try_new` —
/// there is no way to obtain a generator without a seed.
/// `check_rng_path.py` is what keeps it the only path: `Drbg::new` /
/// `Drbg::new_device` are flagged outside this crate's own tests, and so is
/// any boot helper that names the peripheral `Trng` *type*.
pub mod drbg;

/// The **fused** seed source (US-1003): where the generator's seed actually
/// comes from. Binds the OTP key row, the flash UID and the sealed store's
/// `boot.entropy.v1` record through `ckey`'s bound-root HKDF, and mixes a
/// fresh bounded TRNG draw into the nonce slot on every seed — because the
/// fuse half alone is a fixed function of three constant inputs and would
/// replay the same first block on every warm boot. Fails closed on all four
/// refusals, including a wedged peripheral: there is no fuse-only fallback.
pub mod drbg_seed;

/// Secure key/secret storage (US-380). Device: RP2350 secure partition.
pub mod secure_store;

/// US-1070: a **rolled** SHA-512 compression, behind the `digest` trait so it
/// drops into `Hkdf<Sha512>` / `Hmac<Sha512>` unchanged and hashes byte for
/// byte like stock `sha2` — which is the entire safety argument, and the one
/// `platform/tests/sha512_differential.rs` exists to enforce. It replaces the
/// unrolled soft backend's tens of kilobytes of straight-line code with two
/// small loop bodies over a 16-word circular schedule. A `digest`-trait drop:
/// it does not reach ECDSA nonce derivation or signature encoding, and must
/// not (signing constraint S-2). See the module docs for the equivalence
/// argument and the 128-bit length counter.
pub mod sha512;

/// Secure-partition image format v3 — encrypt-then-MAC (US-915): the AEAD
/// sealing layer over [`secure_store`]'s logical serialization.
pub mod store_v3;

/// US-1572: **fused** root keys — a [`fused_key::FusedKey`] holds *where a key
/// comes from*, never the key, so each use re-reads and re-derives into a
/// [`fused_key::FusedRead`] whose lifetime **is** the exposure window. The
/// discipline `drbg_seed` already follows for the DRBG seed, extended to the
/// store key; see the module docs for the pico-hsm failure it is aimed at.
pub mod fused_key;

pub mod cflash;
pub mod cfs;

/// The flash map: one owner for every persistent region's offset, and the
/// compile-time proof that the CI flash budget cannot reach any of them
/// (US-1536).
pub mod flashmap;

/// The per-record key store: geometry and the capacities derived from it
/// (US-1539, US-1540).
pub mod keyregion;

/// C-firmware key hierarchy derivation (US-413 S-413-4).
pub mod ckey;

/// First-boot C→Rust data migration orchestrator (US-413 S-413-5).
pub mod migration;

/// Firmware-manifest boot admission (US-919): the pure foreign-image
/// decision + the streaming manifest hash over the running image.
pub mod fw_manifest;

/// Trussed platform/service seam (S-721-1, US-331): the no_std trussed-core
/// backend over embassy-rp — the `Client` opcard's card logic (S-721-2)
/// issues syscalls through. Host-visible `dispatch`/`runner` wiring (and
/// tests); the device platform (TRNG + littlefs2 stores + LED UI) is
/// `all(feature = "device", target_arch = "arm")`.
pub mod trusted_backend;

/// **The selected board** (US-1080): the pins, the flash size and the board
/// name, resolved once at build time from `firmware/boards/<board>.toml`.
///
/// The constants below are re-exports of that module's, kept at the crate root
/// because they have been addressed from here since US-302. The *values* are
/// no longer written in this file: they come from the board file, which is
/// what lets a second board be a data change. The pin test that used to assert
/// two literals here now asserts **parity with the selected board file** and
/// lives in `platform/tests/board_def.rs` — a test that can fail, which the
/// one it replaced could not.
pub mod board;

/// **One-shot secure-boot key-fingerprint provisioning** (US-1081): the
/// presence-gated, irreversible write of a boot-key fingerprint into the
/// RP2350 OTP, with the anti-rollback counter initialised in the same
/// operation. Enforcement of signed boot is US-1082 and is **not** here.
///
/// Nothing in the tree calls this module yet, and its module docs say which
/// two constants are unverified against the datasheet.
pub mod boot_key;

pub use crate::board::{BOARD_NAME, BUTTON_PIN, LED_PIN};
