//! Trussed platform/service seam for opcard (S-721-1, US-331).
//!
//! This module is the no_std [`trussed`](trussed) platform + service wiring
//! that lets the vendored `opcard` OpenPGP card logic run unmodified on the
//! RP2350. The next story (S-721-2) wires `opcard::Card` onto exactly the
//! client this module produces:
//!
//! * **Host** — [`with_backend`] runs the full client↔service round-trip in
//!   a test scope (the `platform/tests/trusted_backend.rs` seam tests).
//! * **Device** — [`device::DeviceBackend::boot`] builds the platform
//!   (entropy from the RP2350 TRNG, littlefs2 stores on QSPI flash + RAM,
//!   activity-LED UI) and publishes the one `'static` client via
//!   [`device::client`].
//!
//! ## Runner model: "call thyself" (controller decision D1)
//!
//! trussed-core's `syscall!` macro — which opcard uses throughout,
//! unmodified — is a **busy-spin**: `loop { poll() → Pending → loop }` with
//! no yield point. On the single-core cooperative executor, a *separate*
//! runner task would therefore never be scheduled while opcard spins — a
//! deadlock. trussed documents the single-core remedy: the client's `Syscall`
//! implementation runs the service **inline** ("call thyself"; see the
//! header of `trussed-0.2.0/src/client.rs`). That is exactly what
//! [`runner::SyscallRunner`] does: its `syscall()` processes the pending
//! request immediately, in the executor's own task context (the CCID serve
//! task, once S-721-2 spawns it) — EPIC fact 12's "syscall service runner
//! integrated into the firmware executor", read as executing *in* the
//! executor's task context, not as a competing task.
//!
//! ## Persistence (controller decision D2)
//!
//! The trussed card state lives in a littlefs2 filesystem on **QSPI flash**
//! (the `DevFlash` region, see [`device`] constants) — the same data
//! partition the C firmware's littlefs uses. The chunked SecureStore (S-701-2)
//! remains the project's durable *slot* store for app-level records
//! (FIDO/OATH/OpenPGP migration slots); the 8 KB secure partition cannot host
//! a littlefs2 image (512 B entry cap), which is why `DevFlash` is the
//! mechanism here.
//!
//! ## Mechanism scope (dispatch.rs; EPIC fact 13)
//!
//! The card is served by six trussed backends (see [`dispatch::BACKENDS`]):
//! the chunked Staging store, the Auth/PIN store, the software RSA backend
//! (S-724), the software secp256k1 backend (S-724), the software Brainpool
//! backend (US-944) and trussed-core. Between them they cover every
//! `Mechanism` the card logic actually names:
//!
//! - RSA 2048/3072/4096 (`Rsa*Pkcs1v15`), NIST P-256/384/521
//!   (`P256`/`P384`/`P521` and their `…Prehashed` forms), secp256k1
//!   (`Secp256k1*`), Brainpool P-256r1 (`Brainpool*`) — the
//!   Brainpool P-384r1 and P-512r1 arms exist in `pso.rs` but are
//!   unreachable: **P-384r1 was deferred by US-966** and P-512r1 has no
//!   backend. See below;
//! - Ed25519, X25519, ECDH (`SharedSecret`);
//! - AES-256-CBC — the PSO:ENCIPHER/PSO:DECIPHER payload cipher, which the
//!   Extended Capabilities DO advertises (`0x7F` first byte, AES ENC/DEC bit
//!   `0x20`) and which the US-950 roundtrip tests pin on both the virt and
//!   the device path;
//! - ChaCha8-Poly1305 — *not* a card-level secure-messaging cipher (SM is
//!   out of scope: MSE handles only the DEC/AUT key references, and the
//!   Extended Capabilities "Secure Messaging Algorithm" byte is `00`). It is
//!   the wrap-key-to-file KEK `opcard::state` uses to seal keys at rest;
//! - SHA-256 / SHA-512 — the KDF-DO digest (`opcard::command::kdf`, US-947).
//!   Plain hashes, not HMAC.
//!
//! A factory card accepts exactly `AllowedAlgorithms::default_gen()` — NIST
//! P-256/384/521, RSA 2048/3072/4096 (rsa-backend), secp256k1
//! (secp256k1-backend), Brainpool P-256r1 (brainpool-backend),
//! Ed25519, X25519. Brainpool P-384r1 and P-512r1 are both deliberately
//! absent: P-384r1 was **deferred by US-966** and P-512r1 has no backend
//! to defer. Either way PUT DATA of such an attribute closes with 6A80 (see
//! the US-945 note in opcard's `default_gen`). Since US-950, GET DATA FA
//! advertises exactly that set rather than the full enumeration.
//!
//! P-521 note: the PSO length gates in `pso.rs` are a *digest*-length table
//! — P-256=32, P-384=48, P-521=64, Brainpool 32/48/64, secp256k1=32 — which
//! is what OpenPGP card spec V3.4.1 §7.2.10 asks for: the host sends "the
//! hash value which was calculated (32, 48 or 64 bytes, dec.)" and the card
//! zero-pads the DSI up to the field-element width. P-521 is therefore
//! servable end-to-end for the 64-byte SHA-512 DSI a conformant host sends,
//! and 66 bytes is not a legal input. An earlier US-950 note here claimed
//! the opposite; that claim was investigated, disproven and withdrawn — see
//! the amended item 1 in `docs/known-gate-divergences.md`.
//!
//! The one narrowing that survives, and it is not actionable: the card is
//! hash-agnostic — it enforces the DSI length but not which hash produced
//! it — so a host pairing P-521 with something other than SHA-512 would be
//! refused. That is not a legal P-521 configuration (P-521 is defined over
//! SHA-512), so there is nothing to fix and nothing to advertise
//! differently.

pub mod dispatch;
pub mod runner;

#[cfg(all(feature = "device", target_arch = "arm"))]
pub mod device;

#[cfg(all(feature = "host-backend", not(target_arch = "arm")))]
pub mod host;

pub use dispatch::{OpcardDispatch, OpcardDispatchContext};
pub use runner::{with_backend, Backends, Client, SyscallRunner};

#[cfg(all(feature = "device", target_arch = "arm"))]
pub use device::{DeviceBackend, DevicePlatform, LedUi, Rp2350Rng, client, take_client, wipe_internal_fs};

#[cfg(all(feature = "host-backend", not(target_arch = "arm")))]
pub use host::{HostPlatform, with_host_backend};
