//! US-170 (EPIC `PICOForge-COMPAT`) — the RS-Key **soft lock**: the `STATE`
//! sub-command (`0x05`), the `UNLOCK` sub-command (`0x06`), and the
//! `authenticatorConfig` vendor-prototype pair that engages and releases the
//! lock.
//!
//! # Shape: one protocol module, three gates, no durable state of its own
//!
//! Everything here is CBOR, AEAD framing and gating. The state — the master
//! seed, the lock record, the per-power-cycle flag, the MSE channel — is
//! reached exclusively through [`VendorOps`], which
//! [`crate::vendor_state`] already implements on both command paths and
//! [`crate::vendor41::tests`-adjacent suites already exercise. This module
//! therefore implements **no** storage of its own, and every function here is
//! a pure function of `(request bytes, token, ops) -> Outcome`.
//!
//! The signatures deliberately mirror [`crate::vendor41::config_read`] and
//! [`crate::vendor41::config_write`]: an `&mut dyn VendorOps`, the request
//! body, the caller's [`TokenAuth`], an output buffer for the arm that has a
//! body, and a [`Outcome`] back. The dispatcher wires them in the same place
//! it wires `ConfigRead` and `ConfigWrite`.
//!
//! # The three gates are not the same gate, and the difference is the protocol
//!
//! | operation | transport | gate |
//! |---|---|---|
//! | `STATE` (`0x05`) | `0x41` | **none** — `backup_status` passes `None` for the PIN (`picoforge/src/hal/fido/mod.rs:1740-1742`) and the doc comment says *"(ungated)"* at `mod.rs:1737` |
//! | `UNLOCK` (`0x06`) | `0x41` | **possession of the lock key** — `lock_unlock` passes `None` (`mod.rs:1826`) and is documented *"Ungated over the 0x41 channel"* (`mod.rs:1824`) |
//! | engage / release | `0x0D` | **a `0x20` PIN token**, stock CTAP2 MAC ([`lock_engage`], [`lock_release`]) |
//!
//! `UNLOCK` deliberately asks for **no PIN and no touch**. The whole point of
//! a soft lock is that the second factor is the 24-word phrase; adding a
//! button press would make the lock a *rate* limiter rather than a lock, and
//! adding a PIN would mean the device is unusable for a holder who has the
//! phrase and not the PIN.
//!
//! # `0x3D` is load-bearing and appears in exactly one place
//!
//! `UNLOCK` against a device that is **not locked** must answer
//! `0x3D` — [`Ctap2Response::IntegrityFailure`], which RS-Key repurposes as
//! "device is not locked" ([`picoforge/src/hal/fido/mod.rs:1828-1830`]). It
//! matters in two directions:
//!
//! * `lock_disable` sends `UNLOCK` first and tolerates **only** `0x00` and
//!   `0x3D` (`mod.rs:1862-1865`); anything else aborts the release with
//!   `"unlock (wrong key?) failed: status 0x.."`.
//! * `lock_unlock` (the standalone release path) maps `0x3D` to
//!   `"device is not locked"` (`mod.rs:1828-1830`), **not** to the wrong-key
//!   message.
//!
//! So `0x3D` is returned **only** for "not locked", it is checked **before**
//! anything that can fail differently (see [`unlock`]), and a *wrong key* is
//! deliberately answered with something else — because a wrong key that
//! answered `0x3D` would tell a user who typed the right phrase that the
//! device is unlocked when it is not.
//!
//! # The two MAC constructions, and why both are here
//!
//! * **`0x41` sub-commands** — `FF×32 ‖ 0x41 ‖ subCommand ‖ cbor(subCommandParams)`
//!   (`picoforge/src/hal/fido/ops.rs:1581-1586`). That is
//!   [`crate::vendor41::verify_mac`], and [`unlock`] **reuses it verbatim**
//!   rather than writing a second one. It is only reached when a token is
//!   actually attached, which `lock_unlock` never does.
//! * **`authenticatorConfig` (`0x0D`)** — `FF×32 ‖ 0x0D ‖ 0xFF ‖ cbor(subCommandParams)`
//!   (`picoforge/src/hal/fido/ops.rs:987-1002`, the `sign_config_command`
//!   at `ops.rs:1002-1004` pushing `0xff` 32×, `Config`, then `sub_cmd`,
//!   then the params). `verify_mac` cannot express this: it hard-codes
//!   [`crate::vendor41::CMD`] (`0x41`) as the message's command byte and the
//!   sub-command byte as the second byte, and it requires key 1 to be a
//!   [`crate::vendor41::Subcommand`]. So [`verify_config_vendor_mac`] exists.
//!
//! The two differ by **one byte's worth of meaning** and both are required by
//! the protocol; writing them as one parameterised function would mean a
//! function whose only job is to be wrong in one of its two configurations.
//! What the second one *does* share with the first is the part that actually
//! causes failures, and it is spelled out on [`verify_config_vendor_mac`]:
//! the MAC covers the client's own serialised bytes, borrowed, never a
//! re-encoding.
//!
//! # The AEAD is a crate, and the framing is ours
//!
//! [`aead_open`] used to be a hand-written RFC 8439 ChaCha20-Poly1305 living
//! in this file, and these docs used to say — correctly at the time, wrongly
//! now — that `chacha20poly1305` was *not* in the crate's dependency tree and
//! that writing a second AEAD into security firmware was the wrong default. It
//! was: the same cipher was independently hand-rolled a second time in
//! [`crate::vendor_backup`] and a third time in [`crate::vendor_att`]. Three
//! correct copies is not redundancy, it is three times the review for a cipher
//! whose failure modes — a reused nonce, a key that shares keystream with its
//! own one-time key, a clamp applied to the wrong sixteen bytes — are shared
//! by all three and so would not be caught by having three.
//!
//! The cryptography is now [`crypto::chacha20poly1305_open_blob`], over the
//! `chacha20poly1305` crate. What stays here is the part that is genuinely
//! this module's: the `nonce(12) ‖ ct ‖ tag(16)` framing the client dictates
//! ([`backup.rs:64-77`]), the 32-byte plaintext length the lock key is by
//! construction, and the choice to answer `0x27` where the seed-export arm
//! answers `0x3D` for the identical cryptographic event. The frame split
//! cannot be got wrong twice now — it is performed in one place for all three
//! callers.
//!
//! The negative direction is the one worth keeping in mind. A *wrong* tag here
//! is an unlock that never succeeds; it cannot be a tag that wrongly verifies,
//! because the comparison is against a tag computed over a ciphertext this
//! module was handed, and the two vectors in `tests/vendor_lock.rs` come from
//! an implementation this repository did not write.
//!
//! # Where this module's stored form departs from `SoftLock`'s doc comment
//!
//! [`SoftLock::key`] is documented as holding *"the lock key, as
//! `wrap_secret` sealed it"* — the 60-byte `nonce ‖ ct ‖ tag` blob. This
//! module stores the **32-byte raw key** instead, and the reason is that the
//! sealed form is not sufficient to implement `UNLOCK` at all:
//!
//! * At engage, the device receives only the sealed blob. The client holds
//!   the plaintext ([`mod.rs:1836-1853`]: it generates the 32 bytes, wraps
//!   them, and renders *itself* the BIP-39 phrase — the device never sees the
//!   phrase).
//! * At unlock, the client does a **fresh** MSE handshake and seals the same
//!   plaintext under a **different** session key and nonce
//!   ([`mod.rs:1857-1879`] → `wrap_secret` → `mse_handshake`). The two
//!   ciphertexts share nothing, so there is no comparison that relates them.
//!
//! So the device must open the blob at engage time, keep the plaintext, and
//! compare in constant time at unlock time. The doc comment's claim that
//! *"the device never unwraps this at rest"* cannot be satisfied by any
//! implementation of `UNLOCK`.
//!
//! Nothing is lost by storing the plaintext: [`SoftLock`] lives in
//! `VendorSecret`, which is the **sealed** snapshot half (auth-map key 7,
//! [`crate::vendor_state::AUTH_KEY_SECRET`]) — so the raw key is written
//! inside an already-AEAD-sealed snapshot field. The `wrap_secret` seal is a
//! session seal under a key that is gone by the next power cycle, and a seal
//! that cannot be re-opened is not a protection.
//!
//! # What this module does **not** gate, and why that is not a hole
//!
//! `STATE` and `UNLOCK` are ungated because the client sends them ungated,
//! and the two together disclose only four booleans and one AEAD decryption
//! attempt. Neither reads the master seed. The one that would — `EXPORT` — is
//! a different sub-command and a different story (US-172).
//!
//! The `0x20` gate on engage/release is *not* discretionary: an `0x0D`
//! vendor-prototype write that stores a new key, or clears the lock and
//! therefore the at-rest protection on the seed, is exactly the
//! `FieldTier::Identity` situation [`crate::vendor41::config_write`]'
//! identity tier exists for, and the client mints the token for it
//! ([`mod.rs:1845-1847`], [`mod.rs:1870-1872`]).

use crate::cbor::no_heap::{self, Item, Parser};
use crate::crypto;
use crate::ctap2::Ctap2Response;
use crate::device_core::PERM_ACFG;
use crate::vendor41::{self, Outcome, SoftLock, TokenAuth, VendorOps, MASTER_SEED_LEN};
use heapless::Vec as HeaplessVec;

// ---------------------------------------------------------------------------
// The wire constants, each with the client line it is transcribed from.
//
// They are spelled here rather than imported from `vendor41` because
// `vendor41` is the `0x41` channel and three of the five below have **no**
// `0x41` byte in them at all. See the module docs on the two transports.
// ---------------------------------------------------------------------------

/// `RSKEY_VENDOR_STATE` (`picoforge/src/hal/fido/constants.rs:744`).
pub const SUB_STATE: u8 = 0x05;
/// `RSKEY_VENDOR_UNLOCK` (`picoforge/src/hal/fido/constants.rs:746`).
pub const SUB_UNLOCK: u8 = 0x06;

/// CTAP2 `Config` opcode, the command byte the `0x0D` MAC covers
/// (`picoforge/src/hal/fido/constants.rs:64`).
pub const CMD_CONFIG: u8 = 0x0D;

/// `ConfigSubCommand::VendorPrototype`
/// (`picoforge/src/hal/fido/constants.rs:217`).
///
/// **0xFF, not 0x03.** `picoforge/src/hal/fido/ops.rs:1632-1634` passes
/// `ConfigSubCommand::VendorPrototype` to the signer, so the byte inside the
/// MAC is `0xFF`; reading "vendor prototype" as a small number is the single
/// most likely transcription error on this path, and it fails as a `0x33` for
/// a MAC that is arithmetically perfect.
pub const CONFIG_SUB_VENDOR_PROTOTYPE: u8 = 0xFF;

/// `ConfigParam::SubCommand` = 0x01 ([`constants.rs:194`]).
pub const CONFIG_PARAM_SUB_COMMAND: u64 = 0x01;
/// `ConfigParam::SubCommandParams` = 0x02 ([`constants.rs:196`]).
pub const CONFIG_PARAM_SUB_COMMAND_PARAMS: u64 = 0x02;
/// `ConfigParam::PinUvAuthProtocol` = 0x03 ([`constants.rs:198`]).
pub const CONFIG_PARAM_PIN_PROTOCOL: u64 = 0x03;
/// `ConfigParam::PinUvAuthParam` = 0x04 ([`constants.rs:200`]).
pub const CONFIG_PARAM_PIN_PARAM: u64 = 0x04;

/// `RSKEY_AUT_ENABLE` — engage the soft lock
/// (`picoforge/src/hal/fido/constants.rs:766`).
///
/// An 8-byte CBOR **unsigned** integer, not a byte string: `authconfig_vendor`
/// inserts it as `Value::Integer` (`ops.rs:1616-1617`), and the `no_heap`
/// parser reads a key-1 value of `Item::U(v)` with `v` a `u64`.
pub const AUT_ENABLE: u64 = 0x03E4_3F56_B342_85E2;

/// `RSKEY_AUT_DISABLE` — release the soft lock
/// (`picoforge/src/hal/fido/constants.rs:768`).
pub const AUT_DISABLE: u64 = 0x1831_A40F_04A2_5ED9;

/// `authconfig_vendor`'s sub-params key 1: the 64-bit vendor id
/// (`picoforge/src/hal/fido/ops.rs:1616`).
pub const VENDOR_SUB_PARAM_ID: u64 = 0x01;

/// `authconfig_vendor`'s sub-params key for a **byte string** payload:
/// `0x02` (`ops.rs:1620-1623`).
///
/// The client's enum name for this slot is misleading — `VendorSubParam`
/// calls `0x02` a COSE key — and the mapping is by **payload type**, not by
/// meaning: `Bytes → 0x02`, `Integer → 0x03`, `Text → 0x04`
/// (`ops.rs:1618-1627`). The lock blob is a `Value::Bytes`, so it is key
/// `0x02`. Following the enum name instead of the code would read key `0x03`
/// and refuse every engage PicoForge performs.
pub const VENDOR_SUB_PARAM_BSTR: u64 = 0x02;

/// `authenticatorConfig` sub-params key 1 inside `UNLOCK`'s own
/// `subCommandParams`: the sealed lock key (`mod.rs:1821-1822`).
pub const UNLOCK_PARAM_BLOB: u64 = 0x01;

/// The AEAD blob the client produces for a 32-byte secret:
/// `nonce(12) ‖ ct(32) ‖ tag(16)` = **60** bytes.
///
/// From `wrap_secret` (`mod.rs:1799-1806`) over
/// `backup::chacha_seal` (`backup.rs:64-77`, which returns
/// `nonce_b ‖ buf` where `seal_in_place_append_tag` left the tag on the tail).
/// `ring`'s `Aead::seal_in_place_append_tag` appends the 16-byte tag, so the
/// order is **ct then tag** — not `tag ‖ ct`, which is what
/// `chacha20poly1305`'s `encrypt` returns and the reason [`aead_open`] takes
/// the tag off the *end*.
pub const LOCK_BLOB_LEN: usize = 60;

/// Shortest blob [`aead_open`] will look at: `nonce(12) ‖ tag(16)` with an
/// empty ciphertext. Below this there is no way to tell a truncated blob from
/// a malformed one.
///
/// `pub` so the integration test can drive the length refusals without
/// restating the number — a test that used a literal would stop testing the
/// boundary the day the constant changed.
pub const BLOB_MIN: usize = 12 + 16;

// ---------------------------------------------------------------------------
// `STATE` (sub-command `0x05`).
// ---------------------------------------------------------------------------

/// Answer `STATE`: `{1: sealed, 2: has_seed, 3: locked, 4: unlocked}`.
///
/// **Ungated.** `backup_status` calls
/// `rs_key_vendor(RSKEY_VENDOR_STATE, None, None)` (`mod.rs:1740-1742`) — a
/// `None` `params` *and* a `None` `pin` — and the doc comment above it says
/// *"Read `{sealed, has_seed, locked, unlocked}` (ungated)"* (`mod.rs:1737`).
/// There is no `subCommandParams` to read, and a request that carries one is
/// ignored rather than refused: the client never sends one, and refusing a
/// request the protocol does not define is how a feature probe starts
/// answering errors.
///
/// # `sealed` is a parameter, and that is a hole the caller fills
///
/// [`VendorOps`] has **no** method for the export-window seal, so the caller
/// reads it and hands it in. The method to add is proposed in the module
/// docs; until it lands, there is no way for this function to obtain the flag
/// itself. It is a parameter rather than a hard-coded `false` because a
/// hard-coded `false` would be a **lie the client acts on**: PicoForge's
/// backup screen branches on it (a sealed device cannot export, and
/// `backup_finalize` is the one-shot that closes the window), so a device that
/// always reports `sealed = false` would offer an export that `FINALIZE` has
/// already made impossible. The same argument is why the other three are
/// read here and it is not: those three the trait does expose.
///
/// ## The trait change this needs — the exact text
///
/// Add **one read-only** method to [`VendorOps`], next to
/// [`VendorOps::master_seed`]:
///
/// ```ignore
///     /// Whether the one-time export window is permanently closed.
///
///     /// `STATE`'s `sealed`, and the same durable bit `FINALIZE`
///     /// (`RSKEY_VENDOR_FINALIZE`, `0x04`) sets. A device that has run
///     /// `FINALIZE` can never export again, so this is monotonic: it
///     /// is set once and no protocol path clears it.
///
///     /// Read-only on purpose. The *writer* belongs to whichever arm
///     /// implements `FINALIZE`, so the two edits have no overlap to
///     /// reconcile and this module does not need to be re-argued when
///     /// that arm lands.
///     fn export_sealed(&self) -> bool;
/// ```
///
/// Three reasons for a bare getter rather than something richer:
///
/// 1. **Disjointness.** `FINALIZE` needs a *setter*; `STATE` needs a
///    *getter*. Naming them separately means the two Phase I arms are
///    reconciled by adding two methods with no argument between them.
/// 2. **Monotonic, so a bool is the whole type.** The window is open or it
///    is closed forever; there is no third state, and a tri-state would
///    encode a question the protocol does not ask.
/// 3. **Where the bit lives is a separate decision.** `VendorPublic` — the
///    plaintext half, auth-map key 8 — is where an export-window bit
///    belongs: it is not secret, and it has to survive the snapshot
///    encryption boundary so `EXPORT` can refuse on it. If this Phase I
///    series never puts it there, it has to live somewhere else durable,
///    and that is a coordinator's call rather than one this module should
///    make by accident.
///
/// When the method lands, [`state`]'s `sealed` parameter goes away and
/// [`state`] reads it like the other three.
///
/// # All four keys are always present, and always as CBOR booleans
///
/// This is the one part of the module with no protocol text forcing it, so
/// the reason is the client's own parse ([`mod.rs:1558-1565`]):
///
/// ```text
/// Some(Value::Bool(b)) => *b,
/// Some(Value::Integer(n)) => *n != 0,
/// _ => false,          // anything else, AND any missing key
/// ```
///
/// A text string, a byte string, `null`, or an **omitted key** all read as
/// `false`. For `locked` that is a device silently reporting itself
/// *unlocked*, and for `sealed` a device that will refuse an export claiming
/// the window is still open. So:
///
/// * every key is emitted on every response — never conditionally omitted;
/// * every value is a real CBOR `0xF4`/`0xF5` via
///   [`no_heap::push_bool`], never `push_uint(0/1)`.
///
/// A `0`/`1` integer would *happen* to work (the `_` arm above accepts it),
/// which is exactly why it is a hazard: it is correct today and there is no
/// failure to debug if a later refactor swaps it for a string. The encoding
/// is pinned by
/// `tests/vendor_lock.rs::state_emits_every_key_as_a_cbor_bool_not_a_uint`.
///
/// # Key order
///
/// Ascending `1, 2, 3, 4`. The client's decode is a `BTreeMap<Value, Value>`
/// and every read is a lookup by key ([`mod.rs:1558-1565`]), so order is not
/// merely unconstrained but unobservable — the map is rebuilt before
/// `m_bool` ever sees it. Ascending is emitted anyway because it is the
/// canonical CBOR order and therefore the one a byte-comparing test or a
/// future signature over this body would agree with.
///
/// # `locked` is derived, not stored
///
/// It is [`VendorOps::soft_lock`]'s [`SoftLock::engaged`] — the presence of a
/// key — not a flag. See [`SoftLock`]'s own doc for why a stored
/// `engaged: bool` beside `key: Option<..>` is a second source of truth that
/// a torn write can desynchronise.
///
/// # `unlocked` is per-power-cycle and this is not a bug
///
/// It is [`VendorOps::unlocked_this_power_cycle`], which is
/// **volatile**. It reads `false` after every reset, and that is what makes it
/// a second factor rather than a latch: a durable "unlocked" would survive the
/// power cycle it is defined against. Pinned by
/// `tests/vendor_lock.rs::unlocked_is_false_in_a_fresh_session_over_the_same_store`.
pub fn state<const N: usize>(
    ops: &mut dyn VendorOps,
    sealed: bool,
    out: &mut HeaplessVec<u8, N>,
) -> Outcome {
    out.clear();
    let flags = [
        sealed,
        ops.master_seed().is_some(),
        ops.soft_lock().engaged(),
        ops.unlocked_this_power_cycle(),
    ];
    // Four pairs, unconditionally. The `A4` header is written before any
    // value, so there is no path that can produce a short map.
    if no_heap::push_map_header(out, 4).is_err()
        || no_heap::push_uint(out, 1).is_err()
        || no_heap::push_bool(out, flags[0]).is_err()
        || no_heap::push_uint(out, 2).is_err()
        || no_heap::push_bool(out, flags[1]).is_err()
        || no_heap::push_uint(out, 3).is_err()
        || no_heap::push_bool(out, flags[2]).is_err()
        || no_heap::push_uint(out, 4).is_err()
        || no_heap::push_bool(out, flags[3]).is_err()
    {
        // `CTAP2_MAX_MSG`-sized output for a nine-byte map is unreachable, so
        // this is a bug rather than a runtime condition — but the command path
        // owns no recovery, and a partial body behind a non-zero status is the
        // quieter half of a mis-framed reply. Clear, and refuse.
        out.clear();
        return Outcome::plain(Ctap2Response::LimitExceeded);
    }
    Outcome::plain(Ctap2Response::Ok)
}

// ---------------------------------------------------------------------------
// `UNLOCK` (sub-command `0x06`).
// ---------------------------------------------------------------------------

/// Answer `UNLOCK`: open the sealed lock key with the MSE channel, and if it
/// is the right one, load the seed for this power cycle.
///
/// **Ungated at the CTAP layer.** `lock_unlock` sends
/// `rs_key_vendor(RSKEY_VENDOR_UNLOCK, Some(params), None)` (`mod.rs:1826`)
/// — a `None` PIN, so **no key 3 and no key 4** — and is documented *"Ungated
/// over the 0x41 channel"* (`mod.rs:1824`). The gate is the lock key itself:
/// a 32-byte secret the holder wrote down as a 24-word BIP-39 phrase
/// ([`mod.rs:1836-1853`]), sealed to the MSE channel and handed over as
/// `subCommandParams` `{1: <blob>}` (`mod.rs:1818-1822`).
///
/// A token that **is** attached is still verified, against
/// [`vendor41::verify_mac`] and [`vendor41::authorize`] — the `0x41`
/// construction, reused rather than reimplemented. That is exactly
/// [`vendor41::Requirement::TokenOptional`]'s contract for this sub-command
/// ([`vendor41::required_permission`]), and it is what stops a
/// `CREDENTIAL_MANAGEMENT`-only token from being accepted here. The real
/// client never attaches one, so that path is defence in depth, not a
/// requirement the protocol imposes.
///
/// # The order of the checks is load-bearing
///
/// 1. optional MAC,
/// 2. the request shape,
/// 3. **"not locked" → `0x3D`**,
/// 4. the MSE channel,
/// 5. the AEAD tag,
/// 6. the key comparison.
///
/// Step 3 is before step 4 because [`vendor41::verify_mac`]'s sibling
/// status for a missing session is [`Ctap2Response::InvalidParameter`] (`0x02`),
/// and `lock_disable` aborts the whole release on anything that is not `0x00`
/// or `0x3D` ([`mod.rs:1862-1865`]). A device with no lock and no MSE session
/// that answered `0x02` would break "release a lock" for a device that never
/// had one, with a message about a *wrong key*.
///
/// # `0x3D` here, and nowhere else
///
/// [`Ctap2Response::IntegrityFailure`] is officially
/// `CTAP2_ERR_INTEGRITY_FAILURE`; RS-Key repurposes it as *"device is not
/// locked"* ([`mod.rs:1828-1830`]), and the EPIC names the same requirement
/// at `EPIC-fapico2-picoforge-compatibility.md:910`. Every other failure on
/// this path deliberately answers something else:
///
/// | failure | status | why not `0x3D` |
/// |---|---|---|
/// | no MSE session | `0x02` `InvalidParameter` | the client has no session to send a blob in; this is a protocol error, not a lock state |
/// | blob shorter than 28 bytes | `0x03` `InvalidLength` | a shape error, and the client's own `wrap_secret` cannot produce one |
/// | AEAD tag does not verify | `0x27` `OperationDenied` | **the important one.** A wrong key and a tampered blob are indistinguishable after a tag check, and `0x3D` would surface as `"device is not locked"` on the standalone unlock path (`mod.rs:1828-1830`) — telling a user who typed the correct phrase that the device is not locked, when in fact the phrase was wrong |
/// | key matches | — | |
///
/// # A locked device with no master seed still unlocks
///
/// [`VendorOps::master_seed`] is not consulted. `unlocked` is a claim about
/// the *key*, not about the seed: it means "the lock was opened with the
/// secret the holder recorded". A device that is locked over no seed
/// ([`vendor41::VendorOps::master_seed`]'s doc calls that state
/// "representable and truthful") answers `0x00` and reports
/// `{has_seed: false, locked: true, unlocked: true}`, which is a true
/// description of it. Refusing would give a second, undocumented failure
/// status on the one path whose statuses are already protocol-meaningful.
///
/// # The comparison is constant-time
///
/// [`crate::crypto::ct_eq`], the same helper every other MAC check in this
/// firmware goes through ([`vendor41::verify_mac`]'s note on it). The stored
/// key and the recovered key are both 32 bytes, so there is no length
/// variation to leak.
///
/// # A failed unlock does not touch the flag
///
/// [`VendorOps::set_unlocked_this_power_cycle`] is called on exactly one
/// path: after the key matched. Not "set it false first and then true" — a
/// volatile flag that flickers is a flag a concurrent reader can observe
/// half-open.
pub fn unlock(ops: &mut dyn VendorOps, data: &[u8], auth: Option<TokenAuth<'_>>) -> Outcome {
    // --- 1. an attached token is verified; an absent one is legitimate ---
    if let Some(a) = auth {
        if a.blocked {
            // The latch, checked **before** the param — the same order and the
            // same non-charging outcome `identity_gate` uses, for the same
            // reason: the app has already spent its three strikes, and
            // charging a fourth would move the status from the app's `0x34` to
            // the arm's `0x33` and tell the client its token was wrong when
            // the device is refusing all pinUvAuth.
            return Outcome::plain(Ctap2Response::PinAuthBlocked);
        }
        if let Err(outcome) = match vendor41::verify_mac(data, Some(a.token)) {
            Ok(_) => vendor41::authorize(vendor41::Subcommand::Unlock, Some(a.permissions))
                .map_err(Outcome::plain),
            // Only a genuine authentication failure is charged. Malformed
            // CBOR never reached a comparison against anything secret.
            Err(Ctap2Response::PinAuthInvalid) => {
                Err(Outcome::pin_auth_failure(Ctap2Response::PinAuthInvalid))
            }
            Err(e) => Err(Outcome::plain(e)),
        } {
            return outcome;
        }
    }

    // --- 2. the request shape: `{1: 6, 2: {1: <sealed blob>}}` ---
    //
    // Two hops, not one: `data` is the whole `0x41` request map and the blob is
    // inside **its** key 2. `verify_mac` above walked exactly this structure,
    // but it hands the params span back only on the authenticated path — and
    // the real client sends `UNLOCK` bare (`mod.rs:1826`), so the common path
    // has to find the same span itself. One helper does it, so the two cannot
    // land on different pairs of the same bytes.
    let params = match sub_command_params(data) {
        Ok(p) => p,
        Err(e) => return Outcome::plain(e),
    };
    let blob = match unlock_blob(params) {
        Ok(b) => b,
        Err(e) => return Outcome::plain(e),
    };

    // --- 3. "not locked" is `0x3D`, and it is decided before anything else
    //        that can fail differently. See the module-level ordering note. ---
    let lock = ops.soft_lock();
    if !lock.engaged() {
        return Outcome::plain(Ctap2Response::IntegrityFailure);
    }
    let stored = lock.key_bytes().unwrap_or(&[]);

    // --- 4. the MSE channel the client sealed to ---
    // `MseChannel` derives no `Default` (both fields are full-width, and a
    // default-constructed one would be a zero channel key — the very thing
    // `VendorOps::mse_channel` refuses to hand out). The literal is written out
    // so the "all zeros" state is visible at the call site and is overwritten
    // by the `mse_channel` call on the next line, whose `Err` is what the
    // refusal is.
    let mut channel = vendor41::MseChannel { key: [0u8; 32], aad: [0u8; 65] };
    if ops.mse_channel(&mut channel).is_err() {
        return Outcome::plain(Ctap2Response::InvalidParameter);
    }

    // --- 5. open the blob ---
    let mut key = [0u8; MASTER_SEED_LEN];
    if aead_open(&channel.key, &channel.aad, blob, &mut key).is_err() {
        return Outcome::plain(Ctap2Response::OperationDenied);
    }

    // --- 6. constant-time compare, then the flag ---
    if !crate::crypto::ct_eq(&key, stored) {
        return Outcome::plain(Ctap2Response::OperationDenied);
    }
    ops.set_unlocked_this_power_cycle(true);
    Outcome::plain(Ctap2Response::Ok)
}

/// The **raw** bytes of a `0x41` request's `subCommandParams` (CBOR key 2),
/// borrowed from the request, or an empty slice when the map has no key 2.
///
/// This is the same span [`vendor41::verify_mac`] captures and the same rule
/// it applies: a **repeated** key 2 is [`Ctap2Response::InvalidCbor`], because
/// "which params" is undecidable and last-wins would decide it silently. The
/// client omits key 2 entirely for the sub-commands that take none
/// ([`vendor41::verify_mac`]'s note on `ops.rs:1560-1573`), so the empty case
/// is real rather than theoretical — it is not an error here, and a caller that
/// needs a parameter gets [`Ctap2Response::MissingParameter`] from its own
/// parse of the empty slice.
///
/// Key 1 is skipped, not validated: the dispatch arm has already matched the
/// sub-command, and re-deciding it here would be a second place to be wrong.
fn sub_command_params(data: &[u8]) -> Result<&[u8], Ctap2Response> {
    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut span: Option<(usize, usize)> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(2) {
            if span.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            let start = p.pos();
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
            let end = p.pos();
            span = Some((start, end));
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    Ok(match span {
        Some((start, end)) => &data[start..end],
        None => &[],
    })
}

/// Pull the sealed blob out of a `0x41` `subCommandParams` `{1: <bstr>}`.
///
/// The no-alloc parser, so a key this sub-command does not define is skipped
/// rather than refused — `UNLOCK`'s params map is a single pair today, but a
/// client that added a second would get an error from a device that is merely
/// behind, and "unknown key" is not a reason to fail a possession proof.
///
/// Key 1 repeated is [`Ctap2Response::InvalidCbor`], the same rule
/// [`vendor41::verify_mac`] applies to a repeated key 2: last-wins would pick
/// one of two blobs silently, and a caller that cannot say which blob it sent
/// has not proved anything.
fn unlock_blob(data: &[u8]) -> Result<&[u8], Ctap2Response> {
    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut found: Option<Result<&[u8], Ctap2Response>> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(UNLOCK_PARAM_BLOB) {
            if found.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            found = Some(match p.next() {
                Ok(Item::B(b)) => Ok(b),
                // Key 1 present but not a byte string: not the shape this
                // sub-command defines, and coercing it would be guessing.
                _ => Err(Ctap2Response::InvalidCbor),
            });
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    found.unwrap_or(Err(Ctap2Response::MissingParameter))
}

// ---------------------------------------------------------------------------
// Engage / release — the `authenticatorConfig` (`0x0D`) vendor-prototype pair.
// ---------------------------------------------------------------------------

/// Engage the at-rest soft lock: open the client's sealed 32-byte lock key
/// with the MSE channel and store it, so every later `STATE` reports
/// `locked: true`.
///
/// # This is not a `0x41` sub-command
///
/// It goes over CTAP2 `authenticatorConfig` (`0x0D`) as a
/// `VendorPrototype` (`0xFF`) carrying a 64-bit vendor id
/// ([`picoforge/src/hal/fido/ops.rs:1611-1662`]), with the lock blob under
/// sub-params key `0x02` because the payload is a `Value::Bytes`
/// ([`ops.rs:1618-1627`]). The whole `0x41` dispatcher is bypassed, which is
/// why [`Subcommand`] has no variant for it and why this function takes an
/// `0x0D` request body.
///
/// # The gate: a `0x20` token
///
/// `lock_enable` mints one explicitly
/// ([`mod.rs:1845-1847`]: `get_pin_token_with_permission(..,
/// AUTHENTICATOR_CONFIG, None)`) and hands it to `authconfig_vendor`
/// ([`mod.rs:1848-1851`]). Engaging stores a new secret that gates the seed,
/// which is the same class of change as `config_write`'s identity tier, and
/// the refusal for a missing token is [`Ctap2Response::PuatRequired`] (`0x36`)
/// rather than a fall-through to "authorised".
///
/// # What the device does and does not learn
///
/// It learns the 32 lock-key bytes. It never learns the **phrase**: the client
/// generates the entropy, wraps it, and renders the BIP-39 mnemonic itself
/// ([`mod.rs:1836-1853`], ending in `backup::seed_to_mnemonic(&key)`), and
/// the 24 words go to the human, not the token. That is also why the key's
/// entropy is the **host's** and not [`VendorOps::random_bytes`]'s: the
/// device has no say in it, and a firmware that "helpfully" regenerated the
/// key would silently break a phrase the user has already written down. No
/// randomness is drawn here, and that is a property rather than an omission.
///
/// # A device with no master seed may still engage
///
/// `has_seed` and `locked` are independent, and
/// [`vendor41::VendorOps::master_seed`]'s doc calls the combination
/// "representable and truthful". Refusing would make the lock
/// seed-dependent, which the protocol does not: it is a property of the
/// device, and the client may enable it before a seed is ever written.
///
/// # Engaging clears any standing unlock
///
/// [`VendorOps::set_unlocked_this_power_cycle`] is set to `false` on success.
/// A new lock key invalidates whatever the previous key had opened, and
/// leaving the old `true` behind would have `STATE` report a device that is
/// simultaneously locked under a key the caller no longer holds and unlocked
/// for the previous one.
pub fn lock_engage(ops: &mut dyn VendorOps, data: &[u8], auth: Option<TokenAuth<'_>>) -> Outcome {
    // --- the gate, before anything is read or written ---
    let params = match config_vendor_gate(data, auth) {
        Ok(p) => p,
        Err(outcome) => return outcome,
    };

    // --- the vendor id, strictly ---
    let id = match vendor_id(params) {
        Ok(id) => id,
        Err(e) => return Outcome::plain(e),
    };
    if id != AUT_ENABLE {
        // A vendor id this arm does not own. `InvalidSubcommand` and not
        // `InvalidParameter`: the id is the selector *within* the vendor
        // prototype, and the dispatcher must have already offered it to the
        // other `0xFF` arms (`ctap2::CONFIG_CREDENTIAL_EXPIRE`,
        // `CONFIG_CREDENTIAL_REVOKE`) before calling here.
        return Outcome::plain(Ctap2Response::InvalidSubcommand);
    }

    // --- the blob, under sub-params key 0x02 because the payload is bytes ---
    let blob = match vendor_blob(params) {
        Ok(b) => b,
        Err(e) => return Outcome::plain(e),
    };

    // --- open it with the session the client sealed to ---
    // `MseChannel` derives no `Default` (both fields are full-width, and a
    // default-constructed one would be a zero channel key — the very thing
    // `VendorOps::mse_channel` refuses to hand out). The literal is written out
    // so the "all zeros" state is visible at the call site and is overwritten
    // by the `mse_channel` call on the next line, whose `Err` is what the
    // refusal is.
    let mut channel = vendor41::MseChannel { key: [0u8; 32], aad: [0u8; 65] };
    if ops.mse_channel(&mut channel).is_err() {
        return Outcome::plain(Ctap2Response::InvalidParameter);
    }
    let mut key = [0u8; MASTER_SEED_LEN];
    if aead_open(&channel.key, &channel.aad, blob, &mut key).is_err() {
        // A blob this device cannot open is refused, and the lock is **not**
        // engaged. Storing the blob anyway would produce the "engaged but
        // unopenable" device that [`SoftLock`]'s doc exists to make
        // unrepresentable.
        return Outcome::plain(Ctap2Response::OperationDenied);
    }

    // --- all-or-nothing, one call ---
    let lock = match SoftLock::new(&key) {
        Ok(l) => l,
        Err(e) => return Outcome::plain(e),
    };
    if let Err(e) = ops.set_soft_lock(lock) {
        return Outcome::plain(e);
    }
    ops.set_unlocked_this_power_cycle(false);
    Outcome::plain(Ctap2Response::Ok)
}

/// Release the at-rest soft lock: clear the lock record, and refuse unless
/// the seed is already open for this power cycle.
///
/// # The precondition is the client's two-step, not a device policy
///
/// `lock_disable` sends `UNLOCK` first, tolerating `0x00` and `0x3D`
/// ([`mod.rs:1858-1865`]), and only then `authconfig_vendor(RSKEY_AUT_DISABLE,
/// None)` ([`mod.rs:1870-1877`]). So a well-behaved release always arrives
/// with [`VendorOps::unlocked_this_power_cycle`] already `true`.
///
/// A release that arrives without it is refused with
/// [`Ctap2Response::LockRequired`] rather than honoured. The
/// alternative — clearing the lock anyway — is a lock that anyone with a `0x20`
/// token can switch off, which is the same as no lock: the token is a
/// *session* secret the desktop app holds, and the phrase is the thing the
/// user is being asked to remember. `LockRequired` is also the status whose
/// text ("authenticator is locked") is the true one when a human reads the desktop
/// app's error string.
///
/// The **byte** is `0x0A`, not `0x07` (US-1528). `0x07` was a transcription slip
/// and it collided with [`crate::ctap2::Ctap2Command::Reset`], which lives on a
/// different layer entirely — a status and a command opcode must never share a
/// value, because a reader that has lost track of which table it is holding
/// then cannot tell. `CtapError.ERR.LOCK_REQUIRED` and the C SDK's
/// `CTAP1_ERR_LOCK_REQUIRED 0x0a` agree on `0x0A`.
///
/// # `0x3D` is deliberately **not** used here
///
/// It is `UNLOCK`'s "device is not locked", and it is load-bearing in that
/// direction. Reusing it on a different sub-command would put the same byte
/// on the wire for two different meanings, and the client's `0x3D`-means-
/// unlocked reading is written against the `UNLOCK` call specifically.
///
/// # The client sends **no** payload
///
/// `authconfig_vendor(&token, RSKEY_AUT_DISABLE, None)`
/// ([`mod.rs:1872-1873`]) leaves sub-params as `{1: AUT_DISABLE}` and nothing
/// else — the key is chosen by payload *type* ([`ops.rs:1618-1627`]) and
/// there is no payload. A sub-params map carrying `0x02`, `0x03` or `0x04` is
/// therefore **refused**, not ignored: a client that sent one is not the client
/// this protocol defines, and a release that quietly tolerated it would be a
/// release that accepts arguments it does not understand.
///
/// # It clears the unlock flag
///
/// Releasing restores the plaintext seed at rest ([`constants.rs:764`]:
/// *"restore the plaintext seed"*). A `true` `unlocked` afterwards would be a
/// claim that a lock had been opened when the lock no longer exists.
pub fn lock_release(ops: &mut dyn VendorOps, data: &[u8], auth: Option<TokenAuth<'_>>) -> Outcome {
    // --- the gate, before anything is read or written ---
    let params = match config_vendor_gate(data, auth) {
        Ok(p) => p,
        Err(outcome) => return outcome,
    };

    // --- the vendor id, strictly ---
    let id = match vendor_id(params) {
        Ok(id) => id,
        Err(e) => return Outcome::plain(e),
    };
    if id != AUT_DISABLE {
        return Outcome::plain(Ctap2Response::InvalidSubcommand);
    }

    // --- and no payload, which is what the client sends ---
    match payload_present(params) {
        Ok(false) => {}
        Ok(true) => return Outcome::plain(Ctap2Response::InvalidParameter),
        Err(e) => return Outcome::plain(e),
    }

    // --- the precondition: the seed must already be open ---
    if !ops.unlocked_this_power_cycle() {
        return Outcome::plain(Ctap2Response::LockRequired);
    }

    // --- all-or-nothing, one call ---
    if let Err(e) = ops.set_soft_lock(SoftLock::default()) {
        return Outcome::plain(e);
    }
    ops.set_unlocked_this_power_cycle(false);
    Outcome::plain(Ctap2Response::Ok)
}

// ---------------------------------------------------------------------------
// The `0x0D` gate, shared by engage and release.
// ---------------------------------------------------------------------------

/// Verify the `authenticatorConfig` gate and return the **raw bytes** of
/// `subCommandParams`.
///
/// `data` is the CBOR map that followed the `0x0D` opcode byte, i.e. the
/// `{1: subCommand, 2: subCommandParams, 3: pinUvAuthProtocol,
/// 4: pinUvAuthParam}` body ([`constants.rs:192-204`]). The returned slice
/// borrows from `data`.
///
/// # Why this function exists next to [`vendor41::verify_mac`]
///
/// Because the two MAC **constructions** are genuinely different, and one
/// function cannot express both without a flag that means "be wrong".
///
/// ```text
/// 0x41 sub-command:  FF×32 ‖ 0x41 ‖ subCommand ‖ cbor(subCommandParams)   (ops.rs:1581-1586)
/// 0x0D config:       FF×32 ‖ 0x0D ‖ 0xFF      ‖ cbor(subCommandParams)   (ops.rs:1002-1004)
/// ```
///
/// `verify_mac` hard-codes [`vendor41::CMD`] as the command byte and the
/// [`vendor41::Subcommand`] byte as the second, and it refuses any key 1 that
/// is not a `0x41` sub-command — so for an `0x0D` body it answers
/// `0x3E` before it ever compares anything. That is correct behaviour for the
/// channel it was written for and useless here.
///
/// # What is shared, and what must not be re-derived
///
/// The construction is not shared, but the **span** rule is, and it is the
/// only part that produces silent failures. The client MACs
/// `to_vec(&sub_val)` ([`ops.rs:1618`]) — the serialiser's own bytes — so the
/// device must verify against the bytes that arrived, borrowed out of `data`,
/// and never against a re-encoding of a map it rebuilt.
///
/// The failure this prevents is specific and total: a device that
/// re-serialises a *canonical* request produces the same bytes and works; a
/// device that re-serialises a request carrying any non-minimal head, a
/// different key order or a different (still legal) integer width answers
/// `0x33` — "PIN auth invalid" — to a request whose MAC is arithmetically
/// correct, and the user is sent back to the PIN prompt for a token that was
/// never wrong. The host's own `cbor::encode` sorts map keys and re-writes
/// every head canonically ([`crate::cbor`]'s `encode_to`, `Value::M` arm),
/// so a re-encoding implementation is not hypothetical; it is what
/// `app::FidoApp::authenticator_config` does today at `app.rs:1974`
/// (`auth_msg.extend_from_slice(&cbor::encode(params))`).
///
/// Pinned both ways by
/// `tests/vendor_lock.rs::the_config_vendor_mac_is_verified_over_the_clients_own_bytes`.
///
/// # Statuses
///
/// * [`Ctap2Response::PuatRequired`] (`0x36`) — no `auth` token was supplied,
///   or no `pinUvAuthParam` arrived. Never "authorised".
/// * [`Ctap2Response::PinAuthBlocked`] (`0x34`) — the app's latch is set. Not
///   charged: see [`unlock`]'s note, which is the same rule.
/// * [`Ctap2Response::PinAuthInvalid`] (`0x33`) — a param was supplied and did
///   not verify. **Charged**, via [`Outcome::pin_auth_failure`], because a
///   wrong `0x20` token on a vendor-prototype write is exactly the event the
///   app's three-strike counter exists for.
/// * [`Ctap2Response::InvalidSubcommand`] (`0x3E`) — sub-command is not
///   `0xFF` (`CONFIG_SUB_VENDOR_PROTOTYPE`).
/// * [`Ctap2Response::InvalidParameter`] (`0x02`) — `pinUvAuthProtocol` is
///   well-formed and is not `1`. The client hard-codes `1`
///   ([`ops.rs:1645-1648`]).
/// * [`Ctap2Response::UnauthorizedPermission`] (`0x40`) — a token without
///   `AUTHENTICATOR_CONFIG` (`0x20`).
fn config_vendor_gate<'a>(
    data: &'a [u8],
    auth: Option<TokenAuth<'_>>,
) -> Result<&'a [u8], Outcome> {
    // No token is `0x36`, not a fall-through. Spelled out rather than folded
    // into the `?` below for the reason `identity_gate` spells it out: the
    // error arm carries an `Outcome`, and `?` on a `None` here would produce
    // exactly the "no token means no gate" reading.
    let a = match auth {
        Some(a) => a,
        None => return Err(Outcome::plain(Ctap2Response::PuatRequired)),
    };
    if a.blocked {
        return Err(Outcome::plain(Ctap2Response::PinAuthBlocked));
    }

    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Outcome::plain(Ctap2Response::InvalidCbor)),
    };
    let mut sub: Option<u64> = None;
    let mut params_span: Option<(usize, usize)> = None;
    let mut protocol: u64 = 1;
    let mut have_mac = false;
    let mut mac: HeaplessVec<u8, 64> = HeaplessVec::new();

    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor).map_err(plain)?;
        if key == Item::U(CONFIG_PARAM_SUB_COMMAND) {
            if sub.is_some() {
                return Err(Outcome::plain(Ctap2Response::InvalidCbor));
            }
            sub = Some(match p.next() {
                Ok(Item::U(v)) => v,
                // Key 1 present but not an unsigned integer: not the shape
                // this command defines, and coercing it would be guessing.
                _ => return Err(Outcome::plain(Ctap2Response::InvalidCbor)),
            });
        } else if key == Item::U(CONFIG_PARAM_SUB_COMMAND_PARAMS) {
            // Refused on repetition for the same reason `verify_mac` refuses a
            // repeated key 2: the params are **inside** the signed message, so
            // two of them makes "which params was signed" undecidable, and
            // last-wins would decide it silently. It also keeps this function
            // the only place that choice is made.
            if params_span.is_some() {
                return Err(Outcome::plain(Ctap2Response::InvalidCbor));
            }
            let start = p.pos();
            p.skip().map_err(|_| Ctap2Response::InvalidCbor).map_err(plain)?;
            let end = p.pos();
            params_span = Some((start, end));
        } else if key == Item::U(CONFIG_PARAM_PIN_PROTOCOL) {
            // Last-wins, as `verify_mac` does for its key 3: the protocol byte
            // is *outside* the signed message.
            protocol = match p.next() {
                Ok(Item::U(v)) => v,
                _ => return Err(Outcome::plain(Ctap2Response::InvalidCbor)),
            };
        } else if key == Item::U(CONFIG_PARAM_PIN_PARAM) {
            if have_mac {
                return Err(Outcome::plain(Ctap2Response::InvalidCbor));
            }
            have_mac = true;
            mac.clear();
            match p.next() {
                Ok(Item::B(b)) => {
                    mac.extend_from_slice(b)
                        .map_err(|_| Ctap2Response::InvalidLength)
                        .map_err(plain)?
                }
                _ => return Err(Outcome::plain(Ctap2Response::InvalidCbor)),
            }
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor).map_err(plain)?;
        }
    }

    // Protocol 1 is the only one this path defines; the client hard-codes it
    // ([`ops.rs:1645-1648`]). An undefined protocol names a thing this device
    // does not do, which is `0x02` and not a failed MAC.
    if protocol != 1 {
        return Err(Outcome::plain(Ctap2Response::InvalidParameter));
    }
    if !have_mac {
        return Err(Outcome::plain(Ctap2Response::PuatRequired));
    }
    if sub != Some(CONFIG_SUB_VENDOR_PROTOTYPE as u64) {
        return Err(Outcome::plain(Ctap2Response::InvalidSubcommand));
    }

    // The message, byte-exact. 32 + 1 + 1 = 34 fixed bytes, then the params
    // exactly as they arrived. The buffer is 192 to match `verify_mac`'s, so
    // the two channels overflow alike: this path's params are at most
    // `{1: u64, 2: bstr(60)}` = 14 bytes, so the cap is unreachable, and it is
    // sized to the same number anyway rather than to a second opinion.
    let params: &[u8] = match params_span {
        Some((start, end)) => &data[start..end],
        // No key 2 at all. The client always sends one on this path
        // ([`ops.rs:1638-1643`] inserts `sub_val` unconditionally), so this is
        // a shape this firmware does not accept rather than a case.
        None => &[],
    };
    let mut msg: HeaplessVec<u8, 192> = HeaplessVec::new();
    for _ in 0..32 {
        msg.push(0xFF).map_err(|_| Ctap2Response::InvalidLength).map_err(plain)?;
    }
    msg.extend_from_slice(&[CMD_CONFIG, CONFIG_SUB_VENDOR_PROTOTYPE])
        .map_err(|_| Ctap2Response::InvalidLength)
        .map_err(plain)?;
    msg.extend_from_slice(params)
        .map_err(|_| Ctap2Response::InvalidLength)
        .map_err(plain)?;

    if !crate::crypto::pin_verify_auth(1, a.token, &msg, &mac) {
        return Err(Outcome::pin_auth_failure(Ctap2Response::PinAuthInvalid));
    }
    // A `0x20` token is what the client mints
    // ([`mod.rs:1845-1847`], [`mod.rs:1870-1872`]). A token without it is
    // refused, and *after* the MAC: a caller with a valid MAC under the wrong
    // permission is a caller the app should count, and the counter is
    // `Outcome::pin_auth_failure`'s.
    if a.permissions & PERM_ACFG == 0 {
        return Err(Outcome::pin_auth_failure(Ctap2Response::UnauthorizedPermission));
    }
    Ok(params)
}

/// Map a parse status onto a plain `Outcome`, for use with `map_err`.
fn plain(e: Ctap2Response) -> Outcome {
    Outcome::plain(e)
}

/// The 64-bit vendor id (sub-params key 1), strictly.
///
/// `u8::try_from` / range discipline throughout: an id that does not fit the
/// constant it is compared against is a *different* id, and truncating one
/// would let a request for a neighbouring vendor id run the wrong arm.
fn vendor_id(params: &[u8]) -> Result<u64, Ctap2Response> {
    let mut p = Parser::new(params);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut found: Option<Result<u64, Ctap2Response>> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(VENDOR_SUB_PARAM_ID) {
            if found.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            found = Some(match p.next() {
                Ok(Item::U(v)) => Ok(v),
                _ => Err(Ctap2Response::InvalidCbor),
            });
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    found.unwrap_or(Err(Ctap2Response::MissingParameter))
}

/// The sealed blob at sub-params key `0x02` ([`VENDOR_SUB_PARAM_BSTR`]).
fn vendor_blob(params: &[u8]) -> Result<&[u8], Ctap2Response> {
    let mut p = Parser::new(params);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut found: Option<Result<&[u8], Ctap2Response>> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(VENDOR_SUB_PARAM_BSTR) {
            if found.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            found = Some(match p.next() {
                Ok(Item::B(b)) => Ok(b),
                _ => Err(Ctap2Response::InvalidCbor),
            });
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    found.unwrap_or(Err(Ctap2Response::MissingParameter))
}

/// Whether sub-params carries **any** payload key (`0x02`, `0x03` or `0x04`).
///
/// The client's key is chosen by payload type
/// ([`ops.rs:1618-1627`]: `Bytes → 0x02`, `Integer → 0x03`, `Text → 0x04`), so
/// "has a payload" is "has one of the three", not "has `0x02`". Checking only
/// `0x02` would let an `Integer` payload through on a release.
fn payload_present(params: &[u8]) -> Result<bool, Ctap2Response> {
    let mut p = Parser::new(params);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut any = false;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if matches!(key, Item::U(0x02) | Item::U(0x03) | Item::U(0x04)) {
            any = true;
        }
        p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
    }
    Ok(any)
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 (RFC 8439) — see the note in the module docs.
//
// One function, [`aead_open`], is the whole AEAD surface this module needs.
// ---------------------------------------------------------------------------

/// Open a `nonce(12) ‖ ct ‖ tag(16)` blob bound to `aad`, into `out`.
///
/// `out` is exactly [`MASTER_SEED_LEN`] and the blob's plaintext must be
/// exactly that long: the lock key is 32 bytes by construction
/// ([`mod.rs:1836-1838`] fills a `[u8; 32]`), so a blob of any other
/// plaintext length is not one this protocol produced.
///
/// # The tag is at the **end**
///
/// `wrap_secret` calls `backup::chacha_seal`
/// ([`backup.rs:64-77`]), which returns `nonce_b ‖ buf` where `buf` came out
/// of `ring`'s `seal_in_place_append_tag` — appending the tag on the tail. So
/// the order is `ct ‖ tag`, which is *not* what `chacha20poly1305`'s
/// `encrypt` returns (`tag ‖ ct`). That framing split is why this is a call to
/// [`crypto::chacha20poly1305_open_blob`] rather than a one-liner against the
/// crate's own `decrypt`, and it now lives in exactly one place in the
/// firmware instead of one per module.
///
/// `pub` so the integration test can check the opener against external vectors
/// and against every negative direction, rather than only through the two
/// arms that happen to call it. That it is reachable at all is the reason its
/// correctness is checkable from outside this file.
///
/// # What it returns
///
/// Both failure modes collapse to `0x27` ([`Ctap2Response::OperationDenied`])
/// except a length refusal, which is `0x03`. That mapping is this module's,
/// not the primitive's: the seed-export arm answers `0x3D` for the identical
/// cryptographic event, and the AEAD itself is not in a position to have an
/// opinion about which of those a client is told.
pub fn aead_open(
    key: &[u8; 32],
    aad: &[u8],
    blob: &[u8],
    out: &mut [u8; MASTER_SEED_LEN],
) -> Result<(), Ctap2Response> {
    if blob.len() < BLOB_MIN {
        return Err(Ctap2Response::InvalidLength);
    }
    crypto::chacha20poly1305_open_blob(key, aad, blob, out).map_err(|e| match e {
        crypto::AeadError::Length => Ctap2Response::InvalidLength,
        crypto::AeadError::Integrity => Ctap2Response::OperationDenied,
    })
}
