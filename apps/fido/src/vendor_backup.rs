//! US-171 + US-172 (EPIC `PICOForge-COMPAT`) — the seed-backup half of the
//! RS-Key `0x41` channel: **MSE key agreement** (`0x01`), **seed export**
//! (`0x02`), **seed load** (`0x03`) and **finalize** (`0x04`).
//!
//! # What belongs here and what does not
//!
//! This module is **protocol**, the same split `vendor41` documents: it parses
//! the request, decides, and reports an [`Outcome`] plus a response body in a
//! caller-owned buffer. Every durable byte goes through
//! [`vendor41::VendorOps`], because a durable commit has to be transactional
//! against the whole snapshot and only the dispatch arm that owns the keystore
//! can promise that. Nothing here opens a store.
//!
//! The coordinator wires the four arms into `handle_subcommand` and drops their
//! entries from `vendor41::PENDING`; each function's docs name its exact call.
//!
//! # What `mse_establish` already did, and what this module therefore does not
//!
//! The brief for US-171 reads as though the ECDH and the HKDF were to be built
//! here. They are not, and re-deriving them would be a *second* implementation
//! of a byte-exact construction — the exact hazard
//! [`vendor41::derive_mse_channel`] exists to prevent.
//! [`vendor41::VendorOps::mse_establish`] runs the ephemeral ECDH, runs the
//! HKDF, and parks the result in the session. This module's [`mse`] only
//!
//! * parses the host's COSE key out of the request, and
//! * serialises the device's own point back.
//!
//! Two corrections to a naive reading of RFC 8152 are inherited, not
//! re-decided:
//!
//! * The COSE `alg = -25` is **not** honoured as an HKDF parameter set. The
//!   client derives the channel with
//!   `HKDF-SHA256(salt = b"", ikm = z, info = device_point, L = 32)` and
//!   nothing else (`picoforge/src/hal/fido/backup.rs:32-40`); `PartyVInfo` /
//!   `SuppPubInfo` never appear anywhere. `vendor41::derive_mse_channel` is
//!   this firmware's copy of that, and it is what `mse_establish` calls.
//! * The **device's own point** is the HKDF `info` **and** the
//!   ChaCha20-Poly1305 **AAD** for every later seal and open — one value, two
//!   jobs, from two lines of the client: `let aad = peer.clone();` and
//!   `let aad_kdf = aad.clone();` (`picoforge/src/hal/fido/mod.rs:1724-1729`).
//!   Getting one right and the other wrong yields a blob that opens to garbage
//!   on the host while every local check passes, which is why
//!   [`vendor41::MseChannel`] carries the two as one struct: an arm asks the
//!   state for the pair and cannot be handed one without the other.
//!
//! # The non-canonical COSE label order
//!
//! PicoForge builds the host's key through `BTreeMap<Value, Value>`
//! (`picoforge/src/hal/fido/mod.rs:1698-1706`) and writes the map in ascending
//! key order, so the labels reach the wire as **`-3, -2, -1, 1, 3`** — which is
//! *not* RFC 8152 canonical order (canonical sorts the unsigned labels `1, 3`
//! ahead of the negative `-1, -2, -3`). [`cose_key_from_params`] therefore
//! **never assumes an order**: it walks the map and picks labels out by value.
//! The same parser is what makes the firmware accept the *canonical* order,
//! `alg = -7`, and any extra label the client might grow — the US-120 tolerance
//! stated in `lib.rs`.
//!
//! # The returned point must be 65 bytes and on the curve
//!
//! The client reads only `-2` and `-3` and reassembles `0x04 ‖ x ‖ y` itself
//! (`picoforge/src/hal/fido/mod.rs:1711-1723`), then hands those 65 bytes
//! straight to `ring::agreement::UnparsedPublicKey::new(ECDH_P256, …)`. A
//! 33-byte compressed point, a 33-byte coordinate, or a pair that is not on
//! P-256 is rejected **by the host**, not by us — the user sees "ECDH
//! agreement failed" on a device that answered `0x00`. So [`mse`] writes
//! exactly 32 bytes per coordinate, taken from the single `PublicKey` that
//! `mse_establish` derived both from; they cannot be individually well-formed
//! and jointly off-curve.
//!
//! # The authenticated-params trap, and the type that makes it unreachable
//!
//! [`vendor41::verify_mac`] assembles the signed message as
//!
//! ```text
//! 0xFF × 32 ‖ 0x41 ‖ subCommand ‖ CBOR(subCommandParams)
//! ```
//!
//! (`picoforge/src/hal/fido/ops.rs:1581-1588` — note the `0x41`, the RS-Key
//! vendor command, not the stock `0x0D`) and verifies it over the **wire
//! bytes** of `subCommandParams`, which it hands back to the caller. When
//! `subCommandParams` is absent the tail is empty, so `EXPORT` and `FINALIZE`
//! work with no params at all — a first-class outcome there, not a malformed
//! request.
//!
//! The trap is `LOAD`. Its params are `{1: sealed_blob}` — 4 bytes of CBOR head
//! plus a 60-byte blob. An arm that **decoded the map and re-encoded it**
//! would produce different bytes whenever the client's encoding differs from
//! this firmware's writer in any way that is legal in both (map head style, an
//! integer key width, a bstr head form), and the MAC would then fail with
//! `0x33` for a request whose MAC is perfectly correct. No host can debug
//! that and no user can work around it.
//!
//! So this module does not accept "the params" as a value. It accepts
//! [`WireParams`], a newtype with **no public constructor**, produced only by
//!
//! * [`backup_auth`] — which calls `verify_mac` and therefore only ever holds
//!   the span the MAC was just checked over, or
//! * [`ungated_params`] — the same borrow, for the one sub-command the client
//!   sends unauthenticated.
//!
//! An arm that wants the blob must first go through the gate, and the bytes it
//! then sees are by construction the bytes the client signed. There is no code
//! path in which a decoded-then-re-encoded map reaches a MAC check.
//! `tests/vendor_backup.rs::load_accepts_a_mac_over_the_clients_own_bytes`
//! drives a hand-assembled request whose params this crate never encoded.
//!
//! # Why the AEAD is a thin adapter over a crate
//!
//! [`chacha20poly1305_seal`] and [`chacha20poly1305_open`] used to be ~180
//! lines of RFC 8439 arithmetic written out here, and the same cipher was
//! independently hand-rolled a second time in [`crate::vendor_lock`] and a
//! third time in [`crate::vendor_att`]. Each copy was individually correct —
//! and each one was a real review liability: a block cipher in a security
//! applet is code a reader has to *check*, not code a reader can trust, and
//! three correct copies of it means three times the checking for redundancy
//! that buys nothing, because a nonce reuse or a key-mixing mistake would fail
//! all three together.
//!
//! They are now one implementation, [`crate::crypto::chacha20poly1305_seal`]
//! / [`crate::crypto::chacha20poly1305_open`], over the `chacha20poly1305`
//! crate. The two functions here keep their names and their signatures and do
//! exactly two jobs: they name the channel's framing, and they map
//! [`crypto::AeadError`] onto the CTAP2 status `0x41` is specified to answer.
//!
// The wire format is unchanged and unchangeable — it is the client's
//! (`nonce(12) ‖ ct ‖ tag(16)`, AAD = the device's point,
//! `picoforge/src/hal/fido/backup.rs:61-78`). The collapse changed no byte on
//! any wire, which is what let the RFC 8439 vectors in
//! `tests/vendor_backup.rs` be re-pointed at the crate and still pass
//! unchanged: §2.3.2 (block function), §2.5.2 (Poly1305) and §2.8.2 (the full
//! AEAD) are now a check that the *dependency* behaves, rather than a check
//! that our arithmetic does. That is a strictly better place for them to be —
//! and it is the reason the vectors were worth keeping through the change.
//!
//! # Statuses
//!
//! * `EXPORT` on a **sealed** device → [`Ctap2Response::NotAllowed`] (`0x30`).
//! * `EXPORT` on a device with **no seed** → `0x30`, and this is not a guess:
//!   the client's error table has a dedicated `0x30` branch spelled *"operation
//!   not allowed (already sealed, or no OTP DEVK provisioned)"*
//!   (`picoforge/src/hal/fido/mod.rs:1527`).
//!
//! ## Why "no seed" must be a refusal and not a 32-zero-byte seed
//!
//! The tempting alternative is to seal 32 zero bytes. The client's happy path
//! (`picoforge/src/hal/fido/mod.rs:1775-1778`) is `chacha_open` →
//! `try_into::<[u8; 32]>` → `seed_to_mnemonic`, and 32 zero bytes *are* valid
//! 32-byte BIP-39 entropy. The host would render a real, correctly-checksummed,
//! completely meaningless 24-word phrase for the user to write down, and
//! restoring it later would install 32 zero bytes as the device's master seed.
//! A device with no seed has to answer with a status the client already
//! renders as "there is nothing to export here", and that status is `0x30`.
//!
//! * `LOAD` with a blob that fails authentication →
//!   [`Ctap2Response::IntegrityFailure`] (`0x3D`); nothing is written.
//! * `LOAD`/`EXPORT` with a plaintext that is not exactly [`MASTER_SEED_LEN`]
//!   bytes → [`Ctap2Response::InvalidLength`] (`0x03`).
//! * `FINALIZE` with no touch → [`Ctap2Response::UpRequired`] (`0x3B`).

use crate::cbor::no_heap::{self, Item, Parser};
use crate::ctap2::Ctap2Response;
use crate::vendor41::{
    authorize, MseChannel, Outcome, PresenceGate, Subcommand, TokenAuth, VendorOps,
    LOCK_BLOB_MAX, P256_POINT_LEN,
};
// Re-exported rather than used privately so the arm code and the tests can
// both name "the seed is 32 bytes" from *this* module, which is the module that
// enforces it. The value is `vendor41`'s — this is a re-export, not a second
// definition, because a second literal is a second thing to keep in step.
pub use crate::vendor41::MASTER_SEED_LEN;
use crate::CTAP2_MAX_MSG;
use heapless::Vec as HeaplessVec;

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// ChaCha20-Poly1305 nonce width (RFC 8439 §2.8).
pub const NONCE_LEN: usize = 12;

/// Poly1305 tag width (RFC 8439 §2.8).
pub const TAG_LEN: usize = 16;

/// **The minimum legal sealed blob**: `nonce(12) ‖ ct(0) ‖ tag(16)` = 28.
///
/// This is `backup.rs:46-48`'s own floor (`if nonce_and_ct.len() < 12 + 16`),
/// not the 60 bytes a 32-byte payload happens to produce. The two are
/// different numbers and only the first is a rule: a 30-byte blob carrying a
/// 2-byte payload is a legal AEAD message, and bounding at 60 would refuse it.
/// A 28-byte blob is legal too — it is a zero-length plaintext — so the
/// structural check stops at 28 and the *plaintext length* check is a separate,
/// later decision with its own reason. Both are pinned by
/// `tests/vendor_backup.rs::load_bounds_the_blob_at_28_not_at_60`.
pub const BLOB_MIN: usize = NONCE_LEN + TAG_LEN;

/// **The maximum sealed blob this firmware accepts**, 64.
///
/// Deliberately [`LOCK_BLOB_MAX`] and **not** 60. 60 is what a 32-byte payload
/// produces; 64 is the protocol's room for a nonce-version prefix or a future
/// tag width, and it is the same bound the at-rest soft-lock record already
/// uses. An arm that bounded this at 32 — or at 60 — would refuse well-formed
/// requests for a reason no document states.
pub const BLOB_MAX: usize = LOCK_BLOB_MAX;

/// The largest plaintext this channel ever seals or accepts:
/// `BLOB_MAX - NONCE_LEN - TAG_LEN` = 36. The protocol only ever carries
/// [`MASTER_SEED_LEN`], so this is slack, and the slack is bounded here rather
/// than at every use site.
pub const PT_MAX: usize = BLOB_MAX - NONCE_LEN - TAG_LEN;

/// A sealed backup blob in the `nonce(12) ‖ ct ‖ tag(16)` framing.
pub type Blob = HeaplessVec<u8, BLOB_MAX>;

/// The response buffer the `0x41` channel writes into.
pub type Reply = HeaplessVec<u8, CTAP2_MAX_MSG>;

// ---------------------------------------------------------------------------
// The `FINALIZE` latch — the one thing `VendorOps` does not have yet
// ---------------------------------------------------------------------------

/// The durable "the one-time export window is closed" flag, as a separate
/// trait.
///
/// # Why this is not on [`VendorOps`] today, and what has to happen
///
/// `FINALIZE` is the only sub-command in the whole set whose entire effect is a
/// bit, and that bit has no home. [`VendorOps`] has fifteen methods and nothing
/// in it that is not key material or a journal — `master_seed`, `lock`,
/// `org_scalar`, `audit_key`, the audit window. Adding a plain `bool` to that
/// trait would be a new *kind* of member.
///
/// # The reconciliation, in full
///
/// This module's four arms take a single `&mut dyn [`BackupOps`]`, where
/// [`BackupOps`] is `VendorOps + BackupWindow` with a blanket impl. So the
/// coordinator's work is exactly three edits, and **no trait-hierarchy
/// surgery**:
///
/// 1. `vendor_state.rs`: add `impl BackupWindow for KeystoreVendorOps` and
///    `impl BackupWindow for MemoryVendorOps`, two method bodies each, reading
///    and writing `VendorPublic::sealed` through the same `commit(…)` helper
///    every other mutating method already uses.
/// 2. `VendorPublic`: add `sealed: bool` (default `false`) plus its codec pair.
/// 3. `vendor41.rs`: change the `ops` parameter type of `handle` and
///    `handle_subcommand` from `&mut dyn VendorOps` to
///    `&mut dyn crate::vendor_backup::BackupOps` — one word in each signature.
///
/// Adding the two methods to `VendorOps` itself was considered and rejected:
/// `handle` is the module's single dispatch seam, and the two `VendorOps`
/// implementations are in a *different* file, so putting the methods on the
/// trait means the trait grows a member that is neither key material nor a
/// journal while `BackupWindow` still has to exist for this module to compile
/// — two declarations of one thing instead of one. A **second parameter** was
/// also rejected, and this is worth recording because it is a compile error
/// rather than a matter of taste: passing `&mut ops` for both
/// `ops: &mut dyn VendorOps` and `window: &mut dyn BackupWindow` is two
/// mutable borrows of one object in one call, and Rust rejects it — so a
/// two-parameter signature could never be called with the object the
/// implementation already is.
///
/// # What the implementation has to store, and where
///
/// `VendorPublic::sealed: bool`, defaulting to `false`.
///
/// The **public** half, not the sealed one: the bit is not secret, and
/// `VendorPublic` is a fixed-size struct whose codec counts its own pairs, so
/// adding one bool is a new pair in a map header and one field read — with
/// `false` as the default, `VendorPublic::is_empty()` is unchanged and a device
/// that has never seen a `0x41` still writes a **byte-identical** snapshot to
/// one written before this feature existed. Putting it in `VendorSecret` would
/// be wrong twice over: it would change `VendorSecret::is_empty()`'s answer for
/// every existing device, and a flag that decides whether the seed may leave
/// the device has no business living behind the store encryption.
///
/// The setter must be **idempotent and all-or-nothing**, like every other
/// mutating method on the trait: `Ok(())` from [`BackupWindow::seal_backup`]
/// means the bit is durable, and sealing an already-sealed device succeeds
/// without a write.
pub trait BackupWindow {
    /// Whether `FINALIZE` has permanently closed the one-time export window.
    ///
    /// **This is the same bit US-170's `STATE` sub-command reports as its
    /// `sealed` field** (`{1: sealed, …}`, read at
    /// `picoforge/src/hal/fido/mod.rs:1737-1750`). Two stories, one field; the
    /// coordinator reconciles them. This module assumes:
    ///
    /// * US-170 reads it through this same trait method rather than reaching
    ///   into `VendorPublic` itself, so there is exactly one accessor, and
    /// * the value is **durable** — it must survive the power cycle that a
    ///   `VendorSession::clear` simulates — so it lives in `VendorPublic` and
    ///   not in the volatile session.
    ///
    /// If US-170 has already put a `sealed` flag on the trait under a
    /// different name, the merge is a rename plus deleting this declaration —
    /// and the semantics above are what has to survive the rename.
    fn backup_sealed(&self) -> bool;

    /// Permanently close the one-time export window, durably.
    ///
    /// All-or-nothing: `Ok(())` means the bit is durable, and on `Err` the
    /// state is byte-for-byte what it was. A window that reported itself open
    /// after a failed `FINALIZE` is the one state where the user's "yes, seal
    /// it" was acknowledged and did not happen.
    ///
    /// Idempotent: sealing an already-sealed device is `Ok(())` and writes
    /// nothing. The client shows nothing at all for `FINALIZE` — it just
    /// reports "Export window sealed." — so there is no status a host could
    /// usefully distinguish, and a second press failing would be a worse answer
    /// than a second press succeeding.
    fn seal_backup(&mut self) -> Result<(), Ctap2Response>;
}

/// Everything the four `0x41` backup arms need from the state: the
/// [`VendorOps`] operations, plus the [`BackupWindow`] latch.
///
/// # Why one trait and not two parameters
///
/// Because a `VendorOps` implementation *also* implements `BackupWindow`, it is
/// one object, and an arm that took it twice — once as `&mut dyn VendorOps` and
/// once as `&mut dyn BackupWindow` — would be asking for two mutable borrows of
/// the same object in one call. That is a compile error, so the two-parameter
/// shape is not merely inelegate, it is uncallable. This trait is the
/// single-object answer, and the blanket impl is what makes it free: an
/// implementor writes `impl BackupWindow for TheirOps` and nothing else.
///
/// [`VendorOps::mse_establish`]: crate::vendor41::VendorOps::mse_establish
pub trait BackupOps: VendorOps + BackupWindow {}

impl<T: VendorOps + BackupWindow + ?Sized> BackupOps for T {}

// ---------------------------------------------------------------------------
// The params span — the type that makes re-encoding unreachable
// ---------------------------------------------------------------------------

/// The `subCommandParams` value **as the bytes that arrived**, borrowed from the
/// request.
///
/// A newtype with a private field and **no public constructor**. It is produced
/// by exactly two functions, both of which hand back a span read out of the
/// request map rather than built:
///
/// * [`backup_auth`] — for `EXPORT` and `LOAD`, which the client authenticates.
///   The span comes from `vendor41::verify_mac`, i.e. it is the span the MAC
///   was computed over.
/// * [`ungated_params`] — for `MSE`, which the client sends with no token at
///   all (`picoforge/src/hal/fido/mod.rs:1709`; `constants.rs:734-736` lists
///   `MSE` among the ungated sub-commands).
///
/// The name is deliberately *not* "authenticated params": it is the same type
/// for a request nobody authenticated, because what it guarantees is the same
/// property either way — **these are the bytes that arrived, not a
/// re-encoding of them.** That property is what a MAC must cover, and it is
/// the one a `Value` round-trip destroys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireParams<'a> {
    bytes: &'a [u8],
}

impl<'a> WireParams<'a> {
    /// The raw CBOR of the params value, borrowed from the request.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Whether the request carried no `subCommandParams` at all.
    ///
    /// An empty slice is **not** the same as "not supplied" at the CBOR level,
    /// and both are refusals for a sub-command that needs params — but they
    /// are different refusals and a caller that cares can tell them:
    /// `as_bytes().is_empty()` is true for both, while this is only true for a
    /// genuinely absent key 2. `EXPORT` and `FINALIZE` legitimately arrive with
    /// the key absent, which is why neither of them calls this.
    pub const fn is_absent(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The `subCommandParams` span of a request the client sends **unauthenticated**.
///
/// The same borrow [`backup_auth`] makes, without the gate. Only `MSE` uses it
/// (see the module docs on which sub-commands the client authenticates).
pub fn ungated_params(data: &[u8]) -> Result<WireParams<'_>, Outcome> {
    match params_span(data) {
        Ok(bytes) => Ok(WireParams { bytes }),
        Err(e) => Err(Outcome::plain(e)),
    }
}

/// The "PIN token if there is one, otherwise a physical touch" gate, applied to
/// the sub-commands the client authenticates.
///
/// # What the client actually does
///
/// `rs_key_vendor` attaches a `PERM_ACFG` token **only** when its `pin`
/// argument is `Some`; `backup_export` and `backup_restore` pass
/// `pin.as_deref()` (`picoforge/src/hal/fido/mod.rs:1771`, `:1797`), and the
/// client's own comment at `ops.rs:1573-1575` says that without a PIN *"the
/// firmware gates on a physical touch instead, so no auth fields are sent"*.
/// So both cases are legitimate and must be answered differently:
///
/// * a token was supplied → it must carry `PERM_ACFG` and the MAC over the
///   **wire** params must verify. A bad MAC is `0x33` and **is** charged
///   against the app's three-strike counter ([`Outcome::pin_auth_failure`]); a
///   `CREDENTIAL_MANAGEMENT`-only token is `0x40`; a set latch is `0x34` and is
///   **not** charged, for the reason `vendor41::identity_gate` argues at
///   length;
/// * no token → the presence window. Absent one, [`Ctap2Response::UpRequired`],
///   which the HID task answers by opening the window and re-driving the
///   command with a grant, exactly as it does for `makeCredential` and for a
///   benign-tier `CONFIG_WRITE`.
///
/// # The return value is the reason this function exists
///
/// It hands back a [`WireParams`], so an arm cannot reach the params without
/// having gone through the gate, and cannot hold bytes other than the ones
/// `verify_mac` just checked. See the module docs.
///
/// # Why `sub` is a parameter
///
/// The signed message embeds the sub-command byte (`0x41 ‖ sub`), so the MAC
/// for a `LOAD` does not verify as an `EXPORT`. Passing `sub` in rather than
/// re-deriving it means the gate and the arm cannot disagree about which
/// sub-command is being authenticated.
pub fn backup_auth<'a>(
    data: &'a [u8],
    sub: Subcommand,
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
) -> Result<WireParams<'a>, Outcome> {
    let a = match auth {
        Some(a) => a,
        // No token: the client is documented to fall back to a touch, so the
        // window is the gate. `0x3B` (and not `0x36`) is the status that means
        // "ask the human" — the HID task's `UpRequired` retry loop owns that
        // lifecycle. `0x36` is the status for "you sent no usable auth" and
        // would send a user who is *about to be prompted* back to the PIN
        // screen instead.
        None => {
            if !presence.granted() {
                return Err(Outcome::plain(Ctap2Response::UpRequired));
            }
            // A touch-gated request carries no `pinUvAuthParam` at all, so
            // there is nothing to verify and nothing to hand the arm beyond
            // the raw span.
            return ungated_params(data);
        }
    };
    if a.blocked {
        // The app's PIN-auth lockout latch. Deliberately **not** charged: the
        // device is refusing all pinUvAuth, and a charge would move the status
        // the app would have returned (`0x34`) into a `0x33` that tells the
        // client its token was wrong. `vendor41::identity_gate` says this at
        // length and `tests/vendor41.rs` names the test.
        return Err(Outcome::plain(Ctap2Response::PinAuthBlocked));
    }
    let params = match crate::vendor41::verify_mac(data, Some(a.token)) {
        Ok(p) => p,
        // Only a genuine authentication failure is charged. A malformed body,
        // or one declaring a protocol this channel does not define, never
        // reached a comparison against anything secret.
        Err(Ctap2Response::PinAuthInvalid) => {
            return Err(Outcome::pin_auth_failure(Ctap2Response::PinAuthInvalid))
        }
        Err(e) => return Err(Outcome::plain(e)),
    };
    // A legacy `getPinToken` token arrives as `Some(0)` and is refused here.
    // That is the boundary `vendor41::authorize` documents; an arm cannot
    // widen it.
    if let Err(e) = authorize(sub, Some(a.permissions)) {
        return Err(Outcome::plain(e));
    }
    Ok(WireParams { bytes: params })
}

/// The span of CBOR key `2` in the outer request map, borrowed from `data`.
///
/// A second key 2 is refused rather than last-wins, for the reason
/// `verify_mac` refuses one: the params are **inside** the signed message, so
/// two of them makes "which params was signed" undecidable, and a silent
/// choice would be a choice an attacker could make.
fn params_span(data: &[u8]) -> Result<&[u8], Ctap2Response> {
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
            span = Some((start, p.pos()));
        } else {
            // Exactly **one** skip: the key was already consumed by the `next()`
            // above, so this walks the *value*. Two skips here — the reading
            // this file briefly had, on the theory that a map is key/value
            // pairs and an unhandled pair is two items — eats the next pair's
            // key and answers `0x12` to a perfectly well-formed request.
            // `vendor41::verify_mac` gets this right for the same reason.
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    // A genuinely absent key 2 is an empty span, not an error: that is how
    // `EXPORT`, `FINALIZE` and `MSE`'s outer map are all sent. What the *arm*
    // then decides to do about an empty span is its own business, and each of
    // the three says so out loud.
    Ok(match span {
        Some((start, end)) => &data[start..end],
        None => &[],
    })
}

// ---------------------------------------------------------------------------
// US-171 — `MSE` (0x01)
// ---------------------------------------------------------------------------

/// `MSE` — establish the ephemeral-ECDH backup channel and answer with the
/// device's own P-256 point.
///
/// Request: `subCommandParams` = `{1: COSE_Key}` where the COSE key is
/// `{1: 2, 3: -25, -1: 1, -2: x(32), -3: y(32)}` — in whatever label order the
/// client serialised it (see the module docs; it is **not** canonical).
///
/// Response: `{1: COSE_Key}` of the **device's** point, `-2` = x and `-3` = y
/// as 32-byte strings. The client reassembles `0x04 ‖ x ‖ y` and uses it both
/// as the HKDF `info` and as the AAD for every later seal/open.
///
/// **Ungated by protocol** (`picoforge/src/hal/fido/constants.rs:734-736`:
/// *"MSE / STATE / UNLOCK are not"*), which is why this is the one function on
/// the channel that does not call [`backup_auth`]. It still needs `ops`, and
/// not for an authorisation reason: [`VendorOps::mse_establish`] is where the
/// ephemeral scalar, the ECDH and the HKDF live, and the channel it parks there
/// is the one every later seal and open uses. A `MSE` that derived a point and
/// did not record it would be a channel that decrypts nothing.
///
/// The dispatch arm calls `mse(data, out, ops)`, and the return is an
/// [`Outcome`] exactly as for every other arm.
pub fn mse(data: &[u8], out: &mut Reply, ops: &mut dyn VendorOps) -> Outcome {
    let params = match ungated_params(data) {
        Ok(p) => p,
        Err(o) => return o,
    };
    if params.is_absent() {
        // A well-formed map that simply has no `{1: COSE}` is a missing
        // parameter, not a malformed body — the same distinction
        // `extract_subcommand` draws.
        return Outcome::plain(Ctap2Response::MissingParameter);
    }
    let (hx, hy) = match cose_key_from_params(params.as_bytes()) {
        Ok(p) => p,
        Err(e) => return Outcome::plain(e),
    };
    // A local `MsePoint` rather than writing straight into `out`: the body is
    // assembled only once the handshake succeeded, so a failure cannot leave a
    // half-written COSE key behind a non-zero status.
    let mut point = crate::vendor41::MsePoint::default();
    // `mse_establish` refuses an off-curve host point with `0x02` — it runs
    // the point through `parse_cose_ec2_p256_bytes` before drawing any scalar,
    // so a rejected point costs no entropy and no key material. The
    // alternative would be a device that answers `0x00` to a point the host
    // cannot then use.
    if let Err(e) = ops.mse_establish(hx, hy, &mut point) {
        return Outcome::plain(e);
    }
    write_mse_response(out, &point)
}

/// The `mse` body: `{1: {1:2, 3:-25, -1:1, -2:x, -3:y}}`, labels in the client's
/// own order.
fn write_mse_response(
    out: &mut Reply,
    point: &crate::vendor41::MsePoint,
) -> Outcome {
    let write = (|| -> Result<(), Ctap2Response> {
        // Outer: one pair.
        no_heap::push_map_header(out, 1).map_err(cbor_err)?;
        no_heap::push_uint(out, 1).map_err(cbor_err)?;
        // Inner: five labels, in the order `BTreeMap<Value, Value>` emits them.
        no_heap::push_map_header(out, 5).map_err(cbor_err)?;
        no_heap::push_neg(out, -3).map_err(cbor_err)?;
        no_heap::push_bstr(out, &point.y).map_err(cbor_err)?;
        no_heap::push_neg(out, -2).map_err(cbor_err)?;
        no_heap::push_bstr(out, &point.x).map_err(cbor_err)?;
        // The crv **label** is -1 and its value is 1; the kty label is 1 and
        // its value 2; the alg label is 3 and its value -25. So two of the
        // three labels are negative and one is not — and `push_neg(out, 3)`
        // for the last of them is the mistake this comment exists for:
        // `push_neg` takes the *CBOR value* and writes `-1 - v`, so passing
        // the label `3` writes a negative integer 2^64 - 4 behind a nine-byte
        // head. The response is then a well-formed CBOR map that no client can
        // read, from a device that answered `0x00`.
        no_heap::push_neg(out, -1).map_err(cbor_err)?;
        no_heap::push_uint(out, 1).map_err(cbor_err)?; // crv = P-256
        no_heap::push_uint(out, 1).map_err(cbor_err)?; // kty label
        no_heap::push_uint(out, 2).map_err(cbor_err)?; // kty = EC2
        no_heap::push_uint(out, 3).map_err(cbor_err)?; // alg label
        no_heap::push_neg(out, i64::from(crate::COSE_ALG_ECDH_ES_HKDF_256)).map_err(cbor_err)
    })();
    match write {
        Ok(()) => Outcome::plain(Ctap2Response::Ok),
        // A failed body is not a `0x00` with a partial map: the buffer is
        // cleared so nothing partial can ride along behind a non-zero status,
        // which the client would not parse anyway. Same rule as
        // `vendor41::config_read`.
        Err(e) => {
            out.clear();
            Outcome::plain(e)
        }
    }
}

/// Pull `x` and `y` out of `{1: {1: kty, 3: alg, -1: crv, -2: x, -3: y}}`.
///
/// **Order-independent on purpose.** The client's labels arrive as
/// `-3, -2, -1, 1, 3` because it built the map in a `BTreeMap`; RFC 8152
/// canonical order is `1, 3, -1, -2, -3`; and this firmware's own encoder
/// writes a third order. All three are the same map, and an arm that read them
/// positionally would fail against one of them. The walk below is by label
/// value and has no positional assumption at all.
///
/// # Which labels are load-bearing
///
/// Only `-2` and `-3`. `1` (kty), `3` (alg) and `-1` (crv) are **ignored**, for
/// the reason `lib.rs`'s COSE comment states at length (US-120): the two COSE
/// keys PicoForge sends disagree with each other — its `clientPin`
/// key-agreement map carries `alg = -7` (`ops.rs::encode_cose_key`) while this
/// MSE key correctly carries `-25` — and an `alg` check would break interop
/// with the client that has to work. Unknown labels are skipped, not refused,
/// so a client that grows the map keeps working.
///
/// # What *is* refused
///
/// * a body that is not a CBOR map → `0x12`;
/// * a repeated `-2` or `-3` → `0x12` (ambiguous, and "last wins" would be a
///   silent choice about key material);
/// * a `-2` or `-3` that is not a byte string → `0x12`; that is not exactly
///   **32** bytes → `0x03`. **32 exactly**, because a 33-byte compressed point
///   or a 33-byte coordinate is what the host would hand to
///   `UnparsedPublicKey::new(ECDH_P256, …)` and be rejected by — while a
///   truncating copy here would produce a pair that is on *no* curve and a
///   `0x00` that the user reads as a broken host;
/// * a well-formed map missing one of the two → `0x14`.
fn cose_key_from_params(params: &[u8]) -> Result<([u8; 32], [u8; 32]), Ctap2Response> {
    let mut p = Parser::new(params);
    let outer = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    // The COSE key hangs off label 1, and only 1.
    let mut inner: Option<&[u8]> = None;
    for _ in 0..outer {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(1) {
            if inner.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            let start = p.pos();
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
            inner = Some(&params[start..p.pos()]);
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    let inner = inner.ok_or(Ctap2Response::MissingParameter)?;

    let mut q = Parser::new(inner);
    let pairs = match q.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut x: Option<[u8; 32]> = None;
    let mut y: Option<[u8; 32]> = None;
    for _ in 0..pairs {
        let key = q.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::N(-2) {
            if x.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            x = Some(coord32(q.next().map_err(|_| Ctap2Response::InvalidCbor)?)?);
        } else if key == Item::N(-3) {
            if y.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            y = Some(coord32(q.next().map_err(|_| Ctap2Response::InvalidCbor)?)?);
        } else {
            // kty, alg, crv, and anything the client grows: skipped, never
            // refused. See the doc comment. One skip — the value, the key
            // having been consumed by `next()`.
            q.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    match (x, y) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(Ctap2Response::MissingParameter),
    }
}

/// One COSE EC2 coordinate: a byte string of exactly 32 bytes.
///
/// The length is checked with `try_into` rather than a truncating copy — see
/// the doc comment for why a 33-byte value is `0x03` and not a silent prefix.
fn coord32(item: Item<'_>) -> Result<[u8; 32], Ctap2Response> {
    match item {
        Item::B(b) => b.try_into().map_err(|_| Ctap2Response::InvalidLength),
        // A *number* where a byte string belongs: `0x12`, not `0x03`. The
        // request is not the shape the protocol defines, which is a different
        // thing from a shape of the wrong size.
        _ => Err(Ctap2Response::InvalidCbor),
    }
}

// ---------------------------------------------------------------------------
// US-172 — `EXPORT` (0x02)
// ---------------------------------------------------------------------------

/// `EXPORT` — return the master seed, sealed under the MSE channel.
///
/// No params. Authenticated by a `PERM_ACFG` token, or by a physical touch
/// when there is none — see [`backup_auth`]. Response `{1: sealed_blob}`, where
/// the blob is `nonce(12) ‖ ct(32) ‖ tag(16)` = 60 bytes, **sender-chosen
/// nonce**, ChaCha20-Poly1305, AAD = the device's own point.
///
/// # Why the nonce is the *sender's*
///
/// `backup_restore` draws its own 12 random bytes and puts them at the front
/// of the blob it sends (`picoforge/src/hal/fido/mod.rs:1793-1795`); and
/// `backup_export` reads the device's nonce out of the blob it was handed. So
/// the framing is nonce-first and **sender-chosen in both directions**, which
/// is why this function writes the nonce it drew into the response rather than
/// expecting one in the request. A nonce is never reused under one key because
/// the key is per-`MSE`-session and the session's ephemeral scalar is fresh per
/// session (`vendor_state::mse_establish`); within a session, two exports draw
/// two independent nonces from [`VendorOps::random_bytes`].
///
/// # What it refuses, and why "no seed" is a refusal
///
/// * **sealed** → `0x30`. The client has a dedicated `0x30` branch for exactly
///   this: *"operation not allowed (already sealed, or no OTP DEVK
///   provisioned)"* (`picoforge/src/hal/fido/mod.rs:1527`).
/// * **no seed** → `0x30`, for the reason spelled out in the module docs: a
///   32-byte all-zero plaintext is valid 32-byte BIP-39 entropy, and the host
///   would render a correctly-checksummed, completely meaningless 24-word
///   phrase. There is no "honest" 32-byte answer to "I have no seed".
/// * **no `MSE` session** → `0x02` (from `mse_channel`), which is a skipped
///   step rather than a bad value.
///
/// The `phy` proposal is never set: there is nothing to commit, because
/// `EXPORT` only reads and the one state it consults is read through the trait.
pub fn export(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
    out: &mut Reply,
    ops: &mut dyn BackupOps,
) -> Outcome {
    // The gate first, always, and before either state read. A request that
    // failed authentication must not be answered with a fact about the device
    // it was not authorised to learn — including whether the window is open.
    let _params = match backup_auth(data, Subcommand::Export, auth, presence) {
        Ok(p) => p,
        Err(o) => return o,
    };
    if ops.backup_sealed() {
        return Outcome::plain(Ctap2Response::NotAllowed);
    }
    let seed = match ops.master_seed() {
        Some(s) => s,
        // No seed ⇒ no honest 32 bytes. See the doc comment.
        None => return Outcome::plain(Ctap2Response::NotAllowed),
    };
    let mut channel = MseChannel { key: [0u8; 32], aad: [0u8; P256_POINT_LEN] };
    if let Err(e) = ops.mse_channel(&mut channel) {
        return Outcome::plain(e);
    }

    // A fresh nonce per export, from the same entropy the ephemeral scalar came
    // from. A *zero* nonce is the classic repeat-a-nonce-under-a-key failure
    // and it is invisible on the wire, so it is drawn rather than defaulted.
    let mut nonce = [0u8; NONCE_LEN];
    ops.random_bytes(&mut nonce);

    // The wire blob is `nonce(12) ‖ ct(32) ‖ tag(16)` = 60 bytes, and the
    // nonce is **ours** — `backup_export` reads it straight out of the blob it
    // was handed and hands the rest to `chacha_open`, which splits the first 12
    // bytes off as the nonce itself (`backup.rs:49-58`). `chacha20poly1305_seal`
    // deliberately does not prepend it (see its docs), so the framing is added
    // here; leaving it out yields a 48-byte blob that the client splits at 12
    // and fails on.
    // Seal into scratch first: `chacha20poly1305_seal` *clears* its output
    // (it is a "write this" function, not an append), so prepending the nonce
    // into the same buffer would be erased by the call.
    let mut sealed = Blob::new();
    if let Err(e) = chacha20poly1305_seal(&channel.key, &nonce, &channel.aad, &seed, &mut sealed)
    {
        return Outcome::plain(e);
    }
    let mut body_blob = Blob::new();
    if body_blob
        .extend_from_slice(&nonce)
        .and_then(|()| body_blob.extend_from_slice(&sealed))
        .is_err()
    {
        return Outcome::plain(Ctap2Response::LimitExceeded);
    }

    // `{1: bstr(blob)}`. Assembled into a scratch buffer and copied in only
    // once whole, so a length failure cannot leave truncated CBOR behind a
    // `0x00`.
    let write = (|| -> Result<(), Ctap2Response> {
        let mut body: Reply = HeaplessVec::new();
        no_heap::push_map_header(&mut body, 1).map_err(cbor_err)?;
        no_heap::push_uint(&mut body, 1).map_err(cbor_err)?;
        no_heap::push_bstr(&mut body, &body_blob).map_err(cbor_err)?;
        out.extend_from_slice(&body).map_err(|_| Ctap2Response::LimitExceeded)
    })();
    match write {
        Ok(()) => Outcome::plain(Ctap2Response::Ok),
        Err(e) => {
            out.clear();
            Outcome::plain(e)
        }
    }
}

// ---------------------------------------------------------------------------
// US-172 — `LOAD` (0x03)
// ---------------------------------------------------------------------------

/// `LOAD` — install a host-supplied master seed.
///
/// `subCommandParams` = `{1: sealed_blob}`; the blob is the same
/// `nonce(12) ‖ ct ‖ tag(16)` framing, sealed by the **host** under the same
/// channel (`picoforge/src/hal/fido/backup.rs:59-77`). Decrypt, require
/// exactly [`MASTER_SEED_LEN`] bytes, [`VendorOps::set_master_seed`]. Response:
/// status only, no payload.
///
/// # The blob bounds
///
/// [`BLOB_MIN`] (28) … [`BLOB_MAX`] (64). **28 is the floor, not 60**:
/// `backup.rs:46-48` refuses below `12 + 16`, and a 30-byte blob carrying a
/// 2-byte payload is a legal AEAD message. 60 is merely what a 32-byte payload
/// happens to produce. A structural check below the floor is `0x03`; a blob at
/// or above it goes on to the AEAD, and a *decryptable* blob whose plaintext
/// is not 32 bytes is a separate `0x03` at the end. Two different failures,
/// two different meanings.
///
/// # No partial state change, ever
///
/// The seed is written exactly once, after (a) the blob has authenticated and
/// (b) the plaintext has been found to be exactly 32 bytes. A wrong key, a
/// tampered tag, a truncated ciphertext and a wrong-length plaintext are all
/// refusals that leave `master_seed()` reporting what it reported before, and
/// [`VendorOps::set_master_seed`] is itself all-or-nothing, so there is no
/// window in which a partial seed is visible.
///
/// # The length check comes *after* authentication, on purpose
///
/// Checking it first would make the plaintext length an oracle: a caller
/// without the key could submit ciphertexts and learn the decrypted length
/// from which status came back. The order is authenticate, then measure.
///
/// # Sealed devices still accept `LOAD`
///
/// `FINALIZE` closes the *export* window — that is what the client's own
/// sub-command comment says (`constants.rs:742`: *"FINALIZE — seal the one-time
/// export window"*) and what [`finalize`]'s docs say. It does not disable
/// restore: the whole point of a device you have backed up is that it can be
/// restored. Nothing here consults [`BackupWindow`], and
/// `tests/vendor_backup.rs::load_still_works_after_finalize` pins that.
pub fn load(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
    ops: &mut dyn VendorOps,
) -> Outcome {
    // The gate, and its [`WireParams`] return, are the whole point of this
    // function's first line: everything after it works on the bytes the MAC
    // was computed over.
    let params = match backup_auth(data, Subcommand::Load, auth, presence) {
        Ok(p) => p,
        Err(o) => return o,
    };
    if params.is_absent() {
        return Outcome::plain(Ctap2Response::MissingParameter);
    }
    let blob = match blob_from_params(params.as_bytes()) {
        Ok(b) => b,
        Err(e) => return Outcome::plain(e),
    };
    // 12 + 16 is the floor: below it there is no nonce, or no tag, and nothing
    // to authenticate. Checked before any crypto, so an attacker cannot use the
    // error to tell "malformed" from "wrong key".
    if blob.len() < BLOB_MIN || blob.len() > BLOB_MAX {
        return Outcome::plain(Ctap2Response::InvalidLength);
    }

    let mut channel = MseChannel { key: [0u8; 32], aad: [0u8; P256_POINT_LEN] };
    if let Err(e) = ops.mse_channel(&mut channel) {
        return Outcome::plain(e);
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[..NONCE_LEN]);
    let body = &blob[NONCE_LEN..];

    let mut plain = HeaplessVec::<u8, PT_MAX>::new();
    // `0x3D` is CTAP2's "operation failed for integrity reasons" and is the
    // same status the vault uses for a bad wrap, so a caller that already has
    // a "the backup is damaged" string renders it.
    if let Err(e) = chacha20poly1305_open(&channel.key, &nonce, &channel.aad, body, &mut plain) {
        return Outcome::plain(e);
    }
    if plain.len() != MASTER_SEED_LEN {
        return Outcome::plain(Ctap2Response::InvalidLength);
    }
    let mut seed = [0u8; MASTER_SEED_LEN];
    seed.copy_from_slice(&plain);
    // The trait is all-or-nothing, so an `Err` here means the state is
    // untouched. Nothing to roll back at this level, and nothing to charge —
    // the request authenticated; the *store* refused.
    match ops.set_master_seed(seed) {
        Ok(()) => Outcome::plain(Ctap2Response::Ok),
        Err(e) => Outcome::plain(e),
    }
}

/// Pull `{1: sealed_blob}`'s byte string out of the params bytes.
fn blob_from_params(params: &[u8]) -> Result<&[u8], Ctap2Response> {
    let mut p = Parser::new(params);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut blob: Option<&[u8]> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(1) {
            if blob.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            match p.next() {
                Ok(Item::B(b)) => blob = Some(b),
                // Key 1 present but not a byte string: not the shape this
                // sub-command defines.
                _ => return Err(Ctap2Response::InvalidCbor),
            }
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    blob.ok_or(Ctap2Response::MissingParameter)
}

// ---------------------------------------------------------------------------
// US-172 — `FINALIZE` (0x04)
// ---------------------------------------------------------------------------

/// `FINALIZE` — permanently close the one-time export window.
///
/// No params, **touch-gated**, and no payload in the response
/// (`picoforge/src/hal/fido/mod.rs:1755-1763` — `rs_key_vendor(…, None, None)`,
/// and the client reads the status and nothing else).
///
/// The client sends this with **no token**, so it deliberately does not go
/// through [`backup_auth`]: there is no `pinUvAuthParam` in the request to
/// verify, and requiring one would answer `0x36` to the only `FINALIZE` the
/// client ever sends. The gate is a presence window — the one the client
/// documents as *"Touch-gated"* and the HID task re-drives on `0x3B`.
///
/// Idempotent: [`BackupWindow::seal_backup`] is specified idempotent, so an
/// already-sealed device answers `0x00` rather than an invented "already done"
/// code (see that method's docs). A second `FINALIZE` still costs a touch, so a
/// host that spams it cannot wear flash without a human.
pub fn finalize(presence: PresenceGate, ops: &mut dyn BackupWindow) -> Outcome {
    if !presence.granted() {
        return Outcome::plain(Ctap2Response::UpRequired);
    }
    match ops.seal_backup() {
        Ok(()) => Outcome::plain(Ctap2Response::Ok),
        Err(e) => Outcome::plain(e),
    }
}

// ---------------------------------------------------------------------------
// The AEAD
// ---------------------------------------------------------------------------

/// Seal `plaintext` as `ct ‖ tag(16)` — the nonce is **not** prepended here;
/// the caller frames it — under ChaCha20-Poly1305 (RFC 8439 §2.8).
///
/// `aad` is the additional authenticated data: on this channel, the device's
/// own uncompressed P-256 point. It is not optional in spirit — a seal under a
/// different AAD produces a blob the peer will not open, which is the property
/// `tests/vendor_backup.rs::the_aad_is_the_device_point_and_nothing_else`
/// asserts in both directions.
///
/// # This is a thin adapter, not an implementation
///
/// The cryptography lives in [`crate::crypto`], which wraps the
/// `chacha20poly1305` crate (RFC 8439). This function exists only to map
/// [`crypto::AeadError`] onto the CTAP2 status the `0x41` channel answers with,
/// and to keep the name the arm code and the tests already speak. The *only*
/// bound is the output buffer's capacity — a `Result`, not a panic and not a
/// truncation, because a truncated plaintext authenticates. The *protocol*
/// bound, [`PT_MAX`], is enforced by the arms ([`load`] on the blob length,
/// [`export`] trivially, since it always seals [`MASTER_SEED_LEN`] bytes), not
/// here: a general AEAD is what lets the RFC's own 114-byte §2.8.2 message be
/// run through the shipped code in `tests/vendor_backup.rs`.
pub fn chacha20poly1305_seal<const N: usize>(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), Ctap2Response> {
    crate::crypto::chacha20poly1305_seal(key, nonce, aad, plaintext, out)
        .map_err(aead_err)
}

/// Open `ct ‖ tag(16)` under ChaCha20-Poly1305 (RFC 8439 §2.8), appending the
/// plaintext to `out`.
///
/// **Fails closed with `out` untouched.** A tag mismatch returns
/// [`Ctap2Response::IntegrityFailure`] and appends nothing; the
/// authenticate-then-decrypt order is what makes "no partial plaintext" true
/// rather than aspirational, so a caller that ignores the `Err` still holds no
/// attacker-chosen bytes.
///
/// `ct_and_tag` must be at least [`TAG_LEN`]; shorter is a framing error
/// rather than a failed authentication, and is reported as one.
pub fn chacha20poly1305_open<const N: usize>(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), Ctap2Response> {
    crate::crypto::chacha20poly1305_open(key, nonce, aad, ct_and_tag, out).map_err(aead_err)
}

/// Map an AEAD failure onto the status the `0x41` channel uses.
///
/// `Length` covers two distinct things — a blob too short to hold a tag, and
/// an output buffer too small for the plaintext — and both are `0x03` here
/// because this channel's whole message budget is bounded by [`BLOB_MAX`]:
/// there is no input for which "your buffer was too small" is a more useful
/// answer than "that blob is the wrong length". `Integrity` is `0x3D`, CTAP2's
/// "operation failed for integrity reasons" and the same status the vault uses
/// for a bad wrap, so a caller that already has a "the backup is damaged"
/// string renders it.
fn aead_err(e: crate::crypto::AeadError) -> Ctap2Response {
    match e {
        crate::crypto::AeadError::Length => Ctap2Response::InvalidLength,
        crate::crypto::AeadError::Integrity => Ctap2Response::IntegrityFailure,
    }
}

/// Map a no-heap CBOR encoding failure onto the status the `0x41` channel uses.
///
/// `LimitExceeded` and `InvalidCbor` are both mapped to `0x12`, which is what
/// `vendor41::cbor_err` does for the same reason: the client parses the body
/// only on a `0x00`, so any encoding failure is "this response is not usable",
/// and splitting the two would only make the device's answer depend on which
/// of its two 7.6 kB buffers ran out.
fn cbor_err(_: no_heap::CborError) -> Ctap2Response {
    Ctap2Response::InvalidCbor
}
