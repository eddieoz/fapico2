//! US-173 (`AUDIT_READ`, `0x07`) and US-174 (`AUDIT_CHECKPOINT` `0x08`,
//! `AUDIT_CONFIG` `0x0E`) — the RS-Key tamper-evident audit journal over the
//! `0x41` vendor channel (EPIC `PICOForge-COMPAT`, Phase I).
//!
//! # What this module is, and what it deliberately is not
//!
//! The journal's **state** is not here. Ring, epoch accumulator, chain fold,
//! checkpoint key and the all-or-nothing durable commit are all
//! [`VendorOps`](crate::vendor41::VendorOps) methods, already built and already
//! tested (`apps/fido/tests/vendor41_state.rs`). What is here is the three
//! remaining jobs an arm owns and the trait cannot:
//!
//! 1. **gating** — `token_or_touch_gate` below, which is the *union* of the two
//!    gates `vendor41` already has ([`verify_mac`] for an identity-tier token,
//!    [`PresenceGate`] for a benign-tier touch) and neither of them alone;
//! 2. **CBOR framing** of the three response bodies, byte-exact;
//! 3. **the two length/identity invariants** the host checks before it will
//!    believe anything: `entries.len() == 20 × (seq_next − start)` and a
//!    65-byte `0x04`-prefixed public key.
//!
//! The split exists because the state must not be reachable two ways. See
//! `vendor41`'s `VendorOps` docs for the long argument; the short version is
//! that every journal byte on the wire is written exactly once, here, and read
//! exactly once, there.
//!
//! # `no_std` by construction
//!
//! Every buffer on this path is a [`HeaplessVec`], every integer is a `u32` or
//! smaller, and nothing here names `std`. The only allocation-shaped type that
//! appears is `heapless::Vec`, whose capacity is a `const` generic. There is
//! **no** 640-byte scratch buffer, which is the interesting part — see
//! [`write_audit_read_response`] for how the record stream is framed without
//! one, and why that was worth the in-place head patch.
//!
//! [`HeaplessVec`]: heapless::Vec
//!
//! # The one place the EPIC is wrong, and it is the one that costs a device
//!
//! US-174's bullet reads:
//!
//! > Signed message, byte-exact: `"RSK-AUDIT-CKPT-v1"` (18 ASCII bytes,
//! > **no NUL**) ‖ `head(32)` ‖ `seq` u32 **LE** ‖ `challenge(16)`
//!
//! The literal is **17** bytes. `R S K - A U D I T - C K P T - v 1` is
//! 3+1+5+1+4+1+2 = 17, and the client — the only side that verifies — hashes
//! exactly 17: `CKPT_TAG` is a `&[u8]` at `picoforge/src/hal/fido/audit.rs:17`
//! and `verify_checkpoint` does `msg.extend_from_slice(CKPT_TAG)` on it at
//! `audit.rs:160`, with no C-string and no NUL anywhere in the path. The
//! signed message is therefore **69** bytes, not 70.
//!
//! A firmware that implements the bullet *literally* — padding to 18 because
//! the count says 18 — produces a signature that no host accepts, and the host
//! reports it as `signature_ok: false` on a device that is behaving perfectly
//! (`AuditVerification::authentic`, `audit.rs:82-84`). The desktop Audit
//! screen then says the journal is unauthentic on a device with a correct
//! implementation. This module uses
//! [`AUDIT_CHECKPOINT_TAG`](crate::vendor41::AUDIT_CHECKPOINT_TAG) — the
//! constant, never a literal — and the signed-message assembly itself lives in
//! [`vendor41::checkpoint_message`], which is the single place the layout is
//! spelled out. `tests/vendor_audit.rs::checkpoint_signature_verifies_over_the
//! _independently_assembled_message` is a real ECDSA verification against a
//! message the test assembles itself, so a regression here fails as a
//! *verification* failure rather than as a length assertion.
//!
//! # The two trailing bytes nobody reads
//!
//! `AuditRecord::encode` emits 20 bytes: `seq` u32 LE `[0..4]`, `uptime_ms` u32
//! LE `[4..8]`, `event` u8 `[8]`, `aux` u8 `[9]`, `detail` `[10..18]`, then
//! **two bytes the client never parses** — `parse_entries` reads `e[10..18]`
//! and stops (`audit.rs:117-130`), and `fold_chain` hashes the whole 20-byte
//! chunk regardless (`audit.rs:133-143`).
//!
//! That is the trap worth naming: those two bytes are **inside the hash**. The
//! chain is `h_{i+1} = SHA-256(h_i ‖ entry_i)` over the **raw 20 bytes**, so a
//! device that emitted a 18-byte record, or padded with something
//! non-deterministic, would produce a head the host recomputes differently and
//! `head_matches` would be false — a `tamper-evident` log that reports
//! tampering on an untampered device. The two bytes are therefore emitted as
//! `0` ([`AuditRecord::encode`], which is the state layer's job and already
//! correct), and they must be **deterministic**, which zero is. They are
//! ignored by the *parser* and covered by the *hash*, and the host's length
//! rule (`20 × (seq_next − start)`, `audit.rs:175-178`) counts them.
//!
//! [`AuditRecord::encode`]: crate::vendor41::AuditRecord::encode
//!
//! # The degenerate window, and why only an empty `entries` is legal
//!
//! The host's rule is one line (`audit.rs:169-186`):
//!
//! ```text
//! let expected = (seq_next.saturating_sub(start) as usize) * 20;
//! if !entries_bytes.len().is_multiple_of(20) || entries_bytes.len() != expected {
//!     return Err("export length does not match the window — corrupt journal?");
//! }
//! ```
//!
//! Two consequences fall out of `saturating_sub`:
//!
//! * `seq_next == start` (an empty journal — the real state reaches this
//!   whenever `audit_len == 0`) ⇒ `expected == 0` ⇒ **`entries` must be
//!   empty**. A device that refused to answer an empty journal, or padded it,
//!   fails its own host check on a freshly-provisioned token.
//! * `seq_next < start` ⇒ the subtraction saturates to `0` ⇒ **again only an
//!   empty `entries` is accepted**, and no other byte count is. The real
//!   implementations cannot produce this window (`live_start = audit_seq −
//!   audit_len`, `live_end = audit_seq`, and the decoder refuses a stored
//!   `(seq, len)` pair with `seq < len` — `vendor_state`'s
//!   `VendorPublic::live_start`), so it is unreachable through
//!   [`KeystoreVendorOps`] and [`MemoryVendorOps`]. It is pinned anyway, by
//!   a mock `VendorOps` in the test file, because the *framing* has to be
//!   right for a window it will never be handed and the alternative is finding
//!   out from a field report.
//!
//! # Gating, and the counter question
//!
//! `AUDIT_READ`, `AUDIT_CHECKPOINT` and `AUDIT_CONFIG` targets 0/1 are all
//! **"PIN token or, absent a PIN, a physical touch"**. The client expresses
//! this as `rs_key_vendor(sub, params, pin)` (`ops.rs:1556-1596`): with
//! `Some(pin)` it attaches key 3 (`pinUvAuthProtocol`) and key 4
//! (`pinUvAuthParam`); with `None` it attaches **nothing at all** and its own
//! comment says the firmware gates on a touch instead. Both are legitimate
//! requests and both must succeed, so the arm cannot be a pure MAC check (it
//! would answer `0x36` to the ordinary no-PIN case) and cannot be a pure
//! presence check (it would demand a button from a caller that already proved
//! possession of a `0x20` token).
//!
//! [`token_or_touch_gate`] is the union, and the *order* is the substance:
//!
//! ```text
//! auth: Some  -> latch check -> verify_mac -> authorize      (no touch)
//! auth: None  -> presence.granted(), else UpRequired         (no MAC)
//! ```
//!
//! A token is strictly stronger than a touch, so a caller that has one is never
//! asked to also press the button — the same asymmetry `config_write`'s tiers
//! are built on. The other half is the reason the order is a `match` on `auth`
//! rather than an `if granted { ok }` first: the touch path must **not** look
//! at `pinUvAuthParam`, because not looking is what makes it not chargeable.
//!
//! ## Which failures charge the PIN-auth counter
//!
//! [`ChargePinAuth`] is a field on the return type rather than a paragraph, and
//! it is the whole answer to "does this cost the user one of their three
//! strikes". The rule, and its reason:
//!
//! | situation | status | charge? |
//! |---|---|---|
//! | `verify_mac` rejected a `pinUvAuthParam` | `0x33` `PinAuthInvalid` | **yes** |
//! | `TokenAuth::blocked` (three-strike latch already set) | `0x34` `PinAuthBlocked` | no |
//! | no token **and** no touch grant | `0x3B` `UpRequired` | no |
//! | token present, MAC fine, permission bit absent | `0x40` `UnauthorizedPermission` | no |
//! | malformed request (CBOR, missing key, bad length, unknown target) | `0x12`/`0x14`/`0x02`/`0x03` | no |
//! | state refused the operation | whatever the trait returned | no |
//!
//! Two rows need their reasoning spelled out, because they are the two that
//! are easy to get backwards:
//!
//! * **A rejected MAC is the only chargeable failure.** A request whose CBOR
//!   never parsed, or whose challenge was the wrong width, never reached a
//!   comparison against anything secret — it cannot be evidence of a wrong PIN
//!   and charging it would let a single malformed packet burn a strike. This
//!   is `vendor41::identity_gate`'s rule, unchanged.
//! * **The latch is not chargeable, and refusing it is what keeps the status
//!   distinguishable.** Once `TokenAuth::blocked` is set the app has *already*
//!   spent three strikes; charging again would both move `0x34` to `0x33` and
//!   tell a user with a perfectly good token that their token is wrong, sending
//!   them back to a PIN prompt. CTAP2.1 §6.5.7 is about refusing pinUvAuth
//!   *outright*, and `0x34` is the byte that says that.
//!
//! And the one that is easiest to add by accident: **the ungated path must not
//! reach `verify_mac` at all**. `AUDIT_CONFIG` target 2 is the client's
//! documented ungated status query (`mod.rs:1647-1659` passes `None` for the
//! PIN and the constants file says *"read-only status (ungated)"*). Looking at
//! a `pinUvAuthParam` on it would mean charging a failure for a param the
//! client never sends, and three reads of an Audit screen would latch a
//! three-strike lockout against a user who failed nothing.
//!
//! ## Why a touch-gated arm returns `UpRequired` and the host can come back
//!
//! `0x3B` is not a dead end, and this is not a new mechanism: it is the
//! existing one. [`PresenceGate`] already documents the two-step shape.
//!
//! * **Host / emulation.** `PresenceGate::poll` is a synchronous closure. A
//!   token that has a button or a test harness answers `true` on the first
//!   call and the arm proceeds. A harness that answers `false` gets `0x3B`,
//!   which is the correct answer for "no touch was supplied".
//! * **Device (RP2350).** `PresenceGate::window_grant` is **join-only**: the
//!   first call returns `false` and the arm answers `0x3B`; the HID task
//!   catches `UpRequired`, opens a user-presence window, streams keepalives,
//!   and **re-drives the whole command**. The second call finds a grant bound
//!   to this request's presence tag and consumes the press. The blocking is in
//!   the task, not the arm, so `0x41` never blocks a command thread.
//!
//! That is the same contract `makeCredential` has and the same one
//! `config_write`'s presence tier uses (`vendor41::config_write` step 3), so an
//! arm that returns `UpRequired` here needs no new retry machinery in the
//! dispatcher — it needs the same thing `CONFIG_WRITE`'s benign tier already
//! needs. The 32-second client timeout (`ops.rs:1598`,
//! `VENDOR_TOUCH_TIMEOUT_MS`) is what makes the two-step fit: a blocking
//! implementation *could* sit in a poll loop for that long, and this one
//! answers immediately and lets the task own the wait instead.
//!
//! # Order of steps, and why it is decode → gate → act
//!
//! ```text
//! 1. decode the request          (unauthenticated, no state touched)
//! 2. gate                         (authenticated / presence)
//! 3. read or mutate the state     (the only step that can do anything)
//! 4. frame the response
//! ```
//!
//! Steps 1 and 2 are `config_write`'s order verbatim, for the same reason its
//! docs give: the decode can only ever make a request *more* constrained, and
//! the values it produces (a 16-byte challenge, a target byte) are inside
//! `subCommandParams`, so for any request that reaches step 3 the MAC — where
//! one was supplied — has covered exactly the bytes that were decoded. The
//! converse order is not implementable as a *gating* decision at all: it would
//! mean the ungated `AUDIT_CONFIG` target 2 query has to present a token, which
//! the client never obtains for it.
//!
//! [`KeystoreVendorOps`]: crate::vendor_state::KeystoreVendorOps
//! [`MemoryVendorOps`]: crate::vendor_state::MemoryVendorOps

use heapless::Vec as HeaplessVec;

use crate::cbor::no_heap;
use crate::ctap2::Ctap2Response;
use crate::vendor41::{
    authorize, verify_mac, AuditWindow, Checkpoint, PresenceGate, Subcommand, TokenAuth,
    VendorOps, AUDIT_ENTRY_LEN, AUDIT_RING_MAX, P256_POINT_LEN, SIG_DER_MAX,
};

/// The domain separator prefixed to a signed audit checkpoint, re-exported
/// because the test file has to assemble the signed message itself — which is
/// the whole point of the 17-vs-18 test, and it must assemble it from the
/// **constant**, not from a literal in the test.
///
/// See [`vendor41::AUDIT_CHECKPOINT_TAG`] for why the value is 17 bytes and
/// not the 18 the EPIC states, and what happens to a device that pads.
pub use crate::vendor41::AUDIT_CHECKPOINT_TAG;

/// The CTAP2 reply capacity — the same constant `vendor41::handle` is called
/// with on both command paths, and the widest buffer any of these three arms
/// needs (the audit window is 640 bytes plus ~60 of CBOR head).
pub const REPLY_MAX: usize = crate::CTAP2_MAX_MSG;

/// `AUDIT_CONFIG` target `0` — disable the journal
/// (`picoforge/src/hal/fido/constants.rs:757-760`).
pub const AUDIT_CFG_DISABLE: u8 = 0;

/// `AUDIT_CONFIG` target `1` — enable the journal, and start writing to flash.
pub const AUDIT_CFG_ENABLE: u8 = 1;

/// `AUDIT_CONFIG` target `2` — read-only status, **ungated**
/// (`mod.rs:1650-1659`; the client passes `None` for the PIN).
pub const AUDIT_CFG_STATUS: u8 = 2;

/// The `AUDIT_CHECKPOINT` host challenge width, byte-exact
/// (`mod.rs:1604`: `let mut challenge = [0u8; 16]`).
pub const AUDIT_CHALLENGE_LEN: usize = 16;

/// The epoch accumulator width. **Not** negotiable: the client does
/// `m_bytes(&m, 3)?.try_into().map_err(|_| "audit read: epoch is not 32 bytes")`
/// (`mod.rs:1578-1581`), so a 31- or 33-byte epoch is a hard client-side
/// failure. [`AuditWindow::epoch`] is a `[u8; 32]` for the same reason.
pub const AUDIT_EPOCH_LEN: usize = 32;

/// Widest `entries` byte string the ring can produce:
/// [`AUDIT_RING_MAX`] × [`AUDIT_ENTRY_LEN`] = 640.
pub const AUDIT_ENTRIES_MAX: usize = AUDIT_RING_MAX * AUDIT_ENTRY_LEN;

/// Whether the app should charge its three-strike PIN-auth counter.
///
/// A field rather than a comment because the mistake it prevents is
/// asymmetric: a **missing** charge means a rejected MAC never locks anybody
/// out, which looks fine; a **spurious** charge means a malformed request or a
/// no-PIN touch-gated read burns one of a user's three strikes, which looks
/// fine right up until it does not. Both are invisible at the call site, so
/// the value travels with the status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargePinAuth {
    /// Map to `Outcome::pin_auth_failure(status)`. Exactly one condition
    /// produces this: `verify_mac` returned [`Ctap2Response::PinAuthInvalid`],
    /// i.e. a `pinUvAuthParam` was supplied and did not verify.
    Charge,
    /// Map to `Outcome::plain(status)`. Everything else, including every
    /// refusal that did not look at a MAC.
    NoCharge,
}

/// What an arm in this module returns.
///
/// Deliberately **not** [`crate::vendor41::Outcome`]: `Outcome` also carries a
/// `PhyConfig` proposal, which has no meaning here, and returning it would
/// make "does this charge the counter?" a question about a field three
/// components away from the status. This pairs the two directly and
/// [`From<AuditResult>`] converts it in one call at the dispatch site.
///
/// `PartialEq` without `Eq`, matching [`Ctap2Response`] itself — which derives
/// only `PartialEq`. Deriving `Eq` here would not compile, and "this status
/// type has no total order" is not a property this struct gets to override.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AuditResult {
    /// The CTAP2 status byte to put on the wire.
    pub status: Ctap2Response,
    /// Whether the app should charge its PIN-auth failure counter. See the
    /// table in the module docs for the exhaustive list.
    pub charge_pin_auth: ChargePinAuth,
}

impl AuditResult {
    /// `0x00`.
    pub const fn ok() -> Self {
        Self { status: Ctap2Response::Ok, charge_pin_auth: ChargePinAuth::NoCharge }
    }

    /// A status with nothing to charge — the correct answer for every refusal
    /// that did not reject a `pinUvAuthParam`.
    pub const fn plain(status: Ctap2Response) -> Self {
        Self { status, charge_pin_auth: ChargePinAuth::NoCharge }
    }

    /// A refusal of a `pinUvAuthParam`, asking the app to charge the counter.
    pub const fn charge(status: Ctap2Response) -> Self {
        Self { status, charge_pin_auth: ChargePinAuth::Charge }
    }
}

impl From<AuditResult> for crate::vendor41::Outcome {
    fn from(r: AuditResult) -> Self {
        match r.charge_pin_auth {
            ChargePinAuth::Charge => Self::pin_auth_failure(r.status),
            ChargePinAuth::NoCharge => Self::plain(r.status),
        }
    }
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

/// The `AUDIT_READ` / `AUDIT_CHECKPOINT` / `AUDIT_CONFIG`-write gate: a
/// `0x20` pinUvAuth token **or** a physical touch.
///
/// `sub` is the [`Subcommand`] whose permission row [`authorize`] consults;
/// all three audit rows are `Requirement::TokenOptional(PERM_ACFG)`, so a
/// token that *is* presented must carry `acfg` — a `CREDENTIAL_MANAGEMENT`
/// token is refused with `0x40` exactly as `config_write` refuses one.
///
/// # Why the union rather than either gate
///
/// The client's `rs_key_vendor` takes `pin: Option<&str>` and branches
/// (`ops.rs:1573-1589`): `Some` ⇒ keys 3 and 4 are attached and a MAC is
/// computed; `None` ⇒ **no auth fields at all** and the comment says "Without
/// one, the firmware gates on a physical touch instead, so no auth fields are
/// sent". A token-only gate answers `0x36` to the documented no-PIN case; a
/// touch-only gate demands a button from a caller that already proved
/// possession of a token, and — worse — a *decreases* the bar, because a
/// `pinUvAuthParam` riding along would then be ignored entirely, so an attacker
/// with a valid `0x20` token could strip the MAC and downgrade to a touch.
///
/// # The three refusals, and which ones charge
///
/// * `TokenAuth::blocked` ⇒ `0x34`, **no charge**. The latch has already spent
///   its three strikes; charging would both move the status to `0x33` and
///   claim a good token is bad.
/// * no token and no touch ⇒ `0x3B`, **no charge**. Nothing was authenticated,
///   so nothing failed authentication. (Note this is *not* `0x36`
///   `PuatRequired`, which is what `identity_gate` returns for a missing
///   token: here a missing token is the client's normal, documented way to ask
///   for a touch, and `0x36` would send the user back to a PIN prompt for a
///   token the app never obtains.)
/// * a presented token that fails `verify_mac` ⇒ `0x33`, **charged**. This is
///   the only chargeable path in the module.
/// * a presented token whose MAC verifies but whose permission bit is absent ⇒
///   `0x40`, **no charge** — the token was real.
pub fn token_or_touch_gate(
    sub: Subcommand,
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
) -> Result<(), AuditResult> {
    let Some(a) = auth else {
        // The touch path. It must not look at `data`'s key 3/4 even if they are
        // there: a tokenless request is the client's normal shape, and
        // "refusing to look at a param" is what makes this path unchargeable.
        return if presence.granted() {
            Ok(())
        } else {
            Err(AuditResult::plain(Ctap2Response::UpRequired))
        };
    };
    if a.blocked {
        return Err(AuditResult::plain(Ctap2Response::PinAuthBlocked));
    }
    match verify_mac(data, Some(a.token)) {
        // The params span is discarded on purpose. This arm re-decodes the
        // request from `data` (step 1 above), the same way
        // `vendor41::config_write_params` does and for the same reason: the
        // values it decodes (a challenge, a target) are inside the params, so
        // the MAC covered them. Keeping the span would mean two parsers of one
        // request, and `verify_mac`'s duplicate-key-2 refusal is the one place
        // that must be the only decider of which pair is "the params".
        Ok(_) => {}
        Err(Ctap2Response::PinAuthInvalid) => {
            return Err(AuditResult::charge(Ctap2Response::PinAuthInvalid))
        }
        Err(e) => return Err(AuditResult::plain(e)),
    }
    match authorize(sub, Some(a.permissions)) {
        Ok(()) => Ok(()),
        Err(e) => Err(AuditResult::plain(e)),
    }
}

// ---------------------------------------------------------------------------
// Request decoding. Both are strict for `config_write_params`' reasons.
// ---------------------------------------------------------------------------

/// The 16-byte host challenge from `subCommandParams` key 2, key 1.
///
/// Inverse of `audit_verify`'s request (`mod.rs:1604-1611`): a one-pair map
/// whose value is a CBOR **byte string** of exactly 16 bytes.
///
/// `try_into`, not a truncation, for the width: a 15- or 17-byte challenge is
/// not a different challenge, it is a request the protocol does not describe,
/// and truncating it would sign a message the host will not reconstruct.
///
/// Duplicate key 1, a key 2 that is not a map, a challenge that is not a byte
/// string, trailing bytes and a missing key are each refused — the same five
/// refusals [`vendor41::config_write_params`] makes, because the reasons are
/// the same (a repeated key makes the request's meaning order-dependent, and a
/// repeated value makes "which bytes were signed" undecidable).
pub fn checkpoint_challenge(data: &[u8]) -> Result<[u8; AUDIT_CHALLENGE_LEN], Ctap2Response> {
    use crate::cbor::no_heap::{Item, Parser};
    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut challenge: Option<&[u8]> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(2) {
            if challenge.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            let Ok(Item::Map(inner)) = p.next() else {
                return Err(Ctap2Response::InvalidCbor);
            };
            for _ in 0..inner {
                let k = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
                if k == Item::U(1) {
                    if challenge.is_some() {
                        return Err(Ctap2Response::InvalidCbor);
                    }
                    challenge = Some(match p.next() {
                        Ok(Item::B(b)) => b,
                        _ => return Err(Ctap2Response::InvalidCbor),
                    });
                } else {
                    p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
                }
            }
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    if p.remaining() != 0 {
        return Err(Ctap2Response::InvalidCbor);
    }
    let bytes = challenge.ok_or(Ctap2Response::MissingParameter)?;
    <[u8; AUDIT_CHALLENGE_LEN]>::try_from(bytes)
        .map_err(|_| Ctap2Response::InvalidLength)
}

/// The `AUDIT_CONFIG` target from `subCommandParams` key 2, key 1.
///
/// `try_from(u64) -> u8`, not `as u8`: a target of `0x100` truncating to `0`
/// would turn a request the protocol does not define into "disable the audit
/// journal". `vendor41::config_read_target`'s comment on the same conversion
/// is the precedent; it is the same bug with a different byte.
///
/// The width check here is the *shape*; the value check (must be 0, 1 or 2)
/// belongs to [`audit_config`], which is the only thing that can say whether
/// an unrecognised target is a refusal of a defined record or a request for
/// something this firmware does not do.
pub fn audit_config_target(data: &[u8]) -> Result<u8, Ctap2Response> {
    use crate::cbor::no_heap::{Item, Parser};
    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut target: Option<u8> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(2) {
            if target.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            let Ok(Item::Map(inner)) = p.next() else {
                return Err(Ctap2Response::InvalidCbor);
            };
            for _ in 0..inner {
                let k = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
                if k == Item::U(1) {
                    if target.is_some() {
                        return Err(Ctap2Response::InvalidCbor);
                    }
                    target = Some(match p.next() {
                        Ok(Item::U(v)) => {
                            u8::try_from(v).map_err(|_| Ctap2Response::InvalidParameter)?
                        }
                        _ => return Err(Ctap2Response::InvalidCbor),
                    });
                } else {
                    p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
                }
            }
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    if p.remaining() != 0 {
        return Err(Ctap2Response::InvalidCbor);
    }
    target.ok_or(Ctap2Response::MissingParameter)
}

// ---------------------------------------------------------------------------
// US-173: `AUDIT_READ` (sub-command `0x07`).
// ---------------------------------------------------------------------------

/// Handle `AUDIT_READ`: gate, stream the journal window, frame it.
///
/// The request carries **no `subCommandParams` at all** — the client passes
/// `None` (`mod.rs:1573`), which `ops.rs:1563-1565` turns into an *absent* key
/// 2 rather than an empty one. So this arm has nothing to decode and the
/// order collapses to gate → read → frame.
///
/// A `subCommandParams` that *is* present is not rejected: it is ignored. The
/// alternative — demanding its absence — would answer `0x12` to a client that
/// sends an empty map, and the only field in it that could matter is a
/// `pinUvAuthParam`, which [`token_or_touch_gate`] has already either verified
/// or (tokenless) deliberately not looked at. Ignoring it is what keeps the
/// no-charge property of the touch path true.
///
/// # The response, and the one rule that makes it right or rejected
///
/// `{1: start, 2: seq_next, 3: epoch(32), 4: entries}` — and the host rejects
/// the whole thing unless `entries.len() == 20 × (seq_next − start)`
/// (`audit.rs:169-186`). So:
///
/// * no padding, ever;
/// * no short window — the device chooses the window and
///   [`AuditWindow`] is the device's own consistent view of it;
/// * no extras — the host's `is_multiple_of(20)` check rejects a trailing
///   partial record as firmly as a wrong total.
///
/// That check is re-implemented here, against the same formula, as a
/// **post-condition** ([`write_audit_read_response`]'s `expected`). It cannot
/// fire against either real implementation — they are the ones that build both
/// halves — and it exists so that a third `VendorOps` cannot ship a reply the
/// host will call corrupt. The alternative is a device-side inconsistency
/// reported to the user as *"export length does not match the window — corrupt
/// journal?"* (`audit.rs:184`), which is a false accusation of tampering and
/// the single worst thing this channel can do to an operator's trust in it.
pub fn audit_read(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
    ops: &mut dyn VendorOps,
    out: &mut HeaplessVec<u8, REPLY_MAX>,
) -> AuditResult {
    if let Err(r) = token_or_touch_gate(Subcommand::AuditRead, data, auth, presence) {
        return r;
    }
    let (window, written) = match write_audit_read_response(out, &*ops) {
        Ok(v) => v,
        Err(e) => {
            out.clear();
            return AuditResult::plain(e);
        }
    };
    let expected = expected_entries_len(&window);
    if written != expected {
        // A device-side invariant, not a bad request: `ops.audit_window`
        // reported a window it did not fill. `0x21` CTAP2_ERR_PROCESSING is
        // the same "the authenticator could not complete this" the state layer
        // uses for a failed checkpoint sign, and it is loud — see the module
        // docs for why that matters more than the specific byte.
        out.clear();
        return AuditResult::plain(Ctap2Response::Processing);
    }
    AuditResult::ok()
}

/// The number of `entries` bytes the host will expect for `window`.
///
/// The client's rule, transcribed: `audit.rs:175-178`,
/// `(seq_next.saturating_sub(start) as usize) * ENTRY_LEN`.
///
/// `saturating_sub` is not defensive tidiness, it is the host's arithmetic:
/// `seq_next < start` gives `0`, so the **only** legal `entries` for such a
/// window is empty. See the module docs on the degenerate case.
pub const fn expected_entries_len(window: &AuditWindow) -> usize {
    window.seq_next.saturating_sub(window.start) as usize * AUDIT_ENTRY_LEN
}

/// Worst-case size of the `AUDIT_READ` framing **around** the entries: map
/// header (1) ‖ key 1 head (1) ‖ `start` u32 (≤9) ‖ key 2 head (1) ‖
/// `seq_next` u32 (≤9) ‖ key 3 head (1) ‖ epoch head (2) ‖ epoch (32) ‖ key 4
/// head (1) ‖ entries head (3) = **60**, rounded to 64.
///
/// `push_head` is minimal-length, so a real journal's `start`/`seq_next` are
/// 1..=5 bytes and this is never actually approached — the bound is taken at
/// 9 because `push_head` will emit a 64-bit argument for any `u64` it is
/// handed, and a buffer sized for the *typical* width would be a
/// `LimitExceeded` waiting for the first device with a large sequence
/// number.
pub const AUDIT_READ_FRAME_MAX: usize = 64;

/// The `AUDIT_READ` response body: `{1: start, 2: seq_next, 3: epoch(32),
/// 4: entries}`.
///
/// # The 640-byte scratch buffer this does **not** use
///
/// The obvious shape is: call [`VendorOps::audit_window`] into a local
/// `HeaplessVec<u8, 640>`, take its [`AuditWindow`], and `push_bstr` the lot.
/// That is correct and costs 640 bytes of RP2350 stack on every `AUDIT_READ`,
/// for a copy the reply buffer already has room for — which is precisely the
/// cost the `audit_window` doc says it streams *to avoid*:
///
/// > The records are streamed **into the reply buffer**, after the CBOR
/// > byte-string head, exactly as `write_phy_record` does for the PHY record
///
/// So the records are streamed into `out`. The difficulty that creates is a
/// genuine ordering knot, and it is worth spelling out because the two obvious
/// workarounds are both wrong:
///
/// * **Reserve the head, patch it afterwards.** CBOR heads are minimal-length
///   (1 byte below 24, 2 below 256, 3 below 65536) and the largest window is
///   640, so 3 bytes always suffice — but a 3-byte reservation used for a
///   2-byte head leaves a junk byte inside the map, and a 1-byte reservation
///   used for 3 is worse. Fixing it in place means sliding the entries left,
///   which works, and which a later reader is very likely to delete as an
///   optimisation — after which the reply has trailing zeros inside it and the
///   client's decoder either rejects it or tolerates it depending on which
///   `from_slice` it uses, i.e. it fails *sometimes*, on small journals only.
/// * **Encode keys 1 and 2 before the window is known.** Impossible: they *are*
///   the window's `start` and `seq_next`.
///
/// What this does instead is reserve, stream, frame, and close the gap:
///
/// 1. reserve [`AUDIT_READ_FRAME_MAX`] bytes (64) at the tail of the reply;
/// 2. call `ops.audit_window(out)` — the records land **past** the
///    reservation, and `n = out.len() − at − 64` is now known;
/// 3. build the entire framing (map header, keys 1/2/3, and the entries'
///    byte-string **head** at its now-known minimal width) into a
///    64-byte local;
/// 4. `copy_within` the records up by exactly the difference, write the
///    framing into the hole, truncate.
///
/// Two `memmove`s of at most 640 bytes, on a path that is not latency
/// sensitive, and **64 bytes** of stack rather than 640 — an order of magnitude
/// that is worth the explanation above. `copy_within` has memmove semantics,
/// so the shift is correct in the case that looks wrong: an empty journal
/// (`n == 0`) or a small one, where source and destination overlap almost
/// entirely.
///
/// The reservation has to come *first* for a reason worth naming, because the
/// alternative reads as the obvious one and does not work: the records are
/// appended to a buffer that is already full to the end of the reservation, so
/// there is no room to grow afterwards, and `copy_within` with the shift the
/// other way round has a destination past the end of the slice. That is a
/// `dest is out of bounds` panic, and a panic on a `0x41` command is a wedged
/// token — `firmware/src/main.rs`'s panic handler is `loop {}`.
///
/// # Why `ops` is `&dyn` and not `&mut`
///
/// Nothing here mutates. The window is a read, and taking `&mut` would invite
/// a caller to interleave an append with the framing — the exact race
/// [`AuditWindow`]'s docs say the single call exists to prevent.
///
/// # Why the buffer is not generic
///
/// [`VendorOps::audit_window`] takes a `&mut HeaplessVec<u8, CTAP2_MAX_MSG>` —
/// a concrete capacity, not a `const N` — because the device implementation
/// writes a 640-byte ring and the host implementation a 640-byte ring, and
/// making the capacity a parameter would mean the caller could offer a buffer
/// the state then overflows. The consequence here is that this function is
/// also not generic: it takes the same [`REPLY_MAX`] buffer
/// [`audit_read`] is called with, and the only scratch inside it is the
/// [`AUDIT_READ_FRAME_MAX`]-byte reservation, never the records.
///
/// The reservation is a *reservation*, so `audit_window` is required to
/// **append** — which is what [`VendorOps::audit_window`]'s contract says
/// ("write the chosen window's record bytes into `out`") and what both
/// implementations do. A `VendorOps` that truncated instead is answered with
/// [`Ctap2Response::InvalidLength`] rather than a subtraction overflow, which
/// is a panic.
///
/// # The two invariant checks, and why they are here rather than in
/// [`audit_read`]
///
/// `n` is the byte count the host will compare against
/// `20 × (seq_next − start)`. Nothing enforces that they agree; a
/// [`VendorOps`] that reported a window it did not fill would produce a reply
/// the client rejects with *"export length does not match the window — corrupt
/// journal?"* (`audit.rs:184`). [`audit_read`] owns the error, this function
/// owns the count, so the count is returned.
pub fn write_audit_read_response(
    out: &mut HeaplessVec<u8, REPLY_MAX>,
    ops: &dyn VendorOps,
) -> Result<(AuditWindow, usize), Ctap2Response> {
    // --- 1. reserve the framing's worst case, then stream past it ---
    //
    // The reservation has to be *before* the stream, because the records are
    // appended to a buffer that is already full to the reservation's end —
    // there is no room to grow afterwards. Reserving the worst case rather
    // than the exact width is the whole reason the scratch is
    // `AUDIT_READ_FRAME_MAX` and not a second 640 bytes; step 3 gives back
    // whatever the minimal frame did not use.
    let at = out.len();
    out.resize_default(at + AUDIT_READ_FRAME_MAX)
        .map_err(|_| Ctap2Response::LimitExceeded)?;
    let window = ops.audit_window(out)?;
    // `saturating_sub` and then a range check rather than a bare subtraction,
    // because a `VendorOps` that *truncates* `out` (rather than appending, as
    // both shipped implementations do) would otherwise underflow here. A
    // subtraction overflow is a panic, and a panic on a `0x41` command is a
    // wedged token — `firmware/src/main.rs`'s panic handler is `loop {}`. So a
    // state that shrinks the caller's buffer gets a status instead.
    if out.len() < at + AUDIT_READ_FRAME_MAX {
        return Err(Ctap2Response::InvalidLength);
    }
    let n = out.len() - at - AUDIT_READ_FRAME_MAX;

    // --- 2. frame, now that `n` is known ---
    let mut frame: HeaplessVec<u8, AUDIT_READ_FRAME_MAX> = HeaplessVec::new();
    no_heap::push_map_header(&mut frame, 4).map_err(cbor_err)?;
    no_heap::push_uint(&mut frame, 1).map_err(cbor_err)?;
    no_heap::push_uint(&mut frame, window.start as u64).map_err(cbor_err)?;
    no_heap::push_uint(&mut frame, 2).map_err(cbor_err)?;
    no_heap::push_uint(&mut frame, window.seq_next as u64).map_err(cbor_err)?;
    no_heap::push_uint(&mut frame, 3).map_err(cbor_err)?;
    // Exactly 32 bytes, always — `AuditWindow::epoch` is a `[u8; 32]`, so a
    // different width is not expressible here rather than merely discouraged.
    // The client is equally strict on the way back
    // (`try_into().map_err(|_| "audit read: epoch is not 32 bytes")`,
    // `mod.rs:1578-1581`).
    no_heap::push_bstr(&mut frame, &window.epoch).map_err(cbor_err)?;
    no_heap::push_uint(&mut frame, 4).map_err(cbor_err)?;
    // The head only. `push_bstr` is unusable precisely because it takes the
    // content it is describing, and the content is 640 bytes further down the
    // same buffer. `write_config_read_response` does the same thing for the
    // PHY record.
    no_heap::push_head(&mut frame, 2, n as u64).map_err(cbor_err)?;

    // --- 3. close the gap ---
    //
    // The records move **up** by the difference between what was reserved and
    // what the minimal frame needs, and the frame is written into the hole.
    // `copy_within` is a memmove, so the shift is correct even in the case
    // that looks wrong — an empty journal, or a small one, where the ranges
    // overlap almost entirely. The subsequent write into `[at, at+len)`
    // cannot clobber a record, because after the shift every record byte lives
    // at `>= at + frame.len()`.
    out.as_mut_slice()
        .copy_within(at + AUDIT_READ_FRAME_MAX.., at + frame.len());
    out.as_mut_slice()[at..at + frame.len()].copy_from_slice(&frame);
    out.truncate(at + frame.len() + n);

    Ok((window, n))
}

// ---------------------------------------------------------------------------
// US-174: `AUDIT_CHECKPOINT` (sub-command `0x08`).
// ---------------------------------------------------------------------------

/// Handle `AUDIT_CHECKPOINT`: gate, sign the head over the host's challenge,
/// frame it.
///
/// The response is `{1: head(32), 2: seq, 3: sig(DER), 4: pubkey(65)}`
/// (`mod.rs:1617-1621`).
///
/// # Why the response's `head` is the one that was signed
///
/// `audit_verify` compares the response's `head` against the head **it
/// recomputed** from the `AUDIT_READ` window it fetched first
/// (`head_matches`, `mod.rs:1624-1625`; `AuditVerification::authentic`,
/// `audit.rs:82-84`). So a device that read the head, then had a
/// `makeCredential` append a record, then signed, would ship a `head` that
/// does not fold from the window the host already holds, and the host would
/// report the journal unauthentic on a device that is correct. The arm
/// therefore does **not** read the head: [`VendorOps::audit_sign_checkpoint`]
/// takes the challenge, reads its own head and sequence once, signs, and
/// returns both beside the signature. Nothing this function does can
/// desynchronise them.
///
/// # Why the arm does not re-assemble the signed message
///
/// It is not that it cannot — [`vendor41::checkpoint_message`] is public and
/// pure. It is that doing so would give a second place for the 17-vs-18 byte
/// tag bug and the little-endian `seq` to live, and the second place would be
/// the one nobody re-reads. The message is assembled once, in
/// `vendor_state::sign_checkpoint`, and this arm's only relationship to it is
/// the widths it writes: 32 / 4 / 16.
///
/// The test that guards the layout is real: `tests/vendor_audit.rs`
/// reassembles `AUDIT_CHECKPOINT_TAG ‖ head ‖ seq.to_le_bytes() ‖ challenge`
/// from the **published constant** and runs an ECDSA P-256/SHA-256/ASN.1-DER
/// verification of the returned signature against the returned public key. A
/// firmware that padded the tag to 18 fails that test as a *verification
/// failure*, which is precisely the symptom an operator would see.
pub fn audit_checkpoint(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
    ops: &mut dyn VendorOps,
    out: &mut HeaplessVec<u8, REPLY_MAX>,
) -> AuditResult {
    // Step 1 (unauthenticated): the challenge is host-chosen and public, and
    // it is inside `subCommandParams`, so a token-bearing MAC has covered it.
    let challenge = match checkpoint_challenge(data) {
        Ok(c) => c,
        Err(e) => return AuditResult::plain(e),
    };
    if let Err(r) = token_or_touch_gate(Subcommand::AuditCheckpoint, data, auth, presence) {
        return r;
    }
    let mut ck = Checkpoint {
        head: [0; 32],
        seq: 0,
        sig: [0; SIG_DER_MAX],
        sig_len: 0,
        pubkey: [0; P256_POINT_LEN],
    };
    if let Err(e) = ops.audit_sign_checkpoint(&challenge, &mut ck) {
        return AuditResult::plain(e);
    }
    if !(70..=72).contains(&ck.sig_len) {
        // `SEQUENCE { INTEGER r, INTEGER s }` with two minimal-length integers
        // of at most 33 bytes each. Anything outside 70..=72 is not a DER
        // ECDSA P-256 signature and `ring` will reject it on the host with a
        // generic "verification failed" — a device fault reported as a
        // cryptographic one.
        return AuditResult::plain(Ctap2Response::Processing);
    }
    if ck.pubkey[0] != 0x04 {
        // SEC1 **uncompressed** is what the host's `UnparsedPublicKey` parses
        // and what its fingerprint is taken over (`audit.rs:145-149` hashes the
        // raw 65 bytes). A compressed point would be 33 bytes and the host's
        // 16-hex fingerprint would be of different bytes than the ones the
        // operator pinned.
        return AuditResult::plain(Ctap2Response::Processing);
    }
    if let Err(e) = write_checkpoint_response(out, &ck) {
        out.clear();
        return AuditResult::plain(e);
    }
    AuditResult::ok()
}

/// The `AUDIT_CHECKPOINT` response body: `{1: head, 2: seq, 3: sig, 4:
/// pubkey}`.
///
/// Every field is a fixed width, so this is a straight four-pair map with no
/// streaming and no scratch: 32 + 4 + 70..=72 + 65 bytes plus about 20 of CBOR
/// head, i.e. ~190 bytes in a 7609-byte reply.
pub fn write_checkpoint_response<const N: usize>(
    out: &mut HeaplessVec<u8, N>,
    ck: &Checkpoint,
) -> Result<(), Ctap2Response> {
    let sig_len = (ck.sig_len as usize).min(SIG_DER_MAX);
    no_heap::push_map_header(out, 4).map_err(cbor_err)?;
    no_heap::push_uint(out, 1).map_err(cbor_err)?;
    no_heap::push_bstr(out, &ck.head).map_err(cbor_err)?;
    no_heap::push_uint(out, 2).map_err(cbor_err)?;
    no_heap::push_uint(out, ck.seq as u64).map_err(cbor_err)?;
    no_heap::push_uint(out, 3).map_err(cbor_err)?;
    no_heap::push_bstr(out, &ck.sig[..sig_len]).map_err(cbor_err)?;
    no_heap::push_uint(out, 4).map_err(cbor_err)?;
    no_heap::push_bstr(out, &ck.pubkey).map_err(cbor_err)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// US-174: `AUDIT_CONFIG` (sub-command `0x0E`).
// ---------------------------------------------------------------------------

/// Handle `AUDIT_CONFIG`: three targets, two different gates, one response
/// shape.
///
/// | target | meaning | gate |
/// |---|---|---|
/// | [`AUDIT_CFG_DISABLE`] `0` | turn the journal off | token **or** touch |
/// | [`AUDIT_CFG_ENABLE`] `1` | turn the journal on, start writing to flash | token **or** touch |
/// | [`AUDIT_CFG_STATUS`] `2` | read the current state | **none** |
///
/// (`constants.rs:757-760`; `mod.rs:1647-1671`. The client passes `None` for
/// the PIN on the status query and `pin.as_deref()` on the setter, which is
/// what makes target 2 the *ungated* one.)
///
/// # The response is `{1: bool}` and it always has key 1
///
/// `m_bool` (`mod.rs:1558-1565`) reads a CBOR `bool` **or** a non-zero
/// integer, and returns `false` for anything else — including a **missing**
/// key. So a response that omits key 1 is indistinguishable from "the journal
/// is off", and there is no way for the client to tell "off" from "this
/// firmware does not implement `AUDIT_CONFIG`". This function therefore emits
/// key 1 on every success, including the success that says `false`.
///
/// The value is a real CBOR boolean (`0xF5` / `0xF4`, major type 7, simple
/// values 21/20 — `no_heap::push_bool`), which is the first arm of `m_bool`'s
/// match. Emitting `1`/`0` instead would also parse, so the compatibility is
/// wider than it needs to be; emitting a bool is the form that cannot be
/// misread by anything that is not `m_bool` itself. Both facts are asserted in
/// `tests/vendor_audit.rs::the_config_response_is_a_cbor_bool_and_m_bool_would_read_it_back`.
///
/// # The reported state is read back, not assumed
///
/// The response carries `ops.audit_enabled()` **after** the commit, not
/// `target == AUDIT_CFG_ENABLE`. `set_audit_enabled` is all-or-nothing, so on
/// `Ok` the two agree — but "the call succeeded" and "the state is what the
/// call was asked to make it" are different claims, and the second is the one
/// the operator's Audit screen renders.
///
/// # Default is off, and that is checked rather than assumed
///
/// The client's own comment: *"Journalling is opt-in, so nothing is written to
/// flash until it is enabled"* (`mod.rs:1660-1661`). Both state
/// implementations default `audit_enabled: false` on a fresh snapshot
/// (`vendor_state::VendorPublic::default`), so a device that has never been
/// asked to keep a journal has none — and a client that reads the status
/// before enabling gets `false` rather than a surprise.
///
/// # Target 2 must not reach `verify_mac`
///
/// This is the ungated path and the one place in the module where reaching the
/// MAC would be an active bug rather than a missed opportunity: a rejected
/// `pinUvAuthParam` **charges the counter**, and three Audit-screen reads
/// would latch a three-strike lockout against a user who failed nothing —
/// the exact failure `vendor41::identity_gate`'s docs describe for the benign
/// tier. `audit_config_target` is called, the target is compared against
/// [`AUDIT_CFG_STATUS`], and the `else` branch returns before any gate is
/// consulted.
///
/// # An unrecognised target is `0x02`, and it is a statement about the
/// protocol
///
/// Same reasoning and same status as `vendor41::config_write`'s unknown
/// target: the three `RSKEY_*_AUDIT_*` target bytes are the only ones the
/// protocol defines, and answering a fourth with a `0x00` would be a success
/// over bytes nobody has claimed mean anything. The client propagates a
/// non-zero status rather than rendering a false success
/// (`vendor_map`, `mod.rs:1533-1542`).
pub fn audit_config(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
    ops: &mut dyn VendorOps,
    out: &mut HeaplessVec<u8, REPLY_MAX>,
) -> AuditResult {
    let target = match audit_config_target(data) {
        Ok(t) => t,
        Err(e) => return AuditResult::plain(e),
    };
    match target {
        AUDIT_CFG_DISABLE | AUDIT_CFG_ENABLE => {
            if let Err(r) = token_or_touch_gate(Subcommand::AuditConfig, data, auth, presence) {
                return r;
            }
            if let Err(e) = ops.set_audit_enabled(target == AUDIT_CFG_ENABLE) {
                return AuditResult::plain(e);
            }
        }
        // Ungated, and ungated *before* anything looks at `auth`. Note this
        // arm takes `data` nowhere: it does not decode key 3/4, does not call
        // `verify_mac`, and cannot charge.
        AUDIT_CFG_STATUS => {}
        _ => return AuditResult::plain(Ctap2Response::InvalidParameter),
    }
    let enabled = ops.audit_enabled();
    if let Err(e) = write_audit_config_response(out, enabled) {
        out.clear();
        return AuditResult::plain(e);
    }
    AuditResult::ok()
}

/// The `AUDIT_CONFIG` response body: `{1: <bool>}`.
///
/// A real CBOR boolean, and key 1 **always**. See the function's docs for why
/// a missing key is the same as `false` to the client and why that matters.
pub fn write_audit_config_response<const N: usize>(
    out: &mut HeaplessVec<u8, N>,
    enabled: bool,
) -> Result<(), Ctap2Response> {
    no_heap::push_map_header(out, 1).map_err(cbor_err)?;
    no_heap::push_uint(out, 1).map_err(cbor_err)?;
    no_heap::push_bool(out, enabled).map_err(cbor_err)
}

/// `no_heap`'s errors mapped onto CTAP2, matching `vendor41::cbor_err`.
///
/// A full reply buffer is a bug here rather than a runtime condition: the
/// widest body this module produces is ~700 bytes in a [`REPLY_MAX`]
/// (7609-byte) buffer. It still needs a status rather than a panic, because the
/// command path owns no recovery and the device's panic handler is `loop {}`.
fn cbor_err(_e: no_heap::CborError) -> Ctap2Response {
    Ctap2Response::LimitExceeded
}

// ---------------------------------------------------------------------------
// A compile-time statement that this module is `no_std`.
// ---------------------------------------------------------------------------
//
// `vendor41` carries the same note, but it is worth having here too because
// this module is *new*: the failure mode being guarded is a `format!`, a
// `String` or a `Box` creeping in from a doc example, which compiles fine on
// the host test target and then fails the RP2350 build — after the wiring
// commit that pulls it into `lib.rs`, which is exactly the round trip this is
// meant to avoid.
//
// Everything above is `heapless::Vec`, `core::convert`, `core::cmp` and
// fixed-size arrays. There is no `extern crate std` here to remove.

const _: () = {
    // Fails to compile if this crate ever gains a `std` prelude item that
    // shadows these, and is a no-op otherwise. A `const` block is the only
    // place in `no_std` where a "does this type-check" assertion costs
    // nothing at runtime.
    fn _assert_no_std() {
        let _: core::option::Option<u8> = None;
        let _: core::result::Result<(), core::convert::Infallible> = Ok(());
    }
    let _ = _assert_no_std;
};
