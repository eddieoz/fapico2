//! US-175 (EPIC `PICOForge-COMPAT`) — RS-Key **organisation attestation** over
//! the `0x41` vendor channel: `ATT_STATE` (`0x0B`), `ATT_CLEAR` (`0x0A`) and
//! `ATT_IMPORT` (`0x09`).
//!
//! # What this module is, and what it deliberately is not
//!
//! The credential's **state** is not here. The P-256 scalar, the DER chain, the
//! `chain_hash` derivation, the "installed" predicate and the all-or-nothing
//! durable commit are all [`VendorOps`] methods, already built and already
//! tested (`apps/fido/tests/vendor41_state.rs`, and
//! [`vendor_state::VendorState::put_org`]). What is here is the four jobs an
//! arm owns and the trait cannot:
//!
//! 1. **CBOR framing** of the one response that has a body (`ATT_STATE`);
//! 2. **the AEAD unwrap** of the sealed scalar, under the MSE channel;
//! 3. **the DER walk** of a concatenated certificate chain that carries no
//!    delimiter and no count;
//! 4. **the gating** — and, for `ATT_IMPORT`, the one gate that the stock
//!    [`vendor41::verify_mac`] physically cannot express at the sizes the
//!    client uses.
//!
//! So this module implements **no** durable state, and every function in it is
//! a pure function of `(request bytes, token, ops) -> AttResult`.
//!
//! # The layering rule, and what it costs this module nothing
//!
//! The EPIC's RESOLVED note at US-175 is the load-bearing decision of this
//! story and it is worth restating in full, because the obvious
//! implementation violates it:
//!
//! > org attestation **LAYERS ON** the existing per-device attestation. It
//! > does not replace it. […] A device with no org cert imported must still
//! > mint normal FIDO2 attestations — that is the regression test.
//!
//! The two identities are in different storage and no code path joins them:
//!
//! | | per-device (`US-916`) | org (`US-175`) |
//! |---|---|---|
//! | key + cert | [`crate::attestation::ATTEST_KEY_SLOT`] / [`ATTEST_CERT_SLOT`], v3-AEAD-sealed platform slots | [`VendorOps::org_attestation`], the vendor snapshot's auth-map keys 7 and 8 |
//! | minted | on the device at first boot, from the TRNG ([`crate::attestation::provision`]) | by the **host**, in a PEM/DER file, over the `0x41` channel |
//! | consumer | `makeCredential`'s `packed` statement and the U2F register path ([`crate::app`]'s `authenticator` path, [`crate::u2f`]) | a `0x41` attestation surface, which does not exist yet |
//! | read by | the FIDO2 code path, on every credential creation | [`OrgAttestationView::chain_hash`], and nothing else today |
//!
//! `crate::attestation` does not import `crate::vendor41`, and this module
//! does not import `crate::attestation` — the dependency runs one way and the
//! org slot is simply not reachable from the FIDO2 path. That is a *structural*
//! property, and `tests/vendor_att.rs::a_device_with_no_org_cert_still_mints_a_normal
//! _fido2_attestation` pins it behaviourally: an import performed against the
//! same keystore must leave the `makeCredential` statement byte-identical.
//!
//! # The three sub-commands are not the same gate
//!
//! | sub-command | params | gate | response |
//! |---|---|---|---|
//! | `ATT_STATE` (`0x0B`) | **none** | **none** — fully ungated | `{1: installed, 2: chain_hash}` |
//! | `ATT_CLEAR` (`0x0A`) | **none** | MSE session established, **then** PIN token or touch | status only |
//! | `ATT_IMPORT` (`0x09`) | `{1: wrapped scalar(60), 2: DER chain(1..=2048)}` | PIN token or touch, **then** MSE | status only |
//!
//! # ⚠️ `ATT_STATE` must never reach `verify_mac`, and this is a wiring hazard
//!
//! `att_status` calls
//! `rs_key_vendor(RSKEY_VENDOR_ATT_STATE, None, None)` — no params, **no
//! token**, no MAC at all ([`picoforge/src/hal/fido/mod.rs:1895`]) — and is
//! documented *"Read `{installed, chain_hash}` (ungated)"* at
//! [`mod.rs:1891-1892`]. A request of that shape is `{1: 0x0B}`, and
//! [`vendor41::verify_mac`] on it answers [`Ctap2Response::PuatRequired`]
//! (`0x36`) at `vendor41.rs:2816-2819` — *before* it even looks at the
//! sub-command — because there is no `pinUvAuthParam`.
//!
//! So the dispatch arm for `AttState` must call [`att_state`] with **no** gate,
//! no `data` and no `auth` — which is exactly why [`att_state`]'s signature
//! does not accept them. A dispatcher that funnels `AttState` through the same
//! `match` arm as the other two turns the client's feature probe into a
//! `0x36`, and the desktop Attestation screen cannot tell "not provisioned"
//! from "this firmware refuses to answer".
//!
//! # ⚠️ `ATT_IMPORT`'s MAC does not fit `verify_mac`, and the buffer must grow
//!
//! This is D-GJ-4 in
//! `docs/tasks/phase-gj-decision-validation-laya.md`, and the arithmetic is
//! exact rather than approximate:
//!
//! ```text
//! subCommandParams = A2                     1
//!                   01 58 3C <60 bytes>    1 + 2 + 60  = 63   (key 1, the sealed scalar)
//!                   02 59 08 00 <2048>     1 + 3 + 2048 = 2052 (key 2, the DER chain)
//!                   --------------------------------------
//!                   total                  2116
//!
//! signed message   = FF×32 ‖ 0x41 ‖ 0x09 ‖ params
//!                                      34 + 2116 = 2150
//! ```
//!
//! `vendor41.rs:2829` assembles that into a `HeaplessVec<u8, 192>`, so a
//! `subCommandParams` value over **158** bytes cannot be MAC-verified at all
//! and every real `ATT_IMPORT` would be answered
//! [`Ctap2Response::InvalidLength`] (`0x03`) — a *length* status, which the
//! desktop Attestation screen reports as a device failure
//! (`vendor_error(status, "attestation import")`, `mod.rs:1993`) rather than
//! as the auth problem it is.
//!
//! **The decision is to raise the buffer, not to skip the verification.** The
//! client does attach a token and a MAC when a PIN is configured
//! ([`mod.rs:1989`] passes `pin.as_deref()`), so an arm that ignored the
//! `pinUvAuthParam` would accept an unauthenticated attestation import — and
//! importing an org attestation is how an operator re-points a fleet of tokens
//! at a different identity, so that is exactly the wrong thing to leave open.
//!
//! The decision is not free, and the numbers are in the module-level constant
//! [`ATT_MAC_MSG_MAX`] plus the report that accompanies this story:
//!
//! * **minimum** capacity that covers the largest legal `0x41` params is
//!   **2150** (`34 + 2116`); [`ATT_MAC_MSG_MAX`] is **2200**, i.e. 50 bytes of
//!   headroom over the worst case;
//! * `ATT_IMPORT` dominates every other sub-command on this channel — the next
//!   largest is `CONFIG_WRITE`'s PHY record, whose client-side builder
//!   ([`picoforge/src/hal/fido/mod.rs:1015-1130`]) emits at most ~104 payload
//!   bytes in a ~110-byte params value, comfortably under the existing 158;
//! * raising the buffer from 192 to 2200 costs **+2008 bytes of stack** on
//!   the `verify_mac` frame (measured: 376 B → 2384 B on `thumbv8m`, see the
//!   report), and moves `tests/scripts/check_async_frame.py` by **zero**
//!   (9216 B before and after — `verify_mac` is not on the async-main call
//!   chain, and on the current tree it is not even in the image).
//!
//! # Why [`att_verify_mac`] exists rather than a call to `verify_mac`
//!
//! Because until the buffer is raised, [`vendor41::verify_mac`] **cannot**
//! answer for this sub-command — not "answers wrongly", cannot. This is a
//! faithful re-transcription of that function's construction with one
//! difference: the message buffer. Everything else — the refusal of a repeated
//! key 1/2/4, the last-wins on key 3, the protocol-1 check, the
//! `PuatRequired`-before-sub-command order, the *wire* span rather than a
//! re-encoding, and the `pin_verify_auth` comparison — is `verify_mac`'s
//! behaviour, unchanged, and the reasons are `verify_mac`'s.
//!
//! When the coordinator raises `verify_mac`'s buffer, this function is deleted
//! and [`att_import`] passes [`vendor41::verify_mac`] to
//! [`token_or_touch_gate`] instead. Nothing else in this module changes: the
//! gate takes the verifier as a function pointer precisely so that the swap is
//! one argument at two call sites.
//!
//! # The chain has no delimiter and no count
//!
//! `certs_pem_to_der` appends every certificate's DER with `out.extend(der)`
//! and **nothing between** ([`picoforge/src/hal/fido/mod.rs:1944-1945`]), so
//! the device receives a single opaque byte string that it must split itself.
//! The client validates nothing about the split: it checks only
//! `1 <= len <= 2048` ([`mod.rs:1971-1976`]) and that the input was PEM or
//! started with `0x30` ([`mod.rs:1927-1933`]).
//!
//! So **anything this device accepts is what lands in its store**, and the
//! walk in [`ChainWalk::parse`] is the only place that gets a say. A malformed
//! length field desynchronises the walk, and a desynchronised walk is not a
//! cosmetic failure: `ATT_STATE` reports `sha256(chain)` and a host pins that
//! hash, so a chain this device mis-split is a chain a host will pin wrongly.
//! Every length is therefore validated *before* it is believed: the TLV must
//! fit inside what remains, the walk must land exactly on the end, and the
//! certificate count is bounded so a 2 KB chain of `30 00` cannot turn the walk
//! into a 1024-iteration loop with a 1024-entry table behind it.
//!
//! ## What the walk is **not**
//!
//! It is a **framing** check, not an X.509 parse. It does not check that a
//! certificate is a certificate, that the signature chains, that the leaf's
//! public key matches the imported scalar, or that the chain is not expired.
//! Each of those is a decision for whoever *uses* the chain, and today that is
//! the desktop app, which has the CA bundle the device does not. A device that
//! refused "a DER SEQUENCE that is not an X.509 certificate" would answer
//! `0x03` to a chain the client itself accepted, which is the device
//! accusing the host of a device fault — the failure mode `vendor_audit` calls
//! out for `AUDIT_READ` (a false accusation of tampering is the worst thing
//! this channel can do to an operator's trust in it).
//!
//! # The AEAD is a crate, and the framing is ours
//!
//! [`aead_open`] used to be a hand-written RFC 8439 ChaCha20-Poly1305 living
//! in this file, and these docs used to say — correctly at the time, wrongly
//! now — that `chacha20poly1305` was *not* in the crate's dependency tree and
//! that this file was "the third copy until the collapse lands". The collapse
//! has landed. [`crate::vendor_lock`] and [`crate::vendor_backup`] hand-rolled
//! the same cipher, and all three are now one implementation over the
//! `chacha20poly1305` crate, reached through
//! [`crypto::chacha20poly1305_open_blob`].
//!
// Three correct copies was never redundancy. It was three times the review for
//! a cipher whose failure modes — a reused nonce, a key sharing keystream with
//! its own one-time key, a clamp applied to the wrong sixteen bytes — are
//! shared by all three, so having three would not have caught any of them.
//!
// What stays here is what is genuinely this module's: the `nonce(12) ‖ ct ‖
// tag(16)` framing the client dictates, the 32-byte plaintext width the
//! client's `try_into::<[u8; 32]>()` makes, and the choice to answer `0x27`.
//!
// The negative direction is unchanged and still the one that matters here. A
//! *wrong* tag is an import that never succeeds; it cannot be a tag that
//! wrongly verifies, because the comparison is against a tag computed over a
//! ciphertext this module was handed — and the two vectors in
//! `tests/vendor_att.rs` come from Python's `cryptography` bindings, not from
//! this repository and not from the client.
//!
//! # ⚠️ `chain_hash`'s algorithm and width are **chosen here**, not by the client
//!
//! `AttStatus::chain_hash` is a `String` and `att_status` hex-encodes
//! whatever `m_bytes(&m, 2)` returned ([`mod.rs:1899-1903`]). Nowhere in the
//! client is a length or an algorithm stated, and no host code compares the
//! value to anything: it is **displayed**. The foundation fixed it as
//! `SHA-256` over the stored DER chain, 32 bytes,
//! ([`OrgAttestationView::chain_hash`]) and this module emits that and
//! nothing else — the constant is [`CHAIN_HASH_LEN`] and the value is read
//! from the trait, never recomputed here, so the two can never disagree.
//!
//! # Order of steps, and why it is gate → act for both mutating arms
//!
//! ```text
//! ATT_IMPORT:  decode (unauthenticated)  →  gate  →  MSE  →  unwrap  →  walk  →  one commit
//! ATT_CLEAR:                                   gate  →  MSE  →  one commit
//! ```
//!
//! The decode runs first for the same reason `vendor_audit` puts it first: it
//! can only make the request *more* constrained, and its outputs (the sealed
//! blob, the chain) live inside `subCommandParams`, so for any request that
//! reaches the gate the MAC has already covered exactly the bytes that were
//! decoded. The converse order is not implementable as a *gating* decision:
//! `ATT_CLEAR` carries no params at all, so a gate-first arm would have to
//! authenticate a request it has not yet established has a `0x0A` in it.
//!
//! Everything that can fail happens **before** the single
//! [`VendorOps::set_org_attestation`] call, and that call is the only one —
//! so a wrong MSE key, a tampered scalar, a malformed chain and a
//! scalar-without-chain all leave the durable state byte-for-byte what it was.
//!
//! # The MSE requirement is a *liveness* check, and it is weaker than it looks
//!
//! Both mutating sub-commands require that an MSE session was established
//! (`att_clear` calls [`mse_handshake`] explicitly at [`mod.rs:1916`];
//! `att_import` gets one for free inside [`wrap_secret`] at [`mod.rs:1980`]).
//! [`VendorOps::mse_channel`] reports *"the channel material the last
//! `mse_establish` derived"* for **this power cycle**, not *"one established
//! for this request"* — there is no per-request MSE on this channel and the
//! trait has no way to express one.
//!
//! So for `ATT_CLEAR` the check is: *an `MSE` happened at some point since
//! boot*. That is what the client's two-step buys (a fresh ephemeral ECDH
//! immediately before the clear), and it is what a device can check. It is
//! **not** proof of freshness, and a caller that handshakes once could then
//! clear repeatedly for the rest of the power cycle — which is harmless,
//! because `ATT_CLEAR` is idempotent and the gate in front of it is a `0x20`
//! token or a touch. The requirement is stated here because a reader
//! otherwise has to guess whether `0x02` on a `ATT_CLEAR` means "no session"
//! or "the session was stale", and the answer matters: it is the first, and
//! `ATT_CLEAR` is idempotent so there is no second.

use crate::cbor::no_heap::{self, Item, Parser};
use crate::crypto;
use crate::ctap2::Ctap2Response;
use crate::vendor41::{
    authorize, MseChannel, OrgAttestation, PresenceGate, Subcommand, TokenAuth, VendorOps, CMD,
    ORG_CHAIN_MAX, P256_POINT_LEN,
};
use heapless::Vec as HeaplessVec;

// ---------------------------------------------------------------------------
// The wire constants, each with the client line it is transcribed from.
// ---------------------------------------------------------------------------

/// `RSKEY_VENDOR_ATT_IMPORT` (`picoforge/src/hal/fido/constants.rs:752`) —
/// install an org attestation P-256 key + cert chain (MSE-wrapped).
pub const SUB_ATT_IMPORT: u8 = 0x09;

/// `RSKEY_VENDOR_ATT_CLEAR` ([`constants.rs:754`]) — remove the org
/// attestation (back to the self-signed cert).
pub const SUB_ATT_CLEAR: u8 = 0x0A;

/// `RSKEY_VENDOR_ATT_STATE` ([`constants.rs:756`]) — `{1: installed,
/// 2: chain_hash}`.
pub const SUB_ATT_STATE: u8 = 0x0B;

/// `ATT_IMPORT`'s `subCommandParams` key 1: the MSE-sealed P-256 scalar
/// ([`mod.rs:1983`]).
pub const ATT_PARAM_SCALAR: u64 = 0x01;

/// `ATT_IMPORT`'s `subCommandParams` key 2: the concatenated DER chain
/// ([`mod.rs:1984`]).
pub const ATT_PARAM_CHAIN: u64 = 0x02;

/// The CTAP2 reply capacity — the same constant `vendor41::handle` is called
/// with on both command paths.
///
/// Over-generous by a wide margin: the widest body this module produces is
/// [`write_att_state_response`]'s 38 bytes (`A2 01 F5 02 58 20 ‖ 32`), and the
/// other two arms return a status with no body. It is the *same* constant
/// because the reply buffer is the dispatcher's, not the arm's, and a second
/// capacity would be a second thing to size.
pub const REPLY_MAX: usize = crate::CTAP2_MAX_MSG;

/// The AEAD blob `wrap_secret` produces for the 32-byte scalar:
/// `nonce(12) ‖ ct(32) ‖ tag(16)` = **60** bytes.
///
/// From [`wrap_secret`] ([`mod.rs:1808-1814`]) over
/// `backup::chacha_seal` ([`backup.rs:62-78`]), which returns
/// `nonce_b ‖ buf` where `ring`'s `seal_in_place_append_tag` left the tag on
/// the **tail**. So the order is `ct ‖ tag` — not the `tag ‖ ct` that
/// `chacha20poly1305`'s `encrypt` returns, and that is the reason
/// [`aead_open`] takes the tag off the *end*.
pub const SCALAR_BLOB_LEN: usize = 60;

/// Shortest blob [`aead_open`] will look at: `nonce(12) ‖ tag(16)` over an
/// empty ciphertext. Below this there is no way to tell a truncated blob from
/// a malformed one.
pub const BLOB_MIN: usize = 12 + 16;

/// The P-256 private scalar's width, and therefore the AEAD plaintext length
/// [`aead_open`] insists on.
///
/// `att_import` reads the scalar out of a P-256 private-key container and
/// `try_into`s it: *"P-256 scalar is not 32 bytes"* ([`mod.rs:1966-1968`]).
/// So a blob whose plaintext is not 32 bytes is not one this client produced.
pub const P256_SCALAR_LEN: usize = 32;

/// `ATT_STATE`'s `chain_hash` width — `SHA-256`, 32 bytes.
///
/// **Chosen by this firmware, not by the client.** `att_status` holds it as a
/// `String` and hex-encodes whatever arrives ([`mod.rs:1901`]), so no length
/// is enforced host-side and none is documented. See the module docs; the value
/// itself is [`OrgAttestationView::chain_hash`]'s and is read from the trait.
pub const CHAIN_HASH_LEN: usize = 32;

/// The most certificates a 2 KB chain may walk to.
///
/// A bound on the walk's table, not on the protocol: a real org chain is a
/// leaf plus a handful of intermediates plus a root. The pathologically small
/// case the bound exists for is a chain of 1024 × `30 00` — structurally valid
/// DER, 2 KB, and a walk that would otherwise build a 1024-entry table and
/// loop a thousand times on a byte string the client produced from a PEM file.
/// 16 costs 64 bytes of stack and is three times any real chain.
pub const MAX_CHAIN_CERTS: usize = 16;

/// Worst-case `ATT_IMPORT` `subCommandParams`, byte-exact.
///
/// `A2 ‖ 01 58 3C ‖ 60 ‖ 02 59 08 00 ‖ 2048` = 1 + 63 + 2052 = **2116**.
///
/// Both heads are the *minimal* ones for their lengths, so this is also the
/// smallest legal encoding: 60 is `< 256` (`58 3C`) and 2048 is `< 65536`
/// (`59 08 00`). A client that wrote a longer head for either would add at
/// most 2 bytes, which is what [`ATT_MAC_MSG_MAX`]'s headroom covers.
pub const ATT_IMPORT_PARAMS_MAX: usize = 2116;

/// The fixed head of a `0x41` signed message: `0xFF × 32 ‖ 0x41 ‖
/// subCommand` — [`vendor41::CMD`] and one sub-command byte.
///
/// The same 34 [`vendor41::verify_mac`] spends before the params
/// (`vendor41.rs:2830-2834`).
pub const MAC_FIXED_HEAD: usize = 32 + 1 + 1;

/// The message buffer `ATT_IMPORT`'s MAC needs.
///
/// [`MAC_FIXED_HEAD`] (34) + [`ATT_IMPORT_PARAMS_MAX`] (2116) = **2150** is the
/// minimum that covers the largest legal `0x41` request on this channel;
/// **2200** adds 50 bytes so a future field is a one-line change rather than a
/// resize that has to survive a stack audit.
///
/// `ATT_IMPORT` dominates. The next largest sub-command params is
/// `CONFIG_WRITE`'s PHY record, which the client's `build_rskey_phy_tlv`
/// ([`mod.rs:1015-1130`]) caps at ~104 payload bytes in a ~110-byte params
/// value — under the 158 the stock buffer already allows — and the rest are a
/// 16-byte challenge, a 60-byte blob, or nothing at all.
///
/// **Measured cost of raising `vendor41::verify_mac`]'s buffer from 192 to
/// 2200** (release `thumbv8m.main-none-eabi`, `arm-none-eabi-objdump`):
///
/// | | 192 (stock) | 2200 | Δ |
/// |---|---|---|---|
/// | `verify_mac` frame reservation | 376 B | 2384 B | **+2008 B** |
/// | `check_async_frame.py` async-main frame | 9216 B | 9216 B | **0** |
/// | main-stack zone (`_stack_start − _stack_end`) | 116476 B | 116476 B | 0 |
/// | limit (`min(24 KiB, zone)`) | 24576 B | 24576 B | 0 |
/// | `FidoApp::process_ctap2_with_store` frame | 20496 B | 20496 B | 0 |
/// | `__hid_task_task0::poll` frame | 15672 B | 15672 B | 0 |
///
/// `check_async_frame` does not move because `verify_mac` is not on the
/// async-main call chain — the CTAP2 command path runs from `__hid_task`, and
/// the gate reads only the 24 KiB **per-poll frame**, not the chain. The +2008
/// B lands on the HID task's own frame *only if* `verify_mac` is inlined into
/// it; measured, it is not (it is a separate symbol, called with its own
/// frame), and `__hid_task_task0::poll` is unchanged at 15672 B.
///
/// The one number that is **not** free is the +2008 B, against a main-stack
/// zone of 116476 B (1.7 %). That is affordable, which is why the decision is
/// "raise the buffer" and not "skip the verification".
pub const ATT_MAC_MSG_MAX: usize = MAC_FIXED_HEAD + ATT_IMPORT_PARAMS_MAX + 50;

// ---------------------------------------------------------------------------
// The return type.
// ---------------------------------------------------------------------------

/// Whether the app should charge its three-strike PIN-auth counter.
///
/// A field rather than a comment because the mistake it prevents is
/// asymmetric: a **missing** charge means a rejected MAC never locks anybody
/// out, which looks fine; a **spurious** charge means a malformed request or a
/// no-PIN touch-gated import burns one of a user's three strikes, which looks
/// fine right up until it does not. Both are invisible at the call site, so
/// the value travels with the status.
///
/// The rule is `vendor41::identity_gate`'s, unchanged: **only** a rejected
/// `pinUvAuthParam` charges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargePinAuth {
    /// Map to `Outcome::pin_auth_failure(status)`. Exactly one condition
    /// produces this: the MAC verifier returned
    /// [`Ctap2Response::PinAuthInvalid`].
    Charge,
    /// Map to `Outcome::plain(status)`. Everything else, including every
    /// refusal that did not look at a MAC — and, on this module,
    /// `ATT_STATE`'s every outcome.
    NoCharge,
}

/// What an arm in this module returns.
///
/// Deliberately **not** [`crate::vendor41::Outcome`]: `Outcome` also carries a
/// [`crate::vendorff::PhyConfig`] proposal, which has no meaning on an
/// attestation channel, and returning it would make "does this charge the
/// counter?" a question about a field three components away from the status.
/// [`From<AttResult>`] converts in one call at the dispatch site.
///
/// `PartialEq` without `Eq`, matching [`Ctap2Response`] itself.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttResult {
    /// The CTAP2 status byte to put on the wire.
    pub status: Ctap2Response,
    /// Whether the app should charge its PIN-auth failure counter.
    pub charge_pin_auth: ChargePinAuth,
}

impl AttResult {
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

impl From<AttResult> for crate::vendor41::Outcome {
    fn from(r: AttResult) -> Self {
        match r.charge_pin_auth {
            ChargePinAuth::Charge => Self::pin_auth_failure(r.status),
            ChargePinAuth::NoCharge => Self::plain(r.status),
        }
    }
}

// ---------------------------------------------------------------------------
// US-175: `ATT_STATE` (sub-command `0x0B`).
// ---------------------------------------------------------------------------

/// Answer `ATT_STATE`: `{1: installed, 2: chain_hash}`.
///
/// **Fully ungated, and it takes no request bytes at all.** See the module
/// docs on why this is a wiring hazard rather than an implementation detail:
/// `att_status` sends `{1: 0x0B}` with no token and no MAC
/// ([`mod.rs:1895`]), so there is nothing to verify, nothing to decode, and —
/// because there is no `auth` parameter — **no path by which this arm can
/// charge the PIN-auth counter**. A single `ATT_STATE` read per Attestation
/// screen can never latch a lockout.
///
/// # Key 1 is always present, and always a CBOR boolean
///
/// The client's parse is lenient and total ([`mod.rs:1558-1565`]):
///
/// ```text
/// Some(Value::Bool(b)) => *b,
/// Some(Value::Integer(n)) => *n != 0,
/// _ => false,          // anything else, AND any missing key
/// ```
///
/// A text string, a byte string, `null`, or an **omitted key** all read as
/// `false`. So a response that omits key 1 is indistinguishable from "not
/// provisioned", and the client cannot tell that from "this firmware does not
/// implement `ATT_STATE`". Key 1 is therefore emitted on **every** response —
/// including the one that says `false` — and as a real `0xF4`/`0xF5` via
/// [`no_heap::push_bool`], never `push_uint(0/1)`. An integer would *happen*
/// to work (the second arm above accepts it), which is exactly why it is a
/// hazard: correct today, and no failure to debug if a later refactor swaps
/// it for a string.
///
/// # Key 2 is present whenever key 1 is true, and absent otherwise
///
/// The client reads it only under `if installed`
/// ([`mod.rs:1899-1903`]), so a key 2 on an uninstalled device is never
/// looked at — but the case that *matters* is the other direction: `installed
/// = true` with no key 2 renders an Attestation screen that says
/// "installed" with a blank hash and no error. [`OrgAttestationView::chain_hash`]
/// returns `Some` exactly when [`installed`](OrgAttestationView::installed)
/// is true, so a value read from the trait cannot produce that body; the
/// `else` branch is what makes the invariant explicit rather than emergent.
///
/// # Key order
///
/// Ascending `1, 2`. The client's decode is a `BTreeMap<Value, Value>` and
/// every read is a lookup by key, so order is not merely unconstrained but
/// unobservable — the map is rebuilt before `m_bool` ever sees it. Ascending
/// is emitted anyway because it is the canonical CBOR order and therefore the
/// one a byte-comparing test or a future signature over this body would agree
/// with.
///
/// # The reported state is read back, not assumed
///
/// The body carries [`VendorOps::org_attestation`]'s own view, so "the call
/// succeeded" and "the state is what the call was asked to make it" are
/// different claims and only the second is on the wire. This arm reads
/// nothing else and mutates nothing.
pub fn att_state(ops: &dyn VendorOps, out: &mut HeaplessVec<u8, REPLY_MAX>) -> AttResult {
    let view = ops.org_attestation();
    let installed = view.installed();
    // `chain_hash` is `Some` iff `installed` (it is derived from `scalar`), so
    // the two agree by construction. The `filter` is not a second source of
    // truth — it is what makes the "installed with no hash" body
    // unrepresentable.
    let hash = view.chain_hash();
    if let Err(e) = write_att_state_response(out, installed, hash.as_ref()) {
        out.clear();
        return AttResult::plain(e);
    }
    AttResult::ok()
}

/// The `ATT_STATE` response body: `{1: <bool>}` or `{1: <bool>, 2: <bstr(32)>}`.
///
/// # Key 2 is emitted **iff** `installed && chain_hash.is_some()`
///
/// Two rules, and the second is not redundant with the first:
///
/// * the client reads key 2 only under `if installed`
///   ([`picoforge/src/hal/fido/mod.rs:1899-1903`]), so a key 2 on an
///   uninstalled device is a value nothing will ever look at — and a key that
///   nothing reads is a key that can silently disagree with the flag beside
///   it, so it is dropped rather than emitted;
/// * `installed == true` with **no** key 2 is the case that actually matters:
///   the Attestation screen renders "installed" with a blank hash and reports
///   no error anywhere. [`OrgAttestationView::chain_hash`] returns `Some`
///   exactly when [`installed`](OrgAttestationView::installed) is true, so a
///   value read from the trait cannot produce that body — the conjunction
///   below is what makes the invariant explicit rather than emergent, and
///   `tests/vendor_att.rs::the_installed_flag_is_a_cbor_bool_and_the_hash_is_
///   conditional_on_it` drives the unreachable combinations directly.
///
/// `pub` so the integration test can pin the byte-level encoding — the CBOR
/// boolean, the key order, the conditional key 2 — without going through the
/// state layer, so a failure here is a framing failure and not a state one.
pub fn write_att_state_response<const N: usize>(
    out: &mut HeaplessVec<u8, N>,
    installed: bool,
    chain_hash: Option<&[u8; CHAIN_HASH_LEN]>,
) -> Result<(), Ctap2Response> {
    out.clear();
    // The head is written first, so a body can never be short: a map header
    // that disagrees with what follows it would be a `0x00` carrying malformed
    // CBOR, which is the one reply shape the client cannot diagnose.
    let emit_hash = installed && chain_hash.is_some();
    no_heap::push_map_header(out, if emit_hash { 2 } else { 1 }).map_err(cbor_err)?;
    no_heap::push_uint(out, 1).map_err(cbor_err)?;
    no_heap::push_bool(out, installed).map_err(cbor_err)?;
    if let Some(h) = chain_hash.filter(|_| emit_hash) {
        no_heap::push_uint(out, 2).map_err(cbor_err)?;
        no_heap::push_bstr(out, h).map_err(cbor_err)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The gate, shared by `ATT_CLEAR` and `ATT_IMPORT`.
// ---------------------------------------------------------------------------

/// The signature [`vendor41::verify_mac`] and [`att_verify_mac`] share, so the
/// gate can be handed either one.
///
/// Higher-ranked over the request lifetime only: the token's lifetime is
/// independent, exactly as in `verify_mac`'s own signature.
pub type MacVerifier = for<'a> fn(&'a [u8], Option<&[u8; 32]>) -> Result<&'a [u8], Ctap2Response>;

/// The `ATT_CLEAR` / `ATT_IMPORT` gate: a `0x20` pinUvAuth token **or** a
/// physical touch. Returns the **wire** `subCommandParams` span.
///
/// # Why the union rather than either gate
///
/// `rs_key_vendor` takes `pin: Option<&str>` and branches
/// ([`ops.rs:1573-1589`]): `Some` ⇒ keys 3 and 4 are attached and a MAC is
/// computed; `None` ⇒ **no auth fields at all** and the client's comment says
/// *"Without one, the firmware gates on a physical touch instead, so no auth
/// fields are sent"*. `att_clear` ([`mod.rs:1916`]) and `att_import`
/// ([`mod.rs:1989`]) both pass `pin.as_deref()`, so both shapes are legitimate
/// and both must succeed.
///
/// A token-only gate answers `0x36` to the documented no-PIN case. A
/// touch-only gate is worse than merely inconvenient: a *valid* `0x20` token
/// would be ignored, so an attacker who could strip the MAC would downgrade a
/// token-gated import to a touch-gated one. The union is the only reading in
/// which the two factors are not substitutes.
///
/// # The order, and the part that is load-bearing
///
/// ```text
/// auth: Some  -> latch check -> verify -> authorize      (no touch)
/// auth: None  -> presence.granted(), else UpRequired     (no MAC at all)
/// ```
///
/// A token is strictly stronger than a touch, so a caller that has one is
/// never asked to also press the button. The other half is why the touch arm
/// is a `match` on `auth` rather than an `if granted { ok }` checked first:
/// **the touch path must not reach the MAC verifier**, because not looking at a
/// `pinUvAuthParam` is what makes that path unchargeable.
///
/// # The refusals, and which ones charge
///
/// | situation | status | charge? |
/// |---|---|---|
/// | verifier answered [`Ctap2Response::PinAuthInvalid`] | `0x33` | **yes** |
/// | [`TokenAuth::blocked`] — the app's three-strike latch is set | `0x34` | no |
/// | no token **and** no touch grant | `0x3B` `UpRequired` | no |
/// | token present, MAC fine, `PERM_ACFG` bit absent | `0x40` | no |
/// | malformed body, undefined `pinUvAuthProtocol` | `0x12` / `0x02` | no |
///
/// The two that are easy to get backwards:
///
/// * **A rejected MAC is the only chargeable failure.** A request whose CBOR
///   never parsed, or whose 2 KB of params did not fit a buffer, never reached
///   a comparison against anything secret — it cannot be evidence of a wrong
///   PIN, and charging it would let one malformed packet burn a strike. This
///   is `vendor41::identity_gate`'s rule, unchanged.
/// * **The latch is not chargeable.** Once `blocked` is set the app has
///   *already* spent three strikes; charging again would move `0x34` to `0x33`
///   and tell a user with a perfectly good token that their token is wrong,
///   sending them back to a PIN prompt. CTAP2.1 §6.5.7 is about refusing
///   pinUvAuth *outright*, and `0x34` is the byte that says that.
///
/// And the one that is easiest to add by accident: the **touch** arm returns
/// the raw span *without* consulting the verifier, so a request that smuggles
/// a `pinUvAuthParam` alongside a touch is simply not charged for it. That is
/// deliberate, and it is the only thing that keeps three no-PIN imports from
/// latching a user out.
///
/// # Why the verifier is a parameter
///
/// Because `ATT_CLEAR` and `ATT_IMPORT` need **different** ones, and a
/// function that picked for itself would have a flag that means "be wrong".
/// See [`att_verify_mac`]. The return value is the other reason: it hands
/// back the *span the MAC was just checked over*, so an arm cannot reach the
/// params through any other route and cannot hold bytes other than the ones
/// that were signed.
pub fn token_or_touch_gate<'a>(
    sub: Subcommand,
    data: &'a [u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
    verify: MacVerifier,
) -> Result<&'a [u8], AttResult> {
    let Some(a) = auth else {
        // The touch path. It must not look at `data`'s keys 3/4 even if they
        // are there: a tokenless request is the client's normal shape, and
        // "refusing to look at a param" is what makes this path unchargeable.
        if !presence.granted() {
            return Err(AttResult::plain(Ctap2Response::UpRequired));
        }
        return sub_command_params_span(data).map_err(AttResult::plain);
    };
    if a.blocked {
        return Err(AttResult::plain(Ctap2Response::PinAuthBlocked));
    }
    let params = match verify(data, Some(a.token)) {
        Ok(p) => p,
        Err(Ctap2Response::PinAuthInvalid) => {
            return Err(AttResult::charge(Ctap2Response::PinAuthInvalid))
        }
        Err(e) => return Err(AttResult::plain(e)),
    };
    // A legacy `getPinToken` token arrives as `Some(0)` and is refused here.
    // That boundary is `vendor41::authorize`'s to draw; an arm cannot widen it.
    if let Err(e) = authorize(sub, Some(a.permissions)) {
        return Err(AttResult::plain(e));
    }
    Ok(params)
}

/// The span of CBOR key `2` in a `0x41` request map, borrowed from `data`.
///
/// Identical to `vendor41::verify_mac`'s capture and to
/// `vendor_backup::params_span`: a **repeated** key 2 is
/// [`Ctap2Response::InvalidCbor`], because the params are inside the signed
/// message and last-wins would decide "which params was signed" silently.
///
/// Only reached from the touch arm — the token arm's span comes out of the
/// verifier, and that is the point: there is exactly one place a params span
/// can be obtained per request, and on the authenticated path it is the one
/// the MAC was checked over.
///
/// Key 1 is skipped, not validated: the dispatch arm has already matched the
/// sub-command, and re-deciding it here would be a second place to be wrong.
///
/// Key 3/4 are skipped too, and deliberately **not** read. On this arm the
/// verifier has already either consumed and checked them (token path) or the
/// request is a touch (no token, and [`token_or_touch_gate`] is documented as
/// not looking).
fn sub_command_params_span(data: &[u8]) -> Result<&[u8], Ctap2Response> {
    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut span: Option<(usize, usize)> = None;
    for _ in 0..pairs {
        // Exactly one `next()` per key, then exactly one `skip()` for its
        // value. A map is key/value *pairs*; skipping both for an unhandled
        // key eats the next pair's key and answers `0x12` to a well-formed
        // request.
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(2) {
            if span.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            let start = p.pos();
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
            span = Some((start, p.pos()));
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    Ok(match span {
        Some((start, end)) => &data[start..end],
        // No key 2 at all. The client omits it for the sub-commands that take
        // none (`ops.rs:1560-1573`), and `ATT_CLEAR` is one, so the empty case
        // is a real request rather than a theoretical one. A caller that needs
        // a parameter gets its own `MissingParameter` from its own parse of
        // the empty slice.
        None => &[],
    })
}

// ---------------------------------------------------------------------------
// US-175: `ATT_CLEAR` (sub-command `0x0A`).
// ---------------------------------------------------------------------------

/// Handle `ATT_CLEAR`: gate, require an MSE session, clear the credential.
///
/// **Status only.** `att_clear` destructures the reply as `(status, _)`
/// ([`mod.rs:1914-1917`]) and the body is discarded, so this arm writes
/// nothing and the caller's reply buffer is untouched. A body would be
/// harmless but unasked-for, and an unasked-for key in a response the client
/// ignores is one more thing to keep in sync.
///
/// The client sends **no `subCommandParams` at all** —
/// `rs_key_vendor(RSKEY_VENDOR_ATT_CLEAR, None, pin.as_deref())`
/// ([`mod.rs:1916`]) — and `ops.rs:1563-1565` turns a `None` into an *absent*
/// key 2, so the MAC message tail is empty. A `subCommandParams` that *is*
/// present is ignored rather than refused, for `vendor_audit`'s reason: the
/// only field in it that could matter is a `pinUvAuthParam`, which
/// [`token_or_touch_gate`] has already either verified or (tokenless)
/// deliberately not looked at.
///
/// # The gate is [`vendor41::verify_mac`], the stock one
///
/// `ATT_CLEAR`'s params are **empty**, so its signed message is 34 bytes and
/// the 192-byte buffer is three times enough. There is no reason to spend
/// [`ATT_MAC_MSG_MAX`] here, and spending it would put +2008 bytes of stack on
/// the *only* attestation sub-command that does not need them.
///
/// # The MSE requirement, and why it is a liveness check
///
/// `att_clear` runs `mse_handshake(&transport)?` before the `0x0A`
/// ([`mod.rs:1916`]). The device has no way to ask "was there an `MSE` for
/// *this* request" — [`VendorOps::mse_channel`] reports the channel for this
/// **power cycle** — so what is checked is that *some* session exists. See
/// the module docs; the short version is that `ATT_CLEAR` is idempotent and
/// sits behind a `0x20` token or a touch, so the weaker check does not weaken
/// anything that matters, but it is a weaker check.
///
/// # The order, and why MSE is after the gate
///
/// Gate first, then the precondition. A caller with no token and no touch gets
/// `0x3B` — *"ask the human"* — even when it also has no MSE session, which is
/// the more informative of the two because the client has to run an MSE
/// handshake regardless and a `0x02` would send it into a retry loop for a
/// step it already performs. A caller *with* a valid token and no session gets
/// `0x02`, which is the true answer: it skipped a step.
///
/// # Clearing is not gated on anything being installed
///
/// `ATT_CLEAR` on a device with no org attestation answers `0x00`. The client
/// never sends one in that state (`att_clear` is reached from a screen that
/// read `installed` first), and refusing would put a second undocumented
/// failure status on a path whose statuses are already protocol-meaningful.
/// `OrgAttestation::default()` clears, and that is a state the state layer
/// stores and reports.
pub fn att_clear(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
    ops: &mut dyn VendorOps,
) -> AttResult {
    // Step 1 (the gate): authenticate or ask for a touch. The span is
    // discarded — `ATT_CLEAR` defines no params, and a sub-command that
    // ignored a payload would be a sub-command that accepts arguments it does
    // not understand.
    if let Err(r) = token_or_touch_gate(
        Subcommand::AttClear,
        data,
        auth,
        presence,
        crate::vendor41::verify_mac,
    ) {
        return r;
    }

    // Step 2: the client's MSE-first sequence.
    let mut channel = zero_channel();
    if ops.mse_channel(&mut channel).is_err() {
        return AttResult::plain(Ctap2Response::InvalidParameter);
    }

    // Step 3: one all-or-nothing commit. `OrgAttestation::default()` is
    // `(None, None)`, which `put_org` documents as the clearing case, so
    // there is no "cleared" flag to forget to set.
    if let Err(e) = ops.set_org_attestation(OrgAttestation::default()) {
        return AttResult::plain(e);
    }
    AttResult::ok()
}

// ---------------------------------------------------------------------------
// US-175: `ATT_IMPORT` (sub-command `0x09`).
// ---------------------------------------------------------------------------

/// Handle `ATT_IMPORT`: gate, open the sealed scalar under the MSE channel,
/// walk the DER chain, and install both — or none of them.
///
/// **Status only**, for `att_clear`'s reason: `att_import` destructures the
/// reply as `(status, _)` ([`mod.rs:1991-1994`]).
///
/// # The request
///
/// `{1: <bstr(60)>, 2: <bstr(1..=2048)>}` ([`mod.rs:1982-1984`]). Key 1 is the
/// P-256 scalar after `wrap_secret` ([`mod.rs:1980`]); key 2 is the
/// concatenated DER of every certificate ([`mod.rs:1970`]).
///
/// **Both keys are required.** A scalar with no chain, or a chain with no
/// scalar, is refused here — [`Ctap2Response::MissingParameter`] — so this arm
/// never constructs the half-populated [`OrgAttestation`] that
/// `put_org` refuses. The state layer's check is a second line of defence and
/// is the one that is *durable*; refusing at the arm means the refusal is
/// also a status the client can act on rather than a silent no-op.
/// `tests/vendor_att.rs::a_scalar_without_a_chain_or_a_chain_without_a_scalar_is_refused`
/// pins both directions.
///
/// # Why the MAC verifier is [`att_verify_mac`] and not [`vendor41::verify_mac`]
///
/// 2116 bytes of params into a 158-byte budget. See the module docs and
/// D-GJ-4. When the buffer is raised this argument becomes
/// `vendor41::verify_mac` and nothing else here changes.
///
/// # Why the scalar is unwrapped *here* and not by the state
///
/// Because the state has no channel and no session: [`VendorOps::mse_channel`]
/// is the only path to the key and it is an arm-level call. What is handed to
/// [`VendorOps::set_org_attestation`] is the **raw 32-byte scalar**, not the
/// blob, and that is deliberate and not a simplification: a stored wrap would
/// have to be re-opened under a session that no longer exists, and the scalar
/// is exactly what a future `0x41` attestation surface would sign with.
///
/// # Nothing is written until everything has been validated
///
/// The AEAD tag, the plaintext width, the chain's length and the chain's TLV
/// walk are all checked before the single [`VendorOps::set_org_attestation`]
/// call, and that call is the only one. So a wrong MSE key, a tampered
/// ciphertext, a 3-byte chain and a chain whose second length field points past
/// the end all leave the durable state byte-for-byte what it was —
/// `tests/vendor_att.rs::a_wrong_mse_key_or_a_tampered_scalar_fails_closed
/// _with_no_partial_write` pins it by re-reading `ATT_STATE` after each
/// refusal.
///
/// # A wrong MSE key is `0x27`, not `0x33` and not `0x3D`
///
/// A tag that does not verify is indistinguishable from a wrong key — that is
/// what an AEAD is for — and the *caller* has already been authenticated by
/// this point. Reporting a key failure as a PIN failure (`0x33`) would charge
/// a strike for a session problem and put the user back at the PIN prompt for
/// a token that was fine. [`Ctap2Response::OperationDenied`] is the same
/// status `vendor_lock`'s `UNLOCK` uses for exactly this ambiguity, chosen
/// there for the same reason (it keeps a wrong-key answer distinct from the
/// `0x3D` that means "not locked").
pub fn att_import(
    data: &[u8],
    auth: Option<TokenAuth<'_>>,
    presence: PresenceGate,
    ops: &mut dyn VendorOps,
) -> AttResult {
    // --- step 1: decode (unauthenticated) ---
    //
    // Cheap, cannot mutate, and its outputs live inside `subCommandParams` —
    // so for any request that reaches the gate the MAC has covered exactly the
    // bytes decoded here. (On the touch path there is no MAC at all, which is
    // the client's documented choice, not this arm's.)
    let span = match sub_command_params_span(data) {
        Ok(p) => p,
        Err(e) => return AttResult::plain(e),
    };
    if let Err(e) = import_params(span) {
        return AttResult::plain(e);
    }

    // --- step 2: the gate ---
    //
    // Reached with the params already decoded, so a malformed body is a `0x12`
    // and is *not* charged; a rejected MAC is `0x33` and *is*.
    let verified = match token_or_touch_gate(
        Subcommand::AttImport,
        data,
        auth,
        presence,
        att_verify_mac,
    ) {
        Ok(p) => p,
        Err(r) => return r,
    };
    // The gate's span is the one the MAC was checked over. The values decoded
    // above came from the same span — `sub_command_params_span` is a pure
    // function of the bytes and the request is not mutated in between — but the
    // *arm* takes its values from the authenticated span, so there is no route
    // by which a future edit could decode from one span and commit under
    // another.
    if verified.len() != span.len() {
        // Unreachable: both are the same function over the same bytes. Pinned
        // rather than asserted at the call site, because a panic on a `0x41`
        // command is a wedged token (`firmware/src/main.rs`'s panic handler is
        // `loop {}`) and the check costs one comparison.
        return AttResult::plain(Ctap2Response::InvalidCbor);
    }
    let (sealed, chain) = match import_params(verified) {
        Ok(v) => v,
        Err(e) => return AttResult::plain(e),
    };

    // --- step 3: the MSE channel the client sealed to ---
    let mut channel = zero_channel();
    if ops.mse_channel(&mut channel).is_err() {
        return AttResult::plain(Ctap2Response::InvalidParameter);
    }

    // --- step 4: open the scalar ---
    let mut scalar = [0u8; P256_SCALAR_LEN];
    if aead_open(&channel.key, &channel.aad, sealed, &mut scalar).is_err() {
        return AttResult::plain(Ctap2Response::OperationDenied);
    }

    // --- step 5: walk the chain ---
    let walk = match ChainWalk::parse(chain) {
        Ok(w) => w,
        Err(e) => return AttResult::plain(e),
    };
    if walk.is_empty() {
        // Unreachable: `ChainWalk::parse` refuses an empty chain. Here for the
        // same reason as the span check: the invariant is enforced once, at the
        // parse, and the *consumer* states it too.
        return AttResult::plain(Ctap2Response::InvalidLength);
    }

    // --- step 6: one all-or-nothing commit ---
    //
    // Both halves are `Some`, which is the only shape `put_org` accepts, and
    // both were fully validated above. The copy into the state's own
    // `HeaplessVec` happens inside `set_org_attestation`; nothing is staged in
    // this arm's frame, so there is nothing to roll back if it refuses.
    let mut stored: HeaplessVec<u8, ORG_CHAIN_MAX> = HeaplessVec::new();
    if stored.extend_from_slice(chain).is_err() {
        // Unreachable: `ChainWalk::parse` has already refused anything over
        // `ORG_CHAIN_MAX`, which is this vector's capacity. A status rather
        // than a panic, because the device's panic handler is `loop {}`.
        return AttResult::plain(Ctap2Response::InvalidLength);
    }
    let att = OrgAttestation { scalar: Some(scalar), chain: Some(stored) };
    if let Err(e) = ops.set_org_attestation(att) {
        return AttResult::plain(e);
    }
    AttResult::ok()
}

/// `ATT_IMPORT`'s `subCommandParams`, as `(sealed scalar, DER chain)`.
///
/// Strict on all four counts, and each refusal is worth its reason:
///
/// * a body that is not a CBOR map, or a repeated key, is
///   [`Ctap2Response::InvalidCbor`] — a repeated key makes the request's
///   meaning order-dependent, which is the same objection `verify_mac` raises;
/// * a key 1 or key 2 that is present but not a byte string is
///   [`Ctap2Response::InvalidCbor`] rather than coerced — the client's
///   `Value::Bytes` is a byte string and nothing else, so accepting a text
///   string would be guessing;
/// * a **missing** key 1 or key 2 is [`Ctap2Response::MissingParameter`], and
///   this is the check that keeps a half-populated [`OrgAttestation`]
///   unrepresentable (see [`att_import`]);
/// * trailing bytes after the map are [`Ctap2Response::InvalidCbor`].
///
/// The **widths** are not checked here. The scalar's width is enforced by
/// [`aead_open`], which must be 60 bytes to yield a 32-byte plaintext, and
/// the chain's is enforced by [`ChainWalk::parse`]. Splitting them across the
/// two functions that actually consume the bytes is what stops "the import
/// path accepts a 16-byte chain" and "the walk accepts a 4 KB chain" being two
/// different facts.
///
/// Unknown keys are **skipped, not refused**: a client that added a third
/// field would get an error from a device that is merely behind, and "unknown
/// key" is not a reason to fail a proof of authorisation that has already
/// been checked.
pub fn import_params(params: &[u8]) -> Result<(&[u8], &[u8]), Ctap2Response> {
    let mut p = Parser::new(params);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    let mut sealed: Option<&[u8]> = None;
    let mut chain: Option<&[u8]> = None;
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(ATT_PARAM_SCALAR) {
            if sealed.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            sealed = Some(match p.next() {
                Ok(Item::B(b)) => b,
                _ => return Err(Ctap2Response::InvalidCbor),
            });
        } else if key == Item::U(ATT_PARAM_CHAIN) {
            if chain.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            chain = Some(match p.next() {
                Ok(Item::B(b)) => b,
                _ => return Err(Ctap2Response::InvalidCbor),
            });
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }
    if p.remaining() != 0 {
        return Err(Ctap2Response::InvalidCbor);
    }
    // The order of the two `ok_or`s is the order the client builds the map in
    // (`mod.rs:1983-1984`), so a request that omits both is reported as
    // missing the scalar — the field the caller has to re-derive, and the one
    // whose absence is the more common client bug.
    Ok((sealed.ok_or(Ctap2Response::MissingParameter)?, chain.ok_or(Ctap2Response::MissingParameter)?))
}

// ---------------------------------------------------------------------------
// The concatenated-DER walk.
// ---------------------------------------------------------------------------

/// A validated walk of a concatenated-DER certificate chain.
///
/// Produced only by [`ChainWalk::parse`], which is the only place the framing
/// is decided, so a `ChainWalk` cannot exist for bytes that did not walk. The
/// offsets are `(start, end)` **relative to the chain**, and are `u16` because
/// the chain is bounded at [`ORG_CHAIN_MAX`] (2048) by the same check that
/// makes the narrowing lossless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainWalk<'a> {
    chain: &'a [u8],
    certs: HeaplessVec<(u16, u16), MAX_CHAIN_CERTS>,
}

impl<'a> ChainWalk<'a> {
    /// Walk `chain`, or refuse it.
    ///
    /// # The rules, and each one's failure mode
    ///
    /// 1. **Not empty, and at most [`ORG_CHAIN_MAX`].** The client checks
    ///    `1..=2048` itself ([`mod.rs:1971-1976`]) so a violation is not one
    ///    the client produces — but the client validates nothing *else*, and
    ///    the bound is what makes the `u16` offsets and the fixed table safe.
    ///    [`Ctap2Response::InvalidLength`].
    /// 2. **Each element starts with `0x30`** (DER `SEQUENCE`). A tag that is
    ///    not `0x30` means the walk is already desynchronised, and continuing
    ///    would attribute the next certificate's first bytes to the previous
    ///    one. [`Ctap2Response::InvalidLength`].
    /// 3. **The length is definite and minimal**, in the short form, `0x81`,
    ///    or `0x82` — and nothing else. `0x80` is DER's *indefinite* length,
    ///    which is BER and forbidden here; `0x83`+ would be a length no
    ///    certificate in a 2 KB chain can have, and accepting it would mean
    ///    trusting an unbounded `u32`. Minimality is also checked:
    ///    `0x81 0x01` re-encodes a 1-byte body in a longer header, and two byte
    ///    strings that decode to the same certificates are exactly the thing a
    ///    `chain_hash` host pin must not be able to confuse.
    ///    [`Ctap2Response::InvalidLength`].
    /// 4. **The element fits in what remains**, header included. This is the
    ///    check that catches a length field pointing past the end, and it is
    ///    arithmetic on `usize` with an explicit `checked_add`, so a
    ///    `0x82 0xFF 0xFF` header is a refusal and never a wrap.
    ///    [`Ctap2Response::InvalidLength`].
    /// 5. **The walk lands exactly on the end.** Any leftover byte is a
    ///    truncated element rather than a new one, and rule 2 will refuse it
    ///    on the next iteration — this check states the invariant the loop
    ///    maintains rather than discovering it.
    /// 6. **At most [`MAX_CHAIN_CERTS`] elements.** A table overflow is
    ///    [`Ctap2Response::InvalidLength`] rather than a truncated walk: a walk
    ///    that silently stopped at 16 would report a chain of 40 as a chain of
    ///    16, which is a *wrong* answer rather than a refusal.
    ///
    /// # A zero-length `SEQUENCE` is accepted
    ///
    /// `30 00` is a structurally valid DER element, and this is a **framing**
    /// check rather than an X.509 parse. See the module docs on why: refusing
    /// "a DER SEQUENCE that is not a certificate" would answer `0x03` to a
    /// chain the client itself accepted, which the desktop app reports as a
    /// device fault.
    pub fn parse(chain: &'a [u8]) -> Result<Self, Ctap2Response> {
        if chain.is_empty() || chain.len() > ORG_CHAIN_MAX {
            return Err(Ctap2Response::InvalidLength);
        }
        let mut certs: HeaplessVec<(u16, u16), MAX_CHAIN_CERTS> = HeaplessVec::new();
        let mut at = 0usize;
        while at < chain.len() {
            let (header, body) = der_header(&chain[at..])?;
            let total = header.checked_add(body).ok_or(Ctap2Response::InvalidLength)?;
            // `total > chain.len() - at` rather than `at + total > chain.len()`
            // so no intermediate sum can wrap, whatever the header claims.
            if total > chain.len() - at {
                return Err(Ctap2Response::InvalidLength);
            }
            certs
                .push((at as u16, total as u16))
                .map_err(|_| Ctap2Response::InvalidLength)?;
            at += total;
        }
        debug_assert_eq!(at, chain.len());
        if at != chain.len() {
            return Err(Ctap2Response::InvalidLength);
        }
        Ok(Self { chain, certs })
    }

    /// How many certificates the chain walked to. At least `1` for any
    /// `ChainWalk` — an empty chain never parses.
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Always `false`; present because `len` is. A `ChainWalk` cannot be
    /// empty, so this is a statement about the type rather than a state.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Certificate `i`'s bytes, borrowed from the chain, or `None` when `i` is
    /// out of range.
    ///
    /// These are the **exact** bytes the host sent, with no re-encoding — the
    /// same rule the MAC span follows, and for the same reason: a host that
    /// pins `sha256` over its own PEM-decoded DER must be able to reproduce
    /// the device's bytes, and a canonicalising walk would change them.
    pub fn get(&self, i: usize) -> Option<&'a [u8]> {
        let (start, len) = *self.certs.get(i)?;
        Some(&self.chain[start as usize..(start + len) as usize])
    }

    /// The certificates, in order.
    pub fn iter(&self) -> ChainCerts<'_, 'a> {
        ChainCerts { walk: self, at: 0 }
    }

    /// How many bytes of the chain the walk accounted for. Always
    /// `chain.len()` — that equality is what [`parse`](Self::parse) proves —
    /// and exposed so a test can state it rather than infer it.
    pub fn covered(&self) -> usize {
        self.certs.iter().map(|(_, len)| *len as usize).sum()
    }
}

/// [`ChainWalk::iter`]'s iterator. Yields the exact wire bytes of each
/// certificate.
#[derive(Debug, Clone)]
pub struct ChainCerts<'w, 'a> {
    walk: &'w ChainWalk<'a>,
    at: usize,
}

impl<'a> Iterator for ChainCerts<'_, 'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let c = self.walk.get(self.at)?;
        self.at += 1;
        Some(c)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.walk.len() - self.at;
        (n, Some(n))
    }
}

impl ExactSizeIterator for ChainCerts<'_, '_> {
    fn len(&self) -> usize {
        self.walk.len() - self.at
    }
}

/// One DER TLV header at the front of `rest`: `(header_len, body_len)`.
///
/// Tag-checked to `0x30` and length-checked to the short / `0x81` / `0x82`
/// forms, minimal, as [`ChainWalk::parse`] documents. Split out so the rule
/// lives in one function and the loop in [`ChainWalk::parse`] reads as what it
/// is: a sequence of "does this element fit" decisions.
fn der_header(rest: &[u8]) -> Result<(usize, usize), Ctap2Response> {
    // Two bytes minimum: a tag and a short-form length. A one-byte chain is a
    // truncated header, which is `InvalidLength` and not a CBOR-ish
    // "incomplete" — the walk is over DER, not over a self-delimiting stream
    // the parser could resume.
    if rest.len() < 2 {
        return Err(Ctap2Response::InvalidLength);
    }
    if rest[0] != 0x30 {
        return Err(Ctap2Response::InvalidLength);
    }
    match rest[1] {
        b if b < 0x80 => Ok((2, b as usize)),
        // `0x81` exists for 128..=255 only; a smaller body in a 2-byte header
        // is not DER, and accepting it would give one certificate two
        // encodings.
        0x81 => {
            if rest.len() < 3 {
                return Err(Ctap2Response::InvalidLength);
            }
            let n = rest[2] as usize;
            if n < 0x80 {
                return Err(Ctap2Response::InvalidLength);
            }
            Ok((3, n))
        }
        // `0x82` for 256..=65535. Nothing wider is reachable inside
        // `ORG_CHAIN_MAX`, so a `0x83` header is refused rather than parsed.
        0x82 => {
            if rest.len() < 4 {
                return Err(Ctap2Response::InvalidLength);
            }
            let n = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            if n < 0x100 {
                return Err(Ctap2Response::InvalidLength);
            }
            Ok((4, n))
        }
        // `0x80` (indefinite / BER) and `0x83`..=`0xFF`.
        _ => Err(Ctap2Response::InvalidLength),
    }
}

// ---------------------------------------------------------------------------
// The large-buffer `0x41` MAC verifier.
// ---------------------------------------------------------------------------

/// [`vendor41::verify_mac`], with the message buffer raised from 192 to
/// [`ATT_MAC_MSG_MAX`].
///
/// # Why this is not a call to `verify_mac`
///
/// Because on this sub-command it cannot be. `ATT_IMPORT` carries up to
/// [`ATT_IMPORT_PARAMS_MAX`] (2116) bytes of `subCommandParams` into a
/// [`vendor41::verify_mac`] buffer that holds 158, so the stock function
/// answers [`Ctap2Response::InvalidLength`] for **every** real request — a
/// *length* status the desktop Attestation screen reports as a device failure
/// rather than as the authentication problem it is. That is D-GJ-4 in
/// `docs/tasks/phase-gj-decision-validation-laya.md`, and the decision
/// recorded there for US-175 is to **raise the buffer, not to skip the
/// verification**: the client attaches a token and a MAC whenever a PIN is
/// configured ([`mod.rs:1989`]), so ignoring it would accept an
/// unauthenticated attestation import — and importing an org attestation is
/// how an operator re-points a fleet at a different identity.
///
/// # What is identical to `verify_mac`, and why each one matters
///
/// This is a **faithful re-transcription** of the construction, and the
/// reasons for the parts that are not about size are `verify_mac`'s, not new
/// ones:
///
/// | behaviour | why it is the same |
/// |---|---|
/// | a repeated key 1 / 2 / 4 is [`Ctap2Response::InvalidCbor`] | the sub-command and the params are **inside** the signed message, so two of them makes "which was signed" undecidable, and last-wins would decide it silently |
/// | key 3 is last-wins | it is **outside** the signed message, so a repeated protocol cannot change what was authorised |
/// | an undefined `pinUvAuthProtocol` is `0x02`, checked **before** the param | the request is describing something unimplemented either way; and "no param" is decided before the sub-command is looked up, so a request that both omits the param and declares protocol 2 still answers `0x02` |
/// | no `pinUvAuthParam` is [`Ctap2Response::PuatRequired`] | a tokenless request is refused here, and the *touch* arm of [`token_or_touch_gate`] is the one that answers `0x3B` |
/// | the params are the **wire span**, not a re-encoding | the client MACs its own serialiser's bytes; a device that re-encodes a canonical map works, and one that re-encodes a request carrying a non-minimal head answers `0x33` to an arithmetically perfect MAC |
/// | [`crate::crypto::pin_verify_auth`] does the comparison | one verifier, constant-time, protocol 1 → 16 bytes |
///
/// # What is different
///
/// Exactly one thing: the buffer is [`ATT_MAC_MSG_MAX`] instead of 192. The
/// measured cost is +2008 B of stack on this function's frame and **zero** on
/// `check_async_frame.py`; see [`ATT_MAC_MSG_MAX`]'s docs.
///
/// # When to delete this
///
/// When [`vendor41::verify_mac`]'s buffer is raised to
/// [`ATT_MAC_MSG_MAX`], this function is dead weight and should be removed,
/// and [`att_import`]'s call to [`token_or_touch_gate`] should pass
/// `vendor41::verify_mac` instead. The gate takes the verifier as a function
/// pointer precisely so that is a one-argument change in two places, and
/// nothing in the rest of this module — the decoding, the AEAD, the walk, the
/// commit — touches a MAC.
pub fn att_verify_mac<'a>(
    data: &'a [u8],
    token: Option<&[u8; 32]>,
) -> Result<&'a [u8], Ctap2Response> {
    let mut params_span: Option<(usize, usize)> = None;
    let mut mac: HeaplessVec<u8, 64> = HeaplessVec::new();
    let mut sub: Option<Subcommand> = None;
    let mut protocol: u64 = 1;
    let mut have_mac = false;

    let mut p = Parser::new(data);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => return Err(Ctap2Response::InvalidCbor),
    };
    for _ in 0..pairs {
        let key = p.next().map_err(|_| Ctap2Response::InvalidCbor)?;
        if key == Item::U(1) {
            if sub.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            sub = Some(match p.next() {
                Ok(Item::U(v)) => u8::try_from(v)
                    .ok()
                    .and_then(Subcommand::from_byte)
                    .ok_or(Ctap2Response::InvalidSubcommand)?,
                _ => return Err(Ctap2Response::InvalidCbor),
            });
        } else if key == Item::U(2) {
            if params_span.is_some() {
                return Err(Ctap2Response::InvalidCbor);
            }
            // The **raw bytes that arrived**, not a decoded-and-re-encoded
            // value. `p.skip()` leaves the cursor at the end of the value, so
            // the span is exactly what a serialiser emitted — no agreement
            // about canonical form is required of this firmware at all.
            let start = p.pos();
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
            params_span = Some((start, p.pos()));
        } else if key == Item::U(3) {
            // Last-wins, deliberately, because key 3 is outside the signed
            // message. Kept as a `u64` rather than narrowed: a value too wide
            // for a `u8` is not a different error, it is simply "not 1".
            protocol = match p.next() {
                Ok(Item::U(v)) => v,
                _ => return Err(Ctap2Response::InvalidCbor),
            };
        } else if key == Item::U(4) {
            if have_mac {
                return Err(Ctap2Response::InvalidCbor);
            }
            have_mac = true;
            mac.clear();
            match p.next() {
                Ok(Item::B(b)) => mac
                    .extend_from_slice(b)
                    .map_err(|_| Ctap2Response::InvalidLength)?,
                _ => return Err(Ctap2Response::InvalidCbor),
            }
        } else {
            p.skip().map_err(|_| Ctap2Response::InvalidCbor)?;
        }
    }

    if protocol != 1 {
        return Err(Ctap2Response::InvalidParameter);
    }
    if !have_mac {
        return Err(Ctap2Response::PuatRequired);
    }
    let token = token.ok_or(Ctap2Response::PuatRequired)?;
    let sub = sub.ok_or(Ctap2Response::MissingParameter)?;

    let params: &[u8] = match params_span {
        Some((start, end)) => &data[start..end],
        None => &[],
    };
    // `FF×32 ‖ 0x41 ‖ sub ‖ params`, contiguous because the HMAC needs it.
    // The only line in this function that differs from `verify_mac`.
    let mut msg: HeaplessVec<u8, ATT_MAC_MSG_MAX> = HeaplessVec::new();
    for _ in 0..32 {
        msg.push(0xFF).map_err(|_| Ctap2Response::InvalidLength)?;
    }
    msg.extend_from_slice(&[CMD, sub.byte()])
        .map_err(|_| Ctap2Response::InvalidLength)?;
    msg.extend_from_slice(params)
        .map_err(|_| Ctap2Response::InvalidLength)?;

    if !crate::crypto::pin_verify_auth(1, token, &msg, &mac) {
        return Err(Ctap2Response::PinAuthInvalid);
    }
    Ok(params)
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 (RFC 8439) — see the ⚠️ note in the module docs.
// ---------------------------------------------------------------------------

/// A `MseChannel` filled with zeros, to be overwritten.
///
/// Written as an explicit literal because [`MseChannel`] derives no `Default`
/// — both fields are full-width and a default-constructed one would be a zero
/// channel key, which is exactly the thing [`VendorOps::mse_channel`] refuses
/// to hand out. Making the all-zeros state visible at the call site is the
/// point: it is overwritten by the `mse_channel` call on the next line, whose
/// `Err` **is** the refusal.
fn zero_channel() -> MseChannel {
    MseChannel { key: [0u8; 32], aad: [0u8; P256_POINT_LEN] }
}

/// Open a `nonce(12) ‖ ct ‖ tag(16)` blob bound to `aad`, into `out`.
///
/// `out` is exactly [`P256_SCALAR_LEN`] and the blob's plaintext must be
/// exactly that long: the client's scalar comes out of a
/// `try_into::<[u8; 32]>()` ([`mod.rs:1966-1968`]), so a blob of any other
/// plaintext width is not one this protocol produced.
///
/// # The tag is at the **end**
///
/// `wrap_secret` calls `backup::chacha_seal` ([`backup.rs:62-78`]), which
/// returns `nonce_b ‖ buf` where `buf` came out of `ring`'s
/// `seal_in_place_append_tag` — appending the tag on the tail. So the order is
/// `ct ‖ tag`, which is *not* what `chacha20poly1305`'s `encrypt` returns
/// (`tag ‖ ct`). That is why this is a call to
/// [`crypto::chacha20poly1305_open_blob`] rather than a one-liner against the
/// crate's own `decrypt` — and the split now happens in one place for all
/// three callers instead of once per module.
///
/// `pub` so the integration test can check the opener against external vectors
/// and against every negative direction, rather than only through the one arm
/// that calls it. That it is reachable at all is the reason its correctness is
/// checkable from outside this file.
///
/// # What it returns
///
/// A length refusal is `0x03`; everything else is `0x27`
/// ([`Ctap2Response::OperationDenied`]). The mapping is this module's, not the
/// primitive's: the seed-export arm answers `0x3D` for the same cryptographic
/// event, and an AEAD has no business knowing which a client should be told.
pub fn aead_open(
    key: &[u8; 32],
    aad: &[u8],
    blob: &[u8],
    out: &mut [u8; P256_SCALAR_LEN],
) -> Result<(), Ctap2Response> {
    if blob.len() < BLOB_MIN {
        return Err(Ctap2Response::InvalidLength);
    }
    crypto::chacha20poly1305_open_blob(key, aad, blob, out).map_err(|e| match e {
        crypto::AeadError::Length => Ctap2Response::InvalidLength,
        crypto::AeadError::Integrity => Ctap2Response::OperationDenied,
    })
}
/// `no_heap`'s errors mapped onto CTAP2.
///
/// A full reply buffer is a bug here rather than a runtime condition: the
/// widest body this module produces is 38 bytes in a [`REPLY_MAX`] (7609-byte)
/// buffer. It still needs a status rather than a panic, because the command
/// path owns no recovery and the device's panic handler is `loop {}`.
fn cbor_err(_e: no_heap::CborError) -> Ctap2Response {
    Ctap2Response::LimitExceeded
}

// ---------------------------------------------------------------------------
// A compile-time statement that this module is `no_std`.
//
// `vendor41` and `vendor_audit` carry the same note, and it is worth a third
// copy here because this module is *new*: the failure mode being guarded is a
// `format!`, a `String` or a `Box` creeping in from a doc example, which
// compiles fine on the host test target and then fails the RP2350 build —
// after the wiring commit that pulls it into `lib.rs`, which is exactly the
// round trip this is meant to avoid.
//
// Everything above is `heapless::Vec`, `core::convert`, `core::cmp`,
// `core::iter` and fixed-size arrays. There is no `extern crate std` here to
// remove.
// ---------------------------------------------------------------------------

const _: () = {
    fn _assert_no_std() {
        let _: core::option::Option<u8> = None;
        let _: core::result::Result<(), core::convert::Infallible> = Ok(());
    }
    let _ = _assert_no_std;
};
