//! Heapless YKOATH device app (S-711-1, US-353).
//!
//! no_std port of the host `oath` applet: a bounded 68-slot credential table
//! (the chunked-keystore bound; C itself allows 255 slots) with borrowed TLV
//! parsing following `otp.rs::parse_apdu`, plus
//! `boot`/`persist_state` over the `oath.keystore.v1` migration stream via
//! the chunked secure store (fact 8).
//!
//! Stream format (US-413 migration): a record stream of
//! `[fid u16 LE][len u32 LE][payload]` — FIDs `0xBA00..=0xBAFE` are
//! credentials (payload = TLV: TAG_NAME/TAG_KEY/TAG_IMF, C file contents) and
//! `0xBAFF` is the raw OATH access-code key value (no TLV wrapper — C
//! `EF_OATH_CODE` stores the TAG_KEY value verbatim).
//!
//! Scope notes (deliberate):
//! - US-1030: **credential keys are sealed; the access code is not.** Every
//!   credential's `TAG_KEY` is stored as a C-format `"OATH"`-magic GCM
//!   record ([`fapico2_platform::ckey::OathSeal`], unwrapped with the flash
//!   UID + the OTP key row — the key material this path could not reach
//!   before, which is why the first cut of this note said the C sealed form
//!   was not unwrapped here). The plaintext exists only in the running app.
//!   The `0xBAFF` access-code record stays in the clear **on purpose**:
//!   `PICOForge-COMPAT` US-131 replaced the access code with a YKOATH
//!   shared key the device cannot one-way verify, and that phase's
//!   US-1031 acceptance text says so explicitly — "the test asserts the
//!   credential table is what stays sealed". Sealing it would also break
//!   every Yubico client, which is the trade US-131 took deliberately.
//! - The seal's AEAD nonce is a **per-key monotonic generation counter**
//!   ([`SLOT_OATH_SEAL_GENERATION`]), never `store_v3`'s content-hash
//!   scheme: that scheme is sound for a whole-image seal rewritten
//!   atomically and leaks a per-slot change oracle here. See
//!   [`fapico2_platform::ckey::OathSeal::nonce_for`].
//! - The SELECT challenge is session state (C regenerates the challenge on
//!   every SELECT) and is not part of the persisted stream. The OTP PIN
//!   record IS durable since US-904: stream fid `0xBA44` carries
//!   `[counter][salt 16][verifier 32]` (a legacy 33-byte `[counter][verifier]`
//!   record loads and upgrades at the next successful verification).
//! - On boot, credential records that do not decode (missing/oversized
//!   TAG_NAME or TAG_KEY, slot index ≥ 68) are skipped; framing corruption
//!   and an oversized access code are boot errors (the S-711-2 wiring is
//!   fatal-on-error — a locked code must never silently become unlocked).
//! - **The real durable ceiling is 30 maximal credentials**, not 68. US-1010
//!   measured it (`apps/oath/tests/oath_capacity.rs`): a maximal record costs
//!   182 B of stream, and 30 of them are 5,460 B = 12 chunked parts (11 × 496
//!   = 5,456 is 4 B short). The 31st is 5,642 B and is **still 12 parts** —
//!   it does not need a 13th, and it still fits the 5,952 B logical bound.
//!   What stops it is the **rewrite peak**: the double-buffered rewrite holds
//!   the live generation and the one being written at the same time, and this
//!   app also holds one resident entry outside the chunked table (the US-1030
//!   seal high-water mark, `oath.seal.gen.v1`). Persisting 31 would be a
//!   `12 → 12` rewrite peaking at `12 + 12 + 1 = 25 > ` the device store's 24
//!   entries, so `persist_state` reports failure and keeps the dirty flag
//!   (state is retried on the next persist). The 30th is reachable precisely
//!   because it is the first credential to reach 12 parts, and reaching them
//!   rewrites *from* 11: `11 + 12 + 1 = 24 ≤ 24`.
//!
//!   US-133 adds 3 more bytes per credential that carries a property, which
//!   tightens that ceiling a little; it does not change its character. Note
//!   what the ceiling being a *peak* means in use: a PUT that **replaces** a
//!   credential at 30 is a same-width `12 → 12` rewrite, so it is accepted
//!   (`0x9000`) and then not made durable. That is the same clean, retryable
//!   capacity failure, stated here rather than discovered in the field.
//!
//!   The ceiling is set by the **part count under the double-buffered
//!   rewrite**, not by the byte count. Arithmetic done on bytes alone produces
//!   a number the device will not serve, and so does arithmetic that forgets
//!   the resident seal slot — `2 × MAX_PARTS` is the *resident-free* form and
//!   is exactly on the limit, which is why the real app does not get it.
//!   `MAX_CREDS` below is a different kind of bound — a `heapless` table
//!   bound, never a capacity claim.
//!
//!   **All of that paragraph describes the legacy path, and US-1553 replaces
//!   it.** With a key region attached ([`OathApp::attach_region`]) the table is
//!   no longer a chunked whole snapshot in the 24-entry image shared with
//!   FIDO: each credential is one record in one slot of the key region
//!   (`fapico2_platform::keyregion::oath_store`), committed one at a time, so
//!   the double-buffered rewrite peak — the only thing that made the ceiling a
//!   *peak* — does not exist. The ceiling becomes [`MAX_CREDS`], the same
//!   number the table was always sized for, and OATH and FIDO stop competing
//!   for the same entries. The legacy stream is still **read** (the US-413
//!   migration) and still **written** for the records that are not credentials
//!   — the access code and the US-904 OTP-PIN verifier — so `encode_state` is
//!   not dead code.
//!
//!   **Wiring: the region path is live on a device build.** `main.rs` installs
//!   [`install_region_provider`] immediately after `boot::release_key_region()`
//!   — mirroring `fapico2_fido::device_app::install_region_provider` and its
//!   call site — and [`OathApp::attach_region_if_available`] mounts on the
//!   first command. The legacy path remains the fallback whenever the provider
//!   yields nothing, which is what a device with an unavailable OTP row gets:
//!   `boot::derive_oath_payload_key` is an `Option` and answers `None` rather
//!   than halting (S10), and that applet serves the chunked store at the
//!   legacy ceiling. So [`MAX_CREDS`] is the ceiling **when the region mounts**,
//!   and the legacy one otherwise — which is the honest form of the claim, and
//!   why `docs/capacity.md`'s OATH row is still labelled a reservation.
//!
//! - US-1553 (secure storage): **credentials are per-record in the key region,
//!   and the secure store holds no credential table.** The properties are
//!   argued where they are implemented, not here:
//!   * *a mutation is one record, not one table* — [`OathApp::region_sync`], so
//!     a PUT costs one sector erase instead of a 12-part double-buffered
//!     rewrite, and a failure costs one credential rather than the set;
//!   * *durable-before-ack is not weakened* — the record is written **before**
//!     the command returns, and a refused commit rolls the in-RAM table back
//!     and then re-reads the medium, which is authoritative
//!     ([`OathApp::region_reconcile`]);
//!   * *the US-1030 seal-generation ordering is subsumed, not dropped* — the
//!     nonce generation is now the record's own generation, so the counter and
//!     the sealed bytes are programmed by one sector-atomic commit and no
//!     window exists in which one is ahead of the other. The argument is in
//!     `keyregion/oath_store.rs`, "Why the seal generation is the record
//!     generation"; `oath.seal.gen.v1` is still reserved and written on the
//!     legacy path only;
//!   * *the boot path does not touch the region* (S8/S9) — `attach_region` is
//!     to be called at first applet use, after `RUNG_USB`, never from
//!     `OathApp::boot` or `boot_in_place`, and
//!     `apps/oath/tests/oath_keyregion.rs` asserts that a booted app whose
//!     region is mounted never touches the medium. `main.rs` installs the
//!     provider **after** `mark!(RUNG_USB)` for exactly that reason, and
//!     `platform/tests/key_region_boot_gate.rs` fails if either the ordering or
//!     the mount sites move.
//!   * *an unreadable region degrades* — [`OathApp::attach_region`] returns
//!     [`RegionStatus::Degraded`] and the applet serves an **empty** credential
//!     set with a clean status word. Never `fatal_boot`, never a panic: a
//!     failing flash must not become a board that will not enumerate over USB.
//! - US-133 (PICOForge-COMPAT): a credential's Yubiko property bits are
//!   stored with it (`Cred::props`, persisted as a trailing **bare**
//!   `78 <props>` object — the same two-byte dialect the PUT request parser
//!   accepts, *not* `78 01 <props>` BER; see `encode_state`) and the
//!   one bit this firmware enforces, require-touch, gates both
//!   reveal paths — CALCULATE and CALC ALL. A PUT asking for a bit that is
//!   *not* enforced is refused, never accepted and dropped. C-produced
//!   migration records carry no property TLV and decode to "no properties"
//!   unchanged, so the US-413 stream format does not move.

use crate::ct::ct_eq;
use alloc::boxed::Box;
use fapico2_platform::ckey::{OathSeal, OATH_SEAL_OVERHEAD};
use fapico2_platform::dispatch::{App, Sw, MAX_RESPONSE};
use fapico2_platform::keyregion::oath_store::{
    self, Entry, OathCredential, OathStoreError,
};
// US-1553: re-exported because the firmware has to name it to build one. A
// `use` is private to this module, so without this the type is unreachable from
// `main.rs` even though the applet is public.
pub use fapico2_platform::keyregion::oath_store::OathRegion;
use fapico2_platform::presence::PresenceService;
use fapico2_platform::secure_store::chunked;
use fapico2_platform::secure_store::chunked::MAX_LOGICAL_LEN;
use fapico2_platform::secure_store::{SecureStore, SecureStoreError};
use fapico2_platform::trng::Trng;
use heapless::Vec as HeaplessVec;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
/// US-1070: the rolled SHA-512 compression, not `sha2::Sha512`. A `digest`-trait
/// drop-in, so `Hmac` over it is the same construction with the same 128-byte
/// block size and the same 64-byte tag; the key schedule and the output bytes
/// are unchanged and the difference is entirely in code size behind them.
/// Byte-identity is tested, not assumed — see
/// `platform/tests/sha512_differential.rs`.
///
/// The host-only legacy applet (`oath.rs`, `#[cfg(feature = "host")]`) still
/// names `sha2::Sha512`, and deliberately so: it is not in the device
/// closure, so the swap would buy nothing on the RP2350 and would put a
/// differentially-tested dependency into a file kept for host dispatcher
/// tests.
type HmacSha512 = Hmac<fapico2_platform::sha512::Sha512>;

/// OATH AID (C `oath_aid`).
pub const OATH_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

// ISO 7816 status words (mirroring the C firmware's apdu.h).
const SW_OK: Sw = 0x9000;
const SW_WRONG_DATA: Sw = 0x6700;
const SW_SECURITY_STATUS_NOT_SATISFIED: Sw = 0x6982;
const SW_DATA_INVALID: Sw = 0x6984;
const SW_CONDITIONS_NOT_SATISFIED: Sw = 0x6985;
const SW_FILE_FULL: Sw = 0x6A84;
const SW_INCORRECT_PARAMS: Sw = 0x6A80;
const SW_INCORRECT_P1P2: Sw = 0x6A86;
const SW_INS_NOT_SUPPORTED: Sw = 0x6D00;

// TLV tags.
const TAG_NAME: u8 = 0x71;
const TAG_NAME_LIST: u8 = 0x72;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_RESPONSE: u8 = 0x75;
const TAG_NO_RESPONSE: u8 = 0x77;
/// US-133 (PICOForge-COMPAT): the per-credential property object. There was
/// no constant for this tag in the file at all before the story, which is
/// precisely why the object was silently discarded.
const TAG_PROPERTY: u8 = 0x78;
const TAG_VERSION: u8 = 0x79;
const TAG_IMF: u8 = 0x7A;
const TAG_PASSWORD: u8 = 0x80;
const TAG_NEW_PASSWORD: u8 = 0x81;

/// US-133 (PICOForge-COMPAT): Yubico property bits, the value byte of the
/// bare `78 <props>` object.
const PROP_PWS: u8 = 0x01;
const PROP_TOUCH: u8 = 0x02;
/// The bits this firmware actually **enforces**.
///
/// US-133: this is a deliberate allow-list, not a mask. A PUT carrying any
/// bit outside it is refused with [`SW_INCORRECT_PARAMS`] rather than
/// stored-and-ignored, because "the host asked for a protection and the
/// token silently did not apply it" is a worse outcome than "the host was
/// told no". `PROP_PWS` is the one bit that is defined but *not* enforced:
/// PWS asks the applet to re-check the access code before every reveal,
/// which needs a session re-grant this applet does not model. It is named
/// here (rather than left as a bare literal in [`cmd_put`]) so the gap is
/// visible at the definition site and the day it is implemented the
/// allow-list is the only line that has to change.
const PROP_ENFORCED: u8 = PROP_TOUCH;
/// The gap, asserted rather than only described: the enforced set must
/// never grow to cover PWS by accident. When the session re-grant lands,
/// this assertion is the line that has to be deleted on purpose.
const _: () = assert!(PROP_ENFORCED & PROP_PWS == 0);

/// US-130 (PICOForge-COMPAT): length of the `TAG_NAME` TLV value — the
/// **device-id**, i.e. the PBKDF2 salt a host feeds to derive the OATH access
/// key (`picoforge::hal::applets::oath::derive_access_key`). The YKOATH TLV
/// length is a single byte, and the applet emits 8, so the value is
/// fixed-width by construction: the field is `[u8; DEVICE_ID_LEN]`, never a
/// `Vec`, and the length byte is derived from the constant rather than
/// hardcoded.
pub const DEVICE_ID_LEN: usize = 8;

/// US-130: fixed emulation chip-id — host/emulation builds have no OTP row,
/// so the stand-in is the same one the USB `iSerialNumber` and the management
/// `TAG_SERIAL` derive from
/// ([`fapico2_platform::usb_ident::EMULATION_CHIPID`], US-103/R12), keeping
/// every derived identity in the emulation path deterministic and mutually
/// consistent. **Device builds must inject the real chip-id** through
/// [`OathApp::with_chipid`].
pub const EMULATION_CHIPID: u64 = fapico2_platform::usb_ident::EMULATION_CHIPID;

/// US-130 (PICOForge-COMPAT): the OATH device-id for a chip-id,
/// `SHA-256(chipid.to_be_bytes())[..8]`.
///
/// **Why a hash and not the raw chip-id.** The value is public — every SELECT
/// returns it — and is used only as a PBKDF2 *salt*, so it wants a stable,
/// uniform, structure-free 8-byte encoding rather than the chip-id itself
/// (whose low bits are not uniform). The hash is reused rather than a second
/// one invented: [`fapico2_platform::ckey::serial_hash`] is the codebase's
/// existing device-bound hash, and it is the *same* function
/// `usb_ident::serial_hash4` feeds the chip-id for the USB serial and the
/// management `TAG_SERIAL` (US-103/R12). All three device-bound identities
/// are therefore one hash of one input and cannot drift apart; only the
/// truncation length differs (8 bytes here, 4 for the management TLV, 8
/// rendered as decimal digits for USB).
///
/// Deterministic and float-free — SHA-256 over 8 big-endian bytes, so the
/// device (`thumbv8m`) and the host produce bit-identical bytes and no
/// rounding or libc difference can move them.
///
/// Not a secret and not secret-derived: it comes from a public identifier and
/// is disclosed by SELECT. The *password* supplies the entropy; the salt only
/// has to be per-device so one cracked blob does not unlock every other unit.
pub fn device_id_from_chipid(chipid: u64) -> [u8; DEVICE_ID_LEN] {
    let h = fapico2_platform::ckey::serial_hash(&chipid.to_be_bytes());
    [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]
}

// Key algorithm/type masks.
const TYPE_MASK: u8 = 0xF0;
const TYPE_HOTP: u8 = 0x10;
const ALG_MASK: u8 = 0x0F;
const ALG_SHA1: u8 = 0x01;
const ALG_SHA256: u8 = 0x02;
const ALG_SHA512: u8 = 0x03;

// Commands.
const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RESET: u8 = 0x04;
const INS_RENAME: u8 = 0x05;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_VALIDATE: u8 = 0xA3;
const INS_CALC_ALL: u8 = 0xA4;
const INS_SEND_REMAINING: u8 = 0xA5;
const INS_VERIFY_CODE: u8 = 0xB1;
const INS_VERIFY_PIN: u8 = 0xB2;
const INS_CHANGE_PIN: u8 = 0xB3;
const INS_SET_PIN: u8 = 0xB4;

/// US-921/US-903: presence command tag for RESET (INS 0x04) — mgmt parity,
/// the command's own INS. The tag binds a pending presence request to
/// exactly the command that declared it: the device's shared presence
/// runtime grants only the pending tag, so a press latched for another
/// command can never arm the wipe.
pub const PRESENCE_TAG_RESET: u32 = 0x04;
/// US-905/US-921: presence command tag for SET_CODE with empty data
/// clearing a present access code (INS 0x03) — RESET-parity presence
/// consumer (see [`PRESENCE_TAG_RESET`]).
pub const PRESENCE_TAG_SET_CODE_CLEAR: u32 = 0x03;
// Tie the tags to the INS constants they mirror (const `From` is not
// stable, hence the literals above).
const _: () = assert!(PRESENCE_TAG_RESET as u8 == INS_RESET);
const _: () = assert!(PRESENCE_TAG_SET_CODE_CLEAR as u8 == INS_SET_CODE);
/// US-133 (PICOForge-COMPAT): presence tag for CALCULATE (INS 0xA2) on a
/// credential that carries [`PROP_TOUCH`]. Distinct from the CALC ALL tag
/// below so a press latched for one reveal path can never arm the other.
pub const PRESENCE_TAG_CALCULATE: u32 = 0xA2;
/// US-133 (PICOForge-COMPAT): presence tag for CALC ALL (INS 0xA4) when the
/// table holds a [`PROP_TOUCH`] credential. See [`OathApp::cmd_calculate_all`]
/// for why the gate covers the whole stream.
pub const PRESENCE_TAG_CALC_ALL: u32 = 0xA4;
const _: () = assert!(PRESENCE_TAG_CALCULATE as u8 == INS_CALCULATE);
const _: () = assert!(PRESENCE_TAG_CALC_ALL as u8 == INS_CALC_ALL);

/// OTP PIN retry budget (C: MAX_OTP_COUNTER); each check decrements it and a
/// successful verify rewrites the record, resetting the budget.
const MAX_OTP_COUNTER: u8 = 3;

// Storage bounds (heapless).
//
// US-1010: this comment used to say "chunked-keystore bound (the table stream
// must fit MAX_LOGICAL_LEN)", which is false twice over. It is a `heapless`
// **table** bound — it sizes `Cred` slots in RAM, nothing else — and even as a
// stream bound it is unreachable: 68 × 182 B ≈ 12.4 KB against a 5,952 B
// logical cap. The real durable ceiling is **30**, measured in
// `apps/oath/tests/oath_capacity.rs` and derived from the peak of the
// double-buffered rewrite, not from the bytes (see the module docs).
//
// NOT C parity — C allows 255 slots.
const MAX_CREDS: usize = 68;

// US-1553: the RAM table bound and the region's OATH reservation must be the
// same number, and this is the line that keeps them so.
//
// It is the one cross-crate claim in this file that cannot be a `pub use`
// (`platform` does not depend on `apps/oath`, and the dependency runs the other
// way), so it is a `const` assertion over two literals rather than a link. A
// region that could hold fewer credentials than the table has slots would make
// the *extra* table entries unwritable; one that could hold more would refuse
// on a bound this applet never mentions. Both are capacity claims, and
// `mod.rs` refuses to let either be asserted instead of derived — so the
// agreement is asserted here, in the one place both numbers are in scope.
const _: () = assert!(
    oath_store::OATH_SLOTS as usize == MAX_CREDS,
    "the key region's OATH reservation and this applet's table must be the same bound — one \
     bigger makes table entries unwritable, one smaller makes the store refuse on a RAM bound \
     it never mentions"
);

const MAX_NAME: usize = 64;
/// Stored key TLV value: [alg|type, digits, secret ≤ 64].
const MAX_KEY: usize = 66;
/// C `OATH_ACCESS_CODE_MAX_LEN`.
const MAX_ACCESS_CODE: usize = 65;

/// The access code a device ships with, and the reason "no access code" can
/// never mean "open".
///
/// # Why a device that trusts nobody has a code everyone knows
///
/// US-901 granted a session only to a **virgin** applet, so a device holding
/// credentials and no access code was locked — and both first-party clients
/// cannot recover from that, because `yubikit/oath.py`
/// (`_has_key = self._challenge is not None`) and picoforge
/// (`info.password_set()`) decide whether to authenticate from the SELECT
/// response's `74` challenge TLV alone, which this applet emits only when an
/// access code exists. Every credential command then answered `0x6982`, and
/// `SET_CODE` — the only way out — sat behind the same gate.
///
/// Relaxing that to "granted whenever there is no code" fixed the clients and
/// **reopened a closed red-team finding**: with no code configured, an
/// unauthenticated session could `LIST` every credential name and `CALC_ALL`
/// every live TOTP digest.
///
/// This is the third option, and it is the one that keeps both. The applet
/// always has a secret to authenticate against — a **known** one — so an
/// unauthenticated session is refused exactly as before, while a client that
/// *can* authenticate is not locked out. The owner types `123456` once, the
/// same default they already type for OpenPGP's user PIN, and changes it from
/// either GUI afterwards.
///
/// # The residual, stated plainly
///
/// Until the owner changes it, anyone holding the token who tries `123456`
/// gets in. That is **not** a mitigation — it is the OpenPGP default-PIN
/// posture, chosen deliberately: the protection a user relies on is a
/// credential they have changed, and a documented default is visible where a
/// hidden lockout is not. It is recorded in `docs/secure-storage-story-matrix.md`
/// and the OATH section of `AGENTS.md` so no future reader mistakes it for
/// defence in depth.
pub const DEFAULT_ACCESS_CODE: &[u8] = b"123456";
const FID_CRED_BASE: u16 = 0xBA00;
const FID_CRED_MAX: u16 = FID_CRED_BASE + MAX_CREDS as u16 - 1;
const FID_ACCESS_CODE: u16 = 0xBAFF;
/// `oath.keystore.v1` slot (US-413 migration format).
const STATE_SLOT: &[u8] = b"oath.keystore.v1";

/// US-1030: the device-wide **seal high-water mark** — a big-endian `u64`
/// in its own store slot, outside the credential stream.
///
/// # Why it is a device-wide slot and not a field in each record
///
/// A per-record counter restarts at zero when a credential is deleted and
/// the slot index is reused, which would re-derive the nonce that slot's
/// first key already used — under the *same* AEAD key and with a *different*
/// plaintext. That is a nonce-reuse forgery, not a theoretical one: PUT,
/// DELETE, PUT on the same index is an ordinary sequence of YKOATH
/// commands. So the counter is a high-water mark the whole table draws
/// from, and it is **never** reset — not by `RESET`, not by
/// `factory_wipe`, not by a re-provision. It is only ever written forward.
///
/// # Why it is a separate slot rather than a field inside the stream
///
/// Both live in the same store image, so both are programmed atomically by
/// the two-slot persist discipline — that part is equal. The separate slot
/// is what keeps the counter out of `encode_state`'s failure modes (the
/// logical-cap `None`, a refused write) and, more importantly, out of every
/// code path that clears the table. A counter living inside the stream
/// would be reset by the very `RESET` that empties the table.
pub const SLOT_OATH_SEAL_GENERATION: &[u8] = b"oath.seal.gen.v1";
/// US-1030: the per-credential seal generation object, carried beside the
/// sealed `TAG_KEY` in the record payload: `7B 08 <generation BE>`.
///
/// Outside the AEAD on purpose. The blob is byte-identical to C's
/// `"OATH"` record so a C firmware can still read it, and there is nowhere
/// inside that layout to put a counter. It does not need to be *inside*
/// the AEAD to be trustworthy: the nonce is derived from it, so altering it
/// derives a different nonce and the GCM tag then fails. A forged
/// generation is a failed open (refused), never a silent re-key.
const TAG_SEAL_GENERATION: u8 = 0x7B;
/// US-1030: the stored size of a generation object.
const SEAL_GENERATION_LEN: usize = 8;

/// US-1030: write the credential stream and **retire the US-413 migration's
/// plain entry**.
///
/// The migration wrote `oath.keystore.v1` as a *single plain* store entry
/// (`migration::run`), while every write since has used the chunked form
/// (`<slot>.p0NN`). `chunked::write_chunked` does not remove the family key,
/// and `boot_in_place` prefers the chunked read — so without this the
/// plaintext stream the migration left behind would sit in the store
/// forever, shadowed but fully readable. The property this story is about
/// would be true of the live record and false of the medium.
///
/// Ordering: the chunked write lands first, so the entry being deleted is
/// never the only copy. A delete that fails for any reason other than
/// absence is propagated — a leftover plaintext stream is a refusal, not a
/// warning — and the next boot's `read_chunked` still wins, so the retry
/// converges.
fn write_state(store: &mut dyn SecureStore, buf: &[u8]) -> Result<(), SecureStoreError> {
    chunked::write_chunked(store, STATE_SLOT, buf)?;
    match store.delete(STATE_SLOT) {
        Ok(()) | Err(SecureStoreError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// US-1030: read the seal high-water mark.
///
/// **This is the `try_*` discipline the story is about (Appendix A M-1).**
/// A collapsing read would be `store.read(..).ok().map(...)`, which turns a
/// medium fault into "no record" and hands back `0` — and `0` is a value
/// this device has already used, so the next seal would re-derive a nonce
/// that was already spent on different plaintext. Only
/// [`SecureStoreError::NotFound`] means absent; every other error is a
/// fault and propagates, so the caller refuses instead of guessing.
///
/// A record of the wrong length is [`SecureStoreError::Corrupt`], not `0`:
/// it can only have come from a foreign or damaged image, and guessing a
/// value for it is the same bug one layer up.
fn read_seal_generation(store: &mut dyn SecureStore) -> Result<u64, SecureStoreError> {
    let mut raw = [0u8; SEAL_GENERATION_LEN];
    match store.read(SLOT_OATH_SEAL_GENERATION, &mut raw) {
        Ok(n) if n == SEAL_GENERATION_LEN => Ok(u64::from_be_bytes(raw)),
        Ok(_) => Err(SecureStoreError::Corrupt),
        Err(SecureStoreError::NotFound) => Ok(0),
        Err(e) => Err(e),
    }
}

/// US-1030: reserve `count` generations and **persist the reservation
/// before the caller writes anything it protects**.
///
/// The ordering is the whole tear-safety argument. The counter and the
/// sealed records live in one store image, so the persist discipline
/// normally programs them together; but a counter written *after* the seal
/// would, on a cut between the two, leave a sealed record at generation
/// `g` while the counter still reads `g - 1` — and the next pass would
/// hand `g` to a different plaintext. Written first, a cut leaves the
/// counter at `g` and the *old* record still at `g - 1`, so the next pass
/// starts at `g + 1`. Every ordering that could repeat a nonce is excluded.
///
/// Generation `0` is reserved (it means "not sealed by this firmware"), so
/// the reservation refuses to land on it and refuses to wrap.
///
/// # What a full-image rollback does, stated rather than assumed
///
/// An attacker with physical access can restore an *older valid* store
/// image, which rolls the counter back along with the sealed records. That
/// does **not** produce the one thing that matters — a nonce reused on
/// *different* plaintext — because the counter and the keys advance
/// together inside one image: rolling the image back replays a
/// `(generation, key)` pair that the device genuinely held, and the next
/// seal re-derives a nonce that was already paired with *that same*
/// plaintext. GCM nonce reuse with identical plaintext yields identical
/// ciphertext and discloses nothing the equality of the two records does
/// not already disclose. Restoring an image to reach an *older* OTP
/// counter is the same known limitation the whole store has (the EPIC's
/// H-2), and no in-image counter can fix it; only an out-of-image monotonic
/// source could, and this device has none.
fn reserve_seal_generations(
    store: &mut dyn SecureStore,
    count: usize,
) -> Result<u64, SecureStoreError> {
    if count == 0 {
        // An empty table has nothing to seal, so there is nothing to
        // reserve — and writing here would create a counter slot on a store
        // that never held a credential. Note this does **not** lower an
        // existing counter: a device that once had credentials keeps its
        // high-water mark across a RESET, and the next PUT draws from it.
        return Ok(0);
    }
    let base = read_seal_generation(store)?;
    let top = base
        .checked_add(count as u64)
        .filter(|t| *t != 0)
        .ok_or(SecureStoreError::Corrupt)?;
    store.write(SLOT_OATH_SEAL_GENERATION, &top.to_be_bytes())?;
    Ok(base)
}

/// US-713: one-APDU chunk cap, derived from the C CCID transport
/// (`USB_BUFFER_SIZE` 2048 − `CCID_MSG_DATA_OFFSET` 10 − 2 SW bytes,
/// `apdu_limit_response`'s `ne = max_size − 2`): the largest body the C
/// answers in one exchange before switching to 61xx/SEND REMAINING.
const OATH_CHUNK_MAX: usize = 2036;
/// Largest request challenge the chunk state can hold across the 0xA5
/// follow-ups (short-APDU Lc bound). A longer challenge cannot be re-derived
/// mid-stream; a chunked response over one with the US-705 overflow error as
/// the fallback.
const MAX_CHUNK_CHAL: usize = 255;

/// US-713 chunked-response state. The CALC ALL body is a pure function of
/// the slot table, P2 and the challenge, so no response bytes are buffered:
/// each follow-up re-derives the stream and serves the next window. The slot
/// table cannot drift mid-stream — any command other than the continuation
/// resets the state (C `apdu_process` parity). `pos..total` is the
/// undelivered window of the logical body; the challenge copy is session
/// request data (not secret material) and is cleared when the stream ends.
struct ChunkState {
    p2: u8,
    chal: [u8; MAX_CHUNK_CHAL],
    chal_len: u8,
    pos: usize,
    total: usize,
}

impl ChunkState {
    fn zeroize(&mut self) {
        self.chal = [0u8; MAX_CHUNK_CHAL];
        self.chal_len = 0;
        self.p2 = 0;
        self.pos = 0;
        self.total = 0;
    }
}

/// C `apdu.c` `apdu_next` 61xx encoding: SW2 carries the remaining byte
/// count while it fits below 256; at 256 or more it reads 0x00 (the ISO
/// "256 bytes available" form the C writes for any larger remainder).
fn sw_more_data(remaining: usize) -> Sw {
    if remaining >= 256 {
        0x6100
    } else {
        0x6100 | remaining as u16
    }
}

/// Append the portion of `bytes` that falls into the next `want` bytes of
/// the logical stream (bytes before `skip` are already delivered); advances
/// `skip` past fully consumed entries. Returns the number of bytes appended.
fn emit_window(
    resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    bytes: &[u8],
    skip: &mut usize,
    want: usize,
) -> usize {
    if *skip >= bytes.len() {
        *skip -= bytes.len();
        return 0;
    }
    let b = &bytes[*skip..];
    let n = b.len().min(want);
    let _ = resp.extend_from_slice(&b[..n]);
    *skip = 0;
    n
}

#[derive(Clone, Copy)]
struct Cred {
    name: [u8; MAX_NAME],
    name_len: u8,
    key: [u8; MAX_KEY],
    key_len: u8,
    /// HOTP moving factor (8 bytes, big-endian); None for TOTP.
    imf: Option<u64>,
    /// US-133 (PICOForge-COMPAT): the Yubico property bits, persisted with
    /// the credential (see [`TAG_PROPERTY`]). Always a subset of
    /// [`PROP_ENFORCED`] — [`Self::cmd_put`] refuses anything else, so a
    /// stored bit is a bit that is actually enforced at CALCULATE /
    /// CALC ALL and advertised by the extended LIST. Packing it into the
    /// hole before `imf` costs the 68-slot table **zero** bytes of RAM
    /// (`size_of::<Cred>()` is asserted unchanged in the test suite), which
    /// matters: the table is 68 × `size_of::<Cred>()` inside an 11 KiB app
    /// that US-939 already had to move off the async-main stack.
    props: u8,
}

impl Default for Cred {
    fn default() -> Self {
        Cred {
            name: [0; MAX_NAME],
            name_len: 0,
            key: [0; MAX_KEY],
            key_len: 0,
            imf: None,
            props: 0,
        }
    }
}

/// The nth TLV with `tag` in `data` (0-based), walking exactly like C
/// `tlv_walk`: a truncated entry stops the walk, and a trailing tag with no
/// length byte is a zero-length marker (OATH CALCULATE sends a bare `0x74`
/// for HOTP — see test_imf_overwrite).
///
/// **US-133 (PICOForge-COMPAT) — the one exception, and why.** The property
/// object is a *bare value with no length octet*: `78 <props>` is two bytes
/// (`picoforge/src/hal/applets/oath.rs`, "Yubico quirk"). So at a TLV
/// boundary, a `0x78` is **not** a tag whose next byte is a length — the
/// next byte is the property value and the object is done.
///
/// This is not cosmetic. picoforge's `put()` writes the property
/// *between* `TAG_KEY` and `TAG_IMF`, so a walker that reads the property
/// byte as a length consumes the `7A <len>` header of the real HOTP moving
/// factor as its "value", resumes on the counter bytes, reads a length out
/// of them, overruns the buffer and bails out of the walk entirely — and
/// `nth_tlv(data, TAG_IMF, 0)` then answers `None`. A HOTP credential
/// stored by a picoforge client with `touch: true` silently landed with
/// counter 0. Only a byte *at a TLV boundary* is treated this way: value
/// bytes are skipped by the length arithmetic, so a credential name or
/// secret containing `0x78` is unaffected.
fn nth_tlv(data: &[u8], tag: u8, nth: usize) -> Option<&[u8]> {
    let mut i = 0;
    let mut seen = 0;
    while i < data.len() {
        if data[i] == TAG_PROPERTY {
            // Bare two-byte property object; a lone trailing 0x78 is the
            // same shape with an empty value, and ends the stream.
            let value: &[u8] = if i + 1 < data.len() {
                &data[i + 1..i + 2]
            } else {
                &[]
            };
            if seen == nth && tag == TAG_PROPERTY {
                return Some(value);
            }
            if tag == TAG_PROPERTY {
                seen += 1;
            }
            i += if value.is_empty() { 1 } else { 2 };
            continue;
        }
        let len = if i + 1 == data.len() {
            // Bare trailing tag: zero-length value, end of the stream.
            if data[i] == tag && seen == nth {
                return Some(&[]);
            }
            return None;
        } else {
            let l = data[i + 1] as usize;
            if i + 2 + l > data.len() {
                return None;
            }
            l
        };
        if data[i] == tag {
            if seen == nth {
                return Some(&data[i + 2..i + 2 + len]);
            }
            seen += 1;
        }
        i += 2 + len;
    }
    None
}

/// HMAC into a fixed buffer; returns the digest length (C
/// `mbedtls_md_hmac` over `key[2..]` callers pass the secret directly).
fn hmac_into(alg: u8, key: &[u8], data: &[u8], out: &mut [u8; 64]) -> Option<usize> {
    match alg & ALG_MASK {
        ALG_SHA1 => {
            let mut mac = HmacSha1::new_from_slice(key).ok()?;
            mac.update(data);
            out[..20].copy_from_slice(&mac.finalize().into_bytes());
            Some(20)
        }
        ALG_SHA256 => {
            let mut mac = HmacSha256::new_from_slice(key).ok()?;
            mac.update(data);
            out[..32].copy_from_slice(&mac.finalize().into_bytes());
            Some(32)
        }
        ALG_SHA512 => {
            let mut mac = HmacSha512::new_from_slice(key).ok()?;
            mac.update(data);
            out.copy_from_slice(&mac.finalize().into_bytes());
            Some(64)
        }
        _ => None,
    }
}

/// US-904 (SEC-HARDEN): the OTP-PIN record — the first fid past the 68
/// credential slots (the access code is `0xBAFF`).
const FID_OTP_PIN: u16 = 0xBA44;
/// Legacy (pre-US-904) pin record payload: `[counter][verifier 32]`.
const PIN_LEGACY_LEN: usize = 33;
/// Salted pin record payload: `[counter][salt 16][verifier 32]`.
const PIN_SALTED_LEN: usize = 49;
/// Legacy verifier domain separator (the pre-US-904 unsalted form).
const PIN_LEGACY_DOMAIN: &[u8] = b"fapico2-otp-pin";

/// US-904 (SEC-HARDEN): the OTP-PIN record — a salted, device-bound verifier.
/// The salt is drawn per record from the TRNG pool, so the same PIN on two
/// devices (or two records) yields different verifier bytes; the record is
/// durable (stream fid `0xBA44`) and a legacy unsalted record is upgraded in
/// place at the next successful verification.
#[derive(Clone, Copy)]
struct PinRecord {
    /// Retry budget (C `MAX_OTP_COUNTER`): a failure decrements, a success
    /// rewrites it to the maximum.
    counter: u8,
    salt: [u8; 16],
    verifier: [u8; 32],
    /// Loaded from a pre-US-904 33-byte record (no salt): `salt` is zeros
    /// and `verifier` uses the legacy domain until the upgrade.
    legacy: bool,
}

/// US-904 salted PIN verifier: `SHA256(salt || pin)`.
fn pin_verifier(pin: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(pin);
    h.finalize().into()
}

/// The pre-US-904 unsalted form, used only to verify a legacy record.
fn legacy_pin_verifier(pin: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PIN_LEGACY_DOMAIN);
    h.update(pin);
    h.finalize().into()
}

fn push_record(out: &mut HeaplessVec<u8, MAX_LOGICAL_LEN>, fid: u16, payload: &[u8]) {
    let _ = out.extend_from_slice(&fid.to_le_bytes());
    let _ = out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let _ = out.extend_from_slice(payload);
}

/// US-903 (SEC-HARDEN): build-dependent presence default — a device build
/// without an injected source denies (fail closed); emulation/host
/// auto-acks (mgmt parity).
fn default_user_present() -> bool {
    #[cfg(feature = "device")]
    {
        false
    }
    #[cfg(not(feature = "device"))]
    {
        true
    }
}

/// US-1553: the outcome of [`OathApp::attach_region`].
///
/// Two states, and the split is the requirement (S10, "degrade, never halt"):
/// the caller has to be able to tell "the region mounted and here is what was
/// in it" from "the region could not be read and the applet is serving an empty
/// table". Collapsing them would make a failing flash look like a factory-fresh
/// token.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegionStatus {
    /// The region was recovered and read.
    Mounted {
        /// Credentials in the table afterwards, imported ones included.
        live: u16,
        /// Credentials moved in from the legacy `oath.keystore.v1` stream.
        ///
        /// Non-zero exactly once in a device's life — on the mount that found
        /// the region virgin.
        imported: u16,
    },
    /// The region could not be read. The credential table is **empty** and the
    /// applet still answers APDUs.
    Degraded,
}

/// US-1553: the region handle was not where [`OathApp::attach_region`] had just
/// installed it. Unreachable, and named rather than `unwrap`ed so a future
/// change that can drop it is reported rather than panicked.
const E_NO_REGION: &str = "oath: the key-region handle disappeared between statements";

/// US-1553: how the firmware hands this applet a key region.
///
/// A `fn` pointer, and a `fn` pointer **rather than a closure**, because
/// [`REGION_PROVIDER`] stores the provider's code address. A capturing closure
/// would be a data pointer into a stack frame that is gone by the time the
/// applet calls it.
pub type RegionProvider = fn() -> Option<OathRegion>;

/// The installed provider, or a null pointer when none is.
///
/// **A code address in an `AtomicPtr`, transmuted back at the call site** —
/// which is why [`install_region_provider`] insists on a `fn`. There is no
/// `static mut` alternative here that is *also* safe: the applet is reached
/// from the CCID task, and a `static mut` read from task context is exactly the
/// shape `boot.rs`'s `KEY_REGION` discipline spends paragraphs ruling out.
static REGION_PROVIDER: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// US-1553: install the firmware's region provider.
///
/// Called by `firmware/src/main.rs` immediately after `boot::release_key_region`,
/// which is itself immediately after `mark!(RUNG_USB)`. **That ordering is the
/// point, not an accident of where the line landed.** A mount reads up to 68 KiB
/// and opens up to 68 AEAD records; doing that during boot would make boot's
/// latency proportional to how many credentials the owner has, which is what S8
/// and S9 forbid.
///
/// Without this call the whole region path is linked out of the image by LTO —
/// the same thing `main.rs`'s FIDO line documents for its side, and the reason
/// that comment exists.
///
/// **Idempotent**, for the reason `OathApp::reset`'s management hook is: a boot
/// path that reached `RUNG_USB` and found one already installed has been
/// re-entered by a caller meaning the same thing, and failing there would be a
/// halt over nothing (S10).
pub fn install_region_provider(provider: RegionProvider) {
    REGION_PROVIDER.store(provider as *mut (), core::sync::atomic::Ordering::Release);
}

/// The installed provider, or `None`.
///
/// # Safety
///
/// The stored value is a `fn`'s code address, published by
/// [`install_region_provider`] and only ever written with a `RegionProvider`.
/// Calling a code address cannot be a use-after-free the way calling a stale
/// *data* pointer could, which is the property FIDO's equivalent doc leans on.
///
/// # What it does NOT do
///
/// No handle is cached in [`OathApp`], no `once` wrapper, no "have I looked
/// yet" flag. A cached `Option<&'static mut …>` would have to be refreshed when
/// the provider starts answering `Some`, which is the boot-order problem the
/// function pointer exists to avoid. The cost is one indirect call per applet
/// command that reaches an entry point, against a mount that reads the whole
/// table on the first one.
fn region_provider() -> Option<RegionProvider> {
    let raw = REGION_PROVIDER.load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() {
        None
    } else {
        // SAFETY: see the note above — only [`install_region_provider`] writes
        // this, and only with a `RegionProvider`.
        Some(unsafe { core::mem::transmute::<*mut (), RegionProvider>(raw) })
    }
}

pub struct OathApp {
    /// Storage slots in creation order; deleted slots are None and are
    /// reused by the next PUT (C free-slot bitmap parity). Slot index i
    /// maps to stream fid `0xBA00 + i`.
    slots: [Option<Cred>; MAX_CREDS],
    /// OATH access code (validate secret): [alg|type, secret...].
    /// Residual (US-901 → US-904): the salted OTP-PIN verifier (fid 0xBA44)
    /// removed the PIN residual, but the raw access code is still persisted
    /// unencrypted — VALIDATE needs it for the response HMAC — until store
    /// encryption (US-917) lands.
    access_code: Option<([u8; MAX_ACCESS_CODE], u8)>,
    /// Challenge issued by the last SELECT (validate binds to it).
    challenge: [u8; 8],
    validated: bool,
    /// US-904: OTP PIN record — salted verifier, durable via stream fid
    /// `0xBA44` (see [`PinRecord`]).
    pin: Option<PinRecord>,
    /// Set when a command changed persisted state; persist_state writes only
    /// when set (OTP parity) and clears it on success.
    dirty: bool,
    /// Boot-time TRNG pool (US-380): the `App` trait hands no TRNG to the
    /// command path, so the pool is seeded from the platform TRNG at
    /// construction and stretched with SHA256 when exhausted (FidoApp
    /// pattern). Every random byte still ultimately comes from the TRNG.
    rng_pool: HeaplessVec<u8, 512>,
    rng_cursor: usize,
    /// US-903 (SEC-HARDEN): user-presence source (the board button on
    /// device), injected by the firmware via [`with_user_presence`]. `None`
    /// resolves to the build default: fail-closed (`false`) under the
    /// `device` feature, auto-ack otherwise (emulation/host).
    presence: Option<fn() -> bool>,
    /// US-921: the whole grant path (pending request + latch binding) when
    /// the runtime owns the shared presence service (device wiring). Takes
    /// precedence over `presence` — the shared runtime IS the grant path.
    presence_grant: Option<fn(u32) -> bool>,
    /// US-713: pending chunked CALC ALL response (see [`ChunkState`]).
    chunk: Option<ChunkState>,
    /// US-130 (PICOForge-COMPAT): the 8-byte device-id this applet reports
    /// as `TAG_NAME` on SELECT, and therefore the PBKDF2 salt for the OATH
    /// access key. Derived from the chip-id at construction (see
    /// [`device_id_from_chipid`]) and **never persisted**: the store holds
    /// credentials and codes only, so a re-provisioned chip-id can never
    /// leave a stale salt behind.
    device_id: [u8; DEVICE_ID_LEN],
    /// US-1030: the credential-key seal context, derived by the caller from
    /// the flash UID + the OTP key row. A **required** constructor argument
    /// for the same reason `device_id` is (US-130): the sealed form of a
    /// migrated credential cannot be read without it, so a call site that
    /// forgot to supply one would not fail — it would boot and serve keys
    /// this firmware had no way to seal. An `Option` here would put the
    /// whole property behind a `None` the compiler happily accepts, which is
    /// exactly the advisory-chokepoint shape Appendix A M-4 names.
    seal: OathSeal,
    /// US-1030: set by [`Self::load_stream`] when a credential was found
    /// outside this firmware's sealed form — a plaintext C record, or a C
    /// `"OATH"` record carrying no generation object. Boot then re-seals
    /// before serving. The flag is cleared **only** by a re-seal that
    /// reached the medium, so a fault leaves the app refusing rather than
    /// serving the plaintext it just read.
    reseal_pending: bool,
    /// US-1553: the key region this applet stores its credentials in, once one
    /// has been attached at first applet use. `None` is the legacy path — the
    /// chunked `oath.keystore.v1` snapshot in the shared secure store — and it
    /// is the default rather than an error so that every existing caller and
    /// test keeps working unchanged.
    ///
    /// **Boxed, so the cost in `bss` is one pointer.** The handle carries a
    /// `PayloadKey`, and 33 bytes of static on a build that tracks its `bss`
    /// delta would be paid for every session including the ones that never
    /// mount a region. `Option<Box<_>>` is 4 bytes on the device target (the
    /// null-pointer niche) and nothing is allocated until a region is attached
    /// — which is after `platform::rsa_heap::init()`, so the US-961 heap gate
    /// is unaffected.
    region: Option<Box<OathRegion>>,
    /// US-1553: set when the region could not be read, so the credential table
    /// is **empty because nothing could be learned**, not because the owner has
    /// none. It is a distinct state from `region == None` on purpose: the
    /// former is a device with a failing flash, the latter is a device on the
    /// legacy path, and only one of them should answer a PUT with a refusal.
    ///
    /// A single byte rather than an `Option<&'static str>` for the same reason
    /// the rest of this file does not carry reasons in statics: the applet has
    /// no log to write them to, and the difference that matters to a caller is
    /// "degraded or not".
    region_degraded: bool,
}

impl OathApp {
    /// US-901 (SEC-HARDEN): recompute the session grant.
    ///
    /// A session is granted (`validated == true`) exactly while there is **no
    /// secret to authenticate with** — no access code and no OTP PIN. That is
    /// what "no access code set" means on a YubiKey, and it is the only
    /// definition both first-party clients can act on.
    ///
    /// **This used to require virginity as well — no credentials either — and
    /// that was a compatibility lockout, not a hardening.** Both clients decide
    /// whether to authenticate from the SELECT response alone:
    /// `yubikit/oath.py` (`_has_key = self._challenge is not None`) and
    /// picoforge's HAL (`info.password_set()`) both read the `74` challenge
    /// TLV, which this applet emits **only when an access code exists**
    /// ([`Self::select_apdu`]). So on a device holding credentials and no
    /// access code, both GUIs skip VALIDATE and issue LIST / PUT / DELETE /
    /// CALCULATE directly — and every one of them was answered `0x6982`. The
    /// state was also **unrecoverable**: `SET_CODE` and `SET_PIN`, the only ways
    /// to create the missing credential, sit behind the same gate, leaving a
    /// factory reset (magic + touch) as the sole exit.
    ///
    /// Credentials are not a secret that needs authenticating — they are the
    /// thing being managed — and every command that touches one already
    /// requires user presence (`cmd_put`, `cmd_delete`, `cmd_rename`,
    /// `cmd_calculate` and `cmd_calculate_all` each gate on `user_present`), so
    /// dropping the virginity conjunct trades nothing away. It restores what the
    /// owner's configuration already implies.
    ///
    /// This is the single place the grant is derived; never store a self-grant
    /// blindly.
    /// US-901 follow-on: make sure an access code exists, so that "no code"
    /// is never a reachable state on a device.
    ///
    /// Idempotent — an existing code is left alone, so a device that has been
    /// provisioned (or whose owner has chosen a code) is untouched. Called from
    /// every path that can end up without one: the two boots, and
    /// [`Self::reset_state`].
    ///
    /// **Deliberately does not mark `dirty`.** The default is a *constant*, so
    /// persisting it would buy nothing: a boot that finds no access code
    /// re-derives exactly this value, and a boot that finds one has a real
    /// owner-chosen code. Writing it would add a store write to the boot path
    /// and grow the secure partition on every device for no behavioural
    /// difference — and that growth is visible, because `FlashInfo.used`
    /// reports the partition length.
    ///
    /// What *is* persisted is a code the owner chooses: `cmd_set_code` sets
    /// `dirty` itself, and that write is the one that matters.
    fn provision_default_access_code(&mut self) {
        if self.access_code.is_some() {
            return;
        }
        let mut arr = [0u8; MAX_ACCESS_CODE];
        arr[0] = ALG_SHA1;
        let n = DEFAULT_ACCESS_CODE.len();
        arr[1..=n].copy_from_slice(DEFAULT_ACCESS_CODE);
        self.access_code = Some((arr, (n + 1) as u8));
    }

    fn refresh_session_grant(&mut self) {
        self.validated = self.access_code.is_none() && self.pin.is_none();
    }

    /// US-903 (SEC-HARDEN): attach the user-presence source (mirrors
    /// `oath_core.rs` / mgmt). Consulted exactly once per RESET.
    pub fn with_user_presence(mut self, f: fn() -> bool) -> Self {
        self.presence = Some(f);
        self
    }

    // US-130 (PICOForge-COMPAT): there is deliberately **no** `with_chipid`
    // builder here.
    //
    // The first cut of this story had one, mirroring
    // `ManagementApp::with_chipid`, and the construction-time default was the
    // `EMULATION_CHIPID` derivation. Review killed it: that shape makes the
    // *device* path's correctness depend entirely on a separate statement
    // (`app.with_chipid(chipid)` in `firmware/src/main.rs`) that the compiler
    // cannot check and no in-tree test exercises. Deleting that one line
    // restores the exact defect US-130 exists to remove — every unit sharing
    // one PBKDF2 salt — with a fully green build and a fully green suite.
    //
    // So the identifier is a **required constructor argument** instead
    // ([`Self::new`] / [`Self::boot`] / [`Self::new_in_place`] /
    // [`Self::boot_in_place`]). Every call site must name the chip-id it
    // represents, omitting it is a compile error rather than a silent fleet-
    // wide salt, and the emulation stand-in is a deliberate, visible act at
    // each of them.

    /// US-921: attach the shared presence runtime's grant path (device
    /// wiring) — the runtime owns the pending-request slot and the button
    /// latch binding, so destructive commands are granted only by a press
    /// that lands while *this* command's request (its
    /// [`PRESENCE_TAG_RESET`] / [`PRESENCE_TAG_SET_CODE_CLEAR`] tag) is
    /// pending. Takes precedence over `with_user_presence`.
    pub fn with_presence_grant(mut self, g: fn(u32) -> bool) -> Self {
        self.presence_grant = Some(g);
        self
    }

    /// US-939: post-construction variant of [`Self::with_presence_grant`].
    /// The firmware builds the app straight into its static slot
    /// (`boot::init_static_slot_with`) — the by-value builder forced an
    /// 11.3 KiB `OathApp` temporary through the caller's stack frame, part
    /// of the async-main frame overflow.
    pub fn set_presence_grant(&mut self, g: fn(u32) -> bool) {
        self.presence_grant = Some(g);
    }

    /// US-904 (SEC-HARDEN): test/diagnostic accessor for the OTP-PIN record
    /// — `(counter, salt, verifier)`. It reveals only salted material (the
    /// salt and the verifier, never the PIN) and is deliberately kept off
    /// the [`App`] trait; it exists for the `auth_boundary` integration
    /// tests and host-side diagnostics.
    #[doc(hidden)]
    pub fn otp_pin_record(&self) -> Option<(u8, [u8; 16], [u8; 32])> {
        self.pin.map(|p| (p.counter, p.salt, p.verifier))
    }

    /// US-903/US-905 (SEC-HARDEN): the user-presence grant — consulted by
    /// RESET and by empty-data SET_CODE clearing a present access code.
    ///
    /// US-921 device wiring (mgmt parity): with `with_presence_grant`
    /// attached, the whole grant path IS the shared presence service (one
    /// instance for the whole firmware — pending slot + button-latch
    /// binding + clock), so a press with no pending request never arms
    /// anything. The fallback below stays the host/test path: a per-command
    /// service fed by the injected `fn() -> bool` poll (or the build
    /// default — fail-closed on device, auto-ack on host/emulation so the
    /// existing suites stay green); press→consume is synchronous within
    /// the command there, so tick 0 stands in for the clock.
    fn user_present(&mut self, tag: u32) -> bool {
        if let Some(g) = self.presence_grant {
            return g(tag);
        }
        let mut svc = PresenceService::new();
        if !svc.begin_request(tag) {
            return false;
        }
        if match self.presence {
            Some(f) => f(),
            None => default_user_present(),
        } {
            // OATH has no monotonic clock and press→consume is synchronous
            // within this command, so the 10 s window is moot here; tick 0
            // is the injected stand-in (US-921 wires the real clock).
            svc.observe_press(0);
        }
        let grant = svc.request(tag, 0).is_some();
        svc.end_request(tag);
        grant
    }

    /// Fresh empty app (factory state). The TRNG pool is seeded here
    /// (US-380 sole source); the serve loops always go through [`boot`],
    /// which falls back to this on an empty store (S-711-2).
    ///
    /// `device_id` is the 8-byte value SELECT will report as `TAG_NAME` — the
    /// PBKDF2 salt for the OATH access key, so it must be this unit's own. It
    /// is a **required argument** (US-130): pass
    /// `device_id_from_chipid(chipid)`. There is no default and no builder,
    /// because a default here is precisely the silent fleet-wide-salt bug.
    pub fn new<R: Trng>(trng: &mut R, device_id: [u8; DEVICE_ID_LEN], seal: OathSeal) -> Self {
        let mut slot = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: `slot` is a fresh local, written exactly once by
        // `new_in_place` (the write-once-slot discipline), aliased by nothing.
        let app = unsafe { Self::new_in_place(&raw mut slot, trng, device_id, seal) };
        unsafe { core::ptr::read(app) }
    }

    /// US-956: [`Self::new`] writing **directly into a caller-provided
    /// `MaybeUninit` slot**, so the 11.3 KiB app never transits the caller's
    /// stack frame. Every field is written explicitly (never a blanket
    /// zero-fill) — a memset would be wrong for any `Option` whose niche
    /// encoding does not read as `None` at zero.
    ///
    /// `device_id` is required for the reason given on [`Self::new`]: the
    /// device-id is the per-unit PBKDF2 salt, so the caller must state it and
    /// the compiler must insist. `seal` is required for the US-1030 reason
    /// given on the field.
    ///
    /// **Why not a zero or "unset" default.** A `[0u8; 8]` fallback would be
    /// strictly worse than the `EMULATION_CHIPID` default it replaced: it is
    /// *also* a single fleet-wide constant, so every unprovisioned unit would
    /// still share one salt with every other, and it would still fail silently
    /// — it would merely look less like a deliberate value. A wrong-but-obvious
    /// default is no more fail-closed than a right-but-hidden one. The only
    /// shape that cannot rot is the one where there is nothing to forget.
    ///
    /// # Safety
    ///
    /// `slot` must be valid for writes of `size_of::<Self>()` bytes, properly
    /// aligned, and written exactly once (the write-once `static mut` slot
    /// discipline `boot::init_static_slot` establishes for every sibling
    /// slot). The returned reference is the sole handle to the value.
    pub unsafe fn new_in_place<R: Trng>(
        slot: *mut core::mem::MaybeUninit<Self>,
        trng: &mut R,
        device_id: [u8; DEVICE_ID_LEN],
        seal: OathSeal,
    ) -> &'static mut Self {
        let app: *mut Self = slot.cast::<Self>();
        core::ptr::addr_of_mut!((*app).slots).write([None; MAX_CREDS]);
        core::ptr::addr_of_mut!((*app).access_code).write(None);
        core::ptr::addr_of_mut!((*app).challenge).write([0u8; 8]);
        core::ptr::addr_of_mut!((*app).validated).write(false);
        core::ptr::addr_of_mut!((*app).pin).write(None);
        core::ptr::addr_of_mut!((*app).dirty).write(false);
        core::ptr::addr_of_mut!((*app).rng_pool).write(HeaplessVec::new());
        core::ptr::addr_of_mut!((*app).rng_cursor).write(0);
        core::ptr::addr_of_mut!((*app).presence).write(None);
        core::ptr::addr_of_mut!((*app).presence_grant).write(None);
        core::ptr::addr_of_mut!((*app).chunk).write(None);
        core::ptr::addr_of_mut!((*app).device_id).write(device_id);
        core::ptr::addr_of_mut!((*app).seal).write(seal);
        core::ptr::addr_of_mut!((*app).reseal_pending).write(false);
        core::ptr::addr_of_mut!((*app).region).write(None);
        core::ptr::addr_of_mut!((*app).region_degraded).write(false);
        let app = &mut *app;
        app.fill_rng_pool(trng);
        let mut challenge = [0u8; 8];
        app.draw_random(&mut challenge);
        app.challenge = challenge;
        app.refresh_session_grant();
        app
    }

    /// Boot from the secure store: chunked slot first (this app's own
    /// persist form), plain slot as fallback (the US-413 migration writes
    /// the stream as a single plain entry).
    // US-939: `#[inline(never)]` — keystore decode stays out of the Embassy
    // async-main frame (the dark-boot stack overflow).
    //
    // US-956: a thin by-value wrapper over [`Self::boot_in_place`], so the
    // host/emulation suites and the device boot path run the same
    // construction and can never diverge.
    ///
    /// `device_id` is required (US-130) — see [`Self::new`]: the per-unit
    /// PBKDF2 salt may not be defaulted, on this path least of all, because
    /// this is the path the device actually boots. `seal` is required
    /// (US-1030) for the same reason.
    pub fn boot<R: Trng>(
        trng: &mut R,
        store: &mut dyn SecureStore,
        device_id: [u8; DEVICE_ID_LEN],
        seal: OathSeal,
    ) -> Result<Self, SecureStoreError> {
        let mut slot = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: fresh local, written exactly once, aliased by nothing.
        let app = unsafe { Self::boot_in_place(&raw mut slot, trng, store, device_id, seal)? };
        Ok(unsafe { core::ptr::read(app) })
    }

    /// US-956: the real boot, constructing straight into the caller's
    /// `MaybeUninit` slot. The `MAX_LOGICAL_LEN` decode buffer (5,952 B since
    /// US-1010; 8,432 B before, a bound the device store could not meet) is a
    /// genuine temporary (it cannot outlive the call, and the stack zone is
    /// sized for it); the 11,264 B app that the by-value form materialized in
    /// the caller's frame — and then memcpy'd into the static — does not
    /// exist any more. Device-boot rationale and the measured numbers are in
    /// `fapico2_fido::device_app::FidoApp::boot_in_place`.
    ///
    /// # Safety
    ///
    /// Same write-once `static mut` slot contract as [`Self::new_in_place`]:
    /// valid for `size_of::<Self>()` bytes, properly aligned, written exactly
    /// once, sole handle returned.
    #[inline(never)]
    ///
    /// `device_id` is required (US-130) — see [`Self::new`]. This is the
    /// device boot path, so it is the one where a defaulted salt would be
    /// worst: every unit would answer SELECT with the same value and one
    /// recovered keystore would unlock the whole fleet.
    ///
    /// **US-1030 — the boot re-seal, and the fault discipline around it.**
    /// Two re-seal sites exist in this file and both are enumerated here,
    /// because the failure mode this story exists to prevent is a
    /// *silently skipped* one:
    ///
    /// 1. **this function's stream read.** `chunked::read_chunked` and the
    ///    plain-slot fallback both distinguish
    ///    [`SecureStoreError::NotFound`] from every other error and
    ///    propagate the rest. A collapsing `read(...).ok()` here would turn
    ///    a medium fault into "no credentials", and the app would come up
    ///    empty rather than refusing — the caller sees `Ok`, the store still
    ///    holds plaintext keys, and nothing re-seals. It does not collapse.
    /// 2. **[`Self::reserve_seal_generations`], reached from
    ///    [`Self::reseal`] below.** Its counter read discriminates
    ///    `NotFound` from a fault for the same reason: `0` is a value this
    ///    device has already spent.
    ///
    /// A fault at either site returns `Err`, and every device caller treats
    /// that as fatal (`firmware/src/main.rs::boot_oath` → `fatal_boot`)
    /// rather than serving. Because the counter is reserved **before** the
    /// sealed stream is written, a cut between the two leaves the counter
    /// ahead of the record — so the *next* boot re-seals at a strictly
    /// higher generation instead of skipping the re-seal and leaving the
    /// plaintext in place for a cycle. That is the "next boot, not skip"
    /// property the story asks for, and it is a property of the ordering,
    /// not of a retry loop.
    pub unsafe fn boot_in_place<R: Trng>(
        slot: *mut core::mem::MaybeUninit<Self>,
        trng: &mut R,
        store: &mut dyn SecureStore,
        device_id: [u8; DEVICE_ID_LEN],
        seal: OathSeal,
    ) -> Result<&'static mut Self, SecureStoreError> {
        let app = Self::new_in_place(slot, trng, device_id, seal);
        let mut buf = [0u8; MAX_LOGICAL_LEN];
        let n = match chunked::read_chunked(store, STATE_SLOT, &mut buf) {
            Ok(n) => n,
            Err(SecureStoreError::NotFound) => match store.read(STATE_SLOT, &mut buf) {
                Ok(n) => n,
                Err(SecureStoreError::NotFound) => {
                    // Fresh device: provision the default rather than starting
                    // with no secret at all.
                    app.provision_default_access_code();
                    app.refresh_session_grant();
                    return Ok(app);
                }
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        };
        app.load_stream(&buf[..n])?;
        // A device must always have something to authenticate against — see
        // [`DEFAULT_ACCESS_CODE`]. On a fresh device the early `return Ok(app)`
        // above skips this, so it is done here for the loaded case and again
        // on the not-found path below.
        app.provision_default_access_code();
        // Boot restore must not leave a session validated (US-901).
        app.refresh_session_grant();
        // US-1030: re-seal before the app is reachable by any APDU. A
        // failure here is a boot failure (see the note above) — the
        // alternative, serving the plaintext this call just read, is the
        // defect.
        if app.reseal_pending {
            app.reseal(store)?;
        }
        Ok(app)
    }

    /// US-1030: seal every credential key in the table and write the stream
    /// plus the advanced high-water mark. `Err` on any store or AEAD
    /// failure; the app is left `reseal_pending`, so the caller refuses
    /// rather than serving a table it could not seal.
    ///
    /// Public because the never-reuse property is only testable by asking
    /// for a second seal: re-sealing the *same* key is the common case
    /// (every persist does it) and the interesting one, since it is exactly
    /// the case a content-derived nonce would get wrong.
    pub fn reseal(&mut self, store: &mut dyn SecureStore) -> Result<(), SecureStoreError> {
        let buf = self.encode_state(store)?;
        // US-1030: the counter is already durable (reserved first inside
        // `encode_state`), so a failure here cannot re-issue a generation.
        write_state(store, &buf)?;
        self.reseal_pending = false;
        self.dirty = false;
        Ok(())
    }

    /// Discard any pending chunked response (session resets and mid-stream
    /// other commands; C `apdu_process` parity).
    fn clear_chunk(&mut self) {
        if let Some(mut st) = self.chunk.take() {
            st.zeroize();
        }
    }

    fn reset_state(&mut self) {
        self.slots.fill(None);
        self.access_code = None;
        self.pin = None;
        // A factory reset returns the applet to the state a fresh device is in,
        // and that state carries the documented default access code — not an
        // open one. Without this, a reset would leave the most-protected
        // configuration in the product.
        self.provision_default_access_code();
        self.refresh_session_grant();
    }

    /// US-711: factory-reset the app (the management RESET hook): clear the
    /// credential table and mark the emptied state dirty for the persist
    /// gate — the same durable wipe path a PUT uses.
    ///
    /// US-1553: on the key-region path the clear is **68 sector-atomic
    /// tombstone commits**, one per occupied slot, and not a store write — the
    /// store never held the table in the first place. A tombstone rather than
    /// an erase because [`fapico2_platform::keyregion::commit`] has no
    /// single-slot delete: a target programmed `0xFF` is indistinguishable from
    /// a commit that never reached its witness, so `recover` could resurrect a
    /// delete as a replay (`commit.rs`, "Why there is no single-slot delete
    /// here").
    ///
    /// The management hook cannot report a status word, so a failed wipe marks
    /// the applet **degraded** instead of returning an error — a factory reset
    /// that reports success having erased nothing is worse than one that
    /// reports failure, and here the only report available is the flag. The
    /// APDU path ([`Self::cmd_reset`]) does return a status word.
    pub fn reset(&mut self) {
        if self.region.is_some() && self.wipe_region().is_err() {
            self.region_degraded = true;
        }
        self.reset_state();
        if self.region.is_none() {
            self.dirty = true;
        }
    }

    /// US-1553: the region could not be read, so the credential table is
    /// **empty because nothing could be learned**, not because the owner has
    /// none. The caller learns which it is and can say so; the applet cannot
    /// serve a partial table, because a table that silently lost an entry is
    /// indistinguishable from one that never had it.
    pub fn is_region_degraded(&self) -> bool {
        self.region_degraded
    }

    /// US-1553: is a key region attached? `false` means the legacy chunked
    /// stream path, which is the default for every existing caller.
    ///
    /// Also the **"attach was attempted"** flag, which is why
    /// [`Self::attach_region_if_available`] gates on it rather than on
    /// [`Self::is_region_degraded`]: [`Self::attach_region`] writes
    /// `self.region` before any of its failure paths, so `is_some()` means
    /// *tried*, not *succeeded*. A degraded mount must not be retried per APDU
    /// — that would re-read 68 KiB on every command, forever. Degrade and
    /// stick, which `oath_keyregion.rs`'s
    /// `an_unreadable_region_degrades_to_an_empty_set_and_a_clean_status_word`
    /// pins.
    pub fn has_region(&self) -> bool {
        self.region.is_some()
    }

    /// US-1553: mount the key region **once**, on first applet use.
    ///
    /// The applet-side half of the wiring `firmware/src/main.rs` completes by
    /// calling [`install_region_provider`] after `mark!(RUNG_USB)`. The
    /// indirection exists for the same reason it does on the FIDO side
    /// (`apps/fido/src/device_app.rs`): the dispatcher owns `&mut OathApp` for
    /// the process lifetime, so the firmware cannot reach into the applet to
    /// hand it a region — the dependency runs the other way and has to be
    /// inverted.
    ///
    /// # Where it is called, and why all three
    ///
    /// [`App::select_apdu`], [`App::process`] and [`App::factory_wipe`].
    /// `factory_wipe` is the one that is easy to miss and the one that matters:
    /// `firmware/src/tasks.rs` runs `dispatcher.factory_wipe_apps()` on a
    /// management-RESET generation bump **with no prior OATH SELECT**, and
    /// [`Self::reset`] only wipes the region `if self.region.is_some()`.
    /// Unmounted, it would empty the legacy stream and leave the 68 flash records
    /// standing — and `attach_region` would faithfully serve them again on the
    /// next command. A factory reset that resurrects every credential is worse
    /// than one that fails.
    ///
    /// Returns `None` when there is nothing to do: no provider installed (a host
    /// or emulator caller), no region available, or a mount already attempted.
    pub fn attach_region_if_available(&mut self) -> Option<RegionStatus> {
        if self.has_region() {
            return None;
        }
        let provider = region_provider()?;
        Some(self.attach_region(provider()?))
    }

    /// US-1553: attach the key region and mount it into the credential table.
    ///
    /// # When this is called — S8/S9
    ///
    /// **Never from [`Self::boot`] or [`Self::boot_in_place`].** Boot runs
    /// before USB is constructed and inside a time budget, and a mount reads up
    /// to 68 KiB and opens 68 AEAD records; making boot's latency proportional
    /// to how many credentials the owner has is the failure this rule names.
    /// The caller attaches at **first applet use, after `RUNG_USB`**.
    /// `apps/oath/tests/oath_keyregion.rs` asserts the negative half directly:
    /// a booted app whose region is mounted never reads or writes the medium.
    ///
    /// # What it does, in order
    ///
    /// 1. [`fapico2_platform::keyregion::oath_store::OathStore::recover`] —
    ///    finish or abandon a commit a power cut interrupted. A live sector
    ///    caught between its erase and its copy-back reads as **empty**, and
    ///    "this credential is gone" is exactly what a mount that skipped this
    ///    would conclude and report to the owner.
    /// 2. Read and open all [`MAX_CREDS`] slots into the table.
    /// 3. **Import** — see [`Self::import_legacy`].
    /// 4. Recompute the session grant (US-901): a mounted non-empty table is a
    ///    non-virgin applet, so the virgin auto-validate rule must not fire.
    ///
    /// # Degrade, never halt
    ///
    /// Any [`OathStoreError`] leaves the table **empty** and the applet usable,
    /// and is reported as [`RegionStatus::Degraded`]. A `fatal_boot` here turns
    /// a failing flash into a board that will not enumerate over USB at all —
    /// `ykman` cannot reach it, the rescue applet cannot be selected, and the
    /// user is told nothing. An empty credential set with a clean status word is
    /// a token that still works and a fault the caller can log.
    ///
    /// The failure is **all-or-nothing on purpose**: if slot 40 faults and the
    /// other 67 mount, the owner sees a credential list that quietly lost an
    /// entry, and the next PUT will reuse that slot — writing a second identity
    /// on top of one they still believe is there.
    pub fn attach_region(&mut self, region: OathRegion) -> RegionStatus {
        self.region = Some(Box::new(region));
        self.region_degraded = false;
        // Whatever the region says is what the table becomes. The order below is
        // the whole migration argument, so it is worth stating: the legacy
        // table is **only** cleared once the region has been shown to be
        // non-empty, and the legacy credentials are **only** cleared by writing
        // them into a region shown to be empty. Neither side loses anything to
        // the other.
        let had_legacy = self.slots.iter().any(|s| s.is_some());

        // The borrow of the handle is taken inside the expression and ends
        // with it, so the `degrade` calls below can take `&mut self` whole.
        let recovered = self.region.as_mut().map(|handle| handle.store().recover());
        match recovered {
            Some(Ok(_)) => {}
            Some(Err(e)) => return self.degrade(e),
            // Unreachable: the handle was set two lines above and nothing takes
            // it. `degrade` rather than `panic` because the property this
            // function exists for — degrade, never halt — must hold even for a
            // bug, and a panic in `no_std` is a reset vector.
            None => return self.degrade(OathStoreError::Fault(E_NO_REGION)),
        }

        // One counting pass to decide which of the two paths this is. It costs
        // the same 68 slot reads the read pass below would have cost; doing it
        // first is what lets the legacy table stay intact until the region has
        // been shown to be empty.
        let report = match self.region.as_mut() {
            Some(handle) => handle.store().mount(),
            None => return self.degrade(OathStoreError::Fault(E_NO_REGION)),
        };
        let report = match report {
            Ok(r) => r,
            Err(e) => return self.degrade(e),
        };

        // "Virgin" means **no OATH content at all**, not merely nothing
        // readable: a slot holding a record this build cannot open is a
        // credential somebody provisioned, and importing over it would
        // destroy it. Tombstones are not content — a slot holding one is free
        // for an import, which writes at a strictly higher generation.
        let virgin = report.live == 0 && report.undecodable == 0;
        let imported = if virgin {
            self.import_legacy()
        } else {
            self.slots.fill(None);
            for i in 0..MAX_CREDS {
                let entry = match self.region.as_mut() {
                    Some(handle) => handle.store().read(i as u16),
                    None => return self.degrade(OathStoreError::Fault(E_NO_REGION)),
                };
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => return self.degrade(e),
                };
                if let Entry::Live(record) = entry {
                    // A record whose `OathSeal` blob will not open is treated
                    // as an empty table slot, **not** as a fatal error: the
                    // medium read cleanly, so this is a fact about the data,
                    // and the record is one this firmware cannot serve under any
                    // retry. The alternative — reserving the slot — leaks it
                    // forever against a credential nobody can use. The next
                    // PUT overwrites it at a strictly higher generation, which
                    // is an erase-then-program rather than a rewrite.
                    self.slots[i] = self.cred_from_record(&record);
                }
            }
            0
        };

        if imported > 0 {
            // US-1030: everything now in the region carries a sealed key, so
            // the "re-seal before serving" obligation is discharged.
            self.reseal_pending = false;
        }
        if had_legacy {
            // Retire the legacy stream at the next persist: `encode_state` no
            // longer emits credential records once a region is attached, so
            // this write is what makes "the secure store holds no OATH
            // credential table" true of the *medium* and not only of the live
            // record. `tests/oath_keyregion.rs` asserts it on the store's bytes.
            self.dirty = true;
        }
        self.refresh_session_grant();
        let live = self.slots.iter().filter(|s| s.is_some()).count() as u16;
        RegionStatus::Mounted { live, imported }
    }

    /// US-1553: the empty-table degradation path.
    fn degrade(&mut self, reason: OathStoreError) -> RegionStatus {
        self.slots.fill(None);
        self.region_degraded = true;
        self.refresh_session_grant();
        // The reason is kept out of the applet's state on purpose: `no_std`
        // has no log to write it to, and the only difference a caller can act
        // on is degraded-or-not. The error string is still reachable from
        // `OathStore::mount`/`recover` for a caller that wants it.
        let _ = reason;
        RegionStatus::Degraded
    }

    /// US-1553: move a legacy stream credential into the region, once.
    ///
    /// Only when the region came up **empty**. That condition is the
    /// whole safety argument: a region with records in it has already been
    /// migrated, and merging a stream table into it would have to decide what
    /// to do about a name that exists on both sides — and the two sides have no
    /// shared identity, because a stream record carries a table *index* and a
    /// region record carries a *slot*, and nothing ties index 7 to slot 7
    /// across the two schemes except that they are both called 7.
    ///
    /// So the migration is one-way and single-shot, and a device that somehow
    /// has both keeps the region's view: the region's records are the ones the
    /// owner has used since, and the stream's are a snapshot of a state that
    /// has demonstrably already moved on.
    ///
    /// Imports run **highest table index first**, so a failure part-way leaves
    /// the *tail* of the table migrated and the head still in the stream, where
    /// the next boot's legacy read finds it — never a hole in the middle that
    /// both sides believe the other owns.
    fn import_legacy(&mut self) -> u16 {
        let mut imported = 0u16;
        for i in (0..MAX_CREDS).rev() {
            // `Cred` is `Copy`, so the entry survives the borrow `region_sync`
            // takes — which matters, because on a refusal `region_sync`
            // reconciles the table against the medium and the medium says
            // "empty", and this credential must not vanish from RAM because it
            // could not be written. It is still the owner's credential; it is
            // simply not durable yet.
            let Some(cred) = self.slots[i] else { continue };
            if self.region_sync(i).is_err() {
                self.slots[i] = Some(cred);
                self.region_degraded = true;
                break;
            }
            imported += 1;
        }
        imported
    }

    /// US-1553: push table slot `index` to the region and report whether it
    /// reached the medium.
    ///
    /// `Err` means the table now agrees with the medium, not with the caller:
    /// on any failure the slot is re-read ([`Self::region_reconcile`]) and the
    /// **medium wins**. That is the only correct resolution for the one failure
    /// mode that is not a clean refusal — a commit interrupted after the sector
    /// erase, where `commit::recover` will replay the staged record on the next
    /// attempt and the new credential is already the durable one. Rolling the
    /// RAM table back to the *old* credential in that state would leave a token
    /// computing codes from a secret the owner has already replaced.
    fn region_sync(&mut self, index: usize) -> Result<(), ()> {
        if self.region.is_none() {
            return Ok(());
        }
        let result = match self.slots[index] {
            Some(cred) => {
                // Seal first, so the plaintext key never crosses into the
                // region handle's borrow and the nonce generation is the one
                // the commit is about to use.
                //
                // **Every** failure path falls through to `region_reconcile`
                // below, including the ones that never reach the commit — a
                // failure to read the slot's current generation is just as much
                // "the table may now disagree with the medium" as a refused
                // commit is, and leaving the in-RAM credential in place is how
                // a token ends up serving a secret it never stored.
                let record = match self.region_record(index, &cred) {
                    Ok(record) => record,
                    Err(e) => {
                        self.region_reconcile(index);
                        return Err(e);
                    }
                };
                match self.region.as_mut() {
                    Some(handle) => handle.store().write(index as u16, &record).map(|_| ()),
                    None => Ok(()),
                }
            }
            None => match self.region.as_mut() {
                Some(handle) => handle.store().delete(index as u16).map(|_| ()),
                None => Ok(()),
            },
        };
        if result.is_ok() {
            return Ok(());
        }
        self.region_reconcile(index);
        Err(())
    }

    /// US-1553: build the region record for table slot `index`.
    ///
    /// The `OathSeal` nonce generation **is** the region record's generation,
    /// read from the medium a moment earlier. That is the substitution US-1553
    /// makes and `keyregion/oath_store.rs` argues in full: the counter and the
    /// sealed bytes are programmed by one sector-atomic commit, so the US-1030
    /// "reserve before you seal" ordering is not weakened — there is no longer
    /// a second write that could be cut between them, and the slot's generation
    /// is durably monotonic without a resident counter to lose across a reset.
    fn region_record(&mut self, index: usize, cred: &Cred) -> Result<OathCredential, ()> {
        let index_u16 = index as u16;
        let generation = match self.region.as_mut() {
            Some(handle) => handle.store().next_generation(index_u16).map_err(|_| ())?,
            None => return Err(()),
        };
        let mut sealed = [0u8; MAX_KEY + OATH_SEAL_OVERHEAD];
        let n = self
            .seal
            .seal(
                FID_CRED_BASE + index_u16,
                u64::from(generation),
                &cred.key[..cred.key_len as usize],
                &mut sealed,
            )
            .map_err(|_| ())?;
        OathCredential::new(
            &cred.name[..cred.name_len as usize],
            &sealed[..n],
            u64::from(generation),
            cred.imf.unwrap_or(0),
            cred.props,
        )
        .ok_or(())
    }

    /// US-1553: adopt whatever the medium holds at table slot `index`.
    ///
    /// Called after a refused commit, and after any other moment where RAM and
    /// the region could disagree. A read that itself faults sets the degraded
    /// flag: at that point the applet knows it has changed something it cannot
    /// prove was stored, and a token that does not know what it holds should
    /// not serve the table it thinks it has.
    fn region_reconcile(&mut self, index: usize) {
        let entry = match self.region.as_mut() {
            Some(handle) => handle.store().read(index as u16),
            None => return,
        };
        self.slots[index] = match entry {
            Ok(Entry::Live(record)) => self.cred_from_record(&record),
            Ok(_) => None,
            Err(_) => {
                self.region_degraded = true;
                None
            }
        };
        // **The session grant is deliberately not recomputed here.**
        //
        // This used to end with `refresh_session_grant()`, which was a
        // category error: the function reconciles **one slot** against the
        // medium, and medium-vs-RAM agreement says nothing about whether the
        // current session was authenticated. Its only effect was to log the user
        // out — on any device with an access code or PIN the grant is derived
        // false, so a single transient flash failure during a write flipped
        // `validated` from true (a completed VALIDATE) to false, and the next
        // command answered 0x6982 with no explanation.
        //
        // The two states are genuinely independent: a session can be
        // authenticated while a commit is in doubt, and the correct answer to
        // "I do not know what this slot holds" is to stop serving *that slot*,
        // which `self.slots[index] = None` above already does.
    }

    /// US-1553: rebuild a `Cred` from a region record by opening its
    /// `OathSeal` blob.
    ///
    /// `None` for a blob this firmware did not write (an unsealed one) or one
    /// that will not open. The record's `imf` is only honoured for an HOTP
    /// secret — the algorithm/type byte inside the sealed blob is the
    /// authority, exactly as it was when the record was a TLV in a stream, and
    /// a TOTP credential carrying a stale counter must not grow one.
    fn cred_from_record(&mut self, record: &OathCredential) -> Option<Cred> {
        let blob = record.sealed_key();
        if !OathSeal::is_sealed(blob) {
            return None;
        }
        let mut plain = [0u8; MAX_KEY];
        let n = self.seal.open(blob, &mut plain).ok()?;
        if !(2..=MAX_KEY).contains(&n) {
            plain.zeroize();
            return None;
        }
        let mut cred = Cred::default();
        cred.key[..n].copy_from_slice(&plain[..n]);
        cred.key_len = n as u8;
        plain.zeroize();
        let name = record.name();
        cred.name[..name.len()].copy_from_slice(name);
        cred.name_len = name.len() as u8;
        cred.imf = if cred.key[0] & TYPE_MASK == TYPE_HOTP {
            Some(record.imf())
        } else {
            None
        };
        cred.props = record.props() & PROP_ENFORCED;
        Some(cred)
    }

    /// US-1553: tombstone every occupied slot, so a factory reset is durable in
    /// the region rather than only in RAM.
    ///
    /// Not atomic across slots, and cannot be: 68 sector-atomic commits are 68
    /// erases with no way to make the last conditional on the first, which is
    /// the same statement [`fapico2_platform::keyregion::commit::wipe`] makes
    /// about the whole region. The failure direction is chosen — a reset that
    /// stops early leaves *fewer* credentials, not more, and every tombstone
    /// that did land is durable.
    fn wipe_region(&mut self) -> Result<(), Sw> {
        for i in 0..MAX_CREDS {
            if self.slots[i].is_none() {
                continue;
            }
            self.slots[i] = None;
            if self.region_sync(i).is_err() {
                return Err(SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        Ok(())
    }

    /// US-1553: note a credential mutation.
    ///
    /// The `dirty` flag means "the **secure store** is out of date", which is
    /// what [`App::persist_state`] and the gate's partition-image program both
    /// act on. A credential mutation that went to the region has nothing
    /// pending in the store, so marking it dirty would make every credential
    /// write re-serialize the stream and reprogram the partition image — a real
    /// cost, and a lie about where the bytes went.
    fn note_change(&mut self) {
        if self.region.is_none() {
            self.dirty = true;
        }
    }

    /// Decode the `oath.keystore.v1` record stream into the slot table.
    fn load_stream(&mut self, stream: &[u8]) -> Result<(), SecureStoreError> {
        let mut i = 0;
        while i < stream.len() {
            if i + 6 > stream.len() {
                return Err(SecureStoreError::Corrupt);
            }
            let fid = u16::from_le_bytes([stream[i], stream[i + 1]]);
            let len =
                u32::from_le_bytes([stream[i + 2], stream[i + 3], stream[i + 4], stream[i + 5]])
                    as usize;
            i += 6;
            if len > stream.len() - i {
                return Err(SecureStoreError::Corrupt);
            }
            let payload = &stream[i..i + len];
            i += len;
            match fid {
                FID_ACCESS_CODE => {
                    // An oversized code is refused rather than dropped:
                    // silently unlocking a locked token is a security hole.
                    if payload.len() > MAX_ACCESS_CODE {
                        return Err(SecureStoreError::Corrupt);
                    }
                    if !payload.is_empty() {
                        let mut arr = [0u8; MAX_ACCESS_CODE];
                        arr[..payload.len()].copy_from_slice(payload);
                        self.access_code = Some((arr, payload.len() as u8));
                    }
                }
                FID_CRED_BASE..=FID_CRED_MAX => {
                    let idx = (fid - FID_CRED_BASE) as usize;
                    if self.slots[idx].is_some() {
                        continue; // duplicate fid: first record wins
                    }
                    let Some(name) = nth_tlv(payload, TAG_NAME, 0) else {
                        continue; // not a decodable credential (e.g. container marker)
                    };
                    if name.len() > MAX_NAME {
                        continue;
                    }
                    let Some(key) = nth_tlv(payload, TAG_KEY, 0) else {
                        continue;
                    };
                    // US-1030: a credential key is either this firmware's
                    // sealed form (a C `"OATH"` record *with* a generation
                    // object — the shape US-1030 writes) or something that
                    // has to be re-sealed before the app is reachable.
                    //
                    // The three outcomes are deliberately different:
                    //
                    // * sealed, opens, has a generation → nothing to do.
                    // * sealed, opens, **no** generation → a C-produced
                    //   record (C's own nonce is random, so there is no
                    //   generation to record). Adopt it: the credential is
                    //   valid, but the store does not yet know which
                    //   generation it sits at, so re-seal it.
                    // * sealed, does **not** open → refuse the boot. This
                    //   is the hostile case (a rewritten blob, a blob from
                    //   another device, or the 2⁻³² chance a random secret
                    //   happens to begin `"OATH"`×`0x01`). C refuses here
                    //   too (`oath_decrypt_key` returns the error and the
                    //   command fails); the difference is that US-1030 has
                    //   made this path reachable at boot, where "skip the
                    //   record" would silently delete a credential the
                    //   owner still believes they provisioned.
                    let mut plain = [0u8; MAX_KEY];
                    let sealed = OathSeal::is_sealed(key);
                    let key = if sealed {
                        let n = self
                            .seal
                            .open(key, &mut plain)
                            .map_err(|_| SecureStoreError::Corrupt)?;
                        if nth_tlv(payload, TAG_SEAL_GENERATION, 0).is_none() {
                            self.reseal_pending = true;
                        }
                        // An *authenticated* key of an impossible length is
                        // not a credential this firmware ever wrote: refuse
                        // rather than `continue`, which would delete it.
                        if !(2..=MAX_KEY).contains(&n) {
                            plain.zeroize();
                            return Err(SecureStoreError::Corrupt);
                        }
                        &plain[..n]
                    } else {
                        // Plaintext — a C record the C firmware chose not
                        // to seal, or one this firmware wrote before
                        // US-1030. Loaded as-is so nothing is lost, and
                        // re-sealed before any APDU can reach it.
                        self.reseal_pending = true;
                        if !(2..=MAX_KEY).contains(&key.len()) {
                            continue;
                        }
                        key
                    };
                    let imf = if key[0] & TYPE_MASK == TYPE_HOTP {
                        nth_tlv(payload, TAG_IMF, 0).map(|v| {
                            // Left-pad to 8 bytes (host/C parity).
                            let mut be = [0u8; 8];
                            let start = 8usize.saturating_sub(v.len());
                            let take = v.len().min(8);
                            be[start..start + take].copy_from_slice(&v[..take]);
                            u64::from_be_bytes(be)
                        })
                    } else {
                        None
                    };
                    let mut cred = Cred::default();
                    cred.name[..name.len()].copy_from_slice(name);
                    cred.name_len = name.len() as u8;
                    cred.key[..key.len()].copy_from_slice(key);
                    cred.key_len = key.len() as u8;
                    cred.imf = imf;
                    // US-133: the persisted property object, when the
                    // record carries one. Masked to [`PROP_ENFORCED`]:
                    // `cmd_put` cannot produce an unenforceable bit, so a
                    // record that has one came from outside this firmware,
                    // and an attacker who can rewrite the store can rewrite
                    // the secret anyway — what must not happen is a bit
                    // that *looks* enforced in LIST and is not.
                    cred.props = nth_tlv(payload, TAG_PROPERTY, 0)
                        .and_then(|v| v.first().copied())
                        .unwrap_or(0)
                        & PROP_ENFORCED;
                    self.slots[idx] = Some(cred);
                    // US-1030: the unseal scratch does not outlive the
                    // record it produced. (`OathSeal::open` already
                    // zeroizes it on a tag failure; this is the success
                    // path.)
                    plain.zeroize();
                }
                FID_OTP_PIN => {
                    // US-904: a salted record (49 bytes) or a legacy record
                    // (33 bytes, no salt) decode; anything else is stream
                    // corruption — boot refuses rather than re-seeding a
                    // locked code. First record wins (credential parity).
                    if self.pin.is_some() {
                        continue;
                    }
                    let record = match payload.len() {
                        PIN_SALTED_LEN => {
                            let mut salt = [0u8; 16];
                            salt.copy_from_slice(&payload[1..17]);
                            let mut verifier = [0u8; 32];
                            verifier.copy_from_slice(&payload[17..49]);
                            PinRecord {
                                counter: payload[0],
                                salt,
                                verifier,
                                legacy: false,
                            }
                        }
                        PIN_LEGACY_LEN => {
                            let mut verifier = [0u8; 32];
                            verifier.copy_from_slice(&payload[1..33]);
                            PinRecord {
                                counter: payload[0],
                                salt: [0u8; 16],
                                verifier,
                                legacy: true,
                            }
                        }
                        _ => return Err(SecureStoreError::Corrupt),
                    };
                    self.pin = Some(record);
                }
                // 0xBA45..=0xBAFE (idx ≥ 68) and any other fid: outside the
                // bounded table — skipped, not a corruption.
                _ => {}
            }
        }
        Ok(())
    }

    /// US-1553: **the credentials the stream has to carry.**
    ///
    /// Empty once a key region is attached. The region is where a credential
    /// lives; the stream keeps only the two records that were never applet
    /// credentials to begin with — the access code and the US-904 OTP-PIN
    /// verifier — and that is what makes "the secure store holds no applet
    /// credential table" a fact about the *medium* rather than a fact about
    /// the code path that happens to be taken today.
    fn credentials_in_stream(&self) -> impl Iterator<Item = &Cred> {
        self.slots
            .iter()
            .flatten()
            .filter(move |_| self.region.is_none())
    }

    fn encode_len(&self) -> usize {
        let mut total = 0usize;
        for slot in self.credentials_in_stream() {
            total += 6 // [fid][len]
                + 2 + slot.name_len as usize // TAG_NAME
                + 2 + slot.key_len as usize + OATH_SEAL_OVERHEAD // TAG_KEY (US-1030: sealed)
                + 2 + SEAL_GENERATION_LEN // TAG_SEAL_GENERATION (US-1030)
                + usize::from(slot.imf.is_some()) * 10 // TAG_IMF
                + usize::from(slot.props != 0) * 2; // TAG_PROPERTY (US-133)
        }
        if let Some((_, len)) = &self.access_code {
            total += 6 + *len as usize;
        }
        if let Some(rec) = &self.pin {
            // US-904 pin record (fid 0xBA44): salted (49) or, for a not-yet-
            // upgraded legacy record, the legacy 33-byte form.
            total += 6 + if rec.legacy {
                PIN_LEGACY_LEN
            } else {
                PIN_SALTED_LEN
            };
        }
        total
    }

    /// Encode the state as the canonical record stream, **sealing every
    /// credential key** (US-1030).
    ///
    /// The seal is unconditional rather than "only if it changed": a `Cred`
    /// holds the plaintext key and nothing else about how it was sealed, so
    /// there is no way to recognize an unchanged key without carrying the
    /// sealed blob alongside it — 99 extra bytes × 68 slots on an 11 KiB
    /// app. Re-sealing is what makes the second red (never reuse a nonce)
    /// observable at all, and the cost is bounded: the stream is only ever
    /// written when the app is dirty, so a device that does not touch its
    /// credentials does not move the counter and does not program flash.
    ///
    /// # Ordering (the tear-safety property)
    ///
    /// [`reserve_seal_generations`] persists the new high-water mark
    /// **before** the first sealed byte is produced. The stream write itself
    /// is the caller's. So on a power cut the possible states are: counter
    /// ahead, stream old (next boot re-seals higher) — never counter behind
    /// a fresh stream, which is the one state that re-issues a nonce.
    fn encode_state(
        &self,
        store: &mut dyn SecureStore,
    ) -> Result<HeaplessVec<u8, MAX_LOGICAL_LEN>, SecureStoreError> {
        let total = self.encode_len();
        if total > MAX_LOGICAL_LEN {
            return Err(SecureStoreError::Full);
        }
        // US-1030: one reservation for the whole table; credential `i` is
        // sealed at `base + 1 + i`, so two credentials never share a
        // generation even though one counter pass covers them.
        let count = self.credentials_in_stream().count();
        let base = reserve_seal_generations(store, count)?;
        let mut next = base;
        let mut out = HeaplessVec::<u8, MAX_LOGICAL_LEN>::new();
        let mut sealed = [0u8; MAX_KEY + OATH_SEAL_OVERHEAD];
        for (idx, slot) in self.slots.iter().enumerate() {
            if self.region.is_some() {
                break; // US-1553: credentials live in the region, not the stream
            }
            let Some(cred) = slot else { continue };
            next += 1;
            let fid = FID_CRED_BASE + idx as u16;
            // US-1030: seal first, into a fixed scratch, so the record
            // payload below never holds plaintext key bytes.
            let n = self
                .seal
                .seal(fid, next, &cred.key[..cred.key_len as usize], &mut sealed)
                .map_err(|_| SecureStoreError::Corrupt)?;
            // US-133: the trailing `+2` is the worst-case bare `78 <props>`
            // property object; `out.len() == total` at the end is the guard
            // that this buffer is big enough.
            let mut payload = [0u8; 2
                + MAX_NAME
                + 2
                + MAX_KEY
                + OATH_SEAL_OVERHEAD
                + 10
                + 2
                + 2
                + SEAL_GENERATION_LEN];
            let mut p = 0usize;
            payload[p] = TAG_NAME;
            p += 1;
            payload[p] = cred.name_len;
            p += 1;
            payload[p..p + cred.name_len as usize]
                .copy_from_slice(&cred.name[..cred.name_len as usize]);
            p += cred.name_len as usize;
            payload[p] = TAG_KEY;
            p += 1;
            // The YKOATH length byte is one byte, and a sealed key is
            // `key_len + 33` — at most 99, so it still fits.
            payload[p] = (cred.key_len as usize + OATH_SEAL_OVERHEAD) as u8;
            p += 1;
            payload[p..p + n].copy_from_slice(&sealed[..n]);
            p += n;
            // US-1030: the generation the nonce was derived from.
            payload[p] = TAG_SEAL_GENERATION;
            p += 1;
            payload[p] = SEAL_GENERATION_LEN as u8;
            p += 1;
            payload[p..p + SEAL_GENERATION_LEN].copy_from_slice(&next.to_be_bytes());
            p += SEAL_GENERATION_LEN;
            if let Some(imf) = cred.imf {
                payload[p] = TAG_IMF;
                p += 1;
                payload[p] = 8;
                p += 1;
                payload[p..p + 8].copy_from_slice(&imf.to_be_bytes());
                p += 8;
            }
            // US-133: the property object, written last and only when set.
            //
            // **Written in the same bare two-byte dialect the request
            // parser accepts, not in ordinary `78 01 <props>` BER form.**
            // The two are indistinguishable to `nth_tlv` — a walker that
            // treats a boundary `0x78` as bare reads the `01` of a tagged
            // `78 01 02` as the property value and strands the `02` — so
            // the record has to pick one dialect, and it picks the one the
            // applet already speaks. The record is read only by
            // [`Self::load_stream`]; C's C-produced migration records carry
            // no property object at all and decode to `props == 0`
            // unchanged, so the US-413 stream format does not move and no
            // migration step is introduced.
            if cred.props != 0 {
                payload[p] = TAG_PROPERTY;
                p += 1;
                payload[p] = cred.props;
                p += 1;
            }
            push_record(&mut out, fid, &payload[..p]);
        }
        if let Some((code, len)) = &self.access_code {
            push_record(&mut out, FID_ACCESS_CODE, &code[..*len as usize]);
        }
        if let Some(rec) = &self.pin {
            // US-904: a legacy record persists in its legacy form (a sibling
            // mutation can mark the state dirty before the record's own
            // successful verify upgraded it) so the upgrade path survives a
            // reboot; the salted form is the canonical 49-byte record.
            if rec.legacy {
                let mut payload = [0u8; PIN_LEGACY_LEN];
                payload[0] = rec.counter;
                payload[1..33].copy_from_slice(&rec.verifier);
                push_record(&mut out, FID_OTP_PIN, &payload);
            } else {
                let mut payload = [0u8; PIN_SALTED_LEN];
                payload[0] = rec.counter;
                payload[1..17].copy_from_slice(&rec.salt);
                payload[17..49].copy_from_slice(&rec.verifier);
                push_record(&mut out, FID_OTP_PIN, &payload);
            }
        }
        // The `encode_len` accounting above is the guard; a drift here
        // would silently truncate a record, so it is a refusal and not a
        // truncation.
        if out.len() != total {
            return Err(SecureStoreError::Corrupt);
        }
        Ok(out)
    }

    /// Fill the TRNG pool (boot path; US-380 sole randomness source).
    fn fill_rng_pool<R: Trng>(&mut self, trng: &mut R) {
        self.rng_pool.clear();
        self.rng_cursor = 0;
        let mut chunk = [0u8; 64];
        for _ in 0..8 {
            trng.random_bytes(&mut chunk);
            if self.rng_pool.extend_from_slice(&chunk).is_err() {
                break;
            }
        }
    }

    /// Draw `out.len()` bytes from the boot-time TRNG pool; stretch with a
    /// keyed hash when exhausted (FidoApp `draw_random` parity).
    fn draw_random(&mut self, out: &mut [u8]) {
        let pool = &mut self.rng_pool;
        let mut cur = self.rng_cursor;
        for b in out.iter_mut() {
            if cur >= pool.len() {
                let mut mixed = [0u8; 32];
                let mut h = Sha256::new();
                h.update(pool.as_slice());
                mixed.copy_from_slice(&h.finalize());
                pool.clear();
                let _ = pool.extend_from_slice(&mixed);
                cur = 0;
            }
            *b = pool[cur];
            cur += 1;
        }
        self.rng_cursor = cur;
    }

    /// Parse the C-harness APDU: `00 INS P1 P2 00 LH LL data... LE...`.
    /// Borrowed form (OTP parity): the extended header is trusted only when
    /// a data field is actually present.
    ///
    /// US-132 (PICOForge-COMPAT): the **4-byte case-1 header** is accepted.
    /// Before this story the floor was 5 bytes, so a bare
    /// `CLA INS P1 P2` (no Lc, no Le) was dropped to INS 0 and answered
    /// `0x6D00`. That is legal ISO 7816-4 and the C reference takes it —
    /// `apdu.c::apdu_process` has an explicit `buffer_size == 4` branch
    /// (`apdu.nc = apdu.ne = 0`) — but the reference client does not pad:
    /// picoforge's `Apdu::write(CLA_ISO, INS_RESET, 0xDE, 0xAD, &[])` sets
    /// `le: None` with empty data, and `Apdu::encode` emits an Lc **and** a
    /// Le byte only when there is data, so its Reset reaches the wire as
    /// exactly `00 04 DE AD`. With the old floor that frame never reached
    /// `cmd_reset`, so the RESET gate work in this story would have been
    /// unreachable by the client it exists for.
    ///
    /// The change is additive and length-local: it adds `len() == 4` and
    /// moves the floor from 5 to 4. **Every other length takes the identical
    /// path it took before**, byte for byte, and a frame too short to carry
    /// a header (3 bytes or fewer) is still refused as `0x6D00`.
    /// `parse_apdu` is an `OathApp` method, so no other applet's framing
    /// moves with it.
    fn parse_apdu(apdu: &[u8]) -> (u8, u8, u8, &[u8]) {
        if apdu.len() >= 7 && apdu[4] == 0x00 && apdu.len() > 7 + 1 {
            let lc = u16::from_be_bytes([apdu[5], apdu[6]]) as usize;
            let data = if apdu.len() >= 7 + lc {
                &apdu[7..7 + lc]
            } else {
                &apdu[7..]
            };
            return (apdu[1], apdu[2], apdu[3], data);
        }
        if apdu.len() < 4 {
            // Too short to be a header at all — not a command.
            return (0, 0, 0, &[]);
        }
        if apdu.len() == 4 {
            // ISO 7816-4 case 1: no Lc, no Le, no data. C parity
            // (`apdu.c`, `buffer_size == 4`).
            return (apdu[1], apdu[2], apdu[3], &[]);
        }
        let lc = apdu[4] as usize;
        let data = if apdu.len() >= 5 + lc {
            &apdu[5..5 + lc]
        } else {
            &apdu[5..]
        };
        (apdu[1], apdu[2], apdu[3], data)
    }

    fn find_cred(&self, name: &[u8]) -> Option<usize> {
        self.slots.iter().position(|c| {
            c.as_ref().is_some_and(|c| {
                c.name_len as usize == name.len() && &c.name[..c.name_len as usize] == name
            })
        })
    }

    /// Compute the OATH response body (digits + full MAC, or the truncated
    /// form) into `out`; returns its length.
    fn calculate_into(
        &self,
        truncate: bool,
        key: &[u8],
        chal: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        if key.len() < 2 {
            return None;
        }
        let mut mac = [0u8; 64];
        let size = hmac_into(key[0], &key[2..], chal, &mut mac)?;
        let digits = key[1];
        if truncate {
            let offset = mac[size - 1] as usize & 0x0F;
            out[0] = 5;
            out[1] = digits;
            out[2] = mac[offset] & 0x7F;
            out[3..6].copy_from_slice(&mac[offset + 1..offset + 4]);
            Some(6)
        } else {
            out[0] = (size + 1) as u8;
            out[1] = digits;
            out[2..2 + size].copy_from_slice(&mac[..size]);
            Some(2 + size)
        }
    }
}

impl App for OathApp {
    fn aid(&self) -> &[u8] {
        OATH_AID
    }

    fn select(&mut self, internal: bool) -> Sw {
        if !internal {
            // Host-issued SELECT resets the security state (ISO 7816-4): the
            // grant is recomputed by the virgin rule (US-901), never
            // self-granted.
            self.refresh_session_grant();
            // A host-issued SELECT also abandons any chunked response
            // mid-stream (C: SELECT is an APDU, non-continuation → reset).
            self.clear_chunk();
            let mut challenge = [0u8; 8];
            self.draw_random(&mut challenge);
            self.challenge = challenge;
        }
        SW_OK
    }

    fn select_apdu(
        &mut self,
        internal: bool,
        _apdu: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        // US-1553: first applet use in the ordinary case is this SELECT, so
        // this is where the region mounts on a device build.
        self.attach_region_if_available();
        let sw = self.select(internal);
        if sw == SW_OK {
            // US-130 defence in depth. The constructor now *requires* the
            // device-id, so on a real unit this cannot fire — but it is the
            // backstop for the failure the required argument exists to
            // prevent: if a future change ever gives the applet a default
            // again (or a unit somehow boots with the emulation stand-in),
            // SELECT refuses with an error SW instead of handing every unit
            // the same PBKDF2 salt.
            //
            // Fail-closed and non-fatal by design: an error SW leaves the
            // token unusable-but-intact (the credentials are untouched, and
            // the fault is visible in a log), where panicking in `no_std`
            // would reset the board and hide the cause. It cannot be reached
            // on the host build, so the emulation suites — which legitimately
            // use the stand-in — are unaffected.
            #[cfg(target_arch = "arm")]
            if self.device_id == device_id_from_chipid(EMULATION_CHIPID) {
                return SW_CONDITIONS_NOT_SATISFIED;
            }

            let _ = resp.extend_from_slice(&[TAG_VERSION, 3, 4, 3, 0]);
            // US-130: the device-id, derived from the chip-id — NOT a fleet
            // wide literal, because this TLV is the PBKDF2 salt a host uses
            // for the access key.
            let _ = resp.extend_from_slice(&[TAG_NAME, DEVICE_ID_LEN as u8]);
            let _ = resp.extend_from_slice(&self.device_id);
            if self.access_code.is_some() {
                let _ = resp.extend_from_slice(&[TAG_CHALLENGE, 8]);
                let _ = resp.extend_from_slice(&self.challenge);
            }
        }
        sw
    }

    fn deselect(&mut self) {
        // Drop any chunked-response remainder with the session (OpenPgpApp
        // staged-reply parity).
        self.clear_chunk();
    }

    fn process(&mut self, apdu: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        // US-1553: belt and braces. `select_apdu` covers the ordinary path, but
        // a caller that reaches `process` without a SELECT must not be served a
        // legacy-stream table when a region is available. One call, once.
        self.attach_region_if_available();
        let (ins, p1, p2, data) = Self::parse_apdu(apdu);
        let sw = self.handle(ins, p1, p2, data, resp);
        let _ = resp.extend_from_slice(&sw.to_be_bytes());
    }

    /// US-711: the management RESET hook — clear the table, let the persist
    /// gate write the emptied stream (see [`OathApp::reset`]).
    fn factory_wipe(&mut self) {
        // US-1553: **mount before wiping, not after.** `firmware/src/tasks.rs`
        // calls this on a management-RESET generation bump with no prior OATH
        // SELECT, and [`OathApp::reset`] only wipes the region
        // `if self.region.is_some()`. Unmounted, a factory reset would empty the
        // legacy stream and leave all 68 flash records standing — and the next
        // command's mount would serve them again. A reset that resurrects every
        // credential is a worse outcome than a reset that reports it could not
        // run.
        self.attach_region_if_available();
        self.reset();
    }

    fn persist_state(&mut self, store: &mut dyn SecureStore) -> bool {
        if !self.dirty {
            return false;
        }
        // US-1030: a table carrying a key this firmware could not seal is
        // never written in the clear. `encode_state` fails rather than
        // falling back, and the app stays dirty so the gate retries.
        if self.reseal_pending {
            return self.reseal(store).is_ok();
        }
        let Ok(buf) = self.encode_state(store) else {
            return false; // over the chunked cap, or a seal failure — keep dirty, retry later
        };
        let wrote = write_state(store, &buf).is_ok();
        if wrote {
            self.dirty = false;
        }
        wrote
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn is_dirty(&self) -> bool {
        self.dirty
    }
}

impl OathApp {
    fn handle(
        &mut self,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        // US-713: any command other than the continuation discards the
        // undelivered remainder of a chunked response (C `apdu_process`
        // resets the pending response on a non-GET-RESPONSE APDU).
        if ins != INS_SEND_REMAINING {
            self.clear_chunk();
        }
        match ins {
            INS_PUT => self.cmd_put(data),
            INS_DELETE => self.cmd_delete(data),
            INS_SET_CODE => self.cmd_set_code(data),
            INS_RESET => self.cmd_reset(p1, p2),
            INS_RENAME => self.cmd_rename(data),
            INS_LIST => self.cmd_list(data, resp),
            INS_CALCULATE => self.cmd_calculate(p2, data, resp),
            INS_VALIDATE => self.cmd_validate(data, resp),
            INS_CALC_ALL => self.cmd_calculate_all(p2, data, resp),
            INS_SEND_REMAINING => self.cmd_send_remaining(resp),
            INS_VERIFY_CODE => {
                if !self.validated {
                    return SW_SECURITY_STATUS_NOT_SATISFIED;
                }
                SW_OK
            }
            INS_SET_PIN => self.cmd_set_pin(data),
            INS_CHANGE_PIN => self.cmd_change_pin(data),
            INS_VERIFY_PIN => self.cmd_verify_pin(data),
            _ => SW_INS_NOT_SUPPORTED,
        }
    }

    fn cmd_put(&mut self, data: &[u8]) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let key = match nth_tlv(data, TAG_KEY, 0) {
            Some(k) if k.len() >= 2 && k.len() <= MAX_KEY => k,
            Some(_) => return SW_WRONG_DATA,
            None => return SW_INCORRECT_PARAMS,
        };
        let name = match nth_tlv(data, TAG_NAME, 0) {
            Some(n) if n.len() <= MAX_NAME => n,
            Some(_) => return SW_WRONG_DATA,
            None => return SW_INCORRECT_PARAMS,
        };
        // US-133 (PICOForge-COMPAT): the bare `78 <props>` object.
        //
        // **Refuse, never accept-and-drop.** A host that sends a bit this
        // firmware does not enforce has asked for a protection it would
        // not get; answering `0x9000` would be a lie about the credential's
        // security, and the reference client has no way to notice. So an
        // unenforceable bit is `0x6A80` — an unsupported parameter value —
        // and the credential is not stored. `PROP_PWS` (0x01) is the bit
        // this costs today; see [`PROP_ENFORCED`].
        let props = match nth_tlv(data, TAG_PROPERTY, 0) {
            Some(v) => v.first().copied().unwrap_or(0),
            None => 0,
        };
        if props & !PROP_ENFORCED != 0 {
            return SW_INCORRECT_PARAMS;
        }
        // HOTP credentials carry a moving factor: an explicit TAG_IMF is
        // left-padded to 8 bytes; a missing one is stored as zero (C parity).
        let imf = if key[0] & TYPE_MASK == TYPE_HOTP {
            Some(match nth_tlv(data, TAG_IMF, 0) {
                Some(v) => {
                    let mut be = [0u8; 8];
                    let start = 8usize.saturating_sub(v.len());
                    let take = v.len().min(8);
                    be[start..start + take].copy_from_slice(&v[..take]);
                    u64::from_be_bytes(be)
                }
                None => 0,
            })
        } else {
            None
        };
        let mut cred = Cred::default();
        cred.name[..name.len()].copy_from_slice(name);
        cred.name_len = name.len() as u8;
        cred.key[..key.len()].copy_from_slice(key);
        cred.key_len = key.len() as u8;
        cred.imf = imf;
        cred.props = props;
        let idx = match self.find_cred(name) {
            Some(idx) => idx,
            None => match self.slots.iter().position(|c| c.is_none()) {
                Some(free) => free,
                None => return SW_FILE_FULL,
            },
        };
        self.slots[idx] = Some(cred);
        // US-1553: the record is durable before the command answers, so a
        // `0x9000` here means the credential is on the medium. A refusal rolls
        // the table back to whatever the medium says (`region_sync`), which is
        // the only correct resolution: a commit interrupted after its sector
        // erase leaves the *new* credential as the one `recover` will replay.
        if self.region_sync(idx).is_err() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        self.note_change();
        SW_OK
    }

    fn cmd_delete(&mut self, data: &[u8]) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(name) = nth_tlv(data, TAG_NAME, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        match self.find_cred(name) {
            Some(idx) => {
                self.slots[idx] = None;
                // US-1553: a delete is a tombstone commit, not an erase — see
                // `keyregion/oath_store::TOMBSTONE_NAME_LEN`. The slot is
                // reused by the next PUT, at a strictly higher generation.
                if self.region_sync(idx).is_err() {
                    return SW_CONDITIONS_NOT_SATISFIED;
                }
                self.note_change();
                SW_OK
            }
            None => SW_DATA_INVALID,
        }
    }

    fn cmd_rename(&mut self, data: &[u8]) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(old) = nth_tlv(data, TAG_NAME, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        let Some(new) = nth_tlv(data, TAG_NAME, 1) else {
            return SW_INCORRECT_PARAMS;
        };
        // C: renaming onto the same name is wrong data.
        if old == new {
            return SW_WRONG_DATA;
        }
        if new.len() > MAX_NAME {
            return SW_WRONG_DATA;
        }
        match self.find_cred(old) {
            Some(idx) => {
                let cred = self.slots[idx].as_mut().expect("slot present");
                cred.name[..new.len()].copy_from_slice(new);
                cred.name_len = new.len() as u8;
                if self.region_sync(idx).is_err() {
                    return SW_CONDITIONS_NOT_SATISFIED;
                }
                self.note_change();
                SW_OK
            }
            None => SW_DATA_INVALID,
        }
    }

    fn cmd_set_code(&mut self, data: &[u8]) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        if data.is_empty() {
            // US-905 (SEC-HARDEN): clearing a present access code is as hard
            // as setting it — it consumes a user-presence grant (RESET
            // parity). With no code on file it stays a plain no-op success
            // (nothing to clear, no consent needed — C parity).
            if self.access_code.is_some() && !self.user_present(PRESENCE_TAG_SET_CODE_CLEAR) {
                return SW_CONDITIONS_NOT_SATISFIED;
            }
            self.access_code = None;
            // Removing the access code **re-grants**, because the grant is
            // "there is no secret to authenticate with" — and after this line
            // there is none. (This comment previously claimed the opposite, on
            // the virginity rule; see [`Self::refresh_session_grant`].)
            self.refresh_session_grant();
            self.dirty = true;
            return SW_OK;
        }
        let key = match nth_tlv(data, TAG_KEY, 0) {
            Some(k) if k.len() >= 2 && k.len() <= MAX_ACCESS_CODE => k,
            Some(_) => return SW_WRONG_DATA,
            None => return SW_INCORRECT_PARAMS,
        };
        let chal = match nth_tlv(data, TAG_CHALLENGE, 0) {
            Some(c) => c,
            None => return SW_INCORRECT_PARAMS,
        };
        let resp = match nth_tlv(data, TAG_RESPONSE, 0) {
            Some(r) => r,
            None => return SW_INCORRECT_PARAMS,
        };
        let mut mac = [0u8; 64];
        let size = match hmac_into(key[0], &key[1..], chal, &mut mac) {
            Some(s) => s,
            None => return SW_INCORRECT_PARAMS,
        };
        if resp.len() != size || !ct_eq(resp, &mac[..size]) {
            return SW_DATA_INVALID;
        }
        let mut arr = [0u8; MAX_ACCESS_CODE];
        arr[..key.len()].copy_from_slice(key);
        self.access_code = Some((arr, key.len() as u8));
        let mut challenge = [0u8; 8];
        self.draw_random(&mut challenge);
        self.challenge = challenge;
        self.validated = false;
        self.dirty = true;
        SW_OK
    }

    fn cmd_validate(&mut self, data: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) -> Sw {
        let Some(chal) = nth_tlv(data, TAG_CHALLENGE, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        let Some(resp_tag) = nth_tlv(data, TAG_RESPONSE, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        let Some((code, code_len)) = &self.access_code else {
            // US-902 (deliberate C-parity break): with no access code on file
            // VALIDATE can never check anything, so it must not grant — the
            // session state (and the grant) is left untouched.
            return SW_CONDITIONS_NOT_SATISFIED;
        };
        let code = &code[..*code_len as usize];
        let mut mac = [0u8; 64];
        let size = match hmac_into(code[0], &code[1..], &self.challenge, &mut mac) {
            Some(s) => s,
            None => return SW_INCORRECT_PARAMS,
        };
        if resp_tag.len() != size || !ct_eq(resp_tag, &mac[..size]) {
            return SW_DATA_INVALID;
        }
        let size = match hmac_into(code[0], &code[1..], chal, &mut mac) {
            Some(s) => s,
            None => return SW_INCORRECT_PARAMS,
        };
        self.validated = true;
        let _ = resp.push(TAG_RESPONSE);
        let _ = resp.push(size as u8);
        let _ = resp.extend_from_slice(&mac[..size]);
        SW_OK
    }

    fn cmd_calculate(
        &mut self,
        p2: u8,
        data: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        if p2 != 0 && p2 != 1 {
            return SW_INCORRECT_P1P2;
        }
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        // C checks the request challenge before the name (HOTP ignores its
        // value and uses the stored moving factor instead).
        if nth_tlv(data, TAG_CHALLENGE, 0).is_none() {
            return SW_INCORRECT_PARAMS;
        }
        let Some(name) = nth_tlv(data, TAG_NAME, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        let Some(idx) = self.find_cred(name) else {
            return SW_DATA_INVALID;
        };
        // US-133 (PICOForge-COMPAT): a credential that asked for
        // require-touch costs a user-presence grant before its code is
        // released. Checked *after* the lookup so a request for a name that
        // does not exist still answers 0x6A84 without touching the presence
        // state, and the tag is the command's own INS (US-921 binding) so a
        // press latched for RESET — or for a CALC ALL — cannot arm it.
        if self.slots[idx].as_ref().expect("slot present").props & PROP_TOUCH != 0
            && !self.user_present(PRESENCE_TAG_CALCULATE)
        {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        // Copy the key out so the slot can be mutated afterwards (HOTP
        // counter — C updates the file on every calculation).
        let mut key = [0u8; MAX_KEY];
        let (key_len, is_hotp, counter) = {
            let cred = self.slots[idx].as_ref().expect("slot present");
            key[..cred.key_len as usize].copy_from_slice(&cred.key[..cred.key_len as usize]);
            (cred.key_len, cred.key[0] & TYPE_MASK == TYPE_HOTP, cred.imf)
        };
        let key = &key[..key_len as usize];
        // HOTP uses the stored moving factor; TOTP the request challenge.
        let mut body = [0u8; 66];
        let n = if is_hotp {
            let Some(counter) = counter else {
                return SW_INCORRECT_PARAMS;
            };
            self.calculate_into(p2 == 1, key, &counter.to_be_bytes(), &mut body)
        } else {
            let Some(chal) = nth_tlv(data, TAG_CHALLENGE, 0) else {
                return SW_INCORRECT_PARAMS;
            };
            self.calculate_into(p2 == 1, key, chal, &mut body)
        };
        let Some(n) = n else {
            return SW_INCORRECT_PARAMS;
        };
        // US-1553: the HOTP counter is made durable **before** the code is
        // handed out. A CALCULATE that answers `0x9000` with a code but does
        // not advance the counter is a one-shot credential, and a caller that
        // retries would get the same code twice — so the ordering here is the
        // protocol, not a preference. It also means a failed commit cannot
        // leave a response body already written next to an error status word.
        if is_hotp {
            self.slots[idx].as_mut().expect("slot present").imf =
                Some(counter.expect("HOTP counter").wrapping_add(1));
            if self.region_sync(idx).is_err() {
                return SW_CONDITIONS_NOT_SATISFIED;
            }
            self.note_change();
        }
        let _ = resp.push(TAG_RESPONSE + p2);
        let _ = resp.extend_from_slice(&body[..n]);
        SW_OK
    }

    /// MAC size for a stored key's algorithm; 0 when unsupported (the entry
    /// is then skipped, matching `calculate_into` returning `None`). Keep in
    /// sync with `hmac_into`.
    fn mac_size(alg: u8) -> usize {
        match alg & ALG_MASK {
            ALG_SHA1 => 20,
            ALG_SHA256 => 32,
            ALG_SHA512 => 64,
            _ => 0,
        }
    }

    /// US-133 (PICOForge-COMPAT): does any stored credential carry
    /// [`PROP_TOUCH`]? Only TOTP ones matter for a CALC ALL body (HOTP
    /// entries emit `TAG_NO_RESPONSE`, never a code), but gating on the
    /// whole table is the conservative direction: it can refuse a listing
    /// that did not strictly need consent, never release one that did.
    fn any_requires_touch(&self) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|c| c.props & PROP_TOUCH != 0)
    }

    /// Total CALC ALL body length without evaluating any MAC: every entry
    /// size is static per credential (name entry 2 + name; HOTP entry 3;
    /// TOTP response entry 1 + `calculate_into`'s body — 2 + mac full or
    /// 6 truncated; unsupported algorithms contribute nothing).
    fn calc_all_body_len(&self, p2: u8) -> usize {
        let mut total = 0usize;
        for cred in self.slots.iter().flatten() {
            total += 2 + cred.name_len as usize;
            if cred.key[0] & TYPE_MASK == TYPE_HOTP {
                total += 3;
            } else {
                let size = Self::mac_size(cred.key[0]);
                if size > 0 {
                    total += 1 + if p2 == 1 { 6 } else { 2 + size };
                }
            }
        }
        total
    }

    /// Append the `want` bytes of the CALC ALL body starting `from` bytes
    /// into the logical stream, recomputing the per-credential entries (the
    /// body is a pure function of the slot table, P2 and the challenge — and
    /// the chunk state guarantees the table cannot change mid-stream: any
    /// other command resets it). Returns the number of bytes appended.
    fn stream_calc_all(
        &self,
        p2: u8,
        chal: &[u8],
        from: usize,
        want: usize,
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> usize {
        let mut skip = from;
        let mut emitted = 0usize;
        for idx in 0..MAX_CREDS {
            if emitted >= want {
                break;
            }
            let Some(cred) = self.slots[idx].as_ref() else {
                continue;
            };
            // Name entry first (C parity: emitted even when the response
            // entry is skipped for an unsupported algorithm).
            let mut entry: [u8; 2 + MAX_NAME] = [0; 2 + MAX_NAME];
            let nl = cred.name_len as usize;
            entry[0] = TAG_NAME;
            entry[1] = cred.name_len;
            entry[2..2 + nl].copy_from_slice(&cred.name[..nl]);
            emitted += emit_window(resp, &entry[..2 + nl], &mut skip, want - emitted);
            if emitted >= want {
                break;
            }
            let key = &cred.key[..cred.key_len as usize];
            if key[0] & TYPE_MASK == TYPE_HOTP {
                // C: HOTP never calculates in CALC_ALL (no counter advance)
                // — report "no response" with the digit count.
                let e = [TAG_NO_RESPONSE, 1, key[1]];
                emitted += emit_window(resp, &e, &mut skip, want - emitted);
            } else {
                let mut body = [0u8; 66];
                if let Some(n) = self.calculate_into(p2 == 1, key, chal, &mut body) {
                    let mut e = [0u8; 67];
                    e[0] = TAG_RESPONSE + p2;
                    e[1..1 + n].copy_from_slice(&body[..n]);
                    emitted += emit_window(resp, &e[..1 + n], &mut skip, want - emitted);
                }
            }
        }
        emitted
    }

    fn cmd_calculate_all(
        &mut self,
        p2: u8,
        data: &[u8],
        resp: &mut HeaplessVec<u8, MAX_RESPONSE>,
    ) -> Sw {
        if p2 != 0 && p2 != 1 {
            return SW_INCORRECT_P1P2;
        }
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let Some(chal) = nth_tlv(data, TAG_CHALLENGE, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        // US-133 (PICOForge-COMPAT): the property has to be honoured on the
        // *stream* path too, or CALC ALL is a one-command bypass of the
        // very protection CALCULATE just enforced — a host that wanted the
        // code without touching would just call this instead.
        //
        // **One grant gates the whole stream, not one per credential.** A
        // per-credential gate inside [`Self::stream_calc_all`] cannot be
        // built on this state model: the body is deliberately re-derived
        // from the slot table on every `0xA5` window and the stream carries
        // no progress the applet could park a pending grant against, so
        // there would be nowhere to record that credential 3 of 40 was
        // already paid for. A single up-front grant is the honest shape:
        // the user touches once, the whole listing is released, and no
        // path returns a touch-gated code without a press.
        if self.any_requires_touch() && !self.user_present(PRESENCE_TAG_CALC_ALL) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        // US-713: the body is served in chunks of at most OATH_CHUNK_MAX;
        // while more remains the status word is 61xx and INS 0xA5 drains the
        // rest. A stream that cannot be re-derived mid-stream (challenge too
        // long for the chunk state) keeps the US-705 overflow error as the
        // fallback.
        let total = self.calc_all_body_len(p2);
        if chal.len() > MAX_CHUNK_CHAL && total > OATH_CHUNK_MAX {
            return SW_FILE_FULL;
        }
        let first = total.min(OATH_CHUNK_MAX);
        self.stream_calc_all(p2, chal, 0, first, resp);
        if total > first {
            let mut st = ChunkState {
                p2,
                chal: [0u8; MAX_CHUNK_CHAL],
                chal_len: chal.len() as u8,
                pos: first,
                total,
            };
            st.chal[..chal.len()].copy_from_slice(chal);
            self.chunk = Some(st);
            return sw_more_data(total - first);
        }
        SW_OK
    }

    /// US-713: SEND REMAINING — serve the next window of a chunked response.
    /// Without a pending stream this is an error (story decision: an error
    /// SW rather than the C transport's silent empty 9000 for the never-
    /// implemented stub).
    fn cmd_send_remaining(&mut self, resp: &mut HeaplessVec<u8, MAX_RESPONSE>) -> Sw {
        let Some(mut st) = self.chunk.take() else {
            return SW_CONDITIONS_NOT_SATISFIED;
        };
        let want = (st.total - st.pos).min(OATH_CHUNK_MAX);
        let served =
            self.stream_calc_all(st.p2, &st.chal[..st.chal_len as usize], st.pos, want, resp);
        st.pos += served;
        if st.pos < st.total {
            let remaining = st.total - st.pos;
            self.chunk = Some(st);
            return sw_more_data(remaining);
        }
        // Stream consumed: clear the challenge copy with the state.
        st.zeroize();
        SW_OK
    }

    fn cmd_list(&mut self, data: &[u8], resp: &mut HeaplessVec<u8, MAX_RESPONSE>) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        let ext = data == [0x01];
        for cred in self.slots.iter().flatten() {
            // US-705.2: overflow-aware response building — a full
            // MAX_RESPONSE (a full table of maximal names does not fit it)
            // answers an error SW instead of a truncated body with a
            // garbage trailing SW.
            if resp.push(TAG_NAME_LIST).is_err()
                || resp.push(cred.name_len + 1 + u8::from(ext)).is_err()
                || resp.push(cred.key[0]).is_err()
                || resp
                    .extend_from_slice(&cred.name[..cred.name_len as usize])
                    .is_err()
            {
                return SW_FILE_FULL;
            }
            if ext {
                // C appends a props byte built from the credential's
                // PWS/PROPERTY bits. US-133: it used to be a hardcoded 0,
                // so a host that listed its credentials could never see
                // that one of them was require-touch — the property was
                // invisible in both directions. Now it is the stored byte.
                if resp.push(cred.props).is_err() {
                    return SW_FILE_FULL;
                }
            }
        }
        SW_OK
    }

    /// US-132 (PICOForge-COMPAT): OATH factory reset.
    ///
    /// **Gates, in order:** the `0xDE`/`0xAD` P1/P2 magic (else `0x6A86`),
    /// then the user-presence grant (else `0x6985`). Nothing else.
    ///
    /// **Why the session gate is gone (owner decision, 2026-09-27).**
    /// US-903/US-921 gated the wipe on `self.validated` *and* a touch. The
    /// reference client, picoforge, sends a bare `00 04 DE AD` with no
    /// unlock (`picoforge/src/hal/applets/oath.rs` `reset()`), so with the
    /// session gate in place its Reset button was dead — every call answered
    /// `0x6982`. The owner chose picoforge's process as the default because
    /// this firmware is being made compatible with it, and directed that the
    /// decision be documented for future review
    /// (`docs/tasks/us132-oath-reset-picocompat.md`).
    ///
    /// **What this deliberately weakens.** A holder who does *not* know the
    /// OATH access code can now erase the credential table, provided they can
    /// touch the token. Previously they could not. This is an approved
    /// compatibility trade, not an oversight.
    ///
    /// **What it does not weaken.** The magic and the touch both stay, and
    /// they are the *only* gates: no bare APDU with no physical interaction
    /// can drive the wipe. The grant is still bound to
    /// [`PRESENCE_TAG_RESET`] and still consumed from the shared presence
    /// runtime (US-921), so a press latched for another command — or for no
    /// pending request — never arms it.
    ///
    /// **What is unaffected.** The access code still gates reading and
    /// writing credentials: `cmd_put`, `cmd_list`, `cmd_delete`,
    /// `cmd_rename` and `cmd_calculate` keep their `validated` checks
    /// unchanged. Only the wipe path was relaxed.
    fn cmd_reset(&mut self, p1: u8, p2: u8) -> Sw {
        if p1 != 0xDE || p2 != 0xAD {
            return SW_INCORRECT_P1P2;
        }
        // US-903 (SEC-HARDEN), retained in full: the APDU path alone cannot
        // erase the credential table. US-921: the grant is bound to the
        // RESET tag (PRESENCE_TAG_RESET) and consumed from the shared
        // presence runtime — a discarded press (no pending request) never
        // arms it. This is now the ONLY consent gate on the wipe.
        if !self.user_present(PRESENCE_TAG_RESET) {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        // US-1553: on the key-region path the wipe is one tombstone commit per
        // occupied slot, made durable before the command answers. On the legacy
        // path it is the emptied stream below, marked dirty for the gate.
        if self.wipe_region().is_err() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        self.reset_state();
        if self.region.is_none() {
            self.dirty = true;
        }
        SW_OK
    }

    fn cmd_set_pin(&mut self, data: &[u8]) -> Sw {
        if !self.validated {
            return SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        if self.pin.is_some() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        let Some(pw) = nth_tlv(data, TAG_PASSWORD, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        // US-904: the record is salted from the TRNG pool and durable —
        // marking dirty makes the persist gate write the 0xBA44 record.
        let mut salt = [0u8; 16];
        self.draw_random(&mut salt);
        self.pin = Some(PinRecord {
            counter: MAX_OTP_COUNTER,
            salt,
            verifier: pin_verifier(pw, &salt),
            legacy: false,
        });
        self.dirty = true;
        SW_OK
    }

    /// US-904: check a PIN against the salted record. C parity: every check
    /// burns one retry (counter changes mark the state dirty so the budget is
    /// durable); a successful verify resets the budget, upgrades an in-memory
    /// legacy record to the salted form in place, and marks the state dirty.
    ///
    /// US-136 (PICOForge-COMPAT): the EPIC described the legacy-record
    /// migration as happening "on first set_code". It does not, and it cannot:
    /// the trigger is the **first successful verification** — `VERIFY_PIN`
    /// (INS 0xB2) and `CHANGE_PIN` (INS 0xB3) both land here, and those are
    /// the only points at which the applet holds the plaintext PIN and can
    /// re-derive a salted verifier. `SET_CODE` (INS 0x03) is a different
    /// applet secret (the OATH access code, record `0xBAFF`), never sees the
    /// PIN, and cannot migrate anything.
    ///
    /// **And there is no conversion to the YKOATH key model, by
    /// construction.** US-131 stores `PBKDF2-HMAC-SHA1(password, device_id,
    /// 1000, 16)` — a *derived* key; the password is never on the device.
    /// This record stores `SHA256(salt || pin)` — a one-way verifier. A
    /// verifier yields neither the PIN nor the access key, so there is
    /// nothing to convert. Any "migration" between the two would have to
    /// recover a plaintext secret first, i.e. it would have to break the
    /// hash, and the resulting unit would be locked out of its own
    /// credentials irrecoverably. The legacy record's *only* correct
    /// destination is the salted form, which is what the `rec.legacy` branch
    /// below does.
    fn check_pin(&mut self, pw: &[u8]) -> Result<(), Sw> {
        let Some(mut rec) = self.pin else {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        };
        if rec.counter == 0 {
            return Err(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        let verified = if rec.legacy {
            legacy_pin_verifier(pw) == rec.verifier
        } else {
            pin_verifier(pw, &rec.salt) == rec.verifier
        };
        if verified {
            if rec.legacy {
                // US-904 legacy migration: fresh salt, verifier re-derived
                // from the just-verified PIN, upgraded in place.
                let mut salt = [0u8; 16];
                self.draw_random(&mut salt);
                self.pin = Some(PinRecord {
                    counter: MAX_OTP_COUNTER,
                    salt,
                    verifier: pin_verifier(pw, &salt),
                    legacy: false,
                });
            } else {
                rec.counter = MAX_OTP_COUNTER;
                self.pin = Some(rec);
            }
            self.dirty = true;
            Ok(())
        } else {
            rec.counter -= 1;
            self.pin = Some(rec);
            self.dirty = true;
            Err(SW_SECURITY_STATUS_NOT_SATISFIED)
        }
    }

    fn cmd_change_pin(&mut self, data: &[u8]) -> Sw {
        let Some(pw) = nth_tlv(data, TAG_PASSWORD, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        let Some(new_pw) = nth_tlv(data, TAG_NEW_PASSWORD, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        if self.pin.is_none() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        if let Err(sw) = self.check_pin(pw) {
            return sw;
        }
        // US-904: CHANGE_PIN re-salts the record (the salt is per-record
        // TRNG material, so a new verifier is a new record) and marks the
        // state dirty for the persist gate.
        let mut salt = [0u8; 16];
        self.draw_random(&mut salt);
        self.pin = Some(PinRecord {
            counter: MAX_OTP_COUNTER,
            salt,
            verifier: pin_verifier(new_pw, &salt),
            legacy: false,
        });
        self.dirty = true;
        SW_OK
    }

    fn cmd_verify_pin(&mut self, data: &[u8]) -> Sw {
        let Some(pw) = nth_tlv(data, TAG_PASSWORD, 0) else {
            return SW_INCORRECT_PARAMS;
        };
        if self.pin.is_none() {
            return SW_CONDITIONS_NOT_SATISFIED;
        }
        if let Err(sw) = self.check_pin(pw) {
            return sw;
        }
        self.validated = true;
        SW_OK
    }
}

// TEMPORARY MEASUREMENT — removed immediately after the numbers are taken.

