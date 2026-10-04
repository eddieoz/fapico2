//! The key region's derivation chain and its record AAD (US-1547, US-1548).
//!
//! # One root, two subkeys
//!
//! The region is secured by exactly one OTP-rooted key hierarchy, layered on
//! top of the store v3 key rather than beside it:
//!
//! ```text
//! root        = store_v3::derive_store_key(otp_key_1, chipid)
//!             = HKDF-SHA256(salt="PS3F", ikm=otp_key_1 ‖ chipid, info="store")
//!               (store_v3.rs:98-105)
//! index_key   = HKDF-SHA256(salt=∅, ikm=root,        info="fapico2/keyregion/index/v1")
//! payload_key = HKDF-SHA256(salt=∅, ikm=root ‖ pin, info="fapico2/keyregion/payload/v1")
//! ```
//!
//! **Why the root is `derive_store_key` and not a new OTP-rooted HKDF**
//! (S7). It is already `HKDF-SHA256` over exactly the material this region
//! has — the OTP key row (`0xE90`) and the chipid, salted with `"PS3F"` and
//! labelled `"store"` — and it is already the key the firmware derives at boot
//! (`firmware/src/boot.rs:1196`). A second OTP-rooted derivation would be a
//! second answer to "what does the OTP row mean on this device", and the two
//! would then have to be argued to stay in step. This module adds one level
//! **below** that root and changes nothing about it, so S7 cannot regress
//! here: no new input reaches the root, and no caller of `derive_store_key`
//! sees a different key.
//!
//! # Why the index key is not PIN-gated (S1)
//!
//! The index is the part of the region that must be **structurally checkable
//! from a flash dump with no PIN and no user presence**. That is the entire
//! reason the key exists in this shape: a user who has forgotten their PIN,
//! or an operator triaging a dead board, can still be told *which* slots hold
//! records and whether the region's structure is intact. A PIN in the index
//! key's derivation would make the index unreadable in exactly the two cases
//! it is needed, and would buy nothing — the index holds no credential
//! material, and what protects it is that a forged index entry fails its tag.
//!
//! So `derive_index_key` takes the OTP row and the chipid and nothing else.
//! That is visible in its signature, which is the strongest form of the
//! property available in this language: there is no parameter a PIN-derived
//! secret could be passed in. The test
//! `the_index_key_is_not_a_function_of_any_pin_secret` proves the complement
//! — that the same PIN sweep that visibly moves the payload key leaves the
//! index key bit-identical.
//!
//! **What this costs, stated plainly.** The index is authenticated, not
//! confidential, and its authentication rests on the OTP row. That is the same
//! residual the store v3 key already carries and documents (`store_v3.rs:95-97`,
//! and US-918's note at `firmware/src/boot.rs:1183-1189`): the RP2350 OTP row
//! is readable by any code on the device and by a physical attacker, so this
//! is protection against an offline tamper of the flash image, not against an
//! attacker who has read the OTP row. Buying more would mean putting the index
//! key behind a secret the index's own purpose requires it not to be behind.
//!
//! # Why a failed derivation returns `None` and never halts boot (S10)
//!
//! AGENTS.md's hardware warning is blunt about the failure this avoids:
//! `read_otp_key_1()` reporting "no key" takes the board down through
//! `fatal_boot` **before USB is constructed**, and that has already produced a
//! false "the OTP key row is unreadable" failure on known-good commits. A key
//! region must not inherit that behaviour, because it is the one subsystem
//! whose whole value is being reachable on a device nobody can otherwise log
//! into.
//!
//! Every derivation here therefore returns `Option`, and the refusal is
//! **`None`** — never a panic, never `fatal_boot`. A device that cannot derive
//! the index key presents an **empty region**: the same reachability, at USB,
//! that a device with 256 credentials has. A device with zero keys must reach
//! USB exactly as a device with 256 does, and `None` is the only answer to
//! that which is not a brick.
//!
//! The one input this module actually refuses is an **all-zero OTP row** (a
//! factory part, or one the C firmware never initialised). The tree's own
//! newest discipline is that "present but constant" is strictly worse than
//! refusing: `ckey::derive_kbase` and `ckey::derive_drbg_seed` both return
//! [`NeverBootC`](crate::ckey::CKeyError::NeverBootC) on it
//! (`ckey.rs:170`, `ckey.rs:244`), and `drbg_seed.rs:216-223` spells out why —
//! a key derived from a constant input is a keystream any attacker computes
//! offline, which is worse than having no key, because no key at least
//! refuses. `store_v3::derive_store_key` accepts the zero row and documents
//! why (`ckey.rs:311-321`: a never-initialized part has no migrated credential
//! to protect); that reasoning is sound for *sealing* and unsound for an
//! *index*, because an index is exactly the thing a zero row would let anyone
//! forge. So the guard lives here, one level below the root, and changes
//! nothing about the root.
//!
//! # The AAD (S2)
//!
//! `RecordAad` binds **slot, generation and key domain**, and its byte layout
//! is fixed at `AAD_LEN` bytes and versioned by `AAD_MAGIC`.
//!
//! `apps/fido/src/snapshot_crypt.rs`'s `FieldAad` is the house precedent for
//! the shape — fixed-size, built on the stack, an assert on the buffer bound —
//! and it binds slot, scope and credential id. It binds **no generation**,
//! which is the gap this closes: one region holds records from several
//! applets under one payload key, so without a generation and a domain in the
//! AAD a record sealed for one applet's slot would unseal as another's, and a
//! record re-sealed at an older generation would unseal as current.
//!
//! **The layout is authenticated data.** Reordering these bytes does not fail
//! to compile, and does not fail any test that only checks round-trips — it
//! silently invalidates every record already written to the region. It is
//! therefore stated once, here, and pinned to the exact byte string by
//! `the_record_aad_is_exactly_these_eleven_bytes` in
//! `platform/tests/key_region_crypto.rs`. Do not reorder, do not resize, and do
//! not "improve" the encoding. A new layout is a new `AAD_MAGIC`.

use super::Slot;
use crate::store_v3;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// HKDF `info` for the **index** subkey: `b"fapico2/keyregion/index/v1"`.
///
/// Namespaced under `fapico2/keyregion/` and versioned, like the tree's other
/// Rust-side labels (`fapico2/ckey/wrap/v1`, `ckey.rs:756`) rather than like
/// the C-compat ones, which are fixed by a wire format we do not own. The
/// complete label set in the tree, and why none of them can collide:
///
/// | label | site | salt / IKM |
/// |---|---|---|
/// | `"store"` | `store_v3.rs:104`, `:115` | `"PS3F"` / OTP ‖ chipid |
/// | `"DEVICE/ROOT"` | `ckey.rs:186`, `:305` | serial ‖ chipid ‖ entropy / OTP |
/// | `"DEVICE/ROOT\0"` | `apps/piv/src/crypto.rs:32` | `"NO-OTP"` / SHA256(serial) |
/// | `"DRBG/SEED"` | `ckey.rs:198` | serial ‖ chipid ‖ entropy / OTP |
/// | `"PIN/VERIFY"`, `"PIN/TOKEN"`, `"PIN/ENC"`, `"PIN/ENC2"` | `ckey.rs:577`, `:586`, `:595`, `:611` | serial_hash / kver or session |
/// | `"OATH/KEYS"`, `"OATH/SEAL-NONCE/v1"` | `ckey.rs:350`, `:360` | serial_hash / PIN kenc chain |
/// | `"fapico2/ckey/wrap/v1"` | `ckey.rs:756` | serial_hash / OTP |
/// | `"PKOC/manifest/v1"`, `"PKOC/domain/v1"`, `"PKOC/object/v1"` | `ckey.rs:949`, `:968`, `:979` | ∅ / root |
/// | `"fapico2 fido snapshot fields v1"` | `apps/fido/src/snapshot_crypt.rs:75` | ∅ / store key |
/// | `"PicoKeys Vault enrollment v1"` | `apps/fido/src/vault.rs:22` | ∅ / x448 shared secret |
///
/// The collision argument is not "the strings look different" — it is that
/// HKDF's `info` is mixed into the expand step itself, so two derivations over
/// the same IKM with different `info` produce unrelated keys, and the
/// `DEVICE/ROOT` / `DEVICE/ROOT\0` pair above is the tree's own
/// acknowledgement that these labels are load-bearing. Both new labels are
/// prefixed with `fapico2/keyregion/`, a namespace no existing label starts
/// with, so neither can become a prefix-extension of another label the way
/// `DEVICE/ROOT` and `DEVICE/ROOT\0` are of each other.
pub const INDEX_KEY_INFO: &[u8] = b"fapico2/keyregion/index/v1";

/// HKDF `info` for the **payload** subkey: `b"fapico2/keyregion/payload/v1"`.
///
/// The difference from `INDEX_KEY_INFO` that matters is the fourth path
/// segment — and it must be *that* difference, not merely "a different
/// string", because the payload key's IKM is `root ‖ pin_secret` rather than
/// `root`. Two labels over two different IKMs would already be independent;
/// two labels over one IKM would not be, and that is the case the label exists
/// for. The shared `fapico2/keyregion/` prefix keeps the two adjacent in
/// review and apart on the wire.
pub const PAYLOAD_KEY_INFO: &[u8] = b"fapico2/keyregion/payload/v1";

/// Bytes in a derived region key — AES-256.
///
/// Not a new constant for its own sake: it is stated once here so the two key
/// types and the AEAD below all name the same width, and `ckey::KEY_LEN`
/// carries the same value for the same reason. Nothing here derives a key of
/// another width.
pub const KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// The AAD (US-1548)
// ---------------------------------------------------------------------------

/// Magic **and** version of the record AAD: `b"KR01"`.
///
/// Two jobs in four bytes, and both are load-bearing:
///
/// * **Version.** The AAD is authenticated data, so a layout change is not a
///   refactor — it invalidates every record already in the region. A version
///   in the magic means a future layout can be introduced beside this one
///   rather than on top of it.
/// * **Cross-AEAD separation.** This module's AEAD is AES-256-GCM, and so is
///   `store_v3`'s, whose per-entry AAD begins `"PS3F"` (`store_v3.rs:189-207`);
///   `ckey`'s PKOR AAD begins `"PKOR"` (`ckey.rs:894-926`). Without a
///   distinguishing prefix, a keyregion AAD and a store-v3 AAD could in
///   principle be byte-identical for some choice of inputs, and a record would
///   then be transplantable between the two stores under one key. The prefix
///   makes that comparison fail by construction.
pub const AAD_MAGIC: [u8; 4] = *b"KR01";

/// The record AAD's exact length in bytes: magic(4) ‖ domain(1) ‖ slot(2) ‖
/// generation(4).
///
/// Fixed, because it is an authenticated buffer built on the stack on a
/// `no_std` target with no allocator, and because a variable-length AAD is an
/// AAD whose encoding two callers can re-derive differently.
pub const AAD_LEN: usize = 11;

/// Which applet a record belongs to — the AAD's `domain` component.
///
/// **A new applet is a new variant and nothing else changes** in the layout
/// below, which is the point of pinning the tag to one byte and everything
/// else to fixed widths. Two applets in one region is the whole reason the
/// domain is in the AAD: FIDO and OATH share a payload key, so without it a
/// record sealed in an OATH slot would unseal in a FIDO slot of the same
/// generation.
///
/// The discriminants are **not** renumbered, ever. A tag is a byte in
/// authenticated data: swapping `Fido = 1` and `Oath = 2` changes nothing for
/// a fresh build and invalidates every stored record on every existing board.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum KeyDomain {
    /// FIDO2 / U2F credentials (`apps/fido`).
    Fido = 1,
    /// OATH / TOTP credentials (`apps/oath`).
    Oath = 2,
}

impl KeyDomain {
    /// The stable one-byte tag bound into the AAD.
    ///
    /// Never rename, never renumber — the same discipline as
    /// `snapshot_crypt::FieldScope::tag` (`snapshot_crypt.rs:134`), and for
    /// the same reason: this value is part of the authenticated data.
    pub fn tag(self) -> u8 {
        self as u8
    }

    /// Decode a tag read back from a stored header.
    ///
    /// `None` for a tag this build does not know, and the caller must treat
    /// that as **not this record** rather than as a default domain. A default
    /// here would be a record written by an applet this firmware does not have
    /// unsealing as though it were one it does.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(KeyDomain::Fido),
            2 => Some(KeyDomain::Oath),
            _ => None,
        }
    }
}

/// The authenticated header of one sealed record, in its one canonical byte
/// order.
///
/// **This is the single definition of the AAD's byte order in the tree**, and
/// `record.rs` has to delegate to it rather than assemble its own:
///
/// ```text
/// pub struct RecordHeader { domain: Domain, slot: Slot, generation: u32, /* … */ }
///
/// // record.rs — one line, no second encoding:
/// pub fn aad(&self) -> [u8; crypto::AAD_LEN] {
///     crypto::RecordAad::new(KeyDomain::from(self.domain), self.slot, self.generation)
///         .as_bytes()
///         .try_into()
///         .expect("RecordAad is AAD_LEN bytes by construction")
/// }
/// ```
///
/// Two builders of one AAD is a store whose records open under one of them and
/// never under the other, which is why the composition is stated as a signature
/// rather than left to be discovered. `record.rs`'s `AAD_BYTES` should then be
/// `crypto::AAD_LEN`, not an independent expression of its own.
/// `the_record_aad_is_exactly_these_eleven_bytes` in
/// `platform/tests/key_region_crypto.rs` pins the bytes.
///
/// ```text
/// offset  size  field
///      0     4  AAD_MAGIC ("KR01" — version + cross-AEAD separation)
///      4     1  domain tag        (KeyDomain::tag, u8)
///      5     2  slot index        (u16, little-endian)
///      7     4  generation        (u32, little-endian)
/// ```
///
/// The order is the order of the fields in the record header
/// (`RECORD_HEADER_BYTES = 16`, `mod.rs`), and that is not a coincidence to be
/// improved on: the header and the AAD describe the same record, so a reader
/// that walks one can read the other. Endianness is **little-endian** because
/// every scalar this tree writes to flash is little-endian — `store_v3`'s wire
/// format (`store_v3.rs:8`), `PARTITION_IMAGE_MAGIC_V3.to_le_bytes()`,
/// `ckey::build_aad`'s `u32` fields — and one rule is cheaper to hold than two.
///
/// The generation is `u32`, and it must be: `slotmap`'s per-slot high-water
/// mark is a `u32` (`slotmap.rs:267`) and its exhaustion state is `u32::MAX`,
/// so a narrower field would make the allocator's replay refusal unreachable
/// and would turn "generation 65537" into "generation 1" — the exact rollback
/// this AAD exists to catch.
///
/// **What is deliberately not bound:** the body length. GCM authenticates the
/// ciphertext, so a truncated or extended body cannot verify its stored tag,
/// and the header's own CRC32 covers the length field as a torn-write gate
/// (`mod.rs`, `RECORD_HEADER_BYTES`). Binding it here would add a fourth value
/// to an AAD whose three values are what a record's identity actually consists
/// of.
#[derive(Clone, Copy)]
pub struct RecordAad {
    buf: [u8; AAD_LEN],
}

impl RecordAad {
    /// Build the AAD for one record.
    ///
    /// Takes the three values **explicitly and separately** rather than a
    /// header type, because `record.rs` owns the header and this module owns
    /// the encoding. `Slot` is taken as the [`Slot`] type rather than a `u16`
    /// so the position/address chokepoint (`mod.rs`) applies to the AAD too: a
    /// caller cannot authenticate a record for an address it named.
    pub fn new(domain: KeyDomain, slot: Slot, generation: u32) -> Self {
        let mut buf = [0u8; AAD_LEN];
        buf[0..4].copy_from_slice(&AAD_MAGIC);
        buf[4] = domain.tag();
        buf[5..7].copy_from_slice(&slot.index().to_le_bytes());
        buf[7..11].copy_from_slice(&generation.to_le_bytes());
        RecordAad { buf }
    }

    /// The AAD bytes, for `seal_payload` / `open_payload` and their index-key
    /// twins.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The **index** key: PIN-free, derived from the OTP root alone.
///
/// Holds its key in a [`Zeroizing`] and implements `Drop`, and is deliberately
/// neither `Copy` nor `Clone` nor `Debug`:
///
/// * not `Copy` — a copy is a second buffer to forget, and `drbg_seed.rs:229`
///   is the house's reminder that "there is deliberately no named intermediate
///   that would outlive it";
/// * not `Clone` — the same argument, and a `Clone` on a key type is the first
///   step of a key that ends up in a `static`;
/// * not `Debug` — a `Debug` that prints key material is a `Debug` that puts it
///   in a log buffer (`mod.rs`, `Sealed`'s hand-written `Debug`, is the
///   precedent).
///
/// Keys are **per-operation**: derive, use, drop. Nothing in the region keeps
/// one alive between commands.
pub struct IndexKey(Zeroizing<[u8; KEY_LEN]>);

/// The **payload** key: the AES-256-GCM key that seals record bodies.
///
/// Same wrapper discipline as [`IndexKey`] — same reasons, same `Drop`.
/// Constructed only through `derive_payload_key`, the only function in the
/// tree that can produce it, and it requires a PIN-derived secret as an input.
pub struct PayloadKey(Zeroizing<[u8; KEY_LEN]>);

/// Refusal on drop, for both key types.
///
/// The zeroize is explicit **and** the buffer is a [`Zeroizing`], which
/// zeroizes again on its own drop. The redundancy is deliberate: this `Drop`
/// body is also the point at which the host test witness reads the buffer, and
/// it must read it *after* the clear to be evidence of anything. On arm there
/// is no witness and the explicit clear is the whole cost; the same body feeds
/// `testing::record_dropped_key` on host.
macro_rules! impl_key_drop {
    ($t:ident) => {
        impl Drop for $t {
            fn drop(&mut self) {
                let bytes: &mut [u8; KEY_LEN] = &mut self.0;
                bytes.zeroize();
                #[cfg(not(target_arch = "arm"))]
                testing::record_dropped_key(*self.0);
            }
        }
    };
}

impl_key_drop!(IndexKey);
impl_key_drop!(PayloadKey);

impl IndexKey {
    /// The key bytes, for the sealing path and for equality assertions.
    ///
    /// Borrowed for the caller's use and bound to `&self`, so the key cannot
    /// outlive the borrow — the lifetime half of "per-operation, not
    /// resident". `Debug` is deliberately absent, so the only way to observe
    /// these bytes is to ask for them, in code that already holds the key.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl PayloadKey {
    /// The key bytes, for the sealing path. Borrowed, never copied out.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Derivation (US-1547)
// ---------------------------------------------------------------------------

/// One HKDF-SHA256 expansion from the OTP root, with no salt.
///
/// `salt = None` rather than a domain salt: the root is already a
/// domain-separated output of `store_v3`'s `"PS3F"`-salted HKDF, and the
/// `info` label does the separation between the two subkeys. A salt here would
/// be a fourth thing to keep in step for no additional independence.
///
/// The 32-byte output is inside HKDF's `255 × 32` limit, so the expansion
/// cannot fail; the `expect` is unreachable by the same argument `ckey.rs:186`
/// and `store_v3.rs:104` give, and it is a local array, not a boot-fatal path.
fn expand_from_root(ikm: &[u8], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out).expect("32-byte HKDF output always fits");
    out
}

/// The OTP-rooted root every key-region key descends from.
///
/// `store_v3::derive_store_key(otp_key_1, chipid)` — reused, not
/// reimplemented, so the region and the secure partition answer "what does the
/// OTP row mean on this device" with one function (`store_v3.rs:98-105`). See
/// the module docs for why S7 makes that the right layer to build on.
///
/// `None` on an **all-zero OTP row** and on nothing else: a constant input
/// yields a constant root, and a constant root yields an index key any attacker
/// computes offline — the failure mode `ckey.rs:170` and `:244` refuse and
/// `drbg_seed.rs:216-223` explains. `None` is the whole failure behaviour
/// (S10): no panic, no `fatal_boot`, an empty region, USB reached.
pub fn derive_otp_root(
    otp_key_1: &[u8; KEY_LEN],
    chipid: &[u8; 8],
) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    if otp_key_1.iter().all(|&b| b == 0) {
        return None;
    }
    Some(Zeroizing::new(store_v3::derive_store_key(otp_key_1, chipid)))
}

/// The index key: **no PIN, no user presence, no PIN-derived secret.**
///
/// The signature is the proof of S1 — there is no parameter through which
/// PIN-derived material could enter. A PIN secret is absent, not ignored.
///
/// `None` only if [`derive_otp_root`] is `None`.
pub fn derive_index_key(otp_key_1: &[u8; KEY_LEN], chipid: &[u8; 8]) -> Option<IndexKey> {
    let root = derive_otp_root(otp_key_1, chipid)?;
    Some(derive_index_key_from_root(&root))
}

/// [`derive_index_key`] from an already-derived root.
///
/// The split exists so the chain is inspectable: a test can take the root,
/// derive the index key from it, and compare against the one-shot derivation —
/// proving the single HKDF step is exactly that, under the label the module
/// documents, and not something else.
pub fn derive_index_key_from_root(root: &[u8; KEY_LEN]) -> IndexKey {
    IndexKey(Zeroizing::new(expand_from_root(root, INDEX_KEY_INFO)))
}

/// The payload key: the OTP root mixed with a PIN-derived secret.
///
/// `pin_secret` is 32 bytes of **already-derived** material, not a PIN. This
/// module deliberately does not know how the caller made it: the FIDO applet
/// and the OATH applet have different PIN verifiers (`ckey.rs:577-611`), and a
/// derivation that took the raw PIN would have to pick one of them and would
/// then bind the region's security to a PIN-entropy argument it cannot check.
/// Taking the derived secret keeps the layering honest — the region is secured
/// by "something the user's PIN unlocked", and the applet is the only thing
/// entitled to decide what that is.
///
/// `ikm = root ‖ pin_secret` is the `kbase ‖ session` shape of
/// `ckey::pin_kenc2` (`ckey.rs:600-613`), for the same reason: binding the
/// device root in means a leaked PIN-gated value is still device-bound, and
/// the concatenation is length-separated by construction (both halves are
/// fixed-width), so no two inputs can be confused for one another.
pub fn derive_payload_key(
    otp_key_1: &[u8; KEY_LEN],
    chipid: &[u8; 8],
    pin_secret: &[u8; KEY_LEN],
) -> Option<PayloadKey> {
    let root = derive_otp_root(otp_key_1, chipid)?;
    Some(derive_payload_key_from_root(&root, pin_secret))
}

/// [`derive_payload_key`] from an already-derived root. The root is not a
/// substitute for the PIN secret: passing the root's own bytes as the secret
/// yields a key that is **not** the payload key, and two calls with different
/// PIN secrets never collide.
pub fn derive_payload_key_from_root(root: &[u8; KEY_LEN], pin_secret: &[u8; KEY_LEN]) -> PayloadKey {
    let mut ikm = [0u8; 2 * KEY_LEN];
    ikm[..KEY_LEN].copy_from_slice(root);
    ikm[KEY_LEN..].copy_from_slice(pin_secret);
    let key = PayloadKey(Zeroizing::new(expand_from_root(&ikm, PAYLOAD_KEY_INFO)));
    ikm.zeroize();
    key
}

// ---------------------------------------------------------------------------
// Record sealing — the enforcement half of US-1548
// ---------------------------------------------------------------------------

/// GCM nonce length — the `Aes256Gcm` standard 12 bytes, the same
/// `store_v3::V3_NONCE_LEN` and `snapshot_crypt::NONCE_LEN` the rest of the
/// tree seals under. One AEAD, one width.
pub const NONCE_LEN: usize = 12;

/// GCM authentication tag length — 16 bytes, again the tree's width
/// (`store_v3::V3_TAG_LEN`, `snapshot_crypt::TAG_LEN`).
pub const TAG_LEN: usize = 16;

/// Per-record framing overhead: `nonce(12) + tag(16)` — the ciphertext is
/// plaintext-length, because GCM is a stream cipher.
pub const RECORD_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Deterministic record nonce: `SHA-256(key ‖ SHA-256(aad ‖ pt))[..12]`.
///
/// The same mirror-image rule `store_v3::nonce_for` (`store_v3.rs:143-152`)
/// and `snapshot_crypt::field_nonce` (`snapshot_crypt.rs:236-250`) use, and
/// for their reasons:
///
/// * the same content re-seals **byte-identically**, so a record that did not
///   change is not rewritten;
/// * the nonce digests the **full plaintext and the AAD**, so no
///   `(key, nonce)` pair ever encrypts two different plaintexts — the GCM
///   nonce-reuse hazard, which is catastrophic and silent.
///
/// The alternative, a fresh TRNG draw per write, would break the first
/// property and force every unchanged record to be rewritten.
fn record_nonce(key: &[u8; KEY_LEN], aad: &[u8], pt: &[u8]) -> [u8; NONCE_LEN] {
    let mut inner = Sha256::new();
    inner.update(aad);
    inner.update(pt);
    let mut outer = Sha256::new();
    outer.update(key);
    outer.update(inner.finalize());
    let digest = outer.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest[..NONCE_LEN]);
    nonce
}

/// The seal core, over any 32-byte key.
///
/// `Aes256Gcm` from the same `aes-gcm` dependency `store_v3` uses, with the
/// same nonce and tag widths — this is **the house AEAD**, not a second one.
/// What differs from `store_v3` is only the AAD layout, and it has to: the
/// store's AAD binds an image shape (`store_v3.rs:189-207`) and cannot bind a
/// region slot. `store_v3::cipher` is private and returns
/// `SecureStoreError`, so it is not callable from here, and the alternative —
/// editing `store_v3.rs` — is not this module's file.
fn seal_with(key: &[u8; KEY_LEN], aad: &RecordAad, pt: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = pt.len().checked_add(RECORD_OVERHEAD)?;
    if out.len() < end {
        return None;
    }
    let nonce = record_nonce(key, aad.as_bytes(), pt);
    let ct = &mut out[NONCE_LEN..NONCE_LEN + pt.len()];
    ct.copy_from_slice(pt);
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let tag = cipher
        .encrypt_in_place_detached((&nonce).into(), aad.as_bytes(), ct)
        .ok()?;
    out[..NONCE_LEN].copy_from_slice(&nonce);
    out[NONCE_LEN + pt.len()..end].copy_from_slice(tag.as_slice());
    Some(end)
}

/// The open core. Fails closed on every structural failure and on any tag
/// mismatch.
///
/// **On a tag failure `out` is zeroized before returning** (`ckey.rs:533-541`,
/// Appendix A M-5). GCM decrypts in place, so `out` must already hold the
/// ciphertext when the tag is checked — which means that at the moment of
/// failure it holds **attacker-chosen bytes**. Returning those to the caller as
/// though they were a credential is the bug the house rule prevents, and the
/// zeroize is why this is not a bare `decrypt_in_place_detached`.
fn open_with(key: &[u8; KEY_LEN], aad: &RecordAad, sealed: &[u8], out: &mut [u8]) -> Option<usize> {
    let pt_len = sealed.len().checked_sub(RECORD_OVERHEAD)?;
    if out.len() < pt_len {
        return None;
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[..NONCE_LEN]);
    let ct = &sealed[NONCE_LEN..NONCE_LEN + pt_len];
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&sealed[NONCE_LEN + pt_len..]);
    out[..pt_len].copy_from_slice(ct);
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    if cipher
        .decrypt_in_place_detached(
            (&nonce).into(),
            aad.as_bytes(),
            &mut out[..pt_len],
            (&tag).into(),
        )
        .is_err()
    {
        out[..pt_len].zeroize();
        return None;
    }
    Some(pt_len)
}

/// Seal a record body under the **index** key.
///
/// It exists so the index key is not a key that can do nothing: the index is a
/// set of records like any other, authenticated by a tag, readable from a dump
/// with no PIN. `out` must hold at least `pt.len() + RECORD_OVERHEAD`; the
/// sealed length is returned.
pub fn seal_index_record(key: &IndexKey, aad: &RecordAad, pt: &[u8], out: &mut [u8]) -> Option<usize> {
    seal_with(key.as_bytes(), aad, pt, out)
}

/// Unseal an index record. `None` on any structural failure or tag mismatch,
/// **including a mismatch of domain, slot or generation** — the transplant and
/// replay refusal US-1548 is about, applied to the PIN-free half of the region.
pub fn open_index_record(
    key: &IndexKey,
    aad: &RecordAad,
    sealed: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    open_with(key.as_bytes(), aad, sealed, out)
}

/// Seal a record body under the **payload** key — the path that produces the
/// [`Sealed`](super::Sealed) `record.rs` writes to a slot.
pub fn seal_payload(key: &PayloadKey, aad: &RecordAad, pt: &[u8], out: &mut [u8]) -> Option<usize> {
    seal_with(key.as_bytes(), aad, pt, out)
}

/// Unseal a record body under the **payload** key.
///
/// A record presented with the wrong domain, the wrong slot or a stale
/// generation fails here and only here — the AAD is the mechanism, and it
/// needs no help from the record header's own CRC to do it.
pub fn open_payload(key: &PayloadKey, aad: &RecordAad, sealed: &[u8], out: &mut [u8]) -> Option<usize> {
    open_with(key.as_bytes(), aad, sealed, out)
}

// ---------------------------------------------------------------------------
// Host-only observation point for the zeroize assertion
// ---------------------------------------------------------------------------

/// Host-only hooks the device build does not have, for asserting that a key
/// really is cleared when it goes out of scope.
///
/// **Why this exists, and why it is host-only.** "The key is zeroized on drop"
/// is a claim about bytes that are, by then, in freed stack — there is no
/// sound way for a test to read them afterwards. So the key's own `Drop`
/// records what it holds, *after* clearing it, into a thread-local, and the
/// test asserts that record is all zeroes. The claim under test is exactly the
/// production claim: the same `Drop` body runs on arm, where the only
/// difference is that nobody is left to read the result.
#[cfg(not(target_arch = "arm"))]
pub mod testing {
    use core::cell::RefCell;

    std::thread_local! {
        /// Post-zeroize contents of every region key dropped on this thread,
        /// oldest first. Thread-local so the parallel test harness gives each
        /// `#[test]` its own record.
        static DROPPED: RefCell<std::vec::Vec<[u8; super::KEY_LEN]>> =
            const { RefCell::new(std::vec::Vec::new()) };
    }

    /// Called from the key types' `Drop`, after the buffer is cleared.
    pub(super) fn record_dropped_key(bytes: [u8; super::KEY_LEN]) {
        DROPPED.with(|d| d.borrow_mut().push(bytes));
    }

    /// Every key dropped on this thread since the last [`clear`], as the bytes
    /// it held **after** its own zeroize ran.
    pub fn dropped_keys() -> std::vec::Vec<[u8; super::KEY_LEN]> {
        DROPPED.with(|d| d.borrow().clone())
    }

    /// Forget the record, so one test cannot make the next one pass.
    pub fn clear() {
        DROPPED.with(|d| d.borrow_mut().clear());
    }
}