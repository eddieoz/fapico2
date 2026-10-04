//! C-firmware key hierarchy derivation (US-413 S-413-4).
//!
//! Reproduces the C firmware's key schedule bit-exactly so migration can
//! unseal C records without user input where the C design allows it:
//!
//! * C-compat root (US-918 [`derive_kbase_c`]): `kbase_c =
//!   HKDF-SHA256(salt = pico_serial_hash[32], IKM = otp_key_1[32 @ OTP row
//!   0xE90], info = "DEVICE/ROOT")` (`crypto_utils.c:34-42`; serial hash =
//!   `SHA-256(flash UID)`, `serial.c:250-271`; row read = memory-mapped
//!   `OTP_DATA_BASE + row*2`, `otp_rp2350.c:33,69-72`, software write-lock
//!   only). READ-ONLY: opens C-firmware-produced material only (see below).
//! * US-918 bound device root ([`derive_kbase`]): the same KDF shape over a
//!   salt extended with the chipid and the boot-entropy record — see the
//!   `US-918` section below.
//! * FIDO keydev (`EF_KEY_DEV 0xCC00`) unwrap per `fido.c:227-287`:
//!   32 B = `AES-256-CBC(otp_key_1, IV = 0)`; 33 B = `[0x01] ‖
//!   AES-256-CBC(kbase, IV = serial_hash[..16])`; 61 B = PIN-wrapped
//!   `[0x02|0x03] ‖ AES-256-GCM(kenc, nonce, [CBC-wrapped keydev])`.
//! * PKOR/PKOC object-container crypto per `object_crypto_provider.c`
//!   (manifest/record HKDF chains, `record_id‖generation` nonce, 55-byte
//!   AAD, AES-256-GCM or AUTHENTICATED_PUBLIC HMAC-SHA256).
//!
//! All AES-CBC IVs are 16 bytes (`IV_SIZE`, `crypto_utils.h:41`) — the
//! 32-byte `pico_serial_hash` is truncated to its first 16 bytes when used
//! as an IV. `no_std`, no heap; test vectors generated from the C formulas
//! (see `tests` module docs).
//!
//! # US-917: the CBC shapes are READ-ONLY (open-only)
//!
//! The legacy CBC wraps (zero IV / serial-hash-truncated IV) exist only to
//! **open** records produced by the C firmware during migration. New
//! records are wrapped with the US-917 AES-256-GCM format — see
//! [`wrap_aead`] / [`open_aead`] and the dispatching [`open_keydev`]. Do
//! not add a CBC encryption path. Removal condition: the CBC open path is
//! retired when the C-migration cohort ages out — no supported device can
//! still carry un-migrated C-firmware records (every field device has
//! completed its first Rust boot with `migration::MIGRATION_MARKER` set,
//! or its C data partition has been factory-reset).

//! # US-918: the bound device root (kbase)
//!
//! The C key row (OTP 0xE90) is **software write-lock only** in the C
//! design — readable from any code on the board — so the legacy two-input
//! KDF reconstructs the whole C key hierarchy from a leaked OTP row alone.
//! The Rust device root is therefore bound to more material:
//!
//! `kbase = HKDF-SHA256(ikm = otp_key_1, salt = serial_hash ‖
//! chipid.to_be_bytes() ‖ boot_entropy, info = "DEVICE/ROOT")`
//!
//! where `boot_entropy` is a 32-byte TRNG record persisted in the sealed
//! secure store (`migration::SLOT_BOOT_ENTROPY`, created at the first boot
//! persist — see `firmware/src/boot.rs::ensure_boot_entropy`). Two
//! properties follow:
//!
//! * a leaked OTP row alone is **insufficient**: the salt also needs the
//!   chipid (hardware identity) and the entropy record (inside the
//!   AEAD-sealed store, so tampering with it fails the store unseal
//!   instead of yielding a wrong root);
//! * derivation is **fail-closed**: a missing entropy record is
//!   [`CKeyError::MissingBootEntropy`], never a silent fallback to the
//!   two-input KDF. Every caller fails the operation on refusal.
//!
//! The C-compat root ([`derive_kbase_c`], the unchanged two-input KDF)
//! remains ONLY for opening C-firmware-produced material during migration
//! (keydev CBC records, C PIN verifiers, C DEK wrappers, C PKOR
//! manifests) — the C firmware pinned those seals to its own two-input
//! root, which no Rust-side change can re-key. Everything derived by THIS
//! firmware (the migration capture authenticator, the native PW1 KEK, and
//! any future root consumer) goes through the bound [`derive_kbase`].
//!
//! # Residual risk until the CryptoCell cutover (US-924)
//!
//! * The OTP row stays **readable from any code** (memory-mapped NS
//!   alias). The bound root protects Rust-derived secrets, but the
//!   C-compat material above remains reconstructable from a leaked OTP
//!   row by construction — C records cannot be re-keyed.
//! * The OTP software lock set at boot
//!   (`firmware/src/boot.rs::otp_hw_write_lock_key_row`) covers the
//!   non-secure view only (`SWLOCK.NSEC`) **and is runtime-only** — reset
//!   reloads the lock state from the OTP lock pages, so it is not a durable
//!   write-lock (D-14). A durable lock needs an irreversible SBPI lock-page
//!   burn, which is not in this tree. Read-protect
//!   (`INACCESSIBLE` / the secure-view field) is pending the CryptoCell
//!   secure-partition gating. US-924 runs the hardware verification.

use aes::Aes256;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;
/// C `pico_serial_hash` length (`serial.h:37`).
pub const SERIAL_HASH_LEN: usize = 32;
/// AES-CBC IV size (`crypto_utils.h:41`).
pub const IV_LEN: usize = 16;
/// PKOR record AAD size (`object_container.h:34`).
pub const RECORD_AAD_LEN: usize = 55;
/// Object-record auth tag size (`object_store.h:31`).
pub const RECORD_TAG_LEN: usize = 16;
/// PKOR record header size (`object_container.h:32`).
pub const RECORD_HEADER_LEN: usize = 40;
/// US-918: boot-entropy record length — 32 TRNG bytes persisted in the
/// secure store (`migration::SLOT_BOOT_ENTROPY`) and mixed into the bound
/// device root ([`derive_kbase`]).
pub const BOOT_ENTROPY_LEN: usize = 32;

/// `protection` values (`object_container.h:29-31`).
pub const PROTECTION_AUTHENTICATED_PUBLIC: u8 = 1;
pub const PROTECTION_AEAD_SECRET: u8 = 2;

/// C namespace IDs (`src/fido/object_provider.h:23-25`).
pub const NAMESPACE_FIDO: u16 = 0x0002;
pub const NAMESPACE_OATH: u16 = 0x0003;
pub const NAMESPACE_OTP: u16 = 0x0004;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CKeyError {
    /// OTP key row is all-zero: the C firmware never initialized this
    /// device (no data to migrate, abort).
    NeverBootC,
    /// GCM tag mismatch or HMAC mismatch.
    AuthFailed,
    /// Unsupported record / keydev format.
    BadFormat,
    /// Input length does not match the expected shape.
    BadLength,
    /// US-918: the boot-entropy record is absent — the bound device root
    /// refuses derivation (fail-closed; no legacy fallback).
    MissingBootEntropy,
    /// US-1003: the boot-entropy record is present and correctly sized but
    /// is **all zero** — an erased or zeroized slot. Refused by
    /// [`derive_drbg_seed`] only, and deliberately **not** by
    /// [`derive_kbase`]: a zero record is a constant *key*, which is fatal
    /// for a generator (whose whole job is to be unrepeatable) and merely
    /// degenerate for a long-lived device root. The two derivations have
    /// different security properties and this variant keeps them apart.
    DepletedBootEntropy,
    /// Output buffer too small.
    BadRange,
}

/// `SHA-256(flash UID)` — the C `pico_serial_hash` (`serial.c:250-271`;
/// 8-byte flash UID on RP2 via `pico_get_unique_board_id`).
pub fn serial_hash(flash_uid: &[u8]) -> [u8; SERIAL_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(flash_uid);
    hasher.finalize().into()
}

/// US-918 bound device root:
/// `kbase = HKDF-SHA256(ikm = otp_key_1, salt = serial_hash ‖
/// chipid.to_be_bytes() ‖ boot_entropy, info = "DEVICE/ROOT")`.
///
/// Fail-closed: an all-zero OTP row is [`CKeyError::NeverBootC`] (the C
/// firmware never initialized this device) and a missing
/// `boot_entropy` record is [`CKeyError::MissingBootEntropy`] — the
/// caller must fail the operation, never fall back to the legacy
/// two-input KDF ([`derive_kbase_c`]). See the module docs for the
/// binding rationale and the residual risk.
pub fn derive_kbase(
    otp_key_1: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
    chipid: u64,
    boot_entropy: Option<&[u8; BOOT_ENTROPY_LEN]>,
) -> Result<[u8; KEY_LEN], CKeyError> {
    if otp_key_1.iter().all(|&b| b == 0) {
        return Err(CKeyError::NeverBootC);
    }
    let Some(entropy) = boot_entropy else {
        return Err(CKeyError::MissingBootEntropy);
    };
    // Salt = serial_hash(32) ‖ chipid BE(8) ‖ boot_entropy(32) = 72 bytes.
    let mut salt = [0u8; SERIAL_HASH_LEN + core::mem::size_of::<u64>() + BOOT_ENTROPY_LEN];
    salt[..SERIAL_HASH_LEN].copy_from_slice(serial_hash);
    salt[SERIAL_HASH_LEN..SERIAL_HASH_LEN + 8].copy_from_slice(&chipid.to_be_bytes());
    salt[SERIAL_HASH_LEN + 8..].copy_from_slice(entropy);
    let hk = Hkdf::<Sha256>::new(Some(&salt), otp_key_1);
    salt.zeroize();
    let mut out = [0u8; KEY_LEN];
    hk.expand(KBASE_LABEL, &mut out)
        .map_err(|_| CKeyError::BadFormat)?;
    Ok(out)
}

/// The bound device root's HKDF info label (US-1575).
///
/// **This is not `"DEVICE/ROOT"`, and that is the point.** [`derive_kbase`] and
/// [`derive_kbase_c`] both ran the same KDF over the same IKM (`otp_key_1`)
/// with the same info label, separated only by their salts. Domain separation
/// by salt alone is not separation: a caller holding one root reaches the other
/// by deriving with the other salt, and nothing in the API or the type system
/// says which is which. It was mitigated only by a doc comment calling
/// `derive_kbase_c` "open-only" — a convention, one refactor from violation.
///
/// The C label is **immutable**: `"DEVICE/ROOT"` is what the C firmware used
/// (`crypto_utils.c:34-42`), and reproducing it bit-exactly is the entire
/// reason `derive_kbase_c` exists. So the Rust-native root moves instead.
///
/// **What this invalidates:** material already derived from the bound root on a
/// device that has booted with the old label — in practice the migration
/// authority (`migration.rs`), which is its only consumer. A device captured
/// mid-C-migration under the old root will not verify under the new one. That
/// is the price of making the two roots genuinely distinct, and it is cheaper
/// now, before there is a release tag, than after a migration cohort exists.
pub const KBASE_LABEL: &[u8] = b"DEVICE/ROOT/BOUND";

/// US-1003: the DRBG seed label — domain-separates the generator's seed
/// from every other key this device derives over the *same* input
/// material. It is the only thing standing between a leaked seed and the
/// device root (and, through it, every credential the root protects), so it
/// is as load-bearing as the salt and gets the same treatment:
/// [`derive_wrap_key`]'s `fapico2/ckey/wrap/v1`, the store v3 `"store"`,
/// and `"DEVICE/ROOT"`.
const DRBG_SEED_LABEL: &[u8] = b"DRBG/SEED";

/// US-1003: the DRBG seed —
/// `seed = HKDF-SHA256(ikm = otp_key_1, salt = serial_hash ‖
/// chipid.to_be_bytes() ‖ boot_entropy, info = "DRBG/SEED")`.
///
/// The same input material and the same fail-closed policy as
/// [`derive_kbase`], under a different label: a leaked OTP row alone is
/// still insufficient, and a missing `boot_entropy` record is still
/// [`CKeyError::MissingBootEntropy`] with no fallback to the two-input KDF.
/// (The C-compat root is not a fallback here either — the seed is not
/// derived from `derive_kbase`'s output at all, so a compromise of the root
/// does not reach the keystream.)
///
/// # Three refusals, and why the third is here
///
/// * an all-zero OTP row is [`CKeyError::NeverBootC`];
/// * a **missing** record is [`CKeyError::MissingBootEntropy`];
/// * a record that is present, correctly sized, and **all zero** is
///   [`CKeyError::DepletedBootEntropy`].
///
/// The third is not a duplicate of the second. "Absent" and "present but
/// constant" produce *the same key*, and that key is a keystream any
/// attacker can compute offline without ever touching the device — which is
/// strictly worse than having no record at all, because a missing record at
/// least refuses. The check lives here as well as in
/// [`crate::drbg_seed::FuseSeedSource`] on purpose: the source reports it as
/// its own, more specific [`crate::drbg::SeedError`], but a direct caller of
/// this function — which is `pub` — must not be able to skip the invariant
/// the prose above claims it enforces. `derive_kbase` does **not** take this
/// check: a constant *key* is catastrophic for a generator, which must never
/// repeat, and merely degenerate for a long-lived root, where the same
/// constant is already implied by a constant OTP row.
///
/// # Why the salt is zeroized
///
/// The salt holds the boot-entropy record, and the caller drops the seed the
/// moment it is used. Zeroizing the salt closes the same gap on the way out.
/// (The HKDF's internal PRK, derived from `otp_key_1`, is not under this
/// crate's control — exactly as it is not for [`derive_kbase`].)
pub fn derive_drbg_seed(
    otp_key_1: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
    chipid: u64,
    boot_entropy: Option<&[u8; BOOT_ENTROPY_LEN]>,
) -> Result<[u8; KEY_LEN], CKeyError> {
    if otp_key_1.iter().all(|&b| b == 0) {
        return Err(CKeyError::NeverBootC);
    }
    let Some(entropy) = boot_entropy else {
        return Err(CKeyError::MissingBootEntropy);
    };
    if entropy.iter().all(|&b| b == 0) {
        return Err(CKeyError::DepletedBootEntropy);
    }
    // Identical salt layout to `derive_kbase` — only `info` differs.
    let mut salt = [0u8; SERIAL_HASH_LEN + core::mem::size_of::<u64>() + BOOT_ENTROPY_LEN];
    salt[..SERIAL_HASH_LEN].copy_from_slice(serial_hash);
    salt[SERIAL_HASH_LEN..SERIAL_HASH_LEN + 8].copy_from_slice(&chipid.to_be_bytes());
    salt[SERIAL_HASH_LEN + 8..].copy_from_slice(entropy);
    let hk = Hkdf::<Sha256>::new(Some(&salt), otp_key_1);
    salt.zeroize();
    let mut out = [0u8; KEY_LEN];
    hk.expand(DRBG_SEED_LABEL, &mut out)
        .map_err(|_| CKeyError::BadFormat)?;
    Ok(out)
}

/// C-compat root — the pre-US-918 two-input KDF
/// `kbase = HKDF-SHA256(salt = serial_hash, ikm = otp_key_1,
/// info = "DEVICE/ROOT")` (`crypto_utils.c:34-42`).
///
/// **Open-only** (the CBC-shape discipline of the module docs): this is
/// the root the C firmware pinned its seals to, so it opens
/// C-firmware-produced migration material (keydev CBC records, C PIN
/// verifiers, C DEK wrappers, C PKOR manifests) and constructs host-test
/// C fixtures. Never use it for a new Rust-side derivation — new
/// consumers go through the bound [`derive_kbase`]. Aborts with
/// [`CKeyError::NeverBootC`] on an all-zero OTP row (C never
/// initialized).
pub fn derive_kbase_c(
    otp_key_1: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
) -> Result<[u8; KEY_LEN], CKeyError> {
    if otp_key_1.iter().all(|&b| b == 0) {
        return Err(CKeyError::NeverBootC);
    }
    Ok(kbase_c_unchecked(otp_key_1, serial_hash))
}

/// [`derive_kbase_c`]'s KDF with the never-initialized guard removed.
///
/// US-1030: the OATH credential seal has to be derivable on a device the C
/// firmware never ran, because that is exactly the device whose *store* is
/// empty — refusing the derivation there would brick a factory-fresh unit
/// for a key nothing is sealed under. The zero-OTP-row residual is the one
/// [`store_v3::derive_store_key`] already accepts and documents: such a row
/// is public material, so the seal key over it is public too. It is
/// harmless in the only case it can arise (no C firmware ⇒ no migrated
/// credential to protect), and the bound root is what the rest of the
/// device uses.
fn kbase_c_unchecked(
    otp_key_1: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(serial_hash), otp_key_1);
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"DEVICE/ROOT", &mut out).expect("32 okm");
    out
}

// ---------------------------------------------------------------------------
// US-1030 — the OATH credential-key seal (C's `"OATH"`-magic GCM form)
// ---------------------------------------------------------------------------
//
// The C firmware's own sealed key form (`pico-fido/src/fido/oath.c:88,193-265`):
//
// ```text
// ['O','A','T','H'][4] ‖ version 1[1] ‖ nonce[12] ‖ ciphertext ‖ GCM tag[16]
// ```
//
// with the GCM key `kenc = pin_derive_kenc2(oath_derive_key())` and the AAD
// `pico_serial_hash`. Until this section existed nothing in the Rust tree
// could produce or open that form, which is why `oath_core`'s module docs
// said the migration carried OATH keys in the clear and named the missing
// key material (the flash UID + the OTP row) as the blocker.
//
// **Why the C form and not a private one.** Two reasons, both load-bearing.
// The C firmware's own sealed records have to be readable — the migration
// copies them verbatim, and a C-produced `"OATH"` blob that this firmware
// cannot open is a credential that computes the wrong OTP code. And a
// C-readable form means a rollback to the C firmware is not a data-loss
// event, which is the whole promise of the migration.
//
// **Why the nonce is NOT C's.** C draws a fresh TRNG nonce per seal
// (`encrypt_with_aad`, `crypto_utils.c:85`). A *per-key* seal cannot afford
// that: the record is rewritten on every persist, and an RNG nonce that can
// repeat is an AEAD nonce-reuse bug. This firmware writes the nonce as a
// pure function of a **per-key monotonic generation counter**
// ([`OathSeal::nonce_for`]) instead. The record layout is byte-identical to
// C's, so `open` — which always takes the nonce from the record — reads
// both forms.

/// C `oath_secure_key_magic` (`oath.c:88`).
pub const OATH_SEAL_MAGIC: [u8; 4] = *b"OATH";
/// C `OATH_SECURE_KEY_VERSION` (`oath.c:44`).
pub const OATH_SEAL_VERSION: u8 = 1;
/// `magic(4) ‖ version(1) ‖ nonce(12)` — the C record header.
pub const OATH_SEAL_HEADER_LEN: usize = 4 + 1 + WRAP_NONCE_LEN;
/// C `OATH_SECURE_KEY_OVERHEAD` (`oath.c:45`): header + GCM tag.
pub const OATH_SEAL_OVERHEAD: usize = OATH_SEAL_HEADER_LEN + WRAP_TAG_LEN;
/// C `oath_derive_key`'s HKDF label (`oath.c:201`).
const OATH_KEY_LABEL: &[u8] = b"OATH/KEYS";
/// US-1030: the host/emulation stand-in for the OTP key row — the
/// counterpart of [`crate::usb_ident::EMULATION_CHIPID`] for the second
/// input of [`OathSeal::derive`]. Public, constant, and holds no secret:
/// the emulation secure partition holds none either.
pub const EMULATION_OTP_KEY_1: [u8; KEY_LEN] = *b"fapico2-emul-otp-key-row-v1\0\0\0\0\0";
/// US-1030: the nonce-derivation label. Domain-separated from
/// [`OATH_KEY_LABEL`], from `"PIN/ENC2"` and from every other label in this
/// file — the nonce key is a distinct secret from the AEAD key, not a
/// second use of it.
const OATH_NONCE_LABEL: &[u8] = b"OATH/SEAL-NONCE/v1";
/// `OATH_NONCE_LABEL ‖ fid BE ‖ generation BE` — the nonce KDF `info`.
const OATH_NONCE_INFO_LEN: usize = 18 + 2 + 8;

/// The OATH credential-key seal context: the C-compat GCM key, the
/// US-1030 nonce key, and the AAD.
///
/// Holds key material, so it is zeroized on drop and carries no `Debug`
/// (an accidental `{:?}` in a log line is a disclosure). It is stored
/// inside `OathApp`, which lives in a `static mut` for the life of the
/// process — the `Drop` there is a host/test convenience, not the
/// device's protection; the device's is that the value never leaves RAM.
pub struct OathSeal {
    /// `pin_derive_kenc2(oath_derive_key())` — the C GCM key.
    kenc: [u8; KEY_LEN],
    /// US-1030: `HKDF(salt = serial_hash, ikm = kbase_c,
    /// info = "OATH/SEAL-NONCE/v1")` — the per-key nonce KDF root.
    nonce_key: [u8; KEY_LEN],
    /// `pico_serial_hash` — C's AAD, and this device's seal identity.
    aad: [u8; SERIAL_HASH_LEN],
}

impl OathSeal {
    /// US-1030: the host/emulation seal context — derived from the same two
    /// public stand-ins the rest of the emulation path uses
    /// ([`crate::usb_ident::EMULATION_CHIPID`] and
    /// [`EMULATION_OTP_KEY_1`]), so an emulated device's sealed OATH keys
    /// are as reproducible as its device-id and its USB serial.
    ///
    /// Public material on purpose, and named after what it is. It exists so
    /// every host call site has to *say* it is the emulation stand-in —
    /// US-130's "wrong-but-obvious beats right-but-hidden" rule — and so no
    /// host fixture can accidentally decrypt a real device's store.
    pub fn emul() -> Self {
        Self::derive(
            &EMULATION_OTP_KEY_1,
            &crate::usb_ident::EMULATION_CHIPID.to_be_bytes(),
        )
    }

    /// Derive the seal context from the **flash UID + the OTP key row** —
    /// the two inputs the story names, and the two C's `oath_derive_key`
    /// chained over (`derive_kbase_c` over the OTP row, salted by
    /// `SHA-256(flash_uid)`).
    ///
    /// Infallible by construction: see [`kbase_c_unchecked`] for why the
    /// never-initialized guard of [`derive_kbase_c`] is deliberately not
    /// applied here.
    pub fn derive(otp_key_1: &[u8; KEY_LEN], flash_uid: &[u8]) -> Self {
        let sh = serial_hash(flash_uid);
        let kbase = kbase_c_unchecked(otp_key_1, &sh);
        // C `oath_derive_key` (`oath.c:197-203`).
        let hk = Hkdf::<Sha256>::new(Some(&sh), &kbase);
        let mut oath_key = [0u8; KEY_LEN];
        hk.expand(OATH_KEY_LABEL, &mut oath_key).expect("32 okm");
        // C `pin_derive_kenc2(oath_key)` (`crypto_utils.c:70-76`).
        let kenc = pin_kenc2(&sh, &kbase, &oath_key);
        oath_key.zeroize();
        // US-1030: the nonce KDF root, over the same inputs under its own
        // label.
        let hk = Hkdf::<Sha256>::new(Some(&sh), &kbase);
        let mut nonce_key = [0u8; KEY_LEN];
        hk.expand(OATH_NONCE_LABEL, &mut nonce_key).expect("32 okm");
        Self {
            kenc,
            nonce_key,
            aad: sh,
        }
    }

    /// US-1030: the nonce for one seal of one credential —
    /// `HKDF-Expand(prk = nonce_key, info = "OATH/SEAL-NONCE/v1" ‖ fid BE ‖
    /// generation BE, 12)`.
    ///
    /// **The nonce is a per-key monotonic counter, not a content hash.**
    /// `store_v3`'s `nonce = SHA-256(key ‖ SHA-256(entries))[..12]` is
    /// correct for a whole-image seal that is rewritten atomically and
    /// compared byte-for-byte, and wrong here for two reasons. It repeats
    /// whenever the content repeats (this record is re-sealed on every
    /// persist, and re-sealing the same key is the common case, not the
    /// exotic one), and in a per-record seal a content-derived nonce tells
    /// anyone holding two flash reads whether that credential changed in
    /// between. A monotonic generation is neither: it never repeats for a
    /// different plaintext, and it leaks nothing about content.
    ///
    /// `fid` is bound in so two credentials sealed at the same generation
    /// (one allocation pass covers the whole table) never share a nonce.
    pub fn nonce_for(&self, fid: u16, generation: u64) -> [u8; WRAP_NONCE_LEN] {
        let mut info = [0u8; OATH_NONCE_INFO_LEN];
        info[..OATH_NONCE_LABEL.len()].copy_from_slice(OATH_NONCE_LABEL);
        info[OATH_NONCE_LABEL.len()..OATH_NONCE_LABEL.len() + 2]
            .copy_from_slice(&fid.to_be_bytes());
        info[OATH_NONCE_LABEL.len() + 2..].copy_from_slice(&generation.to_be_bytes());
        let hk = Hkdf::<Sha256>::new(None, &self.nonce_key);
        let mut nonce = [0u8; WRAP_NONCE_LEN];
        hk.expand(&info, &mut nonce).expect("12 okm");
        nonce
    }

    /// Whether `blob` is in the sealed form — C's `oath_key_is_secure`
    /// predicate, byte for byte (including its strict `>` on the length: a
    /// zero-length plaintext would produce a 33-byte record that C itself
    /// would not recognize as sealed).
    pub fn is_sealed(blob: &[u8]) -> bool {
        blob.len() > OATH_SEAL_OVERHEAD
            && blob[..4] == OATH_SEAL_MAGIC
            && blob[4] == OATH_SEAL_VERSION
    }

    /// The nonce a sealed record carries — for tests and for the
    /// never-reuse assertion. `None` for a record that is not sealed.
    pub fn nonce_of(blob: &[u8]) -> Option<[u8; WRAP_NONCE_LEN]> {
        if !Self::is_sealed(blob) {
            return None;
        }
        blob[5..5 + WRAP_NONCE_LEN].try_into().ok()
    }

    /// Seal `plaintext` into `out` as a C-format `"OATH"` record at
    /// `generation`; returns the record length.
    pub fn seal(
        &self,
        fid: u16,
        generation: u64,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CKeyError> {
        let total = OATH_SEAL_OVERHEAD + plaintext.len();
        if out.len() < total {
            return Err(CKeyError::BadRange);
        }
        out[..4].copy_from_slice(&OATH_SEAL_MAGIC);
        out[4] = OATH_SEAL_VERSION;
        let nonce = self.nonce_for(fid, generation);
        out[5..5 + WRAP_NONCE_LEN].copy_from_slice(&nonce);
        let ct = &mut out[OATH_SEAL_HEADER_LEN..OATH_SEAL_HEADER_LEN + plaintext.len()];
        ct.copy_from_slice(plaintext);
        let cipher = Aes256Gcm::new_from_slice(&self.kenc).map_err(|_| CKeyError::BadFormat)?;
        let tag = cipher
            .encrypt_in_place_detached(&nonce.into(), &self.aad, ct)
            .map_err(|_| CKeyError::BadFormat)?;
        out[OATH_SEAL_HEADER_LEN + plaintext.len()..total].copy_from_slice(tag.as_slice());
        Ok(total)
    }

    /// Open a `"OATH"` record (C-produced or ours) into `out`; returns the
    /// plaintext length.
    ///
    /// **Appendix A M-5.** The plaintext is copied into `out` *before* the
    /// tag is checked — the plaintext is where it has to be for GCM to
    /// decrypt in place — so on a tag failure `out` holds attacker-chosen
    /// bytes. It is zeroized here before the error returns, which is the
    /// whole reason this is not a bare `decrypt_in_place_detached`.
    pub fn open(&self, blob: &[u8], out: &mut [u8]) -> Result<usize, CKeyError> {
        if !Self::is_sealed(blob) {
            return Err(CKeyError::BadFormat);
        }
        let payload_len = blob.len() - OATH_SEAL_OVERHEAD;
        if out.len() < payload_len {
            return Err(CKeyError::BadRange);
        }
        let nonce: &[u8; WRAP_NONCE_LEN] = blob[5..5 + WRAP_NONCE_LEN]
            .try_into()
            .map_err(|_| CKeyError::BadLength)?;
        let tag: &[u8; WRAP_TAG_LEN] = blob[blob.len() - WRAP_TAG_LEN..]
            .try_into()
            .map_err(|_| CKeyError::BadLength)?;
        out[..payload_len]
            .copy_from_slice(&blob[OATH_SEAL_HEADER_LEN..OATH_SEAL_HEADER_LEN + payload_len]);
        let cipher = Aes256Gcm::new_from_slice(&self.kenc).map_err(|_| CKeyError::BadFormat)?;
        let nonce_arr: [u8; WRAP_NONCE_LEN] = *nonce;
        let tag_arr: [u8; WRAP_TAG_LEN] = *tag;
        if cipher
            .decrypt_in_place_detached(
                (&nonce_arr).into(),
                &self.aad,
                &mut out[..payload_len],
                (&tag_arr).into(),
            )
            .is_err()
        {
            out[..payload_len].zeroize();
            return Err(CKeyError::AuthFailed);
        }
        Ok(payload_len)
    }
}

impl Clone for OathSeal {
    fn clone(&self) -> Self {
        Self {
            kenc: self.kenc,
            nonce_key: self.nonce_key,
            aad: self.aad,
        }
    }
}

impl Drop for OathSeal {
    fn drop(&mut self) {
        self.kenc.zeroize();
        self.nonce_key.zeroize();
    }
}

/// `kver = HMAC-SHA256(kbase, pin)` (`crypto_utils.c:44-49`).
pub fn derive_kver(kbase: &[u8; KEY_LEN], pin: &[u8]) -> [u8; KEY_LEN] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(kbase).expect("hmac key");
    mac.update(pin);
    mac.finalize().into_bytes().into()
}

/// `verifier = HKDF-SHA256(salt = serial_hash, IKM = kver,
/// info = "PIN/VERIFY")` (`crypto_utils.c:51-56`).
pub fn pin_verifier(serial_hash: &[u8; SERIAL_HASH_LEN], kver: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(serial_hash), kver);
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"PIN/VERIFY", &mut out).expect("32 okm");
    out
}

/// `session = HKDF-SHA256(salt = serial_hash, IKM = kver,
/// info = "PIN/TOKEN")` (`crypto_utils.c:58-63`).
pub fn pin_session(serial_hash: &[u8; SERIAL_HASH_LEN], kver: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(serial_hash), kver);
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"PIN/TOKEN", &mut out).expect("32 okm");
    out
}

/// `kenc = HKDF-SHA256(salt = serial_hash, IKM = session,
/// info = "PIN/ENC")` — PIN_KDF_V1 key (`crypto_utils.c:65-67`).
pub fn pin_kenc(serial_hash: &[u8; SERIAL_HASH_LEN], session: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(serial_hash), session);
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"PIN/ENC", &mut out).expect("32 okm");
    out
}

/// `kenc2 = HKDF-SHA256(salt = serial_hash, IKM = kbase ‖ session,
/// info = "PIN/ENC2")` — PIN_KDF_V2 key (`crypto_utils.c:69-75`).
pub fn pin_kenc2(
    serial_hash: &[u8; SERIAL_HASH_LEN],
    kbase: &[u8; KEY_LEN],
    session: &[u8; KEY_LEN],
) -> [u8; KEY_LEN] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(kbase);
    ikm[32..].copy_from_slice(session);
    let hk = Hkdf::<Sha256>::new(Some(serial_hash), &ikm);
    let mut out = [0u8; KEY_LEN];
    hk.expand(b"PIN/ENC2", &mut out).expect("32 okm");
    out
}

/// AES-256-CBC decrypt with zero-padded 16-byte IV
/// (`crypto_utils.c:233-267`; mbedtls low-level CBC, no padding).
fn aes256_cbc_decrypt(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], ct: &mut [u8]) {
    let mut dec = cbc::Decryptor::<Aes256>::new(key.into(), iv.into());
    for chunk in ct.as_chunks_mut::<16>().0 {
        dec.decrypt_block_mut(chunk.into());
    }
}

/// Public wrapper for [`gcm_unwrap_serial_aad`] (S-413-6 OpenPGP DEK flow).
pub fn gcm_unwrap_serial_aad_pub(
    kenc: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
    blob: &mut [u8],
) -> Result<(), CKeyError> {
    gcm_unwrap_serial_aad(kenc, serial_hash, blob)
}

/// Unwrap a `decrypt_with_aad` payload (`[12 B nonce | ct | 16 B tag]`,
/// AES-256-GCM, AAD = `pico_serial_hash`, `crypto_utils.c:117-148`).
/// `version` selects PIN_KDF_V1/V2 kenc derivation.
fn gcm_unwrap_serial_aad(
    kenc: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
    blob: &mut [u8],
) -> Result<(), CKeyError> {
    if blob.len() < 12 + 16 {
        return Err(CKeyError::BadLength);
    }
    let (nonce, rest) = blob.split_at_mut(12);
    let (ct, tag) = rest.split_at_mut(rest.len() - 16);
    let nonce: &[u8; 12] = nonce.first_chunk::<12>().ok_or(CKeyError::BadLength)?;
    let tag: &[u8; 16] = tag.first_chunk::<16>().ok_or(CKeyError::BadLength)?;
    let cipher = Aes256Gcm::new_from_slice(kenc).map_err(|_| CKeyError::BadFormat)?;
    cipher
        .decrypt_in_place_detached(nonce.into(), serial_hash, ct, tag.into())
        .map_err(|_| CKeyError::AuthFailed)
    // ct now holds the plaintext in place (caller reads blob[12..12+len]).
}

/// Result of a keydev unwrap attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeydevStatus {
    /// Unwrapped 32-byte keydev.
    Unwrapped([u8; KEY_LEN]),
    /// 61-byte PIN-wrapped record — needs the user PIN (S-413-6); also
    /// returned for a wrong PIN (constant behavior, no lockout on our side;
    /// the C partition is read-only so retry counters are untouched).
    NeedsPin,
    /// Vendor-wrapped keydev material with no device-side unwrap path.
    NotMigratable,
}

/// Unwrap a C `EF_KEY_DEV 0xCC00` record payload into the 32-byte keydev
/// (`fido.c:227-287`). `pin` (raw bytes) is only consulted for the 61-byte
/// PIN-wrapped format.
///
/// US-917: **READ-ONLY compat** — this function opens legacy C records and
/// must never gain a wrap counterpart; new records use [`wrap_aead`]. See
/// the module docs for the removal condition (migration cohort aged out).
pub fn unwrap_keydev(
    record: &[u8],
    otp_key_1: &[u8; KEY_LEN],
    kbase: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
    pin: Option<&[u8]>,
) -> Result<KeydevStatus, CKeyError> {
    let iv_serial: [u8; IV_LEN] = serial_hash[..IV_LEN].try_into().unwrap();
    match record.len() {
        32 => {
            let mut key: [u8; KEY_LEN] = record.try_into().map_err(|_| CKeyError::BadLength)?;
            aes256_cbc_decrypt(otp_key_1, &[0u8; IV_LEN], &mut key);
            Ok(KeydevStatus::Unwrapped(key))
        }
        33 => {
            if record[0] != 0x01 {
                return Err(CKeyError::BadFormat);
            }
            let mut key: [u8; KEY_LEN] = record[1..].try_into().unwrap();
            aes256_cbc_decrypt(kbase, &iv_serial, &mut key);
            Ok(KeydevStatus::Unwrapped(key))
        }
        61 => {
            let format = record[0];
            if format != 0x02 && format != 0x03 {
                return Err(CKeyError::BadFormat);
            }
            let Some(pin) = pin else {
                return Ok(KeydevStatus::NeedsPin);
            };
            let kver = derive_kver(kbase, pin);
            let session = pin_session(serial_hash, &kver);
            let kenc = if format == 0x03 {
                pin_kenc2(serial_hash, kbase, &session)
            } else {
                pin_kenc(serial_hash, &session)
            };
            // [format][12 nonce | 32 ct | 16 tag] — GCM unwraps to the
            // CBC(kbase)-wrapped keydev, then the CBC layer unwraps it.
            let mut blob = [0u8; 60];
            blob.copy_from_slice(&record[1..]);
            // Wrong PIN: report NeedsPin (per the S-413-6 contract:
            // constant NEEDS_PASSPHRASE behavior, no counter updates — the
            // C partition is read-only for us).
            if gcm_unwrap_serial_aad(&kenc, serial_hash, &mut blob).is_err() {
                return Ok(KeydevStatus::NeedsPin);
            }
            let mut key: [u8; KEY_LEN] = blob[12..44].try_into().unwrap();
            aes256_cbc_decrypt(kbase, &iv_serial, &mut key);
            Ok(KeydevStatus::Unwrapped(key))
        }
        _ => Err(CKeyError::BadLength),
    }
}

// ---------------------------------------------------------------------------
// US-917: AEAD record format for wraps created by this firmware
// ---------------------------------------------------------------------------

/// First byte of a US-917 AEAD record. The legacy C formats use `0x01`
/// (33-byte keydev) and `0x02 | 0x03` (61-byte PIN-wrapped keydev); the
/// 32-byte legacy keydev record is untagged and length-dispatched, so a
/// length-61 AEAD record (tag byte + keydev payload) cannot collide.
pub const WRAP_TAG: u8 = 0x04;

/// GCM nonce length for the AEAD record — one fresh random nonce per
/// record (US-380: drawn from the platform TRNG at the call sites).
pub const WRAP_NONCE_LEN: usize = 12;

/// GCM auth tag length for the AEAD record.
pub const WRAP_TAG_LEN: usize = 16;

/// AEAD record header: format tag + per-record nonce.
pub const WRAP_HEADER_LEN: usize = 1 + WRAP_NONCE_LEN;

/// Total AEAD record overhead: tag byte + nonce + GCM tag.
pub const WRAP_OVERHEAD: usize = WRAP_HEADER_LEN + WRAP_TAG_LEN;

/// US-917 wrap-key KDF label — domain-separates the AEAD record key from
/// both the C `kbase` chain (`"DEVICE/ROOT"`) and the store v3 key
/// (`"store"`), over the same input material the CBC path used.
const WRAP_KEY_LABEL: &[u8] = b"fapico2/ckey/wrap/v1";

/// US-917 AEAD record key: `HKDF-SHA256(salt = serial_hash,
/// ikm = otp_key_1, info = "fapico2/ckey/wrap/v1")` — the same KDF shape
/// as the store v3 seal key ([`crate::store_v3::derive_store_key`]) and
/// the same input material the CBC path used (the OTP key row is the
/// 32-byte record's CBC key; the serial hash feeds the 33-byte record's
/// IV and the `kbase` chain), under a distinct label.
pub fn derive_wrap_key(
    otp_key_1: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(serial_hash), otp_key_1);
    let mut out = [0u8; KEY_LEN];
    hk.expand(WRAP_KEY_LABEL, &mut out).expect("32 okm");
    out
}

/// Wrap a plaintext into the US-917 AEAD record format:
/// `[WRAP_TAG ‖ nonce(12) ‖ ciphertext ‖ GCM tag(16)]` written to `out`
/// (≥ [`WRAP_OVERHEAD`] + `plaintext.len()`); returns the record length.
///
/// The record key (`wrap_key`, from [`derive_wrap_key`]) and the
/// caller-supplied fresh `nonce` are bound together with `aad` — the
/// record's identity bytes: at the migration call sites this is the
/// destination store slot name (e.g. `migration::SLOT_OPENPGP_DEK`), so a
/// record transplanted to another slot or device fails to open. Callers
/// that carry no identity use the format tag constant itself. `no_std`,
/// no heap; the GCM tag failure modes are the store v3 discipline (the
/// AEAD record must fail closed — [`open_aead`] errors, never returns
/// garbage).
pub fn wrap_aead(
    wrap_key: &[u8; KEY_LEN],
    nonce: &[u8; WRAP_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, CKeyError> {
    let total = WRAP_OVERHEAD + plaintext.len();
    if out.len() < total {
        return Err(CKeyError::BadRange);
    }
    out[0] = WRAP_TAG;
    out[1..1 + WRAP_NONCE_LEN].copy_from_slice(nonce);
    let ct = &mut out[WRAP_HEADER_LEN..WRAP_HEADER_LEN + plaintext.len()];
    ct.copy_from_slice(plaintext);
    let cipher = Aes256Gcm::new_from_slice(wrap_key).map_err(|_| CKeyError::BadFormat)?;
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), aad, ct)
        .map_err(|_| CKeyError::BadFormat)?;
    out[WRAP_HEADER_LEN + plaintext.len()..total].copy_from_slice(tag.as_slice());
    Ok(total)
}

/// Open a US-917 AEAD record ([`wrap_aead`] output) into `out`; returns
/// the plaintext length. Fail-closed: a missing format tag is
/// [`CKeyError::BadFormat`] (legacy records never route here), a
/// truncated record [`CKeyError::BadLength`], and a GCM tag mismatch —
/// wrong key, wrong AAD, tampered ciphertext, or a zeroed/stale nonce —
/// [`CKeyError::AuthFailed`] with the output buffer zeroized.
pub fn open_aead(
    record: &[u8],
    wrap_key: &[u8; KEY_LEN],
    aad: &[u8],
    out: &mut [u8],
) -> Result<usize, CKeyError> {
    if record.len() < WRAP_OVERHEAD {
        return Err(CKeyError::BadLength);
    }
    if record[0] != WRAP_TAG {
        return Err(CKeyError::BadFormat);
    }
    let payload_len = record.len() - WRAP_OVERHEAD;
    if out.len() < payload_len {
        return Err(CKeyError::BadRange);
    }
    let mut nonce = [0u8; WRAP_NONCE_LEN];
    nonce.copy_from_slice(&record[1..1 + WRAP_NONCE_LEN]);
    let mut tag = [0u8; WRAP_TAG_LEN];
    tag.copy_from_slice(&record[record.len() - WRAP_TAG_LEN..]);
    out[..payload_len].copy_from_slice(&record[WRAP_HEADER_LEN..WRAP_HEADER_LEN + payload_len]);
    let cipher = Aes256Gcm::new_from_slice(wrap_key).map_err(|_| CKeyError::BadFormat)?;
    if cipher
        .decrypt_in_place_detached(&nonce.into(), aad, &mut out[..payload_len], &tag.into())
        .is_err()
    {
        out.zeroize();
        return Err(CKeyError::AuthFailed);
    }
    Ok(payload_len)
}

/// Open a keydev record in either format (US-917 dispatch): a 61-byte
/// record carrying the [`WRAP_TAG`] opens through the AEAD path (key =
/// [`derive_wrap_key`], AAD = the caller's record identity, plaintext =
/// the 32-byte keydev); every other shape routes to the READ-ONLY legacy
/// CBC unwrap ([`unwrap_keydev`]) — the C-migration compat path.
pub fn open_keydev(
    record: &[u8],
    otp_key_1: &[u8; KEY_LEN],
    kbase: &[u8; KEY_LEN],
    serial_hash: &[u8; SERIAL_HASH_LEN],
    pin: Option<&[u8]>,
    aad: &[u8],
) -> Result<KeydevStatus, CKeyError> {
    if record.len() == WRAP_OVERHEAD + KEY_LEN && record[0] == WRAP_TAG {
        let wrap_key = derive_wrap_key(otp_key_1, serial_hash);
        let mut key = [0u8; KEY_LEN];
        open_aead(record, &wrap_key, aad, &mut key)?;
        return Ok(KeydevStatus::Unwrapped(key));
    }
    // US-917: legacy CBC shapes — open-only compat (see module docs).
    unwrap_keydev(record, otp_key_1, kbase, serial_hash, pin)
}

/// The identity fields of a PKOR record header (40 bytes, big-endian,
/// `object_container.c:357-377`) needed to rebuild the record's AAD, nonce
/// and keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordIdentity {
    pub version: u8,
    pub protection: u8,
    pub record_id: u64,
    pub stored_size: u32,
    pub logical_size: u32,
    pub generation: u32,
    pub namespace_id: u16,
    pub container_kind: u16,
    pub container_id: u32,
    pub object_type: u16,
    pub object_tag: u16,
    pub policy_id: u16,
    pub policy_hash: [u8; 16],
    pub key_domain: u8,
    pub flags: u16,
}

/// Build the 55-byte record AAD
/// (`object_container.c:420-459`): `"PKOR" | version | ns u16 | kind u16 |
/// container_id u32 | type u16 | tag u16 | generation u32 | logical_size
/// u32 | policy_id u16 | policy_hash 16 B | key_domain | protection |
/// flags u16 | record_id u64`, all big-endian.
pub fn build_aad(id: &RecordIdentity) -> [u8; RECORD_AAD_LEN] {
    let mut aad = [0u8; RECORD_AAD_LEN];
    let mut o = 0;
    let be16 = |v: u16| v.to_be_bytes();
    let be32 = |v: u32| v.to_be_bytes();
    let be64 = |v: u64| v.to_be_bytes();
    aad[o..o + 4].copy_from_slice(b"PKOR");
    o += 4;
    aad[o] = id.version;
    o += 1;
    aad[o..o + 2].copy_from_slice(&be16(id.namespace_id));
    o += 2;
    aad[o..o + 2].copy_from_slice(&be16(id.container_kind));
    o += 2;
    aad[o..o + 4].copy_from_slice(&be32(id.container_id));
    o += 4;
    aad[o..o + 2].copy_from_slice(&be16(id.object_type));
    o += 2;
    aad[o..o + 2].copy_from_slice(&be16(id.object_tag));
    o += 2;
    aad[o..o + 4].copy_from_slice(&be32(id.generation));
    o += 4;
    aad[o..o + 4].copy_from_slice(&be32(id.logical_size));
    o += 4;
    aad[o..o + 2].copy_from_slice(&be16(id.policy_id));
    o += 2;
    aad[o..o + 16].copy_from_slice(&id.policy_hash);
    o += 16;
    aad[o] = id.key_domain;
    o += 1;
    aad[o] = id.protection;
    o += 1;
    aad[o..o + 2].copy_from_slice(&be16(id.flags));
    o += 2;
    aad[o..o + 8].copy_from_slice(&be64(id.record_id));
    aad
}

/// 12-byte record nonce: `record_id u64 BE ‖ generation u32 BE`
/// (`object_container.c:373-375`, cross-checked
/// `object_crypto_provider.c:132`).
pub fn record_nonce(record_id: u64, generation: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&record_id.to_be_bytes());
    n[8..].copy_from_slice(&generation.to_be_bytes());
    n
}

/// Manifest key: `HKDF-SHA256(IKM = root, salt = empty,
/// info = ns u16 BE ‖ "PKOC/manifest/v1")` (`object_crypto_provider.c:63-76`).
pub fn derive_manifest_key(root: &[u8; KEY_LEN], namespace_id: u16) -> [u8; KEY_LEN] {
    const MANIFEST_LABEL: &[u8] = b"PKOC/manifest/v1"; // 16 bytes
    let mut info = [0u8; 2 + MANIFEST_LABEL.len()];
    info[..2].copy_from_slice(&namespace_id.to_be_bytes());
    info[2..].copy_from_slice(MANIFEST_LABEL);
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut out = [0u8; KEY_LEN];
    hk.expand(&info, &mut out).expect("32 okm");
    out
}

/// Record key: `HKDF(root → domain key with info = ns u16 BE ‖ key_domain ‖
/// "PKOC/domain/v1") → HKDF(info = "PKOC/object/v1" ‖ AAD[55])`
/// (`object_crypto_provider.c:78-102`).
pub fn derive_record_key(
    root: &[u8; KEY_LEN],
    namespace_id: u16,
    key_domain: u8,
    aad: &[u8; RECORD_AAD_LEN],
) -> [u8; KEY_LEN] {
    const DOMAIN_LABEL: &[u8] = b"PKOC/domain/v1"; // 14 bytes
    let mut domain_info = [0u8; 2 + 1 + DOMAIN_LABEL.len()];
    domain_info[..2].copy_from_slice(&namespace_id.to_be_bytes());
    domain_info[2] = key_domain;
    domain_info[3..].copy_from_slice(DOMAIN_LABEL);
    let hk_domain = Hkdf::<Sha256>::new(None, root);
    let mut domain_key = [0u8; KEY_LEN];
    hk_domain
        .expand(&domain_info, &mut domain_key)
        .expect("32 okm");

    const KEY_LABEL: &[u8] = b"PKOC/object/v1"; // 14 bytes
    let mut object_info = [0u8; KEY_LABEL.len() + RECORD_AAD_LEN];
    object_info[..KEY_LABEL.len()].copy_from_slice(KEY_LABEL);
    object_info[KEY_LABEL.len()..].copy_from_slice(aad);
    let hk_object = Hkdf::<Sha256>::new(None, &domain_key);
    let mut out = [0u8; KEY_LEN];
    hk_object.expand(&object_info, &mut out).expect("32 okm");
    out
}

/// Unseal a PKOR record payload into `out` (≥ `stored.len()` bytes).
/// `protection == AUTHENTICATED_PUBLIC`: plaintext is stored in the clear,
/// tag = truncated-16 `HMAC-SHA256(key, aad ‖ nonce ‖ stored)`
/// (`object_crypto_provider.c:143-169`); otherwise AES-256-GCM
/// (`nonce = record_id‖generation`, AAD = 55 B). Constant-time tag compare.
pub fn unseal_record(
    root: &[u8; KEY_LEN],
    namespace_id: u16,
    id: &RecordIdentity,
    stored: &[u8],
    tag: &[u8; RECORD_TAG_LEN],
    out: &mut [u8],
) -> Result<usize, CKeyError> {
    let aad = build_aad(id);
    let key = derive_record_key(root, namespace_id, id.key_domain, &aad);
    let nonce = record_nonce(id.record_id, id.generation);
    if out.len() < stored.len() {
        return Err(CKeyError::BadRange);
    }
    if id.protection == PROTECTION_AUTHENTICATED_PUBLIC {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&key).map_err(|_| CKeyError::BadFormat)?;
        mac.update(&aad);
        mac.update(&nonce);
        mac.update(stored);
        let full = mac.finalize().into_bytes();
        let mut diff = 0u8;
        for i in 0..RECORD_TAG_LEN {
            diff |= full[i] ^ tag[i];
        }
        if diff != 0 {
            return Err(CKeyError::AuthFailed);
        }
        out[..stored.len()].copy_from_slice(stored);
        Ok(stored.len())
    } else {
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CKeyError::BadFormat)?;
        out[..stored.len()].copy_from_slice(stored);
        cipher
            .decrypt_in_place_detached(&nonce.into(), &aad, &mut out[..stored.len()], tag.into())
            .map_err(|_| CKeyError::AuthFailed)?;
        Ok(stored.len())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Known-answer vectors generated from the C formulas with an
    /// independent implementation (Python hashlib/cryptography):
    /// HKDF = RFC 5869 (mbedtls-compatible), CBC IV = first 16 bytes of the
    /// serial hash (IV_SIZE, crypto_utils.h:41), GCM AAD = full 32-byte
    /// serial hash for keydev records, 55-byte record AAD for PKOR.
    mod vecs {
        pub const UID_HEX: &str = "0102030405060708";
        pub const SERIAL_HASH: &str =
            "66840dda154e8a113c31dd0ad32f7f3a366a80e8136979d8f5a101d3d29d6f72";
        pub const OTP_KEY_1: &str =
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
        pub const KBASE: &str = "c6f8593f4c62c649971024cfd94d6c2babbbf63120d9d9410766698b69fcc352";
        pub const KEYDEV_PLAIN: &str =
            "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";
        pub const KD32_CT: &str =
            "eeb22a772d3c338cfc3632063b877061e8e096a247d4ed6a729259e7d6857eec";
        pub const KD33: &str = "01a0385479d6e53f7e01f26be6909296779002a409ae67450d7b9340bcf846e2f9";
        pub const PIN: &str = "123456";
        pub const KVER: &str = "e31f7d45da58dfc72e90070fd06100ae0d83d27f3059009ee0f0bab84437a328";
        pub const VERIFIER: &str =
            "d70f14079f8d50d4606a547bf339966fc82ebb1ec702d23925f73a399eda60fe";
        pub const SESSION: &str =
            "56e527e90ff673f37e4f5709afc05f753d3c42ddf6ae5e22ecd96836cd791f89";
        pub const KENC1: &str = "50670afecb4799977b6192fd7b8f618027f9f08bce2c90c9e40eeedaf7f23b4c";
        pub const KENC2: &str = "8a20805a5c20356b577afe6370ef6c9bbfdc431b15335d41d06ae0d3ea6dc1de";
        pub const KD61: &str =
            "02505152535455565758595a5bfb1a04be0af704eac566d0ca8675a75949d584b8779399972bcc27a3b906d1d672203288b3aaa3f9bac2bf0e1534ba63";
        pub const AAD_GCM: &str =
            "504b4f52010002000100000007000a000b0000000500000020000000000000000000000000000000000000000200001122334455667788";
        pub const RECORD_CT: &str =
            "937cfd70a9190e4dc0e8c2b2d4c20dbc980a9b26cbacba121bac682dbe18767a";
        pub const RECORD_TAG: &str = "7042ef39ff4fd48260eb2bc238a6f2e3";
        pub const AAD_PUB: &str =
            "504b4f52010002000100000007000a000b0000000500000020000000000000000000000000000000000000000100001122334455667788";
        pub const RECORD_PT: &str =
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        pub const MANIFEST_KEY: &str =
            "61a917c463df6f02c78bdb796e1f33d4ee01c69139e23a239610b8c97e21977e";
        pub const HMAC_TAG: &str = "6f129d96766dd88133af93edca901449";
        pub const RID: u64 = 0x1122334455667788;
        pub const GEN: u32 = 5;
        pub const NS: u16 = 0x0002;
    }

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixture_keys() -> ([u8; KEY_LEN], [u8; KEY_LEN], [u8; SERIAL_HASH_LEN]) {
        let otp: [u8; KEY_LEN] = h(vecs::OTP_KEY_1).try_into().unwrap();
        let sh: [u8; SERIAL_HASH_LEN] = h(vecs::SERIAL_HASH).try_into().unwrap();
        // The C KATs pin the C firmware's two-input root — the compat path.
        let kbase = derive_kbase_c(&otp, &sh).unwrap();
        (otp, kbase, sh)
    }

    #[test]
    fn serial_hash_vector() {
        let sh = serial_hash(&h(vecs::UID_HEX));
        assert_eq!(sh.as_slice(), h(vecs::SERIAL_HASH).as_slice());
    }

    #[test]
    fn kbase_vector() {
        let (_, kbase, _) = fixture_keys();
        assert_eq!(kbase.as_slice(), h(vecs::KBASE).as_slice());
    }

    #[test]
    fn kbase_never_boot_c_on_zero_otp_row() {
        let zero = [0u8; KEY_LEN];
        let sh: [u8; SERIAL_HASH_LEN] = h(vecs::SERIAL_HASH).try_into().unwrap();
        assert_eq!(derive_kbase_c(&zero, &sh), Err(CKeyError::NeverBootC));
    }

    /// US-918: the bound root refuses without the entropy record (no
    /// legacy fallback) and matches an independent HKDF for a fixed input.
    #[test]
    fn kbase_bound_refuses_without_entropy_and_matches_vector() {
        let otp: [u8; KEY_LEN] = h(vecs::OTP_KEY_1).try_into().unwrap();
        let sh: [u8; SERIAL_HASH_LEN] = h(vecs::SERIAL_HASH).try_into().unwrap();
        assert_eq!(
            derive_kbase(&otp, &sh, 0x0102_0304_0506_0708, None),
            Err(CKeyError::MissingBootEntropy)
        );
        // KAT generated with an independent HKDF-SHA256 (Python hmac):
        // salt = serial_hash ‖ chipid BE ‖ 32 × 0xA5.
        //
        // US-1575 changed the vector with the label: the bound root's info is
        // now "DEVICE/ROOT/BOUND" (see KBASE_LABEL). The same generator still
        // reproduces 6bcd…60f4 under the old label, so this remains a check on
        // the derivation rather than on the code's current output.
        let entropy = [0xA5u8; BOOT_ENTROPY_LEN];
        let kbase = derive_kbase(&otp, &sh, 0x0102_0304_0506_0708, Some(&entropy)).unwrap();
        assert_eq!(
            kbase.as_slice(),
            h("83651163da62972b5ba9f53f49567366776e35ab5ba87c217c56668fd019fff8").as_slice()
        );
    }

    #[test]
    fn pin_chain_vectors() {
        let (_, kbase, sh) = fixture_keys();
        let kver = derive_kver(&kbase, vecs::PIN.as_bytes());
        assert_eq!(kver.as_slice(), h(vecs::KVER).as_slice());
        assert_eq!(
            pin_verifier(&sh, &kver).as_slice(),
            h(vecs::VERIFIER).as_slice()
        );
        assert_eq!(
            pin_session(&sh, &kver).as_slice(),
            h(vecs::SESSION).as_slice()
        );
        let session: [u8; KEY_LEN] = h(vecs::SESSION).try_into().unwrap();
        assert_eq!(
            pin_kenc(&sh, &session).as_slice(),
            h(vecs::KENC1).as_slice()
        );
        assert_eq!(
            pin_kenc2(&sh, &kbase, &session).as_slice(),
            h(vecs::KENC2).as_slice()
        );
    }

    #[test]
    fn keydev_32b_unwrap_vector() {
        let (otp, _, _) = fixture_keys();
        let ct: [u8; 32] = h(vecs::KD32_CT).try_into().unwrap();
        assert_eq!(
            unwrap_keydev(&ct, &otp, &[0; KEY_LEN], &[0; SERIAL_HASH_LEN], None).unwrap(),
            KeydevStatus::Unwrapped(h(vecs::KEYDEV_PLAIN).try_into().unwrap())
        );
    }

    #[test]
    fn keydev_33b_unwrap_vector() {
        let (_, kbase, sh) = fixture_keys();
        let rec = h(vecs::KD33);
        assert_eq!(
            unwrap_keydev(&rec, &[0; KEY_LEN], &kbase, &sh, None).unwrap(),
            KeydevStatus::Unwrapped(h(vecs::KEYDEV_PLAIN).try_into().unwrap())
        );
    }

    #[test]
    fn keydev_61b_pin_wrapped_flow() {
        let (_, kbase, sh) = fixture_keys();
        let rec = h(vecs::KD61);
        // No PIN yet: NeedsPin (S-413-6 will supply it).
        assert_eq!(
            unwrap_keydev(&rec, &[0; KEY_LEN], &kbase, &sh, None).unwrap(),
            KeydevStatus::NeedsPin
        );
        // Correct PIN: unwraps to the keydev.
        assert_eq!(
            unwrap_keydev(&rec, &[0; KEY_LEN], &kbase, &sh, Some(vecs::PIN.as_bytes())).unwrap(),
            KeydevStatus::Unwrapped(h(vecs::KEYDEV_PLAIN).try_into().unwrap())
        );
        // Wrong PIN: NeedsPin again (no counter update — C files read-only).
        assert_eq!(
            unwrap_keydev(&rec, &[0; KEY_LEN], &kbase, &sh, Some(b"999999")).unwrap(),
            KeydevStatus::NeedsPin
        );
    }

    #[test]
    fn keydev_bad_lengths_rejected() {
        let (_, kbase, sh) = fixture_keys();
        assert_eq!(
            unwrap_keydev(&[0u8; 40], &[0; KEY_LEN], &kbase, &sh, None),
            Err(CKeyError::BadLength)
        );
    }

    fn record_identity(protection: u8) -> RecordIdentity {
        RecordIdentity {
            version: 1,
            protection,
            record_id: vecs::RID,
            stored_size: 32,
            logical_size: 32,
            generation: vecs::GEN,
            namespace_id: vecs::NS,
            container_kind: 1,
            container_id: 7,
            object_type: 10,
            object_tag: 11,
            policy_id: 0,
            policy_hash: [0u8; 16],
            key_domain: 0,
            flags: 0,
        }
    }

    #[test]
    fn aad_and_nonce_vectors() {
        let aad_gcm = build_aad(&record_identity(PROTECTION_AEAD_SECRET));
        assert_eq!(aad_gcm.len(), 55);
        assert_eq!(aad_gcm.as_slice(), h(vecs::AAD_GCM).as_slice());
        let aad_pub = build_aad(&record_identity(PROTECTION_AUTHENTICATED_PUBLIC));
        assert_eq!(aad_pub.as_slice(), h(vecs::AAD_PUB).as_slice());
        let nonce = record_nonce(vecs::RID, vecs::GEN);
        assert_eq!(&nonce[..8], &vecs::RID.to_be_bytes());
        assert_eq!(&nonce[8..], &vecs::GEN.to_be_bytes());
    }

    #[test]
    fn record_key_and_manifest_key_vectors() {
        let (_, kbase, _) = fixture_keys();
        let _rk = derive_record_key(
            &kbase,
            vecs::NS,
            0,
            &build_aad(&record_identity(PROTECTION_AEAD_SECRET)),
        );
        // The record key is AAD-bound; the AEAD_SECRET vector pins the chain.
        let ct = h(vecs::RECORD_CT);
        let tag: [u8; RECORD_TAG_LEN] = h(vecs::RECORD_TAG).try_into().unwrap();
        let mut out = [0u8; 64];
        let n = unseal_record(
            &kbase,
            vecs::NS,
            &record_identity(PROTECTION_AEAD_SECRET),
            &ct,
            &tag,
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 32);
        assert_eq!(&out[..32], h(vecs::RECORD_PT).as_slice());
        let mk = derive_manifest_key(&kbase, vecs::NS);
        assert_eq!(mk.as_slice(), h(vecs::MANIFEST_KEY).as_slice());
    }

    #[test]
    fn unseal_record_gcm_vector() {
        let (_, kbase, _) = fixture_keys();
        let id = record_identity(PROTECTION_AEAD_SECRET);
        let ct = h(vecs::RECORD_CT);
        let tag: [u8; RECORD_TAG_LEN] = h(vecs::RECORD_TAG).try_into().unwrap();
        let mut out = [0u8; 64];
        let n = unseal_record(&kbase, vecs::NS, &id, &ct, &tag, &mut out).unwrap();
        assert_eq!(n, 32);
        assert_eq!(&out[..32], h(vecs::RECORD_PT).as_slice());
    }

    #[test]
    fn unseal_record_authenticated_public_hmac_vector() {
        let (_, kbase, _) = fixture_keys();
        let id = record_identity(PROTECTION_AUTHENTICATED_PUBLIC);
        let pt = h(vecs::RECORD_PT);
        let tag: [u8; RECORD_TAG_LEN] = h(vecs::HMAC_TAG).try_into().unwrap();
        let mut out = [0u8; 64];
        let n = unseal_record(&kbase, vecs::NS, &id, &pt, &tag, &mut out).unwrap();
        assert_eq!(n, 32);
        assert_eq!(&out[..32], pt.as_slice());
    }

    #[test]
    fn unseal_record_wrong_key_fails() {
        let (_, kbase, _) = fixture_keys();
        let id = record_identity(PROTECTION_AEAD_SECRET);
        let ct = h(vecs::RECORD_CT);
        let tag: [u8; RECORD_TAG_LEN] = h(vecs::RECORD_TAG).try_into().unwrap();
        let mut wrong_root = kbase;
        wrong_root[0] ^= 0x01;
        let mut out = [0u8; 64];
        assert_eq!(
            unseal_record(&wrong_root, vecs::NS, &id, &ct, &tag, &mut out),
            Err(CKeyError::AuthFailed)
        );
    }
}
