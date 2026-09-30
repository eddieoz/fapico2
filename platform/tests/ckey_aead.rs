//! US-917 (SEC-HARDENING): AEAD records for the legacy C-migration wraps.
//!
//! The C firmware wrapped migrated keydev records with AES-256-CBC under a
//! zero IV (32-byte records) or the public serial-hash prefix as IV
//! (33-byte records) — no integrity, no nonce freshness. US-917 introduces
//! a tagged AES-256-GCM record format for anything the Rust side wraps
//! from now on, while the CBC shapes stay **open-only** (compat with
//! records migrated off a C firmware device).
//!
//! The properties pinned here:
//!
//! * **Compat** — legacy CBC keydev records still open through the
//!   dispatching [`fapico2_platform::ckey::open_keydev`].
//! * **Format separation** — an AEAD record must NOT open through the
//!   legacy CBC path (including the truncated/zero-IV shapes) and a
//!   legacy record must NOT open through the AEAD path: both fail closed.
//! * **Round-trip** — wrap → open preserves the plaintext; a per-record
//!   random nonce (platform `Trng`) is embedded and honored.
//! * **Fail-closed AEAD** — a bad tag, a wrong AAD, a wrong key, or a
//!   truncated record is an error, never garbage plaintext.

use fapico2_platform::ckey::{
    self, open_aead, open_keydev, unwrap_keydev, wrap_aead, CKeyError, KeydevStatus, KEY_LEN,
    SERIAL_HASH_LEN, WRAP_HEADER_LEN, WRAP_NONCE_LEN, WRAP_OVERHEAD, WRAP_TAG, WRAP_TAG_LEN,
};
use fapico2_platform::trng::HostTrng;

/// KAT material from the ckey unit tests (S-413-4 vectors): UID
/// 0102..0708, its serial hash, the OTP row, and the 33-byte keydev
/// record wrapping [`KEYDEV_PLAIN`] under `kbase`.
const UID_HEX: &str = "0102030405060708";
const OTP_KEY_1_HEX: &str =
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
/// `[0x01] ‖ AES-256-CBC(kbase, IV = serial_hash[..16])` (C `fido.c:227-287`).
const KD33_HEX: &str =
    "01a0385479d6e53f7e01f26be6909296779002a409ae67450d7b9340bcf846e2f9";
/// `AES-256-CBC(otp_key_1, IV = 0)` (C `fido.c:227-287`).
const KD32_CT_HEX: &str =
    "eeb22a772d3c338cfc3632063b877061e8e096a247d4ed6a729259e7d6857eec";
const KEYDEV_PLAIN_HEX: &str =
    "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";

/// The AAD the migration call sites bind: the record's slot identity
/// (`migration.rs` passes the store slot name; see [`wrap_aead`] docs).
const AAD: &[u8] = b"fido.hkey";

fn h(s: &str) -> std::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture() -> ([u8; KEY_LEN], [u8; KEY_LEN], [u8; SERIAL_HASH_LEN]) {
    let otp: [u8; KEY_LEN] = h(OTP_KEY_1_HEX).try_into().unwrap();
    let sh = ckey::serial_hash(&h(UID_HEX));
    let kbase = ckey::derive_kbase_c(&otp, &sh).unwrap();
    (otp, kbase, sh)
}

fn keydev() -> [u8; KEY_LEN] {
    h(KEYDEV_PLAIN_HEX).try_into().unwrap()
}

/// Fixed nonce for deterministic vectors; freshness is exercised by the
/// [`Trng`]-driven test below.
fn nonce12() -> [u8; WRAP_NONCE_LEN] {
    [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0]
}

fn trng_nonce() -> [u8; WRAP_NONCE_LEN] {
    let mut n = [0u8; WRAP_NONCE_LEN];
    HostTrng.random_bytes(&mut n);
    n
}

use fapico2_platform::trng::Trng;

/// Legacy CBC records (both the zero-IV 32-byte and the serial-hash-IV
/// 33-byte shapes) still open — the CBC path is READ-ONLY compat (US-917)
/// but must not regress, and the dispatching open routes them untouched.
#[test]
fn legacy_cbc_records_still_open() {
    let (otp, kbase, sh) = fixture();
    let kd33 = h(KD33_HEX);
    let kd32 = h(KD32_CT_HEX);
    let expected = keydev();

    // Direct legacy unwrap (compat path) ...
    assert_eq!(
        unwrap_keydev(&kd33, &[0; KEY_LEN], &kbase, &sh, None).unwrap(),
        KeydevStatus::Unwrapped(expected)
    );
    assert_eq!(
        unwrap_keydev(&kd32, &otp, &[0; KEY_LEN], &sh, None).unwrap(),
        KeydevStatus::Unwrapped(expected)
    );
    // ... and through the dispatching open (same result, same route).
    assert_eq!(
        open_keydev(&kd33, &[0; KEY_LEN], &kbase, &sh, None, AAD).unwrap(),
        KeydevStatus::Unwrapped(expected)
    );
    assert_eq!(
        open_keydev(&kd32, &otp, &[0; KEY_LEN], &sh, None, AAD).unwrap(),
        KeydevStatus::Unwrapped(expected)
    );
}

/// A rewrap of an opened legacy record produces the tagged AEAD format:
/// `WRAP_TAG ‖ nonce(12) ‖ ct ‖ GCM tag(16)`, the nonce is carried
/// verbatim, and the ciphertext differs from the plaintext.
#[test]
fn rewrap_produces_tagged_aead_record() {
    let (otp, _, sh) = fixture();
    let wk = ckey::derive_wrap_key(&otp, &sh);
    let nonce = nonce12();
    let mut record = [0u8; WRAP_OVERHEAD + KEY_LEN];
    let n = wrap_aead(&wk, &nonce, AAD, &keydev(), &mut record).unwrap();

    assert_eq!(n, WRAP_OVERHEAD + KEY_LEN);
    assert_eq!(record[0], WRAP_TAG, "the AEAD record carries the format tag");
    assert_eq!(&record[1..1 + WRAP_NONCE_LEN], &nonce, "the per-record nonce is embedded");
    assert_ne!(
        &record[WRAP_HEADER_LEN..WRAP_HEADER_LEN + KEY_LEN],
        &keydev()[..],
        "the plaintext must not be stored in the clear"
    );
}

/// Format separation: the AEAD record is NOT openable by the legacy CBC
/// path (the 61-byte legacy branch only accepts the C format tags
/// `0x02/0x03` — no zero-IV / serial-hash-IV CBC interpretation exists
/// for it), and the legacy records are NOT openable by the AEAD path.
#[test]
fn aead_record_rejected_by_legacy_path_and_vice_versa() {
    let (otp, kbase, sh) = fixture();
    let wk = ckey::derive_wrap_key(&otp, &sh);
    let mut record = [0u8; WRAP_OVERHEAD + KEY_LEN];
    wrap_aead(&wk, &nonce12(), AAD, &keydev(), &mut record).unwrap();

    // Legacy CBC open (which would use IV = 0 or serial_hash[..16]) fails
    // closed on the AEAD record — BadFormat (unknown legacy format tag).
    assert_eq!(
        unwrap_keydev(&record, &otp, &kbase, &sh, None),
        Err(CKeyError::BadFormat)
    );

    // Vice versa: an untagged legacy record is refused by the AEAD path.
    let kd33 = h(KD33_HEX);
    let mut out = [0u8; KEY_LEN];
    assert_eq!(open_aead(&kd33, &wk, AAD, &mut out), Err(CKeyError::BadFormat));
    assert_eq!(
        open_keydev(&kd33, &[0; KEY_LEN], &kbase, &sh, None, AAD).unwrap(),
        KeydevStatus::Unwrapped(keydev()),
        "the legacy record still opens through the dispatching open"
    );
}

/// The legacy-path IV weaknesses do not transfer: truncating an AEAD
/// record, or zeroing its per-record nonce (the CBC records' zero-IV
/// trick), fails closed with no plaintext release.
#[test]
fn aead_record_fails_closed_on_truncation_or_zeroed_nonce() {
    let (otp, _, sh) = fixture();
    let wk = ckey::derive_wrap_key(&otp, &sh);
    let mut record = [0u8; WRAP_OVERHEAD + KEY_LEN];
    wrap_aead(&wk, &nonce12(), AAD, &keydev(), &mut record).unwrap();

    // Truncated record — below the AEAD framing overhead is a length
    // error, and losing even part of the tag fails the GCM check; either
    // way the open errors instead of returning garbage.
    let mut out = [0u8; KEY_LEN];
    assert_eq!(
        open_aead(&record[..WRAP_OVERHEAD - 1], &wk, AAD, &mut out),
        Err(CKeyError::BadLength)
    );
    assert_eq!(
        open_aead(&record[..record.len() - 1], &wk, AAD, &mut out),
        Err(CKeyError::AuthFailed)
    );
    // Zeroed nonce: the GCM tag no longer matches — AuthFailed, and the
    // output buffer must not carry a usable plaintext.
    let mut zeroed = record;
    zeroed[1..1 + WRAP_NONCE_LEN].fill(0);
    assert_eq!(open_aead(&zeroed, &wk, AAD, &mut out), Err(CKeyError::AuthFailed));
    assert!(out.iter().all(|&b| b == 0), "a failed open leaves no plaintext behind");
}

/// Wrap → open round-trip preserves the plaintext, for the keydev shape
/// through the dispatching [`open_keydev`] and for an arbitrary payload
/// (the 48-byte DEK the S-413-6 rewrap persists) through [`open_aead`].
#[test]
fn round_trip_preserves_plaintext() {
    let (otp, _, sh) = fixture();
    let wk = ckey::derive_wrap_key(&otp, &sh);

    // Keydev shape: fresh random nonce per record (US-380: platform Trng).
    let mut record = [0u8; WRAP_OVERHEAD + KEY_LEN];
    wrap_aead(&wk, &trng_nonce(), AAD, &keydev(), &mut record).unwrap();
    let mut out = [0u8; KEY_LEN];
    let n = open_aead(&record, &wk, AAD, &mut out).unwrap();
    assert_eq!(n, KEY_LEN);
    assert_eq!(&out, &keydev()[..]);
    assert_eq!(
        open_keydev(&record, &otp, &[0; KEY_LEN], &sh, None, AAD).unwrap(),
        KeydevStatus::Unwrapped(keydev())
    );

    // Arbitrary payload (DEK-sized): the format is not keydev-specific.
    let dek: [u8; 48] = core::array::from_fn(|i| (i * 7) as u8);
    let mut rec48 = [0u8; WRAP_OVERHEAD + 48];
    wrap_aead(&wk, &trng_nonce(), b"openpgp.dek.v1", &dek, &mut rec48).unwrap();
    let mut out48 = [0u8; 48];
    let n = open_aead(&rec48, &wk, b"openpgp.dek.v1", &mut out48).unwrap();
    assert_eq!(n, 48);
    assert_eq!(out48, dek);
}

/// AEAD integrity is bound to the derived key, the AAD (the record's
/// slot/identity bytes at the call sites), and the ciphertext — any
/// mismatch is `AuthFailed`, never a plaintext.
#[test]
fn aead_open_fails_closed_on_wrong_key_aad_or_ciphertext() {
    let (otp, _, sh) = fixture();
    let wk = ckey::derive_wrap_key(&otp, &sh);
    let mut record = [0u8; WRAP_OVERHEAD + KEY_LEN];
    wrap_aead(&wk, &nonce12(), AAD, &keydev(), &mut record).unwrap();
    let mut out = [0u8; KEY_LEN];

    let mut wrong_key = wk;
    wrong_key[0] ^= 0x01;
    assert_eq!(open_aead(&record, &wrong_key, AAD, &mut out), Err(CKeyError::AuthFailed));

    assert_eq!(
        open_aead(&record, &wk, b"other.identity", &mut out),
        Err(CKeyError::AuthFailed)
    );

    let mut flipped = record;
    flipped[WRAP_HEADER_LEN] ^= 0x01;
    assert_eq!(open_aead(&flipped, &wk, AAD, &mut out), Err(CKeyError::AuthFailed));
    assert!(out.iter().all(|&b| b == 0), "a failed open leaves no plaintext behind");
}

/// The AEAD wrap key is derived with the store-v3 KDF shape
/// (HKDF-SHA256, salt = serial hash) over the same input material the CBC
/// path used (the OTP key row), but under a distinct US-917 label — it
/// differs from `kbase` (the CBC record key) and is deterministic.
#[test]
fn wrap_key_is_domain_separated_from_kbase() {
    let (otp, kbase, sh) = fixture();
    let wk = ckey::derive_wrap_key(&otp, &sh);
    assert_ne!(wk, kbase, "the AEAD record key must not be the CBC record key");
    assert_eq!(wk, ckey::derive_wrap_key(&otp, &sh), "derivation is deterministic");
    let mut other = otp;
    other[0] ^= 0x01;
    assert_ne!(wk, ckey::derive_wrap_key(&other, &sh), "the key binds the OTP row");
}

/// The nonce must be fresh per record: two wraps of the same plaintext
/// under independent `Trng` nonces differ (no CBC-style deterministic
/// IV reuse), and both records still open.
#[test]
fn random_nonces_make_records_distinct_and_openable() {
    let (otp, _, sh) = fixture();
    let wk = ckey::derive_wrap_key(&otp, &sh);
    let mut rec_a = [0u8; WRAP_OVERHEAD + KEY_LEN];
    let mut rec_b = [0u8; WRAP_OVERHEAD + KEY_LEN];
    wrap_aead(&wk, &trng_nonce(), AAD, &keydev(), &mut rec_a).unwrap();
    wrap_aead(&wk, &trng_nonce(), AAD, &keydev(), &mut rec_b).unwrap();
    assert_ne!(
        rec_a[1..1 + WRAP_NONCE_LEN],
        rec_b[1..1 + WRAP_NONCE_LEN],
        "independent Trng draws must give distinct nonces"
    );
    assert_ne!(rec_a, rec_b, "same plaintext under a fresh nonce re-encrypts");
    let mut out_a = [0u8; KEY_LEN];
    let mut out_b = [0u8; KEY_LEN];
    assert_eq!(open_aead(&rec_a, &wk, AAD, &mut out_a).unwrap(), KEY_LEN);
    assert_eq!(open_aead(&rec_b, &wk, AAD, &mut out_b).unwrap(), KEY_LEN);
    assert_eq!(out_a, keydev());
    assert_eq!(out_b, keydev());
}

/// The GCM tag length is the AEAD record's own framing: the record
/// carries exactly one 16-byte tag after the ciphertext (US-917 format).
#[test]
fn aead_record_framing_is_tag_nonce_ct_tag16() {
    assert_eq!(WRAP_TAG_LEN, 16);
    assert_eq!(WRAP_HEADER_LEN, 1 + WRAP_NONCE_LEN);
    assert_eq!(WRAP_OVERHEAD, WRAP_HEADER_LEN + WRAP_TAG_LEN);
    let (_, _, sh) = fixture();
    let otp: [u8; KEY_LEN] = h(OTP_KEY_1_HEX).try_into().unwrap();
    let wk = ckey::derive_wrap_key(&otp, &sh);
    let mut record = [0u8; WRAP_OVERHEAD + KEY_LEN];
    let n = wrap_aead(&wk, &nonce12(), AAD, &keydev(), &mut record).unwrap();
    // 61 bytes total — length-distinct dispatch from the 32/33-byte legacy
    // shapes, with the tag byte separating it from the legacy 61-byte form.
    assert_eq!(n, 61);
    assert_eq!(record[WRAP_HEADER_LEN + KEY_LEN..n].len(), WRAP_TAG_LEN);
}
