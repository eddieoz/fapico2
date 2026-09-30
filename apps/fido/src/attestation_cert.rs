//! Minimal on-device X.509 v3 self-signed certificate builder (US-916).
//!
//! The per-device attestation identity (see [`crate::attestation`]) is minted
//! at first boot, so the certificate has to be built **on the device** — the
//! build has no `cryptography` (Python) and the device build has no heap.
//! This module hand-rolls exactly the DER shapes a packed-attestation
//! self-signed cert needs, into fixed-size [`heapless::Vec`] buffers, so the
//! same code compiles for the RP2350 (`thumbv8m.main-none-eabi`) and the host
//! tests.
//!
//! Shape produced (RFC 5280):
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!   tbsCertificate ::= SEQUENCE {
//!     [0] EXPLICIT INTEGER 2            -- v3
//!     INTEGER serial                    -- 16 TRNG bytes, positive, minimal
//!     AlgorithmIdentifier ecdsa-with-SHA256 (1.2.840.10045.4.3.2, params absent)
//!     Name issuer                       -- CN = "fapico2" (UTF8String)
//!     validity ::= SEQUENCE { UTCTime "250101000000Z", UTCTime "451231235959Z" }
//!     Name subject                      -- == issuer (self-signed)
//!     subjectPublicKeyInfo ::= SEQUENCE {
//!       AlgorithmIdentifier { ecPublicKey, prime256v1 }
//!       BIT STRING (uncompressed 65-byte SEC1 point)
//!     }
//!   }
//!   signatureAlgorithm ::= AlgorithmIdentifier ecdsa-with-SHA256
//!   signatureValue ::= BIT STRING (DER ECDSA sig over the DER TBS bytes)
//!   }
//! ```
//!
//! No extensions: a minimal valid v3 certificate is all a packed
//! attestation statement's `x5c` leaf needs (python-fido2 verifies the
//! signature chain and parses the cert through `cryptography`, which accepts
//! an extension-less v3 certificate).
//!
//! Static validity window: the device has no clock, so the notBefore /
//! notAfter are fixed compile-time strings (2025-01-01 .. 2045-12-31). The
//! cert is device-minted and device-scoped — freshness is attested by the
//! TRNG serial and the per-device key, not by a wall clock.

use heapless::Vec;
use p256::SecretKey;

use crate::crypto;
use fapico2_platform::secure_store::SecureStoreError;

/// Upper bound for the generated certificate. The shape above is ~300 B for
/// a 16-byte serial (see the module docs); 512 B leaves generous headroom
/// and matches the device physical-slot value cap (`DEV_MAX_VALUE_LEN`), so
/// a freshly generated cert even fits a plain slot — it is persisted through
/// the chunked API anyway (see [`crate::attestation`]).
pub const CERT_MAX: usize = 512;

// OID content bytes only (tag + length are added by [`tlv`]).
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
const OID_ID_CN: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7

/// Common Name of the self-signed attestation certificate.
const SUBJECT_CN: &[u8] = b"fapico2";
/// Fixed validity window (device has no clock — see the module docs).
const NOT_BEFORE: &[u8] = b"250101000000Z";
const NOT_AFTER: &[u8] = b"451231235959Z";

type CertBuf = Vec<u8, CERT_MAX>;

fn push(out: &mut CertBuf, b: u8) -> Result<(), SecureStoreError> {
    out.push(b).map_err(|_| SecureStoreError::ValueTooLong)
}

fn extend(out: &mut CertBuf, bytes: &[u8]) -> Result<(), SecureStoreError> {
    out.extend_from_slice(bytes)
        .map_err(|_| SecureStoreError::ValueTooLong)
}

/// DER length octets for `len` (short form < 0x80, else 0x81/0x82 long form).
fn len_bytes(out: &mut CertBuf, len: usize) -> Result<(), SecureStoreError> {
    debug_assert!(len < 0x1_0000, "cert builder buffers are statically bounded");
    if len < 0x80 {
        push(out, len as u8)
    } else if len < 0x100 {
        push(out, 0x81)?;
        push(out, len as u8)
    } else {
        push(out, 0x82)?;
        push(out, (len >> 8) as u8)?;
        push(out, (len & 0xFF) as u8)
    }
}

/// One TLV: `tag || len(content) || content`.
fn tlv(out: &mut CertBuf, tag: u8, content: &[u8]) -> Result<(), SecureStoreError> {
    push(out, tag)?;
    len_bytes(out, content.len())?;
    extend(out, content)
}

/// DER `Name` for issuer **and** subject (self-signed: identical):
/// `SEQ { SET { SEQ { OID 2.5.4.3, UTF8String "fapico2" } } }`.
fn name_der() -> Result<CertBuf, SecureStoreError> {
    let mut atv: CertBuf = Vec::new();
    tlv(&mut atv, 0x06, OID_ID_CN)?;
    tlv(&mut atv, 0x0C, SUBJECT_CN)?;
    let mut rdn: CertBuf = Vec::new();
    tlv(&mut rdn, 0x30, &atv)?;
    let mut name: CertBuf = Vec::new();
    tlv(&mut name, 0x31, &rdn)?;
    let mut seq: CertBuf = Vec::new();
    tlv(&mut seq, 0x30, &name)?;
    Ok(seq)
}

/// DER `INTEGER` serial drawn from the TRNG: 16 bytes, made non-zero,
/// leading zero bytes stripped (minimal length), and 0x00-padded when the
/// top bit of the first significant byte is set (positive INTEGER rule).
fn serial_der(out: &mut CertBuf, rng: &mut impl rand_core::RngCore) -> Result<(), SecureStoreError> {
    let mut s = [0u8; 16];
    rng.fill_bytes(&mut s);
    s[15] |= 1; // never the degenerate all-zero serial
    let mut i = 0;
    while i < 15 && s[i] == 0 {
        i += 1;
    }
    let sig = &s[i..];
    push(out, 0x02)?;
    if sig[0] & 0x80 != 0 {
        len_bytes(out, sig.len() + 1)?;
        push(out, 0x00)?;
    } else {
        len_bytes(out, sig.len())?;
    }
    extend(out, sig)
}

/// Build the self-signed certificate for `key`: sign the DER TBS bytes with
/// `key` (ECDSA-with-SHA256, DER signature — [`crypto::p256_sign_der_into`]
/// hashes internally) and wrap TBS + algorithm + signature into the
/// `Certificate` SEQUENCE. Buffer overflows map to
/// [`SecureStoreError::ValueTooLong`]; with [`CERT_MAX`] = 512 the shape
/// above cannot overflow (worst case ≈ 320 B).
pub(crate) fn build_self_signed(
    key: &SecretKey,
    serial_rng: &mut impl rand_core::RngCore,
) -> Result<CertBuf, SecureStoreError> {
    // ---- TBSCertificate content ----
    let mut body: CertBuf = Vec::new();
    // version [0] EXPLICIT INTEGER 2 (v3).
    tlv(&mut body, 0xA0, &[0x02, 0x01, 0x02])?;
    serial_der(&mut body, serial_rng)?;
    // signature algorithm (params absent, per RFC 5480 §2 for ECDSA sigs).
    let mut alg: CertBuf = Vec::new();
    tlv(&mut alg, 0x06, OID_ECDSA_WITH_SHA256)?;
    tlv(&mut body, 0x30, &alg)?;
    let name = name_der()?;
    extend(&mut body, &name)?; // issuer
    let mut validity: CertBuf = Vec::new();
    tlv(&mut validity, 0x17, NOT_BEFORE)?;
    tlv(&mut validity, 0x17, NOT_AFTER)?;
    tlv(&mut body, 0x30, &validity)?;
    extend(&mut body, &name)?; // subject == issuer (self-signed)
    // subjectPublicKeyInfo: ecPublicKey + prime256v1, uncompressed point.
    let mut spki_alg: CertBuf = Vec::new();
    tlv(&mut spki_alg, 0x06, OID_EC_PUBLIC_KEY)?;
    tlv(&mut spki_alg, 0x06, OID_PRIME256V1)?;
    let mut spki: CertBuf = Vec::new();
    tlv(&mut spki, 0x30, &spki_alg)?;
    let pub_bytes = crypto::public_key_bytes(&key.public_key());
    let mut point: CertBuf = Vec::new();
    push(&mut point, 0x00)?; // BIT STRING unused bits
    extend(&mut point, &pub_bytes)?;
    tlv(&mut spki, 0x03, &point)?;
    tlv(&mut body, 0x30, &spki)?;

    // ---- wrap the TBS in its SEQUENCE ----
    let mut tbs: CertBuf = Vec::new();
    tlv(&mut tbs, 0x30, &body)?;

    // ---- sign the DER TBS bytes with the attestation key ----
    let mut sig = heapless::Vec::<u8, 72>::new();
    crypto::p256_sign_der_into(key, tbs.as_slice(), &mut sig)
        .ok_or(SecureStoreError::Corrupt)?;

    // ---- Certificate ::= SEQUENCE { tbs, alg, BIT STRING sig } ----
    let mut content: CertBuf = Vec::new();
    extend(&mut content, &tbs)?;
    let mut sig_alg: CertBuf = Vec::new();
    tlv(&mut sig_alg, 0x06, OID_ECDSA_WITH_SHA256)?;
    tlv(&mut content, 0x30, &sig_alg)?;
    let mut sig_bits: CertBuf = Vec::new();
    push(&mut sig_bits, 0x00)?; // BIT STRING unused bits
    extend(&mut sig_bits, sig.as_slice())?;
    tlv(&mut content, 0x03, &sig_bits)?;
    let mut cert: CertBuf = Vec::new();
    tlv(&mut cert, 0x30, &content)?;
    Ok(cert)
}
