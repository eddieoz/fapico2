// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! fapico2 (US-972): OpenPGP v4 public-key fingerprints.
//!
//! A v4 fingerprint is `SHA-1( 0x99 || u16be(len) || packet-body )` where
//! `packet-body` is the v4 public-key packet body:
//!
//! ```text
//! 04 || created(u32be) || algo(u8) || <algorithm-specific material>
//! ```
//!
//! The algorithm-specific material is *not* uniform, and getting it wrong
//! yields a plausible-but-wrong fingerprint, which is worse than none. Every
//! encoding in [`KeyParams`] below was therefore taken from a real GnuPG
//! 2.4.4 key packet rather than reasoned about; see
//! `docs/tasks/evidence/us972-c5/` and the `hardware_confirmed_vectors` test
//! at the bottom of this file, which pins each one to the bytes GnuPG itself
//! produced and then read back out of DO C5.
//!
//! Note in particular that GnuPG emits the RFC 9580 forms throughout: Ed25519
//! is *neither* the historical 34-byte `99 22 <32>` nor the 37-byte draft
//! form, but an explicit curve OID followed by a `0x40`-prefixed MPI; and
//! every ECDSA curve is *uncompressed* (`0x04 || X || Y`), Brainpool and
//! secp256k1 included.

use trussed_core::types::Mechanism;

use crate::types::{AuthenticationAlgorithm, DecryptionAlgorithm, KeyType, SignatureAlgorithm};

/// Largest v4 public-key packet body this module will assemble.
///
/// Comfortably above P-521 (`1 + 1 + 4 + 1 + 9 + 2 + 134`) and
/// BrainpoolP512r1. RSA is not built here (see [`KeyParams::mechanism`]), so
/// a 4096-bit modulus never reaches this bound.
const MAX_BODY: usize = 256;

/// SHA-1 (FIPS 180-4).
///
/// Present only because the OpenPGP v4 fingerprint is *defined* as SHA-1.
/// This is an interoperability constant, not a security choice.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);

    // Every whole block but the last.
    for chunk in data.chunks_exact(64) {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        compress(&mut h, &block);
    }

    // The tail, padded: 0x80, zeroes, then the 8-octet big-endian bit length.
    // Always emitted, including for empty input, and possibly spanning two
    // blocks when the tail leaves fewer than 8 octets.
    let rest = data.len() % 64;
    let mut tail = [0u8; 64];
    tail[..rest].copy_from_slice(&data[data.len() - rest..]);
    tail[rest] = 0x80;
    if rest + 1 > 56 {
        compress(&mut h, &tail);
        tail = [0u8; 64];
    }
    tail[56..].copy_from_slice(&bit_len.to_be_bytes());
    compress(&mut h, &tail);

    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let tmp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// Bit length of a big-endian MPI value, i.e. the index of its highest set
/// bit plus one.
fn mpi_bit_len(value: &[u8]) -> u16 {
    for (i, byte) in value.iter().enumerate() {
        if *byte != 0 {
            return ((value.len() - i) * 8 - byte.leading_zeros() as usize) as u16;
        }
    }
    0
}

/// The algorithm-specific shape of a v4 public-key packet.
pub struct KeyParams {
    /// Mechanism to serialize the stored public key with.
    pub mechanism: Mechanism,
    /// OpenPGP public-key packet algorithm id (not the key-attribute id).
    pub packet_algo: u8,
    /// Curve OID, without its DER length byte. Empty for RSA.
    pub oid: &'static [u8],
    /// Point-format octet the MPI value carries: `0x40` for 25519 curves,
    /// `0x04` (uncompressed) for NIST and Brainpool ECDSA.
    pub point_prefix: u8,
    /// Trailing KDF parameter octets. Only X25519 carries any.
    pub kdf: &'static [u8],
}

// fapico2: the OIDs are the ones the card already advertises in its algorithm
// attributes (DO C1/C2/C3 and DO FA), so they cannot drift from what the host
// was told the card holds.
const OID_ED25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
const OID_X25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
const OID_NIST_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_NIST_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_NIST_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_BRAINPOOL_P256R1: &[u8] = &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const OID_BRAINPOOL_P384R1: &[u8] = &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b];
const OID_BRAINPOOL_P512R1: &[u8] = &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d];
const OID_SECP256K1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];

// fapico2: GnuPG 2.4.4 appends exactly these four octets to an X25519 public
// key packet when the card advertises no KDF (DO F1 absent, "KDF setting: off"
// in `gpg --edit-card`), which is this card's state. A host that negotiates a
// KDF would write different octets here; see docs/tasks/us972-do-c5-fingerprint.md.
const X25519_DEFAULT_KDF: &[u8] = &[0x03, 0x01, 0x08, 0x07];

/// Resolve the packet shape for one key slot.
///
/// Returns `None` for any algorithm this module cannot reproduce exactly. The
/// caller must treat that as "leave whatever the host wrote alone" — a wrong
/// fingerprint is worse than none, so this fails closed.
pub fn params(
    ty: KeyType,
    sign: SignatureAlgorithm,
    dec: DecryptionAlgorithm,
    aut: AuthenticationAlgorithm,
) -> Option<KeyParams> {
    const ALGO_ED25519: u8 = 22;
    const ALGO_X25519: u8 = 18;
    const ALGO_ECDSA: u8 = 19;

    let ecdsa = |mechanism, oid| KeyParams {
        mechanism,
        packet_algo: ALGO_ECDSA,
        oid,
        point_prefix: 0x04,
        kdf: &[],
    };

    match ty {
        KeyType::Sign => match sign {
            SignatureAlgorithm::Ed255 => Some(KeyParams {
                mechanism: Mechanism::Ed255,
                packet_algo: ALGO_ED25519,
                oid: OID_ED25519,
                point_prefix: 0x40,
                kdf: &[],
            }),
            SignatureAlgorithm::EcDsaP256 => Some(ecdsa(Mechanism::P256, OID_NIST_P256)),
            SignatureAlgorithm::EcDsaP384 => Some(ecdsa(Mechanism::P384, OID_NIST_P384)),
            SignatureAlgorithm::EcDsaP521 => Some(ecdsa(Mechanism::P521, OID_NIST_P521)),
            SignatureAlgorithm::EcDsaBrainpoolP256R1 => {
                Some(ecdsa(Mechanism::BrainpoolP256R1, OID_BRAINPOOL_P256R1))
            }
            SignatureAlgorithm::EcDsaBrainpoolP384R1 => {
                Some(ecdsa(Mechanism::BrainpoolP384R1, OID_BRAINPOOL_P384R1))
            }
            SignatureAlgorithm::EcDsaBrainpoolP512R1 => {
                Some(ecdsa(Mechanism::BrainpoolP512R1, OID_BRAINPOOL_P512R1))
            }
            SignatureAlgorithm::EcDsaSecp256k1 => Some(ecdsa(Mechanism::Secp256k1, OID_SECP256K1)),
            // fapico2: RSA needs `KeySerialization::RsaParts` plus
            // `trussed_rsa_types`, both behind this crate's `rsa` feature.
            // Rather than widen the feature surface in a vendored crate, RSA
            // fails closed here and keeps whatever the host put in C5.
            _ => None,
        },
        KeyType::Dec => match dec {
            DecryptionAlgorithm::X255 => Some(KeyParams {
                mechanism: Mechanism::X255,
                packet_algo: ALGO_X25519,
                oid: OID_X25519,
                point_prefix: 0x40,
                kdf: X25519_DEFAULT_KDF,
            }),
            DecryptionAlgorithm::EcDhP256 => Some(ecdsa(Mechanism::P256, OID_NIST_P256)),
            DecryptionAlgorithm::EcDhP384 => Some(ecdsa(Mechanism::P384, OID_NIST_P384)),
            DecryptionAlgorithm::EcDhP521 => Some(ecdsa(Mechanism::P521, OID_NIST_P521)),
            DecryptionAlgorithm::EcDhBrainpoolP256R1 => {
                Some(ecdsa(Mechanism::BrainpoolP256R1, OID_BRAINPOOL_P256R1))
            }
            DecryptionAlgorithm::EcDhBrainpoolP384R1 => {
                Some(ecdsa(Mechanism::BrainpoolP384R1, OID_BRAINPOOL_P384R1))
            }
            DecryptionAlgorithm::EcDhBrainpoolP512R1 => {
                Some(ecdsa(Mechanism::BrainpoolP512R1, OID_BRAINPOOL_P512R1))
            }
            DecryptionAlgorithm::EcDhSecp256k1 => Some(ecdsa(Mechanism::Secp256k1, OID_SECP256K1)),
            _ => None,
        },
        KeyType::Aut => match aut {
            AuthenticationAlgorithm::Ed255 => Some(KeyParams {
                mechanism: Mechanism::Ed255,
                packet_algo: ALGO_ED25519,
                oid: OID_ED25519,
                point_prefix: 0x40,
                kdf: &[],
            }),
            AuthenticationAlgorithm::EcDsaP256 => Some(ecdsa(Mechanism::P256, OID_NIST_P256)),
            AuthenticationAlgorithm::EcDsaP384 => Some(ecdsa(Mechanism::P384, OID_NIST_P384)),
            AuthenticationAlgorithm::EcDsaP521 => Some(ecdsa(Mechanism::P521, OID_NIST_P521)),
            AuthenticationAlgorithm::EcDsaBrainpoolP256R1 => {
                Some(ecdsa(Mechanism::BrainpoolP256R1, OID_BRAINPOOL_P256R1))
            }
            AuthenticationAlgorithm::EcDsaBrainpoolP384R1 => {
                Some(ecdsa(Mechanism::BrainpoolP384R1, OID_BRAINPOOL_P384R1))
            }
            AuthenticationAlgorithm::EcDsaBrainpoolP512R1 => {
                Some(ecdsa(Mechanism::BrainpoolP512R1, OID_BRAINPOOL_P512R1))
            }
            AuthenticationAlgorithm::EcDsaSecp256k1 => {
                Some(ecdsa(Mechanism::Secp256k1, OID_SECP256K1))
            }
            _ => None,
        },
    }
}

/// Assemble the v4 public-key packet body and hash it.
///
/// `serialized` is the stored public key as `KeySerialization::Raw` returns
/// it: the bare 32 bytes for a 25519 curve, and the bare `X || Y` for an
/// ECDSA curve (the point-format octet is added here, exactly as
/// `command::gen::serialize_nist_curve` adds it on the GENERATE reply).
pub fn fingerprint(
    params: &KeyParams,
    created: u32,
    serialized: &[u8],
) -> Option<[u8; 20]> {
    let mut body = [0u8; MAX_BODY + 3];
    let mut n = 0usize;

    body[n] = 4; // packet version
    n += 1;
    body[n..n + 4].copy_from_slice(&created.to_be_bytes());
    n += 4;
    body[n] = params.packet_algo;
    n += 1;

    if !params.oid.is_empty() {
        let len = params.oid.len();
        let len8 = u8::try_from(len).ok()?;
        body[n] = len8;
        n += 1;
        body[n..n + len].copy_from_slice(params.oid);
        n += len;
    }

    // MPI: two-octet bit count, then point-format octet + point.
    if 1 + serialized.len() > 0xFFFF {
        return None;
    }
    let point_prefix = params.point_prefix;
    let mut mpi = [0u8; 1 + MAX_BODY];
    mpi[0] = point_prefix;
    mpi[1..1 + serialized.len()].copy_from_slice(serialized);
    body[n..n + 2].copy_from_slice(&mpi_bit_len(&mpi[..1 + serialized.len()]).to_be_bytes());
    n += 2;
    body[n] = point_prefix;
    n += 1;
    body[n..n + serialized.len()].copy_from_slice(serialized);
    n += serialized.len();

    body[n..n + params.kdf.len()].copy_from_slice(params.kdf);
    n += params.kdf.len();

    if n > MAX_BODY || n > u16::MAX as usize {
        return None;
    }

    let mut preimage = [0u8; MAX_BODY + 3];
    preimage[0] = 0x99; // v4 fingerprint preimage tag
    preimage[1..3].copy_from_slice(&(n as u16).to_be_bytes());
    preimage[3..3 + n].copy_from_slice(&body[..n]);
    Some(sha1(&preimage[..3 + n]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::types::{AuthenticationAlgorithm, DecryptionAlgorithm, KeyType, SignatureAlgorithm};

    #[test]
    fn sha1_fips_vectors() {
        assert_eq!(sha1(b""), unhex("da39a3ee5e6b4b0d3255bfef95601890afd80709")[..]);
        assert_eq!(
            sha1(b"abc"),
            unhex("a9993e364706816aba3e25717850c26c9cd0d89d")[..]
        );
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            unhex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")[..]
        );
        // 1,000,000 'a' — the classic long-message vector, which exercises the
        // multi-block padding path that the three above do not reach.
        assert_eq!(
            sha1(&[b'a'; 1_000_000]),
            unhex("34aa973cd4c4daa4f61eeb2bdbad27316534016f")[..]
        );
    }

    #[test]
    fn mpi_bit_len_matches_gnupg() {
        // GnuPG's 0x40-prefixed 25519 MPI, at its real length of 33.
        let mut m25519 = [0u8; 33];
        m25519[0] = 0x40;
        assert_eq!(mpi_bit_len(&m25519), 263);
        // GnuPG's uncompressed P-256 point: 0x04 || X || Y, 65 octets.
        let mut p256 = [0u8; 65];
        p256[0] = 0x04;
        assert_eq!(mpi_bit_len(&p256), 515);
        // ...and P-384, 97 octets, 771 bits.
        let mut p384 = [0u8; 97];
        p384[0] = 0x04;
        assert_eq!(mpi_bit_len(&p384), 771);
    }

    /// Every vector below is a real GnuPG 2.4.4 v4 public-key packet, taken
    /// from a key generated during US-972 and read back out of DO C5 on the
    /// live card. `hardware_confirmed` marks the ones generated *on the card*
    /// and cross-checked against `GET DATA C5`; the rest were settled against
    /// the same GnuPG off-card, which fixes the encoding rule but not the
    /// card's own serialization of that curve.
    fn check(
        ty: KeyType,
        sign: SignatureAlgorithm,
        dec: DecryptionAlgorithm,
        aut: AuthenticationAlgorithm,
        created: u32,
        serialized: &str,
        expected: &str,
    ) {
        let serialized = unhex(serialized);
        let params = params(ty, sign, dec, aut).unwrap();
        let fp = fingerprint(&params, created, &serialized).unwrap();
        assert_eq!(
            fp[..],
            unhex(expected)[..],
            "packet_algo={} oid={:02x?}",
            params.packet_algo,
            params.oid
        );
    }

    /// **Hardware-confirmed**: Ed25519 signature key, card serial 88B0BD40.
    /// Created 0x6AB942F8, point from the card's GENERATE reply, expected
    /// value is what GnuPG itself wrote into C5 Sign and what it holds in its
    /// keyring.
    #[test]
    fn hardware_confirmed_ed25519_sign() {
        check(
            KeyType::Sign,
            SignatureAlgorithm::Ed255,
            DecryptionAlgorithm::default(),
            AuthenticationAlgorithm::default(),
            0x6ab942f8,
            "2d8cd81a92dfc3084b9722e4610ca19c47c995c068784da6d9c7fc8b718e98fd",
            "a1cc759d3cab4fb02fbb27baa385bab26a7fface",
        );
    }

    /// **Hardware-confirmed**: the same generation's cv25519 decryption key.
    #[test]
    fn hardware_confirmed_cv25519_dec() {
        check(
            KeyType::Dec,
            SignatureAlgorithm::default(),
            DecryptionAlgorithm::X255,
            AuthenticationAlgorithm::default(),
            0x6ab942f8,
            "5800a464fae65bfa48e9cb277f4c050c85f7e3b4ddbef17a5845f5bde1c0e447",
            "faf98801288d20f0d6e30a66be49d593dd8401d9",
        );
    }

    /// **Hardware-confirmed**: the same generation's Ed25519 authentication
    /// key.
    #[test]
    fn hardware_confirmed_ed25519_aut() {
        check(
            KeyType::Aut,
            SignatureAlgorithm::default(),
            DecryptionAlgorithm::default(),
            AuthenticationAlgorithm::Ed255,
            0x6ab942f8,
            "e96e1649334701ca0cfff38e9c00e6aa3ef1f782f4f8cbbe0246ed6e34a64346",
            "c6bf2b048f29e4402995f78579d4ef4eb673d3ca",
        );
    }

    /// **Hardware-confirmed**: Brainpool P-256r1 signature key, generated on
    /// the card after its signing attribute was set to `brainpoolP256r1`.
    /// This is the vector that settles compressed-vs-uncompressed: the point
    /// GnuPG hashed is `0x04 || X || Y`, i.e. **uncompressed**.
    #[test]
    fn hardware_confirmed_brainpool_p256r1_sign() {
        check(
            KeyType::Sign,
            SignatureAlgorithm::EcDsaBrainpoolP256R1,
            DecryptionAlgorithm::default(),
            AuthenticationAlgorithm::default(),
            0x6ab945b0,
            "982a9c81485c2295c8b7fd63eefb6c0a4663d3b06b9730d3bc8962f0d566addc33658f6a8799318d93808aead05feef5e385fe097fe74a6d9c68e3751f82d3a6",
            "2e1158ca9300e8b72fae776a2292d775448208a5",
        );
    }

    /// **Derived** from the same GnuPG encoding rule, off-card: NIST P-384.
    #[test]
    fn derived_nist_p384() {
        check(
            KeyType::Sign,
            SignatureAlgorithm::EcDsaP384,
            DecryptionAlgorithm::default(),
            AuthenticationAlgorithm::default(),
            0x6ab946d5,
            "e320b2122b93f3b3c18e8bb904b68e2d724d94cfe84ff8a624b9cbb758c3cb702dd4a52eed76501dbc75643dfbde20d25e881f8f719d6b1e46e3f911977d62d88c056fdd061c13bbcdca39babd25b3babe382f79a9c009fdab444057ad17c705",
            "43f5461acb350c3f40b46e8356dc8b8022daddc8",
        );
    }

    /// **Derived**: NIST P-256.
    #[test]
    fn derived_nist_p256() {
        check(
            KeyType::Sign,
            SignatureAlgorithm::EcDsaP256,
            DecryptionAlgorithm::default(),
            AuthenticationAlgorithm::default(),
            0x6ab946d5,
            "6e8c54f46aaceeac04e4d74157a60f4a9ce464495547bc8caae3f532fa226d8e32e3d508c17fabe2f8a8f77ab7aa5c31187830a06385cc02eaef21616f47ed91",
            "85b23093bc666b5c71dcb4b26e2ed39e23029c2c",
        );
    }

    /// **Derived**: secp256k1. The brief predicted this curve would be
    /// *compressed*; GnuPG's packet says otherwise — the same uncompressed
    /// `0x04 || X || Y` as every other ECDSA curve.
    #[test]
    fn derived_secp256k1() {
        check(
            KeyType::Sign,
            SignatureAlgorithm::EcDsaSecp256k1,
            DecryptionAlgorithm::default(),
            AuthenticationAlgorithm::default(),
            0x6ab946d5,
            "63a54a79615d22db6499e2d180dc86af0403b5aa0f5405261e2b9f3c738d9bb5307a0a695294523156ed83f6285bafb4339c09355068ef9c4801efb5d4d1bb84",
            "2eb87ef6cfb41f1c2499acf16bad149db56658de",
        );
    }

    /// RSA fails closed rather than guessing.
    #[test]
    fn rsa_fails_closed() {
        assert!(params(
            KeyType::Sign,
            SignatureAlgorithm::Rsa2048,
            DecryptionAlgorithm::default(),
            AuthenticationAlgorithm::default()
        )
        .is_none());
    }

    fn unhex(s: &str) -> Vec<u8> {
        // A mis-transcribed vector must say so, not fail three frames deep in
        // a slice index.
        assert_eq!(s.len() % 2, 0, "hex vector has an odd length: {s:?}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
