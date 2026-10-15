//! BIP-340 conformance of the live applet signer (`apps/nostr/src/crypto.rs`)
//! against the full reference vector set, plus adversarial edges.

use audit_secp256kfun::crypto;
use subtle::ConstantTimeEq;
use secp256kfun::{
    marker::{EvenY, NonZero, Public, Zero},
    g, G, Point, Scalar,
};
use sha2::{Digest, Sha256};

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// An in-probe BIP-340 verifier built on the same primitives the applet uses
/// (the applet itself is sign-only). Verdicts are cross-checked against the
/// CSV and against the python oracle's independent implementation.
fn bip340_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Some(P) = Point::<EvenY, Public, NonZero>::from_xonly_bytes(*pk) else {
        return false;
    };
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    let Some(s) = Scalar::<Public, NonZero>::from_bytes(s_bytes) else {
        return false;
    };
    let e_bytes = tagged_hash(b"BIP0340/challenge", &[&sig[..32], pk, msg]);
    let e = Scalar::<Public, Zero>::from_bytes_mod_order(e_bytes);
    let R = g!(s * G - e * P).normalize().non_zero();
    match R {
        Some(r) => r.is_y_even()
            && r.coordinates().0.ct_eq(&{
                let mut rx = [0u8; 32];
                rx.copy_from_slice(&sig[..32]);
                rx
            }).into(),
        None => false,
    }
}

const N_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
    0x41, 0x41,
];
const N_PLUS_1_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
    0x41, 0x42,
];
const ALL_FF: [u8; 32] = [0xFF; 32];

struct Row {
    index: u32,
    sk: Option<[u8; 32]>,
    pk: [u8; 32],
    aux: [u8; 32],
    msg: Vec<u8>,
    sig: [u8; 64],
    verdict: bool,
}

fn load_csv() -> Vec<Row> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../spike-secp256kfun/vectors/bip340.csv"
    );
    let text = std::fs::read_to_string(path).expect("bip340.csv present");
    let mut rows = Vec::new();
    for (i, line) in text.lines().skip(1).enumerate() {
        let f: Vec<&str> = line.split(',').collect();
        assert!(f.len() >= 7, "row {i}: {line}");
        let hex32 = |s: &str| {
            let mut out = [0u8; 32];
            for (j, b) in s.as_bytes().chunks(2).enumerate() {
                out[j] = u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap();
            }
            out
        };
        let hex64 = |s: &str| {
            let mut out = [0u8; 64];
            for (j, b) in s.as_bytes().chunks(2).enumerate() {
                out[j] = u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap();
            }
            out
        };
        let msg = {
            let bytes = f[4].as_bytes();
            (0..bytes.len() / 2)
                .map(|j| u8::from_str_radix(&f[4][2 * j..2 * j + 2], 16).unwrap())
                .collect::<Vec<u8>>()
        };
        rows.push(Row {
            index: f[0].parse().unwrap(),
            sk: if f[1].len() == 64 { Some(hex32(f[1])) } else { None },
            pk: hex32(f[2]),
            aux: hex32(f[3]),
            msg,
            sig: hex64(f[5]),
            verdict: f[6] == "TRUE",
        });
    }
    rows
}

#[test]
fn every_valid_row_reproduces_the_reference_signature_byte_for_byte() {
    let mut checked = 0;
    for row in load_csv() {
        let Some(sk) = row.sk else { continue };
        if !crypto::scalar_valid(&sk) {
            continue; // invalid-key rows are handled by the refusal test
        }
        let sig = crypto::bip340_sign(&sk, &row.msg, &row.aux)
            .unwrap_or_else(|| panic!("row {}: valid key must sign", row.index));
        assert_eq!(
            sig, row.sig,
            "row {}: applet signature diverges from the reference",
            row.index
        );
        checked += 1;
    }
    assert!(checked >= 8, "expected >= 8 sign rows, checked {checked}");
}

/// The reference CSV carries no sign-side invalid-key rows (its refusal rows
/// are verify-only, with an empty sk column). The d' bounds are pinned
/// against the signer directly by `scalar_edges_are_exactly_the_bip340_bounds`;
/// here we pin the CSV shape itself so a future vector refresh that adds
/// sign-refusal rows cannot silently pass through the skip above.
#[test]
fn csv_shape_verify_only_refusal_rows_have_no_secret_key() {
    let mut no_sk = 0;
    let mut invalid_sk = 0;
    for row in load_csv() {
        match row.sk {
            None => no_sk += 1,
            Some(sk) => {
                if !crypto::scalar_valid(&sk) {
                    invalid_sk += 1;
                    assert!(crypto::bip340_sign(&sk, &row.msg, &row.aux).is_none());
                }
            }
        }
    }
    assert!(no_sk >= 3, "expected >= 3 verify-only rows, got {no_sk}");
    // If a future refresh adds sign-refusal rows they are exercised above;
    // today the reference set has none.
    assert_eq!(invalid_sk, 0, "unexpected sign-refusal rows present");
}

#[test]
fn derived_npub_matches_the_pk_column_for_every_signable_row() {
    for row in load_csv() {
        let Some(sk) = row.sk else { continue };
        if !crypto::scalar_valid(&sk) {
            continue;
        }
        assert_eq!(
            crypto::xonly_pubkey(&sk).unwrap(),
            row.pk,
            "row {}: xonly_pubkey != CSV public key",
            row.index
        );
    }
}

#[test]
fn in_probe_verifier_agrees_with_every_csv_verdict() {
    for row in load_csv() {
        assert_eq!(
            bip340_verify(&row.pk, &row.msg, &row.sig),
            row.verdict,
            "row {}: verifier verdict != CSV verdict ({})",
            row.index,
            row.verdict
        );
    }
}

/// Edge scalars around the curve order — the BIP-340 `d'` bounds.
#[test]
fn scalar_edges_are_exactly_the_bip340_bounds() {
    let zero = [0u8; 32];
    let one = {
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    };
    let n_minus_1 = {
        let mut b = N_BYTES;
        let (carry, _) = b
            .iter_mut()
            .rev()
            .fold((1u16, 0usize), |(c, _), byte| {
                let v = *byte as u16;
                let (nb, borrow) = (v.wrapping_sub(c as u16), (v < c) as u16);
                *byte = nb as u8;
                (borrow, 0)
            });
        debug_assert!(carry == 0);
        b
    };
    assert!(!crypto::scalar_valid(&zero), "0 must be refused");
    assert!(crypto::scalar_valid(&one), "1 must be accepted");
    assert!(crypto::scalar_valid(&n_minus_1), "n-1 must be accepted");
    assert!(!crypto::scalar_valid(&N_BYTES), "n must be refused");
    assert!(!crypto::scalar_valid(&N_PLUS_1_BYTES), "n+1 must be refused");
    assert!(!crypto::scalar_valid(&ALL_FF), "2^256-1 must be refused");
    // and signing agrees with validation
    let msg = [0u8; 32];
    let aux = [0u8; 32];
    for bad in [&zero, &N_BYTES, &N_PLUS_1_BYTES, &ALL_FF] {
        assert!(crypto::bip340_sign(bad, &msg, &aux).is_none());
    }
    assert!(crypto::bip340_sign(&one, &msg, &aux).is_some());
}

/// x-only lift edges: zero, the field modulus, non-residues, valid keys.
#[test]
fn xonly_edges_are_rejected_and_accepted_exactly_on_membership() {
    use audit_secp256kfun::nip44;
    assert!(nip44::lift_xonly(&[0u8; 32]).is_none(), "x = 0 refused");
    // p = 2^256 - 2^32 - 977, encoded big-endian
    let p_bytes = {
        let mut b = [0xFFu8; 32];
        b[29] = 0xFF;
        b[30] = 0xFC;
        b[31] = 0x2F;
        b
    };
    assert!(
        nip44::lift_xonly(&p_bytes).is_none(),
        "x = p (>= p after limb check) refused"
    );
    // a non-residue x: search upward from 2 until lift_xonly refuses
    let non_residue = (1u64..)
        .map(|i| {
            let mut b = [0u8; 32];
            b[24..32].copy_from_slice(&((1u64 << 56) + i).to_be_bytes());
            b
        })
        .find(|x| nip44::lift_xonly(x).is_none())
        .expect("non-residues are half the field");
    assert!(nip44::lift_xonly(&non_residue).is_none());
    // G.x is a residue and lifts fine
    let gx: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];
    assert!(nip44::lift_xonly(&gx).is_some());
}

/// Same (sk, msg, aux) => same signature; different aux => different R.
#[test]
fn deterministic_with_aux_and_aux_sensitive() {
    let sk = {
        let mut b = [0u8; 32];
        b[31] = 0x0B; // arbitrary valid key
        b
    };
    let msg = tagged_hash(b"audit/msg", &[b"determinism"]);
    let aux = tagged_hash(b"audit/aux", &[b"determinism"]);
    let s1 = crypto::bip340_sign(&sk, &msg, &aux).unwrap();
    let s2 = crypto::bip340_sign(&sk, &msg, &aux).unwrap();
    assert_eq!(s1, s2, "same inputs must be byte-identical");
    let aux2 = tagged_hash(b"audit/aux", &[b"other"]);
    let s3 = crypto::bip340_sign(&sk, &msg, &aux2).unwrap();
    assert_ne!(s1[..32], s3[..32], "aux must move R");
    // and both signatures verify against the same key
    let pk = crypto::xonly_pubkey(&sk).unwrap();
    assert!(bip340_verify(&pk, &msg, &s1));
    assert!(bip340_verify(&pk, &msg, &s3));
}

/// A pool-simulated aux stream (the shape the device RNG seam produces) must
/// never produce a repeated R over a signing session.
#[test]
fn no_nonce_repetition_over_a_session_sweep() {
    use std::collections::HashSet;
    let sk = {
        let mut b = [0u8; 32];
        b[31] = 0x2A;
        b
    };
    let mut seen = HashSet::new();
    for i in 0u64..2000 {
        let aux = tagged_hash(b"audit/pool", &[i.to_be_bytes().as_slice()]);
        let msg = tagged_hash(b"audit/msg", &[i.to_be_bytes().as_slice()]);
        let sig = crypto::bip340_sign(&sk, &msg, &aux).unwrap();
        assert!(
            seen.insert(sig[..32].to_vec()),
            "R repeated at iteration {i}"
        );
    }
}

/// Fuzzing the signer's arithmetic with hostile message shapes: 0-byte and
/// maximal messages, and messages with every byte 0xFF, must all produce
/// verifiable signatures or a clean refusal — never a panic.
#[test]
fn hostile_message_shapes_never_panic_and_verify() {
    let sk = {
        let mut b = [0u8; 32];
        b[31] = 0x11;
        b
    };
    let pk = crypto::xonly_pubkey(&sk).unwrap();
    let aux = [0u8; 32];
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xFF; 1],
        vec![0x00; 32],
        vec![0xFF; 32],
        vec![0xFF; 100],
        vec![0x00; 4096],
    ];
    for msg in &cases {
        if let Some(sig) = crypto::bip340_sign(&sk, msg, &aux) {
            assert!(bip340_verify(&pk, msg, &sig), "signature over {msg:?} must verify");
        }
    }
}
