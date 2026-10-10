//! US-1654/US-1655/US-1656 — the NIP-44 command arms (`NIP44_ENCRYPT`
//! `0x16`, `NIP44_DECRYPT` `0x17`) over the applet's process path.
//!
//! The primitive layer's vectors live in `nip44.rs`; what the command layer
//! adds is the wire's own decisions: the applet's `MAX_PLAINTEXT` cap
//! (§2.2.1), the device-generated nonce, the refusal order (shape → state →
//! key validation → touch — a press is never spent on an invalid key),
//! `6A80`/`6A87`/`6B00` on hostile bytes, and the round-trip through both
//! arms with the device's own nonce.

use fapico2_nostr::{
    crypto, nip44, NostrApp, INS_NIP44_DECRYPT, INS_NIP44_ENCRYPT, SW_ECC_UNSUPPORTED,
    SW_INVALID_PEER_KEY, MAX_PLAINTEXT,
};
use fapico2_platform::dispatch::{App, Sw, SW_OK};
use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{NostrIdentity, NostrRegion};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use heapless::Vec as HeaplessVec;

#[allow(dead_code, non_upper_case_globals)]
mod vectors {
    include!("nip44_vectors.rs");
}
use vectors::{CONV_KEY_INVALID, CONV_KEY_VECTORS};

// ---------------------------------------------------------------------------
// Fixtures (the keymgmt set, mirrored — test files do not name each other)
// ---------------------------------------------------------------------------

fn region_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fapico2-nostr-us1654-{tag}-{}.bin",
        std::process::id()
    ))
}

fn fixture_key(region: FileKeyRegion) -> NostrRegion {
    let otp_row: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));
    let chipid: [u8; 8] = 0x0000_BADC_0FFE_EE01_0203_u64.to_be_bytes();
    let key = derive_payload_key(&otp_row, &chipid, &NOSTR_PAYLOAD_SECRET)
        .expect("a non-zero OTP row");
    NostrRegion::new(Box::new(region), key)
}

fn fixture_region(path: &std::path::Path) -> NostrRegion {
    let region = FileKeyRegion::create(path, TOTAL_SLOTS).expect("a fresh region file");
    fixture_key(region)
}

fn open_region(path: &std::path::Path) -> NostrRegion {
    let region = FileKeyRegion::open(path).expect("an existing region file");
    fixture_key(region)
}

/// The seeded identity's scalar — every test derives the conversation key
/// from it directly.
fn seed_scalar() -> [u8; 32] {
    core::array::from_fn(|i| 0x21u8.wrapping_add(i as u8))
}

/// An applet whose slot 0 holds a known identity, booted from a reopened
/// region (the store's own commit path, not a fixture shortcut).
fn seeded_app(tag: &str) -> (NostrApp, std::path::PathBuf, [u8; 32]) {
    let path = region_path(tag);
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let scalar = seed_scalar();
        let npub = crypto::xonly_pubkey(&scalar).expect("a valid seed scalar");
        let id = NostrIdentity::new(scalar, npub, b"seed", 0).expect("a valid identity");
        region.store().write(0, &id).expect("seed slot 0");
    }
    let app = NostrApp::boot(open_region(&path));
    (app, path, seed_scalar())
}

/// Drive one APDU through the applet, returning (data, SW).
fn call(app: &mut NostrApp, apdu: &[u8]) -> (HeaplessVec<u8, 4096>, Sw) {
    let mut resp = HeaplessVec::new();
    app.process(apdu, &mut resp);
    assert!(resp.len() >= 2, "the applet must always answer with a status word");
    let n = resp.len();
    let sw = u16::from_be_bytes([resp[n - 2], resp[n - 1]]);
    let data: HeaplessVec<u8, 4096> = resp[..n - 2].iter().copied().collect();
    (data, sw)
}

/// Extended-Lc APDU — the encrypt request carries up to 1,933 bytes of
/// data, which the short form cannot express.
fn apdu_ext(ins: u8, p1: u8, p2: u8, data: &[u8]) -> HeaplessVec<u8, 2300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, ins, p1, p2, 0x00]).unwrap();
    a.extend_from_slice(&(data.len() as u16).to_be_bytes()).unwrap();
    a.extend_from_slice(data).unwrap();
    a
}

/// The first conversation-key vector's peer key — a valid curve point.
fn peer_x() -> [u8; 32] {
    CONV_KEY_VECTORS[0].peer_x
}

// ---------------------------------------------------------------------------
// NIP44_ENCRYPT
// ---------------------------------------------------------------------------

/// The device answer is a spec-shaped payload (`0x02 ‖ nonce ‖ ct ‖ mac`)
/// that decrypts — under the conversation key derived from the identity's
/// scalar and the SAME peer key — back to the exact plaintext.
#[test]
fn encrypt_produces_a_decryptable_spec_payload() {
    let (mut app, path, scalar) = seeded_app("encrypt-roundtrip");
    let plaintext = b"hello, device";
    let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
    req.extend_from_slice(&peer_x()).unwrap();
    req.extend_from_slice(plaintext).unwrap();
    let (data, sw) = call(&mut app, &apdu_ext(INS_NIP44_ENCRYPT, 0, 0, &req));
    std::fs::remove_file(&path).ok();
    assert_eq!(sw, SW_OK);
    // version(1) ‖ nonce(32) ‖ ct(2 + 32) ‖ mac(32)
    assert_eq!(data[0], 0x02, "the v2 version byte leads");
    assert_eq!(data.len(), 99);

    // Round-trip through the primitive with the identity's scalar.
    let ck = nip44::conversation_key(&scalar, &peer_x()).unwrap();
    let mut pt = [0u8; 256];
    let n = nip44::decrypt_with_ck(&ck, &data, &mut pt).expect("the device payload decrypts");
    assert_eq!(&pt[..n], plaintext);
}

/// The §2.2.1 cap is the applet's own `MAX_PLAINTEXT`: 1,900 bytes is the
/// boundary (in), 1,901 is refused (`6A80`).
#[test]
fn encrypt_enforces_the_applet_plaintext_cap() {
    let (mut app, path, _scalar) = seeded_app("encrypt-cap");
    let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
    req.extend_from_slice(&peer_x()).unwrap();
    req.extend_from_slice(&[0x61u8; MAX_PLAINTEXT as usize]).unwrap();
    let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_ENCRYPT, 0, 0, &req));
    assert_eq!(sw, SW_OK, "the boundary plaintext encrypts");
    req.truncate(32 + 1);
    req.extend_from_slice(&[0x61u8; MAX_PLAINTEXT as usize]).unwrap();
    let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_ENCRYPT, 0, 0, &req));
    std::fs::remove_file(&path).ok();
    assert_eq!(sw, 0x6A80, "one byte over the cap is wrong data");
}

/// The nonce is the device's, not the host's: two encrypts of the same
/// plaintext produce different payloads (the device RNG never repeats a
/// draw for two requests) — the property that makes nonce reuse a device
/// bug rather than a host one.
#[test]
fn encrypt_draws_a_fresh_nonce_per_request() {
    let (mut app, path, _scalar) = seeded_app("encrypt-nonce");
    let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
    req.extend_from_slice(&peer_x()).unwrap();
    req.extend_from_slice(b"same plaintext").unwrap();
    let (first, sw1) = call(&mut app, &apdu_ext(INS_NIP44_ENCRYPT, 0, 0, &req));
    let (second, sw2) = call(&mut app, &apdu_ext(INS_NIP44_ENCRYPT, 0, 0, &req));
    std::fs::remove_file(&path).ok();
    assert_eq!((sw1, sw2), (SW_OK, SW_OK));
    assert_ne!(first[..33], second[..33], "the nonces must differ");
}

#[test]
fn encrypt_on_an_empty_slot_is_6a82() {
    let (mut app, path, _scalar) = seeded_app("encrypt-empty");
    let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
    req.extend_from_slice(&peer_x()).unwrap();
    req.extend_from_slice(b"x").unwrap();
    let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_ENCRYPT, 5, 0, &req));
    std::fs::remove_file(&path).ok();
    assert_eq!(sw, 0x6A82);
}

// ---------------------------------------------------------------------------
// NIP44_DECRYPT
// ---------------------------------------------------------------------------

/// A payload built with the reference primitive, addressed to the seeded
/// identity, decrypts to the exact plaintext.
#[test]
fn decrypt_round_trips_a_reference_payload() {
    let (mut app, path, scalar) = seeded_app("decrypt-roundtrip");
    let ck = nip44::conversation_key(&scalar, &peer_x()).unwrap();
    let mut payload = vec![0u8; nip44::MAX_PAYLOAD];
    let n = nip44::encrypt_with_ck(&ck, &[0xA7u8; 32], b"from the host", &mut payload).unwrap();
    let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
    req.extend_from_slice(&peer_x()).unwrap();
    req.extend_from_slice(&payload[..n]).unwrap();
    let (data, sw) = call(&mut app, &apdu_ext(INS_NIP44_DECRYPT, 0, 0, &req));
    std::fs::remove_file(&path).ok();
    assert_eq!(sw, SW_OK);
    assert_eq!(&data[..], b"from the host");
}

/// US-1655's `mac_comparison_is_constant_time`: a single-bit MAC mutation
/// is refused. The comparison is `hmac::Mac::verify_slice`
/// (`apps/nostr/src/nip44.rs`, `decrypt_with_ck`) — never `==` on the
/// digest, which is the botch the spec's vectors cannot detect (every
/// reference vector verifies under both) and the one this test documents.
#[test]
fn mac_comparison_is_constant_time() {
    let (mut app, path, scalar) = seeded_app("decrypt-mac");
    let ck = nip44::conversation_key(&scalar, &peer_x()).unwrap();
    let mut payload = vec![0u8; nip44::MAX_PAYLOAD];
    let n = nip44::encrypt_with_ck(&ck, &[0xA7u8; 32], b"authed", &mut payload).unwrap();
    let mut mutated = payload[..n].to_vec();
    mutated[n - 1] ^= 0x01; // one bit of the MAC
    let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
    req.extend_from_slice(&peer_x()).unwrap();
    req.extend_from_slice(&mutated).unwrap();
    let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_DECRYPT, 0, 0, &req));
    std::fs::remove_file(&path).ok();
    assert_eq!(sw, 0x6A80, "a mutated MAC is wrong data, never a decryption");
}

/// Hostile payloads are refused with a **defined** status word and never
/// slice out of range: the zero prefix, the 6-byte (u32) prefix form the
/// §2.2.1 cap makes unreachable, a payload under the spec's 99-byte floor,
/// a truncated payload, and one above the legal maximum.
#[test]
fn decrypt_hostile_payloads_are_defined_refusals() {
    let (mut app, path, scalar) = seeded_app("decrypt-hostile");
    let ck = nip44::conversation_key(&scalar, &peer_x()).unwrap();
    let mut payload = vec![0u8; nip44::MAX_PAYLOAD];
    let n = nip44::encrypt_with_ck(&ck, &[0xA7u8; 32], b"legit", &mut payload).unwrap();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        // The zero prefix: two zero length bytes are never mis-parsed as a
        // longer form — the version byte alone refuses it.
        ("zero prefix", vec![0x00u8; 99]),
        // The 6-byte (u32) prefix form: a payload whose ciphertext opens
        // with the would-be u32 length bytes — same version byte, and the
        // MAC over it cannot verify, so it is wrong data, never parsed.
        (
            "6-byte prefix",
            {
                let mut p = payload[..n].to_vec();
                p[33..39].copy_from_slice(&[0x02, 0x00, 0x00, 0x01, 0x00, 0x00]);
                p
            },
        ),
        // Under the spec's 99-byte floor.
        ("truncated", payload[..50].to_vec()),
    ];
    for (note, payload) in cases {
        let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
        req.extend_from_slice(&peer_x()).unwrap();
        req.extend_from_slice(&payload).unwrap();
        let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_DECRYPT, 0, 0, &req));
        assert_eq!(sw, 0x6A80, "{note} must be a defined 6A80");
    }
    // Above the legal maximum: one byte past the largest payload the
    // §2.2.1 cap could produce.
    let oversized = vec![0x02u8; 33 + 2 + 2048 + 32 + 1];
    let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
    req.extend_from_slice(&peer_x()).unwrap();
    req.extend_from_slice(&oversized).unwrap();
    let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_DECRYPT, 0, 0, &req));
    std::fs::remove_file(&path).ok();
    assert_eq!(sw, 0x6A80, "above the legal maximum is wrong data");
}

// ---------------------------------------------------------------------------
// Curve-point validation (US-1656)
// ---------------------------------------------------------------------------

/// Zero, non-curve, and the ECC form are each refused on **both**
/// commands. The refusals come before the touch (asserted separately
/// below), so no press is spent on a key the device will not use.
#[test]
fn peer_x_must_be_a_valid_curve_point() {
    let (mut app, path, _scalar) = seeded_app("peer-x-validation");
    let zero = [0u8; 32];
    let non_curve = CONV_KEY_INVALID[0].peer_x; // "sec1 higher than curve.n"
    let ecc_form: [u8; 32] = {
        let mut x = [0u8; 32];
        x[..3].copy_from_slice(&[0xF9, 0x30, 0x8A]);
        x
    };
    for (note, key, expected) in [
        ("zero x", zero, SW_INVALID_PEER_KEY),
        ("non-curve x", non_curve, SW_INVALID_PEER_KEY),
        ("ECC form", ecc_form, SW_ECC_UNSUPPORTED),
    ] {
        // ENCRYPT: the key is the peer.
        let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
        req.extend_from_slice(&key).unwrap();
        req.extend_from_slice(b"x").unwrap();
        let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_ENCRYPT, 0, 0, &req));
        assert_eq!(sw, expected, "ENCRYPT {note}");
        // DECRYPT: the key is the sender, in a well-shaped payload.
        let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
        req.extend_from_slice(&key).unwrap();
        req.extend_from_slice(&[0u8; 99]).unwrap();
        let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_DECRYPT, 0, 0, &req));
        assert_eq!(sw, expected, "DECRYPT {note}");
    }
    std::fs::remove_file(&path).ok();
}

/// Validation is request-shaped, so it precedes the touch: with a denying
/// presence grant, an invalid key still answers `6A87`/`6B00`, not `6985`
/// — a press is never the price of learning a key is bad.
#[test]
fn validation_precedes_the_touch() {
    let (app, path, _scalar) = seeded_app("peer-x-before-touch");
    let mut app = app.with_presence_grant(|_| false);
    let ecc_form: [u8; 32] = {
        let mut x = [0u8; 32];
        x[..3].copy_from_slice(&[0xF9, 0x30, 0x8A]);
        x
    };
    let mut req: HeaplessVec<u8, 2300> = HeaplessVec::new();
    req.extend_from_slice(&ecc_form).unwrap();
    req.extend_from_slice(b"x").unwrap();
    let (_, sw) = call(&mut app, &apdu_ext(INS_NIP44_ENCRYPT, 0, 0, &req));
    std::fs::remove_file(&path).ok();
    assert_eq!(sw, SW_ECC_UNSUPPORTED, "not 6985 — the key is refused first");
}
