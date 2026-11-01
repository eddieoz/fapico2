//! US-1741 — `touch_bypass`: a RAM flag that exempts exactly SIGN, NIP44
//! ENC and NIP44 DEC from the touch (EPIC NOSTR-TOUCH-BYPASS, Phase 1).
//!
//! The invariant the file pins: the bypass is a *signing-only* exemption.
//! While the flag stands the three signing arms skip `user_present`, and
//! the four key-management sites (GENERATE, IMPORT, SET_LABEL, DELETE)
//! demand the touch exactly as before — the flag changes nothing about
//! them. Default state is `false` at every boot: a freshly booted applet
//! touches as it always did.
//!
//! The flag is set here through the host-only state seam
//! (`set_touch_bypass`) because the wire verb that sets it lives in
//! US-1742/US-1743 — these tests pin the *gate's* semantics, not the
//! verb's. RED until the flag and the gate exist.

use fapico2_nostr::{
    crypto, NostrApp, INS_DELETE_KEY, INS_GENERATE_KEY, INS_GET_PUBKEY, INS_LIST_KEYS,
    INS_NIP44_DECRYPT, INS_NIP44_ENCRYPT, INS_SIGN, SW_TOUCH_REQUIRED,
};
use fapico2_platform::dispatch::{App, Sw, SW_OK};
use fapico2_platform::keyregion::crypto::{derive_payload_key, NOSTR_PAYLOAD_SECRET};
use fapico2_platform::keyregion::host::FileKeyRegion;
use fapico2_platform::keyregion::nostr_store::{NostrIdentity, NostrRegion};
use fapico2_platform::keyregion::TOTAL_SLOTS;
use heapless::Vec as HeaplessVec;

// ---------------------------------------------------------------------------
// Fixtures (the presence.rs set, mirrored — test files do not name each other)
// ---------------------------------------------------------------------------

fn region_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fapico2-nostr-us1741-{tag}-{}.bin",
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

/// The seeded identity's scalar — SIGN's fixture signs with it, and the
/// BIP-340 verify below re-derives its public key.
fn seed_scalar() -> [u8; 32] {
    core::array::from_fn(|i| 0x21u8.wrapping_add(i as u8))
}

/// An applet whose slot 1 holds a live identity (the presence.rs shape:
/// SIGN's state refusals must all have passed before the touch is asked).
fn app_with_identity(tag: &str) -> (NostrApp, std::path::PathBuf) {
    let path = region_path(tag);
    std::fs::remove_file(&path).ok();
    {
        let mut region = fixture_region(&path);
        let scalar = seed_scalar();
        let npub = crypto::xonly_pubkey(&scalar).expect("a valid seed scalar");
        let id = NostrIdentity::new(scalar, npub, b"seed", 0).expect("a valid identity");
        region.store().write(1, &id).expect("seed slot 1");
    }
    let app = NostrApp::boot(open_region(&path));
    (app, path)
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

fn apdu(ins: u8, p1: u8, data: &[u8]) -> HeaplessVec<u8, 300> {
    let mut a = HeaplessVec::new();
    a.extend_from_slice(&[0x00, ins, p1, 0x00]).unwrap();
    a.push(data.len() as u8).unwrap();
    a.extend_from_slice(data).unwrap();
    a
}

fn apdu_sign(idx: u8) -> HeaplessVec<u8, 300> {
    apdu(INS_SIGN, idx, &[0x5A; 32])
}

/// A valid curve point that is not the identity — the NIP-44 peer.
fn peer_x() -> [u8; 32] {
    let peer_scalar: [u8; 32] = core::array::from_fn(|i| 0x71u8.wrapping_add(i as u8));
    crypto::xonly_pubkey(&peer_scalar).expect("a valid peer scalar")
}

fn apdu_nip44_encrypt(idx: u8, plaintext: &[u8]) -> HeaplessVec<u8, 300> {
    let mut d = Vec::new();
    d.extend_from_slice(&peer_x());
    d.extend_from_slice(plaintext);
    apdu(INS_NIP44_ENCRYPT, idx, &d)
}

fn apdu_nip44_decrypt(idx: u8, payload: &[u8]) -> HeaplessVec<u8, 300> {
    let mut d = Vec::new();
    d.extend_from_slice(&peer_x());
    d.extend_from_slice(payload);
    apdu(INS_NIP44_DECRYPT, idx, &d)
}

// ---------------------------------------------------------------------------
// BIP-340 verification — the sign story's "the signature verifies" claim,
// an independent re-derivation (the applet signs; this file checks).
// ---------------------------------------------------------------------------

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// BIP-340 verification: `s·G = R + e·P` with `R.x == r` and `R` even-y.
#[allow(non_snake_case)]
fn bip340_verify(px: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> bool {
    use secp256kfun::{
        g,
        marker::{EvenY, NonZero, Public, Zero},
        G, Point, Scalar,
    };
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    let mut s_b = [0u8; 32];
    s_b.copy_from_slice(&sig[32..]);
    let Some(P) = Point::<EvenY, Public, NonZero>::from_xonly_bytes(*px) else {
        return false;
    };
    let Some(s) = Scalar::<Public, NonZero>::from_bytes(s_b) else {
        return false;
    };
    let e_bytes = tagged_hash(b"BIP0340/challenge", &[&r, px, msg]);
    let e = Scalar::<Public, Zero>::from_bytes_mod_order(e_bytes);
    let Some(R) = g!(s * G - e * P).normalize().non_zero() else {
        return false;
    };
    let (rx, _) = R.coordinates();
    rx == r && R.is_y_even()
}

// ---------------------------------------------------------------------------
// US-1741 acceptance
// ---------------------------------------------------------------------------

/// **Bypass on — SIGN answers without a presence grant**: the reply is SW_OK
/// and the signature verifies against the identity's public key.
#[test]
#[ignore = "US-1741 RED: the touch_bypass flag does not exist yet"]
fn bypass_on_sign_answers_without_a_presence_grant() {
    let (app, path) = app_with_identity("sign-bypass");
    let mut app = app
        .with_presence_grant(|_| false)
        .with_rng_provider(|out| out.fill(0x42));
    app.set_touch_bypass(true);
    let (data, sw) = call(&mut app, &apdu_sign(1));
    assert_eq!(sw, SW_OK, "a bypassed SIGN needs no press");
    assert_eq!(data.len(), 64, "npub(32) ‖ sig(64)");
    let npub = crypto::xonly_pubkey(&seed_scalar()).unwrap();
    assert_eq!(&data[..32], &npub[..], "the answer names the signing key");
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&data[32..]);
    let msg = [0x5A; 32];
    assert!(
        bip340_verify(&npub, &msg, &sig),
        "the signature verifies under BIP-340"
    );
    std::fs::remove_file(&path).ok();
}

/// **Bypass on — NIP44 ENC and DEC answer without a presence grant**: both
/// arms run with the grant denied, and the decrypt of the device's own
/// payload returns the exact plaintext.
#[test]
#[ignore = "US-1741 RED: the touch_bypass flag does not exist yet"]
fn bypass_on_nip44_enc_and_dec_answer_without_a_presence_grant() {
    let (app, path) = app_with_identity("nip44-bypass");
    let mut app = app
        .with_presence_grant(|_| false)
        .with_rng_provider(|out| out.fill(0x42));
    app.set_touch_bypass(true);
    let plaintext = b"ten events, one touch";
    let (data, sw) = call(&mut app, &apdu_nip44_encrypt(1, plaintext));
    assert_eq!(sw, SW_OK, "a bypassed NIP44 ENC needs no press");
    let (_, sw) = call(&mut app, &apdu_nip44_decrypt(1, &data));
    assert_eq!(sw, SW_OK, "a bypassed NIP44 DEC needs no press");
    std::fs::remove_file(&path).ok();
}

/// **Bypass on — GENERATE still demands the touch**, and no slot is written.
#[test]
#[ignore = "US-1741 RED: the touch_bypass flag does not exist yet"]
fn bypass_on_generate_still_demands_the_touch() {
    let (app, path) = app_with_identity("generate-bypass");
    let mut app = app.with_presence_grant(|_| false);
    app.set_touch_bypass(true);
    let (_, sw) = call(&mut app, &apdu(INS_GENERATE_KEY, 2, &[]));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "GENERATE never skips the touch");
    // No slot written: the only live identity is still slot 1.
    let (data, sw) = call(&mut app, &apdu(INS_LIST_KEYS, 0, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(data[0], 1, "the refused GENERATE wrote nothing");
    std::fs::remove_file(&path).ok();
}

/// **Bypass on — DELETE still demands the touch**, and the identity survives.
#[test]
#[ignore = "US-1741 RED: the touch_bypass flag does not exist yet"]
fn bypass_on_delete_still_demands_the_touch() {
    let (app, path) = app_with_identity("delete-bypass");
    let mut app = app.with_presence_grant(|_| false);
    app.set_touch_bypass(true);
    let (_, sw) = call(&mut app, &apdu(INS_DELETE_KEY, 1, &[]));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "DELETE never skips the touch");
    let (_, sw) = call(&mut app, &apdu(INS_GET_PUBKEY, 1, &[]));
    assert_eq!(sw, SW_OK, "the identity survives the refused delete");
    std::fs::remove_file(&path).ok();
}

/// **Bypass off — default state touches as today**: a freshly booted applet
/// has the flag down and SIGN without a grant answers 6985.
#[test]
#[ignore = "US-1741 RED: the touch_bypass flag does not exist yet"]
fn bypass_off_default_state_touches_as_today() {
    let (app, path) = app_with_identity("default-off");
    let mut app = app.with_presence_grant(|_| false);
    assert!(
        !app.touch_bypass(),
        "the flag is false at every boot by default"
    );
    let (_, sw) = call(&mut app, &apdu_sign(1));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "the default state demands the touch");
    std::fs::remove_file(&path).ok();
}

/// **Power cycle clears it** — a fresh `NostrApp::boot` over the same region
/// comes up with the flag down, SIGN demanding the grant again. (The boot
/// arm of the US-1741 Step 2 initialization; the full matrix is US-1745.)
#[test]
#[ignore = "US-1741 RED: the touch_bypass flag does not exist yet"]
fn a_fresh_boot_over_the_same_region_clears_the_flag() {
    let (app, path) = app_with_identity("boot-clears");
    let mut app = app.with_presence_grant(|_| false);
    app.set_touch_bypass(true);
    let rebooted = NostrApp::boot(open_region(&path)).with_presence_grant(|_| false);
    assert!(
        !rebooted.touch_bypass(),
        "boot is the same as a power cycle for the RAM flag"
    );
    let mut rebooted = rebooted;
    let (_, sw) = call(&mut rebooted, &apdu_sign(1));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "SIGN demands a grant again after boot");
    std::fs::remove_file(&path).ok();
}
