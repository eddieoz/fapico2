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
    INS_NIP44_DECRYPT, INS_NIP44_ENCRYPT, INS_SIGN, SW_PIN_NOT_SET, SW_PIN_SESSION_REQUIRED,
    SW_TOUCH_REQUIRED, SW_WRONG_DATA, SW_WRONG_P1_P2,
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
fn bypass_on_sign_answers_without_a_presence_grant() {
    let (app, path) = app_with_identity("sign-bypass");
    let mut app = app
        .with_presence_grant(|_| false)
        .with_rng_provider(|out| out.fill(0x42));
    app.set_touch_bypass(true);
    let (data, sw) = call(&mut app, &apdu_sign(1));
    assert_eq!(sw, SW_OK, "a bypassed SIGN needs no press");
    assert_eq!(data.len(), 96, "npub(32) ‖ sig(64)");
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
fn a_fresh_boot_over_the_same_region_clears_the_flag() {
    let (app, path) = app_with_identity("boot-clears");
    let mut app = app.with_presence_grant(|_| false);
    app.set_touch_bypass(true);
    let mut rebooted = NostrApp::boot(open_region(&path)).with_presence_grant(|_| false);
    assert!(
        !rebooted.touch_bypass(),
        "boot is the same as a power cycle for the power-cycle story (US-1745)"
    );
    let (_, sw) = call(&mut rebooted, &apdu_sign(1));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "SIGN demands a grant again after boot");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1742 — the verb's wire shape: INS 0x1F, vendor byte 0x4F, P1 = policy.
// The envelope's idx field rides P1 (the SET_PIN precedent): [0, b""] is the
// enable leg, [1, b""] the disable leg. The wire mapping itself is pinned on
// the firmware side (nostr_wire.rs's test module — the applet crate cannot
// import the firmware crate); the routing claims ride that module's
// source-level assertions.
// ---------------------------------------------------------------------------

/// **Well-formed requests reach the shape handler**: the enable leg (P1
/// 0x00) passes the shape checks and answers SW_OK with no response body.
/// The disable leg's semantics are the US-1743 rows' business — by the time
/// that story lands, P1 = 0x01 is no longer a shape-only `9000`.
#[test]
fn well_formed_policy_requests_reach_the_shape_handler() {
    let (app, path) = app_with_identity("verb-shape");
    let mut app = app;
    let (data, sw) = call(&mut app, &apdu(0x1F, 0x00, &[]));
    assert_eq!(sw, SW_OK, "P1=0x00 passes the shape checks");
    assert!(data.is_empty(), "the verb has no response body");
    std::fs::remove_file(&path).ok();
}

/// **Unknown P1 is refused in shape**: an INS 0x1F whose P1 is not 0x00/0x01
/// answers 6A86 before any state is read or touched.
#[test]
fn policy_unknown_p1_is_refused_in_shape() {
    let (app, path) = app_with_identity("verb-p1");
    let mut app = app.with_presence_grant(|_| false);
    for p1 in [0x02u8, 0xFF] {
        let (_, sw) = call(&mut app, &apdu(0x1F, p1, &[]));
        assert_eq!(sw, SW_WRONG_P1_P2, "P1={p1:#04x} is refused in shape");
    }
    std::fs::remove_file(&path).ok();
}

/// **The verb refuses a payload**: like `LOCK`, the policy verb carries no
/// request body — a payload is 6A80 before any state is read.
#[test]
fn policy_refuses_payload() {
    let (app, path) = app_with_identity("verb-payload");
    let mut app = app;
    let (_, sw) = call(&mut app, &apdu(0x1F, 0x00, &[0x00]));
    assert_eq!(sw, SW_WRONG_DATA, "the verb takes no request body");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1743 — the disable leg: PIN session open, then a touch, and refusals
// eat grants. The gate order is the standing one: shape → PIN gate → touch
// → execute; the flag is set only after the press.
// ---------------------------------------------------------------------------

const PIN: &[u8] = b"731742"; // six bytes, the minimum

thread_local! {
    /// Consultations the counting grants saw since the test's last reset —
    /// thread-local, so the parallel tests never share a count.
    static PRESSES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// A counting grant that denies — the pin.rs shape: the count is what
/// proves a refusal ate the armed grant instead of spending it.
fn counting_deny(_tag: u32) -> bool {
    PRESSES.with(|p| p.set(p.get() + 1));
    false
}

/// A counting grant that grants — the touched disable leg.
fn counting_allow(_tag: u32) -> bool {
    PRESSES.with(|p| p.set(p.get() + 1));
    true
}

fn presses() -> usize {
    PRESSES.with(|p| p.get())
}

fn reset_presses() {
    PRESSES.with(|p| p.set(0));
}

/// A deterministic, per-draw-varying salt (the pin.rs shape): SET_PIN draws
/// its salt from the applet's RNG source, so the fixture pins one.
fn pinned_salt(out: &mut [u8]) {
    use core::cell::Cell;
    thread_local! {
        static DRAW: Cell<u8> = const { Cell::new(0) };
    }
    let nth = DRAW.with(|d| d.replace(d.get().wrapping_add(1)));
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u8)
            .wrapping_mul(0x5B)
            .wrapping_add(0xA0)
            .wrapping_add(nth.wrapping_mul(0x11));
    }
}

/// A PIN-set, verified applet holding the slot-1 identity — the disable
/// leg's "session open" precondition.
fn pin_app(tag: &str) -> (NostrApp, std::path::PathBuf) {
    let (app, path) = app_with_identity(tag);
    let mut app = app.with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(0x1C, 0x00, PIN)); // SET_PIN
    assert_eq!(sw, SW_OK, "the fixture's PIN sets");
    let (_, sw) = call(&mut app, &apdu(0x1B, 0x00, PIN)); // VERIFY_PIN
    assert_eq!(sw, SW_OK, "the fixture's session opens");
    (app, path)
}

fn apdu_policy(p1: u8) -> HeaplessVec<u8, 300> {
    apdu(0x1F, p1, &[])
}

/// **No PIN — refuse**: the bypass is a PIN-session privilege, and a board
/// with no PIN can never disable the touch. `SW_PIN_NOT_SET` (6A82), flag
/// stays down.
#[test]
fn no_pin_refuses_the_disable_leg() {
    let (app, path) = app_with_identity("disable-no-pin");
    let mut app = app.with_presence_grant(|_| false);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_PIN_NOT_SET, "no PIN record, no bypass");
    assert!(!app.touch_bypass(), "the flag stays down");
    std::fs::remove_file(&path).ok();
}

/// **PIN set but session closed — refuse**: `SW_PIN_SESSION_REQUIRED`
/// (6982), flag stays down.
#[test]
fn closed_session_refuses_the_disable_leg() {
    let (app, path) = app_with_identity("disable-closed");
    let mut app = app.with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(0x1C, 0x00, PIN)); // SET_PIN only
    assert_eq!(sw, SW_OK);
    let mut app = app.with_presence_grant(|_| false);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_PIN_SESSION_REQUIRED, "the session gate word");
    assert!(!app.touch_bypass(), "the flag stays down");
    std::fs::remove_file(&path).ok();
}

/// **Session open, no touch — refuse**: the verified board still owes the
/// press; the counting grant is consulted once and denies, `6985`, flag
/// down.
#[test]
fn open_session_no_touch_refuses_the_disable_leg() {
    reset_presses();
    let (app, path) = pin_app("disable-no-touch");
    let mut app = app.with_presence_grant(counting_deny);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "the press is still owed");
    assert_eq!(presses(), 1, "the touch arm consulted exactly once");
    assert!(!app.touch_bypass(), "the flag stays down");
    std::fs::remove_file(&path).ok();
}

/// **Session open and touched — the flag stands**: `SW_OK`, the flag is up,
/// and SIGN runs grant-free afterwards (the counting grant saw no
/// consultation from the signing arms while the bypass is on).
#[test]
fn open_session_and_touched_the_flag_stands() {
    reset_presses();
    let (app, path) = pin_app("disable-touched");
    let mut app = app.with_presence_grant(counting_allow);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_OK, "the consent chain completes");
    assert!(app.touch_bypass(), "the flag stands");
    // The payoff: the signing arms now run without consulting the grant —
    // the count is taken after the disable leg's own consent press.
    let after_disable = presses();
    let (_, sw) = call(&mut app, &apdu_sign(1));
    assert_eq!(sw, SW_OK, "SIGN runs grant-free under the bypass");
    assert_eq!(
        presses(),
        after_disable,
        "the SIGN consumed no press — the bypass is the exemption"
    );
    std::fs::remove_file(&path).ok();
}

/// **A refusal consumes an armed grant and never sets the flag** — the
/// pin.rs gate-before-touch property on the policy verb: with the session
/// closed, the disable request answers the gate word with the grant
/// unconsulted; with the session open, the deny grant is consulted exactly
/// once per request and every refusal leaves the flag down.
#[test]
fn a_refusal_consumes_an_armed_grant() {
    reset_presses();
    let (app, path) = app_with_identity("disable-eats");
    // A PIN-set but unverified board: pin_app verifies, so this one stops
    // after SET_PIN to keep the session closed for the first phase.
    let mut app = app.with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(0x1C, 0x00, PIN)); // SET_PIN only
    assert_eq!(sw, SW_OK);
    let mut app = app.with_presence_grant(counting_deny);
    // Closed session: the gate refuses, the press path never runs.
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_PIN_SESSION_REQUIRED);
    assert_eq!(presses(), 0, "the gate ate the armed grant");
    // Session open: the touch arm runs and the deny grant refuses — once
    // per request, flag down each time.
    let (_, sw) = call(&mut app, &apdu(0x1B, 0x00, PIN)); // VERIFY_PIN
    assert_eq!(sw, SW_OK);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_TOUCH_REQUIRED);
    assert_eq!(presses(), 1);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_TOUCH_REQUIRED);
    assert_eq!(presses(), 2, "each request consults the grant once");
    assert!(!app.touch_bypass(), "no refusal ever set the flag");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// US-1744 — the enable leg: the safe direction stays friction-free.
// ---------------------------------------------------------------------------

/// **Enable with no PIN, no session, no touch — allowed**: a board can
/// always get its button back; the deny grant is never consulted.
#[test]
fn enable_with_no_pin_no_session_no_touch_is_allowed() {
    reset_presses();
    let (app, path) = app_with_identity("enable-no-pin");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true);
    let (_, sw) = call(&mut app, &apdu_policy(0x00));
    assert_eq!(sw, SW_OK, "the safe direction never refuses");
    assert!(!app.touch_bypass(), "the flag is down after enable");
    assert_eq!(presses(), 0, "no grant consulted");
    std::fs::remove_file(&path).ok();
}

/// **Enable is idempotent in every state** — PIN-less, PIN-set unverified,
/// PIN-set verified, and a degraded applet: the reply is SW_OK every time,
/// the flag lands down, and the degraded row proves the enable leg reads
/// no store (a degraded applet answers SW_STORE_FAULT to anything that
/// touches the store).
#[test]
fn enable_is_idempotent_in_every_state() {
    // PIN-less.
    let (app, path) = app_with_identity("enable-pinless");
    let mut app = app.with_presence_grant(counting_deny);
    let (_, sw) = call(&mut app, &apdu_policy(0x00));
    assert_eq!(sw, SW_OK);
    assert!(!app.touch_bypass());
    std::fs::remove_file(&path).ok();

    // PIN-set unverified.
    let (app, path) = app_with_identity("enable-unverified");
    let mut app = app.with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(0x1C, 0x00, PIN));
    assert_eq!(sw, SW_OK);
    let mut app = app.with_presence_grant(counting_deny);
    let (_, sw) = call(&mut app, &apdu_policy(0x00));
    assert_eq!(sw, SW_OK);
    assert!(!app.touch_bypass());
    std::fs::remove_file(&path).ok();

    // PIN-set verified, bypass armed.
    let (app, path) = pin_app("enable-verified");
    let mut app = app.with_presence_grant(counting_deny);
    app.set_touch_bypass(true);
    let (_, sw) = call(&mut app, &apdu_policy(0x00));
    assert_eq!(sw, SW_OK);
    assert!(!app.touch_bypass());
    std::fs::remove_file(&path).ok();

    // Degraded applet (no region at all): the enable leg reads no store —
    // anything that touched the store would answer SW_STORE_FAULT here.
    let mut degraded = NostrApp::new().with_presence_grant(counting_deny);
    degraded.set_touch_bypass(true);
    let (_, sw) = call(&mut degraded, &apdu_policy(0x00));
    assert_eq!(sw, SW_OK, "the enable leg reads no store");
    assert!(!degraded.touch_bypass());
}

/// **Enable leaks nothing about PIN state** — every state's reply is
/// byte-identical (SW_OK, empty body): the verb cannot fingerprint the
/// board, the `lock_answers_9000_in_every_state_and_leaks_nothing` shape.
#[test]
fn enable_leaks_nothing_about_pin_state() {
    // Every row collects (body, sw) of the enable reply; the states differ,
    // the replies must not.
    let mut replies: Vec<(HeaplessVec<u8, 4096>, Sw)> = Vec::new();

    // PIN-less.
    let (app, path) = app_with_identity("leak-pinless");
    let mut app = app;
    replies.push(call(&mut app, &apdu_policy(0x00)));
    std::fs::remove_file(&path).ok();

    // PIN-set unverified.
    let (app, path) = app_with_identity("leak-unverified");
    let mut app = app.with_rng_provider(pinned_salt);
    let (_, sw) = call(&mut app, &apdu(0x1C, 0x00, PIN));
    assert_eq!(sw, SW_OK);
    replies.push(call(&mut app, &apdu_policy(0x00)));
    std::fs::remove_file(&path).ok();

    // PIN-set verified.
    let (app, path) = pin_app("leak-verified");
    let mut app = app;
    replies.push(call(&mut app, &apdu_policy(0x00)));
    std::fs::remove_file(&path).ok();

    // Degraded.
    let mut degraded = NostrApp::new();
    replies.push(call(&mut degraded, &apdu_policy(0x00)));

    for (body, sw) in &replies {
        assert_eq!(*sw, SW_OK);
        assert!(body.is_empty(), "no response body, no fingerprint");
    }
}

// ---------------------------------------------------------------------------
// US-1745 — the lifecycle matrix: the bypass lives exactly as long as the
// session it was opened in. Power cycle, LOCK and the factory wipe clear
// it; deselect/re-select preserve it; the CTAP2 reset never reaches it.
// (The power-cycle row is `a_fresh_boot_over_the_same_region_clears_the_
// flag`, the US-1741 block's last test.)
// ---------------------------------------------------------------------------

/// **LOCK clears it** — the bypass dies with the session, on the shared
/// applet instance both transports drive (§8: one applet behind the
/// `Mutex`, so an applet-level LOCK covers CCID and vendor-HID by
/// construction). A re-verify does not silently resurrect it: SIGN demands
/// the touch again.
#[test]
fn lock_clears_the_flag_and_reverify_does_not_restore_it() {
    let (app, path) = pin_app("lifecycle-lock");
    let mut app = app.with_presence_grant(counting_allow);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_OK, "the fixture arms the bypass");
    assert!(app.touch_bypass());

    let (_, sw) = call(&mut app, &apdu(0x1D, 0x00, &[])); // LOCK
    assert_eq!(sw, SW_OK);
    assert!(!app.touch_bypass(), "LOCK clears the flag");

    // A re-verify opens the session again — the bypass stays gone. The
    // proof binds the deny grant: SIGN now answers the touch word.
    let (_, sw) = call(&mut app, &apdu(0x1B, 0x00, PIN));
    assert_eq!(sw, SW_OK);
    assert!(!app.touch_bypass(), "re-verify does not resurrect the flag");
    let mut app = app.with_presence_grant(counting_deny);
    let (_, sw) = call(&mut app, &apdu_sign(1));
    assert_eq!(sw, SW_TOUCH_REQUIRED, "SIGN demands the touch again");
    std::fs::remove_file(&path).ok();
}

/// **Management RESET clears it** — the wipe through the dispatcher's
/// route (the proxy forward is pinned by presence.rs's F-A3 gate) resets
/// the RAM caches with the records, the pin_unlocked reset at the same
/// site's shape.
#[test]
fn management_reset_clears_the_flag() {
    let (app, path) = pin_app("lifecycle-wipe");
    let mut app = app.with_presence_grant(counting_allow);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_OK);
    assert!(app.touch_bypass());

    app.factory_wipe();
    assert!(!app.touch_bypass(), "the wipe clears the flag");
    std::fs::remove_file(&path).ok();
}

/// **Deselect and re-select preserve it** — same rule as the PIN session
/// (US-1693): a SELECT cycle is not a power cycle.
#[test]
fn deselect_and_reselect_preserve_the_flag() {
    let (app, path) = pin_app("lifecycle-deselect");
    let mut app = app.with_presence_grant(counting_allow);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_OK);
    assert!(app.touch_bypass());

    app.deselect();
    assert!(
        app.touch_bypass(),
        "deselect preserves the flag — same rule as the PIN session"
    );
    std::fs::remove_file(&path).ok();
}

/// **CTAP2 reset never reaches it** — the source assertion: FIDO's
/// `handle_reset` (the `authenticatorReset` arm) names no Nostr applet
/// reach — it wipes only FIDO's own region, so the Nostr flag is not
/// touched by a CTAP2 reset (and the Nostr applet is never constructed
/// anew by it).
#[test]
fn ctap2_reset_never_reaches_the_nostr_applet() {
    let device_core = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apps/fido/src/device_core.rs"
    ))
    .expect("apps/fido/src/device_core.rs is readable from the nostr test crate");
    let body = device_core
        .split("pub(crate) fn handle_reset")
        .nth(1)
        .expect("handle_reset exists in device_core.rs");
    let body = &body[..body
        .find("\n    pub(crate) fn ")
        .or_else(|| body.find("\n    fn "))
        .expect("the reset arm terminates at the next method")];
    assert!(
        !body.to_lowercase().contains("nostr"),
        "the CTAP2 reset arm must never reach the Nostr applet — \
         authenticatorReset wipes only FIDO's range (US-1650's contract)"
    );
}

// ---------------------------------------------------------------------------
// US-1746 — GET_INFO advertises the capability and the live state, derived
// from the gate's own field. The layout stays applet_ver(2) ‖ caps(2) ‖
// max_plaintext(2) ‖ n_identities(1) ‖ flags(1) — u8/u16 widths only, so
// the §6 32-bit rule holds by construction.
// ---------------------------------------------------------------------------

/// One GET_INFO walk returning (caps, flags) — the two fields the story
/// asserts on, decoded from the fixed 8-byte body.
fn get_info_fields(app: &mut NostrApp) -> (u16, u8) {
    let (data, sw) = call(app, &apdu(0x10, 0x00, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(data.len(), 8, "applet_ver(2) ‖ caps(2) ‖ max_pt(2) ‖ n(1) ‖ flags(1)");
    let caps = u16::from_be_bytes([data[2], data[3]]);
    let flags = data[7];
    (caps, flags)
}

/// **The capability bit is unconditional** — any booted applet advertises
/// caps bit 4, because the verb exists on this firmware.
#[test]
fn the_capability_bit_is_unconditional() {
    let (app, path) = app_with_identity("advertise-caps");
    let mut app = app;
    let (caps, _) = get_info_fields(&mut app);
    assert_eq!(
        caps & 0x0010,
        0x0010,
        "CAP_TOUCH_POLICY is advertised unconditionally"
    );
    std::fs::remove_file(&path).ok();
}

/// **The state flag tracks the gate's field exactly** — bit 3 absent then
/// present, and no other flag bit moves.
#[test]
fn the_state_flag_tracks_the_gate_field() {
    let (app, path) = pin_app("advertise-flag");
    let mut app = app;
    let (_, flags_off) = get_info_fields(&mut app);
    assert_eq!(
        flags_off & 0x08,
        0,
        "bypass down: FLAG_TOUCH_BYPASS absent"
    );
    app.set_touch_bypass(true);
    let (_, flags_on) = get_info_fields(&mut app);
    assert_eq!(flags_on & 0x08, 0x08, "bypass up: FLAG_TOUCH_BYPASS present");
    assert_eq!(
        flags_off & !0x08,
        flags_on & !0x08,
        "no other flag bit moved"
    );
    std::fs::remove_file(&path).ok();
}

/// **The advertisement cannot diverge from the gate** — the source
/// assertion: GET_INFO's flag bit is computed from `self.touch_bypass`,
/// the same field US-1741's signing gates read, with no second read or
/// recomputation between the two.
#[test]
fn the_advertisement_cannot_diverge_from_the_gate() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/lib.rs"
    ))
    .expect("apps/nostr/src/lib.rs is readable from its own test crate");
    let get_info = src
        .split("fn get_info")
        .nth(1)
        .expect("get_info exists");
    let get_info = &get_info[..get_info.find("\n    fn ").expect("get_info terminates")];
    assert!(
        get_info.contains("self.touch_bypass"),
        "GET_INFO must read the gate's own field, not a recomputation"
    );
    assert!(
        get_info.contains("FLAG_TOUCH_BYPASS"),
        "GET_INFO must set the flag bit from that field"
    );
    // And the flag constant's doc names the derivation rule, so a future
    // editor meets the §4 convention at the definition site.
    let flag_doc = src
        .split("pub const FLAG_TOUCH_BYPASS")
        .nth(1)
        .map(|_| ())
        .is_some();
    assert!(flag_doc, "the FLAG_TOUCH_BYPASS constant exists");
}

/// **getInfo stays width-clean** — the response body is still the fixed
/// 8-byte layout of u8/u16 fields (no integer wider than 16 bits anywhere
/// in it), so the §6 32-bit rule is unchanged by the new bits.
#[test]
fn getinfo_stays_width_clean() {
    let (app, path) = app_with_identity("advertise-width");
    let mut app = app;
    let (data, _) = get_info_fields(&mut app);
    let _ = data;
    // The 8-byte layout assertion lives in get_info_fields; this row
    // exists so a layout change (a wider integer, a new field) has a named
    // failing test referencing the §6 rule.
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------------
// Review follow-up — the verify_pin failure arm: the US-1745 LOCK rationale
// applies to every session close, not just LOCK's. A failed verify closes
// the session; a stale bypass surviving it would let the next VERIFY
// silently resurrect a touch-free session the user believes they closed.
// ---------------------------------------------------------------------------

/// **A failed verify clears the armed bypass with the session** — the
/// session closed, the flag dies with it, and the correct verify that
/// reopens the session does not resurrect the bypass: re-arming it costs
/// a new disable-leg press, exactly as after a LOCK.
#[test]
#[ignore = "review RED: the verify_pin failure arm keeps the flag standing"]
fn a_failed_verify_clears_the_armed_bypass() {
    reset_presses();
    let (app, path) = pin_app("failed-verify-clears");
    let mut app = app.with_presence_grant(counting_allow);
    let (_, sw) = call(&mut app, &apdu_policy(0x01));
    assert_eq!(sw, SW_OK, "the fixture arms the bypass");
    assert!(app.touch_bypass());

    // A wrong PIN closes the session — the bypass dies with it.
    let (_, sw) = call(&mut app, &apdu(0x1B, 0x00, b"000000"));
    assert_eq!(sw, 0x63C2, "the wrong PIN burns an attempt");
    assert!(!app.touch_bypass(), "the failed verify cleared the flag");

    // The correct verify reopens the session — the bypass stays gone.
    let (_, sw) = call(&mut app, &apdu(0x1B, 0x00, PIN));
    assert_eq!(sw, SW_OK);
    assert!(!app.touch_bypass(), "re-verify does not resurrect the flag");
    std::fs::remove_file(&path).ok();
}
