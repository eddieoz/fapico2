//! US-908 TDD: U2F (CTAP1) REGISTER/AUTHENTICATE require presence.
//!
//! The red-team sequence (`redteam/mitm_ctap.py`) registered and
//! authenticated with zero touch: both U2F paths pushed the
//! `user presence` byte unconditionally and signed. After US-908:
//!
//! * REGISTER without a grant → `SW_CONDITIONS_NOT_SATISFIED` (0x6985),
//!   no attestation material leaves the device.
//! * AUTHENTICATE (control 0x08) without a grant → error byte 0x07
//!   (`NOT_PRESENT`) and **no counter change** — nothing signs.
//! * With an injected grant both steps proceed (attestation path
//!   unchanged) and the counter increments exactly on the granted auth.
//! * Check-only (0x07) stays side-effect-free and returns its spec'd
//!   status family.
//!
//! The injected source follows the US-907 pattern (`with_user_presence`):
//! a process-global toggle (`fn()` pointers cannot capture), so every
//! test holds the lock for its duration. The host/emulation build default
//! auto-acks (parity with the existing green suites); the deny default is
//! the device build (fail-closed).

use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use std::sync::atomic::{AtomicBool, Ordering};

/// Toggle for the injected presence source: `true` = fail-by-default (the
/// host-test stand-in for the device build), `false` = auto-ack.
static PRESENCE_DENIED: AtomicBool = AtomicBool::new(true);

fn injected_presence() -> bool {
    !PRESENCE_DENIED.load(Ordering::SeqCst)
}

/// The injected source is process-global (`fn() -> bool` cannot capture),
/// so the flag flips race under cargo's default per-file parallelism —
/// every test holds this lock for its duration.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// App under test, with the injected (toggleable) presence source attached.
fn app() -> FidoApp {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    FidoApp::boot(&mut trng, &mut store)
        .unwrap()
        .with_user_presence(injected_presence)
}

/// Drive a U2F APDU (short form: CLA INS P1 P2 Lc ‖ body) and return the
/// response bytes (payload ‖ status word).
fn drive(app: &mut FidoApp, ins: u8, p1: u8, body: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, ins, p1, 0x00, body.len() as u8];
    apdu.extend_from_slice(body);
    let mut out = heapless::Vec::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_u2f(&apdu, &mut out);
    out[..n].to_vec()
}

/// U2F REGISTER body: client_param(32) ‖ app_param(32).
fn register_body() -> [u8; 64] {
    let mut b = [0u8; 64];
    b[..32].fill(0xC1); // client_param
    b[32..].fill(0xC2); // app_param
    b
}

/// U2F AUTHENTICATE body: client_param(32) ‖ app_param(32) ‖ kh_len ‖ handle.
fn auth_body(handle: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 32];
    b[..32].fill(0xC1); // client_param
    b.extend_from_slice(&[0xC2; 32]); // app_param
    b.push(handle.len() as u8);
    b.extend_from_slice(handle);
    b
}

/// Key handle from a REGISTER response: 0x05 ‖ pub(65) ‖ kh_len(1) ‖ kh ‖ …
fn register_handle(resp: &[u8]) -> Vec<u8> {
    assert_eq!(resp[0], 0x05, "register response must start with 0x05");
    let len = resp[66] as usize;
    assert_eq!(len, 64, "stateless key handle is 64 bytes");
    resp[67..67 + len].to_vec()
}

/// The red-team register/auth sequence against a fail-by-default source:
/// neither step completes. Register refuses with SW_CONDITIONS_NOT_SATISFIED;
/// authenticate on a known handle returns the NOT_PRESENT error byte (0x07)
/// and the global counter does not move.
#[test]
fn register_and_auth_denied_without_grant() {
    let _g = TEST_LOCK.lock().unwrap();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let mut a = app(); // fail-by-default source (device stand-in)

    // REGISTER: refused, no attestation material.
    let resp = drive(&mut a, 0x01, 0x00, &register_body());
    assert_eq!(resp, [0x69, 0x85], "REGISTER without a grant → 0x6985");
    assert_eq!(a.keystore().cred_counter, 0);

    // Provision a known handle with a grant so the auth denial is
    // meaningful (the red-team replay authenticates a real handle).
    PRESENCE_DENIED.store(false, Ordering::SeqCst);
    let resp = drive(&mut a, 0x01, 0x00, &register_body());
    assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "granted register");
    let handle = register_handle(&resp);

    // Deny again: AUTHENTICATE (enforce, control 0x08) without a grant.
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let before = a.keystore().cred_counter;
    let resp = drive(&mut a, 0x02, 0x08, &auth_body(&handle));
    assert_eq!(
        resp,
        [0x07, 0x00],
        "enforce auth without a grant → NOT_PRESENT (0x07)"
    );
    assert_eq!(
        a.keystore().cred_counter,
        before,
        "the counter must not move without a grant"
    );
    PRESENCE_DENIED.store(false, Ordering::SeqCst);
}

/// With a grant both steps proceed: register answers, and the enforce auth
/// signs with the UP byte set and the counter incremented exactly once.
#[test]
fn granted_register_and_auth_increment_counter_once() {
    let _g = TEST_LOCK.lock().unwrap();
    PRESENCE_DENIED.store(false, Ordering::SeqCst);
    let mut a = app(); // auto-ack (host/emulation default parity)

    let resp = drive(&mut a, 0x01, 0x00, &register_body());
    assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "granted register");
    let handle = register_handle(&resp);

    let before = a.keystore().cred_counter;
    let resp = drive(&mut a, 0x02, 0x08, &auth_body(&handle));
    assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "granted auth signs");
    assert_eq!(resp[0], 0x01, "UP byte set on the granted auth");
    assert_eq!(
        u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]),
        before + 1,
        "the counter increments exactly on the granted auth"
    );
    assert_eq!(a.keystore().cred_counter, before + 1);
}

/// Check-only (0x07) never consumes a grant and never signs: it keeps its
/// spec'd status family (CONDITIONS_NOT_SATISFIED for a valid handle) with
/// the counter untouched.
#[test]
fn check_only_stays_side_effect_free() {
    let _g = TEST_LOCK.lock().unwrap();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let mut a = app();

    PRESENCE_DENIED.store(false, Ordering::SeqCst);
    let resp = drive(&mut a, 0x01, 0x00, &register_body());
    let handle = register_handle(&resp);

    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let before = a.keystore().cred_counter;
    let resp = drive(&mut a, 0x02, 0x07, &auth_body(&handle));
    assert_eq!(resp, [0x69, 0x85], "check-only on a valid handle → 0x6985");
    assert_eq!(a.keystore().cred_counter, before, "check-only never signs");
    PRESENCE_DENIED.store(false, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// US-921: the cross-call consent window — the device build injects
// `request_grant_in_window` (join-only, `fn(u32) -> bool`) and the HID
// task's MSG-arm keepalive loop re-issues the APDU inside the window. The
// host gate below refuses the first call and grants the retry.
// ---------------------------------------------------------------------------

/// Gate modes: 0 = deny, 1 = grant, 2 = refuse the first call then grant.
static GATE_MODE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Calls consumed by the gate since the test last reset it.
static GATE_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The device gate stand-in (`fn(u32) -> bool`, no capture — statics only).
fn windowed_grant(_tag: u32) -> bool {
    let n = GATE_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
    match GATE_MODE.load(Ordering::SeqCst) {
        0 => false,
        1 => true,
        _ => n >= 2,
    }
}

/// The app with the US-921 device gate (`with_presence_grant`) attached.
fn app_windowed() -> FidoApp {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    FidoApp::boot(&mut trng, &mut store)
        .unwrap()
        .with_presence_grant(windowed_grant)
}

/// Case 12 — U2F REGISTER through the windowed gate: the first attempt is
/// the bare 6985 refusal (no attestation material), the granted retry
/// returns the attestation response.
#[test]
fn u2f_register_granted_on_retry_attests() {
    let _g = TEST_LOCK.lock().unwrap();
    GATE_MODE.store(2, Ordering::SeqCst);
    GATE_CALLS.store(0, Ordering::SeqCst);
    let mut a = app_windowed();

    let resp = drive(&mut a, 0x01, 0x00, &register_body());
    assert_eq!(resp, [0x69, 0x85], "the refused first attempt → bare 6985");
    assert_eq!(a.keystore().cred_counter, 0, "nothing signed");

    let resp = drive(&mut a, 0x01, 0x00, &register_body());
    assert_eq!(resp[0], 0x05, "the windowed retry returns the attestation");
    assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00]);
    GATE_MODE.store(0, Ordering::SeqCst);
}

/// Case 13 — U2F enforce AUTHENTICATE (control 0x08) through the windowed
/// gate: the first attempt is the NOT_PRESENT refusal with the counter
/// untouched; the granted retry signs with the counter advanced exactly
/// once.
#[test]
fn u2f_enforce_auth_granted_on_retry_signs_once() {
    let _g = TEST_LOCK.lock().unwrap();
    // Provision with an always-granting gate.
    GATE_MODE.store(1, Ordering::SeqCst);
    let mut a = app_windowed();
    let resp = drive(&mut a, 0x01, 0x00, &register_body());
    let handle = register_handle(&resp);

    GATE_MODE.store(2, Ordering::SeqCst);
    GATE_CALLS.store(0, Ordering::SeqCst);
    let before = a.keystore().cred_counter;
    let resp = drive(&mut a, 0x02, 0x08, &auth_body(&handle));
    assert_eq!(resp, [0x07, 0x00], "the refused first attempt → NOT_PRESENT");
    assert_eq!(a.keystore().cred_counter, before, "nothing signed");

    let resp = drive(&mut a, 0x02, 0x08, &auth_body(&handle));
    assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "the retry signs");
    assert_eq!(resp[0], 0x01, "UP byte set on the granted auth");
    assert_eq!(
        u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]),
        before + 1,
        "the counter advanced exactly once across the window"
    );
    assert_eq!(a.keystore().cred_counter, before + 1);
    GATE_MODE.store(0, Ordering::SeqCst);
}

/// US-921 review (P1-2): U2F check-only (P1=0x07) on a valid handle answers
/// SW 6985 by spec WITHOUT consulting presence — the presence closure is
/// never invoked. The transport loop (tasks.rs / emul_main.rs MSG arm)
/// classifies a bare [0x69, 0x85] as an UP refusal, so it gates windowing
/// on the decoded APDU head BEFORE the refusal check: only REGISTER
/// (INS 0x01) or AUTHENTICATE enforce (INS 0x02, P1 != 0x07) opens the
/// 30 s cross-call consent window. Without that gate, a flood of check-only
/// requests would keep the touch prompt lit and the single presence slot
/// hogged for 30 s (press-laundering DoS) — and a user press during the
/// window would be consumed by a command that never needed presence.
#[test]
fn check_only_never_opens_the_touch_window() {
    let _g = TEST_LOCK.lock().unwrap();
    GATE_MODE.store(1, Ordering::SeqCst); // always-grant: ANY call is visible
    let mut a = app_windowed();

    // Provision a valid handle (REGISTER genuinely consults the gate).
    GATE_CALLS.store(0, Ordering::SeqCst);
    let resp = drive(&mut a, 0x01, 0x00, &register_body());
    let handle = register_handle(&resp);
    let calls_after_register = GATE_CALLS.load(Ordering::SeqCst);
    assert!(
        calls_after_register >= 1,
        "REGISTER must consult the presence gate (control for this test)"
    );

    // Check-only on the valid handle: 6985 with the gate NEVER invoked.
    let resp = drive(&mut a, 0x02, 0x07, &auth_body(&handle));
    assert_eq!(resp, [0x69, 0x85], "check-only on a valid handle → 6985");
    assert_eq!(
        GATE_CALLS.load(Ordering::SeqCst),
        calls_after_register,
        "check-only must not invoke the presence closure — the transport \
         loop's INS/P1 gate skips windowing for it"
    );

    // And an INVALID handle answers WrongData without touching presence
    // either (same gate count).
    let resp = drive(&mut a, 0x02, 0x07, &auth_body(&[0xEE; 64]));
    assert_eq!(resp, [0x6A, 0x80], "check-only on an unknown handle → 6A80");
    assert_eq!(
        GATE_CALLS.load(Ordering::SeqCst),
        calls_after_register,
        "check-only never consults presence, valid handle or not"
    );
    GATE_MODE.store(0, Ordering::SeqCst);
}
