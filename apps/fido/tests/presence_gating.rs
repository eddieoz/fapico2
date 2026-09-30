//! US-907 TDD: CTAP2 GA/MC require presence before signing (device build).
//!
//! The device command path (`device_core.rs`) consults the platform presence
//! service before any assertion/attestation signature is produced:
//!
//! * GA with `options.up != false` and **no grant** → CTAP2 "UP required"
//!   (the synchronous stand-in for the keepalive `0x11` loop → error);
//!   nothing signs and the UP bit is never set.
//! * MC (plain, resident, or UV) likewise consumes a grant — review fix:
//!   plain rk=false/no-UV MC cannot mint a credential + attestation
//!   signature with zero touch.
//! * GA with `options.up=false` still answers — without the UP bit.
//!
//! The fail-by-default source here is a **host-test construct** (injected
//! via `with_user_presence`, mirroring the device build default); the build
//! default on host/emulation auto-acks, so the existing suites stay green
//! (the last test pins that parity).

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// Toggle for the injected presence source. `true` = fail-by-default (the
/// host-test stand-in for the device build); `false` = auto-ack (the
/// host/emulation build default). `fn` pointers cannot capture, so the
/// tests flip this instead of swapping the source.
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

/// CTAP2 makeCredential, no PIN (PIN unset → allowed without a token).
fn mc_req(rk: bool) -> Vec<u8> {
    let mut r: HV<u8, 512> = HV::new();
    let pairs = if rk { 5 } else { 4 };
    nh::push_map_header(&mut r, pairs).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &[0xCC; 32]).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, "example.com").unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, b"user-1").unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap();
    if rk {
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "rk").unwrap();
        nh::push_bool(&mut r, true).unwrap();
    }
    r.as_slice().to_vec()
}

/// CTAP2 getAssertion; `up`: None = no options map (up required by default),
/// Some(b) = options {up: b}. `allow`: optional allowList (non-resident
/// credential id).
fn ga_req(up: Option<bool>, allow: Option<&[u8]>) -> Vec<u8> {
    let mut r: HV<u8, 256> = HV::new();
    let mut pairs = 2usize;
    if up.is_some() {
        pairs += 1;
    }
    if allow.is_some() {
        pairs += 1;
    }
    nh::push_map_header(&mut r, pairs).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "example.com").unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_bstr(&mut r, &[0xDD; 32]).unwrap();
    if let Some(id) = allow {
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_array_header(&mut r, 1).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "type").unwrap();
        nh::push_tstr(&mut r, "public-key").unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_bstr(&mut r, id).unwrap();
    }
    if let Some(up) = up {
        nh::push_uint(&mut r, 5).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "up").unwrap();
        nh::push_bool(&mut r, up).unwrap();
    }
    r.as_slice().to_vec()
}

fn call(app: &mut FidoApp, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
    let mut out: HV<u8, MAX_MSG> = HV::new();
    let n = app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
    let resp = out.as_slice()[..n].to_vec();
    (resp[0], resp[1..].to_vec())
}

/// Credential id from a makeCredential response (attestedCredentialData:
/// rpIdHash(32) flags(1) count(4) aaguid(16) len(2) id).
fn mc_cred_id(cbor: &[u8]) -> Vec<u8> {
    let mut p = Parser::new(cbor);
    assert!(matches!(p.next(), Ok(Item::Map(_))));
    while p.remaining() > 0 {
        let Item::U(k) = p.next().unwrap() else { panic!() };
        if k == 2 {
            let Item::B(ad) = p.next().unwrap() else { panic!() };
            let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
            return ad[55..55 + len].to_vec();
        }
        p.skip().unwrap();
    }
    panic!("no authData in MC response");
}

/// authData flags byte from a GA response (key 2).
fn ga_auth_data_flags(cbor: &[u8]) -> Vec<u8> {
    let mut p = Parser::new(cbor);
    assert!(matches!(p.next(), Ok(Item::Map(_))));
    while p.remaining() > 0 {
        let Item::U(k) = p.next().unwrap() else { panic!() };
        if k == 2 {
            let Item::B(b) = p.next().unwrap() else { panic!() };
            return b.to_vec();
        }
        p.skip().unwrap();
    }
    panic!("no authData in GA response");
}

/// The device-build default: no grant ⇒ nothing signs and nothing is stored.
/// Plain (rk=false, no UV), resident (rk=true) and UV-less MC are all gated
/// (review fix: a plain MC must not mint a credential with zero touch).
#[test]
fn mc_and_ga_denied_without_grant() {
    let _g = TEST_LOCK.lock().unwrap();
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let mut a = app(); // fail-by-default source (device stand-in)

    // Plain MC: denied, and no credential is created.
    let (status, body) = call(&mut a, 0x01, &mc_req(false /* rk */));
    assert_eq!(status, 0x3B, "plain MC without a grant must be denied");
    assert!(body.is_empty(), "no attestation body without a grant");
    assert_eq!(a.keystore().credentials.len(), 0, "nothing created");

    // Resident MC: denied, nothing created.
    let (status, _) = call(&mut a, 0x01, &mc_req(true /* rk */));
    assert_eq!(status, 0x3B, "rk=true MC without a grant must be denied");
    assert_eq!(a.keystore().credentials.len(), 0, "nothing created");

    // GA with no options map (up required by default): denied.
    let (status, body) = call(&mut a, 0x02, &ga_req(None, None));
    assert_eq!(status, 0x3B, "CTAP2_ERR_UP_REQUIRED expected (no grant)");
    assert!(body.is_empty(), "no assertion body without a grant");

    // Explicit up=true: same denial.
    let (status, _) = call(&mut a, 0x02, &ga_req(Some(true), None));
    assert_eq!(status, 0x3B, "up=true without a grant must never sign");
}

#[test]
fn ga_up_false_answers_without_up_bit() {
    let _g = TEST_LOCK.lock().unwrap();
    let mut a = app();
    // Provisioning needs a grant (plain MC is gated too).
    PRESENCE_DENIED.store(false, Ordering::SeqCst);
    let (status, mc_cbor) = call(&mut a, 0x01, &mc_req(false));
    assert_eq!(status, 0x00);
    let cred_id = mc_cred_id(&mc_cbor);
    // Now fail presence again: up=false still answers, UP bit unset.
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
    let (status, cbor) = call(&mut a, 0x02, &ga_req(Some(false), Some(&cred_id)));
    assert_eq!(status, 0x00, "up=false answers without presence");
    let ad = ga_auth_data_flags(&cbor);
    assert_eq!(ad[32] & 0x01, 0x00, "UP bit must NOT be set for up=false");
}

#[test]
fn auto_ack_source_preserves_green_suite() {
    let _g = TEST_LOCK.lock().unwrap();
    // Default (no denial): host/emulation auto-acks — today's behavior,
    // unchanged.
    PRESENCE_DENIED.store(false, Ordering::SeqCst);
    let mut a = app();
    let (status, mc_cbor) = call(&mut a, 0x01, &mc_req(true /* rk */));
    assert_eq!(status, 0x00, "rk=true MC with auto-ack succeeds");
    let cred_id = mc_cred_id(&mc_cbor);
    let (status, cbor) = call(&mut a, 0x02, &ga_req(None, Some(&cred_id)));
    assert_eq!(status, 0x00, "GA with auto-ack succeeds");
    let ad = ga_auth_data_flags(&cbor);
    assert_eq!(ad[32] & 0x01, 0x01, "UP bit set for the auto-ack default");
    PRESENCE_DENIED.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// US-921: the cross-call consent window — the device build injects
// `request_grant_in_window` (join-only, `fn(u32) -> bool`) and the HID
// task's UpRequired keepalive loop re-issues the command inside the
// window. Host parity: a gate that refuses the FIRST call for a tag and
// grants the RETRY models exactly that interleaving.
// ---------------------------------------------------------------------------

/// Gate modes: 0 = deny, 1 = grant, 2 = refuse the first call then grant
/// (the windowed retry).
static GATE_MODE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Calls consumed by the gate since the test last reset it.
static GATE_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The last tag the gate was consulted under (tag-binding pin).
static GATE_TAG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The device gate stand-in (`fn(u32) -> bool`, no capture — statics only).
fn windowed_grant(tag: u32) -> bool {
    GATE_TAG.store(tag, Ordering::SeqCst);
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

/// Case 9 — MC granted on the retry: the first attempt mints nothing (no
/// partial credential state), the granted retry mints the credential
/// exactly once.
#[test]
fn mc_granted_on_retry_mints_exactly_once() {
    let _g = TEST_LOCK.lock().unwrap();
    GATE_MODE.store(2, Ordering::SeqCst);
    GATE_CALLS.store(0, Ordering::SeqCst);
    let mut a = app_windowed();

    // Attempt 1: no grant yet → UpRequired, nothing created.
    let (status, body) = call(&mut a, 0x01, &mc_req(false /* rk */));
    assert_eq!(status, 0x3B, "the refused first attempt must be UpRequired");
    assert!(body.is_empty(), "no attestation body without a grant");
    assert_eq!(a.keystore().credentials.len(), 0, "no partial state");
    assert_eq!(
        GATE_TAG.load(Ordering::SeqCst),
        fapico2_fido::presence_tag_from_channel([1, 2, 3, 4]),
        "the gate must be consulted under the domain-separated \
         channel-derived tag (bit 31 set — US-921 review P0-1)"
    );

    // Attempt 2 (inside the window): granted, the credential is minted
    // exactly once.
    let (status, _) = call(&mut a, 0x01, &mc_req(false));
    assert_eq!(status, 0x00, "the windowed retry must grant");
    assert_eq!(
        a.keystore().credentials.len(),
        1,
        "exactly one credential after the granted retry"
    );
    GATE_MODE.store(0, Ordering::SeqCst);
}

/// Case 10 — GA granted on the retry signs once, and the UP bit is set
/// only on the granted attempt.
#[test]
fn ga_granted_on_retry_signs_once_up_bit_only_on_grant() {
    let _g = TEST_LOCK.lock().unwrap();
    // Provision with an always-granting gate.
    GATE_MODE.store(1, Ordering::SeqCst);
    let mut a = app_windowed();
    let (status, mc_cbor) = call(&mut a, 0x01, &mc_req(false));
    assert_eq!(status, 0x00);
    let cred_id = mc_cred_id(&mc_cbor);

    // GA through the windowed gate: attempt 1 refused (empty body —
    // nothing signs, no flags), attempt 2 signs with the UP bit.
    GATE_MODE.store(2, Ordering::SeqCst);
    GATE_CALLS.store(0, Ordering::SeqCst);
    let (status, body) = call(&mut a, 0x02, &ga_req(None, Some(&cred_id)));
    assert_eq!(status, 0x3B, "the refused first GA must be UpRequired");
    assert!(body.is_empty(), "the refused attempt must not sign");
    let (status, cbor) = call(&mut a, 0x02, &ga_req(None, Some(&cred_id)));
    assert_eq!(status, 0x00, "the windowed retry signs");
    let ad = ga_auth_data_flags(&cbor);
    assert_eq!(ad[32] & 0x01, 0x01, "UP bit set on the granted attempt");
    GATE_MODE.store(0, Ordering::SeqCst);
}

/// Case 11 — `up=false` never consults the gate (no consent is needed, so
/// the window machinery is never touched).
#[test]
fn ga_up_false_never_consults_the_gate() {
    let _g = TEST_LOCK.lock().unwrap();
    GATE_MODE.store(1, Ordering::SeqCst);
    let mut a = app_windowed();
    let (status, mc_cbor) = call(&mut a, 0x01, &mc_req(false));
    assert_eq!(status, 0x00);
    let cred_id = mc_cred_id(&mc_cbor);

    GATE_CALLS.store(0x8000, Ordering::SeqCst);
    GATE_MODE.store(0, Ordering::SeqCst); // deny if ever consulted
    let (status, cbor) = call(&mut a, 0x02, &ga_req(Some(false), Some(&cred_id)));
    assert_eq!(status, 0x00, "up=false answers without presence");
    let ad = ga_auth_data_flags(&cbor);
    assert_eq!(ad[32] & 0x01, 0x00, "UP bit must NOT be set for up=false");
    assert_eq!(
        GATE_CALLS.load(Ordering::SeqCst),
        0x8000,
        "up=false must never call the presence gate"
    );
    GATE_MODE.store(0, Ordering::SeqCst);
}
