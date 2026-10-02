//! US-1530: the A/B probe's `makeCredential` payload, pinned.
//!
//! `scripts/probe_ab_devices.py` drove a 156-byte `makeCredential` at both
//! boards during the passkey-discovery A/B run. Our board answered `0x12`
//! (`CTAP2_ERR_INVALID_CBOR`); the C reference parked. That looked like a
//! regression in the consent window. It was not — the payload is malformed
//! against the CTAP2.1 §6.3.2 request grammar, and both boards reject it the
//! same way. See `.superpowers/sdd/report-mc-regression.md`.
//!
//! These tests exist so the question can never be ambiguous again. Each one
//! asserts a **specific status byte**. Nothing here accepts "0x12 is fine" or
//! "0x00 is fine" — the point is to pin WHICH is correct, and why.
//!
//! Device path (`device_app::FidoApp` / `device_core.rs`) throughout, per
//! AGENTS.md §1: `app.rs` is a host-only twin and proving things on it proves
//! nothing about hardware.

use fapico2_fido::cbor::no_heap as nh;
use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// `with_user_presence` takes a bare `fn() -> bool`, which cannot capture, so
/// the grant is toggled through a process-local flag. Each test binary is its
/// own process, and the tests here are the only writers.
static PRESENT: AtomicBool = AtomicBool::new(false);

fn injected_presence() -> bool {
    PRESENT.load(Ordering::SeqCst)
}

/// The injected source is process-global, so every test holds this lock.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());


/// The exact 156 wire bytes the A/B probe sent, opcode byte included, so the
/// fixture cannot drift from `docs/webauthn-discovery-ab.md`. Decoded
/// (`cbor2.loads(payload[1:])`), it is:
///
/// | key | CTAP2.1 §6.3.2 requires | probe actually sent |
/// |---|---|---|
/// | 1 `clientDataHash` | `bstr` (32 B) | `map {id, name}` — **wrong type** |
/// | 2 `rp` | `map {id: tstr, name?: tstr}` | `map {type, alg}` — a pubKeyCredParams element |
/// | 3 `user` | `map {id: bstr, name?, displayName?}` | `array(1)` of pubKeyCredParams |
/// | 4 `pubKeyCredParams` | `array` of `{type, alg}` | correct — the only well-typed key |
/// | 5 `excludeList` | `array` of descriptors | `bstr` (32 B) — **wrong type** |
/// | 6 `extensions` | `map` | `map {}` — correct |
/// | 7 `options` | `map` | `map {}` — correct, but **no `rk`** |
///
/// The keys are present and ascending; the *values* are the wrong shape. The
/// failure is at key 1, the first field read.
const PROBE_MC_WIRE: &[u8] = &[
    0x01, 0xa7, 0x01, 0xa2, 0x62, 0x69, 0x64, 0x70, 0x61, 0x62, 0x2d, 0x70, 0x72,
    0x6f, 0x62, 0x65, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x64, 0x6e,
    0x61, 0x6d, 0x65, 0x70, 0x61, 0x62, 0x2d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x2e,
    0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x02, 0xa2, 0x63, 0x61, 0x6c, 0x67,
    0x26, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
    0x2d, 0x6b, 0x65, 0x79, 0x03, 0x81, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x26, 0x64,
    0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b,
    0x65, 0x79, 0x04, 0x81, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x26, 0x64, 0x74, 0x79,
    0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79,
    0x05, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xa0, 0x07, 0xa0,
];

fn app(present: bool) -> FidoApp {
    PRESENT.store(present, Ordering::SeqCst);
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    FidoApp::boot(&mut trng, &mut store)
        .unwrap()
        .with_user_presence(injected_presence)
}

fn call(a: &mut FidoApp, opcode: u8, body: &[u8]) -> (u8, usize) {
    let mut out: HV<u8, MAX_MSG> = HV::new();
    let n = a.process_ctap2(opcode, body, [1, 2, 3, 4], &mut out);
    (out.as_slice()[0], n)
}

/// The A/B probe's payload is **INVALID_CBOR, and that is the correct answer.**
///
/// Not "acceptable to be 0x12" — *required* to be. `parse_mc`
/// (`device_core.rs`) reads key 1 as `Item::B(b)` with `b.len() == 32`; the
/// probe sends a map there, which is neither, so the arm falls to its `_` and
/// returns `InvalidCbor`. The C reference's `cbor_make_credential.c` puts
/// `CBOR_FIELD_GET_BYTES(clientDataHash, 1)` at the same key, so it returns
/// 0x12 too — its one `0x01` keepalive comes from
/// `pico-keys-sdk/src/usb/hid/hid.c:587`, which fires after *every* completed
/// CBOR frame regardless of the command's validity, and is therefore not
/// evidence that it parsed anything.
///
/// This is pinned for the *device* path. The same answer is produced at the
/// pre-epic commit `ea298a6`, so no commit on `fix/passkey-discovery` changed
/// it; the bisect log is in the report.
#[test]
fn ab_probe_mc_payload_is_invalid_cbor() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        PROBE_MC_WIRE.len(),
        156,
        "fixture must stay byte-identical to docs/webauthn-discovery-ab.md"
    );
    let mut a = app(true /* presence granted */);
    let (status, n) = call(&mut a, PROBE_MC_WIRE[0], &PROBE_MC_WIRE[1..]);
    assert_eq!(
        status, 0x12,
        "CTAP2_ERR_INVALID_CBOR — key 1 must be bstr(32), the probe sends a map"
    );
    assert_eq!(n, 1, "a rejected request carries no body");
    assert_eq!(
        a.keystore().credentials.len(),
        0,
        "a rejected request must not mint a credential"
    );
}

/// The same rejection with **no** presence grant: the parse fails *before* the
/// gate, so the answer is identical. This is what distinguishes "the parser
/// rejected it" from "the gate refused it", which is precisely the ambiguity
/// the A/B run walked into — the pre-epic firmware emitted an unconditional
/// pre-command keepalive (`0x02` for every `0x01`/`0x02`, removed by US-1506)
/// that made a parse failure *look* like it had reached the presence gate.
#[test]
fn ab_probe_mc_payload_is_rejected_before_the_presence_gate() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut denied = app(false);
    let (status_no_press, _) = call(&mut denied, PROBE_MC_WIRE[0], &PROBE_MC_WIRE[1..]);
    assert_eq!(status_no_press, 0x12, "parse precedes the gate; no UP required");

    let mut granted = app(true);
    let (status_press, _) = call(&mut granted, PROBE_MC_WIRE[0], &PROBE_MC_WIRE[1..]);
    assert_eq!(
        status_press, status_no_press,
        "presence must not change a parse failure"
    );
}

/// The **corrected** payload — the shape the probe intended and a browser
/// actually sends — parses, and then reaches the presence gate.
///
/// This is the half of the story the old probe could not tell. With no grant
/// the answer is `0x3B` (`CTAP2_ERR_UP_REQUIRED`) — the consent window opens.
/// With a grant it is `0x00` and a full attestation object comes back. So the
/// passkey-registration path the epic cares about is intact; only the probe's
/// bytes were wrong.
#[test]
fn corrected_mc_payload_reaches_the_presence_gate() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    fn corrected() -> HV<u8, 512> {
        let mut r: HV<u8, 512> = HV::new();
        nh::push_map_header(&mut r, 7).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_bstr(&mut r, &[0x11; 32]).unwrap(); // clientDataHash
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_tstr(&mut r, "ab-probe.invalid").unwrap();
        nh::push_tstr(&mut r, "name").unwrap();
        nh::push_tstr(&mut r, "ab-probe.invalid").unwrap();
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_bstr(&mut r, b"ab-probe-user").unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_array_header(&mut r, 4).unwrap();
        for alg in [-7, -8, -35, -36] {
            nh::push_map_header(&mut r, 2).unwrap();
            nh::push_tstr(&mut r, "type").unwrap();
            nh::push_tstr(&mut r, "public-key").unwrap();
            nh::push_tstr(&mut r, "alg").unwrap();
            nh::push_neg(&mut r, alg).unwrap();
        }
        nh::push_uint(&mut r, 5).unwrap();
        nh::push_array_header(&mut r, 0).unwrap(); // excludeList
        nh::push_uint(&mut r, 6).unwrap();
        nh::push_map_header(&mut r, 0).unwrap(); // extensions
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "rk").unwrap();
        nh::push_bool(&mut r, true).unwrap();
        r
    }

    // No grant: parses fine, then the gate refuses. 0x3B, not 0x12 — this is
    // the assertion that would have caught the probe's bug in one run.
    let mut denied = app(false);
    let body = corrected();
    let (status, n) = call(&mut denied, 0x01, body.as_slice());
    assert_eq!(
        status, 0x3B,
        "a well-formed MC must reach the gate and answer UP_REQUIRED, \
         not fail CBOR parsing"
    );
    assert_eq!(n, 1, "a refused MC carries no attestation body");
    assert_eq!(denied.keystore().credentials.len(), 0);

    // Grant: full success, with the attested credential data the parser path
    // is supposed to produce.
    let mut granted = app(true);
    let body = corrected();
    let (status, n) = call(&mut granted, 0x01, body.as_slice());
    assert_eq!(status, 0x00, "a well-formed MC with a grant must mint a credential");
    assert!(n > 100, "success carries an attestation object, got {n} bytes");
    assert_eq!(granted.keystore().credentials.len(), 1);

    // The response must actually parse as CTAP2 makeCredentialResponse, so
    // "0x00" is not satisfied by an empty or truncated body.
    let mut out: HV<u8, MAX_MSG> = HV::new();
    let mut granted = app(true);
    let body = corrected();
    let n = granted.process_ctap2(0x01, body.as_slice(), [1, 2, 3, 4], &mut out);
    assert_eq!(out.as_slice()[0], 0x00);
    let mut p = nh::Parser::new(&out.as_slice()[1..n]);
    assert!(
        matches!(p.next(), Ok(nh::Item::Map(_))),
        "makeCredentialResponse must be a CBOR map"
    );
}

/// The **exact bytes `scripts/probe_ab_devices.py` now sends**, pinned here so
/// the probe and the firmware cannot drift apart again. This is the
/// regression's actual fix: the probe stopped emitting a malformed request,
/// and this proves the corrected request is one our parser accepts and routes
/// to the consent window. Encoded with `fido2.cbor.encode` -- the very codec
/// the probe uses -- so the fixture is the probe's real output, not a
/// hand-written approximation of it.
#[test]
fn corrected_probe_wire_bytes_reach_the_presence_gate() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    const CORRECTED_PROBE_BODY: &[u8] = &[
    0xa7, 0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xa2, 0x62,
    0x69, 0x64, 0x70, 0x61, 0x62, 0x2d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x2e, 0x69,
    0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x70, 0x61,
    0x62, 0x2d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c,
    0x69, 0x64, 0x03, 0xa3, 0x62, 0x69, 0x64, 0x4d, 0x61, 0x62, 0x2d, 0x70, 0x72,
    0x6f, 0x62, 0x65, 0x2d, 0x75, 0x73, 0x65, 0x72, 0x64, 0x6e, 0x61, 0x6d, 0x65,
    0x70, 0x61, 0x62, 0x2d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x2e, 0x69, 0x6e, 0x76,
    0x61, 0x6c, 0x69, 0x64, 0x6b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e,
    0x61, 0x6d, 0x65, 0x68, 0x61, 0x62, 0x2d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x04,
    0x84, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x26, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a,
    0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0xa2, 0x63, 0x61,
    0x6c, 0x67, 0x27, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c,
    0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x38, 0x22,
    0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d,
    0x6b, 0x65, 0x79, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x38, 0x23, 0x64, 0x74, 0x79,
    0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79,
    0x05, 0x80, 0x06, 0xa0, 0x07, 0xa1, 0x62, 0x72, 0x6b, 0xf5,
    ];

    // No grant: grammar-valid, so it reaches the gate and is refused for
    // presence -- 0x3B, and emphatically not 0x12.
    let mut denied = app(false);
    let (status, _) = call(&mut denied, 0x01, CORRECTED_PROBE_BODY);
    assert_eq!(status, 0x3B, "the corrected probe payload must reach the gate");

    // With a grant it completes.
    let mut granted = app(true);
    let (status, n) = call(&mut granted, 0x01, CORRECTED_PROBE_BODY);
    assert_eq!(status, 0x00, "corrected probe payload completes with a grant");
    assert!(n > 100, "attestation body present, got {n}");
}
