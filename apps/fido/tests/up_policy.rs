//! US-1526: the `up` policy — decided, written down, and pinned on both
//! twins.
//!
//! The decision itself lives in the code, at the rejection site, on the twin
//! that ships (`device_core.rs::make_credential_inner`, under "THE `up`
//! POLICY, decided"). This file is the other half of the deliverable: the
//! tests, so that changing the policy has to be a deliberate act on a named
//! test rather than an edit that nobody notices.
//!
//! The shape, in one table. Every row is asserted on **both** twins, because
//! the epic's DoD is that the emulator and the board answer identically, and
//! because a host-only assertion is precisely what let US-1514 through.
//!
//! | request | answer | why |
//! |---|---|---|
//! | MC `options.up = false` | `0x2C` INVALID_OPTION | `up` is not advertised (CTAP2.1 §6.1), and the reference rejects it outright — `pico-fido/src/fido/cbor_make_credential.c:387` |
//! | MC `options.up = true` / absent | gated on presence | US-907; never a silent credential |
//! | GA `options.up = false` | **served**, silently, UP bit clear | a silent assertion is a real thing; reference takes it at `cbor_get_assertion.c:322` |
//! | GA `up = false` + hmac-secret | `0x2C` INVALID_OPTION | the reference's one rejected combination, `cbor_get_assertion.c:324` |
//!
//! The GA row and the MC row look contradictory and are not: MC never mints
//! anything new, so refusing `up:false` costs a client nothing it was
//! entitled to; GA signs with a key that already exists, which is what makes
//! a silent assertion meaningful at all.
//!
//! US-1528 moved INVALID_OPTION from `0x2B` to `0x2C`. The *policy* below is
//! unchanged and is not what this story is about — only the byte the policy
//! travels on was wrong, so every one of these rejections was being read by
//! every client as UNSUPPORTED_OPTION. `tests/status_table.rs` is what keeps
//! the byte itself honest; the constant here is deliberately written as a
//! literal so this file keeps testing the wire and not the enum.

use fapico2_fido::app::FidoApp as HostApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::keystore::MemoryKeystore;
use fapico2_fido::FidoApp as DeviceApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// `CTAP2_ERR_INVALID_OPTION` — `CtapError.ERR.INVALID_OPTION`, **0x2C**.
/// US-1528: this was `0x2B`, which is `UNSUPPORTED_OPTION`. Kept as a literal
/// rather than `Ctap2Response::InvalidOption.code()` on purpose: this file's
/// job is to prove the *wire* byte, and reading the value back out of the enum
/// it is supposed to be checking would make every assertion below vacuous.
const INVALID_OPTION: u8 = 0x2C;
/// `CTAP2_ERR_UNSUPPORTED_OPTION` — the byte INVALID_OPTION used to be, and
/// the one a `ne!` guard must also exclude, so "not INVALID_OPTION" is not
/// satisfied by accident by having become UNSUPPORTED_OPTION instead.
const UNSUPPORTED_OPTION: u8 = 0x2B;
const UP_REQUIRED: u8 = 0x3B;
const INVALID_COMMAND: u8 = 0x01;

const MC: u8 = 0x01;
const GA: u8 = 0x02;
const GET_INFO: u8 = 0x04;

// ------------------------------------------------------------------
// Twins
// ------------------------------------------------------------------

/// The host twin (`app.rs`) — std-only, `process_ctap2 -> Vec<u8>`.
fn host() -> HostApp {
    HostApp::with_keystore(MemoryKeystore::new())
}

/// The device twin (`device_app.rs`) — what the RP2350 runs,
/// `process_ctap2(&mut heapless::Vec) -> usize`.
fn device() -> DeviceApp {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    DeviceApp::boot(&mut trng, &mut store).expect("host TRNG + store boot the device app")
}

/// Run one request against both twins and return `(host_status, device_status)`.
///
/// The statuses are the first response byte — enough for every assertion here
/// and insensitive to the two stacks' different body encoders, which are not
/// what this story is about.
fn both_twins(cmd: u8, request: &[u8]) -> (u8, u8) {
    let mut h = host();
    let host_resp = h.process_ctap2(cmd, request, [1, 2, 3, 4]);

    let mut d = device();
    let mut out = HV::<u8, MAX_MSG>::new();
    let n = d.process_ctap2(cmd, request, [1, 2, 3, 4], &mut out);

    assert!(!host_resp.is_empty(), "host twin produced no status byte");
    assert!(n >= 1, "device twin produced no status byte");
    (host_resp[0], out[0])
}

// ------------------------------------------------------------------
// Request builders
// ------------------------------------------------------------------

/// makeCredential: `options` is emitted under CBOR key 7 only when present.
fn mc(up: Option<bool>) -> Vec<u8> {
    let mut map = vec![
        (Value::U(0x01), Value::B(vec![0xCC; 32])),
        (
            Value::U(0x02),
            Value::M(vec![
                (Value::T("id".to_string()), Value::T("example.com".to_string())),
                (Value::T("name".to_string()), Value::T("RP".to_string())),
            ]),
        ),
        (
            Value::U(0x03),
            Value::M(vec![
                (Value::T("id".to_string()), Value::B(b"user-1".to_vec())),
                (Value::T("name".to_string()), Value::T("U".to_string())),
            ]),
        ),
        (
            Value::U(0x04),
            Value::A(vec![Value::M(vec![
                (Value::T("type".to_string()), Value::T("public-key".to_string())),
                (Value::T("alg".to_string()), Value::N(-7)),
            ])]),
        ),
    ];
    if let Some(up) = up {
        map.push((
            Value::U(0x07),
            Value::M(vec![(Value::T("up".to_string()), Value::Bool(up))]),
        ));
    }
    cbor::encode(&Value::M(map))
}

/// getAssertion: `options` under CBOR key 5, `extensions` under key 4.
///
/// `hmac_secret` builds an `hmac-secret` input map in the shape **both**
/// parsers accept — the device's `parse_key_agreement` requires exactly 32-byte
/// coordinates and `parse_hmac_secret_input` (v1 lengths: saltEnc 32, saltAuth
/// 16). The salt contents are never checked on this path: the `up:false` +
/// hmac-secret check runs before any crypto, on both twins.
fn ga(up: Option<bool>, hmac_secret: bool) -> Vec<u8> {
    let mut map = vec![
        (Value::U(0x01), Value::T("example.com".to_string())),
        (Value::U(0x02), Value::B(vec![0xDD; 32])),
    ];
    if hmac_secret {
        map.push((
            Value::U(0x04),
            Value::M(vec![(
                Value::T("hmac-secret".to_string()),
                Value::M(vec![
                    (
                        Value::U(0x01),
                        Value::M(vec![
                            (Value::U(0x01), Value::U(2)),    // kty: EC2
                            (Value::U(0x03), Value::N(-25)),  // alg: ECDH-ES+HKDF-256
                            (Value::N(-1), Value::U(1)),      // crv: P-256
                            (Value::N(-2), Value::B(vec![0x11; 32])),
                            (Value::N(-3), Value::B(vec![0x22; 32])),
                        ]),
                    ),
                    (Value::U(0x02), Value::B(vec![0x33; 32])), // saltEnc, v1 length
                    (Value::U(0x03), Value::B(vec![0x44; 16])), // saltAuth, v1 length
                    (Value::U(0x04), Value::U(1)),             // pinUvAuthProtocol 1
                ]),
            )]),
        ));
    }
    if let Some(up) = up {
        map.push((
            Value::U(0x05),
            Value::M(vec![(Value::T("up".to_string()), Value::Bool(up))]),
        ));
    }
    cbor::encode(&Value::M(map))
}

// ------------------------------------------------------------------
// makeCredential: up:false is INVALID_OPTION, on both twins
// ------------------------------------------------------------------

/// The decision itself. `up:false` is a hard rejection, not a silent mint.
#[test]
fn mc_up_false_is_invalid_option_on_both_twins() {
    let (host_status, device_status) = both_twins(MC, &mc(Some(false)));
    assert_eq!(
        device_status, INVALID_OPTION,
        "device twin must reject MC up:false"
    );
    assert_eq!(
        host_status, device_status,
        "the twins must answer MC up:false identically"
    );
}

/// Names the direction of the epic's divergence hunt: this is the byte the
/// board used to be unable to produce for this request without falling out of
/// the story. `0x01` here would mean the request never reached the `up`
/// check at all.
#[test]
fn mc_up_false_is_not_a_dispatch_failure() {
    let (_, device_status) = both_twins(MC, &mc(Some(false)));
    assert_ne!(device_status, INVALID_COMMAND);
}

/// The neighbouring shapes must NOT be swept into the same rejection — if
/// they were, `0x2C` above would prove nothing about `up` in particular.
///
/// Both option-statuses are excluded. Under US-1528 a `ne!(INVALID_OPTION)`
/// alone was exactly the assertion that kept passing for the wrong reason: the
/// rejection had quietly become `UNSUPPORTED_OPTION`, which is a different
/// byte and still "not INVALID_OPTION".
#[test]
fn mc_up_true_and_absent_are_not_invalid_option() {
    for request in [mc(Some(true)), mc(None)] {
        let (host_status, device_status) = both_twins(MC, &request);
        assert_ne!(
            device_status, INVALID_OPTION,
            "only an explicit up:false is rejected; up:true and an absent \
             options map must not be"
        );
        assert_ne!(
            device_status, UNSUPPORTED_OPTION,
            "and not by the neighbouring status either — a sweep into \
             UNSUPPORTED_OPTION would satisfy the check above"
        );
        assert_eq!(host_status, device_status, "twins must agree");
    }
}

/// Ordering, and this is the part US-907 turns on: the `up:false` rejection
/// happens **before** the presence gate. With a fail-closed presence source —
/// what the device build default resolves to — a request that reached the
/// gate instead of the check would answer `0x3B`, not `0x2C`.
///
/// So there is no path from an accepted MC to a credential minted with zero
/// touch: the only way to skip the touch is to send `up:false`, and that is
/// refused before the keypair is even generated.
#[test]
fn mc_up_false_is_rejected_before_the_presence_gate() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut app = DeviceApp::boot(&mut trng, &mut store)
        .expect("host TRNG + store boot the device app")
        .with_user_presence(|| false);
    let mut out = HV::<u8, MAX_MSG>::new();
    let n = app.process_ctap2(MC, &mc(Some(false)), [1, 2, 3, 4], &mut out);
    assert_eq!(n, 1, "a status-only rejection carries no body");
    assert_eq!(out[0], INVALID_OPTION);

    // The control: the same app, with `up:true` instead, does reach the gate.
    let mut out2 = HV::<u8, MAX_MSG>::new();
    app.process_ctap2(MC, &mc(Some(true)), [1, 2, 3, 4], &mut out2);
    assert_eq!(
        out2[0], UP_REQUIRED,
        "up:true must reach the presence gate and be refused for want of a \
         touch — if this also answered 0x2C the rejection would be catching \
         something other than up:false"
    );
}

// ------------------------------------------------------------------
// getAssertion: up:false is SERVED (except with hmac-secret)
// ------------------------------------------------------------------

/// `up:false` gets past option validation on both twins — the request
/// reaches credential matching instead of being turned away.
///
/// `tests/uv.rs::test_ga_up_false_uv_true_is_not_invalid_option` pins the
/// host twin's half of this; `ga_up_false_asserts_a_credential_silently`
/// below pins the stronger claim.
#[test]
fn ga_up_false_is_served_not_rejected() {
    let (host_status, device_status) = both_twins(GA, &ga(Some(false), false));
    assert_ne!(
        device_status, INVALID_OPTION,
        "a silent getAssertion is a real thing and must not be rejected at \
         option validation"
    );
    assert_eq!(host_status, device_status, "twins must agree");
}

/// The full claim: mint a resident credential, then assert it with
/// `up:false`, on both twins. The credential exists (so the answer is a real
/// assertion, not NO_CREDENTIALS) and the UP bit is clear — a silent
/// authentication.
///
/// This is the test that makes the MC/GA asymmetry credible rather than
/// merely asserted: the same `up` option is refused on makeCredential and
/// honoured on getAssertion, because the first mints something and the second
/// only uses what is already there.
#[test]
fn ga_up_false_asserts_a_credential_silently() {
    // Resident (rk: true) so the later getAssertion can find it by RP alone.
    let create = {
        let mut map = match cbor::decode(&mc(None)).unwrap().0 {
            Value::M(m) => m,
            other => panic!("builder produced {other:?}"),
        };
        map.push((
            Value::U(0x07),
            Value::M(vec![(Value::T("rk".to_string()), Value::Bool(true))]),
        ));
        cbor::encode(&Value::M(map))
    };
    let request = ga(Some(false), false);

    // Host twin.
    let mut h = host();
    let made = h.process_ctap2(MC, &create, [1, 2, 3, 4]);
    assert_eq!(made[0], 0x00, "host twin: the credential must mint");
    let asserted = h.process_ctap2(GA, &request, [1, 2, 3, 4]);
    assert_eq!(asserted[0], 0x00, "host twin: up:false must be served");
    assert!(
        !up_bit(&asserted),
        "host twin: a silent assertion must not set the UP flag"
    );

    // Device twin — same bytes, same expectations.
    let mut d = device();
    let mut out = HV::<u8, MAX_MSG>::new();
    let n_made = d.process_ctap2(MC, &create, [1, 2, 3, 4], &mut out);
    assert_eq!(out[0], 0x00, "device twin: the credential must mint");
    assert!(n_made > 1, "the minted response must carry a CBOR body");
    let mut out2 = HV::<u8, MAX_MSG>::new();
    let n2 = d.process_ctap2(GA, &request, [1, 2, 3, 4], &mut out2);
    assert_eq!(out2[0], 0x00, "device twin: up:false must be served");
    assert!(
        !up_bit(&out2[..n2]),
        "device twin: a silent assertion must not set the UP flag"
    );
}

/// The UP flag of a packed getAssertion response: authData is
/// `rpIdHash(32) || flags(1)`, and bit 0 of `flags` is UP.
fn up_bit(response: &[u8]) -> bool {
    let (value, _) = cbor::decode(&response[1..]).expect("assertion body is CBOR");
    let Value::M(map) = value else {
        panic!("assertion body is not a map")
    };
    let auth_data = map
        .iter()
        .find(|(k, _)| matches!(k, Value::U(0x02)))
        .map(|(_, v)| v)
        .expect("assertion carries authData (key 2)");
    let Value::B(b) = auth_data else {
        panic!("authData is not a byte string")
    };
    b[32] & 0x01 != 0
}

/// The one rejected GA combination — and the parity the brief asked to be
/// checked. It is present on **both** twins: the device has had it since the
/// initial release (`device_core.rs`, `handle_get_assertion`) and the host has
/// its copy in `app.rs`. The brief reported only the host had it; it did not,
/// and this test is what makes that finding durable.
#[test]
fn ga_up_false_with_hmac_secret_is_invalid_option_on_both_twins() {
    let (host_status, device_status) = both_twins(GA, &ga(Some(false), true));
    assert_eq!(
        device_status, INVALID_OPTION,
        "device twin must reject a silent assertion carrying hmac-secret"
    );
    assert_eq!(
        host_status, device_status,
        "the GA hmac-secret rejection must not be host-only — the brief for \
         this story suspected it was; it is not"
    );
}

/// The same request without `up:false` is a normal assertion, so the rejection
/// above is about the *silent* half of the combination and not about
/// hmac-secret being unsupported.
#[test]
fn hmac_secret_without_up_false_is_not_invalid_option() {
    for up in [Some(true), None] {
        let (host_status, device_status) = both_twins(GA, &ga(up, true));
        assert_ne!(
            device_status, INVALID_OPTION,
            "hmac-secret with a present/absent up must not hit the \
             up:false rejection"
        );
        assert_eq!(host_status, device_status, "twins must agree");
    }
}

// ------------------------------------------------------------------
// The advertisement the whole policy rests on
// ------------------------------------------------------------------

/// `up` is not in the getInfo options map. CTAP2.1 §6.1 says a request naming
/// an unadvertised option must be rejected, and that is the rule the MC
/// rejection above rests on — so if this ever changes, the MC policy has to be
/// re-decided with it.
///
/// `tests/getinfo.rs:33` already pins this on the default `Ctap2Info`; this
/// asserts it on the **bytes both twins actually put on the wire**, which is a
/// different claim (a twin could add the option in its own `handle_get_info`
/// and leave the struct alone).
#[test]
fn up_is_not_advertised_by_either_twin() {
    for status_and_options in [
        {
            let mut h = host();
            h.process_ctap2(GET_INFO, &[], [1, 2, 3, 4])
        },
        {
            let mut d = device();
            let mut out = HV::<u8, MAX_MSG>::new();
            let n = d.process_ctap2(GET_INFO, &[], [1, 2, 3, 4], &mut out);
            out[..n].to_vec()
        },
    ] {
        assert_eq!(status_and_options[0], 0x00, "getInfo must succeed");
        let (value, _) = cbor::decode(&status_and_options[1..]).expect("getInfo body is CBOR");
        let map = match &value {
            Value::M(m) => m,
            other => panic!("getInfo body is not a map: {other:?}"),
        };
        let options = map
            .iter()
            .find(|(k, _)| matches!(k, Value::U(0x04)))
            .map(|(_, v)| v)
            .expect("getInfo must carry an options map (key 4)");
        let Value::M(options) = options else {
            panic!("options (key 4) is not a map")
        };
        assert!(
            !options
                .iter()
                .any(|(k, _)| matches!(k, Value::T(s) if s == "up")),
            "the `up` option must stay unadvertised: CTAP2.1 requires a \
             request naming an unadvertised option to be rejected, which is \
             exactly what makeCredential's up:false rejection does"
        );
    }
}