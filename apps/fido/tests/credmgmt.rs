//! Tests for credMgmt completeness (FX-411).

mod common;

use common::*;
use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::crypto;
use fapico2_fido::keystore::MemoryKeystore;

fn cm_req(subcommand: u8, token: &[u8], params: Option<Value>) -> Vec<u8> {
    let mut auth_data: Vec<u8> = vec![subcommand];
    let mut map = vec![(Value::U(0x01), Value::U(subcommand as u64))];
    if let Some(p) = params {
        auth_data.extend_from_slice(&cbor::encode(&p));
        map.push((Value::U(0x02), p));
    }
    map.push((Value::U(0x03), Value::U(2)));
    map.push((
        Value::U(0x04),
        Value::B(crypto::pin_uv_auth_param(2, &token.try_into().unwrap(), &auth_data)),
    ));
    cbor::encode(&Value::M(map))
}

/// The pinUvAuth message PicoForge signs, mirroring
/// `sign_credential_mgmt_command` in
/// `picoforge/src/hal/fido/ops.rs:1671-1694` byte for byte: the bare
/// sub-command byte for GetCredsMetadata (0x01) and EnumerateRpsBegin
/// (0x02), and `subCommand ‖ CBOR(subCommandParams)` for every other
/// sub-command.
fn picoforge_auth_msg(subcommand: u8, params: Option<&Value>) -> Vec<u8> {
    let mut msg = vec![subcommand];
    if let Some(p) = params {
        if !matches!(subcommand, 0x01 | 0x02) {
            msg.extend_from_slice(&cbor::encode(p));
        }
    }
    msg
}

/// A credMgmt request in PicoForge's exact wire form: pinUvAuthProtocol 1
/// with the HMAC truncated to 16 bytes (`ops.rs:1693`,
/// `sig.as_ref()[0..16]`). The sibling `cm_req` above always uses protocol 2
/// with a 32-byte MAC, so it cannot express this form.
///
/// The 16-byte length is not asserted here: it is fixed by the protocol
/// argument two lines down, so an assertion would be a tautology. The real
/// length check lives in `crypto::pin_verify_auth`, which rejects a param
/// whose length disagrees with the declared protocol — a request carrying a
/// 32-byte MAC under protocol 1 fails below, which is what makes these tests
/// exercise the 16-byte path rather than merely assert it.
fn picoforge_cred_req(subcommand: u8, token: &[u8], params: Option<Value>) -> Vec<u8> {
    let auth_msg = picoforge_auth_msg(subcommand, params.as_ref());
    let mac = crypto::pin_uv_auth_param(1, &token.try_into().unwrap(), &auth_msg);
    let mut map = vec![(Value::U(0x01), Value::U(subcommand as u64))];
    if let Some(p) = params {
        map.push((Value::U(0x02), p));
    }
    map.push((Value::U(0x03), Value::U(1)));
    map.push((Value::U(0x04), Value::B(mac)));
    cbor::encode(&Value::M(map))
}

fn make_resident(app: &mut FidoApp<MemoryKeystore>, client: &PinClient, rp: &str, protect: i64) {
    let _ = make_resident_with_id(app, client, rp, protect);
}

/// As `make_resident`, but also returns the new credential's id, pulled from
/// the attested credential data in the makeCredential response.
fn make_resident_with_id(
    app: &mut FidoApp<MemoryKeystore>,
    client: &PinClient,
    rp: &str,
    protect: i64,
) -> Vec<u8> {
    let token = client.get_token(app, 0x09, Some(0x01), None).unwrap();
    let hash = crypto::sha256(rp.as_bytes());
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::B(hash.to_vec())),
        (
            Value::U(0x02),
            Value::M(vec![
                (Value::T("id".to_string()), Value::T(rp.to_string())),
                (Value::T("name".to_string()), Value::T("RP".to_string())),
            ]),
        ),
        (
            Value::U(0x03),
            Value::M(vec![
                (Value::T("id".to_string()), Value::B(b"user".to_vec())),
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
        (
            Value::U(0x06),
            Value::M(vec![(
                Value::T("credProtect".to_string()),
                Value::U(protect as u64),
            )]),
        ),
        (
            Value::U(0x07),
            Value::M(vec![(Value::T("rk".to_string()), Value::Bool(true))]),
        ),
        (Value::U(0x08), Value::B(crypto::pin_uv_auth_param(2, &token.try_into().unwrap(), &hash))),
        (Value::U(0x09), Value::U(2)),
    ]));
    let resp = app.process_ctap2(0x01, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "makeCredential must succeed");
    // authData (CBOR key 2) = rpIdHash(32) ‖ flags(1) ‖ counter(4) ‖
    // aaguid(16) ‖ credIdLen(2) ‖ credId.
    let (v, _) = cbor::decode(&resp[1..]).expect("valid CBOR response");
    let auth_data = match v {
        Value::M(m) => m
            .iter()
            .find(|(k, _)| matches!(k, Value::U(0x02)))
            .and_then(|(_, v)| match v {
                Value::B(b) => Some(b.clone()),
                _ => None,
            })
            .expect("authData (0x02) in the makeCredential response"),
        other => panic!("expected map, got {:?}", other),
    };
    // CTAP2 authData layout: rpIdHash(32) ‖ flags(1) ‖ counter(4) ‖
    // aaguid(16) = 53 bytes, then credIdLen(2) ‖ credId.
    const AUTH_DATA_PREFIX_LEN: usize = 32 + 1 + 4 + 16;
    let id_len_at = AUTH_DATA_PREFIX_LEN;
    let id_len = u16::from_be_bytes([auth_data[id_len_at], auth_data[id_len_at + 1]]) as usize;
    let id_at = id_len_at + 2;
    auth_data[id_at..id_at + id_len].to_vec()
}

#[test]
fn test_enumerate_creds_includes_cred_protect() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com", 2);

    let cm_token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();
    let rp_hash = crypto::sha256(b"example.com");
    let params = Value::M(vec![(Value::U(0x01), Value::B(rp_hash.to_vec()))]);
    let resp = app.process_ctap2(0x0A, &cm_req(0x04, &cm_token, Some(params)), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "enumerateCredsBegin must succeed");
    let (v, _) = cbor::decode(&resp[1..]).unwrap();
    match v {
        Value::M(m) => {
            let protect = m
                .iter()
                .find(|(k, _)| matches!(k, Value::U(0x0A)))
                .map(|(_, v)| match v {
                    Value::U(u) => *u,
                    _ => panic!("credProtect must be uint"),
                })
                .expect("credProtect (0x0A) must be included in enumerateCreds responses");
            assert_eq!(protect, 2);
        }
        other => panic!("expected map, got {:?}", other),
    }
}

#[test]
fn test_metadata_includes_max_possible_remaining() {
    let (mut app, client) = setup();
    let cm_token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();
    let resp = app.process_ctap2(0x0A, &cm_req(0x01, &cm_token, None), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00);
    let (v, _) = cbor::decode(&resp[1..]).unwrap();
    match v {
        Value::M(m) => {
            assert!(
                m.iter().any(|(k, _)| matches!(k, Value::U(0x03))),
                "maxPossibleRemainingCredentials (0x03) must be present"
            );
        }
        other => panic!("expected map, got {:?}", other),
    }
}

#[test]
fn test_enumeration_state_invalidated_by_other_command() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com", 1);

    let cm_token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();
    let resp = app.process_ctap2(0x0A, &cm_req(0x02, &cm_token, None), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "enumerateRpsBegin must succeed");

    // A non-credMgmt command in between resets the enumeration state.
    let _ = app.process_ctap2(0x04, &[], [1, 2, 3, 4]); // getInfo

    let resp = app.process_ctap2(0x0A, &cm_req(0x03, &cm_token, None), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x30, "enumerateRpsNext after a foreign command must be NOT_ALLOWED");
}

#[test]
fn test_get_next_assertion_without_pending_is_not_allowed() {
    let (mut app, _client) = setup();
    let resp = app.process_ctap2(0x08, &[], [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x30, "getNextAssertion with no sequence must be NOT_ALLOWED");
}

#[test]
fn test_u2f_registration_not_discoverable() {
    let (mut app, client) = setup();
    // U2F REGISTER: client_param(32) || app_param(32); INS 0x01.
    let client_param = [0x44u8; 32];
    let app_param = crypto::sha256(b"u2f.example.com");
    let mut apdu: Vec<u8> = vec![0x00, 0x01, 0x03, 0x00, 0x00];
    let apdu_data: Vec<u8> = [client_param.to_vec(), app_param.to_vec()].concat();
    apdu.extend_from_slice(&(apdu_data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(&apdu_data);
    let resp = app.process_u2f(&apdu);
    assert_eq!(
        u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]),
        0x9000,
        "U2F register must succeed"
    );

    // credMgmt enumerateRpsBegin must not surface it.
    let cm_token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();
    let resp = app.process_ctap2(0x0A, &cm_req(0x02, &cm_token, None), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x2E, "U2F registrations must not be enumerable");

    // Discoverable getAssertion must not return it either.
    let ga_req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::T("u2f.example.com".to_string())),
        (Value::U(0x02), Value::B(crypto::sha256(b"client").to_vec())),
    ]));
    let resp = app.process_ctap2(0x02, &ga_req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x2E, "U2F registrations must not be discoverable");
}

/// US-121: the three credMgmt sub-commands PicoForge actually calls, signed
/// with PicoForge's exact scheme (protocol 1, 16-byte MAC, bare sub-command
/// byte for 0x01/0x02), are accepted on the host path.
///
/// This is a regression guard, not a new capability — see the "credMgmt
/// pinUvAuth message" section of `docs/known-gate-divergences.md`.
/// fapico2 signs `subCommand ‖ CBOR(params)` with no `0xFF×32 ‖ 0x0A`
/// prefix, which deviates from CTAP 2.1 but is byte-identical to PicoForge,
/// so no build-time compat feature is needed or wanted.
#[test]
fn picoforge_mac_scheme_is_accepted() {
    let (mut app, client) = setup();
    let cred_id = make_resident_with_id(&mut app, &client, "example.com", 2);
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    // 0x02 enumerateRPsBegin — PicoForge passes subParams = None
    // (`ops.rs:1092`), so the MAC covers the sub-command byte alone.
    let resp = app.process_ctap2(0x0A, &picoforge_cred_req(0x02, &token, None), [1, 2, 3, 4]);
    assert_eq!(
        resp[0], 0x00,
        "enumerateRPsBegin with PicoForge's MAC scheme must succeed"
    );

    // 0x04 enumerateCredentialsBegin — params {1: rpIdHash} (`ops.rs:1244`).
    let rp_hash = crypto::sha256(b"example.com");
    let params = Value::M(vec![(Value::U(0x01), Value::B(rp_hash.to_vec()))]);
    let resp = app.process_ctap2(
        0x0A,
        &picoforge_cred_req(0x04, &token, Some(params)),
        [1, 2, 3, 4],
    );
    assert_eq!(
        resp[0], 0x00,
        "enumerateCredentialsBegin with PicoForge's MAC scheme must succeed"
    );

    // 0x06 deleteCredential — params {2: {type, id}} (`ops.rs:1419`).
    //
    // The literal below lists `type` before `id`, but that source order is
    // NOT what gets signed and NOT what goes on the wire: `cbor::encode`
    // re-sorts map keys by encoded representation (`cbor.rs:441-446`), so it
    // emits `62 69 64` ("id") before `64 74 79 70 65` ("type"). The host
    // rebuilds the same descriptor map and runs it through the same
    // canonicalising encoder (`app.rs:1812-1819`), so client and host sign
    // identical bytes *regardless of the order written here* — which is why
    // this passes, and why reordering the literal (or "fixing"
    // `app.rs:1812-1815` to match it) would change nothing. See the
    // "host re-derives the MAC" note in
    // `docs/known-gate-divergences.md` for the cases where the
    // canonicalisation does *not* save the two sides.
    let params = Value::M(vec![(
        Value::U(0x02),
        Value::M(vec![
            (
                Value::T("type".to_string()),
                Value::T("public-key".to_string()),
            ),
            (Value::T("id".to_string()), Value::B(cred_id)),
        ]),
    )]);
    let resp = app.process_ctap2(
        0x0A,
        &picoforge_cred_req(0x06, &token, Some(params)),
        [1, 2, 3, 4],
    );
    assert_eq!(
        resp[0], 0x00,
        "deleteCredential with PicoForge's MAC scheme must succeed"
    );
}

/// The **positive** half of the host/device credMgmt MAC-scope split.
///
/// The host signs `subCommand` alone for `0x01`/`0x02` — it re-derives the
/// params from parsed fields and yields `None` (`app.rs:1799-1847`) — so a
/// client that signs PicoForge's way (params excluded) is accepted **even
/// when it also sends `subCommandParams`**. The attached params are simply
/// outside the signed scope on this path.
///
/// Its sibling, `device_full_set.rs::device_twin_credmgmt_mac_scope_differs_from_host_for_0x01_and_0x02`,
/// asserts the **negative** half: the device twin signs over the raw params
/// bytes whenever the client sent any (`device_core.rs:2174-2176`) and
/// therefore refuses the very same request with `0x33`. Together they pin
/// both sides of one divergence, on real requests, rather than in prose.
#[test]
fn host_accepts_picoforge_mac_with_params_omitted_from_scope() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com", 2);
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    // Params a client would attach: for 0x01/0x02 these are not part of the
    // host's signed message, so the request is accepted regardless of them.
    let params = Value::M(vec![(
        Value::U(0x01),
        Value::B(crypto::sha256(b"example.com").to_vec()),
    )]);

    for sub in [0x01u8, 0x02u8] {
        let req = picoforge_cred_req(sub, &token, Some(params.clone()));
        let resp = app.process_ctap2(0x0A, &req, [1, 2, 3, 4]);
        assert_eq!(
            resp[0], 0x00,
            "host must accept sub-command {sub:#04x} signed over the sub-command byte alone, \
             with subCommandParams present but outside the signed scope"
        );
    }
}
