//! Tests for uv / alwaysUv / credProtect gating (FX-407).

mod common;

use common::*;
use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::keystore::MemoryKeystore;

fn mc_request(
    hash: &[u8; 32],
    rp_id: &str,
    token: &[u8],
    extensions: Option<Value>,
    resident: bool,
) -> Vec<u8> {
    let mut map = vec![
        (Value::U(0x01), Value::B(hash.to_vec())),
        (
            Value::U(0x02),
            Value::M(vec![
                (Value::T("id".to_string()), Value::T(rp_id.to_string())),
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
    ];
    if let Some(ext) = extensions {
        map.push((Value::U(0x06), ext));
    }
    map.push((
        Value::U(0x07),
        Value::M(vec![(Value::T("rk".to_string()), Value::Bool(resident))]),
    ));
    map.push((Value::U(0x08), Value::B(pin_uv_auth(token, hash))));
    map.push((Value::U(0x09), Value::U(2)));
    cbor::encode(&Value::M(map))
}

fn ga_request(hash: &[u8; 32], rp_id: &str, token: Option<&[u8]>, up: Option<bool>) -> Vec<u8> {
    let mut map = vec![
        (Value::U(0x01), Value::T(rp_id.to_string())),
        (Value::U(0x02), Value::B(hash.to_vec())),
    ];
    if let Some(t) = token {
        map.push((Value::U(0x06), Value::B(pin_uv_auth(t, hash))));
        map.push((Value::U(0x07), Value::U(2)));
    }
    if let Some(up) = up {
        map.push((
            Value::U(0x05),
            Value::M(vec![(Value::T("up".to_string()), Value::Bool(up))]),
        ));
    }
    cbor::encode(&Value::M(map))
}

fn toggle_always_uv(app: &mut FidoApp<MemoryKeystore>, client: &PinClient) {
    let token = client.get_token(app, 0x09, Some(0x20), None).unwrap();
    let auth_msg: Vec<u8> = [vec![0xffu8; 32], vec![0x0d, 0x02]].concat();
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x02)),
        (Value::U(0x03), Value::U(2)),
        (Value::U(0x04), Value::B(pin_uv_auth(&token, &auth_msg))),
    ]));
    let resp = app.process_ctap2(0x0D, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "toggle alwaysUv must succeed");
}

fn make_resident_credential(
    app: &mut FidoApp<MemoryKeystore>,
    client: &PinClient,
    protect: i64,
) {
    let token = client.get_token(app, 0x09, Some(0x01), None).unwrap();
    let hash = [0x61u8; 32];
    let ext = Value::M(vec![(
        Value::T("credProtect".to_string()),
        Value::U(protect as u64),
    )]);
    let resp = app.process_ctap2(
        0x01,
        &mc_request(&hash, "example.com", &token, Some(ext), true),
        [1, 2, 3, 4],
    );
    assert_eq!(resp[0], 0x00, "makeCredential with credProtect must succeed");
}

#[test]
fn test_ga_uv_true_without_param_is_puat_required() {
    let (mut app, _client) = setup();
    let hash = [0x71u8; 32];
    // uv=true with no pinUvAuthParam → PUAT_REQUIRED (0x36), never a
    // UP-only assertion.
    let mut map = cbor::decode(&ga_request(&hash, "example.com", None, None))
        .map(|(v, _)| v)
        .unwrap();
    if let Value::M(ref mut m) = map {
        m.push((
            Value::U(0x05),
            Value::M(vec![(Value::T("uv".to_string()), Value::Bool(true))]),
        ));
    }
    let resp = app.process_ctap2(0x02, &cbor::encode(&map), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x36, "uv=true without pinUvAuthParam must be PUAT_REQUIRED");
}

#[test]
fn test_ga_up_false_uv_true_is_not_invalid_option() {
    let (mut app, _client) = setup();
    let hash = [0x72u8; 32];
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::T("example.com".to_string())),
        (Value::U(0x02), Value::B(hash.to_vec())),
        (
            Value::U(0x05),
            Value::M(vec![
                (Value::T("up".to_string()), Value::Bool(false)),
                (Value::T("uv".to_string()), Value::Bool(true)),
            ]),
        ),
    ]));
    let resp = app.process_ctap2(0x02, &req, [1, 2, 3, 4]);
    // US-1528: INVALID_OPTION is 0x2C. This used to read `assert_ne!(resp[0],
    // 0x2B, ...)` — after the table fix that asserted nothing at all, because
    // the rejection it guards against had simply moved one byte along and
    // 0x2B is now UNSUPPORTED_OPTION. Both neighbours are excluded so the
    // guard cannot be satisfied by either.
    assert_ne!(resp[0], 0x2C, "up=false+uv=true must not be InvalidOption");
    assert_ne!(
        resp[0], 0x2B,
        "…nor UNSUPPORTED_OPTION, which is exactly what this assertion \
         silently degraded into"
    );
    assert_eq!(resp[0], 0x36, "uv=true must demand a PUAT");
}

#[test]
fn test_always_uv_gates_mc_and_ga() {
    let (mut app, client) = setup();
    toggle_always_uv(&mut app, &client);

    // makeCredential without pinUvAuthParam → PUAT_REQUIRED.
    let hash = [0x73u8; 32];
    let bare_mc = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::B(hash.to_vec())),
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
            Value::U(0x07),
            Value::M(vec![(Value::T("rk".to_string()), Value::Bool(false))]),
        ),
    ]));
    let resp = app.process_ctap2(0x01, &bare_mc, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x36, "alwaysUv must gate makeCredential");

    // getAssertion without pinUvAuthParam → PUAT_REQUIRED.
    let resp = app.process_ctap2(0x02, &ga_request(&hash, "example.com", None, None), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x36, "alwaysUv must gate getAssertion");

    // With UV, both succeed.
    let token = client.get_token(&mut app, 0x09, Some(0x01 | 0x02), None).unwrap();
    let resp = app.process_ctap2(
        0x01,
        &mc_request(&hash, "example.com", &token, None, true),
        [1, 2, 3, 4],
    );
    assert_eq!(resp[0], 0x00, "alwaysUv makeCredential with UV must succeed");
    let resp = app.process_ctap2(
        0x02,
        &ga_request(&hash, "example.com", Some(&token), None),
        [1, 2, 3, 4],
    );
    assert_eq!(resp[0], 0x00, "alwaysUv getAssertion with UV must succeed");

    // Toggle alwaysUv off; GA without UV works again (empty store → 0x2E).
    toggle_always_uv(&mut app, &client);
    let resp = app.process_ctap2(0x02, &ga_request(&hash, "example.com", None, None), [1, 2, 3, 4]);
    assert_ne!(resp[0], 0x36, "alwaysUv off must not gate");
}

#[test]
fn test_discoverable_skips_cred_protect_2_without_uv() {
    let (mut app, client) = setup();
    // Resident credential with credProtect=2.
    make_resident_credential(&mut app, &client, 2);

    // Discoverable GA without UV must NOT return it.
    let hash = [0x62u8; 32];
    let resp = app.process_ctap2(0x02, &ga_request(&hash, "example.com", None, None), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x2E, "credProtect=2 must be skipped without UV");

    // With UV it is returned.
    let token = client.get_token(&mut app, 0x09, Some(0x02), None).unwrap();
    let resp = app.process_ctap2(
        0x02,
        &ga_request(&hash, "example.com", Some(&token), None),
        [1, 2, 3, 4],
    );
    assert_eq!(resp[0], 0x00, "credProtect=2 must be returned with UV");
}

#[test]
fn test_cred_protect_out_of_range_is_invalid_parameter() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
    let hash = [0x63u8; 32];
    // credProtect = -1 (N(-1)) must be rejected, not wrap to 255.
    let ext = Value::M(vec![(
        Value::T("credProtect".to_string()),
        Value::N(-1),
    )]);
    let resp = app.process_ctap2(
        0x01,
        &mc_request(&hash, "example.com", &token, Some(ext), false),
        [1, 2, 3, 4],
    );
    assert_eq!(resp[0], 0x02, "expected CTAP2_ERR_INVALID_PARAMETER");
}

#[test]
fn test_u2f_refuses_cred_protect_3_credential() {
    use fapico2_fido::crypto;

    let (mut app, client) = setup();
    // Resident credential with credProtect=3 (UV REQUIRED).
    make_resident_credential(&mut app, &client, 3);

    // Fetch its credential id via credMgmt enumeration (cm token):
    // enumerateCredsBegin (subCmd 0x04) with params {0x01: rpIdHash}.
    let cm_token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();
    let rp_id_hash = crypto::sha256(b"example.com");
    let params = Value::M(vec![(Value::U(0x01), Value::B(rp_id_hash.to_vec()))]);
    let mut auth_data: Vec<u8> = vec![0x04];
    auth_data.extend_from_slice(&cbor::encode(&params));
    let cm_req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x04)),
        (Value::U(0x02), params),
        (Value::U(0x03), Value::U(2)),
        (
            Value::U(0x04),
            Value::B(crypto::pin_uv_auth_param(2, &cm_token.try_into().unwrap(), &auth_data)),
        ),
    ]));
    let resp = app.process_ctap2(0x0A, &cm_req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "enumerateCredsBegin must succeed");
    let (v, _) = cbor::decode(&resp[1..]).unwrap();
    let cred_id: Vec<u8> = match &v {
        Value::M(m) => m
            .iter()
            .find(|(k, _)| matches!(k, Value::U(0x07)))
            .and_then(|(_, v)| match v {
                Value::M(r) => r
                    .iter()
                    .find(|(k, _)| matches!(k, Value::T(t) if t == "id"))
                    .and_then(|(_, v)| match v {
                        Value::B(b) => Some(b.clone()),
                        _ => None,
                    }),
                _ => None,
            })
            .expect("credentialId in response"),
        _ => panic!("expected map"),
    };

    // U2F AUTHENTICATE (P1=0x03) with that key handle must be refused with
    // SW_SECURITY_STATUS_NOT_SATISFIED (0x6982).
    let app_param = crypto::sha256(b"example.com");
    let client_param = [0x33u8; 32];
    let mut apdu_data: Vec<u8> = Vec::new();
    apdu_data.extend_from_slice(&client_param);
    apdu_data.extend_from_slice(&app_param);
    apdu_data.push(cred_id.len() as u8);
    apdu_data.extend_from_slice(&cred_id);
    let mut apdu: Vec<u8> = vec![0x00, 0x02, 0x03, 0x00, 0x00];
    apdu.extend_from_slice(&(apdu_data.len() as u16).to_be_bytes());
    apdu.extend_from_slice(&apdu_data);
    let resp = app.process_u2f(&apdu);
    let status = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    assert_eq!(status, 0x6982, "credProtect=3 must be refused over U2F");
}
