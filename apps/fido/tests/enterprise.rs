//! Tests for enterprise attestation (FX-408).

mod common;

use common::*;
use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::keystore::MemoryKeystore;

fn enable_enterprise_attestation(app: &mut FidoApp<MemoryKeystore>, client: &PinClient) {
    let token = client.get_token(app, 0x09, Some(0x20), None).unwrap();
    let auth_msg: Vec<u8> = [vec![0xffu8; 32], vec![0x0d, 0x01]].concat();
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x01)),
        (Value::U(0x03), Value::U(2)),
        (Value::U(0x04), Value::B(pin_uv_auth(&token, &auth_msg))),
    ]));
    let resp = app.process_ctap2(0x0D, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "enableEnterpriseAttestation must succeed");
}

fn set_enterprise_rp_ids(app: &mut FidoApp<MemoryKeystore>, client: &PinClient, rp_ids: &[&str]) {
    let token = client.get_token(app, 0x09, Some(0x20), None).unwrap();
    let params = Value::M(vec![(
        Value::U(0x01),
        Value::A(rp_ids.iter().map(|r| Value::T(r.to_string())).collect()),
    )]);
    let auth_msg: Vec<u8> = [vec![0xffu8; 32], vec![0x0d, 0x04], cbor::encode(&params)].concat();
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x04)),
        (Value::U(0x02), params),
        (Value::U(0x03), Value::U(2)),
        (Value::U(0x04), Value::B(pin_uv_auth(&token, &auth_msg))),
    ]));
    let resp = app.process_ctap2(0x0D, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "setEnterpriseRPIDList must succeed");
}

fn mc_ep(hash: &[u8; 32], rp_id: &str, token: &[u8], ep_att: Option<u64>) -> Vec<u8> {
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
        (Value::U(0x08), Value::B(pin_uv_auth(token, hash))),
        (Value::U(0x09), Value::U(2)),
    ];
    if let Some(ep) = ep_att {
        map.push((Value::U(0x0A), Value::U(ep)));
    }
    cbor::encode(&Value::M(map))
}

/// Returns (fmt, ep_flag_set) from a makeCredential response.
fn parse_attestation(resp: &[u8]) -> (String, bool) {
    let (v, _) = cbor::decode(&resp[1..]).unwrap();
    match v {
        Value::M(m) => {
            let fmt = m
                .iter()
                .find(|(k, _)| matches!(k, Value::U(0x01)))
                .map(|(_, v)| match v {
                    Value::T(s) => s.clone(),
                    _ => panic!("fmt must be tstr"),
                })
                .unwrap();
            let auth_data = m
                .iter()
                .find(|(k, _)| matches!(k, Value::U(0x02)))
                .map(|(_, v)| match v {
                    Value::B(b) => b.clone(),
                    _ => panic!("authData must be bstr"),
                })
                .unwrap();
            let flags = auth_data[32];
            (fmt, flags & 0x02 != 0)
        }
        _ => panic!("expected map"),
    }
}

#[test]
fn test_ep_att_1_without_enable_is_unauthorized() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
    let hash = [0x81u8; 32];
    let resp = app.process_ctap2(0x01, &mc_ep(&hash, "example.com", &token, Some(1)), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x40, "expected CTAP2_ERR_UNAUTHORIZED_PERMISSION");
}

#[test]
fn test_ep_full_attestation_any_rp_when_enabled() {
    let (mut app, client) = setup();
    enable_enterprise_attestation(&mut app, &client);
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
    let hash = [0x82u8; 32];
    let resp = app.process_ctap2(0x01, &mc_ep(&hash, "any-rp.example", &token, Some(1)), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00);
    let (fmt, ep) = parse_attestation(&resp);
    assert_eq!(fmt, "packed");
    assert!(ep, "epAtt=1 must set the EP flag for any RP");
}

#[test]
fn test_ep_vendor_facilitated_requires_rp_on_list() {
    let (mut app, client) = setup();
    enable_enterprise_attestation(&mut app, &client);
    set_enterprise_rp_ids(&mut app, &client, &["example.com"]);
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();

    // RP on the list → enterprise attestation.
    let hash = [0x83u8; 32];
    let resp = app.process_ctap2(0x01, &mc_ep(&hash, "example.com", &token, Some(2)), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00);
    let (_, ep) = parse_attestation(&resp);
    assert!(ep, "epAtt=2 with listed RP must set the EP flag");

    // RP not on the list → NOT_ALLOWED.
    let hash2 = [0x84u8; 32];
    let resp = app.process_ctap2(0x01, &mc_ep(&hash2, "other.com", &token, Some(2)), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x30, "epAtt=2 with unlisted RP must be NOT_ALLOWED");
}

#[test]
fn test_no_ep_att_returns_basic_attestation() {
    let (mut app, client) = setup();
    enable_enterprise_attestation(&mut app, &client);
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
    let hash = [0x85u8; 32];
    let resp = app.process_ctap2(0x01, &mc_ep(&hash, "example.com", &token, None), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00);
    let (fmt, ep) = parse_attestation(&resp);
    assert_eq!(fmt, "packed", "basic attestation remains packed");
    assert!(!ep, "no EP flag without an epAtt request");
}

#[test]
fn test_ep_att_invalid_value_is_invalid_parameter() {
    let (mut app, client) = setup();
    enable_enterprise_attestation(&mut app, &client);
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
    let hash = [0x86u8; 32];
    let resp = app.process_ctap2(0x01, &mc_ep(&hash, "example.com", &token, Some(3)), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x02, "epAtt=3 must be CTAP2_ERR_INVALID_PARAMETER");
}
