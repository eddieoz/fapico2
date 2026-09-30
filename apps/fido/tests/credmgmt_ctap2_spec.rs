//! credMgmt in the **CTAP2** dialect, as every third-party client speaks it.
//!
//! # Why this file exists
//!
//! `authenticatorCredentialManagement` in this firmware originally
//! implemented only PicoForge's private CBOR dialect: sub-command parameters
//! nested under key `0x02`, `pinUvAuthProtocol` at `0x03`, `pinUvAuthParam`
//! at `0x04`, and sub-commands `0x01`/`0x02` swapped relative to the spec.
//! The response used PicoForge's key numbering too (`rp` at `0x03`,
//! `rpID` at `0x04`, `totalRPs` at `0x05`).
//!
//! PicoForge is a first-party client, so that worked for it — and the test
//! suite, which built its requests with the same non-spec helper the
//! implementation was written against, stayed green. A spec client sending
//! CTAP2 instead had its request parsed as PicoForge's, hit key `0x02`
//! holding an integer where a map was expected, and was answered
//! `CTAP2_ERR_INVALID_CBOR` — which is what left Yubico Authenticator's
//! **Slots** and **Passkeys** screens loading forever.
//!
//! These tests are pinned against the *spec*, not against the
//! implementation, so the dialect cannot silently regress. `credmgmt.rs`
//! keeps covering the PicoForge dialect, and the two files together pin
//! that both are served.
//!
//! Spec references are to CTAP 2.1 §12.1.6.

mod common;

use common::*;
use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::crypto;
use fapico2_fido::keystore::MemoryKeystore;

// Sub-commands, CTAP2 numbering.
const CTAP2_ENUMERATE_RPS_BEGIN: u8 = 0x01;
const CTAP2_GET_CREDS_METADATA: u8 = 0x02;
const CTAP2_ENUMERATE_RPS_NEXT: u8 = 0x03;
const CTAP2_ENUMERATE_CREDS_BEGIN: u8 = 0x04;

/// Build a credMgmt request in CTAP2's flat layout.
///
/// `params` carries the spec's own top-level keys (`0x04` rpIdHash,
/// `0x05` credentialID, `0x06` user); the signed message is assembled from
/// them the way §12.1.6 specifies — `subCommand ‖ rpIdHash`,
/// `subCommand ‖ credentialID`, `subCommand ‖ credentialID ‖ user`.
fn cm_req_ctap2(subcommand: u8, token: &[u8], params: &[(u64, Value)]) -> Vec<u8> {
    let mut auth_msg: Vec<u8> = vec![subcommand];
    for (k, v) in params {
        match (*k, subcommand) {
            // enumerateCredentialsBegin signs the bare 32-byte hash.
            (0x04, CTAP2_ENUMERATE_CREDS_BEGIN) => {
                if let Value::B(b) = v {
                    auth_msg.extend_from_slice(b);
                }
            }
            // deleteCredential / updateUserInformation sign the
            // credentialID map verbatim; updateUserInformation also signs
            // the user map after it.
            (0x05, 0x06) | (0x05, 0x07) => auth_msg.extend_from_slice(&cbor::encode(v)),
            (0x06, 0x07) => auth_msg.extend_from_slice(&cbor::encode(v)),
            _ => {}
        }
    }
    let mut map: Vec<(Value, Value)> = vec![
        (Value::U(0x01), Value::U(subcommand as u64)),
        (Value::U(0x02), Value::U(2)),
    ];
    for (k, v) in params {
        map.push((Value::U(*k), v.clone()));
    }
    map.push((
        Value::U(0x03),
        Value::B(crypto::pin_uv_auth_param(2, &token.try_into().unwrap(), &auth_msg)),
    ));
    map.sort_by_key(|(k, _)| match k {
        Value::U(u) => *u,
        _ => 0,
    });
    cbor::encode(&Value::M(map))
}

fn map_of(resp: &[u8]) -> Vec<(Value, Value)> {
    assert_eq!(resp[0], 0x00, "expected OK, got status {:#04x}", resp[0]);
    match cbor::decode(&resp[1..]).unwrap().0 {
        Value::M(m) => m,
        other => panic!("expected a map, got {:?}", other),
    }
}

fn uint_at(m: &[(Value, Value)], key: u64) -> Option<u64> {
    m.iter().find_map(|(k, v)| match (k, v) {
        (Value::U(u), Value::U(n)) if *u == key => Some(*n),
        _ => None,
    })
}

fn has_key(m: &[(Value, Value)], key: u64) -> bool {
    m.iter().any(|(k, _)| matches!(k, Value::U(u) if *u == key))
}

/// Create one discoverable ("resident") credential for `rp`, the same way
/// `credmgmt.rs::make_resident` does.
fn make_resident(app: &mut FidoApp<MemoryKeystore>, client: &PinClient, rp: &str) {
    make_resident_for(app, client, rp, "user")
}

/// As `make_resident`, with a distinct user handle. Two credentials under a
/// single RP only coexist when their user handles differ, so the tests that
/// need a second enumeration page must vary this.
fn make_resident_for(
    app: &mut FidoApp<MemoryKeystore>,
    client: &PinClient,
    rp: &str,
    user: &str,
) {
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
                (Value::T("id".to_string()), Value::B(user.as_bytes().to_vec())),
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
                Value::U(1),
            )]),
        ),
        (Value::U(0x07), Value::M(vec![(Value::T("rk".to_string()), Value::Bool(true))])),
        (
            Value::U(0x08),
            Value::B(crypto::pin_uv_auth_param(2, &token.try_into().unwrap(), &hash)),
        ),
        (Value::U(0x09), Value::U(2)),
    ]));
    let resp = app.process_ctap2(0x01, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "makeCredential must succeed");
}

/// Ask for a token with `getPinUvAuthTokenUsingUvWithPermissions`
/// (clientPIN sub-command `0x06`) — the no-PIN leg, which proves user
/// presence instead of a PIN. Returns the decrypted 32-byte token.
fn get_uv_token(
    app: &mut FidoApp<MemoryKeystore>,
    client: &PinClient,
    permissions: u8,
) -> Vec<u8> {
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x06)),
        (Value::U(0x03), client.client_cose()),
        (Value::U(0x09), Value::U(permissions as u64)),
    ]));
    let resp = app.process_ctap2(0x06, &req, [1, 2, 3, 4]);
    assert_eq!(
        resp[0], 0x00,
        "getPinUvAuthTokenUsingUvWithPermissions must be answered, not refused"
    );
    let encrypted = match cbor::decode(&resp[1..]).unwrap().0 {
        Value::M(m) => m
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::U(0x02), Value::B(b)) => Some(b.clone()),
                _ => None,
            })
            .expect("pinUvAuthToken (0x02) in the clientPIN response"),
        other => panic!("expected map, got {:?}", other),
    };
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&encrypted[..16]);
    crypto::pin_decrypt_v2(&client.enc_key, &encrypted).expect("decrypt the UV token")
}

/// The regression this whole file guards: a spec-layout request used to be
/// parsed as PicoForge's and rejected with `INVALID_CBOR`.
#[test]
fn ctap2_request_is_not_rejected_as_invalid_cbor() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    // enumerateRPsBegin with the spec's key 0x02 = pinUvAuthProtocol (an
    // integer). PicoForge's parser expects a *map* there and answered 0x12.
    let resp = app.process_ctap2(0x0A, &cm_req_ctap2(CTAP2_ENUMERATE_RPS_BEGIN, &token, &[]), [1, 2, 3, 4]);
    assert_ne!(
        resp[0],
        0x12,
        "a spec-layout credMgmt request must not be answered INVALID_CBOR \
         (that is what hung the Slots and Passkeys screens)"
    );
    assert_eq!(resp[0], 0x00, "enumerateRPsBegin must succeed");
}

/// CTAP2 `0x01` is enumerateRPsBegin and `0x02` is getCredsMetadata — the
/// reverse of PicoForge's numbering. Getting this backwards makes every
/// spec client enumerate nothing.
#[test]
fn ctap2_subcommand_0x01_enumerates_and_0x02_reports_metadata() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    let begin = app.process_ctap2(0x0A, &cm_req_ctap2(CTAP2_ENUMERATE_RPS_BEGIN, &token, &[]), [1, 2, 3, 4]);
    let begin = map_of(&begin);
    assert!(
        has_key(&begin, 0x07),
        "enumerateRPsBegin must report totalRps at key 0x07 (got keys {:?})",
        begin.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>()
    );

    let meta = app.process_ctap2(0x0A, &cm_req_ctap2(CTAP2_GET_CREDS_METADATA, &token, &[]), [1, 2, 3, 4]);
    let meta = map_of(&meta);
    assert!(
        has_key(&meta, 0x01) && has_key(&meta, 0x02),
        "getCredsMetadata must report existingResidentCredentialsCount (0x01) and \
         maxPossibleRemainingResidentCredentialsCount (0x02)"
    );
}

/// The RP listing must arrive under the keys a spec client reads: `rp` (1),
/// `rpID` (2) and `totalRPs` (7). A client that finds none of them has
/// nothing to draw, which is the hang.
#[test]
fn ctap2_enumerate_rps_uses_spec_response_keys() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    let resp = app.process_ctap2(0x0A, &cm_req_ctap2(CTAP2_ENUMERATE_RPS_BEGIN, &token, &[]), [1, 2, 3, 4]);
    let m = map_of(&resp);

    let rp = m.iter().find_map(|(k, v)| match (k, v) {
        (Value::U(0x01), Value::M(rp)) => Some(rp),
        _ => None,
    });
    let rp = rp.expect("rp (key 0x01) must be the RP map");
    assert!(
        rp.iter().any(|(k, v)| matches!((k, v), (Value::T(t), Value::T(_)) if t == "id")),
        "the rp map must carry an \"id\" (the RP id)"
    );

    assert!(
        m.iter().any(|(k, v)| matches!((k, v), (Value::U(0x02), Value::B(b)) if b.len() == 32)),
        "rpID (key 0x02) must be the 32-byte SHA-256 of the RP id"
    );
    assert_eq!(
        uint_at(&m, 0x07),
        Some(1),
        "totalRps (key 0x07) must be 1 for a single resident credential"
    );

    // PicoForge's keys must NOT leak into a spec reply — they collide with
    // spec meanings (0x03 is rpName, 0x04 is userID, 0x05 credentialID).
    assert!(
        !has_key(&m, 0x03) && !has_key(&m, 0x05),
        "a CTAP2 reply must not carry PicoForge's 0x03/0x05 keys"
    );
}

/// The credential listing must arrive under spec keys 1/2/3/4 (user,
/// credentialID, publicKey, totalCredentials).
#[test]
fn ctap2_enumerate_credentials_uses_spec_response_keys() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    let hash = crypto::sha256(b"example.com").to_vec();
    let resp = app.process_ctap2(
        0x0A,
        &cm_req_ctap2(
            CTAP2_ENUMERATE_CREDS_BEGIN,
            &token,
            &[(0x04, Value::B(hash))],
        ),
        [1, 2, 3, 4],
    );
    let m = map_of(&resp);

    assert!(
        m.iter().any(|(k, v)| matches!((k, v), (Value::U(0x01), Value::M(_)))),
        "user (key 0x01) must be present"
    );
    assert!(
        m.iter().any(|(k, v)| matches!((k, v), (Value::U(0x02), Value::M(_)))),
        "credentialID (key 0x02) must be present"
    );
    assert!(
        m.iter().any(|(k, v)| matches!((k, v), (Value::U(0x03), Value::M(_)))),
        "publicKey (key 0x03) must be present"
    );
    assert_eq!(uint_at(&m, 0x04), Some(1), "totalCredentials (key 0x04) must be 1");

    assert!(
        !has_key(&m, 0x07) && !has_key(&m, 0x08),
        "a CTAP2 reply must not carry PicoForge's 0x07/0x08 credential keys"
    );
}

/// enumerateRpsNext must stay on the same channel and keep the spec shape.
#[test]
fn ctap2_enumerate_rps_next_keeps_spec_keys() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "a.example");
    make_resident(&mut app, &client, "b.example");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    let _ = app.process_ctap2(0x0A, &cm_req_ctap2(CTAP2_ENUMERATE_RPS_BEGIN, &token, &[]), [1, 2, 3, 4]);
    let resp = app.process_ctap2(0x0A, &cm_req_ctap2(CTAP2_ENUMERATE_RPS_NEXT, &token, &[]), [1, 2, 3, 4]);
    let m = map_of(&resp);
    assert!(has_key(&m, 0x01), "rp (key 0x01) must be present on enumerateRpsNext");
    assert!(
        m.iter().any(|(k, v)| matches!((k, v), (Value::U(0x02), Value::B(b)) if b.len() == 32)),
        "rpID (key 0x02) must be present on enumerateRpsNext"
    );
}

/// The two dialects must not be confusable: a map at key `0x02` is
/// PicoForge, an integer there is CTAP2. If this ever inverts, PicoForge
/// silently starts receiving spec replies it cannot read.
#[test]
fn dialect_discriminator_is_the_type_of_key_0x02() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    // PicoForge: key 0x02 is a nested sub-command-parameter map, and its
    // enumerateRpsBegin is sub-command 0x02, answered with keys 3/4/5.
    let picoforge_params = Value::M(vec![(
        Value::U(0x01),
        Value::B(crypto::sha256(b"example.com").to_vec()),
    )]);
    let mac = crypto::pin_uv_auth_param(2, &token.try_into().unwrap(), &[0x02]);
    let picoforge = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x02)),
        (Value::U(0x02), picoforge_params),
        (Value::U(0x03), Value::U(2)),
        (Value::U(0x04), Value::B(mac)),
    ]));
    let m = map_of(&app.process_ctap2(0x0A, &picoforge, [1, 2, 3, 4]));
    assert!(
        has_key(&m, 0x03) && has_key(&m, 0x04) && has_key(&m, 0x05),
        "PicoForge must still be answered with its own 3/4/5 keys"
    );
    assert!(!has_key(&m, 0x07), "PicoForge must not receive the spec's totalRps key");
}

/// `getPinUvAuthTokenUsingUvWithPermissions` (clientPIN sub-command `0x06`)
/// is the only way a client on a PIN-less key can obtain a pinUvAuthToken,
/// and GetInfo advertises `uv` — so it must be answered, not refused. Before
/// this it fell through to `InvalidParameter`.
#[test]
fn clientpin_uv_token_subcommand_is_implemented() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "example.com");

    // Minted last: every get_token call replaces the app's single pinUvAuth
    // token slot, so the UV token has to be the one in hand at the credMgmt
    // call below. No PIN is involved in this leg — it proves presence only.
    let token = get_uv_token(&mut app, &client, 0x04);

    let resp = app.process_ctap2(0x0A, &cm_req_ctap2(CTAP2_ENUMERATE_RPS_BEGIN, &token, &[]), [1, 2, 3, 4]);
    assert_eq!(
        resp[0], 0x00,
        "a UV-issued token with the cm permission must authorise credMgmt"
    );
}
/// The same spec behaviour, driven through `device_core.rs`.
///
/// The host tests above exercise `app.rs`, the *host twin*. The RP2350
/// firmware runs a separate implementation — `device_app::FidoApp` over
/// `device_core.rs` — and that is the binary on the board. A fix applied to
/// only one twin would pass every host test and change nothing on hardware,
/// which is exactly the failure mode this module exists to prevent.
///
/// Uses pinUvAuthProtocol 1 throughout (mirroring `pin.rs`'s device twin)
/// so the shared secret can be reproduced with the crate's own helpers.
mod device_twin {
    use fapico2_fido::cbor::no_heap as nh;
    use fapico2_fido::cbor::no_heap::{Item, Parser};
    use fapico2_fido::crypto;
    use fapico2_fido::device_app::FidoApp;
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;
    use heapless::Vec as HV;

    fn grant_always(_tag: u32) -> bool {
        true
    }

    fn client_sk() -> p256::SecretKey {
        p256::SecretKey::from_slice(&[0x77u8; 32]).unwrap()
    }

    /// Push the canonical client COSE key: kty(1)=2, alg(3)=-25, crv(-1)=1,
    /// x(-2), y(-3). `push_neg` takes the real negative value.
    fn push_client_cose<const N: usize>(out: &mut HV<u8, N>, x: &[u8; 32], y: &[u8; 32]) {
        nh::push_map_header(out, 5).unwrap();
        nh::push_uint(out, 1).unwrap();
        nh::push_uint(out, 2).unwrap();
        nh::push_uint(out, 3).unwrap();
        nh::push_neg(out, -25).unwrap();
        nh::push_neg(out, -1).unwrap();
        nh::push_uint(out, 1).unwrap();
        nh::push_neg(out, -2).unwrap();
        nh::push_bstr(out, x).unwrap();
        nh::push_neg(out, -3).unwrap();
        nh::push_bstr(out, y).unwrap();
    }

    fn client_coords() -> ([u8; 32], [u8; 32]) {
        let bytes = crypto::public_key_bytes(&client_sk().public_key());
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        (x, y)
    }

    struct Dev {
        app: FidoApp,
        /// Protocol-1 shared secret: hmac_key == enc_key == k.
        k: [u8; 32],
        x: [u8; 32],
        y: [u8; 32],
    }

    impl Dev {
        fn boot() -> Self {
            let mut trng = HostTrng::new();
            let mut store = HostSecureStore::new();
            let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
            app.set_presence_grant(grant_always);
            let (x, y) = client_coords();

            // getKeyAgreement (0x02) → the authenticator's P-256 point.
            let mut req: HV<u8, 32> = HV::new();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = app.process_ctap2(0x06, req.as_slice(), [1, 2, 3, 4], &mut out);
            assert_eq!(out[0], 0x00, "getKeyAgreement must succeed");
            let resp = out[..n].to_vec();
            let mut p = Parser::new(&resp[1..]);
            let Item::Map(nm) = p.next().unwrap() else {
                panic!("map")
            };
            let mut dev_pub = None;
            for _ in 0..nm {
                let k = match p.next().unwrap() {
                    Item::U(u) => u,
                    other => panic!("key {:?}", other),
                };
                if k == 1 {
                    let Item::Map(nc) = p.next().unwrap() else {
                        panic!("cose map")
                    };
                    let (mut dx, mut dy) = ([0u8; 32], [0u8; 32]);
                    for _ in 0..nc {
                        let lbl = match p.next().unwrap() {
                            Item::U(u) => u as i64,
                            Item::N(n) => n,
                            other => panic!("label {:?}", other),
                        };
                        match lbl {
                            -2 => {
                                if let Item::B(b) = p.next().unwrap() {
                                    dx.copy_from_slice(&b[..32]);
                                }
                            }
                            -3 => {
                                if let Item::B(b) = p.next().unwrap() {
                                    dy.copy_from_slice(&b[..32]);
                                }
                            }
                            _ => {
                                p.next().unwrap();
                            }
                        }
                    }
                    dev_pub = Some((dx, dy));
                } else {
                    p.next().unwrap();
                }
            }
            let (dx, dy) = dev_pub.expect("peerCoseKey at label 1");
            let device_pub =
                crypto::parse_cose_ec2_p256_bytes(&dx, &dy).expect("peer key must be a valid P-256 point");
            let raw = crypto::ecdh_shared_secret(&client_sk(), &device_pub);
            let k = crypto::derive_shared_secret_v1(&raw);
            Self { app, k, x, y }
        }

        fn call(&mut self, cmd: u8, payload: &[u8]) -> Vec<u8> {
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = self.app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
            out[..n].to_vec()
        }

        /// clientPIN getPinUvAuthTokenUsingUvWithPermissions (sub 0x06) —
        /// no PIN involved, so the token path stays independent of setPIN.
        fn uv_token(&mut self, permissions: u8) -> Vec<u8> {
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 4).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 6).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            push_client_cose(&mut req, &self.x, &self.y);
            nh::push_uint(&mut req, 9).unwrap();
            nh::push_uint(&mut req, permissions as u64).unwrap();
            let resp = self.call(0x06, req.as_slice());
            assert_eq!(
                resp[0], 0x00,
                "getPinUvAuthTokenUsingUvWithPermissions must be answered, not refused"
            );
            let mut p = Parser::new(&resp[1..]);
            let Item::Map(nm) = p.next().unwrap() else {
                panic!("map")
            };
            let mut enc: Vec<u8> = Vec::new();
            for _ in 0..nm {
                let k = match p.next().unwrap() {
                    Item::U(u) => u,
                    other => panic!("key {:?}", other),
                };
                if k == 2 {
                    match p.next().unwrap() {
                        Item::B(b) => enc.extend_from_slice(b),
                        other => panic!("pinUvAuthToken {:?}", other),
                    }
                } else {
                    p.next().unwrap();
                }
            }
            let token = crypto::pin_decrypt_v1(&self.k, &enc).expect("decrypt token");
            assert_eq!(token.len(), 32, "the UV token must be 32 bytes");
            token
        }

        /// No PIN is set on this device, so makeCredential must NOT carry a
        /// pinUvAuthParam — supplying one without a PIN is answered
        /// `PinNotSet`. The credential is unprotected, which is what a
        /// freshly-provisioned authenticator looks like.
        fn make_resident(&mut self, rp: &str) {
            let hash = crypto::sha256(rp.as_bytes());
            let mut req: HV<u8, 512> = HV::new();
            nh::push_map_header(&mut req, 5).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_bstr(&mut req, &hash).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_tstr(&mut req, "id").unwrap();
            nh::push_tstr(&mut req, rp).unwrap();
            nh::push_tstr(&mut req, "name").unwrap();
            nh::push_tstr(&mut req, "RP").unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_tstr(&mut req, "id").unwrap();
            nh::push_bstr(&mut req, b"user").unwrap();
            nh::push_tstr(&mut req, "name").unwrap();
            nh::push_tstr(&mut req, "U").unwrap();
            nh::push_uint(&mut req, 4).unwrap();
            nh::push_array_header(&mut req, 1).unwrap();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_tstr(&mut req, "type").unwrap();
            nh::push_tstr(&mut req, "public-key").unwrap();
            nh::push_tstr(&mut req, "alg").unwrap();
            nh::push_neg(&mut req, -7).unwrap();
            nh::push_uint(&mut req, 7).unwrap();
            nh::push_map_header(&mut req, 1).unwrap();
            nh::push_tstr(&mut req, "rk").unwrap();
            nh::push_bool(&mut req, true).unwrap();
            let resp = self.call(0x01, req.as_slice());
            assert_eq!(resp[0], 0x00, "makeCredential must succeed on the device path");
        }

        /// credMgmt in CTAP2's flat layout — the request that used to be
        /// answered `INVALID_CBOR` on this exact path.
        fn enumerate_rps_begin(&mut self, token: &[u8]) -> Vec<u8> {
            let mac = crypto::pin_uv_auth_param(1, &token.try_into().unwrap(), &[0x01]);
            let mut req: HV<u8, 64> = HV::new();
            nh::push_map_header(&mut req, 3).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            nh::push_bstr(&mut req, &mac).unwrap();
            self.call(0x0A, req.as_slice())
        }
    }

    #[test]
    fn device_path_serves_the_ctap2_dialect() {
        let mut dev = Dev::boot();
        dev.make_resident("example.com");

        let cm_token = dev.uv_token(0x04);
        let resp = dev.enumerate_rps_begin(&cm_token);
        assert_ne!(
            resp[0], 0x12,
            "the device path must not answer INVALID_CBOR to a spec-layout request"
        );
        assert_eq!(resp[0], 0x00, "enumerateRpsBegin must succeed on the device path");

        let mut p = Parser::new(&resp[1..]);
        let Item::Map(n) = p.next().unwrap() else {
            panic!("map")
        };
        let mut saw_rp = false;
        let mut saw_rpid = false;
        let mut saw_total = false;
        for _ in 0..n {
            let k = match p.next().unwrap() {
                Item::U(u) => u,
                other => panic!("key {:?}", other),
            };
            match k {
                1 => {
                    // `rp` is a nested map; the streaming parser does not
                    // descend on its own, so its pairs must be consumed or
                    // they are misread as outer keys.
                    if let Item::Map(nr) = p.next().unwrap() {
                        saw_rp = true;
                        for _ in 0..nr {
                            p.next().unwrap();
                            p.next().unwrap();
                        }
                    }
                }
                2 => {
                    if let Item::B(b) = p.next().unwrap() {
                        assert_eq!(b.len(), 32, "rpID (0x02) must be 32 bytes");
                        saw_rpid = true;
                    }
                }
                7 => {
                    saw_total = matches!(p.next().unwrap(), Item::U(_));
                }
                _ => {
                    p.next().unwrap();
                }
            }
        }
        assert!(saw_rp, "rp must be at key 1 (spec), not PicoForge's key 3");
        assert!(saw_rpid, "rpID must be at key 2 (spec)");
        assert!(saw_total, "totalRps must be at key 7 (spec)");
    }
}

/// The "Next" sub-commands cannot be classified from their own bytes.
///
/// PicoForge sends `{1: 0x05}` — and nothing else — for
/// `enumerateCredentialsGetNextCredential`
/// (`picoforge/src/hal/fido/ops.rs:1329-1336`): no sub-command-parameter
/// map, no `pinUvAuthProtocol`, no `pinUvAuthParam`, because Next is
/// unauthenticated by design. CTAP2 sends the identical map. Classifying on
/// the request alone therefore falls back to the default dialect, and
/// PicoForge — which reads `User` at `0x06` — gets a spec-shaped reply
/// instead. That surfaced as
/// `Failed to unlock: User not found in EnumerateCredentialsGetNextCredential response`.
///
/// The enumeration a Next continues is what decides the shape.
#[test]
fn picoforge_getnext_is_answered_in_picoforge_shape() {
    let (mut app, client) = setup();
    make_resident_for(&mut app, &client, "example.com", "alice");
    make_resident_for(&mut app, &client, "example.com", "bob");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    // PicoForge enumerateCredentialsBegin: sub-command 0x04, sub-params
    // nested under key 0x02, protocol at key 0x03.
    let hash = crypto::sha256(b"example.com").to_vec();
    // PicoForge signs `subCommand ‖ CBOR(subCommandParams)`
    // (ops.rs:1677-1694), so the nested map is inside the MAC.
    let sub_params = Value::M(vec![(Value::U(0x01), Value::B(hash))]);
    let mut msg = vec![0x04];
    msg.extend_from_slice(&cbor::encode(&sub_params));
    let mac = crypto::pin_uv_auth_param(2, &token.try_into().unwrap(), &msg);
    let begin = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x04)),
        (Value::U(0x02), sub_params),
        (Value::U(0x03), Value::U(2)),
        (Value::U(0x04), Value::B(mac)),
    ]));
    let resp = app.process_ctap2(0x0A, &begin, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "PicoForge enumerateCredentialsBegin must succeed");
    let first = map_of(&resp);
    assert!(
        has_key(&first, 6) && has_key(&first, 7) && has_key(&first, 8),
        "PicoForge Begin must answer 6/7/8 (user/credentialId/publicKey)"
    );

    // The Next request, byte for byte what PicoForge sends: `{1: 5}` only.
    let next = cbor::encode(&Value::M(vec![(Value::U(0x01), Value::U(0x05))]));
    let resp = app.process_ctap2(0x0A, &next, [1, 2, 3, 4]);
    assert_eq!(
        resp[0], 0x00,
        "PicoForge enumerateCredentialsGetNextCredential must succeed"
    );
    let m = map_of(&resp);
    assert!(
        has_key(&m, 6),
        "PicoForge reads `user` at key 0x06; a CTAP2-shaped reply here is the \
         'User not found in EnumerateCredentialsGetNextCredential' bug"
    );
    assert!(has_key(&m, 7) && has_key(&m, 8) && has_key(&m, 9));
    assert!(
        !has_key(&m, 1) && !has_key(&m, 2),
        "the Next reply must not be in CTAP2's numbering"
    );
}

/// The counterpart: a CTAP2 client whose enumeration began in CTAP2 keeps
/// getting spec keys, even though its Next request is the same `{1: 0x05}`.
#[test]
fn ctap2_getnext_is_answered_in_spec_shape() {
    let (mut app, client) = setup();
    make_resident_for(&mut app, &client, "example.com", "alice");
    make_resident_for(&mut app, &client, "example.com", "bob");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    let hash = crypto::sha256(b"example.com").to_vec();
    let resp = app.process_ctap2(
        0x0A,
        &cm_req_ctap2(CTAP2_ENUMERATE_CREDS_BEGIN, &token, &[(0x04, Value::B(hash))]),
        [1, 2, 3, 4],
    );
    assert_eq!(resp[0], 0x00);

    // Same `{1: 0x05}` as PicoForge sends — the dialect comes from the Begin.
    let next = cbor::encode(&Value::M(vec![(Value::U(0x01), Value::U(0x05))]));
    let resp = app.process_ctap2(0x0A, &next, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "CTAP2 enumerateCredentialsGetNext must succeed");
    let m = map_of(&resp);
    assert!(has_key(&m, 1), "CTAP2 `user` must stay at key 1");
    assert!(has_key(&m, 2) && has_key(&m, 3) && has_key(&m, 4));
    assert!(!has_key(&m, 6), "the Next reply must not be PicoForge-shaped");
}

/// The same ambiguity exists one level up, for `enumerateRpsNext`
/// (`{1: 0x03}` in both dialects).
#[test]
fn picoforge_rps_next_is_answered_in_picoforge_shape() {
    let (mut app, client) = setup();
    make_resident(&mut app, &client, "a.example");
    make_resident(&mut app, &client, "b.example");
    let token = client.get_token(&mut app, 0x09, Some(0x04), None).unwrap();

    // PicoForge enumerateRpsBegin: sub-command 0x02, no sub-params, key 0x03
    // is the protocol (an integer) — that is what identifies the dialect.
    let mac = crypto::pin_uv_auth_param(2, &token.try_into().unwrap(), &[0x02]);
    let begin = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x02)),
        (Value::U(0x03), Value::U(2)),
        (Value::U(0x04), Value::B(mac)),
    ]));
    let resp = app.process_ctap2(0x0A, &begin, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00);
    let m = map_of(&resp);
    assert!(has_key(&m, 3) && has_key(&m, 4) && has_key(&m, 5), "Begin -> 3/4/5");

    // `{1: 0x03}` and nothing else — identical in both dialects.
    let next = cbor::encode(&Value::M(vec![(Value::U(0x01), Value::U(0x03))]));
    let resp = app.process_ctap2(0x0A, &next, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "PicoForge enumerateRpsGetNext must succeed");
    let m = map_of(&resp);
    assert!(
        has_key(&m, 3) && has_key(&m, 4),
        "PicoForge reads rp at 0x03 and rpIdHash at 0x04 on GetNext too"
    );
    assert!(!has_key(&m, 1), "must not be answered in CTAP2's numbering");
}
