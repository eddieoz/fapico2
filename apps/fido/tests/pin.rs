//! Tests for PIN lifecycle correctness (FX-406).

mod common;

use common::*;
use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::crypto;
use fapico2_fido::keystore::MemoryKeystore;

/// Set force_change_pin via authenticatorConfig setMinPINLength (subCmd 0x03).
fn set_force_change_pin(app: &mut FidoApp<MemoryKeystore>, client: &PinClient) {
    let token = client.get_token(app, 0x09, Some(0x20), None).unwrap();
    let params = Value::M(vec![(Value::U(0x03), Value::Bool(true))]);
    let auth_msg: Vec<u8> = [vec![0xffu8; 32], vec![0x0d, 0x03], cbor::encode(&params)].concat();
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x03)),
        (Value::U(0x02), params),
        (Value::U(0x03), Value::U(2)),
        (Value::U(0x04), Value::B(pin_uv_auth(&token, &auth_msg))),
    ]));
    let resp = app.process_ctap2(0x0D, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "setMinPINLength must succeed");
}

/// changePIN from PIN to new_pin. Returns the CTAP2 status byte.
fn change_pin(app: &mut FidoApp<MemoryKeystore>, client: &PinClient, new_pin: &[u8]) -> u8 {
    let mut padded = new_pin.to_vec();
    padded.push(0);
    padded.resize(64, 0);
    let new_pin_enc = crypto::pin_encrypt(2, &client.enc_key, &padded);
    let old_hash_enc = crypto::pin_encrypt(2, &client.enc_key, &crypto::pin_hash(PIN.as_bytes()));
    let mut auth_data = new_pin_enc.clone();
    auth_data.extend_from_slice(&old_hash_enc);
    let auth_param = crypto::pin_uv_auth_param(2, &client.hmac_key, &auth_data);
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x04)),
        (Value::U(0x03), client.client_cose()),
        (Value::U(0x04), Value::B(auth_param)),
        (Value::U(0x05), Value::B(new_pin_enc)),
        (Value::U(0x06), Value::B(old_hash_enc)),
    ]));
    app.process_ctap2(0x06, &req, [1, 2, 3, 4])[0]
}

#[test]
fn test_force_change_blocks_get_pin_token_until_change() {
    let (mut app, client) = setup();
    set_force_change_pin(&mut app, &client);

    // A correct PIN must be rejected with PIN_INVALID while forced.
    let err = client
        .get_token(&mut app, 0x05, None, None)
        .expect_err("getPinToken must fail while force_change_pin is set");
    assert_eq!(err, 0x31, "expected CTAP2_ERR_PIN_INVALID");

    // changePIN succeeds and clears the flag.
    assert_eq!(change_pin(&mut app, &client, b"2345"), 0x00);

    // Verify via a second changePIN cycle using the new PIN as "old": a
    // change with the OLD pin hash must now fail, proving the PIN changed.
    let err2 = change_pin_with_old(&mut app, &client, PIN.as_bytes(), b"3456");
    assert_eq!(err2, 0x31, "old PIN must no longer authenticate");
}

/// changePIN with an explicit old PIN (for post-change checks).
fn change_pin_with_old(
    app: &mut FidoApp<MemoryKeystore>,
    client: &PinClient,
    old_pin: &[u8],
    new_pin: &[u8],
) -> u8 {
    let mut padded = new_pin.to_vec();
    padded.push(0);
    padded.resize(64, 0);
    let new_pin_enc = crypto::pin_encrypt(2, &client.enc_key, &padded);
    let old_hash_enc = crypto::pin_encrypt(2, &client.enc_key, &crypto::pin_hash(old_pin));
    let mut auth_data = new_pin_enc.clone();
    auth_data.extend_from_slice(&old_hash_enc);
    let auth_param = crypto::pin_uv_auth_param(2, &client.hmac_key, &auth_data);
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x04)),
        (Value::U(0x03), client.client_cose()),
        (Value::U(0x04), Value::B(auth_param)),
        (Value::U(0x05), Value::B(new_pin_enc)),
        (Value::U(0x06), Value::B(old_hash_enc)),
    ]));
    app.process_ctap2(0x06, &req, [1, 2, 3, 4])[0]
}

#[test]
fn test_new_pin_padding_after_null_rejected() {
    let (mut app, client) = setup();
    // New PIN bytes: "2345" + null + zeros ... but non-zero at index 20.
    let mut padded = b"2345".to_vec();
    padded.push(0);
    padded.resize(64, 0);
    padded[20] = 0xAA;
    let new_pin_enc = crypto::pin_encrypt(2, &client.enc_key, &padded);
    let old_hash_enc = crypto::pin_encrypt(2, &client.enc_key, &crypto::pin_hash(PIN.as_bytes()));
    let mut auth_data = new_pin_enc.clone();
    auth_data.extend_from_slice(&old_hash_enc);
    let auth_param = crypto::pin_uv_auth_param(2, &client.hmac_key, &auth_data);
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x04)),
        (Value::U(0x03), client.client_cose()),
        (Value::U(0x04), Value::B(auth_param)),
        (Value::U(0x05), Value::B(new_pin_enc)),
        (Value::U(0x06), Value::B(old_hash_enc)),
    ]));
    let resp = app.process_ctap2(0x06, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x37, "expected CTAP2_ERR_PIN_POLICY_VIOLATION");
}

#[test]
fn test_three_pin_uv_auth_failures_block_until_power_cycle() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x05, None, None).unwrap();
    let hash = [0x42u8; 32];

    // First two wrong pinUvAuthParams → PIN_AUTH_INVALID.
    for i in 0..2 {
        let mut bad = pin_uv_auth(&token, &hash);
        bad[0] ^= 0xFF;
        let _ = i;
        let req = cbor::encode(&Value::M(vec![
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
            (Value::U(0x08), Value::B(bad)),
            (Value::U(0x09), Value::U(2)),
        ]));
        let resp = app.process_ctap2(0x01, &req, [1, 2, 3, 4]);
        assert_eq!(resp[0], 0x33, "failure {} must be PIN_AUTH_INVALID", i + 1);
    }

    // Third consecutive failure → PIN_AUTH_BLOCKED.
    let mut bad = pin_uv_auth(&token, &hash);
    bad[0] ^= 0xFF;
    let req = cbor::encode(&Value::M(vec![
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
        (Value::U(0x08), Value::B(bad)),
        (Value::U(0x09), Value::U(2)),
    ]));
    let resp = app.process_ctap2(0x01, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x34, "third consecutive failure must be PIN_AUTH_BLOCKED");

    // Even a correct pinUvAuthParam is refused until power cycle.
    let req_ok = cbor::encode(&Value::M(vec![
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
        (Value::U(0x08), Value::B(pin_uv_auth(&token, &hash))),
        (Value::U(0x09), Value::U(2)),
    ]));
    let resp = app.process_ctap2(0x01, &req_ok, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x34, "blocked until power cycle");
}

#[test]
fn test_get_uv_retries_returns_counter() {
    let (mut app, _client) = setup();
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x07)),
    ]));
    let resp = app.process_ctap2(0x06, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "getUVRetries must succeed");
    let (v, _) = cbor::decode(&resp[1..]).expect("valid CBOR");
    match v {
        Value::M(m) => {
            let uv = m
                .iter()
                .find(|(k, _)| matches!(k, Value::U(0x05)))
                .expect("uvRetries in response");
            assert!(matches!(uv.1, Value::U(_)), "uvRetries must be an unsigned int");
        }
        other => panic!("expected map, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// US-120 (EPIC `PICOForge-COMPAT`): PicoForge compatibility of the COSE
// key-agreement map.
//
// Two facts must hold, and the authenticator validates neither:
//
//  1. `alg` (COSE label 3) may be ES256 (-7) or ECDH-ES+HKDF-256 (-25). CTAP 2.1
//     mandates -25; PicoForge's clientPin key-agreement map carries -7
//     (`picoforge/src/hal/fido/ops.rs::encode_cose_key`), while its RS-Key MSE
//     key carries -25. Both must be accepted on both paths.
//  2. Label order is irrelevant. PicoForge's RS-Key MSE key
//     (`picoforge/src/hal/fido/mod.rs`) is a `BTreeMap` keyed by the integer
//     label, so it serialises as -3, -2, -1, 1, 3 rather than ascending.
//
// See `fapico2_fido::COSE_ALG_ES256` for the load-bearing statement.
//
// Only -2/-3 (the coordinates) matter. The subcommand that actually consumes
// them is setPIN (0x03): getKeyAgreement (0x02) ignores any `keyAgreement` in
// its request, so a test that only drove 0x02 would pass even if the parser
// rejected everything. These tests drive 0x02 for the well-formed peerCoseKey
// and 0x03 for the real guard.
//
// The requests are hand-encoded with `common::push_key_agreement` rather than
// `cbor::encode`, which sorts map keys and would normalise every request back
// to the canonical order — making the ordering half of the contract untested
// on the host twin.
// ---------------------------------------------------------------------------

/// Assert `v` is a well-formed EC2 COSE key (kty=2, crv=1, alg=-25, 32-byte
/// coordinates) and return the coordinates.
fn assert_well_formed_peer_key(v: &Value) -> (Vec<u8>, Vec<u8>) {
    let Value::M(m) = v else {
        panic!("peerCoseKey must be a map, got {:?}", v)
    };
    let int = |k: i64| -> i64 {
        m.iter()
            .find(|(kk, _)| {
                matches!(kk, Value::N(n) if *n == k) || matches!(kk, Value::U(u) if *u as i64 == k)
            })
            .and_then(|(_, val)| match val {
                Value::N(n) => Some(*n),
                Value::U(u) => Some(*u as i64),
                _ => None,
            })
            .unwrap_or_else(|| panic!("label {} present in peerCoseKey", k))
    };
    let bstr = |k: i64| -> Vec<u8> {
        m.iter()
            .find(|(kk, _)| matches!(kk, Value::N(n) if *n == k))
            .and_then(|(_, val)| match val {
                Value::B(b) => Some(b.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("byte string at label {} in peerCoseKey", k))
    };
    assert_eq!(int(1), 2, "kty must be EC2 (2)");
    assert_eq!(
        int(3),
        i64::from(fapico2_fido::COSE_ALG_ECDH_ES_HKDF_256),
        "authenticator advertises ECDH-ES+HKDF-256"
    );
    assert_eq!(int(-1), 1, "crv must be P-256 (1)");
    let x = bstr(-2);
    let y = bstr(-3);
    assert_eq!(x.len(), 32, "x coordinate must be 32 bytes");
    assert_eq!(y.len(), 32, "y coordinate must be 32 bytes");
    (x, y)
}

/// The four (alg, order) combinations the authenticator must accept.
fn compat_combinations() -> [(i64, CoseKeyOrder, &'static str); 4] {
    use fapico2_fido::{COSE_ALG_ECDH_ES_HKDF_256, COSE_ALG_ES256};
    [
        (
            i64::from(COSE_ALG_ECDH_ES_HKDF_256),
            CoseKeyOrder::Canonical,
            "alg=-25, canonical order",
        ),
        (
            i64::from(COSE_ALG_ES256),
            CoseKeyOrder::Canonical,
            "alg=-7, canonical order",
        ),
        (
            i64::from(COSE_ALG_ECDH_ES_HKDF_256),
            CoseKeyOrder::NonCanonical,
            "alg=-25, PicoForge BTreeMap order",
        ),
        (
            i64::from(COSE_ALG_ES256),
            CoseKeyOrder::NonCanonical,
            "alg=-7, PicoForge BTreeMap order",
        ),
    ]
}

/// Guard for the guard: the two label orders must reach the wire as
/// different bytes.
///
/// `cbor::encode` sorts map keys, so any `Value`-built map is normalised to
/// the canonical order before it is sent. If a future edit routes these
/// requests back through `cbor::encode`, the `CoseKeyOrder::NonCanonical`
/// iterations of the tests below silently become duplicates of the
/// `Canonical` ones and the ordering half of the contract goes untested. This
/// test fails loudly in that case.
#[test]
fn cose_key_order_reaches_the_wire() {
    use fapico2_fido::COSE_ALG_ES256;
    let x = [0xaau8; 32];
    let y = [0xbbu8; 32];
    let mut canonical: heapless::Vec<u8, 128> = heapless::Vec::new();
    let mut non_canonical: heapless::Vec<u8, 128> = heapless::Vec::new();
    push_key_agreement(
        &mut canonical,
        &x,
        &y,
        i64::from(COSE_ALG_ES256),
        CoseKeyOrder::Canonical,
    );
    push_key_agreement(
        &mut non_canonical,
        &x,
        &y,
        i64::from(COSE_ALG_ES256),
        CoseKeyOrder::NonCanonical,
    );
    assert_ne!(
        canonical.as_slice(),
        non_canonical.as_slice(),
        "the two label orders must not encode to the same bytes"
    );

    // And the same must hold for the `Value` builder's *input*, which is the
    // trap: `cbor::encode` sorts it away.
    let as_value = |order: CoseKeyOrder| {
        cbor::encode(&cose_key_map_with(&x, &y, i64::from(COSE_ALG_ES256), order))
    };
    assert_eq!(
        as_value(CoseKeyOrder::Canonical),
        as_value(CoseKeyOrder::NonCanonical),
        "cbor::encode normalises map order — use push_key_agreement on the wire"
    );
}

/// US-120: the host `pin::parse_cose_key_map` twin must accept alg=-7 and a
/// non-canonical label order, in every combination, and still derive usable
/// shared secrets.
#[test]
fn key_agreement_accepts_alg_minus7() {
    for (alg, order, label) in compat_combinations() {
        // `PinClient::new` drives getKeyAgreement (0x02) and derives the v1
        // shared keys from the peer key; assert the peer key is well-formed.
        let mut app = FidoApp::with_keystore(MemoryKeystore::new());
        let client = PinClient::new(&mut app);

        let (px, py) = assert_well_formed_peer_key(&peer_cose_key(&mut app));
        assert!(
            crypto::parse_cose_ec2_p256(&px, &py).is_some(),
            "peerCoseKey must be a valid P-256 point ({})",
            label
        );

        assert_eq!(
            client.set_pin_with_cose(&mut app, alg, order),
            0x00,
            "setPIN must accept key-agreement map with {}",
            label
        );

        // Sanity: with the PIN stored, the authenticator accepts the correct
        // PIN and hands back a token. This does NOT re-exercise the map under
        // test — `get_token` sends the canonical alg=-25 map — so it proves
        // the authenticator is in a usable state, not that these coordinates
        // were read. The setPIN assertion above is the guard.
        client
            .get_token(&mut app, 0x05, None, None)
            .unwrap_or_else(|e| {
                panic!(
                    "getPinToken must succeed after setPIN with {} (status {:#04x})",
                    label, e
                )
            });
    }
}

/// US-120: the same guard for the device (`no_std`, no-heap) twin, whose
/// key-agreement parser is `device_core::parse_key_agreement` — a different
/// implementation reached through a different entry point. Driven through
/// `device_app::FidoApp::process_ctap2`, the exact handler the RP2350 serve
/// loop runs.
mod device_twin {
    use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
    use fapico2_fido::crypto;
    use fapico2_fido::device_app::FidoApp;
    use fapico2_fido::{COSE_ALG_ECDH_ES_HKDF_256, COSE_ALG_ES256};
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;
    use heapless::Vec as HV;

    use crate::common::{push_key_agreement, CoseKeyOrder, PIN};

    struct Client {
        app: FidoApp,
        hmac_key: [u8; 32],
        enc_key: [u8; 32],
    }

    /// A fixed client key so the coordinates are deterministic per test.
    fn client_sk() -> p256::SecretKey {
        p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap()
    }

    fn client_coords() -> ([u8; 32], [u8; 32]) {
        let bytes = crypto::public_key_bytes(&client_sk().public_key());
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        (x, y)
    }

    impl Client {
        fn boot(trng: &mut HostTrng) -> Self {
            let mut store = HostSecureStore::new();
            let app = FidoApp::boot(trng, &mut store).unwrap();
            Self {
                app,
                hmac_key: [0; 32],
                enc_key: [0; 32],
            }
        }

        fn call(&mut self, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = self.app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
            let resp = out.as_slice()[..n].to_vec();
            (resp[0], resp[1..].to_vec())
        }

        /// getKeyAgreement (0x02) → assert a well-formed peer COSE key and
        /// derive the v1 shared keys from its coordinates.
        fn get_key_agreement(&mut self) {
            let mut req: HV<u8, 64> = HV::new();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            let (status, cbor) = self.call(0x06, req.as_slice());
            assert_eq!(status, 0x00, "getKeyAgreement must succeed");

            let mut p = Parser::new(&cbor);
            let Item::Map(1) = p.next().unwrap() else {
                panic!("response map")
            };
            assert_eq!(p.next().unwrap(), Item::U(1), "peerCoseKey at label 1");
            let Item::Map(n) = p.next().unwrap() else {
                panic!("COSE key map")
            };
            let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
            let mut saw_kty = false;
            let mut saw_alg = false;
            for _ in 0..n {
                let key = match p.next().unwrap() {
                    Item::U(u) => u as i64,
                    Item::N(nn) => nn,
                    other => panic!("unexpected COSE label {:?}", other),
                };
                match key {
                    1 => {
                        assert_eq!(p.next().unwrap(), Item::U(2), "kty must be EC2 (2)");
                        saw_kty = true;
                    }
                    3 => {
                        // The authenticator advertises the spec value.
                        assert_eq!(
                            p.next().unwrap(),
                            Item::N(i64::from(COSE_ALG_ECDH_ES_HKDF_256)),
                            "authenticator alg must be ECDH-ES+HKDF-256"
                        );
                        saw_alg = true;
                    }
                    -1 => assert_eq!(p.next().unwrap(), Item::U(1), "crv must be P-256 (1)"),
                    -2 => match p.next().unwrap() {
                        Item::B(b) => {
                            assert_eq!(b.len(), 32, "x must be 32 bytes");
                            x.copy_from_slice(b);
                        }
                        other => panic!("x must be a bstr, got {:?}", other),
                    },
                    -3 => match p.next().unwrap() {
                        Item::B(b) => {
                            assert_eq!(b.len(), 32, "y must be 32 bytes");
                            y.copy_from_slice(b);
                        }
                        other => panic!("y must be a bstr, got {:?}", other),
                    },
                    _ => p.skip().unwrap(),
                }
            }
            assert!(saw_kty, "peerCoseKey must carry kty");
            assert!(saw_alg, "peerCoseKey must carry alg");

            // The coordinates are a usable P-256 point...
            let pub_bytes = [x, y].concat();
            let device_pub = crypto::parse_cose_ec2_p256_bytes(&pub_bytes[..32], &pub_bytes[32..])
                .expect("peer key must be a valid P-256 point");
            // ...and yield shared secrets the client can reproduce.
            let raw = crypto::ecdh_shared_secret(&client_sk(), &device_pub);
            let k = crypto::derive_shared_secret_v1(&raw);
            self.hmac_key = k;
            self.enc_key = k;
        }

        fn v1_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut padded = plaintext.to_vec();
            while !padded.len().is_multiple_of(16) {
                padded.push(0);
            }
            let mut buf = [0u8; 96];
            buf[..padded.len()].copy_from_slice(&padded);
            crypto::aes256_cbc_encrypt_into(&self.enc_key, &[0u8; 16], &mut buf[..padded.len()])
                .unwrap();
            buf[..padded.len()].to_vec()
        }

        /// setPIN (0x03) with an explicit `alg` and label order. Returns the
        /// status.
        fn set_pin_with_cose(&mut self, alg: i64, order: CoseKeyOrder) -> u8 {
            let (x, y) = client_coords();
            let pin_enc = self.v1_encrypt(PIN.as_bytes());
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 5).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            // CBOR key 3: the client's key-agreement map.
            nh::push_uint(&mut req, 3).unwrap();
            push_key_agreement(&mut req, &x, &y, alg, order);
            nh::push_uint(&mut req, 5).unwrap();
            nh::push_bstr(&mut req, &pin_enc).unwrap();
            nh::push_uint(&mut req, 4).unwrap();
            let tag = crypto::hmac_sha256(&self.hmac_key, &pin_enc)[..16].to_vec();
            nh::push_bstr(&mut req, &tag).unwrap();
            self.call(0x06, req.as_slice()).0
        }

        /// getPinToken (0x05) with the correct PIN. Returns the CTAP2 status.
        ///
        /// Sanity check only: this sends the canonical alg=-25 map, so it
        /// proves the authenticator is in a usable state, not that the map
        /// under test was read. The setPIN assertion is the guard.
        fn get_pin_token(&mut self) -> u8 {
            let (x, y) = client_coords();
            let pin_hash = crypto::pin_hash(PIN.as_bytes());
            let pin_hash_enc = self.v1_encrypt(&pin_hash);
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 4).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 5).unwrap();
            // CBOR key 3: the client's key-agreement map.
            nh::push_uint(&mut req, 3).unwrap();
            push_key_agreement(
                &mut req,
                &x,
                &y,
                i64::from(COSE_ALG_ECDH_ES_HKDF_256),
                CoseKeyOrder::Canonical,
            );
            nh::push_uint(&mut req, 6).unwrap();
            nh::push_bstr(&mut req, &pin_hash_enc).unwrap();
            self.call(0x06, req.as_slice()).0
        }
    }

    #[test]
    fn device_key_agreement_accepts_alg_minus7() {
        let cases = [
            (
                i64::from(COSE_ALG_ECDH_ES_HKDF_256),
                CoseKeyOrder::Canonical,
                "alg=-25, canonical order",
            ),
            (
                i64::from(COSE_ALG_ES256),
                CoseKeyOrder::Canonical,
                "alg=-7, canonical order",
            ),
            (
                i64::from(COSE_ALG_ECDH_ES_HKDF_256),
                CoseKeyOrder::NonCanonical,
                "alg=-25, PicoForge BTreeMap order",
            ),
            (
                i64::from(COSE_ALG_ES256),
                CoseKeyOrder::NonCanonical,
                "alg=-7, PicoForge BTreeMap order",
            ),
        ];
        for (alg, order, label) in cases {
            let mut trng = HostTrng::new();
            let mut client = Client::boot(&mut trng);
            client.get_key_agreement();

            assert_eq!(
                client.set_pin_with_cose(alg, order),
                0x00,
                "setPIN must accept key-agreement map with {}",
                label
            );
            assert_eq!(
                client.get_pin_token(),
                0x00,
                "getPinToken must succeed after setPIN with {}",
                label
            );
        }
    }
}
