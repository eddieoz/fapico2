//! US-909: durable FIDO PIN retry/lockout state.
//!
//! The 3-strike PIN-mismatch latch (`needs_power_cycle` +
//! `new_pin_mismatches`) must survive both a new HID client connection
//! (`clear_session_state`) and an emulator restart (snapshot persist +
//! reload). Only a correct PIN — or a power cycle with zero mismatches —
//! clears it. Regression link (US-923): the `PIN_AUTH_BLOCKED` latch set by
//! the pinUvAuth failure streak stays durable the same way.

mod common;

use common::*;
use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::crypto;
use fapico2_fido::keystore::FileKeystore;

const PIN_INVALID: u8 = 0x31;
const PIN_AUTH_INVALID: u8 = 0x33;
const PIN_AUTH_BLOCKED: u8 = 0x34;

fn temp_path(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("us909-{}-{}.fido", std::process::id(), tag));
    let _ = std::fs::remove_file(&p);
    p
}

/// getPinToken (0x05) with pinHashEnc derived from the WRONG pin.
/// Returns the CTAP2 status byte.
fn wrong_pin_attempt(app: &mut FidoApp<FileKeystore>, client: &PinClient) -> u8 {
    let wrong = crypto::pin_hash(b"0000");
    let pin_hash_enc = crypto::pin_encrypt(2, &client.enc_key, &wrong);
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x05)),
        (Value::U(0x03), client.client_cose()),
        (Value::U(0x06), Value::B(pin_hash_enc)),
    ]));
    app.process_ctap2(0x06, &req, [1, 2, 3, 4])[0]
}

/// getRetries (0x01) → (retries, powerCycleState).
fn get_retries(app: &mut FidoApp<FileKeystore>) -> (u8, bool) {
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x01)),
    ]));
    let resp = app.process_ctap2(0x06, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "getRetries must succeed");
    let (v, _) = cbor::decode(&resp[1..]).expect("valid CBOR");
    let Value::M(m) = v else { panic!("map expected") };
    let get = |key: u64| -> Option<&Value> {
        m.iter().find(|(k, _)| matches!(k, Value::U(u) if *u == key)).map(|(_, v)| v)
    };
    let retries = match get(3) {
        Some(Value::U(u)) => *u as u8,
        _ => panic!("retries in response"),
    };
    let power = matches!(get(4), Some(Value::Bool(true)));
    (retries, power)
}

#[test]
fn lockout_survives_snapshot_and_reconnect() {
    let path = temp_path("latch");
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    let client = PinClient::new(&mut app);
    client.set_pin(&mut app);

    // Two wrong PINs: each consumes a retry, returns PinInvalid.
    assert_eq!(wrong_pin_attempt(&mut app, &client), PIN_INVALID);
    assert_eq!(wrong_pin_attempt(&mut app, &client), PIN_INVALID);

    // Snapshot persisted; fresh app from the store (emulator restart). The
    // host app mints a fresh key-agreement key per instance, so the client
    // re-runs getKeyAgreement against the reloaded app.
    drop(app);
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    let client = PinClient::new(&mut app);

    // New HID client connection on the restarted process: the mismatch
    // budget must NOT reset (US-909).
    app.clear_session_state();

    // One remaining wrong attempt triggers the 3-strike latch.
    assert_eq!(wrong_pin_attempt(&mut app, &client), PIN_AUTH_BLOCKED);

    // Another new HID connection does NOT clear the latch.
    app.clear_session_state();
    assert_eq!(wrong_pin_attempt(&mut app, &client), PIN_AUTH_BLOCKED);

    // getRetries keeps exposing the lockout (spec: retries budget + power
    // cycle state). The budget drains on every attempt (8 - 4 attempts),
    // including the latched ones.
    let (retries, power) = get_retries(&mut app);
    assert_eq!(retries, 4);
    assert!(power, "powerCycleState must report the durable latch");

    // A correct PIN clears the latch (durable until then only).
    let token = client.get_token(&mut app, 0x05, None, None);
    assert!(token.is_ok(), "correct PIN must unlock");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pin_uv_auth_streak_latch_stays_durable() {
    // US-923 regression: the pinUvAuthParam failure streak that sets the
    // PIN_AUTH_BLOCKED latch must survive a new HID connection (the latch is
    // `needs_power_cycle`/`blocked`, not the volatile streak counter).
    let path = temp_path("puvauth");
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    let client = PinClient::new(&mut app);
    client.set_pin(&mut app);
    // Mint a token first: pinUvAuth failures are only counted against a
    // session that holds a token (CTAP2.1 §6.5.7).
    let _ = client.get_token(&mut app, 0x05, None, None).unwrap();

    // makeCredential with a garbage pinUvAuthParam: three consecutive
    // pinUvAuth failures latch PIN_AUTH_BLOCKED (FX-406).
    let bad_mc = || {
        cbor::encode(&Value::M(vec![
            (Value::U(0x01), Value::B(vec![0u8; 32])),
            (Value::U(0x02), Value::M(vec![
                (Value::T("id".to_string()), Value::T("example.com".to_string())),
                (Value::T("name".to_string()), Value::T("RP".to_string())),
            ])),
            (Value::U(0x03), Value::M(vec![
                (Value::T("id".to_string()), Value::B(b"user".to_vec())),
                (Value::T("name".to_string()), Value::T("U".to_string())),
            ])),
            (Value::U(0x04), Value::A(vec![Value::M(vec![
                (Value::T("type".to_string()), Value::T("public-key".to_string())),
                (Value::T("alg".to_string()), Value::N(-7)),
            ])])),
            (Value::U(0x08), Value::B(vec![0u8; 16])),
            (Value::U(0x09), Value::U(2)),
        ]))
    };
    assert_eq!(app.process_ctap2(0x01, &bad_mc(), [1, 2, 3, 4])[0], PIN_AUTH_INVALID);
    assert_eq!(app.process_ctap2(0x01, &bad_mc(), [1, 2, 3, 4])[0], PIN_AUTH_INVALID);
    assert_eq!(app.process_ctap2(0x01, &bad_mc(), [1, 2, 3, 4])[0], PIN_AUTH_BLOCKED);

    // New HID connection: the latch survives.
    app.clear_session_state();
    assert_eq!(app.process_ctap2(0x01, &bad_mc(), [1, 2, 3, 4])[0], PIN_AUTH_BLOCKED);

    // And it survives a snapshot reload (emulator restart).
    drop(app);
    let mut app = FidoApp::with_keystore(FileKeystore::load_or_create(path.clone()).unwrap());
    assert_eq!(app.process_ctap2(0x01, &bad_mc(), [1, 2, 3, 4])[0], PIN_AUTH_BLOCKED);

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// US-909 review: the same pinUvAuthParam streak latch on the **device**
// command path (`device_core.rs`). The device latch must set
// `needs_power_cycle` — the flag `verify_token` actually gates on — and be
// durable, mirroring `pin_uv_auth_streak_latch_stays_durable` above. Driven
// through `FidoApp::process_ctap2` (the exact handler the RP2350 serve loop
// runs) with the no-heap CBOR writer, per the device-path test convention.
// ---------------------------------------------------------------------------
mod device_twin {
    use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
    use fapico2_fido::crypto;
    use fapico2_fido::device_app::FidoApp;
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;
    use heapless::Vec as HV;

    const PIN_AUTH_INVALID: u8 = 0x33;
    const PIN_AUTH_BLOCKED: u8 = 0x34;

    struct Client {
        app: FidoApp,
        hmac_key: [u8; 32],
        enc_key: [u8; 32],
        pin_token: Option<[u8; 32]>,
    }

    impl Client {
        fn boot(trng: &mut HostTrng) -> (Self, HostSecureStore) {
            let mut store = HostSecureStore::new();
            let app = FidoApp::boot(trng, &mut store).unwrap();
            (Self { app, hmac_key: [0; 32], enc_key: [0; 32], pin_token: None }, store)
        }

        fn call(&mut self, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = self.app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
            let resp = out.as_slice()[..n].to_vec();
            (resp[0], resp[1..].to_vec())
        }

        /// clientPin getKeyAgreement → derive the v1 shared keys.
        fn derive_keys(&mut self) {
            let mut req: HV<u8, 64> = HV::new();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            let (status, cbor) = self.call(0x06, req.as_slice());
            assert_eq!(status, 0x00, "getKeyAgreement failed");
            let mut p = Parser::new(&cbor);
            assert!(matches!(p.next(), Ok(Item::Map(1))));
            assert_eq!(p.next().unwrap(), Item::U(1));
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            let Item::Map(n) = p.next().unwrap() else { panic!() };
            for _ in 0..n {
                let key = match p.next().unwrap() {
                    Item::U(u) => u as i64,
                    Item::N(n) => n,
                    _ => panic!(),
                };
                match key {
                    -2 => match p.next().unwrap() {
                        Item::B(b) => x.copy_from_slice(b),
                        _ => panic!(),
                    },
                    -3 => match p.next().unwrap() {
                        Item::B(b) => y.copy_from_slice(b),
                        _ => panic!(),
                    },
                    _ => p.skip().unwrap(),
                }
            }
            let client_sk = p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap();
            let device_pub = crypto::parse_cose_ec2_p256_bytes(&x, &y).expect("device pubkey");
            let raw = crypto::ecdh_shared_secret(&client_sk, &device_pub);
            let k = crypto::derive_shared_secret_v1(&raw);
            self.hmac_key = k;
            self.enc_key = k;
        }

        fn push_client_key_agreement(&self, out: &mut HV<u8, 256>) {
            let client_sk = p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap();
            let bytes = crypto::public_key_bytes(&client_sk.public_key());
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&bytes[1..33]);
            y.copy_from_slice(&bytes[33..65]);
            nh::push_map_header(out, 5).unwrap();
            nh::push_uint(out, 1).unwrap();
            nh::push_uint(out, 2).unwrap();
            nh::push_uint(out, 3).unwrap();
            nh::push_neg(out, -25).unwrap();
            nh::push_neg(out, -1).unwrap();
            nh::push_uint(out, 1).unwrap();
            nh::push_neg(out, -2).unwrap();
            nh::push_bstr(out, &x).unwrap();
            nh::push_neg(out, -3).unwrap();
            nh::push_bstr(out, &y).unwrap();
        }

        fn v1_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut padded = plaintext.to_vec();
            while !padded.len().is_multiple_of(16) {
                padded.push(0);
            }
            let mut buf = [0u8; 96];
            buf[..padded.len()].copy_from_slice(&padded);
            let zero_iv = [0u8; 16];
            crypto::aes256_cbc_encrypt_into(&self.enc_key, &zero_iv, &mut buf[..padded.len()]).unwrap();
            buf[..padded.len()].to_vec()
        }

        fn set_pin(&mut self, pin: &[u8]) {
            self.derive_keys();
            let pin_enc = self.v1_encrypt(pin);
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 5).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            self.push_client_key_agreement(&mut req);
            nh::push_uint(&mut req, 5).unwrap();
            nh::push_bstr(&mut req, &pin_enc).unwrap();
            nh::push_uint(&mut req, 4).unwrap();
            let tag = crypto::hmac_sha256(&self.hmac_key, &pin_enc)[..16].to_vec();
            nh::push_bstr(&mut req, &tag).unwrap();
            let (status, _) = self.call(0x06, req.as_slice());
            assert_eq!(status, 0x00, "setPIN failed");
        }

        /// getPinToken → raw token (v1).
        fn get_pin_token(&mut self, pin: &[u8]) {
            let pin_hash = crypto::pin_hash(pin);
            let pin_hash_enc = self.v1_encrypt(&pin_hash);
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 4).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 5).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            self.push_client_key_agreement(&mut req);
            nh::push_uint(&mut req, 6).unwrap();
            nh::push_bstr(&mut req, &pin_hash_enc).unwrap();
            let (status, cbor) = self.call(0x06, req.as_slice());
            assert_eq!(status, 0x00, "getPinToken failed");
            let mut p = Parser::new(&cbor);
            assert!(matches!(p.next(), Ok(Item::Map(1))));
            assert_eq!(p.next().unwrap(), Item::U(2));
            let Item::B(ct) = p.next().unwrap() else { panic!() };
            let mut buf = [0u8; 96];
            buf[..ct.len()].copy_from_slice(ct);
            let zero_iv = [0u8; 16];
            crypto::aes256_cbc_decrypt_into(&self.enc_key, &zero_iv, &mut buf[..ct.len()]).unwrap();
            let mut token = [0u8; 32];
            token.copy_from_slice(&buf[..32]);
            self.pin_token = Some(token);
        }

        /// makeCredential with a garbage pinUvAuthParam (protocol v2):
        /// returns the CTAP2 status byte.
        fn bad_mc_status(&mut self, challenge: &[u8; 32]) -> u8 {
            let mut r: HV<u8, 512> = HV::new();
            nh::push_map_header(&mut r, 6).unwrap();
            nh::push_uint(&mut r, 1).unwrap();
            nh::push_bstr(&mut r, challenge).unwrap();
            nh::push_uint(&mut r, 2).unwrap();
            nh::push_map_header(&mut r, 1).unwrap();
            nh::push_tstr(&mut r, "id").unwrap();
            nh::push_tstr(&mut r, "example.com").unwrap();
            nh::push_uint(&mut r, 3).unwrap();
            nh::push_map_header(&mut r, 1).unwrap();
            nh::push_tstr(&mut r, "id").unwrap();
            nh::push_bstr(&mut r, b"user").unwrap();
            nh::push_uint(&mut r, 4).unwrap();
            nh::push_array_header(&mut r, 1).unwrap();
            nh::push_map_header(&mut r, 2).unwrap();
            nh::push_tstr(&mut r, "type").unwrap();
            nh::push_tstr(&mut r, "public-key").unwrap();
            nh::push_tstr(&mut r, "alg").unwrap();
            nh::push_neg(&mut r, -7).unwrap();
            nh::push_uint(&mut r, 8).unwrap();
            nh::push_bstr(&mut r, &[0u8; 16]).unwrap();
            nh::push_uint(&mut r, 9).unwrap();
            nh::push_uint(&mut r, 2).unwrap();
            self.call(0x01, r.as_slice()).0
        }

        /// getRetries → (retries, powerCycleState).
        fn get_retries(&mut self) -> (u8, bool) {
            let mut req: HV<u8, 64> = HV::new();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            let (status, cbor) = self.call(0x06, req.as_slice());
            assert_eq!(status, 0x00, "getRetries must succeed");
            let mut p = Parser::new(&cbor);
            assert!(matches!(p.next(), Ok(Item::Map(_))));
            let (mut retries, mut power) = (0u8, false);
            while p.remaining() > 0 {
                let Item::U(k) = p.next().unwrap() else { panic!() };
                match k {
                    3 => retries = match p.next().unwrap() {
                        Item::U(u) => u as u8,
                        _ => panic!(),
                    },
                    4 => power = matches!(p.next().unwrap(), Item::Bool(true)),
                    _ => p.skip().unwrap(),
                }
            }
            (retries, power)
        }
    }

    #[test]
    fn device_pin_uv_auth_streak_latch_stays_durable() {
        let mut trng = HostTrng::new();
        let (mut client, mut store) = Client::boot(&mut trng);
        client.set_pin(b"1234");
        client.get_pin_token(b"1234");

        // Three consecutive garbage pinUvAuthParams latch PIN_AUTH_BLOCKED
        // (FX-406) — the review found the device latch left the gate flag
        // (`needs_power_cycle`) unset, so verify_token kept accepting.
        assert_eq!(client.bad_mc_status(&[7u8; 32]), PIN_AUTH_INVALID);
        assert_eq!(client.bad_mc_status(&[7u8; 32]), PIN_AUTH_INVALID);
        assert_eq!(client.bad_mc_status(&[7u8; 32]), PIN_AUTH_BLOCKED);
        let (retries, power) = client.get_retries();
        assert_eq!(retries, 8, "getRetries budget intact");
        assert!(power, "powerCycleState must report the latch");

        // New HID client connection: the latch survives (the volatile token
        // and streak are wiped; the durable flags are not).
        client.app.clear_session_state();
        assert_eq!(client.bad_mc_status(&[7u8; 32]), PIN_AUTH_BLOCKED);

        // And it survives a snapshot reload (emulator restart).
        client.app.persist_if_dirty(&mut store);
        let image = store.partition_image();
        drop(client);
        let mut restored = HostSecureStore::new();
        restored.from_partition_image(&image);
        let mut trng2 = HostTrng::new();
        let app = FidoApp::boot(&mut trng2, &mut restored).unwrap();
        let mut client2 = Client {
            app,
            hmac_key: [0; 32],
            enc_key: [0; 32],
            pin_token: None,
        };
        // The gate is checked before any session key/token material, so the
        // stale-session client still sees the durable latch.
        assert_eq!(client2.bad_mc_status(&[7u8; 32]), PIN_AUTH_BLOCKED);
        let (retries, power) = client2.get_retries();
        assert_eq!(retries, 8);
        assert!(power, "powerCycleState must survive the reboot");
    }
}
