//! clientPIN sub-command `0x06` (`getPinUvAuthTokenUsingUvWithPermissions`)
//! is refused `InvalidSubcommand` (0x3E) by BOTH twins — and the refusal
//! must not open a presence window.
//!
//! Why this file exists. The device used to mint a pinUvAuthToken on a
//! presence grant alone from this sub-command. Measured on hardware against
//! demo.yubico.com/webauthn: the client armed the device with `0x01
//! PROCESSING` / `0x02 UP NEEDED`, waited 30.2 s, and closed with `0x2D
//! KEEPALIVE_CANCEL` — no PIN prompt ever appeared, because the PIN prompt
//! is a client-side decision the client had not made. GetInfo advertises the
//! canonical Client-PIN-only shape (`clientPin` per state, `uv` absent,
//! `pinUvAuthToken` true), and CTAP 2.2 §5.4.6 grants sub-command `0x06`
//! only when the `uv` option is present and true. The C reference never
//! implemented it: `pico-fido2/src/fido/cbor_client_pin.c` chains
//! 0x01/0x02/0x03/0x04/0x09|0x05 and falls through to
//! `CTAP2_ERR_INVALID_SUBCOMMAND` (line 909).
//!
//! The falsifiability seam. The transport (`firmware/src/hid_serve.rs`)
//! parks a command in the consent slot and opens the 30 s touch window only
//! when the app answers **`UpRequired` (0x3B)** on a presence-windowed
//! command — `0x06` is in that set. So a status-only assertion would have
//! passed before this fix too (the arm answered `PinAuthBlocked` or
//! `UpRequired` depending on state, never a token-less `0x3E`). The test
//! that cannot lie is the **presence-denied** device run: with the presence
//! source hard-denied, the removed arm was forced down its
//! `user_present == false` path and answered `UpRequired` (0x3B). The fixed
//! code refuses `0x3E` *before* presence is consulted. Asserting
//! `0x3E and not 0x3B` under denied presence therefore fails on the old
//! code and passes on the new — see the report for both runs.

mod common;

use common::*;

// ---------------------------------------------------------------------------
// Host twin (`app.rs` + `pin.rs`)
// ---------------------------------------------------------------------------

type FidoAppMem = fapico2_fido::app::FidoApp<fapico2_fido::keystore::MemoryKeystore>;

/// A fully-formed `0x06` request: keyAgreement present, permissions present.
/// The refusal must come from the sub-command gate, not a missing-parameter
/// short-circuit.
fn host_uv_request(client: &PinClient) -> Vec<u8> {
    fapico2_fido::cbor::encode(&fapico2_fido::cbor::Value::M(vec![
        (fapico2_fido::cbor::Value::U(0x01), fapico2_fido::cbor::Value::U(2)),
        (fapico2_fido::cbor::Value::U(0x02), fapico2_fido::cbor::Value::U(0x06)),
        (fapico2_fido::cbor::Value::U(0x03), client.client_cose()),
        (fapico2_fido::cbor::Value::U(0x09), fapico2_fido::cbor::Value::U(0x04)),
    ]))
}

#[test]
fn host_06_is_refused_invalid_subcommand() {
    let mut app = FidoAppMem::with_keystore(fapico2_fido::keystore::MemoryKeystore::new());
    let client = PinClient::new(&mut app);
    let resp = app.process_ctap2(0x06, &host_uv_request(&client), [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x3E, "0x06 must be refused InvalidSubcommand");
    assert_eq!(
        resp.len(),
        1,
        "the refusal is a bare status byte — no CBOR body, no token"
    );
}

/// The PIN legs the advertisement actually names (`0x05`/`0x09`, CTAP 2.2
/// §5.4.6) are untouched: both still mint a 32-byte token on a PIN-set app.
#[test]
fn host_05_and_09_pin_legs_still_mint() {
    // `setup` already sets the PIN (a second setPIN would answer NotAllowed).
    let (mut app, client) = setup();

    let token_09 = client
        .get_token(&mut app, 0x09, Some(0x04), None)
        .expect("0x09 (with permissions) must still mint");
    assert_eq!(token_09.len(), 32);

    let token_05 = client
        .get_token(&mut app, 0x05, None, None)
        .expect("0x05 (legacy getPinToken) must still mint");
    assert_eq!(token_05.len(), 32);
}

// ---------------------------------------------------------------------------
// Device twin (`device_app.rs` + `device_core.rs`) — the RP2350 binary.
// ---------------------------------------------------------------------------

mod device {
    use fapico2_fido::cbor::no_heap as nh;
    use fapico2_fido::cbor::no_heap::{Item, Parser};
    use fapico2_fido::crypto;
    use fapico2_fido::device_app::FidoApp;
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;
    use heapless::Vec as HV;

    const INVALID_SUBCOMMAND: u8 = 0x3E;
    const UP_REQUIRED: u8 = 0x3B;

    fn deny_all() -> bool {
        false
    }

    fn grant_all(_tag: u32) -> bool {
        true
    }

    /// The falsifiability device: presence hard-DENIED. Under the removed
    /// arm, `0x06` with no touch answered `UpRequired` — the exact byte the
    /// transport parks into the 30 s window. If that arm ever comes back,
    /// the next test goes red on `0x3B`.
    fn boot_presence_denied() -> FidoApp {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        FidoApp::boot(&mut trng, &mut store)
            .unwrap()
            .with_user_presence(deny_all)
    }

    /// Presence auto-granted: even a real touch must not mint a `0x06`
    /// token.
    fn boot_presence_granted() -> FidoApp {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        FidoApp::boot(&mut trng, &mut store)
            .unwrap()
            .with_presence_grant(grant_all)
    }

    fn call(app: &mut FidoApp, cmd: u8, payload: &[u8]) -> Vec<u8> {
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
        out[..n].to_vec()
    }

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

    /// getKeyAgreement → the v1 shared keys (hmac_key == enc_key == k) and
    /// the client's public coordinates.
    fn handshake(app: &mut FidoApp, client_sk: &p256::SecretKey) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut req: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        let resp = call(app, 0x06, req.as_slice());
        assert_eq!(resp[0], 0x00, "getKeyAgreement must succeed");
        // {1: {1: 2, 3: -25, -1: 1, -2: x, -3: y}} — the COSE map is nested
        // under label 1, so descend into it explicitly.
        let mut p = Parser::new(&resp[1..]);
        let Item::Map(_) = p.next().unwrap() else { panic!("map") };
        let Item::U(1) = p.next().unwrap() else { panic!("label 1") };
        let Item::Map(n) = p.next().unwrap() else { panic!("cose map") };
        let mut dx = [0u8; 32];
        let mut dy = [0u8; 32];
        let mut saw_x = false;
        let mut saw_y = false;
        for _ in 0..n {
            let k = match p.next().unwrap() {
                Item::U(u) => u as i64,
                Item::N(n) => n,
                other => panic!("label {:?}", other),
            };
            match k {
                -2 => match p.next().unwrap() {
                    Item::B(b) => {
                        dx.copy_from_slice(b);
                        saw_x = true;
                    }
                    other => panic!("x {:?}", other),
                },
                -3 => match p.next().unwrap() {
                    Item::B(b) => {
                        dy.copy_from_slice(b);
                        saw_y = true;
                    }
                    other => panic!("y {:?}", other),
                },
                _ => {
                    p.skip().unwrap();
                }
            }
        }
        assert!(saw_x && saw_y, "device public point missing");
        let device_pub = crypto::parse_cose_ec2_p256_bytes(&dx, &dy).expect("device pubkey");
        let raw = crypto::ecdh_shared_secret(client_sk, &device_pub);
        let k = crypto::derive_shared_secret_v1(&raw);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let bytes = crypto::public_key_bytes(&client_sk.public_key());
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        (k, x, y)
    }

    /// THE test: denied presence, fully-formed `0x06` request →
    /// `InvalidSubcommand`, **not** `UpRequired`. This is the assertion that
    /// proves no presence window opens: the transport only enters the window
    /// on a `0x3B` answer, so a `0x3E` here means the request can never arm
    /// the device — it is answered immediately, in one pass.
    #[test]
    fn device_06_refused_without_opening_a_presence_window() {
        let mut app = boot_presence_denied();
        let client_sk = p256::SecretKey::from_slice(&[0x77u8; 32]).unwrap();
        let (k, x, y) = handshake(&mut app, &client_sk);
        let _ = k;
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 4).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        push_client_cose(&mut req, &x, &y);
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        let resp = call(&mut app, 0x06, req.as_slice());
        assert_eq!(
            resp[0], INVALID_SUBCOMMAND,
            "0x06 must refuse InvalidSubcommand with no touch available"
        );
        assert_ne!(
            resp[0], UP_REQUIRED,
            "a UpRequired answer here is the removed arm — it is what the \
             transport parks into the 30 s no-PIN window"
        );
        assert_eq!(resp.len(), 1, "bare status byte: no token was minted");
    }

    /// Same refusal with presence auto-granted: a touch alone must not mint
    /// a token either way.
    #[test]
    fn device_06_refused_even_when_a_touch_is_granted() {
        let mut app = boot_presence_granted();
        let client_sk = p256::SecretKey::from_slice(&[0x77u8; 32]).unwrap();
        let (_k, x, y) = handshake(&mut app, &client_sk);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 4).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        push_client_cose(&mut req, &x, &y);
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        let resp = call(&mut app, 0x06, req.as_slice());
        assert_eq!(
            resp[0], INVALID_SUBCOMMAND,
            "even a granted touch must not mint a 0x06 token"
        );
        assert_eq!(resp.len(), 1);
    }

    /// The PIN legs are untouched on the shipping path: setPIN then a `0x09`
    /// token with the cm permission still mints, end to end.
    #[test]
    fn device_09_pin_leg_still_mints() {
        let mut app = boot_presence_granted();
        let client_sk = p256::SecretKey::from_slice(&[0x77u8; 32]).unwrap();
        let (k, x, y) = handshake(&mut app, &client_sk);

        // setPIN (v1): raw PIN, zero-padded, HMAC(k, pinEnc)[..16] auth.
        let mut padded = b"1234".to_vec();
        while padded.len() < 16 {
            padded.push(0);
        }
        let mut buf = [0u8; 96];
        buf[..padded.len()].copy_from_slice(&padded);
        crypto::aes256_cbc_encrypt_into(&k, &[0u8; 16], &mut buf[..padded.len()]).unwrap();
        let pin_enc = buf[..padded.len()].to_vec();
        let tag = crypto::hmac_sha256(&k, &pin_enc)[..16].to_vec();
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        push_client_cose(&mut req, &x, &y);
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_bstr(&mut req, &pin_enc).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &tag).unwrap();
        let resp = call(&mut app, 0x06, req.as_slice());
        assert_eq!(resp[0], 0x00, "setPIN must succeed on the device path");

        // 0x09 with permissions 0x04 (cm) — the leg every working site uses.
        let pin_hash = crypto::pin_hash(b"1234");
        let mut hbuf = [0u8; 96];
        hbuf[..16].copy_from_slice(&pin_hash);
        crypto::aes256_cbc_encrypt_into(&k, &[0u8; 16], &mut hbuf[..16]).unwrap();
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        push_client_cose(&mut req, &x, &y);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &hbuf[..16]).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        let resp = call(&mut app, 0x06, req.as_slice());
        assert_eq!(resp[0], 0x00, "the 0x09 PIN token leg must still work");
        let mut p = Parser::new(&resp[1..]);
        let Item::Map(nm) = p.next().unwrap() else { panic!("map") };
        let mut enc: Vec<u8> = Vec::new();
        for _ in 0..nm {
            let key = match p.next().unwrap() {
                Item::U(u) => u,
                other => panic!("key {:?}", other),
            };
            if key == 2 {
                match p.next().unwrap() {
                    Item::B(b) => enc.extend_from_slice(b),
                    other => panic!("token {:?}", other),
                }
            } else {
                p.next().unwrap();
            }
        }
        let token = crypto::pin_decrypt_v1(&k, &enc).expect("token decrypts");
        assert_eq!(token.len(), 32, "a real 32-byte pinUvAuthToken");
    }
}
