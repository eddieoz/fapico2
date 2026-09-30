//! S-701-4 TDD: core CTAP2 (makeCredential / getAssertion / clientPin) on the
//! **device** command path.
//!
//! The test acts as the CTAP2 client (python-fido2's role): it derives the
//! PIN protocol v1 shared secret against the device `hkey`, sets a PIN,
//! mints a PIN token and performs a full makeCredential → getAssertion
//! ceremony through `FidoApp::process_ctap2` — the exact handler code the
//! RP2350 serve loop runs. The ES256 assertion signature is verified against
//! the returned COSE key.

use fapico2_fido::cbor::no_heap::{Item, Parser};
use fapico2_fido::crypto;
use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// CTAP2 client response: status byte + parsed CBOR item stream is walked by
/// the caller; here we just check framing helpers.
struct DeviceClient {
    app: FidoApp,
    /// PIN protocol v1 keys derived from the device key agreement.
    hmac_key: [u8; 32],
    enc_key: [u8; 32],
    pin_token: Option<[u8; 32]>,
}

impl DeviceClient {
    fn new(app: FidoApp) -> Self {
        Self { app, hmac_key: [0; 32], enc_key: [0; 32], pin_token: None }
    }

    fn call(&mut self, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        let mut out: HV<u8, MAX_MSG> = HV::new();
        let n = self.app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
        let resp = out.as_slice()[..n].to_vec();
        let status = resp[0];
        (status, resp[1..].to_vec())
    }

    /// clientPin getKeyAgreement → derive v1 shared keys.
    fn derive_keys(&mut self) {
        let mut req: HV<u8, 64> = HV::new();
        fapico2_fido::cbor::no_heap::push_map_header(&mut req, 2).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap(); // pinUvAuthProtocol
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 2).unwrap(); // subcommand
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 2).unwrap(); // getKeyAgreement
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "getKeyAgreement failed");
        // {1: {1: 2, 3: -25, -1: 1, -2: x, -3: y}}
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

    /// The client's ephemeral key agreement public key (COSE map, fixed).
    fn push_client_key_agreement(&self, out: &mut HV<u8, 256>) {
        let client_sk = p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap();
        let bytes = crypto::public_key_bytes(&client_sk.public_key());
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        fapico2_fido::cbor::no_heap::push_map_header(out, 5).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(out, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(out, 2).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(out, 3).unwrap();
        fapico2_fido::cbor::no_heap::push_neg(out, -25).unwrap();
        fapico2_fido::cbor::no_heap::push_neg(out, -1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(out, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_neg(out, -2).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(out, &x).unwrap();
        fapico2_fido::cbor::no_heap::push_neg(out, -3).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(out, &y).unwrap();
    }

    /// Encrypt a payload with the v1 enc key (zero IV, block-aligned).
    fn v1_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut padded = plaintext.to_vec();
        while !padded.len().is_multiple_of(16) {
            padded.push(0);
        }
        let mut buf: [u8; 96] = [0; 96];
        buf[..padded.len()].copy_from_slice(&padded);
        let zero_iv = [0u8; 16];
        crypto::aes256_cbc_encrypt_into(&self.enc_key, &zero_iv, &mut buf[..padded.len()]).unwrap();
        buf[..padded.len()].to_vec()
    }

    fn v1_decrypt(&self, ct: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 96];
        buf[..ct.len()].copy_from_slice(ct);
        let zero_iv = [0u8; 16];
        crypto::aes256_cbc_decrypt_into(&self.enc_key, &zero_iv, &mut buf[..ct.len()]).unwrap();
        buf[..ct.len()].to_vec()
    }

    /// setPIN/changePIN pinUvAuthParam: keyed with the ECDH shared-secret
    /// HMAC key (protocol v1).
    fn pin_auth_shared(&self, msg: &[u8]) -> Vec<u8> {
        crypto::hmac_sha256(&self.hmac_key, msg)[..16].to_vec()
    }

    /// MC/GA pinUvAuthParam: HMAC-SHA256(pinToken, msg) truncated to 16
    /// bytes (protocol v1) — the key is the minted pin token.
    fn pin_auth(&self, msg: &[u8]) -> Vec<u8> {
        let token = self.pin_token.expect("pin token minted");
        crypto::hmac_sha256(&token, msg)[..16].to_vec()
    }

    /// clientPin setPIN with the v1 protocol.
    fn set_pin(&mut self, pin: &[u8]) {
        self.derive_keys();
        let pin_enc = self.v1_encrypt(pin);
        let mut req: HV<u8, 256> = HV::new();
        fapico2_fido::cbor::no_heap::push_map_header(&mut req, 5).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap(); // protocol v1
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 2).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 3).unwrap(); // setPIN
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 3).unwrap(); // keyAgreement
        self.push_client_key_agreement(&mut req);
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 5).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(&mut req, &pin_enc).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 4).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(&mut req, &self.pin_auth_shared(&pin_enc)).unwrap();
        let (status, _) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "setPIN failed");
    }

    /// clientPin getPinToken → raw token.
    fn get_pin_token(&mut self, pin: &[u8]) {
        let pin_hash = crypto::pin_hash(pin);
        let pin_hash_enc = self.v1_encrypt(&pin_hash);
        let mut req: HV<u8, 256> = HV::new();
        fapico2_fido::cbor::no_heap::push_map_header(&mut req, 4).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 2).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 5).unwrap(); // getPinToken
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 3).unwrap(); // keyAgreement
        self.push_client_key_agreement(&mut req);
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 6).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(&mut req, &pin_hash_enc).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "getPinToken failed");
        let mut p = Parser::new(&cbor);
        assert!(matches!(p.next(), Ok(Item::Map(1))));
        assert_eq!(p.next().unwrap(), Item::U(2));
        let Item::B(ct) = p.next().unwrap() else { panic!() };
        let pt = self.v1_decrypt(ct);
        let mut token = [0u8; 32];
        token.copy_from_slice(&pt[..32]);
        self.pin_token = Some(token);
    }
}

/// Build a makeCredential request CBOR map.
fn build_mc_req(rp_id: &str, user_id: &[u8], challenge: &[u8; 32], rk: bool, pin_auth: Option<&[u8]>) -> Vec<u8> {
    let mut r: HV<u8, 512> = HV::new();
    let mut pairs = 4usize;
    if pin_auth.is_some() {
        pairs += 2;
    }
    if rk {
        pairs += 1;
    }
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, pairs).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_bstr(&mut r, challenge).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 2).unwrap();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "id").unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, rp_id).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 3).unwrap();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "id").unwrap();
    fapico2_fido::cbor::no_heap::push_bstr(&mut r, user_id).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 4).unwrap();
    fapico2_fido::cbor::no_heap::push_array_header(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 2).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "type").unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "public-key").unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "alg").unwrap();
    fapico2_fido::cbor::no_heap::push_neg(&mut r, -7).unwrap();
    if rk {
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 7).unwrap();
        fapico2_fido::cbor::no_heap::push_map_header(&mut r, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_tstr(&mut r, "rk").unwrap();
        fapico2_fido::cbor::no_heap::push_bool(&mut r, true).unwrap();
    }
    if let Some(auth) = pin_auth {
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 8).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(&mut r, auth).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 9).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 1).unwrap();
    }
    r.as_slice().to_vec()
}

fn build_ga_req(rp_id: &str, challenge: &[u8; 32], pin_auth: Option<&[u8]>) -> Vec<u8> {
    let mut r: HV<u8, 256> = HV::new();
    let mut pairs = 2usize;
    if pin_auth.is_some() {
        pairs += 2;
    }
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, pairs).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, rp_id).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 2).unwrap();
    fapico2_fido::cbor::no_heap::push_bstr(&mut r, challenge).unwrap();
    if let Some(auth) = pin_auth {
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 6).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(&mut r, auth).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 7).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 1).unwrap();
    }
    r.as_slice().to_vec()
}

/// Parse a getAssertion response into (authData, signature DER).
fn parse_assertion(cbor: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut p = Parser::new(cbor);
    assert!(matches!(p.next(), Ok(Item::Map(_))));
    let mut auth_data = None;
    let mut sig = None;
    while p.remaining() > 0 {
        let Item::U(k) = p.next().unwrap() else { panic!() };
        match k {
            2 => auth_data = Some(p.next().unwrap()),
            3 => sig = Some(p.next().unwrap()),
            _ => p.skip().unwrap(),
        }
    }
    (
        match auth_data { Some(Item::B(b)) => b.to_vec(), _ => panic!("no authData") },
        match sig { Some(Item::B(b)) => b.to_vec(), _ => panic!("no sig") },
    )
}

/// Extract the credential COSE key (x||y) from MC authData attested data.
fn parse_mc_response(cbor: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
    let mut p = Parser::new(cbor);
    assert!(matches!(p.next(), Ok(Item::Map(3))));
    let mut auth_data = None;
    while p.remaining() > 0 {
        let Item::U(k) = p.next().unwrap() else { panic!() };
        match k {
            2 => auth_data = Some(p.next().unwrap()),
            _ => p.skip().unwrap(),
        }
    }
    let Item::B(ad) = auth_data.unwrap() else { panic!() };
    // attestedCredentialData at offset 37: aaguid(16) len(2) id cose
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cose_start = 37 + 16 + 2 + id_len;
    let cose = &ad[cose_start..];
    // COSE map: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let mut p = Parser::new(cose);
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
    (ad.to_vec(), ad[37 + 18..37 + 18 + id_len].to_vec(), x, y)
}

#[test]
fn make_credential_get_assertion_device_path() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let app = FidoApp::boot(&mut trng, &mut store).unwrap();
    let mut client = DeviceClient::new(app);

    // --- getInfo advertises the CTAPHID_MAX_MSG claim and PIN capability ---
    let (status, cbor) = client.call(0x04, &[]);
    assert_eq!(status, 0x00);
    let mut p = Parser::new(&cbor);
    assert!(matches!(p.next(), Ok(Item::Map(_))));
    let mut max_msg = 0u64;
    let mut client_pin = None;
    while p.remaining() > 0 {
        let item = p.next();
        if !matches!(item, Ok(Item::U(_))) {
            panic!("getInfo key not uint at pos {}: {item:?} cbor={cbor:02x?}", p.pos());
        }
        let Item::U(k) = item.unwrap() else { unreachable!() };
        match k {
            5 => max_msg = match p.next().unwrap() { Item::U(u) => u, _ => panic!() },
            4 => {
                // options map: look for clientPin
                let Item::Map(n) = p.next().unwrap() else { panic!() };
                for _ in 0..n {
                    let key = p.next().unwrap();
                    let val = p.next().unwrap();
                    if key == Item::T("clientPin") {
                        client_pin = Some(matches!(val, Item::Bool(true)));
                    }
                }
            }
            _ => p.skip().unwrap(),
        }
    }
    assert_eq!(max_msg, 7609, "maxMsgSize claim honored");
    assert_eq!(client_pin, Some(false), "PIN not yet set");

    // --- PIN: set + token (clientPin protocol v1) ---
    client.set_pin(b"1234");
    client.get_pin_token(b"1234");
    assert!(client.pin_token.is_some());

    // --- makeCredential (rk=false, with pinUvAuth) ---
    let challenge = [0xCCu8; 32];
    let pin_auth = client.pin_auth(&challenge);
    let (status, cbor) = client.call(0x01, &build_mc_req("example.com", b"user-1", &challenge, true, Some(&pin_auth)));
    assert_eq!(status, 0x00, "makeCredential failed");
    let (_auth_data, cred_id, x, y) = parse_mc_response(&cbor);
    assert_eq!(cred_id.len(), 32);

    // Without a pinUvAuthParam, a further MC with PIN set → PUAT_REQUIRED.
    let (status, _) = client.call(0x01, &build_mc_req("example.com", b"user-1", &challenge, false, None));
    assert_eq!(status, 0x36, "PUAT_REQUIRED expected with PIN set");

    // --- getAssertion + ES256 signature verification against the COSE key ---
    let challenge2 = [0xDDu8; 32];
    let pin_auth2 = client.pin_auth(&challenge2);
    let (status, cbor) = client.call(0x02, &build_ga_req("example.com", &challenge2, Some(&pin_auth2)));
    assert_eq!(status, 0x00, "getAssertion failed");
    let (auth_data, sig_der) = parse_assertion(&cbor);
    // flags: UP | UV
    assert_eq!(auth_data[32] & 0x05, 0x05, "UP and UV flags set");
    // Verify the ES256 signature over authData || clientDataHash.
    let vk = {
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&x);
        point[33..65].copy_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&point).unwrap()
    };
    let sig = Signature::from_der(&sig_der).expect("DER signature");
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&challenge2);
    vk.verify(&signed, &sig).expect("assertion signature verifies against the COSE key");

    // --- reboot: the credential survives and getAssertion still works ---
    // (the firmware persists via the HID dispatch hook; the test calls the
    // same dirty-gated persist entry point explicitly)
    client.app.persist_if_dirty(&mut store);
    let image = store.partition_image();
    drop(client);
    drop(store);
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);
    let app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    let mut client2 = DeviceClient::new(app2);
    // Session state (token) is volatile — re-mint after reboot.
    client2.set_pin_probe();
    client2.get_pin_token(b"1234");
    let pin_auth3 = client2.pin_auth(&challenge2);
    let (status, cbor) = client2.call(0x02, &build_ga_req("example.com", &challenge2, Some(&pin_auth3)));
    assert_eq!(status, 0x00, "getAssertion after reboot failed");
    let (auth_data2, sig_der2) = parse_assertion(&cbor);
    // The sign counter advanced across the reboot.
    let count1 = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let count2 = u32::from_be_bytes([auth_data2[33], auth_data2[34], auth_data2[35], auth_data2[36]]);
    assert!(count2 > count1, "sign counter persisted and advanced");
    let sig2 = Signature::from_der(&sig_der2).unwrap();
    let mut signed2 = auth_data2.clone();
    signed2.extend_from_slice(&challenge2);
    vk.verify(&signed2, &sig2).expect("post-reboot assertion verifies");
}

impl DeviceClient {
    /// After a reboot the PIN-v1 session keys differ (fresh key agreement);
    /// re-derive against the (persistent) device hkey.
    fn set_pin_probe(&mut self) {
        self.derive_keys();
    }
}
