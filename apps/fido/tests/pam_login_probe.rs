//! Reproduction of the pam_u2f login flow on the device command path.
//!
//! pamu2fcfg -N registers a **non-resident** credential through a PIN-secured
//! makeCredential (libfido2 `fido_dev_make_cred(dev, cred, pin)`); pam_u2f's
//! key-presence probe is then a **token-less** getAssertion over an allowList
//! with `up:false`. This test drives exactly that sequence through
//! `FidoApp::process_ctap2` — the handler the RP2350 serve loop runs — and
//! pins what each step must answer.

use fapico2_fido::cbor::no_heap::{Item, Parser};
use fapico2_fido::crypto;
use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

struct DeviceClient {
    app: FidoApp,
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
        (resp[0], resp[1..].to_vec())
    }

    fn derive_keys(&mut self) {
        let mut req: HV<u8, 64> = HV::new();
        fapico2_fido::cbor::no_heap::push_map_header(&mut req, 2).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 2).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 2).unwrap();
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

    fn v1_decrypt(&self, ct: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; 96];
        buf[..ct.len()].copy_from_slice(ct);
        let zero_iv = [0u8; 16];
        crypto::aes256_cbc_decrypt_into(&self.enc_key, &zero_iv, &mut buf[..ct.len()]).unwrap();
        buf[..ct.len()].to_vec()
    }

    fn pin_auth_shared(&self, msg: &[u8]) -> Vec<u8> {
        crypto::hmac_sha256(&self.hmac_key, msg)[..16].to_vec()
    }

    fn pin_auth(&self, msg: &[u8]) -> Vec<u8> {
        let token = self.pin_token.expect("pin token minted");
        crypto::hmac_sha256(&token, msg)[..16].to_vec()
    }

    fn set_pin(&mut self, pin: &[u8]) {
        self.derive_keys();
        let pin_enc = self.v1_encrypt(pin);
        let mut req: HV<u8, 256> = HV::new();
        fapico2_fido::cbor::no_heap::push_map_header(&mut req, 5).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 2).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 3).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 3).unwrap();
        self.push_client_key_agreement(&mut req);
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 5).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(&mut req, &pin_enc).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 4).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(&mut req, &self.pin_auth_shared(&pin_enc)).unwrap();
        let (status, _) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "setPIN failed");
    }

    fn get_pin_token(&mut self, pin: &[u8]) {
        let pin_hash = crypto::pin_hash(pin);
        let pin_hash_enc = self.v1_encrypt(&pin_hash);
        let mut req: HV<u8, 256> = HV::new();
        fapico2_fido::cbor::no_heap::push_map_header(&mut req, 4).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 1).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 2).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 5).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut req, 3).unwrap();
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

    fn get_info_options(&mut self) -> Vec<(String, bool)> {
        let (status, cbor) = self.call(0x04, &[]);
        assert_eq!(status, 0x00);
        let mut p = Parser::new(&cbor);
        assert!(matches!(p.next(), Ok(Item::Map(_))));
        let mut opts = Vec::new();
        while p.remaining() > 0 {
            let Item::U(k) = p.next().unwrap() else { panic!() };
            if k == 4 {
                let Item::Map(n) = p.next().unwrap() else { panic!() };
                for _ in 0..n {
                    let key = match p.next().unwrap() {
                        Item::T(s) => s.to_string(),
                        _ => panic!(),
                    };
                    let val = matches!(p.next().unwrap(), Item::Bool(true));
                    opts.push((key, val));
                }
            } else {
                p.skip().unwrap();
            }
        }
        opts
    }
}

/// pamu2fcfg -N's registration: non-resident ES256, pinUvAuthParam present,
/// no extensions.
fn build_mc_req(rp_id: &str, user_id: &[u8], challenge: &[u8; 32], pin_auth: &[u8]) -> Vec<u8> {
    let mut r: HV<u8, 512> = HV::new();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 6).unwrap();
    // 1: clientDataHash
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_bstr(&mut r, challenge).unwrap();
    // 2: rp
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 2).unwrap();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "id").unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, rp_id).unwrap();
    // 3: user
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 3).unwrap();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "id").unwrap();
    fapico2_fido::cbor::no_heap::push_bstr(&mut r, user_id).unwrap();
    // 4: pubKeyCredParams
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 4).unwrap();
    fapico2_fido::cbor::no_heap::push_array_header(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 2).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "type").unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "public-key").unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "alg").unwrap();
    fapico2_fido::cbor::no_heap::push_neg(&mut r, -7).unwrap();
    // 8: pinUvAuthParam
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 8).unwrap();
    fapico2_fido::cbor::no_heap::push_bstr(&mut r, pin_auth).unwrap();
    // 9: pinUvAuthProtocol
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 9).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 1).unwrap();
    r.as_slice().to_vec()
}

/// pam_u2f's silent probe: 1 rpId, 2 clientDataHash, 3 allowList, 5 options.
fn build_ga_req(rp_id: &str, challenge: &[u8; 32], allow_id: &[u8], up: bool, pin_auth: Option<&[u8]>) -> Vec<u8> {
    let mut r: HV<u8, 512> = HV::new();
    let mut pairs = 4usize;
    if pin_auth.is_some() {
        pairs += 2;
    }
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, pairs).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, rp_id).unwrap();
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 2).unwrap();
    fapico2_fido::cbor::no_heap::push_bstr(&mut r, challenge).unwrap();
    // 3: allowList
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 3).unwrap();
    fapico2_fido::cbor::no_heap::push_array_header(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 2).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "id").unwrap();
    fapico2_fido::cbor::no_heap::push_bstr(&mut r, allow_id).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "type").unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "public-key").unwrap();
    // 5: options
    fapico2_fido::cbor::no_heap::push_uint(&mut r, 5).unwrap();
    fapico2_fido::cbor::no_heap::push_map_header(&mut r, 1).unwrap();
    fapico2_fido::cbor::no_heap::push_tstr(&mut r, "up").unwrap();
    fapico2_fido::cbor::no_heap::push_bool(&mut r, up).unwrap();
    if let Some(auth) = pin_auth {
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 6).unwrap();
        fapico2_fido::cbor::no_heap::push_bstr(&mut r, auth).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 7).unwrap();
        fapico2_fido::cbor::no_heap::push_uint(&mut r, 1).unwrap();
    }
    r.as_slice().to_vec()
}

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

fn parse_mc_cred_id(cbor: &[u8]) -> (Vec<u8>, [u8; 32], [u8; 32]) {
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
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad[37 + 18..37 + 18 + id_len].to_vec();
    let cose = &ad[37 + 16 + 2 + id_len..];
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
    (cred_id, x, y)
}

#[test]
fn pam_login_probe_on_device_path() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let app = FidoApp::boot(&mut trng, &mut store).unwrap();
    let mut client = DeviceClient::new(app);

    // --- PIN set, exactly as on the user's board ---
    client.set_pin(b"1234");
    client.get_pin_token(b"1234");

    // --- the advertisement the PIN state forces ---
    let opts = client.get_info_options();
    let always_uv = opts.iter().find(|(k, _)| k == "alwaysUv").map(|(_, v)| *v);
    let client_pin = opts.iter().find(|(k, _)| k == "clientPin").map(|(_, v)| *v);
    assert_eq!(client_pin, Some(true));
    assert_eq!(always_uv, Some(true), "a PIN-set board advertises alwaysUv");

    // --- pamu2fcfg -N registration: non-resident, PIN-secured ---
    let challenge = [0xCCu8; 32];
    let pin_auth = client.pin_auth(&challenge);
    let (status, cbor) =
        client.call(0x01, &build_mc_req("pam://ShadowL", b"eddieoz", &challenge, &pin_auth));
    assert_eq!(status, 0x00, "makeCredential failed");
    let (cred_id, x, y) = parse_mc_cred_id(&cbor);

    // --- pam_u2f's silent key-presence probe: token-less, up:false ---
    let challenge2 = [0xDDu8; 32];
    let (status, _) = client.call(
        0x02,
        &build_ga_req("pam://ShadowL", &challenge2, &cred_id, false, None),
    );
    // The board advertises alwaysUv (§6.2.2), so a token-less getAssertion
    // must be answered PUAT_REQUIRED — the reference derives the same way,
    // and a `false` here would be the claim that no token is needed. The
    // consequence for PAM is *client-side*: pam_u2f 1.3.0's discovery probe
    // (`get_authenticators`, util.c:822) accepts only FIDO_OK as "key
    // present", so this answer is logged "Key not found in authenticator 0"
    // and the module falls back to the password *before* its PIN prompt,
    // which lives after the probe. Workarounds are configuration, not
    // firmware: `nodetect` or a resident (`-r`) credential both skip the
    // probe and reach the PIN prompt.
    assert_eq!(status, 0x36, "token-less GA must demand a PIN token");

    // --- the real authentication: GA with the PIN token ---
    let pin_auth2 = client.pin_auth(&challenge2);
    let (status, cbor) = client.call(
        0x02,
        &build_ga_req("pam://ShadowL", &challenge2, &cred_id, false, Some(&pin_auth2)),
    );
    assert_eq!(status, 0x00, "token-backed GA must find the allowList credential");
    let (auth_data, sig_der) = parse_assertion(&cbor);
    assert_eq!(auth_data[32] & 0x04, 0x04, "UV flag set");
    assert_eq!(auth_data[32] & 0x01, 0x00, "up:false served silently");
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
    vk.verify(&signed, &sig).expect("assertion signature verifies");
}
