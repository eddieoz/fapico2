//! Strict CTAP2 canonical-CBOR ordering regression for the **device**
//! serializer (`no_heap` writer).
//!
//! The `no_heap` writer never sorts — wire order is insertion order — while
//! the host/emulation path sorts every map at encode time. That asymmetry
//! shipped a getAssertion credential descriptor as `{"type","id"}` on the
//! hardware path (non-canonical: 0x64 "type" must sort after 0x62 "id"),
//! which Chromium rejects with `kCtap2ErrInvalidCBOR` /
//! `DecoderError::OUT_OF_ORDER_KEY` (S-701-4 follow-up, Token2 sign-in
//! failure). The emulation suite cannot catch this class of bug because its
//! writer canonicalizes.
//!
//! These tests drive `FidoApp::process_ctap2` — the exact handler code the
//! RP2350 serve loop runs — and walk every raw response byte with a strict
//! canonical decoder: every map key must sort strictly ascending by its
//! CTAP2 canonical encoding (major type, then shortest length, then
//! byte-wise; equivalent to lexicographic order over the minimal encodings
//! the no-heap writer emits).

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use fapico2_fido::crypto;
use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

// ---------------------------------------------------------------------------
// Strict canonical-order checker over the zero-copy parser.
// ---------------------------------------------------------------------------

/// Canonical encoding of a map key (major-type head + content). The no-heap
/// writer only emits minimal-length heads, so lexicographic byte comparison
/// of these encodings is exactly the CTAP2 canonical ordering rule.
fn key_bytes(item: Item<'_>) -> Vec<u8> {
    let mut buf: HV<u8, 72> = HV::new();
    match item {
        Item::U(v) => nh::push_uint(&mut buf, v),
        Item::N(n) => nh::push_neg(&mut buf, n),
        Item::B(b) => nh::push_bstr(&mut buf, b),
        Item::T(s) => nh::push_tstr(&mut buf, s),
        other => panic!("map key must be an integer or string: {other:?}"),
    }
    .unwrap();
    buf.as_slice().to_vec()
}

/// Recursively walk `p`, requiring every map's keys to sort strictly
/// ascending by canonical encoding.
fn check_canonical(p: &mut Parser<'_>, path: &str) -> Result<(), String> {
    let item = p.next().map_err(|e| format!("{path}: decode error {e:?}"))?;
    match item {
        Item::Map(n) => {
            let mut prev: Option<Vec<u8>> = None;
            for i in 0..n {
                let k = p.next().map_err(|e| format!("{path}: key {i} decode error {e:?}"))?;
                let kb = key_bytes(k);
                if let Some(pv) = &prev {
                    if kb.as_slice() <= pv.as_slice() {
                        return Err(format!(
                            "{path}: map pair #{i} key {k:?} out of canonical order \
                             (encoded {kb:02x?} must sort strictly after {pv:02x?})"
                        ));
                    }
                }
                prev = Some(kb);
                check_canonical(p, &format!("{path}.{k:?}"))?;
            }
            Ok(())
        }
        Item::Array(n) => {
            for _ in 0..n {
                check_canonical(p, path)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Assert `cbor` is a single well-formed, canonically ordered CBOR item.
fn assert_canonical(cbor: &[u8], what: &str) {
    let mut p = Parser::new(cbor);
    if let Err(e) = check_canonical(&mut p, what) {
        panic!("{e}\nraw bytes: {:02x?}", cbor);
    }
    assert_eq!(p.remaining(), 0, "{what}: trailing bytes after CBOR item: {:02x?}", &cbor[cbor.len() - p.remaining()..]);
}

// ---------------------------------------------------------------------------
// Device client: PIN v1 ceremony + MC/GA/credMgmt over process_ctap2.
// ---------------------------------------------------------------------------

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

struct DeviceClient {
    app: FidoApp,
    hmac_key: [u8; 32],
    enc_key: [u8; 32],
    pin_token: Option<[u8; 32]>,
}

impl DeviceClient {
    fn boot() -> Self {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        let app = FidoApp::boot(&mut trng, &mut store).unwrap();
        Self { app, hmac_key: [0; 32], enc_key: [0; 32], pin_token: None }
    }

    fn call(&mut self, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        let mut out: HV<u8, MAX_MSG> = HV::new();
        let n = self.app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
        let resp = out.as_slice()[..n].to_vec();
        let status = resp[0];
        (status, resp[1..].to_vec())
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

    /// setPIN + getPinUvAuthTokenUsingPinWithPermissions (mc|ga|cm|lbf|acfg).
    fn setup_pin(&mut self, pin: &[u8]) {
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

        let pin_hash = crypto::pin_hash(pin);
        let pin_hash_enc = self.v1_encrypt(&pin_hash);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        self.push_client_key_agreement(&mut req);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &pin_hash_enc).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 0x37).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "getPinUvAuthToken failed");
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        let _ = p.next().unwrap();
        let Item::B(ct) = p.next().unwrap() else { panic!() };
        let mut buf = [0u8; 96];
        buf[..ct.len()].copy_from_slice(ct);
        let zero_iv = [0u8; 16];
        crypto::aes256_cbc_decrypt_into(&self.enc_key, &zero_iv, &mut buf[..ct.len()]).unwrap();
        let mut token = [0u8; 32];
        token.copy_from_slice(&buf[..32]);
        self.pin_token = Some(token);
    }

    /// MC/GA pinUvAuthParam: HMAC-SHA256(pinToken, msg) truncated to 16 bytes.
    fn pin_auth(&self, msg: &[u8]) -> Vec<u8> {
        let token = self.pin_token.expect("pin token minted");
        crypto::hmac_sha256(&token, msg)[..16].to_vec()
    }

    /// makeCredential (rk=true, user name+displayName) with the extension
    /// set that exercises the authData extensions map ordering:
    /// hmac-secret-mc + largeBlobKey + minPinLength. Returns the response CBOR.
    fn make_cred_extended(&mut self, rp: &str, user: &[u8], challenge: &[u8; 32]) -> Vec<u8> {
        // hmac-secret-mc input: {1: keyAgreement, 2: salt_enc, 3: salt_auth, 4: protocol}
        let salt = [0x5Au8; 32];
        let salt_enc = self.v1_encrypt(&salt);
        let salt_auth = crypto::hmac_sha256(&self.hmac_key, &salt_enc)[..16].to_vec();
        let mut hs: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut hs, 4).unwrap();
        nh::push_uint(&mut hs, 1).unwrap();
        self.push_client_key_agreement(&mut hs);
        nh::push_uint(&mut hs, 2).unwrap();
        nh::push_bstr(&mut hs, &salt_enc).unwrap();
        nh::push_uint(&mut hs, 3).unwrap();
        nh::push_bstr(&mut hs, &salt_auth).unwrap();
        nh::push_uint(&mut hs, 4).unwrap();
        nh::push_uint(&mut hs, 1).unwrap();

        let mut r: HV<u8, 768> = HV::new();
        nh::push_map_header(&mut r, 8).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_bstr(&mut r, challenge).unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_tstr(&mut r, rp).unwrap();
        nh::push_uint(&mut r, 3).unwrap();
        // user entity: canonical request order id < name < displayName
        nh::push_map_header(&mut r, 3).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_bstr(&mut r, user).unwrap();
        nh::push_tstr(&mut r, "name").unwrap();
        nh::push_tstr(&mut r, "User Name").unwrap();
        nh::push_tstr(&mut r, "displayName").unwrap();
        nh::push_tstr(&mut r, "Display Name").unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_array_header(&mut r, 1).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "type").unwrap();
        nh::push_tstr(&mut r, "public-key").unwrap();
        nh::push_tstr(&mut r, "alg").unwrap();
        nh::push_neg(&mut r, -7).unwrap();
        // extensions: largeBlobKey(0x6C 'l') < minPinLength(0x6C 'm') < hmac-secret-mc(0x6E)
        nh::push_uint(&mut r, 6).unwrap();
        nh::push_map_header(&mut r, 3).unwrap();
        nh::push_tstr(&mut r, "largeBlobKey").unwrap();
        nh::push_bool(&mut r, true).unwrap();
        nh::push_tstr(&mut r, "minPinLength").unwrap();
        nh::push_bool(&mut r, true).unwrap();
        nh::push_tstr(&mut r, "hmac-secret-mc").unwrap();
        r.extend_from_slice(hs.as_slice()).unwrap();
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "rk").unwrap();
        nh::push_bool(&mut r, true).unwrap();
        nh::push_uint(&mut r, 8).unwrap();
        nh::push_bstr(&mut r, &self.pin_auth(challenge)).unwrap();
        nh::push_uint(&mut r, 9).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        let (status, cbor) = self.call(0x01, r.as_slice());
        assert_eq!(status, 0x00, "makeCredential failed");
        cbor
    }

    /// getAssertion with pinUvAuth. Returns the response CBOR.
    fn get_assertion(&mut self, rp: &str, challenge: &[u8; 32]) -> Vec<u8> {
        let mut r: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut r, 4).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, rp).unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_bstr(&mut r, challenge).unwrap();
        nh::push_uint(&mut r, 6).unwrap();
        nh::push_bstr(&mut r, &self.pin_auth(challenge)).unwrap();
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        let (status, cbor) = self.call(0x02, r.as_slice());
        assert_eq!(status, 0x00, "getAssertion failed");
        cbor
    }

    /// credMgmt call: subcommand + optional params (raw CBOR map).
    fn cred_mgmt(&mut self, sub: u8, params: Option<Vec<u8>>) -> (u8, Vec<u8>) {
        let mut r: HV<u8, 256> = HV::new();
        let pairs = 1 + if params.is_some() { 1 } else { 0 } + 2;
        nh::push_map_header(&mut r, pairs).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_uint(&mut r, sub as u64).unwrap();
        if let Some(p) = &params {
            nh::push_uint(&mut r, 2).unwrap();
            r.extend_from_slice(p.as_slice()).ok();
        }
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        let mut auth_msg: Vec<u8> = vec![sub];
        if let Some(p) = &params {
            auth_msg.extend_from_slice(p.as_slice());
        }
        nh::push_bstr(&mut r, &self.pin_auth(&auth_msg)).unwrap();
        self.call(0x0A, r.as_slice())
    }
}

// ---------------------------------------------------------------------------
// Regression tests.
// ---------------------------------------------------------------------------

/// The browser sign-in path: makeCredential + getAssertion responses must be
/// canonically ordered byte-for-byte. Catches the getAssertion credential
/// descriptor `{"type","id"}` violation (Chromium OUT_OF_ORDER_KEY) and the
/// makeCredential extensions-map `hmac-secret-mc` misplacement.
#[test]
fn mc_ga_device_responses_are_canonically_ordered() {
    let mut client = DeviceClient::boot();
    client.setup_pin(b"1234");

    let challenge = [0xCCu8; 32];
    let mc = client.make_cred_extended("example.com", b"user-1", &challenge);
    assert_canonical(&mc, "makeCredential response");

    let challenge2 = [0xDDu8; 32];
    let ga = client.get_assertion("example.com", &challenge2);
    assert_canonical(&ga, "getAssertion response");
}

/// Credential-management responses must be canonically ordered: the
/// enumerateCreds user entity used to emit `displayName` before `id`.
#[test]
fn cred_mgmt_device_responses_are_canonically_ordered() {
    let mut client = DeviceClient::boot();
    client.setup_pin(b"1234");

    let challenge = [0xEEu8; 32];
    let mc = client.make_cred_extended("cmtest.example", b"user-1", &challenge);
    assert_canonical(&mc, "makeCredential response");

    // enumerateCredsBegin (0x04) for the credential's RP.
    let rp_id_hash = crypto::sha256(b"cmtest.example");
    let mut params: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut params, 1).unwrap();
    nh::push_uint(&mut params, 1).unwrap();
    nh::push_bstr(&mut params, &rp_id_hash).unwrap();
    let (status, cbor) = client.cred_mgmt(0x04, Some(params.as_slice().to_vec()));
    assert_eq!(status, 0x00, "enumerateCredsBegin failed");
    assert_canonical(&cbor, "enumerateCredsBegin response");
}
