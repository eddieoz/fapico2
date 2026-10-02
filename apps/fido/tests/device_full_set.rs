//! S-701-5 TDD: the full CTAP2 command set on the device path — credMgmt
//! enumerate/delete, largeBlobs set+get round-trip and U2F register/
//! authenticate, driven through `FidoApp::process_ctap2` / `process_u2f` /
//! `process_vendor_vault` on host (the exact code the RP2350 runs).

use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
use fapico2_fido::crypto;
use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

const MAX_MSG: usize = fapico2_fido::CTAP2_MAX_MSG;

/// Minimal CTAP2 client over the device path (PIN protocol v1).
struct Client {
    app: FidoApp,
    hmac_key: [u8; 32],
    enc_key: [u8; 32],
    pin_token: Option<[u8; 32]>,
}

impl Client {
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
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00);
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        let _ = p.next().unwrap();
        let Item::Map(n) = p.next().unwrap() else { panic!() };
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
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
        let device_pub = crypto::parse_cose_ec2_p256_bytes(&x, &y).unwrap();
        let raw = crypto::ecdh_shared_secret(&client_sk, &device_pub);
        let k = crypto::derive_shared_secret_v1(&raw);
        self.hmac_key = k;
        self.enc_key = k;
    }

    fn v1_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut padded = plaintext.to_vec();
        while !padded.len().is_multiple_of(16) {
            padded.push(0);
        }
        let zero_iv = [0u8; 16];
        let mut buf = [0u8; 96];
        buf[..padded.len()].copy_from_slice(&padded);
        crypto::aes256_cbc_encrypt_into(&self.enc_key, &zero_iv, &mut buf[..padded.len()]).unwrap();
        buf[..padded.len()].to_vec()
    }

    fn v1_decrypt(&self, ct: &[u8]) -> Vec<u8> {
        let zero_iv = [0u8; 16];
        let mut buf = [0u8; 96];
        buf[..ct.len()].copy_from_slice(ct);
        crypto::aes256_cbc_decrypt_into(&self.enc_key, &zero_iv, &mut buf[..ct.len()]).unwrap();
        buf[..ct.len()].to_vec()
    }

    fn pin_auth_shared(&self, msg: &[u8]) -> Vec<u8> {
        crypto::hmac_sha256(&self.hmac_key, msg)[..16].to_vec()
    }

    fn pin_auth(&self, msg: &[u8]) -> Vec<u8> {
        let token = self.pin_token.expect("token");
        crypto::hmac_sha256(&token, msg)[..16].to_vec()
    }

    fn setup_pin(&mut self, pin: &[u8]) {
        self.derive_keys();
        // setPIN
        let pin_enc = self.v1_encrypt(pin);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        nh::push_uint(&mut req, 3).unwrap(); // keyAgreement
        self.push_ka(&mut req);
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_bstr(&mut req, &pin_enc).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &self.pin_auth_shared(&pin_enc)).unwrap();
        let (status, _) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "setPIN");
        // getPinToken with all permissions the test needs (mc|ga|cm|lbf|acfg).
        let pin_hash = crypto::pin_hash(pin);
        let pin_hash_enc = self.v1_encrypt(&pin_hash);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 9).unwrap(); // getPinUvAuthTokenUsingPinWithPermissions
        nh::push_uint(&mut req, 3).unwrap();
        self.push_ka(&mut req);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &pin_hash_enc).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 0x37).unwrap(); // mc|ga|cm|lbf|acfg (host bit values; BE needs protocol v2)
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, 0x00, "getPinUvAuthToken");
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        let _ = p.next().unwrap();
        let Item::B(ct) = p.next().unwrap() else { panic!() };
        let pt = self.v1_decrypt(ct);
        let mut token = [0u8; 32];
        token.copy_from_slice(&pt[..32]);
        self.pin_token = Some(token);
    }

    fn push_ka(&self, out: &mut HV<u8, 256>) {
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

    /// makeCredential (rk=True) with pinUvAuth; returns the credential id.
    fn make_cred(&mut self, rp: &str, user: &[u8]) -> Vec<u8> {
        let challenge = [0xCCu8; 32];
        let mut r: HV<u8, 512> = HV::new();
        nh::push_map_header(&mut r, 7).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_bstr(&mut r, &challenge).unwrap();
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_tstr(&mut r, rp).unwrap();
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_bstr(&mut r, user).unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_array_header(&mut r, 1).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "type").unwrap();
        nh::push_tstr(&mut r, "public-key").unwrap();
        nh::push_tstr(&mut r, "alg").unwrap();
        nh::push_neg(&mut r, -7).unwrap();
        nh::push_uint(&mut r, 7).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "rk").unwrap();
        nh::push_bool(&mut r, true).unwrap();
        nh::push_uint(&mut r, 8).unwrap();
        nh::push_bstr(&mut r, &self.pin_auth(&challenge)).unwrap();
        nh::push_uint(&mut r, 9).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        let (status, cbor) = self.call(0x01, r.as_slice());
        assert_eq!(status, 0x00, "makeCredential");
        // pull credential id out of the authData attested credential data
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        let mut id = Vec::new();
        while p.remaining() > 0 {
            let Item::U(k) = p.next().unwrap() else { panic!() };
            match k {
                2 => {
                    let Item::B(ad) = p.next().unwrap() else { panic!() };
                    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
                    id = ad[55..55 + id_len].to_vec();
                }
                _ => p.skip().unwrap(),
            }
        }
        id
    }

    /// credMgmt call: subcommand + optional params (raw CBOR map).
    fn cred_mgmt(&mut self, sub: u8, params: Option<Vec<u8>>) -> (u8, Vec<u8>) {
        self.cred_mgmt_dbg(sub, params, false)
    }

    fn cred_mgmt_dbg(&mut self, sub: u8, params: Option<Vec<u8>>, dbg: bool) -> (u8, Vec<u8>) {
        let mut r: HV<u8, 256> = HV::new();
        let pairs = 1 + if params.is_some() { 1 } else { 0 } + 2;
        nh::push_map_header(&mut r, pairs).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_uint(&mut r, sub as u64).unwrap();
        if let Some(p) = &params {
            // subCommandParams is carried as a MAP (not a bstr wrapper).
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
        if dbg {
            eprintln!("cm req sub={sub:#x}: {:02x?}", r.as_slice());
        }
        let res = self.call(0x0A, r.as_slice());
        if dbg {
            eprintln!("cm resp: {:02x?}", res.1);
        }
        res
    }

    /// US-121: a credMgmt call signed exactly as PicoForge signs it.
    ///
    /// Mirrors `sign_credential_mgmt_command`
    /// (`picoforge/src/hal/fido/ops.rs:1671-1694`): the pinUvAuth message is
    /// the bare sub-command byte for GetCredsMetadata (0x01) and
    /// EnumerateRpsBegin (0x02) — even when params are present — and
    /// `subCommand ‖ CBOR(subCommandParams)` otherwise, HMAC-SHA-256
    /// truncated to 16 bytes under pinUvAuthProtocol 1.
    fn picoforge_cred_mgmt(&mut self, sub: u8, params: Option<&[u8]>) -> (u8, Vec<u8>) {
        let mut auth_msg: Vec<u8> = vec![sub];
        if let Some(p) = params {
            if !matches!(sub, 0x01 | 0x02) {
                auth_msg.extend_from_slice(p);
            }
        }
        self.cred_mgmt_signed(sub, params, &auth_msg)
    }

    /// A credMgmt request on the device path with an explicitly supplied
    /// pinUvAuth message, so a test can sign the *device's* way (raw params
    /// bytes always included when the client sent any) as well as
    /// PicoForge's way (params excluded for `0x01`/`0x02`).
    fn cred_mgmt_signed(
        &mut self,
        sub: u8,
        params: Option<&[u8]>,
        auth_msg: &[u8],
    ) -> (u8, Vec<u8>) {
        let mac = crypto::hmac_sha256(&self.pin_token.expect("token"), auth_msg);
        let mac = mac[..16].to_vec();

        let mut r: HV<u8, 256> = HV::new();
        let pairs = 1 + usize::from(params.is_some()) + 2;
        nh::push_map_header(&mut r, pairs).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_uint(&mut r, sub as u64).unwrap();
        if let Some(p) = params {
            nh::push_uint(&mut r, 2).unwrap();
            r.extend_from_slice(p).ok();
        }
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_uint(&mut r, 1).unwrap(); // pinUvAuthProtocol 1
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_bstr(&mut r, &mac).unwrap();
        self.call(0x0A, r.as_slice())
    }
}

#[test]
fn cred_mgmt_largeblobs_u2f_device_path() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let app = FidoApp::boot(&mut trng, &mut store).unwrap();
    let mut client = Client::new(app);
    client.setup_pin(b"1234");

    // --- register two resident credentials on different RPs ---
    let _id1 = client.make_cred("rp1.example", b"user-1");
    let _id2 = client.make_cred("rp1.example", b"user-2");
    let _id3 = client.make_cred("rp2.example", b"user-3");

    // --- credMgmt metadata (0x01) ---
    let (status, cbor) = client.cred_mgmt(0x01, None);
    assert_eq!(status, 0x00);
    {
        let mut p = Parser::new(&cbor);
        let Item::Map(3) = p.next().unwrap() else { panic!() };
        let mut existing = 0u64;
        for _ in 0..3 {
            let k = p.next().unwrap();
            let v = p.next().unwrap();
            if k == Item::U(1) {
                existing = match v { Item::U(u) => u, _ => panic!() };
            }
        }
        assert_eq!(existing, 3, "metadata: 3 resident credentials");
    }

    // --- credMgmt enumerateRpsBegin (0x02) → 2 RPs, totalRps = 2 ---
    let (status, _cbor) = client.cred_mgmt(0x02, None);
    assert_eq!(status, 0x00, "enumerateRpsBegin");
    // enumerateRpsGetNext (0x03) until NotAllowed (0x2D is keepalive-cancel;
    // here the sequence ends with the second RP). US-1528 moved the
    // keepalive-cancel byte 0x2C → 0x2D, so this aside was the one place in
    // the tree that quoted it as a live value and had to move with it.
    let (status, _) = client.cred_mgmt(0x03, None);
    assert_eq!(status, 0x00, "enumerateRpsGetNext (2nd RP)");

    // --- enumerateCredsBegin for rp1 (0x04) → 2 creds; delete the first ---
    let rp1_hash = crypto::sha256(b"rp1.example");
    let mut params: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut params, 1).unwrap();
    nh::push_uint(&mut params, 1).unwrap();
    nh::push_bstr(&mut params, &rp1_hash).unwrap();
    let (status, cbor) = client.cred_mgmt_dbg(0x04, Some(params.as_slice().to_vec()), true);
    assert_eq!(status, 0x00, "enumerateCredsBegin");
    let mut cred_id = None;
    {
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        while p.remaining() > 0 {
            let Item::U(k) = p.next().unwrap() else { panic!() };
            match k {
                7 => {
                    let Item::Map(m) = p.next().unwrap() else { panic!() };
                    for _ in 0..m {
                        match p.next().unwrap() {
                            Item::T("id") => {
                                if cred_id.is_none() {
                                    if let Item::B(b) = p.next().unwrap() {
                                        cred_id = Some(b.to_vec());
                                    }
                                } else {
                                    p.skip().unwrap();
                                }
                            }
                            _ => p.skip().unwrap(),
                        }
                    }
                }
                _ => p.skip().unwrap(),
            }
        }
    }
    let cred_id = cred_id.expect("credential id in enumerate response");

    // --- deleteCredential (0x06): params {2: {type, id}} ---
    let mut params: HV<u8, 128> = HV::new();
    nh::push_map_header(&mut params, 1).unwrap();
    nh::push_uint(&mut params, 2).unwrap();
    nh::push_map_header(&mut params, 2).unwrap();
    nh::push_tstr(&mut params, "id").unwrap();
    nh::push_bstr(&mut params, &cred_id).unwrap();
    nh::push_tstr(&mut params, "type").unwrap();
    nh::push_tstr(&mut params, "public-key").unwrap();
    let (status, _) = client.cred_mgmt(0x06, Some(params.as_slice().to_vec()));
    assert_eq!(status, 0x00, "deleteCredential");
    // metadata reflects the deletion
    let (status, cbor) = client.cred_mgmt(0x01, None);
    assert_eq!(status, 0x00);
    {
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        let mut existing = 0u64;
        for _ in 0..3 {
            let k = p.next().unwrap();
            let v = p.next().unwrap();
            if k == Item::U(1) {
                existing = match v { Item::U(u) => u, _ => panic!() };
            }
        }
        assert_eq!(existing, 2, "one credential deleted");
    }

    // --- largeBlobs: set (single fragment) + get round-trip ---
    // payload = one encoded blob + 16-byte truncated SHA-256 checksum
    let mut payload: Vec<u8> = vec![0x82, 0x01, 0x02]; // dummy blob array
    payload.extend_from_slice(b"blob-bytes");
    let digest = crypto::sha256(&payload);
    payload.extend_from_slice(&digest[..16]);
    let mut req: HV<u8, 2048> = HV::new();
    nh::push_map_header(&mut req, 5).unwrap();
    nh::push_uint(&mut req, 2).unwrap();
    nh::push_bstr(&mut req, &payload).unwrap();
    nh::push_uint(&mut req, 3).unwrap();
    nh::push_uint(&mut req, 0).unwrap(); // offset
    nh::push_uint(&mut req, 4).unwrap();
    nh::push_uint(&mut req, payload.len() as u64).unwrap();
    nh::push_uint(&mut req, 6).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    // pinUvAuthParam over 0xff*32 || 0x0c 0x00 || offset || sha256(fragment)
    let mut msg: Vec<u8> = vec![0xffu8; 32];
    msg.extend_from_slice(&[0x0c, 0x00]);
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&crypto::sha256(&payload));
    nh::push_uint(&mut req, 5).unwrap();
    nh::push_bstr(&mut req, &client.pin_auth(&msg)).unwrap();
    let (status, _) = client.call(0x0C, req.as_slice());
    assert_eq!(status, 0x00, "largeBlobs set");

    // read back the first fragment
    let mut req: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut req, 2).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, payload.len() as u64).unwrap();
    nh::push_uint(&mut req, 3).unwrap();
    nh::push_uint(&mut req, 0).unwrap();
    let (status, cbor) = client.call(0x0C, req.as_slice());
    assert_eq!(status, 0x00, "largeBlobs get");
    {
        let mut p = Parser::new(&cbor);
        let _ = p.next().unwrap();
        let _ = p.next().unwrap();
        let Item::B(b) = p.next().unwrap() else { panic!() };
        // The stored array INCLUDES the trailing checksum (host parity).
        assert_eq!(b, payload.as_slice(), "large blob round-trips");
    }

    // --- U2F over CTAPHID MSG: VERSION + REGISTER + AUTHENTICATE ---
    {
        let mut out: HV<u8, MAX_MSG> = HV::new();
        let n = client.app.process_u2f(b"\x00\x03\x00\x00\x00", &mut out);
        assert_eq!(&out.as_slice()[..n], b"U2F_V2\x90\x00");

        // REGISTER: client_param(32) || app_param(32)
        let mut apdu: Vec<u8> = vec![0x00, 0x01, 0x03, 0x00, 64];
        apdu.extend(vec![0xAAu8; 32]);
        apdu.extend(vec![0xBBu8; 32]);
        let n = client.app.process_u2f(&apdu, &mut out);
        let resp = out.as_slice()[..n].to_vec();
        assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "U2F REGISTER status");
        assert_eq!(resp[0], 0x05, "registration reserved byte");
        let kh_len = resp[66] as usize;
        let key_handle = resp[67..67 + kh_len].to_vec();

        // AUTHENTICATE (enforce, P1=0x03)
        let mut apdu: Vec<u8> = vec![0x00, 0x02, 0x03, 0x00, (65 + kh_len) as u8];
        apdu.extend(vec![0xAAu8; 32]);
        apdu.extend(vec![0xBBu8; 32]);
        apdu.push(kh_len as u8);
        apdu.extend_from_slice(&key_handle);
        let n = client.app.process_u2f(&apdu, &mut out);
        let resp = out.as_slice()[..n].to_vec();
        assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "U2F AUTHENTICATE status");
        assert_eq!(resp[0], 0x01, "user presence byte");
        // counter increments on a second enforce-authentication
        let n = client.app.process_u2f(&apdu, &mut out);
        let resp2 = out.as_slice()[..n].to_vec();
        let c1 = u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]);
        let c2 = u32::from_be_bytes([resp2[1], resp2[2], resp2[3], resp2[4]]);
        assert_eq!(c2, c1 + 1, "U2F counter increments");
    }

    // --- vendor vault: STATUS before/after unenroll (auth path) ---
    {
        let mut req: HV<u8, 128> = HV::new();
        nh::push_map_header(&mut req, 3).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 6).unwrap(); // UNENROLL
        nh::push_uint(&mut req, 3).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &client.pin_auth(&{
            let mut m: Vec<u8> = vec![0xffu8; 32];
            m.extend_from_slice(&[0x0d, 0x06]);
            m
        })).unwrap();
        let mut out: HV<u8, MAX_MSG> = HV::new();
        // The vendor function rides CTAPHID vendor 0x41; process directly.
        let _ = client.app.process_vendor_vault(req.as_slice(), &mut out);
        assert_eq!(out.as_slice()[0], 0x00, "vault unenroll accepted with acfg/cm token");
    }

    // --- reboot: credentials + large blob array persist ---
    client.app.persist_if_dirty(&mut store);
    let image = store.partition_image();
    drop(client);
    drop(store);
    let mut restored = HostSecureStore::new();
    restored.from_partition_image(&image);
    let mut app2 = FidoApp::boot(&mut trng, &mut restored).unwrap();
    // US-714: the U2F registration is stateless (no store entry); the two
    // resident CTAP2 credentials are the only stored ones.
    assert_eq!(app2.keystore().cred_count(), 2, "credentials survive reboot (2 resident)");
    assert!(app2.keystore().large_blob_array.is_some(), "large blob array survives reboot");

    // persist_if_dirty is clean after a fresh boot-load
    assert!(!app2.persist_if_dirty(&mut restored));
}

/// US-121 device twin: pins the **device** half of the credMgmt MAC-scope
/// split between the two twins.
///
/// The device signs `subCommand ‖ raw subCommandParams bytes` whenever the
/// client sent params (`device_core.rs:2174-2176`). The host instead
/// re-derives the params from parsed fields and signs the sub-command byte
/// alone for `0x01`/`0x02` (`app.rs:1799-1847`). So for `0x01`/`0x02` with
/// params attached, the *same* request is accepted by one twin and refused
/// by the other, depending only on which side's MAC rule the client signed:
///
/// * signed the **device's** way (params included) → accepted here;
/// * signed **PicoForge's** way (params excluded) → `0x33 PIN_AUTH_INVALID`.
///
/// The host's accepting half is asserted by
/// `credmgmt.rs::host_accepts_picoforge_mac_with_params_omitted_from_scope`.
///
/// Interop is unaffected, because PicoForge sends no params for `0x01`/`0x02`
/// — which is exactly the wire form the pre-existing
/// `cred_mgmt_largeblobs_u2f_device_path` already exercises (protocol 1, a
/// 16-byte MAC, `subCommand ‖ params`, covering `0x01`/`0x02`/`0x04`/`0x06`).
/// This test is deliberately NOT a second copy of that coverage; it covers
/// only the params-present case the sibling test never reaches.
#[test]
fn device_twin_credmgmt_mac_scope_differs_from_host_for_0x01_and_0x02() {
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let app = FidoApp::boot(&mut trng, &mut store).unwrap();
    let mut client = Client::new(app);
    client.setup_pin(b"1234");
    let _ = client.make_cred("example.com", b"user-1");

    let rp_hash = crypto::sha256(b"example.com");
    let mut params: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut params, 1).unwrap();
    nh::push_uint(&mut params, 1).unwrap();
    nh::push_bstr(&mut params, &rp_hash).unwrap();

    for sub in [0x01u8, 0x02u8] {
        // Signed the device's way: subCommand ‖ raw params.
        let device_msg: Vec<u8> = [vec![sub], params.as_slice().to_vec()].concat();
        let (status, _) = client.cred_mgmt_signed(sub, Some(params.as_slice()), &device_msg);
        assert_eq!(
            status, 0x00,
            "device must accept sub-command {sub:#04x} when params are inside the signed scope"
        );

        // Signed PicoForge's way: params excluded.
        let (status, _) = client.picoforge_cred_mgmt(sub, Some(params.as_slice()));
        assert_eq!(
            status, 0x33,
            "device must refuse sub-command {sub:#04x} signed with params outside the scope; \
             the host accepts the identical request"
        );
    }
}
