//! US-1532: `pubKeyCredParams` must not be length-capped below what a real
//! client sends.
//!
//! # What was wrong
//!
//! `McReq::algs` was `HeaplessVec<i32, 8>` on the **device** twin, and
//! `parse_mc` answers `CTAP2_ERR_LIMIT_EXCEEDED` the moment a push overflows
//! (`device_core.rs:340`). CTAP 2.1 §6.1.2 puts no cap on the array. Chrome
//! sends ten:
//!
//! ```text
//! <- 0x1 (kAuthenticatorMakeCredential) {..., 4: [
//!      {"alg": -7}, {"alg": -8}, {"alg": -35}, {"alg": -36}, {"alg": -37},
//!      {"alg": -257}, {"alg": -47}, {"alg": -48}, {"alg": -49}, {"alg": -50}],
//!    ...}
//! -> (CTAP2 error code 0x15 (kCtap2ErrLimitExceeded))
//! ```
//!
//! Reproduced on hardware (`/dev/hidraw8`, PIN 123456) by replaying Chrome's
//! ten entries: `0x15`, zero keepalives, no presence window — the request was
//! refused during parsing, before any credential could be created. The same
//! request carrying one algorithm armed normally. That is why
//! `demo.yubico.com/webauthn-technical/registration` could not register while
//! sites whose browser sends a shorter list could.
//!
//! # Why the whole host suite was green
//!
//! `app.rs` holds the same list in an unbounded `Vec<PubKeyCredParam>`, so the
//! host twin accepts any length and every host-only test passed throughout.
//! This is AGENTS.md §1's twin trap on the request parser rather than the
//! command path: fixing `app.rs` — or only testing it — would have changed
//! nothing on the RP2350.
//!
//! # What these tests hold
//!
//! * the **device** twin serves a makeCredential carrying Chrome's exact ten;
//! * the **host** twin does too, so the two cannot drift back;
//! * the cap is now 16, and 16 is served while the boundary above it is not
//!   silently truncated — an authenticator that quietly drops algorithms it
//!   cannot store would answer with a credential the client never agreed to.

mod common;

use common::*;
use fapico2_fido::cbor::{self, Value};

const LIMIT_EXCEEDED: u8 = 0x15;

/// Chrome's default `pubKeyCredParams`, verbatim from
/// `make_credential_request_handler` in Chrome's device log.
const CHROME_ALGS: [i64; 10] = [-7, -8, -35, -36, -37, -257, -47, -48, -49, -50];

fn cred_params(algs: &[i64]) -> Value {
    Value::A(
        algs
            .iter()
            .map(|a| {
                Value::M(vec![
                    (Value::T("type".into()), Value::T("public-key".into())),
                    (Value::T("alg".into()), Value::N(*a)),
                ])
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Host twin (`app.rs`) — unbounded today, and must stay accepting
// ---------------------------------------------------------------------------

fn host_mc(
    app: &mut fapico2_fido::app::FidoApp<fapico2_fido::keystore::MemoryKeystore>,
    token: &[u8],
    algs: &[i64],
) -> u8 {
    let hash = [0x5au8; 32];
    let param = pin_uv_auth(token, &hash);
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::B(hash.to_vec())),
        (
            Value::U(0x02),
            Value::M(vec![
                (Value::T("id".into()), Value::T("demo.yubico.com".into())),
                (Value::T("name".into()), Value::T("Yubico Demo".into())),
            ]),
        ),
        (
            Value::U(0x03),
            Value::M(vec![
                (Value::T("id".into()), Value::B(vec![0x02; 32])),
                (Value::T("name".into()), Value::T("u".into())),
                (Value::T("displayName".into()), Value::T("u".into())),
            ]),
        ),
        (Value::U(0x04), cred_params(algs)),
        (Value::U(0x05), Value::A(vec![])),
        (Value::U(0x08), Value::B(param.to_vec())),
        (Value::U(0x09), Value::U(2)),
    ]));
    app.process_ctap2(0x01, &req, [1, 2, 3, 4])[0]
}

#[test]
fn host_serves_chromes_ten_algorithms() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
    assert_eq!(
        host_mc(&mut app, &token, &CHROME_ALGS),
        0x00,
        "the host twin must accept the list Chrome sends"
    );
}

// ---------------------------------------------------------------------------
// Device twin (`device_app.rs` + `device_core.rs`) — the one that shipped the
// defect, and the only one with a fixed-capacity field
// ---------------------------------------------------------------------------

mod device {
    use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
    use fapico2_fido::crypto;
    use fapico2_fido::device_app::FidoApp;
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;
    use heapless::Vec as HV;

    const CHROME_ALGS: [i64; 10] = [-7, -8, -35, -36, -37, -257, -47, -48, -49, -50];

    struct Device {
        app: FidoApp,
        sk: p256::SecretKey,
        key: [u8; 32],
    }

    impl Device {
        fn boot() -> Self {
            let mut trng = HostTrng::new();
            let mut store = HostSecureStore::new();
            Self {
                app: FidoApp::boot(&mut trng, &mut store).unwrap(),
                sk: p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap(),
                key: [0; 32],
            }
        }

        fn call(&mut self, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = self.app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
            let resp = out.as_slice()[..n].to_vec();
            (resp[0], resp[1..].to_vec())
        }

        fn push_client_key_agreement(&self, out: &mut HV<u8, 256>) {
            let bytes = crypto::public_key_bytes(&self.sk.public_key());
            nh::push_map_header(out, 5).unwrap();
            nh::push_uint(out, 1).unwrap();
            nh::push_uint(out, 2).unwrap();
            nh::push_uint(out, 3).unwrap();
            nh::push_neg(out, -25).unwrap();
            nh::push_neg(out, -1).unwrap();
            nh::push_uint(out, 1).unwrap();
            nh::push_neg(out, -2).unwrap();
            nh::push_bstr(out, &bytes[1..33]).unwrap();
            nh::push_neg(out, -3).unwrap();
            nh::push_bstr(out, &bytes[33..65]).unwrap();
        }

        fn derive_keys(&mut self) {
            let mut req: HV<u8, 64> = HV::new();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            let (status, body) = self.call(0x06, req.as_slice());
            assert_eq!(status, 0x00, "getKeyAgreement failed");
            let mut p = Parser::new(&body);
            assert!(matches!(p.next(), Ok(Item::Map(1))));
            assert_eq!(p.next().unwrap(), Item::U(1));
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            let Item::Map(n) = p.next().unwrap() else { panic!() };
            for _ in 0..n {
                let key = match p.next().unwrap() {
                    Item::U(u) => u as i64,
                    Item::N(v) => v,
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
                    _ => {
                        p.skip().unwrap();
                    }
                }
            }
            let dev = crypto::parse_cose_ec2_p256_bytes(&x, &y).expect("device pubkey");
            let raw = crypto::ecdh_shared_secret(&self.sk, &dev);
            self.key = crypto::derive_shared_secret_v1(&raw);
        }

        fn v1_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut padded = plaintext.to_vec();
            while !padded.len().is_multiple_of(16) {
                padded.push(0);
            }
            let mut buf = [0u8; 96];
            buf[..padded.len()].copy_from_slice(&padded);
            crypto::aes256_cbc_encrypt_into(&self.key, &[0u8; 16], &mut buf[..padded.len()]).unwrap();
            buf[..padded.len()].to_vec()
        }

        fn set_pin(&mut self) {
            self.derive_keys();
            let pin_enc = self.v1_encrypt(b"1234");
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
            let tag = crypto::hmac_sha256(&self.key, &pin_enc)[..16].to_vec();
            nh::push_bstr(&mut req, &tag).unwrap();
            assert_eq!(self.call(0x06, req.as_slice()).0, 0x00, "setPIN");
        }

        fn pin_token(&mut self) -> [u8; 32] {
            self.derive_keys();
            let enc = self.v1_encrypt(&crypto::pin_hash(b"1234"));
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 5).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 9).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            self.push_client_key_agreement(&mut req);
            nh::push_uint(&mut req, 6).unwrap();
            nh::push_bstr(&mut req, &enc).unwrap();
            nh::push_uint(&mut req, 9).unwrap();
            nh::push_uint(&mut req, 0x01).unwrap();
            let (status, body) = self.call(0x06, req.as_slice());
            assert_eq!(status, 0x00, "getPinToken(0x09)");
            let mut p = Parser::new(&body);
            let Item::Map(n) = p.next().unwrap() else { panic!() };
            let mut raw = Vec::new();
            for _ in 0..n {
                match p.next().unwrap() {
                    Item::U(2) => {
                        let Item::B(b) = p.next().unwrap() else { panic!() };
                        raw = crypto::pin_decrypt(1, &self.key, b).expect("token decrypts");
                    }
                    _ => {
                        p.skip().unwrap();
                    }
                }
            }
            raw.try_into().expect("32-byte token")
        }

        fn mc_with_algs(&mut self, algs: &[i64]) -> u8 {
            let token = self.pin_token();
            let hash = [0x5au8; 32];
            let param = crypto::pin_uv_auth_param(2, &token, &hash);
            let mut req: HV<u8, 1024> = HV::new();
            nh::push_map_header(&mut req, 6).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_bstr(&mut req, &hash).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_tstr(&mut req, "id").unwrap();
            nh::push_tstr(&mut req, "demo.yubico.com").unwrap();
            nh::push_tstr(&mut req, "name").unwrap();
            nh::push_tstr(&mut req, "Yubico Demo").unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_tstr(&mut req, "id").unwrap();
            nh::push_bstr(&mut req, b"user").unwrap();
            nh::push_tstr(&mut req, "name").unwrap();
            nh::push_tstr(&mut req, "U").unwrap();
            nh::push_uint(&mut req, 4).unwrap();
            nh::push_array_header(&mut req, algs.len()).unwrap();
            for a in algs {
                nh::push_map_header(&mut req, 2).unwrap();
                nh::push_tstr(&mut req, "type").unwrap();
                nh::push_tstr(&mut req, "public-key").unwrap();
                nh::push_tstr(&mut req, "alg").unwrap();
                nh::push_neg(&mut req, *a).unwrap();
            }
            nh::push_uint(&mut req, 8).unwrap();
            nh::push_bstr(&mut req, &param).unwrap();
            nh::push_uint(&mut req, 9).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            self.call(0x01, req.as_slice()).0
        }
    }

    /// The row that was red on hardware.
    #[test]
    fn device_serves_chromes_ten_algorithms() {
        let mut d = Device::boot();
        d.set_pin();
        assert_eq!(
            d.mc_with_algs(&CHROME_ALGS),
            0x00,
            "US-1532: Chrome sends ten pubKeyCredParams entries and CTAP 2.1 \
             §6.1.2 caps them at nothing. Answering 0x15 here refused every \
             registration on this site while leaving the host suite green."
        );
    }

    #[test]
    fn device_serves_a_single_algorithm() {
        let mut d = Device::boot();
        d.set_pin();
        assert_eq!(d.mc_with_algs(&[-7]), 0x00);
    }

    /// The cap is 16. Past it the device must still refuse rather than
    /// silently drop entries: an authenticator that answered with a credential
    /// built from an algorithm the client never listed in full would be
    /// answering a different question than the one asked.
    #[test]
    fn device_accepts_up_to_sixteen_and_refuses_beyond() {
        let sixteen: Vec<i64> = (1..=16).map(|i| -i).collect();
        let mut d = Device::boot();
        d.set_pin();
        assert_eq!(
            d.mc_with_algs(&sixteen),
            0x00,
            "16 algorithms must be served"
        );

        let seventeen: Vec<i64> = (1..=17).map(|i| -i).collect();
        let mut d = Device::boot();
        d.set_pin();
        assert_eq!(
            d.mc_with_algs(&seventeen),
            super::LIMIT_EXCEEDED,
            "past the documented cap the request must be refused, not truncated"
        );
    }
}