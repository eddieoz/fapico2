//! US-1529: `makeCredUvNotRqd` must describe the makeCredential UV gate the
//! device actually implements.
//!
//! # What was wrong
//!
//! `Ctap2Info::default` seeded the option with a hard-coded `true`, on the
//! reasoning recorded in its own comment: *"makeCredential does not require UV
//! when no PIN is set."* CTAP 2.1 §6.1.3 does not mean that. The option is
//! *"Support for making non-discoverable credentials without requiring User
//! Verification"*, and `false`/absent means the device *"requires some form of
//! user verification for creating non-discoverable credentials, **regardless
//! of the parameters the platform supplies**"*. Nothing in it is scoped to the
//! no-PIN state.
//!
//! So on a device with a PIN set — which is the state the shipped board is in —
//! the advertisement licensed a request the device refuses. §6.1.2 step 7.2
//! lets a client that read `true` send `makeCredential` with no
//! `pinUvAuthParam` and no `uv` option; both twins answer that with `0x36`
//! (`CTAP2_ERR_PIN_POLICY_VIOLATION`).
//!
//! It is not a hypothetical client. The installed library decides UV policy
//! from this option by name (`fido2/client/__init__.py::_should_use_uv`):
//!
//! ```text
//! elif mc and uv_configured and not info.options.get("makeCredUvNotRqd"):
//!     return True
//! ```
//!
//! Read `true`, it declines to ask for a PIN; `make_credential` then sends
//! `opts = None` (`fido2/client/__init__.py:833`) and the request is refused.
//! This is US-1512's rule in a second option: the advertisement must not put a
//! client on a path the device cannot complete.
//!
//! # What these tests hold
//!
//! Not "the option is present" — that is the test that let the defect
//! through. In each reachable PIN/alwaysUv state these assert the *coherence*
//! between what GetInfo claims and what `makeCredential` then does:
//!
//! | state                    | `makeCredUvNotRqd` | MC, no token, no options |
//! |--------------------------|--------------------|--------------------------|
//! | no PIN                   | `true`             | `0x00` (served)          |
//! | PIN set                  | `false`            | `0x36` (refused)         |
//! | PIN set + `alwaysUv`     | `false`            | `0x36` (refused)         |
//!
//! The invariant behind the table is the one with teeth, and it is asserted on
//! both twins: **if the device advertises `true`, a no-options makeCredential
//! must succeed; if it advertises `false`, the same request must be refused.**
//! The old hard-coded `true` fails the second row on both twins. A presence
//! check would not.
//!
//! Two further things are pinned because they are easy to break next:
//!
//! * `alwaysUv: true` forces `makeCredUvNotRqd: false` — §6.1.3's MUST, and
//!   the reference enforces it structurally
//!   (`pico-fido/src/fido/cbor_get_info.c:149`).
//! * With the PIN set and the claim withdrawn, the request a conformant client
//!   is then *required* to send (`pinUvAuthParam`) succeeds — so `false`
//!   points the client at a path the device completes, not merely away from
//!   one.

mod common;

use common::*;
use fapico2_fido::cbor::{self, Value};

const PUAT_REQUIRED: u8 = 0x36;

/// CTAP2 makeCredential with **no** `options` map and **no** `pinUvAuthParam`.
///
/// This is the request the advertisement governs. It is built with the
/// no-heap writer so the absence of both keys is unambiguous — a helper that
/// defaulted them would test the wrong thing.
fn mc_bare() -> Vec<u8> {
    use fapico2_fido::cbor::no_heap as nh;
    use heapless::Vec as HV;
    let mut r: HV<u8, 256> = HV::new();
    nh::push_map_header(&mut r, 4).unwrap();
    nh::push_uint(&mut r, 1).unwrap();
    nh::push_bstr(&mut r, &[0xCC; 32]).unwrap();
    nh::push_uint(&mut r, 2).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_tstr(&mut r, "example.com").unwrap();
    nh::push_uint(&mut r, 3).unwrap();
    nh::push_map_header(&mut r, 1).unwrap();
    nh::push_tstr(&mut r, "id").unwrap();
    nh::push_bstr(&mut r, b"user-1").unwrap();
    nh::push_uint(&mut r, 4).unwrap();
    nh::push_array_header(&mut r, 1).unwrap();
    nh::push_map_header(&mut r, 2).unwrap();
    nh::push_tstr(&mut r, "type").unwrap();
    nh::push_tstr(&mut r, "public-key").unwrap();
    nh::push_tstr(&mut r, "alg").unwrap();
    nh::push_neg(&mut r, -7).unwrap();
    r.as_slice().to_vec()
}

/// Pull `options` (getInfo key 0x04) out of a GetInfo response.
fn options_of(resp: &[u8]) -> Vec<(String, bool)> {
    assert_eq!(resp[0], 0x00, "GetInfo must succeed");
    let (v, _) = cbor::decode(&resp[1..]).expect("valid CBOR");
    let Value::M(m) = v else { panic!("getInfo must be a map") };
    let Value::M(opts) = m
        .iter()
        .find_map(|(k, v)| match k {
            Value::U(0x04) => Some(v.clone()),
            _ => None,
        })
        .expect("getInfo key 0x04 (options)")
    else {
        panic!("options must be a map");
    };
    opts.iter()
        .map(|(k, v)| {
            let Value::T(name) = k else { panic!("option key must be text") };
            let Value::Bool(b) = v else { panic!("option value must be a bool") };
            (name.clone(), *b)
        })
        .collect()
}

fn option_of(opts: &[(String, bool)], key: &str) -> Option<bool> {
    opts.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
}

/// THE INVARIANT, in one place, so both twins state it the same way.
///
/// `advertised == true` licenses the bare request (§6.1.2 step 7.2, for
/// rk=false); `advertised == false` withdraws it (§6.1.2 step 7.3). Either
/// the device serves what it advertises or it refuses what it withdraws.
/// Anything else is a lie on the wire.
fn assert_claim_matches_behaviour(state: &str, advertised: Option<bool>, bare_mc: u8) {
    match advertised {
        Some(true) => assert_eq!(
            bare_mc, 0x00,
            "[{state}] advertises makeCredUvNotRqd=true, so a client may send \
             makeCredential with no pinUvAuthParam and no uv option — the \
             device must serve it. It answered 0x{bare_mc:02X}."
        ),
        Some(false) => assert_eq!(
            bare_mc, PUAT_REQUIRED,
            "[{state}] advertises makeCredUvNotRqd=false, so the client must \
             do UV; the bare request is not one it is entitled to send. It \
             answered 0x{bare_mc:02X} instead of 0x36."
        ),
        None => panic!("[{state}] makeCredUvNotRqd must be advertised"),
    }
}

/// §6.1.3: `alwaysUv` true ⇒ `makeCredUvNotRqd` MUST be false. Independent of
/// the coherence rule above, so it is checked on its own — a device could
/// pass coherence by refusing everything while still breaking the MUST.
fn assert_no_contradiction(state: &str, opts: &[(String, bool)]) {
    if option_of(opts, "alwaysUv") == Some(true) {
        assert_eq!(
            option_of(opts, "makeCredUvNotRqd"),
            Some(false),
            "[{state}] CTAP2.1 §6.1.3: with alwaysUv=true the authenticator \
             MUST set makeCredUvNotRqd to false"
        );
    }
}

// ---------------------------------------------------------------------------
// Host twin (`app.rs`)
// ---------------------------------------------------------------------------

type Host = fapico2_fido::app::FidoApp<fapico2_fido::keystore::MemoryKeystore>;

fn host_fresh() -> Host {
    Host::with_keystore(fapico2_fido::keystore::MemoryKeystore::new())
}

fn toggle_always_uv(app: &mut Host, client: &PinClient) {
    let token = client.get_token(app, 0x09, Some(0x20), None).unwrap();
    let auth_msg: Vec<u8> = [vec![0xffu8; 32], vec![0x0d, 0x02]].concat();
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(0x02)),
        (Value::U(0x03), Value::U(2)),
        (Value::U(0x04), Value::B(pin_uv_auth(&token, &auth_msg))),
    ]));
    assert_eq!(app.process_ctap2(0x0D, &req, [1, 2, 3, 4])[0], 0x00);
}

#[test]
fn host_no_pin_advertises_and_serves() {
    let mut app = host_fresh();
    let opts = options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    assert_claim_matches_behaviour(
        "host, no PIN",
        option_of(&opts, "makeCredUvNotRqd"),
        app.process_ctap2(0x01, &mc_bare(), [1, 2, 3, 4])[0],
    );
    assert_no_contradiction("host, no PIN", &opts);
}

#[test]
fn host_pin_set_withdraws_the_claim() {
    let (mut app, _client) = setup();
    let opts = options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    assert_claim_matches_behaviour(
        "host, PIN set",
        option_of(&opts, "makeCredUvNotRqd"),
        app.process_ctap2(0x01, &mc_bare(), [1, 2, 3, 4])[0],
    );
    assert_no_contradiction("host, PIN set", &opts);
}

/// The point of withdrawing the claim is that the request it redirects the
/// client to actually works. With `false`, §6.1.2 step 7.3 obliges the client
/// to send `pinUvAuthParam`; if that then failed, `false` would have moved the
/// client from one dead end to another.
#[test]
fn host_pin_set_serves_the_request_the_withdrawn_claim_redirects_to() {
    let (mut app, client) = setup();
    let token = client.get_token(&mut app, 0x09, Some(0x01), None).unwrap();
    let hash = [0x5au8; 32];
    let resp = app.process_ctap2(0x01, &make_mc_request(&hash, "example.com", &token), [1, 2, 3, 4]);
    assert_eq!(
        resp[0],
        0x00,
        "with makeCredUvNotRqd=false the client must send pinUvAuthParam, and \
         that path has to complete"
    );
}

#[test]
fn host_always_uv_forces_the_claim_false() {
    let (mut app, client) = setup();
    toggle_always_uv(&mut app, &client);
    let opts = options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    assert_eq!(option_of(&opts, "alwaysUv"), Some(true));
    assert_claim_matches_behaviour(
        "host, PIN set + alwaysUv",
        option_of(&opts, "makeCredUvNotRqd"),
        app.process_ctap2(0x01, &mc_bare(), [1, 2, 3, 4])[0],
    );
    assert_no_contradiction("host, PIN set + alwaysUv", &opts);
}

// ---------------------------------------------------------------------------
// Device twin (`device_app.rs` + `device_core.rs`) — the RP2350 binary.
// ---------------------------------------------------------------------------

mod device {
    use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
    use fapico2_fido::crypto;
    use fapico2_fido::device_app::FidoApp;
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;
    use heapless::Vec as HV;

    /// The device command path. `app.rs` is a host-only twin; a fix applied to
    /// one and not the other passes the host suite and changes nothing on
    /// hardware (AGENTS.md §1). The advertisement and the gate both live in
    /// `device_core.rs`, so both halves of the invariant are proven here.
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

        /// clientPIN getKeyAgreement → v1 shared key.
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

        /// getPinUvAuthTokenUsingPinWithPermissions (0x09) under PIN/UV auth
        /// protocol **one** — the protocol this fixture's `derive_keys`
        /// actually derives for. Returns the raw (decrypted) token, scoped
        /// to `permissions`: the config command demands `PERM_ACFG` and
        /// refuses a token without it, so the scope is a parameter rather
        /// than a constant.
        fn pin_token_with(&mut self, permissions: u8) -> Vec<u8> {
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
            nh::push_uint(&mut req, permissions as u64).unwrap();
            let (status, body) = self.call(0x06, req.as_slice());
            assert_eq!(status, 0x00, "getPinToken(0x09)");
            let mut p = Parser::new(&body);
            let Item::Map(n) = p.next().unwrap() else { panic!() };
            let mut raw = Vec::new();
            for _ in 0..n {
                match p.next().unwrap() {
                    Item::U(2) => {
                        let Item::B(b) = p.next().unwrap() else { panic!() };
                        // Protocol one encrypts the token with the same
                        // shared key this fixture encrypted the PIN hash
                        // with, and prefixes no IV — so decrypt it. Taking
                        // the response bytes verbatim yields the CIPHERTEXT
                        // and every later pinUvAuthParam is rejected with
                        // 0x33, which is a confusing way to learn that.
                        raw = crypto::pin_decrypt(1, &self.key, b).expect("token decrypts");
                    }
                    _ => {
                        p.skip().unwrap();
                    }
                }
            }
            assert!(!raw.is_empty(), "a token must come back");
            raw
        }

        /// MC-scoped token (0x01).
        fn pin_token(&mut self) -> Vec<u8> {
            self.pin_token_with(0x01)
        }

        /// authenticatorConfig (0x0D) sub-command 0x02, toggleAlwaysUv.
        /// The signed message is `0xff*32 || 0x0d || subCmd` (no params).
        fn toggle_always_uv(&mut self) {
            // PERM_ACFG (0x20): the config command checks it before it looks
            // at anything else, so an MC-scoped token is refused with 0x33.
            let token: [u8; 32] = self.pin_token_with(0x20).try_into().expect("32-byte token");
            let mut msg: HV<u8, 64> = HV::new();
            msg.extend_from_slice(&[0xffu8; 32]).ok();
            msg.extend_from_slice(&[0x0d, 0x02]).ok();
            let param = crypto::pin_uv_auth_param(2, &token, msg.as_slice());
            let mut req: HV<u8, 128> = HV::new();
            nh::push_map_header(&mut req, 3).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 4).unwrap();
            nh::push_bstr(&mut req, &param).unwrap();
            assert_eq!(self.call(0x0D, req.as_slice()).0, 0x00, "toggle alwaysUv");
        }

        fn options(&mut self) -> Vec<(String, bool)> {
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = self.app.process_ctap2(0x04, &[], [1, 2, 3, 4], &mut out);
            super::options_of(&out.as_slice()[..n])
        }

        /// The bare request: no `options` map, no `pinUvAuthParam`.
        fn mc_bare(&mut self) -> u8 {
            self.call(0x01, &super::mc_bare()).0
        }

        /// makeCredential carrying `pinUvAuthParam` — what a conformant
        /// client sends once `makeCredUvNotRqd` is `false`.
        fn mc_with_token(&mut self) -> u8 {
            let token: [u8; 32] = self.pin_token().try_into().expect("32-byte token");
            let hash = [0x5au8; 32];
            let param = crypto::pin_uv_auth_param(2, &token, &hash);
            let mut req: HV<u8, 512> = HV::new();
            nh::push_map_header(&mut req, 6).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_bstr(&mut req, &hash).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_map_header(&mut req, 2).unwrap();
            nh::push_tstr(&mut req, "id").unwrap();
            nh::push_tstr(&mut req, "example.com").unwrap();
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
            nh::push_uint(&mut req, 8).unwrap();
            nh::push_bstr(&mut req, &param).unwrap();
            nh::push_uint(&mut req, 9).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            self.call(0x01, req.as_slice()).0
        }
    }

    #[test]
    fn device_no_pin_advertises_and_serves() {
        let mut d = Device::boot();
        let opts = d.options();
        super::assert_claim_matches_behaviour(
            "device, no PIN",
            super::option_of(&opts, "makeCredUvNotRqd"),
            d.mc_bare(),
        );
        super::assert_no_contradiction("device, no PIN", &opts);
    }

    /// The row that was broken on hardware: a PIN-set device advertised
    /// `makeCredUvNotRqd: true` and then refused the request that claim
    /// licenses with `0x36`.
    #[test]
    fn device_pin_set_withdraws_the_claim() {
        let mut d = Device::boot();
        d.set_pin();
        let opts = d.options();
        super::assert_claim_matches_behaviour(
            "device, PIN set",
            super::option_of(&opts, "makeCredUvNotRqd"),
            d.mc_bare(),
        );
        super::assert_no_contradiction("device, PIN set", &opts);
    }

    #[test]
    fn device_pin_set_serves_the_request_the_withdrawn_claim_redirects_to() {
        let mut d = Device::boot();
        d.set_pin();
        assert_eq!(
            d.mc_with_token(),
            0x00,
            "with makeCredUvNotRqd=false the client must send pinUvAuthParam, \
             and that path has to complete"
        );
    }

    #[test]
    fn device_always_uv_forces_the_claim_false() {
        let mut d = Device::boot();
        d.set_pin();
        d.toggle_always_uv();
        let opts = d.options();
        assert_eq!(super::option_of(&opts, "alwaysUv"), Some(true));
        super::assert_claim_matches_behaviour(
            "device, PIN set + alwaysUv",
            super::option_of(&opts, "makeCredUvNotRqd"),
            d.mc_bare(),
        );
        super::assert_no_contradiction("device, PIN set + alwaysUv", &opts);
    }
}