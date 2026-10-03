//! US-1512: GetInfo's `pinUvAuthToken` must describe a token route the
//! device can actually complete, and must agree with `clientPin`.
//!
//! Both twins are driven here on purpose. `app.rs` is the host-only twin and
//! `device_core.rs` is what the RP2350 binary runs; a fix applied to one and
//! not the other passes the host suite and changes nothing on hardware.
//!
//! The rule under test is `ctap2::pin_uv_auth_token_available`:
//!
//! * no PIN configured  → `true`. The capability covers the PIN-based token
//!   legs (`0x05`/`0x09`) per CTAP 2.2 §5.4.6; clientPIN sub-command `0x06`
//!   (`getPinUvAuthTokenUsingUvWithPermissions`) is NOT part of the offer —
//!   this build has no built-in UV method, `uv` is absent from GetInfo, and
//!   the sub-command is refused `InvalidSubcommand` (0x3E) on both twins.
//! * PIN set, healthy    → `true`, via the `0x05`/`0x09` legs.
//! * durable lockout     → `false`, because a correct PIN is required before
//!   any token is minted again (the `0x05`/`0x09` success path clears the
//!   latch and mints together).
//!
//! `false` is a LOCKOUT, not a wall: the `0x05`/`0x09` legs carry no up-front
//! gate on purpose and their success path clears the latch and mints the
//! token together, so one correct PIN restores the advertisement. Pinned on
//! BOTH twins by `a_correct_pin_restores_the_route_it_withdrew` and
//! `device::device_correct_pin_restores_the_route_it_withdrew`.

mod common;

use common::*;
use fapico2_fido::cbor::{self, Value};

/// Pull the `options` map (getInfo key 0x04) out of a GetInfo response.
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

// ---------------------------------------------------------------------------
// US-1525: `uv` is never advertised, on either twin.
// ---------------------------------------------------------------------------

/// The comment above sub-command `0x06` in `device_core.rs` used to justify
/// the sub-command by claiming "GetInfo reports the `uv` option". It never
/// did. Advertising it would promise a built-in user-verification mechanism
/// this build has nothing to check against, so the invariant is pinned here
/// instead — on both twins — and the comment must not cite it again.
#[test]
fn uv_is_never_advertised_on_the_host_twin() {
    let mut app = FidoAppMem::with_keystore(fapico2_fido::keystore::MemoryKeystore::new());
    let opts = options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    assert_eq!(option_of(&opts, "uv"), None, "the host twin must not advertise uv");
    // ...while still advertising the token mechanism, which is what the
    // sub-command's comment now points at instead.
    assert_eq!(option_of(&opts, "pinUvAuthToken"), Some(true));
}

/// The options vector is a 16-slot heapless vec and `set_option` swallows a
/// failed push with `.ok()`, so a seventeenth key would vanish with no
/// diagnostic. Pinning the advertised set by length as well as by value
/// makes an addition show up as a test failure instead. Ten is the current
/// count: `Ctap2Info::default` seeds seven and `handle_get_info` adds
/// `authnrCfg`, `enterpriseAttestation` and `alwaysUv` — `clientPin` and
/// `pinUvAuthToken` overwrite in place via `set_option`'s `find`.
const ADVERTISED_OPTIONS: usize = 10;

fn assert_pin_pair(opts: &[(String, bool)], want_pin: bool, want_token: bool) {
    assert_eq!(
        opts.len(),
        ADVERTISED_OPTIONS,
        "every advertised option must survive the 16-slot vector: {opts:?}"
    );
    assert_eq!(option_of(opts, "clientPin"), Some(want_pin));
    assert_eq!(option_of(opts, "pinUvAuthToken"), Some(want_token));
}

// ---------------------------------------------------------------------------
// Host twin (`app.rs`)
// ---------------------------------------------------------------------------

/// Three wrong PINs: the durable 3-strike latch (`needs_power_cycle`).
fn latch_host(app: &mut FidoAppMem, client: &PinClient) {
    for _ in 0..3 {
        let wrong = fapico2_fido::crypto::pin_hash(b"0000");
        let enc = fapico2_fido::crypto::pin_encrypt(2, &client.enc_key, &wrong);
        let req = cbor::encode(&Value::M(vec![
            (Value::U(0x01), Value::U(2)),
            (Value::U(0x02), Value::U(0x05)),
            (Value::U(0x03), client.client_cose()),
            (Value::U(0x06), Value::B(enc)),
        ]));
        let _ = app.process_ctap2(0x06, &req, [1, 2, 3, 4])[0];
    }
}

type FidoAppMem = fapico2_fido::app::FidoApp<fapico2_fido::keystore::MemoryKeystore>;

#[test]
fn host_fresh_device_still_advertises_the_token_route() {
    let mut app = FidoAppMem::with_keystore(fapico2_fido::keystore::MemoryKeystore::new());
    let opts = options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    // The pairing that started this story: no PIN configured.
    assert_pin_pair(&opts, false, true);
}

#[test]
fn host_pin_set_advertises_both() {
    let (mut app, _client) = setup();
    let opts = options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    assert_pin_pair(&opts, true, true);
}

#[test]
fn host_locked_out_withdraws_the_token_route() {
    let (mut app, client) = setup();
    latch_host(&mut app, &client);
    let opts = options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    assert_pin_pair(&opts, true, false);
}

/// The lockout is a LOCKOUT, not a wall, and this is the test that says so.
///
/// `ctap2::pin_uv_auth_token_available`'s doc comment once claimed that once
/// the durable flag latches "every PIN leg refuses ... a client reads `true`,
/// mints a token, and is then refused at the first command" — which is the
/// inverse of what `device_core.rs:1917-1925` does thirteen lines later: the
/// `0x05`/`0x09` success path clears `blocked` and `needs_power_cycle` *and*
/// mints the token in the same breath. The value `!(blocked ||
/// needs_power_cycle)` was always right; the reason given for it was not, and
/// it contradicted itself four sentences later.
///
/// So the corrected claim — "not until you present the correct PIN", not "not
/// ever" — gets a test on the host twin, and the device module below pins the
/// same thing on the twin that actually ships. Without this, the next reader
/// of the doc comment has only prose to go on, and prose is what was wrong.
#[test]
fn a_correct_pin_restores_the_route_it_withdrew() {
    let (mut app, client) = setup();
    latch_host(&mut app, &client);
    assert_pin_pair(
        &options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4])),
        true,
        false,
    );

    // The correct PIN, on the leg that has no up-front lockout gate.
    let correct = fapico2_fido::crypto::pin_hash(b"1234");
    let enc = fapico2_fido::crypto::pin_encrypt(2, &client.enc_key, &correct);
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x05)),
        (Value::U(0x03), client.client_cose()),
        (Value::U(0x06), Value::B(enc)),
    ]));
    let resp = app.process_ctap2(0x06, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "a correct PIN must not be refused by the latch");
    // ...and it really is a token: key 0x02, a byte string, present and
    // non-empty. `assert_ne!(resp[0], 0x00)` alone would pass on any other
    // success shape, which is the "test that cannot fail" failure the US-1528
    // work already hit once in this tree.
    let (v, _) = cbor::decode(&resp[1..]).expect("valid CBOR");
    let Value::M(m) = v else { panic!("token response must be a map") };
    let tok = m
        .iter()
        .find_map(|(k, v)| match k {
            Value::U(0x02) => Some(v.clone()),
            _ => None,
        })
        .expect("token response key 0x02");
    let Value::B(b) = tok else { panic!("key 0x02 must be a byte string") };
    assert!(!b.is_empty(), "the restored route must mint a real token");

    // The advertisement came back, in the same exchange.
    assert_pin_pair(
        &options_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4])),
        true,
        true,
    );
}

/// clientPIN sub-command `0x06` is refused `InvalidSubcommand` (0x3E) in
/// every state — fresh, PIN-set, or durably locked out. This test used to
/// pin the *opposite* on the locked-out side: it asserted `PinAuthBlocked`
/// (0x34), i.e. that a token leg existed and merely honoured the lockout.
/// The refusal is now unconditional — CTAP 2.2 §5.4.6 grants `0x06` only
/// when the `uv` option is advertised, and it never is — so the lockout
/// gate US-1512 put inside the arm is superseded, not preserved.
#[test]
fn host_uv_subcommand_is_refused_in_every_state() {
    // Fresh, no PIN.
    let mut fresh = FidoAppMem::with_keystore(fapico2_fido::keystore::MemoryKeystore::new());
    let fresh_req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x06)),
        (Value::U(0x03), Value::M(vec![])),
        (Value::U(0x09), Value::U(0x04)),
    ]));
    let resp = fresh.process_ctap2(0x06, &fresh_req, [1, 2, 3, 4]);
    assert_eq!(
        resp[0], 0x3E,
        "0x06 must be refused InvalidSubcommand on a fresh device, before any lockout state"
    );

    // Durably locked out.
    let (mut locked, client) = setup();
    latch_host(&mut locked, &client);
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x06)),
        (Value::U(0x03), Value::M(vec![])),
        (Value::U(0x09), Value::U(0x04)),
    ]));
    let resp = locked.process_ctap2(0x06, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x3E, "lockout or not, 0x06 has no leg here");
    assert_eq!(
        resp.len(),
        1,
        "the refusal is a bare status byte — no CBOR body, no token"
    );
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

    struct Device {
        app: FidoApp,
        hmac_key: [u8; 32],
        enc_key: [u8; 32],
    }

    impl Device {
        fn boot() -> Self {
            let mut trng = HostTrng::new();
            let mut store = HostSecureStore::new();
            Self {
                app: FidoApp::boot(&mut trng, &mut store).unwrap(),
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

        fn push_client_key_agreement(&self, out: &mut HV<u8, 256>) {
            let sk = p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap();
            let bytes = crypto::public_key_bytes(&sk.public_key());
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

        /// clientPIN getKeyAgreement → v1 shared keys.
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
                    _ => p.skip().unwrap(),
                }
            }
            let sk = p256::SecretKey::from_slice(&[0x99u8; 32]).unwrap();
            let device_pub = crypto::parse_cose_ec2_p256_bytes(&x, &y).expect("device pubkey");
            let raw = crypto::ecdh_shared_secret(&sk, &device_pub);
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
            crypto::aes256_cbc_encrypt_into(&self.enc_key, &zero_iv(), &mut buf[..padded.len()]).unwrap();
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

        /// getPinToken (0x05) with the wrong PIN. Returns the status byte.
        fn wrong_pin(&mut self, pin: &[u8]) -> u8 {
            let enc = self.v1_encrypt(&crypto::pin_hash(pin));
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 4).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 5).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            self.push_client_key_agreement(&mut req);
            nh::push_uint(&mut req, 6).unwrap();
            nh::push_bstr(&mut req, &enc).unwrap();
            self.call(0x06, req.as_slice()).0
        }

        /// getPinToken (0x05) with the CORRECT pin — the leg that clears the
        /// durable latch (`device_core.rs:1917-1925`) and mints the token in
        /// the same breath. Returns the status byte.
        fn correct_pin(&mut self, pin: &[u8]) -> (u8, usize) {
            let enc = self.v1_encrypt(&crypto::pin_hash(pin));
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 4).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 5).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            self.push_client_key_agreement(&mut req);
            nh::push_uint(&mut req, 6).unwrap();
            nh::push_bstr(&mut req, &enc).unwrap();
            let (status, body) = self.call(0x06, req.as_slice());
            (status, body.len())
        }

        /// clientPIN sub-command `0x06` — refused, never minted. Returns the
        /// status byte. The request is fully formed (keyAgreement +
        /// permissions) so the refusal can only come from the sub-command
        /// gate itself, not from a missing-parameter short-circuit.
        fn uv_subcommand_status(&mut self) -> u8 {
            self.derive_keys();
            let mut req: HV<u8, 256> = HV::new();
            nh::push_map_header(&mut req, 4).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 1).unwrap();
            nh::push_uint(&mut req, 2).unwrap();
            nh::push_uint(&mut req, 6).unwrap();
            nh::push_uint(&mut req, 3).unwrap();
            self.push_client_key_agreement(&mut req);
            nh::push_uint(&mut req, 9).unwrap();
            nh::push_uint(&mut req, 4).unwrap();
            self.call(0x06, req.as_slice()).0
        }

        fn options(&mut self) -> Vec<(String, bool)> {
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = self.app.process_ctap2(0x04, &[], [1, 2, 3, 4], &mut out);
            super::options_of(&out.as_slice()[..n])
        }
    }

    fn zero_iv() -> [u8; 16] {
        [0u8; 16]
    }

    /// The pairing this story exists for, on the binary that actually ships.
    /// The capability is advertised even with no PIN — it names the
    /// `0x05`/`0x09` legs — while sub-command `0x06` is refused outright.
    #[test]
    fn device_fresh_still_advertises_the_token_route() {
        let mut d = Device::boot();
        let opts = d.options();
        super::assert_pin_pair(&opts, false, true);
        // And 0x06 is refused with InvalidSubcommand on the same fresh
        // device — the advertisement does not point at a UV leg, because
        // there is no UV leg.
        assert_eq!(
            d.uv_subcommand_status(),
            0x3E,
            "0x06 must be refused on a fresh device, before any lockout state"
        );
    }

    /// US-1525, device side: the comment above sub-command `0x06` must not
    /// be able to cite a `uv` option that this binary does not send.
    #[test]
    fn uv_is_never_advertised_on_the_device_twin() {
        let mut d = Device::boot();
        let opts = d.options();
        assert_eq!(super::option_of(&opts, "uv"), None, "the device twin must not advertise uv");
        assert_eq!(super::option_of(&opts, "pinUvAuthToken"), Some(true));
    }

    #[test]
    fn device_pin_set_advertises_both() {
        let mut d = Device::boot();
        d.set_pin(b"1234");
        let opts = d.options();
        super::assert_pin_pair(&opts, true, true);
    }

    #[test]
    fn device_locked_out_withdraws_the_token_route() {
        let mut d = Device::boot();
        d.set_pin(b"1234");
        for _ in 0..3 {
            d.wrong_pin(b"0000");
        }
        let opts = d.options();
        super::assert_pin_pair(&opts, true, false);
    }

    /// Sub-command `0x06` is refused in every state on the shipping binary
    /// too. This test used to pin coherence in the other direction — minting
    /// `0x00` when the advert said `true`, `PIN_AUTH_BLOCKED` when it said
    /// `false` — which pinned the non-conformant UV leg. The advertisement's
    /// `pinUvAuthToken` bit now names the `0x05`/`0x09` legs only; `0x06`
    /// answers `InvalidSubcommand` regardless of lockout, so the
    /// advertisement cannot be read as promising it.
    #[test]
    fn device_uv_subcommand_is_refused_in_every_state() {
        let mut fresh = Device::boot();
        let opts = fresh.options();
        assert_eq!(super::option_of(&opts, "pinUvAuthToken"), Some(true));
        assert_eq!(fresh.uv_subcommand_status(), 0x3E);

        let mut locked = Device::boot();
        locked.set_pin(b"1234");
        for _ in 0..3 {
            locked.wrong_pin(b"0000");
        }
        let opts = locked.options();
        assert_eq!(super::option_of(&opts, "pinUvAuthToken"), Some(false));
        assert_eq!(
            locked.uv_subcommand_status(),
            0x3E,
            "the refusal is unconditional — it must not depend on lockout state"
        );
    }

    /// The device half of `a_correct_pin_restores_the_route_it_withdrew`.
    ///
    /// This is the twin that matters: `device_core.rs`, not `app.rs`, is what
    /// the RP2350 runs, and the corrected reading of the lockout is a claim
    /// about `device_core.rs:1917-1925`. The host twin alone would leave it
    /// unproven on hardware.
    #[test]
    fn device_correct_pin_restores_the_route_it_withdrew() {
        let mut d = Device::boot();
        d.set_pin(b"1234");
        for _ in 0..3 {
            d.wrong_pin(b"0000");
        }
        super::assert_pin_pair(&d.options(), true, false);

        let (status, body_len) = d.correct_pin(b"1234");
        assert_eq!(status, 0x00, "a correct PIN must not be refused by the latch");
        assert!(body_len > 0, "the restored route must return a token body");
        super::assert_pin_pair(&d.options(), true, true);
        // The route the advertisement restored is the PIN leg, which the
        // `0x00` above already proves end to end. Sub-command `0x06` stays
        // refused — the restoration never re-opens the UV leg because there
        // never was one to re-open.
        assert_eq!(
            d.uv_subcommand_status(),
            0x3E,
            "the refusal of 0x06 is independent of lockout state"
        );
    }
}
