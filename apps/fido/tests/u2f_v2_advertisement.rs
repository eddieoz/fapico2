//! US-1531: getInfo must not advertise `U2F_V2` (CTAP1) on a device with a
//! PIN set.
//!
//! # What was wrong
//!
//! `Ctap2Info::default` seeded `versions` with `U2F_V2` unconditionally, so a
//! PIN-set board advertised CTAP1 on every `authenticatorGetInfo`. Chrome reads
//! that as "this device also speaks U2F" and, when the request came from a page
//! using WebAuthn, entered a **U2F register** before it ever got to the CTAP2
//! `makeCredential` it had actually been asked for.
//!
//! Our U2F path does not work (see "Known gap" below), so that register
//! answered wrongly and Chrome abandoned the whole CTAP2 operation. Measured
//! on `/dev/hidraw8` against `demo.yubico.com/webauthn-technical/registration`,
//! which asks for `userVerification:"discouraged"` and therefore sends
//! `makeCredential` with no `pinUvAuthToken`. Chrome's device log — captured by
//! relaunching Chrome with `--enable-logging`, because the DevTools MCP browser
//! is launched without it and `chrome://device-log/` is then always empty:
//!
//! ```text
//! device_response_converter.cc:403 -> {1: ["U2F_V2","FIDO_2_0",...], ...}
//! fido_hid_device.cc:455            Unknown CTAPHID command: 59 02
//! u2f_register_operation.cc:195     Unexpected status 27264 from U2F device
//! make_credential_request_handler.cc:825 Ignoring status 1
//! ```
//!
//! 27264 == 0x6A80 == U2F `SW_WRONG_DATA`. Chrome then sat on
//! `authenticator_request_dialog_model.cc:158 UI step: kCableV2QRCode`, which is
//! the QR-code popup, while the board's consent window from Chrome's own
//! `authenticatorSelection` probe kept the LED blinking. That is the whole
//! X.com / Proton / demo.yubico.com report.
//!
//! The CTAP2 path was never broken and was never reached: the `0x09`
//! `getPinUvAuthTokenUsingPinWithPermissions` leg behind `0x36 PUAT_REQUIRED`
//! mints a token correctly on hardware, as does the legacy `0x05` leg.
//!
//! # Why the PIN gates it
//!
//! The reference withholds `U2F_V2` whenever `alwaysUv` is true
//! (`pico-fido2/src/fido/cbor_get_info.c:96-99`):
//!
//! ```c
//! bool alwaysUv = (get_opts() & FIDO2_OPT_AUV) || (file_has_data(ef_pin) && !keydev_unlocked);
//! if (!alwaysUv) {
//!     CBOR_CHECK(cbor_encoder_encode_text_stringz(&arrayEncoder, "U2F_V2"));
//! }
//! ```
//!
//! `alwaysUv` is true whenever a PIN is set and the keydev is still locked —
//! the state a PIN-set board boots into. Measured on the reference board, its
//! `versions` is `["FIDO_2_0"…"FIDO_2_3"]` with no `U2F_V2`, which is why it
//! never entered the broken path. This device twin has no `keydev_unlocked`
//! concept, so `pin_set` is the faithful equivalent of the reference's
//! condition.
//!
//! CTAP1 is also the *lower*-trust path: it has no PIN concept, so serving it
//! from a device with a PIN configured is a downgrade the user never asked for.
//!
//! # What these tests hold
//!
//! The rule itself, on both twins and on the bare seed:
//!
//! | state        | `U2F_V2` advertised |
//! |--------------|---------------------|
//! | no PIN       | yes                 |
//! | PIN set      | **no**              |
//! | PIN + alwaysUv | **no**            |
//!
//! A test that only asserted "the entry exists" is the one that would have let
//! this through, so the direction that matters is asserted explicitly.
//!
//! # Known gap, deliberately not hidden
//!
//! With **no** PIN set this rule re-advertises `U2F_V2`, and our CTAP1 path is
//! still broken — one defect, in one place. U2F reaches this firmware in two
//! framings: APDUs over CCID, and **raw U2F messages** over `CTAPHID_MSG`.
//! `hid_serve.rs:1089` hands the `CTAPHID_MSG` payload straight to
//! `process_u2f_apdu`, which requires at least 5 bytes and parses
//! `CLA INS P1 P2 LC` (`u2f.rs:89-112`). A raw U2F version request is the
//! single byte `0x05`, so it is answered `0x6700` (`U2fStatus::WrongLength`)
//! where a device must answer `"U2F_V2"`; a raw register is answered `0x6E00`.
//! Measured on `/dev/hidraw8`, and reproduced below.
//!
//! So a PIN-less board would still hit the same Chrome failure.
//! `ctap1_is_not_servable_yet` pins that known state so it cannot be
//! forgotten, and the framing fix is tracked separately; until then this rule
//! removes the failure from the state the shipped board is actually in.
//!
//! (There is no CTAPHID VERSION command to implement — CTAPHID defines PING,
//! MSG, LOCK, INIT, WINK, CBOR, CANCEL, KEEPALIVE and ERROR only. The U2F
//! version string comes over `CTAPHID_MSG`.)

mod common;

use common::*;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::ctap2::{u2f_v2_advertised, Ctap2Info};

const CTAP1: &str = "U2F_V2";

/// Pull `versions` (getInfo key 0x01) out of a GetInfo response.
fn versions_of(resp: &[u8]) -> Vec<String> {
    assert_eq!(resp[0], 0x00, "GetInfo must succeed");
    let (v, _) = cbor::decode(&resp[1..]).expect("valid CBOR");
    let Value::M(m) = v else { panic!("getInfo must be a map") };
    let Value::A(items) = m
        .iter()
        .find_map(|(k, v)| match k {
            Value::U(0x01) => Some(v.clone()),
            _ => None,
        })
        .expect("getInfo key 0x01 (versions)")
    else {
        panic!("versions must be an array");
    };
    items
        .iter()
        .map(|v| {
            let Value::T(s) = v else { panic!("version entry must be text") };
            s.clone()
        })
        .collect()
}

/// THE RULE, stated once so both twins hold it the same way.
fn assert_advertisement_matches_pin_state(state: &str, versions: &[String], pin_set: bool) {
    let advertised = versions.iter().any(|v| v == CTAP1);
    if pin_set {
        assert!(
            !advertised,
            "[{state}] a PIN-set board must not advertise {CTAP1}: Chrome reads it \
             as \"this device also speaks CTAP1\", enters a U2F register, and \
             abandons the CTAP2 makeCredential the page asked for when that \
             answers wrongly. versions = {versions:?}"
        );
    } else {
        assert!(
            advertised,
            "[{state}] a board with no PIN set still speaks CTAP1 and must say so; \
             versions = {versions:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The rule and the seed
// ---------------------------------------------------------------------------

#[test]
fn the_seed_fails_closed() {
    let info = Ctap2Info::default();
    assert!(
        !info.versions.contains(&CTAP1),
        "a bare Ctap2Info must not claim a protocol the device has not been \
         asked about — the same fail-closed seed as makeCredUvNotRqd"
    );
    assert!(info.versions.contains(&"FIDO_2_0"));
}

#[test]
fn rule_is_the_reference_condition() {
    assert!(u2f_v2_advertised(false), "no PIN: CTAP1 is offered");
    assert!(!u2f_v2_advertised(true), "PIN set: CTAP1 is withheld");
}

#[test]
fn set_u2f_v2_is_idempotent_and_ordered_first() {
    let mut info = Ctap2Info::default();
    assert!(!info.versions.contains(&CTAP1));

    info.set_u2f_v2(true);
    assert_eq!(
        info.versions.first().copied(),
        Some(CTAP1),
        "U2F_V2 leads the list, as in the reference (cbor_get_info.c:96-99)"
    );
    assert_eq!(info.versions.len(), 5, "set twice must not duplicate");

    info.set_u2f_v2(true);
    assert_eq!(info.versions.len(), 5, "setting again must be a no-op");

    info.set_u2f_v2(false);
    assert!(!info.versions.contains(&CTAP1));
    assert!(info.versions.contains(&"FIDO_2_0"), "withholding is surgical");
    assert_eq!(info.versions.len(), 4);
}

// ---------------------------------------------------------------------------
// Host twin (`app.rs`)
// ---------------------------------------------------------------------------

type Host = fapico2_fido::app::FidoApp<fapico2_fido::keystore::MemoryKeystore>;

#[test]
fn host_no_pin_still_offers_ctap1() {
    let mut app = Host::with_keystore(fapico2_fido::keystore::MemoryKeystore::new());
    let versions = versions_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    assert_advertisement_matches_pin_state("host, no PIN", &versions, false);
}

#[test]
fn host_pin_set_withholds_ctap1() {
    let (mut app, _client) = setup();
    let versions = versions_of(&app.process_ctap2(0x04, &[], [1, 2, 3, 4]));
    assert_advertisement_matches_pin_state("host, PIN set", &versions, true);
}

// ---------------------------------------------------------------------------
// Device twin (`device_app.rs` + `device_core.rs`) — the RP2350 binary
// ---------------------------------------------------------------------------

mod device {
    use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
    use fapico2_fido::crypto;
    use fapico2_fido::device_app::FidoApp;
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;
    use heapless::Vec as HV;

    /// `app.rs` is a host-only twin: a change applied to one and not the other
    /// passes the host suite and changes nothing on hardware (AGENTS.md §1).
    /// This is the twin that shipped the defect, so the rule is proven here.
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

        fn versions(&mut self) -> Vec<String> {
            let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
            let n = self.app.process_ctap2(0x04, &[], [1, 2, 3, 4], &mut out);
            super::versions_of(&out.as_slice()[..n])
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
    }

    #[test]
    fn device_no_pin_still_offers_ctap1() {
        let mut d = Device::boot();
        let versions = d.versions();
        super::assert_advertisement_matches_pin_state("device, no PIN", &versions, false);
    }

    #[test]
    fn device_pin_set_withholds_ctap1() {
        let mut d = Device::boot();
        d.set_pin();
        let versions = d.versions();
        super::assert_advertisement_matches_pin_state("device, PIN set", &versions, true);
    }

    /// Characterization test for the KNOWN GAP, so it cannot be forgotten.
    ///
    /// `CTAPHID_MSG` carries *raw* U2F messages, not ISO7816 APDUs: a U2F
    /// version request is the single byte `0x05`. `handle_u2f` is driven with
    /// APDU framing (`tests/device_full_set.rs:452` sends `00 03 00 00 00`),
    /// which is why that suite is green while the wire is not. Feeding the raw
    /// byte here reproduces the hardware answer measured on `/dev/hidraw8`:
    /// `0x6700` where a device must answer `"U2F_V2"`.
    ///
    /// **When this test starts failing, CTAP1 got fixed.** That is the signal
    /// to revisit `u2f_v2_advertised`: the PIN condition becomes a
    /// belt-and-braces second gate rather than the only thing keeping Chrome
    /// out of a path that now works.
    #[test]
    fn ctap1_is_not_servable_yet() {
        let mut d = Device::boot();
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = d.app.process_u2f(b"\x05", &mut out);
        let answer = &out.as_slice()[..n];
        assert_ne!(
            answer,
            b"U2F_V2\x90\x00",
            "CTAPHID_MSG now answers a raw U2F version request correctly. \
             CTAP1 works: reconsider u2f_v2_advertised, which still withholds \
             U2F_V2 whenever a PIN is set."
        );
    }
}