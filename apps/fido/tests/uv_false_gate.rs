//! US-15xx regression: the `makeCredUvNotRqd: false` UV gate must hold for
//! **every** request shape, not just the ones it happens to like.
//!
//! The wire proof (real board, USB serial 94746395, PIN set, `alwaysUv`
//! false, `makeCredUvNotRqd` false, 2026-10-03, three separate processes
//! with ~35 s settle each per US-1510):
//!
//! | request                       | status                          |
//! |---|---|
//! | no `pinUvAuthParam`, `uv` absent | `0x36` PUAT_REQUIRED          |
//! | no `pinUvAuthParam`, `uv: false` | touch window armed, closed with `0x2D` KEEPALIVE_CANCEL after ~30 s |
//! | no `pinUvAuthParam`, `uv: true`  | `0x36` PUAT_REQUIRED          |
//!
//! The middle row is the bug. The old gate
//!
//! ```ignore
//! if pin_set && req.pin_uv_auth_param.is_none()
//!     && (!req.options_present || req.uv != Some(false)) { PuatRequired }
//! ```
//!
//! lifted its own condition for an explicit `uv: false`, so such a request
//! fell through to the presence gate and **armed the device for a touch with
//! no PIN verified** — exactly what the X.com reporter saw (a QR code in the
//! browser, then the key arming). It also contradicts the advertisement:
//! `makeCredUvNotRqd: false` means the device requires user verification for
//! makeCredential *“regardless of the parameters the platform supplies”*
//! (CTAP 2.1 §6.1.3, quoted at `ctap2.rs::make_cred_uv_not_rqd`).
//!
//! The fix drops the `uv` term: once a PIN is set, a `makeCredential` without
//! `pinUvAuthParam` is `0x36`, full stop. This matches the reference's
//! alwaysUv branch (`pico-fido/src/fido/cbor_make_credential.c:393-397`,
//! `pinUvAuthParam.present == false && options.uv != ptrue` →
//! `CTAP2_ERR_PUAT_REQUIRED`) and the advertisement, and it is a tightening:
//! the no-PIN path (`makeCredUvNotRqd: true`) still serves `uv: false`
//! without a token, which the last test pins so nobody "fixes" it into a
//! blanket refusal.
//!
//! Device path (`device_app::FidoApp` / `device_core.rs`) throughout, per
//! AGENTS.md §1 — `app.rs` is a host-only twin, and both copies are pinned
//! here because both carried the inverted term.

mod common;

use common::setup;

const PUAT_REQUIRED: u8 = 0x36;
const OK: u8 = 0x00;

// ---------------------------------------------------------------------------
// Device twin (`device_app.rs` + `device_core.rs`)
// ---------------------------------------------------------------------------

mod device {
    use fapico2_fido::cbor::no_heap::{self as nh, Item, Parser};
    use fapico2_fido::crypto;
    use fapico2_fido::device_app::FidoApp;
    use fapico2_platform::secure_store::HostSecureStore;
    use fapico2_platform::trng::HostTrng;
    use heapless::Vec as HV;

    /// Denied presence: with the gate fixed, the `uv: false` request must be
    /// refused *before* the presence gate is even consulted; with the gate
    /// regressed, the absence of a grant is what turns the armed touch
    /// window into a decided `0x3B` rather than a minted credential.
    /// (`with_user_presence` takes "is presence granted", so the injected
    /// source here answers `false` — always denied.)
    static GRANTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    fn never_granted() -> bool {
        GRANTED.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The injected source is process-global (`fn() -> bool` cannot
    /// capture), so every test holds this lock.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
                app: FidoApp::boot(&mut trng, &mut store)
                    .unwrap()
                    .with_user_presence(never_granted),
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
                    _ => p.skip().unwrap(),
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

    /// makeCredential with no `pinUvAuthParam` and an `options` map whose
    /// `uv` entry is absent (`None`), `false`, or `true`.
    pub fn mc_with_options(uv: Option<bool>) -> HV<u8, 512> {
        let mut r: HV<u8, 512> = HV::new();
        nh::push_map_header(&mut r, 6).unwrap();
        nh::push_uint(&mut r, 1).unwrap();
        nh::push_bstr(&mut r, &[0x11; 32]).unwrap(); // clientDataHash
        nh::push_uint(&mut r, 2).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_tstr(&mut r, "uv-gate.invalid").unwrap();
        nh::push_tstr(&mut r, "name").unwrap();
        nh::push_tstr(&mut r, "uv-gate.invalid").unwrap();
        nh::push_uint(&mut r, 3).unwrap();
        nh::push_map_header(&mut r, 1).unwrap();
        nh::push_tstr(&mut r, "id").unwrap();
        nh::push_bstr(&mut r, b"uv-gate-user").unwrap();
        nh::push_uint(&mut r, 4).unwrap();
        nh::push_array_header(&mut r, 1).unwrap();
        nh::push_map_header(&mut r, 2).unwrap();
        nh::push_tstr(&mut r, "type").unwrap();
        nh::push_tstr(&mut r, "public-key").unwrap();
        nh::push_tstr(&mut r, "alg").unwrap();
        nh::push_neg(&mut r, -7).unwrap();
        nh::push_uint(&mut r, 5).unwrap();
        nh::push_array_header(&mut r, 0).unwrap(); // excludeList
        nh::push_uint(&mut r, 7).unwrap(); // options
        match uv {
            None => nh::push_map_header(&mut r, 0).unwrap(),
            Some(v) => {
                nh::push_map_header(&mut r, 1).unwrap();
                nh::push_tstr(&mut r, "uv").unwrap();
                nh::push_bool(&mut r, v).unwrap();
            }
        }
        r
    }

    pub fn with_pin(mc: fn(Option<bool>) -> HV<u8, 512>, uv: Option<bool>) -> (u8, usize) {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut d = Device::boot();
        d.set_pin();
        let body = mc(uv);
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = d.app.process_ctap2(0x01, body.as_slice(), [1, 2, 3, 4], &mut out);
        let creds = d.app.keystore().credentials.len();
        assert_eq!(creds, 0, "a gated MC must not mint a credential");
        (out.as_slice()[0], n)
    }

    pub fn without_pin(mc: fn(Option<bool>) -> HV<u8, 512>, uv: Option<bool>) -> u8 {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut d = Device::boot();
        let body = mc(uv);
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        d.app.process_ctap2(0x01, body.as_slice(), [1, 2, 3, 4], &mut out);
        let status = out.as_slice()[0];
        assert_eq!(
            status,
            fapico2_fido::ctap2::Ctap2Response::UpRequired.code(),
            "no-PIN uv:false must reach the presence gate, not be minted blind"
        );
        assert_eq!(d.app.keystore().credentials.len(), 0);
        status
    }
}

/// Wire case 1: `uv` absent, PIN set, no `pinUvAuthParam` → `0x36`.
/// (Board evidence: 0x36.)
#[test]
fn device_pin_set_uv_absent_is_puat_required() {
    let (status, n) = device::with_pin(device::mc_with_options, None);
    assert_eq!(status, PUAT_REQUIRED, "no-options-map UV gate");
    assert_eq!(n, 1, "a gated MC carries no body");
}

/// Wire case 2 — THE bug. `uv: false`, PIN set, no `pinUvAuthParam` must be
/// `0x36` like every other token-less shape. Before the fix this skipped the
/// gate and armed a touch window (board evidence: 0x2D after the ~30 s
/// window closed; on the denied-presence fixture: `0x3B`).
#[test]
fn device_pin_set_uv_false_is_puat_required() {
    let (status, n) = device::with_pin(device::mc_with_options, Some(false));
    assert_eq!(
        status, PUAT_REQUIRED,
        "uv:false must not bypass the makeCredUvNotRqd:false gate — \
         the old gate let it arm a touch with no PIN verified"
    );
    assert_eq!(n, 1);
}

/// Wire case 3: `uv: true`, PIN set, no `pinUvAuthParam` → `0x36`.
/// (Board evidence: 0x36.)
#[test]
fn device_pin_set_uv_true_is_puat_required() {
    let (status, _) = device::with_pin(device::mc_with_options, Some(true));
    assert_eq!(status, PUAT_REQUIRED);
}

/// Scoping pin: with NO PIN set the same `uv: false` request is still served
/// up to the presence gate (`makeCredUvNotRqd` is `true` there — §6.1.3 only
/// forbids the bypass once the device is PIN-protected). This is what stops
/// the fix from becoming a blanket refusal for fresh devices.
#[test]
fn device_no_pin_uv_false_still_reaches_the_presence_gate() {
    device::without_pin(device::mc_with_options, Some(false));
}

// ---------------------------------------------------------------------------
// Host twin (`app.rs`) — the same gate, the same inversion, pinned too.
// ---------------------------------------------------------------------------

fn mc_host(uv: Option<bool>) -> Vec<u8> {
    device::mc_with_options(uv).as_slice().to_vec()
}

/// With the old gate this request MINTED A CREDENTIAL on the host twin
/// (presence auto-acks there), which is the same defect one level up.
#[test]
fn host_pin_set_uv_false_is_puat_required() {
    let (mut app, _client) = setup();
    // Pre-fix this request MINTED A CREDENTIAL on the host twin (0x00 — the
    // presence source auto-acks there), which is the same defect one level
    // up; the status byte alone is the assertion that catches it.
    let resp = app.process_ctap2(0x01, &mc_host(Some(false)), [1, 2, 3, 4]);
    assert_eq!(resp[0], PUAT_REQUIRED, "uv:false must not bypass the gate");
    assert_eq!(resp.len(), 1);
}

#[test]
fn host_pin_set_uv_absent_is_puat_required() {
    let (mut app, _client) = setup();
    assert_eq!(app.process_ctap2(0x01, &mc_host(None), [1, 2, 3, 4])[0], PUAT_REQUIRED);
}

#[test]
fn host_pin_set_uv_true_is_puat_required() {
    let (mut app, _client) = setup();
    assert_eq!(app.process_ctap2(0x01, &mc_host(Some(true)), [1, 2, 3, 4])[0], PUAT_REQUIRED);
}

#[test]
fn host_pin_set_token_still_mints() {
    // The path the advertisement redirects conforming clients to must keep
    // working: pinUvAuthParam present → OK (host presence auto-acks), with a
    // full attestation object (the credential was actually minted).
    let (mut app, client) = setup();
    let token: [u8; 32] = client
        .get_token(&mut app, 0x09, Some(0x01), None)
        .unwrap()
        .try_into()
        .expect("32-byte token");
    let hash = [0x5au8; 32];
    let param = fapico2_fido::crypto::pin_uv_auth_param(2, &token, &hash);
    let req = fapico2_fido::cbor::encode(&fapico2_fido::cbor::Value::M(vec![
        (fapico2_fido::cbor::Value::U(1), fapico2_fido::cbor::Value::B(hash.to_vec())),
        (
            fapico2_fido::cbor::Value::U(2),
            fapico2_fido::cbor::Value::M(vec![
                (fapico2_fido::cbor::Value::T("id".into()), fapico2_fido::cbor::Value::T("uv-gate.invalid".into())),
                (fapico2_fido::cbor::Value::T("name".into()), fapico2_fido::cbor::Value::T("uv-gate.invalid".into())),
            ]),
        ),
        (
            fapico2_fido::cbor::Value::U(3),
            fapico2_fido::cbor::Value::M(vec![
                (fapico2_fido::cbor::Value::T("id".into()), fapico2_fido::cbor::Value::B(b"uv-gate-user".to_vec())),
            ]),
        ),
        (
            fapico2_fido::cbor::Value::U(4),
            fapico2_fido::cbor::Value::A(vec![fapico2_fido::cbor::Value::M(vec![
                (fapico2_fido::cbor::Value::T("type".into()), fapico2_fido::cbor::Value::T("public-key".into())),
                (fapico2_fido::cbor::Value::T("alg".into()), fapico2_fido::cbor::Value::N(-7)),
            ])]),
        ),
        (fapico2_fido::cbor::Value::U(5), fapico2_fido::cbor::Value::A(vec![])),
        (fapico2_fido::cbor::Value::U(6), fapico2_fido::cbor::Value::M(vec![])),
        (fapico2_fido::cbor::Value::U(8), fapico2_fido::cbor::Value::B(param)),
        (fapico2_fido::cbor::Value::U(9), fapico2_fido::cbor::Value::U(2)),
    ]));
    let resp = app.process_ctap2(0x01, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], OK, "pinUvAuthParam path must keep minting");
    assert!(resp.len() > 100, "success carries an attestation object, got {}B", resp.len());
}
