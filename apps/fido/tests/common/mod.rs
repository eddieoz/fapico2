//! Shared CTAP2 client helpers for the fapico2-fido integration tests.

use fapico2_fido::app::FidoApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::crypto;
use fapico2_fido::keystore::{Keystore, MemoryKeystore};

pub const PIN: &str = "1234";

/// A minimal CTAP2 client driving the clientPin subcommands over
/// `process_ctap2`, holding the shared secret state.
pub struct PinClient {
    /// Uncompressed SEC1 public key (65 bytes, 0x04 prefix).
    client_pub_sec1: [u8; 65],
    /// Shared-secret HMAC key (client side, protocol v2).
    pub hmac_key: [u8; 32],
    /// Shared-secret encryption key (client side, protocol v2).
    pub enc_key: [u8; 32],
}

/// Label order of a serialised COSE key map.
///
/// CTAP 2.1 / RFC 8152 present COSE keys in ascending label order
/// (1, 3, -1, -2, -3). Some PicoForge maps are instead built with a
/// `BTreeMap`, which emits -3, -2, -1, 1, 3. Both are legal CBOR and the
/// authenticator must accept both (US-120).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // shared helper: not every test binary uses every one
pub enum CoseKeyOrder {
    /// Ascending: 1, 3, -1, -2, -3.
    Canonical,
    /// `BTreeMap` order: -3, -2, -1, 1, 3.
    NonCanonical,
}

/// The canonical, spec-conformant COSE key-agreement map: `alg` =
/// `COSE_ALG_ECDH_ES_HKDF_256` (-25), ascending label order.
pub fn cose_key_map(x: &[u8], y: &[u8]) -> Value {
    cose_key_map_with(
        x,
        y,
        i64::from(fapico2_fido::COSE_ALG_ECDH_ES_HKDF_256),
        CoseKeyOrder::Canonical,
    )
}

/// A COSE key-agreement map with an explicit `alg` and label order.
///
/// US-120 — see the rationale at `fapico2_fido::COSE_ALG_ES256`.
///
/// NOTE: [`cbor::encode`] sorts map keys, so this builder can only ever
/// reach the wire in [`CoseKeyOrder::Canonical`]. Use [`push_key_agreement`]
/// when the on-wire label order is what the test is about.
pub fn cose_key_map_with(x: &[u8], y: &[u8], alg: i64, order: CoseKeyOrder) -> Value {
    let kty = (Value::U(1), Value::U(2));
    let alg = (Value::U(3), Value::N(alg));
    let crv = (Value::N(-1), Value::U(1));
    let cx = (Value::N(-2), Value::B(x.to_vec()));
    let cy = (Value::N(-3), Value::B(y.to_vec()));
    let pairs = match order {
        CoseKeyOrder::Canonical => vec![kty, alg, crv, cx, cy],
        CoseKeyOrder::NonCanonical => vec![cy, cx, crv, kty, alg],
    };
    Value::M(pairs)
}

/// One COSE label paired with the closure that writes its value, in a
/// no-heap output buffer of capacity `N`.
type CoseLabelPair<'a, const N: usize> = (i64, &'a dyn Fn(&mut heapless::Vec<u8, N>));

/// Byte-level (`cbor::no_heap`) encoder for the same map.
///
/// Unlike [`cose_key_map_with`] this does **not** go through [`cbor::encode`],
/// so the labels reach the wire in exactly the order given. That is the only
/// way to exercise the label-order tolerance of either key-agreement parser
/// (US-120), and it works on both twins: the host parser runs off decoded
/// bytes, the device one (`device_core::parse_key_agreement`) off the same
/// no-heap writer.
#[allow(dead_code)] // shared helper: not every test binary uses every one
pub fn push_key_agreement<const N: usize>(
    out: &mut heapless::Vec<u8, N>,
    x: &[u8],
    y: &[u8],
    alg: i64,
    order: CoseKeyOrder,
) {
    use fapico2_fido::cbor::no_heap as nh;
    let push_label = |out: &mut heapless::Vec<u8, N>, label: i64| {
        if label > 0 {
            nh::push_uint(out, label as u64).unwrap();
        } else {
            nh::push_neg(out, label).unwrap();
        }
    };
    let kty = |out: &mut heapless::Vec<u8, N>| nh::push_uint(out, 2).unwrap();
    let alg_v = |out: &mut heapless::Vec<u8, N>| nh::push_neg(out, alg).unwrap();
    let crv = |out: &mut heapless::Vec<u8, N>| nh::push_uint(out, 1).unwrap();
    let cx = |out: &mut heapless::Vec<u8, N>| nh::push_bstr(out, x).unwrap();
    let cy = |out: &mut heapless::Vec<u8, N>| nh::push_bstr(out, y).unwrap();
    let pairs: [CoseLabelPair<'_, N>; 5] = match order {
        CoseKeyOrder::Canonical => [(1, &kty), (3, &alg_v), (-1, &crv), (-2, &cx), (-3, &cy)],
        CoseKeyOrder::NonCanonical => [(-3, &cy), (-2, &cx), (-1, &crv), (1, &kty), (3, &alg_v)],
    };
    nh::push_map_header(out, 5).unwrap();
    for (label, value) in pairs {
        push_label(out, label);
        value(out);
    }
}

pub fn parse_resp(data: &[u8]) -> Value {
    assert_eq!(data[0], 0x00, "clientPin command must succeed");
    let (v, _) = cbor::decode(&data[1..]).expect("valid CBOR response");
    v
}

/// clientPin getKeyAgreement (0x02) → the authenticator's peer COSE key.
///
/// The status byte is asserted to be `0x00` and the response is decoded, so
/// callers that only need the coordinates can ignore the return value.
#[allow(dead_code)] // shared helper: not every test binary uses every one
pub fn peer_cose_key<K: Keystore>(app: &mut FidoApp<K>) -> Value {
    let req = cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(2)),
        (Value::U(0x02), Value::U(0x02)),
    ]));
    let resp = app.process_ctap2(0x06, &req, [1, 2, 3, 4]);
    assert_eq!(resp[0], 0x00, "getKeyAgreement must succeed");
    match parse_resp(&resp) {
        Value::M(m) => m
            .iter()
            .find(|(k, _)| matches!(k, Value::U(1)))
            .map(|(_, v)| v.clone())
            .expect("keyAgreement in response"),
        other => panic!("expected map, got {:?}", other),
    }
}

impl PinClient {
    pub fn new<K: Keystore>(app: &mut FidoApp<K>) -> Self {
        let key = peer_cose_key(app);
        let (x, y) = match &key {
            Value::M(m) => {
                let get = |key: i64| -> Vec<u8> {
                    m.iter()
                        .find(|(k, _)| matches!(k, Value::N(n) if *n == key))
                        .map(|(_, v)| match v {
                            Value::B(b) => b.clone(),
                            _ => panic!("bstr expected"),
                        })
                        .expect("coordinate present")
                };
                (get(-2), get(-3))
            }
            _ => panic!("expected COSE key map"),
        };
        let server_pub = crypto::parse_cose_ec2_p256(&x, &y).expect("valid server pubkey");

        let (client_secret, client_public) = crypto::generate_p256_keypair();
        let raw = crypto::ecdh_shared_secret(&client_secret, &server_pub);
        let mut shared = [0u8; 64];
        crypto::hkdf_sha256(None, &raw, b"CTAP2 HMAC key", &mut shared[..32]);
        crypto::hkdf_sha256(None, &raw, b"CTAP2 AES key", &mut shared[32..]);
        let mut hmac_key = [0u8; 32];
        let mut enc_key = [0u8; 32];
        hmac_key.copy_from_slice(&shared[..32]);
        enc_key.copy_from_slice(&shared[32..]);
        let pt = crypto::public_key_bytes(&client_public);
        Self {
            client_pub_sec1: pt,
            hmac_key,
            enc_key,
        }
    }

    /// The client's key-agreement map: the canonical one (alg = -25,
    /// ascending labels).
    pub fn client_cose(&self) -> Value {
        let (x, y) = self.client_coords();
        cose_key_map(&x, &y)
    }

    /// The client's public-key coordinates (x‖y halves of its SEC1 key).
    fn client_coords(&self) -> ([u8; 32], [u8; 32]) {
        let x: [u8; 32] = self.client_pub_sec1[1..33].try_into().unwrap();
        let y: [u8; 32] = self.client_pub_sec1[33..65].try_into().unwrap();
        (x, y)
    }

    /// setPIN (0x03) with an explicit key-agreement `alg` and label order.
    /// Returns the CTAP2 status byte.
    ///
    /// The request is hand-encoded with the no-heap writer ([`push_key_agreement`])
    /// rather than [`cbor::encode`], which sorts map keys and would silently
    /// normalise every request back to the canonical label order — leaving
    /// the ordering half of the US-120 contract untested.
    #[allow(dead_code)] // shared helper: not every test binary uses every one
    pub fn set_pin_with_cose<K: Keystore>(
        &self,
        app: &mut FidoApp<K>,
        alg: i64,
        order: CoseKeyOrder,
    ) -> u8 {
        use fapico2_fido::cbor::no_heap as nh;
        let (x, y) = self.client_coords();
        let mut new_pin = PIN.as_bytes().to_vec();
        new_pin.push(0);
        new_pin.resize(64, 0);
        let new_pin_enc = crypto::pin_encrypt(2, &self.enc_key, &new_pin);
        let auth_param = crypto::pin_uv_auth_param(2, &self.hmac_key, &new_pin_enc);
        let mut req: heapless::Vec<u8, 256> = heapless::Vec::new();
        nh::push_map_header(&mut req, 5).unwrap();
        // 1: pinUvAuthProtocol = 2 (v2 — the host stack's default here).
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        // 2: subcommand = setPIN.
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        // 3: the client's key-agreement map.
        nh::push_uint(&mut req, 3).unwrap();
        push_key_agreement(&mut req, &x, &y, alg, order);
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &auth_param).unwrap();
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_bstr(&mut req, &new_pin_enc).unwrap();
        app.process_ctap2(0x06, req.as_slice(), [1, 2, 3, 4])[0]
    }

    pub fn set_pin<K: Keystore>(&self, app: &mut FidoApp<K>) {
        let mut new_pin = PIN.as_bytes().to_vec();
        new_pin.push(0);
        new_pin.resize(64, 0);
        let new_pin_enc = crypto::pin_encrypt(2, &self.enc_key, &new_pin);
        let auth_param = crypto::pin_uv_auth_param(2, &self.hmac_key, &new_pin_enc);
        let req = cbor::encode(&Value::M(vec![
            (Value::U(0x01), Value::U(2)),
            (Value::U(0x02), Value::U(0x03)),
            (Value::U(0x03), self.client_cose()),
            (Value::U(0x04), Value::B(auth_param)),
            (Value::U(0x05), Value::B(new_pin_enc)),
        ]));
        let resp = app.process_ctap2(0x06, &req, [1, 2, 3, 4]);
        assert_eq!(resp[0], 0x00, "setPIN must succeed");
    }

    /// getPinToken (0x05) or getPinUvAuthTokenUsingPinWithPermissions (0x09).
    /// Returns the raw 32-byte token.
    ///
    /// `dead_code` is allowed because `tests/common/` is compiled into *every*
    /// test binary in this crate and a shared helper is not called by all of
    /// them. The clippy gate in `run_tests.sh` runs `--all-targets -D
    /// warnings`, so a helper only `pin_perms.rs` calls is dead in
    /// `pin_uv_advert.rs` — a gate failure, not a defect.
    #[allow(dead_code)]
    pub fn get_token<K: Keystore>(
        &self,
        app: &mut FidoApp<K>,
        subcommand: u8,
        permissions: Option<u8>,
        rpid: Option<&str>,
    ) -> Result<Vec<u8>, u8> {
        let pin_hash = crypto::pin_hash(PIN.as_bytes());
        let pin_hash_enc = crypto::pin_encrypt(2, &self.enc_key, &pin_hash);
        let mut map = vec![
            (Value::U(0x01), Value::U(2)),
            (Value::U(0x02), Value::U(subcommand as u64)),
            (Value::U(0x03), self.client_cose()),
            (Value::U(0x06), Value::B(pin_hash_enc)),
        ];
        if let Some(p) = permissions {
            map.push((Value::U(0x09), Value::U(p as u64)));
        }
        if let Some(rp) = rpid {
            map.push((Value::U(0x0A), Value::T(rp.to_string())));
        }
        let req = cbor::encode(&Value::M(map));
        let resp = app.process_ctap2(0x06, &req, [1, 2, 3, 4]);
        if resp[0] != 0x00 {
            return Err(resp[0]);
        }
        let (v, _) = cbor::decode(&resp[1..]).expect("valid CBOR response");
        let enc_token = match &v {
            Value::M(m) => m
                .iter()
                .find(|(k, _)| matches!(k, Value::U(2)))
                .map(|(_, v)| match v {
                    Value::B(b) => b.clone(),
                    _ => panic!("bstr token expected"),
                })
                .expect("pinToken in response"),
            _ => panic!("expected map"),
        };
        let raw = crypto::pin_decrypt(2, &self.enc_key, &enc_token).expect("token decrypts");
        Ok(raw)
    }
}

#[allow(dead_code)] // shared helpers: not every test binary uses every one
pub fn pin_uv_auth(token: &[u8], data: &[u8]) -> Vec<u8> {
    crypto::pin_uv_auth_param(2, token.try_into().unwrap(), data)
}

#[allow(dead_code)] // shared helpers: not every test binary uses every one
pub fn make_mc_request(hash: &[u8; 32], rp_id: &str, token: &[u8]) -> Vec<u8> {
    make_mc_request_alg(hash, rp_id, token, -7)
}

/// [`make_mc_request`] with an explicit COSE `alg` in the key parameters.
///
/// ES256 (`-7`) remains the default so every existing caller is unchanged.
/// The parameterisation exists because the four advertised curves fail key
/// generation for different reasons and only a per-curve test can tell those
/// apart — see the P-521 regression test in `keygen.rs`.
#[allow(dead_code)]
pub fn make_mc_request_alg(hash: &[u8; 32], rp_id: &str, token: &[u8], alg: i64) -> Vec<u8> {
    cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::B(hash.to_vec())),
        (
            Value::U(0x02),
            Value::M(vec![
                (Value::T("id".to_string()), Value::T(rp_id.to_string())),
                (Value::T("name".to_string()), Value::T("RP".to_string())),
            ]),
        ),
        (
            Value::U(0x03),
            Value::M(vec![
                (Value::T("id".to_string()), Value::B(b"user".to_vec())),
                (Value::T("name".to_string()), Value::T("U".to_string())),
            ]),
        ),
        (
            Value::U(0x04),
            Value::A(vec![Value::M(vec![
                (Value::T("type".to_string()), Value::T("public-key".to_string())),
                (Value::T("alg".to_string()), Value::N(alg)),
            ])]),
        ),
        (Value::U(0x08), Value::B(pin_uv_auth(token, hash))),
        (Value::U(0x09), Value::U(2)),
    ]))
}

#[allow(dead_code)] // shared helpers: not every test binary uses every one
pub fn make_ga_request(hash: &[u8; 32], rp_id: &str, token: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::T(rp_id.to_string())),
        (Value::U(0x02), Value::B(hash.to_vec())),
        (Value::U(0x06), Value::B(pin_uv_auth(token, hash))),
        (Value::U(0x07), Value::U(2)),
    ]))
}

#[allow(dead_code)] // shared helpers: not every test binary uses every one
pub fn make_cm_request(subcommand: u8, token: &[u8]) -> Vec<u8> {
    let auth_data: Vec<u8> = vec![subcommand];
    cbor::encode(&Value::M(vec![
        (Value::U(0x01), Value::U(subcommand as u64)),
        (Value::U(0x03), Value::U(2)),
        (
            Value::U(0x04),
            Value::B(pin_uv_auth(token, &auth_data)),
        ),
    ]))
}


/// Fresh app + PIN-configured client.
#[allow(dead_code)] // shared helper: not every test binary uses it
pub fn setup() -> (FidoApp<MemoryKeystore>, PinClient) {
    let mut app = FidoApp::with_keystore(MemoryKeystore::new());
    let client = PinClient::new(&mut app);
    client.set_pin(&mut app);
    (app, client)
}
