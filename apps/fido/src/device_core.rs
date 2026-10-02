//! No-heap CTAP2 core command path for the device (S-701-4, US-324):
//! makeCredential, getAssertion (+ getNextAssertion), clientPin (v1+v2) and
//! Reset, implemented over the [`DeviceKeystore`] and the no-heap CBOR /
//! crypto layers.
//!
//! The host tests in `apps/fido/tests/device_core_mc_ga.rs` drive **this**
//! code through `FidoApp::process_ctap2` — the same handler code the RP2350
//! serve loop runs. There are no `#[cfg]` forks in the command path.

use crate::cbor::no_heap::{self, Item, Parser};
use crate::crypto;
use crate::device_app::FidoApp;
use crate::device_keystore::{DeviceCoseKey, DeviceCredential, DEVICE_MAX_CREDS};
use crate::ctap2::Ctap2Response;
use crate::stateless;
use crate::{AAGUID, CTAP1_VERSION};
use fapico2_platform::secure_store::SecureStore;
use fapico2_platform::trng::Trng;
use heapless::Vec as HeaplessVec;

/// pinUvAuthPermission bits (host `app.rs` parity).
pub const PERM_MC: u8 = 0x01;
pub const PERM_GA: u8 = 0x02;
pub const PERM_CM: u8 = 0x04;
pub const PERM_BE: u8 = 0x08;
pub const PERM_LBF: u8 = 0x10;
pub const PERM_ACFG: u8 = 0x20;
pub const PERM_CM_PERSISTENT: u8 = 0x40;

const MAX_PIN_RETRIES: u8 = 8;
/// Maximum RP-ID / name text bytes accepted in requests.
const TEXT_MAX: usize = 64;

type Err = u8;

fn err(code: Ctap2Response) -> Err {
    code.code()
}

/// Fixed-size scratch buffer for decrypted PIN material that is wiped
/// (zero-filled) when dropped, so early error returns never leave plaintext
/// PIN bytes on the stack (US-703).
struct PinScratch([u8; 96]);

impl PinScratch {
    fn new() -> Self {
        PinScratch([0u8; 96])
    }
}

impl core::ops::Deref for PinScratch {
    type Target = [u8; 96];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for PinScratch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for PinScratch {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// hmac-secret input map (CTAP2.1 §6.7): {1: keyAgreement, 2: saltEnc,
/// 3: saltAuth, 4: pinUvAuthProtocol}.
#[derive(Debug, Clone)]
pub struct HmacSecretInput {
    /// Raw x||y halves of the client key-agreement public key.
    pub key_agreement: [u8; 64],
    pub salt_enc: HeaplessVec<u8, 80>,
    pub salt_auth: HeaplessVec<u8, 64>,
    pub protocol: u8,
}

/// Parsed makeCredential request (fixed-size).
pub struct McReq {
    pub client_data_hash: [u8; 32],
    pub rp_id: HeaplessVec<u8, TEXT_MAX>,
    pub user_handle: HeaplessVec<u8, 64>,
    pub user_name: HeaplessVec<u8, TEXT_MAX>,
    pub user_display_name: HeaplessVec<u8, TEXT_MAX>,
    /// Requested algorithms (only type=="public-key" params).
    pub algs: HeaplessVec<i32, 8>,
    pub exclude: HeaplessVec<HeaplessVec<u8, 64>, 8>,
    pub options_present: bool,
    pub rk: Option<bool>,
    pub up: Option<bool>,
    pub uv: Option<bool>,
    pub pin_uv_auth_param: Option<HeaplessVec<u8, 64>>,
    pub pin_uv_protocol: u8,
    pub cred_protect: u8,
    pub cred_blob: Option<HeaplessVec<u8, 32>>,
    pub hmac_secret: bool,
    pub hmac_secret_mc: Option<HmacSecretInput>,
    pub large_blob_key: bool,
    pub min_pin_length: bool,
    pub third_party_payment: bool,
}

/// Parsed getAssertion request (fixed-size).
pub struct GaReq {
    pub rp_id: HeaplessVec<u8, TEXT_MAX>,
    pub client_data_hash: [u8; 32],
    pub allow: HeaplessVec<HeaplessVec<u8, 64>, 8>,
    pub up: Option<bool>,
    pub uv: Option<bool>,
    pub pin_uv_auth_param: Option<HeaplessVec<u8, 64>>,
    pub pin_uv_protocol: u8,
    pub hmac_secret_input: Option<HmacSecretInput>,
    pub get_cred_blob: bool,
    pub large_blob_key: bool,
    pub third_party_payment: bool,
}

/// Count Unicode codepoints (non-continuation bytes in UTF-8).
fn count_codepoints(data: &[u8]) -> usize {
    data.iter().filter(|&&b| (b & 0xC0) != 0x80).count()
}

/// Parse a COSE EC2 key-agreement map {1: kty, 3: alg, -1: crv, -2: x, -3: y}
/// from the request stream (consumed inline). Returns x||y.
///
/// Every label is matched by value in the loop, so map order is irrelevant,
/// and every non-coordinate label — `alg` (3) included — falls into the skip
/// arm below. Both are deliberate; see the US-120 rationale at
/// `crate::COSE_ALG_ES256`.
fn parse_key_agreement(p: &mut Parser<'_>) -> Option<[u8; 64]> {
    let Item::Map(n) = p.next().ok()? else { return None };
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let mut have = false;
    for _ in 0..n {
        let key = match p.next().ok()? {
            Item::U(u) => u as i64,
            Item::N(n) => n,
            _ => return None,
        };
        match key {
            -2 => match p.next().ok()? {
                Item::B(b) if b.len() == 32 => {
                    x.copy_from_slice(b);
                    have = true;
                }
                _ => return None,
            },
            -3 => match p.next().ok()? {
                Item::B(b) if b.len() == 32 => y.copy_from_slice(b),
                _ => return None,
            },
            _ => p.skip().ok()?,
        }
    }
    have.then_some([x, y].concat_into())
}

/// Extension helper: concatenate the two 32-byte halves into a 64-byte array
/// without allocating.
trait Concat64 {
    fn concat_into(self) -> [u8; 64];
}
impl Concat64 for [[u8; 32]; 2] {
    fn concat_into(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self[0]);
        out[32..].copy_from_slice(&self[1]);
        out
    }
}

/// Parse the hmac-secret input map {1: keyAgreement, 2: saltEnc, 3: saltAuth,
/// 4: pinUvAuthProtocol} (consumed inline).
fn parse_hmac_secret_input(p: &mut Parser<'_>) -> Option<HmacSecretInput> {
    let Item::Map(n) = p.next().ok()? else { return None };
    let mut hs = HmacSecretInput {
        key_agreement: [0; 64],
        salt_enc: HeaplessVec::new(),
        salt_auth: HeaplessVec::new(),
        protocol: 1,
    };
    for _ in 0..n {
        let key = match p.next().ok()? {
            Item::U(u) => u,
            _ => return None,
        };
        match key {
            1 => hs.key_agreement = parse_key_agreement(p)?,
            2 => match p.next().ok()? {
                Item::B(b) => hs.salt_enc.extend_from_slice(b).ok()?,
                _ => return None,
            },
            3 => match p.next().ok()? {
                Item::B(b) => hs.salt_auth.extend_from_slice(b).ok()?,
                _ => return None,
            },
            4 => match p.next().ok()? {
                Item::U(u) => hs.protocol = u as u8,
                _ => return None,
            },
            _ => p.skip().ok()?,
        }
    }
    Some(hs)
}

/// Parse a makeCredential request (CTAP2.1 §6.1 key numbering: 1
/// clientDataHash, 2 rp, 3 user, 4 pubKeyCredParams, 5 excludeList,
/// 6 extensions, 7 options, 8 pinUvAuthParam, 9 pinUvAuthProtocol).
pub fn parse_mc(data: &[u8]) -> Result<McReq, Err> {
    if data.is_empty() {
        return Err(err(Ctap2Response::MissingParameter));
    }
    let mut r = McReq {
        client_data_hash: [0; 32],
        rp_id: HeaplessVec::new(),
        user_handle: HeaplessVec::new(),
        user_name: HeaplessVec::new(),
        user_display_name: HeaplessVec::new(),
        algs: HeaplessVec::new(),
        exclude: HeaplessVec::new(),
        options_present: false,
        rk: None,
        up: None,
        uv: None,
        pin_uv_auth_param: None,
        pin_uv_protocol: 2,
        cred_protect: 0,
        cred_blob: None,
        hmac_secret: false,
        hmac_secret_mc: None,
        large_blob_key: false,
        min_pin_length: false,
        third_party_payment: false,
    };
    let mut p = Parser::new(data);
    let mut has_cdh = false;
    let Item::Map(n) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
        return Err(err(Ctap2Response::InvalidCbor));
    };
    for _ in 0..n {
        let key = match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
            Item::U(k) => k,
            _ => return Err(err(Ctap2Response::InvalidCbor)),
        };
        match key {
            1 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                Item::B(b) if b.len() == 32 => {
                    r.client_data_hash.copy_from_slice(b);
                    has_cdh = true;
                }
                Item::B(_) => return Err(err(Ctap2Response::InvalidLength)),
                _ => return Err(err(Ctap2Response::InvalidCbor)),
            },
            2 => {
                // rp: map { "id": tstr, "name"?: tstr }
                let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..m {
                    match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::T("id") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::T(s) => {
                                if r.rp_id.extend_from_slice(s.as_bytes()).is_err() {
                                    return Err(err(Ctap2Response::InvalidLength));
                                }
                            }
                            _ => return Err(err(Ctap2Response::InvalidCbor)),
                        },
                        Item::T("name") => {
                            p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?;
                        }
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                    }
                }
            }
            3 => {
                // user: map { "id": bstr, "name"?, "displayName"? }
                let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..m {
                    match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::T("id") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::B(b) => {
                                if r.user_handle.extend_from_slice(b).is_err() {
                                    return Err(err(Ctap2Response::InvalidLength));
                                }
                            }
                            _ => return Err(err(Ctap2Response::InvalidCbor)),
                        },
                        Item::T("name") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::T(s) => {
                                let _ = r.user_name.extend_from_slice(s.as_bytes());
                            }
                            _ => return Err(err(Ctap2Response::InvalidCbor)),
                        },
                        Item::T("displayName") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::T(s) => {
                                let _ = r.user_display_name.extend_from_slice(s.as_bytes());
                            }
                            _ => return Err(err(Ctap2Response::InvalidCbor)),
                        },
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                    }
                }
            }
            4 => {
                let Item::Array(a) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..a {
                    let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                        return Err(err(Ctap2Response::InvalidCbor));
                    };
                    let mut type_ok = false;
                    let mut alg: Option<i32> = None;
                    for _ in 0..m {
                        match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::T("type") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::T(s) => type_ok = s == "public-key",
                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                            },
                            Item::T("alg") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::N(n) => alg = Some(n as i32),
                                Item::U(u) => alg = Some(u as i32),
                                _ => return Err(err(Ctap2Response::CborUnexpectedType)),
                            },
                            _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                        }
                    }
                    if !type_ok {
                        continue;
                    }
                    if r.algs.push(alg.unwrap_or(0)).is_err() {
                        return Err(err(Ctap2Response::LimitExceeded));
                    }
                }
                if r.algs.is_empty() {
                    return Err(err(Ctap2Response::MissingParameter));
                }
            }
            5 => {
                let Item::Array(a) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..a {
                    let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                        return Err(err(Ctap2Response::InvalidCbor));
                    };
                    let mut id: HeaplessVec<u8, 64> = HeaplessVec::new();
                    let mut type_ok = false;
                    for _ in 0..m {
                        match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::T("type") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::T(s) => type_ok = s == "public-key",
                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                            },
                            Item::T("id") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::B(b) => {
                                    if id.extend_from_slice(b).is_err() {
                                        return Err(err(Ctap2Response::InvalidLength));
                                    }
                                }
                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                            },
                            _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                        }
                    }
                    if type_ok && !id.is_empty() && r.exclude.push(id).is_err() {
                        return Err(err(Ctap2Response::LimitExceeded));
                    }
                }
            }
            6 => {
                let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..m {
                    match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::T("thirdPartyPayment") => {
                            r.third_party_payment = matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            );
                        }
                        Item::T("minPinLength") => {
                            r.min_pin_length = matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            );
                        }
                        Item::T("credBlob") => {
                            if let Item::B(b) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                let mut blob = HeaplessVec::new();
                                if blob.extend_from_slice(b).is_ok() {
                                    r.cred_blob = Some(blob);
                                } else {
                                    r.cred_blob = None;
                                }
                            }
                        },
                        Item::T("hmac-secret") => {
                            r.hmac_secret = matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            );
                        }
                        Item::T("hmac-secret-mc") => {
                            r.hmac_secret_mc =
                                parse_hmac_secret_input(&mut p).filter(|hs| hs.protocol == 1 || hs.protocol == 2);
                            if r.hmac_secret_mc.is_none() {
                                return Err(err(Ctap2Response::InvalidParameter));
                            }
                        }
                        Item::T("largeBlobKey") => {
                            r.large_blob_key = matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            );
                        }
                        Item::T("credentialProtectionPolicy") | Item::T("credProtect") => {
                            r.cred_protect = match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::U(u) if u <= 3 => u as u8,
                                Item::N(n) if (1..=3).contains(&n) => n as u8,
                                Item::Bool(true) => 1,
                                Item::U(_) | Item::N(_) => return Err(err(Ctap2Response::InvalidParameter)),
                                _ => 0,
                            };
                        }
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                    }
                }
            }
            7 => {
                r.options_present = true;
                let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..m {
                    match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::T("rk") => {
                            r.rk = Some(matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            ));
                        }
                        Item::T("up") => {
                            r.up = Some(matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            ));
                        }
                        Item::T("uv") => {
                            r.uv = Some(matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            ));
                        }
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                    }
                }
            }
            8 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                Item::B(b) => {
                    let mut param = HeaplessVec::new();
                    if param.extend_from_slice(b).is_err() {
                        return Err(err(Ctap2Response::InvalidLength));
                    }
                    r.pin_uv_auth_param = Some(param);
                }
                _ => return Err(err(Ctap2Response::InvalidCbor)),
            },
            9 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                Item::U(u) => r.pin_uv_protocol = u as u8,
                _ => return Err(err(Ctap2Response::InvalidCbor)),
            },
            _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
        }
    }
    if !has_cdh || r.rp_id.is_empty() || r.algs.is_empty() {
        return Err(err(Ctap2Response::MissingParameter));
    }
    Ok(r)
}

/// Parse a getAssertion request (§6.2: 1 rpId, 2 clientDataHash, 3 allowList,
/// 4 extensions, 5 options, 6 pinUvAuthParam, 7 pinUvAuthProtocol).
pub fn parse_ga(data: &[u8]) -> Result<GaReq, Err> {
    if data.is_empty() {
        return Err(err(Ctap2Response::MissingParameter));
    }
    let mut r = GaReq {
        rp_id: HeaplessVec::new(),
        client_data_hash: [0; 32],
        allow: HeaplessVec::new(),
        up: None,
        uv: None,
        pin_uv_auth_param: None,
        pin_uv_protocol: 2,
        hmac_secret_input: None,
        get_cred_blob: false,
        large_blob_key: false,
        third_party_payment: false,
    };
    let mut p = Parser::new(data);
    let Item::Map(n) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
        return Err(err(Ctap2Response::InvalidCbor));
    };
    for _ in 0..n {
        let key = match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
            Item::U(k) => k,
            _ => return Err(err(Ctap2Response::InvalidCbor)),
        };
        match key {
            1 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                Item::T(s) => {
                    if r.rp_id.extend_from_slice(s.as_bytes()).is_err() {
                        return Err(err(Ctap2Response::InvalidLength));
                    }
                }
                _ => return Err(err(Ctap2Response::InvalidCbor)),
            },
            2 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                Item::B(b) if b.len() == 32 => r.client_data_hash.copy_from_slice(b),
                _ => return Err(err(Ctap2Response::InvalidCbor)),
            },
            3 => {
                let Item::Array(a) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..a {
                    let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                        return Err(err(Ctap2Response::InvalidCbor));
                    };
                    let mut id: HeaplessVec<u8, 64> = HeaplessVec::new();
                    let mut type_ok = false;
                    for _ in 0..m {
                        match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::T("type") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::T(s) => type_ok = s == "public-key",
                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                            },
                            Item::T("id") => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::B(b) => {
                                    if id.extend_from_slice(b).is_err() {
                                        return Err(err(Ctap2Response::InvalidLength));
                                    }
                                }
                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                            },
                            _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                        }
                    }
                    if type_ok && r.allow.push(id).is_err() {
                        return Err(err(Ctap2Response::LimitExceeded));
                    }
                }
            }
            4 => {
                let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..m {
                    match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::T("hmac-secret") => {
                            // GA hmac-secret input: a map (CTAP2.1 §6.7).
                            match parse_hmac_secret_input(&mut p) {
                                Some(hs) if hs.protocol == 1 || hs.protocol == 2 => {
                                    r.hmac_secret_input = Some(hs);
                                }
                                _ => return Err(err(Ctap2Response::InvalidParameter)),
                            }
                        }
                        Item::T("credBlob") => {
                            r.get_cred_blob = matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            );
                        }
                        Item::T("largeBlobKey") => {
                            r.large_blob_key = matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            );
                        }
                        Item::T("thirdPartyPayment") => {
                            r.third_party_payment = matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            );
                        }
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                    }
                }
            }
            5 => {
                let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                    return Err(err(Ctap2Response::InvalidCbor));
                };
                for _ in 0..m {
                    match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::T("up") => {
                            r.up = Some(matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            ));
                        }
                        Item::T("uv") => {
                            r.uv = Some(matches!(
                                p.next().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                Item::Bool(true)
                            ));
                        }
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                    }
                }
            }
            6 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                Item::B(b) => {
                    let mut param = HeaplessVec::new();
                    if param.extend_from_slice(b).is_err() {
                        return Err(err(Ctap2Response::InvalidLength));
                    }
                    r.pin_uv_auth_param = Some(param);
                }
                _ => return Err(err(Ctap2Response::InvalidCbor)),
            },
            7 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                Item::U(u) => r.pin_uv_protocol = u as u8,
                _ => return Err(err(Ctap2Response::InvalidCbor)),
            },
            _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
        }
    }
    if r.rp_id.is_empty() {
        return Err(err(Ctap2Response::MissingParameter));
    }
    Ok(r)
}

/// US-907: the build-default presence source. The device build fails
/// closed (no press poll wired → no grant); host/emulation builds auto-ack
/// (mgmt `default_user_present` parity) so the existing suites stay green.
///
/// `pub(crate)` as of US-115, because [`crate::vendor41::PresenceGate`]
/// resolves through it rather than carrying a second copy of the same two-arm
/// `cfg`. A third definition of "no probe wired means no grant" is a third
/// thing to keep in step with the other two, and the `0x41` `CONFIG_WRITE`
/// benign tier is the third consumer.
pub(crate) fn default_user_present() -> bool {
    #[cfg(feature = "device")]
    {
        false
    }
    #[cfg(not(feature = "device"))]
    {
        true
    }
}

/// Draw `out.len()` bytes from a boot-time TRNG pool and advance `cursor`.
///
/// US-176 splits this out of [`FidoApp::draw_random`] for one reason: the
/// `0x41` state seam has to hand [`crate::vendor_state::KeystoreVendorOps`] an
/// entropy closure while the app's **other** fields (its keystore, its PIN
/// token) are borrowed at the same time, and a `&mut self` method would
/// borrow the whole app. Two disjoint field borrows compose; a whole-struct
/// borrow does not. The logic is unchanged and lives in exactly one place.
pub(crate) fn take_random(
    pool: &mut heapless::Vec<u8, 512>,
    cursor: &mut usize,
    out: &mut [u8],
) {
    let mut cur = *cursor;
    for b in out.iter_mut() {
        if cur >= pool.len() {
            // Stretch: re-key the pool with its own hash.
            let mut mixed = [0u8; 32];
            crypto::sha256_into(pool.as_slice(), &mut mixed);
            pool.clear();
            let _ = pool.extend_from_slice(&mixed);
            cur = 0;
        }
        *b = pool[cur];
        cur += 1;
    }
    *cursor = cur;
}

impl FidoApp {
    /// Draw `out.len()` bytes from the boot-time TRNG pool (US-380: every
    /// random byte ultimately comes from the platform TRNG; the pool is
    /// refilled at boot and stretched with a keyed hash when exhausted).
    pub(crate) fn draw_random(&mut self, out: &mut [u8]) {
        take_random(&mut self.rng_pool, &mut self.rng_cursor, out)
    }

    fn random_cred_id(&mut self) -> [u8; 32] {
        let mut id = [0u8; 32];
        self.draw_random(&mut id);
        id
    }

    /// US-907: the user-presence grant for CTAP2 GA/MC signing — routed
    /// through the platform presence service (bound, timed, single-use).
    /// The command declares itself pending under its CTAP channel tag, one
    /// press poll may arm a grant for *that* tag, and the grant is consumed
    /// exactly once.
    ///
    /// US-921 device wiring: with `with_presence_grant` attached, the whole
    /// grant path IS the runtime's shared presence service (one instance for
    /// the whole firmware — pending slot + button-latch binding + clock), so
    /// a press with no pending request never arms anything. The fallback
    /// below stays the host/test path: a per-command service fed by the
    /// injected `fn() -> bool` poll (or the build default — fail-closed on
    /// device → CTAP2 UpRequired, auto-ack on host/emulation so the existing
    /// host suites stay green); press→consume is synchronous within the
    /// command there, so tick 0 stands in for the clock.
    pub(crate) fn user_present(&mut self, tag: u32) -> bool {
        if let Some(g) = self.presence_grant {
            return g(tag);
        }
        use fapico2_platform::presence::PresenceService;
        let mut svc = PresenceService::new();
        if !svc.begin_request(tag) {
            return false;
        }
        if match self.presence {
            Some(f) => f(),
            None => default_user_present(),
        } {
            // Press→consume is synchronous within this command, so the
            // 10 s window is moot here; tick 0 is the injected stand-in
            // (US-921 wires the real clock).
            svc.observe_press(0);
        }
        let grant = svc.request(tag, 0).is_some();
        svc.end_request(tag);
        grant
    }

    // ------------------------------------------------------------------
    // makeCredential (0x01)
    // ------------------------------------------------------------------
    pub(crate) fn handle_make_credential(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        out.clear();
        out.push(0x00).ok();
        match self.make_credential_inner(data, out, store) {
            Ok(()) => {}
            Err(code) => {
                out.clear();
                out.push(code).ok();
            }
        }
        out.len()
    }

    fn token_allows(&self, perm: u8) -> bool {
        match self.token_permissions {
            0 => perm == PERM_MC || perm == PERM_GA,
            p => p & perm != 0,
        }
    }

    fn token_rp_id_ok(&self, rp_id: &[u8]) -> bool {
        self.token_rp_id.is_empty() || self.token_rp_id.as_slice() == rp_id
    }

    pub(crate) fn note_pin_auth_failure(&mut self) -> Err {
        self.auth_failures = self.auth_failures.saturating_add(1);
        if self.auth_failures >= 3 {
            // US-909 review: latch BOTH flags like the host twin — the gate
            // `verify_token` enforces is `needs_power_cycle`; `blocked` alone
            // leaves the pinUvAuthParam replay gate inert on device builds.
            // `dirty` feeds the shell's `persist_if_dirty` flush.
            self.keystore.pin_state.blocked = true;
            self.keystore.pin_state.needs_power_cycle = true;
            self.keystore.dirty = true;
            err(Ctap2Response::PinAuthBlocked)
        } else {
            err(Ctap2Response::PinAuthInvalid)
        }
    }

    fn verify_token(&mut self, protocol: u8, param: Option<&HeaplessVec<u8, 64>>, cdh: &[u8; 32]) -> Result<bool, Err> {
        let Some(param) = param else { return Ok(false) };
        let pin_set = self.keystore.pin_state.pin_hash.is_some();
        if !pin_set {
            return Err(err(Ctap2Response::PinNotSet));
        }
        if self.keystore.pin_state.needs_power_cycle {
            return Err(err(Ctap2Response::PinAuthBlocked));
        }
        if param.is_empty() {
            return Err(err(Ctap2Response::PinAuthInvalid));
        }
        if protocol != 1 && protocol != 2 {
            return Err(err(Ctap2Response::InvalidParameter));
        }
        let Some(token) = self.pin_token else {
            return Err(err(Ctap2Response::PinAuthInvalid));
        };
        if !crypto::pin_verify_auth(protocol, &token, cdh, param) {
            return Err(self.note_pin_auth_failure());
        }
        self.auth_failures = 0;
        Ok(true)
    }

    fn make_credential_inner(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> Result<(), Err> {
        let req = parse_mc(data)?;
        let pin_set = self.keystore.pin_state.pin_hash.is_some();

        // Algorithm selection before the PIN check (C parity).
        let mut alg: i32 = 0;
        for a in &req.algs {
            if *a == crate::COSE_ALG_ES256 {
                // The device path serves ES256 (the advertised default);
                // EdDSA/P-384/P-521 land with the multi-alg work.
                alg = *a;
                break;
            }
        }
        if alg == 0 {
            return Err(err(Ctap2Response::UnsupportedAlgorithm));
        }

        // PIN / pinUvAuth.
        let mut uv = false;
        if req.pin_uv_auth_param.is_some() {
            uv = self.verify_token(req.pin_uv_protocol, req.pin_uv_auth_param.as_ref(), &req.client_data_hash)?;
            if uv && !self.token_allows(PERM_MC) {
                return Err(err(Ctap2Response::PinAuthInvalid));
            }
            if uv && !self.token_rp_id_ok(req.rp_id.as_slice()) {
                return Err(err(Ctap2Response::PinAuthInvalid));
            }
        }
        // US-1529: this is the gate the `makeCredUvNotRqd` advertisement
        // describes. It is deliberately UNCHANGED — the advertisement was
        // fixed to match it, not the reverse (weakening the gate is US-907 /
        // US-921's to make, not this story's). It is the reference's 8.1
        // branch, `pico-fido/src/fido/cbor_make_credential.c:404`. Read
        // together with `ctap2::make_cred_uv_not_rqd`: a client that sees
        // `makeCredUvNotRqd: false` here knows to send `pinUvAuthParam`, and
        // a client that does not is refused on purpose.
        if pin_set && req.pin_uv_auth_param.is_none() && (!req.options_present || req.uv != Some(false)) {
            return Err(err(Ctap2Response::PuatRequired));
        }

        // Exclude list.
        for id in &req.exclude {
            if let Some(cred) = self.keystore.get_credential(id) {
                let (revoked, protect) = (cred.revoked, cred.cred_protect);
                if revoked || (protect == 3 && !uv) {
                    continue;
                }
                return Err(err(Ctap2Response::CredentialExcluded));
            }
        }

        // US-1526 — THE `up` POLICY, decided. This rejection is deliberate,
        // legal and load-bearing. Everything the story asked to be written
        // down is here, at the site, rather than in a commit message nobody
        // reads at the next refactor:
        //
        // WHAT: a makeCredential carrying `options.up = false` is answered
        // `CTAP2_ERR_INVALID_OPTION` (0x2C — US-1528 moved this from 0x2B,
        // which every client decodes as UNSUPPORTED_OPTION), on both twins.
        // It is NOT a parse failure and NOT an accident of ordering.
        //
        // WHY IT IS LEGAL: this authenticator does not advertise `up` at all
        // (`ctap2.rs`'s `Ctap2Info::default`, pinned by
        // `tests/getinfo.rs::test_get_info_has_required_fields`), and
        // CTAP2.1 §6.1 requires a request naming an unadvertised option to be
        // rejected. The alternative reading — "the spec permits up=false, so
        // we must serve it" — ignores the half of the rule that the option has
        // to be advertised for the request to be answerable at all.
        //
        // WHY IT IS ALSO C PARITY, which is the stronger argument: the
        // reference firmware does exactly this, unconditionally, in every
        // build — `pico-fido/src/fido/cbor_make_credential.c:387`:
        //
        //     if (options.up == pfalse) { //5.6
        //         CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
        //     }
        //
        // It is not inside an `#ifdef`. The two lines the reference leaves
        // commented out immediately below (`//else if (options.up == NULL)
        // //5.7  //rup = ptrue;`) are the "absent means UP" default, which we
        // get for free by never special-casing absence. So this is not a
        // fapico2 policy invented on top of the reference — it is the
        // reference.
        //
        // WHAT IT COSTS: a client that sends up=false gets an error where a
        // CTAP2.1-conformant authenticator might have minted a credential.
        // What we can verify, we checked: in `fido2` 2.2.1 the ONLY site that
        // sends `up: false` is `_filter_creds`
        // (`fido2/client/__init__.py:593`), a **getAssertion** allowList
        // probe — `grep -rn '"up"' fido2/` returns exactly that one line —
        // and getAssertion's `up:false` is served (below). `make_credential`
        // takes `options` as a caller-supplied mapping
        // (`fido2/ctap2/base.py:376`), so a caller *could* put up=false in it;
        // we have no observation of one doing so. The epic's claim that
        // Chrome's autofill and conditional-mediation paths send it is
        // plausible and is NOT verified here — no Chrome source was read, and
        // guessing at a browser's wire from a comment is exactly the failure
        // mode a previous commit in this lane shipped.
        //
        // WHAT WOULD HAVE TO CHANGE TO RELAX IT: three things, not one.
        // (1) Advertise `up` in the getInfo options map — which stops
        // matching the reference and would make every *absent* option
        // ambiguous. (2) Delete this check and the `req.up != Some(false)`
        // guard on the presence gate below, or a plain rk=false / no-UV
        // credential could be minted with zero touch, which is US-907's
        // requirement and which this epic explicitly does not relax.
        // (3) Mirror both in `app.rs` — the host twin has its own copy at
        // `app.rs:1305`, and the epic's DoD is that the two answer
        // identically. Relaxing only one twin is the exact defect US-1514
        // was filed for.
        //
        // `tests/up_policy.rs` pins all of this on both twins.
        if req.options_present && req.up == Some(false) {
            return Err(err(Ctap2Response::InvalidOption));
        }
        if req.uv == Some(true) && !uv {
            return Err(err(Ctap2Response::PuatRequired));
        }
        if !uv && self.keystore.pin_state.always_uv {
            return Err(err(Ctap2Response::PuatRequired));
        }

        // US-907 (review fix): every MC that reaches here asserts user
        // presence (`up != false` — an explicit up=false was rejected with
        // InvalidOption above), so a plain rk=false/no-UV MC cannot mint a
        // credential + attestation signature with zero touch. Gated after
        // validation: a rejected request never burns a grant.
        if req.up != Some(false)
            && !self.user_present(crate::device_app::presence_tag_from_channel(
                self.current_channel,
            ))
        {
            return Err(err(Ctap2Response::UpRequired));
        }

        // Generate the credential keypair (ES256) from the TRNG pool.
        // US-1007: this was a bare `loop { draw_random(..); if valid break }`
        // — an unbounded rejection sampler over a draw that cannot report
        // failure, so an exhausted pool spun forever and the request never
        // came back. `try_fill_valid` caps the rejection and returns, which
        // is what turns "the card stopped answering" into a status byte.
        let mut scalar = [0u8; 32];
        // `try_fill_valid_with`, not `try_fill_valid`: the pool draw is not
        // an `RngCore` and cannot report a refusal, so the attempt cap is
        // the only thing bounding this. An exhausted pool serves the same
        // bytes forever and used to spin on them forever.
        crypto::try_fill_valid_with(
            &mut |out: &mut [u8]| {
                self.draw_random(out);
                Ok(())
            },
            &mut scalar,
            |b| p256::SecretKey::from_slice(b).is_ok(),
        )
        .map_err(|_| err(Ctap2Response::Other))?;
        let sk = p256::SecretKey::from_slice(&scalar).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
        let pub_bytes = crypto::public_key_bytes(&sk.public_key());
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&pub_bytes[1..33]);
        y.copy_from_slice(&pub_bytes[33..65]);
        let cose_key = DeviceCoseKey::es256(x, y);

        // Credential ID: resident → derived (C parity), else random.
        let rp_id_hash = crypto::sha256(req.rp_id.as_slice());
        let resident = req.rk == Some(true);
        let cred_id: HeaplessVec<u8, 64> = if resident {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(b"fapico2-resident-id");
            h.update(rp_id_hash);
            h.update(req.user_handle.as_slice());
            let digest = h.finalize();
            let mut v: HeaplessVec<u8, 64> = HeaplessVec::new();
            v.extend_from_slice(&digest).ok();
            v
        } else {
            let id = self.random_cred_id();
            let mut v: HeaplessVec<u8, 64> = HeaplessVec::new();
            v.extend_from_slice(&id).ok();
            v
        };

        // largeBlobKey: resident-only (derived, C parity).
        if req.large_blob_key && !resident {
            return Err(err(Ctap2Response::InvalidOption));
        }
        let large_blob_key = if req.large_blob_key {
            let mut lbk = [0u8; 32];
            crypto::hmac_sha256_into(self.hkey.to_bytes().as_slice(), &cred_id, &mut lbk);
            Some(lbk)
        } else {
            None
        };

        // Flags: UP | AT (+ UV, + ED when extensions are present).
        let mut flags: u8 = 0x01 | 0x40;
        if uv {
            flags |= 0x04;
        }
        let cred_blob_stored = req
            .cred_blob
            .as_ref()
            .map(|b| b.len() <= crate::DEFAULT_MAX_CRED_BLOB_LENGTH)
            .unwrap_or(false);
        let has_extensions = req.third_party_payment
            || req.min_pin_length
            || req.cred_blob.is_some()
            || req.hmac_secret
            || req.hmac_secret_mc.is_some()
            || req.large_blob_key
            || req.cred_protect > 0;
        if has_extensions {
            flags |= 0x80;
        }

        let sign_count = self.keystore.cred_counter;

        // authData = rpIdHash(32) flags(1) count(4) aaguid(16) len(2) id cose
        // [extensions].
        let mut auth_data: HeaplessVec<u8, 768> = HeaplessVec::new();
        auth_data.extend_from_slice(&rp_id_hash).ok();
        auth_data.push(flags).ok();
        auth_data.extend_from_slice(&sign_count.to_be_bytes()).ok();
        auth_data.extend_from_slice(&AAGUID).ok();
        auth_data.extend_from_slice(&(cred_id.len() as u16).to_be_bytes()).ok();
        auth_data.extend_from_slice(&cred_id).ok();
        // Standard COSE wire format for attestedCredentialData.
        cose_key
            .encode_wire(&mut auth_data)
            .map_err(|_| err(Ctap2Response::KeyStoreFull))?;

        if has_extensions {
            // Count the emitted extension pairs first (canonical map).
            let mut n = 0usize;
            if req.third_party_payment { n += 1; }
            if req.min_pin_length { n += 1; }
            if req.cred_protect > 0 { n += 1; }
            if req.hmac_secret { n += 1; }
            let mut hmac_out: HeaplessVec<u8, 80> = HeaplessVec::new();
            if let Some(hs) = &req.hmac_secret_mc {
                derive_hmac_output(self, hs, uv, &mut hmac_out)?;
                n += 1;
            }
            if req.cred_blob.is_some() { n += 1; }
            if req.large_blob_key { n += 1; }
            no_heap::push_map_header(&mut auth_data, n).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            if req.cred_blob.is_some() {
                no_heap::push_tstr(&mut auth_data, "credBlob").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_bool(&mut auth_data, cred_blob_stored).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
            if req.cred_protect > 0 {
                no_heap::push_tstr(&mut auth_data, "credProtect").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_uint(&mut auth_data, req.cred_protect as u64).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
            if req.hmac_secret {
                no_heap::push_tstr(&mut auth_data, "hmac-secret").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_bool(&mut auth_data, true).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
            if req.large_blob_key {
                no_heap::push_tstr(&mut auth_data, "largeBlobKey").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_bool(&mut auth_data, true).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
            if req.min_pin_length {
                no_heap::push_tstr(&mut auth_data, "minPinLength").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_uint(&mut auth_data, self.keystore.pin_state.min_pin_length as u64)
                    .map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
            if !hmac_out.is_empty() {
                no_heap::push_tstr(&mut auth_data, "hmac-secret-mc").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_bstr(&mut auth_data, &hmac_out).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
            if req.third_party_payment {
                no_heap::push_tstr(&mut auth_data, "thirdPartyPayment").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_bool(&mut auth_data, true).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
        }

        // Store the credential (counter increments before persist, FX-409).
        let mut cred = DeviceCredential {
            credential_id: cred_id.clone(),
            public_key: cose_key,
            private_key: scalar,
            rp_id_hash,
            rp_id: req.rp_id.clone(),
            user_handle: req.user_handle.clone(),
            user_name: req.user_name.clone(),
            user_display_name: req.user_display_name.clone(),
            cred_protect: req.cred_protect,
            large_blob_key,
            hmac_secret: HeaplessVec::new(),
            cred_blob: if cred_blob_stored {
                let mut b: HeaplessVec<u8, 64> = HeaplessVec::new();
                if let Some(blob) = &req.cred_blob {
                    let _ = b.extend_from_slice(blob.as_slice());
                }
                b
            } else {
                HeaplessVec::new()
            },
            third_party_payment: req.third_party_payment,
            pin_complexity_policy: false,
            resident,
            algorithm: alg,
            counter: sign_count,
            revoked: false,
            expires_at: None,
        };
        cred.credential_id = cred_id.clone();
        // SOAK-FINDING-1: transactional capacity — with the store bound, the
        // registration (counter bump included, per FX-409 the persisted
        // counter covers it) commits only if the resulting snapshot still
        // persists; on failure everything rolls back and the command answers
        // CTAP2_ERR_KEY_STORE_FULL with zero side effects.
        let counter_before = self.keystore.cred_counter;
        self.keystore.cred_counter = counter_before.wrapping_add(1);
        let stored = match store {
            Some(store) => self.keystore.store_credential_checked(cred, store),
            None => self.keystore.store_credential(cred),
        };
        if stored.is_err() {
            self.keystore.cred_counter = counter_before;
            return Err(err(Ctap2Response::KeyStoreFull));
        }

        // Response: {1: "packed", 2: authData, 3: {alg, sig}} — packed
        // self-attestation signed with the credential key (the device build
        // carries no attestation certificate).
        let mut signed: HeaplessVec<u8, 832> = HeaplessVec::new();
        signed.extend_from_slice(auth_data.as_slice()).ok();
        signed.extend_from_slice(&req.client_data_hash).ok();
        let mut sig: HeaplessVec<u8, 72> = HeaplessVec::new();
        crypto::p256_sign_der_into(&sk, signed.as_slice(), &mut sig)
            .ok_or(err(Ctap2Response::KeyStoreFull))?;

        no_heap::push_map_header(out, 3 + usize::from(large_blob_key.is_some())).ok();
        no_heap::push_uint(out, 1).ok();
        no_heap::push_tstr(out, "packed").ok();
        no_heap::push_uint(out, 2).ok();
        no_heap::push_bstr(out, &auth_data).ok();
        no_heap::push_uint(out, 3).ok();
        no_heap::push_map_header(out, 2).ok();
        no_heap::push_tstr(out, "alg").ok();
        no_heap::push_neg(out, i64::from(crate::COSE_ALG_ES256)).ok();
        no_heap::push_tstr(out, "sig").ok();
        no_heap::push_bstr(out, &sig).ok();
        if let Some(lbk) = large_blob_key {
            no_heap::push_uint(out, 5).ok();
            no_heap::push_bstr(out, &lbk).ok();
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // getAssertion (0x02) + getNextAssertion (0x08)
    // ------------------------------------------------------------------
    pub(crate) fn handle_get_assertion(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        out.clear();
        out.push(0x00).ok();
        let r = (|| -> Result<(), Err> {
            let req = parse_ga(data)?;
            let mut uv = false;
            if req.pin_uv_auth_param.is_some() {
                uv = self.verify_token(req.pin_uv_protocol, req.pin_uv_auth_param.as_ref(), &req.client_data_hash)?;
                if uv && !self.token_allows(PERM_GA) {
                    return Err(err(Ctap2Response::PinAuthInvalid));
                }
                if uv && !self.token_rp_id_ok(req.rp_id.as_slice()) {
                    return Err(err(Ctap2Response::PinAuthInvalid));
                }
            }
            if req.uv == Some(true) && !uv {
                return Err(err(Ctap2Response::PuatRequired));
            }
            if !uv && self.keystore.pin_state.always_uv {
                return Err(err(Ctap2Response::PuatRequired));
            }
            // US-1526: getAssertion `up:false` is SERVED (a silent assertion, no UP
            // bit) — unlike makeCredential above, which rejects it. That
            // asymmetry is the reference's, not ours:
            // `pico-fido/src/fido/cbor_get_assertion.c` takes the silent path
            // (`bool silent = (up == false && uv == false);` at :322, and the
            // UP gate at :488 fires only for `up == ptrue || absent`) and
            // rejects exactly one combination — hmac-secret with a silent
            // assertion, at :324:
            //
            //     if (options.up == pfalse && extensions.hmac_secret == ptrue) {
            //         CBOR_ERROR(CTAP2_ERR_INVALID_OPTION);
            //     }
            //
            // The device twin had this check from the initial release; the
            // host twin has its copy at `app.rs:1655`. The brief for this
            // story flagged the two as possibly divergent (host-only). They
            // are not: both reject, with the same byte, in the same position
            // in the validation order. `tests/up_policy.rs` pins the parity
            // so the next reader does not have to re-derive it by reading two
            // parsers.
            if req.up == Some(false) && req.hmac_secret_input.is_some() {
                return Err(err(Ctap2Response::InvalidOption));
            }
            let do_up = req.up != Some(false);
            // US-907: presence is consulted before anything signs. No grant
            // ⇒ the CTAP2 "UP required" keepalive path (loop then error —
            // synchronously the UpRequired status): no assertion is built,
            // so no signature is produced and the UP bit is never set.
            if do_up
                && !self.user_present(crate::device_app::presence_tag_from_channel(
                    self.current_channel,
                ))
            {
                return Err(err(Ctap2Response::UpRequired));
            }

            let rp_id_hash = crypto::sha256(req.rp_id.as_slice());
            let mut matched: HeaplessVec<HeaplessVec<u8, 64>, DEVICE_MAX_CREDS> = HeaplessVec::new();
            if !req.allow.is_empty() {
                for id in &req.allow {
                    if let Some(cred) = self.keystore.get_credential(id) {
                        let (revoked, protect, rp) = (cred.revoked, cred.cred_protect, cred.rp_id_hash);
                        if revoked || (protect == 3 && !uv) || rp != rp_id_hash {
                            continue;
                        }
                        if matched.push(id.clone()).is_err() {
                            return Err(err(Ctap2Response::LimitExceeded));
                        }
                        // AllowList returns exactly one credential.
                        break;
                    }
                }
            } else {
                // Resident credentials for the RP, newest first; credProtect
                // >= 2 withheld without UV.
                let mut ids: HeaplessVec<HeaplessVec<u8, 64>, DEVICE_MAX_CREDS> = HeaplessVec::new();
                for cred in &self.keystore.credentials {
                    if cred.resident
                        && !cred.revoked
                        && (uv || cred.cred_protect < 2)
                        && cred.rp_id_hash == rp_id_hash
                        && ids.push(cred.credential_id.clone()).is_err()
                    {
                        return Err(err(Ctap2Response::LimitExceeded));
                    }
                }
                // Reverse (newest first).
                while let Some(id) = ids.pop() {
                    let _ = matched.push(id);
                }
            }
            if matched.is_empty() {
                return Err(err(Ctap2Response::NoCredentials));
            }
            let first = matched.remove(0);
            let total = if req.allow.is_empty() { matched.len() + 1 } else { 1 };
            let has_more = req.allow.is_empty() && !matched.is_empty();
            if has_more {
                self.ga_pending = Some(crate::device_app::DeviceGaState {
                    remaining: matched,
                    client_data_hash: req.client_data_hash,
                    uv,
                    do_up,
                    total,
                    channel: self.current_channel,
                });
            } else {
                self.ga_pending = None;
            }
            self.build_assertion(
                &first,
                &req.client_data_hash,
                uv,
                do_up,
                total,
                total > 1,
                req.hmac_secret_input.as_ref(),
                req.get_cred_blob,
                req.large_blob_key,
                req.third_party_payment,
                out,
                store,
            )
        })();
        match r {
            Ok(()) => {}
            Err(code) => {
                out.clear();
                out.push(code).ok();
            }
        }
        out.len()
    }

    #[allow(clippy::too_many_arguments)]
    fn build_assertion(
        &mut self,
        cred_id: &[u8],
        client_data_hash: &[u8; 32],
        uv: bool,
        do_up: bool,
        total: usize,
        is_first_of_many: bool,
        hmac_input: Option<&HmacSecretInput>,
        get_cred_blob: bool,
        large_blob_key: bool,
        third_party_payment: bool,
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> Result<(), Err> {
        // Copy the credential fields out first (the hmac-secret derivation
        // needs &mut self for the TRNG pool).
        let Some(cred) = self.keystore.get_credential(cred_id) else {
            return Err(err(Ctap2Response::NoCredentials));
        };
        let rp_id_hash = cred.rp_id_hash;
        let cred_blob = if get_cred_blob { Some(cred.cred_blob.clone()) } else { None };
        let lbk = cred.large_blob_key;
        let user_handle = cred.user_handle.clone();
        let resident = cred.resident;
        let private_key = cred.private_key;

        // SOAK-FINDING-1 review round 2: transactional counter bump — the
        // snapshot is made durable here or the bump reverts.
        //
        // US-1011: the second half of SOAK-FINDING-1's sentence — "the
        // assertion signs the durable counter so it can never regress after
        // a reboot" — was true when written and is **false now**. The bump
        // is batched, so this call returns a value that is in RAM only on all
        // but every `COUNTER_PERSIST_INTERVAL`-th one. The property that
        // replaced it is monotonicity: a restore starts a whole window above
        // the durable image, so a power cut inside the window can only skip
        // *forward*, never repeat. See
        // `device_keystore::bump_credential_counter_checked`, which says the
        // same thing and warns that a reader assuming the signed counter is
        // durable is wrong here.
        //
        // What is unchanged is the revert: on a persist *failure* the bump
        // rolls back and the reply signs the durable value, so a failing
        // store never latches the durable-before-ack gate.
        let sign_count = self
            .keystore
            .bump_credential_counter_checked(cred_id, store)
            .ok_or(err(Ctap2Response::NoCredentials))?;

        let mut hmac_out: HeaplessVec<u8, 80> = HeaplessVec::new();
        if let Some(hs) = hmac_input {
            derive_hmac_output(self, hs, uv, &mut hmac_out)?;
        }
        let mut flags: u8 = 0;
        if do_up {
            flags |= 0x01;
        }
        if uv {
            flags |= 0x04;
        }
        let has_extensions = third_party_payment || get_cred_blob || !hmac_out.is_empty();
        if has_extensions {
            flags |= 0x80;
        }

        let mut auth_data: HeaplessVec<u8, 768> = HeaplessVec::new();
        auth_data.extend_from_slice(&rp_id_hash).ok();
        auth_data.push(flags).ok();
        auth_data.extend_from_slice(&sign_count.to_be_bytes()).ok();
        if has_extensions {
            let mut n = 0;
            if third_party_payment { n += 1; }
            if !hmac_out.is_empty() { n += 1; }
            if cred_blob.is_some() { n += 1; }
            no_heap::push_map_header(&mut auth_data, n).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            if let Some(blob) = cred_blob {
                no_heap::push_tstr(&mut auth_data, "credBlob").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_bstr(&mut auth_data, &blob).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
            if !hmac_out.is_empty() {
                no_heap::push_tstr(&mut auth_data, "hmac-secret").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_bstr(&mut auth_data, &hmac_out).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
            if third_party_payment {
                no_heap::push_tstr(&mut auth_data, "thirdPartyPayment").map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                no_heap::push_bool(&mut auth_data, true).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
            }
        }

        // Sign authData || clientDataHash with the credential key (DER).
        let sk = p256::SecretKey::from_slice(&private_key)
            .map_err(|_| err(Ctap2Response::InvalidCommand))?;
        let mut signed: HeaplessVec<u8, 832> = HeaplessVec::new();
        signed.extend_from_slice(auth_data.as_slice()).ok();
        signed.extend_from_slice(client_data_hash).ok();
        let mut sig: HeaplessVec<u8, 72> = HeaplessVec::new();
        crypto::p256_sign_der_into(&sk, signed.as_slice(), &mut sig)
            .ok_or(err(Ctap2Response::InvalidCommand))?;

        no_heap::push_map_header(out, {
            let mut n = 3;
            if resident && !user_handle.is_empty() { n += 1; }
            if is_first_of_many && total > 1 { n += 1; }
            if large_blob_key && lbk.is_some() { n += 1; }
            n
        }).ok();
        no_heap::push_uint(out, 1).ok();
        no_heap::push_map_header(out, 2).ok();
        no_heap::push_tstr(out, "id").ok();
        no_heap::push_bstr(out, cred_id).ok();
        no_heap::push_tstr(out, "type").ok();
        no_heap::push_tstr(out, "public-key").ok();
        no_heap::push_uint(out, 2).ok();
        no_heap::push_bstr(out, &auth_data).ok();
        no_heap::push_uint(out, 3).ok();
        no_heap::push_bstr(out, &sig).ok();
        if resident && !user_handle.is_empty() {
            no_heap::push_uint(out, 4).ok();
            no_heap::push_map_header(out, 1).ok();
            no_heap::push_tstr(out, "id").ok();
            no_heap::push_bstr(out, &user_handle).ok();
        }
        if is_first_of_many && total > 1 {
            no_heap::push_uint(out, 5).ok();
            no_heap::push_uint(out, total as u64).ok();
        }
        if large_blob_key {
            if let Some(k) = lbk {
                no_heap::push_uint(out, 7).ok();
                no_heap::push_bstr(out, &k).ok();
            }
        }
        Ok(())
    }

    pub(crate) fn handle_get_next_assertion(
        &mut self,
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        out.clear();
        out.push(0x00).ok();
        let r = (|| -> Result<(), Err> {
            let Some(state) = self.ga_pending.as_mut() else {
                return Err(err(Ctap2Response::NotAllowed));
            };
            if state.channel != self.current_channel {
                return Err(err(Ctap2Response::NotAllowed));
            }
            if state.remaining.is_empty() {
                self.ga_pending = None;
                return Err(err(Ctap2Response::NoCredentials));
            }
            let id = state.remaining.remove(0);
            let total = state.total;
            let uv = state.uv;
            let do_up = state.do_up;
            let cdh = state.client_data_hash;
            let is_last = state.remaining.is_empty();
            if is_last {
                self.ga_pending = None;
            }
            self.build_assertion(&id, &cdh, uv, do_up, total, !is_last, None, false, false, false, out, store)
        })();
        match r {
            Ok(()) => {}
            Err(code) => {
                out.clear();
                out.push(code).ok();
            }
        }
        out.len()
    }

    // ------------------------------------------------------------------
    // clientPin (0x06) — protocols v1 and v2, no-heap
    // ------------------------------------------------------------------
    pub(crate) fn handle_client_pin(&mut self, data: &[u8], out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>) -> usize {
        out.clear();
        out.push(0x00).ok();
        let r = self.client_pin_inner(data, out);
        match r {
            Ok(()) => {}
            Err(code) => {
                out.clear();
                out.push(code).ok();
            }
        }
        out.len()
    }

    fn derive_shared(&self, protocol: u8, client_pub: &p256::PublicKey) -> [u8; 64] {
        let raw = crypto::ecdh_shared_secret(&self.hkey, client_pub);
        if protocol == 1 {
            let k = crypto::derive_shared_secret_v1(&raw);
            let mut shared = [0u8; 64];
            shared[..32].copy_from_slice(&k);
            shared[32..].copy_from_slice(&k);
            shared
        } else {
            crypto::derive_shared_secret_v2(&raw)
        }
    }

    /// Decrypt a PIN-protocol payload into `out` (v1: zero IV; v2: leading
    /// 16-byte IV). Returns the used length of `out`.
    fn pin_decrypt_into(protocol: u8, enc_key: &[u8; 32], data: &[u8], out: &mut [u8; 96]) -> Option<usize> {
        if protocol == 1 {
            if data.is_empty() || !data.len().is_multiple_of(16) || data.len() > 96 {
                return None;
            }
            out[..data.len()].copy_from_slice(data);
            crypto::pin_cbc_decrypt_zero_iv(enc_key, &mut out[..data.len()]).ok()?;
            Some(data.len())
        } else {
            if data.len() < 32 || !data.len().is_multiple_of(16) || data.len() > 96 + 16 {
                return None;
            }
            let ct_len = data.len() - 16;
            out[..ct_len].copy_from_slice(&data[16..]);
            let iv: [u8; 16] = data[..16].try_into().ok()?;
            crypto::aes256_cbc_decrypt_into(enc_key, &iv, &mut out[..ct_len]).ok()?;
            Some(ct_len)
        }
    }

    fn client_pin_inner(&mut self, data: &[u8], out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>) -> Result<(), Err> {
        let mut protocol: u8 = 0;
        let mut subcommand: u8 = 0;
        let mut key_agreement: Option<[u8; 64]> = None;
        let mut auth_param: Option<HeaplessVec<u8, 64>> = None;
        let mut new_pin_enc: Option<HeaplessVec<u8, 96>> = None;
        let mut pin_hash_enc: Option<HeaplessVec<u8, 96>> = None;
        let mut permissions: Option<u8> = None;
        let mut rp_id: HeaplessVec<u8, TEXT_MAX> = HeaplessVec::new();

        {
            let mut p = Parser::new(data);
            let Item::Map(n) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                return Err(err(Ctap2Response::InvalidCbor));
            };
            for _ in 0..n {
                let key = match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                    Item::U(k) => k,
                    _ => return Err(err(Ctap2Response::InvalidCbor)),
                };
                match key {
                    1 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => protocol = u as u8,
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    2 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => subcommand = u as u8,
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    3 => key_agreement = parse_key_agreement(&mut p),
                    4 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::B(b) => {
                            let mut v = HeaplessVec::new();
                            if v.extend_from_slice(b).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            auth_param = Some(v);
                        }
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    5 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::B(b) => {
                            let mut v = HeaplessVec::new();
                            if v.extend_from_slice(b).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            new_pin_enc = Some(v);
                        }
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    6 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::B(b) => {
                            let mut v = HeaplessVec::new();
                            if v.extend_from_slice(b).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            pin_hash_enc = Some(v);
                        }
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    9 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => permissions = Some(u as u8),
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    10 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::T(s) => {
                            let _ = rp_id.extend_from_slice(s.as_bytes());
                        }
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                }
            }
        }

        if protocol != 1 && protocol != 2 {
            return Err(err(Ctap2Response::InvalidParameter));
        }
        if subcommand == 0 {
            return Err(err(Ctap2Response::MissingParameter));
        }

        match subcommand {
            0x01 => {
                // getRetries
                let retries = self.keystore.pin_state.retries;
                let power = self.keystore.pin_state.blocked
                    || self.keystore.pin_state.needs_power_cycle;
                no_heap::push_map_header(out, if power { 2 } else { 1 }).ok();
                no_heap::push_uint(out, 3).ok();
                no_heap::push_uint(out, retries as u64).ok();
                if power {
                    no_heap::push_uint(out, 4).ok();
                    no_heap::push_bool(out, true).ok();
                }
                Ok(())
            }
            0x07 => {
                // getUVRetries: keys 4 (powerCycleState) and 5 (uvRetries),
                // mirroring sub-command 0x01's conditional map header.
                // US-1513: the budget was a hard-coded 3 and the existing
                // test only checked the CBOR type, so nothing observed it.
                // It now tracks the same `auth_failures` counter the latch
                // uses, and the durable lockout is reported alongside.
                let power = self.keystore.pin_state.blocked
                    || self.keystore.pin_state.needs_power_cycle;
                let uv_retries = crate::ctap2::uv_retries(self.auth_failures);
                no_heap::push_map_header(out, if power { 2 } else { 1 }).ok();
                // Ascending key order, as everywhere else in this map:
                // 4 (powerCycleState) then 5 (uvRetries).
                if power {
                    no_heap::push_uint(out, 4).ok();
                    no_heap::push_bool(out, true).ok();
                }
                no_heap::push_uint(out, 5).ok();
                no_heap::push_uint(out, uv_retries as u64).ok();
                Ok(())
            }
            0x02 => {
                // getKeyAgreement
                let pub_bytes = crypto::public_key_bytes(&self.hkey.public_key());
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                x.copy_from_slice(&pub_bytes[1..33]);
                y.copy_from_slice(&pub_bytes[33..65]);
                no_heap::push_map_header(out, 1).ok();
                no_heap::push_uint(out, 1).ok();
                no_heap::push_map_header(out, 5).ok();
                no_heap::push_uint(out, 1).ok();
                no_heap::push_uint(out, 2).ok();
                no_heap::push_uint(out, 3).ok();
                no_heap::push_neg(out, i64::from(crate::COSE_ALG_ECDH_ES_HKDF_256)).ok();
                no_heap::push_neg(out, -1).ok();
                no_heap::push_uint(out, 1).ok();
                no_heap::push_neg(out, -2).ok();
                no_heap::push_bstr(out, &x).ok();
                no_heap::push_neg(out, -3).ok();
                no_heap::push_bstr(out, &y).ok();
                Ok(())
            }
            0x03 => {
                // setPIN
                if self.keystore.pin_state.pin_hash.is_some() {
                    return Err(err(Ctap2Response::NotAllowed));
                }
                let ka = key_agreement.ok_or(err(Ctap2Response::MissingParameter))?;
                let enc = new_pin_enc.ok_or(err(Ctap2Response::MissingParameter))?;
                let param = auth_param.ok_or(err(Ctap2Response::MissingParameter))?;
                let client_pub =
                    crypto::parse_cose_ec2_p256_bytes(&ka[..32], &ka[32..]).ok_or(err(Ctap2Response::PinAuthInvalid))?;
                let shared = self.derive_shared(protocol, &client_pub);
                let mut hmac_key = [0u8; 32];
                let mut enc_key = [0u8; 32];
                hmac_key.copy_from_slice(&shared[..32]);
                enc_key.copy_from_slice(&shared[32..]);
                if !crypto::pin_verify_auth(protocol, &hmac_key, enc.as_slice(), &param) {
                    return Err(err(Ctap2Response::PinAuthInvalid));
                }
                let mut decoded = PinScratch::new();
                let n = Self::pin_decrypt_into(protocol, &enc_key, enc.as_slice(), &mut decoded)
                    .ok_or(err(Ctap2Response::PinAuthInvalid))?;
                // PIN validation: ≤ 64 bytes, NUL-terminated padding.
                if n > 64 || decoded[63] != 0 {
                    return Err(err(Ctap2Response::PinPolicyViolation));
                }
                let pin_len = decoded[..n].iter().position(|&b| b == 0).unwrap_or(n);
                if decoded[pin_len..n].iter().any(|&b| b != 0) {
                    return Err(err(Ctap2Response::PinPolicyViolation));
                }
                let min_pin = self.keystore.pin_state.min_pin_length as usize;
                if count_codepoints(&decoded[..pin_len]) < min_pin {
                    return Err(err(Ctap2Response::PinPolicyViolation));
                }
                // US-910: set/change-PIN emit the salted, stretched format
                // (single dirty flush below keeps it atomic).
                let pin_hash = crypto::pin_hash(&decoded[..pin_len]);
                let mut salt = [0u8; 16];
                self.draw_random(&mut salt);
                let (verifier, iter) = crypto::pin_verifier_upgrade(&pin_hash, &salt);
                self.keystore.pin_state.pin_hash = Some(verifier);
                self.keystore.pin_state.pin_verifier_format =
                    crypto::PIN_VERIFIER_FORMAT_STRETCHED;
                self.keystore.pin_state.pin_salt = Some(salt);
                self.keystore.pin_state.pin_iter = iter;
                self.keystore.pin_state.retries = MAX_PIN_RETRIES;
                self.keystore.pin_state.blocked = false;
                self.keystore.dirty = true;
                self.keystore.pin_state.needs_power_cycle = false;
                self.keystore.pin_state.new_pin_mismatches = 0;
                no_heap::push_map_header(out, 0).ok();
                Ok(())
            }
            0x04 => {
                // changePIN
                if self.keystore.pin_state.pin_hash.is_none() {
                    return Err(err(Ctap2Response::PinNotSet));
                }
                if self.keystore.pin_state.retries == 0 {
                    return Err(err(Ctap2Response::PinBlocked));
                }
                // US-909: no needs_power_cycle gate here — a correct old PIN
                // is what clears the durable 3-strike latch (success path
                // below resets it).
                let ka = key_agreement.ok_or(err(Ctap2Response::MissingParameter))?;
                let pin_hash_enc = pin_hash_enc.ok_or(err(Ctap2Response::MissingParameter))?;
                let enc = new_pin_enc.ok_or(err(Ctap2Response::MissingParameter))?;
                let param = auth_param.ok_or(err(Ctap2Response::MissingParameter))?;
                let client_pub =
                    crypto::parse_cose_ec2_p256_bytes(&ka[..32], &ka[32..]).ok_or(err(Ctap2Response::PinAuthInvalid))?;
                let shared = self.derive_shared(protocol, &client_pub);
                let mut hmac_key = [0u8; 32];
                let mut enc_key = [0u8; 32];
                hmac_key.copy_from_slice(&shared[..32]);
                enc_key.copy_from_slice(&shared[32..]);
                // Verify over (newPinEnc || pinHashEnc).
                let mut auth_data: HeaplessVec<u8, 224> = HeaplessVec::new();
                auth_data.extend_from_slice(enc.as_slice()).ok();
                auth_data.extend_from_slice(pin_hash_enc.as_slice()).ok();
                if !crypto::pin_verify_auth(protocol, &hmac_key, auth_data.as_slice(), &param) {
                    return Err(err(Ctap2Response::PinAuthInvalid));
                }
                let mut decoded = PinScratch::new();
                let old_len =
                    Self::pin_decrypt_into(protocol, &enc_key, pin_hash_enc.as_slice(), &mut decoded)
                        .ok_or(err(Ctap2Response::PinAuthInvalid))?;
                if old_len < 16 {
                    return Err(err(Ctap2Response::PinAuthInvalid));
                }
                let mut old_hash = [0u8; 16];
                old_hash.copy_from_slice(&decoded[..16]);

                // Decrement retries before comparison (C parity).
                self.keystore.pin_state.retries = self.keystore.pin_state.retries.saturating_sub(1);
                self.keystore.dirty = true;
                let stored = self.keystore.pin_state.pin_hash.ok_or(err(Ctap2Response::PinNotSet))?;
                let (fmt, salt, iter) = {
                    let s = &self.keystore.pin_state;
                    (s.pin_verifier_format, s.pin_salt, s.pin_iter)
                };
                if !crypto::pin_verifier_matches(&stored, fmt, salt.as_ref(), iter, &old_hash) {
                    if self.keystore.pin_state.retries == 0 {
                        return Err(err(Ctap2Response::PinBlocked));
                    }
                    self.keystore.pin_state.new_pin_mismatches += 1;
                    if self.keystore.pin_state.blocked
                            || self.keystore.pin_state.new_pin_mismatches >= 3 {
                        self.keystore.pin_state.blocked = true;
                        self.keystore.pin_state.needs_power_cycle = true;
                        self.keystore.dirty = true;
                        return Err(err(Ctap2Response::PinAuthBlocked));
                    }
                    self.keystore.dirty = true;
                    return Err(err(Ctap2Response::PinInvalid));
                }
                // US-910: successful verification of a legacy record
                // migrates it (wrong PINs never reach here).
                if self.keystore.pin_state.pin_verifier_format
                    != crypto::PIN_VERIFIER_FORMAT_STRETCHED
                {
                    let mut salt = [0u8; 16];
                    self.draw_random(&mut salt);
                    let (verifier, iter) = crypto::pin_verifier_upgrade(&old_hash, &salt);
                    self.keystore.pin_state.pin_hash = Some(verifier);
                    self.keystore.pin_state.pin_verifier_format =
                        crypto::PIN_VERIFIER_FORMAT_STRETCHED;
                    self.keystore.pin_state.pin_salt = Some(salt);
                    self.keystore.pin_state.pin_iter = iter;
                    self.keystore.dirty = true;
                }
                // PIN matches — validate the new PIN.
                let mut decoded_new = PinScratch::new();
                let n = Self::pin_decrypt_into(protocol, &enc_key, enc.as_slice(), &mut decoded_new)
                    .ok_or(err(Ctap2Response::PinAuthInvalid))?;
                if n > 64 || decoded_new[63] != 0 {
                    return Err(err(Ctap2Response::PinPolicyViolation));
                }
                let pin_len = decoded_new[..n].iter().position(|&b| b == 0).unwrap_or(n);
                if decoded_new[pin_len..n].iter().any(|&b| b != 0) {
                    return Err(err(Ctap2Response::PinPolicyViolation));
                }
                let min_pin = self.keystore.pin_state.min_pin_length as usize;
                if count_codepoints(&decoded_new[..pin_len]) < min_pin {
                    return Err(err(Ctap2Response::PinPolicyViolation));
                }
                // US-910: changePIN emits the salted, stretched format.
                let new_pin_hash = crypto::pin_hash(&decoded_new[..pin_len]);
                let mut salt = [0u8; 16];
                self.draw_random(&mut salt);
                let (verifier, iter) = crypto::pin_verifier_upgrade(&new_pin_hash, &salt);
                self.keystore.pin_state.pin_hash = Some(verifier);
                self.keystore.pin_state.pin_verifier_format =
                    crypto::PIN_VERIFIER_FORMAT_STRETCHED;
                self.keystore.pin_state.pin_salt = Some(salt);
                self.keystore.pin_state.pin_iter = iter;
                self.keystore.pin_state.retries = MAX_PIN_RETRIES;
                self.keystore.pin_state.blocked = false;
                self.keystore.pin_state.force_pin_change = false;
                self.keystore.dirty = true;
                self.keystore.pin_state.needs_power_cycle = false;
                self.keystore.pin_state.new_pin_mismatches = 0;
                no_heap::push_map_header(out, 0).ok();
                Ok(())
            }
            0x05 | 0x09 => {
                // getPinToken / getPinUvAuthTokenUsingPinWithPermissions
                if subcommand == 0x09 {
                    let permissions = permissions.ok_or(err(Ctap2Response::MissingParameter))?;
                    if permissions & PERM_BE != 0 && protocol != 2 {
                        return Err(err(Ctap2Response::PinAuthInvalid));
                    }
                }
                if self.keystore.pin_state.pin_hash.is_none() {
                    return Err(err(Ctap2Response::PinNotSet));
                }
                if self.keystore.pin_state.retries == 0 {
                    return Err(err(Ctap2Response::PinBlocked));
                }
                let ka = key_agreement.ok_or(err(Ctap2Response::MissingParameter))?;
                let pin_hash_enc = pin_hash_enc.ok_or(err(Ctap2Response::MissingParameter))?;
                let client_pub =
                    crypto::parse_cose_ec2_p256_bytes(&ka[..32], &ka[32..]).ok_or(err(Ctap2Response::PinAuthInvalid))?;
                let shared = self.derive_shared(protocol, &client_pub);
                let mut enc_key = [0u8; 32];
                enc_key.copy_from_slice(&shared[32..]);
                let mut decoded = PinScratch::new();
                let n = Self::pin_decrypt_into(protocol, &enc_key, pin_hash_enc.as_slice(), &mut decoded)
                    .ok_or(err(Ctap2Response::PinAuthInvalid))?;
                if n < 16 {
                    return Err(err(Ctap2Response::PinAuthInvalid));
                }
                // Decrement retries before comparison (C parity).
                self.keystore.pin_state.retries = self.keystore.pin_state.retries.saturating_sub(1);
                self.keystore.dirty = true;
                let stored = self.keystore.pin_state.pin_hash.ok_or(err(Ctap2Response::PinNotSet))?;
                let (fmt, salt, iter) = {
                    let s = &self.keystore.pin_state;
                    (s.pin_verifier_format, s.pin_salt, s.pin_iter)
                };
                let mut candidate = [0u8; 16];
                candidate.copy_from_slice(&decoded[..16]);
                if !crypto::pin_verifier_matches(&stored, fmt, salt.as_ref(), iter, &candidate) {
                    if self.keystore.pin_state.retries == 0 {
                        return Err(err(Ctap2Response::PinBlocked));
                    }
                    self.keystore.pin_state.new_pin_mismatches += 1;
                    if self.keystore.pin_state.blocked
                            || self.keystore.pin_state.new_pin_mismatches >= 3 {
                        self.keystore.pin_state.blocked = true;
                        self.keystore.pin_state.needs_power_cycle = true;
                        self.keystore.dirty = true;
                        return Err(err(Ctap2Response::PinAuthBlocked));
                    }
                    self.keystore.dirty = true;
                    return Err(err(Ctap2Response::PinInvalid));
                }
                // US-910: successful verification of a legacy record
                // migrates it (wrong PINs never reach here).
                if self.keystore.pin_state.pin_verifier_format
                    != crypto::PIN_VERIFIER_FORMAT_STRETCHED
                {
                    let mut salt = [0u8; 16];
                    self.draw_random(&mut salt);
                    let (verifier, iter) = crypto::pin_verifier_upgrade(&candidate, &salt);
                    self.keystore.pin_state.pin_hash = Some(verifier);
                    self.keystore.pin_state.pin_verifier_format =
                        crypto::PIN_VERIFIER_FORMAT_STRETCHED;
                    self.keystore.pin_state.pin_salt = Some(salt);
                    self.keystore.pin_state.pin_iter = iter;
                    self.keystore.dirty = true;
                }
                // US-909: a correct PIN clears the durable 3-strike latch
                // (success path below resets it).
                if self.keystore.pin_state.force_pin_change {
                    return Err(err(Ctap2Response::PinInvalid));
                }
                self.keystore.pin_state.retries = MAX_PIN_RETRIES;
                self.keystore.pin_state.blocked = false;
                self.keystore.dirty = true;
                self.keystore.pin_state.needs_power_cycle = false;
                self.keystore.pin_state.new_pin_mismatches = 0;

                // Raw pin token (32 TRNG-pool bytes) + permissions binding.
                let mut token = [0u8; 32];
                self.draw_random(&mut token);
                self.pin_token = Some(token);
                self.token_permissions = if subcommand == 0x05 { 0 } else { permissions.unwrap_or(0) };
                // rpId (key 0x0A) binds the 0x09 token when present.
                self.token_rp_id.clear();
                if subcommand == 0x09 && !rp_id.is_empty() {
                    let _ = self.token_rp_id.extend_from_slice(&rp_id);
                }
                // Encrypt the token for the response.
                let mut encrypted: HeaplessVec<u8, 96> = HeaplessVec::new();
                if protocol == 1 {
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&token);
                    crypto::pin_cbc_encrypt_zero_iv(&enc_key, &mut buf).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                    encrypted.extend_from_slice(&buf).ok();
                } else {
                    let mut iv = [0u8; 16];
                    self.draw_random(&mut iv);
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&token);
                    crypto::aes256_cbc_encrypt_into(&enc_key, &iv, &mut buf)
                        .map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                    encrypted.extend_from_slice(&iv).ok();
                    encrypted.extend_from_slice(&buf).ok();
                }
                no_heap::push_map_header(out, 1).ok();
                no_heap::push_uint(out, 2).ok();
                no_heap::push_bstr(out, &encrypted).ok();
                Ok(())
            }
            0x06 => {
                // getPinUvAuthTokenUsingUvWithPermissions.
                //
                // The no-PIN leg of the token exchange: the client proves
                // nothing but a user-presence gesture, and this build's
                // authenticator has no separate user-verification secret to
                // check. It is what a client falls back to when the key has
                // no PIN, so it has to answer rather than refuse, or the
                // client has no way to obtain a pinUvAuthToken at all and the
                // resident-credential screens never resolve.
                //
                // US-1525: this comment used to justify the sub-command by
                // claiming "GetInfo reports the `uv` option". It never did,
                // and it still does not — `uv` is deliberately not
                // advertised (see `ctap2::Ctap2Info::default`), because this
                // build has nothing to verify against and promising a
                // mechanism that does not exist would be the real lie. What
                // is advertised is `pinUvAuthToken`, which claims the token
                // *mechanism*, not a UV method; US-1512 sets its value to
                // true except under the durable lockout — the same
                // `blocked || needs_power_cycle` gate applied below — so the
                // capability is advertised exactly when it is offered.
                // `tests/pin_uv_advert.rs` asserts `uv` stays absent on both
                // twins so this premise cannot be quietly reinstated.
                // Fail-closed on presence: the grant is the only thing being
                // asserted, so without a press this answers `UpRequired` and
                // the transport opens a keepalive window and retries. A
                // token is therefore never minted without a real touch.
                let permissions = permissions.ok_or(err(Ctap2Response::MissingParameter))?;
                let ka = key_agreement.ok_or(err(Ctap2Response::MissingParameter))?;
                // US-1512: the durable lockout that every PIN leg already
                // refuses. Without this gate `0x06` stayed the one token
                // route that ignored it, so a locked-out device still
                // minted a full-permission token while GetInfo — correctly —
                // had stopped advertising that it could.
                if self.keystore.pin_state.blocked || self.keystore.pin_state.needs_power_cycle {
                    return Err(err(Ctap2Response::PinAuthBlocked));
                }
                let client_pub =
                    crypto::parse_cose_ec2_p256_bytes(&ka[..32], &ka[32..]).ok_or(err(Ctap2Response::PinAuthInvalid))?;
                if !self.user_present(crate::device_app::presence_tag_from_channel(
                    self.current_channel,
                )) {
                    return Err(err(Ctap2Response::UpRequired));
                }
                let shared = self.derive_shared(protocol, &client_pub);
                let mut enc_key = [0u8; 32];
                enc_key.copy_from_slice(&shared[32..]);

                let mut token = [0u8; 32];
                self.draw_random(&mut token);
                self.pin_token = Some(token);
                self.token_permissions = permissions;
                // A UV token is not bound to an rpId — the permission mask
                // is the whole of its scope.
                self.token_rp_id.clear();

                let mut encrypted: HeaplessVec<u8, 96> = HeaplessVec::new();
                if protocol == 1 {
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&token);
                    crypto::pin_cbc_encrypt_zero_iv(&enc_key, &mut buf).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                    encrypted.extend_from_slice(&buf).ok();
                } else {
                    let mut iv = [0u8; 16];
                    self.draw_random(&mut iv);
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&token);
                    crypto::aes256_cbc_encrypt_into(&enc_key, &iv, &mut buf)
                        .map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                    encrypted.extend_from_slice(&iv).ok();
                    encrypted.extend_from_slice(&buf).ok();
                }
                no_heap::push_map_header(out, 1).ok();
                no_heap::push_uint(out, 2).ok();
                no_heap::push_bstr(out, &encrypted).ok();
                Ok(())
            }
            _ => Err(err(Ctap2Response::InvalidParameter)),
        }
    }

    // ------------------------------------------------------------------
    // Reset (0x07)
    // ------------------------------------------------------------------
    pub(crate) fn handle_reset(&mut self, out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>) -> usize {
        out.clear();
        // Fresh device random + credential wipe (the hkey is regenerated on
        // the next boot from the store — the snapshot the reset writes is
        // entirely new state).
        let mut seed = [0u8; 32];
        self.draw_random(&mut seed);
        self.keystore.reset_from_seed(seed);
        // Regenerate the persistent hkey from the pool (TRNG-derived).
        // US-1007: bounded for the same reason as the makeCredential arm —
        // this was a bare rejection loop over a draw that cannot report
        // failure. `handle_reset` returns a byte count rather than a
        // `Result`, so a refusal cannot be propagated as a status; it
        // leaves `hkey` at its current value, which is what the `if let Ok`
        // below already did for the parse. The residual is real and is
        // stated rather than hidden: a reset taken while the pool cannot
        // produce does not rotate the `hkey`. That is strictly better than
        // the alternative, which is a request that never returns, and the
        // window is the same one D-9 describes (a generator that has
        // stopped producing).
        let mut scalar = [0u8; 32];
        if crypto::try_fill_valid_with(
            &mut |out: &mut [u8]| {
                self.draw_random(out);
                Ok(())
            },
            &mut scalar,
            |b| p256::SecretKey::from_slice(b).is_ok(),
        )
        .is_ok()
        {
            if let Ok(sk) = p256::SecretKey::from_slice(&scalar) {
                self.hkey = sk;
            }
        }
        // Zeroize before dropping — `None` alone leaves the 32 bytes
        // resident in RAM (the invariant `device_app::clear_session_state`
        // states out loud).
        if let Some(mut token) = self.pin_token.take() {
            token.fill(0);
        }
        self.pin_token = None;
        self.token_permissions = 0;
        self.token_rp_id.clear();
        self.ga_pending = None;
        self.keystore.pin_state.needs_power_cycle = false;
        self.keystore.pin_state.new_pin_mismatches = 0;
        self.auth_failures = 0;
        self.keystore.dirty = true;
        out.push(0x00).ok();
        out.len()
    }

    // ------------------------------------------------------------------
    // getInfo (0x04) — full CTAP2.1 info map, no-heap serialization
    // ------------------------------------------------------------------
    pub(crate) fn handle_get_info(&mut self, out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>) -> usize {
        out.clear();
        let mut info = crate::ctap2::Ctap2Info::default();
        // S-701-5: the full command set is served on device.
        info.set_option("authnrCfg", true);
        info.set_option("enterpriseAttestation", true);
        info.set_option("alwaysUv", self.keystore.pin_state.always_uv);
        // US-1529: derived, not hard-coded — see `ctap2::make_cred_uv_not_rqd`
        // for the spec text, the client-side decision it feeds, and the
        // measured per-state behaviour. Both UV options are read from the same
        // `pin_state`, so they cannot contradict each other on the wire: with
        // `always_uv` set, `makeCredUvNotRqd` is necessarily `false` (§6.1.3's
        // MUST), which is exactly what the MC gate in `make_credential_inner`
        // does — `if !uv && always_uv { PuatRequired }`.
        info.set_option(
            "makeCredUvNotRqd",
            crate::ctap2::make_cred_uv_not_rqd(
                self.keystore.pin_state.pin_hash.is_some(),
                self.keystore.pin_state.always_uv,
            ),
        );
        // Encrypted state fields (IV(16) || AES-CBC ct(16)), deterministic
        // plaintext over the persisted device random (host parity).
        let mut iv = [0u8; 16];
        self.draw_random(&mut iv);
        let mut key = [0u8; 32];
        crypto::hmac_sha256_into(b"fapico2-encStateKey", &self.keystore.device_random, &mut key);
        let mut state_data: HeaplessVec<u8, 36> = HeaplessVec::new();
        state_data.extend_from_slice(&self.keystore.device_random).ok();
        state_data.extend_from_slice(&self.keystore.cred_counter.to_le_bytes()).ok();
        let mut state_pt = [0u8; 32];
        crypto::hmac_sha256_into(b"fapico2-credStoreState", state_data.as_slice(), &mut state_pt);
        let mut enc_state: HeaplessVec<u8, 64> = HeaplessVec::new();
        enc_state.extend_from_slice(&iv).ok();
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&state_pt[..16]);
        crypto::pin_cbc_encrypt_zero_iv(&key, &mut buf).ok();
        enc_state.extend_from_slice(&buf).ok();
        info.enc_cred_store_state = enc_state;

        let mut iv2 = [0u8; 16];
        self.draw_random(&mut iv2);
        let mut id_pt = [0u8; 32];
        crypto::hmac_sha256_into(b"fapico2-encIdentifier", &self.keystore.device_random, &mut id_pt);
        let mut enc_id: HeaplessVec<u8, 64> = HeaplessVec::new();
        enc_id.extend_from_slice(&iv2).ok();
        let mut buf2 = [0u8; 16];
        buf2.copy_from_slice(&id_pt[..16]);
        crypto::pin_cbc_encrypt_zero_iv(&key, &mut buf2).ok();
        enc_id.extend_from_slice(&buf2).ok();
        info.enc_identifier = enc_id;

        info.set_option("clientPin", self.keystore.pin_state.pin_hash.is_some());
        // US-1512: the capability half of the PIN/UV pair, kept adjacent to
        // `clientPin` so a reader can check the two against each other. It
        // goes through the shared helper so this twin and `app.rs` cannot
        // drift; the rule is at `ctap2::pin_uv_auth_token_available`.
        info.set_option(
            "pinUvAuthToken",
            crate::ctap2::pin_uv_auth_token_available(
                self.keystore.pin_state.blocked,
                self.keystore.pin_state.needs_power_cycle,
            ),
        );
        out.push(0x00).ok();
        info.write_cbor_into::<{ crate::CTAP2_MAX_MSG }>(out).ok();
        out.len()
    }

    // ------------------------------------------------------------------
    // authenticatorSelection (0x0B) — US-1514
    // ------------------------------------------------------------------
    //
    // Deliberately NOT gated on user presence, and the reasoning is in the
    // commit message rather than being a summary of it:
    //
    // * `fido2`'s `Ctap2.selection()` (ctap2/base.py:575) calls
    //   `send_cbor(Ctap2.CMD.SELECTION, ...)` with no data, and `send_cbor`
    //   (`:286`) does `status = response[0]; if status != 0x00: raise
    //   CtapError(status)`. So *any* non-zero answer — `UpRequired` (0x3B),
    //   `UserActionTimeout` (0x2F), `ActionTimeout` (0x3A) — is an exception
    //   at the caller, not a wait. There is no wire shape in which a gated
    //   selection reads as a successful selection to this client.
    // * The `UpRequired` → keepalive → retry loop that turns a bare `0x3B`
    //   into a touch prompt lives in the *transport*, not here, and its
    //   predicate does not include `0x0B`:
    //   `presence_windowed = up_request || ctap_cmd == vendor41::CMD ||
    //   ctap_cmd == 0x06` (with `up_request = ctap_cmd == 0x01 ||
    //   ctap_cmd == 0x02`) in `firmware/src/hid_serve.rs`. There is no
    //   separate emulator copy of the predicate to drift from — US-1524 made
    //   `emul_hid::serve_pass` call the same `serve_once`, so both paths
    //   evaluate this one expression.
    //   So gating here would answer a bare 0x3B that never opens a window,
    //   never prompts and never retries — a deadlock, not a prompt.
    // * The reference C firmware gates too (`pico-fido/src/fido/
    //   cbor_selection.c` calls `wait_button_pressed()`), but the gate is
    //   disarmed by default: it resolves through
    //   `button_wait_start()` (pico-keys-sdk/src/button.c:113), which
    //   auto-queues `EV_BUTTON_PRESSED` when `up_btn` is unset AND
    //   `force_button_wait` is false — and `cbor_selection.c`'s
    //   `force_button_wait = true` is inside `#ifdef FORCE_BUTTON_WAIT`,
    //   a CMake option that is off unless requested. fapico2's
    //   `vendorff::PhyConfig` has no `up_btn` field either, so the other
    //   disarm is unreachable here. The reference's *default build* answer is
    //   therefore `CTAP2_OK` with no touch, which is what this returns and
    //   what the host twin returns.
    // * `Ctap2Response::ActionTimeout` (0x3A) stays unproduced. The
    //   reference does not use it here either: on a real timeout
    //   `cbor_selection.c` returns `CTAP2_ERR_USER_ACTION_TIMEOUT` = 0x2F,
    //   not 0x3A. The old host comment cited 0x3A and was wrong.
    pub(crate) fn handle_authenticator_selection(
        &mut self,
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
    ) -> usize {
        out.clear();
        out.push(Ctap2Response::Ok.code()).ok();
        out.len()
    }
}

/// Derive the hmac-secret output for encrypted salts (CTAP2.1 §6.7) — the
/// no-heap mirror of the host `derive_hmac_output` (same domain-separated
/// credential-random derivation, so outputs are interchangeable).
fn derive_hmac_output(
    app: &mut FidoApp,
    hs: &HmacSecretInput,
    uv: bool,
    out: &mut HeaplessVec<u8, 80>,
) -> Result<(), u8> {
    let Some(client_pub) = crypto::parse_cose_ec2_p256_bytes(&hs.key_agreement[..32], &hs.key_agreement[32..]) else {
        return Err(Ctap2Response::PinAuthInvalid.code());
    };
    let raw = crypto::ecdh_shared_secret(&app.hkey, &client_pub);
    let (hmac_key, enc_key): ([u8; 32], [u8; 32]) = if hs.protocol == 1 {
        let k = crypto::derive_shared_secret_v1(&raw);
        (k, k)
    } else {
        let shared = crypto::derive_shared_secret_v2(&raw);
        let mut hk = [0u8; 32];
        let mut ek = [0u8; 32];
        hk.copy_from_slice(&shared[..32]);
        ek.copy_from_slice(&shared[32..]);
        (hk, ek)
    };
    if !crypto::pin_verify_auth(hs.protocol, &hmac_key, hs.salt_enc.as_slice(), hs.salt_auth.as_slice()) {
        return Err(Ctap2Response::PinAuthInvalid.code());
    }
    let mut salt_dec = [0u8; 96];
    let salt_len =
        FidoApp::pin_decrypt_into(hs.protocol, &enc_key, hs.salt_enc.as_slice(), &mut salt_dec)
            .ok_or(Ctap2Response::InvalidParameter.code())?;
    let hkey_bytes = app.hkey.to_bytes();
    let mut crd = [0u8; 32];
    if uv {
        crypto::hmac_sha256_into(hkey_bytes.as_slice(), b"fapico2-hmac-cred-random-uv", &mut crd);
    } else {
        crypto::hmac_sha256_into(hkey_bytes.as_slice(), b"fapico2-hmac-cred-random", &mut crd);
    }
    let mut out_buf = [0u8; 32];
    crypto::hmac_sha256_into(&crd, &salt_dec[..32.min(salt_len)], &mut out_buf);
    out.clear();
    if hs.protocol == 1 {
        let mut buf = out_buf;
        crypto::pin_cbc_encrypt_zero_iv(&enc_key, &mut buf).map_err(|_| Ctap2Response::KeyStoreFull.code())?;
        out.extend_from_slice(&buf).ok();
    } else {
        let mut iv = [0u8; 16];
        app.draw_random(&mut iv);
        crypto::aes256_cbc_encrypt_into(&enc_key, &iv, &mut out_buf)
            .map_err(|_| Ctap2Response::KeyStoreFull.code())?;
        out.extend_from_slice(&iv).ok();
        out.extend_from_slice(&out_buf).ok();
    }
    if salt_len >= 64 {
        // Two-salt form: append the second encrypted output.
        let mut out2 = [0u8; 32];
        crypto::hmac_sha256_into(&crd, &salt_dec[32..64], &mut out2);
        if hs.protocol == 1 {
            crypto::pin_cbc_encrypt_zero_iv(&enc_key, &mut out2).map_err(|_| Ctap2Response::KeyStoreFull.code())?;
            out.extend_from_slice(&out2).ok();
        } else {
            let mut iv = [0u8; 16];
            app.draw_random(&mut iv);
            crypto::aes256_cbc_encrypt_into(&enc_key, &iv, &mut out2)
                .map_err(|_| Ctap2Response::KeyStoreFull.code())?;
            out.extend_from_slice(&iv).ok();
            out.extend_from_slice(&out2).ok();
        }
    }
    Ok(())
}

// Keep the version constants referenced (the getInfo versions list uses
// crate::CTAP2_VERSIONS via the shell's hand-written map replacement above).
#[allow(dead_code)]
fn _version_constants_used() -> &'static [&'static str] {
    &[CTAP1_VERSION]
}

// Trng is referenced for doc links / future direct-TRNG paths.
#[allow(dead_code)]
fn _trng_used<T: Trng>(_t: &T) {}


// ---------------------------------------------------------------------------
// S-701-5: full CTAP2 command set on device — credMgmt (0x0A), largeBlobs
// (0x0C), authenticatorConfig (0x0D), U2F (CTAPHID MSG) and the vendor vault.
// ---------------------------------------------------------------------------

use crate::device_app::{CmCredState, CmRpState, LbPending, VaultPending};

/// CTAP2.1 largeBlobs response/checksum geometry.
const LB_CHECKSUM_LEN: usize = 16;

/// Which CBOR dialect a credentialManagement request arrived in.
///
/// Two are in the wild and they are *not* interchangeable:
///
/// * **PicoForge** — the first-party management client. Key `0x02` holds a
///   *map* of sub-command parameters, `pinUvAuthProtocol` sits at `0x03` and
///   `pinUvAuthParam` at `0x04`. Sub-commands `0x01`/`0x02` are
///   getCredsMetadata / enumerateRpsBegin. This is the layout this command
///   was originally written against and it must keep working byte for byte.
/// * **CTAP2** — what every third-party client speaks (ykman, Yubico
///   Authenticator, browsers). Keys are flat: `0x02` pinUvAuthProtocol,
///   `0x03` pinUvAuthParam, `0x04` rpIdHash, `0x05` credentialID,
///   `0x06` user. Sub-commands `0x01`/`0x02` are enumerateRPsBegin /
///   getCredsMetadata — the *reverse* of PicoForge's.
///
/// The two are told apart by the CBOR type at the low keys: PicoForge puts a
/// map at `0x02` and an integer at `0x03`, CTAP2 puts an integer at `0x02`
/// and a byte string at `0x03`. Neither layout can be mistaken for the other.
///
/// The response key sets genuinely collide (PicoForge `0x04` is rpIdHash,
/// CTAP2 `0x04` is userID; PicoForge `0x07` is credentialID, CTAP2 `0x07`
/// is totalRPs), so a merged map is impossible — each dialect has to be
/// answered in its own shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CmDialect {
    PicoForge,
    // Spec is the safe default: an unrecognised request is far more
    // likely to come from a third-party client than from PicoForge.
    #[default]
    Ctap2,
}

/// Canonical credMgmt sub-command identity, independent of the wire dialect.
///
/// These are the CTAP2 §12.1.6 values. PicoForge swaps the first two; the
/// parser maps a PicoForge wire value onto these before anything downstream
/// looks at it, so the dispatch arms need no dialect branches.
const CM_GET_METADATA: u8 = 0x02;
const CM_ENUMERATE_RPS_BEGIN: u8 = 0x01;
const CM_ENUMERATE_RPS_NEXT: u8 = 0x03;
const CM_ENUMERATE_CREDS_BEGIN: u8 = 0x04;
const CM_ENUMERATE_CREDS_NEXT: u8 = 0x05;
const CM_DELETE_CRED: u8 = 0x06;
const CM_UPDATE_USER: u8 = 0x07;

/// Identify the dialect of a credentialManagement request body.
///
/// A pre-scan of the top-level map's *types* only. PicoForge's key `0x02` is
/// a map and CTAP2's is an integer, and neither dialect ever puts the other's
/// type in that slot, so the two cannot be confused. When key `0x02` is
/// absent (PicoForge omits it for sub-commands that take no parameters) the
/// integer at key `0x03` is the fallback signal, because CTAP2's key `0x03`
/// is always pinUvAuthParam — a byte string.
fn cm_dialect(data: &[u8]) -> CmDialect {
    let mut p = Parser::new(data);
    let Ok(Item::Map(n)) = p.next() else {
        return CmDialect::Ctap2;
    };
    for _ in 0..n {
        let Ok(Item::U(k)) = p.next() else {
            return CmDialect::Ctap2;
        };
        match k {
            2 => match p.next() {
                Ok(Item::Map(_)) => return CmDialect::PicoForge,
                Ok(Item::U(_)) | Ok(Item::N(_)) => return CmDialect::Ctap2,
                // Consumed by the `next()` above; nothing left to skip.
                _ => {}
            },
            3 => match p.next() {
                Ok(Item::U(_)) | Ok(Item::N(_)) => return CmDialect::PicoForge,
                _ => {}
            },
            _ => {
                if p.skip().is_err() {
                    return CmDialect::Ctap2;
                }
            }
        }
    }
    CmDialect::Ctap2
}

impl FidoApp {
    // -- credMgmt (0x0A) ---------------------------------------------------

    pub(crate) fn handle_cred_mgmt(&mut self, data: &[u8], out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>) -> usize {
        out.clear();
        out.push(0x00).ok();
        let r = self.cred_mgmt_inner(data, out);
        match r {
            Ok(()) => {}
            Err(code) => {
                out.clear();
                out.push(code).ok();
            }
        }
        out.len()
    }

    fn cred_mgmt_inner(&mut self, data: &[u8], out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>) -> Result<(), Err> {
        if data.is_empty() {
            return Err(err(Ctap2Response::MissingParameter));
        }
        let dialect = cm_dialect(data);
        // The response encoders read this: the two dialects' key sets collide,
        // so a request has to be answered in the shape its sender asked in.
        self.cm_dialect = dialect;
        let mut wire_subcommand: u8 = 0;
        let mut protocol: u8 = 2;
        let mut param: Option<HeaplessVec<u8, 64>> = None;
        let mut rp_id_hash: Option<[u8; 32]> = None;
        let mut cred_id: Option<HeaplessVec<u8, 64>> = None;
        let mut user_id: Option<HeaplessVec<u8, 64>> = None;
        let mut user_name: Option<HeaplessVec<u8, TEXT_MAX>> = None;
        let mut user_dn: Option<HeaplessVec<u8, TEXT_MAX>> = None;
        // Byte-exact copies of what the client signed over. PicoForge signs
        // `subCommand ‖ CBOR(subCommandParams)`; CTAP2 signs
        // `subCommand ‖ rpIdHash ‖ credentialID ‖ user`. Either way these are
        // the bytes *as received*, never rebuilt from the parsed fields — a
        // client signs exactly the encoding it sent, key order included.
        let mut raw_params: Option<HeaplessVec<u8, 256>> = None;
        let mut raw_rp: Option<HeaplessVec<u8, 64>> = None;
        let mut raw_cred: Option<HeaplessVec<u8, 160>> = None;
        let mut raw_user: Option<HeaplessVec<u8, 224>> = None;

        {
            let mut p = Parser::new(data);
            let Item::Map(n) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                return Err(err(Ctap2Response::InvalidCbor));
            };
            for _ in 0..n {
                let key = match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                    Item::U(k) => k,
                    _ => return Err(err(Ctap2Response::InvalidCbor)),
                };
                if dialect == CmDialect::Ctap2 {
                    // CTAP2 §12.1.6: flat top-level keys, no nesting. Every
                    // value the pinUvAuth message covers is captured raw
                    // before it is decoded.
                    match key {
                        1 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::U(u) => wire_subcommand = u as u8,
                            _ => return Err(err(Ctap2Response::InvalidCbor)),
                        },
                        2 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::U(u) => protocol = u as u8,
                            _ => return Err(err(Ctap2Response::InvalidCbor)),
                        },
                        3 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            Item::B(b) => {
                                let mut v = HeaplessVec::new();
                                if v.extend_from_slice(b).is_err() {
                                    return Err(err(Ctap2Response::InvalidLength));
                                }
                                param = Some(v);
                            }
                            _ => return Err(err(Ctap2Response::InvalidCbor)),
                        },
                        4 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                            // rpIdHash — signed over as the bare 32 bytes,
                            // not as a CBOR byte string.
                            Item::B(b) if b.len() == 32 => {
                                let mut h = [0u8; 32];
                                h.copy_from_slice(b);
                                rp_id_hash = Some(h);
                                let mut v: HeaplessVec<u8, 64> = HeaplessVec::new();
                                if v.extend_from_slice(b).is_err() {
                                    return Err(err(Ctap2Response::InvalidLength));
                                }
                                raw_rp = Some(v);
                            }
                            _ => return Err(err(Ctap2Response::InvalidCbor)),
                        },
                        5 => {
                            // credentialID — signed over as its CBOR map.
                            let start = p.pos();
                            p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?;
                            let end = p.pos();
                            let mut raw: HeaplessVec<u8, 160> = HeaplessVec::new();
                            if raw.extend_from_slice(&data[start..end]).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            raw_cred = Some(raw);
                            let mut q = Parser::new(&data[start..end]);
                            let Item::Map(cm) =
                                q.next().map_err(|_| err(Ctap2Response::InvalidCbor))?
                            else {
                                return Err(err(Ctap2Response::InvalidCbor));
                            };
                            let mut id: HeaplessVec<u8, 64> = HeaplessVec::new();
                            for _ in 0..cm {
                                match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                    Item::T("id") => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                        Item::B(b) => {
                                            if id.extend_from_slice(b).is_err() {
                                                return Err(err(Ctap2Response::InvalidLength));
                                            }
                                        }
                                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                                    },
                                    _ => q.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                }
                            }
                            cred_id = Some(id);
                        }
                        6 => {
                            // user — signed over as its CBOR map.
                            let start = p.pos();
                            p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?;
                            let end = p.pos();
                            let mut raw: HeaplessVec<u8, 224> = HeaplessVec::new();
                            if raw.extend_from_slice(&data[start..end]).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            raw_user = Some(raw);
                            let mut q = Parser::new(&data[start..end]);
                            let Item::Map(um) =
                                q.next().map_err(|_| err(Ctap2Response::InvalidCbor))?
                            else {
                                return Err(err(Ctap2Response::InvalidCbor));
                            };
                            for _ in 0..um {
                                match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                    Item::T("id") => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                        Item::B(b) => {
                                            let mut v = HeaplessVec::new();
                                            let _ = v.extend_from_slice(b);
                                            user_id = Some(v);
                                        }
                                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                                    },
                                    Item::T("name") => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                        Item::T(s) => {
                                            let mut v = HeaplessVec::new();
                                            let _ = v.extend_from_slice(s.as_bytes());
                                            user_name = Some(v);
                                        }
                                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                                    },
                                    Item::T("displayName") => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                        Item::T(s) => {
                                            let mut v = HeaplessVec::new();
                                            let _ = v.extend_from_slice(s.as_bytes());
                                            user_dn = Some(v);
                                        }
                                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                                    },
                                    _ => q.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                }
                            }
                        }
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                    }
                    continue;
                }
                // PicoForge: sub-command parameters nested under key 0x02,
                // pinUvAuthProtocol at 0x03, pinUvAuthParam at 0x04.
                match key {
                    1 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => wire_subcommand = u as u8,
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    3 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => protocol = u as u8,
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    4 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::B(b) => {
                            let mut v = HeaplessVec::new();
                            if v.extend_from_slice(b).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            param = Some(v);
                        }
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    2 => {
                        // Capture the raw params bytes for the pinUvAuth
                        // message (byte-exact with what the client signed).
                        let start = p.pos();
                        p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?;
                        let end = p.pos();
                        let mut raw = HeaplessVec::new();
                        if raw.extend_from_slice(&data[start..end]).is_err() {
                            return Err(err(Ctap2Response::InvalidLength));
                        }
                        raw_params = Some(raw);
                        // Re-parse the captured params for the fields.
                        let mut q = Parser::new(&data[start..end]);
                        let Item::Map(m) = q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                            return Err(err(Ctap2Response::InvalidCbor));
                        };
                        for _ in 0..m {
                            let sk = match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::U(u) => u,
                                _ => continue,
                            };
                            match sk {
                                1 => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                    Item::B(b) if b.len() == 32 => {
                                        let mut h = [0u8; 32];
                                        h.copy_from_slice(b);
                                        rp_id_hash = Some(h);
                                    }
                                    _ => return Err(err(Ctap2Response::InvalidCbor)),
                                },
                                2 => {
                                    let Item::Map(cm) = q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                                        return Err(err(Ctap2Response::InvalidCbor));
                                    };
                                    let mut id: HeaplessVec<u8, 64> = HeaplessVec::new();
                                    for _ in 0..cm {
                                        match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                            Item::T("id") => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                                Item::B(b) => {
                                                    if id.extend_from_slice(b).is_err() {
                                                        return Err(err(Ctap2Response::InvalidLength));
                                                    }
                                                }
                                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                                            },
                                            _ => q.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                        }
                                    }
                                    cred_id = Some(id);
                                }
                                3 => {
                                    let Item::Map(um) = q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                                        return Err(err(Ctap2Response::InvalidCbor));
                                    };
                                    for _ in 0..um {
                                        match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                            Item::T("id") => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                                Item::B(b) => {
                                                    let mut v = HeaplessVec::new();
                                                    let _ = v.extend_from_slice(b);
                                                    user_id = Some(v);
                                                }
                                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                                            },
                                            Item::T("name") => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                                Item::T(s) => {
                                                    let mut v = HeaplessVec::new();
                                                    let _ = v.extend_from_slice(s.as_bytes());
                                                    user_name = Some(v);
                                                }
                                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                                            },
                                            Item::T("displayName") => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                                Item::T(s) => {
                                                    let mut v = HeaplessVec::new();
                                                    let _ = v.extend_from_slice(s.as_bytes());
                                                    user_dn = Some(v);
                                                }
                                                _ => return Err(err(Ctap2Response::InvalidCbor)),
                                            },
                                            _ => q.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                                        }
                                    }
                                }
                                _ => q.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                            }
                        }
                    }
                    _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                }
            }
        }
        if wire_subcommand == 0 {
            return Err(err(Ctap2Response::MissingParameter));
        }

        // PicoForge numbers getCredsMetadata 0x01 and enumerateRpsBegin 0x02;
        // CTAP2 numbers them the other way round. Everything below works in
        // the canonical CTAP2 numbering, so PicoForge's pair is swapped here
        // and nowhere else. `wire_subcommand` — not this value — is what goes
        // into the pinUvAuth message, in both dialects.
        let subcommand = match (dialect, wire_subcommand) {
            (CmDialect::PicoForge, 0x01) => CM_GET_METADATA,
            (CmDialect::PicoForge, 0x02) => CM_ENUMERATE_RPS_BEGIN,
            (_, w) => w,
        };

        // PIN auth: every subcommand except the enumerate-next pair.
        let needs_pincmd = !matches!(subcommand, CM_ENUMERATE_RPS_NEXT | CM_ENUMERATE_CREDS_NEXT);
        if needs_pincmd {
            let param = match param {
                Some(p) => p,
                None => return Err(err(Ctap2Response::PuatRequired)),
            };
            if protocol != 1 && protocol != 2 {
                return Err(err(Ctap2Response::InvalidParameter));
            }
            // A PIN is not the only way to be authorised: a factory-fresh key
            // has none, and CTAP2 expects a pinUvAuthToken minted from built-in
            // user verification to stand in for it. Gating on "a PIN is set"
            // alone left such a key unable to use credentialManagement at all,
            // so the real requirement — a live token — is checked instead.
            // Nothing is weakened: the token below is still verified, and one
            // can only exist if a token sub-command succeeded (0x06 only after
            // a user-presence grant). With neither, this is still PinNotSet.
            if self.keystore.pin_state.pin_hash.is_none() && self.pin_token.is_none() {
                return Err(err(Ctap2Response::PinNotSet));
            }
            if self.keystore.pin_state.needs_power_cycle {
                return Err(err(Ctap2Response::PinAuthBlocked));
            }
            let token = self.pin_token.ok_or(err(Ctap2Response::PinAuthInvalid))?;
            let mut auth_msg: HeaplessVec<u8, 512> = HeaplessVec::new();
            auth_msg.push(wire_subcommand).ok();
            match dialect {
                // PicoForge signs `subCommand ‖ CBOR(subCommandParams)` —
                // one opaque blob, captured at parse time.
                CmDialect::PicoForge => {
                    if let Some(raw) = &raw_params {
                        auth_msg.extend_from_slice(raw.as_slice()).ok();
                    }
                }
                // CTAP2 §12.1.6 signs the parameters that the sub-command
                // actually carries, concatenated in spec order and never
                // CBOR-wrapped: rpIdHash for enumerateCredentialsBegin,
                // credentialID for deleteCredential, and credentialID ‖ user
                // for updateUserInformation.
                CmDialect::Ctap2 => match subcommand {
                    CM_ENUMERATE_CREDS_BEGIN => {
                        if let Some(raw) = &raw_rp {
                            auth_msg.extend_from_slice(raw.as_slice()).ok();
                        }
                    }
                    CM_DELETE_CRED => {
                        if let Some(raw) = &raw_cred {
                            auth_msg.extend_from_slice(raw.as_slice()).ok();
                        }
                    }
                    CM_UPDATE_USER => {
                        if let Some(raw) = &raw_cred {
                            auth_msg.extend_from_slice(raw.as_slice()).ok();
                        }
                        if let Some(raw) = &raw_user {
                            auth_msg.extend_from_slice(raw.as_slice()).ok();
                        }
                    }
                    _ => {}
                },
            }
            if !crypto::pin_verify_auth(protocol, &token, auth_msg.as_slice(), &param) {
                return Err(self.note_pin_auth_failure());
            }
            self.auth_failures = 0;
            if !self.token_allows(PERM_CM | PERM_CM_PERSISTENT) {
                return Err(err(Ctap2Response::PinAuthInvalid));
            }
        }

        match subcommand {
            CM_GET_METADATA => {
                // Keys 1/2 are the spec's existingResidentCredentialsCount /
                // maxPossibleRemainingResidentCredentialsCount; key 3 (total
                // capacity) is the PicoForge extension. Both dialects read the
                // first two, and CTAP2 clients ignore the unknown third.
                let existing = self.keystore.cred_count();
                let remaining = self.keystore.max_remaining_creds();
                no_heap::push_map_header(out, 3).ok();
                no_heap::push_uint(out, 1).ok();
                no_heap::push_uint(out, existing as u64).ok();
                no_heap::push_uint(out, 2).ok();
                no_heap::push_uint(out, remaining as u64).ok();
                no_heap::push_uint(out, 3).ok();
                no_heap::push_uint(out, (existing + remaining) as u64).ok();
                Ok(())
            }
            CM_ENUMERATE_RPS_BEGIN => {
                // enumerateRpsBegin
                let mut rps: heapless::Vec<([u8; 32], heapless::Vec<u8, 64>), { crate::device_keystore::DEVICE_MAX_CREDS }> =
                    heapless::Vec::new();
                for cred in &self.keystore.credentials {
                    if !cred.resident || cred.revoked {
                        continue;
                    }
                    if rps.iter().any(|(h, _)| *h == cred.rp_id_hash) {
                        continue;
                    }
                    if rps.push((cred.rp_id_hash, cred.rp_id.clone())).is_err() {
                        return Err(err(Ctap2Response::LimitExceeded));
                    }
                }
                if rps.is_empty() {
                    return Err(err(Ctap2Response::NoCredentials));
                }
                let total = rps.len();
                let (hash, rp_id) = rps.remove(0);
                self.cm_rp_state = Some(CmRpState { rps, cursor: 0, channel: self.current_channel, dialect: self.cm_dialect });
                let rp_str =
                    core::str::from_utf8(rp_id.as_slice()).map_err(|_| err(Ctap2Response::InvalidCbor))?;
                match self.cm_dialect {
                    // CTAP2 §12.1.6: rp(1) ‖ rpID(2) ‖ totalRPs(7). A client
                    // that cannot find keys 1/2/7 has nothing to render,
                    // which is what left the Slots and Passkeys screens
                    // spinning forever.
                    CmDialect::Ctap2 => {
                        no_heap::push_map_header(out, 3).ok();
                        no_heap::push_uint(out, 1).ok();
                        no_heap::push_map_header(out, 1).ok();
                        no_heap::push_tstr(out, "id").ok();
                        no_heap::push_tstr(out, rp_str).ok();
                        no_heap::push_uint(out, 2).ok();
                        no_heap::push_bstr(out, &hash).ok();
                        no_heap::push_uint(out, 7).ok();
                        no_heap::push_uint(out, total as u64).ok();
                    }
                    // PicoForge: rp(3) ‖ rpIdHash(4) ‖ totalRps(5), byte for
                    // byte what it has always been sent.
                    CmDialect::PicoForge => {
                        no_heap::push_map_header(out, 3).ok();
                        no_heap::push_uint(out, 3).ok();
                        no_heap::push_map_header(out, 1).ok();
                        no_heap::push_tstr(out, "id").ok();
                        no_heap::push_tstr(out, rp_str).ok();
                        no_heap::push_uint(out, 4).ok();
                        no_heap::push_bstr(out, &hash).ok();
                        no_heap::push_uint(out, 5).ok();
                        no_heap::push_uint(out, total as u64).ok();
                    }
                }
                Ok(())
            }
            CM_ENUMERATE_RPS_NEXT => {
                // enumerateRpsGetNext
                let mut done = false;
                let result = (|| -> Result<([u8; 32], heapless::Vec<u8, 64>, CmDialect), Err> {
                    let Some(state) = self.cm_rp_state.as_mut() else {
                        return Err(err(Ctap2Response::NotAllowed));
                    };
                    if state.channel != self.current_channel {
                        return Err(err(Ctap2Response::NotAllowed));
                    }
                    if state.cursor >= state.rps.len() {
                        self.cm_rp_state = None;
                        return Err(err(Ctap2Response::NotAllowed));
                    }
                    let item = state.rps[state.cursor].clone();
                    state.cursor += 1;
                    if state.cursor >= state.rps.len() {
                        done = true;
                    }
                    Ok((item.0, item.1, state.dialect))
                })();
                let (hash, rp_id, dialect) = result?;
                // This request's own bytes cannot say which dialect it is —
                // both dialects send exactly `{1: 0x03}` here — so the
                // enumeration it continues decides the response shape.
                self.cm_dialect = dialect;
                if done {
                    self.cm_rp_state = None;
                }
                let rp_str =
                    core::str::from_utf8(rp_id.as_slice()).map_err(|_| err(Ctap2Response::InvalidCbor))?;
                // CTAP2 omits totalRps here — only the Begin response carries
                // it (key 7). PicoForge's two-key shape is unchanged.
                let rp_key = match self.cm_dialect {
                    CmDialect::Ctap2 => 1u64,
                    CmDialect::PicoForge => 3,
                };
                let hash_key = match self.cm_dialect {
                    CmDialect::Ctap2 => 2u64,
                    CmDialect::PicoForge => 4,
                };
                no_heap::push_map_header(out, 2).ok();
                no_heap::push_uint(out, rp_key).ok();
                no_heap::push_map_header(out, 1).ok();
                no_heap::push_tstr(out, "id").ok();
                no_heap::push_tstr(out, rp_str).ok();
                no_heap::push_uint(out, hash_key).ok();
                no_heap::push_bstr(out, &hash).ok();
                Ok(())
            }
            CM_ENUMERATE_CREDS_BEGIN => {
                // enumerateCredsBegin
                let hash = rp_id_hash.ok_or(err(Ctap2Response::MissingParameter))?;
                let mut ids: heapless::Vec<heapless::Vec<u8, 64>, { crate::device_keystore::DEVICE_MAX_CREDS }> =
                    heapless::Vec::new();
                for cred in &self.keystore.credentials {
                    if cred.resident
                        && !cred.revoked
                        && cred.rp_id_hash == hash
                        && ids.push(cred.credential_id.clone()).is_err()
                    {
                        return Err(err(Ctap2Response::LimitExceeded));
                    }
                }
                // newest first
                let mut ordered: heapless::Vec<heapless::Vec<u8, 64>, { crate::device_keystore::DEVICE_MAX_CREDS }> =
                    heapless::Vec::new();
                while let Some(id) = ids.pop() {
                    let _ = ordered.push(id);
                }
                if ordered.is_empty() {
                    return Err(err(Ctap2Response::NoCredentials));
                }
                let total = ordered.len();
                let first = ordered.remove(0);
                self.cm_cred_state = Some(CmCredState { creds: ordered, total, channel: self.current_channel, dialect: self.cm_dialect });
                self.cm_cred_response(&first, total, out)
            }
            CM_ENUMERATE_CREDS_NEXT => {
                // enumerateCredsGetNext
                let result = (|| -> Result<(heapless::Vec<u8, 64>, usize, CmDialect), Err> {
                    let Some(state) = self.cm_cred_state.as_mut() else {
                        return Err(err(Ctap2Response::NotAllowed));
                    };
                    if state.channel != self.current_channel {
                        return Err(err(Ctap2Response::NotAllowed));
                    }
                    if state.creds.is_empty() {
                        self.cm_cred_state = None;
                        return Err(err(Ctap2Response::NotAllowed));
                    }
                    Ok((state.creds.remove(0), state.total, state.dialect))
                })();
                let (id, total, dialect) = result?;
                // PicoForge sends `{1: 0x05}` for this sub-command and CTAP2
                // sends `{1: 0x05}` too — identical bytes, so the request
                // cannot be classified. The enumeration it continues can:
                // PicoForge reads `User` at 0x06 and got a CTAP2-shaped
                // reply here, which is what surfaced as "User not found in
                // EnumerateCredentialsGetNextCredential response".
                self.cm_dialect = dialect;
                if self
                    .cm_cred_state
                    .as_ref()
                    .map(|s| s.creds.is_empty())
                    .unwrap_or(true)
                {
                    self.cm_cred_state = None;
                }
                self.cm_cred_response(&id, total, out)
            }
            CM_DELETE_CRED => {
                // deleteCredential
                let id = cred_id.ok_or(err(Ctap2Response::MissingParameter))?;
                if id.is_empty() {
                    return Err(err(Ctap2Response::MissingParameter));
                }
                match self.keystore.delete_credential(id.as_slice()) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(err(Ctap2Response::NoCredentials)),
                }
            }
            CM_UPDATE_USER => {
                // updateUserInformation
                let id = cred_id.ok_or(err(Ctap2Response::MissingParameter))?;
                let uid = user_id.ok_or(err(Ctap2Response::MissingParameter))?;
                {
                    let cred = self
                        .keystore
                        .get_credential_mut(id.as_slice())
                        .ok_or(err(Ctap2Response::NoCredentials))?;
                    if cred.user_handle != uid && !cred.user_handle.is_empty() {
                        return Err(err(Ctap2Response::InvalidParameter));
                    }
                    if let Some(name) = &user_name {
                        if !name.is_empty() {
                            cred.user_name = name.clone();
                        }
                    }
                    if let Some(dn) = &user_dn {
                        if !dn.is_empty() {
                            cred.user_display_name = dn.clone();
                        }
                    }
                }
                self.keystore.dirty = true;
                Ok(())
            }
            _ => Err(err(Ctap2Response::InvalidCommand)),
        }
    }

    /// Build the enumerateCreds response body for one credential.
    fn cm_cred_response(&self, cred_id: &[u8], total: usize, out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>) -> Result<(), Err> {
        let cred = self
            .keystore
            .get_credential(cred_id)
            .ok_or(err(Ctap2Response::NoCredentials))?;
        let mut n = 4usize;
        if cred.cred_protect > 0 { n += 1; }
        if cred.large_blob_key.is_some() { n += 1; }
        if cred.third_party_payment { n += 1; }
        // CTAP2 §12.1.6 numbers these 1/2/3/4/5/6/7; PicoForge numbers the
        // same seven things 6/7/8/9/0x0A/0x0B/0x0C. The two sets overlap
        // (key 6 is `user` to PicoForge and `largeBlobKey` to CTAP2), so one
        // response cannot satisfy both — it is written in the sender's shape.
        let (k_user, k_cred, k_pk, k_total, k_protect, k_blob, k_tpp) =
            match self.cm_dialect {
                CmDialect::Ctap2 => (1u64, 2, 3, 4, 5, 6, 7),
                CmDialect::PicoForge => (6, 7, 8, 9, 0x0A, 0x0B, 0x0C),
            };
        no_heap::push_map_header(out, n).ok();
        no_heap::push_uint(out, k_user).ok();
        let mut un = 1usize;
        if !cred.user_name.is_empty() { un += 1; }
        if !cred.user_display_name.is_empty() { un += 1; }
        no_heap::push_map_header(out, un).ok();
        no_heap::push_tstr(out, "id").ok();
        no_heap::push_bstr(out, &cred.user_handle).ok();
        if !cred.user_name.is_empty() {
            no_heap::push_tstr(out, "name").ok();
            no_heap::push_tstr(out, core::str::from_utf8(cred.user_name.as_slice()).map_err(|_| err(Ctap2Response::InvalidCbor))?).ok();
        }
        if !cred.user_display_name.is_empty() {
            no_heap::push_tstr(out, "displayName").ok();
            no_heap::push_tstr(out, core::str::from_utf8(cred.user_display_name.as_slice()).map_err(|_| err(Ctap2Response::InvalidCbor))?).ok();
        }
        no_heap::push_uint(out, k_cred).ok();
        no_heap::push_map_header(out, 2).ok();
        no_heap::push_tstr(out, "id").ok();
        no_heap::push_bstr(out, cred_id).ok();
        no_heap::push_tstr(out, "type").ok();
        no_heap::push_tstr(out, "public-key").ok();
        // publicKey — standard COSE wire format
        no_heap::push_uint(out, k_pk).ok();
        cred.public_key.encode_wire(out).map_err(|_| err(Ctap2Response::KeyStoreFull))?;
        no_heap::push_uint(out, k_total).ok();
        no_heap::push_uint(out, total as u64).ok();
        if cred.cred_protect > 0 {
            no_heap::push_uint(out, k_protect).ok();
            no_heap::push_uint(out, cred.cred_protect as u64).ok();
        }
        if let Some(k) = &cred.large_blob_key {
            no_heap::push_uint(out, k_blob).ok();
            no_heap::push_bstr(out, k).ok();
        }
        if cred.third_party_payment {
            no_heap::push_uint(out, k_tpp).ok();
            no_heap::push_bool(out, true).ok();
        }
        Ok(())
    }

    // -- largeBlobs (0x0C) --------------------------------------------------

    pub(crate) fn handle_large_blobs(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        out.clear();
        out.push(0x00).ok();
        let r = self.large_blobs_inner(data, out, store);
        match r {
            Ok(()) => {}
            Err(code) => {
                out.clear();
                out.push(code).ok();
            }
        }
        out.len()
    }

    fn large_blobs_inner(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> Result<(), Err> {
        if data.is_empty() {
            return Err(err(Ctap2Response::MissingParameter));
        }
        let mut get: Option<usize> = None;
        let mut set: Option<HeaplessVec<u8, { crate::CTAP2_MAX_MSG - 16 }>> = None;
        let mut offset = 0usize;
        let mut length: Option<usize> = None;
        let mut param: Option<HeaplessVec<u8, 64>> = None;
        let mut protocol: u8 = 1;
        {
            let mut p = Parser::new(data);
            let Item::Map(n) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                return Err(err(Ctap2Response::InvalidCbor));
            };
            for _ in 0..n {
                let key = match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                    Item::U(k) => k,
                    _ => return Err(err(Ctap2Response::InvalidCbor)),
                };
                match key {
                    1 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => get = Some(u as usize),
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    },
                    2 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::B(b) => {
                            let mut v = HeaplessVec::new();
                            if v.extend_from_slice(b).is_err() {
                                return Err(err(Ctap2Response::InvalidParameter));
                            }
                            set = Some(v);
                        }
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    },
                    3 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => offset = u as usize,
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    },
                    4 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => length = Some(u as usize),
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    },
                    5 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::B(b) => {
                            let mut v = HeaplessVec::new();
                            if v.extend_from_slice(b).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            param = Some(v);
                        }
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    },
                    6 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => protocol = u as u8,
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    },
                    _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                }
            }
        }

        if let Some(fragment) = set {
            // Write path: pinUvAuth over 0xff*32 || 0x0c 0x00 || offset u32LE
            // || SHA-256(fragment); token must carry the lbf permission.
            let param = param.ok_or(err(Ctap2Response::PuatRequired))?;
            if protocol != 1 && protocol != 2 {
                return Err(err(Ctap2Response::InvalidParameter));
            }
            let token = self.pin_token.ok_or(err(Ctap2Response::PinAuthInvalid))?;
            if !self.token_allows(PERM_LBF) {
                return Err(err(Ctap2Response::PinAuthInvalid));
            }
            let mut msg: HeaplessVec<u8, 96> = HeaplessVec::new();
            for _ in 0..32 {
                msg.push(0xff).ok();
            }
            msg.extend_from_slice(&[0x0c, 0x00]).ok();
            msg.extend_from_slice(&(offset as u32).to_le_bytes()).ok();
            let mut frag_hash = [0u8; 32];
            crypto::sha256_into(fragment.as_slice(), &mut frag_hash);
            msg.extend_from_slice(&frag_hash).ok();
            if !crypto::pin_verify_auth(protocol, &token, msg.as_slice(), &param) {
                return Err(self.note_pin_auth_failure());
            }
            self.auth_failures = 0;
            // Fragment assembly.
            if offset == 0 {
                let total = match length {
                    Some(l) if l > LB_CHECKSUM_LEN && l <= crate::device_keystore::LARGE_BLOB_MAX => l,
                    _ => return Err(err(Ctap2Response::InvalidParameter)),
                };
                if fragment.len() > total {
                    return Err(err(Ctap2Response::InvalidParameter));
                }
                let mut buf: heapless::Vec<u8, { crate::device_keystore::LARGE_BLOB_MAX }> =
                    heapless::Vec::new();
                if buf.extend_from_slice(fragment.as_slice()).is_err() {
                    return Err(err(Ctap2Response::InvalidParameter));
                }
                self.lb_pending = Some(LbPending { total, buf });
            } else {
                let pending = self.lb_pending.as_mut().ok_or(err(Ctap2Response::InvalidParameter))?;
                if offset != pending.buf.len() || pending.buf.len() + fragment.len() > pending.total {
                    return Err(err(Ctap2Response::InvalidParameter));
                }
                if pending.buf.extend_from_slice(fragment.as_slice()).is_err() {
                    return Err(err(Ctap2Response::InvalidParameter));
                }
            }
            let complete = self
                .lb_pending
                .as_ref()
                .map(|p| p.buf.len() == p.total)
                .unwrap_or(false);
            if complete {
                let pending = self.lb_pending.take().unwrap();
                // Host parity: the stored array INCLUDES its trailing
                // 16-byte checksum (clients strip it on read).
                let check_start = pending.buf.len() - LB_CHECKSUM_LEN;
                let mut expect = [0u8; 32];
                crypto::sha256_into(&pending.buf.as_slice()[..check_start], &mut expect);
                if pending.buf.as_slice()[check_start..] != expect[..LB_CHECKSUM_LEN] {
                    return Err(err(Ctap2Response::IntegrityFailure));
                }
                // SOAK-FINDING-1: transactional commit — the large-blob
                // array grows the snapshot, so it is made durable here or
                // rolled back (an un-persistable dirty state is what wedged
                // the soak).
                let old_lba = self.keystore.large_blob_array.clone();
                let committed = self.keystore.grow_checked(
                    store,
                    |ks| {
                        ks.large_blob_array = Some(pending.buf);
                        ks.dirty = true;
                    },
                    |ks| ks.large_blob_array = old_lba,
                );
                if !committed {
                    return Err(err(Ctap2Response::KeyStoreFull));
                }
            }
            return Ok(());
        }

        // Read path.
        let get = get.ok_or(err(Ctap2Response::InvalidParameter))?;
        let empty = {
            // Default: the encoded empty array + its truncated SHA-256.
            let mut d = HeaplessVec::new();
            d.push(0x80).ok();
            let mut h = [0u8; 32];
            crypto::sha256_into(&[0x80], &mut h);
            d.extend_from_slice(&h[..LB_CHECKSUM_LEN]).ok();
            d
        };
        let arr = match &self.keystore.large_blob_array {
            Some(a) => a.clone(),
            None => empty,
        };
        if offset >= arr.len() {
            return Err(err(Ctap2Response::InvalidParameter));
        }
        let end = (offset + get).min(arr.len());
        no_heap::push_map_header(out, 1).ok();
        no_heap::push_uint(out, 1).ok();
        no_heap::push_bstr(out, &arr[offset..end]).ok();
        Ok(())
    }

    // -- authenticatorConfig (0x0D) -----------------------------------------

    pub(crate) fn handle_authenticator_config(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        out.clear();
        out.push(0x00).ok();
        let r = self.authenticator_config_inner(data, out, store);
        match r {
            Ok(()) => {}
            Err(code) => {
                out.clear();
                out.push(code).ok();
            }
        }
        out.len()
    }

    fn authenticator_config_inner(
        &mut self,
        data: &[u8],
        _out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        // `mut` is US-170's, and only US-170's: the RS-Key soft-lock arms
        // reborrow this (`&mut store`) so `with_keystore_ops` can hand it to
        // `KeystoreVendorOps`. Every other arm here *moves* it into
        // `grow_checked` and never rebinds it, so a by-value parameter was
        // enough until the one arm that hands it out rather than takes it.
        mut store: Option<&mut dyn SecureStore>,
    ) -> Result<(), Err> {
        if data.is_empty() {
            return Err(err(Ctap2Response::MissingParameter));
        }
        let mut sub_cmd: u8 = 0;
        let mut protocol: u8 = 2;
        let mut param: Option<HeaplessVec<u8, 64>> = None;
        let mut params: Option<(usize, usize)> = None; // raw byte range
        {
            let mut p = Parser::new(data);
            let Item::Map(n) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                return Err(err(Ctap2Response::InvalidCbor));
            };
            for _ in 0..n {
                let key = match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                    Item::U(k) => k,
                    _ => return Err(err(Ctap2Response::InvalidCbor)),
                };
                match key {
                    1 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => sub_cmd = u as u8,
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    },
                    3 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => protocol = u as u8,
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    },
                    4 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::B(b) => {
                            let mut v = HeaplessVec::new();
                            if v.extend_from_slice(b).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            param = Some(v);
                        }
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    2 => {
                        let start = p.pos();
                        p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?;
                        params = Some((start, p.pos()));
                    }
                    _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                }
            }
        }
        if sub_cmd == 0 {
            return Err(err(Ctap2Response::MissingParameter));
        }
        // PIN auth: config commands require the ACFG permission and verify
        // over 0xff*32 || 0x0d || subcmd || cbor(params).
        if self.keystore.pin_state.pin_hash.is_none() {
            return Err(err(Ctap2Response::PinNotSet));
        }
        if self.keystore.pin_state.needs_power_cycle {
            return Err(err(Ctap2Response::PinAuthBlocked));
        }
        let token = self.pin_token.ok_or(err(Ctap2Response::PinAuthInvalid))?;
        if self.token_permissions & PERM_ACFG == 0 {
            return Err(err(Ctap2Response::PinAuthInvalid));
        }
        if protocol != 1 && protocol != 2 {
            return Err(err(Ctap2Response::InvalidParameter));
        }
        let mut msg: HeaplessVec<u8, 288> = HeaplessVec::new();
        for _ in 0..32 {
            msg.push(0xff).ok();
        }
        msg.extend_from_slice(&[0x0d, sub_cmd]).ok();
        if let Some((s, e)) = params {
            msg.extend_from_slice(&data[s..e]).ok();
        }
        let param = param.ok_or(err(Ctap2Response::PuatRequired))?;
        if !crypto::pin_verify_auth(protocol, &token, msg.as_slice(), &param) {
            return Err(self.note_pin_auth_failure());
        }
        self.auth_failures = 0;

        match sub_cmd {
            0x01 => {
                // enableEnterpriseAttestation
                self.keystore.pin_state.enterprise_attestation = true;
                self.keystore.dirty = true;
                Ok(())
            }
            0x02 => {
                // toggleAlwaysUv
                self.keystore.pin_state.always_uv = !self.keystore.pin_state.always_uv;
                self.keystore.dirty = true;
                Ok(())
            }
            0x03 => {
                // setMinPINLength: params {1: newMinPinLength, 2: minPinRPIDs,
                // 3: forceChangePin, 4: pinComplexityPolicy}
                let (s, e) = params.ok_or(err(Ctap2Response::MissingParameter))?;
                let mut new_min: Option<u64> = None;
                let mut rp_ids: heapless::Vec<heapless::Vec<u8, TEXT_MAX>, 8> = heapless::Vec::new();
                let mut p = Parser::new(&data[s..e]);
                let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? else {
                    return Err(err(Ctap2Response::InvalidParameter));
                };
                for _ in 0..m {
                    let key = match p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? {
                        Item::U(k) => k,
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    };
                    match key {
                        1 => match p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? {
                            Item::U(u) => new_min = Some(u),
                            _ => return Err(err(Ctap2Response::InvalidParameter)),
                        },
                        2 | 3 => {
                            let Item::Array(a) = p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? else {
                                return Err(err(Ctap2Response::InvalidParameter));
                            };
                            for _ in 0..a {
                                match p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? {
                                    Item::T(t) => {
                                        let mut v = HeaplessVec::new();
                                        if v.extend_from_slice(t.as_bytes()).is_err() || rp_ids.push(v).is_err() {
                                            return Err(err(Ctap2Response::LimitExceeded));
                                        }
                                    }
                                    _ => return Err(err(Ctap2Response::InvalidParameter)),
                                }
                            }
                        }
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidParameter))?,
                    }
                }
                if let Some(min) = new_min {
                    if !(4..=63).contains(&min) {
                        return Err(err(Ctap2Response::PinPolicyViolation));
                    }
                    if (min as u8) < self.keystore.pin_state.min_pin_length {
                        return Err(err(Ctap2Response::PinPolicyViolation));
                    }
                }
                // SOAK-FINDING-1: the minPinLength RP-id list grows the
                // snapshot — commit transactionally (durable or undone).
                let old_min = self.keystore.pin_state.min_pin_length;
                let old_ids = self.keystore.pin_state.min_pin_rp_ids.clone();
                let committed = self.keystore.grow_checked(
                    store,
                    |ks| {
                        if let Some(min) = new_min {
                            ks.pin_state.min_pin_length = min as u8;
                        }
                        if !rp_ids.is_empty() {
                            ks.pin_state.min_pin_rp_ids = rp_ids;
                        }
                        ks.dirty = true;
                    },
                    |ks| {
                        ks.pin_state.min_pin_length = old_min;
                        ks.pin_state.min_pin_rp_ids = old_ids;
                    },
                );
                if !committed {
                    return Err(err(Ctap2Response::KeyStoreFull));
                }
                Ok(())
            }
            0x04 => {
                // setEnterpriseRPIDList: params {1: [rpId]}
                let (s, e) = params.ok_or(err(Ctap2Response::MissingParameter))?;
                let mut ids: heapless::Vec<heapless::Vec<u8, TEXT_MAX>, 8> = heapless::Vec::new();
                let mut p = Parser::new(&data[s..e]);
                let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? else {
                    return Err(err(Ctap2Response::InvalidParameter));
                };
                for _ in 0..m {
                    let key = match p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? {
                        Item::U(k) => k,
                        _ => return Err(err(Ctap2Response::InvalidParameter)),
                    };
                    match key {
                        1 => {
                            let Item::Array(a) = p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? else {
                                return Err(err(Ctap2Response::InvalidParameter));
                            };
                            for _ in 0..a {
                                match p.next().map_err(|_| err(Ctap2Response::InvalidParameter))? {
                                    Item::T(t) => {
                                        let mut v = HeaplessVec::new();
                                        if v.extend_from_slice(t.as_bytes()).is_err() || ids.push(v).is_err() {
                                            return Err(err(Ctap2Response::LimitExceeded));
                                        }
                                    }
                                    _ => return Err(err(Ctap2Response::InvalidParameter)),
                                }
                            }
                        }
                        _ => p.skip().map_err(|_| err(Ctap2Response::InvalidParameter))?,
                    }
                }
                // SOAK-FINDING-1: transactional commit (durable or undone).
                let old_ids = self.keystore.pin_state.enterprise_rp_ids.clone();
                let committed = self.keystore.grow_checked(
                    store,
                    |ks| {
                        ks.pin_state.enterprise_rp_ids = ids;
                        ks.dirty = true;
                    },
                    |ks| ks.pin_state.enterprise_rp_ids = old_ids,
                );
                if !committed {
                    return Err(err(Ctap2Response::KeyStoreFull));
                }
                Ok(())
            }
            0xFF => {
                // US-113: `vendorPrototype` — the pico-fido legacy physical
                // config framing (PicoForge framing (B)). It arrives *here*,
                // inside the sub-command `match`, because `0xFF` is a
                // sub-command of `authenticatorConfig` (0x0D) and not a
                // top-level CTAP2 opcode; the gate above has already
                // established a set PIN, a live token carrying PERM_ACFG, and
                // a valid MAC over these exact params bytes.
                //
                // Framings (B) and (C) cannot alias: (C) is the top-level
                // opcode `0x41`, dispatched in `process_ctap2_with_store`'s
                // own `match`, and its sub-commands are one byte where these
                // ids are 64.
                let (s, e) = params.ok_or(err(Ctap2Response::MissingParameter))?;
                // US-170: the RS-Key soft-lock pair shares this arm rather
                // than getting a second one, for the same reason the framing
                // is here at all — `0xFF` is a *sub*-command, so the one place
                // that answers it is this `match`, and a parallel `0xFF` arm
                // elsewhere would be a second answer to "which vendor ids
                // exist". The lookup is the two ids, not a second decode:
                // `PhyCommand::decode` has never heard of them and answers
                // `0x02` for both, so it cannot be the thing that recognises
                // them, and asking it to would mean teaching the pico-fido
                // framing about a PicoForge RS-Key command.
                //
                // Order within the arm is therefore the id set, and the two
                // sets are disjoint 64-bit values
                // (`tests/vendor_lock.rs::no_rs_key_lock_id_collides_with_a_vendorff_or_credential_id`),
                // so the check below can only ever divert a request the
                // framing would have refused as an unknown id anyway.
                if let Some(id) = rs_key_lock_id(&data[s..e]) {
                    return self.config_vendor_lock(data, id, &mut store);
                }
                let cmd = crate::vendorff::PhyCommand::decode(&data[s..e]).map_err(err)?;
                // Refuse before opening the transaction: a range failure must
                // not be reported out of a closure whose error channel the
                // store borrow has already consumed.
                crate::vendorff::validate(&cmd).map_err(err)?;
                // SOAK-FINDING-1 parity: committed transactionally, so a
                // snapshot that cannot be made durable is a clean rejection
                // rather than a dirty latch the HID task's persist gate would
                // then fail on.
                let old_phy = self.keystore.phy;
                let committed = self.keystore.grow_checked(
                    store,
                    |ks| {
                        // `validate` ran one line up, and `apply` repeats
                        // every range check rather than trusting that, so the
                        // `Result` here cannot be `Err` unless the two
                        // functions disagree — which would be a bug in
                        // `vendorff` itself, not in this caller. It is
                        // discarded rather than propagated because the
                        // closure's error channel has nowhere to go once the
                        // store borrow has been taken; `phy` is
                        // size-stable either way, so the dirty snapshot the
                        // gate would program is still parseable.
                        let _ = crate::vendorff::apply(&mut ks.phy, &cmd);
                        ks.dirty = true;
                    },
                    |ks| ks.phy = old_phy,
                );
                if !committed {
                    return Err(err(Ctap2Response::KeyStoreFull));
                }
                Ok(())
            }
            _ => Err(err(Ctap2Response::InvalidSubcommand)),
        }
    }

    /// US-170: run one `authenticatorConfig` soft-lock arm on the device.
    ///
    /// Reached only from the `0xFF` arm of [`FidoApp::authenticator_config_inner`],
    /// and only with an `id` that is not one of the pico-fido physical-config
    /// ids — so the dispatch decision itself is made in the caller, in the
    /// same `match` that answers the framing, and this method only maps a
    /// recognised id onto an arm.
    ///
    /// ## The four borrows
    ///
    /// Identical in shape to the `0x41` arm in `device_app.rs:643-665`:
    /// `KeystoreVendorOps` needs the snapshot, the volatile session, the store
    /// and an entropy closure, and they are four **disjoint fields** of this
    /// app. The closure captures only `rng_pool` and `rng_cursor`
    /// (edition-2021 disjoint capture) precisely so it can be taken while
    /// `keystore` and `vendor_session` are borrowed mutably beside it; a
    /// `&mut self` method for the entropy — the shape this app has everywhere
    /// else — would borrow the whole struct and collide with all of them. That
    /// is the whole reason `take_random` is a free function
    /// (`device_core.rs:674`).
    ///
    /// `store` is **reborrowed** (`&mut store`), not moved. It is this
    /// function's own `Option<&mut dyn SecureStore>` parameter, so the reborrow
    /// ends when the closure does and the caller's own `store` is whole again
    /// on return — which is what lets `authenticator_config_inner` keep passing
    /// `store` *by value* into the `grow_checked` calls in the `0x03`/`0x04`/
    /// `0xFF` framing arms with no change to their signatures. Threading a
    /// `&mut Option<..>` through `handle_authenticator_config` instead would
    /// have been a wider edit for a borrow the reborrow already scopes
    /// correctly.
    ///
    /// ## The gate ran already, and is run again anyway
    ///
    /// `authenticator_config_inner` verified the `0x0D` MAC over
    /// **`&data[s..e]`** — the client's own bytes, not a re-encoding — and
    /// established a set PIN, an unlatched app, a live token and `PERM_ACFG`
    /// before the `match` was reached. So the `TokenAuth` built here is
    /// already known-good and is passed in anyway:
    /// [`crate::vendor_lock::lock_engage`] and [`crate::vendor_lock::lock_release`]
    /// are also `0x41`-channel code in the same module and have no way to know
    /// which caller they are under, so the gate inside them is the only gate
    /// they have. Re-running it costs one HMAC and buys a refusal that does
    /// not depend on this function remembering what the caller did.
    ///
    /// `blocked: false` is **derived**, not assumed: the latch
    /// (`keystore.pin_state.needs_power_cycle`) is checked above the `match`
    /// and returns `PinAuthBlocked` before this is entered, so a `true` here
    /// is unreachable. It is written as the constant rather than read from the
    /// field so that the "and if that check ever moves" question has an answer
    /// at this line instead of needing one.
    fn config_vendor_lock(
        &mut self,
        data: &[u8],
        id: u64,
        store: &mut Option<&mut dyn SecureStore>,
    ) -> Result<(), Err> {
        // `token` is a `[u8; 32]` by value (`Copy`), so `auth` below borrows a
        // local rather than a field of this app — which is what lets the four
        // field borrows coexist at all. `self.token_permissions` is a `u8`
        // read here, for the same reason.
        let auth = crate::vendor41::TokenAuth {
            token: &self.pin_token.ok_or(err(Ctap2Response::PinAuthInvalid))?,
            permissions: self.token_permissions,
            blocked: false,
        };
        let mut random =
            |buf: &mut [u8]| take_random(&mut self.rng_pool, &mut self.rng_cursor, buf);
        let outcome = crate::vendor_state::with_keystore_ops(
            &mut self.keystore,
            &mut self.vendor_session,
            store,
            &mut random,
            |ops| {
                if id == crate::vendor_lock::AUT_ENABLE {
                    crate::vendor_lock::lock_engage(ops, data, Some(auth))
                } else if id == crate::vendor_lock::AUT_DISABLE {
                    crate::vendor_lock::lock_release(ops, data, Some(auth))
                } else {
                    // Unreachable from the caller, which only forwards the two
                    // ids — but a default arm that picked the wrong one of the
                    // two would engage a lock, so it refuses instead.
                    crate::vendor41::Outcome::plain(Ctap2Response::InvalidParameter)
                }
            },
        );
        // `Outcome::phy` is ignored on purpose: neither lock arm sets it. The
        // lock record is committed *inside* `KeystoreVendorOps::set_soft_lock`,
        // which is `grow_checked` — apply, persist, undo on failure — so
        // "durable before the ack" is already true by the time this returns,
        // and there is no second record to commit here the way the `0x41` arm
        // has for `config_write`'s `PhyConfig`.
        if outcome.pin_auth_failure {
            // Unreachable given the gate above, and honoured anyway for the
            // reason the host twin does: a charging decision dropped because
            // the caller believed it could not fire is a counter that
            // silently stops counting.
            return Err(self.note_pin_auth_failure());
        }
        match outcome.status {
            Ctap2Response::Ok => Ok(()),
            other => Err(err(other)),
        }
    }
}

/// The RS-Key soft-lock vendor id in a `vendorPrototype` `subCommandParams`
/// map, or `None` when the map does not carry one of the two.
///
/// ## It answers about **two** ids, not "the" id
///
/// That restriction is the whole point and it is load-bearing rather than
/// cosmetic. The first cut of this function returned *any* key-1 unsigned
/// integer, on the reading that it only had to be permissive enough to
/// recognise the two. That reading is wrong: the caller diverts to the
/// soft-lock arms on a `Some`, so a permissive `Some` also diverts
/// `PhysicalLedGpio` — and `config_vendor_lock`'s default arm answers
/// `InvalidParameter` to an id it does not own, so every pico-fido
/// `vendorff` write came back `0x02`.
/// `tests/vendor41.rs::vendor_prototype_set_led_gpio_persists` is what caught
/// it, and it is the reason the next paragraph is about `None`.
///
/// ## `None` is "not mine", not "malformed"
///
/// Every `None` — a params span that is not a map, a map with no key 1, a key
/// 1 that is not an unsigned integer, a CBOR parse failure, or a perfectly
/// well-formed id this firmware does not own — routes the request to the
/// `crate::vendorff` decoder. That decoder owns "what is a valid vendor id"
/// for its framing and produces the right status for a malformed one
/// (`0x02` / `0x12`), so a request this firmware already answered before
/// US-170 keeps exactly the status it had, which is the property that makes
/// adding an arm to this `match` a no-op for every other id.
///
/// ## Why not `PhyCommand::decode` and branch on its `Err`
///
/// Because that would make the pico-fido framing the place that knows the
/// RS-Key command ids, and a decode failure is not a reliable signal anyway:
/// it is also what a `vendorff` id with a *malformed payload* produces, so
/// "decode failed" cannot distinguish "an id I have never heard of" from "an
/// id I know, sent wrong", and treating the second as the first would hand
/// every malformed physical-config write to the soft-lock arms.
///
/// ## First match wins, and it wins on a repeated key
///
/// A repeated key 1 is decided by the **first** value, so a map carrying
/// `1: AUT_ENABLE, 1: AUT_DISABLE` is routed as an engage. That is
/// deliberately the opposite of `vendor_lock::vendor_id`'s rule (which refuses
/// a repeated key 1 as `0x12`): the two can disagree because this answer is
/// only ever used to *route* — the arm it routes to re-parses the very same
/// bytes with the stricter rule, so the permissive answer here is never the
/// answer that reaches the client.
fn rs_key_lock_id(params: &[u8]) -> Option<u64> {
    let mut p = Parser::new(params);
    let Item::Map(n) = p.next().ok()? else { return None };
    for _ in 0..n {
        match p.next().ok()? {
            Item::U(crate::vendor_lock::VENDOR_SUB_PARAM_ID) => {
                return match p.next() {
                    Ok(Item::U(crate::vendor_lock::AUT_ENABLE)) => {
                        Some(crate::vendor_lock::AUT_ENABLE)
                    }
                    Ok(Item::U(crate::vendor_lock::AUT_DISABLE)) => {
                        Some(crate::vendor_lock::AUT_DISABLE)
                    }
                    _ => None,
                }
            }
            _ => p.skip().ok()?,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// S-701-5: U2F (CTAP1 over CTAPHID_MSG) on the device path.
// ---------------------------------------------------------------------------

/// U2F status codes (APDU response, big-endian suffix).
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum U2fStatus {
    NoError = 0x9000,
    WrongData = 0x6A80,
    SecurityStatusNotSatisfied = 0x6982,
    ConditionsNotSatisfied = 0x6985,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    WrongLength = 0x6700,
    /// US-908: enforce-mode AUTHENTICATE without a presence grant — the
    /// CTAP1 `NOT_PRESENT` error byte (0x07) as the response payload.
    NotPresent = 0x0700,
}

impl U2fStatus {
    pub fn code(self) -> u16 {
        self as u16
    }
}

/// FIDO Alliance management AID (SELECT over CTAPHID_MSG).
const U2F_MANAGEMENT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

impl FidoApp {
    /// Process a U2F APDU (device path, no-heap). Response = payload bytes +
    /// status word appended into `out`.
    pub(crate) fn handle_u2f(
        &mut self,
        apdu: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        out.clear();
        let r = self.u2f_inner(apdu, out, store);
        let status = match r {
            Ok(()) => U2fStatus::NoError.code(),
            Err(s) => {
                out.clear();
                s.code()
            }
        };
        out.extend_from_slice(&status.to_be_bytes()).ok();
        out.len()
    }

    fn u2f_inner(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> Result<(), U2fStatus> {
        if data.len() < 5 {
            return Err(U2fStatus::WrongLength);
        }
        let cla = data[0];
        let ins = data[1];
        let p1 = data[2];
        if cla != 0x00 {
            return Err(U2fStatus::ClaNotSupported);
        }
        // LC: short form at data[4]; extended 0x00 || LenHI || LenLO.
        let (lc, hdr): (usize, usize) = if data.len() == 5 {
            (0, 5)
        } else if data[4] == 0x00 {
            if data.len() < 7 {
                return Err(U2fStatus::WrongLength);
            }
            (u16::from_be_bytes([data[5], data[6]]) as usize, 7)
        } else {
            (data[4] as usize, 5)
        };
        let apdu_data = if data.len() >= hdr + lc {
            &data[hdr..hdr + lc]
        } else {
            &data[hdr..]
        };
        match ins {
            0x01 => self.u2f_register(apdu_data, out, store),
            0x02 => self.u2f_authenticate(apdu_data, p1, out, store),
            0x03 => {
                out.extend_from_slice(crate::CTAP1_VERSION.as_bytes()).ok();
                Ok(())
            }
            0xA4 if p1 == 0x04 => {
                // SELECT AID: acknowledge the FIDO management AID.
                if apdu_data == U2F_MANAGEMENT_AID {
                    Ok(())
                } else {
                    Err(U2fStatus::InsNotSupported)
                }
            }
            _ => Err(U2fStatus::InsNotSupported),
        }
    }

    fn u2f_register(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        _store: Option<&mut dyn SecureStore>,
    ) -> Result<(), U2fStatus> {
        // REGISTER: client_param(32) || app_param(32)
        if data.len() < 64 {
            return Err(U2fStatus::WrongLength);
        }
        let client_param = &data[0..32];
        let app_param = &data[32..64];

        // US-908: a silent register must never mint a key handle nor emit
        // an attestation signature. No grant ⇒ SW_CONDITIONS_NOT_SATISFIED
        // (C `cmd_register.c` parity); the attestation path is unchanged.
        // US-921 review (P0-1): the tag is the domain-separated presence
        // tag, not the raw CID (raw channel equality checks elsewhere keep
        // comparing `current_channel` verbatim).
        if !self.user_present(crate::device_app::presence_tag_from_channel(
            self.current_channel,
        )) {
            return Err(U2fStatus::ConditionsNotSatisfied);
        }

        // US-714 (C parity): a U2F registration is STATELESS — the key
        // handle carries a random 32-byte HKDF-salt path plus an HMAC tag
        // binding the appId, and the private scalar is re-derived from the
        // device master at authentication (C `cmd_register.c` →
        // `derive_key`). Nothing is stored: no credential, no chunked part.
        let master = stateless::master_from_device_random(&self.keystore.device_random);
        let mut path = [0u8; stateless::KEY_PATH_LEN];
        let mut word = [0u8; 4];
        for chunk in path.as_chunks_mut::<4>().0 {
            self.draw_random(&mut word);
            word[3] |= 0x80; // C: val |= 0x80000000 (LE word, MSB set)
            chunk.copy_from_slice(&word);
        }
        let scalar = stateless::derive_scalar_from_path(&master, &path);
        let sk = p256::SecretKey::from_slice(scalar.bytes())
            .map_err(|_| U2fStatus::WrongData)?; // ≈2⁻³² scalar ≥ curve order (C: read_key failure)
        let pub_bytes = crypto::public_key_bytes(&sk.public_key());

        // Key handle = path (32) ‖ HMAC-SHA256(scalar, appId ‖ path) (32).
        let mut app_id = [0u8; 32];
        app_id.copy_from_slice(app_param);
        let tag = stateless::handle_tag(&scalar, &app_id, &path);
        let mut cred_id = [0u8; stateless::KEY_HANDLE_LEN];
        cred_id[..stateless::KEY_PATH_LEN].copy_from_slice(&path);
        cred_id[stateless::KEY_PATH_LEN..].copy_from_slice(&tag);
        // Nothing is stored (US-714): U2F creds are stateless and never
        // discoverable (finding 8), and the registration costs no store
        // slot — the scalar dies with this frame, zeroized.

        // Response: 0x05 || pub(65) || kh_len(1) || kh || cert || sig
        out.push(0x05).ok();
        out.extend_from_slice(&pub_bytes).ok();
        out.push(cred_id.len() as u8).ok();
        out.extend_from_slice(&cred_id).ok();
        // US-916: the per-device attestation identity provisioned at boot
        // (see `crate::attestation`) replaces the old repo static pair.
        out.extend_from_slice(self.attestation.cert_bytes()).ok();
        // Signature over 0x00 || app_param || client_param || kh || pub.
        let mut sign_base: HeaplessVec<u8, 200> = HeaplessVec::new();
        sign_base.push(0x00).ok();
        sign_base.extend_from_slice(app_param).ok();
        sign_base.extend_from_slice(client_param).ok();
        sign_base.extend_from_slice(&cred_id).ok();
        sign_base.extend_from_slice(&pub_bytes).ok();
        let mut sig: HeaplessVec<u8, 72> = HeaplessVec::new();
        crypto::p256_sign_der_into(self.attestation.key(), sign_base.as_slice(), &mut sig)
            .ok_or(U2fStatus::WrongData)?;
        out.extend_from_slice(sig.as_slice()).ok();
        Ok(())
    }

    fn u2f_authenticate(
        &mut self,
        data: &[u8],
        p1: u8,
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> Result<(), U2fStatus> {
        // AUTHENTICATE: client_param(32) || app_param(32) || kh_len(1) || kh
        // REGISTER: client_param(32) || app_param(32) — `data` is apdu_data.
        // US-701: the bound is `< 65` (kh_len lives at data[64]) — the host
        // twin u2f.rs is the reference; the device copy had drifted to `< 64`,
        // panicking on a 64-byte body.
        if data.len() < 65 {
            return Err(U2fStatus::WrongLength);
        }
        let client_param = &data[0..32];
        let app_param = &data[32..64];
        let kh_len = data[64] as usize;
        if data.len() < 65 + kh_len {
            return Err(U2fStatus::WrongLength);
        }
        let key_handle = &data[65..65 + kh_len];

        // US-714 (C parity): a stateless-shaped handle (C format, 64 bytes)
        // re-derives its key from the device master and verifies the
        // constant-time appId tag; the legacy store-backed path handles
        // everything else. The store lookup runs first so legacy
        // (pre-US-714) handles keep working unchanged.
        let master = stateless::master_from_device_random(&self.keystore.device_random);
        let mut app_id = [0u8; 32];
        app_id.copy_from_slice(app_param);
        let stateless_valid = stateless::verify_handle(&master, &app_id, key_handle);

        if p1 == 0x07 {
            // Check-only: CONDITIONS_NOT_SATISFIED when valid.
            let legacy_valid = self
                .keystore
                .get_credential(key_handle)
                .map(|c| c.rp_id_hash == app_param)
                .unwrap_or(false);
            if legacy_valid || stateless_valid {
                return Err(U2fStatus::ConditionsNotSatisfied);
            }
            return Err(U2fStatus::WrongData);
        }

        // US-908: enforce mode signs only with a presence grant. No grant
        // ⇒ the CTAP1 NOT_PRESENT error byte (0x07); nothing signs and the
        // counter never moves. Check-only above stays side-effect-free.
        if !self.user_present(crate::device_app::presence_tag_from_channel(
            self.current_channel,
        )) {
            return Err(U2fStatus::NotPresent);
        }

        if stateless_valid {
            // Stateless enforce (C `derive_key` + `verify_key` path): sign
            // with the re-derived scalar. The global counter is the C
            // `ef_counter` parity (a stateless credential has no stored
            // per-credential counter); the bump is transactional and the
            // reply signs the durable value (SOAK-FINDING-1). The scalar is
            // parsed BEFORE the bump (review minor): a parse failure must
            // not consume a durable counter.
            let mut path = [0u8; stateless::KEY_PATH_LEN];
            path.copy_from_slice(&key_handle[..stateless::KEY_PATH_LEN]);
            let scalar = stateless::derive_scalar_from_path(&master, &path);
            let sk =
                p256::SecretKey::from_slice(scalar.bytes()).map_err(|_| U2fStatus::WrongData)?;
            let counter = self.keystore.bump_global_counter_checked(store);

            out.push(0x01).ok(); // user presence
            out.extend_from_slice(&counter.to_be_bytes()).ok();
            let mut sign_base: HeaplessVec<u8, 80> = HeaplessVec::new();
            sign_base.extend_from_slice(app_param).ok();
            sign_base.push(0x01).ok();
            sign_base.extend_from_slice(&counter.to_be_bytes()).ok();
            sign_base.extend_from_slice(client_param).ok();
            let mut sig: HeaplessVec<u8, 72> = HeaplessVec::new();
            crypto::p256_sign_der_into(&sk, sign_base.as_slice(), &mut sig)
                .ok_or(U2fStatus::WrongData)?;
            out.extend_from_slice(sig.as_slice()).ok();
            return Ok(());
        }

        // Legacy (pre-US-714) store-backed handle: per-credential counter.
        let private_key = {
            let cred = self.keystore.get_credential(key_handle).ok_or(U2fStatus::WrongData)?;
            if cred.rp_id_hash != app_param {
                return Err(U2fStatus::WrongData);
            }
            if cred.cred_protect == 3 {
                return Err(U2fStatus::SecurityStatusNotSatisfied);
            }
            cred.private_key
        };
        // SOAK-FINDING-1 review round 2: transactional counter bump —
        // durable or reverted.
        //
        // US-1011: the second half of the original claim — "the reply signs
        // the durable counter so a persist failure can never latch the
        // durable-before-ack gate" — conflated two things, and only half of
        // it survives. The persist-failure half is intact: the bump reverts
        // and the reply signs the durable value. The "signs the durable
        // counter" half is **false now** — the bump is batched, so this
        // returns a RAM-only value on all but every `COUNTER_PERSIST_INTERVAL`
        // -th call. What guarantees non-repetition instead is US-1012's
        // restore: a whole window above the durable image, so a power cut
        // skips forward only. See
        // `device_keystore::bump_credential_counter_checked`.
        let counter = self
            .keystore
            .bump_credential_counter_checked(key_handle, store)
            .ok_or(U2fStatus::WrongData)?;

        out.push(0x01).ok(); // user presence
        out.extend_from_slice(&counter.to_be_bytes()).ok();
        let mut sign_base: HeaplessVec<u8, 80> = HeaplessVec::new();
        sign_base.extend_from_slice(app_param).ok();
        sign_base.push(0x01).ok();
        sign_base.extend_from_slice(&counter.to_be_bytes()).ok();
        sign_base.extend_from_slice(client_param).ok();
        let sk = p256::SecretKey::from_slice(&private_key).map_err(|_| U2fStatus::WrongData)?;
        let mut sig: HeaplessVec<u8, 72> = HeaplessVec::new();
        crypto::p256_sign_der_into(&sk, sign_base.as_slice(), &mut sig).ok_or(U2fStatus::WrongData)?;
        out.extend_from_slice(sig.as_slice()).ok();
        Ok(())
    }

    // -- vendor vault (CTAPHID vendor 0x41, function 0x05) ------------------

    /// Handle the vault vendor function (device path, no-heap). `data` is the
    /// CBOR request {1: subcommand, 2: params, 3: protocol, 4: pinUvAuthParam}.
    pub(crate) fn handle_vendor_vault(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> usize {
        out.clear();
        out.push(0x00).ok();
        let r = self.vendor_vault_inner(data, out, store);
        match r {
            Ok(()) => {}
            Err(code) => {
                out.clear();
                out.push(code).ok();
            }
        }
        out.len()
    }

    fn vendor_vault_inner(
        &mut self,
        data: &[u8],
        out: &mut HeaplessVec<u8, { crate::CTAP2_MAX_MSG }>,
        store: Option<&mut dyn SecureStore>,
    ) -> Result<(), Err> {
        let mut subcommand: Option<u8> = None;
        let mut raw_params: Option<HeaplessVec<u8, 128>> = None;
        let mut protocol: u8 = 1;
        let mut param: Option<HeaplessVec<u8, 64>> = None;
        let mut packet: Option<HeaplessVec<u8, 256>> = None;
        {
            let mut p = Parser::new(data);
            let Item::Map(n) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                return Err(err(Ctap2Response::InvalidCbor));
            };
            for _ in 0..n {
                let key = match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                    Item::U(k) => k,
                    _ => return Err(err(Ctap2Response::InvalidCbor)),
                };
                match key {
                    1 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => subcommand = Some(u as u8),
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    2 => {
                        let start = p.pos();
                        let mut raw = HeaplessVec::new();
                        // Capture the raw params (map) bytes for pin auth and
                        // parse the packet when present.
                        let Item::Map(m) = p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                            return Err(err(Ctap2Response::InvalidCbor));
                        };
                        let _ = m;
                        let end = p.pos();
                        if raw.extend_from_slice(&data[start..end]).is_err() {
                            return Err(err(Ctap2Response::InvalidLength));
                        }
                        raw_params = Some(raw);
                        // packet = params {1: bstr}
                        let mut q = Parser::new(&data[start..end]);
                        let Item::Map(m) = q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? else {
                            return Err(err(Ctap2Response::InvalidCbor));
                        };
                        for _ in 0..m {
                            match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                Item::U(1) => match q.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                                    Item::B(b) => {
                                        let mut v = HeaplessVec::new();
                                        if v.extend_from_slice(b).is_err() {
                                            return Err(err(Ctap2Response::InvalidParameter));
                                        }
                                        packet = Some(v);
                                    }
                                    _ => return Err(err(Ctap2Response::InvalidParameter)),
                                },
                                _ => q.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                            }
                        }
                    }
                    3 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::U(u) => protocol = u as u8,
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    4 => match p.next().map_err(|_| err(Ctap2Response::InvalidCbor))? {
                        Item::B(b) => {
                            let mut v = HeaplessVec::new();
                            if v.extend_from_slice(b).is_err() {
                                return Err(err(Ctap2Response::InvalidLength));
                            }
                            param = Some(v);
                        }
                        _ => return Err(err(Ctap2Response::InvalidCbor)),
                    },
                    _ => p.skip().map_err(|_| err(Ctap2Response::InvalidCbor))?,
                }
            }
        }
        let subcommand = subcommand.ok_or(err(Ctap2Response::MissingParameter))?;

        // Every subcommand except STATUS requires a PIN-authorized token.
        if subcommand != 0x01 {
            let param = param.ok_or(err(Ctap2Response::PuatRequired))?;
            let token = self.pin_token.ok_or(err(Ctap2Response::PinAuthInvalid))?;
            if !self.token_allows(PERM_ACFG) && !self.token_allows(PERM_CM) {
                return Err(err(Ctap2Response::UnauthorizedPermission));
            }
            // auth message: 0xff*32 || 0x0d || subcommand || raw_params
            let mut msg: HeaplessVec<u8, 192> = HeaplessVec::new();
            for _ in 0..32 {
                msg.push(0xff).ok();
            }
            msg.extend_from_slice(&[0x0d, subcommand]).ok();
            if let Some(raw) = &raw_params {
                msg.extend_from_slice(raw.as_slice()).ok();
            }
            if !crypto::pin_verify_auth(protocol, &token, msg.as_slice(), &param) {
                return Err(self.note_pin_auth_failure());
            }
            self.auth_failures = 0;
        }

        match subcommand {
            0x01 => {
                // STATUS: enrolled vault id (or empty)
                no_heap::push_map_header(out, 1).ok();
                no_heap::push_uint(out, 1).ok();
                match &self.keystore.vault_state {
                    Some(v) => no_heap::push_bstr(out, v).ok(),
                    None => no_heap::push_bstr(out, b"").ok(),
                };
                Ok(())
            }
            0x02 => {
                // ENROLL_BEGIN: fresh X448 keypair + challenge
                let mut secret_bytes = [0u8; 56];
                self.draw_random(&mut secret_bytes);
                let secret = x448::Secret::from_bytes(&secret_bytes)
                    .ok_or(err(Ctap2Response::Processing))?;
                let public = x448::PublicKey::from(&secret);
                let mut challenge = [0u8; 32];
                self.draw_random(&mut challenge);
                let mut pub_bytes = [0u8; 56];
                pub_bytes.copy_from_slice(public.as_bytes());
                self.vault_pending = Some(VaultPending {
                    secret: *secret.as_bytes(),
                    public: pub_bytes,
                    challenge,
                });
                no_heap::push_map_header(out, 2).ok();
                no_heap::push_uint(out, 1).ok();
                no_heap::push_bstr(out, &pub_bytes).ok();
                no_heap::push_uint(out, 2).ok();
                no_heap::push_bstr(out, &challenge).ok();
                Ok(())
            }
            0x03 => {
                // ENROLL_FINISH
                let pending = match self.vault_pending.take() {
                    Some(p) => p,
                    None => return Err(err(Ctap2Response::NotAllowed)),
                };
                let packet = packet.ok_or(err(Ctap2Response::InvalidParameter))?;
                if packet.len() < 2 + 12 + 16 {
                    return Err(err(Ctap2Response::InvalidParameter));
                }
                let cert_len = u16::from_be_bytes([packet[0], packet[1]]) as usize;
                if packet.len() < 2 + cert_len + 12 + 16 {
                    return Err(err(Ctap2Response::InvalidParameter));
                }
                let cert = &packet[2..2 + cert_len];
                let nonce: [u8; 12] = packet[2 + cert_len..2 + cert_len + 12]
                    .try_into()
                    .map_err(|_| err(Ctap2Response::InvalidParameter))?;
                let cert_public = crate::vault::x448_public_from_cert(cert)
                    .ok_or(err(Ctap2Response::InvalidParameter))?;
                let peer = x448::PublicKey::from_bytes(&cert_public)
                    .ok_or(err(Ctap2Response::InvalidParameter))?;
                let secret = x448::Secret::from_bytes(&pending.secret)
                    .ok_or(err(Ctap2Response::Processing))?;
                let shared = secret
                    .to_diffie_hellman(&peer)
                    .ok_or(err(Ctap2Response::InvalidParameter))?;
                let mut info: HeaplessVec<u8, 256> = HeaplessVec::new();
                info.extend_from_slice(crate::vault::ENROLL_INFO).ok();
                info.extend_from_slice(&pending.challenge).ok();
                info.extend_from_slice(&cert_public).ok();
                info.extend_from_slice(&pending.public).ok();
                let mut session_key = [0u8; 32];
                {
                    use hkdf::Hkdf;
                    let hk = Hkdf::<sha2::Sha256>::new(None, shared.as_bytes());
                    hk.expand(info.as_slice(), &mut session_key)
                        .map_err(|_| err(Ctap2Response::KeyStoreFull))?;
                }
                let body_start = 2 + cert_len + 12;
                let mut body: HeaplessVec<u8, 128> = HeaplessVec::new();
                if body.extend_from_slice(&packet[body_start..]).is_err() {
                    return Err(err(Ctap2Response::InvalidParameter));
                }
                let plain_len = crate::vault::decrypt_enrollment_packet_in_place(
                    &session_key,
                    &nonce,
                    &mut body,
                    info.as_slice(),
                )
                .ok_or(err(Ctap2Response::IntegrityFailure))?;
                if plain_len < 32 + 1 {
                    return Err(err(Ctap2Response::InvalidParameter));
                }
                let mut vault_id = [0u8; 32];
                {
                    let mut m: HeaplessVec<u8, 64> = HeaplessVec::new();
                    m.extend_from_slice(crate::vault::VAULT_ID_DOMAIN).ok();
                    m.extend_from_slice(&body.as_slice()[..32]).ok();
                    crypto::sha256_into(m.as_slice(), &mut vault_id);
                }
                // SOAK-FINDING-1: transactional commit (durable or undone).
                let old_vault = self.keystore.vault_state;
                let committed = self.keystore.grow_checked(
                    store,
                    |ks| {
                        ks.vault_state = Some(vault_id);
                        ks.dirty = true;
                    },
                    |ks| ks.vault_state = old_vault,
                );
                if !committed {
                    return Err(err(Ctap2Response::KeyStoreFull));
                }
                no_heap::push_map_header(out, 1).ok();
                no_heap::push_uint(out, 1).ok();
                no_heap::push_bstr(out, &vault_id).ok();
                Ok(())
            }
            0x04 | 0x05 => Err(err(Ctap2Response::NotAllowed)),
            0x06 => {
                // UNENROLL
                self.keystore.vault_state = None;
                self.keystore.dirty = true;
                Ok(())
            }
            _ => Err(err(Ctap2Response::InvalidSubcommand)),
        }
    }
}
