//! EPIC `FIDO-SSH-RESIDENT-KEYS` (US-1615…US-1627) — `ssh-keygen -K` must
//! download fapico2's resident keys.
//!
//! # The defect, in one paragraph
//!
//! `ssh-keygen -K` drives **libfido2 1.14.0**, whose `credman_tx` transmits
//! *every* credential-management operation with the hard-coded command byte
//! `CTAP_CBOR_CRED_MGMT_PRE` (`0x41`) — no `0x0A` fallback exists in that
//! release. fapico2 routes `0x41` to the RS-Key vendor channel
//! (`vendor41::CMD`), so libfido2's very first credMgmt call
//! (`getCredsMetadata`) never reaches `handle_cred_mgmt`. The two request
//! grammars are the same CBOR shape (`{1: subCommand, 2: params?, 3:
//! pinUvAuthProtocol, 4: pinUvAuthParam}`), so the preview request is parsed
//! as RS-Key `Mse` (`0x01`), and the vendor channel answers a vendor-class
//! status. OpenSSH's error ladder (`sk_usbhid.c:723` → `ssh_sk.c:350` →
//! `ssherr.c`) turns any status outside the `0x33/0x34/0x36` class into
//! `SSH_ERR_INVALID_FORMAT` — the reported *"Unable to load resident keys:
//! invalid format"*.
//!
//! These tests drive the **device twin** (`device_app::FidoApp` over
//! `HostTrng`/`HostSecureStore`) exactly as `credmgmt_ctap2_spec.rs`
//! does, so the shipping command path is what is asserted — not the host
//! twin (AGENTS.md §1).
//!
//! # Story map
//!
//! * US-1615 — the gate: libfido2's metadata request on `0x41` must be
//!   answered with preview-shape metadata (keys 1/2). Was `#[ignore]`d with
//!   the captured pre-fix byte (`0x14`) until US-1618 routed it.
//! * US-1618 — the full libfido2 `read_rks` walk on `0x41`, and vendor41
//!   surviving on the same command byte.

use fapico2_fido::cbor::no_heap as nh;
use fapico2_fido::cbor::no_heap::{Item, Parser};
use fapico2_fido::crypto;
use fapico2_fido::device_app::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HV;

fn grant_always(_tag: u32) -> bool {
    true
}

fn client_sk() -> p256::SecretKey {
    p256::SecretKey::from_slice(&[0x77u8; 32]).unwrap()
}

/// Push the canonical client COSE key: kty(1)=2, alg(3)=-25, crv(-1)=1,
/// x(-2), y(-3).
fn push_client_cose<const N: usize>(out: &mut HV<u8, N>, x: &[u8; 32], y: &[u8; 32]) {
    nh::push_map_header(out, 5).unwrap();
    nh::push_uint(out, 1).unwrap();
    nh::push_uint(out, 2).unwrap();
    nh::push_uint(out, 3).unwrap();
    nh::push_neg(out, -25).unwrap();
    nh::push_neg(out, -1).unwrap();
    nh::push_uint(out, 1).unwrap();
    nh::push_neg(out, -2).unwrap();
    nh::push_bstr(out, x).unwrap();
    nh::push_neg(out, -3).unwrap();
    nh::push_bstr(out, y).unwrap();
}

fn client_coords() -> ([u8; 32], [u8; 32]) {
    let bytes = crypto::public_key_bytes(&client_sk().public_key());
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    (x, y)
}

/// A PIN-set device twin with a protocol-1 shared secret, mirroring
/// `credmgmt_ctap2_spec.rs::device_twin::Dev`.
struct Dev {
    app: FidoApp,
    /// Protocol-1 shared secret: hmac_key == enc_key == k.
    k: [u8; 32],
    x: [u8; 32],
    y: [u8; 32],
}

impl Dev {
    fn boot() -> Self {
        let mut trng = HostTrng::new();
        let mut store = HostSecureStore::new();
        let mut app = FidoApp::boot(&mut trng, &mut store).unwrap();
        app.set_presence_grant(grant_always);
        let (x, y) = client_coords();

        // getKeyAgreement (0x02) → the authenticator's P-256 point.
        let mut req: HV<u8, 32> = HV::new();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        let resp = Self::raw(&mut app, 0x06, req.as_slice());
        assert_eq!(resp[0], 0x00, "getKeyAgreement must succeed");
        let mut p = Parser::new(&resp[1..]);
        let Item::Map(nm) = p.next().unwrap() else {
            panic!("map")
        };
        let mut dev_pub = None;
        for _ in 0..nm {
            let k = match p.next().unwrap() {
                Item::U(u) => u,
                other => panic!("key {:?}", other),
            };
            if k == 1 {
                let Item::Map(nc) = p.next().unwrap() else {
                    panic!("cose map")
                };
                let (mut dx, mut dy) = ([0u8; 32], [0u8; 32]);
                for _ in 0..nc {
                    let lbl = match p.next().unwrap() {
                        Item::U(u) => u as i64,
                        Item::N(n) => n,
                        other => panic!("label {:?}", other),
                    };
                    match lbl {
                        -2 => {
                            if let Item::B(b) = p.next().unwrap() {
                                dx.copy_from_slice(&b[..32]);
                            }
                        }
                        -3 => {
                            if let Item::B(b) = p.next().unwrap() {
                                dy.copy_from_slice(&b[..32]);
                            }
                        }
                        _ => {
                            p.next().unwrap();
                        }
                    }
                }
                dev_pub = Some((dx, dy));
            } else {
                p.next().unwrap();
            }
        }
        let (dx, dy) = dev_pub.expect("peerCoseKey at label 1");
        let device_pub =
            crypto::parse_cose_ec2_p256_bytes(&dx, &dy).expect("peer key must be a valid P-256 point");
        let raw = crypto::ecdh_shared_secret(&client_sk(), &device_pub);
        let k = crypto::derive_shared_secret_v1(&raw);
        Self { app, k, x, y }
    }

    fn raw(app: &mut FidoApp, cmd: u8, payload: &[u8]) -> Vec<u8> {
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = app.process_ctap2(cmd, payload, [1, 2, 3, 4], &mut out);
        out[..n].to_vec()
    }

    fn call(&mut self, cmd: u8, payload: &[u8]) -> Vec<u8> {
        Self::raw(&mut self.app, cmd, payload)
    }

    /// clientPIN setPIN (v1), as the spec twin does it.
    fn set_pin(&mut self, pin: &[u8]) {
        let mut padded = pin.to_vec();
        while !padded.len().is_multiple_of(16) || padded.len() < 16 {
            padded.push(0);
        }
        let mut buf = [0u8; 96];
        buf[..padded.len()].copy_from_slice(&padded);
        crypto::aes256_cbc_encrypt_into(&self.k, &[0u8; 16], &mut buf[..padded.len()]).unwrap();
        let pin_enc = buf[..padded.len()].to_vec();
        let tag = crypto::hmac_sha256(&self.k, &pin_enc)[..16].to_vec();
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        push_client_cose(&mut req, &self.x, &self.y);
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_bstr(&mut req, &pin_enc).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &tag).unwrap();
        let resp = self.call(0x06, req.as_slice());
        assert_eq!(resp[0], 0x00, "setPIN failed on the device twin");
    }

    /// clientPIN sub-command 0x09 — the PIN token leg, with permissions.
    fn pin_token(&mut self, pin: &[u8], permissions: u8) -> Vec<u8> {
        let pin_hash = crypto::pin_hash(pin);
        let mut padded = pin_hash.to_vec();
        while !padded.len().is_multiple_of(16) {
            padded.push(0);
        }
        let mut buf = [0u8; 96];
        buf[..padded.len()].copy_from_slice(&padded);
        crypto::aes256_cbc_encrypt_into(&self.k, &[0u8; 16], &mut buf[..padded.len()]).unwrap();
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        push_client_cose(&mut req, &self.x, &self.y);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &buf[..padded.len()]).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, permissions as u64).unwrap();
        let resp = self.call(0x06, req.as_slice());
        assert_eq!(resp[0], 0x00, "the 0x09 PIN token leg must still work");
        let mut p = Parser::new(&resp[1..]);
        let Item::Map(nm) = p.next().unwrap() else {
            panic!("map")
        };
        let mut enc: Vec<u8> = Vec::new();
        for _ in 0..nm {
            let k = match p.next().unwrap() {
                Item::U(u) => u,
                other => panic!("key {:?}", other),
            };
            if k == 2 {
                match p.next().unwrap() {
                    Item::B(b) => enc.extend_from_slice(b),
                    other => panic!("pinUvAuthToken {:?}", other),
                }
            } else {
                p.next().unwrap();
            }
        }
        let token = crypto::pin_decrypt_v1(&self.k, &enc).expect("decrypt token");
        assert_eq!(token.len(), 32, "the PIN token must be 32 bytes");
        token
    }

    /// Create one discoverable credential for `rp` with user handle `user`.
    /// Run **before** `set_pin`: on a PIN-less device makeCredential needs no
    /// token and no UV (makeCredUvNotRqd), which is the same provisioning the
    /// spec twin uses.
    fn make_resident_for(&mut self, rp: &str, user: &[u8]) {
        let hash = crypto::sha256(rp.as_bytes());
        let mut req: HV<u8, 512> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_bstr(&mut req, &hash).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_tstr(&mut req, "id").unwrap();
        nh::push_tstr(&mut req, rp).unwrap();
        nh::push_tstr(&mut req, "name").unwrap();
        nh::push_tstr(&mut req, "RP").unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_tstr(&mut req, "id").unwrap();
        nh::push_bstr(&mut req, user).unwrap();
        nh::push_tstr(&mut req, "name").unwrap();
        nh::push_tstr(&mut req, "U").unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_array_header(&mut req, 1).unwrap();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_tstr(&mut req, "type").unwrap();
        nh::push_tstr(&mut req, "public-key").unwrap();
        nh::push_tstr(&mut req, "alg").unwrap();
        nh::push_neg(&mut req, -7).unwrap();
        nh::push_uint(&mut req, 7).unwrap();
        nh::push_map_header(&mut req, 1).unwrap();
        nh::push_tstr(&mut req, "rk").unwrap();
        nh::push_bool(&mut req, true).unwrap();
        let resp = self.call(0x01, req.as_slice());
        assert_eq!(resp[0], 0x00, "makeCredential must succeed on the device twin");
    }
}

/// libfido2 1.14.0's request shapes, as `credman_tx` puts them on the wire.
///
/// All three authenticated builders use the **preview** MAC scope: the
/// message is `subCommand ‖ cbor(params)` with no `0xFF×32` prefix, and the
/// key is the protocol-1 PIN token. `{1: sub, 2: params?, 3: 1, 4: mac}`.
fn preview_mac_req(token: &[u8], sub: u8) -> Vec<u8> {
    let mac = crypto::pin_uv_auth_param(1, &token.try_into().unwrap(), &[sub]);
    let mut req: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut req, 3).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, sub as u64).unwrap();
    nh::push_uint(&mut req, 3).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 4).unwrap();
    nh::push_bstr(&mut req, &mac).unwrap();
    req.as_slice().to_vec()
}

/// The unauthenticated `enumerate…GetNext` pair: `{1: sub}` and nothing else.
fn preview_bare(sub: u8) -> Vec<u8> {
    let mut req: HV<u8, 8> = HV::new();
    nh::push_map_header(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, sub as u64).unwrap();
    req.as_slice().to_vec()
}

/// libfido2's `enumerateCredentialsBegin`: `{1: 0x04, 2: {1: rpIdHash}, 3: 1,
/// 4: mac}`, with the MAC over `0x04 ‖ cbor({1: rpIdHash})`.
fn preview_creds_begin(token: &[u8], hash: &[u8; 32]) -> Vec<u8> {
    let mut params: HV<u8, 40> = HV::new();
    nh::push_map_header(&mut params, 1).unwrap();
    nh::push_uint(&mut params, 1).unwrap();
    nh::push_bstr(&mut params, hash).unwrap();
    let mut msg: HV<u8, 48> = HV::new();
    msg.push(0x04).unwrap();
    msg.extend_from_slice(params.as_slice()).unwrap();
    let mac = crypto::pin_uv_auth_param(1, &token.try_into().unwrap(), msg.as_slice());
    let mut req: HV<u8, 128> = HV::new();
    nh::push_map_header(&mut req, 4).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 0x04).unwrap();
    nh::push_uint(&mut req, 2).unwrap();
    req.extend_from_slice(params.as_slice()).unwrap();
    nh::push_uint(&mut req, 3).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 4).unwrap();
    nh::push_bstr(&mut req, &mac).unwrap();
    req.as_slice().to_vec()
}

/// A genuine RS-Key vendor request: MSE (`0x01`) with a COSE host point in
/// key 2, no MAC (MSE is ungated). The params value is `{1: {COSE}}` — the
/// COSE key hangs off label 1.
fn vendor_mse_request() -> Vec<u8> {
    let (x, y) = client_coords();
    let mut cose: HV<u8, 80> = HV::new();
    push_client_cose(&mut cose, &x, &y);
    let mut req: HV<u8, 96> = HV::new();
    nh::push_map_header(&mut req, 2).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 0x01).unwrap();
    nh::push_uint(&mut req, 2).unwrap();
    nh::push_map_header(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    req.extend_from_slice(cose.as_slice()).unwrap();
    req.as_slice().to_vec()
}

/// The top-level keys of a successful (`0x00`) response body. Nested
/// containers are skipped whole, so inner map keys never masquerade as outer
/// ones.
fn top_keys(resp: &[u8]) -> Vec<u64> {
    assert_eq!(resp[0], 0x00, "expected OK; got status {:#04x}", resp[0]);
    let mut p = Parser::new(&resp[1..]);
    let Item::Map(n) = p.next().unwrap() else {
        panic!("response body must be a map")
    };
    let mut out = Vec::new();
    for _ in 0..n {
        let k = match p.next().unwrap() {
            Item::U(u) => u,
            other => panic!("key {:?}", other),
        };
        out.push(k);
        p.skip().unwrap();
    }
    out
}

/// The value of top-level `key`, if present. Only the value is returned; the
/// borrow is of `resp` itself, so callers keep `resp` alive (bind the call).
fn value_at<'a>(resp: &'a [u8], want: u64) -> Option<Item<'a>> {
    let mut p = Parser::new(&resp[1..]);
    let Item::Map(n) = p.next().ok()? else {
        return None;
    };
    for _ in 0..n {
        let k = match p.next().ok()? {
            Item::U(u) => u,
            _ => return None,
        };
        if k == want {
            return p.next().ok();
        }
        p.skip().ok()?;
    }
    None
}

fn has_key(keys: &[u64], key: u64) -> bool {
    keys.contains(&key)
}

/// **US-1615 — the gate, now green (US-1618 flipped it).** libfido2 1.14's
/// `getCredsMetadata` under CTAP2 command `0x41` must be answered by the
/// credential manager with a preview-shape metadata map (keys 1 = existing,
/// 2 = remaining counts), not by the RS-Key vendor channel.
///
/// Captured pre-fix behaviour: `0x14` (`MissingParameter`), returned by
/// `vendor_backup::mse` because libfido2's request carries no key-2 params —
/// outside the `0x33/0x34/0x36` PIN_REQUIRED class, so OpenSSH reported
/// `SSH_ERR_INVALID_FORMAT` (*"invalid format"*). See the epic's §1.2.
#[test]
fn us1615_libfido2_metadata_on_0x41_reaches_the_credential_manager() {
    let mut dev = Dev::boot();
    dev.set_pin(b"1234");
    let token = dev.pin_token(b"1234", 0x04); // PERM_CM

    let resp = dev.call(0x41, &preview_mac_req(&token, 0x01));
    let keys = top_keys(&resp);
    assert!(
        matches!(value_at(&resp, 1), Some(Item::U(_))),
        "existingResidentCredentialsCount at key 1"
    );
    assert!(
        matches!(value_at(&resp, 2), Some(Item::U(_))),
        "maxPossibleRemainingResidentCredentialsCount at key 2"
    );
    assert!(has_key(&keys, 1) && has_key(&keys, 2));
}

/// **US-1618 — the full libfido2 1.14 `read_rks` walk on `0x41`.** Every
/// request libfido2 makes while walking `fido_credman_get_dev_metadata` →
/// `fido_credman_get_dev_rp` → `fido_credman_get_dev_rk` must be answered by
/// the credential manager in the preview response keys, including the
/// unauthenticated `Next` pair, which is routed by the pending enumeration.
#[test]
fn us1618_libfido2_read_rks_walk_on_0x41() {
    let mut dev = Dev::boot();
    dev.make_resident_for("ssh:example.com", b"alice");
    dev.make_resident_for("ssh:example.com", b"bob");
    dev.set_pin(b"1234");
    let token = dev.pin_token(b"1234", 0x04);
    let hash = crypto::sha256(b"ssh:example.com");

    // getCredsMetadata — keys 1/2.
    let meta = dev.call(0x41, &preview_mac_req(&token, 0x01));
    let keys = top_keys(&meta);
    assert!(has_key(&keys, 1) && has_key(&keys, 2), "metadata keys 1/2");

    // enumerateRPsBegin — rp(3), rpIDHash(4), totalRPs(5).
    let begin = dev.call(0x41, &preview_mac_req(&token, 0x02));
    let keys = top_keys(&begin);
    assert!(has_key(&keys, 3), "rp map at key 3");
    assert!(
        matches!(value_at(&begin, 4), Some(Item::B(b)) if b == hash.as_slice()),
        "rpIDHash at key 4 must equal the RP hash"
    );
    assert!(
        matches!(value_at(&begin, 5), Some(Item::U(1))),
        "totalRPs at key 5 must be 1"
    );

    // enumerateRPsGetNext — single RP, so the Begin consumed it and the Next
    // is answered NO_CREDENTIALS/NotAllowed by the manager, not by vendor41.
    let resp = dev.call(0x41, &preview_bare(0x03));
    assert_eq!(resp[0], 0x30, "a Next past the last RP is NotAllowed");

    // enumerateCredentialsBegin — user(6), credentialID(7), publicKey(8),
    // totalCredentials(9).
    let cb = dev.call(0x41, &preview_creds_begin(&token, &hash));
    let keys = top_keys(&cb);
    assert!(has_key(&keys, 6), "user map at key 6");
    assert!(has_key(&keys, 7), "credentialID map at key 7");
    assert!(has_key(&keys, 8), "publicKey at key 8");
    assert!(
        matches!(value_at(&cb, 9), Some(Item::U(2))),
        "totalCredentials at key 9 must be 2"
    );

    // enumerateCredentialsGetNextCredential — {1: 0x05}, routed by the pending
    // credential enumeration on this channel.
    let cn = dev.call(0x41, &preview_bare(0x05));
    let keys = top_keys(&cn);
    assert!(has_key(&keys, 6) && has_key(&keys, 7), "next credential keys 6/7");
}

/// **US-1618, vendor-survival scenario.** A genuine RS-Key request on `0x41`
/// — MSE with a COSE point and no MAC — is still served by vendor41, whose
/// response is a COSE key at key 1 (a map), never a credMgmt metadata map
/// (integer keys 1/2).
#[test]
fn us1618_vendor_mse_on_0x41_is_untouched() {
    let mut dev = Dev::boot();
    dev.set_pin(b"1234");
    let _ = dev.pin_token(b"1234", 0x04);

    let resp = dev.call(0x41, &vendor_mse_request());
    assert!(
        matches!(value_at(&resp, 1), Some(Item::Map(_))),
        "vendor MSE answers a COSE key map at key 1, not credMgmt counts"
    );
    assert_eq!(resp[0], 0x00, "vendor MSE must succeed; got {:#04x}", resp[0]);
}
