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
//! * US-1615 — the red gate: libfido2's metadata request on `0x41` must be
//!   answered with preview-shape metadata (keys 1/2). Ignored until US-1618
//!   routes it, with the captured pre-fix reply byte in the attribute.
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
}

/// libfido2 1.14.0's `getCredsMetadata` request as `credman_tx` puts it on
/// the wire: `{1: 0x01, 3: 1, 4: mac}` — sub-command `0x01`, protocol 1, and
/// a MAC over the **bare sub-command byte** (preview scope: no `0xFF×32`
/// prefix, no params to append). The MAC key is the protocol-1 PIN token.
fn libfido2_metadata_request(token: &[u8]) -> Vec<u8> {
    let mac = crypto::pin_uv_auth_param(1, &token.try_into().unwrap(), &[0x01]);
    let mut req: HV<u8, 64> = HV::new();
    nh::push_map_header(&mut req, 3).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 0x01).unwrap();
    nh::push_uint(&mut req, 3).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_uint(&mut req, 4).unwrap();
    nh::push_bstr(&mut req, &mac).unwrap();
    req.as_slice().to_vec()
}

/// **US-1615 — the red gate.** libfido2 1.14's `getCredsMetadata` under CTAP2
/// command `0x41` must be answered by the credential manager with a
/// preview-shape metadata map (keys 1 = existing, 2 = remaining counts), not
/// by the RS-Key vendor channel.
///
/// # Captured pre-fix behaviour (US-1615, first run of this test)
///
/// The reply byte is **`0x14`** (`Ctap2Response::MissingParameter`): the
/// request is parsed as RS-Key `Mse` (`0x01`) — libfido2's request carries no
/// key-2 params, so `vendor_backup::mse` refuses before any MAC is even
/// consulted. `0x14` is outside the `0x33/0x34/0x36` PIN_REQUIRED class in
/// `sk_usbhid.c`'s `fidoerr_to_skerr`, so OpenSSH reports
/// `SSH_ERR_INVALID_FORMAT` — the reported *"invalid format"*. Consistent
/// with the epic's §1.2 ladder, so the root-cause analysis stands.
#[ignore = "US-1615 red gate: 0x41 is answered 0x14 by vendor41's Mse arm. \
            Flips green when US-1618 routes preview requests to handle_cred_mgmt."]
#[test]
fn us1615_libfido2_metadata_on_0x41_reaches_the_credential_manager() {
    let mut dev = Dev::boot();
    dev.set_pin(b"1234");
    let token = dev.pin_token(b"1234", 0x04); // PERM_CM

    let req = libfido2_metadata_request(&token);
    let resp = dev.call(0x41, &req);
    assert_eq!(
        resp[0], 0x00,
        "getCredsMetadata on 0x41 must succeed; captured reply byte {:#04x}",
        resp[0]
    );
    // Preview-shape metadata: keys 1 (existing) and 2 (remaining) — the only
    // keys libfido2 1.14.0's `credman_parse_metadata` reads.
    let mut p = Parser::new(&resp[1..]);
    let Item::Map(n) = p.next().unwrap() else {
        panic!("metadata body must be a map")
    };
    let mut saw_existing = false;
    let mut saw_remaining = false;
    for _ in 0..n {
        let k = match p.next().unwrap() {
            Item::U(u) => u,
            other => panic!("key {:?}", other),
        };
        match k {
            1 => {
                assert!(matches!(p.next().unwrap(), Item::U(_)));
                saw_existing = true;
            }
            2 => {
                assert!(matches!(p.next().unwrap(), Item::U(_)));
                saw_remaining = true;
            }
            _ => {
                p.next().unwrap();
            }
        }
    }
    assert!(saw_existing, "existingResidentCredentialsCount at key 1");
    assert!(saw_remaining, "maxPossibleRemainingResidentCredentialsCount at key 2");
}
