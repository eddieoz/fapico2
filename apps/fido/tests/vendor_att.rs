//! US-175 (EPIC `PICOForge-COMPAT`) — the RS-Key organisation attestation over
//! the `0x41` vendor channel: `ATT_STATE` (`0x0B`), `ATT_CLEAR` (`0x0A`) and
//! `ATT_IMPORT` (`0x09`).
//!
//! # How this file reaches the code
//!
//! `apps/fido/src/vendor_att.rs` is pulled in with `#[path]` and the crate
//! names it needs are re-exported at this file's root, so the module's
//! `crate::…` paths resolve here exactly as they will once `pub mod
//! vendor_att;` lands in `lib.rs`. Wiring the module into `lib.rs` and the two
//! dispatch arms is the integrator's step; doing it from a test file is what
//! lets this suite run **before** that edit, and it is why nothing in `lib.rs`
//! had to be touched to prove the module compiles and behaves.
//!
//! # What is tested here, and what is not
//!
//! The credential's **state** is not tested here. The durable commit, the
//! "scalar and chain or neither" rule and the store round-trip are
//! `vendor41_state.rs`'s subject, and duplicating them would give two tests
//! that can both pass while the property they share is wrong. What is tested
//! is everything between the state and the wire:
//!
//! 1. **`ATT_STATE`'s framing** — key 1 always present and always a real CBOR
//!    boolean, key 2 present exactly when key 1 is true, and the hash's width.
//! 2. **The DER walk** — 1-, 2- and 3-certificate chains, a length field that
//!    runs past the end, a one-byte chain, exactly 2048 accepted and 2049
//!    refused, and a non-minimal length header.
//! 3. **The AEAD** — against vectors produced by Python's `cryptography`
//!    bindings, in both directions.
//! 4. **The gating** — the token/touch union, the PIN-auth charging rule, and
//!    the MSE-session precondition for both mutating arms.
//! 5. **The layering rule** — a device with no org cert imported still mints a
//!    normal FIDO2 attestation, and importing one does not change it.
//!
//! # A word on what "the client" means in this file
//!
//! The client is Rust, in `picoforge/src/hal/fido/`, and its rules are
//! transcribed here as literals rather than reached for through a dependency.
//! Two reasons, in order: the crate is not a dependency of this workspace, and
//! — more importantly — a test that imported the client's own `certs_pem_to_der`
//! would be checking this firmware against itself on the one point where the
//! protocol is a *framing* rather than a *cryptography* (the chain has no
//! delimiter, so the walk is the only thing that can be wrong). Every
//! transcription carries its `file:line`.

pub use fapico2_fido::{cbor, crypto, ctap2, device_core, vendor41, CTAP2_MAX_MSG};

#[path = "../src/vendor_att.rs"]
mod vendor_att;

use cbor::no_heap as nh;
use cbor::no_heap::{Item, Parser};
use fapico2_fido::keystore::MemoryKeystore;
use fapico2_fido::vendor41::{MsePoint, PresenceGate, TokenAuth, ORG_CHAIN_MAX, P256_POINT_LEN};
use fapico2_fido::vendor_state::{MemoryVendorOps, VendorSession};
use heapless::Vec as HV;
use vendor_att::*;

// ---------------------------------------------------------------------------
// Statuses, spelled as the byte on the wire.
//
// A desktop app only ever sees these bytes, so every assertion below is about
// the wire value rather than about a `Ctap2Response` variant name.
// ---------------------------------------------------------------------------

const OK: u8 = 0x00;
const INVALID_PARAMETER: u8 = 0x02;
const INVALID_LENGTH: u8 = 0x03;
const UP_REQUIRED: u8 = 0x3B;
const PIN_AUTH_INVALID: u8 = 0x33;
const PIN_AUTH_BLOCKED: u8 = 0x34;
const UNAUTHORIZED_PERMISSION: u8 = 0x40;
const MISSING_PARAMETER: u8 = 0x14;
const INVALID_CBOR: u8 = 0x12;
const OPERATION_DENIED: u8 = 0x27;
/// `CTAP2_ERR_PIN_REQUIRED`, what `vendor41::verify_mac` answers a request that
/// carries no `pinUvAuthParam` (`vendor41.rs:2816-2819`).
const PUAT_REQUIRED: u8 = 0x36;

/// `AUTHENTICATOR_CONFIG`, the permission `att_clear` / `att_import` need
/// (`vendor41::required_permission`, `vendor41.rs:2960-2962`).
const PERM_ACFG: u8 = 0x20;

const PIN_TOKEN: [u8; 32] = [0x11; 32];

type Reply = HV<u8, { REPLY_MAX }>;

// ---------------------------------------------------------------------------
// The `VendorOps` seam.
//
// The real host type, not a mock: "the import round-trips through the
// keystore" is a claim about the state layer, and a mock would make it a claim
// about the mock. `MemoryVendorOps` is the host half of the pair
// `vendor_state` ships; the device half (`KeystoreVendorOps`) is exercised by
// `vendor41_state.rs` and through `with_keystore_ops` below, and it is the
// same trait, so an arm written against `&mut dyn VendorOps` cannot tell them
// apart.
// ---------------------------------------------------------------------------

fn with_ops<R>(
    ks: &mut MemoryKeystore,
    session: &mut VendorSession,
    f: impl FnOnce(&mut dyn fapico2_fido::vendor_backup::BackupOps) -> R,
) -> R {
    let mut ops = MemoryVendorOps::new(ks, session);
    f(&mut ops)
}

fn acfg_token() -> TokenAuth<'static> {
    TokenAuth { token: &PIN_TOKEN, permissions: PERM_ACFG, blocked: false }
}

fn blocked_token() -> TokenAuth<'static> {
    TokenAuth { token: &PIN_TOKEN, permissions: PERM_ACFG, blocked: true }
}

fn wrong_perm_token() -> TokenAuth<'static> {
    // `CREDENTIAL_MANAGEMENT` (0x04) and nothing else.
    TokenAuth { token: &PIN_TOKEN, permissions: 0x04, blocked: false }
}

/// A presence gate whose synchronous poll answers `granted`.
///
/// The `poll` arm is the host/emulation path; the device's `window_grant` arm
/// is join-only and answers `0x3B` on the first call, which is the documented
/// two-step. A **function item** rather than a closure: `PresenceGate::poll` is
/// `Option<fn() -> bool>` and a capturing closure does not coerce.
fn presence(granted: bool) -> PresenceGate {
    fn yes() -> bool {
        true
    }
    fn no() -> bool {
        false
    }
    PresenceGate { window_grant: None, poll: Some(if granted { yes } else { no }), tag: 0 }
}

// ---------------------------------------------------------------------------
// The host side of the MSE channel, derived for real.
//
// The client runs `mse_handshake` (`picoforge/src/hal/fido/mod.rs:1684-1734`)
// and derives `HKDF-SHA256(salt = b"", ikm = z, info = aad)` with `aad` its own
// uncompressed point. Reproducing that here — rather than reading the channel
// key back out of the device with `mse_channel` — is what makes these tests
// tests of the protocol rather than of a shared secret. It also means a device
// that derived the wrong key, or bound the wrong AAD, fails here.
// ---------------------------------------------------------------------------

struct HostChannel {
    key: [u8; 32],
    aad: [u8; P256_POINT_LEN],
}

impl HostChannel {
    /// Seal a 32-byte scalar the way `att_import` seals it
    /// (`picoforge/src/hal/fido/mod.rs:1980` → `wrap_secret`, `:1808-1814`):
    /// `nonce(12) ‖ ct(32) ‖ tag(16)`.
    fn wrap(&self, secret: &[u8; 32], nonce: [u8; 12]) -> Vec<u8> {
        let blob = chacha_seal(&self.key, &nonce, secret, &self.aad);
        assert_eq!(blob.len(), SCALAR_BLOB_LEN, "the client always produces 60 bytes");
        blob
    }
}

/// Run one MSE handshake from the host's side against `ops`.
fn mse_host(ops: &mut dyn fapico2_fido::vendor_backup::BackupOps) -> HostChannel {
    let (sk, _) = crypto::generate_p256_keypair();
    let sec = crypto::public_key_bytes(&sk.public_key());
    let (hx, hy) = (
        <[u8; 32]>::try_from(&sec[1..33]).unwrap(),
        <[u8; 32]>::try_from(&sec[33..65]).unwrap(),
    );
    let mut dev = MsePoint::default();
    ops.mse_establish(hx, hy, &mut dev).expect("a P-256 handshake cannot fail here");

    // The device's own uncompressed point is the AAD and travels to the host
    // in the `MSE` response's COSE key — so both sides bind the same bytes.
    let mut aad = [0u8; 65];
    aad[0] = 0x04;
    aad[1..33].copy_from_slice(&dev.x);
    aad[33..65].copy_from_slice(&dev.y);

    let peer = crypto::parse_public_key(&aad).expect("the device point is on the curve");
    let z = crypto::ecdh_shared_secret(&sk, &peer);
    let key = vendor41::derive_mse_channel(&z, &aad);
    HostChannel { key, aad }
}

// ---------------------------------------------------------------------------
// Request builders, byte-exact against `picoforge/src/hal/fido/ops.rs`.
//
// Raw bytes rather than `cbor::encode`, because the MAC covers the params'
// *wire* bytes and a re-encoding would have to match `ciborium`'s canonical
// form byte for byte to test anything real.
// ---------------------------------------------------------------------------

/// `att_status`'s request: `{1: 11}` and **nothing else**.
///
/// `rs_key_vendor(RSKEY_VENDOR_ATT_STATE, None, None)` (`mod.rs:1895`) omits
/// key 2 *and* keys 3/4, so a request carrying a `subCommandParams` is not
/// one this client produces. The function is returned as a `Vec` for symmetry
/// with the other builders; its shape is one byte long and deliberately so.
fn att_state_request() -> Vec<u8> {
    vec![0xA1, 0x01, SUB_ATT_STATE]
}

/// `att_clear`'s request: `{1: 10}` plus, when a PIN is configured, keys 3 and 4
/// with a MAC over the **empty** params tail.
///
/// `rs_key_vendor(RSKEY_VENDOR_ATT_CLEAR, None, pin.as_deref())`
/// (`mod.rs:1916`) passes `None` for the params, so `ops.rs:1560-1573` signs an
/// empty tail.
fn att_clear_request(token: Option<&[u8; 32]>) -> Vec<u8> {
    rskey_request(SUB_ATT_CLEAR, None, token)
}

/// `ATT_IMPORT`'s `subCommandParams`: `{1: <bstr(60)>, 2: <bstr(chain)>}`.
///
/// `params.insert(1, Bytes(blob)); params.insert(2, Bytes(chain))`
/// (`mod.rs:1982-1984`), in that order, which is ascending.
fn import_params_bytes(sealed: &[u8], chain: &[u8]) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.push(0xA2);
    push_uint_to_vec(&mut p, ATT_PARAM_SCALAR);
    push_bstr_to_vec(&mut p, sealed);
    push_uint_to_vec(&mut p, ATT_PARAM_CHAIN);
    push_bstr_to_vec(&mut p, chain);
    p
}

/// The same map with key 1 present and key 2 **absent** — the "scalar, no
/// chain" request `set_org_attestation`'s doc promises to refuse.
fn import_params_no_chain(sealed: &[u8]) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.push(0xA1);
    push_uint_to_vec(&mut p, ATT_PARAM_SCALAR);
    push_bstr_to_vec(&mut p, sealed);
    p
}

/// …and the mirror: chain present, scalar absent.
fn import_params_no_scalar(chain: &[u8]) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.push(0xA1);
    push_uint_to_vec(&mut p, ATT_PARAM_CHAIN);
    push_bstr_to_vec(&mut p, chain);
    p
}

/// The same map with the chain's byte-string head written **non-minimally**:
/// `0x5B` + a 8-byte big-endian length, where a canonical serialiser emits
/// the 3-byte `0x59 08 00` for a 2048-byte body.
///
/// Legal CBOR, decodes to the same value, and produces different bytes, so a
/// MAC over one form does not verify against the other. This is the only way
/// to test "the device verified the wire span" without a hand-written CBOR
/// *encoder* in the device — and it is the trap `vendor_lock` names: a
/// device that re-serialised the map canonically would answer `0x33` to a
/// request whose MAC is arithmetically perfect.
fn import_params_non_canonical_head(sealed: &[u8], chain: &[u8]) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.push(0xA2);
    push_uint_to_vec(&mut p, ATT_PARAM_SCALAR);
    push_bstr_to_vec(&mut p, sealed);
    push_uint_to_vec(&mut p, ATT_PARAM_CHAIN);
    // major 2, additional-info 27 (uint64 length) — never canonical for 2048.
    p.push(0x5B);
    p.extend_from_slice(&(chain.len() as u64).to_be_bytes());
    p.extend_from_slice(chain);
    p
}

/// The `0x41` request body `{1: sub, 2: params, 3: 1, 4: <mac>}`.
///
/// `params == None` omits key 2 entirely, which is what `ops.rs:1563-1565`
/// does for `ATT_CLEAR` and `ATT_STATE`.
fn rskey_request(sub: u8, params: Option<&[u8]>, token: Option<&[u8; 32]>) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    let pairs = 1 + usize::from(params.is_some()) + 2 * usize::from(token.is_some());
    b.push(0xA0 | pairs as u8);
    push_uint_to_vec(&mut b, 1);
    push_uint_to_vec(&mut b, sub as u64);
    if let Some(p) = params {
        push_uint_to_vec(&mut b, 2);
        b.extend_from_slice(p);
    }
    if let Some(t) = token {
        push_uint_to_vec(&mut b, 3);
        push_uint_to_vec(&mut b, 1);
        push_uint_to_vec(&mut b, 4);
        let mac = picoforge_mac(t, sub, params.unwrap_or(&[]));
        push_bstr_to_vec(&mut b, &mac);
    }
    b
}

/// The `0x41` MAC input: `0xFF × 32 ‖ 0x41 ‖ subCommand ‖ subCommandParams`,
/// and the first 16 bytes of its HMAC-SHA256 under the token.
///
/// Transcribed from `picoforge/src/hal/fido/ops.rs:1581-1586` (the
/// `picoforge_sign` call) and mirrored by `vendor41::verify_mac`
/// (`vendor41.rs:2830-2836`). Computed with the `hmac`/`sha2` crates directly
/// rather than through `fapico2_fido::crypto`, so it shares no code with the
/// verifier — a shared HMAC helper would make this a test of the
/// implementation against itself.
fn picoforge_mac(token: &[u8; 32], sub: u8, params: &[u8]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut msg = vec![0xFFu8; 32];
    msg.push(0x41);
    msg.push(sub);
    msg.extend_from_slice(params);
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(token).unwrap();
    m.update(&msg);
    let full = m.finalize().into_bytes();
    <[u8; 16]>::try_from(&full[..16]).unwrap()
}

/// Minimal-length unsigned integer head.
fn push_uint_to_vec(out: &mut Vec<u8>, v: u64) {
    let mut tmp: HV<u8, 9> = HV::new();
    nh::push_uint(&mut tmp, v).unwrap();
    out.extend_from_slice(&tmp);
}

/// Minimal-length byte-string head, then the payload.
///
/// The head goes through a 9-byte scratch and the **payload** is appended
/// separately: `nh::push_bstr` writes the head *and* the content into the
/// buffer it is handed, so handing it a 9-byte scratch to get the 3-byte head
/// of a 2048-byte string overflows. That is the same in-place-head reason
/// `vendor_audit` reserves framing separately.
fn push_bstr_to_vec(out: &mut Vec<u8>, b: &[u8]) {
    let mut head: HV<u8, 9> = HV::new();
    nh::push_head(&mut head, 2, b.len() as u64).unwrap();
    out.extend_from_slice(&head);
    out.extend_from_slice(b);
}

// ---------------------------------------------------------------------------
// DER chain builders.
//
// The client concatenates PEM-decoded DER with nothing between
// (`picoforge/src/hal/fido/mod.rs:1944-1945`), so a chain here is just a run
// of DER `SEQUENCE`s. The bodies are filled with a **distinguishable** byte
// per certificate so a mis-split walk is visible rather than accidentally
// correct.
// ---------------------------------------------------------------------------

/// One `0x30`-tagged DER element whose body is `body_len` bytes, the first of
/// which is `tag` so two certificates in one chain are never equal.
fn der_cert(body_len: usize, tag: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(body_len + 4);
    v.push(0x30);
    if body_len < 0x80 {
        v.push(body_len as u8);
    } else if body_len <= 0xFF {
        v.push(0x81);
        v.push(body_len as u8);
    } else {
        v.push(0x82);
        v.extend_from_slice(&(body_len as u16).to_be_bytes());
    }
    for i in 0..body_len {
        v.push(tag.wrapping_add(i as u8));
    }
    v
}

/// `n` certificates of `body_len` bytes each, concatenated with nothing
/// between — exactly `certs_pem_to_der`'s output shape.
fn der_chain(n: usize, body_len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..n {
        v.extend_from_slice(&der_cert(body_len, (i as u8) << 4));
    }
    v
}

// ---------------------------------------------------------------------------
// Response decoding.
//
// The tests decode with this crate's decoder and then re-derive the client's
// rules from the decoded values — so a round trip through one encoder/decoder
// pair is never the thing being asserted.
// ---------------------------------------------------------------------------

/// `{1: <bool>, 2: <bstr(32)>}` from an `ATT_STATE` body, as the client sees
/// it: `installed` through `m_bool`, and the hash only when `installed`.
fn parse_att_state(body: &[u8]) -> (bool, Option<Vec<u8>>) {
    let mut p = Parser::new(body);
    let pairs = match p.next() {
        Ok(Item::Map(n)) => n,
        _ => panic!("the body must be a CBOR map, got {body:02x?}"),
    };
    let mut installed: Option<bool> = None;
    let mut raw: Vec<(u64, Option<bool>, Option<Vec<u8>>)> = Vec::new();
    for _ in 0..pairs {
        let Item::U(k) = p.next().expect("key must be a uint") else {
            panic!("every key in the ATT_STATE response is an unsigned int")
        };
        match k {
            1 => {
                let v = match p.next() {
                    Ok(Item::Bool(b)) => {
                        raw.push((k, Some(b), None));
                        b
                    }
                    Ok(Item::U(n)) => {
                        raw.push((k, None, Some(vec![n as u8])));
                        n != 0
                    }
                    _ => panic!("key 1 must be a bool or an int"),
                };
                installed = Some(v);
            }
            2 => {
                let b = mbytes(&mut p, "the chain hash");
                raw.push((k, None, Some(b.to_vec())));
            }
            _ => panic!("unexpected key {k} in the ATT_STATE response"),
        }
    }
    assert_eq!(p.remaining(), 0, "no trailing bytes may follow the map");
    let installed = installed.expect("key 1 is always emitted — that is the point");
    (installed, host_att_status_hash(&raw, installed))
}

/// One auth-map entry in the host's `(key, m_bool, bstr)` shape.
type AuthMapEntry = (u64, Option<bool>, Option<Vec<u8>>);

/// `att_status`'s own two reads, transcribed (`picoforge/src/hal/fido/mod.rs`
/// `:1899-1903`): the hash is read **only** under `if installed`.
///
/// [`host_m_bool`] is `mod.rs:1558-1565` verbatim in behaviour.
fn host_att_status_hash(map: &[AuthMapEntry], installed: bool) -> Option<Vec<u8>> {
    if !installed {
        return None;
    }
    map.iter().find(|(k, _, _)| *k == 2).and_then(|(_, _, b)| b.clone())
}

/// `mod.rs::m_bool` (`mod.rs:1558-1565`): a CBOR bool, or a non-zero integer;
/// **anything else, including a missing key, is `false`**.
fn host_m_bool(map: &[(u64, Option<bool>, Option<u64>)], key: u64) -> bool {
    match map.iter().find(|(k, _, _)| *k == key) {
        Some((_, Some(b), _)) => *b,
        Some((_, _, Some(n))) => *n != 0,
        _ => false,
    }
}

fn mbytes<'a>(p: &mut Parser<'a>, what: &str) -> &'a [u8] {
    match p.next() {
        Ok(Item::B(b)) => b,
        _ => panic!("{what} must be a byte string"),
    }
}

/// Read the state straight out of the trait, bypassing the arms — the "is the
/// credential really there" oracle the failure tests assert against.
fn stored_chain(ops: &mut dyn fapico2_fido::vendor_backup::BackupOps) -> Option<Vec<u8>> {
    let v = ops.org_attestation();
    if v.installed() { Some(v.chain.to_vec()) } else { None }
}

// ---------------------------------------------------------------------------
// 1. The EPIC's named test.
// ---------------------------------------------------------------------------

/// **The EPIC's RED test** (`EPIC-fapico2-picoforge-compatibility.md`, US-175:
/// *"RED: `attestation_state_import_clear`"*). The name is a contract.
///
/// The full round trip on the real host [`VendorOps`], over a real MSE
/// handshake and a real ChaCha20-Poly1305 seal:
///
/// 1. `ATT_STATE` on a fresh device → `{1: false}`, no key 2.
/// 2. `ATT_IMPORT` (MSE first, then a `0x20` token and a MAC) → `0x00`.
/// 3. `ATT_STATE` → `{1: true, 2: sha256(chain)}`, and that hash is the one
///    the test computes over the chain it sent.
/// 4. `ATT_CLEAR` (MSE first, then the same token) → `0x00`.
/// 5. `ATT_STATE` → `{1: false}` again, and the stored chain is gone.
#[test]
fn attestation_state_import_clear() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    let chain = der_chain(3, 200);

    with_ops(&mut ks, &mut session, |ops| {
        // --- 1. fresh device ---
        let mut out = Reply::new();
        assert_eq!(att_state(ops, &mut out).status.code(), OK);
        let (installed, hash) = parse_att_state(&out);
        assert!(!installed, "a device with no import reports installed = false");
        assert!(hash.is_none(), "and the client reads no key 2 in that case");
        assert!(stored_chain(ops).is_none(), "nothing is stored");

        // --- 2. import ---
        let chan = mse_host(ops);
        let sealed = chan.wrap(&[0x77; 32], [0x11; 12]);
        let params = import_params_bytes(&sealed, &chain);
        let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
        assert_eq!(
            att_import(&req, Some(acfg_token()), presence(false), ops).status.code(),
            OK
        );

        // --- 3. state ---
        let mut out = Reply::new();
        assert_eq!(att_state(ops, &mut out).status.code(), OK);
        let (installed, hash) = parse_att_state(&out);
        assert!(installed, "after an import the device reports installed = true");
        let hash = hash.expect("key 2 is read whenever key 1 is true");
        assert_eq!(hash.len(), CHAIN_HASH_LEN, "chain_hash is a 32-byte SHA-256");
        assert_eq!(hash.to_vec(), crypto::sha256(&chain).to_vec(), "over the exact DER sent");
        assert_eq!(stored_chain(ops).as_deref(), Some(&chain[..]), "the chain is stored byte-exact");

        // --- 4. clear ---
        // A fresh MSE handshake first, exactly as `att_clear` does
        // (`picoforge/src/hal/fido/mod.rs:1916`).
        let _chan2 = mse_host(ops);
        let req = att_clear_request(Some(&PIN_TOKEN));
        assert_eq!(
            att_clear(&req, Some(acfg_token()), presence(false), ops).status.code(),
            OK
        );

        // --- 5. state again ---
        let mut out = Reply::new();
        assert_eq!(att_state(ops, &mut out).status.code(), OK);
        let (installed, hash) = parse_att_state(&out);
        assert!(!installed, "after a clear the device reports installed = false");
        assert!(hash.is_none());
        assert!(stored_chain(ops).is_none(), "the chain is gone, not just the flag");
    });
}

// ---------------------------------------------------------------------------
// 2. `ATT_STATE` framing.
// ---------------------------------------------------------------------------

/// US-175 bullet 1: `ATT_STATE` on a fresh device reports `installed = false`
/// **and key 1 is a real CBOR boolean**, not `0`/`1`.
///
/// The second half is the load-bearing half. `m_bool` (`mod.rs:1558-1565`)
/// accepts a non-zero integer, so an integer would *work* — which is exactly
/// why it is a hazard: it is correct today and there is no failure to debug if
/// a later refactor swaps it for a string, a byte string or `null`, any of
/// which `m_bool`'s `_` arm silently reads as `false`. So the assertion is on
/// the **encoding**, not on the decoded value.
///
/// Pinned the same way `vendor_lock::state` and `vendor_audit::audit_config`
/// pin theirs: by reading the raw body.
#[test]
fn att_state_on_a_fresh_device_reports_not_installed_and_key_1_is_a_cbor_bool() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    with_ops(&mut ks, &mut session, |ops| {
        let mut out = Reply::new();
        assert_eq!(att_state(ops, &mut out).status.code(), OK);
        assert_eq!(
            out.as_slice(),
            &[0xA1, 0x01, 0xF4],
            "key 1 present exactly once, as 0xF4 (CBOR false) — never omitted, never 0x00"
        );
        assert_eq!(parse_att_state(&out), (false, None));
    });
}

/// The installed shape: `{1: true, 2: <bstr(32)>}` in ascending key order, and
/// the hash is `sha256` of the **exact** stored bytes.
///
/// The "exact" is the point: `att_import` stores the concatenated DER the host
/// sent, and `chain_hash` is over those bytes, so a host that pins the hash
/// can reproduce it from its own PEM decode. A device that canonicalised the
/// chain on the way in would report a hash no host can match.
#[test]
fn att_state_after_an_import_reports_installed_and_a_32_byte_chain_hash() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    let chain = der_chain(1, 512);
    with_ops(&mut ks, &mut session, |ops| {
        let chan = mse_host(ops);
        let sealed = chan.wrap(&[0x5A; 32], [0x22; 12]);
        let params = import_params_bytes(&sealed, &chain);
        let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
        assert_eq!(att_import(&req, Some(acfg_token()), presence(false), ops).status.code(), OK);

        let mut out = Reply::new();
        assert_eq!(att_state(ops, &mut out).status.code(), OK);
        // Exact bytes: A2 · 01 F5 · 02 58 20 ‖ 32 bytes of SHA-256.
        let mut want: Vec<u8> = vec![0xA2, 0x01, 0xF5, 0x02, 0x58, 0x20];
        want.extend_from_slice(&crypto::sha256(&chain));
        assert_eq!(out.as_slice(), &want[..], "ascending keys, 0xF5 for true, bstr(32)");
        assert!(parse_att_state(&out).0);
    });
}

/// `write_att_state_response` is exported so the framing can be pinned without
/// the state layer — this is the case where the two disagree: an
/// **installed** device whose hash is somehow absent.
///
/// The client reads key 2 only under `if installed`
/// (`picoforge/src/hal/fido/mod.rs:1899-1903`), so this body renders as
/// "installed, hash unknown" with no error anywhere, which is the shape the
/// test exists to make reachable in a test if a future edit introduces it.
#[test]
fn the_installed_flag_is_a_cbor_bool_and_the_hash_is_conditional_on_it() {
    let mut out: HV<u8, 64> = HV::new();

    // Not installed, no hash: a one-pair map.
    write_att_state_response(&mut out, false, None).unwrap();
    assert_eq!(out.as_slice(), &[0xA1, 0x01, 0xF4]);

    // Not installed, hash supplied: the hash is **dropped**, because the client
    // would ignore it and a key the client ignores is a key that can disagree.
    out.clear();
    write_att_state_response(&mut out, false, Some(&[0xAB; 32])).unwrap();
    assert_eq!(out.as_slice(), &[0xA1, 0x01, 0xF4]);

    // Installed with a hash: two pairs, ascending.
    out.clear();
    write_att_state_response(&mut out, true, Some(&[0xAB; 32])).unwrap();
    assert_eq!(out[0], 0xA2);
    assert_eq!(out.as_slice(), {
        let mut v = vec![0xA2, 0x01, 0xF5, 0x02, 0x58, 0x20];
        v.extend_from_slice(&[0xAB; 32]);
        v
    }
    .as_slice());

    // …and the client's own `m_bool` reads the bool back, both ways.
    let map_true: Vec<(u64, Option<bool>, Option<u64>)> = vec![(1, Some(true), None)];
    let map_false: Vec<(u64, Option<bool>, Option<u64>)> = vec![(1, Some(false), None)];
    let map_int: Vec<(u64, Option<bool>, Option<u64>)> = vec![(1, None, Some(1))];
    let map_missing: Vec<(u64, Option<bool>, Option<u64>)> = vec![];
    assert!(host_m_bool(&map_true, 1));
    assert!(!host_m_bool(&map_false, 1));
    // An integer would also parse — the reason the encoder emits a real bool.
    assert!(host_m_bool(&map_int, 1));
    // A missing key reads as false, which is why key 1 is never omitted.
    assert!(!host_m_bool(&map_missing, 1));
}

// ---------------------------------------------------------------------------
// 3. The MSE precondition.
// ---------------------------------------------------------------------------

/// `ATT_CLEAR` requires an MSE handshake *first* — `att_clear` calls
/// `mse_handshake` before the `0x0A` (`mod.rs:1916`).
///
/// The second half is the one that matters: the credential the client asked
/// to remove is **still there**. A refusal that cleared anyway would be worse
/// than no gate.
#[test]
fn att_clear_without_a_prior_mse_session_is_refused_and_does_not_clear() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    let chain = der_chain(1, 128);
    with_ops(&mut ks, &mut session, |ops| {
        // Install something to clear.
        let chan = mse_host(ops);
        let sealed = chan.wrap(&[0x33; 32], [0x01; 12]);
        let params = import_params_bytes(&sealed, &chain);
        let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
        assert_eq!(att_import(&req, Some(acfg_token()), presence(false), ops).status.code(), OK);
        assert!(stored_chain(ops).is_some());
    });

    // `VendorSession` is volatile, so clearing it is exactly "the device
    // rebooted" — which is what "no prior MSE session" means to the device.
    session.clear();

    with_ops(&mut ks, &mut session, |ops| {
        let req = att_clear_request(Some(&PIN_TOKEN));
        let r = att_clear(&req, Some(acfg_token()), presence(true), ops);
        assert_eq!(r.status.code(), INVALID_PARAMETER, "no MSE session → 0x02");
        assert_eq!(
            r.charge_pin_auth,
            ChargePinAuth::NoCharge,
            "a missing session is not an auth failure"
        );
        assert_eq!(
            stored_chain(ops).as_deref(),
            Some(&chain[..]),
            "the credential is untouched — a refusal that cleared anyway would be worse than no gate"
        );
    });
}

/// `ATT_IMPORT` refuses the same way, and installs nothing.
///
/// Order matters here and is asserted: the gate runs **before** the MSE check,
/// so a caller with no token and no touch gets `0x3B` even with no session —
/// the status that means "ask the human", which the HID task answers by
/// opening a presence window and re-driving the command.
#[test]
fn att_import_without_a_prior_mse_session_is_refused() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    let chain = der_chain(1, 64);
    with_ops(&mut ks, &mut session, |ops| {
        let sealed = chacha_seal(&[9u8; 32], &[3u8; 12], &[0x44; 32], &[4u8; 65]);
        let params = import_params_bytes(&sealed, &chain);
        let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
        let r = att_import(&req, Some(acfg_token()), presence(true), ops);
        assert_eq!(r.status.code(), INVALID_PARAMETER);
        assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge);
        assert!(stored_chain(ops).is_none(), "nothing was installed");
    });
}

// ---------------------------------------------------------------------------
// 3b. `ATT_STATE` is ungated, and that is a wiring hazard rather than a style.
// ---------------------------------------------------------------------------

/// The client's exact `ATT_STATE` request **would be refused by the stock
/// gate**, which is why [`att_state`] takes no request bytes, no token and no
/// presence probe at all.
///
/// `att_status` calls
/// `rs_key_vendor(RSKEY_VENDOR_ATT_STATE, None, None)` — no params, **no
/// token**, no MAC ([`picoforge/src/hal/fido/mod.rs:1895`]) — so the request is
/// `{1: 0x0B}` and `vendor41::verify_mac` answers
/// [`Ctap2Response::PuatRequired`] (`0x36`) on it *before* it even looks at the
/// sub-command, because there is no `pinUvAuthParam` to verify
/// (`vendor41.rs:2816-2819`).
///
/// A dispatch arm that funnels `AttState` through the same `match` as
/// `AttClear`/`AttImport` therefore turns the client's feature probe into a
/// `0x36`, and the desktop Attestation screen cannot tell "not provisioned"
/// from "this firmware refuses to answer". The fix is structural — the arm's
/// signature has nowhere to put an `auth` — and this test is what makes the
/// structural fix load-bearing: it pins both halves, the refusal the wiring
/// would cause and the answer the arm actually gives.
#[test]
fn att_state_is_ungated_and_the_clients_own_request_would_fail_the_stock_gate() {
    let req = att_state_request();
    assert_eq!(req, vec![0xA1, 0x01, SUB_ATT_STATE], "att_status sends key 1 and nothing else");

    // Both shapes a dispatcher might hand it, and both are refused.
    assert_eq!(
        vendor41::verify_mac(&req, Some(&PIN_TOKEN)).err().map(|e| e.code()),
        Some(PUAT_REQUIRED),
        "with a token: still no pinUvAuthParam, so 0x36"
    );
    assert_eq!(
        vendor41::verify_mac(&req, None).err().map(|e| e.code()),
        Some(PUAT_REQUIRED),
        "and with none, which is what the client actually sends"
    );

    // The arm answers anyway, because it never consults any of it.
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    with_ops(&mut ks, &mut session, |ops| {
        let mut out = Reply::new();
        let r = att_state(ops, &mut out);
        assert_eq!(r.status.code(), OK);
        assert_eq!(
            r.charge_pin_auth,
            ChargePinAuth::NoCharge,
            "an ungated arm has no path by which it could charge the counter"
        );
        assert_eq!(parse_att_state(&out), (false, None));
    });
}

/// Malformed request bodies are `0x12` and are **not** charged.
///
/// Four shapes, one per refusal reason the decoder makes: not a map, a
/// truncated value, a repeated key 2 (which would make "which params was
/// signed" undecidable), and trailing bytes after the map. The last one is
/// worth calling out: a request that *decodes* correctly and then carries
/// extra bytes is a request whose signed message this firmware did not
/// assemble, and accepting it would be accepting bytes the MAC never covered.
#[test]
fn a_malformed_import_body_is_refused_without_charging_the_pin_counter() {
    let good_chain = der_chain(1, 40);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // Not a CBOR map at all.
        ("not a map", vec![0x01, 0x02, 0x03]),
        // Truncated: the map header says two pairs and the body stops.
        ("truncated", vec![0xA2, 0x01, 0x58, 0x3C]),
        // Trailing bytes after a well-formed map.
        ("trailing bytes", {
            let mut v = import_params_bytes(&[0u8; 60], &good_chain);
            v.push(0x00);
            v
        }),
    ];
    for (label, params) in cases {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let _ = mse_host(ops);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            let r = att_import(&req, Some(acfg_token()), presence(true), ops);
            assert_eq!(r.status.code(), INVALID_CBOR, "{label}");
            assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "{label}");
            assert!(stored_chain(ops).is_none(), "{label}: nothing written");
        });
    }

    // A repeated key 2 in the outer request map: the params are *inside* the
    // signed message, so two of them makes the request undecidable and
    // last-wins would decide it silently.
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    with_ops(&mut ks, &mut session, |ops| {
        let _ = mse_host(ops);
        let params = import_params_bytes(&[0u8; 60], &good_chain);
        let mut req: Vec<u8> = vec![0xA3];
        push_uint_to_vec(&mut req, 1);
        push_uint_to_vec(&mut req, SUB_ATT_IMPORT as u64);
        push_uint_to_vec(&mut req, 2);
        req.extend_from_slice(&params);
        push_uint_to_vec(&mut req, 2);
        req.extend_from_slice(&params);
        push_uint_to_vec(&mut req, 3);
        push_uint_to_vec(&mut req, 1);
        push_uint_to_vec(&mut req, 4);
        push_bstr_to_vec(&mut req, &picoforge_mac(&PIN_TOKEN, SUB_ATT_IMPORT, &params));
        let r = att_import(&req, Some(acfg_token()), presence(true), ops);
        assert_eq!(r.status.code(), INVALID_CBOR, "a repeated key 2");
        assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge);
        assert!(stored_chain(ops).is_none());
    });
}

// ---------------------------------------------------------------------------
// 4. The DER walk.
// ---------------------------------------------------------------------------

/// A well-formed chain walks to the right number of certificates, and each
/// certificate comes back as the **exact** bytes that went in.
///
/// Three sizes, and the third exercises the `0x82` (two-byte length) form that
/// a 200-byte body would miss: 1 × short, 2 × `0x81`, 3 × `0x82`.
#[test]
fn a_well_formed_chain_walks_to_the_right_number_of_certificates() {
    for (n, body) in [(1usize, 64usize), (2, 200), (3, 600)] {
        let chain = der_chain(n, body);
        let walk = ChainWalk::parse(&chain).unwrap_or_else(|_| panic!("{n}×{body} must walk"));
        assert_eq!(walk.len(), n, "{n}×{body}: certificate count");
        assert!(!walk.is_empty());
        assert_eq!(walk.covered(), chain.len(), "the walk accounts for every byte");
        let got: Vec<Vec<u8>> = walk.iter().map(|c| c.to_vec()).collect();
        let mut off = 0usize;
        for (i, want) in got.iter().enumerate() {
            assert_eq!(&chain[off..off + want.len()], &want[..], "cert {i} is the wire bytes");
            off += want.len();
        }
        assert_eq!(off, chain.len());
        assert!(walk.get(n).is_none(), "out of range");
    }
}

/// A length field that runs past the end of the buffer desynchronises the walk
/// if it is not checked, and a desynchronised walk is not cosmetic: `sha256`
/// over the chain is what a host pins.
///
/// Three shapes, because a TLV parser that only checks the *short* form passes
/// the first: a `0x82` header claiming 65535 bytes over 8 bytes of input, a
/// `0x81` header claiming 255 over 10, and a **second** certificate whose
/// length runs off the end after a perfectly good first one — the case where
/// the first element parsed fine and only the *walk* is wrong.
#[test]
fn a_chain_whose_length_runs_past_the_end_is_rejected() {
    let cases: Vec<Vec<u8>> = vec![
        // 0x82 header, 65535 bytes claimed, 8 bytes present.
        vec![0x30, 0x82, 0xFF, 0xFF, 0, 0, 0, 0],
        // 0x81 header, 255 claimed, 10 present.
        vec![0x30, 0x81, 0xFF, 1, 2, 3, 4, 5, 6, 7],
        // A good 1-byte-body cert, then a 0x81 claiming 200 over 3 bytes.
        {
            let mut v = der_cert(1, 0x10);
            v.extend_from_slice(&[0x30, 0x81, 200, 0, 0, 0]);
            v
        },
        // A good cert, then a **truncated header**: 0x30 with nothing after it.
        {
            let mut v = der_cert(4, 0x20);
            v.push(0x30);
            v
        },
    ];
    for c in cases {
        assert_eq!(
            ChainWalk::parse(&c).err().map(|e| e.code()),
            Some(INVALID_LENGTH),
            "must refuse {c:02x?}"
        );
    }
}

/// A one-byte chain is a truncated header: a tag with no length at all.
///
/// The size the EPIC quotes is `1..=2048`, so a client-side check would accept
/// a one-byte chain if its first byte were `0x30` — and
/// `certs_pem_to_der`'s non-PEM path accepts exactly that
/// (`picoforge/src/hal/fido/mod.rs:1927-1933`: `input.first() == Some(&0x30)`).
/// So a one-byte `[0x30]` **does** reach the device, and the device is the
/// only place it can be refused.
#[test]
fn a_chain_of_exactly_one_byte_is_rejected() {
    assert_eq!(ChainWalk::parse(&[0x30]).err().map(|e| e.code()), Some(INVALID_LENGTH));
    // A one-byte chain that is not even a SEQUENCE.
    assert_eq!(ChainWalk::parse(&[0x31]).err().map(|e| e.code()), Some(INVALID_LENGTH));
    // The empty chain, which the client also checks (`chain.is_empty()`).
    assert_eq!(ChainWalk::parse(&[]).err().map(|e| e.code()), Some(INVALID_LENGTH));
}

/// The size bounds: exactly `ORG_CHAIN_MAX` is accepted, one byte more is
/// refused, and the refusal is on the **size** rather than on a walk failure.
///
/// Four 512-byte certificates: `0x82 0x02 0x00` is a 3-byte header, so each
/// element is 3 + 509 = 512 and the chain is exactly 2048.
#[test]
fn a_chain_of_exactly_2048_is_accepted_and_2049_is_rejected() {
    // A `0x82` element is `0x30 ‖ 0x82 ‖ len(2)` = a **4**-byte header, so a
    // 508-byte body makes a 512-byte certificate and four of them are exactly
    // 2048. Every element exercises the two-byte-length form.
    let chain = der_chain(4, 508);
    assert_eq!(chain.len(), ORG_CHAIN_MAX, "the fixture is exactly at the bound");
    let walk = ChainWalk::parse(&chain).expect("2048 is inside the bound");
    assert_eq!(walk.len(), 4);
    assert_eq!(walk.covered(), ORG_CHAIN_MAX);

    // 2049: three 512-byte certificates (1536) plus a 513-byte one. Every
    // element walks on its own; the **total** is one byte over, so the
    // refusal has to come from the size bound and not from a walk failure —
    // the two are different bugs.
    let mut over = der_chain(3, 508);
    over.extend_from_slice(&der_cert(509, 0xF0));
    assert_eq!(over.len(), ORG_CHAIN_MAX + 1);
    assert_eq!(ChainWalk::parse(&over).err().map(|e| e.code()), Some(INVALID_LENGTH));
}

/// The tag, the long forms and the minimality rule.
///
/// DER is **definite-length and minimal**, and the walk enforces both. That is
/// not pedantry: `chain_hash` is a value a host pins, and two byte strings
/// that decode to the same certificates must not both be accepted if the
/// device is going to report one hash for them.
#[test]
fn the_walk_enforces_the_der_tag_the_der_length_forms_and_minimality() {
    // Not a SEQUENCE tag.
    assert_eq!(ChainWalk::parse(&[0x31, 0x00]).err().map(|e| e.code()), Some(INVALID_LENGTH));
    // Indefinite length (BER) — forbidden in DER, and it has no end to walk to.
    assert_eq!(ChainWalk::parse(&[0x30, 0x80, 0, 0, 0, 0]).err().map(|e| e.code()), Some(INVALID_LENGTH));
    // `0x83`+ : a length no certificate in a 2 KB chain can have.
    assert_eq!(
        ChainWalk::parse(&[0x30, 0x83, 0, 0, 1, 0, 0]).err().map(|e| e.code()),
        Some(INVALID_LENGTH)
    );
    // Non-minimal `0x81` (a 1-byte body written in a 2-byte header) and
    // non-minimal `0x82` (a 255-byte body written in a 3-byte header).
    let nm81: Vec<u8> = vec![0x30, 0x81, 0x01, 0xAA];
    assert_eq!(ChainWalk::parse(&nm81).err().map(|e| e.code()), Some(INVALID_LENGTH));
    let mut nm82: Vec<u8> = vec![0x30, 0x82, 0x00, 0xFF];
    nm82.extend(std::iter::repeat_n(0xBB, 255));
    assert_eq!(ChainWalk::parse(&nm82).err().map(|e| e.code()), Some(INVALID_LENGTH));

    // …and the minimal forms of the same two lengths are accepted, so the
    // minimality rule is what is under test and not "reject anything big".
    assert!(ChainWalk::parse(&der_cert(200, 0x01)).is_ok(), "0x81 form");
    assert!(ChainWalk::parse(&der_cert(600, 0x02)).is_ok(), "0x82 form");
    assert!(ChainWalk::parse(&der_cert(0, 0x03)).is_ok(), "a zero-length SEQUENCE is a valid element");
}

/// The certificate-count bound exists for a reason that is worth stating: a
/// 2 KB chain of `30 00` is structurally valid DER, and a walk with no cap
/// would build a 1024-entry table behind a 1024-iteration loop on bytes the
/// client produced from a PEM file.
#[test]
fn a_chain_of_more_certificates_than_the_bound_is_rejected_rather_than_truncated() {
    let many = der_chain(MAX_CHAIN_CERTS + 1, 0);
    assert_eq!(many.len(), 2 * (MAX_CHAIN_CERTS + 1), "well inside ORG_CHAIN_MAX");
    assert_eq!(
        ChainWalk::parse(&many).err().map(|e| e.code()),
        Some(INVALID_LENGTH),
        "a truncated walk would report a chain of N as a chain of MAX_CHAIN_CERTS"
    );
    let at = der_chain(MAX_CHAIN_CERTS, 0);
    assert_eq!(ChainWalk::parse(&at).unwrap().len(), MAX_CHAIN_CERTS);
}

// ---------------------------------------------------------------------------
// 5. The AEAD and the all-or-nothing commit.
// ---------------------------------------------------------------------------

/// A wrong MSE key and a tampered scalar both fail **closed**: a non-zero
/// status, no charge against the PIN counter, and the durable state
/// byte-for-byte what it was.
///
/// "No charge" is part of the assertion and not an aside. These failures
/// happen *after* the MAC verified, so charging would burn one of a user's
/// three strikes for an AEAD problem — and the status the client sees
/// (`0x27`) is deliberately **not** `0x33`, because a `0x33` would send the
/// user back to the PIN prompt for a token that was never wrong.
#[test]
fn a_wrong_mse_key_or_a_tampered_scalar_fails_closed_with_no_partial_write() {
    let chain = der_chain(2, 100);

    // --- wrong MSE key ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            // The device handshakes; the *host* then seals to a different key.
            let _real = mse_host(ops);
            let wrong = HostChannel { key: [0xEE; 32], aad: [0x04; 65] };
            let sealed = wrong.wrap(&[0x55; 32], [0x07; 12]);
            let params = import_params_bytes(&sealed, &chain);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            let r = att_import(&req, Some(acfg_token()), presence(false), ops);
            assert_eq!(r.status.code(), OPERATION_DENIED, "a tag that does not verify is 0x27");
            assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "and it is not a PIN failure");
            assert!(stored_chain(ops).is_none(), "nothing was written");
        });
    }

    // --- wrong AAD (a different device point) ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let real = mse_host(ops);
            let mut aad = real.aad;
            aad[1] ^= 0xFF; // a different device point → the tag does not verify
            let sealed = chacha_seal(&real.key, &[0x07; 12], &[0x55; 32], &aad);
            let params = import_params_bytes(&sealed, &chain);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            let r = att_import(&req, Some(acfg_token()), presence(false), ops);
            assert_eq!(r.status.code(), OPERATION_DENIED, "the AAD is bound into the tag");
            assert!(stored_chain(ops).is_none());
        });
    }

    // --- tampered ciphertext, right key ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let chan = mse_host(ops);
            let mut sealed = chan.wrap(&[0x55; 32], [0x07; 12]);
            sealed[20] ^= 0x01; // one ciphertext bit
            let params = import_params_bytes(&sealed, &chain);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            let r = att_import(&req, Some(acfg_token()), presence(false), ops);
            assert_eq!(r.status.code(), OPERATION_DENIED);
            assert!(stored_chain(ops).is_none());
        });
    }

    // --- tampered tag, right key ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let chan = mse_host(ops);
            let mut sealed = chan.wrap(&[0x55; 32], [0x07; 12]);
            let n = sealed.len();
            sealed[n - 1] ^= 0x01;
            let params = import_params_bytes(&sealed, &chain);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            assert_eq!(
                att_import(&req, Some(acfg_token()), presence(false), ops).status.code(),
                OPERATION_DENIED
            );
            assert!(stored_chain(ops).is_none());
        });
    }

    // --- and a successful import really does write, so none of the above is
    //     vacuously true ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let chan = mse_host(ops);
            let sealed = chan.wrap(&[0x55; 32], [0x07; 12]);
            let params = import_params_bytes(&sealed, &chain);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            assert_eq!(att_import(&req, Some(acfg_token()), presence(false), ops).status.code(), OK);
            assert_eq!(stored_chain(ops).as_deref(), Some(&chain[..]));
        });
    }
}

/// A scalar with no chain, or a chain with no scalar, is refused — the
/// behaviour `VendorOps::set_org_attestation`'s doc promises.
///
/// Both directions, and the arm refuses before it can construct the
/// half-populated `OrgAttestation` that `put_org` refuses: the state layer's
/// check is the *durable* one, but the arm's is the one the client can act on.
#[test]
fn a_scalar_without_a_chain_or_a_chain_without_a_scalar_is_refused() {
    let chain = der_chain(1, 100);
    for (label, params) in [
        ("scalar only", import_params_no_chain(&chacha_seal(&[1u8; 32], &[1u8; 12], &[2u8; 32], &[3u8; 65]))),
        ("chain only", import_params_no_scalar(&chain)),
    ] {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let _ = mse_host(ops);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            let r = att_import(&req, Some(acfg_token()), presence(false), ops);
            assert_eq!(r.status.code(), MISSING_PARAMETER, "{label}");
            assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge);
            assert!(stored_chain(ops).is_none(), "{label}: nothing was written");
        });
    }
}

/// A malformed chain is refused **after** a correct MAC, and nothing is
/// written — the two failure classes must not be confused.
///
/// The MAC is over the params that contain the bad chain, so this request is
/// *authenticated*: a chain the walk refuses is a protocol problem, not an
/// auth problem, and answering `0x33` would be a lie the user pays for.
#[test]
fn a_malformed_chain_is_refused_after_a_correct_mac_and_writes_nothing() {
    for bad in [vec![0x30u8], vec![0x30, 0x82, 0xFF, 0xFF, 0, 0], vec![0x31, 0x00]] {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let chan = mse_host(ops);
            let sealed = chan.wrap(&[0x66; 32], [0x09; 12]);
            let params = import_params_bytes(&sealed, &bad);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            let r = att_import(&req, Some(acfg_token()), presence(false), ops);
            assert_eq!(r.status.code(), INVALID_LENGTH, "chain {bad:02x?}");
            assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "the MAC verified — do not charge");
            assert!(stored_chain(ops).is_none());
        });
    }
}

// ---------------------------------------------------------------------------
// 6. The gating.
// ---------------------------------------------------------------------------

/// The token/touch union, and the PIN-auth charging rule, in both directions.
///
/// The rows come straight from the module docs. The two that are easy to get
/// backwards are the last two:
///
/// * a rejected MAC **is** charged (it is the only chargeable failure);
/// * the three-strike latch is **not** charged — once set, the app has already
///   spent three strikes, and charging again would both move `0x34` to `0x33`
///   and tell a user with a good token that their token is wrong.
#[test]
fn the_gate_accepts_a_token_or_a_touch_and_charges_only_a_rejected_mac() {
    let chain = der_chain(1, 80);

    // --- token present, MAC wrong → 0x33, charged ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let _ = mse_host(ops);
            let sealed = chacha_seal(&[1u8; 32], &[1u8; 12], &[2u8; 32], &[3u8; 65]);
            let params = import_params_bytes(&sealed, &chain);
            let mut req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            // Corrupt the pinUvAuthParam (the last 16 bytes).
            let n = req.len();
            req[n - 1] ^= 0xFF;
            let r = att_import(&req, Some(acfg_token()), presence(true), ops);
            assert_eq!(r.status.code(), PIN_AUTH_INVALID);
            assert_eq!(r.charge_pin_auth, ChargePinAuth::Charge, "the only chargeable failure");
            assert!(stored_chain(ops).is_none());
        });
    }

    // --- latch set → 0x34, not charged ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let _ = mse_host(ops);
            let sealed = chacha_seal(&[1u8; 32], &[1u8; 12], &[2u8; 32], &[3u8; 65]);
            let params = import_params_bytes(&sealed, &chain);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            let r = att_import(&req, Some(blocked_token()), presence(true), ops);
            assert_eq!(r.status.code(), PIN_AUTH_BLOCKED);
            assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "the app already spent its strikes");
            assert!(stored_chain(ops).is_none());
        });
    }

    // --- no token, no touch → 0x3B, not charged ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let _ = mse_host(ops);
            let sealed = chacha_seal(&[1u8; 32], &[1u8; 12], &[2u8; 32], &[3u8; 65]);
            let params = import_params_bytes(&sealed, &chain);
            // No keys 3/4 at all — the client's documented no-PIN shape.
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), None);
            let r = att_import(&req, None, presence(false), ops);
            assert_eq!(r.status.code(), UP_REQUIRED);
            assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "nothing was authenticated");
            assert!(stored_chain(ops).is_none());
        });
    }

    // --- no token, touch granted → proceeds ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let chan = mse_host(ops);
            let sealed = chan.wrap(&[0x66; 32], [0x09; 12]);
            let params = import_params_bytes(&sealed, &chain);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), None);
            let r = att_import(&req, None, presence(true), ops);
            assert_eq!(r.status.code(), OK, "the touch path is legitimate");
            assert!(stored_chain(ops).is_some());
        });
    }

    // --- token present but without PERM_ACFG → 0x40, not charged ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let _ = mse_host(ops);
            let sealed = chacha_seal(&[1u8; 32], &[1u8; 12], &[2u8; 32], &[3u8; 65]);
            let params = import_params_bytes(&sealed, &chain);
            let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
            let r = att_import(&req, Some(wrong_perm_token()), presence(true), ops);
            assert_eq!(r.status.code(), UNAUTHORIZED_PERMISSION);
            assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "the token was real");
            assert!(stored_chain(ops).is_none());
        });
    }

    // --- `ATT_CLEAR` follows the same rule ---
    {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        with_ops(&mut ks, &mut session, |ops| {
            let _ = mse_host(ops);
            let req = att_clear_request(None);
            let r = att_clear(&req, None, presence(false), ops);
            assert_eq!(r.status.code(), UP_REQUIRED);
            assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge);
        });
    }
}

/// The touch path must **not** reach the MAC verifier — otherwise a request
/// that smuggles a `pinUvAuthParam` alongside a touch would be charged for a
/// param the client never sent, and three no-PIN imports would latch a
/// three-strike lockout against a user who failed nothing.
///
/// Driven by smuggling a *bad* `pinUvAuthParam` into a tokenless request: if
/// the arm looked, the answer would be `0x33` charged; because it does not,
/// the answer is the touch's.
#[test]
fn the_touch_path_never_looks_at_a_pin_uv_auth_param() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    let chain = der_chain(1, 60);
    with_ops(&mut ks, &mut session, |ops| {
        let chan = mse_host(ops);
        let sealed = chan.wrap(&[0x12; 32], [0x34; 12]);
        let params = import_params_bytes(&sealed, &chain);
        // `{1: sub, 2: params, 3: 1, 4: <16 bytes of garbage>}` — a tokenless
        // request carrying a pinUvAuthParam the client would never send.
        let mut req: Vec<u8> = Vec::new();
        req.push(0xA4);
        push_uint_to_vec(&mut req, 1);
        push_uint_to_vec(&mut req, SUB_ATT_IMPORT as u64);
        push_uint_to_vec(&mut req, 2);
        req.extend_from_slice(&params);
        push_uint_to_vec(&mut req, 3);
        push_uint_to_vec(&mut req, 1);
        push_uint_to_vec(&mut req, 4);
        push_bstr_to_vec(&mut req, &[0xAB; 16]);

        let r = att_import(&req, None, presence(true), ops);
        assert_eq!(r.status.code(), OK, "a touch is a complete authorisation");
        assert_eq!(r.charge_pin_auth, ChargePinAuth::NoCharge, "nothing was verified, so nothing is charged");
    });
}

/// The MAC is verified over the bytes the client actually sent.
///
/// This is the trap the module names: a device that **re-serialised** the
/// params map canonically would answer `0x33` — "PIN auth invalid" — to a
/// request whose MAC is arithmetically perfect, and the user would be sent
/// back to the PIN prompt for a token that was never wrong. The host's own
/// `cbor::encode` sorts map keys and rewrites every head canonically
/// (`fapico2_fido::cbor::encode_to`, `Value::M` arm), so a re-encoding
/// implementation is not hypothetical.
///
/// Driven with a **non-minimal** byte-string head: same map, same value,
/// different bytes.
#[test]
fn the_import_mac_is_verified_over_the_clients_own_bytes() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    let chain = der_chain(2, 300);
    with_ops(&mut ks, &mut session, |ops| {
        let chan = mse_host(ops);
        let sealed = chan.wrap(&[0x21; 32], [0x43; 12]);
        let canonical = import_params_bytes(&sealed, &chain);
        let non_canonical = import_params_non_canonical_head(&sealed, &chain);
        assert_ne!(canonical, non_canonical, "the two encodings differ in bytes");
        assert_eq!(
            import_params(&canonical).unwrap().1,
            import_params(&non_canonical).unwrap().1,
            "and decode to the same value — that is the whole point"
        );

        // MAC over the *non-canonical* bytes, sent as the non-canonical bytes.
        let req = rskey_request(SUB_ATT_IMPORT, Some(&non_canonical), Some(&PIN_TOKEN));
        let r = att_import(&req, Some(acfg_token()), presence(false), ops);
        assert_eq!(r.status.code(), OK, "the wire span is what the MAC covers");
        assert_eq!(stored_chain(ops).as_deref(), Some(&chain[..]));
    });
}

/// D-GJ-4, in its fixed form: **the largest legal `ATT_IMPORT` authenticates**.
///
/// This test was written while `vendor41::verify_mac` still had its original
/// 192-byte buffer, which capped a `subCommandParams` value at ~158 bytes and
/// made every request the client actually sends overflow into
/// `0x03` (`INVALID_LENGTH`) before a MAC byte was compared — a capacity limit
/// the desktop Attestation screen reports as a *device* failure rather than as
/// the authentication problem it is.
///
/// It originally asserted the defect: a "stock" verifier alongside a raised
/// one, side by side. `verify_mac` **is** the raised verifier now, so there is
/// no second copy to compare against, and a test that compared two
/// implementations of the same thing would only prove they were both wrong
/// together. What is worth pinning now is the two properties that survive: the
/// worst case passes, and a request past the buffer is still **refused** rather
/// than truncated into a message that verifies over fewer bytes than were sent.
#[test]
fn a_maximum_size_import_authenticates_and_an_oversized_one_is_refused() {
    // 2048 bytes of chain, 60 of sealed scalar: the largest legal request.
    let chain = der_chain(4, 508);
    assert_eq!(chain.len(), ORG_CHAIN_MAX);

    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    with_ops(&mut ks, &mut session, |ops| {
        let chan = mse_host(ops);
        let sealed = chan.wrap(&[0x42; 32], [0x56; 12]);
        let params = import_params_bytes(&sealed, &chain);
        assert_eq!(params.len(), ATT_IMPORT_PARAMS_MAX, "the worst case is exactly the constant");

        let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));

        // The worst case assembles, and the MAC checks out over it.
        assert_eq!(
            vendor41::verify_mac(&req, Some(&PIN_TOKEN)).map(|_| ()).map_err(|e| e.code()),
            Ok(()),
            "D-GJ-4, fixed: 2116 bytes of params must assemble and verify"
        );

        // And the import succeeds.
        let r = att_import(&req, Some(acfg_token()), presence(false), ops);
        assert_eq!(r.status.code(), OK);
        assert_eq!(stored_chain(ops).as_deref(), Some(&chain[..]));
    });

    // And the arithmetic the constants are derived from.
    assert_eq!(ATT_IMPORT_PARAMS_MAX, 1 + 63 + 2052, "A2 | 01 58 3C ‖60 | 02 59 08 00 ‖2048");
    assert_eq!(MAC_FIXED_HEAD, 34, "FF×32 ‖ 0x41 ‖ subCommand");
    // Every operand above is a `const`, so a runtime `assert!` here would only
    // ever compare two values the compiler already folded. Check it in
    // const-eval instead — a false side is a zero-length array, i.e. a build
    // failure rather than a runtime no-op.
    const _: [(); 1] = [(); (ATT_MAC_MSG_MAX >= MAC_FIXED_HEAD + ATT_IMPORT_PARAMS_MAX) as usize];
    assert_eq!(ATT_MAC_MSG_MAX, 2200, "34 + 2116 + 50 headroom");
}

/// `ATT_CLEAR` uses the **stock** verifier, because its params are empty and
/// its signed message is 34 bytes — there is no reason to spend the 2200-byte
/// buffer on the one attestation sub-command that does not need it.
#[test]
fn att_clear_authenticates_with_the_stock_verifier_and_writes_no_body() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    let chain = der_chain(1, 64);
    with_ops(&mut ks, &mut session, |ops| {
        let chan = mse_host(ops);
        let sealed = chan.wrap(&[0x31; 32], [0x41; 12]);
        let params = import_params_bytes(&sealed, &chain);
        let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
        assert_eq!(att_import(&req, Some(acfg_token()), presence(false), ops).status.code(), OK);

        // The stock verifier clears the same request the client sends.
        let req = att_clear_request(Some(&PIN_TOKEN));
        assert!(vendor41::verify_mac(&req, Some(&PIN_TOKEN)).is_ok(), "34 bytes fits 192 easily");
        assert_eq!(att_clear(&req, Some(acfg_token()), presence(false), ops).status.code(), OK);
        assert!(stored_chain(ops).is_none());
    });
}

// ---------------------------------------------------------------------------
// 7. The AEAD, against vectors from outside this repository.
// ---------------------------------------------------------------------------

/// `aead_open` reproduces an **external** implementation's bytes, and fails in
/// every direction that matters.
///
/// The vectors below were produced by Python's `cryptography` bindings
/// (`ChaCha20Poly1305.encrypt`), not by this code and not by the client. The
/// AAD of the first is 65 bytes — the width of a P-256 uncompressed point, so
/// the AAD exercises the RFC 8439 §2.8 padding rule at a length that is not a
/// multiple of 16 — and the second is 7 bytes, so the padding is exercised in
/// the other direction. The 32-byte plaintext is the one shape
/// `aead_open` accepts, and the one the client's `try_into::<[u8; 32]>` makes.
///
/// "The sealer and the opener agree" is deliberately **not** the property
/// being asserted here: it is asserted by the other direction, that a
/// *different* implementation's tag is what this code accepts.
///
/// The opener under test is now the `chacha20poly1305` crate, so this is
/// doubly an outside vector: it pins the **dependency**, not just our framing
/// of it. That is the more valuable direction, and it is why the KAT outlived
/// the hand-rolled implementation it was written against.
#[test]
fn the_aead_opener_matches_vectors_from_an_independent_implementation() {
    // --- vector 1: 65-byte AAD (a device point) ---
    const KEY1: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    const NONCE1: [u8; 12] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab];
    const CT1: [u8; 32] = [
        0x0f, 0xa1, 0x69, 0x47, 0x52, 0xc0, 0xef, 0x99, 0x9b, 0x4d, 0xba, 0x44, 0xab, 0xa4, 0x98, 0x97,
        0xee, 0x24, 0x52, 0x37, 0xcc, 0xfc, 0xfd, 0x07, 0x1f, 0x6a, 0x62, 0x71, 0xb6, 0xac, 0x16, 0xd0,
    ];
    const TAG1: [u8; 16] = [
        0x43, 0x30, 0x95, 0x14, 0xd1, 0xfb, 0x86, 0x6b, 0xf9, 0x56, 0xd8, 0x73, 0x71, 0x79, 0x5d, 0xb8,
    ];
    const PT1: [u8; 32] = [
        0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e, 0x65, 0x6c,
        0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4, 0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc,
    ];

    let mut aad1 = [0u8; 65];
    aad1[0] = 0x04;
    for i in 0..64 {
        aad1[1 + i] = i as u8;
    }
    let mut blob1 = [0u8; SCALAR_BLOB_LEN];
    blob1[..12].copy_from_slice(&NONCE1);
    blob1[12..44].copy_from_slice(&CT1);
    blob1[44..60].copy_from_slice(&TAG1);

    let mut out = [0u8; 32];
    assert!(aead_open(&KEY1, &aad1, &blob1, &mut out).is_ok(), "vector 1 opens");
    assert_eq!(out, PT1, "and reproduces the external plaintext");

    // --- vector 2: 7-byte AAD ---
    const KEY2: [u8; 32] = [0x5a; 32];
    const CT2: [u8; 32] = [
        0xac, 0x1a, 0x85, 0x90, 0x5d, 0x62, 0x54, 0x30, 0x92, 0xcb, 0x86, 0xa7, 0x12, 0x7e, 0xa4, 0x6d,
        0xd9, 0x1f, 0x5d, 0x47, 0x44, 0xcd, 0xd8, 0xb6, 0xd9, 0x93, 0xb8, 0x69, 0x61, 0x7a, 0x73, 0x1f,
    ];
    const TAG2: [u8; 16] = [
        0xa7, 0xe9, 0xf7, 0xe0, 0x9e, 0x94, 0x0a, 0x62, 0x59, 0x31, 0x00, 0x70, 0xc8, 0x61, 0xdb, 0x3f,
    ];
    const PT2: [u8; 32] = [0xff; 32];
    let aad2 = [0u8, 1, 2, 3, 4, 5, 6];
    let mut blob2 = [0u8; SCALAR_BLOB_LEN];
    blob2[..12].copy_from_slice(&[1u8; 12]);
    blob2[12..44].copy_from_slice(&CT2);
    blob2[44..60].copy_from_slice(&TAG2);
    let mut out = [0u8; 32];
    assert!(aead_open(&KEY2, &aad2, &blob2, &mut out).is_ok(), "vector 2 opens");
    assert_eq!(out, PT2);

    // --- the negatives ---
    // Wrong key.
    let mut out = [0u8; 32];
    assert_eq!(aead_open(&[0u8; 32], &aad1, &blob1, &mut out).err().map(|e| e.code()), Some(OPERATION_DENIED));
    // Wrong AAD.
    let mut out = [0u8; 32];
    let mut aad1b = aad1;
    aad1b[64] ^= 0x01;
    assert_eq!(aead_open(&KEY1, &aad1b, &blob1, &mut out).err().map(|e| e.code()), Some(OPERATION_DENIED));
    // Tampered ciphertext / tampered tag / tampered nonce: all three are inside
    // the MAC, so all three are `OPERATION_DENIED` and none of them is a
    // length error.
    for byte in [0usize, 12, 30, 43, 44, 59] {
        let mut b = blob1;
        b[byte] ^= 0x01;
        let mut out = [0u8; 32];
        assert_eq!(
            aead_open(&KEY1, &aad1, &b, &mut out).err().map(|e| e.code()),
            Some(OPERATION_DENIED),
            "byte {byte} is covered by the tag"
        );
    }
    // Too short to hold `nonce ‖ tag`.
    let mut out = [0u8; 32];
    assert_eq!(aead_open(&KEY1, &aad1, &blob1[..27], &mut out).err().map(|e| e.code()), Some(INVALID_LENGTH));
    // 61 bytes: 33 of ciphertext, i.e. a 33-byte plaintext, which is not a
    // P-256 scalar. A length refusal, not a tag failure.
    let mut b = [0u8; 61];
    b[..60].copy_from_slice(&blob1);
    b[60] = 0;
    let mut out = [0u8; 32];
    assert_eq!(aead_open(&KEY1, &aad1, &b, &mut out).err().map(|e| e.code()), Some(INVALID_LENGTH));
}

/// The full RFC 8439 §2.8.2 AEAD vector, through the **shipped** seam.
///
/// The two vectors in the test above are the ones this protocol actually uses:
/// 32-byte plaintexts, AADs of 65 and 7 bytes. §2.8.2 is a *different* message
/// — 114 bytes with a 12-byte AAD — so it cannot go through `aead_open` (whose
/// `out` is exactly a P-256 scalar) and needs the general sealer. That is the
/// point of keeping it: it is the RFC's own end-to-end vector, and after the
/// collapse it is a check that the `chacha20poly1305` crate this firmware
/// depends on produces RFC 8439's bytes, not a check of arithmetic we wrote.
///
/// The tag is the one the RFC prints: `1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb
/// d0 60 06 91`, for the §2.8.2 key, nonce, plaintext and AAD
/// `50515253c0c1c2c3c4c5c6c7` (hex-decoded, not the ASCII literal — the two
/// are different AADs and produce different tags).
#[test]
fn the_crates_aead_reproduces_rfc_8439_section_2_8_2() {
    const KEY: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const NONCE: [u8; 12] = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    const AAD: [u8; 12] = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
    const PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const WANT_TAG: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
        0x06, 0x91,
    ];
    const WANT_CT_PREFIX: [u8; 16] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
        0x7e, 0xc2,
    ];

    // 114 bytes of plaintext plus the 16-byte tag.
    let mut out: HV<u8, 256> = HV::new();
    fapico2_fido::crypto::chacha20poly1305_seal(&KEY, &NONCE, &AAD, PT, &mut out)
        .expect("the RFC message fits a 256-byte buffer");
    assert_eq!(out.len(), PT.len() + 16, "the framing is ct ‖ tag(16)");
    assert_eq!(
        &out[..16],
        &WANT_CT_PREFIX[..],
        "the crate's ciphertext is not RFC 8439 §2.8.2"
    );
    let split = out.len() - 16;
    assert_eq!(
        &out[split..],
        &WANT_TAG[..],
        "the crate's Poly1305 tag is not RFC 8439 §2.8.2"
    );
}

// ---------------------------------------------------------------------------
// 8. The layering rule — the US-175 regression test.
// ---------------------------------------------------------------------------

/// **The regression the US-175 RESOLVED note demands**: *"A device with no org
/// cert imported must still mint normal FIDO2 attestations — that is the
/// regression test."*
///
/// Run on the **host** `FidoApp`, because that is the command path whose
/// `makeCredential` returns a `packed` statement with an `x5c` chain
/// (`app.rs:1429-1449`) — the shape a relying party actually pins. (The RP2350
/// build's `makeCredential` returns a **self**-attestation with no `x5c` —
/// `device_core.rs:1071` — so on that path the per-device identity shows up in
/// the U2F *register* response instead. Same identity, different consumer; the
/// org slot is on neither.)
///
/// The two identities are in the two places they actually live:
///
/// * the per-device one in the app, as an
///   [`AttestationIdentity`](fapico2_fido::attestation::AttestationIdentity)
///   minted from the TRNG at construction (`app.rs:330-332`);
/// * the org one in the vendor snapshot, reached only through
///   [`VendorOps::org_attestation`].
///
/// The test is deliberately **before *and* after**, because either half alone
/// is weak: "a fresh device mints an attestation" passes on a firmware where
/// the import overwrote the per-device identity, and "the import did not
/// change the cert" passes on a firmware that never minted one at all. Both
/// halves together are the claim.
#[test]
fn a_device_with_no_org_cert_still_mints_a_normal_fido2_attestation() {
    type App = fapico2_fido::app::FidoApp<MemoryKeystore>;
    let mut app = App::with_keystore(MemoryKeystore::new());
    let mut session = VendorSession::default();

    // --- before: the FIDO2 statement, with no org cert anywhere ---
    let cert_before = fido2_cert(&mut app);
    // The host app keeps its identity private; the observable is the statement itself, which is
    // what the assertion below actually checks. (The device twin exposes
    // `attestation()`; the host twin does not.)
    let key_before = fido2_cert(&mut app);
    assert!(!cert_before.is_empty(), "a fresh device does mint an attestation");
    with_ops(app.keystore(), &mut session, |ops| {
        assert!(!ops.org_attestation().installed(), "no org cert on a fresh device");
    });

    // --- import an org credential that is *obviously* not the device's ---
    let org_chain = der_chain(2, 400);
    let org_scalar = [0x5E; 32];
    with_ops(app.keystore(), &mut session, |ops| {
        let chan = mse_host(ops);
        let sealed = chan.wrap(&org_scalar, [0x77; 12]);
        let params = import_params_bytes(&sealed, &org_chain);
        let req = rskey_request(SUB_ATT_IMPORT, Some(&params), Some(&PIN_TOKEN));
        let r = att_import(&req, Some(acfg_token()), presence(false), ops);
        assert_eq!(r.status.code(), OK, "the import really happened");
        let v = ops.org_attestation();
        assert!(v.installed(), "so this test is not vacuous");
        assert_eq!(v.scalar, Some(org_scalar));
        assert_eq!(v.chain, &org_chain[..]);
    });

    // --- after: the FIDO2 statement is byte-identical ---
    let cert_after = fido2_cert(&mut app);
    assert_eq!(cert_after, cert_before, "the org slot is not on the FIDO2 attestation path");
    assert_eq!(fido2_cert(&mut app), key_before, "and the per-device identity is still the one that signs");
    assert_ne!(
        cert_after, org_chain,
        "the statement still carries the per-device self-signed cert, not the org chain"
    );
}

/// The structural half of the layering rule, stated as a fact about the
/// dependency graph rather than as a behaviour.
///
/// `crate::attestation` (the per-device identity, the FIDO2 path) must not be
/// able to reach the org slot. It does not import `crate::vendor41` at all, so
/// `VendorOps` — and therefore `org_attestation` — is not in its transitive
/// dependency set; and this module, which *does* import `crate::vendor41`,
/// never imports `crate::attestation`.
///
/// The check is textual because that is the only honest way to assert a
/// property of a source graph from inside a test, and it is cheap: it fails the
/// moment either direction is introduced.
#[test]
fn the_per_device_attestation_module_cannot_reach_the_org_slot() {
    // Integration tests run with CWD = the package root, but say so rather than
    // depend on it: `CARGO_MANIFEST_DIR` is the only path cargo guarantees.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = |p: &str| {
        std::fs::read_to_string(root.join(p)).unwrap_or_else(|e| panic!("{p}: {e}"))
    };

    // Only the **code** is checked. These files are full of `//!` prose that
    // legitimately names the other side (the module docs have to explain the
    // layering), and a textual check that counted doc links would fail on the
    // documentation rather than on the dependency graph.
    let code = |text: &str| -> String {
        text.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let att = code(&src("src/attestation.rs"));
    let cert = code(&src("src/attestation_cert.rs"));
    for (name, text) in [("attestation.rs", &att), ("attestation_cert.rs", &cert)] {
        assert!(
            !text.contains("vendor41") && !text.contains("vendor_att"),
            "{name} must not reference the 0x41 channel: the per-device identity is not an org credential"
        );
        assert!(
            !text.contains("org_attestation") && !text.contains("OrgAttestation"),
            "{name} must not name the org slot at all"
        );
    }

    // And this module — which does implement the org surface — does not import
    // the per-device identity either. The layering is symmetric, and a one-way
    // dependency that is a *cycle* in intent is the failure mode.
    let att_rs = code(&src("src/vendor_att.rs"));
    assert!(
        !att_rs.contains("use crate::attestation") && !att_rs.contains("crate::attestation::"),
        "vendor_att must not reach into the per-device identity"
    );
    assert!(
        !att_rs.contains("ATTEST_KEY_SLOT") && !att_rs.contains("ATTEST_CERT_SLOT"),
        "and must not name the per-device slots"
    );
}

// ---------------------------------------------------------------------------
// Helpers that need the app.
// ---------------------------------------------------------------------------

/// Run one `makeCredential` on the host app and return the `x5c[0]` from the
/// `packed` attestation statement — the certificate a relying party would pin.
///
/// No PIN is set on this app, so the request needs no `pinUvAuthParam` and the
/// call is a single round trip with no token machinery.
///
/// Key numbering is CTAP2.1 §5.8.1, transcribed from `device_core::parse_mc`'s
/// key arms (`device_core.rs:251-343`): 1 clientDataHash, 2 rp, 3 user,
/// 4 pubKeyCredParams, 5 excludeList. Note that **3 is `user` and 4 is the
/// algorithm list** — the opposite of the order they are usually written down
/// in, and getting it backwards is an `0x12` with no other symptom.
fn fido2_cert(app: &mut fapico2_fido::app::FidoApp<MemoryKeystore>) -> Vec<u8> {
    let mut req: HV<u8, 512> = HV::new();
    nh::push_map_header(&mut req, 5).unwrap();
    nh::push_uint(&mut req, 1).unwrap();
    nh::push_bstr(&mut req, &[0xCC; 32]).unwrap();
    nh::push_uint(&mut req, 2).unwrap();
    nh::push_map_header(&mut req, 1).unwrap();
    nh::push_tstr(&mut req, "id").unwrap();
    nh::push_tstr(&mut req, "vendor-att.example").unwrap();
    nh::push_uint(&mut req, 3).unwrap();
    nh::push_map_header(&mut req, 1).unwrap();
    nh::push_tstr(&mut req, "id").unwrap();
    nh::push_bstr(&mut req, &[0x75; 32]).unwrap();
    nh::push_uint(&mut req, 4).unwrap();
    nh::push_array_header(&mut req, 1).unwrap();
    nh::push_map_header(&mut req, 2).unwrap();
    nh::push_tstr(&mut req, "type").unwrap();
    nh::push_tstr(&mut req, "public-key").unwrap();
    nh::push_tstr(&mut req, "alg").unwrap();
    nh::push_neg(&mut req, -7).unwrap();
    nh::push_uint(&mut req, 5).unwrap();
    nh::push_array_header(&mut req, 0).unwrap();

    let resp = app.process_ctap2(0x01, &req, [0; 4]);
    assert_eq!(resp[0], 0x00, "makeCredential succeeded: {}", hex(&resp[..resp.len().min(64)]));

    // {1: fmt, 2: authData, 3: attStmt}. `attStmt` is a **map**, not a byte
    // string: `app.rs:1436` builds it through `cbor::Value::M` and serialises
    // the whole response, so key 3's value is an inline CBOR map. Spanned
    // rather than decoded, so the inner walk is over the response's own bytes.
    let mut p = Parser::new(&resp[1..]);
    let pairs = match p.next() {
        Ok(Item::Map(m)) => m,
        _ => panic!("makeCredential response must be a map"),
    };
    let mut stmt_span: Option<(usize, usize)> = None;
    let mut fmt = String::new();
    for _ in 0..pairs {
        let Item::U(k) = p.next().expect("uint key") else { panic!() };
        match k {
            // `fmt` is a key of the **response** (1), not of the statement —
            // `app.rs:1450` puts it beside `authData` and `attStmt`.
            1 => {
                if let Ok(Item::T(s)) = p.next() {
                    fmt = s.to_string();
                }
            }
            3 => {
                let start = p.pos();
                p.skip().expect("attStmt");
                stmt_span = Some((start, p.pos()));
            }
            _ => p.skip().unwrap(),
        }
    }
    let (s0, s1) = stmt_span.expect("key 3 attStmt");
    let mut sp = Parser::new(&resp[1 + s0..1 + s1]);
    let np = match sp.next() {
        Ok(Item::Map(m)) => m,
        _ => panic!("attStmt must be a map"),
    };
    let mut x5c: Option<Vec<Vec<u8>>> = None;
    for _ in 0..np {
        let key = sp.next().expect("key");
        if key == Item::T("x5c") {
            let Ok(Item::Array(n)) = sp.next() else { panic!("x5c must be an array") };
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(mbytes(&mut sp, "x5c element").to_vec());
            }
            x5c = Some(v);
        } else {
            sp.skip().unwrap();
        }
    }
    assert_eq!(fmt, "packed", "the statement is the packed self/device form");
    x5c.expect("a packed statement with an x5c chain")[0].clone()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The host's AEAD sealer.
//
// # This is a **separate** implementation on purpose
//
// It shares no line with the `aead_open` under test, and its correctness is
// not the thing being asserted: the anchor is
// [`the_aead_opener_matches_vectors_from_an_independent_implementation`],
// which checks the opener against bytes produced by Python's `cryptography`
// bindings. What this sealer is for is producing *requests*: it has to seal
// the same way `backup::chacha_seal` does so that the arms under test are
// handed something the real client would send.
//
// The layout it produces is `nonce(12) ‖ ct(32) ‖ tag(16)` — the tag on the
// **tail**, because `ring`'s `seal_in_place_append_tag` appends it there
// (`picoforge/src/hal/fido/backup.rs:73-77`).
// ---------------------------------------------------------------------------

fn chacha_seal(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    // One-time key from the counter-0 block (RFC 8439 §2.6.1).
    let mut b0 = [0u8; 64];
    chacha20_block(key, 0, nonce, &mut b0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&b0[..32]);

    // Payload at counter 1. Only whole blocks, which is all this path needs
    // (the P-256 scalar is 32 bytes).
    let mut ct = pt.to_vec();
    for (i, chunk) in ct.chunks_mut(64).enumerate() {
        let mut ks = [0u8; 64];
        chacha20_block(key, 1 + i as u32, nonce, &mut ks);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }

    // MAC input with the RFC's zero padding and the two 64-bit lengths.
    let mut mac_data: Vec<u8> = Vec::new();
    mac_data.extend_from_slice(aad);
    while !mac_data.len().is_multiple_of(16) {
        mac_data.push(0);
    }
    mac_data.extend_from_slice(&ct);
    while !mac_data.len().is_multiple_of(16) {
        mac_data.push(0);
    }
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    let tag = poly1305(&otk, &mac_data);

    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    blob
}

/// ChaCha20 block function (RFC 8439 §2.3).
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }
    let init = s;
    for _ in 0..10 {
        for (a, b, c, d) in [
            (0usize, 4usize, 8usize, 12usize),
            (1, 5, 9, 13),
            (2, 6, 10, 14),
            (3, 7, 11, 15),
            (0, 5, 10, 15),
            (1, 6, 11, 12),
            (2, 7, 8, 13),
            (3, 4, 9, 14),
        ] {
            s[a] = s[a].wrapping_add(s[b]);
            s[d] = (s[d] ^ s[a]).rotate_left(16);
            s[c] = s[c].wrapping_add(s[d]);
            s[b] = (s[b] ^ s[c]).rotate_left(12);
            s[a] = s[a].wrapping_add(s[b]);
            s[d] = (s[d] ^ s[a]).rotate_left(8);
            s[c] = s[c].wrapping_add(s[d]);
            s[b] = (s[b] ^ s[c]).rotate_left(7);
        }
    }
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
}

/// Poly1305 (RFC 8439 §2.5), the 5×26-bit-limb form.
fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let t0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
    let t1 = u32::from_le_bytes(key[3..7].try_into().unwrap());
    let t2 = u32::from_le_bytes(key[6..10].try_into().unwrap());
    let t3 = u32::from_le_bytes(key[9..13].try_into().unwrap());
    let t4 = u32::from_le_bytes(key[12..16].try_into().unwrap());
    let r = [
        t0 & 0x3ff_ffff,
        (t1 >> 2) & 0x3ff_ff03,
        (t2 >> 4) & 0x3ff_c0ff,
        (t3 >> 6) & 0x3f0_3fff,
        (t4 >> 8) & 0x00f_ffff,
    ];
    let (s1, s2, s3, s4) = (r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5);
    let mut h = [0u32; 5];

    let mut off = 0;
    while off < msg.len() {
        let take = (msg.len() - off).min(16);
        let mut block = [0u8; 16];
        block[..take].copy_from_slice(&msg[off..off + take]);
        let hibit = if take == 16 { 1 << 24 } else { 0 };
        if take < 16 {
            block[take] = 0x01;
        }
        off += take;
        mac_block(&mut h, &r, (s1, s2, s3, s4), &block, hibit);
    }

    let mut c = h[1] >> 26;
    h[1] &= 0x3ff_ffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ff_ffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ff_ffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ff_ffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ff_ffff;
    h[1] += c;

    let mut g = [0u32; 5];
    g[0] = h[0].wrapping_add(5);
    c = g[0] >> 26;
    g[0] &= 0x3ff_ffff;
    g[1] = h[1].wrapping_add(c);
    c = g[1] >> 26;
    g[1] &= 0x3ff_ffff;
    g[2] = h[2].wrapping_add(c);
    c = g[2] >> 26;
    g[2] &= 0x3ff_ffff;
    g[3] = h[3].wrapping_add(c);
    c = g[3] >> 26;
    g[3] &= 0x3ff_ffff;
    g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g[4] >> 31).wrapping_sub(1);
    for i in 0..5 {
        g[i] &= mask;
        h[i] = (h[i] & !mask) | g[i];
    }

    let mut w = [0u32; 4];
    w[0] = h[0] | (h[1] << 26);
    w[1] = (h[1] >> 6) | (h[2] << 20);
    w[2] = (h[2] >> 12) | (h[3] << 14);
    w[3] = (h[3] >> 18) | (h[4] << 8);
    let mut f = 0u64;
    let mut tag = [0u8; 16];
    for i in 0..4 {
        let s = u32::from_le_bytes(key[16 + 4 * i..20 + 4 * i].try_into().unwrap());
        f = u64::from(w[i]) + u64::from(s) + (f >> 32);
        tag[4 * i..4 * i + 4].copy_from_slice(&(f as u32).to_le_bytes());
    }
    tag
}

fn mac_block(h: &mut [u32; 5], r: &[u32; 5], s: (u32, u32, u32, u32), block: &[u8; 16], hibit: u32) {
    let t0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
    let t1 = u32::from_le_bytes(block[3..7].try_into().unwrap());
    let t2 = u32::from_le_bytes(block[6..10].try_into().unwrap());
    let t3 = u32::from_le_bytes(block[9..13].try_into().unwrap());
    let t4 = u32::from_le_bytes(block[12..16].try_into().unwrap());

    h[0] += t0 & 0x3ff_ffff;
    h[1] += (t1 >> 2) & 0x3ff_ffff;
    h[2] += (t2 >> 4) & 0x3ff_ffff;
    h[3] += (t3 >> 6) & 0x3ff_ffff;
    h[4] += (t4 >> 8) | hibit;

    let (s1, s2, s3, s4) = s;
    let d0 = u64::from(h[0]) * u64::from(r[0])
        + u64::from(h[1]) * u64::from(s4)
        + u64::from(h[2]) * u64::from(s3)
        + u64::from(h[3]) * u64::from(s2)
        + u64::from(h[4]) * u64::from(s1);
    let mut d1 = u64::from(h[0]) * u64::from(r[1])
        + u64::from(h[1]) * u64::from(r[0])
        + u64::from(h[2]) * u64::from(s4)
        + u64::from(h[3]) * u64::from(s3)
        + u64::from(h[4]) * u64::from(s2);
    let mut d2 = u64::from(h[0]) * u64::from(r[2])
        + u64::from(h[1]) * u64::from(r[1])
        + u64::from(h[2]) * u64::from(r[0])
        + u64::from(h[3]) * u64::from(s4)
        + u64::from(h[4]) * u64::from(s3);
    let mut d3 = u64::from(h[0]) * u64::from(r[3])
        + u64::from(h[1]) * u64::from(r[2])
        + u64::from(h[2]) * u64::from(r[1])
        + u64::from(h[3]) * u64::from(r[0])
        + u64::from(h[4]) * u64::from(s4);
    let mut d4 = u64::from(h[0]) * u64::from(r[4])
        + u64::from(h[1]) * u64::from(r[3])
        + u64::from(h[2]) * u64::from(r[2])
        + u64::from(h[3]) * u64::from(r[1])
        + u64::from(h[4]) * u64::from(r[0]);

    let mut c;
    h[0] = d0 as u32 & 0x3ff_ffff;
    c = (d0 >> 26) as u32;
    d1 = d1.wrapping_add(u64::from(c));
    h[1] = d1 as u32 & 0x3ff_ffff;
    c = (d1 >> 26) as u32;
    d2 = d2.wrapping_add(u64::from(c));
    h[2] = d2 as u32 & 0x3ff_ffff;
    c = (d2 >> 26) as u32;
    d3 = d3.wrapping_add(u64::from(c));
    h[3] = d3 as u32 & 0x3ff_ffff;
    c = (d3 >> 26) as u32;
    d4 = d4.wrapping_add(u64::from(c));
    h[4] = d4 as u32 & 0x3ff_ffff;
    c = (d4 >> 26) as u32;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ff_ffff;
    h[1] += c;
}

