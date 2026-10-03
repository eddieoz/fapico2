//! US-170 (EPIC `PICOForge-COMPAT`) — the RS-Key soft lock: `STATE` (`0x05`),
//! `UNLOCK` (`0x06`), and the `authenticatorConfig` (`0x0D`) vendor-prototype
//! pair that engages and releases the lock.
//!
//! # How this file reaches the code
//!
//! `apps/fido/src/vendor_lock.rs` is pulled in with `#[path]` and the crate
//! names it needs are re-exported at this file's root, so the module's
//! `crate::…` paths resolve here exactly as they will once
//! `pub mod vendor_lock;` lands in `lib.rs`. Wiring the module into `lib.rs`
//! and the two dispatch arms is the integrator's step; doing it from a test
//! file is what lets this suite run **before** that edit, and it is why
//! nothing in `lib.rs` had to be touched to prove the module compiles and
//! behaves.
//!
//! The re-exports are load-bearing rather than decorative: `vendor_lock.rs`
//! spells its dependencies `crate::cbor`, `crate::ctap2`, `crate::crypto`,
//! `crate::device_core` and `crate::vendor41`, and inside a `#[path]` module
//! `crate` is *this* test binary. Without the `pub use` below, every one of
//! those paths would be unresolvable and the module would not compile here —
//! which is exactly the drift a `#[path]` include can introduce, so it is
//! stated rather than left to be discovered.
//!
//! # The AEAD is pinned to an implementation outside this repository
//!
//! `vendor_lock.rs` used to contain a hand-written RFC 8439 ChaCha20-Poly1305
//! of its own; it is now [`fapico2_fido::crypto::chacha20poly1305_open_blob`]
//! over the `chacha20poly1305` crate, shared with the other two `0x41` arms.
//! Every vector in
//! [`the_chacha20_block_keystream_matches_rfc_8439`] and
//! [`aead_open_matches_vectors_from_an_independent_implementation`] was
//! produced by Python's `cryptography` bindings, **not** by this code and
//! **not** by the client. Two of them are additionally the RFC's own:
//! the keystream is RFC 8439 §2.4.2, and the reference implementation used to
//! generate the others was itself checked against the RFC 8439 §2.8.2 tag
//! (`1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91`) before it was trusted.
//!
//! Those vectors now do double duty, and the second job is the reason the
//! collapse is safe to make. The opener under test is the crate, so a vector
//! from an outside implementation is no longer just a check on *our* code — it
//! is the thing that would catch the **dependency** being wrong, a version
//! bump that changed a tag, or a build that silently stopped linking it. The
//! KAT outlived the implementation it was written for, which is the correct
//! direction for a test to fail in.
//!
//! The test-side sealer is a **separate** implementation on purpose. It shares
//! no line with the opener under test, and it is itself pinned to the same
//! vectors — so "the sealer and the opener agree" is not the property being
//! asserted. "The opener reproduces an external implementation's bytes" is.

pub use fapico2_fido::{cbor, crypto, ctap2, device_core, vendor41, CTAP2_MAX_MSG};

/// The shared `clientPin` client, for the end-to-end section only.
///
/// Section 5 needs a real `0x20` PIN token on **both** stacks, and
/// `common::PinClient` is the host stack's answer to that; re-deriving a
/// `clientPin` exchange here would be a second implementation of the one
/// sub-command sequence the host already has a fixture for, and the two
/// drifting is exactly the class of bug this file exists to catch. The device
/// half carries its own (`DeviceClient`), because the device's `clientPin` is
/// a different function in a different file.
mod common;

#[path = "../src/vendor_lock.rs"]
mod vendor_lock;

use cbor::no_heap as nh;
use cbor::Value;
use fapico2_fido::keystore::{Keystore, MemoryKeystore};
use fapico2_fido::vendor41::{TokenAuth, VendorOps};
use fapico2_fido::vendor_state::{MemoryVendorOps, VendorSession};
use fapico2_platform::secure_store::SecureStore;
use heapless::Vec as HV;
use vendor_lock::*;

// ---------------------------------------------------------------------------
// Statuses, spelled as the byte on the wire.
//
// A desktop app only ever sees these bytes, so every assertion below is about
// the wire value rather than about a `Ctap2Response` variant name.
// ---------------------------------------------------------------------------

const OK: u8 = 0x00;
const INVALID_PARAMETER: u8 = 0x02;
/// US-1528: was `0x07`, which is `Ctap2Command::Reset` — a different layer's
/// constant, and the collision is why the two tables were easy to confuse.
/// `CtapError.ERR.LOCK_REQUIRED` and `CTAP1_ERR_LOCK_REQUIRED 0x0a` agree.
const LOCK_REQUIRED: u8 = 0x0A;
const INVALID_CBOR: u8 = 0x12;
const MISSING_PARAMETER: u8 = 0x14;
const OPERATION_DENIED: u8 = 0x27;
const PIN_AUTH_INVALID: u8 = 0x33;
const PIN_AUTH_BLOCKED: u8 = 0x34;
const PUAT_REQUIRED: u8 = 0x36;
/// **Load-bearing.** `CTAP2_ERR_INTEGRITY_FAILURE` officially, repurposed by
/// RS-Key as "device is not locked" (`picoforge/src/hal/fido/mod.rs:1828-1830`).
const NOT_LOCKED: u8 = 0x3D;
const INVALID_SUBCOMMAND: u8 = 0x3E;
const UNAUTHORIZED_PERMISSION: u8 = 0x40;

/// `AUTHENTICATOR_CONFIG`, the permission `lock_enable` / `lock_disable` mint
/// (`picoforge/src/hal/fido/mod.rs:1846`, `:1871`).
const PERM_ACFG: u8 = 0x20;

/// The reply buffer, the same `CTAP2_MAX_MSG` the `0x41` path uses.
type Reply = HV<u8, { fapico2_fido::CTAP2_MAX_MSG }>;

const PIN_TOKEN: [u8; 32] = [0x11; 32];

// ---------------------------------------------------------------------------
// The `VendorOps` seam.
// ---------------------------------------------------------------------------

/// A host [`VendorOps`] over a real [`MemoryKeystore`].
///
/// The real type, not a mock: "the lock record round-trips through the
/// keystore" and "`unlocked` did **not**" are claims about the state layer, and
/// a mock would make them claims about the mock. `MemoryVendorOps` is the host
/// half of the pair `vendor_state` ships; the device half
/// (`KeystoreVendorOps`) is exercised by `tests/vendor41_state.rs` and is the
/// same trait, so an arm written against `&mut dyn VendorOps` cannot tell them
/// apart.
fn with_ops<R>(
    ks: &mut MemoryKeystore,
    session: &mut VendorSession,
    f: impl FnOnce(&mut dyn fapico2_fido::vendor_backup::BackupOps) -> R,
) -> R {
    let mut ops = MemoryVendorOps::new(ks, session);
    f(&mut ops)
}

/// The `0x20` token, wrapped the way the dispatch arms wrap it.
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

// ---------------------------------------------------------------------------
// The host side of the MSE channel, derived for real.
//
// The client runs `mse_handshake` (`picoforge/src/hal/fido/mod.rs:1684-1734`)
// and derives `HKDF-SHA256(salt = b"", ikm = z, info = aad)` with `aad` its own
// uncompressed point. Reproducing that here — rather than reading the channel
// key back out of the device with `mse_channel` — is what makes the test a
// test of the protocol rather than of a shared secret. It also means a device
// that derived the wrong key, or bound the wrong AAD, fails here.
// ---------------------------------------------------------------------------

/// The host's half of one MSE session: the channel key and the AAD.
struct HostChannel {
    key: [u8; 32],
    aad: [u8; 65],
}

impl HostChannel {
    /// Seal a 32-byte lock key the way `wrap_secret` does
    /// (`picoforge/src/hal/fido/mod.rs:1799-1806`): `nonce(12) ‖ ct(32) ‖ tag(16)`.
    fn wrap(&self, secret: &[u8; 32], nonce: [u8; 12]) -> Vec<u8> {
        let blob = chacha_seal(&self.key, &nonce, secret, &self.aad);
        assert_eq!(blob.len(), LOCK_BLOB_LEN, "the client always produces 60 bytes");
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
    let mut dev = vendor41::MsePoint::default();
    ops.mse_establish(hx, hy, &mut dev).expect("a P-256 handshake cannot fail here");

    // The device's own uncompressed point is the AAD, and travels to the host
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
// ---------------------------------------------------------------------------

/// `backup_status`'s request: `{1: 5}` and **nothing else**.
///
/// `rs_key_vendor(RSKEY_VENDOR_STATE, None, None)` (`mod.rs:1740-1742`) omits
/// key 2 *and* keys 3/4, so a request carrying a `subCommandParams` is not one
/// this client produces.
fn state_request() -> Vec<u8> {
    vec![0xA1, 0x01, SUB_STATE]
}

/// `lock_unlock`'s request: `{1: 6, 2: {1: <blob>}}`, no MAC, no token
/// (`mod.rs:1820-1826`).
fn unlock_request(blob: &[u8]) -> Vec<u8> {
    let mut params: HV<u8, 96> = HV::new();
    nh::push_map_header(&mut params, 1).unwrap();
    nh::push_uint(&mut params, UNLOCK_PARAM_BLOB).unwrap();
    nh::push_bstr(&mut params, blob).unwrap();
    rskey(SUB_UNLOCK, &params)
}

/// `UNLOCK` with the `0x41` channel's own MAC attached, under an explicit
/// token.
///
/// The real client sends `UNLOCK` **bare** (`mod.rs:1826`) — no key 3, no key
/// 4 — and this firmware is built for exactly that. An end-to-end test cannot
/// reproduce it, though: `vendor41::verify_mac` answers `PuatRequired` on a
/// missing param, and the app only reaches that check with a token when one is
/// **live** — and neither stack exposes a way to forget the one
/// `getPinUvAuthToken` just minted (`pin_token` is private on both, and
/// neither has a "drop my token" command). So the only request shape an
/// end-to-end test can produce is the *other* legal one: a token attached and
/// a MAC over it.
///
/// That is a documented path, not a workaround. `vendor_lock::unlock`'s doc
/// says a token that **is** attached "is still verified, against
/// `vendor41::verify_mac` and `vendor41::authorize` — that is exactly
/// `Requirement::TokenOptional`'s contract for this sub-command". So driving
/// it still exercises the part under test — the AEAD open, the constant-time
/// key comparison and the `set_unlocked_this_power_cycle` — and additionally
/// proves the optional-token arm is verified when present.
fn unlock_request_with_token(blob: &[u8], token: &[u8; 32]) -> Vec<u8> {
    let mut params: HV<u8, 96> = HV::new();
    nh::push_map_header(&mut params, 1).unwrap();
    nh::push_uint(&mut params, UNLOCK_PARAM_BLOB).unwrap();
    nh::push_bstr(&mut params, blob).unwrap();
    // `FF×32 ‖ 0x41 ‖ sub ‖ cbor(params)` — `vendor41::verify_mac`'s message.
    let mut msg = vec![0xFFu8; 32];
    msg.push(0x41);
    msg.push(SUB_UNLOCK);
    msg.extend_from_slice(&params);
    let mac: [u8; 16] = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(token).unwrap();
        m.update(&msg);
        <[u8; 16]>::try_from(&m.finalize().into_bytes()[..16]).unwrap()
    };
    let mut b: HV<u8, 192> = HV::new();
    nh::push_map_header(&mut b, 4).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, SUB_UNLOCK as u64).unwrap();
    nh::push_uint(&mut b, 2).unwrap();
    b.extend_from_slice(&params).unwrap();
    nh::push_uint(&mut b, 3).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, 4).unwrap();
    nh::push_bstr(&mut b, &mac).unwrap();
    b.to_vec()
}

/// `{1: sub, 2: params}` — the `0x41` request body, in the key order
/// PicoForge's canonical CBOR produces.
fn rskey(sub: u8, params: &[u8]) -> Vec<u8> {
    let mut b: HV<u8, 128> = HV::new();
    nh::push_map_header(&mut b, 2).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, sub as u64).unwrap();
    nh::push_uint(&mut b, 2).unwrap();
    b.extend_from_slice(params).unwrap();
    b.to_vec()
}

/// `authconfig_vendor`'s `subCommandParams`: `{1: <vendor id>, 2: <blob>}`.
///
/// Key `2` — not `3` — because the payload is a `Value::Bytes` and the key is
/// chosen by payload **type** (`ops.rs:1618-1627`). The client's enum calls
/// this slot a COSE key; following the enum name would read key `3` and refuse
/// every engage PicoForge performs.
fn engage_sub_params(id: u64, blob: &[u8]) -> Vec<u8> {
    let mut p: HV<u8, 128> = HV::new();
    nh::push_map_header(&mut p, 2).unwrap();
    nh::push_uint(&mut p, VENDOR_SUB_PARAM_ID).unwrap();
    nh::push_uint(&mut p, id).unwrap();
    nh::push_uint(&mut p, VENDOR_SUB_PARAM_BSTR).unwrap();
    nh::push_bstr(&mut p, blob).unwrap();
    p.to_vec()
}

/// The same map with the **byte string's head written non-minimally**:
/// `0x59 00 3C` (2-byte length) where a canonical serialiser emits `0x58 3C`.
///
/// Legal CBOR, decodes to the same value, and — the point — produces different
/// bytes, so a MAC over one form does not verify against the other. This is the
/// only way to test "the device verified the wire span" without a hand-written
/// CBOR encodder in the test: the two forms are the *same map*.
fn engage_sub_params_non_canonical(id: u64, blob: &[u8]) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.push(0xA2);
    push_uint_to_vec(&mut p, VENDOR_SUB_PARAM_ID);
    push_uint_to_vec(&mut p, id);
    p.push(0x02);
    assert!(blob.len() < 256);
    p.push(0x59); // major 2, 2-byte length argument — NOT minimal for a 60-byte string
    p.extend_from_slice(&(blob.len() as u16).to_be_bytes());
    p.extend_from_slice(blob);
    p
}

/// `lock_disable`'s `subCommandParams`: `{1: <id>}` and **no payload**
/// (`mod.rs:1872-1873` passes `None`, so `ops.rs:1619-1627` inserts no key).
fn release_sub_params(id: u64) -> Vec<u8> {
    let mut p: HV<u8, 32> = HV::new();
    nh::push_map_header(&mut p, 1).unwrap();
    nh::push_uint(&mut p, VENDOR_SUB_PARAM_ID).unwrap();
    nh::push_uint(&mut p, id).unwrap();
    p.to_vec()
}

/// The `0x0D` request body `{1: 0xFF, 2: <sub params>, 3: 1, 4: <mac>}`
/// (`ops.rs:1636-1652`).
///
/// `mac` is a parameter so a test can put the **wrong** one in: the signature
/// `picoforge_sign` computes is over `sub_params` as given, and the point of
/// the byte-span test is to MAC one serialisation and send another.
fn config_vendor_request(sub_params: &[u8], mac: [u8; 16]) -> Vec<u8> {
    let mut b: HV<u8, 256> = HV::new();
    nh::push_map_header(&mut b, 4).unwrap();
    nh::push_uint(&mut b, CONFIG_PARAM_SUB_COMMAND).unwrap();
    nh::push_uint(&mut b, CONFIG_SUB_VENDOR_PROTOTYPE as u64).unwrap();
    nh::push_uint(&mut b, CONFIG_PARAM_SUB_COMMAND_PARAMS).unwrap();
    b.extend_from_slice(sub_params).unwrap();
    nh::push_uint(&mut b, CONFIG_PARAM_PIN_PROTOCOL).unwrap();
    nh::push_uint(&mut b, 1).unwrap();
    nh::push_uint(&mut b, CONFIG_PARAM_PIN_PARAM).unwrap();
    nh::push_bstr(&mut b, &mac).unwrap();
    b.to_vec()
}

/// The `0x0D` MAC, byte-exact: `HMAC-SHA256(token, FF×32 ‖ 0x0D ‖ 0xFF ‖
/// subCommandParams)[0..16]` (`ops.rs:1002-1004`, driven from `ops.rs:1632`).
///
/// Computed with the `hmac`/`sha2` crates directly rather than through
/// `fapico2_fido::crypto`, so it shares no code with the verifier — a shared
/// HMAC helper would make this a test of the implementation against itself.
fn picoforge_config_mac(token: &[u8; 32], sub_params: &[u8]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut msg = vec![0xFFu8; 32];
    msg.push(0x0D);
    msg.push(0xFF);
    msg.extend_from_slice(sub_params);
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(token).unwrap();
    m.update(&msg);
    let full = m.finalize().into_bytes();
    <[u8; 16]>::try_from(&full[..16]).unwrap()
}

/// `mac_over` is what the client signed; `sent` is what goes on the wire.
fn engage_request(sent: &[u8], mac_over: &[u8]) -> Vec<u8> {
    config_vendor_request(sent, picoforge_config_mac(&PIN_TOKEN, mac_over))
}

fn release_request(sent: &[u8], mac_over: &[u8]) -> Vec<u8> {
    config_vendor_request(sent, picoforge_config_mac(&PIN_TOKEN, mac_over))
}

// ---------------------------------------------------------------------------
// Small `no_heap::push_uint` variant that writes into a `Vec`.
//
// The crate's takes a `HeaplessVec`; the one non-canonical request below
// assembles into a `Vec` and must not silently become a 128-byte fixed buffer
// the test then truncates.
// ---------------------------------------------------------------------------

mod push {
    use fapico2_fido::cbor::no_heap as nh;
    use heapless::Vec as HV;

    /// Append a minimally-encoded unsigned integer to `out`.
    pub fn push_uint_to_vec(out: &mut Vec<u8>, v: u64) {
        let mut tmp: HV<u8, 9> = HV::new();
        nh::push_uint(&mut tmp, v).unwrap();
        out.extend_from_slice(&tmp);
    }
}
use push::push_uint_to_vec;

/// The decoded `STATE` map, as the four keys the client reads.
struct StateFlags {
    sealed: bool,
    has_seed: bool,
    locked: bool,
    unlocked: bool,
}

/// Read `STATE` and decode it the way `m_bool` does — but **strictly**,
/// refusing a non-`bool`.
///
/// `m_bool` (`picoforge/src/hal/fido/mod.rs:1558-1565`) coerces a non-zero
/// integer and maps *everything else, including a missing key*, to `false`.
/// Reproducing that leniency here would let every test below pass against an
/// encoding the client reads as a lie, so this decoder is the opposite: it is
/// the assertion.
fn read_state(ops: &mut dyn VendorOps, sealed: bool) -> (u8, StateFlags) {
    let mut out = Reply::new();
    let outcome = state(ops, sealed, &mut out);
    let status = outcome.status.code();
    if status != OK {
        return (status, StateFlags { sealed: false, has_seed: false, locked: false, unlocked: false });
    }
    (status, parse_state_body(&out))
}

/// The strict decode half of [`read_state`], split out so the end-to-end
/// section can read a `STATE` body that came off the **`0x41` wire** rather
/// than out of a `VendorOps` it owns.
///
/// One decoder, not two: the whole point of the strictness is that it *is* the
/// assertion, and a second decoder for the device twin would be a second place
/// for the strictness to be lost — and a `0`/`1` integer would read as `true`
/// in one of them and be pinned by the other.
fn parse_state_body(body: &[u8]) -> StateFlags {
    let (v, used) = cbor::decode(body).expect("STATE must be a CBOR map");
    assert_eq!(used, body.len(), "trailing bytes after the STATE map");
    let pairs = match v {
        Value::M(m) => m,
        other => panic!("STATE is not a map: {other:?}"),
    };
    assert_eq!(pairs.len(), 4, "STATE must carry exactly four keys: {pairs:?}");
    let mut f = StateFlags { sealed: false, has_seed: false, locked: false, unlocked: false };
    for (k, val) in pairs {
        let key = match k {
            Value::U(u) => u,
            other => panic!("STATE key is not an unsigned integer: {other:?}"),
        };
        let b = match val {
            Value::Bool(b) => b,
            other => panic!("STATE key {key} is not a CBOR bool: {other:?}"),
        };
        match key {
            1 => f.sealed = b,
            2 => f.has_seed = b,
            3 => f.locked = b,
            4 => f.unlocked = b,
            other => panic!("STATE has an unexpected key {other}"),
        }
    }
    f
}

// ---------------------------------------------------------------------------
// 1. The AEAD, against implementations outside this repository.
// ---------------------------------------------------------------------------

/// RFC 8439 §2.4.2's keystream: key `00..1f`, nonce
/// `00:00:00:00:00:00:00:4a:00:00:00:00`, counter 1, all-zero plaintext — so
/// the output **is** the block function's.
///
/// This is a published RFC vector rather than one generated here, and it
/// exercises the block function the AEAD needs at counters 0 (one-time key)
/// and 1 (payload).
#[test]
fn the_chacha20_block_keystream_matches_rfc_8439() {
    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const NONCE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    const WANT: [u8; 64] = [
        0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1,
        0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63, 0x1d, 0xed,
        0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2,
        0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78,
        0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92,
        0xb5, 0x79, 0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34,
        0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd,
        0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7,
    ];
    let mut ks = [0u8; 64];
    chacha20_keystream(&KEY, 1, &NONCE, &mut ks);
    assert_eq!(ks, WANT, "the ChaCha20 block function is not RFC 8439");
}

/// The same §2.4.2 keystream, now reached through the **crate** the firmware
/// links, rather than through a block function of our own.
///
/// This is the assertion that survived the collapse intact and changed
/// meaning: `vendor_lock` no longer has a `chacha20_block` to call, because
/// the block function is inside `chacha20poly1305` now. It is still worth
/// pinning, because ChaCha20 is a stream cipher — encrypting 64 zero bytes
/// *is* the counter-1 keystream — so §2.4.2 is checkable through the shipped
/// AEAD with no new dependency. If a version bump of `chacha20poly1305` ever
/// changed the keystream, or the message counter moved off 1, this is what
/// says so, and it says it in the RFC's own bytes rather than against
/// something this repository wrote.
#[test]
fn the_crates_keystream_matches_rfc_8439_through_the_shipped_aead() {
    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const NONCE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    const WANT: [u8; 64] = [
        0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1,
        0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63, 0x1d, 0xed,
        0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2,
        0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78,
        0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92,
        0xb5, 0x79, 0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34,
        0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd,
        0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7,
    ];
    // 64 bytes of plaintext plus the 16-byte tag.
    let mut out: HV<u8, 128> = HV::new();
    fapico2_fido::crypto::chacha20poly1305_seal(&KEY, &NONCE, b"", &[0u8; 64], &mut out)
        .expect("64 zero bytes plus a tag fit a 128-byte buffer");
    assert_eq!(
        &out[..64],
        &WANT[..],
        "the chacha20poly1305 crate's keystream is not RFC 8439 §2.4.2"
    );
    assert_eq!(out.len(), 80, "and the framing is still ct ‖ tag(16)");
}

/// `aead_open` reproduces an implementation this repository did not write.
///
/// Two vectors, because the two together cover the padding branches the real
/// path takes: a 65-byte AAD (the uncompressed P-256 point — pad 15) with a
/// 32-byte ciphertext (pad 0), and a 5-byte AAD (pad 11) with the same
/// ciphertext length. Both are `nonce(12) ‖ ct(32) ‖ tag(16)`, i.e. exactly
/// the 60-byte form `wrap_secret` produces.
#[test]
fn aead_open_matches_vectors_from_an_independent_implementation() {
    // key 5a17…, nonce a1b2…, aad = 0x04 ‖ 00..3f (65 bytes), pt = 03 0a 11 …
    const KEY: [u8; 32] = [
        0x5a, 0x17, 0x13, 0x91, 0x2c, 0x1c, 0x3a, 0x0d, 0x1f, 0x0e, 0x7c, 0x8b, 0x9a, 0x4d, 0x5e,
        0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09, 0x1a, 0x2b, 0x3c, 0x4d,
        0x5e, 0x6f,
    ];
    const NONCE: [u8; 12] =
        [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c];
    const PT: [u8; 32] = [
        0x03, 0x0a, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34,
        0x3b, 0x42, 0x49, 0x50, 0x57, 0x5e, 0x65, 0x6c,
        0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4,
        0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc,
    ];
    const TAG: [u8; 16] = [
        0x2b, 0x72, 0xb2, 0x5a, 0x67, 0x13, 0x4a, 0x13,
        0x0d, 0xed, 0x2e, 0xfd, 0xd3, 0x68, 0x1e, 0x7b,
    ];
    const CT: [u8; 32] = [
        0x96, 0xa6, 0x4e, 0xe2, 0x41, 0x72, 0xfc, 0x7e,
        0x92, 0x2c, 0x52, 0x0d, 0x14, 0x97, 0x03, 0x68,
        0x28, 0xe1, 0xf1, 0x2f, 0xb5, 0x80, 0x37, 0x54,
        0x0c, 0xf6, 0xf8, 0xd7, 0x62, 0xa3, 0xfd, 0x84,
    ];

    // 65-byte AAD, the real protocol's.
    let mut aad = [0u8; 65];
    aad[0] = 0x04;
    for (i, b) in aad[1..].iter_mut().enumerate() {
        *b = i as u8;
    }
    let blob: Vec<u8> = NONCE.iter().chain(CT.iter()).chain(TAG.iter()).copied().collect();
    let mut out = [0u8; 32];
    aead_open(&KEY, &aad, &blob, &mut out).expect("the vector must open");
    assert_eq!(out, PT);

    // 5-byte AAD, so the other padding length is covered too.
    const KEY2: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
        0xfe, 0x0f,
    ];
    const NONCE2: [u8; 12] = [0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04];
    const PT2: [u8; 32] = [
        0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
        0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
        0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
        0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
    ];
    const TAG2: [u8; 16] = [
        0xe7, 0x22, 0xdd, 0xe3, 0x91, 0x13, 0xd3, 0x42,
        0xf9, 0x14, 0x98, 0x1f, 0xd1, 0xf4, 0xca, 0x27,
    ];
    const CT2: [u8; 32] = [
        0xcc, 0xcb, 0x0d, 0x6a, 0xf0, 0xf5, 0xb4, 0xea,
        0xef, 0xf8, 0xad, 0x8d, 0x12, 0xda, 0x08, 0x03,
        0xe2, 0x30, 0xf8, 0x7c, 0x87, 0x2a, 0x87, 0xfe,
        0x98, 0x69, 0x25, 0x69, 0x4a, 0xf3, 0xd2, 0xbe,
    ];
    let blob2: Vec<u8> = NONCE2.iter().chain(CT2.iter()).chain(TAG2.iter()).copied().collect();
    aead_open(&KEY2, b"pico!", &blob2, &mut out).expect("the 5-byte-AAD vector must open");
    assert_eq!(out, PT2);

    // And the negative directions, because an opener that accepts everything is
    // worse than one that opens nothing.
    let mut bad = blob.clone();
    bad[20] ^= 0x01; // one flipped ciphertext bit
    assert!(aead_open(&KEY, &aad, &bad, &mut out).is_err(), "a tampered ct must not open");
    let mut bad = blob.clone();
    let n = bad.len();
    bad[n - 1] ^= 0x01; // one flipped tag bit
    assert!(aead_open(&KEY, &aad, &bad, &mut out).is_err(), "a tampered tag must not open");
    let mut bad_aad = aad;
    bad_aad[64] ^= 0x01;
    assert!(aead_open(&KEY, &bad_aad, &blob, &mut out).is_err(), "a changed AAD must not open");
    let mut bad_key = KEY;
    bad_key[0] ^= 0x01;
    assert!(aead_open(&bad_key, &aad, &blob, &mut out).is_err(), "a changed key must not open");
    assert!(aead_open(&KEY, &aad, &blob[..40], &mut out).is_err(), "a truncated blob must not open");
    assert!(aead_open(&KEY, &aad, &blob[..BLOB_MIN - 1], &mut out).is_err());
}

/// A failed open leaves `out` holding **no** attacker-chosen bytes.
///
/// This is a separate test from the negatives above, because those only assert
/// the *status*; this one asserts the *state of the caller's buffer*, which is
/// the property that makes "fails closed" mean something. A caller that logs
/// `out`, reuses it, or branches on it after ignoring the `Err` must not be
/// able to observe a decrypted attacker-supplied buffer.
///
/// The implementation detail that makes this true is worth naming: the blob is
/// `nonce ‖ ct ‖ tag`, so the ciphertext has to be copied into `out` *before*
/// the keystream is XORed into it. The ciphertext is therefore briefly in the
/// output buffer even on the failure path — so the seam clears it rather than
/// leaving the caller's buffer full of something the peer chose. Without that
/// clear, a tamper-and-observe caller would read the modified ciphertext back
/// out of a buffer the API had just refused to fill.
#[test]
fn a_failed_open_leaves_the_output_buffer_cleared() {
    const KEY: [u8; 32] = [0x5a; 32];
    let nonce = [0xa1; 12];
    let pt = [0x03u8; 32];
    let mut aad = [0u8; 65];
    aad[0] = 0x04;

    // A blob that is genuinely valid, to prove the setup is right.
    let good = chacha_seal(&KEY, &nonce, &pt, &aad);
    let mut out = [0u8; 32];
    aead_open(&KEY, &aad, &good, &mut out).expect("the sealed blob must open");
    assert_eq!(out, pt, "precondition: the good blob opens to the plaintext");

    // Same blob, one ciphertext bit flipped: must fail, and must leave the
    // buffer with nothing in it.
    let mut bad = good.clone();
    bad[20] ^= 0x01;
    out = [0xAB; 32]; // a recognisable pre-fill, so "untouched" is provable
    assert!(aead_open(&KEY, &aad, &bad, &mut out).is_err(), "a tampered ct must not open");
    assert_eq!(
        out,
        [0u8; 32],
        "a failed open must leave no attacker-chosen bytes in the output buffer"
    );

    // And the same for a failed *seal* into a buffer that had prior contents:
    // the sealer is documented to clear, so a caller cannot read a stale
    // plaintext out of a reused scratch buffer.
    let mut scratch: HV<u8, 64> = HV::new();
    scratch.extend_from_slice(&[0xCD; 60]).unwrap();
    fapico2_fido::crypto::chacha20poly1305_seal(&KEY, &nonce, &aad, &pt, &mut scratch)
        .expect("32 bytes plus a tag fit a 64-byte buffer");
    assert_eq!(scratch.len(), 48, "the sealer clears before it writes");
    assert_ne!(&scratch[..], &[0xCD; 48][..], "so no stale bytes survive");
}

// ---------------------------------------------------------------------------
// 2. `STATE`.
// ---------------------------------------------------------------------------

/// The EPIC's named test (`EPIC-fapico2-picoforge-compatibility.md:907`), kept
/// as a contract: the four keys, in the client's order, with the meanings the
/// desktop app reads them for.
#[test]
fn state_reports_seed_and_lock_flags() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();

    // Fresh device: no seed, no lock, not unlocked.
    with_ops(&mut ks, &mut session, |ops| {
        let mut out = Reply::new();
        assert_eq!(state(ops, false, &mut out).status.code(), OK);
        let (v, used) = cbor::decode(&out).unwrap();
        assert_eq!(used, out.len());
        let pairs = match v {
            Value::M(m) => m,
            other => panic!("not a map: {other:?}"),
        };
        let keys: Vec<u64> = pairs
            .iter()
            .map(|(k, _)| match k {
                Value::U(u) => *u,
                other => panic!("key is not a uint: {other:?}"),
            })
            .collect();
        assert_eq!(keys, vec![1, 2, 3, 4], "STATE must carry keys 1..4, ascending");
    });

    // A seed appears.
    with_ops(&mut ks, &mut session, |ops| {
        ops.set_master_seed([0x5A; 32]).unwrap();
    });
    // A lock, engaged with a known key.
    with_ops(&mut ks, &mut session, |ops| {
        ops.set_soft_lock(vendor41::SoftLock::new(&[0x33; 32]).unwrap()).unwrap();
    });
    // And the unlock flag, which is session state.
    with_ops(&mut ks, &mut session, |ops| {
        ops.set_unlocked_this_power_cycle(true);
    });

    with_ops(&mut ks, &mut session, |ops| {
        let (status, f) = read_state(ops, true);
        assert_eq!(status, OK);
        assert_eq!(
            (f.sealed, f.has_seed, f.locked, f.unlocked),
            (true, true, true, true),
            "every flag must be reported, and `sealed` is the caller's to supply"
        );
    });
}

/// All four keys, on every response, encoded as CBOR **bools**.
///
/// The client's `m_bool` (`picoforge/src/hal/fido/mod.rs:1558-1565`) maps a
/// non-`Bool`, a non-`Integer`, **and a missing key** to `false`. For `locked`
/// that is a device reporting itself unlocked, and for `sealed` a device that
/// will refuse an export while claiming the window is open.
///
/// A `0`/`1` integer *would* work — the same function accepts a non-zero
/// `Integer` — which is precisely the hazard: correct today, no failure to
/// debug if a later refactor swaps it for a text string. So the bytes are
/// asserted, not just the decoded value.
#[test]
fn state_emits_every_key_as_a_cbor_bool_not_a_uint() {
    // All sixteen combinations of the four flags, from a **fresh keystore
    // each time** (`set_master_seed` has no inverse on the trait, so a single
    // keystore cannot walk the space). A key that were emitted conditionally
    // would be caught whichever way it was conditional.
    for bits in 0u8..16 {
        let mut ks = MemoryKeystore::new();
        let mut session = VendorSession::default();
        let sealed = bits & 0x01 != 0;
        let has_seed = bits & 0x02 != 0;
        let locked = bits & 0x04 != 0;
        let unlocked = bits & 0x08 != 0;
        with_ops(&mut ks, &mut session, |ops| {
            if has_seed {
                ops.set_master_seed([0x11; 32]).unwrap();
            }
            if locked {
                ops.set_soft_lock(vendor41::SoftLock::new(&[0x22; 32]).unwrap()).unwrap();
            }
            if unlocked {
                ops.set_unlocked_this_power_cycle(true);
            }
            let mut out = Reply::new();
            assert_eq!(state(ops, sealed, &mut out).status.code(), OK, "bits {bits:#04b}");

            let body = out.clone();
            // `A4` — a four-pair map, always, whatever the flags are.
            assert_eq!(body[0], 0xA4, "bits {bits:#04b}: STATE must always be a 4-pair map");
            assert_eq!(body.len(), 9, "bits {bits:#04b}: A4 + 4×(key, bool)");
            let want = [sealed, has_seed, locked, unlocked];
            for (i, key) in [1u8, 2, 3, 4].iter().enumerate() {
                assert_eq!(body[1 + i * 2], *key, "bits {bits:#04b}: pair {i} key");
                let vb = body[2 + i * 2];
                assert_eq!(vb, if want[i] { 0xF5 } else { 0xF4 }, "bits {bits:#04b}: key {key}");
                assert!(
                    vb == 0xF4 || vb == 0xF5,
                    "bits {bits:#04b}: key {key} encoded {vb:#04x}; the client's m_bool reads \
                     anything but Bool/non-zero-Integer as false"
                );
            }
        });
    }
}

/// A fresh device: `has_seed = false`, `locked = false`, `unlocked = false`.
#[test]
fn state_on_a_fresh_device_reports_no_seed_and_no_lock() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    with_ops(&mut ks, &mut session, |ops| {
        let (status, f) = read_state(ops, false);
        assert_eq!(status, OK);
        assert!(!f.has_seed, "a device with no seed must say so");
        assert!(!f.locked, "a device with no lock key must not claim to be locked");
        assert!(!f.unlocked, "nothing is unlocked before an UNLOCK");
    });
}

/// After `set_master_seed`: `has_seed = true`. `locked` is untouched by it.
#[test]
fn state_after_a_master_seed_reports_has_seed() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    with_ops(&mut ks, &mut session, |ops| ops.set_master_seed([0x7E; 32]).unwrap());
    with_ops(&mut ks, &mut session, |ops| {
        let (status, f) = read_state(ops, false);
        assert_eq!(status, OK);
        assert!(f.has_seed);
        assert!(!f.locked, "writing a seed does not engage a lock");
        assert!(!f.unlocked);
    });
}

/// After engaging: `locked = true`. After `UNLOCK`: `unlocked = true`.
#[test]
fn state_after_engaging_then_unlocking_reports_locked_then_unlocked() {
    let (mut ks, mut session) = engage_and_mse();
    let ch = with_ops(&mut ks, &mut session, mse_host);
    let key = [0x3C; 32];
    let blob = ch.wrap(&key, [0x11; 12]);
    let sub = engage_sub_params(AUT_ENABLE, &blob);
    let req = engage_request(&sub, &sub);

    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &req, Some(acfg_token())).status.code(), OK);
    });
    with_ops(&mut ks, &mut session, |ops| {
        let (status, f) = read_state(ops, false);
        assert_eq!(status, OK);
        assert!(f.locked, "engaging must make STATE report locked");
        assert!(!f.unlocked, "engaging must not unlock anything");
    });

    // A **fresh** MSE handshake, as `lock_unlock` does (`mod.rs:1806`).
    let ch2 = with_ops(&mut ks, &mut session, mse_host);
    let blob2 = ch2.wrap(&key, [0x22; 12]);
    let ureq = unlock_request(&blob2);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(unlock(ops, &ureq, None).status.code(), OK);
    });
    with_ops(&mut ks, &mut session, |ops| {
        let (status, f) = read_state(ops, false);
        assert_eq!(status, OK);
        assert!(f.locked, "unlocking does not disengage the lock");
        assert!(f.unlocked);
    });
}

/// `unlocked` is per-power-cycle, not durable.
///
/// The second `VendorSession` is the model of a power cycle on this firmware:
/// `VendorSession` is the volatile half of the state, `clear()`ed wherever the
/// firmware already simulates a reset for a new HID client
/// (`vendor_state::VendorSession::clear`), and the *same* `MemoryKeystore` is
/// behind both — so the lock and the seed demonstrably survived while the
/// unlock did not.
#[test]
fn unlocked_is_false_in_a_fresh_session_over_the_same_store() {
    let (mut ks, mut session) = engage_and_mse();
    let ch = with_ops(&mut ks, &mut session, mse_host);
    let key = [0x3C; 32];
    let blob = ch.wrap(&key, [0x11; 12]);
    let sub = engage_sub_params(AUT_ENABLE, &blob);
    let req = engage_request(&sub, &sub);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &req, Some(acfg_token())).status.code(), OK);
    });
    let ch2 = with_ops(&mut ks, &mut session, mse_host);
    let ureq = unlock_request(&ch2.wrap(&key, [0x33; 12]));
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(unlock(ops, &ureq, None).status.code(), OK);
        assert!(ops.unlocked_this_power_cycle());
    });

    // --- the power cycle: a new volatile session over the same store ---
    let mut session2 = VendorSession::default();
    with_ops(&mut ks, &mut session2, |ops| {
        assert!(!ops.unlocked_this_power_cycle(), "a fresh session is not unlocked");
        let (status, f) = read_state(ops, false);
        assert_eq!(status, OK);
        assert!(!f.unlocked, "STATE must report `unlocked: false` after a power cycle");
        assert!(f.locked, "…while the lock itself is durable and still engaged");
    });

    // The old session is untouched by any of this: a power cycle is a *new*
    // session, not a mutation of the old one, and the flag is per-session
    // volatile state rather than something the store rewinds.
    let _ = session2;
}

// ---------------------------------------------------------------------------
// 3. `UNLOCK`.
// ---------------------------------------------------------------------------

/// `UNLOCK` on a device that is not locked answers **exactly `0x3D`**.
///
/// `0x3D` is `CTAP2_ERR_INTEGRITY_FAILURE` officially and RS-Key's "device is
/// not locked" in practice (`mod.rs:1828-1830`). `lock_disable` sends `UNLOCK`
/// before every release and tolerates **only** `0x00` and `0x3D`
/// (`mod.rs:1862-1865`); `lock_unlock` maps it to `"device is not locked"`
/// rather than to the wrong-key message. Any other byte here aborts the
/// release with `"unlock (wrong key?) failed: status 0x.."`.
#[test]
fn unlock_on_a_not_locked_device_answers_exactly_3d() {
    let mut ks = MemoryKeystore::new();
    let mut session = VendorSession::default();
    // A perfectly-formed request with a perfectly-good blob: the **only**
    // reason the answer can be anything is that no lock is engaged, and the
    // only acceptable answer is `0x3D`.
    with_ops(&mut ks, &mut session, |ops| {
        let ch = mse_host(ops);
        let req = unlock_request(&ch.wrap(&[0x01; 32], [0x44; 12]));
        let outcome = unlock(ops, &req, None);
        assert_eq!(outcome.status.code(), NOT_LOCKED, "must be exactly 0x3D");
        assert!(!outcome.pin_auth_failure, "0x3D is not a PIN-auth failure");
        assert!(!ops.unlocked_this_power_cycle());
    });

    // And it is `0x3D` even with **no MSE session at all** — the "not locked"
    // answer must not be reachable-around by the channel check, because a
    // device that answered `0x02` here would break "release a lock" for a
    // device that never had one.
    let mut ks2 = MemoryKeystore::new();
    let mut session2 = VendorSession::default();
    with_ops(&mut ks2, &mut session2, |ops| {
        let outcome = unlock(ops, &unlock_request(&[0x00; 60]), None);
        assert_eq!(outcome.status.code(), NOT_LOCKED);
    });

    // A malformed request is still a malformed request: `0x3D` is a statement
    // about the lock, not a catch-all.
    let mut ks3 = MemoryKeystore::new();
    let mut session3 = VendorSession::default();
    with_ops(&mut ks3, &mut session3, |ops| {
        assert_eq!(unlock(ops, &[0xFF, 0xFF], None).status.code(), INVALID_CBOR);
        // `{1: 6, 2: {}}` — no key 1 in the params.
        let mut p: HV<u8, 8> = HV::new();
        nh::push_map_header(&mut p, 0).unwrap();
        assert_eq!(
            unlock(ops, &rskey(SUB_UNLOCK, &p), None).status.code(),
            MISSING_PARAMETER
        );
    });
}

/// A wrong key fails closed, does **not** set the flag, and — critically — does
/// not answer `0x3D`.
///
/// A wrong key that answered `0x3D` would surface on the standalone unlock
/// path as `"device is not locked"` (`mod.rs:1828-1830`): telling a user who
/// typed the **correct** phrase that the device is unlocked when it is not.
#[test]
fn unlock_with_the_wrong_key_fails_closed_and_leaves_the_flag_down() {
    let (mut ks, mut session) = engage_and_mse();
    let ch = with_ops(&mut ks, &mut session, mse_host);
    let sub = engage_sub_params(AUT_ENABLE, &ch.wrap(&[0x3C; 32], [0x11; 12]));
    let req = engage_request(&sub, &sub);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &req, Some(acfg_token())).status.code(), OK);
    });

    for wrong in [[0x3D; 32], [0x00; 32], {
        let mut k = [0x3Cu8; 32];
        k[31] ^= 0x01;
        k
    }] {
        let ch2 = with_ops(&mut ks, &mut session, mse_host);
        let ureq = unlock_request(&ch2.wrap(&wrong, [0x55; 12]));
        with_ops(&mut ks, &mut session, |ops| {
            let status = unlock(ops, &ureq, None).status.code();
            assert_eq!(status, OPERATION_DENIED, "a wrong key must not answer 0x3D");
            assert_ne!(status, NOT_LOCKED, "0x3D means 'not locked'; it must not be reused");
            assert!(!ops.unlocked_this_power_cycle(), "a failed unlock must not set the flag");
        });
    }

    // A blob sealed to a *different* channel is also refused: the AAD is the
    // device point, so a blob from an earlier session does not open even with
    // the right key.
    with_ops(&mut ks, &mut session, |ops| {
        let stale = ch.wrap(&[0x3C; 32], [0x66; 12]);
        let outcome = unlock(ops, &unlock_request(&stale), None);
        assert_eq!(outcome.status.code(), OPERATION_DENIED);
    });
}

/// Engage → `UNLOCK` round-trips: the right key opens it, and a device that
/// stores the key can be unlocked again after the session is dropped.
#[test]
fn engaging_then_unlocking_round_trips_the_locked_key() {
    let (mut ks, mut session) = engage_and_mse();
    with_ops(&mut ks, &mut session, |ops| ops.set_master_seed([0xB0; 32]).unwrap());

    // Two independent 32-byte keys, so "the stored key is the one the client
    // generated" is not a coincidence of using the same constant twice.
    let key_a = [0xA5; 32];
    let key_b = [0x5A; 32];

    let ch = with_ops(&mut ks, &mut session, mse_host);
    let sub = engage_sub_params(AUT_ENABLE, &ch.wrap(&key_a, [0x77; 12]));
    let req = engage_request(&sub, &sub);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &req, Some(acfg_token())).status.code(), OK);
    });

    // `key_b` does not open it.
    let ch2 = with_ops(&mut ks, &mut session, mse_host);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(
            unlock(ops, &unlock_request(&ch2.wrap(&key_b, [0x88; 12])), None).status.code(),
            OPERATION_DENIED
        );
    });

    // `key_a` does.
    let ch3 = with_ops(&mut ks, &mut session, mse_host);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(
            unlock(ops, &unlock_request(&ch3.wrap(&key_a, [0x99; 12])), None).status.code(),
            OK
        );
        assert!(ops.unlocked_this_power_cycle());
    });

    // And after a simulated power cycle the lock is still there and still
    // opens with the same key — the durable half survived.
    let mut session2 = VendorSession::default();
    let ch4 = with_ops(&mut ks, &mut session2, mse_host);
    with_ops(&mut ks, &mut session2, |ops| {
        assert!(!ops.unlocked_this_power_cycle());
        assert_eq!(
            unlock(ops, &unlock_request(&ch4.wrap(&key_a, [0xAA; 12])), None).status.code(),
            OK
        );
        assert_eq!(ops.master_seed(), Some([0xB0; 32]), "the seed is still there to load");
    });
}

// ---------------------------------------------------------------------------
// 4. The engage / release MAC.
// ---------------------------------------------------------------------------

/// The `0x0D` MAC is verified over **the client's own serialised bytes**, and
/// a re-encoded map is rejected.
///
/// The two forms below are **the same CBOR map**: `0x58 0x3C` and
/// `0x59 0x00 0x3C` both denote a 60-byte byte string, both are legal, and the
/// crate's no-alloc parser decodes both to `Item::B(60 bytes)`. Only the bytes
/// differ.
///
/// * MAC over the wire bytes, wire bytes sent → accepted. The device verified
///   the span it received.
/// * MAC over the **re-encoded** (minimal) form, non-minimal form sent →
///   rejected with `0x33`. A device that decoded the map and re-serialised it
///   before verifying would have compared against the minimal form and
///   **accepted** this — so the rejection is exactly the property.
///
/// This is not hypothetical: `app::FidoApp::authenticator_config` does
/// `auth_msg.extend_from_slice(&cbor::encode(params))` at `app.rs:1974`, and
/// `cbor::encode` re-sorts map keys and re-writes every head canonically
/// (`cbor.rs`'s `encode_to`, `Value::M` arm). It happens to agree with the
/// client on a canonical request, which is exactly what makes it a latent bug
/// rather than a visible one.
#[test]
fn the_config_vendor_mac_is_verified_over_the_clients_own_bytes() {
    let (mut ks, mut session) = engage_and_mse();
    let ch = with_ops(&mut ks, &mut session, mse_host);

    let wire = engage_sub_params_non_canonical(AUT_ENABLE, &ch.wrap(&[0x3C; 32], [0x11; 12]));
    let re_encoded = engage_sub_params(AUT_ENABLE, &ch.wrap(&[0x3C; 32], [0x11; 12]));
    assert_ne!(wire, re_encoded, "the two forms must differ in bytes");
    assert_eq!(wire.len(), re_encoded.len() + 1, "only the byte-string head differs");

    // MAC over the bytes that are actually sent.
    let good = engage_request(&wire, &wire);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &good, Some(acfg_token())).status.code(), OK);
    });

    // Same request, MAC over a re-encoding. A re-encoding verifier accepts it;
    // a wire-span verifier does not.
    let mut ks2 = MemoryKeystore::new();
    let mut session2 = VendorSession::default();
    with_ops(&mut ks2, &mut session2, |ops| {
        let ch2 = mse_host(ops);
        let wire2 = engage_sub_params_non_canonical(AUT_ENABLE, &ch2.wrap(&[0x3C; 32], [0x11; 12]));
        let reenc2 = engage_sub_params(AUT_ENABLE, &ch2.wrap(&[0x3C; 32], [0x11; 12]));
        let bad = engage_request(&wire2, &reenc2);
        let outcome = lock_engage(ops, &bad, Some(acfg_token()));
        assert_eq!(
            outcome.status.code(),
            PIN_AUTH_INVALID,
            "a MAC over a re-encoded map must not verify against the wire bytes"
        );
        assert!(outcome.pin_auth_failure, "and it must be charged as an auth failure");
        assert!(!ops.soft_lock().engaged(), "and it must not have engaged a lock");
    });
}

/// The `0x20` gate, and the `0x33`-is-charged rule.
#[test]
fn engage_requires_a_0x20_token_and_charges_a_wrong_one() {
    let (mut ks, mut session) = engage_and_mse();
    let ch = with_ops(&mut ks, &mut session, mse_host);
    let sub = engage_sub_params(AUT_ENABLE, &ch.wrap(&[0x3C; 32], [0x11; 12]));
    let good = engage_request(&sub, &sub);

    // No token at all: `0x36`, never "authorised".
    with_ops(&mut ks, &mut session, |ops| {
        let outcome = lock_engage(ops, &good, None);
        assert_eq!(outcome.status.code(), PUAT_REQUIRED);
        assert!(!outcome.pin_auth_failure, "a missing token is not a failed token");
        assert!(!ops.soft_lock().engaged());
    });

    // No `pinUvAuthParam` in the request: also `0x36`.
    let bare: Vec<u8> = {
        let mut b: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut b, 3).unwrap();
        nh::push_uint(&mut b, CONFIG_PARAM_SUB_COMMAND).unwrap();
        nh::push_uint(&mut b, CONFIG_SUB_VENDOR_PROTOTYPE as u64).unwrap();
        nh::push_uint(&mut b, CONFIG_PARAM_SUB_COMMAND_PARAMS).unwrap();
        b.extend_from_slice(&sub).unwrap();
        nh::push_uint(&mut b, CONFIG_PARAM_PIN_PROTOCOL).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        b.to_vec()
    };
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &bare, Some(acfg_token())).status.code(), PUAT_REQUIRED);
    });

    // The app's three-strike latch: `0x34`, and **not** charged.
    with_ops(&mut ks, &mut session, |ops| {
        let outcome = lock_engage(ops, &good, Some(blocked_token()));
        assert_eq!(outcome.status.code(), PIN_AUTH_BLOCKED);
        assert!(!outcome.pin_auth_failure, "the latch has already spent its strikes");
    });

    // A token without `AUTHENTICATOR_CONFIG`: `0x40`. Charged, because a valid
    // MAC under the wrong permission is a real event for the app's counter.
    with_ops(&mut ks, &mut session, |ops| {
        let outcome = lock_engage(ops, &good, Some(wrong_perm_token()));
        assert_eq!(outcome.status.code(), UNAUTHORIZED_PERMISSION);
        assert!(outcome.pin_auth_failure);
        assert!(!ops.soft_lock().engaged());
    });

    // A wrong token: `0x33`, charged.
    with_ops(&mut ks, &mut session, |ops| {
        let wrong = [0x77u8; 32];
        let mut mac = picoforge_config_mac(&wrong, &sub);
        mac[0] ^= 0xff;
        let req = config_vendor_request(&sub, mac);
        let outcome = lock_engage(ops, &req, Some(acfg_token()));
        assert_eq!(outcome.status.code(), PIN_AUTH_INVALID);
        assert!(outcome.pin_auth_failure);
    });

    // A protocol the device does not define: `0x02`, not a failed MAC.
    with_ops(&mut ks, &mut session, |ops| {
        // `0xFF` as a CBOR *value* is the "break" stop code, not a uint —
        // uint 255 is `0x18 0xFF`, which is what the client's serialiser emits
        // and what `push_uint` produces. Hand-writing `0xFF` here would be a
        // CBOR error rather than the protocol error under test.
        let mut b: Vec<u8> = Vec::new();
        b.push(0xA4);
        b.push(0x01);
        push_uint_to_vec(&mut b, CONFIG_SUB_VENDOR_PROTOTYPE as u64);
        b.push(0x02);
        b.extend_from_slice(&sub);
        b.push(0x03);
        b.push(0x02); // protocol 2 — a real CTAP2 protocol, not one this path defines
        b.push(0x04);
        b.push(0x50);
        b.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            lock_engage(ops, &b, Some(acfg_token())).status.code(),
            INVALID_PARAMETER
        );
    });

    // A sub-command that is not `VendorPrototype`: `0x3E`.
    with_ops(&mut ks, &mut session, |ops| {
        // `0xA4` = a 4-pair map; `0x03` = SetMinPinLength, not VendorPrototype.
        let mut b: Vec<u8> = vec![0xA4, 0x01, 0x03, 0x02];
        b.extend_from_slice(&sub);
        b.push(0x03);
        b.push(0x01);
        b.push(0x04);
        b.push(0x50);
        b.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            lock_engage(ops, &b, Some(acfg_token())).status.code(),
            INVALID_SUBCOMMAND
        );
    });
}

/// A vendor id this arm does not own is `0x3E`, and a blob under the wrong key
/// slot is not a blob.
#[test]
fn engage_refuses_a_vendor_id_that_is_not_its_own() {
    let (mut ks, mut session) = engage_and_mse();
    let ch = with_ops(&mut ks, &mut session, mse_host);
    let blob = ch.wrap(&[0x3C; 32], [0x11; 12]);

    // `RSKEY_AUT_DISABLE` sent to the engage arm.
    let sub = engage_sub_params(AUT_DISABLE, &blob);
    let req = engage_request(&sub, &sub);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &req, Some(acfg_token())).status.code(), INVALID_SUBCOMMAND);
        assert!(!ops.soft_lock().engaged());
    });

    // The blob under key `0x03` (the `Integer` slot) instead of `0x02` (the
    // `Bytes` slot). The client never sends this — `authconfig_vendor` chooses
    // the key by payload type (`ops.rs:1618-1627`) — and an arm that looked for
    // key `3` because the client's enum calls key `2` a "COSE key" would read
    // the wrong map and either refuse everything or, worse, accept an integer
    // where a sealed blob belongs.
    let mut sub3: Vec<u8> = Vec::new();
    sub3.push(0xA2);
    sub3.push(0x01);
    push_uint_to_vec(&mut sub3, AUT_ENABLE);
    sub3.push(0x03);
    sub3.push(0x1A);
    sub3.extend_from_slice(&blob[..4]);
    let req3 = engage_request(&sub3, &sub3);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &req3, Some(acfg_token())).status.code(), MISSING_PARAMETER);
    });

    // The right key slot, no payload at all.
    let noblob = release_sub_params(AUT_ENABLE);
    let req4 = engage_request(&noblob, &noblob);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &req4, Some(acfg_token())).status.code(), MISSING_PARAMETER);
    });
}

/// Release refuses a payload, and refuses a lock that has not been opened.
#[test]
fn release_refuses_a_payload_and_an_unopened_lock() {
    let (mut ks, mut session) = engage_and_mse();
    let ch = with_ops(&mut ks, &mut session, mse_host);
    let sub = engage_sub_params(AUT_ENABLE, &ch.wrap(&[0x3C; 32], [0x11; 12]));
    let req = engage_request(&sub, &sub);
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_engage(ops, &req, Some(acfg_token())).status.code(), OK);
    });

    // The client's own form: `{1: AUT_DISABLE}`, no payload.
    let plain = release_sub_params(AUT_DISABLE);
    let good = release_request(&plain, &plain);
    // …but the lock has not been opened, so this is `0x0A` and not `0x00`.
    with_ops(&mut ks, &mut session, |ops| {
        let outcome = lock_release(ops, &good, Some(acfg_token()));
        assert_eq!(outcome.status.code(), LOCK_REQUIRED);
        assert_ne!(outcome.status.code(), NOT_LOCKED, "0x3D is UNLOCK's status, not this one's");
        assert!(ops.soft_lock().engaged(), "a refused release leaves the lock on");
    });

    // Open it, then send a release **with** a payload. `lock_disable` passes
    // `None` (`mod.rs:1873`), so a payload means a client this protocol does
    // not define; accepting arguments it cannot interpret is how a release
    // ends up meaning two things.
    let ch2 = with_ops(&mut ks, &mut session, mse_host);
    let ureq = unlock_request(&ch2.wrap(&[0x3C; 32], [0x22; 12]));
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(unlock(ops, &ureq, None).status.code(), OK);
    });
    for payload_key in [0x02u64, 0x03, 0x04] {
        let mut sp: Vec<u8> = Vec::new();
        sp.push(0xA2);
        sp.push(0x01);
        push_uint_to_vec(&mut sp, AUT_DISABLE);
        push_uint_to_vec(&mut sp, payload_key);
        sp.push(0x41);
        sp.push(0x61);
        let bad = release_request(&sp, &sp);
        with_ops(&mut ks, &mut session, |ops| {
            assert_eq!(
                lock_release(ops, &bad, Some(acfg_token())).status.code(),
                INVALID_PARAMETER,
                "a payload under key {payload_key:#04x} must be refused"
            );
            assert!(ops.soft_lock().engaged());
        });
    }

    // And the gate applies to release exactly as it does to engage.
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_release(ops, &good, None).status.code(), PUAT_REQUIRED);
        assert!(ops.soft_lock().engaged());
    });
    // The right call now succeeds and clears both the lock and the flag.
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_release(ops, &good, Some(acfg_token())).status.code(), OK);
        assert!(!ops.soft_lock().engaged());
        assert!(!ops.unlocked_this_power_cycle(), "a released lock is not an open one");
    });
    // A second release is `0x0A` again, not a `0x00` that did nothing.
    with_ops(&mut ks, &mut session, |ops| {
        assert_eq!(lock_release(ops, &good, Some(acfg_token())).status.code(), LOCK_REQUIRED);
    });
    // And `UNLOCK` on the released device is `0x3D` again.
    with_ops(&mut ks, &mut session, |ops| {
        let ch3 = mse_host(ops);
        assert_eq!(
            unlock(ops, &unlock_request(&ch3.wrap(&[0x3C; 32], [0x33; 12])), None).status.code(),
            NOT_LOCKED
        );
    });
}

// ---------------------------------------------------------------------------
// 5. The constants, against the client.
// ---------------------------------------------------------------------------

/// Every published constant, checked against the client line it is transcribed
/// from. Literal values, not imports: a test that read them from
/// `vendor_lock` would prove it agrees with itself.
#[test]
fn the_published_constants_are_the_clients() {
    // The client's actual `STATE` request, decoded: `{1: 5}` and nothing else.
    // `state()` takes no request bytes at all — there is no
    // `subCommandParams` to read — so this is the one place the shape the
    // client sends is asserted, and it is asserted against the exported
    // constant the dispatch arm will match on.
    let (v, used) = cbor::decode(&state_request()).unwrap();
    assert_eq!(used, 3, "STATE is a 1-pair map: three bytes, no params map");
    match v {
        Value::M(m) => {
            assert_eq!(m.len(), 1, "STATE carries no subCommandParams");
            match &m[0] {
                (Value::U(1), Value::U(s)) => assert_eq!(
                    *s, SUB_STATE as u64,
                    "the client's STATE sub-command must be the one this module names"
                ),
                other => panic!("unexpected STATE request pair: {other:?}"),
            }
        }
        other => panic!("STATE request is not a map: {other:?}"),
    }
    // …and the two `0x41` sub-commands must be the ones the existing
    // dispatcher already enumerates, or the arm is unreachable.
    assert_eq!(
        vendor41::Subcommand::from_byte(SUB_STATE),
        Some(vendor41::Subcommand::State)
    );
    assert_eq!(
        vendor41::Subcommand::from_byte(SUB_UNLOCK),
        Some(vendor41::Subcommand::Unlock)
    );
    // `backup_status` and `lock_unlock` both pass `None` for the PIN
    // (`mod.rs:1741`, `:1826`), which is what makes them `TokenOptional` rows
    // rather than `Permission` rows — the arm's decision to accept a tokenless
    // `UNLOCK` has to agree with that table or the two documents disagree.
    for sub in [vendor41::Subcommand::State, vendor41::Subcommand::Unlock] {
        assert_eq!(
            vendor41::required_permission(sub),
            vendor41::Requirement::TokenOptional(PERM_ACFG),
            "{sub:?} must stay a TokenOptional row: the client sends it bare"
        );
    }

    assert_eq!(SUB_STATE, 0x05, "picoforge/src/hal/fido/constants.rs:744");
    assert_eq!(SUB_UNLOCK, 0x06, "constants.rs:746");
    assert_eq!(CMD_CONFIG, 0x0D, "constants.rs:64");
    assert_eq!(CONFIG_SUB_VENDOR_PROTOTYPE, 0xFF, "constants.rs:217 — NOT 0x03");
    assert_eq!(CONFIG_PARAM_SUB_COMMAND, 0x01, "constants.rs:194");
    assert_eq!(CONFIG_PARAM_SUB_COMMAND_PARAMS, 0x02, "constants.rs:196");
    assert_eq!(CONFIG_PARAM_PIN_PROTOCOL, 0x03, "constants.rs:198");
    assert_eq!(CONFIG_PARAM_PIN_PARAM, 0x04, "constants.rs:200");
    assert_eq!(VENDOR_SUB_PARAM_ID, 0x01, "ops.rs:1616");
    assert_eq!(VENDOR_SUB_PARAM_BSTR, 0x02, "ops.rs:1620 — Bytes, not the enum's COSE key");
    assert_eq!(UNLOCK_PARAM_BLOB, 0x01, "mod.rs:1821");
    assert_eq!(AUT_ENABLE, 0x03E4_3F56_B342_85E2, "constants.rs:766");
    assert_eq!(AUT_DISABLE, 0x1831_A40F_04A2_5ED9, "constants.rs:768");
    assert_eq!(LOCK_BLOB_LEN, 60, "nonce(12) ‖ ct(32) ‖ tag(16)");
    assert_eq!(PERM_ACFG, 0x20, "device_core::PERM_ACFG, the bit the client mints");
}

// ---------------------------------------------------------------------------
// Fixtures and the independent test-side sealer.
// ---------------------------------------------------------------------------

/// A fresh keystore with a master seed, and a fresh session.
fn engage_and_mse() -> (MemoryKeystore, VendorSession) {
    let mut ks = MemoryKeystore::new();
    ks.get_auth_state_mut().vendor.secret.master_seed = Some([0x42; 32]);
    (ks, VendorSession::default())
}

// ---------------------------------------------------------------------------
// The test's own ChaCha20-Poly1305.
//
// Deliberately separate from `vendor_lock.rs`'s: a test that opened a blob its
// own sealer produced would pass even if both were wrong in the same way. This
// one is pinned to
// [`the_chacha20_block_keystream_matches_rfc_8439`] and to the two external
// vectors in [`aead_open_matches_vectors_from_an_independent_implementation`]
// — and the *opener* is separately pinned to those same external bytes, which
// is the assertion that actually matters.
// ---------------------------------------------------------------------------

/// The ChaCha20 block function (RFC 8439 §2.3).
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    let init = s;
    for _ in 0..10 {
        for (a, b, c, d) in [
            (0, 4, 8, 12),
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

/// One 64-byte keystream block.
fn chacha20_keystream(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    chacha20_block(key, counter, nonce, out);
}

/// The AEAD seal, in `ring`'s `wrap_secret` form: `nonce(12) ‖ ct ‖ tag(16)`.
fn chacha_seal(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    // One-time key from the counter-0 block (RFC 8439 §2.6.1).
    let mut b0 = [0u8; 64];
    chacha20_block(key, 0, nonce, &mut b0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&b0[..32]);

    // Payload at counter 1. Only whole blocks, which is all this path needs
    // (the lock key is 32 bytes).
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
        h[i] = (h[i] & !mask) | (g[i] & mask);
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

fn mac_block(h: &mut [u32; 5], r: &[u32; 5], s: (u32, u32, u32, u32), b: &[u8; 16], hibit: u32) {
    let t0 = u32::from_le_bytes(b[0..4].try_into().unwrap());
    let t1 = u32::from_le_bytes(b[3..7].try_into().unwrap());
    let t2 = u32::from_le_bytes(b[6..10].try_into().unwrap());
    let t3 = u32::from_le_bytes(b[9..13].try_into().unwrap());
    let t4 = u32::from_le_bytes(b[12..16].try_into().unwrap());
    h[0] += t0 & 0x3ff_ffff;
    h[1] += (t1 >> 2) & 0x3ff_ffff;
    h[2] += (t2 >> 4) & 0x3ff_ffff;
    h[3] += (t3 >> 6) & 0x3ff_ffff;
    h[4] += (t4 >> 8) | hibit;
    let (s1, s2, s3, s4) = s;
    let d0 = u64::from(h[0]) * u64::from(r[0]) + u64::from(h[1]) * u64::from(s4)
        + u64::from(h[2]) * u64::from(s3)
        + u64::from(h[3]) * u64::from(s2)
        + u64::from(h[4]) * u64::from(s1);
    let mut d1 = u64::from(h[0]) * u64::from(r[1]) + u64::from(h[1]) * u64::from(r[0])
        + u64::from(h[2]) * u64::from(s4)
        + u64::from(h[3]) * u64::from(s3)
        + u64::from(h[4]) * u64::from(s2);
    let mut d2 = u64::from(h[0]) * u64::from(r[2]) + u64::from(h[1]) * u64::from(r[1])
        + u64::from(h[2]) * u64::from(r[0])
        + u64::from(h[3]) * u64::from(s4)
        + u64::from(h[4]) * u64::from(s3);
    let mut d3 = u64::from(h[0]) * u64::from(r[3]) + u64::from(h[1]) * u64::from(r[2])
        + u64::from(h[2]) * u64::from(r[1])
        + u64::from(h[3]) * u64::from(r[0])
        + u64::from(h[4]) * u64::from(s4);
    let mut d4 = u64::from(h[0]) * u64::from(r[4]) + u64::from(h[1]) * u64::from(r[3])
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

// Keep the unused import honest: `SecureStore` is what `MemoryKeystore`
// implements, and naming it documents that this is the real store.
#[allow(dead_code)]
fn _assert_the_real_store_is_in_scope(_: &dyn SecureStore) {}

// ---------------------------------------------------------------------------
// 5. End to end: the two `0x0D` arms, driven through the **real** dispatch.
//
// Everything above calls `lock_engage` / `lock_release` directly. That proves
// the module and proves nothing about the wiring — an arm nobody routes to
// passes every test in section 4. So this section drives the two requests
// through `FidoApp::process_ctap2` / `process_ctap2_with_store` on **both**
// stacks, with a real `0x20` PIN token, a real `0x41` MSE handshake to seal
// the blob to, and a real `0x41` `STATE` to read the result back.
//
// # The shape of every test here
//
// `0x0D` carries a `0x20` token's MAC; the blob is sealed to the MSE channel
// established by an earlier `0x41` `MSE`; the observable is the `locked` bit
// of a later `0x41` `STATE`. None of the three can be faked without
// re-implementing one of them, so a passing test here is a statement about the
// whole path rather than about any one function.
//
// # Both stacks, deliberately
//
// The host `0x0D` handler (`app.rs::authenticator_config`) and the device one
// (`device_core.rs::authenticator_config_inner`) are **different functions**
// with different gates, and they did not agree once already: the device MACs
// the client's own bytes (`&data[s..e]`), the host MACs a **re-encoding** of
// a decoded map (`app.rs:1974`'s `cbor::encode(params)`). A test that only
// drove one of them would not have noticed. Every behavioural assertion below
// is therefore made on both, from the same bytes.
// ---------------------------------------------------------------------------

/// The client's `MSE` `subCommandParams`: `{1: <COSE EC2>}` with the labels
/// in the **`BTreeMap` order** `-3, -2, -1, 1, 3`
/// (`picoforge/src/hal/fido/mod.rs:1698-1706`).
///
/// The `BTreeMap` order and not the RFC 8152 canonical one on purpose: the
/// canonical order is the one a test would write from the spec, and a device
/// that only accepted *that* would pass this test and fail against PicoForge.
/// `vendor_backup::mse` accepts both (US-120), and driving the client's
/// actual shape is what makes the lock tests exercise the same parse the
/// shipping client goes through.
fn mse_sub_params(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut p: HV<u8, 160> = HV::new();
    nh::push_map_header(&mut p, 1).unwrap();
    nh::push_uint(&mut p, 1).unwrap();
    nh::push_map_header(&mut p, 5).unwrap();
    nh::push_neg(&mut p, -3).unwrap();
    nh::push_bstr(&mut p, y).unwrap();
    nh::push_neg(&mut p, -2).unwrap();
    nh::push_bstr(&mut p, x).unwrap();
    nh::push_neg(&mut p, -1).unwrap();
    nh::push_uint(&mut p, 1).unwrap();
    nh::push_uint(&mut p, 1).unwrap();
    nh::push_uint(&mut p, 2).unwrap();
    nh::push_uint(&mut p, 3).unwrap();
    nh::push_neg(&mut p, -25).unwrap();
    p.to_vec()
}

/// The device's own uncompressed point out of an `MSE` response body,
/// `{1: {1:2, 3:-25, -1:1, -2:x, -3:y}}`, as SEC1 `0x04 ‖ x ‖ y`.
fn mse_device_point(body: &[u8]) -> [u8; 65] {
    let mut p = nh::Parser::new(body);
    let mut point = [0u8; 65];
    point[0] = 0x04;
    assert!(matches!(p.next(), Ok(nh::Item::Map(1))), "MSE body is a 1-pair map");
    assert_eq!(p.next().unwrap(), nh::Item::U(1), "and that pair is key 1");
    assert!(matches!(p.next(), Ok(nh::Item::Map(5))), "the COSE key has five labels");
    for _ in 0..5 {
        let label = match p.next().unwrap() {
            nh::Item::N(n) => n,
            nh::Item::U(u) => u as i64,
            other => panic!("COSE label is neither a signed nor unsigned int: {other:?}"),
        };
        match label {
            -2 => match p.next().unwrap() {
                nh::Item::B(b) => point[1..33].copy_from_slice(b),
                other => panic!("-2 is not a byte string: {other:?}"),
            },
            -3 => match p.next().unwrap() {
                nh::Item::B(b) => point[33..65].copy_from_slice(b),
                other => panic!("-3 is not a byte string: {other:?}"),
            },
            _ => p.skip().unwrap(),
        }
    }
    point
}

/// Complete the host's half of the MSE handshake against a device `0x04 ‖ x
/// ‖ y`, by the client's own derivation
/// (`HKDF-SHA256(salt = b"", ikm = z, info = aad)`, `mod.rs:1684-1734`).
fn mse_finish(sk: &p256::SecretKey, device_point: &[u8; 65]) -> HostChannel {
    let peer = crypto::parse_public_key(device_point).expect("the device point is on the curve");
    let z = crypto::ecdh_shared_secret(sk, &peer);
    let key = vendor41::derive_mse_channel(&z, device_point);
    HostChannel { key, aad: *device_point }
}

// ---------------------------------------------------------------------------
// 5a. The host stack.
// ---------------------------------------------------------------------------

/// A host app with a PIN set and a live `0x20` token, plus the raw token.
///
/// The token is returned because it is the HMAC key the `0x0D` MAC is built
/// with, and handing the test the *raw* token rather than a helper is what
/// lets it build the **wrong** MAC on purpose for the refusal tests — a
/// `sign` closure that could only ever be called correctly could not.
fn host_app_with_acfg_token() -> (fapico2_fido::app::FidoApp<MemoryKeystore>, [u8; 32]) {
    use fapico2_fido::keystore::Keystore as _;
    let (mut app, client) = common::setup();
    let token = client.get_token(&mut app, 0x09, Some(PERM_ACFG), None).expect("getPinToken");
    assert!(app.keystore().get_pin_state().pin_hash.is_some(), "setup sets a PIN");
    (app, <[u8; 32]>::try_from(&token[..32]).unwrap())
}

/// Drive one `0x41` sub-command on the host and return `(status, body)`.
fn host_rskey<K: fapico2_fido::keystore::Keystore>(
    app: &mut fapico2_fido::app::FidoApp<K>,
    req: &[u8],
) -> (u8, Vec<u8>) {
    let resp = app.process_ctap2(0x41, req, [1, 2, 3, 4]);
    (resp[0], resp[1..].to_vec())
}

/// Establish the MSE channel on the host app and return the host's half of it,
/// ready to `wrap` a lock key for.
///
/// The host's P-256 secret is generated here and **not** returned: unlike
/// `DeviceClient`, which needs it again for the `UNLOCK` leg, the host tests
/// re-seal the same 32 bytes through [`HostChannel::wrap`] rather than through
/// a second handshake, so keeping the key would be a field no test reads.
fn host_mse<K: fapico2_fido::keystore::Keystore>(
    app: &mut fapico2_fido::app::FidoApp<K>,
) -> HostChannel {
    let (sk, _pk) = crypto::generate_p256_keypair();
    let sec = crypto::public_key_bytes(&sk.public_key());
    let (hx, hy) = (
        <[u8; 32]>::try_from(&sec[1..33]).unwrap(),
        <[u8; 32]>::try_from(&sec[33..65]).unwrap(),
    );
    let (status, body) = host_rskey(app, &rskey(0x01, &mse_sub_params(&hx, &hy)));
    assert_eq!(status, OK, "the ungated MSE handshake cannot fail on a valid point");
    mse_finish(&sk, &mse_device_point(&body))
}

/// Read `STATE` over the real `0x41` channel on the host app.
fn host_state<K: fapico2_fido::keystore::Keystore>(
    app: &mut fapico2_fido::app::FidoApp<K>,
) -> StateFlags {
    let (status, body) = host_rskey(app, &state_request());
    assert_eq!(status, OK, "STATE is ungated and cannot fail here");
    parse_state_body(&body)
}

/// The `0x0D` request body signed with an **explicit** token.
///
/// The file's own [`engage_request`] signs with the constant [`PIN_TOKEN`],
/// which is what section 4's direct-to-`lock_engage` tests use because they
/// hand it [`acfg_token`]. An end-to-end test cannot: the app mints its own
/// token from the TRNG pool, and re-using `engage_request` here would have
/// every such test sign with a key the app never held and be refused `0x33` —
/// a passing assertion for the wrong reason would have looked like a wiring
/// failure. So the framing is shared and only the signing key differs.
fn config_request_for(token: &[u8; 32], sent: &[u8], mac_over: &[u8]) -> Vec<u8> {
    let mac: [u8; 16] = <[u8; 16]>::try_from(&mac_over_with(token, mac_over)[..])
        .expect("pinUvAuthParam is 16 bytes");
    config_vendor_request(sent, mac)
}

/// Send one `0x0D` vendor-prototype request on the host app and return the
/// CTAP2 status byte.
///
/// `mac_over` is what the token signed and `sent` is the params on the wire —
/// the same split [`config_request_for`] uses, so a test can put a **wrong**
/// MAC or a **non-canonical** serialisation on the wire without restating the
/// framing.
fn host_config(
    app: &mut fapico2_fido::app::FidoApp<MemoryKeystore>,
    token: &[u8; 32],
    sent: &[u8],
    mac_over: &[u8],
) -> u8 {
    app.process_ctap2(
        0x0D,
        &config_request_for(token, sent, mac_over),
        [1, 2, 3, 4],
    )[0]
}

/// The `0x0D` MAC under an explicit token, so the refusal tests can sign with
/// the *wrong* key rather than with a mutated copy of the right one.
///
/// Mutating the MAC after signing and signing with a different key fail for
/// different reasons — the first is what a stale `pinUvAuthParam` looks like,
/// the second is what a token from another session looks like — and the
/// module charges both, so both are worth driving.
fn mac_over_with(token: &[u8; 32], sub_params: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut msg = vec![0xFFu8; 32];
    msg.push(0x0D);
    msg.push(0xFF);
    msg.extend_from_slice(sub_params);
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(token).unwrap();
    m.update(&msg);
    m.finalize().into_bytes()[..16].to_vec()
}

/// `# a_valid_0d_engage_reaches_the_lock_and_state_says_so` (host)
///
/// The load-bearing end-to-end claim: a canonical `AUT_ENABLE` with a valid
/// `0x0D` MAC under a `0x20` token comes back `0x00` **through**
/// `cfg_vendor_prototype`, and a subsequent `0x41` `STATE` — a different
/// channel, a different function, a different `VendorOps` — reports
/// `locked: true`.
///
/// `has_seed` is asserted `false` alongside, because `lock_engage` documents
/// that engaging over no seed is legal and a host that quietly required a seed
/// would fail a PicoForge sequence that enables the lock before the first
/// backup. A test that only checked `locked` would not notice that swap.
#[test]
fn host_a_valid_0d_engage_reaches_the_lock_and_state_says_so() {
    let (mut app, token) = host_app_with_acfg_token();
    assert!(!host_state(&mut app).locked, "a fresh device is not locked");

    let channel = host_mse(&mut app);
    let blob = channel.wrap(&[0xC0; 32], [0x11; 12]);
    let sub = engage_sub_params(AUT_ENABLE, &blob);
    assert_eq!(
        host_config(&mut app, &token, &sub, &sub),
        OK,
        "an AUT_ENABLE with a valid 0x0D MAC and a 0x20 token must be accepted \
         by the host `0xFF` arm"
    );

    let flags = host_state(&mut app);
    assert!(flags.locked, "STATE must now report locked: true");
    assert!(
        !flags.has_seed,
        "engaging over no master seed is legal and must not be reported as a seed"
    );
    assert!(
        !flags.unlocked,
        "engage clears any standing unlock, so a device that has never been \
         unlocked must not claim it is"
    );
}

/// `# a_valid_0d_release_releases_it` (host)
///
/// The two-step the client performs: `UNLOCK` over `0x41`, then
/// `AUT_DISABLE` over `0x0D`. Only the second leg is under test here, so the
/// first is driven through the real `0x41` channel with the client's own
/// re-seal (`lock_disable` does a *fresh* handshake and seals the same
/// plaintext under a new nonce — `vendor_lock.rs`'s module docs, the
/// "stored form departs from SoftLock's doc comment" section).
///
/// The release also has a precondition, `unlocked_this_power_cycle`, and
/// driving the `UNLOCK` first is what satisfies it. A release without it is
/// `0x0A` `LockRequired`, which is asserted separately below — this test is
/// the *happy* two-step, not the refusal.
#[test]
fn host_a_valid_0d_release_releases_it() {
    let (mut app, token) = host_app_with_acfg_token();
    let channel = host_mse(&mut app);
    let lock_key = [0x5A; 32];
    let blob = channel.wrap(&lock_key, [0x22; 12]);
    let engage = engage_sub_params(AUT_ENABLE, &blob);
    assert_eq!(host_config(&mut app, &token, &engage, &engage), OK);
    assert!(host_state(&mut app).locked);

    // Leg one: `UNLOCK` over `0x41`, with a **fresh** seal under a new nonce
    // and the same channel — which is what `wrap_secret` + `mse_handshake`
    // does at `mod.rs:1857-1879`.
    let unseal = channel.wrap(&lock_key, [0x33; 12]);
    let (status, _) = host_rskey(&mut app, &unlock_request_with_token(&unseal, &token));
    assert_eq!(status, OK, "UNLOCK with the right phrase must succeed");
    let flags = host_state(&mut app);
    assert!(flags.locked && flags.unlocked, "the device is locked *and* open this cycle");

    // Leg two: `AUT_DISABLE` over `0x0D`.
    let release = release_sub_params(AUT_DISABLE);
    assert_eq!(
        host_config(&mut app, &token, &release, &release),
        OK,
        "an AUT_DISABLE with a valid MAC and an already-open seed must release"
    );
    let flags = host_state(&mut app);
    assert!(!flags.locked, "STATE must now report locked: false");
    assert!(!flags.unlocked, "releasing clears the unlock flag as well");
}

/// `# a_bad_0d_mac_is_refused_and_changes_nothing` (host)
///
/// Three refusal shapes, one assertion each, because they are refused at
/// three different places and a single "it returned non-zero" would not say
/// which one is load-bearing:
///
/// 1. a MAC over *different* bytes than were sent,
/// 2. a MAC made with a *different* key (a token from another session),
/// 3. a `0x20`-shaped token that has been replaced by a `0x04`
///    (`CREDENTIAL_MANAGEMENT`) one — right key, wrong permission.
///
/// In all three the lock must be **unchanged**, and that is the half that
/// matters: an arm that returns `0x33` *after* writing the record has
/// authenticated nothing and destroyed the previous lock, and only a
/// before/after `STATE` catches that.
#[test]
fn host_a_bad_0d_mac_is_refused_and_changes_nothing() {
    let (mut app, token) = host_app_with_acfg_token();
    let channel = host_mse(&mut app);
    let blob = channel.wrap(&[0xC0; 32], [0x44; 12]);
    let good = engage_sub_params(AUT_ENABLE, &blob);
    // Read once, up front, and assert it here rather than at the bottom: a
    // "before" that is only checked at the end reads as a leftover, and this
    // is the fact the whole test rests on — every `!locked` below is only
    // meaningful because the device started unlocked.
    assert!(!host_state(&mut app).locked, "the device starts unlocked");

    // 1. right key, but the MAC is over a *different* serialisation.
    let other = engage_sub_params(AUT_ENABLE, &channel.wrap(&[0xC1; 32], [0x45; 12]));
    assert_eq!(
        host_config(&mut app, &token, &good, &other),
        PIN_AUTH_INVALID,
        "a MAC over bytes other than the ones sent must not authorise"
    );
    assert!(!host_state(&mut app).locked, "and must not have engaged the lock");

    // 2. right bytes, wrong key.
    let other_token = [0x7F; 32];
    assert_eq!(
        host_config(&mut app, &other_token, &good, &good),
        PIN_AUTH_INVALID,
        "a MAC under a key the device did not mint must not authorise"
    );
    assert!(!host_state(&mut app).locked, "and must not have engaged the lock");

    // 3. a good engage *before* the refusals is what makes the assertion
    //    below meaningful, so do it now and re-check it survives.
    assert_eq!(host_config(&mut app, &token, &good, &good), OK);
    let engaged = host_state(&mut app);
    assert!(engaged.locked);
    assert_eq!(
        host_config(&mut app, &other_token, &release_sub_params(AUT_DISABLE), &release_sub_params(AUT_DISABLE)),
        PIN_AUTH_INVALID,
        "a release under a foreign key must not release"
    );
    let after = host_state(&mut app);
    assert_eq!(after.locked, engaged.locked, "a refused release must not clear the lock");
    assert_eq!(after.unlocked, engaged.unlocked, "nor touch the unlock flag");
}

/// `# the_arms_are_unreachable_without_a_0x20_token` (host)
///
/// The gate is the point of the story, so it is asserted from the **outside**:
/// a token minted for `CREDENTIAL_MANAGEMENT` (0x04) and a legacy
/// `getPinToken` (0x05, permissions `0`) both drive a well-formed, correctly
/// MAC'd `AUT_ENABLE` and both are refused — with the lock still unset.
///
/// The status on the host is `0x33` rather than the module's own `0x40`
/// `UnauthorizedPermission`, and that is a real and deliberate difference:
/// `app::FidoApp::authenticator_config` refuses a token without `0x20` at
/// `app.rs:1958-1961` — *before* the `match` — and answers `PinAuthInvalid`
/// there. So the host never reaches the module's permission check, and the
/// module's more precise `0x40` is a device-path answer. Asserting the host's
/// byte here is the assertion; asserting `0x40` on the host would be a test
/// that fails for the right reason and passes for none.
#[test]
fn host_the_arms_are_unreachable_without_a_0x20_token() {
    let (mut app, client) = common::setup();
    // A `CREDENTIAL_MANAGEMENT`-only token.
    let cm = client.get_token(&mut app, 0x09, Some(0x04), None).expect("getPinToken");
    let cm: [u8; 32] = <[u8; 32]>::try_from(&cm[..32]).unwrap();
    // A legacy `getPinToken` (0x05): permissions `0` on both stacks.
    let legacy = client.get_token(&mut app, 0x05, None, None).expect("getPinToken");
    let legacy: [u8; 32] = <[u8; 32]>::try_from(&legacy[..32]).unwrap();

    let channel = host_mse(&mut app);
    let blob = channel.wrap(&[0xC0; 32], [0x55; 12]);
    let sub = engage_sub_params(AUT_ENABLE, &blob);
    assert_eq!(
        host_config(&mut app, &cm, &sub, &sub),
        PIN_AUTH_INVALID,
        "a CREDENTIAL_MANAGEMENT token must not engage the lock"
    );
    assert_eq!(
        host_config(&mut app, &legacy, &sub, &sub),
        PIN_AUTH_INVALID,
        "a legacy permissions-0 token must not engage the lock"
    );
    assert!(!host_state(&mut app).locked, "neither may have engaged the lock");
    assert_eq!(
        host_config(&mut app, &cm, &release_sub_params(AUT_DISABLE), &release_sub_params(AUT_DISABLE)),
        PIN_AUTH_INVALID,
        "nor may a CREDENTIAL_MANAGEMENT token release one"
    );
}

/// `# a_vendorff_id_still_reaches_its_own_arm` (host)
///
/// The dispatch-order check, in the direction that protects the *older*
/// story. `PhysicalLedGpio` is written through the same `0xFF` sub-command
/// and the same `match`, one guard line above the two lock arms, and it must
/// still land in [`crate::vendorff`] — answered `0x00` and persisted — rather
/// than falling into `lock_engage`, which would refuse it as
/// `InvalidSubcommand` (`lock_engage` checks the id itself and
/// `vendor_lock.rs`'s doc says the dispatcher "must have already offered it to
/// the other `0xFF` arms before calling here").
///
/// The `locked` assertion is the second half: even a hypothetical
/// mis-dispatch that somehow reached a lock arm could not have *engaged* a
/// lock, because `lock_engage` re-checks the id. Two independent guards, and
/// this test is what makes the second one not dead code.
#[test]
fn host_a_vendorff_id_still_reaches_its_own_arm() {
    use fapico2_fido::keystore::Keystore as _;
    let (mut app, token) = host_app_with_acfg_token();
    // `vendorff` packs a GPIO number under sub-params key `0x03`
    // (`ops.rs:1624-1626`: `Integer → 0x03`).
    let mut sub: HV<u8, 32> = HV::new();
    nh::push_map_header(&mut sub, 2).unwrap();
    nh::push_uint(&mut sub, VENDOR_SUB_PARAM_ID).unwrap();
    nh::push_uint(&mut sub, fapico2_fido::vendorff::LED_GPIO).unwrap();
    nh::push_uint(&mut sub, 0x03).unwrap();
    nh::push_uint(&mut sub, 15).unwrap();
    let sub = sub.to_vec();

    assert_eq!(
        host_config(&mut app, &token, &sub, &sub),
        OK,
        "a PhysicalLedGpio write must still be accepted by cfg_physical_config"
    );
    assert_eq!(
        app.keystore().get_auth_state().phy.led_gpio,
        Some(15),
        "and must still persist the value that arm exists to persist"
    );
    assert!(!host_state(&mut app).locked, "a physical-config write is not a lock engage");
}

/// `# a_vendorff_id_is_not_a_lock_id_and_vice_versa` (host)
///
/// The id-set disjointness the dispatch order rests on, asserted over the
/// **live** `SUPPORTED_IDS` rather than a copy of it: a new `vendorff` id
/// added later that collides with `AUT_ENABLE` would be caught here and not
/// by any behavioural test, because whichever arm the `match` happened to order
/// first would simply win and the other would become unreachable.
///
/// The reverse direction is asserted too, for the device selector
/// (`device_core::rs_key_lock_id`, which is private): the *observable* is
/// that a `vendorff` id still lands in `cfg_physical_config`, which
/// [`host_a_vendorff_id_still_reaches_its_own_arm`] covers. Between the two
/// tests every id in every set is placed exactly once.
#[test]
fn host_no_rs_key_lock_id_collides_with_a_vendorff_or_credential_id() {
    let lock_ids = [AUT_ENABLE, AUT_DISABLE];
    assert_ne!(lock_ids[0], lock_ids[1], "the two lock ids must differ from each other");
    for (name, id) in fapico2_fido::vendorff::SUPPORTED_IDS {
        for lock in lock_ids {
            assert_ne!(
                *id, lock,
                "vendorff id {name} collides with a vendor_lock id — the `0xFF` \
                 match would silently make one of the two arms unreachable"
            );
        }
    }
    for cred in [
        fapico2_fido::ctap2::CONFIG_CREDENTIAL_REVOKE,
        fapico2_fido::ctap2::CONFIG_CREDENTIAL_EXPIRE,
    ] {
        for lock in lock_ids {
            assert_ne!(
                cred, lock,
                "a ctap2 credential-config id collides with a vendor_lock id"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5b. The device stack — the same requests over `device_app::FidoApp`.
// ---------------------------------------------------------------------------

/// A device client: the app, its `HostSecureStore`, and the `0x20` token.
///
/// Protocol **v1** throughout (`getKeyAgreement` v1, `AES-CBC` with a zero IV,
/// HMAC-SHA256 keys taken from the front 32 bytes of the shared secret). The
/// choice is not load-bearing for what is under test — every `0x0D` and `0x41`
/// message here is protocol **1** because `vendor_lock::config_vendor_gate`
/// accepts only `1` and the client hard-codes it (`ops.rs:1645-1648`) — but
/// the PIN sub-commands are the only ones here that would differ, and v1 is
/// the smaller thing to reproduce.
///
/// The store is returned because it has to stay borrowed-in for
/// `process_ctap2_with_store` on the `0x0D` call, and because
/// `KeystoreVendorOps::set_soft_lock` is a `grow_checked` that persists
/// through it: a device test with `store: None` would prove the in-RAM
/// behaviour and not the commit.
/// A **copy** of the device's live token.
///
/// `DeviceClient::config` takes `&mut self`, so a test that wants to sign with
/// the app's own current token cannot pass `&c.token` — the immutable borrow
/// and the mutable one collide. A `u8` array is `Copy`, so handing it over by
/// value costs nothing and the alternative (`let t = c.token;` at each of
/// eight call sites) is eight places for the copy to be forgotten.
fn live_token(c: &DeviceClient) -> [u8; 32] {
    c.token
}

struct DeviceClient {
    app: fapico2_fido::device_app::FidoApp,
    store: fapico2_platform::secure_store::HostSecureStore,
    hmac_key: [u8; 32],
    enc_key: [u8; 32],
    token: [u8; 32],
    client_sk: p256::SecretKey,
}

impl DeviceClient {
    fn boot() -> Self {
        use fapico2_platform::trng::HostTrng;
        let mut trng = HostTrng::new();
        let mut store = fapico2_platform::secure_store::HostSecureStore::new();
        let app = fapico2_fido::device_app::FidoApp::boot(&mut trng, &mut store).unwrap();
        let client_sk = p256::SecretKey::from_slice(&[0x99; 32]).unwrap();
        Self { app, store, hmac_key: [0; 32], enc_key: [0; 32], token: [0; 32], client_sk }
    }

    /// One CTAP2 command, with the store bound.
    fn call(&mut self, cmd: u8, payload: &[u8]) -> (u8, Vec<u8>) {
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = self.app.process_ctap2_with_store(cmd, payload, [1, 2, 3, 4], &mut out, Some(&mut self.store));
        let resp = out.as_slice()[..n].to_vec();
        (resp[0], resp[1..].to_vec())
    }

    /// The host's `(x, y)` from the fixed client key.
    fn coords(&self) -> ([u8; 32], [u8; 32]) {
        let sec = crypto::public_key_bytes(&self.client_sk.public_key());
        (
            <[u8; 32]>::try_from(&sec[1..33]).unwrap(),
            <[u8; 32]>::try_from(&sec[33..65]).unwrap(),
        )
    }

    fn push_key_agreement(&self, out: &mut HV<u8, 256>) {
        let (x, y) = self.coords();
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

    /// `clientPin` `getKeyAgreement` (v1) → the two shared keys.
    fn derive_keys(&mut self) {
        let mut req: HV<u8, 64> = HV::new();
        nh::push_map_header(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, OK, "getKeyAgreement");
        let mut p = nh::Parser::new(&cbor);
        assert!(matches!(p.next(), Ok(nh::Item::Map(1))));
        assert_eq!(p.next().unwrap(), nh::Item::U(1));
        let nh::Item::Map(n) = p.next().unwrap() else { panic!("a COSE key is a map") };
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        for _ in 0..n {
            let label = match p.next().unwrap() {
                nh::Item::N(v) => v,
                nh::Item::U(v) => v as i64,
                other => panic!("COSE label: {other:?}"),
            };
            match label {
                -2 => match p.next().unwrap() {
                    nh::Item::B(b) => x.copy_from_slice(b),
                    other => panic!("-2: {other:?}"),
                },
                -3 => match p.next().unwrap() {
                    nh::Item::B(b) => y.copy_from_slice(b),
                    other => panic!("-3: {other:?}"),
                },
                _ => p.skip().unwrap(),
            }
        }
        let device_pub = crypto::parse_cose_ec2_p256_bytes(&x, &y).expect("device pubkey");
        let raw = crypto::ecdh_shared_secret(&self.client_sk, &device_pub);
        let k = crypto::derive_shared_secret_v1(&raw);
        self.hmac_key = k;
        self.enc_key = k;
    }

    /// v1 `AES-CBC` with a zero IV, as `clientPin` v1 does.
    fn v1_encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut padded = plaintext.to_vec();
        while !padded.len().is_multiple_of(16) {
            padded.push(0);
        }
        let mut buf = [0u8; 96];
        assert!(padded.len() <= buf.len(), "v1 PIN material is 96 bytes at most");
        buf[..padded.len()].copy_from_slice(&padded);
        crypto::aes256_cbc_encrypt_into(&self.enc_key, &[0u8; 16], &mut buf[..padded.len()]).unwrap();
        buf[..padded.len()].to_vec()
    }

    /// `clientPin` `setPIN`.
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
        self.push_key_agreement(&mut req);
        nh::push_uint(&mut req, 5).unwrap();
        nh::push_bstr(&mut req, &pin_enc).unwrap();
        nh::push_uint(&mut req, 4).unwrap();
        nh::push_bstr(&mut req, &crypto::hmac_sha256(&self.hmac_key, &pin_enc)[..16]).unwrap();
        let (status, _) = self.call(0x06, req.as_slice());
        assert_eq!(status, OK, "setPIN");
    }

    /// `clientPin` `getPinUvAuthTokenUsingPinWithPermissions` (`0x09`).
    ///
    /// `permissions` goes in **key 9** on this path
    /// (`device_core.rs`'s clientPin key map), which is `0x20` for
    /// `AUTHENTICATOR_CONFIG` — the exact token `lock_enable` mints
    /// (`mod.rs:1845-1847`).
    fn get_pin_token(&mut self, pin: &[u8], permissions: u8) -> [u8; 32] {
        let pin_hash = crypto::pin_hash(pin);
        let pin_hash_enc = self.v1_encrypt(&pin_hash);
        let mut req: HV<u8, 256> = HV::new();
        nh::push_map_header(&mut req, 5).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 1).unwrap();
        nh::push_uint(&mut req, 2).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, 3).unwrap();
        self.push_key_agreement(&mut req);
        nh::push_uint(&mut req, 6).unwrap();
        nh::push_bstr(&mut req, &pin_hash_enc).unwrap();
        nh::push_uint(&mut req, 9).unwrap();
        nh::push_uint(&mut req, permissions as u64).unwrap();
        let (status, cbor) = self.call(0x06, req.as_slice());
        assert_eq!(status, OK, "getPinUvAuthTokenUsingPinWithPermissions");
        let mut p = nh::Parser::new(&cbor);
        assert!(matches!(p.next(), Ok(nh::Item::Map(1))));
        assert_eq!(p.next().unwrap(), nh::Item::U(2), "the encrypted token is key 2");
        let nh::Item::B(ct) = p.next().unwrap() else { panic!("the token is a byte string") };
        let mut buf = [0u8; 96];
        assert!(ct.len() <= buf.len());
        buf[..ct.len()].copy_from_slice(ct);
        crypto::aes256_cbc_decrypt_into(&self.enc_key, &[0u8; 16], &mut buf[..ct.len()]).unwrap();
        let mut token = [0u8; 32];
        token.copy_from_slice(&buf[..32]);
        token
    }

    /// Complete the MSE handshake over the real `0x41` channel.
    fn mse(&mut self) -> HostChannel {
        let (x, y) = self.coords();
        let (status, body) = self.call(0x41, &rskey(0x01, &mse_sub_params(&x, &y)));
        assert_eq!(status, OK, "the ungated MSE handshake on the device path");
        mse_finish(&self.client_sk, &mse_device_point(&body))
    }

    fn state(&mut self) -> StateFlags {
        let (status, body) = self.call(0x41, &state_request());
        assert_eq!(status, OK, "STATE is ungated on the device path too");
        parse_state_body(&body)
    }

    /// One `0x0D` vendor-prototype request under an **explicit** token.
    ///
    /// Explicit rather than "whatever `self.token` is" because two of the
    /// tests drive a request under a token the device never minted (a foreign
    /// key) or never granted `0x20` (a `0x04` token), and a self-borrowing
    /// `&self.token` would have made those two unwriteable.
    fn config(&mut self, token: &[u8; 32], sent: &[u8], mac_over: &[u8]) -> u8 {
        self.call(0x0D, &config_request_for(token, sent, mac_over)).0
    }
}

/// `# a_valid_0d_engage_reaches_the_lock_and_state_says_so` (device)
///
/// The same claim as the host test above, on the other stack. It is a separate
/// test rather than a shared helper because the two `0x0D` handlers are
/// different functions with different gates, and the point of running both is
/// that a wiring change to one need not touch the other — which is only
/// asserted if they are separately asserted.
#[test]
fn device_a_valid_0d_engage_reaches_the_lock_and_state_says_so() {
    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    c.token = c.get_pin_token(b"12345678", PERM_ACFG);
    assert!(!c.state().locked, "a fresh device is not locked");

    let channel = c.mse();
    let blob = channel.wrap(&[0xC0; 32], [0x11; 12]);
    let sub = engage_sub_params(AUT_ENABLE, &blob);
    assert_eq!(
        c.config(&live_token(&c), &sub, &sub),
        OK,
        "an AUT_ENABLE with a valid 0x0D MAC must be accepted by the device `0xFF` arm"
    );
    let flags = c.state();
    assert!(flags.locked, "STATE must now report locked: true");
    assert!(!flags.has_seed, "engaging over no master seed is legal");
    assert!(!flags.unlocked, "engage clears any standing unlock");
}

/// `# the_engaged_lock_survives_a_reboot` (device)
///
/// The one property the host twin cannot have and the device exists for:
/// `set_soft_lock` goes through `KeystoreVendorOps`, whose commit is
/// `grow_checked` — apply, **persist**, undo on failure. Without a store bound
/// (`process_ctap2` with `store: None`, the dispatcher-bridge path) that
/// persist is skipped, and "engaged" is a RAM fact.
///
/// So the app is dropped and a **fresh** one booted from the same
/// `HostSecureStore`, which is the only way to reach the bytes the RP2350's
/// secure partition would hold across a power cycle. The volatile
/// `unlocked_this_power_cycle` flag must come back `false` from the same
/// read — that is the property that makes the lock a second factor rather than
/// a latch, and it is why a reboot is the interesting observation and not
/// just the `locked` bit.
#[test]
fn device_the_engaged_lock_survives_a_reboot() {
    use fapico2_platform::trng::HostTrng;
    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    c.token = c.get_pin_token(b"12345678", PERM_ACFG);
    let channel = c.mse();
    let blob = channel.wrap(&[0xC0; 32], [0x66; 12]);
    let sub = engage_sub_params(AUT_ENABLE, &blob);
    assert_eq!(c.config(&live_token(&c), &sub, &sub), OK);
    assert!(c.state().locked);

    // Drop the app; keep the store. A fresh boot reads the same bytes.
    let mut store = c.store;
    let mut trng = HostTrng::new();
    let mut app = fapico2_fido::device_app::FidoApp::boot(&mut trng, &mut store).unwrap();
    let (status, body) = {
        let mut out: HV<u8, { fapico2_fido::CTAP2_MAX_MSG }> = HV::new();
        let n = app.process_ctap2_with_store(0x41, &state_request(), [1, 2, 3, 4], &mut out, Some(&mut store));
        let r = out.as_slice()[..n].to_vec();
        (r[0], r[1..].to_vec())
    };
    assert_eq!(status, OK, "STATE after reboot");
    let flags = parse_state_body(&body);
    assert!(flags.locked, "the lock record must have been persisted, not just written to RAM");
    assert!(
        !flags.unlocked,
        "and the per-power-cycle unlock must not have survived it — a durable \
         `unlocked` would be a latch, not a second factor"
    );
}

/// `# a_valid_0d_release_releases_it` (device)
///
/// The device twin of the two-step. Both legs run, the second over the real
/// `0x0D` dispatch, and the release is asserted against a `STATE` read back
/// off the wire.
#[test]
fn device_a_valid_0d_release_releases_it() {
    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    c.token = c.get_pin_token(b"12345678", PERM_ACFG);
    let channel = c.mse();
    let lock_key = [0x5A; 32];
    let engage = engage_sub_params(AUT_ENABLE, &channel.wrap(&lock_key, [0x22; 12]));
    assert_eq!(c.config(&live_token(&c), &engage, &engage), OK);
    assert!(c.state().locked);

    let (status, _) = c.call(
        0x41,
        &unlock_request_with_token(&channel.wrap(&lock_key, [0x33; 12]), &live_token(&c)),
    );
    assert_eq!(status, OK, "UNLOCK over the device 0x41 path");
    let flags = c.state();
    assert!(flags.locked && flags.unlocked, "locked, and open for this power cycle");

    let release = release_sub_params(AUT_DISABLE);
    assert_eq!(
        c.config(&live_token(&c), &release, &release),
        OK,
        "an AUT_DISABLE with a valid MAC and an open seed must release"
    );
    let flags = c.state();
    assert!(!flags.locked, "STATE must now report locked: false");
    assert!(!flags.unlocked, "releasing clears the unlock flag as well");
}

/// `# a_bad_0d_mac_is_refused_and_changes_nothing` (device)
///
/// The same three refusal shapes as the host test, on the device. The
/// difference that matters and is *not* asserted as equal: on the device the
/// gate that refuses a wrong key is `authenticator_config_inner`'s own, over
/// `&data[s..e]`, and it charges the same three-strike counter the host does —
/// which is why the third strike's `0x34` is checked here.
#[test]
fn device_a_bad_0d_mac_is_refused_and_changes_nothing() {
    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    c.token = c.get_pin_token(b"12345678", PERM_ACFG);
    let channel = c.mse();
    let good = engage_sub_params(AUT_ENABLE, &channel.wrap(&[0xC0; 32], [0x44; 12]));

    // A MAC over different bytes than were sent.
    let other = engage_sub_params(AUT_ENABLE, &channel.wrap(&[0xC1; 32], [0x45; 12]));
    assert_eq!(
        c.config(&live_token(&c), &good, &other),
        PIN_AUTH_INVALID,
        "a MAC over bytes other than the ones sent must not authorise"
    );
    assert!(!c.state().locked, "and must not have engaged the lock");

    // A MAC under a key the device did not mint.
    let foreign = [0x7F; 32];
    assert_eq!(
        c.config(&foreign, &good, &good),
        PIN_AUTH_INVALID,
        "a MAC under a foreign key must not authorise"
    );
    assert!(!c.state().locked, "and must not have engaged the lock");

    // The counter is the app's existing durable three-strike latch
    // (`device_core::FidoApp::note_pin_auth_failure`, which latches at
    // `auth_failures >= 3`), not anything `vendor_lock` implements. Two
    // refusals have already been charged above — the wrong-bytes one and the
    // foreign-key one — so the *next* one is the third and must latch.
    //
    // Asserting the latch rather than just the last `0x33` is what makes this
    // a claim about **charging**: an arm that refused without counting would
    // answer `0x33` here, and "a bad-MAC refusal that did not move the
    // counter" is exactly the bug the latch exists to stop. The final
    // assertion is the other half — once latched, a *correct* MAC under the
    // app's own token is refused too, which is the latch and not a signature
    // failure. Without it, an implementation that answered `0x34` for its own
    // reasons would pass.
    assert_eq!(
        c.config(&foreign, &good, &good),
        PIN_AUTH_BLOCKED,
        "the third charged refusal must answer PIN_AUTH_BLOCKED, not \
         PIN_AUTH_INVALID"
    );
    assert_eq!(
        c.config(&live_token(&c), &good, &good),
        PIN_AUTH_BLOCKED,
        "and a *correct* MAC under the app's own token is refused too, which is \
         the latch and not a signature failure"
    );
    assert!(!c.state().locked, "no attempt in this test may have engaged the lock");
}

/// `# the_arms_are_unreachable_without_a_0x20_token` (device)
///
/// A `CREDENTIAL_MANAGEMENT` token (0x04) and a legacy `getPinToken` (0x05,
/// permissions `0`) must both be refused — and here the refusal comes from
/// `authenticator_config_inner`'s own `PERM_ACFG` check
/// (`device_core.rs:2712`), which returns `PinAuthInvalid` before the sub-
/// command `match`. Asserting the lock is still unset is the half that
/// matters: a check that refused *after* dispatch would still be a check that
/// ran.
#[test]
fn device_the_arms_are_unreachable_without_a_0x20_token() {
    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    let channel = c.mse();
    let sub = engage_sub_params(AUT_ENABLE, &channel.wrap(&[0xC0; 32], [0x55; 12]));

    let cm = c.get_pin_token(b"12345678", 0x04);
    assert_eq!(
        c.config(&cm, &sub, &sub),
        PIN_AUTH_INVALID,
        "a CREDENTIAL_MANAGEMENT token must not engage the lock"
    );
    let legacy = c.get_pin_token(b"12345678", 0x00);
    assert_eq!(
        c.config(&legacy, &sub, &sub),
        PIN_AUTH_INVALID,
        "a permissions-0 token must not engage the lock"
    );
    assert!(!c.state().locked, "neither may have engaged the lock");
}

/// `# a_vendorff_id_still_reaches_its_own_arm` (device)
///
/// The dispatch-order check on the device, and the one that has a history:
/// the device `0xFF` arm recognises the lock ids with a **private** selector
/// (`device_core::rs_key_lock_id`) before handing off to `vendorff`, and a
/// first cut of that selector returned *any* key-1 unsigned integer. That
/// diverted every `vendorff` id to `config_vendor_lock`, whose default arm
/// answers `InvalidParameter`, and this test is what caught it — the
/// equivalent host test could not have, because the host `match` is written
/// with literal constant patterns and cannot over-match.
#[test]
fn device_a_vendorff_id_still_reaches_its_own_arm() {
    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    c.token = c.get_pin_token(b"12345678", PERM_ACFG);
    let mut sub: HV<u8, 32> = HV::new();
    nh::push_map_header(&mut sub, 2).unwrap();
    nh::push_uint(&mut sub, VENDOR_SUB_PARAM_ID).unwrap();
    nh::push_uint(&mut sub, fapico2_fido::vendorff::LED_GPIO).unwrap();
    nh::push_uint(&mut sub, 0x03).unwrap();
    nh::push_uint(&mut sub, 15).unwrap();
    let sub = sub.to_vec();

    assert_eq!(
        c.config(&live_token(&c), &sub, &sub),
        OK,
        "a PhysicalLedGpio write must still be accepted by the device 0xFF arm"
    );
    assert_eq!(
        c.app.keystore().phy.led_gpio,
        Some(15),
        "and must still persist the value that arm exists to persist"
    );
    assert!(!c.state().locked, "a physical-config write is not a lock engage");
}

/// `# the_host_and_the_device_answer_the_same_bytes_the_same_way` (host +
/// device)
///
/// The parity test, and the reason the section runs on both stacks at all.
///
/// It sends **the same four `0x0D` requests** — engage, release, engage under
/// a foreign key, engage under a `0x04` token — to both, through their own
/// dispatch, and asserts the four status bytes match. What it is really
/// asserting is that the two `0x0D` handlers have not drifted: they are
/// separate functions in separate files with separate gates, and the host one
/// MACs a **re-encoding** while the device one MACs the client's bytes, so
/// "the same input gives the same output" is a claim that needs making on
/// every change rather than once.
///
/// The four chosen are exactly the four where the host and the device *could*
/// differ and currently do not. The one where they genuinely differ — the
/// permission failure, `0x33` from the host's pre-`match` check and `0x33`
/// from the device's pre-`match` check — is included precisely because it is
/// the case that would have drifted silently had either check been moved.
#[test]
fn host_and_device_answer_the_same_0d_requests_the_same_way() {
    let lock_key = [0x5A; 32];

    // ---- host ----
    let (mut host, client) = common::setup();
    let token: [u8; 32] =
        <[u8; 32]>::try_from(&client.get_token(&mut host, 0x09, Some(PERM_ACFG), None).unwrap()[..32])
            .unwrap();
    let host_channel = host_mse(&mut host);
    let host_engage = engage_sub_params(AUT_ENABLE, &host_channel.wrap(&lock_key, [0x77; 12]));
    let host_release = release_sub_params(AUT_DISABLE);
    let host_ok_engage = host_config(&mut host, &token, &host_engage, &host_engage);
    let (status, _) =
        host_rskey(&mut host, &unlock_request_with_token(&host_channel.wrap(&lock_key, [0x78; 12]), &token));
    assert_eq!(status, OK, "host UNLOCK");
    let host_ok_release = host_config(&mut host, &token, &host_release, &host_release);
    let host_bad_key = host_config(&mut host, &[0x7F; 32], &host_engage, &host_engage);
    // The wrong-permission leg has to come **last** on the host, and for a
    // structural reason rather than a stylistic one: `get_token` *replaces*
    // the app's live `pin_token`, and `authenticator_config` reads the live
    // one — so a request under a `0x04` token is only a `0x04` request if the
    // `0x04` token is the one the app is holding. Minting it earlier would
    // have silently turned the three legs above into `0x04` requests too.
    let host_cm: [u8; 32] =
        <[u8; 32]>::try_from(&client.get_token(&mut host, 0x09, Some(0x04), None).unwrap()[..32])
            .unwrap();
    let host_wrong_perm = host_config(&mut host, &host_cm, &host_engage, &host_engage);

    // ---- device ----
    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    let cm = c.get_pin_token(b"12345678", 0x04);
    c.token = c.get_pin_token(b"12345678", PERM_ACFG);
    let channel = c.mse();
    let dev_engage = engage_sub_params(AUT_ENABLE, &channel.wrap(&lock_key, [0x77; 12]));
    let dev_release = release_sub_params(AUT_DISABLE);
    let dev_ok_engage = c.config(&live_token(&c), &dev_engage, &dev_engage);
    let (status, _) = c.call(
        0x41,
        &unlock_request_with_token(&channel.wrap(&lock_key, [0x78; 12]), &live_token(&c)),
    );
    assert_eq!(status, OK, "device UNLOCK");
    let dev_ok_release = c.config(&live_token(&c), &dev_release, &dev_release);
    let dev_bad_key = c.config(&[0x7F; 32], &dev_engage, &dev_engage);
    let dev_wrong_perm = c.config(&cm, &dev_engage, &dev_engage);

    assert_eq!(host_ok_engage, dev_ok_engage, "engage status");
    assert_eq!(host_ok_release, dev_ok_release, "release status");
    assert_eq!(host_bad_key, dev_bad_key, "engage under a foreign key");
    assert_eq!(
        host_wrong_perm, dev_wrong_perm,
        "engage under a 0x04 token — the one leg both stacks refuse, from \
         their own pre-`match` PERM_ACFG checks, and the two are separate \
         functions in separate files"
    );
    assert_eq!(OK, host_ok_engage, "sanity: a valid engage is accepted on both");
    assert_eq!(OK, host_ok_release, "sanity: a valid release is accepted on both");
    assert_eq!(PIN_AUTH_INVALID, host_bad_key, "sanity: a foreign key is refused on both");
    assert_eq!(PIN_AUTH_INVALID, host_wrong_perm, "sanity: a 0x04 token is refused on both");
}

/// `# a_vendorff_id_does_not_engage_a_lock_on_either_stack` (host + device)
///
/// The reverse of the previous dispatch-order test, and the one that says the
/// two id sets are not merely *equal* but *separated*: on each stack, a
/// `vendorff` id drives its own arm to a `0x00` and leaves `locked` false.
///
/// It is a separate test rather than an extra assertion on the two above
/// because the thing being pinned is the **cross-stack** claim — that neither
/// stack routes a pico-fido id into a RS-Key arm — and a per-stack assertion
/// cannot express "neither" as a single thing.
#[test]
fn a_vendorff_id_does_not_engage_a_lock_on_either_stack() {
    use fapico2_fido::keystore::Keystore as _;
    let mut sub: HV<u8, 32> = HV::new();
    nh::push_map_header(&mut sub, 2).unwrap();
    nh::push_uint(&mut sub, VENDOR_SUB_PARAM_ID).unwrap();
    nh::push_uint(&mut sub, fapico2_fido::vendorff::VIDPID).unwrap();
    nh::push_uint(&mut sub, 0x03).unwrap();
    nh::push_uint(&mut sub, 0x0001_C000 | 0x0002_0000).unwrap();
    let sub = sub.to_vec();

    let (mut host, token) = host_app_with_acfg_token();
    assert_eq!(host_config(&mut host, &token, &sub, &sub), OK, "host vid/pid write");
    assert_eq!(host.keystore().get_auth_state().phy.vid_pid, Some(0x0001_C000 | 0x0002_0000));
    assert!(!host_state(&mut host).locked, "host: a vid/pid write is not a lock engage");

    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    c.token = c.get_pin_token(b"12345678", PERM_ACFG);
    assert_eq!(c.config(&live_token(&c), &sub, &sub), OK, "device vid/pid write");
    assert_eq!(c.app.keystore().phy.vid_pid, Some(0x0001_C000 | 0x0002_0000));
    assert!(!c.state().locked, "device: a vid/pid write is not a lock engage");
}

/// `# a_non_canonical_engage_is_refused_on_the_device_and_never_reaches_the_host` (host + device)
///
/// The one place the two stacks are documented to **differ**, asserted rather
/// than glossed.
///
/// `app.rs::authenticator_config` builds the `0x0D` MAC message from
/// `cbor::encode(params)` — a **re-encoding** of a map it decoded
/// (`app.rs:1974`). The re-encoding sorts keys and rewrites every head
/// canonically, so a request whose params carry a legal non-minimal byte-string
/// head is MAC'd by the client over bytes the host does not reconstruct. The
/// host therefore answers `0x33` in `authenticator_config` **before**
/// `cfg_vendor_prototype` is entered, and the module's own
/// span-preserving verification never runs.
///
/// The device MACs `&data[s..e]` — the client's own bytes — so it accepts
/// the same request. That is the *correct* behaviour and it is the reason
/// `vendor_lock.rs` has its own `verify_config_vendor_mac` rather than
/// reusing `vendor41::verify_mac`.
///
/// Both halves are asserted, and the asymmetry is the point: if a future edit
/// "fixes" the host to re-encode differently, or the device to re-encode at
/// all, this test is what notices. It is also the concrete form of the
/// limitation reported alongside the wiring — the host cannot currently reach
/// a non-canonical `0xFF` request at all, which is harmless for PicoForge
/// (whose params are a `BTreeMap` the `cbor` crate serialised canonically)
/// and is a real limitation for anyone who is not.
#[test]
fn a_non_canonical_engage_is_refused_on_the_host_and_accepted_on_the_device() {
    let lock_key = [0xC0; 32];

    // ---- device: the client's own bytes are what is MAC'd ----
    let mut c = DeviceClient::boot();
    c.set_pin(b"12345678");
    c.token = c.get_pin_token(b"12345678", PERM_ACFG);
    let channel = c.mse();
    let blob = channel.wrap(&lock_key, [0x88; 12]);
    let canonical = engage_sub_params(AUT_ENABLE, &blob);
    // MAC the **canonical** form, send the non-canonical one. A device that
    // re-encodes would answer 0x33; a device that MACs the wire span answers
    // 0x00, which is the whole claim.
    let non_canonical = engage_sub_params_non_canonical(AUT_ENABLE, &blob);
    assert_ne!(
        non_canonical, canonical,
        "the two serialisations must actually differ in bytes, or this test \
         is asserting nothing"
    );
    // The client signs the bytes it is about to send, non-canonical head and
    // all. A device that MACs the wire span verifies it; a device that
    // re-encodes reconstructs different bytes and answers `0x33`.
    assert_eq!(
        c.config(&live_token(&c), &non_canonical, &non_canonical),
        OK,
        "the device MACs the client's own bytes, so a legal non-minimal head \
         still verifies"
    );
    assert!(c.state().locked, "and the lock is engaged");

    // ---- host: a re-encoding cannot match, and the refusal is upstream ----
    let (mut host, token) = host_app_with_acfg_token();
    let host_channel = host_mse(&mut host);
    let host_blob = host_channel.wrap(&lock_key, [0x88; 12]);
    let host_non_canonical = engage_sub_params_non_canonical(AUT_ENABLE, &host_blob);
    assert_eq!(
        host_config(&mut host, &token, &host_non_canonical, &host_non_canonical),
        PIN_AUTH_INVALID,
        "the host re-encodes the params before MACing, so a non-minimal head \
         cannot verify — the refusal happens in authenticator_config, before \
         cfg_vendor_prototype, and is the documented host limitation"
    );
    assert!(
        !host_state(&mut host).locked,
        "and the host must not have engaged the lock from a request it could \
         not authenticate"
    );
}
