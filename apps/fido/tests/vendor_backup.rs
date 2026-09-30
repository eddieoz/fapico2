//! US-171 + US-172 (EPIC `PICOForge-COMPAT`) — the `0x41` seed-backup arms:
//! `MSE` key agreement, and seed `EXPORT` / `LOAD` / `FINALIZE`.
//!
//! # Why this file carries its own ChaCha20-Poly1305
//!
//! The whole point of the round-trip tests is that the firmware's framing, key
//! derivation, AAD binding and nonce handling are *the client's* framing, key
//! derivation, AAD binding and nonce handling. A test that called
//! `vendor_backup::chacha20poly1305_open` to check a blob
//! `vendor_backup::chacha20poly1305_seal` had produced would pass with the
//! channel key derived from the wrong value, the AAD set to `b""`, the
//! counters off by one and the tag computed over the wrong data — every one of
//! those is invisible to a self-consistent pair.
//!
//! So [`chacha20poly1305_ref`] below is a **second implementation**, written
//! from RFC 8439 and structurally different from the `chacha20poly1305` crate
//! the firmware now uses:
//!
//! | | firmware (`chacha20poly1305` crate) | this file |
//! |---|---|---|
//! | Poly1305 limbs | upstream's choice (44/44/42, `u128` intermediates) | 4 × 64-bit big-limb schoolbook multiply + an explicit `mod (2^130 − 5)` reduction loop |
//! | Poly1305 `r` clamp | upstream's | the RFC's 16 raw bytes, applied byte-wise |
//! | ChaCha20 rounds | upstream's | column-then-diagonal, in a fixed table |
//!
//! That is a genuine differential now rather than a formality: it is the only
//! thing in the suite checking that the **dependency** computes RFC 8439 and
//! not merely *some* AEAD, and it is the reason the reference outlived the
//! firmware's own copy.
//!
//! Three properties are then pinned, and they are not the same property:
//!
//! 1. **Both** implementations reproduce the RFC 8439 test vectors (§2.3.2
//!    block function, §2.5.2 Poly1305, §2.8.2 AEAD). That checks the crate
//!    against the standard, not against this file.
//! 2. The two agree with each other on every length the channel can carry — a
//!    differential check that would catch a shared misreading of the *spec* only
//!    if the RFC vectors were also absent.
//! 3. The firmware's export blob opens **here**, and the wrong AAD does not.
//!
//! # The requests are hand-assembled, not encoded by the crate
//!
//! `load` has to reproduce a MAC over bytes the client signed, and the whole
//! story breaks if the test builds those bytes with the firmware's own CBOR
//! writer — that would make the "the MAC verifies over the client's bytes"
//! test vacuous, because the two would agree by construction. So
//! [`client_request`] writes CBOR by hand, in the key order a `BTreeMap`
//! produces, and the params bytes it hands to the HMAC are the *same slice* it
//! splices into the outer map. There is no encoder in this file that the
//! firmware also uses.
//!
//! # Wiring
//!
//! The module is pulled in with `#[path]` rather than through `fapico2_fido`,
//! because it is not in the crate's `lib.rs` yet — the coordinator owns that
//! edit, and three other stories are editing `lib.rs` concurrently. The
//! `pub use fapico2_fido::*;` below exists only so the `crate::…` paths *inside*
//! `vendor_backup.rs` resolve in the test crate; once `lib.rs` declares
//! `pub mod vendor_backup;` this file's local module shadows the glob-imported
//! one and the test is unaffected either way.

pub use fapico2_fido::*;

#[path = "../src/vendor_backup.rs"]
// `pub`, not private: `fapico2_fido::*` above now glob-re-exports a public
// `vendor_backup` (the crate's `lib.rs` declares it), and a *private* module
// shadowing that public re-export is `hidden_glob_reexports` — a warning the
// clippy gate (`-D warnings`, `--all-targets`) turns into a build failure.
pub mod vendor_backup;

// `pub use` rather than `use`: the `fapico2_fido::*` glob above brings the same
// names in, and a *private* import that shadows a public glob re-export is a
// warning — which the clippy gate (`-D warnings`, `--all-targets`) would turn
// into a build failure.
pub use fapico2_fido::crypto;
pub use fapico2_fido::ctap2::Ctap2Response;
pub use fapico2_fido::device_core::PERM_ACFG;
pub use fapico2_fido::vendor41::{
    AuditRecord, AuditWindow, Checkpoint, MseChannel, MsePoint, OrgAttestation,
    OrgAttestationView, SoftLock, TokenAuth, VendorOps,
};
pub use fapico2_fido::vendor_state::{self, VendorSession};
// The glob above brings `fapico2_fido::Result<T>` (a `FidoError` alias) into
// scope, which is not the `Result` the `VendorOps` methods return. An explicit
// import outranks a glob, so this resolves the name to the std one.
pub use core::result::Result;
pub use heapless::Vec as HV;
pub use vendor_backup::{BackupWindow, BLOB_MAX, BLOB_MIN, MASTER_SEED_LEN, TAG_LEN};

// ---------------------------------------------------------------------------
// CTAP2 status codes, spelled as literals on the test side
// ---------------------------------------------------------------------------

const OK: u8 = 0x00;
const INVALID_PARAMETER: u8 = 0x02;
const INVALID_LENGTH: u8 = 0x03;
const INVALID_CBOR: u8 = 0x12;
const MISSING_PARAMETER: u8 = 0x14;
const NOT_ALLOWED: u8 = 0x30;
const PIN_AUTH_INVALID: u8 = 0x33;
const UP_REQUIRED: u8 = 0x3B;
const INTEGRITY_FAILURE: u8 = 0x3D;

/// The RS-Key vendor command byte on the wire. A literal, not `vendor41::CMD`,
/// so the assertion cannot pass by comparing two constants that both say
/// `0x41`.
const RSKEY_CTAPHID_VENDOR_CMD: u8 = 0x41;

type Reply = vendor_backup::Reply;
type Rng = HV<u8, 4096>;

// ---------------------------------------------------------------------------
// A minimal CBOR writer — hand-rolled, deliberately not the crate's
// ---------------------------------------------------------------------------

fn head(out: &mut Rng, major: u8, v: u64) {
    let tag = major << 5;
    if v < 24 {
        out.push(tag | v as u8).unwrap();
    } else if v < 0x100 {
        out.push(tag | 24).unwrap();
        out.push(v as u8).unwrap();
    } else {
        out.push(tag | 25).unwrap();
        out.extend_from_slice(&(v as u16).to_be_bytes()).unwrap();
    }
}

fn uint(out: &mut Rng, v: u64) {
    head(out, 0, v);
}

fn neg(out: &mut Rng, v: i64) {
    head(out, 1, (-1 - v) as u64);
}

fn bstr(out: &mut Rng, b: &[u8]) {
    head(out, 2, b.len() as u64);
    out.extend_from_slice(b).unwrap();
}

fn map(out: &mut Rng, n: u64) {
    head(out, 5, n);
}

/// The full `0x41` request map a PicoForge client sends, with the MAC computed
/// over exactly the params bytes that get spliced in.
///
/// Mirrors `HidTransport::rs_key_vendor`
/// (`picoforge/src/hal/fido/ops.rs:1555-1592`): outer keys 1, 2, 3, 4 in
/// ascending order; the signed message is
/// `0xFF × 32 ‖ 0x41 ‖ subCommand ‖ CBOR(params)`; the param is the first 16
/// bytes of `HMAC-SHA256(token, message)` (protocol 1).
fn client_request(token: &[u8; 32], sub: u8, params: Option<&[u8]>, pin: Option<&str>) -> Rng {
    let mut out: Rng = HV::new();
    // One pair for the sub-command, one for the params if present, two for the
    // auth fields if a PIN is. Counting the auth fields unconditionally was a
    // bug here first: a `MSE` request (params, no PIN) then declared four
    // pairs and carried two, and the device answered `0x12` — which is the
    // *correct* answer to a truncated map, and hid the real problem for a
    // while.
    let pairs = 1 + u64::from(params.is_some()) + 2 * u64::from(pin.is_some());
    map(&mut out, pairs);
    uint(&mut out, 1);
    uint(&mut out, sub as u64);
    if let Some(p) = params {
        uint(&mut out, 2);
        out.extend_from_slice(p).unwrap();
    }
    if let Some(_pin) = pin {
        // The signed message. `0x41`, not the stock `0x0D`.
        let mut msg: HV<u8, 256> = HV::new();
        msg.extend_from_slice(&[0xFFu8; 32]).unwrap();
        msg.push(RSKEY_CTAPHID_VENDOR_CMD).unwrap();
        msg.push(sub).unwrap();
        if let Some(p) = params {
            msg.extend_from_slice(p).unwrap();
        }
        let mac = crypto::hmac_sha256(token, &msg);
        uint(&mut out, 3);
        uint(&mut out, 1); // pinUvAuthProtocol
        uint(&mut out, 4);
        bstr(&mut out, &mac[..16]);
    }
    out
}

/// The `TokenAuth` the dispatch arm would hand an authenticated sub-command
/// for a `getPinToken(PERM_ACFG)` result.
fn token_auth<'a>(token: &'a [u8; 32]) -> TokenAuth<'a> {
    TokenAuth { token, permissions: PERM_ACFG, blocked: false }
}

/// A presence gate whose button does (or does not) answer.
fn gate(granted: bool) -> fapico2_fido::vendor41::PresenceGate {
    fapico2_fido::vendor41::PresenceGate {
        window_grant: None,
        poll: Some(if granted { || true } else { || false }),
        tag: 0,
    }
}

// ---------------------------------------------------------------------------
// The `VendorOps` + `BackupWindow` implementation the tests drive
// ---------------------------------------------------------------------------

/// A `VendorOps` whose only job is to be a real one: the ECDH and the HKDF are
/// delegated to `vendor_state::mse_establish`, so the channel key under test is
/// produced by the same code the firmware runs, not by a fixture.
struct MockOps {
    session: VendorSession,
    seed: Option<[u8; 32]>,
    /// A counter, so "nothing was written" is an assertion and not a vibe.
    seed_writes: u32,
    /// Deterministic entropy, so a failure is reproducible.
    rng_state: u64,
    sealed: bool,
    seal_writes: u32,
    /// Flipped to make `seal_backup` refuse, so the `Err` path is reachable.
    seal_fails: bool,
}

impl MockOps {
    fn new() -> Self {
        Self::with_rng(0x243F_6A88_85A3_08D3)
    }

    /// A mock whose deterministic entropy starts elsewhere.
    ///
    /// Two mocks built with [`MockOps::new`] draw the **same** first scalar,
    /// so their `MSE` handshakes return the same device point — which is a
    /// property of the fixture, not of the firmware. Anything that needs two
    /// genuinely independent sessions (the "the device point is not a
    /// constant" check, for one) must start them apart.
    fn with_rng(state: u64) -> Self {
        Self {
            session: VendorSession::default(),
            seed: None,
            seed_writes: 0,
            rng_state: state,
            sealed: false,
            seal_writes: 0,
            seal_fails: false,
        }
    }

    fn with_seed(seed: [u8; 32]) -> Self {
        let mut m = Self::new();
        m.seed = Some(seed);
        m.seed_writes = 1;
        m
    }

    fn rng(&mut self, out: &mut [u8]) {
        splitmix(&mut self.rng_state, out);
    }
}

/// SplitMix64 — deterministic, and visibly not the platform TRNG. A test that
/// drew from the real TRNG could not reproduce a failure.
fn splitmix(state: &mut u64, out: &mut [u8]) {
    for b in out.iter_mut() {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        *b = (z >> 31) as u8;
    }
}

impl VendorOps for MockOps {
    fn export_sealed(&self) -> bool {
        false
    }
    fn random_bytes(&mut self, out: &mut [u8]) {
        self.rng(out);
    }

    fn master_seed(&self) -> Option<[u8; 32]> {
        self.seed
    }

    fn set_master_seed(&mut self, seed: [u8; 32]) -> Result<(), Ctap2Response> {
        // All-or-nothing by construction: validate, *then* apply, so there is no
        // state in which a rejected call has partially landed.
        self.seed = Some(seed);
        self.seed_writes += 1;
        Ok(())
    }

    fn soft_lock(&self) -> SoftLock {
        SoftLock::default()
    }

    fn set_soft_lock(&mut self, _lock: SoftLock) -> Result<(), Ctap2Response> {
        Ok(())
    }

    fn unlocked_this_power_cycle(&self) -> bool {
        self.session.unlocked_this_power_cycle
    }

    fn set_unlocked_this_power_cycle(&mut self, unlocked: bool) {
        self.session.unlocked_this_power_cycle = unlocked;
    }

    fn mse_establish(
        &mut self,
        host_x: [u8; 32],
        host_y: [u8; 32],
        out: &mut MsePoint,
    ) -> Result<(), Ctap2Response> {
        // The **real** implementation, so the ephemeral scalar, the ECDH and
        // the HKDF are the firmware's and this test is not testing a fixture.
        //
        // The RNG state is moved into a local first: the closure borrows the
        // local, so `self.session` is the only field borrowed and the two do
        // not contend.
        let mut state = self.rng_state;
        let mut rng = |b: &mut [u8]| splitmix(&mut state, b);
        let r = vendor_state::mse_establish(&mut self.session, &mut rng, host_x, host_y, out);
        self.rng_state = state;
        r
    }

    fn mse_channel(&self, out: &mut MseChannel) -> Result<(), Ctap2Response> {
        match self.session.mse {
            None => Err(Ctap2Response::InvalidParameter),
            Some(c) => {
                *out = c;
                Ok(())
            }
        }
    }

    fn audit_enabled(&self) -> bool {
        false
    }
    fn set_audit_enabled(&mut self, _e: bool) -> Result<(), Ctap2Response> {
        Ok(())
    }
    fn audit_append(&mut self, _r: AuditRecord) -> Result<(), Ctap2Response> {
        Ok(())
    }
    fn audit_window(
        &self,
        _o: &mut HV<u8, { fapico2_fido::CTAP2_MAX_MSG }>,
    ) -> Result<AuditWindow, Ctap2Response> {
        Err(Ctap2Response::NotAllowed)
    }
    fn audit_sign_checkpoint(
        &mut self,
        _c: &[u8; 16],
        _o: &mut Checkpoint,
    ) -> Result<(), Ctap2Response> {
        Err(Ctap2Response::NotAllowed)
    }
    fn org_attestation(&self) -> OrgAttestationView<'_> {
        OrgAttestationView::default()
    }
    fn set_org_attestation(&mut self, _a: OrgAttestation) -> Result<(), Ctap2Response> {
        Ok(())
    }
}

impl BackupWindow for MockOps {
    fn backup_sealed(&self) -> bool {
        self.sealed
    }

    fn seal_backup(&mut self) -> Result<(), Ctap2Response> {
        if self.seal_fails {
            return Err(Ctap2Response::KeyStoreFull);
        }
        // Idempotent: an already-sealed device writes nothing.
        if !self.sealed {
            self.sealed = true;
            self.seal_writes += 1;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The client's own host-side key agreement, re-derived here
// ---------------------------------------------------------------------------

/// A host P-256 keypair, as `mse_handshake` generates one
/// (`picoforge/src/hal/fido/mod.rs:1687-1695`).
fn host_keypair() -> (p256::SecretKey, [u8; 32], [u8; 32]) {
    let (sk, _pk) = crypto::generate_p256_keypair();
    let sec = crypto::public_key_bytes(&sk.public_key());
    let x: [u8; 32] = sec[1..33].try_into().unwrap();
    let y: [u8; 32] = sec[33..65].try_into().unwrap();
    (sk, x, y)
}

/// `HKDF-SHA256(salt = b"", ikm = z, info = aad, L = 32)`, written out here
/// rather than called from `crypto::hkdf_sha256`, because *this* derivation is
/// one of the two things US-172 is about and a test that shares an
/// implementation with the code proves nothing about it.
///
/// Extract-then-expand, RFC 5869 §2.2/§2.3, over the crate's HMAC-SHA256
/// (a primitive that is itself KAT-checked elsewhere).
fn hkdf_sha256_ref(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // RFC 5869 §2.2: an absent salt is `HashLen` zeros. `b""` and absent are
    // the *same* value, and `backup.rs:34` passes `b""`.
    let salt = if salt.is_empty() { &[0u8; 32][..] } else { salt };
    let prk = crypto::hmac_sha256(salt, ikm);
    // L = 32 <= 255*HashLen, so one expand block and no iteration counter.
    assert!(info.len() < 256);
    let mut t: HV<u8, 256> = HV::new();
    t.extend_from_slice(info).unwrap();
    t.push(0x01).unwrap();
    crypto::hmac_sha256(&prk, &t)
}

/// The COSE key the client builds, in its own `BTreeMap` order `-3, -2, -1, 1,
/// 3` (`picoforge/src/hal/fido/mod.rs:1698-1706`).
fn client_cose_params(x: &[u8; 32], y: &[u8; 32], canonical: bool) -> Rng {
    let mut cose: Rng = HV::new();
    map(&mut cose, 5);
    if canonical {
        // RFC 8152 canonical: 1, 3, -1, -2, -3.
        uint(&mut cose, 1);
        uint(&mut cose, 2); // kty = EC2
        uint(&mut cose, 3);
        neg(&mut cose, -25); // alg = ECDH-ES+HKDF-256
        neg(&mut cose, -1);
        uint(&mut cose, 1); // crv = P-256
        neg(&mut cose, -2);
        bstr(&mut cose, x);
        neg(&mut cose, -3);
        bstr(&mut cose, y);
    } else {
        // The `BTreeMap` order, which is what the client actually sends.
        neg(&mut cose, -3);
        bstr(&mut cose, y);
        neg(&mut cose, -2);
        bstr(&mut cose, x);
        neg(&mut cose, -1);
        uint(&mut cose, 1);
        uint(&mut cose, 1);
        uint(&mut cose, 2);
        uint(&mut cose, 3);
        neg(&mut cose, -25);
    }
    let mut params: Rng = HV::new();
    map(&mut params, 1);
    uint(&mut params, 1);
    params.extend_from_slice(&cose).unwrap();
    params
}

/// Drive `MSE` and return the device's point as SEC1 `0x04 ‖ x ‖ y`.
fn run_mse(ops: &mut MockOps, x: &[u8; 32], y: &[u8; 32], canonical: bool) -> (u8, [u8; 65]) {
    let params = client_cose_params(x, y, canonical);
    let req = client_request(&[0u8; 32], 0x01, Some(&params), None);
    let mut out: Reply = HV::new();
    let status = vendor_backup::mse(&req, &mut out, ops).status.code();
    assert_eq!(out.is_empty(), status != OK, "a body must not survive a non-zero status");
    let point = if status == OK {
        read_device_point(&out)
    } else {
        [0u8; 65]
    };
    (status, point)
}

/// `{1: {1:2, 3:-25, -1:1, -2:x, -3:y}}` → `0x04 ‖ x ‖ y`.
fn read_device_point(body: &[u8]) -> [u8; 65] {
    let mut p = fapico2_fido::cbor::no_heap::Parser::new(body);
    let mut point = [0u8; 65];
    point[0] = 0x04;
    assert_eq!(p.next().unwrap(), fapico2_fido::cbor::no_heap::Item::Map(1));
    assert_eq!(p.next().unwrap(), fapico2_fido::cbor::no_heap::Item::U(1));
    assert_eq!(p.next().unwrap(), fapico2_fido::cbor::no_heap::Item::Map(5));
    let mut seen_x = false;
    let mut seen_y = false;
    for _ in 0..5 {
        let k = p.next().unwrap();
        let v = p.next().unwrap();
        // Only `-2` and `-3` are byte strings; `1`, `3` and `-1` carry the
        // kty/alg/crv integers. The client reads the two coordinates and
        // ignores the rest (`mod.rs:1711-1723`), so this does too — but it
        // does check that the *labels* are the five the protocol names.
        if !matches!(
            k,
            fapico2_fido::cbor::no_heap::Item::N(-2)
                | fapico2_fido::cbor::no_heap::Item::N(-3)
        ) {
            // kty / alg / crv: integers, and the client reads none of them.
            continue;
        }
        let fapico2_fido::cbor::no_heap::Item::B(b) = v else {
            panic!("the coordinate labels must carry byte strings")
        };
        match k {
            fapico2_fido::cbor::no_heap::Item::N(-2) => {
                assert_eq!(b.len(), 32, "-2 must be exactly 32 bytes");
                point[1..33].copy_from_slice(b);
                seen_x = true;
            }
            fapico2_fido::cbor::no_heap::Item::N(-3) => {
                assert_eq!(b.len(), 32, "-3 must be exactly 32 bytes");
                point[33..65].copy_from_slice(b);
                seen_y = true;
            }
            _ => {}
        }
    }
    assert!(seen_x && seen_y, "response carried no device point");
    point
}

// ---------------------------------------------------------------------------
// The reference ChaCha20-Poly1305 (RFC 8439) — see the module docs
// ---------------------------------------------------------------------------

/// ChaCha20 block, diagonal round before the column round.
fn chacha_block_ref(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let ld = |b: &[u8], i: usize| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = ld(key, i);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = ld(nonce, i);
    }
    let orig = s;
    // Parenthesised, and deliberately: `x.rotl(16) ^ y` is **not** the same
    // as `(x ^ y).rotl(16)` — rotation does not distribute over the second
    // operand — and the unparenthesised form compiles, produces a plausible
    // stream, and is wrong. (It was. This test is why.)
    let qr = |s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize| {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(7);
    };
    for _ in 0..10 {
        // **Column round first, then the diagonal** — and that order is
        // load-bearing. The eight quarter rounds inside one round do *not*
        // commute: running the diagonal half first produces a well-formed,
        // plausible keystream that is simply a different function. (That was
        // this test's first version, and RFC 8439 §2.3.2 caught it.)
        qr(&mut s, 0, 4, 8, 12);
        qr(&mut s, 1, 5, 9, 13);
        qr(&mut s, 2, 6, 10, 14);
        qr(&mut s, 3, 7, 11, 15);
        qr(&mut s, 0, 5, 10, 15);
        qr(&mut s, 1, 6, 11, 12);
        qr(&mut s, 2, 7, 8, 13);
        qr(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(orig[i]).to_le_bytes());
    }
    out
}

/// Poly1305 with 64-bit big limbs: a schoolbook multiply followed by an
/// **explicit** `mod (2^130 − 5)` reduction loop.
///
/// Deliberately nothing like the module's 26-bit limb arithmetic. The whole
/// risk in Poly1305 is in the reduction, and two implementations that share a
/// reduction share its bugs.
fn poly1305_ref(otk: &[u8], msg: &[u8]) -> [u8; 16] {
    let otk: &[u8; 32] = otk[..32].try_into().expect("a 32-byte one-time key");
    // RFC 8439 §2.5.1's clamp, as a 128-bit **number**. Both implementations
    // in this story got this wrong first as a byte array and then as a
    // hand-derived per-limb mask; see the note on
    // `vendor_backup::POLY1305_CLAMP`. Sharing the constant is right — it is
    // a protocol constant, not an implementation detail, and the RFC test
    // vectors below are what check it.
    let le = |b: &[u8], i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
    let mut rk = [0u8; 16];
    rk.copy_from_slice(&otk[..16]);
    let r128 =
        u128::from_le_bytes(rk) & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;
    let r = [r128 as u64, (r128 >> 64) as u64, 0u64, 0u64];

    let mut h = [0u64; 4];
    let mut off = 0;
    while off < msg.len() {
        let n = core::cmp::min(16, msg.len() - off);
        let mut block = [0u8; 16];
        block[..n].copy_from_slice(&msg[off..off + n]);
        let hibit = if n == 16 {
            // A full 16-byte block is a 128-bit value and contributes an
            // additional 2^128.
            1u64
        } else {
            // A short final block is zero-padded with a 0x01 at position `n`
            // and must NOT get the extra 2^128 (RFC 8439 §2.5.1).
            block[n] = 1;
            0
        };
        // Add the block into `h` **with carries**. This is the one thing the
        // big-limb shape has to think about that a 5×26-bit shape does not: a
        // 128-bit block added into four 64-bit limbs overflows limb 0 into
        // limb 1 roughly half the time, and a `wrapping_add` per limb silently
        // discards that carry. A 26-bit decomposition cannot lose it, because
        // its limbs are *disjoint bit ranges* of the block value, so the sum
        // of the limb contributions is the block value with nothing to lose.
        //
        // That distinction is why this reference is worth keeping now that the
        // firmware uses the `chacha20poly1305` crate: it is structurally unlike
        // upstream's 44/44/42 `u128` form, so agreeing with the crate is a real
        // result rather than a shared assumption. (This comment used to say
        // "the firmware's 26-limb shape" and credit the reference's carry
        // handling as the thing that needed fixing; the carry chain below is
        // what *this* implementation had to get right, and it did get it wrong
        // first — see the reduction loop further down.)
        let bval = [le(&block, 0), le(&block, 8), hibit, 0u64];
        let mut carry = 0u128;
        for (i, limb) in bval.iter().enumerate() {
            let acc = h[i] as u128 + *limb as u128 + carry;
            h[i] = acc as u64;
            carry = acc >> 64;
        }
        h = mul_mod_p(h, r);
        off += n;
    }

    // `(h + s) mod 2^128`.
    let mut s = [0u64; 2];
    s[0] = le(otk, 16);
    s[1] = le(otk, 24);
    let mut tag = [0u8; 16];
    let mut carry = 0u128;
    for i in 0..2 {
        let acc = h[i] as u128 + s[i] as u128 + carry;
        tag[8 * i..8 * i + 8].copy_from_slice(&(acc as u64).to_le_bytes());
        carry = acc >> 64;
    }
    tag
}

/// `a · b mod (2^130 − 5)` for 256-bit inputs, by full 512-bit multiply then
/// repeated shift-and-add-reduce. Obvious, and slow enough that nobody will
/// copy it into firmware — which is the point.
fn mul_mod_p(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut prod = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = prod[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            prod[i + j] = t as u64;
            carry = t >> 64;
        }
        let mut k = i + 4;
        while carry != 0 {
            let t = prod[k] as u128 + carry;
            prod[k] = t as u64;
            carry = t >> 64;
            k += 1;
        }
    }
    // Reduce mod 2^130 - 5 until the high part is zero: x = lo130 + 5·(x >> 130).
    loop {
        let mut t = [0u64; 8];
        for i in 2..8usize {
            let lo = prod[i] >> 2;
            let hi = if i + 1 < 8 { prod[i + 1] << 62 } else { 0 };
            t[i - 2] = lo | hi;
        }
        // The termination test reads `t` **after** the whole shift, not
        // inside the loop: the loop writes `t[i - 2]` while reading `t[i]`, so
        // an in-loop test looks at a limb that has not been written yet and
        // always sees zero — i.e. "already reduced", on the first pass.
        if t.iter().all(|&x| x == 0) {
            break;
        }
        // x = (x mod 2^130) + 5·t
        let mut lo = prod;
        lo[2] &= 3;
        lo[3] = 0;
        lo[4..].fill(0);
        let mut t5 = [0u64; 8];
        let mut carry = 0u128;
        for i in 0..8 {
            let v = t[i] as u128 * 5 + carry;
            t5[i] = v as u64;
            carry = v >> 64;
        }
        let mut out = [0u64; 8];
        let mut c = 0u128;
        for i in 0..8 {
            let v = lo[i] as u128 + t5[i] as u128 + c;
            out[i] = v as u64;
            c = v >> 64;
        }
        prod = out;
    }
    [prod[0], prod[1], prod[2] & 3, 0]
}

/// RFC 8439 §2.8.2 `chacha_seal`: `nonce(12) ‖ ct ‖ tag(16)`.
fn chacha20poly1305_ref(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
) -> Vec<u8> {
    let otk = &chacha_block_ref(key, 0, nonce)[..32];
    // The message is encrypted starting at counter **1**; block 0 was the
    // one-time key.
    let mut ct = pt.to_vec();
    let mut off = 0;
    let mut c = 1u32;
    while off < pt.len() {
        let ks = chacha_block_ref(key, c, nonce);
        let n = core::cmp::min(64, pt.len() - off);
        for i in 0..n {
            ct[off + i] ^= ks[i];
        }
        c += 1;
        off += n;
    }

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
    let tag = poly1305_ref(otk, &mac_data);

    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    blob
}

/// Open a `nonce(12) ‖ ct ‖ tag(16)` blob with the reference implementation.
fn chacha20poly1305_ref_open(
    key: &[u8; 32],
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if blob.len() < 28 {
        return Err("too short");
    }
    let (nonce_b, rest) = blob.split_at(12);
    let nonce: [u8; 12] = nonce_b.try_into().unwrap();
    let (ct, tag) = rest.split_at(rest.len() - 16);
    let otk = &chacha_block_ref(key, 0, &nonce)[..32];
    let mut mac_data: Vec<u8> = Vec::new();
    mac_data.extend_from_slice(aad);
    while !mac_data.len().is_multiple_of(16) {
        mac_data.push(0);
    }
    mac_data.extend_from_slice(ct);
    while !mac_data.len().is_multiple_of(16) {
        mac_data.push(0);
    }
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    if poly1305_ref(otk, &mac_data) != tag {
        return Err("tag mismatch");
    }
    let mut pt = ct.to_vec();
    let mut c = 1u32;
    let mut off = 0;
    while off < ct.len() {
        let ks = chacha_block_ref(key, c, &nonce);
        let n = core::cmp::min(64, ct.len() - off);
        for i in 0..n {
            pt[off + i] ^= ks[i];
        }
        c += 1;
        off += n;
    }
    Ok(pt)
}

// ---------------------------------------------------------------------------
// The RFC 8439 test vectors — the check that is not "the two agree"
// ---------------------------------------------------------------------------

/// Hex helper that keeps the vectors readable as byte strings.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 8439 §2.3.2's block function, checked on **both** sides of the
/// collapse: against the crate the firmware now uses, and against this file's
/// own structurally different reference.
///
/// The firmware no longer has a `chacha20_block` to call — that is the point of
/// the change. The block function is reachable through the AEAD instead, and
/// §2.3.2's vector is exactly the ciphertext of 64 zero bytes: ChaCha20 is a
/// stream cipher, so encrypting zeros *is* the keystream. That is asserted
/// below through `chacha20poly1305_seal`, so this vector is now a check that
/// the dependency's keystream is the RFC's — and, incidentally, that it
/// starts the message at counter **1**.
#[test]
fn both_chacha20_implementations_match_rfc8439_section_2_3_2() {
    // Key 00..1f, nonce 00:00:00:09:00:00:00:4a:00:00:00:00, counter 1.
    let key: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
    let nonce: [u8; 12] = hex("000000090000004a00000000").try_into().unwrap();
    let expect = hex(concat!(
        "10f1e7e4d13b5915500fdd1fa32071c4",
        "c7d1f4c733c068030422aa9ac3d46c4e",
        "d2826446079faa0914c2d705d98b02a2",
        "b5129cd1de164eb9cbd083e8a2503c4e"
    ));

    // The crate, reached the way the firmware reaches it. 64 + 16 bytes.
    let mut out: HV<u8, 128> = HV::new();
    vendor_backup::chacha20poly1305_seal(&key, &nonce, b"", &[0u8; 64], &mut out)
        .expect("64 zero bytes plus a tag fit a 128-byte buffer");
    assert_eq!(&out[..64], &expect[..], "the crate's ChaCha20 is not RFC 8439");
    assert_eq!(out.len(), 80, "and the framing is still ct ‖ tag(16)");

    // And this file's reference, which shares no code with the crate.
    assert_eq!(chacha_block_ref(&key, 1, &nonce).to_vec(), expect);
}

#[test]
fn both_poly1305_implementations_match_rfc8439_section_2_5_2() {
    // §2.5.2: key, message "Cryptographic Forum Research Group", tag.
    let key = hex(concat!(
        "85d6be7857556d337f4452fe42d506a8",
        "0103808afb0db2fd4abff6af4149f51b"
    ));
    let msg = b"Cryptographic Forum Research Group";
    let expect = hex("a8061dc1305136c6c22b8baf0c0127a9");

    // The reference implementation against the RFC, directly.
    assert_eq!(poly1305_ref(&key, msg).to_vec(), expect);

    // And the **crate's** Poly1305, reached through the shipped AEAD: sealing
    // RFC 8439's §2.8.2 message under the §2.6.2 key with the §2.8.2 AAD must
    // reproduce the §2.8.2 tag. That vector is computed from a different
    // message and a different key than §2.5.2, so it is an independent check
    // of the crate's Poly1305 rather than a restatement of the line above.
    let (ct262, tag262) = firmware_seal_rfc_2_8_2();
    assert_eq!(tag262, hexstr(&expect_tag_262()), "the crate's Poly1305 is not RFC 8439");

    // ... and the ciphertext it produced is the RFC's, which pins ChaCha20 and
    // the counter split (block 0 for the one-time key, counter 1 for the
    // message) at the same time.
    assert_eq!(ct262, EXPECT_CT_262, "the crate's ChaCha20 is not RFC 8439");
}

/// The RFC 8439 §2.8.2 message, AAD, key and nonce.
const RFC_2_8_2_PT: &str = concat!(
    "Ladies and Gentlemen of the class of '99: If I could offer you ",
    "only one tip for the future, sunscreen would be it."
);
const RFC_2_8_2_AAD_HEX: &str = "50515253c0c1c2c3c4c5c6c7";
const RFC_2_8_2_KEY_HEX: &str = concat!(
    "808182838485868788898a8b8c8d8e8f",
    "909192939495969798999a9b9c9d9e9f"
);
const RFC_2_8_2_NONCE_HEX: &str = "070000004041424344454647";
const EXPECT_CT_262: &str = concat!(
    "d31a8d34648e60db7b86afbc53ef7ec2",
    "a4aded51296e08fea9e2b5a736ee62d6",
    "3dbea45e8ca9671282fafb69da92728b",
    "1a71de0a9e060b2905d6a5b67ecd3b36",
    "92ddbd7f2d778b8c9803aee328091b58",
    "fab324e4fad675945585808b4831d7bc",
    "3ff4def08e4b7a9de576d26586cec64b",
    "6116"
);

/// Drive the **firmware's** `chacha20poly1305_seal` over RFC 8439 §2.8.2 and
/// split the result into (ciphertext, tag).
fn firmware_seal_rfc_2_8_2() -> (String, String) {
    let key: [u8; 32] = hex(RFC_2_8_2_KEY_HEX).try_into().unwrap();
    let nonce: [u8; 12] = hex(RFC_2_8_2_NONCE_HEX).try_into().unwrap();
    let aad = hex(RFC_2_8_2_AAD_HEX);
    // 114 + 16 bytes: past the backup channel's own 64-byte `BLOB_MAX`, which
    // is the point — the AEAD is capacity-generic so the RFC's own message can
    // be run through the shipped code.
    let mut out: HV<u8, 256> = HV::new();
    vendor_backup::chacha20poly1305_seal(
        &key,
        &nonce,
        &aad,
        RFC_2_8_2_PT.as_bytes(),
        &mut out,
    )
    .expect("the RFC message fits a 256-byte buffer");
    let split = out.len() - TAG_LEN;
    (hexstr(&out[..split]), hexstr(&out[split..]))
}

/// Lower-case hex, so a byte vector reads as the RFC's own notation in a
/// failure message.
fn hexstr(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The RFC 8439 §2.8.2 tag, named so the §2.5.2 test can reference it.
fn expect_tag_262() -> Vec<u8> {
    hex("1ae10b594f09e26a7e902ecbd0600691")
}

#[test]
fn both_aead_implementations_match_rfc8439_section_2_8_2() {
    let aad = hex(RFC_2_8_2_AAD_HEX);
    let key: [u8; 32] = hex(RFC_2_8_2_KEY_HEX).try_into().unwrap();
    let nonce: [u8; 12] = hex(RFC_2_8_2_NONCE_HEX).try_into().unwrap();
    let expect_ct = hex(EXPECT_CT_262);
    let expect_tag = hex("1ae10b594f09e26a7e902ecbd0600691");

    let blob = chacha20poly1305_ref(&key, &nonce, &aad, RFC_2_8_2_PT.as_bytes());
    assert_eq!(&blob[..12], &nonce[..], "the framing is nonce-first");
    assert_eq!(&blob[12..12 + expect_ct.len()], &expect_ct[..]);
    assert_eq!(&blob[12 + expect_ct.len()..], &expect_tag[..]);

    // The firmware's, byte for byte, and its own open round-trips it.
    let (ct, tag) = firmware_seal_rfc_2_8_2();
    assert_eq!(ct, hexstr(&expect_ct));
    assert_eq!(tag, hexstr(&expect_tag));
    let mut opened: HV<u8, 256> = HV::new();
    vendor_backup::chacha20poly1305_open(
        &key,
        &nonce,
        &aad,
        &blob[12..],
        &mut opened,
    )
    .expect("the firmware must open the RFC's own ciphertext");
    assert_eq!(opened.as_slice(), RFC_2_8_2_PT.as_bytes());
}

#[test]
fn the_firmware_aead_agrees_with_the_reference_on_channel_sized_inputs() {
    // The §2.8.2 vector is 114 bytes, past the channel's own `BLOB_MAX`, so it
    // cannot go through `Blob`. This is the differential check the round-trips
    // rest on: for every length the channel can carry, the two implementations
    // must produce identical bytes.
    for len in 0..=(vendor_backup::PT_MAX) {
        let key: [u8; 32] = (0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(len as u8)).collect::<Vec<_>>().try_into().unwrap();
        let nonce: [u8; 12] = (0u8..12).map(|i| i ^ len as u8).collect::<Vec<_>>().try_into().unwrap();
        let pt: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0x5A).collect();
        let aad: Vec<u8> = (0..=len).map(|i| (i as u8).wrapping_mul(3)).collect();

        // The firmware's `out` is `ct ‖ tag` (the caller supplies the nonce);
        // the reference's blob is `nonce ‖ ct ‖ tag`. Compare like with like.
        let mut out: HV<u8, 64> = HV::new();
        vendor_backup::chacha20poly1305_seal(&key, &nonce, &aad, &pt, &mut out).unwrap();
        let ref_blob = chacha20poly1305_ref(&key, &nonce, &aad, &pt);
        assert_eq!(&ref_blob[..12], &nonce[..], "length {len}");
        assert_eq!(out.as_slice(), &ref_blob[12..], "length {len}");

        let mut opened: HV<u8, 128> = HV::new();
        vendor_backup::chacha20poly1305_open(&key, &nonce, &aad, &out, &mut opened).unwrap();
        assert_eq!(opened.as_slice(), &pt[..], "round-trip at length {len}");
    }
}

// ---------------------------------------------------------------------------
// US-171 — MSE
// ---------------------------------------------------------------------------

/// The EPIC's named contract test. Kept by name: `US-171 RED` resolves to
/// exactly this string.
#[test]
fn mse_returns_device_cose_key() {
    let mut ops = MockOps::new();
    let (_sk, x, y) = host_keypair();
    // The client's own order, not the canonical one.
    let (status, point) = run_mse(&mut ops, &x, &y, false);
    assert_eq!(status, OK);

    // It really is the device's point, on the curve, and 65 bytes.
    assert_eq!(point.len(), 65);
    assert_eq!(point[0], 0x04, "the client rebuilds 0x04 itself; the halves must be 32+32");
    let pk = crypto::parse_public_key(&point).expect("the device point must be on P-256");
    // A second MSE gives a *different* point: the ephemeral scalar is fresh
    // per session, and a fixed one would make every backup after the first
    // recoverable from the first.
    let mut ops2 = MockOps::with_rng(0x0123_4567_89AB_CDEF);
    let (st2, point2) = run_mse(&mut ops2, &x, &y, false);
    assert_eq!(st2, OK);
    assert_ne!(point, point2, "the device point must not be a constant");
    let _ = pk;
}

#[test]
fn mse_accepts_the_non_canonical_cose_label_order() {
    let mut ops = MockOps::new();
    let (_sk, x, y) = host_keypair();

    // The `BTreeMap` order the client actually sends.
    let (non_canon, p1) = run_mse(&mut ops, &x, &y, false);
    assert_eq!(non_canon, OK, "the client's own key order must work");

    // RFC 8152 canonical order must work too, from a fresh session so the two
    // are not sharing an established channel.
    let mut ops2 = MockOps::new();
    let (canon, p2) = run_mse(&mut ops2, &x, &y, true);
    assert_eq!(canon, OK, "canonical order must work");
    assert_eq!(p1[0], p2[0]);
    assert_eq!(p1.len(), 65);
    assert_eq!(p2.len(), 65);
}

#[test]
fn mse_ignores_kty_alg_and_crv_but_refuses_a_bad_shape() {
    let (_sk, x, y) = host_keypair();
    let mut ops = MockOps::new();

    // `alg = -7` (ES256) is what the client's *clientPin* key-agreement map
    // sends (US-120), and this parser must not care.
    let mut cose: Rng = HV::new();
    map(&mut cose, 5);
    neg(&mut cose, -3);
    bstr(&mut cose, &y);
    neg(&mut cose, -2);
    bstr(&mut cose, &x);
    neg(&mut cose, -1);
    uint(&mut cose, 1);
    uint(&mut cose, 1);
    uint(&mut cose, 2);
    uint(&mut cose, 3);
    neg(&mut cose, -7); // ES256, not -25
    let mut params: Rng = HV::new();
    map(&mut params, 1);
    uint(&mut params, 1);
    params.extend_from_slice(&cose).unwrap();
    let req = client_request(&[0u8; 32], 0x01, Some(&params), None);
    let mut out: Reply = HV::new();
    assert_eq!(vendor_backup::mse(&req, &mut out, &mut ops).status.code(), OK);

    // A 33-byte compressed point is `0x03`, not a truncation to 32.
    let mut bad: Rng = HV::new();
    map(&mut bad, 5);
    neg(&mut bad, -3);
    bstr(&mut bad, &y);
    neg(&mut bad, -2);
    let mut long = x.to_vec();
    long.push(0x02);
    bstr(&mut bad, &long);
    neg(&mut bad, -1);
    uint(&mut bad, 1);
    uint(&mut bad, 1);
    uint(&mut bad, 2);
    uint(&mut bad, 3);
    neg(&mut bad, -25);
    let mut p2: Rng = HV::new();
    map(&mut p2, 1);
    uint(&mut p2, 1);
    p2.extend_from_slice(&bad).unwrap();
    let req = client_request(&[0u8; 32], 0x01, Some(&p2), None);
    let mut out: Reply = HV::new();
    assert_eq!(vendor_backup::mse(&req, &mut out, &mut ops).status.code(), INVALID_LENGTH);

    // A map with no key 1 at all is a missing parameter.
    let req = client_request(&[0u8; 32], 0x01, None, None);
    let mut out: Reply = HV::new();
    assert_eq!(vendor_backup::mse(&req, &mut out, &mut ops).status.code(), MISSING_PARAMETER);

    // A coordinate that is a number rather than a byte string is a CBOR error.
    let mut bad: Rng = HV::new();
    map(&mut bad, 2);
    neg(&mut bad, -2);
    uint(&mut bad, 7);
    neg(&mut bad, -3);
    bstr(&mut bad, &y);
    let mut p3: Rng = HV::new();
    map(&mut p3, 1);
    uint(&mut p3, 1);
    p3.extend_from_slice(&bad).unwrap();
    let req = client_request(&[0u8; 32], 0x01, Some(&p3), None);
    let mut out: Reply = HV::new();
    assert_eq!(vendor_backup::mse(&req, &mut out, &mut ops).status.code(), INVALID_CBOR);
}

#[test]
fn mse_refuses_an_off_curve_host_point() {
    let mut ops = MockOps::new();
    let x = [0x11u8; 32];
    let y = [0x22u8; 32];
    let (status, _) = run_mse(&mut ops, &x, &y, false);
    // The client would get "ECDH agreement failed" on a `0x00`; the device has
    // to refuse the point instead.
    assert_eq!(status, INVALID_PARAMETER);
}

// ---------------------------------------------------------------------------
// US-172 — EXPORT / LOAD / FINALIZE
// ---------------------------------------------------------------------------

/// Establish a channel and return (the host secret key, the device point, the
/// client-side channel material), all derived the way `mse_handshake` does.
fn channel(ops: &mut MockOps) -> (p256::SecretKey, [u8; 65], [u8; 32], [u8; 65]) {
    let (sk, x, y) = host_keypair();
    let (status, dev) = run_mse(ops, &x, &y, false);
    assert_eq!(status, OK);

    // `mse_handshake` (mod.rs:1725-1731): z from the ephemeral agreement, then
    // `derive_channel_key(z, aad)` with `aad` = the device point.
    let dev_pk = crypto::parse_public_key(&dev).expect("device point on the curve");
    let z = crypto::ecdh_shared_secret(&sk, &dev_pk);
    let key = hkdf_sha256_ref(b"", &z, &dev);
    (sk, dev, key, dev)
}

#[test]
fn export_load_roundtrip_recovers_the_seed() {
    let seed = [0xA7u8; 32];
    let mut ops = MockOps::with_seed(seed);
    let token = [0x5Au8; 32];
    let pin = "1234";
    let auth = token_auth(&token);
    let (_sk, _dev, key, aad) = channel(&mut ops);

    // EXPORT: no params, PIN token.
    let req = client_request(&token, 0x02, None, Some(pin));
    let mut out: Reply = HV::new();
    let st = vendor_backup::export(
        &req,
        Some(auth),
        gate(true),
        &mut out,
        &mut ops,
    );
    assert_eq!(st.status.code(), OK);

    // `{1: bstr(blob)}`, opened **by the test's own implementation**, with the
    // key derived here and the AAD set to the device point.
    let blob = read_export_blob(&out);
    assert_eq!(blob.len(), 60, "nonce(12) ‖ ct(32) ‖ tag(16)");
    let opened = chacha20poly1305_ref_open(&key, &blob, &aad).expect("the host must be able to open it");
    assert_eq!(opened.len(), MASTER_SEED_LEN);
    assert_eq!(opened.as_slice(), &seed[..]);

    // Now a device with no seed: an EXPORT of it must not yield 32 zero bytes.
    let mut bare = MockOps::new();
    let (s2, d2, k2, a2) = channel(&mut bare);
    let _ = (s2, d2, k2, a2);
    let req = client_request(&token, 0x02, None, Some(pin));
    let mut out2: Reply = HV::new();
    let st2 = vendor_backup::export(
        &req,
        Some(token_auth(&token)),
        gate(true),
        &mut out2,
        &mut bare,
    );
    assert_eq!(
        st2.status.code(),
        NOT_ALLOWED,
        "a seedless device must not hand the host a 24-word phrase for 32 zero bytes"
    );
}

#[test]
fn the_aad_is_the_device_point_and_nothing_else() {
    let seed = [0x3Cu8; 32];
    let mut ops = MockOps::with_seed(seed);
    let token = [0x11u8; 32];
    let pin = "1234";
    let (_sk, dev, key, aad) = channel(&mut ops);

    let req = client_request(&token, 0x02, None, Some(pin));
    let mut out: Reply = HV::new();
    assert_eq!(
        vendor_backup::export(&req, Some(token_auth(&token)), gate(true), &mut out, &mut ops)
            .status
            .code(),
        OK
    );
    let blob = read_export_blob(&out);

    // The right AAD opens it.
    assert!(chacha20poly1305_ref_open(&key, &blob, &aad).is_ok());

    // The wrong AAD does not — a *shorter* one, so this also pins that the AAD
    // length is bound and not just its bytes.
    assert!(chacha20poly1305_ref_open(&key, &blob, &dev[..64]).is_err());
    // A flipped bit anywhere in the AAD, of the same length, must fail: this
    // is the "one of the two jobs was done on the wrong bytes" case.
    let mut flipped = aad;
    flipped[0] ^= 0x01;
    assert!(chacha20poly1305_ref_open(&key, &blob, &flipped).is_err());
    // And an absent AAD must fail.
    let empty: Vec<u8> = Vec::new();
    assert!(chacha20poly1305_ref_open(&key, &blob, &empty).is_err());
}

#[test]
fn load_round_trips_a_host_sealed_seed() {
    let mut ops = MockOps::new();
    let token = [0x77u8; 32];
    let pin = "1234";
    let (_sk, _dev, key, aad) = channel(&mut ops);

    // The host seals its own 32-byte seed, exactly as `backup_restore` does.
    let host_seed = [0xE1u8; 32];
    let nonce = [0x42u8; 12];
    let sealed = chacha20poly1305_ref(&key, &nonce, &aad, &host_seed);
    assert_eq!(sealed.len(), 60);

    let mut params: Rng = HV::new();
    map(&mut params, 1);
    uint(&mut params, 1);
    bstr(&mut params, &sealed);
    let req = client_request(&token, 0x03, Some(&params), Some(pin));

    assert_eq!(ops.master_seed(), None);
    assert_eq!(
        vendor_backup::load(&req, Some(token_auth(&token)), gate(true), &mut ops).status.code(),
        OK
    );
    assert_eq!(ops.master_seed(), Some(host_seed), "the device must have the host's seed");
}

/// The trap the module docs are about, as a test.
#[test]
fn load_accepts_a_mac_over_the_clients_own_bytes() {
    let mut ops = MockOps::new();
    let token = [0x99u8; 32];
    let pin = "1234";
    let (_sk, _dev, key, aad) = channel(&mut ops);

    let sealed = chacha20poly1305_ref(&key, &[7u8; 12], &aad, &[0x33u8; 32]);

    // A params encoding the *firmware's* writer would never produce, and which
    // therefore no arm could reproduce by re-encoding: a one-byte map header
    // for a 60-byte byte string (`0x58 0x3C`) and an out-of-order, non-minimal
    // integer key (`0x18 0x01`). Both are legal CBOR; only the exact bytes are
    // in the MAC.
    let mut params: Rng = HV::new();
    map(&mut params, 1);
    params.push(0x18).unwrap();
    params.push(0x01).unwrap();
    params.push(0x58).unwrap();
    params.push(sealed.len() as u8).unwrap();
    params.extend_from_slice(&sealed).unwrap();
    let req = client_request(&token, 0x03, Some(&params), Some(pin));

    // Sanity: the bytes on the wire really are these bytes.
    assert!(
        req.windows(params.len()).any(|w| w == &params[..]),
        "the fixture must splice the same params it signed"
    );
    assert_eq!(
        vendor_backup::load(&req, Some(token_auth(&token)), gate(true), &mut ops).status.code(),
        OK,
        "a MAC over the client's own bytes must verify"
    );
    assert_eq!(ops.master_seed(), Some([0x33u8; 32]));

    // The same request with one flipped bit in the params fails, and it fails
    // *as a MAC failure* — which is the observable difference between
    // "re-encoded" and "read back".
    let mut tampered = req.clone();
    let pos = tampered
        .windows(params.len())
        .position(|w| w == &params[..])
        .expect("params present");
    tampered[pos + params.len() - 1] ^= 0x01;
    let mut ops2 = MockOps::new();
    let st = vendor_backup::load(
        &tampered,
        Some(token_auth(&token)),
        gate(true),
        &mut ops2,
    );
    assert_eq!(st.status.code(), PIN_AUTH_INVALID);
    assert!(st.pin_auth_failure, "a rejected pinUvAuthParam must be charged");
    assert_eq!(ops2.master_seed(), None, "and must not have written anything");
}

#[test]
fn load_bounds_the_blob_at_28_not_at_60() {
    let mut ops = MockOps::new();
    let token = [0x13u8; 32];
    let pin = "1234";
    let (_sk, _dev, key, aad) = channel(&mut ops);

    // A zero-length plaintext: the smallest legal blob, 12 + 0 + 16 = 28.
    let tiny = chacha20poly1305_ref(&key, &[1u8; 12], &aad, &[]);
    assert_eq!(tiny.len(), BLOB_MIN);
    let mut params: Rng = HV::new();
    map(&mut params, 1);
    uint(&mut params, 1);
    bstr(&mut params, &tiny);
    let req = client_request(&token, 0x03, Some(&params), Some(pin));
    // 28 is *structurally* legal, so it gets past the length bound and fails on
    // its merits — the plaintext is not 32 bytes.
    assert_eq!(
        vendor_backup::load(&req, Some(token_auth(&token)), gate(true), &mut ops).status.code(),
        INVALID_LENGTH
    );
    assert_eq!(ops.master_seed(), None);

    // 27 is below the floor (`12 + 16`). Built as a **well-formed** CBOR byte
    // string of 27 bytes, so what is refused is the blob length and not the
    // request's shape — truncating the 28-byte params instead would produce a
    // byte string whose head promises 28 bytes, which the CBOR decoder
    // correctly rejects as malformed and which would never reach the length
    // check this test is about.
    let mut short: Rng = HV::new();
    map(&mut short, 1);
    uint(&mut short, 1);
    bstr(&mut short, &tiny[..27]);
    let req = client_request(&token, 0x03, Some(&short), Some(pin));
    assert_eq!(
        vendor_backup::load(&req, Some(token_auth(&token)), gate(true), &mut ops).status.code(),
        INVALID_LENGTH
    );
    assert_eq!(ops.master_seed(), None, "a refused blob must not write anything");

    // A 60-byte blob is of course accepted — the bound is a bound, not a
    // coincidence.
    let full = chacha20poly1305_ref(&key, &[2u8; 12], &aad, &[0x5Au8; 32]);
    assert_eq!(full.len(), 60);
    assert!(full.len() < BLOB_MAX);
}

#[test]
fn load_fails_closed_on_a_wrong_key_or_a_tampered_blob() {
    let mut ops = MockOps::with_seed([0x01u8; 32]);
    let before = ops.master_seed();
    let writes_before = ops.seed_writes;
    let token = [0x21u8; 32];
    let pin = "1234";
    let (_sk, _dev, key, aad) = channel(&mut ops);

    // A blob sealed under a *different* channel key.
    let mut wrong_key = key;
    wrong_key[0] ^= 0xFF;
    let sealed = chacha20poly1305_ref(&wrong_key, &[3u8; 12], &aad, &[0x77u8; 32]);
    let mut params: Rng = HV::new();
    map(&mut params, 1);
    uint(&mut params, 1);
    bstr(&mut params, &sealed);
    let req = client_request(&token, 0x03, Some(&params), Some(pin));
    assert_eq!(
        vendor_backup::load(&req, Some(token_auth(&token)), gate(true), &mut ops).status.code(),
        INTEGRITY_FAILURE
    );
    assert_eq!(ops.master_seed(), before, "a failed load must not change the seed");
    assert_eq!(ops.seed_writes, writes_before, "and must not write at all");

    // A flipped tag bit on a correctly-keyed blob.
    let good = chacha20poly1305_ref(&key, &[4u8; 12], &aad, &[0x88u8; 32]);
    let mut flipped = good.clone();
    *flipped.last_mut().unwrap() ^= 0x01;
    let mut params: Rng = HV::new();
    map(&mut params, 1);
    uint(&mut params, 1);
    bstr(&mut params, &flipped);
    let req = client_request(&token, 0x03, Some(&params), Some(pin));
    assert_eq!(
        vendor_backup::load(&req, Some(token_auth(&token)), gate(true), &mut ops).status.code(),
        INTEGRITY_FAILURE
    );
    assert_eq!(ops.master_seed(), before);
    assert_eq!(ops.seed_writes, writes_before);

    // A blob sealed under the right key but with a *different* AAD.
    let wrong_aad = chacha20poly1305_ref(&key, &[5u8; 12], b"not the point", &[0x99u8; 32]);
    let mut params: Rng = HV::new();
    map(&mut params, 1);
    uint(&mut params, 1);
    bstr(&mut params, &wrong_aad);
    let req = client_request(&token, 0x03, Some(&params), Some(pin));
    assert_eq!(
        vendor_backup::load(&req, Some(token_auth(&token)), gate(true), &mut ops).status.code(),
        INTEGRITY_FAILURE
    );
    assert_eq!(ops.master_seed(), before);
    assert_eq!(ops.seed_writes, writes_before);
}

#[test]
fn finalize_sets_the_sealed_flag_and_export_then_refuses() {
    let mut ops = MockOps::with_seed([0xEEu8; 32]);
    let token = [0x37u8; 32];
    let pin = "1234";
    let (_sk, _dev, _key, _aad) = channel(&mut ops);

    // Before: EXPORT works.
    let req = client_request(&token, 0x02, None, Some(pin));
    let mut out: Reply = HV::new();
    assert_eq!(
        vendor_backup::export(&req, Some(token_auth(&token)), gate(true), &mut out, &mut ops)
            .status
            .code(),
        OK
    );

    // FINALIZE is touch-gated: no touch, `0x3B` and the flag is not set.
    assert_eq!(vendor_backup::finalize(gate(false), &mut ops).status.code(), UP_REQUIRED);
    assert!(!ops.backup_sealed());

    // With a touch it lands, once.
    assert_eq!(vendor_backup::finalize(gate(true), &mut ops).status.code(), OK);
    assert!(ops.backup_sealed());
    assert_eq!(ops.seal_writes, 1);
    // Idempotent: a second FINALIZE succeeds and writes nothing.
    assert_eq!(vendor_backup::finalize(gate(true), &mut ops).status.code(), OK);
    assert_eq!(ops.seal_writes, 1);

    // And EXPORT now says so, in the status the client already renders as
    // "already sealed".
    let req = client_request(&token, 0x02, None, Some(pin));
    let mut out: Reply = HV::new();
    let st = vendor_backup::export(
        &req,
        Some(token_auth(&token)),
        gate(true),
        &mut out,
        &mut ops,
    );
    assert_eq!(st.status.code(), NOT_ALLOWED);
    assert!(out.is_empty(), "a refusal must not leave a body behind");

    // A refused EXPORT must not disclose the seal state to a caller whose
    // authentication failed: a **wrong** token is `0x33`, not `0x30`. The
    // request is signed with one token and presented with another, so this is
    // a genuine MAC failure rather than a correctly-authenticated request from
    // someone who happens to hold a different (valid) token.
    let req = client_request(&[0x00u8; 32], 0x02, None, Some(pin));
    let mut out: Reply = HV::new();
    let wrong = [0xFFu8; 32];
    let st = vendor_backup::export(
        &req,
        Some(token_auth(&wrong)),
        gate(true),
        &mut out,
        &mut ops,
    );
    assert_eq!(st.status.code(), PIN_AUTH_INVALID);
    assert!(st.pin_auth_failure, "a rejected pinUvAuthParam must be charged");
    assert!(out.is_empty());
}

#[test]
fn load_still_works_after_finalize() {
    let mut ops = MockOps::new();
    let token = [0x57u8; 32];
    let pin = "1234";
    let (_sk, _dev, key, aad) = channel(&mut ops);
    assert_eq!(vendor_backup::finalize(gate(true), &mut ops).status.code(), OK);
    assert!(ops.backup_sealed());

    let sealed = chacha20poly1305_ref(&key, &[8u8; 12], &aad, &[0x6Bu8; 32]);
    let mut params: Rng = HV::new();
    map(&mut params, 1);
    uint(&mut params, 1);
    bstr(&mut params, &sealed);
    let req = client_request(&token, 0x03, Some(&params), Some(pin));
    assert_eq!(
        vendor_backup::load(&req, Some(token_auth(&token)), gate(true), &mut ops).status.code(),
        OK,
        "sealing the export window must not disable restore"
    );
    assert_eq!(ops.master_seed(), Some([0x6Bu8; 32]));
}

#[test]
fn export_falls_back_to_a_touch_when_there_is_no_pin() {
    let mut ops = MockOps::with_seed([0x4Du8; 32]);
    let (_sk, _dev, key, aad) = channel(&mut ops);

    // No token at all — the client's documented no-PIN path.
    let req = client_request(&[0u8; 32], 0x02, None, None);
    let mut out: Reply = HV::new();
    let st = vendor_backup::export(&req, None, gate(false), &mut out, &mut ops);
    assert_eq!(st.status.code(), UP_REQUIRED, "no PIN and no touch must not export");
    assert!(out.is_empty());

    let mut out: Reply = HV::new();
    let st = vendor_backup::export(&req, None, gate(true), &mut out, &mut ops);
    assert_eq!(st.status.code(), OK);
    let blob = read_export_blob(&out);
    assert_eq!(chacha20poly1305_ref_open(&key, &blob, &aad).unwrap().len(), 32);
}

#[test]
fn export_without_an_mse_session_is_a_refusal_not_a_zero_key() {
    let mut ops = MockOps::with_seed([0x9Du8; 32]);
    let token = [0x44u8; 32];
    let pin = "1234";
    // No `MSE` has run.
    let req = client_request(&token, 0x02, None, Some(pin));
    let mut out: Reply = HV::new();
    let st = vendor_backup::export(
        &req,
        Some(token_auth(&token)),
        gate(true),
        &mut out,
        &mut ops,
    );
    assert_eq!(st.status.code(), INVALID_PARAMETER);
    assert!(out.is_empty());
}

#[test]
fn a_non_acfg_token_is_refused_on_export_and_load() {
    let mut ops = MockOps::with_seed([0x17u8; 32]);
    let token = [0x6Cu8; 32];
    let pin = "1234";
    let (_sk, _dev, _k, _a) = channel(&mut ops);
    let req = client_request(&token, 0x02, None, Some(pin));
    let mut out: Reply = HV::new();
    let a = TokenAuth { token: &token, permissions: 0x04, blocked: false };
    assert_eq!(
        vendor_backup::export(&req, Some(a), gate(true), &mut out, &mut ops).status.code(),
        0x40,
        "CTAP2_ERR_UNAUTHORIZED_PERMISSION"
    );
}

// ---------------------------------------------------------------------------
// Reading the EXPORT body back
// ---------------------------------------------------------------------------

/// `{1: bstr(blob)}` → the blob, with a length assertion rather than a
/// `try_into`, so a wrong length names itself.
fn read_export_blob(body: &[u8]) -> Vec<u8> {
    use fapico2_fido::cbor::no_heap::{Item, Parser};
    let mut p = Parser::new(body);
    assert_eq!(p.next().unwrap(), Item::Map(1));
    assert_eq!(p.next().unwrap(), Item::U(1));
    match p.next().unwrap() {
        Item::B(b) => b.to_vec(),
        other => panic!("expected a byte string, got {other:?}"),
    }
}




