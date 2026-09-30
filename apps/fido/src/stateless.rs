//! US-714 (POLISH-PUB): stateless U2F key handles — C parity.
//!
//! C reference: `pico-fido2/src/fido/cmd_register.c:74` →
//! `fido.c::derive_key`, and `cmd_authenticate.c` → `verify_key`. A U2F key
//! handle is 64 bytes:
//!
//! ```text
//! [0..32]   key path — 8 little-endian u32 HKDF salts, each with the MSB
//!           set (C: `val |= 0x80000000`), drawn from the TRNG at
//!           registration;
//! [32..64]  HMAC-SHA256 tag over `appId ‖ path`, keyed by the derived
//!           private scalar (C: `key_handle + KEY_PATH_LEN`).
//! ```
//!
//! Derivation (C `derive_key`, byte-for-byte): a 67-byte scratch `outk`
//! seeded with the device master at `[0..32]` (the rest zeros); 8 rounds of
//! `HKDF-SHA512(salt = path word i, ikm = outk[0..32], info = outk[32..64])`
//! each writing 67 output bytes back into `outk`; the private scalar is
//! `outk[0..32]` after the last round. The appId is bound to the handle by
//! the tag alone — at authentication the scalar is re-derived from the
//! handle's own salts and the tag is re-checked in constant time, so a U2F
//! (non-resident) registration consumes **no** store slot: C parity,
//! unlimited non-resident credentials.
//!
//! The device master is domain-separated from the persisted per-device
//! random (`device_random` — the same secret that keys encIdentifier /
//! encStateKey through distinct HMAC domains): `master = HKDF-SHA256(ikm =
//! device_random, info = "fapico2 u2f master v1")`. There is no dedicated C
//! `keydev` slot in this port; `device_random` is the equivalent per-device
//! secret and lives in the secure store, so a factory reset invalidates
//! every stateless handle (C parity: regenerating the device key does the
//! same).

use crate::crypto;

/// C `KEY_HANDLE_LEN` (fido.h:36) = KEY_PATH_LEN (32) + SHA-256 tag (32).
pub const KEY_HANDLE_LEN: usize = 64;
/// C `KEY_PATH_LEN` (fido.h:32).
pub const KEY_PATH_LEN: usize = 32;
/// C `KEY_PATH_ENTRIES` (fido.h:33) = KEY_PATH_LEN / sizeof(uint32).
const KEY_PATH_ENTRIES: usize = 8;

/// Domain-separation label for the stateless-credential device master.
const MASTER_INFO: &[u8] = b"fapico2 u2f master v1";

/// The derived per-credential private scalar. Zeroized on drop (US-704
/// precedent: `PinScratch`) so early error returns never leave the scalar
/// on the stack.
pub struct StatelessScalar([u8; 32]);

impl StatelessScalar {
    /// Wrap a derived scalar.
    fn new(scalar: [u8; 32]) -> Self {
        StatelessScalar(scalar)
    }

    /// The scalar bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for StatelessScalar {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl core::ops::Deref for StatelessScalar {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for StatelessScalar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Derive the stateless-credential device master from the persisted
/// per-device random (see the module docs). Zeroized on drop like every
/// other derived secret here.
pub fn master_from_device_random(device_random: &[u8; 32]) -> StatelessScalar {
    let mut master = [0u8; 32];
    crypto::hkdf_sha256(None, device_random, MASTER_INFO, &mut master);
    StatelessScalar::new(master)
}

/// True when the handle has the C stateless shape: exactly [`KEY_HANDLE_LEN`]
/// bytes and every little-endian path word with the MSB set (C
/// `verify_key`'s gate). Legacy store-backed handles (arbitrary bytes, the
/// pre-US-714 format) never match, so detection is unambiguous.
pub fn is_stateless(key_handle: &[u8]) -> bool {
    if key_handle.len() != KEY_HANDLE_LEN {
        return false;
    }
    // Plain loop (review minor): the slice windows are statically in bounds,
    // so no `try_into().expect()` panic path is needed.
    for i in 0..KEY_PATH_ENTRIES {
        let w = &key_handle[i * 4..i * 4 + 4];
        if u32::from_le_bytes([w[0], w[1], w[2], w[3]]) & 0x8000_0000 == 0 {
            return false;
        }
    }
    true
}

/// Derive the private scalar from the master and a 32-byte path (the first
/// handle region). C `derive_key` replayed with `new_key = false`.
pub fn derive_scalar_from_path(master: &[u8; 32], path: &[u8; KEY_PATH_LEN]) -> StatelessScalar {
    // `outk` mirrors the C 67-byte scratch: [0..32] ikm, [32..64] info
    // (zeros on the first round — a fresh `outk` beyond the device key).
    let mut ikm = [0u8; 32];
    ikm.copy_from_slice(master);
    let mut info = [0u8; 32];
    let mut okm = [0u8; 67];
    for word in 0..KEY_PATH_ENTRIES {
        hkdf_sha512(&path[word * 4..word * 4 + 4], &ikm, &info, &mut okm);
        ikm.copy_from_slice(&okm[..32]);
        info.copy_from_slice(&okm[32..64]);
    }
    // Zeroize the scratch (review minor; C zeroizes `outk` on every exit):
    // after the last round `okm[0..32]` holds the scalar in the clear.
    okm.fill(0);
    info.fill(0);
    StatelessScalar::new(ikm)
}

/// The whole handle → scalar convenience for the auth path. `None` when the
/// handle is not [`KEY_HANDLE_LEN`] bytes (callers answer the wire error;
/// never a panic — US-701 bound discipline).
pub fn derive_scalar(master: &[u8; 32], key_handle: &[u8]) -> Option<StatelessScalar> {
    if key_handle.len() != KEY_HANDLE_LEN {
        return None;
    }
    let mut path = [0u8; KEY_PATH_LEN];
    path.copy_from_slice(&key_handle[..KEY_PATH_LEN]);
    Some(derive_scalar_from_path(master, &path))
}

/// C `derive_key` `new_key = true` tail: HMAC-SHA256 over `appId ‖ path`
/// keyed by the derived scalar, stored at `key_handle[KEY_PATH_LEN..]`.
pub fn handle_tag(scalar: &StatelessScalar, app_id: &[u8; 32], path: &[u8; KEY_PATH_LEN]) -> [u8; 32] {
    let mut key_base = [0u8; 32 + KEY_PATH_LEN];
    key_base[..32].copy_from_slice(app_id);
    key_base[32..].copy_from_slice(path);
    crypto::hmac_sha256(scalar.bytes(), &key_base)
}

/// C `verify_key`: constant-time tag check for a stateless handle. A
/// malformed handle or a wrong tag is `false` — never a panic.
pub fn verify_handle(master: &[u8; 32], app_id: &[u8; 32], key_handle: &[u8]) -> bool {
    if !is_stateless(key_handle) {
        return false;
    }
    let Some(scalar) = derive_scalar(master, key_handle) else {
        return false;
    };
    let mut path = [0u8; KEY_PATH_LEN];
    path.copy_from_slice(&key_handle[..KEY_PATH_LEN]);
    let tag = handle_tag(&scalar, app_id, &path);
    crypto::ct_eq(&tag, &key_handle[KEY_PATH_LEN..])
}

/// HKDF-SHA512 — the C derivation chain runs over SHA-512
/// (`mbedtls_md_info_from_type(MBEDTLS_MD_SHA512)`), 67 output bytes per
/// round like the C `sizeof(outk)` bound.
///
/// US-1070: the hasher is [`fapico2_platform::sha512::Sha512`] — the rolled
/// compression — not `sha2::Sha512`. It is a `digest`-trait drop-in, so the
/// derivation chain, the `Hkdf` construction and the output bytes are
/// unchanged; the only thing that moved is how much code sits behind them.
/// Byte-identity with the stock implementation is not asserted here, it is
/// tested case by case in
/// `platform/tests/sha512_differential.rs`, against the NIST vectors and
/// against `sha2` directly. Reverting this line restores the stock hasher
/// with no other change.
fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    use fapico2_platform::sha512::Sha512;
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    // The only failure mode is `okm.len() > 255 * hash_len`; every caller
    // passes a fixed 67-byte buffer, so this is statically unreachable —
    // no panic path (review minor). On the impossible error the caller's
    // zeroed buffer stays as-is, which fails closed.
    let _ = hk.expand(info, okm);
}
