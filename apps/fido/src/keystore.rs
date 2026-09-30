//! Keystore for fapico2-fido.

use crate::cbor;
use crate::crypto;
use crate::snapshot_crypt::{self, FieldAad, FieldScope};
use crate::vendorff::{
    IdentityName, LedConf, PHY_FIELD_ENABLED_USB_ITF, PHY_FIELD_LED_CONF, PHY_FIELD_MANUFACTURER,
    PHY_FIELD_PRODUCT,
};
use fapico2_platform::secure_store::SecureStore;
use std::fmt::Debug;

/// A stored credential.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: CosePublicKey,
    /// P-256 private key scalar (32 bytes), needed for assertion signing.
    pub private_key: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    /// RP ID text (needed for credMgmt enumerateRps / enumerateCreds responses).
    pub rp_id: Option<String>,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub cred_protect: u8,
    pub large_blob_key: Option<[u8; 32]>,
    pub hmac_secret: Option<Vec<u8>>,
    pub cred_blob: Option<Vec<u8>>,
    pub third_party_payment: bool,
    pub pin_complexity_policy: bool,
    pub resident: bool,
    pub algorithm: i32,
    pub counter: u32,
    /// Revoked flag — set by the vendor CONFIG_CREDENTIAL_REVOKE command.
    /// Revoked credentials are excluded from makeCredential exclude lists
    /// and fail getAssertion with NO_CREDENTIALS.
    pub revoked: bool,
    /// Optional expiration timestamp (seconds since epoch) set by the vendor
    /// CONFIG_CREDENTIAL_EXPIRE command. Currently stored but not enforced
    /// in this build.
    pub expires_at: Option<u32>,
}

/// COSE public key.
#[derive(Debug, Clone, PartialEq)]
pub struct CosePublicKey {
    pub kty: i32,
    pub alg: i32,
    pub crv: Option<i32>,
    pub x: Option<Vec<u8>>,
    pub y: Option<Vec<u8>>,
    pub n: Option<Vec<u8>>,
    pub e: Option<Vec<u8>>,
    pub okp_key: Option<Vec<u8>>,
}

impl CosePublicKey {
    pub fn es256(x: [u8; 32], y: [u8; 32]) -> Self {
        Self::ec2(-7, x, y)
    }

    /// Create a COSE EC2 key with the given algorithm (e.g. -7 for ES256,
    /// -9 for ESP256) and P-256 coordinates.
    pub fn ec2(alg: i32, x: [u8; 32], y: [u8; 32]) -> Self {
        Self {
            kty: 2,
            alg,
            crv: Some(1),
            x: Some(x.to_vec()),
            y: Some(y.to_vec()),
            n: None,
            e: None,
            okp_key: None,
        }
    }

    pub fn eddsa(key: [u8; 32]) -> Self {
        Self {
            kty: 1,
            alg: -8,
            crv: Some(6),
            x: Some(key.to_vec()),
            y: None,
            n: None,
            e: None,
            okp_key: None,
        }
    }

    pub fn algorithm(&self) -> i32 {
        self.alg
    }
}

/// PIN state.
#[derive(Debug, Clone, PartialEq)]
pub struct PinState {
    /// Verifier bytes: `SHA256(PIN)[..16]` in the legacy format, or the
    /// salted stretched verifier (US-910) when `pin_verifier_format == 1`.
    pub pin_hash: Option<[u8; 16]>,
    /// US-910 verifier format stamp: `0` = legacy unsalted, `1` = salted
    /// stretched (`crypto::PIN_VERIFIER_FORMAT_STRETCHED`).
    pub pin_verifier_format: u8,
    /// US-910 per-device TRNG salt (16 bytes) for the stretched verifier.
    pub pin_salt: Option<[u8; 16]>,
    /// US-910 iteration count for the stretched verifier.
    pub pin_iter: u32,
    /// Remaining retries, 0..=8.
    pub retries: u8,
    /// Persistent power-cycle lockout flag (survives reconnects).
    pub blocked: bool,
    /// Durable 3-strike flag (US-909): set after 3 consecutive PIN
    /// mismatches; survives reconnects and snapshots. Cleared only by a
    /// correct PIN.
    pub needs_power_cycle: bool,
    /// Durable counter of consecutive PIN mismatches (US-909); persisted in
    /// the keystore snapshot. Cleared only by a correct PIN.
    pub new_pin_mismatches: u8,
    /// Volatile counter of consecutive pinUvAuthParam verification failures
    /// (MC/GA/credMgmt/config). At 3, the authenticator blocks until
    /// power cycle. Not persisted.
    pub auth_failures: u8,
    pub min_pin_length: u8,
    pub min_pin_rp_ids: Vec<String>,
    pub always_uv: bool,
    pub force_pin_change: bool,
    pub pin_complexity_policy: bool,
    pub enterprise_attestation: bool,
    /// Enterprise RP ID list (Config setEnterpriseRPIDList).
    pub enterprise_rp_ids: Vec<String>,
}

impl Default for PinState {
    fn default() -> Self {
        Self {
            pin_hash: None,
            pin_verifier_format: 0,
            pin_salt: None,
            pin_iter: 0,
            retries: 8,
            blocked: false,
            needs_power_cycle: false,
            new_pin_mismatches: 0,
            auth_failures: 0,
            min_pin_length: 4,
            min_pin_rp_ids: Vec::new(),
            always_uv: false,
            force_pin_change: false,
            pin_complexity_policy: false,
            enterprise_attestation: false,
            enterprise_rp_ids: Vec::new(),
        }
    }
}

/// Authenticator state.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthState {
    pub pin_state: PinState,
    pub cred_counter: u32,
    pub large_blob_array: Option<Vec<u8>>,
    pub vault_state: Option<Vec<u8>>,
    /// Per-device random, generated once at keystore creation and persisted.
    /// Seeds the stable encIdentifier / encCredStoreState getInfo fields.
    pub device_random: [u8; 32],
    /// US-113: the physical configuration written through the
    /// `vendorPrototype` (`0xFF`) sub-command — auth-map key 6, plaintext, the
    /// same record the device keystore stores. See [`crate::vendorff`] for the
    /// framing; the host twin keeps it because the emulation binary drives
    /// this stack, and a configuration that survives a real reboot and not a
    /// host one would be a divergence between the two.
    ///
    /// UNSEALED, unlike keys 1-5: `crate::vendorff`'s security section
    /// records the deliberate deviation, the named `FieldScope::AuthPhy`
    /// alternative that was not taken, and the two distinct surfaces (command
    /// path vs. direct snapshot tampering) on which this record becomes
    /// load-bearing. Read that section before relying on any of it.
    pub phy: crate::vendorff::PhyConfig,
    /// US-176: the RS-Key `0x41` Phase I state — the same
    /// [`crate::vendor_state::VendorState`] the no-heap device keystore holds
    /// under snapshot auth keys 7 (sealed) and 8 (plaintext).
    ///
    /// It is here because the host and device snapshots are documented to be
    /// **byte-interchangeable** (S-324), and an emulation binary that could
    /// read a device snapshot but not write one — or write one the device would
    /// refuse — would break that at exactly the point the Phase I stories start
    /// driving state through both command paths. The two codecs are separate
    /// functions over one key numbering for the same reason
    /// `device_keystore.rs`'s are: they are two implementations of one format,
    /// not one implementation and a fork.
    pub vendor: crate::vendor_state::VendorState,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            pin_state: PinState::default(),
            cred_counter: 0,
            large_blob_array: None,
            vault_state: None,
            device_random: crypto::random_bytes::<32>(),
            phy: crate::vendorff::PhyConfig::default(),
            vendor: crate::vendor_state::VendorState::default(),
        }
    }
}

/// Keystore trait.
pub trait Keystore: Debug {
    fn get_pin_state(&self) -> &PinState;
    fn get_pin_state_mut(&mut self) -> &mut PinState;
    fn save_pin_state(&mut self) -> Result<(), KeystoreError>;
    fn get_auth_state(&self) -> &AuthState;
    fn get_auth_state_mut(&mut self) -> &mut AuthState;
    fn save_auth_state(&mut self) -> Result<(), KeystoreError>;
    fn store_credential(&mut self, cred: StoredCredential) -> Result<(), KeystoreError>;
    fn get_credential(&self, id: &[u8]) -> Option<&StoredCredential>;
    fn get_credential_mut(&mut self, id: &[u8]) -> Option<&mut StoredCredential>;
    fn delete_credential(&mut self, id: &[u8]) -> Result<(), KeystoreError>;
    fn list_credentials(&self) -> Vec<&StoredCredential>;
    fn list_credentials_by_rp(&self, rp_id_hash: &[u8; 32]) -> Vec<&StoredCredential>;
    fn cred_count(&self) -> usize;
    fn max_remaining_creds(&self) -> usize;
    fn reset(&mut self) -> Result<(), KeystoreError>;
    /// Clear volatile session state (needs_power_cycle, new_pin_mismatches).
    /// Called when a new HID client connects (simulated power-cycle).
    fn clear_session_state(&mut self);
    /// Durable-before-ack flush hook (US-424): persist buffered durable state
    /// to the keystore's medium; return true iff durable bytes were written
    /// this call. `FileKeystore` writes on every mutation (nothing buffered —
    /// default stands); `MemoryKeystore` has no durable medium (default
    /// stands).
    ///
    /// US-430 (Phase B hand-off #4): a keystore that **buffers** durable
    /// state between mutations MUST override `persist_if_dirty` to flush it
    /// — the default `false` means the gate treats the app as never-dirty,
    /// so a buffering keystore left on the default would never be flushed by
    /// the platform persist gate.
    fn persist_if_dirty(&mut self) -> bool {
        false
    }
}

/// Keystore errors.
#[derive(Debug, Clone, PartialEq)]
pub enum KeystoreError {
    Full,
    NotFound,
    Io,
    Invalid,
}

/// In-memory keystore for testing and host builds.
#[derive(Debug)]
pub struct MemoryKeystore {
    auth_state: AuthState,
    credentials: Vec<StoredCredential>,
    max_creds: usize,
}

impl MemoryKeystore {
    pub fn new() -> Self {
        Self {
            auth_state: AuthState::default(),
            credentials: Vec::new(),
            max_creds: 256,
        }
    }

    pub fn with_max_creds(max_creds: usize) -> Self {
        Self {
            auth_state: AuthState::default(),
            credentials: Vec::new(),
            max_creds,
        }
    }
}

impl Default for MemoryKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl Keystore for MemoryKeystore {
    fn get_pin_state(&self) -> &PinState {
        &self.auth_state.pin_state
    }

    fn get_pin_state_mut(&mut self) -> &mut PinState {
        &mut self.auth_state.pin_state
    }

    fn save_pin_state(&mut self) -> Result<(), KeystoreError> {
        Ok(())
    }

    fn get_auth_state(&self) -> &AuthState {
        &self.auth_state
    }

    fn get_auth_state_mut(&mut self) -> &mut AuthState {
        &mut self.auth_state
    }

    fn save_auth_state(&mut self) -> Result<(), KeystoreError> {
        Ok(())
    }

    fn store_credential(&mut self, cred: StoredCredential) -> Result<(), KeystoreError> {
        if let Some(pos) = self
            .credentials
            .iter()
            .position(|c| c.credential_id == cred.credential_id)
        {
            self.credentials[pos] = cred;
        } else {
            if self.credentials.len() >= self.max_creds {
                return Err(KeystoreError::Full);
            }
            self.credentials.push(cred);
        }
        Ok(())
    }

    fn get_credential(&self, id: &[u8]) -> Option<&StoredCredential> {
        self.credentials.iter().find(|c| c.credential_id == id)
    }

    fn get_credential_mut(&mut self, id: &[u8]) -> Option<&mut StoredCredential> {
        self.credentials.iter_mut().find(|c| c.credential_id == id)
    }

    fn delete_credential(&mut self, id: &[u8]) -> Result<(), KeystoreError> {
        let pos = self.credentials.iter().position(|c| c.credential_id == id);
        match pos {
            Some(p) => {
                self.credentials.remove(p);
                Ok(())
            }
            None => Err(KeystoreError::NotFound),
        }
    }

    fn list_credentials(&self) -> Vec<&StoredCredential> {
        self.credentials.iter().collect()
    }

    fn list_credentials_by_rp(&self, rp_id_hash: &[u8; 32]) -> Vec<&StoredCredential> {
        self.credentials
            .iter()
            .filter(|c| c.rp_id_hash == *rp_id_hash)
            .collect()
    }

    fn cred_count(&self) -> usize {
        self.credentials.len()
    }

    fn max_remaining_creds(&self) -> usize {
        self.max_creds.saturating_sub(self.credentials.len())
    }

    fn reset(&mut self) -> Result<(), KeystoreError> {
        self.auth_state = AuthState::default();
        self.credentials.clear();
        Ok(())
    }

    /// Clear volatile session state (new HID client connection). US-909: the
    /// PIN-mismatch counters and the 3-strike latch are durable now — only a
    /// correct PIN clears them. The per-session pinUvAuth streak stays
    /// volatile (its durable effect is the `blocked` latch).
    fn clear_session_state(&mut self) {
        self.auth_state.pin_state.auth_failures = 0;
    }
}

/// File-backed keystore for the emulator (US-322). Wraps a MemoryKeystore and
/// persists a CBOR snapshot to disk on every mutating operation so that state
/// survives an emulator process restart.
///
/// US-380: persistence routes through the platform
/// [`SecureStore`](fapico2_platform::secure_store) so that on device the
/// snapshot lands in the RP2350 secure partition (never plain flash) and on
/// host the backing file stands in for that partition. The on-disk layout is
/// unchanged from the pre-US-380 `std::fs` path (raw CBOR + atomic
/// `<path>.tmp` rename), so the frozen keystore tests keep passing.
///
/// Secure-partition key slot for the keystore snapshot.
const FILE_KEYSTORE_SLOT: &[u8] = b"fido.keystore.v1";

/// US-911: the store key the file keystore seals its snapshot's sensitive
/// fields with. The [`fapico2_platform::secure_store::FileSecureStore`]
/// backing file is the secure-partition stand-in (it holds no real secrets
/// and has no key of its own), but the snapshot it carries must not hold
/// plaintext credential keys either — a fixed, documented key (see
/// [`snapshot_crypt::file_snapshot_store_key`]) keeps host files sealed too.
fn file_store_key() -> [u8; 32] {
    snapshot_crypt::file_snapshot_store_key()
}

#[derive(Debug)]
pub struct FileKeystore {
    inner: MemoryKeystore,
    store: fapico2_platform::secure_store::FileSecureStore,
}

/// Snapshot of the keystore serializable via the CTAP2 CBOR encoder.
struct KeystoreSnapshot {
    auth_state: AuthState,
    credentials: Vec<StoredCredential>,
    max_creds: usize,
}

impl KeystoreSnapshot {
    /// US-911: `key` = the secure-store key the sensitive snapshot fields
    /// are AEAD-sealed under (`None` = the legacy plaintext format — the
    /// unkeyed-store shape). Non-sensitive metadata stays plaintext either
    /// way so enumeration keeps working.
    fn to_cbor(&self, key: Option<&[u8; 32]>) -> Vec<u8> {
        // CBOR array: [max_creds, auth_state_cbor, credentials_array]
        let auth_cbor = self.auth_state.to_cbor(key);
        let creds_cbor: Vec<Vec<u8>> =
            self.credentials.iter().map(|c| c.to_cbor(key)).collect();
        let mut arr = Vec::new();
        arr.push(crate::cbor::encode(&crate::cbor::Value::U(self.max_creds as u64)));
        arr.push(crate::cbor::encode(&auth_cbor));
        let creds_arr = crate::cbor::Value::A(
            creds_cbor.into_iter().map(crate::cbor::Value::B).collect(),
        );
        arr.push(crate::cbor::encode(&creds_arr));
        // Top-level map: key 1 = the snapshot array; US-911 adds key 2, the
        // sealed-format marker, when the sensitive fields are encrypted.
        let mut m = vec![(
            crate::cbor::Value::U(1),
            crate::cbor::Value::A(arr.into_iter().map(crate::cbor::Value::B).collect()),
        )];
        if key.is_some() {
            m.push((
                crate::cbor::Value::U(snapshot_crypt::SEALED_MARKER_KEY),
                crate::cbor::Value::U(snapshot_crypt::SEALED_MARKER_VALUE),
            ));
        }
        crate::cbor::encode(&crate::cbor::Value::M(m))
    }

    /// Parse a snapshot. `key` = the store key the sealed fields were
    /// encrypted under; the `{2: 2}` marker decides the format, so a legacy
    /// plaintext snapshot parses with any `key` (backward compatibility).
    /// `None` = corrupt (callers must refuse, FX-409/FX-440).
    fn from_cbor(bytes: &[u8], key: Option<&[u8; 32]>) -> Option<Self> {
        let (val, _) = crate::cbor::decode(bytes).ok()?;
        let map = match val {
            crate::cbor::Value::M(m) => m,
            _ => return None,
        };
        // US-911: format marker — `{2: 2}` = the sensitive fields are
        // sealed. An unknown marker value is a future format: refuse.
        let sealed = match map
            .iter()
            .find(|(k, _)| matches!(k, crate::cbor::Value::U(snapshot_crypt::SEALED_MARKER_KEY)))
            .map(|(_, v)| v)
        {
            None => false,
            Some(crate::cbor::Value::U(u)) if *u == snapshot_crypt::SEALED_MARKER_VALUE => true,
            Some(_) => return None,
        };
        if sealed && key.is_none() {
            // A sealed snapshot without its store key cannot be opened.
            return None;
        }
        let arr_val = map.iter().find(|(k, _)| matches!(k, crate::cbor::Value::U(1)))?;
        let arr = match &arr_val.1 {
            crate::cbor::Value::A(a) => a,
            _ => return None,
        };
        if arr.len() < 3 {
            return None;
        }
        let max_creds = match &arr[0] {
            crate::cbor::Value::B(b) => {
                let (v, _) = crate::cbor::decode(b).ok()?;
                match v {
                    crate::cbor::Value::U(u) => u as usize,
                    _ => return None,
                }
            }
            _ => return None,
        };
        let auth_state = match &arr[1] {
            crate::cbor::Value::B(b) => AuthState::from_cbor(b, key, sealed)?,
            _ => return None,
        };
        // arr[2] is a byte string containing an encoded array of credential
        // byte strings. Decode it first, then decode each credential.
        let credentials = match &arr[2] {
            crate::cbor::Value::B(b) => {
                let (creds_val, _) = crate::cbor::decode(b).ok()?;
                let creds = match creds_val {
                    crate::cbor::Value::A(a) => a,
                    _ => return None,
                };
                let mut out = Vec::new();
                for c in creds {
                    match c {
                        crate::cbor::Value::B(b) => {
                            out.push(StoredCredential::from_cbor(b.as_slice(), key, sealed)?);
                        }
                        _ => return None,
                    }
                }
                out
            }
            _ => return None,
        };
        Some(Self {
            auth_state,
            credentials,
            max_creds,
        })
    }
}

/// Public snapshot codec (S-701-3): the single definition of the
/// `fido.keystore.v1` CBOR map format. The host [`FileKeystore`] and the
/// no-heap [`crate::device_keystore::DeviceKeystore`] both read and write
/// through this layout, so a host-written snapshot and a device-written
/// snapshot are interchangeable.
pub mod snapshot {
    use super::{AuthState, StoredCredential};

    /// Serialize a snapshot: CBOR map `{1: [bstr(max_creds), bstr(auth),
    /// bstr([bstr(cred), ...])], 2?: 2}`.
    ///
    /// US-911: `key` = the secure-store key the sensitive fields
    /// (credential private keys, hmac-secret / largeBlob values,
    /// `device_random`) are AEAD-sealed under — `Some` also stamps the
    /// `{2: 2}` sealed-format marker. `None` = the legacy plaintext format
    /// (the unkeyed-store shape).
    pub fn encode(
        auth_state: &AuthState,
        credentials: &[StoredCredential],
        max_creds: usize,
        key: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let snap = super::KeystoreSnapshot {
            auth_state: clone_auth(auth_state),
            credentials: credentials.to_vec(),
            max_creds,
        };
        snap.to_cbor(key)
    }

    /// Parse a snapshot; `None` = corrupt (callers must refuse, FX-409/FX-440).
    /// US-911: `key` = the store key opening the sealed sensitive fields;
    /// the `{2: 2}` marker decides the format, so a legacy plaintext
    /// snapshot parses with any `key`. A sealed snapshot with `key = None`
    /// (or a wrong key at an auth-level field) is corrupt.
    pub fn parse(
        bytes: &[u8],
        key: Option<&[u8; 32]>,
    ) -> Option<(AuthState, Vec<StoredCredential>, usize)> {
        let snap = super::KeystoreSnapshot::from_cbor(bytes, key)?;
        Some((snap.auth_state, snap.credentials, snap.max_creds))
    }

    // The snapshot struct owns its data; the codec above clones the borrowed
    // inputs (host-only path — alloc is available here).
    fn clone_auth(a: &AuthState) -> AuthState {
        a.clone()
    }
}

impl FileKeystore {
    /// Load from `path` if it exists, otherwise create a fresh keystore and
    /// persist it. A snapshot that exists but cannot be parsed is an error:
    /// the corrupt file is never silently overwritten (FX-409).
    pub fn load_or_create(path: std::path::PathBuf) -> Result<Self, KeystoreError> {
        let store = fapico2_platform::secure_store::FileSecureStore::new(path);
        let location = store.path().display().to_string();
        let inner = if store.contains(FILE_KEYSTORE_SLOT) {
            let bytes = store.read_all(FILE_KEYSTORE_SLOT).map_err(|_| KeystoreError::Io)?;
            match KeystoreSnapshot::from_cbor(&bytes, Some(&file_store_key())) {
                Some(snap) => MemoryKeystore {
                    auth_state: snap.auth_state,
                    credentials: snap.credentials,
                    max_creds: snap.max_creds,
                },
                None => {
                    eprintln!(
                        "fapico2: refusing to load corrupt keystore at {}",
                        location
                    );
                    return Err(KeystoreError::Invalid);
                }
            }
        } else {
            MemoryKeystore::new()
        };
        let ks = Self { inner, store };
        ks.persist()?;
        Ok(ks)
    }

    /// Serialize the current state to the secure partition atomically. The
    /// platform [`FileSecureStore`](fapico2_platform::secure_store) writes to
    /// `<path>.tmp` then renames over the target, so a crash mid-write never
    /// corrupts the snapshot (FX-409).
    fn persist(&self) -> Result<(), KeystoreError> {
        let snap = KeystoreSnapshot {
            auth_state: self.inner.auth_state.clone(),
            credentials: self.inner.credentials.clone(),
            max_creds: self.inner.max_creds,
        };
        // US-911: the sensitive fields are sealed under the file keystore's
        // fixed store key (host files hold no real secrets, but must not
        // carry plaintext credential keys either).
        let bytes = snap.to_cbor(Some(&file_store_key()));
        self.store
            .write_all(FILE_KEYSTORE_SLOT, &bytes)
            .map_err(|_| KeystoreError::Io)
    }
}

impl Keystore for FileKeystore {
    fn get_pin_state(&self) -> &PinState {
        self.inner.get_pin_state()
    }
    fn get_pin_state_mut(&mut self) -> &mut PinState {
        self.inner.get_pin_state_mut()
    }
    fn save_pin_state(&mut self) -> Result<(), KeystoreError> {
        self.inner.save_pin_state()?;
        self.persist()
    }
    fn get_auth_state(&self) -> &AuthState {
        self.inner.get_auth_state()
    }
    fn get_auth_state_mut(&mut self) -> &mut AuthState {
        self.inner.get_auth_state_mut()
    }
    fn save_auth_state(&mut self) -> Result<(), KeystoreError> {
        self.inner.save_auth_state()?;
        self.persist()
    }
    fn store_credential(&mut self, cred: StoredCredential) -> Result<(), KeystoreError> {
        self.inner.store_credential(cred)?;
        self.persist()
    }
    fn get_credential(&self, id: &[u8]) -> Option<&StoredCredential> {
        self.inner.get_credential(id)
    }
    fn get_credential_mut(&mut self, id: &[u8]) -> Option<&mut StoredCredential> {
        self.inner.get_credential_mut(id)
    }
    fn delete_credential(&mut self, id: &[u8]) -> Result<(), KeystoreError> {
        self.inner.delete_credential(id)?;
        self.persist()
    }
    fn list_credentials(&self) -> Vec<&StoredCredential> {
        self.inner.list_credentials()
    }
    fn list_credentials_by_rp(&self, rp_id_hash: &[u8; 32]) -> Vec<&StoredCredential> {
        self.inner.list_credentials_by_rp(rp_id_hash)
    }
    fn cred_count(&self) -> usize {
        self.inner.cred_count()
    }
    fn max_remaining_creds(&self) -> usize {
        self.inner.max_remaining_creds()
    }
    fn reset(&mut self) -> Result<(), KeystoreError> {
        self.inner.reset()?;
        self.persist()
    }
    fn clear_session_state(&mut self) {
        self.inner.clear_session_state();
    }
}

// ------------------------------------------------------------------
// CBOR serialization for persistence (US-322). These impls encode the
// keystore value types as CBOR values so FileKeystore can snapshot and
// restore state without pulling in serde.
// ------------------------------------------------------------------

impl CosePublicKey {
    fn to_cbor(&self) -> cbor::Value {
        use cbor::Value::*;
        let mut entries: Vec<(cbor::Value, cbor::Value)> =
            vec![(U(1), U(self.kty as u64)), (U(3), N(self.alg as i64))];
        if let Some(crv) = self.crv {
            entries.push((U(2), N(crv as i64)));
        }
        if let Some(ref x) = self.x {
            entries.push((N(-1), B(x.clone())));
        }
        if let Some(ref y) = self.y {
            entries.push((N(-2), B(y.clone())));
        }
        if let Some(ref n) = self.n {
            entries.push((N(-3), B(n.clone())));
        }
        if let Some(ref e) = self.e {
            entries.push((N(-4), B(e.clone())));
        }
        if let Some(ref k) = self.okp_key {
            entries.push((N(-5), B(k.clone())));
        }
        M(entries)
    }

    fn from_cbor(val: &cbor::Value) -> Option<Self> {
        let map = match val {
            cbor::Value::M(m) => m,
            _ => return None,
        };
        // Helper: extract integer key (U or N) from a map entry key.
        let key_int = |k: &cbor::Value| -> Option<i64> {
            match k {
                cbor::Value::U(u) => Some(*u as i64),
                cbor::Value::N(n) => Some(*n),
                _ => None,
            }
        };
        let find = |key: i64| -> Option<&cbor::Value> {
            map.iter().find(|(k, _)| key_int(k) == Some(key)).map(|(_, v)| v)
        };
        let kty = find(1).and_then(|v| match v {
            cbor::Value::U(u) => Some(*u as i32),
            _ => None,
        })?;
        let get_int = |key: i64| -> Option<i64> { find(key).and_then(|v| match v { cbor::Value::N(n) => Some(*n), _ => None }) };
        let get_bytes = |key: i64| -> Option<Vec<u8>> { find(key).and_then(|v| match v { cbor::Value::B(b) => Some(b.clone()), _ => None }) };
        let alg = get_int(3).unwrap_or(-7) as i32;
        let crv = get_int(2).map(|c| c as i32);
        let x = get_bytes(-1);
        let y = get_bytes(-2);
        let n = get_bytes(-3);
        let e = get_bytes(-4);
        let okp_key = get_bytes(-5);
        Some(Self { kty, alg, crv, x, y, n, e, okp_key })
    }
}

impl StoredCredential {
    /// US-911: seal one sensitive field when a store key is present; the
    /// plaintext form is the legacy (`None`) fallback. The AAD binds the
    /// snapshot slot, the field scope and THIS credential's ID.
    fn seal_field(&self, key: Option<&[u8; 32]>, scope: FieldScope, pt: &[u8]) -> Vec<u8> {
        match key {
            Some(k) => {
                let aad = FieldAad::new(FILE_KEYSTORE_SLOT, scope, &self.credential_id);
                let mut blob = vec![0u8; pt.len() + snapshot_crypt::FIELD_OVERHEAD];
                // Unreachable failure: the blob is exactly sized and the
                // host fields are heap-sized — `seal_field` cannot fail.
                snapshot_crypt::seal_field(k, aad.bytes(), pt, &mut blob)
                    .expect("seal_field on a caller-sized host blob cannot fail");
                blob
            }
            None => pt.to_vec(),
        }
    }

    fn to_cbor(&self, key: Option<&[u8; 32]>) -> Vec<u8> {
        use cbor::Value::*;
        let mut entries: Vec<(cbor::Value, cbor::Value)> = vec![
            (U(1), B(self.credential_id.clone())),
            (U(2), self.public_key.to_cbor()),
            // US-911: private_key (3), cred_blob (17), large_blob_key (18)
            // and hmac_secret (19) are sensitive — sealed under the store
            // key. rpId/user id/credProtect flags (11-15) stay plaintext so
            // credential enumeration keeps working.
            (U(3), B(self.seal_field(key, FieldScope::CredentialPrivateKey, &self.private_key))),
            (U(4), B(self.rp_id_hash.to_vec())),
            (U(5), U(self.algorithm as u64)),
            (U(6), U(self.counter as u64)),
            (U(7), Bool(self.resident)),
            (U(8), Bool(self.third_party_payment)),
            (U(9), Bool(self.pin_complexity_policy)),
            (U(10), Bool(self.revoked)),
            (U(14), B(self.user_handle.clone())),
            (U(15), U(self.cred_protect as u64)),
        ];
        if let Some(ref blob) = self.cred_blob {
            entries.push((U(17), B(self.seal_field(key, FieldScope::CredentialBlob, blob))));
        }
        if let Some(ref k) = self.large_blob_key {
            entries.push((
                U(18),
                B(self.seal_field(key, FieldScope::CredentialLargeBlobKey, k.as_ref())),
            ));
        }
        if let Some(ref s) = self.hmac_secret {
            entries.push((U(19), B(self.seal_field(key, FieldScope::CredentialHmacSecret, s))));
        }
        if let Some(ref rp) = self.rp_id {
            entries.push((U(11), T(rp.clone())));
        }
        if let Some(ref name) = self.user_name {
            entries.push((U(12), T(name.clone())));
        }
        if let Some(ref dn) = self.user_display_name {
            entries.push((U(13), T(dn.clone())));
        }
        if let Some(ts) = self.expires_at {
            entries.push((U(16), U(ts as u64)));
        }
        cbor::encode(&M(entries))
    }

    /// Decode one credential. `sealed` (the snapshot's `{2: 2}` marker) says
    /// the sensitive fields are AEAD-sealed under `key`.
    ///
    /// US-911 refusal contract: a sensitive field that fails to open kills
    /// the ENTRY, never zeroes it away — the plaintext metadata is kept, the
    /// secret fields are unusable and the credential is marked `revoked`
    /// (filtered from enumeration, refused from signing).
    fn from_cbor(bytes: &[u8], key: Option<&[u8; 32]>, sealed: bool) -> Option<Self> {
        let (val, _) = cbor::decode(bytes).ok()?;
        let map = match val {
            cbor::Value::M(m) => m,
            _ => return None,
        };
        let key_int = |k: &cbor::Value| -> Option<i64> {
            match k {
                cbor::Value::U(u) => Some(*u as i64),
                cbor::Value::N(n) => Some(*n),
                _ => None,
            }
        };
        let find = |key: i64| -> Option<&cbor::Value> {
            map.iter().find(|(k, _)| key_int(k) == Some(key)).map(|(_, v)| v)
        };
        let get_bytes = |key: i64| -> Option<Vec<u8>> { find(key).and_then(|v| match v { cbor::Value::B(b) => Some(b.clone()), _ => None }) };
        let get_uint = |key: i64| -> Option<u64> { find(key).and_then(|v| match v { cbor::Value::U(u) => Some(*u), _ => None }) };
        let get_bool = |key: i64| -> bool { find(key).is_some_and(|v| matches!(v, cbor::Value::Bool(true))) };
        let get_text = |key: i64| -> Option<String> { find(key).and_then(|v| match v { cbor::Value::T(s) => Some(s.clone()), _ => None }) };
        let credential_id = get_bytes(1)?;
        let public_key = CosePublicKey::from_cbor(find(2)?)?;
        let stored_private_key = get_bytes(3)?;
        let rp_id_hash_bytes = get_bytes(4)?;
        if rp_id_hash_bytes.len() != 32 {
            return None;
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&rp_id_hash_bytes);
        // US-911: the metadata fields (plaintext in both formats).
        let mut cred_blob = get_bytes(17);
        let mut large_blob_key = get_bytes(18).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
        let mut hmac_secret = get_bytes(19);
        let mut revoked = get_bool(10);
        let private_key;
        if sealed {
            let key = key.expect("sealed snapshot carries its store key");
            let open = |scope: FieldScope, blob: &[u8]| -> Option<Vec<u8>> {
                let aad = FieldAad::new(FILE_KEYSTORE_SLOT, scope, &credential_id);
                snapshot_crypt::open_field_vec(key, aad.bytes(), blob)
            };
            let mut killed = false;
            private_key = match open(FieldScope::CredentialPrivateKey, &stored_private_key) {
                Some(pt) => pt,
                None => {
                    killed = true;
                    Vec::new()
                }
            };
            if let Some(blob) = cred_blob.take() {
                match open(FieldScope::CredentialBlob, &blob) {
                    Some(pt) => cred_blob = Some(pt),
                    None => killed = true,
                }
            }
            large_blob_key = match get_bytes(18) {
                Some(blob) => match open(FieldScope::CredentialLargeBlobKey, &blob) {
                    Some(pt) => <[u8; 32]>::try_from(pt.as_slice()).ok(),
                    None => {
                        killed = true;
                        None
                    }
                },
                None => None,
            };
            hmac_secret = match get_bytes(19) {
                Some(blob) => match open(FieldScope::CredentialHmacSecret, &blob) {
                    Some(pt) => Some(pt),
                    None => {
                        killed = true;
                        None
                    }
                },
                None => None,
            };
            if killed {
                // The entry is refused, not zeroed: metadata survives, the
                // secrets do not, the credential is dead.
                revoked = true;
                hmac_secret = None;
                large_blob_key = None;
                cred_blob = None;
                eprintln!(
                    "fapico2: a stored credential failed field decryption — marked revoked (metadata kept)"
                );
            }
        } else {
            private_key = stored_private_key;
        }
        Some(Self {
            credential_id,
            public_key,
            private_key,
            rp_id_hash,
            rp_id: get_text(11),
            user_handle: get_bytes(14).unwrap_or_default(),
            user_name: get_text(12),
            user_display_name: get_text(13),
            cred_protect: get_uint(15).unwrap_or(0) as u8,
            large_blob_key,
            hmac_secret,
            cred_blob,
            third_party_payment: get_bool(8),
            pin_complexity_policy: get_bool(9),
            resident: get_bool(7),
            algorithm: get_uint(5).unwrap_or(0) as i32,
            counter: get_uint(6).unwrap_or(0) as u32,
            revoked,
            expires_at: get_uint(16).map(|t| t as u32),
        })
    }
}

impl PinState {
    #[doc(hidden)]
    pub fn to_cbor_for_test(&self) -> cbor::Value {
        self.to_cbor()
    }

    #[doc(hidden)]
    pub fn from_cbor_for_test(val: &cbor::Value) -> Option<Self> {
        Self::from_cbor(val)
    }

    fn to_cbor(&self) -> cbor::Value {
        use cbor::Value::*;
        let mut entries: Vec<(cbor::Value, cbor::Value)> = vec![
            (U(1), U(self.retries as u64)),
            (U(2), Bool(self.blocked)),
            (U(3), Bool(self.needs_power_cycle)),
            (U(4), U(self.new_pin_mismatches as u64)),
            (U(5), U(self.min_pin_length as u64)),
            (U(6), Bool(self.always_uv)),
            (U(7), Bool(self.force_pin_change)),
            (U(8), Bool(self.pin_complexity_policy)),
            (U(9), Bool(self.enterprise_attestation)),
            (U(10), Bool(self.pin_hash.is_some())),
        ];
        if let Some(h) = self.pin_hash {
            entries.push((U(11), B(h.to_vec())));
        }
        entries.push((U(12), A(self.min_pin_rp_ids.iter().map(|s| T(s.clone())).collect())));
        entries.push((U(13), A(self.enterprise_rp_ids.iter().map(|s| T(s.clone())).collect())));
        // US-910: salted stretched verifier record — keys 14/15/16 exist
        // only in the stretched format, so legacy snapshots are unchanged.
        if self.pin_verifier_format == crypto::PIN_VERIFIER_FORMAT_STRETCHED {
            entries.push((U(14), U(self.pin_verifier_format as u64)));
            if let Some(salt) = self.pin_salt {
                entries.push((U(15), B(salt.to_vec())));
            }
            entries.push((U(16), U(self.pin_iter as u64)));
        }
        M(entries)
    }

    fn from_cbor(val: &cbor::Value) -> Option<Self> {
        use cbor::Value::*;
        let map = match val {
            M(m) => m,
            _ => return None,
        };
        let key_int = |k: &cbor::Value| -> Option<i64> {
            match k {
                cbor::Value::U(u) => Some(*u as i64),
                cbor::Value::N(n) => Some(*n),
                _ => None,
            }
        };
        let find = |key: i64| -> Option<&cbor::Value> {
            map.iter().find(|(k, _)| key_int(k) == Some(key)).map(|(_, v)| v)
        };
        let get_uint = |key: i64| -> Option<u64> { find(key).and_then(|v| match v { cbor::Value::U(u) => Some(*u), _ => None }) };
        let get_bool = |key: i64| -> bool { find(key).is_some_and(|v| matches!(v, cbor::Value::Bool(true))) };
        let get_bytes = |key: i64| -> Option<Vec<u8>> { find(key).and_then(|v| match v { cbor::Value::B(b) => Some(b.clone()), _ => None }) };
        let mut s = Self::default();
        if let Some(r) = get_uint(1) {
            s.retries = r as u8;
        }
        s.blocked = get_bool(2);
        s.needs_power_cycle = get_bool(3);
        if let Some(m) = get_uint(4) {
            s.new_pin_mismatches = m as u8;
        }
        if let Some(m) = get_uint(5) {
            s.min_pin_length = m as u8;
        }
        s.always_uv = get_bool(6);
        s.force_pin_change = get_bool(7);
        s.pin_complexity_policy = get_bool(8);
        s.enterprise_attestation = get_bool(9);
        match get_bytes(11) {
            Some(b) if b.len() == 16 => {
                let mut h = [0u8; 16];
                h.copy_from_slice(&b);
                s.pin_hash = Some(h);
            }
            // A present-but-malformed pin hash is a parse error, not
            // "no PIN set" (FX-409: preserves lockout state).
            Some(_) => return None,
            None => {}
        }
        if let Some(arr) = find(12).and_then(|v| match v { cbor::Value::A(a) => Some(a), _ => None }) {
            s.min_pin_rp_ids = arr.iter().filter_map(|i| match i { cbor::Value::T(s) => Some(s.clone()), _ => None }).collect();
        }
        if let Some(arr) = find(13).and_then(|v| match v { cbor::Value::A(a) => Some(a), _ => None }) {
            s.enterprise_rp_ids = arr.iter().filter_map(|i| match i { cbor::Value::T(s) => Some(s.clone()), _ => None }).collect();
        }
        // US-910: stretched-verifier fields. Key 14 is the format stamp;
        // a stretched record must carry its salt (key 15) or the snapshot
        // is corrupt — the verifier would be unverifiable.
        if let Some(f) = get_uint(14) {
            s.pin_verifier_format = f as u8;
        }
        if let Some(b) = get_bytes(15) {
            let salt: Option<[u8; 16]> = <[u8; 16]>::try_from(b.as_slice()).ok();
            s.pin_salt = salt;
        }
        if let Some(i) = get_uint(16) {
            // US-910 (review): pin_iter drives the verifier's stretched
            // SHA-256 rounds, so an attacker-crafted snapshot with a huge
            // iteration count wedges the PIN path for hours of compute.
            // Corrupt input is refused, never truncated.
            if i > crypto::PIN_VERIFIER_ROUNDS as u64 {
                return None;
            }
            s.pin_iter = i as u32;
        }
        if s.pin_verifier_format == crypto::PIN_VERIFIER_FORMAT_STRETCHED && s.pin_salt.is_none() {
            return None;
        }
        Some(s)
    }
}

impl AuthState {
    /// **Tests only.** The auth map as a CBOR value.
    ///
    /// `phy` (auth-map key 6) is written by this codec *and* by the device
    /// keystore's, in the same snapshot envelope, and US-113 review found the
    /// two silently disagreeing — one refused a 33-bit `vid_pid` where the
    /// other truncated it, so identical bytes loaded into two different hardware
    /// configurations depending on which stack read them. US-117 widened the
    /// record again, with a `u16` mask and a 17-byte block, which adds two
    /// more ways to drift: a field number one codec writes and the other
    /// refuses outright, and a value shape that is a byte string where every
    /// other field is an integer.
    ///
    /// This seam exists so that agreement can be checked from outside both
    /// modules rather than inferred from two unit tests that each sit next to
    /// one codec.
    /// `tests/vendor41.rs::key6_round_trips_through_both_keystores` is that
    /// check. `#[doc(hidden)]` follows [`PinState::to_cbor_for_test`] in this
    /// file.
    #[doc(hidden)]
    pub fn to_cbor_for_test(&self, key: Option<&[u8; 32]>) -> cbor::Value {
        self.to_cbor(key)
    }

    /// **Tests only.** The decode half of [`Self::to_cbor_for_test`], taking
    /// the `sealed` flag the snapshot format carries.
    #[doc(hidden)]
    pub fn from_cbor_for_test(bytes: &[u8], key: Option<&[u8; 32]>, sealed: bool) -> Option<Self> {
        Self::from_cbor(bytes, key, sealed)
    }

    /// US-911: the auth-level sensitive fields — large_blob_array (3),
    /// vault_state (4), device_random (5, the stateless master) — are
    /// sealed under the store key (AAD scope tags, empty credential ID).
    fn to_cbor(&self, key: Option<&[u8; 32]>) -> cbor::Value {
        use cbor::Value::*;
        let seal = |scope: FieldScope, pt: &[u8]| -> Vec<u8> {
            match key {
                Some(k) => {
                    let aad = FieldAad::new(FILE_KEYSTORE_SLOT, scope, &[]);
                    let mut blob = vec![0u8; pt.len() + snapshot_crypt::FIELD_OVERHEAD];
                    // Unreachable failure: the blob is exactly sized and
                    // the host fields are heap-sized.
                    snapshot_crypt::seal_field(k, aad.bytes(), pt, &mut blob)
                        .expect("seal_field on a caller-sized host blob cannot fail");
                    blob
                }
                None => pt.to_vec(),
            }
        };
        let mut entries: Vec<(cbor::Value, cbor::Value)> =
            vec![(U(1), self.pin_state.to_cbor()), (U(2), U(self.cred_counter as u64))];
        if let Some(ref blob) = self.large_blob_array {
            entries.push((U(3), B(seal(FieldScope::AuthLargeBlobArray, blob))));
        }
        if let Some(ref vault) = self.vault_state {
            entries.push((U(4), B(seal(FieldScope::AuthVaultState, vault))));
        }
        entries.push((U(5), B(seal(FieldScope::AuthDeviceRandom, &self.device_random))));
        // US-113: key 6, emitted only once something was written, so a device
        // that has never seen a `0xFF` keeps byte-identical snapshots to
        // before this story. Plaintext in both formats — see `AuthState::phy`.
        if self.phy != crate::vendorff::PhyConfig::default() {
            let mut phy: Vec<(cbor::Value, cbor::Value)> = Vec::new();
            if let Some(v) = self.phy.vid_pid {
                phy.push((U(1), U(v as u64)));
            }
            if let Some(v) = self.phy.led_gpio {
                phy.push((U(2), U(v as u64)));
            }
            if let Some(v) = self.phy.led_brightness {
                phy.push((U(3), U(v as u64)));
            }
            if let Some(v) = self.phy.options {
                phy.push((U(4), U(v as u64)));
            }
            if let Some(v) = self.phy.enabled_usb_itf {
                phy.push((U(PHY_FIELD_ENABLED_USB_ITF), U(v as u64)));
            }
            if let Some(block) = self.phy.led_conf {
                phy.push((U(PHY_FIELD_LED_CONF), B(block.0.to_vec())));
            }
            // The two identity names: same field numbers, same order, and the
            // same "stored bytes only, no terminator" rule as the device
            // encoder in `device_keystore.rs`. The two must agree byte-for-byte
            // — that is what
            // `tests/vendor41.rs::key6_round_trips_through_both_keystores` is
            // for, and it is why these are spelled out here rather than
            // derived from `field_count` and a field list.
            if let Some(name) = self.phy.product {
                phy.push((U(PHY_FIELD_PRODUCT), B(name.as_bytes().to_vec())));
            }
            if let Some(name) = self.phy.manufacturer {
                phy.push((U(PHY_FIELD_MANUFACTURER), B(name.as_bytes().to_vec())));
            }
            entries.push((U(6), M(phy)));
        }
        // US-176: the RS-Key `0x41` state, auth keys 7 (sealed) and 8
        // (plaintext). The byte layouts come from `vendor_state` so the two
        // stacks cannot drift on them; what is host-specific is only the AAD
        // slot name, which is already different for keys 3/4/5.
        //
        // Both keys are omitted when their half is empty, so a host that has
        // never seen a `0x41` keeps writing byte-identical snapshots.
        if let Some(pt) = self.vendor.secret_plaintext().ok().flatten() {
            entries.push((U(7), B(seal(FieldScope::AuthVendorSecret, &pt))));
        }
        if let Some(bytes) = self.vendor.public_bytes().ok().flatten() {
            // The map's layout is `vendor_state`'s to define and is written
            // once, by `public_bytes`; the host wraps it in the same byte
            // string the device writes, so the two decoders take the same arm.
            entries.push((U(8), B(bytes.to_vec())));
        }
        M(entries)
    }

    /// US-911: an auth-level field that fails to open fails the WHOLE
    /// snapshot (`None` = Corrupt, fatal per FX-409) — the stateless master
    /// is never garbage.
    fn from_cbor(bytes: &[u8], key: Option<&[u8; 32]>, sealed: bool) -> Option<Self> {
        use cbor::Value::*;
        let (val, _) = cbor::decode(bytes).ok()?;
        let map = match val {
            M(m) => m,
            _ => return None,
        };
        // US-911 helper: open an auth-level sealed field; failure is fatal.
        let open = |scope: FieldScope, blob: &[u8]| -> Option<Vec<u8>> {
            let key = key?;
            let aad = FieldAad::new(FILE_KEYSTORE_SLOT, scope, &[]);
            snapshot_crypt::open_field_vec(key, aad.bytes(), blob)
        };
        let mut s = Self::default();
        if let Some(pin_val) = map.iter().find(|(k, _)| matches!(k, cbor::Value::U(1))).map(|(_, v)| v) {
            if let Some(ps) = PinState::from_cbor(pin_val) {
                s.pin_state = ps;
            }
        }
        if let Some(u) = map.iter().find(|(k, _)| matches!(k, cbor::Value::U(2))).and_then(|(_, v)| match v {
            cbor::Value::U(u) => Some(*u),
            _ => None,
        }) {
            s.cred_counter = u as u32;
        }
        if let Some(bytes) = map.iter().find(|(k, _)| matches!(k, cbor::Value::U(5))).and_then(|(_, v)| match v {
            cbor::Value::B(b) => Some(b.clone()),
            _ => None,
        }) {
            let pt = if sealed {
                open(FieldScope::AuthDeviceRandom, &bytes)?
            } else {
                bytes
            };
            if pt.len() == 32 {
                s.device_random.copy_from_slice(&pt);
            } else if sealed {
                // A successfully-decrypted but wrong-length master is not a
                // value we can trust (the device decoder refuses it too).
                return None;
            }
        }
        // FX-409: large_blob_array and vault_state must round-trip.
        if let Some(b) = map.iter().find(|(k, _)| matches!(k, cbor::Value::U(3))).and_then(|(_, v)| match v {
            cbor::Value::B(b) => Some(b.clone()),
            _ => None,
        }) {
            let pt = if sealed {
                open(FieldScope::AuthLargeBlobArray, &b)?
            } else {
                b
            };
            s.large_blob_array = Some(pt);
        }
        if let Some(b) = map.iter().find(|(k, _)| matches!(k, cbor::Value::U(4))).and_then(|(_, v)| match v {
            cbor::Value::B(b) => Some(b.clone()),
            _ => None,
        }) {
            let pt = if sealed {
                open(FieldScope::AuthVaultState, &b)?
            } else {
                b
            };
            s.vault_state = Some(pt);
        }
        // US-113: physical config (key 6). Absent in every snapshot written
        // before this story, which is why the default is left in place rather
        // than an absent key being an error.
        if let Some(phy_val) = map.iter().find(|(k, _)| matches!(k, cbor::Value::U(6))).map(|(_, v)| v) {
            let cbor::Value::M(pairs) = phy_val else {
                // A key-6 value that is not a map: the snapshot is not one
                // this firmware wrote. Refusing is the FX-440 contract; taking
                // the default would silently discard an operator's hardware
                // configuration, which is exactly the write whose loss nobody
                // would notice until the device came up wrong.
                return None;
            };
            for (k, v) in pairs {
                let field = match k {
                    cbor::Value::U(u) => *u,
                    _ => return None,
                };
                // US-117: field 6 is the only one that is not an integer, so
                // the value's CBOR type is selected *by the field* rather than
                // demanded of every field. Dispatching on `field` first (below)
                // is what keeps the "unknown field is a refusal" rule intact
                // for a map that mixes the two shapes.
                if field == PHY_FIELD_LED_CONF {
                    let cbor::Value::B(bytes) = v else {
                        return None;
                    };
                    s.phy.led_conf = Some(LedConf(
                        <[u8; LedConf::LEN]>::try_from(bytes.as_slice()).ok()?,
                    ));
                    continue;
                }
                // Fields 7 and 8 are the two identity names — the record's
                // other byte-string members, dispatched by field number for
                // the same reason as field 6. Bounds come from
                // `IdentityName::new`, so a stored name the two decoders
                // disagree about cannot survive: a name too long, or carrying
                // an interior NUL, refuses the snapshot here exactly as it
                // refuses the write in `vendor41::apply_phy_record`.
                if field == PHY_FIELD_PRODUCT || field == PHY_FIELD_MANUFACTURER {
                    let cbor::Value::B(bytes) = v else {
                        return None;
                    };
                    let name = IdentityName::new(core::str::from_utf8(bytes).ok()?)?;
                    if field == PHY_FIELD_PRODUCT {
                        s.phy.product = Some(name);
                    } else {
                        s.phy.manufacturer = Some(name);
                    }
                    continue;
                }
                let cbor::Value::U(raw) = v else {
                    return None;
                };
                match (field, *raw) {
                    (1, u) if u <= u32::MAX as u64 => s.phy.vid_pid = Some(u as u32),
                    (2, u) if u <= u8::MAX as u64 => s.phy.led_gpio = Some(u as u8),
                    (3, u) if u <= u8::MAX as u64 => s.phy.led_brightness = Some(u as u8),
                    (4, u) if u <= u16::MAX as u64 => s.phy.options = Some(u as u16),
                    // US-117: the `DEV_CONF` enabled-interface mask. Spelled
                    // with the `vendorff` constant rather than a bare `5`,
                    // because the encoder writes it by name and a decoder
                    // matching a literal is the half of the pair that drifts.
                    (PHY_FIELD_ENABLED_USB_ITF, u) if u <= u16::MAX as u64 => {
                        s.phy.enabled_usb_itf = Some(u as u16)
                    }
                    _ => return None,
                }
            }
        }
        // US-176: the RS-Key `0x41` state. Both halves are re-encoded and handed
        // to `vendor_state`'s own decoders rather than decoded here, so the
        // layout and the refusal rules exist exactly once — a second
        // implementation in this file is a second place for them to disagree,
        // and this pair of codecs has already disagreed once (the `vid_pid`
        // width in `us113_tests` below).
        //
        // The two halves keep their opposite policies: key 7 failing to open
        // fails the whole snapshot (`?`), key 8 degrading to its default.
        if let Some(cbor::Value::B(b)) =
            map.iter().find(|(k, _)| matches!(k, cbor::Value::U(7))).map(|(_, v)| v)
        {
            let pt = if sealed {
                open(FieldScope::AuthVendorSecret, b)?
            } else {
                b.clone()
            };
            s.vendor.secret =
                crate::vendor_state::VendorState::decode_secret(&pt, key, sealed).ok()?;
        }
        if let Some(cbor::Value::B(b)) =
            map.iter().find(|(k, _)| matches!(k, cbor::Value::U(8))).map(|(_, v)| v)
        {
            s.vendor.public = crate::vendor_state::VendorState::decode_public(b);
        }
        Some(s)
    }
}

#[cfg(test)]
mod us113_tests {
    //! The key-6 (`phy`) decoder arm's twin, in `device_keystore.rs`.
    //!
    //! Both tests exist for one reason: US-113 review found that the two
    //! key-6 decoders disagreed about a `vid_pid` wider than `u32` — this one
    //! refused, the device one truncated — so identical snapshot bytes loaded
    //! into different hardware configurations depending on which stack read
    //! them. The pair pins the shared answer.

    use super::*;

    /// `{1: <vid>}` — the auth map's key-6 value.
    fn key6_value(vid: u64) -> cbor::Value {
        cbor::Value::M(vec![(cbor::Value::U(1), cbor::Value::U(vid))])
    }

    /// The host decoder must refuse a `vid_pid` wider than `u32`, exactly as
    /// the device decoder does. Refusing is the shared answer because the
    /// alternative — truncating — yields a device that enumerates under an
    /// identity nobody selected.
    #[test]
    fn key6_vidpid_wider_than_u32_is_refused() {
        let mut auth = cbor::Value::M(vec![(cbor::Value::U(6), key6_value(0x1_0000_0000))]);
        let bytes = crate::cbor::encode(&auth);
        assert!(
            AuthState::from_cbor(&bytes, None, false).is_none(),
            "a 33-bit stored vid_pid must fail the snapshot outright rather \
             than truncate. Its twin in `device_keystore.rs` asserts the same \
             for the same bytes; the two decoders must not drift apart"
        );

        // The accept path, so the refusal above is about the width and not
        // about the map shape this helper builds.
        auth = cbor::Value::M(vec![(cbor::Value::U(6), key6_value(0x1209_0001))]);
        let bytes = crate::cbor::encode(&auth);
        let ok = AuthState::from_cbor(&bytes, None, false).expect("an in-range vid_pid must load");
        assert_eq!(ok.phy.vid_pid, Some(0x1209_0001));
    }
}
