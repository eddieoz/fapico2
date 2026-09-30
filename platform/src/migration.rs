//! First-boot C→Rust data migration orchestrator (US-413 S-413-5).
//!
//! Runs once on the first Rust boot after a C-firmware device is flashed:
//! detect (C partition used ∧ OTP key present ∧ Rust store empty ∧ no
//! migration marker), then re-seed the Rust [`SecureStore`] slots from the
//! C data partition — **strictly read-only** on the C region (the walker in
//! [`crate::cfs`] never writes; byte-identity is test-enforced).
//!
//! Per-class behavior (see `docs/tasks/us413-migration-feasibility.md`
//! section 8):
//!
//! * **Silent**: FIDO keydev (32/33 B records) → `fido.hkey`;
//!   management `EF_DEV_CONF` → `mgmt.conf.v1`; OATH / OTP / OpenPGP /
//!   PIV / FIDO-container records → per-class keystore slots as
//!   length-prefixed `[fid u16 LE][len u32 LE][payload]` streams (data
//!   preserved verbatim; app restore is post-cutover per the epic).
//! * **Passphrase-gated** (flagged, completed by the S-413-6 APDU): a
//!   61-byte PIN-wrapped keydev, and OpenPGP DEK wrappers (`0x1099`,
//!   `0x109A–0x109D`) whose private keys unlock only with the user's PW1.
//! * **Not migratable**: vendor-wrapped keydev material (`0xCC01`) with no
//!   device-side unwrap path (reported, never fatal).
//!
//! The C resident-credential containers (PKOC objects under the FIDO
//! namespace) are preserved byte-exact in the FIDO-container slot; the
//! v1.0.0 FIDO app is a shell (CTAP getInfo only), so live credential
//! re-encoding into the CBOR keystore snapshot is post-cutover work — the
//! data is preserved, matching the OATH/OTP pattern.

use crate::cflash::DataPartition;
use crate::cfs::{Cfs, CFlashSource, PoolBounds};
use crate::ckey::{self, CKeyError, KeydevStatus};
use crate::cfs::MAX_WHOLE_PAYLOAD;
use crate::secure_store::{SecureStore, SecureStoreError, MAX_VALUE_LEN};
use heapless::Vec as HVec;

/// Migration-complete marker slot. Presence makes every later boot a no-op.
pub const MIGRATION_MARKER: &[u8] = b"mig.done.v1";
/// FIDO persistent ECDH key slot (`apps/fido/src/device_app.rs:24`).
pub const SLOT_FIDO_HKEY: &[u8] = b"fido.hkey";
/// Management `EF_DEV_CONF` slot (`apps/mgmt/src/lib.rs:89`).
pub const SLOT_MGMT_CONF: &[u8] = b"mgmt.conf.v1";
pub const SLOT_OPENPGP: &[u8] = b"openpgp.keystore.v1";
pub const SLOT_OATH: &[u8] = b"oath.keystore.v1";
pub const SLOT_OTP: &[u8] = b"otp.keystore.v1";
pub const SLOT_PIV: &[u8] = b"piv.keystore.v1";
/// Raw preserved C FIDO container records (post-cutover restore input).
pub const SLOT_FIDO_CONTAINER: &[u8] = b"fido.ccontainer.v1";
/// Decrypted OpenPGP DEK (48 B: IV + key), written by the S-413-6
/// passphrase flow; the post-cutover OpenPGP app restores private keys
/// from it.
pub const SLOT_OPENPGP_DEK: &[u8] = b"openpgp.dek.v1";
/// US-918: the boot-entropy record (32 TRNG bytes, [`ckey::BOOT_ENTROPY_LEN`])
/// created at the first boot persist (device: `boot::ensure_boot_entropy`
/// before any derive caller; emulation: the same lifecycle through
/// `persist_boot_change`). It rides the v3-AEAD-sealed store image, so it is
/// authenticated (tamper → unseal fails → refuse) and is mixed into the
/// bound device root ([`ckey::derive_kbase`]) — a leaked OTP row alone must
/// not reconstruct the root. REQUIRED before any [`ckey::derive_kbase`]
/// caller runs on a store: the bound derivation refuses without it.
pub const SLOT_BOOT_ENTROPY: &[u8] = b"boot.entropy.v1";
/// Capture authenticator: HMAC-SHA256(kbase, serial_hash || captured bytes).
const SLOT_OPENPGP_SOURCE: &[u8] = b"openpgp.mig.source.v1";
/// Source-bound PW1 attempt state: source MAC (32), remaining (1), maximum (1).
/// Initialized only during capture, never regenerated during completion.
const SLOT_OPENPGP_RETRIES: &[u8] = b"openpgp.mig.retries.v1";
const SLOT_OPENPGP_PW3_RETRIES: &[u8] = b"openpgp.mig.pw3tries.v1";
const SLOT_OPENPGP_RC_RETRIES: &[u8] = b"openpgp.mig.rctries.v1";

/// Per-class record cap (matches the C side: ~68 resident credential slots
/// max, tens of OpenPGP DOs; 256 is comfortably above any real device).
const MAX_RECORDS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Marker slot present (this or an earlier boot already migrated).
    AlreadyMigrated,
    /// The Rust store already holds app secrets — not a first boot.
    StoreNotEmpty,
    /// C partition never initialized (no C data at all).
    CStateFactoryFresh,
    /// C partition initialized but file-less.
    CStateEmpty,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub hkey_migrated: bool,
    /// A 61-byte PIN-wrapped keydev and/or OpenPGP DEK wrappers are present:
    /// the S-413-6 passphrase APDU completes those classes.
    pub needs_passphrase: bool,
    pub dev_conf_migrated: bool,
    /// Vendor-wrapped keydev only — hkey not recoverable.
    pub keydev_not_migratable: bool,
    pub openpgp_records: u16,
    pub oath_records: u16,
    pub otp_records: u16,
    pub piv_records: u16,
    pub fido_container_records: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    Skipped(SkipReason),
    Done(MigrationReport),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationError {
    Cfs(crate::cfs::CfsError),
    CKey(CKeyError),
    Store(SecureStoreError),
    /// A class slot exceeded the store's per-slot value cap.
    SlotOverflow,
}

impl From<crate::cfs::CfsError> for MigrationError {
    fn from(e: crate::cfs::CfsError) -> Self {
        MigrationError::Cfs(e)
    }
}
impl From<CKeyError> for MigrationError {
    fn from(e: CKeyError) -> Self {
        MigrationError::CKey(e)
    }
}
impl From<SecureStoreError> for MigrationError {
    fn from(e: SecureStoreError) -> Self {
        MigrationError::Store(e)
    }
}

/// US-918: the chipid as a `u64` big-endian word — the inverse of the
/// device boot path's `chipid.to_be_bytes()` flash-UID convention
/// (`firmware/src/boot.rs` passes `&chipid.to_be_bytes()` as the UID).
/// Fail-closed: fewer than 8 UID bytes is [`CKeyError::BadLength`].
///
/// `pub` since US-1003: the DRBG seed derivation binds the chipid the same
/// way, and it re-reads this rather than re-deriving the word, so the two
/// roots can never disagree about which device they are for.
pub fn chipid_from_uid(uid: &[u8]) -> Result<u64, CKeyError> {
    let bytes: [u8; 8] = uid
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .ok_or(CKeyError::BadLength)?;
    Ok(u64::from_be_bytes(bytes))
}

/// US-918: load the boot-entropy record ([`SLOT_BOOT_ENTROPY`]) from the
/// store. `Ok(None)` only for a genuinely absent record (the caller's
/// bound derivation then refuses — fail-closed); a record of the wrong
/// length is [`CKeyError::BadLength`] (corrupt media, never guess).
///
/// `pub` since US-1003: the DRBG seed reads the *same* record, and a
/// second reader with its own length rule is how a "the record was there,
/// the other reader just accepted a short one" divergence starts. One
/// accessor, one rule.
///
/// # The local is zeroized (I-2)
///
/// This is a live-entropy record, and it is now written into a
/// [`zeroize::Zeroizing`] buffer that is cleared on every return — success,
/// refusal, and error alike. Before US-1003's review fix those 32 bytes
/// outlived the frame on the stack. The value still *leaves* this function
/// by value (its callers need it), so this closes **this** copy and not the
/// caller's: the DRBG seed path wraps its own copy in `Zeroizing` for that
/// reason, and `boot_kbase`'s caller-side copy is US-918's to change.
pub fn boot_entropy_from<K: SecureStore>(
    store: &mut K,
) -> Result<Option<[u8; ckey::BOOT_ENTROPY_LEN]>, MigrationError> {
    let mut entropy = zeroize::Zeroizing::new([0u8; ckey::BOOT_ENTROPY_LEN]);
    match store.read(SLOT_BOOT_ENTROPY, &mut entropy[..]) {
        Ok(n) if n == entropy.len() => Ok(Some(*entropy)),
        Ok(_) => Err(CKeyError::BadLength.into()),
        Err(SecureStoreError::NotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// US-918: the bound device root for this device, derived with the
/// boot-entropy record read from `store` (fail-closed: a missing record is
/// [`CKeyError::MissingBootEntropy`]). The Rust-side root consumer —
/// everything THIS firmware derives; the C-firmware root
/// ([`ckey::derive_kbase_c`]) stays open-only for C-produced material.
fn boot_kbase<K: SecureStore>(
    store: &mut K,
    otp: &[u8; 32],
    uid: &[u8],
) -> Result<zeroize::Zeroizing<[u8; 32]>, MigrationError> {
    let entropy = boot_entropy_from(store)?;
    Ok(zeroize::Zeroizing::new(ckey::derive_kbase(
        otp,
        &ckey::serial_hash(uid),
        chipid_from_uid(uid)?,
        entropy.as_ref(),
    )?))
}

/// Stable, domain-separated native PW1 KEK for an authenticated captured source.
/// This is internal migration plumbing, not an authentication decision.
///
/// US-918: derived through the bound device root — the boot-entropy record
/// is read from `store` (fail-closed, [`ckey::CKeyError::MissingBootEntropy`]
/// when absent), so a leaked OTP row alone does not reconstruct the KEK.
pub fn native_openpgp_wrapping_key<K: SecureStore>(
    store: &mut K,
    otp: &[u8; 32], uid: &[u8], source: &[u8; 32],
) -> Result<zeroize::Zeroizing<[u8; 32]>, MigrationError> {
    use hmac::Mac;
    let root = boot_kbase(store, otp, uid)?;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&root[..])
        .map_err(|_| CKeyError::BadLength)?;
    mac.update(b"fapico2/openpgp/native-pw1-kek/v1");
    mac.update(source);
    Ok(zeroize::Zeroizing::new(mac.finalize().into_bytes().into()))
}

/// One migrated record in a class slot: `[fid u16 LE][len u32 LE][payload]`.
fn push_tlv(
    slot: &mut heapless::Vec<u8, { crate::secure_store::MAX_VALUE_LEN }>,
    fid: u16,
    payload: &[u8],
) -> Result<(), MigrationError> {
    let mut hdr = [0u8; 6];
    hdr[0..2].copy_from_slice(&fid.to_le_bytes());
    hdr[2..6].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    slot.extend_from_slice(&hdr)
        .map_err(|_| MigrationError::SlotOverflow)?;
    slot.extend_from_slice(payload)
        .map_err(|_| MigrationError::SlotOverflow)
}

/// Caller-provided working buffers. ~96 KiB total — on device these live in
/// a `static mut` (bss), never on the boot-path stack.
pub struct MigrationBuffers {
    /// Largest single-record read (`cfs::MAX_WHOLE_PAYLOAD`).
    pub scratch: [u8; MAX_WHOLE_PAYLOAD],
    pub openpgp: HVec<u8, MAX_VALUE_LEN>,
    pub oath: HVec<u8, MAX_VALUE_LEN>,
    pub otp: HVec<u8, MAX_VALUE_LEN>,
    pub piv: HVec<u8, MAX_VALUE_LEN>,
    pub fido: HVec<u8, MAX_VALUE_LEN>,
}

impl Default for MigrationBuffers {
    fn default() -> Self {
        Self::new()
    }
}

impl MigrationBuffers {
    pub const fn new() -> Self {
        MigrationBuffers {
            scratch: [0; MAX_WHOLE_PAYLOAD],
            openpgp: HVec::new(),
            oath: HVec::new(),
            otp: HVec::new(),
            piv: HVec::new(),
            fido: HVec::new(),
        }
    }

    fn clear(&mut self) {
        self.openpgp.clear();
        self.oath.clear();
        self.otp.clear();
        self.piv.clear();
        self.fido.clear();
    }
}

/// Look up the newest record, while validating the entire captured stream.
/// C's linked list is newest-first; older duplicate FIDs must not win.
fn captured_record(bytes: &[u8], fid: u16) -> Result<Option<&[u8]>, MigrationError> {
    let mut rest = bytes;
    let mut found = None;
    while !rest.is_empty() {
        let header = rest.get(..6).ok_or(CKeyError::BadFormat)?;
        let id = u16::from_le_bytes([header[0], header[1]]);
        let len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        rest = &rest[6..];
        let payload = rest.get(..len).ok_or(CKeyError::BadLength)?;
        if id == fid && found.is_none() {
            found = Some(payload);
        }
        rest = &rest[len..];
    }
    Ok(found)
}

fn be16(bytes: &[u8], offset: usize) -> Result<u16, CKeyError> {
    let value = bytes.get(offset..offset + 2).ok_or(CKeyError::BadLength)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn be32(bytes: &[u8], offset: usize) -> Result<u32, CKeyError> {
    let value = bytes.get(offset..offset + 4).ok_or(CKeyError::BadLength)?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

/// A capture verified against the device-bound source authenticator.
/// Record lookup retains C's newest-first duplicate semantics.
pub struct OpenPgpCapture<'a> {
    bytes: &'a [u8],
    source: [u8; 32],
}

impl OpenPgpCapture<'_> {
    /// Authenticator identifying this exact source and device.
    pub fn source(&self) -> [u8; 32] {
        self.source
    }

    /// Read an authenticated public key selected by its merged-C manifest.
    /// Unsupported extensions and ambiguous generations fail closed. No DEK is
    /// needed and unauthenticated logical public-file copies are never used.
    pub fn read_public_key(
        &self,
        fid: u16,
        otp: &[u8; 32],
        uid: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, MigrationError> {
        self.read_key_object(fid, otp, uid, None, out)
    }

    /// Unseal the manifest-selected private object with the completed C DEK.
    /// The caller owns zeroizing output scratch; no source records are changed.
    pub fn read_private_key(
        &self,
        fid: u16,
        otp: &[u8; 32],
        uid: &[u8],
        dek: &[u8; 48],
        out: &mut [u8],
    ) -> Result<Option<usize>, MigrationError> {
        let root: &[u8; 32] = dek[16..].try_into().map_err(|_| CKeyError::BadLength)?;
        let result = self.read_key_object(fid, otp, uid, Some(root), out);
        if result.is_err() {
            use zeroize::Zeroize;
            out.zeroize();
        }
        result
    }

    fn read_key_object(
        &self,
        fid: u16,
        otp: &[u8; 32],
        uid: &[u8],
        private_root: Option<&[u8; 32]>,
        out: &mut [u8],
    ) -> Result<Option<usize>, MigrationError> {
        if !(0x10d1..=0x10d3).contains(&fid) {
            return Err(CKeyError::BadFormat.into());
        }
        // The C manifests/PKOR records are pinned to the C firmware's own
        // two-input root (US-918: open-only compat, see `derive_kbase_c`).
        let root = zeroize::Zeroizing::new(ckey::derive_kbase_c(otp, &ckey::serial_hash(uid))?);
        let seal_root: &[u8; 32] = private_root.unwrap_or(&root);
        let mut selected = None;
        for prefix in [0xe800, 0xe900] {
            if let Some(bytes) = self.record(prefix | (fid & 255))? {
                if bytes.is_empty() {
                    continue;
                }
                // Deliberately stricter than C's fallback: a damaged candidate
                // must not silently roll the identity back to an older key.
                let candidate = self.public_candidate(fid, bytes, &root)?;
                match &selected {
                    Some((generation, _)) if *generation == candidate.0 => {
                        return Err(CKeyError::BadFormat.into());
                    }
                    Some((generation, _)) if *generation > candidate.0 => {}
                    _ => selected = Some(candidate),
                }
            }
        }
        let wanted_type = if private_root.is_some() { 1u16 } else { 2u16 };
        let Some((_, identities)) = selected else {
            return if self.record(fid)?.is_some_and(|v| !v.is_empty()) {
                Err(CKeyError::BadFormat.into())
            } else {
                Ok(None)
            };
        };
        let Some(identity) = identities.iter().find(|id| id.object_type == wanted_type) else {
            return Err(CKeyError::BadFormat.into());
        };
        let record = self.record(identity.record_id as u16)?.ok_or(CKeyError::BadFormat)?;
        // US-705.3: guarded slicing (defense-in-depth) — a damaged/stored_size
        // corrupt record returns BadLength instead of panicking on an
        // out-of-range index, even though `public_candidate` validates the
        // record layout first.
        let end = 40 + identity.stored_size as usize;
        let body = record.get(40..end).ok_or(CKeyError::BadLength)?;
        let tag: &[u8; ckey::RECORD_TAG_LEN] = record
            .get(end..)
            .and_then(|t| t.try_into().ok())
            .ok_or(CKeyError::BadLength)?;
        Ok(Some(ckey::unseal_record(seal_root, 5, identity, body, tag, out)?))
    }

    fn public_candidate(
        &self,
        fid: u16,
        bytes: &[u8],
        root: &[u8; 32],
    ) -> Result<(u32, heapless::Vec<ckey::RecordIdentity, 2>), MigrationError> {
        use hmac::Mac;
        use sha2::Digest;
        use subtle::ConstantTimeEq;
        if bytes.len() < 48 || &bytes[..6] != b"PKOC\x01\x20" {
            return Err(CKeyError::BadFormat.into());
        }
        let count = be16(bytes, 24)? as usize;
        // This importer supports the producer's two-object key profile, not
        // arbitrary container extensions or additional object types.
        if count != 2 || bytes[26..28] != [36, 0]
            || be16(bytes, 28)? != 0 || be16(bytes, 30)? as usize != bytes.len()
            || bytes.len() != 32 + count * 36 + 16
        {
            return Err(CKeyError::BadLength.into());
        }
        let key = zeroize::Zeroizing::new(ckey::derive_manifest_key(root, 5));
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&key[..])
            .map_err(|_| CKeyError::BadFormat)?;
        mac.update(&bytes[..bytes.len() - 16]);
        if !bool::from(mac.finalize().into_bytes()[..16].ct_eq(&bytes[bytes.len() - 16..])) {
            return Err(CKeyError::AuthFailed.into());
        }
        let generation = be32(bytes, 16)?;
        if be16(bytes, 6)? != 0 || be16(bytes, 8)? != 5 || be16(bytes, 10)? != 1
            || be32(bytes, 12)? != fid as u32 || generation == 0
            || be32(bytes, 20)? >= generation
        {
            return Err(CKeyError::BadFormat.into());
        }
        let policy = sha2::Sha256::digest([
            1, 1, 0x1f, 0xff, 0, 0, 4, 0x60, 0, 0, 0, 0, 0, 1, 0, 0,
        ]);
        let mut identities = heapless::Vec::<ckey::RecordIdentity, 2>::new();
        for index in 0..count {
            let d = &bytes[32 + index * 36..32 + (index + 1) * 36];
            let typ = (index + 1) as u16;
            let protection = if typ == 1 { 2 } else { 1 };
            let flags = if typ == 1 { 6 } else { 10 };
            let rid = u64::from_be_bytes(d[12..20].try_into().map_err(|_| CKeyError::BadLength)?);
            let prefix = if typ == 1 { 0xea00 } else { 0xeb00 };
            if be16(d, 0)? != typ || be16(d, 2)? != 0 || be32(d, 4)? == 0
                || be16(d, 24)? != 0x500 || d[26] != 0 || d[27] != protection
                || be16(d, 28)? != flags || d[30..] != [0; 6]
                || ![prefix | (fid & 255), (prefix + 0x100) | (fid & 255)]
                    .iter().any(|allowed| u64::from(*allowed) == rid)
            {
                return Err(CKeyError::BadFormat.into());
            }
            let mut policy_hash = [0; 16];
            policy_hash.copy_from_slice(&policy[..16]);
            let id = ckey::RecordIdentity {
                version: 1, protection, record_id: rid,
                stored_size: be32(d, 20)?, logical_size: be32(d, 8)?,
                generation: be32(d, 4)?, namespace_id: 5, container_kind: 1,
                container_id: fid as u32, object_type: typ, object_tag: 0,
                policy_id: 0x500, policy_hash, key_domain: 0, flags,
            };
            let record = self.record(rid as u16)?.ok_or(CKeyError::BadFormat)?;
            if record.len() < 56 || &record[..4] != b"PKOR" || record[4] != 1
                || record[5] != protection || be16(record, 6)? != 40
                || record[8..16] != rid.to_be_bytes()
                || be32(record, 16)? != id.stored_size
                || be32(record, 20)? != id.logical_size
                || id.logical_size != id.stored_size
                || be32(record, 24)? != id.generation
                || record[28..40] != ckey::record_nonce(rid, id.generation)
                || record.len() - 56 != id.stored_size as usize
            {
                return Err(CKeyError::BadFormat.into());
            }
            identities.push(id).map_err(|_| CKeyError::BadFormat)?;
        }
        Ok((generation, identities))
    }

    /// Read a captured logical or physical record without accessing C flash.
    pub fn record(&self, fid: u16) -> Result<Option<&[u8]>, MigrationError> {
        captured_record(self.bytes, fid)
    }
}

/// Load and authenticate a complete captured OpenPGP stream into caller scratch.
/// No store writes occur, including on malformed or unauthenticated input.
pub fn read_openpgp_capture<'a, K: SecureStore>(
    store: &mut K,
    otp: &[u8; 32],
    uid: &[u8],
    scratch: &'a mut [u8],
) -> Result<OpenPgpCapture<'a>, MigrationError> {
    use subtle::ConstantTimeEq;
    let sh = ckey::serial_hash(uid);
    // US-918: the capture authenticator is keyed by the BOUND device root
    // (chipid + boot entropy) — the same root `run` wrote it with.
    let kbase = boot_kbase(store, otp, uid)?;
    let n = crate::secure_store::chunked::read_chunked(store, SLOT_OPENPGP, scratch)?;
    let bytes = &scratch[..n];
    let mut source = [0; 32];
    if store.read(SLOT_OPENPGP_SOURCE, &mut source)? != source.len()
        || !bool::from(source.ct_eq(&capture_mac(bytes, &sh, &kbase)))
    {
        return Err(CKeyError::AuthFailed.into());
    }
    captured_record(bytes, 0)?; // Validate the full TLV stream before exposing it.
    Ok(OpenPgpCapture { bytes, source })
}

fn capture_mac(bytes: &[u8], sh: &[u8; 32], kbase: &[u8; 32]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(kbase).expect("HMAC key");
    mac.update(b"fapico2/openpgp/capture/v1");
    mac.update(sh);
    mac.update(bytes);
    mac.finalize().into_bytes().into()
}

/// Outcome of compatibility PIN verification, distinct from DEK completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapturedPinResult {
    /// Correct PIN; no DEK has been released by verification.
    Verified,
    /// Incorrect PIN and the persisted attempts left after this request.
    Rejected { remaining: u8 },
    /// No attempts remain; the supplied PIN was not checked.
    Blocked,
    /// The captured credential profile is not supported.
    Unsupported,
}

/// Verify captured PW1 using the completion retry authority, without releasing a DEK.
/// The caller must durably persist store changes before acknowledging any result.
pub fn verify_captured_openpgp_pw1<K: SecureStore>(
    store: &mut K,
    otp: &[u8; 32],
    uid: &[u8],
    bufs: &mut MigrationBuffers,
    passphrase: &[u8],
) -> Result<CapturedPinResult, MigrationError> {
    if captured_openpgp_pw1_handed_off(store)? {
        return Err(SecureStoreError::Corrupt.into());
    }
    verify_captured_pw1_inner(store, otp, uid, bufs, passphrase)
}

/// Authenticate only an interrupted, source-bound native install. A committed
/// handoff can never re-enter this route. Caller flushes even errors/rejections.
pub fn verify_pending_openpgp_pw1<K: SecureStore>(
    store: &mut K, otp: &[u8; 32], uid: &[u8],
    bufs: &mut MigrationBuffers, passphrase: &[u8],
) -> Result<CapturedPinResult, MigrationError> {
    if !captured_openpgp_pw1_handoff_pending(store)? {
        return Err(SecureStoreError::Corrupt.into());
    }
    verify_captured_pw1_inner(store, otp, uid, bufs, passphrase)
}

fn verify_captured_pw1_inner<K: SecureStore>(
    store: &mut K, otp: &[u8; 32], uid: &[u8],
    bufs: &mut MigrationBuffers, passphrase: &[u8],
) -> Result<CapturedPinResult, MigrationError> {
    use subtle::ConstantTimeEq;
    use zeroize::Zeroizing;
    let n = crate::secure_store::chunked::read_chunked(store, SLOT_OPENPGP, &mut bufs.scratch)?;
    let captured = &bufs.scratch[..n];
    let sh = Zeroizing::new(ckey::serial_hash(uid));
    // US-918: capture authenticator — bound root; PIN chain — C root (the
    // C firmware created the verifier records, open-only compat).
    let kbase = boot_kbase(store, otp, uid)?;
    let kbase_c = Zeroizing::new(ckey::derive_kbase_c(otp, &sh)?);
    let mut source = [0; 32];
    if store.read(SLOT_OPENPGP_SOURCE, &mut source)? != source.len()
        || !bool::from(source.ct_eq(&capture_mac(captured, &sh, &kbase)))
    {
        return Err(CKeyError::AuthFailed.into());
    }
    let verifier = captured_record(captured, 0x1081)?.ok_or(CKeyError::BadFormat)?;
    let (result, mut attempts) = check_captured_pw1(
        store, &source, verifier, &sh, &kbase_c, passphrase,
    )?;
    if result == CapturedPinResult::Verified {
        attempts[32] = attempts[33];
        store.write(SLOT_OPENPGP_RETRIES, &attempts)?;
    }
    Ok(result)
}

/// Slots holding migration-owned opcard compatibility credentials.
pub const SLOT_OPENPGP_HANDOFF: &[u8] = b"openpgp.mig.handoff.v1";

/// Read the authenticated capture's current PW1 budget without spending an attempt.
pub fn captured_openpgp_pw1_retries<K: SecureStore>(
    store: &mut K,
    otp: &[u8; 32],
    uid: &[u8],
    bufs: &mut MigrationBuffers,
) -> Result<u8, MigrationError> {
    use subtle::ConstantTimeEq;
    let capture = read_openpgp_capture(store, otp, uid, &mut bufs.scratch)?;
    let verifier = capture.record(0x1081)?.ok_or(CKeyError::BadFormat)?;
    if verifier.len() != 34 || verifier[1] != 1 {
        return Err(CKeyError::BadFormat.into());
    }
    let mut attempts = [0; 34];
    if store.read(SLOT_OPENPGP_RETRIES, &mut attempts)? != attempts.len()
        || !bool::from(attempts[..32].ct_eq(&capture.source()))
        || attempts[32] > attempts[33]
    {
        return Err(SecureStoreError::Corrupt.into());
    }
    Ok(attempts[32])
}

/// Whether a source-bound OpenPGP capture was recorded (other migrated
/// app classes do not imply that an OpenPGP capture exists).
pub fn has_openpgp_capture<K: SecureStore>(store: &K) -> bool {
    store.contains(SLOT_OPENPGP_SOURCE)
}

/// Has the compatibility credential handed off to the native opcard PIN?
pub fn captured_openpgp_pw1_handed_off<K: SecureStore>(
    store: &mut K,
) -> Result<bool, MigrationError> {
    Ok(openpgp_handoff_state(store)?.is_some())
}

fn openpgp_handoff_state<K: SecureStore>(store: &mut K) -> Result<Option<bool>, MigrationError> {
    let mut source = [0; 32];
    let mut flag = [0; 33];
    let n = match store.read(SLOT_OPENPGP_HANDOFF, &mut flag) {
        Err(SecureStoreError::NotFound) => return Ok(None),
        Ok(n) => n,
        Err(error) => return Err(error.into()),
    };
    if store.read(SLOT_OPENPGP_SOURCE, &mut source)? != 32 || flag[..32] != source {
        return Err(SecureStoreError::Corrupt.into());
    }
    match n {
        32 => Ok(Some(false)),
        33 if flag[32] == 0 => Ok(Some(true)),
        _ => Err(SecureStoreError::Corrupt.into()),
    }
}

/// True only while native credential installation is pending for this source.
pub fn captured_openpgp_pw1_handoff_pending<K: SecureStore>(store: &mut K) -> Result<bool, MigrationError> {
    Ok(openpgp_handoff_state(store)? == Some(true))
}

/// Retire APDU compatibility verification while retaining budgeted install recovery.
pub fn begin_captured_openpgp_pw1_handoff<K: SecureStore>(store: &mut K) -> Result<(), MigrationError> {
    match openpgp_handoff_state(store)? {
        Some(true) => return Ok(()),
        Some(false) => return Err(SecureStoreError::Corrupt.into()),
        None => {}
    }
    let mut pending = [0; 33];
    if store.read(SLOT_OPENPGP_SOURCE, &mut pending[..32])? != 32 {
        return Err(SecureStoreError::Corrupt.into());
    }
    store.write(SLOT_OPENPGP_HANDOFF, &pending)?;
    Ok(())
}

/// Durably record the one-time native handoff. Callers acknowledge the APDU
/// only after the store is durably flushed.
pub fn commit_captured_openpgp_pw1_handoff<K: SecureStore>(
    store: &mut K,
) -> Result<(), MigrationError> {
    let mut source = [0; 32];
    if store.read(SLOT_OPENPGP_SOURCE, &mut source)? != 32 {
        return Err(SecureStoreError::Corrupt.into());
    }
    store.write(SLOT_OPENPGP_HANDOFF, &source)?;
    Ok(())
}

/// Read the source-bound PW3 retry budget. Missing state is never reinitialized.
pub fn captured_openpgp_pw3_retries<K: SecureStore>(
    store: &mut K, otp: &[u8; 32], uid: &[u8], bufs: &mut MigrationBuffers,
) -> Result<u8, MigrationError> {
    use subtle::ConstantTimeEq;
    let capture = read_openpgp_capture(store, otp, uid, &mut bufs.scratch)?;
    let verifier = capture.record(0x1083)?.ok_or(CKeyError::BadFormat)?;
    if verifier.len() != 34 || verifier[1] != 1 {
        return Err(CKeyError::BadFormat.into());
    }
    let mut attempts = [0; 34];
    if store.read(SLOT_OPENPGP_PW3_RETRIES, &mut attempts)? != attempts.len()
        || !bool::from(attempts[..32].ct_eq(&capture.source()))
        || attempts[32] > attempts[33]
    {
        return Err(SecureStoreError::Corrupt.into());
    }
    Ok(attempts[32])
}

/// Verify PW3 independently of the PW1 handoff. Caller persists before replying.
pub fn verify_captured_openpgp_pw3<K: SecureStore>(
    store: &mut K, otp: &[u8; 32], uid: &[u8], bufs: &mut MigrationBuffers,
    passphrase: &[u8],
) -> Result<CapturedPinResult, MigrationError> {
    use zeroize::Zeroizing;
    let capture = read_openpgp_capture(store, otp, uid, &mut bufs.scratch)?;
    let verifier = capture.record(0x1083)?.ok_or(CKeyError::BadFormat)?;
    let sh = Zeroizing::new(ckey::serial_hash(uid));
    // US-918: the C firmware created the verifier records — C root.
    let kbase = Zeroizing::new(ckey::derive_kbase_c(otp, &sh)?);
    let (result, mut attempts) = check_captured_pin(
        store, &capture.source(), verifier, &sh, &kbase, passphrase,
        SLOT_OPENPGP_PW3_RETRIES,
    )?;
    if result == CapturedPinResult::Verified {
        attempts[32] = attempts[33];
        store.write(SLOT_OPENPGP_PW3_RETRIES, &attempts)?;
    }
    Ok(result)
}

/// Read the source-bound ResetCode retry budget. Absent captures report None.
pub fn captured_openpgp_rc_retries<K: SecureStore>(
    store: &mut K, otp: &[u8; 32], uid: &[u8], bufs: &mut MigrationBuffers,
) -> Result<Option<u8>, MigrationError> {
    use subtle::ConstantTimeEq;
    let capture = read_openpgp_capture(store, otp, uid, &mut bufs.scratch)?;
    let Some(verifier) = capture.record(0x1082)? else { return Ok(None) };
    if verifier.len() != 34 || verifier[1] != 1 {
        return Err(CKeyError::BadFormat.into());
    }
    let mut attempts = [0; 34];
    if store.read(SLOT_OPENPGP_RC_RETRIES, &mut attempts)? != attempts.len()
        || !bool::from(attempts[..32].ct_eq(&capture.source()))
        || attempts[32] > attempts[33]
    {
        return Err(SecureStoreError::Corrupt.into());
    }
    Ok(Some(attempts[32]))
}

/// Verify the captured ResetCode independently of PW1/PW3 budgets. Caller
/// persists before replying. Absent captures report Unsupported.
pub fn verify_captured_openpgp_rc<K: SecureStore>(
    store: &mut K, otp: &[u8; 32], uid: &[u8], bufs: &mut MigrationBuffers,
    passphrase: &[u8],
) -> Result<CapturedPinResult, MigrationError> {
    use zeroize::Zeroizing;
    let capture = read_openpgp_capture(store, otp, uid, &mut bufs.scratch)?;
    let Some(verifier) = capture.record(0x1082)? else {
        return Ok(CapturedPinResult::Unsupported);
    };
    let sh = Zeroizing::new(ckey::serial_hash(uid));
    // US-918: the C firmware created the verifier records — C root.
    let kbase = Zeroizing::new(ckey::derive_kbase_c(otp, &sh)?);
    let (result, mut attempts) = check_captured_pin(
        store, &capture.source(), verifier, &sh, &kbase, passphrase,
        SLOT_OPENPGP_RC_RETRIES,
    )?;
    if result == CapturedPinResult::Verified {
        attempts[32] = attempts[33];
        store.write(SLOT_OPENPGP_RC_RETRIES, &attempts)?;
    }
    Ok(result)
}

// One attempt-spending primitive for VERIFY and DEK completion. The caller
// resets the budget only after its entire operation succeeds, so a failed
// unwrap or DEK write does not erase the spent attempt.
fn check_captured_pw1<K: SecureStore>(
    store: &mut K,
    source: &[u8; 32],
    verifier: &[u8],
    sh: &[u8; 32],
    kbase: &[u8; 32],
    passphrase: &[u8],
) -> Result<(CapturedPinResult, [u8; 34]), MigrationError> {
    check_captured_pin(store, source, verifier, sh, kbase, passphrase, SLOT_OPENPGP_RETRIES)
}

fn check_captured_pin<K: SecureStore>(
    store: &mut K, source: &[u8; 32], verifier: &[u8], sh: &[u8; 32],
    kbase: &[u8; 32], passphrase: &[u8], slot: &[u8],
) -> Result<(CapturedPinResult, [u8; 34]), MigrationError> {
    use subtle::ConstantTimeEq;
    use zeroize::Zeroizing;
    if verifier.len() != 34 || verifier[1] != 1 {
        return Ok((CapturedPinResult::Unsupported, [0; 34]));
    }
    let mut attempts = [0; 34];
    if store.read(slot, &mut attempts)? != attempts.len()
        || !bool::from(attempts[..32].ct_eq(source))
        || attempts[32] > attempts[33]
    {
        return Err(SecureStoreError::Corrupt.into());
    }
    if attempts[32] == 0 {
        return Ok((CapturedPinResult::Blocked, attempts));
    }
    attempts[32] -= 1;
    store.write(slot, &attempts)?;
    let kver = Zeroizing::new(ckey::derive_kver(kbase, passphrase));
    let expected = Zeroizing::new(ckey::pin_verifier(sh, &kver));
    let result = if passphrase.len() == verifier[0] as usize
        && bool::from(expected.as_slice().ct_eq(&verifier[2..]))
    {
        CapturedPinResult::Verified
    } else {
        CapturedPinResult::Rejected { remaining: attempts[32] }
    };
    Ok((result, attempts))
}

/// US-917: read the migrated OpenPGP DEK (48 B: IV ‖ key) into `dek`.
///
/// The S-413-6 completion persists the DEK as a US-917 AEAD record
/// ([`ckey::wrap_aead`], AAD = [`SLOT_OPENPGP_DEK`], key =
/// [`ckey::derive_wrap_key`]). The pre-US-917 plaintext form is still
/// accepted here (open-only compat, like the CBC shapes in [`ckey`]) — a
/// successful passphrase-class completion re-wraps it in place, after
/// which only the AEAD record remains.
pub fn read_openpgp_dek<K: SecureStore>(
    store: &mut K,
    otp_key_1: &[u8; 32],
    uid: &[u8],
    dek: &mut [u8; 48],
) -> Result<(), MigrationError> {
    use zeroize::Zeroize;
    let wrap_key = ckey::derive_wrap_key(otp_key_1, &ckey::serial_hash(uid));
    let mut record = [0u8; ckey::WRAP_OVERHEAD + 48];
    let n = store.read(SLOT_OPENPGP_DEK, &mut record)?;
    if n == ckey::WRAP_OVERHEAD + 48 {
        let opened = ckey::open_aead(&record, &wrap_key, SLOT_OPENPGP_DEK, dek.as_mut())?;
        if opened != 48 {
            dek.zeroize();
            return Err(SecureStoreError::Corrupt.into());
        }
        Ok(())
    } else if n == 48 {
        // Pre-US-917 plaintext DEK — open-only compat (see US-917).
        dek.copy_from_slice(&record[..48]);
        Ok(())
    } else {
        dek.zeroize();
        Err(SecureStoreError::Corrupt.into())
    }
}

/// US-918: the MAC check uses the bound device root (chipid + boot entropy);
/// `kbase_c` opens the C-produced verifier and DEK wrapper, and `uid` keys
/// the bound-root derivation for the MAC.
#[allow(clippy::too_many_arguments)]
fn complete_captured_openpgp<K: SecureStore>(
    store: &mut K,
    bufs: &mut MigrationBuffers,
    sh: &[u8; 32],
    kbase_c: &[u8; 32],
    otp_key_1: &[u8; 32],
    uid: &[u8],
    nonce: &[u8; 12],
    passphrase: &[u8],
) -> Result<ClassStatus, MigrationError> {
    use subtle::ConstantTimeEq;
    use zeroize::Zeroizing;
    if captured_openpgp_pw1_handed_off(store)? {
        return Err(SecureStoreError::Corrupt.into());
    }
    let n = crate::secure_store::chunked::read_chunked(store, SLOT_OPENPGP, &mut bufs.scratch)?;
    let captured = &bufs.scratch[..n];
    // US-918: the capture authenticator is keyed by the bound device root
    // (`run` wrote it); the DEK/PIN chain stays on the C root (`kbase_c`).
    let kbase = boot_kbase(store, otp_key_1, uid)?;
    let mut source = [0; 32];
    if store.read(SLOT_OPENPGP_SOURCE, &mut source)? != source.len()
        || !bool::from(source.ct_eq(&capture_mac(captured, sh, &kbase)))
    {
        return Err(CKeyError::AuthFailed.into());
    }
    let Some(wrapper) = captured_record(captured, 0x109a)? else {
        // The legacy CFB route must not release an unauthenticated DEK.
        return Ok(if captured_record(captured, 0x1099)?.is_some() {
            ClassStatus::NotMigratable
        } else {
            ClassStatus::None
        });
    };
    let verifier = captured_record(captured, 0x1081)?.ok_or(CKeyError::BadFormat)?;
    if verifier.len() != 34 || verifier[1] != 1 || wrapper.len() != 77 || wrapper[0] != 3 {
        return Ok(ClassStatus::NotMigratable);
    }
    let (result, mut attempts) = check_captured_pw1(
        store, &source, verifier, sh, kbase_c, passphrase,
    )?;
    match result {
        CapturedPinResult::Verified => {}
        CapturedPinResult::Unsupported => return Ok(ClassStatus::NotMigratable),
        CapturedPinResult::Rejected { .. } | CapturedPinResult::Blocked => {
            return Ok(ClassStatus::NeedsPassphrase);
        }
    }
    // US-918: the DEK wrapper and PIN chain are C-firmware-produced — the
    // C root (`kbase_c`), never the bound root.
    let kver = Zeroizing::new(ckey::derive_kver(kbase_c, passphrase));
    let session = Zeroizing::new(ckey::pin_session(sh, &kver));
    let kenc = Zeroizing::new(ckey::pin_kenc2(sh, kbase_c, &session));
    let mut blob = Zeroizing::new([0u8; 76]);
    blob.copy_from_slice(&wrapper[1..]);
    ckey::gcm_unwrap_serial_aad_pub(&kenc, sh, &mut blob[..])?;
    // US-917: the rewrite site — the decrypted C DEK is re-wrapped into
    // the AEAD record format before it is persisted. The legacy C record
    // shapes stay open-only (see the `ckey` module docs); the AAD binds
    // the destination slot identity and `nonce` is a fresh platform-TRNG
    // draw threaded from the firmware migration handler.
    let wrap_key = ckey::derive_wrap_key(otp_key_1, sh);
    let mut record = [0u8; ckey::WRAP_OVERHEAD + 48];
    let n = ckey::wrap_aead(&wrap_key, nonce, SLOT_OPENPGP_DEK, &blob[12..60], &mut record)?;
    store.write(SLOT_OPENPGP_DEK, &record[..n])?;
    attempts[32] = attempts[33];
    store.write(SLOT_OPENPGP_RETRIES, &attempts)?;
    Ok(ClassStatus::Migrated)
}

fn is_openpgp_capture_fid(fid: u16) -> bool {
    crate::cfs::is_openpgp_migration_fid(fid)
        || matches!(fid, 0x1080..=0x1084 | 0x109d | 0x00e8..=0x00ed)
}

/// Detect + re-seed. Runs once on the boot path, before app spawn; every
/// later boot with the marker set is a no-op.
// US-939: `#[inline(never)]` -- the walk/decode scratch stays in this
// function's own frame, out of the firmware's Embassy async-main frame.
#[inline(never)]
pub fn run<S: CFlashSource + ?Sized, K: SecureStore>(
    src: &S,
    part: DataPartition,
    store: &mut K,
    otp_key_1: &[u8; 32],
    flash_uid: &[u8],
    bufs: &mut MigrationBuffers,
) -> Result<MigrationOutcome, MigrationError> {
    bufs.clear();
    // Idempotence gates, in order.
    if store.contains(MIGRATION_MARKER) {
        return Ok(MigrationOutcome::Skipped(SkipReason::AlreadyMigrated));
    }
    if store.contains(SLOT_FIDO_HKEY) || store.contains(SLOT_MGMT_CONF) {
        return Ok(MigrationOutcome::Skipped(SkipReason::StoreNotEmpty));
    }

    let bounds = PoolBounds::from_partition(part);
    let cfs = Cfs::new(src, bounds);
    let mut recs: HVec<crate::cfs::RecordDesc, MAX_RECORDS> = HVec::new();
    let state = cfs.scan(&mut recs)?;
    match state {
        crate::cfs::CState::FactoryFresh => {
            return Ok(MigrationOutcome::Skipped(SkipReason::CStateFactoryFresh))
        }
        crate::cfs::CState::Empty => {
            return Ok(MigrationOutcome::Skipped(SkipReason::CStateEmpty))
        }
        crate::cfs::CState::Used => {}
    }

    // C key schedule (NeverBootC aborts — an all-zero OTP row means the C
    // firmware never initialized this device). US-918: two roots —
    // `kbase_c` (the C firmware's own two-input root) opens the
    // C-produced records; the bound device root (chipid + boot entropy,
    // fail-closed) keys the capture authenticator written below, so a
    // leaked OTP row alone does not reconstruct it.
    let sh = ckey::serial_hash(flash_uid);
    let kbase_c = ckey::derive_kbase_c(otp_key_1, &sh)?;
    let chipid = chipid_from_uid(flash_uid)?;
    let entropy = boot_entropy_from(store)?;
    let kbase = zeroize::Zeroizing::new(ckey::derive_kbase(
        otp_key_1,
        &sh,
        chipid,
        entropy.as_ref(),
    )?);

    // Preflight before any class can write. The device has 16 physical slots;
    // reserve eight for the marker, DEK, source/progress/auth bookkeeping and
    // normal app boot. Only a verified-empty destination needs one initial
    // capture generation; occupied stores retain the two-generation budget.
    // Use device chunk limits, not the host's 16 KiB single-value limit.
    // Larger source sets stay untouched for recovery.
    let mut openpgp_bytes = 0usize;
    let mut other_slots = 0usize;
    let mut classes = [false; 6];
    for rec in &recs {
        if is_openpgp_capture_fid(rec.fid) {
            openpgp_bytes = openpgp_bytes.checked_add(6 + rec.len as usize)
                .ok_or(MigrationError::SlotOverflow)?;
        } else {
            let class = match rec.fid {
                0xcc00 => Some(0),
                0x1122 => Some(1),
                0xba00..=0xbaff => Some(2),
                0xbb00..=0xbb03 | 0x10a0 => Some(3),
                0x1184 | 0x1185 | 0xff00 | 0xc101..=0xc1ff | 0x0082..=0x0087 => Some(4),
                0xce00 | 0xce01 | 0xce03 | 0xce04 | 0xc000 | 0xc001 | 0xcf00..=0xd0ff | 0x1101 => Some(5),
                _ => None,
            };
            if let Some(class) = class {
                if !classes[class] {
                    classes[class] = true;
                    other_slots += 1;
                }
            }
        }
    }
    if openpgp_bytes != 0 {
        let parts = openpgp_bytes.div_ceil(crate::secure_store::chunked::PART_PAYLOAD_MAX);
        let pw3_slots = usize::from(recs.iter().any(|rec| rec.fid == 0x1083));
        let rc_slots = usize::from(recs.iter().any(|rec| rec.fid == 0x1082));
        // US-918: the boot-entropy slot is created on the boot path BEFORE
        // this migration runs, so a fresh device's destination holds exactly
        // that one record — still a verified-empty destination (one capture
        // generation). Anything else is occupied (two-generation budget).
        let capture_slots = if store.is_empty()?
            || store.is_empty_except(SLOT_BOOT_ENTROPY)? { parts } else { parts * 2 };
        if capture_slots + other_slots + 8 + pw3_slots + rc_slots > 16 {
            return Err(MigrationError::SlotOverflow);
        }
    }

    // Validate OpenPGP credential metadata before *any* class writes. C lists
    // are newest-first, so only the first copy of each retry DO is authoritative.
    let mut remaining = None;
    let mut maximum = None;
    let mut has_pw1 = false;
    let mut has_pw3 = false;
    let mut has_rc = false;
    let mut rc_remaining = None;
    let mut rc_maximum = None;
    let mut pw3_remaining = None;
    let mut pw3_maximum = None;
    for rec in &recs {
        match rec.fid {
            0x1081 => has_pw1 = true,
            0x1083 => has_pw3 = true,
            0x1082 => has_rc = true,
            0x10c4 if remaining.is_none() => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)? as usize;
                remaining = Some(*bufs.scratch[..n].get(4).ok_or(CKeyError::BadLength)?);
                pw3_remaining = bufs.scratch[..n].get(6).copied();
                rc_remaining = bufs.scratch[..n].get(5).copied();
            }
            0x10c5 if maximum.is_none() => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)? as usize;
                maximum = Some(*bufs.scratch[..n].get(1).ok_or(CKeyError::BadLength)?);
                pw3_maximum = bufs.scratch[..n].get(3).copied();
                rc_maximum = bufs.scratch[..n].get(2).copied();
            }
            _ => {}
        }
    }
    if has_pw1 {
        let remaining = remaining.ok_or(CKeyError::BadFormat)?;
        let maximum = maximum.ok_or(CKeyError::BadFormat)?;
        if remaining > maximum {
            return Err(CKeyError::BadFormat.into());
        }
    }

    if has_pw3 && pw3_remaining.ok_or(CKeyError::BadFormat)?
        > pw3_maximum.ok_or(CKeyError::BadFormat)?
    {
        return Err(CKeyError::BadFormat.into());
    }

    if has_rc && rc_remaining.ok_or(CKeyError::BadFormat)?
        > rc_maximum.ok_or(CKeyError::BadFormat)?
    {
        return Err(CKeyError::BadFormat.into());
    }

    let mut report = MigrationReport::default();

    for rec in &recs {
        match rec.fid {
            // FIDO keydev: unwrap now (silent) or flag for S-413-6.
            0xCC00 => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)?;
                match ckey::unwrap_keydev(&bufs.scratch[..n as usize], otp_key_1, &kbase_c, &sh, None) {
                    Ok(KeydevStatus::Unwrapped(k)) => {
                        store.write(SLOT_FIDO_HKEY, &k)?;
                        report.hkey_migrated = true;
                    }
                    Ok(KeydevStatus::NeedsPin) => report.needs_passphrase = true,
                    Ok(KeydevStatus::NotMigratable) => report.keydev_not_migratable = true,
                    Err(_) => report.keydev_not_migratable = true,
                }
            }
            0xCC01 => report.keydev_not_migratable = true,
            // Management EF_DEV_CONF: verbatim blob.
            0x1122 => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)?;
                store.write(SLOT_MGMT_CONF, &bufs.scratch[..n as usize])?;
                report.dev_conf_migrated = true;
            }
            // OpenPGP: PIN hashes, public keys, binding sigs, DOs, DEK
            // wrappers (DEK presence flags the passphrase class).
            fid if is_openpgp_capture_fid(fid) => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)?;
                push_tlv(&mut bufs.openpgp, rec.fid, &bufs.scratch[..n as usize])?;
                report.openpgp_records += 1;
                if matches!(rec.fid, 0x1099..=0x109D) {
                    report.needs_passphrase = true;
                }
            }
            0xBA00..=0xBAFF => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)?;
                push_tlv(&mut bufs.oath, rec.fid, &bufs.scratch[..n as usize])?;
                report.oath_records += 1;
            }
            0xBB00..=0xBB03 | 0x10A0 => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)?;
                push_tlv(&mut bufs.otp, rec.fid, &bufs.scratch[..n as usize])?;
                report.otp_records += 1;
            }
            // PIV (re-seed only; serving deferred per the epic).
            0x1184 | 0x1185 | 0xFF00 | 0xC101..=0xC1FF | 0x0082..=0x0087 => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)?;
                push_tlv(&mut bufs.piv, rec.fid, &bufs.scratch[..n as usize])?;
                report.piv_records += 1;
            }
            // FIDO container records (vault, creds, RPs, counter, large
            // blob): preserved verbatim for post-cutover restore.
            0xCE00 | 0xCE01 | 0xCE03 | 0xCE04 | 0xC000 | 0xC001 | 0xCF00..=0xD0FF | 0x1101 => {
                let n = cfs.read_whitelisted(rec, &mut bufs.scratch)?;
                push_tlv(&mut bufs.fido, rec.fid, &bufs.scratch[..n as usize])?;
                report.fido_container_records += 1;
            }
            _ => {}
        }
    }

    // Persist everything, then the marker (set on success — a crash before
    // this line leaves the store empty and the next boot retries).
    if !bufs.openpgp.is_empty() {
        crate::secure_store::chunked::write_chunked(store, SLOT_OPENPGP, &bufs.openpgp)?;
        let n = crate::secure_store::chunked::read_chunked(store, SLOT_OPENPGP, &mut bufs.scratch)?;
        if bufs.scratch[..n] != bufs.openpgp[..] {
            return Err(MigrationError::Store(SecureStoreError::Corrupt));
        }
        let source = capture_mac(&bufs.openpgp, &sh, &kbase);
        store.write(SLOT_OPENPGP_SOURCE, &source)?;
        if has_pw3 {
            let mut attempts = [0; 34];
            attempts[..32].copy_from_slice(&source);
            attempts[32] = pw3_remaining.ok_or(CKeyError::BadFormat)?;
            attempts[33] = pw3_maximum.ok_or(CKeyError::BadFormat)?;
            store.write(SLOT_OPENPGP_PW3_RETRIES, &attempts)?;
        }
        if has_rc {
            let mut attempts = [0; 34];
            attempts[..32].copy_from_slice(&source);
            attempts[32] = rc_remaining.ok_or(CKeyError::BadFormat)?;
            attempts[33] = rc_maximum.ok_or(CKeyError::BadFormat)?;
            store.write(SLOT_OPENPGP_RC_RETRIES, &attempts)?;
        }
        if captured_record(&bufs.openpgp, 0x1081)?.is_some() {
            let status = captured_record(&bufs.openpgp, 0x10c4)?.ok_or(CKeyError::BadFormat)?;
            let maxima = captured_record(&bufs.openpgp, 0x10c5)?.ok_or(CKeyError::BadFormat)?;
            // C indexes PW1 by (FID & 15) == 1; status uses 3 + index.
            let remaining = *status.get(4).ok_or(CKeyError::BadLength)?;
            let maximum = *maxima.get(1).ok_or(CKeyError::BadLength)?;
            if remaining > maximum {
                return Err(CKeyError::BadFormat.into());
            }
            let mut attempts = [0; 34];
            attempts[..32].copy_from_slice(&source);
            attempts[32] = remaining;
            attempts[33] = maximum;
            store.write(SLOT_OPENPGP_RETRIES, &attempts)?;
        }
    }
    if !bufs.oath.is_empty() {
        store.write(SLOT_OATH, &bufs.oath)?;
    }
    if !bufs.otp.is_empty() {
        store.write(SLOT_OTP, &bufs.otp)?;
    }
    if !bufs.piv.is_empty() {
        store.write(SLOT_PIV, &bufs.piv)?;
    }
    if !bufs.fido.is_empty() {
        store.write(SLOT_FIDO_CONTAINER, &bufs.fido)?;
    }
    let marker = [
        u8::from(report.hkey_migrated),
        u8::from(report.needs_passphrase),
        u8::from(report.dev_conf_migrated),
        u8::from(report.keydev_not_migratable),
    ];
    store.write(MIGRATION_MARKER, &marker)?;
    Ok(MigrationOutcome::Done(report))
}


// ---------------------------------------------------------------------------
// S-413-6: interactive (passphrase-gated) class completion
// ---------------------------------------------------------------------------

/// Per-class status returned by the migration APDU (one byte in the
/// response data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassStatus {
    Migrated = 0,
    NeedsPassphrase = 1,
    NotMigratable = 2,
    None = 3,
    Error = 4,
}

impl ClassStatus {
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Complete one passphrase-gated migration class. Class 0 retains the FIDO
/// source-flash flow. Class 1 uses only authenticated captured OpenPGP records
/// and source-bound stored PW1 retries. Missing/corrupt capture fails closed;
/// unsupported legacy profiles stay pending, never yielding an unchecked DEK.
///
/// `nonce` is a fresh per-record draw from the platform TRNG (US-380) —
/// consumed by the class-1 US-917 DEK rewrap (see [`complete_captured_openpgp`]).
/// Class 0's rewrite site persists the unwrapped keydev as the raw 32-byte
/// value `apps/fido` consumes (the C CBC record itself is only ever opened,
/// never re-created — see the `ckey` module docs); it does not use `nonce`.
///
/// Store mutations, including failed attempts, must be durably persisted by
/// the caller before acknowledging a result.
#[allow(clippy::too_many_arguments)] // device context mirrors the C call shape
pub fn complete_passphrase_class<S: CFlashSource + ?Sized, K: SecureStore>(
    src: &S,
    part: DataPartition,
    store: &mut K,
    otp_key_1: &[u8; 32],
    flash_uid: &[u8],
    bufs: &mut MigrationBuffers,
    class: u8,
    nonce: &[u8; 12],
    passphrase: &[u8],
) -> Result<ClassStatus, MigrationError> {
    let sh = ckey::serial_hash(flash_uid);
    // US-918: the C-record opens run on the C firmware's own root
    // (`kbase_c`); `complete_captured_openpgp` derives the bound device
    // root itself for the capture-authenticator check.
    let kbase_c = ckey::derive_kbase_c(otp_key_1, &sh)?;
    if class == 1 {
        return complete_captured_openpgp(
            store, bufs, &sh, &kbase_c, otp_key_1, flash_uid, nonce, passphrase,
        );
    }
    let bounds = PoolBounds::from_partition(part);
    let cfs = Cfs::new(src, bounds);
    let mut recs: HVec<crate::cfs::RecordDesc, MAX_RECORDS> = HVec::new();
    if cfs.scan(&mut recs)? != crate::cfs::CState::Used {
        return Ok(ClassStatus::None);
    }
    match class {
        0 => {
            // FIDO keydev: newest 0xCC00 record wins (C scans the same way).
            let mut saw_vendor_only = false;
            for rec in &recs {
                match rec.fid {
                    0xCC01 => saw_vendor_only = true,
                    0xCC00 => {
                        let n = cfs.read_whitelisted(rec, &mut bufs.scratch)?;
                        let payload = &bufs.scratch[..n as usize];
                        return match ckey::unwrap_keydev(
                            payload,
                            otp_key_1,
                            &kbase_c,
                            &sh,
                            Some(passphrase),
                        ) {
                            Ok(KeydevStatus::Unwrapped(k)) => {
                                store.write(SLOT_FIDO_HKEY, &k)?;
                                Ok(ClassStatus::Migrated)
                            }
                            // 32/33-byte records need no PIN — a sealed
                            // 61-byte record with a bad PIN lands here.
                            Ok(KeydevStatus::NeedsPin) => Ok(ClassStatus::NeedsPassphrase),
                            Ok(KeydevStatus::NotMigratable) | Err(_) => {
                                Ok(ClassStatus::NotMigratable)
                            }
                        };
                    }
                    _ => {}
                }
            }
            Ok(if saw_vendor_only {
                ClassStatus::NotMigratable
            } else {
                ClassStatus::None
            })
        }
        _ => Ok(ClassStatus::Error),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cflash::{FLASH_XIP_BASE, PT_JSON_DATA_START};
    use crate::secure_store::HostSecureStore;
    use std::vec;
    use std::vec::Vec;

    // Fixed vectors from the ckey KATs (S-413-4): UID 0102..0708, OTP row,
    // kbase, and the 33-byte keydev record wrapping KEYDEV_PLAIN under kbase.
    const UID_HEX: &str = "0102030405060708";
    const OTP_HEX: &str =
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
    const KD33_HEX: &str =
        "01a0385479d6e53f7e01f26be6909296779002a409ae67450d7b9340bcf846e2f9";
    const KEYDEV_PLAIN_HEX: &str =
        "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";
    // S-413-6 vectors: PW1 "123456" session; EF_DEK_PW1 (0x109A, new
    // format) sealing a 48-byte DEK under kenc2 (AAD = serial hash).
    const PW1: &str = "123456";
    // US-917: tests pin a fixed nonce for reproducibility; production call
    // sites draw it from the platform TRNG (US-380).
    const NONCE: [u8; 12] = [0x9u8; 12];
    const DEK76_HEX: &str =
        "03707172737475767778797a7b3330bb3a10da08c4d4e575d654536c7217b6f355beeca6cd4ac8888fcbfecbe7fc5722fc574f63022264f472c4e6b511574ad0366885a71a68aba9f5adbf83d0";
    const DEK_PT_HEX: &str =
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";
    const KD61_HEX: &str =
        "02505152535455565758595a5bfb1a04be0af704eac566d0ca8675a75949d584b8779399972bcc27a3b906d1d672203288b3aaa3f9bac2bf0e1534ba63";

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const PART_START: u32 = FLASH_XIP_BASE + PT_JSON_DATA_START;
    const PART_END: u32 = FLASH_XIP_BASE + PT_JSON_DATA_START + 3064 * 1024;

    struct MemFlash {
        img: Vec<u8>,
        base: u32,
    }

    impl MemFlash {
        fn new() -> Self {
            MemFlash {
                img: vec![0xFFu8; (PART_END - PART_START) as usize],
                base: PART_START,
            }
        }
        fn bounds(&self) -> PoolBounds {
            PoolBounds::from_partition(DataPartition {
                start: PART_START,
                end: PART_END,
            })
        }
        fn write(&mut self, addr: u32, bytes: &[u8]) {
            let o = (addr - self.base) as usize;
            self.img[o..o + bytes.len()].copy_from_slice(bytes);
        }
        /// Append a record at the current downward cursor; returns its address.
        fn push_record(&mut self, cursor: &mut u32, fid: u16, data: &[u8]) -> u32 {
            *cursor -= 12 + 2 + data.len() as u32;
            let base = *cursor;
            self.write(base, &0u32.to_le_bytes());
            self.write(base + 4, &0u32.to_le_bytes());
            self.write(base + 8, &fid.to_le_bytes());
            self.write(base + 10, &(data.len() as u16).to_le_bytes());
            self.write(base + 12, data);
            base
        }
        fn link(&mut self, new_base: u32, older: u32) {
            self.write(new_base, &older.to_le_bytes());
        }
        fn hard_init(&mut self) {
            let b = self.bounds();
            self.write(b.end_rom_pool, &0u32.to_le_bytes());
            self.write(b.end_rom_pool + 4, &0u32.to_le_bytes());
            self.write(b.data_end, &0u32.to_le_bytes());
        }
        fn publish_head(&mut self, addr: u32) {
            let b = self.bounds();
            self.write(b.data_end, &addr.to_le_bytes());
        }
    }

    impl CFlashSource for MemFlash {
        fn read(&self, addr: u32, buf: &mut [u8]) {
            let o = (addr - self.base) as usize;
            buf.copy_from_slice(&self.img[o..o + buf.len()]);
        }
    }

    /// Used partition with one record per migratable class, newest-first.
    fn used_fixture(with_dek: bool, keydev_61b: bool) -> MemFlash {
        let mut f = MemFlash::new();
        let mut cursor = f.bounds().data_end;
        let keydev = if keydev_61b {
            // Real 61-byte PIN-wrapped KAT (ckey vectors): PIN "123456".
            f.push_record(&mut cursor, 0xCC00, &h(KD61_HEX))
        } else {
            f.push_record(&mut cursor, 0xCC00, &h(KD33_HEX))
        };
        let devconf = f.push_record(&mut cursor, 0x1122, &[0x07, 0xF4, 0x1C, 0x0F]);
        let oath = f.push_record(&mut cursor, 0xBA01, &[0xAA; 40]);
        let otp_slot = f.push_record(&mut cursor, 0xBB00, &[0xBB; 20]);
        let pgp_pk = f.push_record(&mut cursor, 0x10D1, &[0xC5; 100]);
        let pgp_dek = if with_dek {
            let verifier = f.push_record(&mut cursor, 0x1081, &h(
                "0601d70f14079f8d50d4606a547bf339966fc82ebb1ec702d23925f73a399eda60fe"
            ));
            let status = f.push_record(&mut cursor, 0x10c4, &[1, 127, 127, 127, 3, 3, 3]);
            let maxima = f.push_record(&mut cursor, 0x10c5, &[3, 3, 3, 3]);
            let wrapper = f.push_record(&mut cursor, 0x109A, &h(DEK76_HEX));
            f.link(wrapper, maxima);
            f.link(maxima, status);
            f.link(status, verifier);
            f.link(verifier, pgp_pk);
            Some(wrapper)
        } else {
            None
        };
        let piv_cert = f.push_record(&mut cursor, 0xC101, &[0xC9; 64]);
        let cred = f.push_record(&mut cursor, 0xCF00, &[0xCD; 50]);
        // Chain newest → oldest, head published last.
        let order = [
            cred,
            piv_cert,
            pgp_dek.unwrap_or(pgp_pk),
            pgp_pk,
            otp_slot,
            oath,
            devconf,
            keydev,
        ];
        for w in order.windows(2) {
            if pgp_dek != Some(w[0]) {
                f.link(w[0], w[1]);
            }
        }
        f.link(keydev, 0);
        f.hard_init();
        f.publish_head(cred);
        f
    }

    fn bufs() -> MigrationBuffers {
        MigrationBuffers::new()
    }

    fn part() -> DataPartition {
        DataPartition { start: PART_START, end: PART_END }
    }

    fn otp() -> [u8; 32] {
        h(OTP_HEX).try_into().unwrap()
    }

    /// US-918: seed the boot-entropy slot with the fixed test vector so the
    /// bound device root is derivable. Harmless for tests that never reach
    /// derivation (zero-OTP check fires first).
    fn seed_entropy(store: &mut HostSecureStore) {
        const ENTROPY: [u8; ckey::BOOT_ENTROPY_LEN] = [0xA5u8; ckey::BOOT_ENTROPY_LEN];
        store.write(SLOT_BOOT_ENTROPY, &ENTROPY).unwrap();
    }

    #[test]
    fn migrates_all_classes_silently_and_preserves_c_region() {
        let f = used_fixture(false, false);
        let before = f.img.clone();
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut b = bufs();

        let out = run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b)
            .expect("migration runs");
        let report = match out {
            MigrationOutcome::Done(r) => r,
            other => panic!("expected Done, got {other:?}"),
        };
        assert!(report.hkey_migrated);
        assert!(!report.needs_passphrase);
        assert!(report.dev_conf_migrated);
        assert_eq!(report.oath_records, 1);
        assert_eq!(report.otp_records, 1);
        assert_eq!(report.openpgp_records, 1);
        assert_eq!(report.piv_records, 1);
        assert_eq!(report.fido_container_records, 1);

        // hkey == unwrapped keydev (KAT vector).
        let mut hk = [0u8; 32];
        let n = store.read(SLOT_FIDO_HKEY, &mut hk).unwrap();
        assert_eq!(&hk[..n], h(KEYDEV_PLAIN_HEX).as_slice());
        // DEV_CONF verbatim.
        let mut dc = [0u8; 16];
        let n = store.read(SLOT_MGMT_CONF, &mut dc).unwrap();
        assert_eq!(&dc[..n], &[0x07, 0xF4, 0x1C, 0x0F]);
        // OATH slot TLV: [fid LE][len u32 LE][payload].
        let mut ob = [0u8; 128];
        store.read(SLOT_OATH, &mut ob).unwrap();
        assert_eq!(&ob[0..2], &0xBA01u16.to_le_bytes());
        assert_eq!(&ob[2..6], &40u32.to_le_bytes());
        assert_eq!(&ob[6..46], &[0xAA; 40]);
        // OpenPGP slot carries the pubkey record.
        let mut pb = [0u8; 256];
        crate::secure_store::chunked::read_chunked(&mut store, SLOT_OPENPGP, &mut pb).unwrap();
        assert_eq!(&pb[0..2], &0x10D1u16.to_le_bytes());
        assert_eq!(&pb[2..6], &100u32.to_le_bytes());
        // Marker present.
        assert!(store.contains(MIGRATION_MARKER));

        // C region byte-identical (read-only guarantee).
        assert_eq!(f.img, before, "C partition bytes must not change");
    }

    #[test]
    fn rerun_after_marker_is_a_noop() {
        let f = used_fixture(false, false);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        {
            let mut b = bufs();
            run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        }
        let img_before = store.partition_image();
        let mut b = bufs();
        let out = run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        assert_eq!(out, MigrationOutcome::Skipped(SkipReason::AlreadyMigrated));
        assert_eq!(store.partition_image(), img_before, "second boot changes nothing");
    }

    #[test]
    fn factory_fresh_and_empty_skip_without_store_writes() {
        for make_state in [false, true] {
            let mut f = MemFlash::new();
            if make_state {
                f.hard_init(); // initialized but file-less
            }
            let mut store = HostSecureStore::new();
            let mut b = bufs();
            let out = run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
            let expected = if make_state {
                SkipReason::CStateEmpty
            } else {
                SkipReason::CStateFactoryFresh
            };
            assert_eq!(out, MigrationOutcome::Skipped(expected));
            // No store writes at all.
            assert!(!store.contains(MIGRATION_MARKER));
            assert!(!store.contains(SLOT_FIDO_HKEY));
            assert!(!store.contains(SLOT_MGMT_CONF));
        }
    }

    #[test]
    fn non_empty_store_skips() {
        let f = used_fixture(false, false);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        store.write(SLOT_FIDO_HKEY, &[1; 32]).unwrap();
        let mut b = bufs();
        let out = run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        assert_eq!(out, MigrationOutcome::Skipped(SkipReason::StoreNotEmpty));
    }

    #[test]
    fn pin_wrapped_keydev_flags_needs_passphrase() {
        let f = used_fixture(false, true);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut b = bufs();
        let out = run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        let report = match out {
            MigrationOutcome::Done(r) => r,
            other => panic!("expected Done, got {other:?}"),
        };
        assert!(!report.hkey_migrated);
        assert!(report.needs_passphrase);
        assert!(!store.contains(SLOT_FIDO_HKEY));
        assert!(store.contains(MIGRATION_MARKER));
    }

    #[test]
    fn openpgp_dek_flags_needs_passphrase() {
        let f = used_fixture(true, false);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut b = bufs();
        let out = run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        let report = match out {
            MigrationOutcome::Done(r) => r,
            other => panic!("expected Done, got {other:?}"),
        };
        assert!(report.needs_passphrase);
        assert!(report.hkey_migrated);
        // The DEK wrapper bytes are preserved in the OpenPGP slot.
        let mut pb = vec![0u8; 512];
        let n = crate::secure_store::chunked::read_chunked(&mut store, SLOT_OPENPGP, &mut pb).unwrap();
        let openpgp = &pb[..n];
        assert!(openpgp.windows(2).any(|w| w == 0x109Au16.to_le_bytes()));
    }

    #[test]
    fn never_boot_c_aborts() {
        let f = used_fixture(false, false);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let zero = [0u8; 32];
        let mut b = bufs();
        assert_eq!(
            run(&f, part(), &mut store, &zero, &h(UID_HEX), &mut b),
            Err(MigrationError::CKey(CKeyError::NeverBootC))
        );
    }

    #[test]
    fn complete_fido_pin_migrates_keydev() {
        let f = used_fixture(false, true);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        // S-413-5 ran: silent classes migrated, hkey pending.
        {
            let mut b = bufs();
            run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        }
        assert!(!store.contains(SLOT_FIDO_HKEY));
        // Correct PIN completes the class. (Class 0 does not consume the
        // US-917 nonce — its rewrite site persists the raw keydev value.)
        let mut b = bufs();
        let st = complete_passphrase_class(
            &f, part(), &mut store, &otp(), &h(UID_HEX), &mut b, 0, &NONCE, PW1.as_bytes(),
        )
        .unwrap();
        assert_eq!(st, ClassStatus::Migrated);
        let mut hk = [0u8; 32];
        let n = store.read(SLOT_FIDO_HKEY, &mut hk).unwrap();
        assert_eq!(&hk[..n], h(KEYDEV_PLAIN_HEX).as_slice());
    }

    #[test]
    fn complete_fido_pin_wrong_pin_is_needs_passphrase() {
        let f = used_fixture(false, true);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut b = bufs();
        run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        let mut b = bufs();
        let st = complete_passphrase_class(
            &f, part(), &mut store, &otp(), &h(UID_HEX), &mut b, 0, &NONCE, b"999999",
        )
        .unwrap();
        assert_eq!(st, ClassStatus::NeedsPassphrase);
        assert!(!store.contains(SLOT_FIDO_HKEY));
    }

    #[test]
    fn complete_openpgp_pw1_migrates_dek() {
        let f = used_fixture(true, false);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut b = bufs();
        run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        let mut b = bufs();
        let st = complete_passphrase_class(
            &f, part(), &mut store, &otp(), &h(UID_HEX), &mut b, 1, &NONCE, PW1.as_bytes(),
        )
        .unwrap();
        assert_eq!(st, ClassStatus::Migrated);
        // US-917: the DEK is persisted as the AEAD record format.
        let mut raw = [0u8; 96];
        let n = store.read(SLOT_OPENPGP_DEK, &mut raw).unwrap();
        assert_eq!(n, ckey::WRAP_OVERHEAD + 48);
        assert_eq!(raw[0], ckey::WRAP_TAG);
        // And it opens back to the plaintext DEK through the shared reader.
        let mut dek = [0u8; 48];
        read_openpgp_dek(&mut store, &otp(), &h(UID_HEX), &mut dek).unwrap();
        assert_eq!(&dek, h(DEK_PT_HEX).as_slice());
    }

    #[test]
    fn completion_rewraps_a_legacy_plaintext_dek_as_aead() {
        // US-917 requirement 2: a DEK persisted by a pre-US-917 completion
        // (plaintext slot value) is re-wrapped into the AEAD format by the
        // next successful passphrase-class completion.
        let f = used_fixture(true, false);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut b = bufs();
        run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        // Simulate the pre-US-917 state: plaintext 48-byte DEK in the slot.
        store.write(SLOT_OPENPGP_DEK, &h(DEK_PT_HEX)).unwrap();
        let mut b = bufs();
        let st = complete_passphrase_class(
            &f, part(), &mut store, &otp(), &h(UID_HEX), &mut b, 1, &NONCE, PW1.as_bytes(),
        )
        .unwrap();
        assert_eq!(st, ClassStatus::Migrated);
        let mut raw = [0u8; 96];
        let n = store.read(SLOT_OPENPGP_DEK, &mut raw).unwrap();
        assert_eq!(n, ckey::WRAP_OVERHEAD + 48);
        assert_eq!(raw[0], ckey::WRAP_TAG);
        let mut dek = [0u8; 48];
        read_openpgp_dek(&mut store, &otp(), &h(UID_HEX), &mut dek).unwrap();
        assert_eq!(&dek, h(DEK_PT_HEX).as_slice());
    }

    #[test]
    fn complete_openpgp_pw1_wrong_passphrase_is_needs_passphrase() {
        let f = used_fixture(true, false);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut b = bufs();
        run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        let mut b = bufs();
        let st = complete_passphrase_class(
            &f, part(), &mut store, &otp(), &h(UID_HEX), &mut b, 1, &NONCE, b"wrong!",
        )
        .unwrap();
        assert_eq!(st, ClassStatus::NeedsPassphrase);
        assert!(!store.contains(SLOT_OPENPGP_DEK));
    }

    #[test]
    fn complete_class_none_when_no_pending_work() {
        // Keydev already 33 B (migrated silently); no DEK present.
        let f = used_fixture(false, false);
        let mut store = HostSecureStore::new();
        seed_entropy(&mut store);
        let mut b = bufs();
        run(&f, part(), &mut store, &otp(), &h(UID_HEX), &mut b).unwrap();
        let mut b = bufs();
        assert_eq!(
            complete_passphrase_class(
                &f, part(), &mut store, &otp(), &h(UID_HEX), &mut b, 1, &NONCE, PW1.as_bytes(),
            )
            .unwrap(),
            ClassStatus::None
        );
    }
}
