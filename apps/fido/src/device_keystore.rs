//! No-heap device credential keystore (S-701-3, US-324).
//!
//! Port of the host [`crate::keystore`] model to fixed-size heapless
//! structures that compile for the RP2350: credentials, PIN state and
//! authenticator state snapshot with the **same CBOR map format** as the
//! host `crate::keystore::snapshot` codec (key numbering identical), into
//! the chunked `fido.keystore.v1` slot (`fapico2_platform::secure_store::
//! chunked`) — so a host-written snapshot and a device-written snapshot are
//! interchangeable, and the snapshot survives the device's 512-B physical
//! value cap.
//!
//! Bounded by design: the resident credential set is
//! [`SNAPSHOT_MAX_CREDS`], and the store's **capacity** — how many credentials
//! the device can hold at all — is [`DEVICE_MAX_CREDS`], which is derived from
//! the per-record key region rather than asserted here. A snapshot that does not
//! fit the resident bound is a parse error — corrupt input is refused, never
//! truncated (FX-440 parity with FX-409).
//!
//! # Two bounds, because they are two different questions (US-1552)
//!
//! The number this file used to carry for both was `12`, and it answered
//! neither:
//!
//! * **Capacity — [`DEVICE_MAX_CREDS`].** How many passkeys the device can
//!   hold. This is [`fapico2_platform::keyregion::FIDO_CAPACITY`] (856 at the
//!   shipping geometry), which is a function of the region's size, the measured
//!   record size, the commit protocol and the index reservation
//!   (`keyregion/mod.rs`, "Capacities — derived, never asserted"). The old `12`
//!   was a literal in a file no region could contradict, and it was unreachable
//!   anyway: the real ceiling was `other_slots + old_parts + new_parts <= 24`
//!   in the shared `Rp2350SecureStore`, which is four credentials
//!   (`apps/fido/tests/key_store_ceiling.rs`).
//!
//! * **Resident set — [`SNAPSHOT_MAX_CREDS`].** How many credentials the
//!   *snapshot codec* will encode or decode. It stays 12, because the snapshot's
//!   CBOR is a whole-image format and `chunked::MAX_PARTS * PART_PAYLOAD_MAX`
//!   is 5,952 bytes — a **format** bound, not a store bound, and it will not move
//!   when the store does.
//!
//! Putting them under one name is what made `DEVICE_MAX_CREDS` a fiction: it was
//! read as a capacity in `DeviceKeystore::max_creds` and as an array size in
//! six `heapless::Vec`s in `device_core.rs`/`device_app.rs`, and no change to
//! the region could move the first without detonating the second.

use crate::cbor::no_heap::{self, CborError, Item, Parser};
use crate::crypto;
use crate::snapshot_crypt::{self, FieldScope, FIELD_OVERHEAD, MAX_FIELD_PT};
use crate::vendorff::{
    IdentityName, LedConf, PHY_FIELD_ENABLED_USB_ITF, PHY_FIELD_LED_CONF, PHY_FIELD_MANUFACTURER,
    PHY_FIELD_PRODUCT,
};
use fapico2_platform::keyregion::FIDO_CAPACITY;
use fapico2_platform::secure_store::{chunked, SecureStore, SecureStoreError};
use heapless::Vec as HeaplessVec;

/// Snapshot slot (chunked) — the same logical slot the host `FileKeystore`
/// uses.
pub const KEYSTORE_SLOT: &[u8] = b"fido.keystore.v1";

/// **The capacity: how many FIDO credentials this device can hold.**
///
/// [`fapico2_platform::keyregion::FIDO_CAPACITY`] — **856** at the shipping
/// geometry, and derived rather than asserted: `keyregion/mod.rs` computes it
/// as `TOTAL_SLOTS − OATH_CAPACITY − SCRATCHPAD_SLOTS − INDEX_SLOT_COUNT` and
/// has a compile-time assertion that the four terms claim every slot exactly
/// once. Change the region's size, the measured record size, the commit
/// protocol or the index reservation and this number moves with them.
///
/// The `12` this replaced was the *resident* bound ([`SNAPSHOT_MAX_CREDS`])
/// being read as a capacity. On the board it was not even reachable: a soak
/// partition holds 24 secure-store entries shared with every other applet, so
/// the fourth registration's rewrite (`12 + 6 + 7 > 24`) refused the fifth with
/// `KeyStoreFull` — `apps/fido/tests/key_store_ceiling.rs`.
pub const DEVICE_MAX_CREDS: usize = FIDO_CAPACITY as usize;

/// Credentials the resident snapshot codec will hold — a **format** bound, not a
/// capacity.
///
/// Unchanged at 12, and it must stay separate from [`DEVICE_MAX_CREDS`]: the
/// snapshot is one whole-image CBOR document, so its bound is the chunked
/// slot's payload (`chunked::MAX_PARTS * chunked::PART_PAYLOAD_MAX` = 5,952 B,
/// US-1010), and no store with more capacity makes a longer snapshot legal.
///
/// It is also the array size of [`DeviceKeystore::credentials`], so it is a
/// **RAM** figure as much as a format one: `DeviceCredential` measures 720
/// bytes, so 12 of them is 8,640 bytes of `.bss`. A resident array sized to
/// [`DEVICE_MAX_CREDS`] would be 856 × 720 = **616,320 bytes** against 532,480
/// bytes of RAM on an RP2350 — which is why the per-record store
/// (`keyregion::fido_store::FidoRecordStore`) is stateless and loads one
/// credential at a time into a bounded `CredentialWindow`, and why the array is
/// a transitional shape on the not-yet-migrated snapshot path rather than the
/// destination.
pub const SNAPSHOT_MAX_CREDS: usize = 12;

/// How many credential IDs one CTAP operation may hold in RAM at once.
///
/// The bound on the *pending* lists `getAssertion` and credential management
/// build — the assertion remainder after the first one is returned, the RPs of
/// an `enumerateRPsBegin`, the IDs of an `enumerateCredsBegin`.
///
/// It is emphatically **not** a capacity and must not be one: each element is
/// 64 bytes of credential ID (72 with the `heapless` length), so sizing these
/// vectors at [`DEVICE_MAX_CREDS`] would be 856 × 72 = **61,632 bytes of stack**
/// in `get_assertion`, on a task whose whole frame is already the boot path's
/// 5,056-byte budget in miniature. The number lives here so the two are never
/// confused again.
///
/// **Why 12, and why that is a deliberate choice rather than a leftover.** CTAP
/// 2.1 does not bound how many passkeys one relying party may register, so this
/// is a genuine limit and not a claim about the spec. It is 12 because it is the
/// value these vectors already had — they were sized by [`DEVICE_MAX_CREDS`] when
/// that was 12 — and **keeping it is what makes the decoupling free**: `.bss`
/// does not move by a byte, and no wire behaviour changes, so the only thing
/// this constant buys is the separation of the two questions. Beyond it the
/// device answers `CTAP2_ERR_LIMIT_EXCEEDED` (0x27) rather than truncating,
/// which is the refusal `device_core.rs` already returns on overflow.
///
/// Raising it is a `.bss` decision, not a correctness one: 16 entries of
/// 64-byte credential IDs is +288 bytes per list across four statics plus two
/// stack frames, against a part whose statics are already 439 KiB of 520 KiB
/// (`secure_store.rs`'s DARK-BOOT-1 note). When the on-demand read path lands
/// (US-1554's follow-through) these lists become a cursor into the key region's
/// index and this constant goes away with them.
pub const MAX_PENDING_CREDENTIAL_IDS: usize = 12;
/// US-1011: how many signature-counter bumps may accumulate in RAM before the
/// whole keystore image is rewritten to the store.
///
/// **This number was chosen by reasoning, not measured.** No board was
/// attached, so there is no wear measurement behind it; the two terms of the
/// trade-off are as follows, and both are argued in `docs/erase-budget.md` §4a.
///
/// * **Wear side.** `docs/erase-budget.md` measures one persist at 8 sector
///   erasures landing on 8 distinct sectors, so each sector collects one erase
///   cycle per persist and the per-persist ceiling is `100,000 / 1 = 100,000`
///   (a *literature* NOR endurance figure, not a measurement of the part
///   fitted to a Pico 2). The ceiling is linear in this constant: at 32 it is
///   **3.2 million assertions**.
///
///   Note what that is and is not. A deployment doing 10,000 assertions a day
///   exhausts the partition in **320 days — about 0.88 years** — not the 878
///   years an earlier draft of this comment claimed. That arithmetic was wrong
///   by a factor of 1,000, and it inverted the argument: it made the current
///   value look like it already outlives any deployment, when a 10 k/day
///   deployment is short of a year even *after* the batching.
///
///   So 32 is **not** chosen because it already outlives anything. It is the
///   smallest value that moves the lifetime out of the part's endurance
///   envelope by ~32x while keeping the post-cut forward skip below small.
///   **A larger value would very likely serve wear better, and this branch
///   cannot justify one** — there is no board, so no measurement of the
///   fitted part's real endurance. That is US-1007's decision to make on
///   hardware, not a documentation one. See `docs/erase-budget.md` §4a, whose
///   `check_erase_budget.py` check now fails if this constant and the
///   document's disagree.
///
/// * **Safety side.** The window is how far `signCount` may skip *forward* if
///   the device loses power inside it — at most this many assertions, because
///   the restore in [`DeviceKeystore::load`] starts a whole window above the
///   durable image (US-1012). FIDO does not read `signCount` as a count of
///   assertions; it is an opaque value that must simply never repeat, so a
///   forward skip costs nothing in clone-detection terms. It does mean the
///   value a restored device signs is not consecutive with the one before the
///   cut, and a reader diffing two `signCount`s by hand will see a jump. 32
///   keeps that jump at a size no plausible heuristic resolves.
///
/// **Chosen: 32.** A power of two so the comparison is a constant compare with
/// no division, the smallest value that moves the lifetime out of the flash
/// part's endurance envelope by a factor of ~32, and small enough that the
/// post-cut skip stays in the noise. It is *not* chosen because it already
/// outlives any deployment — see the wear bullet; the corrected arithmetic
/// says the opposite.
///
/// Changing it is a deliberate edit of this comment, of `PINNED_INTERVAL` in
/// `tests/counter_batching.rs` and `tests/counter_monotonic.rs`, and of
/// `docs/erase-budget.md` §4a. **The prose is no longer the coupling**:
/// `check_erase_budget.py` now reads this constant out of the source and
/// fails if the document's `COUNTER_PERSIST_INTERVAL` and
/// `batched_assertion_ceiling` disagree with it, in either direction.
///
/// **What the window is not.** It never defers anything but the counter. A
/// credential created, deleted or grown inside a window persists on its own
/// terms, immediately, on its own account — see
/// [`DeviceKeystore::store_credential_checked`],
/// [`DeviceKeystore::grow_checked`] and the `dirty` flag discipline in
/// [`DeviceKeystore::persist_if_dirty`].
pub const COUNTER_PERSIST_INTERVAL: u16 = 32;

/// US-1012: **why** a snapshot is being decoded, which fixes both halves of
/// the restore mechanism at once — how much slack the counters get, and how
/// much of the batch window is already spent.
///
/// The two are one mechanism and only safe together. Granting slack without
/// spending the window lets a restored device run a whole extra window past
/// the skip and sign a `signCount` the client has already seen, which is a
/// clone-detection failure; spending the window without granting the slack
/// resumes at the durable value, which is the same regression by another
/// route. An enum rather than a `slack: u32` parameter because the pairing
/// must not be expressible apart: a caller that passes a bare number has to
/// decide, separately and silently, whether it is a restore, and a caller
/// that wants one half for another reason gets the other half by accident.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Decode {
    /// A faithful read of the stored bytes — the host interchange codec and
    /// every decode-for-inspection. No slack, and a window that is genuinely
    /// empty (0 bumps used), because nothing has happened that has not been
    /// written.
    Faithful,
    /// A restore from the durable image after a power cut. The counters start
    /// a whole window above the durable image, and that window arrives
    /// **already spent**, so the first assertion after the power-on writes the
    /// counter down and the in-RAM counter can never run more than one window
    /// ahead of the store.
    Restore,
}

impl Decode {
    /// `(counter slack, initial batch window)` for this mode.
    ///
    /// The slack is [`COUNTER_PERSIST_INTERVAL`] as a `u32` because it is added
    /// to `u32` counters and saturates rather than wrapping — see
    /// [`DeviceKeystore::load`]. The window is the same constant as a `u16`
    /// because that is what [`DeviceKeystore::counter_unpersisted`] holds.
    fn slack_and_window(self) -> (u32, u16) {
        match self {
            Decode::Faithful => (0, 0),
            Decode::Restore => (
                COUNTER_PERSIST_INTERVAL as u32,
                COUNTER_PERSIST_INTERVAL,
            ),
        }
    }
}

/// Maximum large-blob array bytes (CTAP2.1 §6.10; matches the host
/// MAX_LARGE_BLOB_ARRAY + 16-byte SHA-256 checksum).
pub const LARGE_BLOB_MAX: usize = 1024;
/// Max credential-ID / user-handle / blob bytes per credential.
const ID_MAX: usize = 64;
/// Max RP ID / user name text bytes.
const NAME_MAX: usize = 64;
/// Max hmac-secret bytes.
const HMAC_MAX: usize = 64;

/// The auth-map scratch [`DeviceKeystore::to_cbor`] builds into.
///
/// # Why it is 4,608 and not 1,536
///
/// US-176 added the RS-Key `0x41` state, whose **plaintext** half alone is
/// bounded by `2,048` (org attestation chain) + `640` (32 audit records × 20) +
/// `32` (epoch) + a few headers ≈ 2,750 bytes, and the old 1,536 could not hold
/// a third of that. The bound is the worst case of everything the auth map can
/// hold, not the usual case, and it is written out rather than derived at
/// compile time because a `const` arithmetic expression over
/// `AUDIT_RING_MAX`/`ORG_CHAIN_MAX` would have to track three crates' bounds to
/// stay correct and would silently stop being worst-case the first time one of
/// them grew:
///
/// | field | worst case |
/// |---|---|
/// | pin state (key 1) | ~250 |
/// | cred counter (key 2) | 3 |
/// | large-blob array (key 3, sealed) | 1,024 + 28 + 3 |
/// | vault state (key 4, sealed) | 32 + 28 + 3 |
/// | device random (key 5, sealed) | 32 + 28 + 3 |
/// | physical config (key 6) | ~40 |
/// | vendor secret (key 7, sealed) | 200 + 28 + 3 |
/// | vendor public (key 8) | 2,048 + 640 + 32 + 3, ~2,750 |
/// | map header + 7 pair keys | ~10 |
/// | **total** | **~4,450** |
///
/// `tests/vendor41_state.rs::the_auth_scratch_holds_the_worst_case_auth_map`
/// encodes a state at every one of those bounds and asserts the map fits, so a
/// field added without a line here fails a test rather than a device.
///
/// # Why the cost is acceptable
///
/// 4,608 bytes of stack in a function marked `#[inline(never)]`, in a call
/// chain that already carries an 8,448-byte output buffer. It is not free, and
/// the ceiling it pushes against is the real one: the snapshot *total* is
/// bounded by the chunked slot's 5,952-byte payload (US-1010), so a device with a full
/// credential list can now run out of room where it did not before. That is
/// reported rather than hidden — see `vendor_state`'s module docs, and
/// `grow_checked`, which turns the shortfall into a clean `0x28`.
pub const AUTH_SCRATCH: usize = 4_608;

/// COSE public key (fixed-size; P-256 EC2 or OKP).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeviceCoseKey {
    pub kty: i32,
    pub alg: i32,
    pub crv: Option<i32>,
    /// EC2 x (32) or OKP public key (32).
    pub x: Option<[u8; 32]>,
    /// EC2 y (32).
    pub y: Option<[u8; 32]>,
}

impl DeviceCoseKey {
    /// P-256 ES256 key from 32-byte coordinates.
    pub fn es256(x: [u8; 32], y: [u8; 32]) -> Self {
        Self { kty: 2, alg: -7, crv: Some(1), x: Some(x), y: Some(y) }
    }
}

/// A stored credential (fixed-size mirror of the host `StoredCredential`).
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCredential {
    pub credential_id: HeaplessVec<u8, ID_MAX>,
    pub public_key: DeviceCoseKey,
    /// P-256 private scalar (32 bytes).
    pub private_key: [u8; 32],
    pub rp_id_hash: [u8; 32],
    pub rp_id: HeaplessVec<u8, NAME_MAX>,
    pub user_handle: HeaplessVec<u8, ID_MAX>,
    pub user_name: HeaplessVec<u8, NAME_MAX>,
    pub user_display_name: HeaplessVec<u8, NAME_MAX>,
    pub cred_protect: u8,
    pub large_blob_key: Option<[u8; 32]>,
    pub hmac_secret: HeaplessVec<u8, HMAC_MAX>,
    pub cred_blob: HeaplessVec<u8, ID_MAX>,
    pub third_party_payment: bool,
    pub pin_complexity_policy: bool,
    pub resident: bool,
    pub algorithm: i32,
    pub counter: u32,
    pub revoked: bool,
    pub expires_at: Option<u32>,
}

/// US-911: seal one sensitive snapshot field and push it as a bstr into
/// `out`. `None` key = the legacy plaintext fallback (unkeyed store). The
/// AAD binds the snapshot slot, the field scope and the credential ID
/// (empty for auth-level fields).
///
/// `pub(crate)` since US-176, which seals the RS-Key `0x41` state through the
/// same primitive rather than a second one. The alternative — a sealer in
/// `vendor_state` — would be a second place the AAD is assembled, and the AAD
/// is what stops a value written as one field being replayed as another.
pub(crate) fn seal_push<const N: usize>(
    key: Option<&[u8; 32]>,
    scope: FieldScope,
    cred_id: &[u8],
    pt: &[u8],
    out: &mut HeaplessVec<u8, N>,
) -> Result<(), CborError> {
    match key {
        Some(k) => {
            if pt.len() > MAX_FIELD_PT {
                return Err(CborError::BufferFull);
            }
            let mut aad: HeaplessVec<u8, 176> = HeaplessVec::new();
            snapshot_crypt::field_aad_heapless(KEYSTORE_SLOT, scope, cred_id, &mut aad)?;
            // Stack scratch bounded by MAX_FIELD_PT — the largest sensitive
            // field is the large-blob array.
            let mut blob = [0u8; MAX_FIELD_PT + FIELD_OVERHEAD];
            let end = pt.len() + FIELD_OVERHEAD;
            snapshot_crypt::seal_field(k, &aad, pt, &mut blob[..end])?;
            no_heap::push_bstr(out, &blob[..end])
        }
        None => no_heap::push_bstr(out, pt),
    }
}

/// US-911: open one sealed field into `scratch`; returns the plaintext
/// length. Fails closed on any tag mismatch.
///
/// `pub(crate)` since US-176 — see [`seal_push`]'s note.
pub(crate) fn open_sealed_field(
    key: &[u8; 32],
    scope: FieldScope,
    cred_id: &[u8],
    blob: &[u8],
    scratch: &mut [u8],
) -> Option<usize> {
    let mut aad: HeaplessVec<u8, 176> = HeaplessVec::new();
    snapshot_crypt::field_aad_heapless(KEYSTORE_SLOT, scope, cred_id, &mut aad).ok()?;
    snapshot_crypt::open_field(key, &aad, blob, scratch)
}

impl DeviceCredential {
    pub(crate) fn new_template() -> Self {
        Self {
            credential_id: HeaplessVec::new(),
            public_key: DeviceCoseKey { kty: 2, alg: -7, crv: Some(1), x: None, y: None },
            private_key: [0; 32],
            rp_id_hash: [0; 32],
            rp_id: HeaplessVec::new(),
            user_handle: HeaplessVec::new(),
            user_name: HeaplessVec::new(),
            user_display_name: HeaplessVec::new(),
            cred_protect: 0,
            large_blob_key: None,
            hmac_secret: HeaplessVec::new(),
            cred_blob: HeaplessVec::new(),
            third_party_payment: false,
            pin_complexity_policy: false,
            resident: false,
            algorithm: -7,
            counter: 0,
            revoked: false,
            expires_at: None,
        }
    }

    /// Encode with the host `StoredCredential::to_cbor` key numbering, in
    /// canonical key order (all single-byte unsigned keys: 1..=19).
    ///
    /// US-911: `key` = the store key the sensitive fields (private_key 3,
    /// cred_blob 17, large_blob_key 18, hmac_secret 19) are AEAD-sealed
    /// under; metadata (rpId, user id, credProtect flags) stays plaintext
    /// for enumeration. `None` = the legacy plaintext fallback.
    pub fn encode<const N: usize>(
        &self,
        key: Option<&[u8; 32]>,
        out: &mut HeaplessVec<u8, N>,
    ) -> Result<(), CborError> {
        // US-911: the sealed fields add up to 4 × 28 B of framing, so the
        // body bound grew from 768.
        let mut body: HeaplessVec<u8, 896> = HeaplessVec::new();
        let mut n = 12;
        if !self.cred_blob.is_empty() { n += 1; }
        if self.large_blob_key.is_some() { n += 1; }
        if !self.hmac_secret.is_empty() { n += 1; }
        if !self.rp_id.is_empty() { n += 1; }
        if !self.user_name.is_empty() { n += 1; }
        if !self.user_display_name.is_empty() { n += 1; }
        if self.expires_at.is_some() { n += 1; }
        no_heap::push_map_header(&mut body, n)?;
        no_heap::push_uint(&mut body, 1)?;
        no_heap::push_bstr(&mut body, &self.credential_id)?;
        no_heap::push_uint(&mut body, 2)?;
        self.public_key.encode(&mut body)?;
        no_heap::push_uint(&mut body, 3)?;
        seal_push(key, FieldScope::CredentialPrivateKey, &self.credential_id, &self.private_key, &mut body)?;
        no_heap::push_uint(&mut body, 4)?;
        no_heap::push_bstr(&mut body, &self.rp_id_hash)?;
        // Host parity: StoredCredential::to_cbor stores the algorithm as
        // U(alg as u64) (two's complement), not a proper CBOR negative.
        no_heap::push_uint(&mut body, 5)?;
        no_heap::push_uint(&mut body, self.algorithm as u64)?;
        no_heap::push_uint(&mut body, 6)?;
        no_heap::push_uint(&mut body, self.counter as u64)?;
        no_heap::push_uint(&mut body, 7)?;
        no_heap::push_bool(&mut body, self.resident)?;
        no_heap::push_uint(&mut body, 8)?;
        no_heap::push_bool(&mut body, self.third_party_payment)?;
        no_heap::push_uint(&mut body, 9)?;
        no_heap::push_bool(&mut body, self.pin_complexity_policy)?;
        no_heap::push_uint(&mut body, 10)?;
        no_heap::push_bool(&mut body, self.revoked)?;
        if !self.rp_id.is_empty() {
            no_heap::push_uint(&mut body, 11)?;
            no_heap::push_tstr(&mut body, core::str::from_utf8(&self.rp_id).map_err(|_| CborError::InvalidUtf8)?)?;
        }
        if !self.user_name.is_empty() {
            no_heap::push_uint(&mut body, 12)?;
            no_heap::push_tstr(&mut body, core::str::from_utf8(&self.user_name).map_err(|_| CborError::InvalidUtf8)?)?;
        }
        if !self.user_display_name.is_empty() {
            no_heap::push_uint(&mut body, 13)?;
            no_heap::push_tstr(&mut body, core::str::from_utf8(&self.user_display_name).map_err(|_| CborError::InvalidUtf8)?)?;
        }
        no_heap::push_uint(&mut body, 14)?;
        no_heap::push_bstr(&mut body, &self.user_handle)?;
        no_heap::push_uint(&mut body, 15)?;
        no_heap::push_uint(&mut body, self.cred_protect as u64)?;
        if let Some(ts) = self.expires_at {
            no_heap::push_uint(&mut body, 16)?;
            no_heap::push_uint(&mut body, ts as u64)?;
        }
        if !self.cred_blob.is_empty() {
            no_heap::push_uint(&mut body, 17)?;
            seal_push(key, FieldScope::CredentialBlob, &self.credential_id, &self.cred_blob, &mut body)?;
        }
        if let Some(k) = &self.large_blob_key {
            no_heap::push_uint(&mut body, 18)?;
            seal_push(key, FieldScope::CredentialLargeBlobKey, &self.credential_id, k, &mut body)?;
        }
        if !self.hmac_secret.is_empty() {
            no_heap::push_uint(&mut body, 19)?;
            seal_push(key, FieldScope::CredentialHmacSecret, &self.credential_id, &self.hmac_secret, &mut body)?;
        }
        no_heap::push_bstr(out, &body)
    }

    /// Decode one credential from a CBOR map (host key numbering). `None` on
    /// any structural mismatch — corrupt input is refused.
    ///
    /// US-911: `sealed` = the snapshot's `{2: 2}` marker; the sensitive
    /// fields (3/17/18/19) are AEAD-sealed under `key`. A field that fails
    /// to open kills the ENTRY (metadata kept, secrets unusable,
    /// `revoked = true`) — never a silent zero.
    fn decode(bytes: &[u8], key: Option<&[u8; 32]>, sealed: bool) -> Option<Self> {
        let mut c = Self::new_template();
        let mut p = Parser::new(bytes);
        match p.next().ok()? {
            Item::Map(n) => n,
            _ => return None,
        };
        // US-911: the sensitive fields are captured raw and opened after the
        // walk (the credential ID may be encoded after them).
        let mut raw_private: Option<&[u8]> = None;
        let mut raw_cred_blob: Option<&[u8]> = None;
        let mut raw_large_blob: Option<&[u8]> = None;
        let mut raw_hmac: Option<&[u8]> = None;
        for _ in 0.. {
            let key_num = match p.next().ok()? {
                Item::U(k) => k,
                _ => return None,
            };
            match key_num {
                1 => match p.next().ok()? {
                    Item::B(b) => c.credential_id.extend_from_slice(b).ok()?,
                    _ => return None,
                },
                2 => c.public_key = DeviceCoseKey::decode_value(&mut p)?,
                3 => match p.next().ok()? {
                    Item::B(b) => raw_private = Some(b),
                    _ => return None,
                },
                4 => match p.next().ok()? {
                    Item::B(b) if b.len() == 32 => c.rp_id_hash.copy_from_slice(b),
                    _ => return None,
                },
                5 => match p.next().ok()? {
                    Item::U(u) => c.algorithm = u as i32,
                    Item::N(n) => c.algorithm = n as i32,
                    _ => return None,
                },
                6 => match p.next().ok()? {
                    Item::U(u) => c.counter = u as u32,
                    _ => return None,
                },
                7 => match p.next().ok()? {
                    Item::Bool(b) => c.resident = b,
                    _ => return None,
                },
                8 => match p.next().ok()? {
                    Item::Bool(b) => c.third_party_payment = b,
                    _ => return None,
                },
                9 => match p.next().ok()? {
                    Item::Bool(b) => c.pin_complexity_policy = b,
                    _ => return None,
                },
                10 => match p.next().ok()? {
                    Item::Bool(b) => c.revoked = b,
                    _ => return None,
                },
                11 => match p.next().ok()? {
                    Item::T(s) => c.rp_id.extend_from_slice(s.as_bytes()).ok()?,
                    _ => return None,
                },
                12 => match p.next().ok()? {
                    Item::T(s) => c.user_name.extend_from_slice(s.as_bytes()).ok()?,
                    _ => return None,
                },
                13 => match p.next().ok()? {
                    Item::T(s) => c.user_display_name.extend_from_slice(s.as_bytes()).ok()?,
                    _ => return None,
                },
                14 => match p.next().ok()? {
                    Item::B(b) => c.user_handle.extend_from_slice(b).ok()?,
                    _ => return None,
                },
                15 => match p.next().ok()? {
                    Item::U(u) => c.cred_protect = u as u8,
                    _ => return None,
                },
                16 => match p.next().ok()? {
                    Item::U(u) => c.expires_at = Some(u as u32),
                    _ => return None,
                },
                17 => match p.next().ok()? {
                    Item::B(b) => raw_cred_blob = Some(b),
                    _ => return None,
                },
                18 => match p.next().ok()? {
                    Item::B(b) => raw_large_blob = Some(b),
                    _ => return None,
                },
                19 => match p.next().ok()? {
                    Item::B(b) => raw_hmac = Some(b),
                    _ => return None,
                },
                _ => p.skip().ok()?,
            }
            if p.remaining() == 0 {
                break;
            }
        }
        if sealed {
            let key = key?;
            let mut scratch = [0u8; MAX_FIELD_PT + FIELD_OVERHEAD];
            let mut killed = false;
            // private_key: must be present (as in the legacy format) and
            // must decrypt to exactly 32 bytes.
            let blob = raw_private?;
            match open_sealed_field(
                key,
                FieldScope::CredentialPrivateKey,
                &c.credential_id,
                blob,
                &mut scratch,
            ) {
                Some(32) => c.private_key.copy_from_slice(&scratch[..32]),
                _ => killed = true,
            }
            if let Some(blob) = raw_cred_blob {
                match open_sealed_field(
                    key,
                    FieldScope::CredentialBlob,
                    &c.credential_id,
                    blob,
                    &mut scratch,
                ) {
                    Some(n) if n <= ID_MAX => {
                        c.cred_blob.clear();
                        c.cred_blob.extend_from_slice(&scratch[..n]).ok()?;
                    }
                    _ => killed = true,
                }
            }
            if let Some(blob) = raw_large_blob {
                match open_sealed_field(
                    key,
                    FieldScope::CredentialLargeBlobKey,
                    &c.credential_id,
                    blob,
                    &mut scratch,
                ) {
                    Some(32) => {
                        c.large_blob_key = Some(<[u8; 32]>::try_from(&scratch[..32]).ok()?)
                    }
                    _ => killed = true,
                }
            }
            if let Some(blob) = raw_hmac {
                match open_sealed_field(
                    key,
                    FieldScope::CredentialHmacSecret,
                    &c.credential_id,
                    blob,
                    &mut scratch,
                ) {
                    Some(n) if n <= HMAC_MAX => {
                        c.hmac_secret.clear();
                        c.hmac_secret.extend_from_slice(&scratch[..n]).ok()?;
                    }
                    _ => killed = true,
                }
            }
            if killed {
                // The entry is refused, not zeroed: metadata survives, the
                // secrets do not, the credential is dead.
                c.revoked = true;
                c.private_key = [0u8; 32];
                c.hmac_secret.clear();
                c.large_blob_key = None;
                c.cred_blob.clear();
            }
        } else {
            // Legacy plaintext fields (the pre-US-911 shape).
            match raw_private {
                Some(b) if b.len() == 32 => c.private_key.copy_from_slice(b),
                _ => return None,
            }
            if let Some(b) = raw_cred_blob {
                c.cred_blob.extend_from_slice(b).ok()?;
            }
            if let Some(b) = raw_large_blob {
                if b.len() != 32 {
                    return None;
                }
                c.large_blob_key = Some(<[u8; 32]>::try_from(b).ok()?);
            }
            if let Some(b) = raw_hmac {
                c.hmac_secret.extend_from_slice(b).ok()?;
            }
        }
        Some(c)
    }
}

impl DeviceCoseKey {
    /// Encode the COSE key map: `{1: kty, 2?: crv, 3: alg, -1: x, -2: y}`
    /// (host ordering; single-byte keys sort 1,2,3 then the negatives).
    pub fn encode<const N: usize>(&self, out: &mut HeaplessVec<u8, N>) -> Result<(), CborError> {
        let mut body: HeaplessVec<u8, 128> = HeaplessVec::new();
        let mut n = 2;
        if self.crv.is_some() {
            n += 1;
        }
        if self.x.is_some() {
            n += 1;
        }
        if self.y.is_some() {
            n += 1;
        }
        no_heap::push_map_header(&mut body, n)?;
        no_heap::push_uint(&mut body, 1)?;
        no_heap::push_uint(&mut body, self.kty as u64)?;
        if let Some(crv) = self.crv {
            no_heap::push_uint(&mut body, 2)?;
            no_heap::push_neg(&mut body, crv as i64)?;
        }
        no_heap::push_uint(&mut body, 3)?;
        no_heap::push_neg(&mut body, self.alg as i64)?;
        if let Some(x) = &self.x {
            no_heap::push_neg(&mut body, -1)?;
            no_heap::push_bstr(&mut body, x)?;
        }
        if let Some(y) = &self.y {
            no_heap::push_neg(&mut body, -2)?;
            no_heap::push_bstr(&mut body, y)?;
        }
        out.extend_from_slice(&body).map_err(|_| CborError::BufferFull)
    }

    /// Encode the COSE key in the **standard wire format** used inside
    /// authData attestedCredentialData: `{1: kty, 3: alg, -1: crv, -2: x,
    /// -3: y}` (the host `encode_cose_pubkey` layout — note the snapshot
    /// format used by [`DeviceCoseKey::encode`] differs).
    pub fn encode_wire<const N: usize>(&self, out: &mut HeaplessVec<u8, N>) -> Result<(), CborError> {
        let mut body: HeaplessVec<u8, 128> = HeaplessVec::new();
        no_heap::push_map_header(&mut body, 5)?;
        no_heap::push_uint(&mut body, 1)?;
        no_heap::push_uint(&mut body, self.kty as u64)?;
        no_heap::push_uint(&mut body, 3)?;
        no_heap::push_neg(&mut body, self.alg as i64)?;
        no_heap::push_neg(&mut body, -1)?;
        no_heap::push_uint(&mut body, self.crv.unwrap_or(1) as u64)?;
        no_heap::push_neg(&mut body, -2)?;
        match &self.x {
            Some(x) => no_heap::push_bstr(&mut body, x)?,
            None => no_heap::push_bstr(&mut body, &[0u8; 32])?,
        }
        no_heap::push_neg(&mut body, -3)?;
        match &self.y {
            Some(y) => no_heap::push_bstr(&mut body, y)?,
            None => no_heap::push_bstr(&mut body, &[0u8; 32])?,
        }
        out.extend_from_slice(&body).map_err(|_| CborError::BufferFull)
    }

    fn decode_value(p: &mut Parser<'_>) -> Option<Self> {
        let n = match p.next().ok()? {
            Item::Map(n) => n,
            _ => return None,
        };
        let mut k = Self { kty: 2, alg: -7, crv: None, x: None, y: None };
        for _ in 0..n {
            let key = match p.next().ok()? {
                Item::U(u) => u as i64,
                Item::N(n) => n,
                _ => return None,
            };
            match key {
                1 => match p.next().ok()? {
                    Item::U(u) => k.kty = u as i32,
                    _ => return None,
                },
                2 => match p.next().ok()? {
                    Item::N(n) => k.crv = Some(n as i32),
                    _ => return None,
                },
                3 => match p.next().ok()? {
                    Item::N(n) => k.alg = n as i32,
                    _ => return None,
                },
                -1 => match p.next().ok()? {
                    Item::B(b) if b.len() == 32 => k.x = Some(<[u8; 32]>::try_from(b).ok()?),
                    _ => return None,
                },
                -2 => match p.next().ok()? {
                    Item::B(b) if b.len() == 32 => k.y = Some(<[u8; 32]>::try_from(b).ok()?),
                    _ => return None,
                },
                _ => {
                    p.skip().ok()?;
                }
            }
        }
        Some(k)
    }
}

/// Device PIN state (fixed-size mirror of the host `PinState`).
#[derive(Debug, Clone, PartialEq)]
pub struct DevicePinState {
    /// Verifier bytes: legacy `SHA256(PIN)[..16]`, or the salted stretched
    /// verifier (US-910) when `pin_verifier_format == 1`.
    pub pin_hash: Option<[u8; 16]>,
    /// US-910 verifier format stamp (`0` legacy, `1` stretched).
    pub pin_verifier_format: u8,
    /// US-910 per-device TRNG salt for the stretched verifier.
    pub pin_salt: Option<[u8; 16]>,
    /// US-910 iteration count for the stretched verifier.
    pub pin_iter: u32,
    pub retries: u8,
    pub blocked: bool,
    /// US-909: durable 3-strike latch (snapshot keys 3/4; was previously
    /// encoded as constants `false`/`0`).
    pub needs_power_cycle: bool,
    /// US-909: durable consecutive PIN-mismatch counter.
    pub new_pin_mismatches: u8,
    pub min_pin_length: u8,
    pub min_pin_rp_ids: HeaplessVec<HeaplessVec<u8, NAME_MAX>, 8>,
    pub always_uv: bool,
    pub force_pin_change: bool,
    pub pin_complexity_policy: bool,
    pub enterprise_attestation: bool,
    pub enterprise_rp_ids: HeaplessVec<HeaplessVec<u8, NAME_MAX>, 8>,
}

impl Default for DevicePinState {
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
            min_pin_length: 4,
            min_pin_rp_ids: HeaplessVec::new(),
            always_uv: false,
            force_pin_change: false,
            pin_complexity_policy: false,
            enterprise_attestation: false,
            enterprise_rp_ids: HeaplessVec::new(),
        }
    }
}

impl DevicePinState {
    /// Host `PinState::to_cbor` key numbering (1..13, 12/13 always present).
    /// Writes the bare CBOR map (the host nests the Value directly).
    fn encode_into<const N: usize>(&self, out: &mut HeaplessVec<u8, N>) -> Result<(), CborError> {
        let mut body: HeaplessVec<u8, 512> = HeaplessVec::new();
        // US-910: stretched-verifier keys exist only in the stretched
        // format (with the salt present — a stretched record without a
        // salt would be unverifiable, so it encodes as legacy), leaving
        // legacy snapshots byte-identical to before.
        let stretched = self.pin_verifier_format == crypto::PIN_VERIFIER_FORMAT_STRETCHED
            && self.pin_salt.is_some();
        no_heap::push_map_header(
            &mut body,
            12 + if self.pin_hash.is_some() { 1 } else { 0 }
                + if stretched { 3 } else { 0 },
        )?;
        no_heap::push_uint(&mut body, 1)?;
        no_heap::push_uint(&mut body, self.retries as u64)?;
        no_heap::push_uint(&mut body, 2)?;
        no_heap::push_bool(&mut body, self.blocked)?;
        // Keys 3/4: durable 3-strike latch + mismatch counter (US-909).
        no_heap::push_uint(&mut body, 3)?;
        no_heap::push_bool(&mut body, self.needs_power_cycle)?;
        no_heap::push_uint(&mut body, 4)?;
        no_heap::push_uint(&mut body, self.new_pin_mismatches as u64)?;
        no_heap::push_uint(&mut body, 5)?;
        no_heap::push_uint(&mut body, self.min_pin_length as u64)?;
        no_heap::push_uint(&mut body, 6)?;
        no_heap::push_bool(&mut body, self.always_uv)?;
        no_heap::push_uint(&mut body, 7)?;
        no_heap::push_bool(&mut body, self.force_pin_change)?;
        no_heap::push_uint(&mut body, 8)?;
        no_heap::push_bool(&mut body, self.pin_complexity_policy)?;
        no_heap::push_uint(&mut body, 9)?;
        no_heap::push_bool(&mut body, self.enterprise_attestation)?;
        no_heap::push_uint(&mut body, 10)?;
        no_heap::push_bool(&mut body, self.pin_hash.is_some())?;
        if let Some(h) = &self.pin_hash {
            no_heap::push_uint(&mut body, 11)?;
            no_heap::push_bstr(&mut body, h)?;
        }
        no_heap::push_uint(&mut body, 12)?;
        no_heap::push_array_header(&mut body, self.min_pin_rp_ids.len())?;
        for id in &self.min_pin_rp_ids {
            no_heap::push_tstr(&mut body, core::str::from_utf8(id).map_err(|_| CborError::InvalidUtf8)?)?;
        }
        no_heap::push_uint(&mut body, 13)?;
        no_heap::push_array_header(&mut body, self.enterprise_rp_ids.len())?;
        for id in &self.enterprise_rp_ids {
            no_heap::push_tstr(&mut body, core::str::from_utf8(id).map_err(|_| CborError::InvalidUtf8)?)?;
        }
        // US-910: stretched-verifier keys (see the header count above).
        if stretched {
            no_heap::push_uint(&mut body, 14)?;
            no_heap::push_uint(&mut body, self.pin_verifier_format as u64)?;
            if let Some(salt) = &self.pin_salt {
                no_heap::push_uint(&mut body, 15)?;
                no_heap::push_bstr(&mut body, salt)?;
            }
            no_heap::push_uint(&mut body, 16)?;
            no_heap::push_uint(&mut body, self.pin_iter as u64)?;
        }
        out.extend_from_slice(&body).map_err(|_| CborError::BufferFull)
    }

    fn decode_pairs(p: &mut Parser<'_>, n: u64) -> Option<Self> {
        let mut s = Self::default();
        for _ in 0..n {
            let key = match p.next().ok()? {
                Item::U(k) => k,
                _ => return None,
            };
            match key {
                1 => match p.next().ok()? {
                    Item::U(u) => s.retries = u as u8,
                    _ => return None,
                },
                2 => match p.next().ok()? {
                    Item::Bool(b) => s.blocked = b,
                    _ => return None,
                },
                3 => match p.next().ok()? {
                    Item::Bool(b) => s.needs_power_cycle = b,
                    _ => return None,
                },
                4 => match p.next().ok()? {
                    Item::U(u) => s.new_pin_mismatches = u as u8,
                    _ => return None,
                },
                5 => match p.next().ok()? {
                    Item::U(u) => s.min_pin_length = u as u8,
                    _ => return None,
                },
                6 => match p.next().ok()? {
                    Item::Bool(b) => s.always_uv = b,
                    _ => return None,
                },
                7 => match p.next().ok()? {
                    Item::Bool(b) => s.force_pin_change = b,
                    _ => return None,
                },
                8 => match p.next().ok()? {
                    Item::Bool(b) => s.pin_complexity_policy = b,
                    _ => return None,
                },
                9 => match p.next().ok()? {
                    Item::Bool(b) => s.enterprise_attestation = b,
                    _ => return None,
                },
                10 => {
                    // Presence/marker only — key 11 carries the hash.
                    let _ = p.next().ok()?;
                }
                11 => match p.next().ok()? {
                    Item::B(b) if b.len() == 16 => {
                        s.pin_hash = Some(<[u8; 16]>::try_from(b).ok()?)
                    }
                    // Present-but-malformed hash: parse error (FX-409).
                    _ => return None,
                },
                12 | 13 => {
                    let Item::Array(n) = p.next().ok()? else { return None };
                    let mut ids: HeaplessVec<HeaplessVec<u8, NAME_MAX>, 8> = HeaplessVec::new();
                    for _ in 0..n {
                        match p.next().ok()? {
                            Item::T(t) => {
                                let mut v = HeaplessVec::new();
                                v.extend_from_slice(t.as_bytes()).ok()?;
                                ids.push(v).ok()?;
                            }
                            _ => return None,
                        }
                    }
                    if key == 12 {
                        s.min_pin_rp_ids = ids;
                    } else {
                        s.enterprise_rp_ids = ids;
                    }
                }
                14 => match p.next().ok()? {
                    Item::U(u) => s.pin_verifier_format = u as u8,
                    _ => return None,
                },
                15 => match p.next().ok()? {
                    Item::B(b) if b.len() == 16 => {
                        s.pin_salt = Some(<[u8; 16]>::try_from(b).ok()?)
                    }
                    // A stretched record without a salt is corrupt (FX-409).
                    _ => return None,
                },
                16 => match p.next().ok()? {
                    // US-910 (review): pin_iter drives the verifier's
                    // stretched SHA-256 rounds, so an attacker-crafted
                    // snapshot with a huge iteration count wedges the PIN
                    // path. Corrupt input is refused, never truncated.
                    Item::U(u) if u <= crypto::PIN_VERIFIER_ROUNDS as u64 => {
                        s.pin_iter = u as u32
                    }
                    _ => return None,
                },
                _ => p.skip().ok()?,
            }
        }
        Some(s)
    }
}

/// No-heap device keystore.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceKeystore {
    pub pin_state: DevicePinState,
    pub credentials: HeaplessVec<DeviceCredential, SNAPSHOT_MAX_CREDS>,
    pub cred_counter: u32,
    /// Per-device random (32 bytes) seeding the encIdentifier /
    /// encCredStoreState getInfo fields.
    pub device_random: [u8; 32],
    /// Large-blob array (snapshot auth key 3; host interchange format).
    pub large_blob_array: Option<HeaplessVec<u8, LARGE_BLOB_MAX>>,
    /// Vendor vault state (snapshot auth key 4): the 32-byte vault id.
    pub vault_state: Option<[u8; 32]>,
    /// US-113: the physical configuration written through the
    /// `vendorPrototype` (`0xFF`) sub-command. Persisted as auth-map key 6 —
    /// plaintext, because none of it is secret (a VID/PID pair and three small
    /// integers) and sealing it would add a failure mode to a write whose only
    /// cost is a few bytes. See [`crate::vendorff`] for the framing and for why
    /// storing it is not the same as applying it.
    ///
    /// UNSEALED, unlike keys 1-5: `crate::vendorff`'s security section
    /// records the deliberate deviation, the named `FieldScope::AuthPhy`
    /// alternative that was not taken, and the two distinct surfaces (command
    /// path vs. direct snapshot tampering) on which this record becomes
    /// load-bearing. Read that section before relying on any of it.
    pub phy: crate::vendorff::PhyConfig,
    /// US-176: the RS-Key `0x41` Phase I state (master seed, soft lock, audit
    /// journal, org attestation) — snapshot auth keys **7 (sealed)** and **8
    /// (plaintext)**.
    ///
    /// Two keys with two failure policies, and the split is the design: the
    /// sealed half is key material and fails the whole snapshot when it cannot
    /// be opened, the plaintext half is a journal and a certificate chain and
    /// degrades to its documented default. Read
    /// [`crate::vendor_state`]'s module docs before changing either — in
    /// particular before moving either half across the line, because the
    /// plaintext half's largest field (a 2,048-byte chain) does not fit
    /// [`MAX_FIELD_PT`] and could not be sealed without chunking.
    pub vendor: crate::vendor_state::VendorState,
    pub max_creds: usize,
    /// Set by every mutating operation; consumed by
    /// [`DeviceKeystore::persist_if_dirty`].
    pub(crate) dirty: bool,
    /// SOAK-FINDING-1: a transactional mutation already wrote this dirty
    /// snapshot into the store — the persist gate must program the
    /// partition image WITHOUT rewriting it (the rewrite would double the
    /// chunked transient occupancy on a store at its slot bound).
    ///
    /// Invariant: `stored == true` implies the store holds EXACTLY this
    /// dirty snapshot, so skipping the rewrite and programming the image is
    /// equivalent to a fresh `persist()`. Every code path that mutates the
    /// snapshot must therefore either go through a transactional helper
    /// (which sets `stored` only on its own successful persist) or leave
    /// `stored == false` — a plain `dirty = true` mutation with a stale
    /// `stored` would program an image missing that mutation. Callers hold
    /// this by construction: no handler mutates the keystore after a
    /// transactional helper within the same command, and plain mutations
    /// only ever run when `stored == false`.
    pub(crate) stored: bool,
    /// US-1011: signature-counter bumps that have happened in RAM since the
    /// last successful whole-image write, and which are therefore **not** in
    /// the store. One keystore-wide window (not per credential), because one
    /// whole-image write resets every counter at once: a credential that has
    /// not been used since the last write has nothing to write, and one that
    /// has been used N times has N to write, so a shared window of
    /// [`COUNTER_PERSIST_INTERVAL`] bounds both.
    ///
    /// The invariant everything else rests on: **at most
    /// `COUNTER_PERSIST_INTERVAL` bumps may be un-persisted**, and a
    /// successful write of any kind sets this back to 0. US-1012 turns that
    /// into the monotonicity guarantee (a restore starts a whole window above
    /// the durable image, so a cut can only ever skip forward).
    ///
    /// Reset at every site that writes the snapshot, not only the counter's
    /// own: a credential created or deleted mid-window persists the counter
    /// along with it, and the window must start again from there.
    pub(crate) counter_unpersisted: u16,
}

/// Decoded auth-map parts (see [`DeviceKeystore::decode_auth`]).
pub type AuthParts = (
    DevicePinState,
    u32,
    [u8; 32],
    Option<HeaplessVec<u8, LARGE_BLOB_MAX>>,
    Option<[u8; 32]>,
    crate::vendorff::PhyConfig,
    crate::vendor_state::VendorState,
);

impl DeviceKeystore {
    /// A fresh keystore with TRNG-derived device random.
    ///
    /// # Why this is `Result` (US-1005 fix)
    ///
    /// It used to return `Self` and draw through
    /// [`Trng::random_bytes`](fapico2_platform::trng::Trng::random_bytes)
    /// into a `[0u8; 32]`, which is the **plain-draw** half of D-9's two
    /// symptoms and the one that really is all-zeros: a refused draw leaves
    /// the buffer untouched, so a starved generator produced a keystore
    /// whose `device_random` is 32 zero bytes. Nothing downstream notices.
    /// That value is the HKDF `ikm` behind the per-device stateless U2F
    /// master (`stateless::master_from_device_random`), so the failure is a
    /// **predictable U2F master on every device that hit it** — every
    /// registered handle from a token in that state is derivable by anyone
    /// who knows the all-zero input. The `debug_assert!` on the seam could
    /// not catch it in the field: `debug-assertions` is off in the release
    /// profile, so the only guard was a tripwire that is absent from the
    /// shipped image.
    ///
    /// A rejection sampler (`p256::SecretKey::random`) has the opposite
    /// symptom — it loops rather than yielding zeros — and was fixed
    /// separately under US-1007. Both are real; only this one is silent.
    pub fn fresh<R: fapico2_platform::trng::Trng>(
        trng: &mut R,
    ) -> Result<Self, fapico2_platform::trng::TrngError> {
        let mut device_random = [0u8; 32];
        trng.try_random_bytes(&mut device_random)?;
        Ok(Self {
            pin_state: DevicePinState::default(),
            credentials: HeaplessVec::new(),
            cred_counter: 0,
            device_random,
            large_blob_array: None,
            vault_state: None,
            phy: crate::vendorff::PhyConfig::default(),
            vendor: crate::vendor_state::VendorState::default(),
            // **The smaller of the two bounds, and that is the point.**
            //
            // `max_creds` is wire-visible: credMgmt `getMetadata` answers
            // `maxPossibleRemainingResidentCredentialsCount` from
            // `max_remaining_creds`, and a number the device cannot honour is
            // exactly the defect AGENTS.md §4 is about ("a wire claim the device
            // does not honour"). The store's capacity is [`DEVICE_MAX_CREDS`];
            // the binding constraint today is the resident snapshot array at
            // [`SNAPSHOT_MAX_CREDS`], and the honest answer is the smaller of
            // them.
            //
            // When the per-record backend lands and the array goes away, this
            // expression collapses to `DEVICE_MAX_CREDS` with no other edit —
            // which is the reason it is written as a `min` of two named bounds
            // rather than as a literal that has to be remembered.
            max_creds: DEVICE_MAX_CREDS.min(SNAPSHOT_MAX_CREDS),
            dirty: true,
            stored: false,
            // A fresh keystore has issued no counter value at all, so the
            // whole window is available: the first assertion after a
            // first-ever boot may be batched like any other.
            counter_unpersisted: 0,
        })
    }

    /// Load from the chunked `fido.keystore.v1` slot. `Ok(None)` = fresh
    /// partition (no snapshot yet); `Err(Corrupt)` = a snapshot exists but
    /// does not parse — the caller must treat this as fatal (FX-440), never
    /// silently overwrite.
    ///
    /// US-911: the sealed fields open under the store's AEAD key
    /// ([`SecureStore::store_key`]); an unkeyed store reads the legacy
    /// plaintext snapshot format.
    ///
    /// # US-1012: a restore starts a whole window ABOVE the durable image
    ///
    /// This is the restore path, and it is where the signature counter's
    /// monotonicity is bought. US-1011 batches the counter's persist, so
    /// between rewrites the reply signs a value that is **not durable**; a
    /// power cut inside a window would otherwise restore the durable value and
    /// the device would sign a `signCount` the client had already seen — a
    /// repeat, which is exactly the clone-detection failure a sign counter
    /// exists to prevent (and a regression is worse still).
    ///
    /// So a restore does not resume at the durable value. It resumes at
    /// `durable + COUNTER_PERSIST_INTERVAL`, and marks the whole window as
    /// already spent, so the first assertion after a power-on writes the
    /// counter down. The two halves are one mechanism and neither works
    /// without the other:
    ///
    /// ```text
    /// restore:   counter = durable + W,  counter_unpersisted = W
    /// write 1:   counter = durable + W + 1  (window closed, store written)
    /// write k:   counter = durable + kW + 1, un-persisted counter <= W - 1
    /// cut at j:  seen <= durable + kW + W - 1 < durable + kW + W  =  restore
    /// ```
    ///
    /// The `W - 1` is the strictness: the restored value is **greater** than
    /// anything the cut-away session had signed, not merely equal, because the
    /// window-closing write fires on the `W`-th bump and leaves at most
    /// `W - 1` un-persisted. `apps/fido/tests/counter_monotonic.rs` pins that
    /// at every point of the window, for the per-credential counter and for
    /// the keystore-wide one — and it takes its cuts twice, the second from a
    /// device that was itself restored, because that is the only state in
    /// which the *spend* half of this mechanism is observable.
    ///
    /// This is a deliberate *skip forward*, never a rewind: a device and a
    /// clone of it restore the same durable image and are granted the same
    /// slack, so the two stay in lockstep and the ordering clone detection
    /// relies on is preserved. What is given up is the tightness of "how many
    /// assertions have happened" — FIDO does not read `signCount` that way.
    ///
    /// The addition saturates rather than wraps: a `u32` counter is 4.29
    /// billion assertions from saturation, and a wrapped counter would repeat
    /// values no matter what this code does.
    #[inline(never)]
    pub fn load(store: &mut dyn SecureStore) -> Result<Option<Self>, SecureStoreError> {
        if !chunked::contains_chunked(store, KEYSTORE_SLOT) {
            return Ok(None);
        }
        let mut bytes = [0u8; chunked::MAX_LOGICAL_LEN];
        let n = chunked::read_chunked(store, KEYSTORE_SLOT, &mut bytes)?;
        let key = store.store_key();
        // The slack is folded into the decode rather than applied to a
        // `let mut ks` afterwards: a named local of a 12-KiB `DeviceKeystore`
        // is a SECOND copy of it on the stack (measured — the boot chain grew
        // by exactly one keystore, 91,964 -> 106,048 B, and `load`'s own
        // frame went to 57 KB), and the return value has to be moved into the
        // caller's slot regardless. `decode` builds the value once, in place.
        Self::decode(&bytes[..n], key.as_ref(), Decode::Restore)
            .ok_or(SecureStoreError::Corrupt)
            .map(Some)
    }

    /// Parse a snapshot in the host `fido.keystore.v1` CBOR map format:
    /// `{1: [bstr(max_creds), bstr(auth), bstr([bstr(cred), ...])], 2?: 2}`.
    ///
    /// US-911: the `{2: 2}` marker says the sensitive fields are
    /// AEAD-sealed under `key` — a sealed snapshot with `key = None` (or a
    /// wrong key at an auth-level field) is corrupt; a legacy plaintext
    /// snapshot parses with any `key`.
    pub fn from_cbor(bytes: &[u8], key: Option<&[u8; 32]>) -> Option<Self> {
        // A faithful read of the stored bytes, and the host interchange codec
        // shares it. A decode-for-inspection must not come back carrying a
        // device's post-restore guess in it, nor arriving with a spent window
        // it never earned.
        Self::decode(bytes, key, Decode::Faithful)
    }

    /// The decode itself, with **why** it is being decoded as a parameter:
    /// [`Decode::Faithful`] from [`Self::from_cbor`],
    /// [`Decode::Restore`] from [`Self::load`].
    ///
    /// This is an enum rather than a bare `slack: u32` on purpose. The two
    /// halves of US-1012 are one mechanism — a restore that *grants* a window
    /// of slack above the durable image and *spends* it immediately — and
    /// deriving the spent window from `slack == 0` couples the two only
    /// through that inequality. A future caller wanting a non-zero slack for
    /// some other reason would silently get a window already marked spent, and
    /// one wanting to spend it twice would get a silent rewind. The enum makes
    /// the two behaviours unrepresentable apart.
    ///
    /// `#[inline(never)]` for the same reason `load` and `to_cbor` carry it:
    /// the value is a 12-KiB `DeviceKeystore` and the scratch buffers below
    /// are on top of it, so inlining this into a caller that also holds one
    /// would put two on the stack at once.
    #[inline(never)]
    fn decode(bytes: &[u8], key: Option<&[u8; 32]>, mode: Decode) -> Option<Self> {
        let (slack, counter_unpersisted) = mode.slack_and_window();
        // Pass 0 — scan the top-level map (1 or 2 entries, either key
        // order) so the sealed flag is known before any credential is
        // decoded. The borrowed slices survive the pass (zero-copy).
        let mut p = Parser::new(bytes);
        let n_entries = match p.next().ok()? {
            Item::Map(n) if (1..=2).contains(&n) => n as usize,
            _ => return None,
        };
        let mut sealed = false;
        let mut max_b: Option<&[u8]> = None;
        let mut auth_b: Option<&[u8]> = None;
        let mut creds_b: Option<&[u8]> = None;
        for _ in 0..n_entries {
            let key_num = match p.next().ok()? {
                Item::U(k) => k,
                _ => return None,
            };
            match key_num {
                1 => {
                    let Item::Array(3) = p.next().ok()? else { return None };
                    let Item::B(b) = p.next().ok()? else { return None };
                    max_b = Some(b);
                    let Item::B(b) = p.next().ok()? else { return None };
                    auth_b = Some(b);
                    let Item::B(b) = p.next().ok()? else { return None };
                    creds_b = Some(b);
                }
                snapshot_crypt::SEALED_MARKER_KEY => {
                    match p.next().ok()? {
                        Item::U(u) if u == snapshot_crypt::SEALED_MARKER_VALUE => {}
                        _ => return None,
                    }
                    sealed = true;
                }
                _ => return None,
            }
        }
        if p.remaining() != 0 || max_b.is_none() {
            return None;
        }
        if sealed && key.is_none() {
            // A sealed snapshot without its store key cannot be opened.
            return None;
        }
        let max_creds = {
            let mut q = Parser::new(max_b?);
            match q.next().ok()? {
                // The snapshot's own bound, not the store's capacity: this is
                // a whole-image CBOR document, so the array it decodes into is
                // sized by the chunked slot's payload. Reading `maxCreds` from
                // an image and letting it exceed what the array can hold is how
                // a corrupt header becomes a heapless `push` failure; the
                // `min` is the same refusal as before.
                //
                // It is then raised to the binding bound, so a snapshot written
                // by a build with a different `maxCreds` cannot leave this one
                // advertising a capacity it will not honour on the wire
                // (`DeviceKeystore::fresh`, and AGENTS.md §4).
                Item::U(u) => (u as usize).min(SNAPSHOT_MAX_CREDS),
                _ => return None,
            }
        };
        let (pin_state, cred_counter, device_random, large_blob_array, vault_state, phy, vendor) =
            Self::decode_auth(auth_b?, key, sealed)?;
        let mut creds: HeaplessVec<DeviceCredential, SNAPSHOT_MAX_CREDS> = HeaplessVec::new();
        let mut q = Parser::new(creds_b?);
        let n = match q.next().ok()? {
            Item::Array(n) => n,
            _ => return None,
        };
        for _ in 0..n {
            let Item::B(c) = q.next().ok()? else { return None };
            creds.push(DeviceCredential::decode(c, key, sealed)?).ok()?;
        }
        // US-1012's slack, folded in here so the value is built once (see
        // `load`). `0` from `from_cbor`: nothing granted, nothing spent, the
        // stored bytes as they are.
        let cred_counter = cred_counter.saturating_add(slack);
        for c in &mut creds {
            c.counter = c.counter.saturating_add(slack);
        }
        Some(Self {
            pin_state,
            credentials: creds,
            cred_counter,
            device_random,
            large_blob_array,
            vault_state,
            phy,
            vendor,
            max_creds: max_creds.max(DEVICE_MAX_CREDS.min(SNAPSHOT_MAX_CREDS)),
            dirty: false,
            stored: false,
            // A restore is handed its slack already spent: the first assertion
            // after a power-on writes the counter down, so the in-RAM counter
            // can never run more than one window ahead of the store. Starting
            // the window at 0 instead would let it run a whole extra window
            // past the skip and hand a restored device a value below one the
            // client had already seen.
            counter_unpersisted,
        })
    }

    /// auth map: `{1?: pin, 2?: cred_counter, 3?: large_blob_array,
    /// 4?: vault_state, 5?: device_random}`. US-911: keys 3/4/5 are sealed
    /// under `key` when `sealed`; ANY open failure fails the whole snapshot
    /// (`None` = Corrupt, fatal per FX-440) — the stateless master is never
    /// garbage.
    fn decode_auth(
        bytes: &[u8],
        key: Option<&[u8; 32]>,
        sealed: bool,
    ) -> Option<AuthParts> {
        let mut pin = DevicePinState::default();
        let mut counter = 0u32;
        let mut random = [0u8; 32];
        let mut large_blob_array: Option<HeaplessVec<u8, LARGE_BLOB_MAX>> = None;
        let mut vault_state: Option<[u8; 32]> = None;
        // US-113: absent in every snapshot written before this story, which is
        // why it starts at `PhyConfig::default()` rather than being read from
        // a required key.
        let mut phy = crate::vendorff::PhyConfig::default();
        // US-176: same reason, and the same default. The two halves then take
        // their own failure policies inside `decode_auth` — see the `7` and `8`
        // arms.
        let mut vendor = crate::vendor_state::VendorState::default();
        let mut p = Parser::new(bytes);
        match p.next().ok()? {
            Item::Map(n) => n,
            _ => return None,
        };
        // US-911: one bounded scratch serves every sealed field open.
        let mut scratch = [0u8; MAX_FIELD_PT + FIELD_OVERHEAD];
        for _ in 0.. {
            let key_num = match p.next().ok()? {
                Item::U(k) => k,
                _ => return None,
            };
            match key_num {
                1 => {
                    let Item::Map(n) = p.next().ok()? else { return None };
                    let r = DevicePinState::decode_pairs(&mut p, n);
                    pin = r?;
                }
                2 => match p.next().ok()? {
                    Item::U(u) => counter = u as u32,
                    _ => return None,
                },
                5 => match p.next().ok()? {
                    Item::B(b) if !sealed => {
                        if b.len() != 32 {
                            return None;
                        }
                        random.copy_from_slice(b);
                    }
                    Item::B(blob) => {
                        let n = open_sealed_field(
                            key?,
                            FieldScope::AuthDeviceRandom,
                            &[],
                            blob,
                            &mut scratch,
                        )?;
                        if n != 32 {
                            return None;
                        }
                        random.copy_from_slice(&scratch[..32]);
                    }
                    _ => return None,
                },
                3 => match p.next().ok()? {
                    Item::B(b) if !sealed => {
                        if b.len() > LARGE_BLOB_MAX {
                            return None;
                        }
                        large_blob_array = Some(b.iter().copied().collect());
                    }
                    Item::B(blob) => {
                        let n = open_sealed_field(
                            key?,
                            FieldScope::AuthLargeBlobArray,
                            &[],
                            blob,
                            &mut scratch,
                        )?;
                        if n > LARGE_BLOB_MAX {
                            return None;
                        }
                        large_blob_array = Some(scratch[..n].iter().copied().collect());
                    }
                    _ => return None,
                },
                4 => match p.next().ok()? {
                    Item::B(b) if !sealed => {
                        if b.len() != 32 {
                            return None;
                        }
                        vault_state = Some(<[u8; 32]>::try_from(b).ok()?);
                    }
                    Item::B(blob) => {
                        let n = open_sealed_field(
                            key?,
                            FieldScope::AuthVaultState,
                            &[],
                            blob,
                            &mut scratch,
                        )?;
                        if n != 32 {
                            return None;
                        }
                        vault_state = Some(<[u8; 32]>::try_from(&scratch[..32]).ok()?);
                    }
                    _ => return None,
                },
                6 => {
                    // US-113: `{1: vid_pid, 2: led_gpio, 3: led_brightness,
                    // 4: options, 5: enabled_usb_itf, 6: led_conf}` — absent
                    // keys mean "never written", which is why every field is an
                    // `Option` on the other side.
                    let Item::Map(n) = p.next().ok()? else { return None };
                    for _ in 0..n {
                        let k = match p.next().ok()? {
                            Item::U(k) => k,
                            _ => return None,
                        };
                        // US-117: `led_conf` is the one field whose value is a
                        // byte string, so the value's type is selected *by the
                        // field* rather than demanded of every field. Reading
                        // the key first is what keeps the "an unknown field
                        // refuses the snapshot" rule below intact for a map
                        // that mixes the two shapes. The host decoder in
                        // `keystore.rs` dispatches the same way, and on the same
                        // `vendorff` constants.
                        if k == PHY_FIELD_LED_CONF {
                            let Item::B(bytes) = p.next().ok()? else { return None };
                            let block = <[u8; LedConf::LEN]>::try_from(bytes).ok()?;
                            phy.led_conf = Some(LedConf(block));
                            continue;
                        }
                        // Fields 7 and 8 are the two identity names, the
                        // record's other byte-string members. Dispatched by
                        // field number for the same reason: the value's CBOR
                        // type follows from *which field it is in*, and
                        // demanding an integer of every field would refuse
                        // them.
                        if k == PHY_FIELD_PRODUCT || k == PHY_FIELD_MANUFACTURER {
                            let Item::B(bytes) = p.next().ok()? else { return None };
                            let name = IdentityName::new(
                                core::str::from_utf8(bytes).ok()?,
                            )?;
                            if k == PHY_FIELD_PRODUCT {
                                phy.product = Some(name);
                            } else {
                                phy.manufacturer = Some(name);
                            }
                            continue;
                        }
                        let v = match p.next().ok()? {
                            Item::U(u) => u,
                            // A non-integer in a field that is an integer:
                            // refuse the snapshot rather than substitute a
                            // default, which would look like a successful
                            // load of a configuration nobody wrote.
                            _ => return None,
                        };
                        match (k, v) {
                            // US-113 review: this guard was missing here and
                            // present in the host decoder, so a 33-bit
                            // `vid_pid` was refused by one keystore and
                            // silently truncated by the other — the same
                            // bytes, two different hardware configs. Refuse
                            // on both: truncating a VID/PID pair would
                            // produce a device that enumerates as an id
                            // nobody chose, and the sibling arm twenty lines
                            // below already takes the refuse path.
                            (1, u) if u <= u32::MAX as u64 => phy.vid_pid = Some(u as u32),
                            (2, u) if u <= u8::MAX as u64 => phy.led_gpio = Some(u as u8),
                            (3, u) if u <= u8::MAX as u64 => phy.led_brightness = Some(u as u8),
                            (4, u) if u <= u16::MAX as u64 => phy.options = Some(u as u16),
                            // US-117: the `DEV_CONF` enabled-interface mask,
                            // bounded exactly as the host decoder bounds it and
                            // named with the same `vendorff` constant, so the
                            // two decoders cannot drift on the number. See
                            // `tests/vendor41.rs::key6_round_trips_through_both_keystores`.
                            (PHY_FIELD_ENABLED_USB_ITF, u) if u <= u16::MAX as u64 => {
                                phy.enabled_usb_itf = Some(u as u16)
                            }
                            // An out-of-range stored value: same reasoning as
                            // above, one level up.
                            _ => return None,
                        }
                    }
                }
                7 => {
                    // US-176, the **sealed** half. A field that fails to open
                    // is fatal to the whole snapshot, and that is the existing
                    // US-911 auth-level rule rather than a new one: this is the
                    // master seed, the soft-lock key, the org attestation
                    // scalar and the audit checkpoint key, and a wallet that
                    // comes up with a *default* master would answer
                    // `has_seed = false` and then `EXPORT` a set of bytes
                    // that are not the ones the holder wrote down.
                    let Item::B(blob) = p.next().ok()? else { return None };
                    vendor.secret =
                        crate::vendor_state::VendorState::decode_secret(blob, key, sealed).ok()?;
                }
                8 => {
                    // US-176, the **plaintext** half. The opposite policy, and
                    // the asymmetry is the design: nothing here is secret, and
                    // a token carrying twelve enrolled credentials must not
                    // fail to boot over a corrupt audit ring. A blob this
                    // firmware would not have written decodes to the
                    // documented default, so the device comes up with an empty
                    // journal and `ATT_STATE` reporting `installed = false` —
                    // true, because the credential can no longer be produced.
                    //
                    // A key 8 whose value is **not** a byte string degrades the
                    // same way a malformed one does, rather than failing the
                    // snapshot the way auth key 6's "not a map" does. That is
                    // the one place this decoder's two halves disagree about
                    // what a wrong CBOR *type* means, and it is deliberate: key
                    // 6 carries an operator's hardware configuration whose loss
                    // nobody would notice until the device came up wrong, while
                    // key 8 carries an opt-in journal and a certificate chain
                    // whose loss costs two features. The host decoder takes the
                    // same view (it skips a non-byte-string key 8), and
                    // `tests/vendor41_state.rs::a_mistyped_key8_degrades_on_both_stacks`
                    // is what holds the two to it.
                    if let Ok(Item::B(blob)) = p.next() {
                        vendor.public = crate::vendor_state::VendorState::decode_public(blob);
                    }
                }
                _ => {
                    p.skip().ok()?;
                }
            }
            if p.remaining() == 0 {
                return Some((pin, counter, random, large_blob_array, vault_state, phy, vendor));
            }
        }
        None
    }

    /// Serialize in the host snapshot format. US-911: `key` = the store key
    /// the sensitive fields are sealed under (`None` = legacy plaintext).
    ///
    /// `#[inline(never)]` for the same reason `boot_in_place` carries it
    /// (US-939): this function's two scratch buffers are on the command path's
    /// stack, and inlining them into an Embassy poll would fold ~12 KiB of
    /// encoding scratch into the async-main frame the
    /// `check_async_frame.py` gate bounds.
    #[inline(never)]
    pub fn to_cbor<const N: usize>(
        &self,
        key: Option<&[u8; 32]>,
        out: &mut HeaplessVec<u8, N>,
    ) -> Result<(), CborError> {
        out.clear();
        let mut auth: HeaplessVec<u8, AUTH_SCRATCH> = HeaplessVec::new();
        no_heap::push_map_header(
            &mut auth,
            // US-113: key 6 is emitted only when something was written, so a
            // device that has never seen a `0xFF` keeps byte-identical
            // snapshots to before this story. US-176 keys 7/8 follow the same
            // rule, and for the same reason: a device that has never seen a
            // `0x41` must keep writing exactly the bytes it wrote before.
            3 + if self.large_blob_array.is_some() { 1 } else { 0 }
                + if self.vault_state.is_some() { 1 } else { 0 }
                + if self.phy == crate::vendorff::PhyConfig::default() { 0 } else { 1 }
                + if self.vendor.secret.is_empty() { 0 } else { 1 }
                + if self.vendor.public.is_empty() { 0 } else { 1 },
        )?;
        no_heap::push_uint(&mut auth, 1)?;
        self.pin_state.encode_into(&mut auth)?;
        no_heap::push_uint(&mut auth, 2)?;
        no_heap::push_uint(&mut auth, self.cred_counter as u64)?;
        if let Some(arr) = &self.large_blob_array {
            no_heap::push_uint(&mut auth, 3)?;
            seal_push(key, FieldScope::AuthLargeBlobArray, &[], arr, &mut auth)?;
        }
        if let Some(v) = &self.vault_state {
            no_heap::push_uint(&mut auth, 4)?;
            seal_push(key, FieldScope::AuthVaultState, &[], v, &mut auth)?;
        }
        no_heap::push_uint(&mut auth, 5)?;
        seal_push(key, FieldScope::AuthDeviceRandom, &[], &self.device_random, &mut auth)?;
        if self.phy != crate::vendorff::PhyConfig::default() {
            no_heap::push_uint(&mut auth, 6)?;
            let phy = self.phy;
            no_heap::push_map_header(&mut auth, phy.field_count())?;
            if let Some(v) = phy.vid_pid {
                no_heap::push_uint(&mut auth, 1)?;
                no_heap::push_uint(&mut auth, v as u64)?;
            }
            if let Some(v) = phy.led_gpio {
                no_heap::push_uint(&mut auth, 2)?;
                no_heap::push_uint(&mut auth, v as u64)?;
            }
            if let Some(v) = phy.led_brightness {
                no_heap::push_uint(&mut auth, 3)?;
                no_heap::push_uint(&mut auth, v as u64)?;
            }
            if let Some(v) = phy.options {
                no_heap::push_uint(&mut auth, 4)?;
                no_heap::push_uint(&mut auth, v as u64)?;
            }
            if let Some(v) = phy.enabled_usb_itf {
                no_heap::push_uint(&mut auth, PHY_FIELD_ENABLED_USB_ITF)?;
                no_heap::push_uint(&mut auth, v as u64)?;
            }
            if let Some(block) = phy.led_conf {
                // US-117: the record's one byte-string field. The length is
                // `LedConf::LEN`, so the head is a single-byte CBOR major-2
                // length (0x50 | 17 = 0x61) and the content follows verbatim —
                // `push_bstr` is unusable here for the same reason
                // `write_config_read_response` cannot use it: it takes the
                // content it is describing.
                no_heap::push_uint(&mut auth, PHY_FIELD_LED_CONF)?;
                no_heap::push_head(&mut auth, 2, LedConf::LEN as u64)?;
                auth.extend_from_slice(&block.0).map_err(|_| CborError::BufferFull)?;
            }
            // The two identity names, emitted after the integer fields and in
            // ascending key order. The length is a CBOR byte-string head over
            // the stored bytes only — no terminator — which is exactly what
            // the decoder above hands to `IdentityName::new`.
            for (key, name) in [
                (PHY_FIELD_PRODUCT, phy.product),
                (PHY_FIELD_MANUFACTURER, phy.manufacturer),
            ] {
                if let Some(name) = name {
                    no_heap::push_uint(&mut auth, key)?;
                    no_heap::push_head(&mut auth, 2, name.as_bytes().len() as u64)?;
                    auth.extend_from_slice(name.as_bytes()).map_err(|_| CborError::BufferFull)?;
                }
            }
        }
        // US-176: the RS-Key `0x41` state, two keys and two policies. The
        // sealed half is one AEAD field covering all four secrets together, so
        // a snapshot can never hold a new soft-lock key beside the old seed;
        // the plaintext half is the journal and the org attestation chain.
        self.vendor.encode_secret(key, &mut auth)?;
        self.vendor.encode_public(&mut auth)?;

        let mut creds: HeaplessVec<u8, 8192> = HeaplessVec::new();
        no_heap::push_array_header(&mut creds, self.credentials.len())?;
        for c in &self.credentials {
            c.encode(key, &mut creds)?;
        }

        no_heap::push_map_header(out, if key.is_some() { 2 } else { 1 })?;
        no_heap::push_uint(out, 1)?;
        no_heap::push_array_header(out, 3)?;
        {
            let (ub, un) = no_heap::uint_bytes(self.max_creds as u64);
            no_heap::push_bstr(out, &ub[..un])?;
        }
        no_heap::push_bstr(out, &auth)?;
        no_heap::push_bstr(out, &creds)?;
        if key.is_some() {
            // US-911: the sealed-format marker (top-level key 2 before key 1
            // would be uncanonical — the marker is appended last; the
            // decoder handles either order).
            no_heap::push_uint(out, snapshot_crypt::SEALED_MARKER_KEY)?;
            no_heap::push_uint(out, snapshot_crypt::SEALED_MARKER_VALUE)?;
        }
        Ok(())
    }

    /// Persist the snapshot into the chunked `fido.keystore.v1` slot.
    /// US-911: the sensitive fields are sealed under the store's AEAD key
    /// ([`SecureStore::store_key`]); an unkeyed store (pre-US-915 shape)
    /// keeps the legacy plaintext snapshot.
    pub fn persist(&self, store: &mut dyn SecureStore) -> Result<(), SecureStoreError> {
        let key = store.store_key();
        let mut buf: HeaplessVec<u8, 8448> = HeaplessVec::new();
        self.to_cbor(key.as_ref(), &mut buf)
            .map_err(|_| SecureStoreError::ValueTooLong)?;
        chunked::write_chunked(store, KEYSTORE_SLOT, &buf)
    }

    /// Dirty-gated persistence (US-388 hook): `true` = the snapshot changed
    /// and was re-persisted; the caller must then flash the secure partition.
    /// A failed store write keeps `dirty` set (US-421 failure contract — the
    /// change retries on the next persist run, it is never silently dropped).
    ///
    /// US-1011: both success arms close the counter's batch window. This is
    /// the gate the batched counter deliberately does **not** set `dirty` for,
    /// so a counter-only window costs no write at all — but any write that
    /// does happen (here, or through a transactional helper) carries the
    /// in-RAM counters with it and restarts the window from zero.
    pub fn persist_if_dirty(&mut self, store: &mut dyn SecureStore) -> bool {
        if !self.dirty {
            return false;
        }
        // SOAK-FINDING-1: a transactional mutation already wrote this
        // snapshot into the store. Report it so the caller programs the
        // partition image, but do NOT rewrite the snapshot here — the
        // rewrite would transiently hold old+new chunked generations again
        // and fail on a store at its slot bound (re-latching the gate).
        if self.stored {
            self.stored = false;
            self.dirty = false;
            self.counter_unpersisted = 0;
            return true;
        }
        let wrote = self.persist(store).is_ok();
        if wrote {
            self.dirty = false;
            self.counter_unpersisted = 0;
        }
        wrote
    }

    // ---- model operations (mirror the host `Keystore` trait semantics) ----

    #[allow(clippy::result_unit_err)] // heapless push failure has a single mode
    pub fn store_credential(&mut self, cred: DeviceCredential) -> Result<(), ()> {
        if let Some(slot) = self
            .credentials
            .iter_mut()
            .position(|c| c.credential_id == cred.credential_id)
        {
            self.credentials[slot] = cred;
        } else {
            self.credentials.push(cred).map_err(|_| ())?;
        }
        self.dirty = true;
        Ok(())
    }

    /// Transactional credential store (SOAK-FINDING-1, S-731-2): store the
    /// credential only if the resulting snapshot still persists into
    /// `store` — serialize-ahead against the actual store. On persist
    /// failure the mutation is rolled back and the dirty flag restored, so
    /// no un-persistable dirty state survives (the soak wedge: an
    /// un-persistable snapshot latched `dirty` and the US-425/427
    /// durable-before-ack gate answered every command — reads included —
    /// with CTAPHID ERROR/INVALID_COMMAND). `Ok(())` = applied and durable
    /// in the store; `dirty` stays set so the caller's persist gate still
    /// programs the secure-partition image before the reply.
    #[allow(clippy::result_unit_err)] // heapless push failure has a single mode
    pub fn store_credential_checked(
        &mut self,
        cred: DeviceCredential,
        store: &mut dyn SecureStore,
    ) -> Result<(), ()> {
        let dirty_before = self.dirty;
        // Replace-in-place keeps the slot count; remember the previous entry
        // so a failed persist can restore it byte-for-byte.
        match self
            .credentials
            .iter()
            .position(|c| c.credential_id == cred.credential_id)
        {
            Some(slot) => {
                let old = core::mem::replace(&mut self.credentials[slot], cred);
                self.dirty = true;
                if self.persist(store).is_ok() {
                    self.note_durable_write();
                    return Ok(());
                }
                self.credentials[slot] = old;
            }
            None => {
                self.credentials.push(cred).map_err(|_| ())?;
                self.dirty = true;
                if self.persist(store).is_ok() {
                    self.note_durable_write();
                    return Ok(());
                }
                self.credentials.pop();
            }
        }
        self.dirty = dirty_before;
        Err(())
    }

    /// Transactional grow-mutation core (SOAK-FINDING-1): apply `f`, then
    /// make the resulting snapshot durable in `store`; on persist failure
    /// run `undo` and restore the dirty flag. With `store = None` (the
    /// dispatcher bridge path, whose persist gate runs after
    /// `App::process`) only `f` runs — the legacy mutate-and-mark-dirty
    /// behavior. `true` = applied; with a bound store the snapshot is
    /// already durable in it and the caller's persist gate still programs
    /// the partition image before the reply.
    pub(crate) fn grow_checked(
        &mut self,
        store: Option<&mut dyn SecureStore>,
        f: impl FnOnce(&mut Self),
        undo: impl FnOnce(&mut Self),
    ) -> bool {
        let Some(store) = store else {
            f(self);
            return true;
        };
        let dirty_before = self.dirty;
        f(self);
        if self.persist(store).is_ok() {
            self.note_durable_write();
            return true;
        }
        undo(self);
        self.dirty = dirty_before;
        false
    }

    /// US-1011: record that a transactional helper has just written the whole
    /// snapshot into the store. The store now holds **exactly** this snapshot,
    /// which is the `stored` flag's documented invariant, and it also holds
    /// every counter value in it — so the counter's batch window is closed and
    /// the next [`COUNTER_PERSIST_INTERVAL`] bumps start a fresh one.
    ///
    /// Every site that persists and then sets `stored = true` goes through
    /// here. A site that persisted and forgot to close the window would let
    /// the counter run `2 x COUNTER_PERSIST_INTERVAL` ahead of the store
    /// between two writes, which is exactly the un-bounded regression window
    /// US-1012 has to rule out.
    fn note_durable_write(&mut self) {
        self.stored = true;
        self.counter_unpersisted = 0;
    }

    pub fn get_credential(&self, id: &[u8]) -> Option<&DeviceCredential> {
        self.credentials.iter().find(|c| c.credential_id.as_slice() == id)
    }

    pub fn get_credential_mut(&mut self, id: &[u8]) -> Option<&mut DeviceCredential> {
        self.credentials
            .iter_mut()
            .find(|c| c.credential_id.as_slice() == id)
    }

    /// Transactional signature-counter bump (S-731-2 review, round 2),
    /// batched (US-1011): increment the credential's counter, and make the
    /// snapshot durable in the actual store **once per
    /// [`COUNTER_PERSIST_INTERVAL`] bumps** instead of on every one.
    ///
    /// # The reply now signs a counter that is not yet durable
    ///
    /// This is a deliberate weakening of the previous durable-before-ack
    /// behaviour, and it is the whole point of the story: a counter bump
    /// rewrote the *entire* keystore image, and `docs/erase-budget.md`
    /// measures that rewrite at 8 sector erasures, so a high-traffic
    /// credential exhausted the flash long before the device was retired.
    /// Between rewrites the reply signs a value that is in RAM only.
    ///
    /// It is legal because US-1012 guarantees such a value can never be seen
    /// twice: the restore path starts a whole window above the durable image,
    /// so a power loss inside the window makes the counter skip **forward**,
    /// never repeat. `tests/counter_monotonic.rs` pins that at every point of
    /// the window. **A reader who assumes the signed counter is durable is
    /// wrong here** — that assumption was true before US-1011 and is not true
    /// after it.
    ///
    /// On persist failure the bump REVERTS (the pre-US-1011 behaviour, kept
    /// whole): the reply signs the durable counter and `dirty` is restored,
    /// so a failing store never latches the durable-before-ack gate. With
    /// `store = None` (dispatcher bridge path) the bump is the legacy
    /// mutate-and-mark-dirty and the caller's gate writes it. Returns the
    /// counter the reply must use, or `None` if the credential is unknown.
    pub(crate) fn bump_credential_counter_checked(
        &mut self,
        id: &[u8],
        store: Option<&mut dyn SecureStore>,
    ) -> Option<u32> {
        let next = {
            let c = self.get_credential_mut(id)?;
            c.counter = c.counter.wrapping_add(1);
            c.counter
        };
        let Some(store) = store else {
            self.cred_counter = self.cred_counter.max(next);
            self.dirty = true;
            return Some(next);
        };
        let dirty_before = self.dirty;
        let window_before = self.counter_unpersisted;
        self.counter_unpersisted = self.counter_unpersisted.saturating_add(1);
        if self.counter_unpersisted >= COUNTER_PERSIST_INTERVAL {
            self.dirty = true;
            if self.persist(store).is_ok() {
                self.note_durable_write();
                // Ordering note (pre-existing, widened by US-1011): this runs
                // *after* `persist()`, so on this path the durable
                // `cred_counter` written into the snapshot is the value from
                // *before* the max, while the in-RAM one is the max. The two
                // therefore diverge for up to one window until the next
                // window-closing write, where the max is applied again and
                // they agree.
                //
                // **This is not a clone-detection hazard.** `cred_counter` is
                // the keystore-wide counter that *stateless* U2F credentials
                // authenticate against; the per-credential counter this
                // function just bumped lives in `c.counter` and is what a
                // CTAP2 getAssertion for this credential compares. FIDO
                // compares signCount per credential, so a keystore-wide
                // counter that lags cannot make a credential's own counter
                // repeat. It is recorded here because the staleness window grew
                // from 0 to up to `COUNTER_PERSIST_INTERVAL` and the asymmetry
                // deserves to be deliberate rather than discovered. Moving the
                // max above the `persist()` would fix the lag and re-open the
                // ordering the US-714 CRITICAL comment protects on the
                // sibling function, so it is left alone.
                self.cred_counter = self.cred_counter.max(next);
                return Some(next);
            }
            // Revert: the reply signs the durable (pre-bump) counter.
            if let Some(c) = self.get_credential_mut(id) {
                c.counter = next.wrapping_sub(1);
            }
            self.dirty = dirty_before;
            self.counter_unpersisted = window_before;
            return Some(next.wrapping_sub(1));
        }
        // Batched: the window is not full, so this bump rides in RAM until a
        // later one closes it. The store does NOT hold this snapshot, so the
        // `stored` flag must be cleared — the flag's documented invariant is
        // "`stored == true` implies the store holds exactly this snapshot",
        // and leaving it set here would let the next command's growth
        // mutation (a credential created, deleted or grown) skip its own
        // write. `dirty` is deliberately left alone: the counter-only window
        // is not a reason to program the secure partition.
        self.stored = false;
        self.cred_counter = self.cred_counter.max(next);
        Some(next)
    }

    /// US-714: global signature-counter bump for **stateless** U2F
    /// credentials (C `get_sign_counter` / `ef_counter` parity): a stateless
    /// credential has no stored per-credential counter, so the keystore-wide
    /// counter is bumped. On persist failure the bump reverts and the durable
    /// (pre-bump) counter is returned (SOAK-FINDING-1 discipline, same as
    /// [`DeviceKeystore::bump_credential_counter_checked`]).
    ///
    /// # It batches too — deliberately, not by omission (US-1011)
    ///
    /// The story names `cred_counter`, and this sibling is in scope anyway,
    /// for three reasons a reader should be able to check:
    ///
    /// 1. **Same cost.** A stateless U2F authenticate used to rewrite the
    ///    whole keystore image for one counter, exactly as the per-credential
    ///    path did. Batching one and not the other would leave the CTAP1
    ///    wear hole open and make it look deliberate.
    /// 2. **Same role.** This is the keystore-wide signature counter, with the
    ///    same clone-detection duty and the same "never repeat" requirement,
    ///    so US-1012's restore slack covers it on the same terms.
    /// 3. **Same state.** Both bumps share one window
    ///    ([`DeviceKeystore::counter_unpersisted`]), so a mixed workload —
    ///    CTAP2 assertions and CTAP1 authenticates interleaved — still costs
    ///    one rewrite per [`COUNTER_PERSIST_INTERVAL`] bumps in total, not one
    ///    per counter.
    ///
    /// The `mutate before persist` ordering the US-714 review marked
    /// CRITICAL is preserved verbatim: `to_cbor` serializes
    /// `self.cred_counter`, so on the rewrite path the assignment must
    /// precede `persist()`.
    pub(crate) fn bump_global_counter_checked(
        &mut self,
        store: Option<&mut dyn SecureStore>,
    ) -> u32 {
        let next = self.cred_counter.wrapping_add(1);
        let Some(store) = store else {
            self.cred_counter = next;
            self.dirty = true;
            return next;
        };
        let dirty_before = self.dirty;
        let window_before = self.counter_unpersisted;
        // Mutate BEFORE persisting (review CRITICAL): `to_cbor` serializes
        // `self.cred_counter`, so the assignment must precede `persist()` or
        // the durable snapshot keeps the old value while the reply signs
        // `next` — a counter regression and value reuse after reboot.
        let old = self.cred_counter;
        self.cred_counter = next;
        self.counter_unpersisted = self.counter_unpersisted.saturating_add(1);
        if self.counter_unpersisted >= COUNTER_PERSIST_INTERVAL {
            self.dirty = true;
            if self.persist(store).is_ok() {
                self.note_durable_write();
                return next;
            }
            // Revert: the reply signs the durable (pre-bump) counter.
            self.cred_counter = old;
            self.dirty = dirty_before;
            self.counter_unpersisted = window_before;
            return old;
        }
        // Batched: see `bump_credential_counter_checked` for why `stored` is
        // cleared and `dirty` is left alone.
        self.stored = false;
        next
    }

    #[allow(clippy::result_unit_err)]
    pub fn delete_credential(&mut self, id: &[u8]) -> Result<(), ()> {
        let pos = self
            .credentials
            .iter()
            .position(|c| c.credential_id.as_slice() == id)
            .ok_or(())?;
        self.credentials.remove(pos);
        self.dirty = true;
        Ok(())
    }

    pub fn cred_count(&self) -> usize {
        self.credentials.len()
    }

    pub fn max_remaining_creds(&self) -> usize {
        self.max_creds.saturating_sub(self.credentials.len())
    }

    /// The per-device secret, readable.
    ///
    /// # Why this exists (US-1005 fix)
    ///
    /// Not to be *used* — the field is deliberately otherwise private, and
    /// every in-crate consumer reaches it through a named derivation
    /// ([`stateless::master_from_device_random`](crate::stateless::master_from_device_random))
    /// rather than by reading bytes. It exists because after the
    /// `device_random` draws were made fallible, the property that fix
    /// establishes — *a refused draw does not replace the secret* — was
    /// **unobservable from outside this crate**, which is a large part of why
    /// the original silent-zero bug survived: the only guard was a
    /// `debug_assert!` that release builds do not compile, and no
    /// integration test could have failed on the behaviour.
    ///
    /// `tests/device_random_fallible.rs` is that test. It is read-only, it
    /// grants no capability (a caller holding a `DeviceKeystore` is already
    /// inside the trust boundary — it can persist, reset and derive), and it
    /// is what turns the fix from an assertion into a checked one.
    pub fn device_random(&self) -> &[u8; 32] {
        &self.device_random
    }

    /// Full reset from a caller-supplied TRNG-derived seed (the device
    /// command path draws from the boot-time pool, S-701-4).
    pub fn reset_from_seed(&mut self, seed: [u8; 32]) {
        self.pin_state = DevicePinState::default();
        self.credentials.clear();
        self.cred_counter = 0;
        self.device_random = seed;
        self.large_blob_array = None;
        self.vault_state = None;
        self.dirty = true;
    }

    /// Full reset (CTAP2 Reset): fresh PIN state and empty credential table.
    ///
    /// # Why this is `Result` (US-1005 fix)
    ///
    /// The same all-zeros hazard as [`fresh`](Self::fresh), and the same
    /// reason: a refused infallible draw leaves a zero-initialised buffer
    /// looking like output, and this one *replaces* a good `device_random`
    /// with it. A reset that wiped the credential table and then installed a
    /// predictable stateless master would leave the device looking factory-
    /// reset while every U2F handle it had ever issued became derivable.
    ///
    /// A refusal leaves the keystore **untouched** — the credential table is
    /// not wiped and the previous `device_random` stays — so the caller can
    /// answer an error rather than report a successful reset.
    ///
    /// Note the contrast with [`reset_from_seed`](Self::reset_from_seed),
    /// which is the path the device request handler actually takes (via a
    /// pool draw it can already refuse) and which cannot fail this way: it is
    /// handed bytes, it does not draw them.
    pub fn reset<R: fapico2_platform::trng::Trng>(
        &mut self,
        trng: &mut R,
    ) -> Result<(), fapico2_platform::trng::TrngError> {
        let mut device_random = [0u8; 32];
        trng.try_random_bytes(&mut device_random)?;
        self.pin_state = DevicePinState::default();
        self.credentials.clear();
        self.cred_counter = 0;
        self.device_random = device_random;
        self.dirty = true;
        Ok(())
    }
}


#[cfg(test)]
mod us113_tests {
    //! The key-6 (`phy`) decoder arms, in the place the private decoder lives.
    //!
    //! These cannot be integration tests: `AuthState::from_cbor` is private,
    //! and the snapshot *envelope* around it is a different format on each
    //! side, so a shared test would have to re-implement two envelopes to
    //! reach one function. The point of putting them here is that the pair of
    //! them — this one and its twin in `keystore.rs` — is the cross-path
    //! agreement check: the same forged bytes must be refused identically by
    //! the device and the host decoder.

    use super::*;
    use crate::cbor::no_heap as nh;

    /// `{1: <v>, 2: <gpio>}` — the auth map's key-6 value, with `vid_pid`
    /// set to whatever `vid` is. Built by hand because no encoder can emit an
    /// out-of-range value, which is the whole point.
    fn key6_map(vid: u64) -> heapless::Vec<u8, 32> {
        let mut b = heapless::Vec::new();
        nh::push_map_header(&mut b, 1).unwrap();
        nh::push_uint(&mut b, 1).unwrap();
        nh::push_uint(&mut b, vid).unwrap();
        b
    }

    /// US-113 review: a `vid_pid` wider than `u32` must be **refused** by
    /// this decoder, and the twin test in `keystore.rs` refuses the same
    /// bytes. Truncating here instead would make the device boot as a
    /// VID/PID the client never asked for — the failure mode R-5 names — so
    /// refuse, and refuse the whole snapshot, as every other out-of-range
    /// auth field does.
    #[test]
    fn key6_vidpid_wider_than_u32_is_refused() {
        let ks = DeviceKeystore::fresh(&mut fapico2_platform::trng::HostTrng::new()).expect("host TRNG");
        let mut snap = heapless::Vec::<u8, 2048>::new();
        ks.to_cbor(None, &mut snap).expect("encode a well-formed snapshot");
        // Sanity: the same helper's output IS accepted when in range, so a
        // refusal below is about the width and not about the map shape.
        let ok = DeviceKeystore::from_cbor(&snap, None).expect("the encoder's own output must load");
        assert_eq!(ok.phy, crate::vendorff::PhyConfig::default());

        // Rebuild the auth map with a 33-bit vid_pid by hand-wrapping the
        // decoder's own entry point through a minimal snapshot.
        let auth = {
            let mut a: heapless::Vec<u8, 64> = heapless::Vec::new();
            nh::push_map_header(&mut a, 1).unwrap();
            nh::push_uint(&mut a, 6).unwrap();
            a.extend_from_slice(key6_map(0x1_0000_0000).as_slice()).unwrap();
            a
        };
        let out = DeviceKeystore::decode_auth(auth.as_slice(), None, false);
        assert!(
            out.is_none(),
            "a 33-bit stored vid_pid must fail the snapshot outright, not be \
             truncated to a valid-looking 32-bit value. Its twin in \
             `keystore.rs` refuses the same bytes; if one of the two ever \
             starts truncating, the device and the emulator would load the \
             same snapshot into different hardware configurations"
        );
    }
}

#[cfg(test)]
mod us1011_batched_path_tests {
    //! The batched (window not yet full) path's effect on `stored`.
    //!
    //! These live here, and not in `tests/counter_batching.rs`, because
    //! `stored` is private and because the property is a *unit* property: the
    //! integration test can only reach it with `stored == false`, which is the
    //! state the batched path leaves it in. Pinning the clear needs the
    //! precondition `stored == true` at bump time — unreachable through the
    //! product today, since `firmware/src/tasks.rs` runs the persist gate after
    //! every HID command and `persist_if_dirty`'s `stored` arm clears the flag
    //! on its way out.
    //!
    //! It is pinned anyway, as defence in depth. The failure it guards is
    //! "a delete is a lie": `persist_if_dirty` *skips* the rewrite when
    //! `stored == true`, so a batched counter bump that left the flag set would
    //! make the next command's growth mutation (a credential created, deleted
    //! or grown) look already-durable, and the mutation would never reach the
    //! store.
    //!
    //! The two integration tests that already exist —
    //! `counter_batching.rs::credential_deleted_inside_a_batch_window_is_durable`
    //! and its created-credential mirror — pin that failure *end to end*, from
    //! `stored == false`. Neither of them can see the clear itself, and
    //! deleting the two `self.stored = false` lines leaves every fido test
    //! green.

    use super::*;
    use fapico2_platform::secure_store::rp2350::Rp2350SecureStore;

    /// A keystore holding one credential, in the state a transactional
    /// persist leaves it in: the store holds this snapshot, so `stored` is
    /// `true` and the persist gate is entitled to skip the next rewrite.
    fn stored_snapshot() -> DeviceKeystore {
        let mut ks = DeviceKeystore::fresh(&mut fapico2_platform::trng::HostTrng::new()).expect("host TRNG");
        let mut id = heapless::Vec::<u8, 64>::new();
        id.extend_from_slice(&[0x5Au8; 32]).unwrap();
        let cred = DeviceCredential {
            credential_id: id,
            public_key: DeviceCoseKey::es256([1; 32], [2; 32]),
            private_key: [0x0B; 32],
            rp_id_hash: [0xA0; 32],
            rp_id: heapless::Vec::new(),
            user_handle: heapless::Vec::new(),
            user_name: heapless::Vec::new(),
            user_display_name: heapless::Vec::new(),
            cred_protect: 0,
            large_blob_key: None,
            hmac_secret: heapless::Vec::new(),
            cred_blob: heapless::Vec::new(),
            third_party_payment: false,
            pin_complexity_policy: false,
            resident: false,
            algorithm: -7,
            counter: 0,
            revoked: false,
            expires_at: None,
        };
        ks.store_credential(cred).unwrap();
        ks
    }

    /// US-1011: a bump that rides in an open window does not reach the store,
    /// so it must **clear** `stored` — the store does not hold this snapshot,
    /// and the flag's documented invariant is "`stored == true` implies the
    /// store holds EXACTLY this snapshot".
    ///
    /// Paired with `a_batched_bump_leaves_dirty_alone`: the clear is the
    /// required half, and `dirty` staying untouched is the wear saving.
    #[test]
    fn a_batched_credential_bump_clears_stored() {
        let mut store = Rp2350SecureStore::new();
        let mut ks = stored_snapshot();
        assert!(
            ks.persist(&mut store).is_ok(),
            "the fixture snapshot must be encodable"
        );
        // The precondition this path must survive: the flag is set, so a
        // batched bump that failed to clear it would be invisible from the
        // outside.
        ks.stored = true;

        let signed = ks
            .bump_credential_counter_checked(&[0x5Au8; 32], Some(&mut store))
            .expect("the fixture credential is present");
        assert_eq!(signed, 1, "the first bump signs 1");
        assert_eq!(ks.counter_unpersisted, 1, "the window is open, not closed");
        assert!(
            !ks.stored,
            "a batched counter bump must clear `stored`: the store does NOT hold \
             this snapshot, and leaving the flag set would let the next \
             command's growth mutation (a credential created, deleted or grown) \
             be skipped by the persist gate as 'already durable' — delete \
             becomes a lie that only a reboot can undo"
        );
    }

    /// The same, for the keystore-wide counter a stateless U2F credential
    /// authenticates against (`bump_global_counter_checked`). Pinned
    /// separately because the two helpers are separate functions with
    /// separate `self.stored = false` lines, and a reviewer deleting one of
    /// them must see a failure.
    #[test]
    fn a_batched_global_bump_clears_stored() {
        let mut store = Rp2350SecureStore::new();
        let mut ks = stored_snapshot();
        assert!(
            ks.persist(&mut store).is_ok(),
            "the fixture snapshot must be encodable"
        );
        ks.stored = true;

        let signed = ks.bump_global_counter_checked(Some(&mut store));
        assert_eq!(signed, 1, "the first bump signs 1");
        assert_eq!(ks.counter_unpersisted, 1, "the window is open, not closed");
        assert!(
            !ks.stored,
            "the batched global bump must clear `stored` for the same reason \
             the per-credential one does: the stateless counter is not in the \
             store yet, so the next growth mutation must not be skipped"
        );
    }

    /// The mirror of the two above, and the reason the clear is not simply
    /// "always clear": a bump that DOES close the window writes the snapshot,
    /// so `stored` must be left `true`. Without this, the two clears would
    /// pass for an implementation that cleared the flag unconditionally.
    #[test]
    fn a_window_closing_bump_leaves_stored_set() {
        let mut store = Rp2350SecureStore::new();
        let mut ks = stored_snapshot();
        // A fresh keystore starts with an empty window, so drive it to the
        // last bump before the window closes: one short of the interval.
        ks.counter_unpersisted = COUNTER_PERSIST_INTERVAL - 1;
        ks.stored = true;

        let signed = ks
            .bump_credential_counter_checked(&[0x5Au8; 32], Some(&mut store))
            .expect("the fixture credential is present");
        // The fixture credential's own counter starts at 0 and only this one
        // bump reaches it, so the reply signs 1 — the *window* is what is
        // being driven, not the counter.
        assert_eq!(signed, 1, "the window-closing bump signs the bumped value");
        assert_eq!(
            ks.counter_unpersisted,
            0,
            "the window-closing write resets the window"
        );
        assert!(
            ks.stored,
            "the window-closing bump DID write the snapshot, so `stored` must \
             be set: the store holds exactly this snapshot, and clearing the \
             flag here would cost a redundant rewrite on the next command"
        );
    }

    /// `dirty` is the gate's only instruction to program the secure
    /// partition, and a counter that has not been written is not a reason to
    /// program it. So the batched path leaves `dirty` alone — the wear saving
    /// US-1011 exists for. Pinned next to the `stored` clear because the two
    /// are the same decision, and an edit that "helpfully" marked the snapshot
    /// dirty here would silently undo the whole story.
    #[test]
    fn a_batched_bump_leaves_dirty_alone() {
        let mut store = Rp2350SecureStore::new();
        let mut ks = stored_snapshot();
        assert!(
            ks.persist(&mut store).is_ok(),
            "the fixture snapshot must be encodable"
        );
        ks.dirty = false;

        let _ = ks.bump_credential_counter_checked(&[0x5Au8; 32], Some(&mut store));
        assert!(
            !ks.dirty,
            "a batched counter bump must not mark the snapshot dirty: that \
             flag is the persist gate's only instruction to write, and a \
             counter that has not been written must not look like one that has"
        );
        let _ = ks.bump_global_counter_checked(Some(&mut store));
        assert!(
            !ks.dirty,
            "same for the global counter: marking dirty here would restore the \
             one-write-per-assertion cost US-1011 removed"
        );
    }
}
