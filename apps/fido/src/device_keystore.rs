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
//!   *snapshot codec* will encode or decode. It stays 12, and the reason it was
//!   12 was never a capacity: the snapshot's CBOR is a whole-image format whose
//!   length is bounded by `chunked::MAX_LOGICAL_LEN`, and **5,952 bytes is a
//!   single-generation figure that is not reachable on the device** — see
//!   [`SNAPSHOT_MAX_CREDS`]'s own comment and `chunked::MAX_LOGICAL_LEN`. It is
//!   a **format** bound, not a store bound, and it will not move when the store
//!   does.
//!
//! US-1564 corrected what used to sit here. The previous text read: *"It stays
//! 12, because the snapshot's CBOR is a whole-image format and
//! `chunked::MAX_PARTS * PART_PAYLOAD_MAX` is 5,952 bytes"* — phrased so that
//! the 12 read as a consequence of fitting a 5,952-byte payload. It never was.
//! The store's occupancy arithmetic was
//! `other_slots + old_parts + new_parts <= 24`, and twelve credentials would
//! have needed `12 + 8 + 8 = 28`; the real ceiling was **four**
//! (`apps/fido/tests/key_store_ceiling.rs`). Stating the format bound is
//! useful; implying it produced the 12 is how the wrong number survived two
//! orders of magnitude.
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
use fapico2_platform::keyregion::commit::CommitError;
use fapico2_platform::keyregion::crypto::{IndexKey, PayloadKey};
use fapico2_platform::keyregion::fido_store::{self, FidoRecordStore};
use fapico2_platform::keyregion::index::RpIdHash;
use fapico2_platform::keyregion::on_demand::{self, CredentialWindow, SlotQuery};
use fapico2_platform::keyregion::record;
use fapico2_platform::keyregion::{KeyRegion, Slot, SlotRead, FIDO_CAPACITY, FIDO_RECORD_MAX};
use fapico2_platform::secure_store::{chunked, SecureStore, SecureStoreError};
use heapless::Vec as HeaplessVec;
use zeroize::{Zeroize, Zeroizing};

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

/// Which store answers a credential-capacity question (US-1557).
///
/// # Why this is an enum and not a number
///
/// `AGENTS.md` §1: "`app.rs` is the host twin, not the shipped one. Fixing only
/// `app.rs` passes every host test and changes nothing on hardware." The
/// concrete expression of that for capacity is this: the two twins both answer
/// credMgmt `getMetadata` with `{1: existing, 2: remaining, 3: total}`, both
/// answer it with a `u32`, and both are *right* — but they are right about
/// different stores, and nothing in either response says which.
///
/// Left implicit, that is a divergence a reader cannot see and a test cannot
/// state: the host twin's `MemoryKeystore::with_max_creds(4)` reports a total of
/// 4, the device reports 856, and both numbers are correct answers to "how many
/// credentials can this hold?". A parity assertion that just compared the two
/// numbers would be asserting that they differ; one that skipped the number
/// would be asserting nothing.
///
/// So each twin reports **which** store, and
/// [`Self::advertised_capacity`] returns the number only where the number
/// means something about a device:
///
/// | backend | `advertised_capacity()` | why |
/// |---|---|---|
/// | [`KeyRegion`](Self::KeyRegion) | `Some(FIDO_CAPACITY)` | the device's real ceiling, derived from the region's geometry |
/// | [`Snapshot`](Self::Snapshot) | `None` | a **test fixture bound** — [`SNAPSHOT_MAX_CREDS`], or whatever a `MemoryKeystore` was configured with. Not a device claim, so it is not published as one. |
///
/// `None` is the honest answer for the host twin and it is enforced at the type
/// level: the host's `getMetadata` still puts a number on the wire (it has to —
/// it is the CTAP reply), but nothing in the API invites a caller to read it as
/// the device's capacity, and
/// `apps/fido/tests/twin_parity.rs` asserts both halves of the divergence rather
/// than leaving it to be discovered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialBackend {
    /// The per-record key region: what the shipped device uses, with
    /// [`FIDO_CAPACITY`] credentials.
    KeyRegion,
    /// The resident snapshot array: what the host twin, the dispatcher bridge
    /// and a not-yet-migrated device use.
    ///
    /// Bounded by [`SNAPSHOT_MAX_CREDS`] as a *format* bound and by whatever a
    /// host `Keystore` was configured with as a *fixture* bound; see the
    /// variant's note above for why neither is published.
    Snapshot,
}

impl CredentialBackend {
    /// The capacity this backend will advertise, or `None` when it has no
    /// device-meaningful one.
    ///
    /// `None` for [`Snapshot`](Self::Snapshot) is the whole point of the enum:
    /// it makes "the host twin's number is not the device's number" a value a
    /// test can compare rather than a sentence in a comment.
    pub const fn advertised_capacity(self) -> Option<u32> {
        match self {
            CredentialBackend::KeyRegion => Some(FIDO_CAPACITY),
            CredentialBackend::Snapshot => None,
        }
    }
}

/// Credentials the resident snapshot codec will hold — a **format** bound, not a
/// capacity, and the 5,952 B it is derived from is **not a reachable length**.
///
/// US-1010 corrected the *number*: the snapshot's bound is
/// `chunked::MAX_PARTS * chunked::PART_PAYLOAD_MAX` = 12 × 496 = 5,952 B, not
/// the 17-part 8,432 B it used to carry. US-1564 corrects the *reading* of it,
/// because this comment used to present the 12 as following from that figure
/// and it never did.
///
/// **5,952 B is a single-generation figure, and no device reaches it.** The
/// chunked slot is **double-buffered** — a write goes to the buffer *not*
/// holding the current set (`secure_store.rs`, "A logical slot may span up to
/// `chunked::MAX_PARTS` parts per buffer") — so a rewrite of a maximum-width
/// value transiently needs `2 × MAX_PARTS` physical entries, and `MAX_PARTS`
/// is 12 because `2 × 12 = 24` exactly exhausts `Rp2350SecureStore::DEV_MAX_ENTRIES`
/// (`secure_store.rs`'s compile-time assertion). Any applet holding an entry
/// of its own alongside the table — and every credential applet does — pushes
/// `parts_live + parts_being_written + resident` past 24, and the first
/// full-width rewrite returns `SecureStoreError::Full`. OATH is the worked
/// example: its durable ceiling is **30** maximal credentials, measured, not the
/// 68 its table is sized for.
///
/// So the honest chain is: the codec's bound is a *format* bound; the number 12
/// is the resident array size and therefore a **RAM** figure; and neither is a
/// statement about how many credentials the device can hold, which is
/// [`DEVICE_MAX_CREDS`] and nothing else.
///
/// Unchanged at 12, and it must stay separate from [`DEVICE_MAX_CREDS`]: the
/// snapshot is one whole-image CBOR document, so no store with more capacity
/// makes a longer snapshot legal.
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

/// How many of one RP's slots a region enumeration will name at once.
///
/// The **slot** list, not the credential list: each element is one `Slot` (two
/// bytes), so 32 costs 64 B of stack — where a `MAX_PENDING_CREDENTIAL_IDS`-sized
/// *credential* list would cost the same 64 bytes of pointers and then 32 x 720 B
/// of `DeviceCredential` behind them, one opened at a time.
///
/// It is 32 and not 12 for a reason worth stating: the enumeration has two bounds
/// and this is the one that fires **first**. `MAX_PENDING_CREDENTIAL_IDS` limits
/// what the device can *serve* in one `getAssertion` (12 assertions, then
/// `getNextAssertion`); this limits what it can *see*. A site with 20 resident
/// passkeys must have all 20 enumerable by credential management even though a
/// single assertion returns at most 12 of them — so the two constants answer
/// different questions and are deliberately not the same number.
///
/// The residual limit is real and is stated rather than hidden: a site with more
/// than 32 resident passkeys has the tail unreachable by enumeration, and the
/// device answers `LIMIT_EXCEEDED` rather than truncating. CTAP 2.1 puts no bound
/// on how many passkeys one relying party may register, so this is a genuine
/// ceiling — chosen for stack cost, and cheap to raise because it is one constant
/// and no record format depends on it.
pub const MAX_ENUMERATED_SLOTS: usize = 32;
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
/// bounded by `chunked::MAX_LOGICAL_LEN` — 5,952 B at one generation (US-1010),
/// which is **not** a length the device store can actually hold, because the
/// chunked slot is double-buffered and any applet with an entry of its own
/// pushes the rewrite peak past `DEV_MAX_ENTRIES` ([`SNAPSHOT_MAX_CREDS`]'s
/// comment has the arithmetic). So a device with a full credential list can now
/// run out of room where it did not before. That is reported rather than hidden
/// — see `vendor_state`'s module docs, and `grow_checked`, which turns the
/// shortfall into a clean `0x28`.
pub const AUTH_SCRATCH: usize = 4_608;

/// Width of a P-256 private scalar, in bytes.
///
/// Named once so [`PrivateScalar`] and every "32 bytes" claim about the field
/// have one spelling. It is the P-256 group order's byte width, and it is not
/// configurable: a wider field is a different curve's key and a narrower one
/// cannot express a scalar.
pub const PRIVATE_KEY_LEN: usize = 32;

/// A credential's P-256 private scalar, cleared when it goes out of scope
/// (US-1550, matching pico-hsm's `sc_hsm.c:869`).
///
/// # Why this is a type and not a `[u8; 32]`
///
/// The field it replaces was a bare `[u8; 32]`, which has no destructor, so
/// every owned `DeviceCredential` that held one left 32 bytes of signing key in
/// freed stack for the rest of the command. On the key-region path
/// (`device_core.rs::region_credential`) that is **one 720-byte stack copy per
/// lookup** — the exclude-list walk in makeCredential opens one per excluded
/// ID, the allow-list walk in getAssertion one per entry, credMgmt one per
/// enumerated slot, and every one of them is a distinct 32-byte key that
/// nothing wipes. The same was true of `self.keystore.credentials`, where a
/// deleted or overwritten credential dropped a struct whose private key
/// survived in the vacated slot.
///
/// `record::Plaintext` (`keyregion/record.rs`, "Why this type exists") and
/// `crypto::IndexKey`/`PayloadKey` (`keyregion/crypto.rs`, "Keys") already
/// make this guarantee by type for the region half of the store. This is the
/// applet-half counterpart, and it is deliberately the same shape: a
/// [`Zeroizing`] buffer, an explicit [`Drop`], no `Copy`, no `Clone`, no
/// `Debug` that prints the bytes.
///
/// # Why not `Clone`
///
/// `crypto.rs` states the rule for the region's keys and it is the same rule
/// here: "a `Clone` on a key type is the first step of a key that ends up in a
/// `static`", and a copy is "a second buffer to forget"
/// (`crypto.rs:330-345`). The places that genuinely need a second copy — the
/// one site in `device_core.rs::build_assertion` that ends a borrow before the
/// counter bump — call [`Self::copy_out`], which returns another
/// [`PrivateScalar`] and therefore another buffer that clears itself. The name
/// is the point: a clone is invisible, `copy_out` reads as a copy at the call
/// site and the reader can go and check it drops.
///
/// # Why `PartialEq` is constant-time
///
/// The only comparisons are tests and the "is this credential still usable"
/// question, so the timing argument is weak — but it costs three lines to make
/// the type's equality not depend on where the first differing byte is, and a
/// key type whose `PartialEq` is a `memcmp` is the kind of thing that later
/// gets called from a path where the argument *is* weak.
pub struct PrivateScalar(Zeroizing<[u8; PRIVATE_KEY_LEN]>);

impl PrivateScalar {
    /// The all-zero scalar — "no key here", which is what
    /// [`DeviceCredential::new_template`] and a revoked credential hold.
    ///
    /// A real value rather than an `Option`, because CTAP's credential record
    /// has a fixed key-3 field and an absent one would be a wire change. The
    /// security of this state is that it is **unusable**: P-256 rejects a zero
    /// scalar (`device_core.rs`'s `p256::SecretKey::from_slice` leg), so a
    /// credential whose scalar is zero cannot sign, whatever the rest of its
    /// record says.
    ///
    /// Not `const`: `Zeroizing::new` is not a const fn, and a `const` here
    /// would only be reachable from a `static`, which is the one place a key
    /// must never live (`crypto.rs`, "not `Copy` — a copy is a second buffer
    /// to forget").
    pub fn zero() -> Self {
        PrivateScalar(Zeroizing::new([0u8; PRIVATE_KEY_LEN]))
    }

    /// Take ownership of 32 bytes of key material.
    pub fn from_bytes(bytes: [u8; PRIVATE_KEY_LEN]) -> Self {
        PrivateScalar(Zeroizing::new(bytes))
    }

    /// Copy key material out of a slice, refusing anything that is not exactly
    /// [`PRIVATE_KEY_LEN`] bytes.
    ///
    /// The width check is not pedantry: a truncated scalar is a *different*
    /// (and usually invalid) key, and silently left-padding or right-truncating
    /// one would mint a credential whose public key does not match its private
    /// key — a signature no relying party can ever verify.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let fixed: [u8; PRIVATE_KEY_LEN] = bytes.try_into().ok()?;
        Some(PrivateScalar(Zeroizing::new(fixed)))
    }

    /// The scalar, **borrowed**.
    ///
    /// Borrowed and never returned by value on purpose: a method returning
    /// `[u8; 32]` would be a method whose result outlives the zeroize, which is
    /// the whole bug this type exists to remove (`fused_key::FusedRead::as_bytes`
    /// is the precedent for the argument).
    pub fn expose(&self) -> &[u8; PRIVATE_KEY_LEN] {
        &self.0
    }

    /// An owned second copy, for the caller that must end a borrow before it
    /// takes `&mut self`.
    ///
    /// The one sanctioned duplication, and it is a *type* rather than a
    /// `Clone` impl so that a reader who sees the call can see the obligation:
    /// the returned [`PrivateScalar`] clears itself at the end of the scope that
    /// named it.
    pub fn copy_out(&self) -> Self {
        PrivateScalar(Zeroizing::new(*self.0))
    }

    /// Overwrite with 32 fresh bytes, clearing whatever was here.
    ///
    /// The mutation path [`DeviceCredential::decode`] uses when it opens a
    /// sealed field, and — more importantly — the one it uses when it **revokes**
    /// a credential whose sealed fields failed to open. Assigning
    /// `Zeroizing::new([0; 32])` would have the same effect but reads like
    /// "the key is now the zero key", which is true of the value and false of
    /// the operation; `zero()` says the key was wiped.
    pub fn set_from_slice(&mut self, bytes: &[u8]) -> Option<()> {
        let fixed: [u8; PRIVATE_KEY_LEN] = bytes.try_into().ok()?;
        self.0 = Zeroizing::new(fixed);
        Some(())
    }

    /// Wipe the scalar in place, leaving an unusable credential behind.
    ///
    /// Named `wipe` rather than `zero` so it cannot collide with the
    /// associated constructor [`Self::zero`], and so a call site reads as an
    /// action on a key that exists rather than as a value being produced.
    ///
    /// **This records the host witness too**, and the reason is specific: the
    /// one call site that matters is [`DeviceCredential::decode`]'s revocation
    /// arm, and that is a `wipe` on a credential that is *still alive and still
    /// owned by the keystore*. Nothing will drop it for hours of uptime, so if
    /// only `Drop` recorded, the claim "a revoked credential's key was actually
    /// cleared rather than merely marked unusable" would be untestable — and an
    /// untestable security claim is an assertion in a comment.
    pub fn wipe(&mut self) {
        #[cfg(not(target_arch = "arm"))]
        let was_nonzero = !self.is_zero();
        let bytes: &mut [u8; PRIVATE_KEY_LEN] = &mut self.0;
        bytes.zeroize();
        #[cfg(not(target_arch = "arm"))]
        testing::record_dropped_scalar(*self.0, was_nonzero);
    }

    /// Is this the unusable all-zero state?
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Drop for PrivateScalar {
    /// Clear the bytes, then — on host only — record what was there *after* the
    /// clear so a test can read it.
    ///
    /// The `was_nonzero` flag is the half that stops the test being vacuous.
    /// "The witness saw zeroes" is satisfied just as well by a scalar that was
    /// never written as by one that was, so the buffer's populated-ness is
    /// sampled **before** the clear and carried in the record. This is
    /// `fused_key::FusedRead::drop`'s shape (`fused_key.rs:223-237`), and
    /// `crypto.rs`'s key drop is the one place in the tree that lacks it.
    ///
    /// The redundant clear is deliberate: `Zeroizing` would do it anyway, and
    /// this body is also where the host witness reads the buffer — after the
    /// clear, so that what it reports is evidence of the clear rather than of
    /// the clear having been skipped.
    fn drop(&mut self) {
        #[cfg(not(target_arch = "arm"))]
        let was_nonzero = !self.is_zero();
        let bytes: &mut [u8; PRIVATE_KEY_LEN] = &mut self.0;
        bytes.zeroize();
        #[cfg(not(target_arch = "arm"))]
        testing::record_dropped_scalar(*self.0, was_nonzero);
    }
}

impl Default for PrivateScalar {
    /// The all-zero scalar — see [`PrivateScalar::zero`].
    fn default() -> Self {
        Self::zero()
    }
}

/// Never prints the bytes — `Sealed`'s and `Plaintext`'s rule
/// (`keyregion/mod.rs:349-355`, `keyregion/record.rs:679-686`): a `Debug`
/// that dumps a private key puts it in a log buffer, and a log buffer outlives
/// the stack frame the key was cleared in by a very long way.
impl core::fmt::Debug for PrivateScalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PrivateScalar(<redacted>)")
    }
}

/// Constant-time equality over the scalar's bytes.
///
/// See the type's docs for why a key type's equality is not a `memcmp`.
impl PartialEq for PrivateScalar {
    fn eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..PRIVATE_KEY_LEN {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

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
///
/// # Not `Clone`, and why
///
/// The derive was dropped with US-1550. A `DeviceCredential` is 720 bytes and
/// 32 of those are a private key, so a `Clone` is a `Clone` of a key — the
/// first step of a key that ends up somewhere nobody will drop it
/// (`keyregion/crypto.rs:330-345`). No caller needed it: every site that wants
/// to keep a credential past a borrow takes an explicit
/// [`PrivateScalar::copy_out`] of the one field it is still holding, which is
/// both narrower and self-clearing. The compiler is what makes this stick —
/// there is no `clone()` to reach for.
///
/// # `Debug` is hand-written, not derived
///
/// A derived `Debug` on this struct would print `private_key` — and, because
/// it is a struct of mostly arrays, in full. That is a credential key in a log
/// buffer, which is exactly the outcome
/// [`keyregion::record::Plaintext`](fapico2_platform::keyregion::record::Plaintext)
/// and [`CredentialWindow`] refuse to allow. `large_blob_key` is redacted for
/// the same reason: it is derived from the private key and a `Debug` that
/// printed it would still be printing key-equivalent material.
#[derive(PartialEq)]
pub struct DeviceCredential {
    pub credential_id: HeaplessVec<u8, ID_MAX>,
    pub public_key: DeviceCoseKey,
    /// P-256 private scalar (32 bytes), zeroized when it goes out of scope.
    pub private_key: PrivateScalar,
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

/// A `Debug` for [`DeviceCredential`] that prints its **identity and policy**,
/// never its secrets.
///
/// Three of its fields are key material or key-equivalent: `private_key` (the
/// scalar itself), `large_blob_key` (derived from it, and returned to clients
/// in cleartext by design — so it must not also be in a log) and `hmac_secret`
/// (a credential-key-encrypted salt, useless to an attacker but a second copy
/// of something that only had one). All three are summarised here. Everything
/// else this prints is what a log is for: which credential, for which relying
/// party, with which policy.
///
/// The lengths rather than the bytes are the point for `credential_id`,
/// `rp_id`, `user_handle`, `user_name`, `user_display_name` and `cred_blob`:
/// they are not secrets, they are personal data, and a credential ID in a log
/// is a credential ID a site can still be correlated against.
impl core::fmt::Debug for DeviceCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceCredential")
            .field("credential_id", &format_args!("<{} B>", self.credential_id.len()))
            .field("public_key", &self.public_key)
            .field("private_key", &self.private_key)
            .field("rp_id", &format_args!("<{} B>", self.rp_id.len()))
            .field("user_handle", &format_args!("<{} B>", self.user_handle.len()))
            .field("cred_protect", &self.cred_protect)
            .field(
                "large_blob_key",
                &self.large_blob_key.as_ref().map(|_| "<redacted>"),
            )
            .field("hmac_secret", &format_args!("<{} B>", self.hmac_secret.len()))
            .field("cred_blob", &format_args!("<{} B>", self.cred_blob.len()))
            .field("third_party_payment", &self.third_party_payment)
            .field("pin_complexity_policy", &self.pin_complexity_policy)
            .field("resident", &self.resident)
            .field("algorithm", &self.algorithm)
            .field("counter", &self.counter)
            .field("revoked", &self.revoked)
            .field("expires_at", &self.expires_at)
            .finish()
    }
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
            private_key: PrivateScalar::zero(),
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
        seal_push(
            key,
            FieldScope::CredentialPrivateKey,
            &self.credential_id,
            self.private_key.expose(),
            &mut body,
        )?;
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
            let key_num = match p.next() {
                Ok(Item::U(k)) => k,
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
                Some(32) => {
                    c.private_key.set_from_slice(&scratch[..32])?;
                }
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
                // Wipe rather than assign: a revoked credential must leave no
                // recoverable scalar behind, and `zero()` says the intent where
                // a fresh all-zero `PrivateScalar` reads like a value.
                c.private_key.wipe();
                c.hmac_secret.clear();
                c.large_blob_key = None;
                c.cred_blob.clear();
            }
        } else {
            // Legacy plaintext fields (the pre-US-911 shape).
            match raw_private {
                Some(b) if b.len() == PRIVATE_KEY_LEN => {
                    c.private_key.set_from_slice(b)?;
                }
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
///
/// **`Clone` was dropped with US-1550**, with [`DeviceCredential`]'s: a clone
/// of this type is a clone of every credential private key it holds, and
/// nothing in the tree called it. Keeping the derive would have required a
/// `Clone` on [`PrivateScalar`] for its sake.
#[derive(Debug, PartialEq)]
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
    /// US-1562: the batched signature-counter window over the **key region**,
    /// the counterpart of [`Self::counter_unpersisted`].
    ///
    /// **On the app rather than on a static beside it**, for the same reason the
    /// snapshot's half is here: the window is session state that must never
    /// reach the medium, and a field of the value `boot.rs` parks in
    /// `FIDO_APP` is the one place that guarantees it. Its cost is
    /// [`CounterWindow`]'s own size — bounded by the *batch*
    /// ([`CounterWindow::PENDING_MAX`] entries), never by the store, which is
    /// the property that lets the region hold [`FIDO_CAPACITY`] credentials
    /// from a window this small.
    ///
    /// **Always constructed restored, for the reason `decode`'s own arm gives.**
    /// Only one of the two backends is live on a given board
    /// (`FidoApp::region_keys_for` answers which one, and the command path asks
    /// it the same question), and the other one's window is simply unused — which
    /// is what keeps the applet from needing a second field to choose between
    /// them.
    pub(crate) counter_window: CounterWindow,
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
    ///
    /// `#[inline(never)]` because the value is a 12-KiB `DeviceKeystore`
    /// and `boot_in_place` binds one to hold the result: inlined, its
    /// `VendorState::default` (~2,700 B) and the struct literal land in the
    /// caller's frame on top of it. Measured on this tree, outlining it
    /// took the async-main boot chain from 101,756 B to 99,028 B.
    #[inline(never)]
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
            // US-1562: restored, not fresh — see `decode`'s arm for why a
            // keystore that has no snapshot to restore from still starts the
            // region's window spent. A `DeviceKeystore::fresh()` is the
            // "no snapshot yet" state, and on a region-backed board that is also
            // "no way to tell", so the safe answer is the one that costs a skip.
            counter_window: CounterWindow::restored(),
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
        // caller's slot regardless. `decode_into` builds the value once, in
        // place — including the credential array, which is the other copy
        // that used to sit inside `decode`'s frame (8,640 B of reservation for
        // however many credentials are present).
        let mut out = None;
        if !Self::decode_into(&bytes[..n], key.as_ref(), Decode::Restore, &mut out) {
            return Err(SecureStoreError::Corrupt);
        }
        Ok(out)
    }

    /// Read **only** the physical-config record (auth-map key 6) out of the
    /// stored snapshot, without ever building a [`DeviceKeystore`].
    ///
    /// # Why this exists rather than `load(store)?.map(|ks| ks.phy)`
    ///
    /// US-1550 made `DeviceCredential::private_key` a `PrivateScalar`, which
    /// zeroizes on drop — and drop glue is contagious: it gives
    /// `DeviceCredential` a `Drop`, and therefore `DeviceKeystore` one too. A
    /// droppable 12-KiB value is no longer a `memcpy` a compiler may elide
    /// into its destination, so every frame that *binds* one reserves one.
    /// Measured on this tree: removing the drop glue alone took
    /// `hid_task`'s poll frame from 29,344 B to 16,096 B and the boot chain
    /// from 101,756 B to 91,444 B — the whole of this epic's regression, with
    /// the zeroization left in place.
    ///
    /// The victim was `FidoApp::sync_phy`, called from the HID task's
    /// per-command generation check (`firmware/src/tasks.rs`'s
    /// `DeviceFido::sync_generations`). It wanted a ~40-byte `PhyConfig` and
    /// paid a 12-KiB keystore for it: that one `let ks = ...` was 19,904 B of
    /// the poll frame (27,616 B → 7,712 B once it stopped being materialized).
    ///
    /// **Not a shortcut on validation.** The walk below is `decode`'s own
    /// top-level scan and `decode_auth` unchanged — so every sealed-field,
    /// out-of-range and unknown-key rule is enforced exactly as a full load
    /// enforces it — and each credential is decoded and dropped. The only
    /// difference from `load` is that no
    /// `HeaplessVec<DeviceCredential, SNAPSHOT_MAX_CREDS>` is ever built: peak
    /// scratch is one 720-byte `DeviceCredential` instead of twelve, and no
    /// keystore at all.
    ///
    /// `None` means exactly what `sync_phy` already read as "nothing to
    /// adopt": no snapshot in the slot, or one this build refuses to parse.
    /// It is deliberately **not** an error — refusing to adopt leaves the
    /// in-RAM copy alone, which is the fail-safe direction
    /// (`sync_phy`'s own doc comment).
    pub fn load_phy(store: &mut dyn SecureStore) -> Option<crate::vendorff::PhyConfig> {
        Self::scan_phy(store).map(|(_, _, _, _, _, phy, _)| phy)
    }

    /// The scan behind [`Self::load_phy`]: the whole-document walk plus
    /// `decode_auth`, with the credentials validated and discarded.
    ///
    /// `#[inline(never)]` for the same reason `load` and `decode` carry it —
    /// its scratch is the 5,952-byte chunked buffer and `decode_auth`'s
    /// bounded one, and inlining that into the HID poll would fold ~10 KiB of
    /// decode scratch into the async frame.
    #[inline(never)]
    fn scan_phy(store: &mut dyn SecureStore) -> Option<AuthParts> {
        if !chunked::contains_chunked(store, KEYSTORE_SLOT) {
            return None;
        }
        let mut bytes = [0u8; chunked::MAX_LOGICAL_LEN];
        let n = chunked::read_chunked(store, KEYSTORE_SLOT, &mut bytes).ok()?;
        let key = store.store_key();

        // Pass 0 — `decode`'s own scan, rule for rule: the sealed flag has to
        // be known before any field is opened, and a sealed document with no
        // store key is unopenable.
        let mut p = Parser::new(&bytes[..n]);
        let n_entries = match p.next().ok()? {
            Item::Map(n) if (1..=2).contains(&n) => n,
            _ => return None,
        };
        let mut sealed = false;
        let mut auth_b: Option<&[u8]> = None;
        let mut creds_b: Option<&[u8]> = None;
        for _ in 0..n_entries {
            let key_num = match p.next() {
                Ok(Item::U(k)) => k,
                _ => return None,
            };
            match key_num {
                1 => {
                    let Item::Array(3) = p.next().ok()? else { return None };
                    // `max_creds` is checked for shape only. Its bound is
                    // `decode`'s business, and this reader has no array to
                    // bound — reading a value it cannot use would make a
                    // perfectly good `phy` unreadable.
                    let Item::B(_) = p.next().ok()? else { return None };
                    let Item::B(b) = p.next().ok()? else { return None };
                    auth_b = Some(b);
                    let Item::B(b) = p.next().ok()? else { return None };
                    creds_b = Some(b);
                }
                snapshot_crypt::SEALED_MARKER_KEY => {
                    match p.next() {
                        Ok(Item::U(u)) if u == snapshot_crypt::SEALED_MARKER_VALUE => {}
                        _ => return None,
                    }
                    sealed = true;
                }
                _ => return None,
            }
        }
        if p.remaining() != 0 || auth_b.is_none() {
            return None;
        }
        if sealed && key.is_none() {
            // The same refusal `decode` makes: a sealed snapshot with no
            // store key cannot be opened.
            return None;
        }
        let auth = Self::decode_auth(auth_b?, key.as_ref(), sealed)?;
        // Each credential is decoded and immediately dropped. This is what
        // keeps `load`'s "one unopenable credential fails the whole snapshot"
        // rule without holding more than one of them at a time — the vector is
        // the 8,640 bytes, and it is the vector this reader refuses to build.
        let mut q = Parser::new(creds_b?);
        let count = match q.next().ok()? {
            Item::Array(n) => n,
            _ => return None,
        };
        for _ in 0..count {
            let Item::B(c) = q.next().ok()? else { return None };
            let _ = DeviceCredential::decode(c, key.as_ref(), sealed)?;
        }
        Some(auth)
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
    fn decode_into(
        bytes: &[u8],
        key: Option<&[u8; 32]>,
        mode: Decode,
        out: &mut Option<Self>,
    ) -> bool {
        let (slack, counter_unpersisted) = mode.slack_and_window();
        // Pass 0 — scan the top-level map (1 or 2 entries, either key
        // order) so the sealed flag is known before any credential is
        // decoded. The borrowed slices survive the pass (zero-copy).
        let mut p = Parser::new(bytes);
        let n_entries = match p.next() {
            Ok(Item::Map(n)) if (1..=2).contains(&n) => n as usize,
            _ => return false,
        };
        let mut sealed = false;
        let mut max_b: Option<&[u8]> = None;
        let mut auth_b: Option<&[u8]> = None;
        let mut creds_b: Option<&[u8]> = None;
        for _ in 0..n_entries {
            let key_num = match p.next() {
                Ok(Item::U(k)) => k,
                _ => return false,
            };
            match key_num {
                1 => {
                    let Ok(Item::Array(3)) = p.next() else { return false };
                    let Ok(Item::B(b)) = p.next() else { return false };
                    max_b = Some(b);
                    let Ok(Item::B(b)) = p.next() else { return false };
                    auth_b = Some(b);
                    let Ok(Item::B(b)) = p.next() else { return false };
                    creds_b = Some(b);
                }
                snapshot_crypt::SEALED_MARKER_KEY => {
                    match p.next() {
                        Ok(Item::U(u)) if u == snapshot_crypt::SEALED_MARKER_VALUE => {}
                        _ => return false,
                    }
                    sealed = true;
                }
                _ => return false,
            }
        }
        if p.remaining() != 0 || max_b.is_none() {
            return false;
        }
        if sealed && key.is_none() {
            // A sealed snapshot without its store key cannot be opened.
            return false;
        }
        let max_creds = {
            let Some(max_b) = max_b else { return false };
            let mut q = Parser::new(max_b);
            match q.next() {
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
                Ok(Item::U(u)) => (u as usize).min(SNAPSHOT_MAX_CREDS),
                _ => return false,
            }
        };
        let Some(auth_b) = auth_b else { return false };
        let (pin_state, cred_counter, device_random, large_blob_array, vault_state, phy, vendor) =
            match Self::decode_auth(auth_b, key, sealed) {
                Some(parts) => parts,
                None => return false,
            };
        // Credentials go **straight into their destination** rather than
        // through a local `HeaplessVec` (US-951: the boot chain carries three
        // copies of a 12-KiB keystore, and this one is pure duplication —
        // `HeaplessVec<DeviceCredential, SNAPSHOT_MAX_CREDS>` is 8,640 B of
        // reservation for however many credentials are actually present).
        //
        // The value is written whole, and only once every fallible step before
        // it has succeeded, so there is exactly one failure window left — the
        // credential loop — and it ends by putting `*out` back to `None`. A
        // half-built keystore can never escape: `Option`'s `None` is a state
        // that needs no initialization, and dropping it runs no
        // `DeviceCredential::drop` over uninitialized memory.
        *out = Some(Self {
            pin_state,
            credentials: HeaplessVec::new(),
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
            // US-1562. **Not derived from `mode`, and the asymmetry is the
            // point.** The snapshot can tell a restore from a fresh image because
            // the whole document was in hand at decode; the key region cannot be
            // touched at all until `RUNG_USB` (S8/S9), so at construction there
            // is nothing in the applet that distinguishes "a device with eight
            // hundred signed assertions" from "a device that has never signed
            // one". Answering `fresh()` on an unreadable question is the
            // direction that repeats a `signCount` after a power cut, which is
            // the one outcome a signature counter exists to prevent, so every
            // session starts restored. A credential enrolled moments earlier pays
            // for it by signing `COUNTER_PERSIST_INTERVAL + 1` on its first
            // assertion: over-skipping is legal (FIDO asks that a `signCount`
            // never *repeat*, never that it advance by one), and the cost is one
            // spare counter value on a credential that has no history to repeat.
            counter_window: CounterWindow::restored(),
        });
        // The credential loop — the only remaining fallible step, and the one
        // the block scope exists for: the `&mut` borrow of `*out` has to end
        // before a failure can put it back to `None`.
        let ok = {
            let Some(ks) = out.as_mut() else {
                return false;
            };
            let Some(creds_b) = creds_b else { return false };
            let mut q = Parser::new(creds_b);
            let mut ok = true;
            let n = match q.next() {
                Ok(Item::Array(n)) => n,
                _ => {
                    ok = false;
                    0
                }
            };
            for _ in 0..n {
                if !ok {
                    break;
                }
                let cred = match q.next() {
                    Ok(Item::B(c)) => match DeviceCredential::decode(c, key, sealed) {
                        Some(v) => v,
                        None => {
                            ok = false;
                            break;
                        }
                    },
                    _ => {
                        ok = false;
                        break;
                    }
                };
                if ks.credentials.push(cred).is_err() {
                    ok = false;
                    break;
                }
            }
            // US-1012's slack, folded in here so the value is built once (see
            // `load`). `0` from `from_cbor`: nothing granted, nothing spent,
            // the stored bytes as they are.
            if ok {
                ks.cred_counter = ks.cred_counter.saturating_add(slack);
                for c in &mut ks.credentials {
                    c.counter = c.counter.saturating_add(slack);
                }
            }
            ok
        };
        if !ok {
            *out = None;
            return false;
        }
        true
    }

    /// [`Self::decode_into`] in value position: the by-value form, for the
    /// callers that genuinely want a `DeviceKeystore` back.
    ///
    /// Only `from_cbor` uses this — the host interchange decoder, which is not
    /// on the boot chain. `load` calls `decode_into` directly so that the
    /// credentials are built into the slot `load` already has to own, rather
    /// than through a second 8,640-byte vector that `decode_into`'s caller
    /// would then have to hold alongside it.
    #[inline(never)]
    fn decode(bytes: &[u8], key: Option<&[u8; 32]>, mode: Decode) -> Option<Self> {
        let mut out = None;
        if Self::decode_into(bytes, key, mode, &mut out) {
            out
        } else {
            None
        }
    }

    /// auth map: `{1?: pin, 2?: cred_counter, 3?: large_blob_array,
    /// 4?: vault_state, 5?: device_random}`. US-911: keys 3/4/5 are sealed
    /// under `key` when `sealed`; ANY open failure fails the whole snapshot
    /// (`None` = Corrupt, fatal per FX-440) — the stateless master is never
    /// garbage.
    ///
    /// `#[inline(always)]`, against the grain, because of what a **second**
    /// call site does to the boot chain. `scan_phy` reads the same auth map
    /// (see `load_phy`), and with one caller LLVM folds this body into
    /// `decode_into` — where its scratch overlaps the caller's live state and
    /// costs nothing extra. With two callers it stops folding, becomes its own
    /// 13,368-byte frame, and that frame is *added* to the chain rather than
    /// merged: measured, the async-main boot chain went 91,120 B -> 102,172 B,
    /// over the 98,304 B ceiling.
    ///
    /// That is the same trade the `#[inline(never)]`s above make in the other
    /// direction, and it is worth stating plainly because it is not a
    /// readability choice: a third caller, or an LLVM that stops honouring the
    /// attribute, puts the gate red again with the fix intact in the source.
    #[inline(always)]
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
            let key_num = match p.next() {
                Ok(Item::U(k)) => k,
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

    /// Remove this snapshot's credential array, and make that removal durable.
    ///
    /// The last step of [`migrate_snapshot_to_region`], and the only one that
    /// writes. Returns the number retired, or the store's error with **this
    /// keystore restored to exactly what it was** — see the rollback note
    /// below.
    ///
    /// # Rollback, and SOAK-FINDING-1
    ///
    /// The array is *taken* before the write and put back on failure, and
    /// `dirty` is restored to whatever it was. That is the whole of the
    /// rollback, and it is the shape SOAK-FINDING-1 asks for: a mutation that
    /// could not be persisted is never left latched. A retirement that failed
    /// with `dirty = true` and an empty array would be the worst of both — the
    /// device would report an empty credential set, refuse an enrolment with
    /// `KeyStoreFull`, and persist that answer on the next flush.
    ///
    /// # `stored`, not `dirty`
    ///
    /// A successful retirement **is** a transactional mutation, so it sets
    /// `stored = true` on the same terms [`Self::store_credential_checked`] does
    /// and for the same reason: the store now holds exactly this snapshot, so
    /// the persist gate must program the partition image *without* rewriting
    /// the snapshot — which on a store at its slot bound would transiently hold
    /// both chunked generations and fail, re-latching the very gate this
    /// honours.
    ///
    /// # What this does not retire
    ///
    /// Only `credentials`. The PIN state, the counters, `device_random`, the
    /// large-blob array, the vault state, `phy` and the `0x41` vendor state are
    /// all still written — the snapshot remains the keystore, and only its
    /// credential set has moved.
    pub fn retire_credentials(&mut self, store: &mut dyn SecureStore) -> Result<u32, SecureStoreError> {
        let count = self.credentials.len();
        if count == 0 {
            return Ok(0);
        }
        // Taken, not cleared: `HeaplessVec` has no cheap "restore what was
        // there", and the alternative — encoding the array back into it — is
        // the one operation whose cost is proportional to the thing being
        // rescued. `core::mem::take` on a `Vec`-shaped field is a four-word
        // move, and it leaves a valid empty vector in its place so nothing
        // observes a half-cleared keystore if the write below panics.
        let taken = core::mem::take(&mut self.credentials);
        let was_dirty = self.dirty;
        self.dirty = true;
        match self.persist(store) {
            Ok(()) => {
                // Every record derived from these credentials was durable before
                // this call — the caller establishes that — so the write above
                // is what makes "migrated" true rather than merely believed.
                self.dirty = false;
                self.stored = true;
                self.counter_unpersisted = 0;
                Ok(count as u32)
            }
            Err(e) => {
                self.credentials = taken;
                self.dirty = was_dirty;
                Err(e)
            }
        }
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

    /// US-1562: this device's batched signature-counter window over the key
    /// region.
    ///
    /// **Read-only on purpose.** A mutable accessor would let a caller record a
    /// pending value the store never learned about, and the next bump would then
    /// sign *above* a value that was never written — which is a counter that
    /// skips rather than repeats, so it would pass every test here and be wrong
    /// in the only direction FIDO cares about once the window is spent. Every
    /// mutation goes through [`RegionCredentials::bump_credential_counter`].
    pub fn region_counter_window(&self) -> &CounterWindow {
        &self.counter_window
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

// ---------------------------------------------------------------------------
// US-1555 / US-1563 — the per-record region backend (US-1552's applet half)
// ---------------------------------------------------------------------------

/// Why a region-backed credential operation did not happen.
///
/// Three states and no more, for the reason `AGENTS.md` §4 makes load-bearing:
/// a wire claim the device cannot honour is the defect, so "we could not find
/// out" ([`Self::Unreachable`](Self::Unreachable)) is never folded into "there is
/// nothing there". `device_keystore.rs`'s old `Result<(), ()>` could not express
/// that distinction, and the credMgmt `getMetadata` reply is exactly where it
/// would be visible to a user as a device claiming a full store it had not
/// measured.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegionCredentialError {
    /// **No region, or the region could not be reached.** `boot::key_region()`
    /// answers `None` before `release_key_region()`, and S8/S9 require the applet
    /// to cope rather than halt — so this degrades to an empty credential set
    /// and a clean CTAP error, never a panic and never `fatal_boot`.
    ///
    /// `reason` is the transport's own `&'static str`, or a named constant
    /// below for the "no region installed" case.
    Unreachable(&'static str),
    /// Every slot in FIDO's range is occupied, tombstoned or not.
    Full,
    /// The credential does not fit the record the slot stride can hold.
    TooLarge {
        /// What was offered.
        len: usize,
        /// The bound: `FIDO_RECORD_MAX` (836).
        max: usize,
    },
    /// No credential with this ID exists.
    NoSuchCredential,
    /// The record would not encode or decode as a credential.
    ///
    /// A fact about the data, never about the transport — the same split
    /// `record::read` draws.
    Malformed,
    /// The commit, seal or index write failed.
    Store(fido_store::FidoStoreError),
}

/// The `"no region installed"` reason string for [`RegionCredentialError::Unreachable`].
///
/// A named constant rather than an inline literal so a log line and a test can
/// match on it, and so the "the boot path has not released the region" case is
/// distinguishable from a flash that is genuinely failing — the S10 obligation
/// to *report* rather than halt.
pub const E_NO_REGION: &str =
    "fido: the key region is not reachable (not installed, or not yet released)";

// ---------------------------------------------------------------------------
// US-1561 — the batched signature counter over the per-record region
// ---------------------------------------------------------------------------

/// US-1561: the batched signature-counter window over the per-record region.
///
/// **No new constant, deliberately.** The window flushes on
/// [`COUNTER_PERSIST_INTERVAL`] — the same constant the snapshot path uses —
/// and introducing a second literal here would be two numbers a reviewer has to
/// diff by eye, which is the exact defect the `check_erase_budget.py` coupling
/// exists to remove.
///
/// **The interval is re-*derived* here, not inherited by habit.** 32 was chosen
/// for a persist that cost **8 sector erases on 8 distinct sectors, one per
/// sector**. A per-record counter write costs **6 sector erases on 3 distinct
/// sectors**, and the distribution is nothing like uniform — both the record
/// commit and the index rewrite stage through the **same** commit scratchpad,
/// so **one 4 KiB sector collects four of the six**. Both halves matter and they
/// point opposite ways, so the arithmetic has to be made again.
/// `docs/erase-budget.md` §4c has it; the short form is
///
/// | | whole-snapshot persist | per-record counter write |
/// |---|---:|---:|
/// | sector erases per **durable write** | 8 | 6 |
/// | distinct sectors touched | 8 | 3 |
/// | erases on the busiest **single** sector | 1 | **4** |
/// | sector erases per **assertion** | 8 | 6 / 32 = 0.1875 |
///
/// Two consequences, and the first is not the one a reader expects:
///
/// * the **per-assertion byte** cost falls from 32 KiB to 12 KiB (2.7×), which
///   is the win the per-record store was built for;
/// * the **lifetime in assertions falls**, because the divisor is the busiest
///   single sector and it went from 1 to 4: per-**persist** 100,000 → 25,000, and
///   per-**assertion** 3,200,000 → **800,000**. Fewer bytes per assertion does
///   not mean more assertions per sector when the bytes land on the *same*
///   sector four times over.
///
/// 32 is still the value the applet flushes on, and changing it is not a
/// documentation decision: it moves the CTAP1 forward-skip budget as well as the
/// wear, and the factor that would justify a different one needs a measurement
/// of the fitted flash part (US-1007) that this branch does not have. The
/// honest statement of where this leaves the design is that **the scratchpad,
/// not the record, is the wear bottleneck** — one sector out of 960 absorbing
/// two thirds of every durable counter write's erases — and shrinking that is
/// the change that would move the number, not the interval.
///
/// # Why it is not the snapshot's `dirty` flag, and not a credential array
///
/// The window holds **no credentials** — a `(slot, counter)` list, at most
/// [`CounterWindow::PENDING_MAX`] entries — so it is bounded by the *batch*,
/// never by the store. That is what keeps it compatible with the derived
/// capacity: `DeviceCredential` is 720 bytes and a resident array of them is
/// the thing [`DEVICE_MAX_CREDS`] = 856 can never have
/// (`fido_store.rs`'s module docs).
///
/// # The invariant, and the weakening
///
/// **At most [`COUNTER_PERSIST_INTERVAL`] bumps are un-persisted, and the reply
/// may sign a counter that is not yet the durable one.** The second half is the
/// deliberate weakening US-1011 made; [`CounterWindow::restored`] and
/// [`CounterWindow::resume_from`] are US-1012's two halves making it safe, on
/// the same terms as [`DeviceKeystore::load`] — a restore grants one window of
/// slack **and spends it**, so a cut inside a window can only skip forward.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CounterWindow {
    /// Slots holding a counter that is not durable yet, and the value each now
    /// carries.
    pending: HeaplessVec<(Slot, u32), { CounterWindow::PENDING_MAX }>,
    /// Bumps since the last successful durable write, over the whole store.
    ///
    /// **Store-wide, not per credential, for the reason the snapshot window is**
    /// (`DeviceKeystore::counter_unpersisted`): one flush writes every pending
    /// record at once, so a shared budget bounds the total number of durable
    /// writes without bounding how many credentials may be in flight — which is
    /// what makes a mixed workload cost one flush per
    /// [`COUNTER_PERSIST_INTERVAL`] bumps in total rather than one per counter.
    unpersisted: u16,
    /// Whether this session began as a **restore** from the durable image.
    ///
    /// The flag, not the slack arithmetic: [`Self::resume_base`] is what applies
    /// US-1012's grant, and the flag is only what turns it on. It never clears —
    /// "this session started from a restore image" is a fact about the session,
    /// not about the current window.
    restore: bool,
    /// Slots whose restore slack has already been granted this session.
    ///
    /// **Bounded, and the bound costs counter space rather than correctness.**
    /// Once it is full, [`Self::resume_base`] keeps granting the slack to slots
    /// it has never seen: a slack applied twice is a *larger forward skip*, and
    /// FIDO's requirement is that a `signCount` never repeats — never that it
    /// advances by one. So the overflow direction is the safe one, and the bound
    /// exists only because this is a fixed-size array on a part with no spare
    /// RAM. 32 slots is 64 bytes and covers every device whose power-on sees
    /// fewer than 32 distinct credentials.
    resumed: HeaplessVec<Slot, { CounterWindow::RESUME_TRACK_MAX }>,
}

impl CounterWindow {
    /// Slots a window can hold before a flush is forced.
    ///
    /// **Equal to the batch interval on purpose.** It is the smallest bound that
    /// makes [`Self::record`] unable to refuse: the window closes after
    /// [`COUNTER_PERSIST_INTERVAL`] bumps and each bump touches one slot, so
    /// "the list is full" and "the window is full" are the same event, and
    /// [`RegionCredentials::bump_counter`] flushes between them.
    pub const PENDING_MAX: usize = COUNTER_PERSIST_INTERVAL as usize;

    /// US-1012: the counter slack a restored session is granted, in counter
    /// values — one whole batch window.
    ///
    /// The arithmetic is US-1012's, made exact: before the cut a credential's
    /// in-RAM counter was at most `durable + COUNTER_PERSIST_INTERVAL - 1`, so a
    /// restored device must not sign anything below that, and `durable + W` is
    /// the first value it may sign.
    pub const RESTORE_SLACK: u32 = COUNTER_PERSIST_INTERVAL as u32;

    /// A window for a session that has issued no counter value yet: nothing
    /// granted, nothing spent, nothing pending.
    pub const RESUME_TRACK_MAX: usize = 32;

    /// A window for a session that has issued no counter value yet: nothing
    /// granted, nothing spent, nothing pending.
    pub const fn fresh() -> Self {
        CounterWindow {
            pending: HeaplessVec::new(),
            unpersisted: 0,
            restore: false,
            resumed: HeaplessVec::new(),
        }
    }

    /// A window for a session that began as a **restore**: the whole budget
    /// spent, so the first bump writes down.
    ///
    /// This is the "spend" half of US-1012 and [`Self::resume_from`] is the
    /// "grant" half; the applet applies the grant to each credential it reads.
    /// Granting without spending would let a restored device run a whole extra
    /// window past the skip; spending without granting would resume at the
    /// durable value and **repeat** it, which is the clone-detection failure
    /// both halves exist to prevent. See [`DeviceKeystore::load`], which states
    /// the same mechanism for the snapshot path.
    pub const fn restored() -> Self {
        CounterWindow {
            pending: HeaplessVec::new(),
            unpersisted: COUNTER_PERSIST_INTERVAL,
            restore: true,
            resumed: HeaplessVec::new(),
        }
    }

    /// US-1012: the counter value a record read from the durable image resumes
    /// from on a session that began as a restore.
    ///
    /// `saturating_add`, like [`DeviceKeystore::decode`]'s slack: a wrapped
    /// counter repeats values whatever this code does, and 2³² assertions from
    /// saturation is not a deployment.
    pub const fn resume_from(durable: u32) -> u32 {
        durable.saturating_add(Self::RESTORE_SLACK)
    }

    /// Did this session begin as a restore from the durable image?
    pub const fn is_restore(&self) -> bool {
        self.restore
    }

    /// US-1012's "grant" half, applied **here** rather than left to the caller.
    ///
    /// # Why it cannot be the caller's job
    ///
    /// The snapshot path grants the slack at *decode*, and its decoder reads the
    /// whole snapshot — so every credential is reached exactly once per session
    /// and there is nothing to forget. **The region store has no such sweep.**
    /// S9 forbids the boot path from touching the key region, so a restored
    /// device meets its records one at a time, on first use, and a caller that
    /// has to remember "and add the slack the first time" will eventually not.
    ///
    /// That failure is invisible until it is a clone-detection failure: the
    /// counter resumes at the durable value, the device signs a `signCount` the
    /// client has already seen, and every other assertion in the story still
    /// passes. So the grant is part of the window, keyed on the slot, and
    /// [`Self::resumed`] remembers which records have had it.
    ///
    /// Returns the value `slot`'s counter may be raised from: `durable` on a
    /// session that did not begin as a restore, [`Self::resume_from`] of it on
    /// the first use of a record in one that did, and the durable value itself
    /// for a record already resumed.
    pub fn resume_base(&mut self, slot: Slot, durable: u32) -> u32 {
        if !self.restore || self.resumed.contains(&slot) {
            return durable;
        }
        // `push` failing is the overflow case named in `resumed`'s docs: the
        // slack is granted anyway, which skips further forward and never
        // repeats. Deliberately not handled by refusing — a refusal would be a
        // credential that cannot sign after a power cut.
        let _ = self.resumed.push(slot);
        Self::resume_from(durable)
    }

    /// Bumps that have happened since the last durable write.
    pub const fn unpersisted(&self) -> u16 {
        self.unpersisted
    }

    /// How many slots hold a counter that is not durable yet.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The pending `(slot, counter)` pairs, oldest first.
    pub fn pending(&self) -> &[(Slot, u32)] {
        self.pending.as_slice()
    }

    /// Must the applet write now?
    ///
    /// Two reasons, and both are load-bearing: the batch budget is spent
    /// (US-1011's window) or the pending list is full ([`Self::PENDING_MAX`]).
    pub fn should_flush(&self) -> bool {
        self.unpersisted >= COUNTER_PERSIST_INTERVAL || self.pending_full()
    }

    /// Whether [`Self::record`] could refuse.
    pub fn pending_full(&self) -> bool {
        self.pending.len() >= Self::PENDING_MAX
    }

    /// The counter `slot` currently carries, durable or pending.
    ///
    /// A pending entry wins, and it is strictly newer than what is in the
    /// region because [`Self::record`] only ever raises it.
    pub fn pending_value(&self, slot: Slot) -> Option<u32> {
        self.pending.iter().find(|(s, _)| *s == slot).map(|(_, c)| *c)
    }

    /// Record that `slot`'s counter now reads `counter`.
    ///
    /// A slot already in the list is **updated, not appended** — the window
    /// tracks a value per slot, not a bump log — while `unpersisted` still
    /// rises, because the budget is in **bumps**.
    ///
    /// Returns `false` only when the pending list is full. That is the one
    /// failure [`RegionCredentials::bump_counter`] handles by flushing first,
    /// and it is a `bool` rather than a panic because a silently dropped bump
    /// would let the next one sign a *lower* value — a clone-detection failure,
    /// which is the one outcome worse than a reported error.
    pub fn record(&mut self, slot: Slot, counter: u32) -> bool {
        if let Some(entry) = self.pending.iter_mut().find(|(s, _)| *s == slot) {
            entry.1 = counter;
        } else if self.pending.push((slot, counter)).is_err() {
            return false;
        }
        self.unpersisted = self.unpersisted.saturating_add(1);
        true
    }

    /// One pending entry has become durable; drop it from the window.
    pub(crate) fn commit_pending(&mut self, index: usize) {
        self.pending.remove(index);
        self.unpersisted = self.unpersisted.saturating_sub(1);
    }

    /// US-1562: undo one [`Self::record`] — put `slot` back to `counter` and
    /// give back the budget the bump consumed.
    ///
    /// **Only ever called when the durable write that was supposed to carry the
    /// raised value failed**, so this is the SOAK-FINDING-1 rollback on the
    /// region path: the reply signs what the window held before the command, so
    /// a flash that refuses a counter never lets the device sign a value it
    /// cannot back. The applet-side mirror is
    /// [`DeviceKeystore::bump_credential_counter_checked`]'s revert arm, and the
    /// two have to agree — a rollback in one backend and not the other would be
    /// the same signing discipline with two different answers to "what happens
    /// when the flash says no".
    ///
    /// The entry is **not removed**, only lowered, and that is the whole point:
    /// the next bump reads [`Self::pending_value`] and raises from there, so a
    /// lowered entry keeps the counter moving forward. Removing it would hand
    /// the next bump a *durable* value to raise from — and on a restored
    /// session that is a value the cut-away session already signed, which is
    /// the clone-detection repeat the whole restore mechanism exists to prevent.
    ///
    /// `unpersisted` falls by one because the budget counts **bumps**
    /// ([`Self::record`]) and the bump being undone is one of them.
    pub(crate) fn restore_pending(&mut self, slot: Slot, counter: u32) {
        if let Some(entry) = self.pending.iter_mut().find(|(s, _)| *s == slot) {
            entry.1 = counter;
        }
        self.unpersisted = self.unpersisted.saturating_sub(1);
    }

    /// Every pending entry is durable: close the window.
    ///
    /// Never called for an empty flush — see [`RegionCredentials::flush_counters`],
    /// where an empty list means "nothing happened", not "the budget reset".
    pub(crate) fn note_durable_write(&mut self) {
        self.pending.clear();
        self.unpersisted = 0;
    }
}

/// The record body one FIDO credential occupies, as a CBOR map.
///
/// **The same map the snapshot codec writes**, not a second format. That is the
/// point of reaching for [`DeviceCredential::encode`] rather than defining a
/// region-specific layout: `AGENTS.md` §5 names "two formats for one thing" as
/// the defect class this epic keeps finding (`DEVICE_MAX_CREDS` against the
/// region; two AAD builders in `record.rs`/`crypto.rs`). One credential has one
/// encoding, and a record is that encoding sealed.
///
/// The `None` key is load-bearing and not merely "the legacy path":
/// [`DeviceCredential::encode`]'s `key` parameter seals the four sensitive
/// fields (private key, credBlob, largeBlobKey, hmacSecret) with US-911's
/// per-field AEAD. Inside a region record that would be **sealing twice** — the
/// whole body is already one AEAD under the payload key, with an AAD naming the
/// slot, the generation and the domain. A second inner layer buys no
/// confidentiality and costs 4 × 28 bytes of every record's 836, which is
/// capacity taken from the user to protect data the outer layer already protects.
/// So the region's record body is the *plaintext* form, and the single
/// confidentiality boundary is `record::seal`.
///
/// `FIDO_RECORD_MAX` (836) is `mod.rs`'s measured bound for exactly this shape,
/// and `assert_credentials_fit_the_record` below fails the build if it stops
/// being true.
pub const CREDENTIAL_RECORD_MAX: usize = FIDO_RECORD_MAX as usize;

/// Serialize one credential into a region record body.
///
/// `None` on an encode failure or on a body larger than
/// [`CREDENTIAL_RECORD_MAX`] — refused rather than truncated, for the reason
/// `mod.rs`'s stride assertion gives: a record written short is a credential
/// that silently lost a field.
pub fn credential_record_body(cred: &DeviceCredential) -> Option<HeaplessVec<u8, CREDENTIAL_RECORD_MAX>> {
    let mut out: HeaplessVec<u8, CREDENTIAL_RECORD_MAX> = HeaplessVec::new();
    // `None` key: the outer record AEAD is the confidentiality boundary. See
    // `CREDENTIAL_RECORD_MAX`'s docs.
    cred.encode(None, &mut out).ok()?;
    Some(out)
}

/// The CBOR **map** inside a credential record body, or `None`.
///
/// # Why a strip is needed at all
///
/// [`DeviceCredential::encode`] writes its map *wrapped in a bstr* — it ends
/// with `no_heap::push_bstr(out, &body)` — because the host interchange snapshot
/// stores each credential as one element of an array of byte strings
/// ([`DeviceKeystore::to_cbor`]). [`DeviceCredential::decode`] correspondingly
/// expects the **unwrapped** map, and the snapshot decoder hands it the element
/// its own CBOR parser already unwrapped (`device_keystore.rs:1339`).
///
/// A region record has no array around it, so nothing unwraps the bstr for us.
/// Storing the bstr-wrapped bytes and stripping them on read keeps **one**
/// encoding — the applet's own — rather than introducing a region-specific
/// layout that happens to hold the same map under different framing. That is
/// the `AGENTS.md` §5 argument again: two framings for one record is how a
/// future field ends up written through one and read through the other.
///
/// The strip is strict — a bstr header, then exactly the rest of the buffer.
/// Truncated or over-long framing is refused rather than clamped, because a body
/// whose framing does not describe its content is a fact about the data.
pub fn credential_map_in_body(body: &[u8]) -> Option<&[u8]> {
    match Parser::new(body).next() {
        Ok(Item::B(inner)) => Some(inner),
        _ => None,
    }
}

/// Parse one credential out of a region record body.
///
/// `None` on anything that is not a well-formed credential map, which is also
/// how a **tombstone** is recognised — see [`is_deleted_body`].
///
/// A record that fails here is a fact about the data and costs itself alone
/// (US-1549's fail-closed property); it is not turned into "the store is empty",
/// because that is the memoization US-1573 exists to prevent.
pub fn credential_from_record_body(body: &[u8]) -> Option<DeviceCredential> {
    if is_deleted_body(body) {
        return None;
    }
    let map = credential_map_in_body(body)?;
    // `None` key and `sealed = false`: the plaintext form `encode` wrote. See
    // `CREDENTIAL_RECORD_MAX`'s docs.
    DeviceCredential::decode(map, None, false)
}

/// Is this opened record body a tombstone?
///
/// A one-byte `0xFF` body — `fido_store::TOMBSTONE_BODY`, and the reason it is
/// unambiguous is that file's. Named here so a caller counting live credentials
/// does not have to reach into the store for one predicate, and so the check is
/// made on **plaintext**: an erased slot reads as all-`0xFF` too, and treating
/// "never written" as "deleted" would make the two indistinguishable to a count.
pub fn is_deleted_body(body: &[u8]) -> bool {
    fido_store::is_tombstone(body)
}

/// Recognises a credential ID inside an opened record's plaintext.
///
/// The applet's half of [`fido_store::CredentialProbe`]. It is a *second* copy
/// of the CBOR map's key-1 read, and that is a real cost — so it is stated
/// rather than hidden: the alternative, having the store carry the applet's
/// layout, is what `CredentialProbe`'s own docs refuse ("a second parser here
/// would be a second definition of a record's contents"). One short walk that
/// stops at key 1 is cheaper than moving the credential codec into the store.
pub struct CredentialIdProbe<'a> {
    /// The credential ID to look for.
    pub credential_id: &'a [u8],
}

impl fido_store::CredentialProbe for CredentialIdProbe<'_> {
    fn matches(&self, plaintext: &[u8], credential_id: &[u8]) -> bool {
        credential_id_in_body(plaintext, credential_id)
    }
}

/// Does this credential record body hold `credential_id`?
///
/// Reads CBOR key `1` — `DeviceCredential::encode`'s credential-ID field — and
/// compares it **in full**, because returning `true` here is a claim that the
/// record *is* that credential and a prefix match would let a 16-byte ID claim
/// a 64-byte one.
///
/// A malformed body is `false` rather than a panic: the body came out of an
/// AEAD that verified, so it is this build's own encoding or a forgery, and
/// neither is worth aborting a `getAssertion` over.
pub fn credential_id_in_body(body: &[u8], credential_id: &[u8]) -> bool {
    // Unwrap the bstr first — see `credential_map_in_body` for why the record
    // body carries one. A body that is not bstr-wrapped is not this format, and
    // answering `false` is what keeps a probe from matching against bytes it
    // does not understand.
    let Some(map) = credential_map_in_body(body) else {
        return false;
    };
    let mut p = Parser::new(map);
    match p.next() {
        Ok(Item::Map(_)) => {}
        _ => return false,
    }
    loop {
        if p.remaining() == 0 {
            return false;
        }
        let key = match p.next() {
            Ok(Item::U(k)) => k,
            _ => return false,
        };
        let item = match p.next() {
            Ok(item) => item,
            Err(_) => return false,
        };
        if key == 1 {
            return matches!(item, Item::B(b) if b == credential_id);
        }
        // Keys 2..=19 all hold a scalar, a byte string or a **map** (the COSE
        // key at key 2). `next` already consumed each one, so there is nothing
        // to skip — and skipping here would advance past the next key and make
        // the walk read the wrong pair.
    }
}

/// The region's two keys, held together because they are always used together.
///
/// **Not stored.** A `DeviceKeystore` may hold one of these for the length of one
/// command and no longer: `crypto.rs` states its keys as "per-operation: derive,
/// use, drop", and this type does not outlive the operation that made it. A
/// credential set that is "resident" in flash and re-derived per command is the
/// property the whole per-record design exists to have.
pub struct RegionKeys {
    /// PIN-free, OTP-rooted: *finding* a credential never needs the PIN.
    pub index: IndexKey,
    /// PIN-derived: *opening* one does.
    pub payload: PayloadKey,
}

/// How the applet derives the region's `pin_secret`.
///
/// [`crypto::derive_payload_key`] takes "already-derived material, not a PIN"
/// and says explicitly that "the applet is the only thing entitled to decide
/// what that is". This is that decision, and it is **not** the one
/// `crypto.rs`'s own wording suggests:
///
/// ```text
/// pin_secret = SHA-256("fapico2/fido/keyregion/pin/v1" ‖ device_random)
/// ```
///
/// **Device-rooted, not PIN-gated — deliberately, and at a cost this states.**
///
/// The alternative is to mix in the PIN verifier, which `crypto.rs` describes as
/// the point ("the region is secured by 'something the user's PIN unlocked'").
/// It was the first implementation here, and it is **wrong for this device**,
/// for a reason that is about data rather than about cryptography:
///
/// > `pin_hash` is `None` on a PIN-less device. A secret derived from it is
/// > therefore *different* after the user sets a PIN — so **every credential
/// > enrolled before that moment becomes unreadable**, permanently, and the
/// > record bodies stay on the part consuming slots.
///
/// That is the failure mode `AGENTS.md` §5 names from the other end: "a design
/// that is maximally secure and stores four keys is not secure, it is broken".
/// Re-keying the region on `setPIN` would fix it, and is a separate story with
/// its own transaction (it is a **whole-region rewrite**: every record sealed
/// under the old key, with a power cut mid-way leaving some credentials under
/// one key and some under the other). Shipping the PIN-gated derivation without
/// that transaction would trade a real security property for a data-loss bug,
/// which is the trade `AGENTS.md` §5 tells you not to make.
///
/// **What is given up, named as the brief requires.** An attacker holding the
/// **OTP row and the chipid** — the same material `store_v3::derive_store_key`
/// takes — can derive this secret and read every credential record. That is not
/// a new exposure: the snapshot backend seals its credential fields under
/// `snapshot_crypt::field_key(store_key)`, and `store_key` **is**
/// `derive_store_key(OTP ‖ chipid)`. So this is **parity with the backend being
/// replaced**, not a weakening of it, and the honest summary is that per-record
/// storage does not change what a full-OTP attacker can read.
///
/// The **index key** is the half that does not depend on this: it is
/// OTP-rooted and PIN-free either way, so a user who has forgotten their PIN can
/// still be told which slots hold records — which is the property `index.rs`
/// exists for and the one this derivation does not give up.
///
/// **The label** is namespaced like every other HKDF label in the tree
/// (`crypto.rs`'s label table), so it cannot collide with one of those, and the
/// device_random it mixes is the TRNG draw the snapshot already persists in its
/// sealed auth map (key 5) — so it is available on every boot with no new state.
pub fn region_pin_secret(_pin_state: &DevicePinState, device_random: &[u8; 32]) -> [u8; 32] {
    const INFO: &[u8] = b"fapico2/fido/keyregion/pin/v1";
    let mut input: HeaplessVec<u8, 64> = HeaplessVec::new();
    input.extend_from_slice(INFO).ok();
    input.extend_from_slice(device_random).ok();
    let mut out = [0u8; 32];
    crate::crypto::hkdf_sha256(None, input.as_slice(), INFO, &mut out);
    out
}

/// What one region-backed signature-counter bump produced.
///
/// US-1562, and the three answers are not one answer with a `bool` bolted on.
/// `DeviceKeystore::bump_credential_counter_checked` (crate-private) collapses
/// the same three
/// into "the counter to sign", because a snapshot persist either rewrites the
/// whole image or does not — there is no in-between to report. A **per-record**
/// write has one: a flush writes several records, so the record this assertion
/// is about may be durable, or may not have been reached before a later record
/// failed. A caller that only saw `u32` would sign a value it could not tell
/// from one the flash had just refused.
///
/// `Reverted` is the SOAK-FINDING-1 arm: the bump is undone and the reply signs
/// what the window held before the command, so a sick flash never lets the
/// device sign a counter it has not committed. `Unreadable` is the only arm a
/// caller must refuse on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionCounterBump {
    /// Sign `counter`: the window is still open, so this value is in RAM only.
    Batched(u32),
    /// Sign `counter`: the window closed and the record is now in the region, so
    /// the value survives a power cut without a restore.
    Durable(u32),
    /// Sign `counter`: the durable write failed and the bump was rolled back, so
    /// this is the value the window held **before** this command — on a restored
    /// session, the granted restore base rather than the raw durable one.
    Reverted(u32),
    /// The credential's record could not be read: absent, a tombstone, or a
    /// flash fault. The caller must refuse the command rather than sign.
    Unreadable,
}

/// [`RegionCredentials::raise_counter`]'s three outcomes, before they are
/// widened into [`RegionCounterBump`].
///
/// Separate only so that the *primitive* ([`RegionCredentials::bump_counter`],
/// which US-1561's caller holds) and the *applet seam*
/// ([`RegionCredentials::bump_credential_counter`], which US-1562 added) share one
/// implementation of the rollback rather than two that could disagree.
enum Raise {
    /// Recorded in the window, not yet written.
    Signed(u32),
    /// Recorded **and** written.
    Durable(u32),
    /// The write failed and the window was rolled back to this value.
    RolledBack(u32),
}

/// The region-backed credential store: one sealed record per credential.
///
/// # Why this exists at all
///
/// `DeviceKeystore::credentials` is a resident
/// `HeaplessVec<DeviceCredential, 12>` — 12 × 720 B = **8,640 bytes of `.bss`**
/// and a ceiling of twelve, against a derived region capacity of
/// [`FIDO_CAPACITY`] (**856**). Resizing that array to the capacity is
/// arithmetically impossible: 856 × 720 = 616 KB against 532 KB of RAM on the
/// part. This type is the other shape — nothing resident, one credential
/// decrypted at a time into the caller's [`CredentialWindow`] — and it is what
/// makes the capacity reachable at all.
///
/// # Why it holds no cache
///
/// Deliberately stateless, for the reason `fido_store.rs`'s module docs give:
/// a store with an in-RAM copy of what is on the medium is a store that can
/// latch dirty state, and SOAK-FINDING-1's `stored` arm is exactly that latch.
/// There is nothing here to keep in step with the region because there is
/// nothing here.
///
/// # Keys
///
/// [`RegionKeys`] is derived per operation and dropped with it. The index key is
/// OTP-rooted and PIN-free, so credMgmt can *enumerate* a device the owner has
/// forgotten the PIN for; the payload key is PIN-derived, so opening one is not
/// possible without it. A caller holding only the index key learns which slots
/// hold records and nothing about what is in them.
pub struct RegionCredentials<'a, 'k> {
    store: FidoRecordStore<'a>,
    keys: &'k RegionKeys,
}

impl<'a, 'k> RegionCredentials<'a, 'k> {
    /// Wrap a region with the keys to seal and open its records.
    ///
    /// **Reads nothing.** No discovery scan, no `recover`, no index probe: S8/S9
    /// forbid the boot path from touching the key region, and a constructor is
    /// the sort of thing a boot path calls. The first read happens in the first
    /// operation, which is after `RUNG_USB`.
    ///
    /// The keys are **borrowed**, not taken, so one derivation serves a whole
    /// command — `RegionKeys` is deliberately not `Clone` and not `Copy`
    /// (`crypto.rs`: "a `Clone` on a key type is the first step of a key that
    /// ends up in a `static`"), so taking them by value would force a fresh
    /// derivation per record rather than per operation.
    pub fn new(region: &'a mut dyn KeyRegion, keys: &'k RegionKeys) -> Self {
        RegionCredentials { store: FidoRecordStore::new(region), keys }
    }

    /// How many FIDO credentials this region holds: [`FIDO_CAPACITY`].
    ///
    /// A re-export of [`FidoRecordStore::capacity`] so a caller holding this
    /// type does not have to name the store to ask the one number the credMgmt
    /// reply is about.
    pub const fn capacity() -> u32 {
        FIDO_CAPACITY
    }

    /// Store one credential: a sealed record, then an index entry for it.
    ///
    /// The order is [`FidoRecordStore::put`]'s, and the reason is in its docs:
    /// a record with no entry is merely *unfindable*, while an entry naming a
    /// slot with no record reads as a credential that is not one.
    ///
    /// `nonce` is this method's caller to supply. The store deliberately does
    /// not derive one (`record::seal`'s docs: a module holding no key has no
    /// business choosing a GCM nonce), and the applet has a TRNG pool to draw
    /// from — a **fresh draw per write**, which is stronger than the
    /// content-derived nonce `crypto::record_nonce` would give and costs one
    /// pool draw.
    pub fn put(
        &mut self,
        nonce: &[u8; record::NONCE_LEN],
        cred: &DeviceCredential,
    ) -> Result<fido_store::PutReport, RegionCredentialError> {
        let body = credential_record_body(cred).ok_or(RegionCredentialError::Malformed)?;
        let rp_hash = RpIdHash::from_bytes(cred.rp_id_hash);
        self.store
            .put(&self.keys.payload, &self.keys.index, nonce, &rp_hash, body.as_slice())
            .map_err(map_store_error)
    }

    /// Load the credential of `rp_id_hash` whose ID is `credential_id`, into
    /// `out`.
    ///
    /// `rp_id_hash: None` searches **every** FIDO entry. A browser's credential
    /// ID begins with the RP's `rp_id_hash` (CTAP 2.1 §5.8.3), so a caller that
    /// has one should pass it — and passing it costs the store one index
    /// comparison per entry instead of one AEAD per entry.
    ///
    /// Costs `candidates + 1` AEAD operations: the index cannot answer a
    /// by-ID query alone because it stores no credential ID (`fido_store.rs`,
    /// `CredentialIdLocator`'s docs), so each candidate is opened once to
    /// identify it and the winner is then loaded. `out` is cleared first and on
    /// drop ([`CredentialWindow`]), so a failed lookup cannot serve the previous
    /// operation's credential.
    pub fn load_by_id(
        &mut self,
        rp_id_hash: Option<&[u8; 32]>,
        credential_id: &[u8],
        out: &mut CredentialWindow,
    ) -> SlotRead<()> {
        let hash = rp_id_hash.map(|h| RpIdHash::from_bytes(*h));
        let probe = CredentialIdProbe { credential_id };
        drop_hit(self.store.load_by_credential_id(
            &self.keys.payload,
            &self.keys.index,
            hash.as_ref(),
            credential_id,
            &probe,
            out,
        ))
        // The window now holds the record's bytes. Whether they are a
        // *credential* is a second, separate question — a tombstone opens
        // fine and is not a credential — and it is answered by
        // `credential_from_record_body` at the call site. Reporting `Present`
        // here and letting the caller decode is what keeps one fail-closed
        // composition (`on_demand::load`) from being reassembled at a fourth
        // call site (`record.rs`'s rule).
    }

    /// US-1562: [`Self::load_by_id`] **and the slot the record occupies**.
    ///
    /// The same single `on_demand::load` composition and the same cost — it
    /// keeps the store's [`on_demand::OnDemandHit`] instead of dropping it — and
    /// it exists because a signature-counter bump is addressed by slot
    /// ([`Self::bump_credential_counter`]) while a credential is looked up by
    /// ID. Asking for the slot separately would be a **second** index walk and a
    /// second round of AEAD probes to learn a number the first lookup had
    /// already computed, and the two walks could disagree about a slot that had
    /// been compacted in between.
    ///
    /// **The slot is the answer only for a record that is really a credential.**
    /// A tombstone opens fine and is not one, so this says `Present` and lets the
    /// caller decode — the same division of labour [`Self::load_by_id`] keeps.
    pub fn load_by_id_at(
        &mut self,
        rp_id_hash: Option<&[u8; 32]>,
        credential_id: &[u8],
        out: &mut CredentialWindow,
    ) -> SlotRead<Slot> {
        let hash = rp_id_hash.map(|h| RpIdHash::from_bytes(*h));
        let probe = CredentialIdProbe { credential_id };
        match self.store.load_by_credential_id(
            &self.keys.payload,
            &self.keys.index,
            hash.as_ref(),
            credential_id,
            &probe,
            out,
        ) {
            SlotRead::Present(hit) => SlotRead::Present(hit.slot()),
            SlotRead::Absent => SlotRead::Absent,
            SlotRead::Fault(why) => SlotRead::Fault(why),
        }
    }

    /// Load one credential of one RP into `out`, addressed by RP alone.
    ///
    /// The discovery form — "does this site have anything here?" — which is what
    /// a resident-credential `getAssertion` asks when the client sends no
    /// allowList. Answers with the index's choice of one; use
    /// [`Self::load_by_id`] when the credential ID is known.
    pub fn load_by_rp(
        &mut self,
        rp_id_hash: &[u8; 32],
        out: &mut CredentialWindow,
    ) -> SlotRead<()> {
        let hash = RpIdHash::from_bytes(*rp_id_hash);
        drop_hit(self.store.load_by_rp(&self.keys.payload, &self.keys.index, &hash, out))
    }

    /// Delete the credential with ID `credential_id`: a tombstone commit, then
    /// the index entries naming its slot are cleared.
    ///
    /// `None` when no live credential has that ID. The tombstone half is
    /// `fido_store`'s (`TOMBSTONE_BODY`, and `commit.rs`'s reason for having no
    /// single-slot delete); the index half matters just as much, because an
    /// entry left behind is a credential every enumeration still returns.
    ///
    /// **The slot stays occupied until [`Self::compact`] runs.** A tombstone is a
    /// record, so the allocator will not hand it out — the deliberate
    /// consequence of `commit.rs` refusing an erased target. Callers that care
    /// about capacity call `compact` after the delete; `remaining_capacity` is
    /// the number that tells them whether they need to.
    pub fn delete(
        &mut self,
        nonce: &[u8; record::NONCE_LEN],
        credential_id: &[u8],
    ) -> Result<fido_store::DeleteReport, RegionCredentialError> {
        let slot = self.find_slot(credential_id)?;
        self.store.delete(&self.keys.payload, slot, nonce).map_err(map_store_error)
    }

    /// Free the slots of `sector` that hold tombstones.
    ///
    /// The second half of the delete story, and the half that makes the freed
    /// capacity reachable: a tombstone is a record, so its slot is off the free
    /// list until this rewrites the sector without it. See
    /// [`FidoRecordStore::compact`] for why a sector rewrite is the right shape
    /// here and why no cut point can lose a credential.
    pub fn compact(&mut self, sector: Slot) -> Result<fido_store::CompactionReport, RegionCredentialError> {
        self.store.compact(&self.keys.payload, sector).map_err(map_store_error)
    }

    /// US-1561: the counter the record in `slot` carries right now — durable or
    /// batched.
    ///
    /// The pending value is consulted first because it is the one the region does
    /// **not** have yet, and a caller that read the durable value after a bump
    /// would hand back a number the device has already signed past — which is
    /// the shape of a clone-detection failure even though no signature repeats.
    pub fn counter_value(
        &mut self,
        window: &CounterWindow,
        slot: Slot,
    ) -> Result<u32, RegionCredentialError> {
        if let Some(pending) = window.pending_value(slot) {
            return Ok(pending);
        }
        self.read_counter(slot)
    }

    /// The counter the **durable** record in `slot` carries, with no pending
    /// window consulted.
    ///
    /// Split out from [`Self::counter_value`] because a caller that has just
    /// written a counter — or that is deliberately about to be handed the
    /// pre-bump value on a failed write — must be able to say "what is actually
    /// in the region" without the window answering for it.
    pub fn durable_counter(&mut self, slot: Slot) -> Result<u32, RegionCredentialError> {
        self.read_counter(slot)
    }

    /// US-1561: make one record's counter durable.
    ///
    /// The only place a counter write touches the medium. It is
    /// [`fido_store::FidoRecordStore::update`] run against a slot the caller
    /// already names — a record commit plus the index rewrite that follows it —
    /// and that function's docs give the order, the generation rule and the
    /// fault window. What is added here is the **read-modify-write**: the record
    /// is opened, its counter replaced, and the applet's own codec
    /// ([`credential_record_body`]) re-encodes it.
    ///
    /// Re-encoding rather than patching in place, because the record body is a
    /// CBOR map and a counter is not at a fixed offset in it — `push_uint`
    /// re-chooses the encoding width when the value grows past a byte. The bytes
    /// that come back out are the bytes that go in, because both ends are the
    /// applet's codec and not a second layout to keep in step
    /// (`AGENTS.md` §5).
    ///
    /// A tombstone reaches here as [`RegionCredentialError::Malformed`]: the
    /// tombstone body is one byte and does not decode as a credential, so a
    /// counter write cannot resurrect a deleted one.
    pub fn write_counter(
        &mut self,
        nonce: &[u8; record::NONCE_LEN],
        slot: Slot,
        counter: u32,
    ) -> Result<fido_store::PutReport, RegionCredentialError> {
        let mut buf = CredentialWindow::new();
        match self.load_slot(slot, &mut buf) {
            SlotRead::Present(()) => {}
            SlotRead::Absent => return Err(RegionCredentialError::NoSuchCredential),
            SlotRead::Fault(why) => return Err(RegionCredentialError::Unreachable(why)),
        }
        let mut cred =
            credential_from_record_body(buf.as_slice()).ok_or(RegionCredentialError::Malformed)?;
        cred.counter = counter;
        let body = credential_record_body(&cred).ok_or(RegionCredentialError::Malformed)?;
        let rp_hash = RpIdHash::from_bytes(cred.rp_id_hash);
        self.store
            .update(&self.keys.payload, &self.keys.index, slot, nonce, &rp_hash, body.as_slice())
            .map_err(map_store_error)
    }

    /// US-1561: bump `slot`'s signature counter, batching the durable write.
    ///
    /// `current` is the counter the applet holds — what
    /// [`Self::counter_value`] returned, which is the **pending** value when
    /// the window has one and the durable value otherwise.
    ///
    /// **The restore slack is applied inside this function, not by the caller.**
    /// A caller passing `durable + W` by hand would be one forgotten line away
    /// from signing a `signCount` the client has already seen, and every other
    /// assertion in the story would still pass; see
    /// [`CounterWindow::resume_base`] for the whole argument. The applet's job
    /// is to read the record and pass it here.
    ///
    /// Returns the counter the reply must sign. **It is not the durable counter
    /// until the window closes** — the weakening US-1011 made, in a store whose
    /// write pattern has since changed shape and whose divisor has been
    /// re-derived (`docs/erase-budget.md` §4c).
    ///
    /// **US-1562: a durable write that fails is answered, not propagated.** The
    /// window is rolled back and the value it held *before* this call is
    /// returned, which is SOAK-FINDING-1's discipline and the mirror of
    /// `DeviceKeystore::bump_credential_counter_checked`'s revert arm. The
    /// [`Err`] this can still return is the unreachable "the window could not
    /// hold the write" case below, which is a defect rather than a medium
    /// failure. Callers that want to *tell* the two apart use
    /// [`Self::bump_credential_counter`].
    ///
    /// `next_nonce` supplies a fresh GCM nonce per durable write. The store does
    /// not derive one (`record::seal`'s docs: a module holding no key has no
    /// business choosing a nonce), and a repeated nonce under one key is
    /// catastrophic for GCM; on the device this is one draw from the applet's
    /// TRNG pool.
    pub fn bump_counter(
        &mut self,
        window: &mut CounterWindow,
        slot: Slot,
        current: u32,
        next_nonce: &mut dyn FnMut() -> [u8; record::NONCE_LEN],
    ) -> Result<u32, RegionCredentialError> {
        match self.raise_counter(window, slot, current, next_nonce)? {
            Raise::Signed(next) | Raise::Durable(next) => Ok(next),
            Raise::RolledBack(previous) => Ok(previous),
        }
    }

    /// US-1562: the bump an assertion or a U2F authenticate needs, addressed by
    /// slot and answering all three outcomes distinctly.
    ///
    /// [`Self::bump_counter`] collapses them, which is right for its own
    /// "return the counter to sign" contract and wrong for a caller that has to
    /// decide whether to serve the assertion at all. The three are genuinely
    /// different: `Batched` is a value the device has signed but not written,
    /// `Durable` is one it can rebuild from the region alone, and `Reverted` is
    /// one the flash refused. Only `Unreadable` refuses the command, and it is
    /// the only one — `build_assertion`'s applet-side caller maps it to
    /// `CTAP2_ERR_NO_CREDENTIALS` exactly as it already did when the bump
    /// resolved the credential out of the snapshot.
    ///
    /// The read that precedes the bump is a genuine three-state question
    /// ([`Self::counter_value`]'s own docs), so a faulted region is `Unreadable`
    /// rather than a silently wrong counter.
    pub fn bump_credential_counter(
        &mut self,
        window: &mut CounterWindow,
        slot: Slot,
        next_nonce: &mut dyn FnMut() -> [u8; record::NONCE_LEN],
    ) -> RegionCounterBump {
        let current = match self.counter_value(window, slot) {
            Ok(current) => current,
            Err(_) => return RegionCounterBump::Unreadable,
        };
        match self.raise_counter(window, slot, current, next_nonce) {
            Ok(Raise::Signed(next)) => RegionCounterBump::Batched(next),
            Ok(Raise::Durable(next)) => RegionCounterBump::Durable(next),
            // SOAK-FINDING-1: the write failed, the window was rolled back, and
            // the reply signs what the window held before this command. The
            // flash error is deliberately not surfaced — `docs` on the snapshot
            // arm says the same thing, and the two backends disagreeing about
            // what a sick store means is the failure `AGENTS.md` §5's "one
            // record format" rule exists to prevent.
            Ok(Raise::RolledBack(previous)) => RegionCounterBump::Reverted(previous),
            Err(_) => RegionCounterBump::Unreadable,
        }
    }

    /// Raise `slot`'s value in the window, writing the window down when it is
    /// due, and say which of the three outcomes happened.
    ///
    /// The one place the region's batching rules live; [`Self::bump_counter`]
    /// and [`Self::bump_credential_counter`] are the two shapes callers hold it
    /// in, so the rollback that SOAK-FINDING-1 requires cannot be implemented
    /// by one caller and forgotten by the other.
    fn raise_counter(
        &mut self,
        window: &mut CounterWindow,
        slot: Slot,
        current: u32,
        next_nonce: &mut dyn FnMut() -> [u8; record::NONCE_LEN],
    ) -> Result<Raise, RegionCredentialError> {
        // A full pending list is the only way `record` refuses, and a flush
        // empties it — so flushing *before* the record is what makes the refusal
        // unreachable rather than merely unlikely.
        //
        // A flush that fails here is answered the same way a failure below is:
        // nothing of this command's has been recorded yet, so the reply signs
        // what the window already held and the next assertion retries.
        if window.pending_full() && self.flush_counters(window, next_nonce).is_err() {
            return Ok(Raise::RolledBack(Self::held_value(window, slot, current)));
        }
        // **Read the base after the flush above**, because the flush empties the
        // pending list and `pending_value` is where an in-flight session's own
        // newest value lives.
        let pre = window.pending_value(slot).unwrap_or_else(|| window.resume_base(slot, current));
        let base = pre.saturating_add(1);
        if !window.record(slot, base) {
            // Unreachable — the list was just emptied or had room. Reported
            // rather than swallowed, because the alternative is signing `base`
            // without recording it, and the next bump would then read a *lower*
            // durable value and sign a repeat.
            return Err(RegionCredentialError::Unreachable(
                "fido: the counter window could not hold the pending write",
            ));
        }
        if !window.should_flush() {
            return Ok(Raise::Signed(base));
        }
        if self.flush_counters(window, next_nonce).is_err() {
            // The durable write failed. If this slot's entry is **still** pending
            // then the flush never reached it, so the region still holds `pre`
            // and the bump is undone; if it is not pending the flush wrote it
            // before failing on a later record, so the durable value is `base`
            // and there is nothing to undo. `flush_counters` drops entries one
            // at a time on success, so this test is exact rather than a guess.
            if window.pending_value(slot) == Some(base) {
                window.restore_pending(slot, pre);
                return Ok(Raise::RolledBack(pre));
            }
            return Ok(Raise::Durable(base));
        }
        Ok(Raise::Durable(base))
    }

    /// What `slot` holds when the window has nothing pending for it: the
    /// restore-granted value, which is `current` on a session that did not begin
    /// as a restore and [`CounterWindow::resume_from`] of it on one that did.
    ///
    /// A separate accessor because the rollback answer is *not* `current` on a
    /// restored session: signing the raw durable value there would sign a number
    /// the cut-away session already signed, which is the clone-detection repeat
    /// US-1012's grant exists to avoid. The grant is memoised in the window, so
    /// calling this on the error path spends nothing the next bump needs.
    fn held_value(window: &mut CounterWindow, slot: Slot, current: u32) -> u32 {
        window.pending_value(slot).unwrap_or_else(|| window.resume_base(slot, current))
    }

    /// US-1561: make every batched counter durable, and report how many records
    /// were written.
    ///
    /// **Entries are dropped one at a time, on success**, so a write that fails
    /// part-way leaves the rest pending and the next flush retries them. A flush
    /// that cleared the window up front and then failed would drop counters the
    /// device had already signed — the same lost-update shape SOAK-FINDING-1 is
    /// about, in a store that keeps none of the state in RAM to be lost.
    ///
    /// An **empty** flush writes nothing and does not close the window. A
    /// restore arrives with an already-spent window and no pending entries, and
    /// zeroing the budget there would spend the restore's whole guarantee on
    /// nothing: the first assertion after the power-on would then ride in RAM
    /// exactly like the thirty-first, which is the repeat US-1012 rules out.
    pub fn flush_counters(
        &mut self,
        window: &mut CounterWindow,
        next_nonce: &mut dyn FnMut() -> [u8; record::NONCE_LEN],
    ) -> Result<u32, RegionCredentialError> {
        let mut written = 0u32;
        // No `at += 1`: `commit_pending(at)` removes the entry, so the next
        // pending record shifts down into the slot just vacated.
        let at = 0usize;
        while at < window.pending_len() {
            let (slot, counter) = window.pending()[at];
            self.write_counter(&next_nonce(), slot, counter)?;
            window.commit_pending(at);
            written += 1;
        }
        if written > 0 {
            window.note_durable_write();
        }
        Ok(written)
    }

    /// Open `slot` and answer with its durable counter.
    fn read_counter(&mut self, slot: Slot) -> Result<u32, RegionCredentialError> {
        let mut buf = CredentialWindow::new();
        match self.load_slot(slot, &mut buf) {
            SlotRead::Present(()) => {}
            SlotRead::Absent => return Err(RegionCredentialError::NoSuchCredential),
            SlotRead::Fault(why) => return Err(RegionCredentialError::Unreachable(why)),
        }
        credential_from_record_body(buf.as_slice())
            .map(|c| c.counter)
            .ok_or(RegionCredentialError::Malformed)
    }

    /// How many FIDO index entries the region holds.
    ///
    /// The count `remainingDiscoverableCredentialsCount` is derived from — see
    /// [`Self::remaining`] for why the *index* and not the records is the right
    /// thing to count.
    pub fn used(&mut self) -> Option<u32> {
        match self.store.fido_entries() {
            SlotRead::Present(n) => Some(n),
            SlotRead::Absent | SlotRead::Fault(_) => None,
        }
    }

    /// How many more credentials this region can take, or `None` when the index
    /// could not be read.
    ///
    /// `None` rather than `0` on a fault, and that distinction is the point:
    /// reporting `0` would refuse an enrolment with a claim about capacity the
    /// device never established, which is the wire-claim defect `AGENTS.md` §4 is
    /// about.
    pub fn remaining(&mut self) -> Option<u32> {
        self.store.remaining_capacity()
    }

    /// The slots holding one RP's credentials, appended to `out`.
    ///
    /// **Index slots only** — no payload key is in this signature, so there is
    /// nowhere for one to arrive. This is the enumeration a credMgmt
    /// `enumerateCredsBegin` walks and the candidate list a `getAssertion`
    /// builds, and it is what makes credMgmt a *PIN-gated* enumeration: the
    /// slots come from the index, the credential bodies are opened one at a time
    /// by the caller.
    pub fn slots_for_rp(&mut self, rp_id_hash: &[u8; 32], out: &mut [Slot]) -> Option<usize> {
        let hash = RpIdHash::from_bytes(*rp_id_hash);
        match self.store.slots_for_rp(&self.keys.index, &hash, out) {
            SlotRead::Present(n) => Some(n),
            SlotRead::Absent | SlotRead::Fault(_) => None,
        }
    }

    /// The slot of the `n`-th FIDO index entry, in index order.
    ///
    /// **A cursor, not a materialised list.** credMgmt's `enumerateRPs` has to
    /// walk every credential the device holds, and at 856 credentials a
    /// `Vec<Slot>` of them is 1.7 KB — on a task frame that already carries an
    /// 836-byte `CredentialWindow`. Walking the index one entry at a time and
    /// keeping one `Slot` is the same reason `index::walk_present` streams a
    /// single 1 KiB image (`index.rs`, "Why the entry is 32 bytes").
    ///
    /// `None` past the last entry **and** for a region that cannot be read —
    /// the same `Option`, deliberately, because the caller's loop treats both as
    /// "stop" and inventing a third state here would only be discarded at the
    /// call site. A caller that must distinguish them uses
    /// [`Self::inspect_index`](FidoRecordStore::inspect_index), which is the
    /// operation that reports a fault.
    ///
    /// O(n) per call, so a full walk is O(n²) index reads. That is the honest
    /// cost of a stateless store: caching the cursor across commands is exactly
    /// the resident state `fido_store.rs` refuses to keep, and a 32 KiB index
    /// materialised in RAM is more than six times the boot stack
    /// (`index.rs`, "Bounded and fixed is a boot-path constraint").
    pub fn nth_entry_slot(&mut self, n: u32) -> Option<Slot> {
        let mut seen = 0u32;
        let mut ordinal = 0u32;
        while ordinal < fapico2_platform::keyregion::index::index_capacity() {
            let slot = fapico2_platform::keyregion::index::entry_slot(ordinal)?;
            let raw = self.store.region().read_slot(slot).ok()?;
            let at = fapico2_platform::keyregion::index::entry_offset(ordinal) as usize;
            let cell = &raw[at..at + fapico2_platform::keyregion::index::INDEX_ENTRY_BYTES];
            if let SlotRead::Present(entry) =
                fapico2_platform::keyregion::index::IndexEntry::decode(cell)
            {
                if entry.domain() == fapico2_platform::keyregion::crypto::KeyDomain::Fido {
                    if seen == n {
                        return Some(entry.slot());
                    }
                    seen += 1;
                }
            }
            ordinal += 1;
        }
        None
    }

    /// Open the record in `slot` into `out`, without consulting the index.
    ///
    /// The enumeration's inner step: credMgmt already knows the slot from the
    /// index walk, so re-deriving it from a credential ID would cost a second
    /// index pass for no answer. `Absent` covers the tombstone case the same way
    /// it covers a corrupt record — one bad record costs itself alone.
    pub fn load_slot(&mut self, slot: Slot, out: &mut CredentialWindow) -> SlotRead<()> {
        drop_hit(on_demand::load(
            self.store.region(),
            &mut DirectLocator { slot },
            &self.keys.payload,
            &SlotQuery::RpIdTag { tag: &[0u8; on_demand::RP_ID_TAG_LEN] },
            out,
        ))
    }

    /// Is a credential with ID `credential_id` already in the region?
    ///
    /// **The idempotence check the migration needs, and nothing else.**
    /// [`migrate_snapshot_to_region`] asks this before every write so a re-run
    /// after an interrupted migration does not put a second record and a second
    /// index entry for a credential that is already durable — which is what
    /// would make a passkey enumerate twice and assert against either copy.
    ///
    /// It delegates to the store's own [`CredentialIdLocator`] through
    /// [`on_demand::load`], deliberately rather than walking the index here: a
    /// second walk would be a second definition of "which slots hold this
    /// credential", and the two could disagree about a tombstone or a corrupt
    /// record (`AGENTS.md` §5).
    ///
    /// Cost is `candidates + 1` AEAD operations — the same price
    /// [`Self::load_by_id`] pays, and the index cannot answer a by-ID query
    /// alone because it stores no credential ID (`fido_store.rs`,
    /// `CredentialIdLocator`'s docs). Bounded in practice by the migration
    /// having at most [`SNAPSHOT_MAX_CREDS`] credentials to ask about.
    ///
    /// Three states, and the caller must keep them apart: `Present(false)` means
    /// "looked, and it is not there" — safe to write; `Fault` means the region
    /// could not be read, and writing over it could destroy a credential that
    /// is really there, so it must **not** be read as `false`
    /// (`mod.rs`'s [`SlotRead`]).
    pub fn contains_credential(&mut self, credential_id: &[u8]) -> SlotRead<bool> {
        let probe = CredentialIdProbe { credential_id };
        let mut locator =
            fido_store::CredentialIdLocator::new(
                &self.keys.index,
                &self.keys.payload,
                None,
                credential_id,
                &probe,
            );
        // `on_demand::load` insists on a query even though this locator narrows
        // only by the credential ID it already holds. The same argument as
        // `load_by_id`'s: a tag-only query is the honest choice — it is the one
        // the locator will not use, and claiming otherwise would be a lie a
        // future caller could act on.
        let tag: &[u8; on_demand::RP_ID_TAG_LEN] = &[0u8; on_demand::RP_ID_TAG_LEN];
        let mut window = CredentialWindow::new();
        match on_demand::load(
            self.store.region(),
            &mut locator,
            &self.keys.payload,
            &SlotQuery::RpIdTag { tag },
            &mut window,
        ) {
            // A tombstone opens cleanly and `load` reports it as a hit, so a
            // deleted credential would read as present and never be migrated.
            // `is_deleted_body` is the same predicate
            // `credential_from_record_body` uses, for the same reason: the
            // answer "not present" sends the allocator somewhere new, and the
            // answer "present" would strand the snapshot's copy of this
            // credential forever. Re-enrolment, not migration, is what reclaims
            // a tombstoned slot.
            //
            // The slot itself is discarded: the answer is a yes/no, and the
            // migration never overwrites an existing slot — it lets the
            // allocator choose, so a first run and a re-run take one path.
            SlotRead::Present(_) => SlotRead::Present(!is_deleted_body(window.as_slice())),
            SlotRead::Absent => SlotRead::Present(false),
            SlotRead::Fault(why) => SlotRead::Fault(why),
        }
    }

    /// The slot holding the credential with ID `credential_id`.
    ///
    /// # Why a locator and not a scan of this module's own
    ///
    /// The store already owns "find a credential by its ID": `CredentialIdLocator`
    /// narrows by RP through the index and then opens candidates, and its docs
    /// say so. Re-implementing that walk here would be a second definition of
    /// the same lookup, which is the defect `AGENTS.md` §5 names twice over. So
    /// this borrows it — and pays `candidates + 1` AEAD operations for it, which
    /// is the price the store's docs state for a query the index cannot answer
    /// alone.
    ///
    /// # The window is a scratch buffer, not a result
    ///
    /// It exists because [`on_demand::load`] needs somewhere to put the record it
    /// opens, and it is dropped — zeroized by `CredentialWindow::drop` — before
    /// this returns. The caller gets a **slot number**, not a credential, so a
    /// delete never needs the plaintext and the private key never sits in a
    /// buffer across a sector erase.
    fn find_slot(&mut self, credential_id: &[u8]) -> Result<Slot, RegionCredentialError> {
        let probe = CredentialIdProbe { credential_id };
        let mut locator = fido_store::CredentialIdLocator::new(
            &self.keys.index,
            &self.keys.payload,
            None,
            credential_id,
            &probe,
        );
        let mut window = CredentialWindow::new();
        let tag = &[0u8; on_demand::RP_ID_TAG_LEN];
        match on_demand::load(
            self.store.region(),
            &mut locator,
            &self.keys.payload,
            &SlotQuery::RpIdTag { tag },
            &mut window,
        ) {
            SlotRead::Present(hit) => Ok(hit.slot()),
            SlotRead::Absent => Err(RegionCredentialError::NoSuchCredential),
            SlotRead::Fault(why) => Err(RegionCredentialError::Unreachable(why)),
        }
    }
}

/// A [`SlotLocator`] that answers one known slot.
///
/// The enumeration's locator: credMgmt already holds the slot from its index
/// walk, so this exists so `load_slot` goes through
/// [`on_demand::load`] — the composed fail-closed path, with its `out`-cleared
/// first guarantee and its one-decryption property — rather than reassembling
/// `record::decode` plus `record::open` at a fourth call site (`record.rs`'s
/// standing rule).
struct DirectLocator {
    slot: Slot,
}

impl on_demand::SlotLocator for DirectLocator {
    fn locate(&mut self, _region: &mut dyn KeyRegion, _want: &SlotQuery<'_>) -> on_demand::Located {
        on_demand::Located::Found(self.slot)
    }
}

/// Discard a [`SlotRead`]'s payload, keeping its three states.
///
/// One function rather than three `match`es at the call sites, and the reason
/// it exists is the one `SlotRead`'s own docs warn about: **a caller that
/// collapses `Fault` into `Absent` memoizes a transport failure as a decided
/// fact.** Written once, the collapse is visible in one place instead of three,
/// and there is no arm here that turns a `Fault` into "no such credential".
fn drop_hit(outcome: SlotRead<on_demand::OnDemandHit>) -> SlotRead<()> {
    match outcome {
        SlotRead::Present(_) => SlotRead::Present(()),
        SlotRead::Absent => SlotRead::Absent,
        SlotRead::Fault(why) => SlotRead::Fault(why),
    }
}

/// Translate a store error into the applet's three-state vocabulary.
///
/// **One mapping, in one place**, because the alternative is each call site
/// deciding what "the region is full" and "the region is sick" mean, and getting
/// them differently — which is how `KeyStoreFull` (0x28, a capacity statement)
/// ends up being returned for a flash that is merely failing.
fn map_store_error(e: fido_store::FidoStoreError) -> RegionCredentialError {
    match e {
        fido_store::FidoStoreError::Full | fido_store::FidoStoreError::IndexFull => {
            RegionCredentialError::Full
        }
        fido_store::FidoStoreError::CredentialTooLarge { len, max } => {
            RegionCredentialError::TooLarge { len, max }
        }
        fido_store::FidoStoreError::RegionUnreadable(why)
        | fido_store::FidoStoreError::IndexUnreadable(why)
        | fido_store::FidoStoreError::Commit(CommitError::Flash { reason: why, .. }) => {
            RegionCredentialError::Unreachable(why)
        }
        other => RegionCredentialError::Store(other),
    }
}

// ---------------------------------------------------------------------------
// US-1558 — migrating a snapshot into records
// ---------------------------------------------------------------------------

/// What one [`migrate_snapshot_to_region`] did.
///
/// # Why this is a report and not a `Result`
///
/// The gherkin's obligations are *"every credential is written"* and *"each
/// snapshot slot is retired only after every record is durable"*. A failure to
/// write one record is not an error the caller should surface to a user as a
/// fault: the device still answers every command, from the snapshot, exactly as
/// it did before the migration ran. So the failure is a **state the migration
/// rests in** ([`Self::Deferred`]) rather than a `Result` an applet might treat
/// as fatal — which is S10's "degrade, never halt" in the shape this story
/// actually needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MigrationOutcome {
    /// The snapshot holds no credentials. This is the **steady state**, and it
    /// is what makes the snapshot itself the migration marker: an empty
    /// credential array is a statement that has been made durable by
    /// [`DeviceKeystore::retire_credentials`]'s `persist`, not a value in RAM
    /// that a power cut can undo.
    ///
    /// Cost on the steady-state path: one `len()` on a resident vector, before
    /// any region borrow is taken. Every command pays it.
    AlreadyMigrated,
    /// Every credential in the snapshot is a durable record, **and** the
    /// snapshot's credential array has been retired.
    Retired {
        /// Records written by *this* run.
        migrated: u32,
        /// Credentials that were already durable — the re-run case, below.
        already_present: u32,
        /// Credentials removed from the snapshot. Equal to
        /// `migrated + already_present` when the retirement landed.
        retired: u32,
    },
    /// The migration did not finish, and **the snapshot is intact** — so it is
    /// still the store, and the next applet use tries again.
    ///
    /// `reason` is the transport's own `&'static str`, or
    /// [`E_NO_REGION`](crate::device_keystore::E_NO_REGION) when the region was
    /// never reachable. Neither is a panic and neither is a `fatal_boot`
    /// (S10/S11), and neither is reported to the user: the device enumerates
    /// from the snapshot and every command keeps working.
    Deferred(&'static str),
}

/// The reason string for "there is no region to migrate into".
///
/// A named constant so a log line and a test can match it, and so the
/// unreachable-region case is distinguishable from a flash that is failing.
pub const E_MIGRATION_NO_REGION: &str =
    "fido: no key region to migrate the snapshot into (not installed, or not yet released)";

/// The reason string for "there is no store to migrate out of".
///
/// The bridge dispatch path hands `process_ctap2` no `SecureStore` at all
/// (`device_app.rs`, `process_ctap2`), so there is nowhere the retirement could
/// be made durable. Migrating anyway would leave records in the region and the
/// credentials **also** in the snapshot, which is the half-applied state the
/// gherkin forbids.
pub const E_MIGRATION_NO_STORE: &str =
    "fido: no secure store to retire the snapshot from (the persist gate runs after the command)";

/// The reason string for "a record or the retirement write did not land".
///
/// Distinct from the two above because they have different fixes: this one
/// means the medium refused, and the next applet use retries the whole run.
/// Reported, never surfaced to the user — see [`MigrationOutcome`].
pub const E_MIGRATION_STORE_FAILED: &str =
    "fido: the key region refused a record write; the snapshot is intact and still the store";

/// Write every snapshot credential into the key region as its own record, then
/// retire the snapshot's credential array — in that order.
///
/// ```gherkin
/// Scenario: a provisioned device upgrades without losing keys
///   Given a store holding a populated fido.keystore.v1 snapshot
///   When the new firmware first touches the applet after RUNG_USB
///   Then every credential is written as an individual record
///   And the snapshot slot is retired only after every record is durable
///   And an interrupted migration leaves the snapshot intact and re-runs next time
///   And a device whose OTP row is unavailable still enumerates
/// ```
///
/// # The marker is the snapshot itself
///
/// There is no separate "migrated" flag, and that is the whole design. The
/// question a restart has to answer is "were these credentials made durable as
/// records?" and the snapshot's own credential array answers it:
///
/// * **array non-empty** ⇒ not every credential is a durable record. Re-run.
/// * **array empty** ⇒ [`DeviceKeystore::retire_credentials`] wrote it that way,
///   so every record was durable *before* the write that emptied it.
///
/// A flag would need its own atomicity argument, and the argument would be the
/// same one: written *after* the last record and *before* the array is cleared,
/// it is a third thing that can be lost in a window where the array is not.
/// `AGENTS.md` §5: take the simpler one.
///
/// # "Retire only after every record is durable"
///
/// Enforced by ordering and pinned by
/// `tests/snapshot_migration.rs::the_snapshot_is_retired_only_after_the_last_record`:
/// [`RegionCredentials::put`] returns only after `commit::commit` has made the
/// record atomic and `write_index_entry` has put the entry in the index. The
/// loop below returns the moment any credential fails, so the retirement call
/// is unreachable while any credential is not durable. There is no window to
/// reason about because there is no early return and no `continue`.
///
/// # "An interrupted migration re-runs, and does not duplicate"
///
/// Re-running is not enough on its own: a migration interrupted after three of
/// twelve credentials would, naively, write all twelve again and leave two
/// records — and two index entries — naming the same credential. A device that
/// does that enumerates a passkey twice and can assert against either copy.
///
/// So each credential is **looked for before it is written**
/// ([`RegionCredentials::contains_credential`], the store's own
/// `CredentialIdLocator` — not a second walk written here). A credential
/// already in the region is counted, not re-written. That makes the whole
/// migration idempotent in the one sense that matters, and it needs no
/// per-credential progress marker: the region is the progress marker.
///
/// The cost is `SNAPSHOT_MAX_CREDS × entries` AEAD operations on a device that
/// is mid-migration, and **nothing at all** afterwards, because the steady
/// state is [`MigrationOutcome::AlreadyMigrated`] and returns before a region
/// borrow is taken. A device in the deferred state re-runs on each applet use,
/// which is bounded by the same product — and a device that cannot write a
/// record cannot write it more cheaply by waiting.
///
/// # Why this needs no PIN
///
/// `region_pin_secret`'s own docs: the payload key is **device-rooted**, mixed
/// from the `device_random` the snapshot already persists, and *not* from
/// `pin_hash`. So a credential enrolled before the user set a PIN opens under
/// the same key after, and the migration runs identically on a PIN-set and a
/// PIN-less board. Had the derivation been PIN-gated, "migrate at first applet
/// use" would have had to wait for a PIN entry that may never come.
///
/// # What it does not migrate
///
/// Only credentials. `pin_state`, `cred_counter`, `device_random`,
/// `large_blob_array`, `vault_state`, `phy` and the `0x41` vendor state stay in
/// the snapshot — they are the keystore, not the credential set, and the
/// credential array is the only thing this design moves. OATH's
/// `oath.keystore.v1` is the same story in `apps/oath`, which is not this
/// file's.
///
/// # What a caller must not do
///
/// Call this on the boot path. S8/S9 forbid the boot path from reading the
/// region at all, and `FidoApp::boot` restores the snapshot long before
/// `boot::release_key_region()` runs — the region is not even reachable there.
/// The device calls it from `process_ctap2_with_store`, which is by
/// construction after `RUNG_USB`.
pub fn migrate_snapshot_to_region(
    region: &mut dyn KeyRegion,
    keys: &RegionKeys,
    nonce: &mut dyn FnMut() -> [u8; record::NONCE_LEN],
    ks: &mut DeviceKeystore,
    store: Option<&mut dyn SecureStore>,
) -> MigrationOutcome {
    // The steady state, before anything is borrowed or read. A device past this
    // story pays one `len()` per command.
    if ks.credentials.is_empty() {
        return MigrationOutcome::AlreadyMigrated;
    }
    let Some(store) = store else {
        return MigrationOutcome::Deferred(E_MIGRATION_NO_STORE);
    };

    let mut migrated: u32 = 0;
    let mut already_present: u32 = 0;
    {
        let mut creds = RegionCredentials::new(region, keys);
        for i in 0..ks.credentials.len() {
            // Borrowed, never cloned: `DeviceCredential` is 720 B and the
            // resident array is the 8,640 B this epic exists to delete, so the
            // loop must not add a second copy of one. `credential_id` is cloned
            // only because `contains_credential` borrows it while `ks` is
            // borrowed again by `put` — 32 B, not 720.
            let credential_id = ks.credentials[i].credential_id.clone();
            match creds.contains_credential(&credential_id) {
                // Found: a previous, interrupted run already made this one
                // durable. Counting it is what makes a re-run idempotent.
                SlotRead::Present(true) => already_present += 1,
                SlotRead::Present(false) => {
                    if creds.put(&nonce(), &ks.credentials[i]).is_err() {
                        // **No retirement, and no partial application.** The
                        // snapshot is untouched — nothing above writes to it —
                        // so every credential on it is still readable through
                        // the path this device used before the migration ran.
                        return MigrationOutcome::Deferred(E_MIGRATION_STORE_FAILED);
                    }
                    migrated += 1;
                }
                // A transport failure, or a record that is there but does not
                // open. Both stop the run: the first because we do not know what
                // is durable, the second because writing a second copy of a
                // credential we cannot read is how a passkey gets enumerated
                // twice.
                SlotRead::Absent | SlotRead::Fault(_) => {
                    return MigrationOutcome::Deferred(E_MIGRATION_STORE_FAILED);
                }
            }
        }
    }

    // Every credential above returned `Ok` from `put`, which returns only after
    // the sector commit is atomic and the index entry is written. Only now is
    // the snapshot's array cleared.
    match ks.retire_credentials(store) {
        Ok(retired) => MigrationOutcome::Retired { migrated, already_present, retired },
        // The records are durable and the snapshot still holds them. That is a
        // duplicate, not a data loss, and it is resolved by the next run, which
        // finds all twelve already present and tries the retirement again.
        Err(_) => MigrationOutcome::Deferred(E_MIGRATION_STORE_FAILED),
    }
}

// ---------------------------------------------------------------------------
// Host-only observation point for the US-1550 zeroization assertion
// ---------------------------------------------------------------------------

/// Host-only hooks the device build does not have, for asserting that a
/// credential's private scalar really is cleared when the credential goes out
/// of scope.
///
/// **Why this exists, and why it is host-only.** "The private key is zeroized
/// when the credential drops" is a claim about bytes that are, by then, in
/// freed stack — there is no sound way for a test to read them back. So the
/// scalar's own [`Drop`] records what it holds, *after* clearing it, into a
/// thread-local, and the test asserts against that record. The claim under test
/// is exactly the production claim: the same `Drop` body runs on arm, where the
/// only difference is that nobody is left to read the result. This is
/// `keyregion::crypto::testing` and `fused_key::testing` restated for the
/// applet half of the store, and it exists for the same class of problem.
///
/// **Why `was_nonzero` is here and `crypto::testing` does not have it.** Without
/// it, "every recorded buffer was all zeroes" is satisfied exactly as well by a
/// [`PrivateScalar::zero`] — a template credential, a revoked one, a
/// `default()` — as by a key that was really loaded and really wiped. The applet
/// half has far more zero scalars in normal traffic than the region half has
/// zero keys, so a witness without the flag would be vacuous here more often
/// than anywhere else in the tree. `fused_key::DropWitness` is the shape to
/// copy, and `apps/fido/tests/credential_zeroize.rs` copies it.
#[cfg(not(target_arch = "arm"))]
pub mod testing {
    use core::cell::RefCell;

    /// What one dropped [`PrivateScalar`](super::PrivateScalar) held, recorded by
    /// its own `Drop` after its explicit zeroize ran.
    #[cfg(not(target_arch = "arm"))]
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub struct DroppedScalar {
        /// Whether the buffer held anything before its zeroize ran.
        ///
        /// The half that makes "it was cleared" mean anything: a scalar that
        /// was never populated would otherwise satisfy the assertion for free.
        pub was_nonzero: bool,
        /// The bytes the buffer held **after** the zeroize — expected all
        /// zeroes.
        pub bytes: [u8; super::PRIVATE_KEY_LEN],
    }

    std::thread_local! {
        /// Post-zeroize contents of every credential scalar dropped on this
        /// thread, oldest first. Thread-local so the parallel test harness
        /// gives each `#[test]` its own record.
        static DROPPED: RefCell<std::vec::Vec<DroppedScalar>> =
            const { RefCell::new(std::vec::Vec::new()) };
    }

    /// Called from [`PrivateScalar`](super::PrivateScalar)'s `Drop`, after the
    /// buffer is cleared.
    pub(super) fn record_dropped_scalar(bytes: [u8; super::PRIVATE_KEY_LEN], was_nonzero: bool) {
        DROPPED.with(|d| d.borrow_mut().push(DroppedScalar { was_nonzero, bytes }));
    }

    /// Every credential scalar dropped on this thread since the last [`clear`].
    pub fn dropped_scalars() -> std::vec::Vec<DroppedScalar> {
        DROPPED.with(|d| d.borrow().clone())
    }

    /// Forget the record, so one test cannot make the next one pass.
    pub fn clear() {
        DROPPED.with(|d| d.borrow_mut().clear());
    }
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

const _: () = {
    // The record the applet writes must be the record the region's stride was
    // sized from. `FIDO_RECORD_MAX` is measured against *this* encoding
    // (`mod.rs:52-67`), so a change to `DeviceCredential::encode` that grows a
    // credential past it has to stop the build here rather than truncate the
    // longest legitimate credential to fit — the exact failure
    // `DEVICE_MAX_CREDS = 12` was.
    assert!(
        CREDENTIAL_RECORD_MAX == FIDO_RECORD_MAX as usize,
        "the applet's record bound must be the region's measured FIDO record bound — one \
         credential, one record, one number"
    );
    // `CredentialWindow` is sized for the largest record the store can *write*,
    // so a credential that encodes to at most that fits the one buffer every
    // load goes through. If this ever fails, `credential_record_body` is
    // returning bodies no window can hold and every load fails with an error
    // indistinguishable from a corrupt record.
    assert!(
        CREDENTIAL_RECORD_MAX <= on_demand::ON_DEMAND_WINDOW_BYTES,
        "the applet's record bound must fit the on-demand window — a credential larger \
         than the window would fail to load as though it were corrupt"
    );
    // A tombstone must be distinguishable from a credential body without a
    // version byte or a magic string. `DeviceCredential::encode` always emits a
    // CBOR map header first, and CBOR major type 5 with additional information
    // 31 is the break stop code, never a map — so a one-byte 0xFF body cannot be
    // a credential. Stated so a future "shorten the tombstone" edit cannot make
    // a deleted credential decode as a broken one.
    assert!(
        TOMBSTONE_PROOF.len() == 1,
        "a FIDO tombstone is a one-byte body; anything longer could collide with a \
         credential map header"
    );
};

/// Compile-time witness that `0xFF` cannot begin a credential map.
///
/// Never evaluated and never used: its job is to make the sentence above a
/// checked statement rather than a claim. CBOR major type 5 is the map type and
/// 0xFF is major type 7 (simple value / float) with additional information 31
/// (indefinite-length "break"), which `cbor.rs`'s parser rejects outright.
const TOMBSTONE_PROOF: [u8; 1] = [0xFF];

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
            private_key: PrivateScalar::from_bytes([0x0B; 32]),
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
