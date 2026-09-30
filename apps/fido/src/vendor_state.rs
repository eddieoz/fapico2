//! US-176 (EPIC `PICOForge-COMPAT`) — the durable state the twelve
//! [`crate::vendor41::PENDING`] arms need, and the implementations of
//! [`crate::vendor41::VendorOps`] that reach it.
//!
//! This is the **Phase I foundation**: no sub-command is implemented here, and
//! [`crate::vendor41::PENDING`] still holds all twelve. What lands is the
//! storage, the codec and both command paths' implementations, so the six
//! Phase I stories (US-170 … US-175) are protocol work with the storage
//! already done.
//!
//! # Why this is a sibling module and not part of `vendor41`
//!
//! `vendor41` is the **protocol**: which sub-commands exist, what a MAC
//! covers, which gate a sub-command owes its caller, and the
//! [`crate::vendor41::VendorOps`] contract the arms program against. It has no
//! keystore and must not acquire one — see [`crate::vendor41::handle`] on why
//! US-106's `store` parameter was added and US-115 removed it.
//!
//! This module is the **storage**: a struct, a CBOR codec, and two
//! implementations of that contract over the two keystores the firmware has.
//! Keeping them apart is what lets `vendor41` stay keystore-free (so its
//! "this module decides, the dispatch arm commits" rule cannot be violated by
//! a field it happens to own) and lets the two implementations share the state
//! machine without `vendor41` importing either keystore.
//!
//! # Where the state lives: the FIDO keystore, split in two halves
//!
//! [`VendorState`] is a field of both keystores' auth maps, alongside
//! [`crate::vendorff::PhyConfig`] (snapshot auth key 6) and the sealed keys
//! 3/4/5. It is **two** keys, not one, and the split is the design:
//!
//! | auth key | contents | sealed | a corrupt blob is |
//! |---|---|---|---|
//! | 7 | master seed, soft-lock key, org attestation scalar, audit checkpoint key | yes | **fatal** — the whole snapshot is `Corrupt` |
//! | 8 | audit ring + epoch + sequence + enabled bit, org attestation chain | no | **the documented defaults** |
//!
//! The two failure policies differ because the two contents are different
//! kinds of thing, and both policies are forced by the US-911 contract that
//! already exists rather than invented here.
//!
//! * The **secret** half is the same class of material as `device_random`
//!   (auth key 5, "the stateless master"): an auth-level field that fails to
//!   open fails the **whole snapshot** (`None` = `Corrupt`, fatal per FX-440),
//!   because a wallet whose master is garbage must not come up empty.
//!   Substituting a default here would answer `has_seed = false` to a device
//!   that has a seed, and `EXPORT` would then return 32 bytes that are not the
//!   ones the holder wrote down as a BIP-39 phrase — a silent key loss, which
//!   is the worst outcome this state has.
//! * The **public** half holds nothing secret: a journal the owner explicitly
//!   opted into, a certificate chain anyone can verify, and a boolean. A
//!   structurally-broken blob there is a firmware-version or torn-write
//!   artefact, and refusing to boot a token carrying twelve enrolled
//!   credentials over a corrupt *audit ring* trades a lost log for a lost
//!   token. So it decodes to [`VendorPublic::default`] and the device comes up
//!   with `audit_len = 0` and `org_chain = None` — the documented defaults, and
//!   `ATT_STATE` then reports `installed = false`, which is a **true** statement
//!   about a credential the device can no longer produce.
//!
//! Neither half ever panics. The device panic handler is `loop {}`
//! (`firmware/src/main.rs`), so a panic in a decoder is a wedged token until
//! the user unplugs it — which is why the public half's decoder returns a value
//! and never indexes, and the secret half's returns a `Result`.
//!
//! # The snapshot-capacity interaction, stated rather than hidden
//!
//! `DeviceKeystore::to_cbor`'s `auth` scratch had to grow for this (see
//! [`crate::device_keystore::AUTH_SCRATCH`]), and the snapshot's total is
//! bounded by the chunked slot's 5,952-byte payload (US-1010: 12 parts x 496 B,
//! the largest value the device store can accept — see `chunked::MAX_PARTS`)
//! ([`fapico2_platform::secure_store::chunked::MAX_LOGICAL_LEN`]). A device
//! holding the maximum twelve credentials *and* a 2,048-byte org chain can
//! exceed that, and `DeviceKeystore::persist` answers `ValueTooLong`.
//! `grow_checked` then runs its undo closure and the caller gets
//! `CTAP2_ERR_KEYSTORE_FULL` (`0x28`) — a clean refusal, never a torn write and
//! never a `0x00` true only in RAM. That is the transactional contract working
//! as intended, but it does mean `ATT_IMPORT` can be refused on a nearly-full
//! token. The alternative — shrinking [`ORG_CHAIN_MAX`] below the 2,048 the
//! protocol defines — would refuse a chain the client considers valid, which is
//! worse.
//!
//! # What this module does **not** decide
//!
//! Which gate each sub-command owes. That is
//! [`crate::vendor41::required_permission`], which has a row per sub-command,
//! and twelve of the rows are [`crate::vendor41::Requirement::TokenOptional`] —
//! so a Phase I arm that admits a tokenless request is admitting one it has
//! promised to gate on a touch
//! ([`crate::vendor41::requires_presence_when_tokenless`]). Nothing here makes
//! that decision, and nothing here can be used to skip it.

use crate::cbor::no_heap::{self, CborError, Item, Parser};
use crate::ctap2::Ctap2Response;
use crate::crypto;
use crate::snapshot_crypt::{FieldScope, FIELD_OVERHEAD};
use crate::vendor41::{
    self, AuditRecord, AuditWindow, Checkpoint, MseChannel, MsePoint, OrgAttestation,
    OrgAttestationView, SoftLock, VendorOps, AUDIT_ENTRY_LEN, AUDIT_RING_MAX,
    LOCK_BLOB_MAX, MASTER_SEED_LEN, ORG_CHAIN_MAX, SIG_DER_MAX,
};
use crate::CTAP2_MAX_MSG;
use fapico2_platform::secure_store::SecureStore;
use heapless::Vec as HeaplessVec;

/// Snapshot **auth-map key 7** — the sealed half of [`VendorState`].
pub const AUTH_KEY_SECRET: u64 = 7;
/// Snapshot **auth-map key 8** — the plaintext half of [`VendorState`].
pub const AUTH_KEY_PUBLIC: u64 = 8;

/// Worst-case plaintext of the sealed half: four byte strings (32 + 64 + 32 +
/// 32 = 160), four pair keys, and a 4-pair map header.
///
/// Stated rather than derived so the sealer's output buffer is a named
/// constant and not a guess: [`fapico2_platform::snapshot_crypt::seal_field`]
/// takes a caller-sized output and has no heap to grow into, so an
/// under-estimated bound here is a `BufferFull` on a device that has a seed.
pub const SECRET_PT_MAX: usize = 200;
/// Worst-case sealed blob: plaintext + `nonce(12)` + `tag(16)` + a CBOR
/// byte-string head of at most 3 bytes.
pub const SECRET_BLOB_MAX: usize = SECRET_PT_MAX + FIELD_OVERHEAD + 3;

/// Worst-case plaintext of the **public** half: a 2,048-byte chain, 32 live
/// records (640 bytes), a 32-byte epoch, five pair keys and a 5-pair map
/// header, with 3-byte CBOR heads on the two byte strings.
pub const PUBLIC_PT_MAX: usize = ORG_CHAIN_MAX + AUDIT_RING_MAX * AUDIT_ENTRY_LEN + 32 + 32;

/// The sealed half: the four pieces of key material this channel exists to
/// manage.
///
/// [`Copy`] and about 130 bytes, deliberately — it is the half that has to be
/// reproducible byte-for-byte, and a `Copy` half cannot be handed an aliased
/// buffer that an encoder writes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VendorSecret {
    /// The 32-byte master seed, if the device has one.
    pub master_seed: Option<[u8; MASTER_SEED_LEN]>,
    /// The soft-lock record. `engaged` is derived from this (see
    /// [`SoftLock::engaged`]), so this is the only place the lock lives.
    pub lock: SoftLock,
    /// The organisation attestation P-256 scalar.
    pub org_scalar: Option<[u8; 32]>,
    /// The audit checkpoint signing scalar, minted from the TRNG the first time
    /// one is needed. See [`VendorOps::audit_sign_checkpoint`] for why it is a
    /// slot and not something derived from existing state.
    pub audit_key: Option<[u8; 32]>,
}

impl VendorSecret {
    /// Whether the half is entirely absent, which is what keeps a device that
    /// has never seen a `0x41` write **byte-identical** snapshots to before
    /// this module existed — the same discipline auth key 6 follows.
    pub const fn is_empty(&self) -> bool {
        self.master_seed.is_none()
            && self.lock.key.is_none()
            && self.org_scalar.is_none()
            && self.audit_key.is_none()
    }

    /// How many `{key: value}` pairs the encoding writes. A method rather than
    /// a constant so a field added to the struct without a matching pair here
    /// would be an encoding that *drops* it, and this count is what the map
    /// header is sized from.
    fn pair_count(&self) -> usize {
        usize::from(self.master_seed.is_some())
            + usize::from(self.lock.key.is_some())
            + usize::from(self.org_scalar.is_some())
            + usize::from(self.audit_key.is_some())
    }
}

/// The plaintext half: what the device would be willing to show anyone.
///
/// Not a security boundary in either direction. It is plaintext because
/// nothing in it is secret *and* because its two largest fields — a 640-byte
/// ring and a 2,048-byte chain — do not fit
/// [`fapico2_platform::snapshot_crypt::MAX_FIELD_PT`] (1,024) as a sealed
/// field, so sealing it would mean either chunking it across two AEAD fields
/// or refusing the protocol's own 2,048-byte chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorPublic {
    /// Whether the journal is recording. Opt-in; a disabled journal ignores
    /// [`VendorOps::audit_append`].
    pub audit_enabled: bool,
    /// The next sequence number — one past the last record written. `u32`
    /// because the wire field is (`audit.rs:120`), and a journal that wrapped
    /// is one whose chain no longer means "everything since reset".
    pub audit_seq: u32,
    /// `h₀` — the accumulator evicted history has been folded into.
    pub audit_epoch: [u8; 32],
    /// The live records, in the order they were appended, **cyclically**: live
    /// record `i` of the window is
    /// `ring[(audit_seq - audit_len + i) % AUDIT_RING_MAX]`.
    pub audit_ring: [[u8; AUDIT_ENTRY_LEN]; AUDIT_RING_MAX],
    /// How many slots of `audit_ring` are live, `0..=AUDIT_RING_MAX`.
    pub audit_len: u8,
    /// The organisation attestation DER chain.
    pub org_chain: Option<HeaplessVec<u8, ORG_CHAIN_MAX>>,
    /// Whether the one-time seed-export window is **permanently closed**.
    ///
    /// Set by `FINALIZE` (`0x04`) and read by `EXPORT` (to refuse) and by
    /// `STATE`'s key 1. It lives in the *public* half rather than beside the
    /// seed because it is a flag, not a secret -- and because
    /// [`VendorPublic::is_empty`] compares against `Self::default()`, and
    /// `false` is the default: a device that has never run a `0x41` still
    /// writes a byte-identical snapshot. Putting it in the sealed half would
    /// have changed the `is_empty` answer for every device already in the
    /// field.
    ///
    /// **Monotonic.** Nothing in the protocol clears it, and no path should:
    /// it answers "may this token ever export a seed again", and an answer that
    /// can go back to yes is not one.
    pub sealed: bool,
}

impl Default for VendorPublic {
    fn default() -> Self {
        Self {
            sealed: false,
            audit_enabled: false,
            audit_seq: 0,
            audit_epoch: [0u8; 32],
            audit_ring: [[0u8; AUDIT_ENTRY_LEN]; AUDIT_RING_MAX],
            audit_len: 0,
            org_chain: None,
        }
    }
}

impl VendorPublic {
    /// Whether the half is entirely absent (the snapshot-keeps-its-bytes
    /// condition; see [`VendorSecret::is_empty`] for why it matters).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// One past the last live sequence number.
    pub const fn live_end(&self) -> u32 {
        self.audit_seq
    }

    /// The first live sequence number. Cannot underflow: `push_audit` only
    /// grows `len` alongside `seq`, and the decoder refuses a stored pair
    /// where `seq < len`.
    pub const fn live_start(&self) -> u32 {
        self.audit_seq - self.audit_len as u32
    }

    /// Index of the `i`-th live record in [`Self::audit_ring`].
    fn slot(&self, i: usize) -> usize {
        let n = self.audit_len as usize;
        (self.audit_seq as usize + AUDIT_RING_MAX - n + i) % AUDIT_RING_MAX
    }

    /// Append one record, evicting the oldest into the epoch when full.
    ///
    /// Pure state machine: no I/O, no clock, and — the property the
    /// all-or-nothing writes rely on — **it cannot fail**. A full ring is not
    /// an error; it is the reason `epoch` exists ("an epoch accumulator that
    /// absorbs evicted history", `audit.rs:5-6`).
    pub fn push_audit(&mut self, record: AuditRecord) {
        let slot = (self.audit_seq as usize) % AUDIT_RING_MAX;
        if self.audit_len as usize == AUDIT_RING_MAX {
            // Fold the record about to be overwritten into the chain, so `head`
            // still covers everything ever recorded. The fold is
            // `h = SHA-256(h ‖ entry)` — the same function the host applies
            // per entry (`audit.rs::fold_chain`), applied here to the record
            // that is about to leave the window.
            self.audit_epoch = fold(self.audit_epoch, &self.audit_ring[slot]);
        } else {
            self.audit_len += 1;
        }
        self.audit_ring[slot] = record.encode(self.audit_seq);
        self.audit_seq += 1;
    }

    /// The chain head over the live window: `fold(epoch, entries)`.
    ///
    /// This is the value the host recomputes from the bytes it received and
    /// compares against the signed `head` (`audit.rs:180-181`;
    /// `mod.rs::audit_verify`'s `head_matches`), so it must be the fold of
    /// **exactly** the records [`Self::write_audit_window`] would return — same
    /// order, same start. Two functions, one loop each, both reading
    /// [`Self::slot`], is the shape that keeps that true.
    pub fn audit_head(&self) -> [u8; 32] {
        let mut h = self.audit_epoch;
        for i in 0..self.audit_len as usize {
            h = fold(h, &self.audit_ring[self.slot(i)]);
        }
        h
    }

    /// The live records, in sequence order, appended to `out`.
    ///
    /// Streams rather than returning a slice because the ring is
    /// cyclically-indexed: a borrow of a contiguous range is not expressible
    /// without either copying into a second 640-byte buffer or an accessor the
    /// caller has to remember to index modulo — and the second is a
    /// reproducibility bug waiting for the first `AUDIT_READ` after an
    /// eviction.
    pub fn write_audit_window<const N: usize>(
        &self,
        out: &mut HeaplessVec<u8, N>,
    ) -> Result<(), Ctap2Response> {
        for i in 0..self.audit_len as usize {
            out.extend_from_slice(&self.audit_ring[self.slot(i)])
                .map_err(|_| Ctap2Response::LimitExceeded)?;
        }
        Ok(())
    }
}

/// `SHA-256(h ‖ entry)` — the chain's one step, and the client's
/// (`audit.rs::fold_chain`).
fn fold(h: [u8; 32], entry: &[u8; AUDIT_ENTRY_LEN]) -> [u8; 32] {
    let mut msg = [0u8; 32 + AUDIT_ENTRY_LEN];
    msg[..32].copy_from_slice(&h);
    msg[32..].copy_from_slice(entry);
    crypto::sha256(&msg)
}

/// The Phase I durable state: the sealed [`VendorSecret`] and the plaintext
/// [`VendorPublic`], stored as two snapshot auth-map keys.
///
/// `Clone` rather than `Copy` because of the 2 KB chain, and it is never
/// copied on the write path — each operation changes one field and reverts
/// exactly that field, which is what keeps the undo closure small. See
/// [`crate::device_keystore::DeviceKeystore::grow_checked`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VendorState {
    pub secret: VendorSecret,
    pub public: VendorPublic,
}

impl VendorState {
    /// Validate and install an org attestation credential, all-or-nothing.
    ///
    /// The two fields are checked **together** and the call refuses if only one
    /// is present, because `ATT_STATE`'s `installed` bit and its `chain_hash`
    /// are read from the same object: a scalar with no chain reports
    /// `installed = true` and a hash of nothing, which a host would then pin
    /// as an org identity that verifies against no certificate.
    pub fn put_org(&mut self, att: OrgAttestation) -> Result<(), Ctap2Response> {
        let OrgAttestation { scalar, chain } = att;
        match (scalar, chain) {
            (None, None) => {
                self.secret.org_scalar = None;
                self.public.org_chain = None;
                Ok(())
            }
            (Some(s), Some(c)) => {
                self.secret.org_scalar = Some(s);
                self.public.org_chain = Some(c);
                Ok(())
            }
            // A half-populated credential is a caller bug, not a state this
            // firmware will store.
            _ => Err(Ctap2Response::InvalidParameter),
        }
    }

    // ---- the sealed half's codec (auth key 7) -----------------------------
    //
    // A CBOR map `{1?: bstr(32), 2?: bstr(≤64), 3?: bstr(32), 4?: bstr(32)}`,
    // sealed as **one** field under `FieldScope::AuthVendorSecret`. One field
    // rather than four so the four pieces of key material move together: a
    // snapshot holding a new soft-lock key beside the old seed is a wallet
    // whose lock cannot be opened, and per-field sealing cannot express "all of
    // it or none of it".
    //
    // The two codecs are separated into "the plaintext map" and "seal it" so
    // the **host** keystore — which builds a `cbor::Value` rather than a
    // `HeaplessVec`, and which AADs to `FILE_KEYSTORE_SLOT` rather than the
    // device slot — can share the map's byte layout without copying it. That
    // is the whole of what "one format, two codecs" means here: the layout is
    // written once, and what differs between the stacks is only the slot name
    // in the AAD (already true of keys 3/4/5).

    /// The sealed half's plaintext map bytes, or `None` when it is empty.
    pub fn secret_plaintext(&self) -> Result<Option<HeaplessVec<u8, SECRET_PT_MAX>>, CborError> {
        if self.secret.is_empty() {
            return Ok(None);
        }
        let mut pt: HeaplessVec<u8, SECRET_PT_MAX> = HeaplessVec::new();
        no_heap::push_map_header(&mut pt, self.secret.pair_count())?;
        if let Some(s) = &self.secret.master_seed {
            no_heap::push_uint(&mut pt, 1)?;
            no_heap::push_bstr(&mut pt, &s[..])?;
        }
        if let Some(k) = self.secret.lock.key_bytes() {
            no_heap::push_uint(&mut pt, 2)?;
            no_heap::push_bstr(&mut pt, k)?;
        }
        if let Some(s) = &self.secret.org_scalar {
            no_heap::push_uint(&mut pt, 3)?;
            no_heap::push_bstr(&mut pt, &s[..])?;
        }
        if let Some(k) = &self.secret.audit_key {
            no_heap::push_uint(&mut pt, 4)?;
            no_heap::push_bstr(&mut pt, &k[..])?;
        }
        Ok(Some(pt))
    }

    /// Encode the sealed half into `out`. `Ok(false)` means the half is empty
    /// and the key is **not** written at all.
    pub fn encode_secret<const N: usize>(
        &self,
        key: Option<&[u8; 32]>,
        out: &mut HeaplessVec<u8, N>,
    ) -> Result<bool, CborError> {
        let Some(pt) = self.secret_plaintext()? else {
            return Ok(false);
        };
        no_heap::push_uint(out, AUTH_KEY_SECRET)?;
        crate::device_keystore::seal_push(key, FieldScope::AuthVendorSecret, &[], &pt, out)?;
        Ok(true)
    }

    /// Decode auth key 7. `Err` is **fatal to the snapshot** — US-911's
    /// auth-level rule, the same one `device_random` follows: the master is
    /// never garbage.
    ///
    /// `sealed` is the snapshot's own format marker, exactly as keys 3/4/5 read
    /// it. A legacy plaintext snapshot with no key 7 decodes to
    /// `Ok(VendorSecret::default())` because the **key is absent**, not because
    /// it failed to open; `DeviceKeystore::decode_auth` never calls this in
    /// that case, and the branch is here so the two are independent.
    // `Result<_, ()>` deliberately: the only caller is `decode_auth`, which
    // turns it into `Option` for `from_cbor`'s `None` = Corrupt, so a named
    // error type would be a second thing to map at the one place that already
    // has the mapping. The same choice `grow_checked` documents with its own
    // `#[allow(clippy::result_unit_err)]`.
    #[allow(clippy::result_unit_err)]
    pub fn decode_secret(
        bytes: &[u8],
        key: Option<&[u8; 32]>,
        sealed: bool,
    ) -> Result<VendorSecret, ()> {
        let mut out = VendorSecret::default();
        let pt: HeaplessVec<u8, SECRET_PT_MAX> = match key {
            Some(k) => {
                let mut scratch = [0u8; SECRET_BLOB_MAX];
                let n = crate::device_keystore::open_sealed_field(
                    k,
                    FieldScope::AuthVendorSecret,
                    &[],
                    bytes,
                    &mut scratch[..],
                )
                .ok_or(())?;
                if n > SECRET_PT_MAX {
                    return Err(());
                }
                scratch[..n].try_into().map_err(|_| ())?
            }
            None => {
                if sealed {
                    // A sealed snapshot whose store key is gone cannot be
                    // opened — the same refusal `DeviceKeystore::from_cbor`
                    // makes before it reaches any field.
                    return Err(());
                }
                bytes.try_into().map_err(|_| ())?
            }
        };
        let mut p = Parser::new(&pt);
        let n = match p.next() {
            Ok(Item::Map(n)) => n,
            _ => return Err(()),
        };
        for _ in 0..n {
            let k = match p.next() {
                Ok(Item::U(k)) => k,
                _ => return Err(()),
            };
            match (k, p.next()) {
                (1, Ok(Item::B(b))) => out.master_seed = Some(exact32(b).ok_or(())?),
                (2, Ok(Item::B(b))) => {
                    if b.is_empty() || b.len() > LOCK_BLOB_MAX {
                        return Err(());
                    }
                    out.lock = SoftLock::new(b).map_err(|_| ())?
                }
                (3, Ok(Item::B(b))) => out.org_scalar = Some(exact32(b).ok_or(())?),
                (4, Ok(Item::B(b))) => out.audit_key = Some(exact32(b).ok_or(())?),
                // A key this firmware does not define, or a known key with the
                // wrong value type, refuses the field rather than being
                // skipped. The *outer* auth map's unknown-key rule is the
                // opposite and is `DeviceKeystore::decode_auth`'s; the
                // difference is deliberate and is the module docs' two
                // failure policies — an inner field is something *this* module
                // wrote, and half-understanding it is how a snapshot becomes a
                // state no single operation could produce.
                _ => return Err(()),
            }
        }
        if p.remaining() != 0 {
            return Err(());
        }
        Ok(out)
    }

    // ---- the plaintext half's codec (auth key 8) --------------------------

    /// The plaintext half's map bytes, or `None` when it is at its default.
    ///
    /// Shared with the host codec for the same reason as
    /// [`Self::secret_plaintext`]: one writer for the layout, so the two
    /// snapshots cannot drift on a field only one of them has heard of.
    pub fn public_bytes(&self) -> Result<Option<HeaplessVec<u8, PUBLIC_PT_MAX>>, CborError> {
        if self.public.is_empty() {
            return Ok(None);
        }
        let p = &self.public;
        let mut out: HeaplessVec<u8, PUBLIC_PT_MAX> = HeaplessVec::new();
        no_heap::push_map_header(&mut out, 5 + usize::from(p.org_chain.is_some()))?;
        no_heap::push_uint(&mut out, 1)?;
        no_heap::push_uint(&mut out, u64::from(p.audit_enabled))?;
        no_heap::push_uint(&mut out, 2)?;
        no_heap::push_uint(&mut out, p.audit_seq as u64)?;
        no_heap::push_uint(&mut out, 3)?;
        no_heap::push_bstr(&mut out, &p.audit_epoch)?;
        no_heap::push_uint(&mut out, 4)?;
        no_heap::push_head(&mut out, 2, (p.audit_len as usize * AUDIT_ENTRY_LEN) as u64)?;
        for i in 0..p.audit_len as usize {
            out.extend_from_slice(&p.audit_ring[p.slot(i)]).map_err(|_| CborError::BufferFull)?;
        }
        if let Some(chain) = &p.org_chain {
            no_heap::push_uint(&mut out, 5)?;
            no_heap::push_bstr(&mut out, chain)?;
        }
        // Key 6 last, so the map stays in ascending key order whether or not
        // key 5 was written. The decoder is order-independent, but an encoder
        // that emitted 6 before 5 would produce a map this file's own writer
        // never produces, and the next reader to add a key would have no
        // signal about which order the writer actually means.
        no_heap::push_uint(&mut out, 6)?;
        no_heap::push_uint(&mut out, u64::from(p.sealed))?;
        Ok(Some(out))
    }

    /// Encode the plaintext half into `out`. `Ok(false)` means the half is at
    /// its default and the key is not written.
    pub fn encode_public<const N: usize>(
        &self,
        out: &mut HeaplessVec<u8, N>,
    ) -> Result<bool, CborError> {
        let Some(bytes) = self.public_bytes()? else {
            return Ok(false);
        };
        no_heap::push_uint(out, AUTH_KEY_PUBLIC)?;
        // A **byte string wrapping** the map, not the bare map. Auth key 7 is
        // a bstr and this makes key 8 the same shape, which buys two things:
        // the two decoders take the same `Item::B` arm and cannot drift on
        // "is the value a map or a bstr", and a future extension of the public
        // half (a new field, a version tag) can be added inside the wrapping
        // without changing the auth map's own shape — which is what the
        // `{1: [...], 2: 2}` snapshot marker does at the top level.
        no_heap::push_bstr(out, &bytes)?;
        Ok(true)
    }

    /// Decode auth key 8 into `public`, or leave it at [`VendorPublic::default`]
    /// if the blob is not one this firmware wrote.
    ///
    /// **Infallible on purpose**, and that is the whole difference from
    /// [`Self::decode_secret`]. See the module docs: this half is not the
    /// master, and a token with twelve enrolled credentials must not fail to
    /// boot over a corrupt audit ring. Every failure below therefore lands on
    /// the documented defaults rather than propagating:
    ///
    /// * not a map, a truncated blob, trailing bytes, an unknown field, a field
    ///   of the wrong CBOR type, a ring whose length is not a whole number of
    ///   records or exceeds [`AUDIT_RING_MAX`], a `seq` that would make
    ///   [`VendorPublic::live_start`] underflow, a chain longer than
    ///   [`ORG_CHAIN_MAX`], an epoch that is not 32 bytes.
    ///
    /// The default is a *complete* state, not a hole: `audit_enabled = false`,
    /// `audit_seq = 0`, `audit_len = 0`, `audit_epoch = [0; 32]`,
    /// `org_chain = None` — and therefore `ATT_STATE` reports
    /// `installed = false`, true, because the device can no longer produce the
    /// credential. Every arm of the loop returns the **whole** default rather
    /// than the partially built `out`: a half-decoded journal is not a shorter
    /// journal, it is one whose `seq` and `len` no longer describe each other.
    pub fn decode_public(bytes: &[u8]) -> VendorPublic {
        let mut p = Parser::new(bytes);
        let mut out = VendorPublic::default();
        let n = match p.next() {
            Ok(Item::Map(n)) => n,
            _ => return out,
        };
        for _ in 0..n {
            let key = match p.next() {
                Ok(Item::U(k)) => k,
                _ => return VendorPublic::default(),
            };
            match (key, p.next()) {
                (1, Ok(Item::U(v))) => out.audit_enabled = v != 0,
                (6, Ok(Item::U(v))) => out.sealed = v != 0,
                (2, Ok(Item::U(v))) => {
                    if v > u32::MAX as u64 {
                        return VendorPublic::default();
                    }
                    out.audit_seq = v as u32;
                }
                (3, Ok(Item::B(b))) => match <[u8; 32]>::try_from(b) {
                    Ok(e) => out.audit_epoch = e,
                    Err(_) => return VendorPublic::default(),
                },
                (4, Ok(Item::B(b))) => {
                    if b.len() % AUDIT_ENTRY_LEN != 0 || b.len() > AUDIT_RING_MAX * AUDIT_ENTRY_LEN
                    {
                        return VendorPublic::default();
                    }
                    let count = b.len() / AUDIT_ENTRY_LEN;
                    if out.audit_seq < count as u32 {
                        return VendorPublic::default();
                    }
                    out.audit_len = count as u8;
                    // The stored ring is the *live* window in order, so it is
                    // written back at the tail of a full-width array and
                    // `slot` lines up with the order the client saw: `seq` is
                    // one past the last, so the last record sits at `seq - 1`.
                    for (i, chunk) in b.as_chunks::<AUDIT_ENTRY_LEN>().0.iter().enumerate() {
                        out.audit_ring[out.slot(i)].copy_from_slice(chunk);
                    }
                }
                (5, Ok(Item::B(b))) => {
                    if b.len() > ORG_CHAIN_MAX {
                        return VendorPublic::default();
                    }
                    // `heapless`'s `FromIterator` is infallible once the
                    // length bound above is checked, so there is nothing left
                    // to fail here — which is why the collect is not an error
                    // path and the `org_chain` assignment cannot fail.
                    out.org_chain =
                        Some(b.iter().copied().collect::<HeaplessVec<u8, ORG_CHAIN_MAX>>());
                }
                _ => return VendorPublic::default(),
            }
        }
        if p.remaining() != 0 {
            return VendorPublic::default();
        }
        out
    }
}

fn exact32(b: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(b).ok()
}

/// The volatile half: what must **not** survive a power cycle.
///
/// A field of each `FidoApp`, not of the keystore, for the same reason
/// `auth_failures` is: the session/durable split is the one US-909 drew, and
/// US-111's module docs name the durable-counter mistake explicitly. Putting
/// any of this in the snapshot would make "unlocked this power cycle" survive
/// the power cycle it is defined against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VendorSession {
    /// Whether the soft-locked seed has been loaded this power cycle.
    /// `STATE`'s `unlocked` is exactly this.
    pub unlocked_this_power_cycle: bool,
    /// The channel material the last `MSE` derived, for this power cycle.
    pub mse: Option<MseChannel>,
}

impl VendorSession {
    /// Forget the session. Called wherever the firmware already simulates a
    /// power cycle for a new HID client, so "this power cycle" means here what
    /// it means to the rest of the app.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

// ---------------------------------------------------------------------------
// The pieces both implementations share, so a byte-exact construction exists
// once. See `vendor41`'s note on why these live in the protocol module and
// here both — the *constants* are protocol, the *state* is storage, and the two
// implementations must not be the place either is written twice.
// ---------------------------------------------------------------------------

/// Establish one MSE channel and stash it on the session.
///
/// Free rather than a method on either implementation so the host and device
/// paths cannot produce two different channel keys from one host point. The
/// ephemeral scalar is fresh per session: reusing one would make every backup
/// channel after the first recoverable from the first.
pub fn mse_establish(
    session: &mut VendorSession,
    random: &mut dyn FnMut(&mut [u8]),
    host_x: [u8; 32],
    host_y: [u8; 32],
    out: &mut MsePoint,
) -> Result<(), Ctap2Response> {
    let peer = crypto::parse_cose_ec2_p256_bytes(&host_x, &host_y)
        .ok_or(Ctap2Response::InvalidParameter)?;
    let mut scalar = [0u8; 32];
    random(&mut scalar);
    let secret =
        crypto::secret_key_from_bytes(&scalar).ok_or(Ctap2Response::InvalidParameter)?;
    let point = crypto::public_key_bytes(&secret.public_key());
    let z = crypto::ecdh_shared_secret(&secret, &peer);
    let key = vendor41::derive_mse_channel(&z, &point);
    out.x.copy_from_slice(&point[1..33]);
    out.y.copy_from_slice(&point[33..65]);
    session.mse = Some(MseChannel { key, aad: point });
    Ok(())
}

/// Mint a fresh audit checkpoint signing scalar, or refuse.
///
/// A scalar outside `[1, n-1]` is not a P-256 key at all, and that is a TRNG
/// failure rather than a protocol error. `Err` here is
/// [`Ctap2Response::Processing`] so the caller **does not store** it: storing a
/// scalar `crypto::secret_key_from_bytes` will refuse would make the *next*
/// load fail, and a failing load of the sealed half is fatal to the snapshot.
pub fn mint_audit_key(random: &mut dyn FnMut(&mut [u8])) -> Result<[u8; 32], Ctap2Response> {
    let mut k = [0u8; 32];
    random(&mut k);
    if crypto::secret_key_from_bytes(&k).is_none() {
        return Err(Ctap2Response::Processing);
    }
    Ok(k)
}

/// Sign the checkpoint message with `key` and fill the response.
///
/// `head` and `seq` are **parameters**, not reads, and that is the point: the
/// caller reads them once from its own state, signs, and returns the same
/// values in the response, so the bytes the host folds from the window and the
/// bytes that were signed cannot disagree. See
/// [`VendorOps::audit_sign_checkpoint`].
pub fn sign_checkpoint(
    key: &[u8; 32],
    head: &[u8; 32],
    seq: u32,
    challenge: &[u8; 16],
    out: &mut Checkpoint,
) -> Result<(), Ctap2Response> {
    let secret = crypto::secret_key_from_bytes(key).ok_or(Ctap2Response::Processing)?;
    let mut msg: HeaplessVec<u8, 1024> = HeaplessVec::new();
    vendor41::checkpoint_message(head, seq, challenge, &mut msg)?;
    let mut der: HeaplessVec<u8, SIG_DER_MAX> = HeaplessVec::new();
    crypto::p256_sign_der_into(&secret, &msg, &mut der).ok_or(Ctap2Response::Processing)?;
    out.head = *head;
    out.seq = seq;
    out.pubkey = crypto::public_key_bytes(&secret.public_key());
    out.sig = [0u8; SIG_DER_MAX];
    out.sig_len = der.len() as u8;
    out.sig[..der.len()].copy_from_slice(&der);
    Ok(())
}

/// Translate a commit result into the trait's contract.
///
/// `unchanged` says the operation was a no-op — the value being written is the
/// value already stored — which is the one case where a refused persist is
/// still a success, because there was nothing to land.
fn durable(committed: bool, unchanged: bool) -> Result<(), Ctap2Response> {
    if committed || unchanged {
        Ok(())
    } else {
        Err(Ctap2Response::KeyStoreFull)
    }
}

/// The device implementation of [`VendorOps`]: over
/// [`crate::device_keystore::DeviceKeystore`] and the chunked [`SecureStore`],
/// with [`crate::device_keystore::DeviceKeystore::grow_checked`] as the only
/// commit.
///
/// # The all-or-nothing property, and where it comes from
///
/// Every mutating method is three steps and the order is the property:
///
/// 1. **validate**, and return on failure having touched nothing;
/// 2. `grow_checked` — apply, then
///    [`crate::device_keystore::DeviceKeystore::persist`]; on a persist
///    failure run the undo closure, which restores the *one* field the method
///    changed, and answer `CTAP2_ERR_KEYSTORE_FULL` (`0x28`);
/// 3. `Ok(())`, which is only reached once the bytes are durable.
///
/// So "a failure cannot half-commit" is not a promise this type makes to its
/// caller; it is a consequence of there being exactly one commit primitive and
/// of every method changing one field. The undo closures are deliberately
/// **narrow** — `Option<[u8; 32]>` for a seed, 20 bytes plus a `u8` and a
/// `u32` for a journal record — because a closure that cloned the whole state
/// would put 2 KB on the command path's stack for every audit append. The one
/// wide undo is [`Self::set_org_attestation`], whose payload is 2 KB wide, so a
/// 2 KB undo is the honest cost of making that one atomic.
/// `tests/vendor41_state.rs::a_refused_write_leaves_the_state_byte_identical`
/// and `::a_store_that_cannot_be_written_reverts_and_refuses` are the two
/// directions of that.
///
/// # Why it borrows the keystore rather than owning it
///
/// `handle` is called from inside a dispatch `match` on the app, so the app is
/// already mutably borrowed. Owning the keystore would mean taking it out of
/// the app for the duration of a command, and the keystore is the app's
/// authoritative state — it must not become a temporary.
///
/// # Three lifetimes, and why not fewer
///
/// `ks`, `session` and `random` share `'a`: they are three fields of one
/// `&mut self`, so they share its borrow. The store is a *fourth* thing and is
/// held as `&'st mut Option<&'sto mut dyn SecureStore>` — a reborrowable handle
/// rather than `Option<&'st mut dyn SecureStore>` — and that shape is not
/// cosmetic:
///
/// * Holding the store **by value** with the same `'a` does not compile at the
///   dispatch arm. `&'a mut (dyn SecureStore + 'a)` is invariant enough in the
///   referent that the compiler picks the *longest* region it can, which is
///   the whole of the arm's frame, and the subsequent move of the arm's own
///   `store` parameter then fails.
/// * Holding it by value with its own lifetime has the same problem: region
///   inference again picks the longest region, and a `&'st mut` stored in a
///   local keeps that borrow alive to the end of the local's scope rather than
///   to the end of the commit.
///
/// A `&'st mut Option<&'in mut _>` is reborrowed per commit, so the borrow is
/// exactly as long as the commit and the region has nothing to maximise. Three
/// parameters is the price; [`with_keystore_ops`] hides them at the one call
/// site, which is the only place that ever builds this type.
pub struct KeystoreVendorOps<'a, 'st, 'sto> {
    /// The snapshot both durable halves live in.
    pub ks: &'a mut crate::device_keystore::DeviceKeystore,
    /// The volatile half; never persisted.
    pub session: &'a mut VendorSession,
    /// The store the snapshot is written to. `None` is the dispatcher-bridge
    /// path (`grow_checked`'s own convention: apply, mark dirty, and let the
    /// durable-before-ack gate flush it later).
    pub store: &'st mut Option<&'sto mut dyn SecureStore>,
    /// Entropy, for the one-time audit checkpoint key and the MSE ephemeral
    /// scalar. A closure rather than a [`fapico2_platform::trng::Trng`] because
    /// the device serve loop holds no TRNG handle and draws from a boot-filled
    /// pool (`device_app`'s `rng_pool`), so a `Trng` would have to be threaded
    /// through `process_ctap2` to reach a value already on the app.
    pub random: &'a mut dyn FnMut(&mut [u8]),
}

/// The single commit path: apply, persist, undo on failure.
///
/// A free function over the two fields rather than a method, because
/// `grow_checked` takes the keystore **and** the store as arguments of the
/// same call and a `&mut self` method cannot produce two reborrows of its own
/// fields that outlive the call. One function means all seven mutating methods
/// commit the same way, which is the property the all-or-nothing claim rests
/// on.
fn commit(
    ks: &mut crate::device_keystore::DeviceKeystore,
    store: &mut Option<&mut dyn SecureStore>,
    apply: impl FnOnce(&mut crate::device_keystore::DeviceKeystore),
    undo: impl FnOnce(&mut crate::device_keystore::DeviceKeystore),
) -> bool {
    ks.grow_checked(
        match store {
            Some(s) => Some(&mut **s),
            None => None,
        },
        apply,
        undo,
    )
}

/// Build the device [`VendorOps`] and run `f` against it.
///
/// The only supported way to construct [`KeystoreVendorOps`]: it elides the
/// three lifetimes at the one call site, so a reader of `device_app.rs` sees
/// four field borrows and not three lifetime parameters. The store is
/// reborrowed, so `f` — and every commit inside it — holds it for exactly as
/// long as that commit and the caller may use its own `store` again on return.
pub fn with_keystore_ops<R>(
    ks: &mut crate::device_keystore::DeviceKeystore,
    session: &mut VendorSession,
    store: &mut Option<&mut dyn SecureStore>,
    random: &mut dyn FnMut(&mut [u8]),
    f: impl FnOnce(&mut dyn crate::vendor_backup::BackupOps) -> R,
) -> R {
    let mut ops = KeystoreVendorOps { ks, session, store, random };
    f(&mut ops)
}

impl KeystoreVendorOps<'_, '_, '_> {
    /// The stored org attestation as the borrowed view the trait hands out.
    fn view(&self) -> OrgAttestationView<'_> {
        OrgAttestationView {
            scalar: self.ks.vendor.secret.org_scalar,
            chain: self.ks.vendor.public.org_chain.as_ref().map_or(&[][..], |c| &c[..]),
        }
    }
}

impl VendorOps for KeystoreVendorOps<'_, '_, '_> {
    fn random_bytes(&mut self, out: &mut [u8]) {
        (self.random)(out)
    }

    fn master_seed(&self) -> Option<[u8; 32]> {
        self.ks.vendor.secret.master_seed
    }

    fn set_master_seed(&mut self, seed: [u8; 32]) -> Result<(), Ctap2Response> {
        let old = self.ks.vendor.secret.master_seed;
        let committed = commit(
            self.ks,
            self.store,
            |ks| ks.vendor.secret.master_seed = Some(seed),
            |ks| ks.vendor.secret.master_seed = old,
        );
        // `grow_checked`'s return is read rather than discarded: the difference
        // between "the seed is stored" and "the seed is in RAM" is the whole
        // property `EXPORT` will be built on.
        durable(committed, old == Some(seed))
    }

    fn soft_lock(&self) -> SoftLock {
        self.ks.vendor.secret.lock
    }

    fn set_soft_lock(&mut self, lock: SoftLock) -> Result<(), Ctap2Response> {
        let old = self.ks.vendor.secret.lock;
        let committed = commit(
            self.ks,
            self.store,
            |ks| ks.vendor.secret.lock = lock,
            |ks| ks.vendor.secret.lock = old,
        );
        durable(committed, old == lock)
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
        mse_establish(self.session, self.random, host_x, host_y, out)
    }

    fn mse_channel(&self, out: &mut MseChannel) -> Result<(), Ctap2Response> {
        match self.session.mse {
            // A zero key would be `HKDF(0, 0)`, which decrypts nothing and
            // looks like a working session. "No session" is a refusal.
            None => Err(Ctap2Response::InvalidParameter),
            Some(c) => {
                *out = c;
                Ok(())
            }
        }
    }

    fn export_sealed(&self) -> bool {
        self.ks.vendor.public.sealed
    }

    fn audit_enabled(&self) -> bool {
        self.ks.vendor.public.audit_enabled
    }

    fn set_audit_enabled(&mut self, enabled: bool) -> Result<(), Ctap2Response> {
        let old = self.ks.vendor.public.audit_enabled;
        let committed = commit(
            self.ks,
            self.store,
            |ks| ks.vendor.public.audit_enabled = enabled,
            |ks| ks.vendor.public.audit_enabled = old,
        );
        durable(committed, old == enabled)
    }

/// US-172 `FINALIZE`'s writer. A separate trait from [`VendorOps`] because the
/// bit is a policy flag rather than key material or journal state, and giving
/// [`VendorOps`] a non-key member for it would have meant the same declaration
/// living in two traits.
///
/// It exists as a supertrait of [`BackupOps`] rather than as a second parameter
/// on `handle` because a two-parameter signature is not merely inelegant here,
/// it is **uncallable**: passing `&mut ops` for both is two mutable borrows of
/// one object in a single call, which Rust rejects. That is the whole reason
/// `BackupOps` is a trait and not a pair.
///
/// **Idempotent and all-or-nothing.** A second `FINALIZE` on an already-sealed
/// device writes nothing and answers `Ok`, because the client has no way to
/// distinguish "already sealed" from "sealed just now" and both render as
/// success.
    fn audit_append(&mut self, record: AuditRecord) -> Result<(), Ctap2Response> {
        // The opt-in is enforced here rather than left to the arm: the client's
        // contract is that "nothing is written to flash until it is enabled"
        // (`mod.rs::audit_set_enabled`), and an arm that appended anyway would
        // spend a flash write per event on a device whose owner never asked for
        // a journal. Not an error either — this protocol has no "journal
        // disabled" status and the client has nothing to map one to.
        if !self.ks.vendor.public.audit_enabled {
            return Ok(());
        }
        // The undo is the evicted slot plus the old length, sequence and epoch:
        // `push_audit` either overwrites one record (leaving `len` alone) or
        // grows `len` by one, and on a full ring it also folds into the epoch.
        let slot = (self.ks.vendor.public.audit_seq as usize) % AUDIT_RING_MAX;
        let evicted = self.ks.vendor.public.audit_ring[slot];
        let old_len = self.ks.vendor.public.audit_len;
        let old_seq = self.ks.vendor.public.audit_seq;
        let old_epoch = self.ks.vendor.public.audit_epoch;
        let committed = commit(
            self.ks,
            self.store,
            |ks| ks.vendor.public.push_audit(record),
            |ks| {
                ks.vendor.public.audit_ring[slot] = evicted;
                ks.vendor.public.audit_len = old_len;
                ks.vendor.public.audit_seq = old_seq;
                ks.vendor.public.audit_epoch = old_epoch;
            },
        );
        durable(committed, false)
    }

    fn audit_window(
        &self,
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> Result<AuditWindow, Ctap2Response> {
        let p = &self.ks.vendor.public;
        p.write_audit_window(out)?;
        Ok(AuditWindow { start: p.live_start(), seq_next: p.live_end(), epoch: p.audit_epoch })
    }

    fn audit_sign_checkpoint(
        &mut self,
        challenge: &[u8; 16],
        out: &mut Checkpoint,
    ) -> Result<(), Ctap2Response> {
        // One consistent read: head and `seq` are taken before anything is
        // written and returned beside the signature, so the response cannot
        // describe a different journal than the one that was signed.
        let head = self.ks.vendor.public.audit_head();
        let seq = self.ks.vendor.public.live_end();
        let key = match self.ks.vendor.secret.audit_key {
            Some(k) => k,
            None => {
                // Mint once, durably, then use it. A token whose journal has
                // never been signed has no key yet, and a key that changed
                // between two checkpoints would invalidate every fingerprint a
                // host had already pinned.
                let k = mint_audit_key(self.random)?;
                let committed = commit(
                    self.ks,
                    self.store,
                    |ks| ks.vendor.secret.audit_key = Some(k),
                    |ks| ks.vendor.secret.audit_key = None,
                );
                if !committed {
                    return Err(Ctap2Response::KeyStoreFull);
                }
                k
            }
        };
        sign_checkpoint(&key, &head, seq, challenge, out)
    }

    fn org_attestation(&self) -> OrgAttestationView<'_> {
        self.view()
    }

    fn set_org_attestation(&mut self, att: OrgAttestation) -> Result<(), Ctap2Response> {
        // Validate into a probe first: `put_org` is the only thing that can
        // reject, and running it before `grow_checked` means a refusal never
        // reaches the apply step at all.
        let mut probe = VendorState::default();
        probe.put_org(att)?;
        let old_secret = self.ks.vendor.secret.org_scalar;
        let old_chain = self.ks.vendor.public.org_chain.clone();
        let committed = commit(
            self.ks,
            self.store,
            |ks| {
                ks.vendor.secret.org_scalar = probe.secret.org_scalar;
                ks.vendor.public.org_chain = probe.public.org_chain.take();
            },
            |ks| {
                ks.vendor.secret.org_scalar = old_secret;
                ks.vendor.public.org_chain = old_chain.clone();
            },
        );
        durable(committed, false)
    }
}

// ---------------------------------------------------------------------------
// The host implementation.
//
// The host twin persists through the [`crate::keystore::Keystore`] trait
// (`save_auth_state`) rather than a [`SecureStore`], and has no `grow_checked`,
// so it is a separate implementation for that reason alone.
//
// The two cannot drift in their **decisions** — the validation, the ring
// eviction, the fold, the checkpoint message, the MSE derivation all live in
// this module or in `vendor41`, and neither implementation contains any of
// them. What the two do differ in is exactly one thing, and it is the thing
// `grow_checked` exists for: the host mutates and then saves, and a save
// failure is reported rather than swallowed. That is the weaker contract, and
// it is the same one the host's existing `cfg_physical_config` keeps — see
// `vendor41::handle`'s commit note for why the host's is the weaker one and
// why the RP2350 does not rely on it.
// ---------------------------------------------------------------------------

/// The host implementation of [`VendorOps`], over a
/// [`crate::keystore::Keystore`].
///
/// # It borrows the *keystore*, not the auth state
///
/// The obvious shape — `&mut AuthState` plus `&mut K` — does not compile at
/// either call site: [`crate::keystore::Keystore::get_auth_state_mut`] hands
/// out a borrow **of** `K`, so holding one and `&mut K` at the same time is
/// the same object borrowed twice. Since the host app owns one `K` and reaches
/// the state through it, the struct borrows the `K` and calls the accessors
/// itself. The device twin does not have this problem — its snapshot and its
/// store are two separate fields — and keeps the two-borrow shape, which is
/// also the more honest description of what it is doing.
#[cfg(feature = "host")]
pub struct MemoryVendorOps<'a, K: crate::keystore::Keystore> {
    /// The keystore that owns the auth state **and** the durable medium.
    pub store: &'a mut K,
    /// The volatile half.
    pub session: &'a mut VendorSession,
}

#[cfg(feature = "host")]
impl<'a, K: crate::keystore::Keystore> MemoryVendorOps<'a, K> {
    /// Bind the two pieces. The app splits its own field borrows at the call
    /// site; on the host `FidoApp` that is `keystore` and `vendor_session`,
    /// which are different fields of the same struct.
    pub fn new(store: &'a mut K, session: &'a mut VendorSession) -> Self {
        Self { store, session }
    }

    /// Apply, then persist; `Err` if the persist failed.
    ///
    /// No undo. That is the documented host contract and it is *weaker* than
    /// the device's on purpose: a `MemoryKeystore` cannot fail, and a
    /// `FileKeystore` failure means the host process is already in a state
    /// where the in-memory value is the only copy there is — rolling it back
    /// would discard the operator's change rather than preserve it. The RP2350
    /// never uses this path; `grow_checked` is what the device relies on.
    fn commit(&mut self, apply: impl FnOnce(&mut Self)) -> Result<(), Ctap2Response> {
        apply(self);
        self.store.save_auth_state().map_err(|_| Ctap2Response::KeyStoreFull)
    }
}

#[cfg(feature = "host")]
impl<K: crate::keystore::Keystore> VendorOps for MemoryVendorOps<'_, K> {
    fn random_bytes(&mut self, out: &mut [u8]) {
        fapico2_platform::trng::random_bytes_into(out);
    }

    fn master_seed(&self) -> Option<[u8; 32]> {
        self.store.get_auth_state().vendor.secret.master_seed
    }

    fn set_master_seed(&mut self, seed: [u8; 32]) -> Result<(), Ctap2Response> {
        self.commit(|s| s.store.get_auth_state_mut().vendor.secret.master_seed = Some(seed))
    }

    fn soft_lock(&self) -> SoftLock {
        self.store.get_auth_state().vendor.secret.lock
    }

    fn set_soft_lock(&mut self, lock: SoftLock) -> Result<(), Ctap2Response> {
        self.commit(|s| s.store.get_auth_state_mut().vendor.secret.lock = lock)
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
        let mut random = |b: &mut [u8]| fapico2_platform::trng::random_bytes_into(b);
        mse_establish(self.session, &mut random, host_x, host_y, out)
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

    fn export_sealed(&self) -> bool {
        self.store.get_auth_state().vendor.public.sealed
    }

    fn audit_enabled(&self) -> bool {
        self.store.get_auth_state().vendor.public.audit_enabled
    }

    fn set_audit_enabled(&mut self, enabled: bool) -> Result<(), Ctap2Response> {
        self.commit(|s| s.store.get_auth_state_mut().vendor.public.audit_enabled = enabled)
    }



    fn audit_append(&mut self, record: AuditRecord) -> Result<(), Ctap2Response> {
        if !self.store.get_auth_state().vendor.public.audit_enabled {
            return Ok(());
        }
        self.commit(|s| s.store.get_auth_state_mut().vendor.public.push_audit(record))
    }

    fn audit_window(
        &self,
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> Result<AuditWindow, Ctap2Response> {
        let p = &self.store.get_auth_state().vendor.public;
        p.write_audit_window(out)?;
        Ok(AuditWindow { start: p.live_start(), seq_next: p.live_end(), epoch: p.audit_epoch })
    }

    fn audit_sign_checkpoint(
        &mut self,
        challenge: &[u8; 16],
        out: &mut Checkpoint,
    ) -> Result<(), Ctap2Response> {
        // One consistent read, before anything is written, and the same values
        // go into the response — see `vendor41::VendorOps::audit_sign_checkpoint`.
        let (head, seq) = {
            let p = &self.store.get_auth_state().vendor.public;
            (p.audit_head(), p.live_end())
        };
        let key = match self.store.get_auth_state().vendor.secret.audit_key {
            Some(k) => k,
            None => {
                let mut random = |b: &mut [u8]| fapico2_platform::trng::random_bytes_into(b);
                let k = mint_audit_key(&mut random)?;
                self.commit(|s| s.store.get_auth_state_mut().vendor.secret.audit_key = Some(k))?;
                k
            }
        };
        sign_checkpoint(&key, &head, seq, challenge, out)
    }

    fn org_attestation(&self) -> OrgAttestationView<'_> {
        let v = &self.store.get_auth_state().vendor;
        OrgAttestationView {
            scalar: v.secret.org_scalar,
            chain: v.public.org_chain.as_ref().map_or(&[][..], |c| &c[..]),
        }
    }

    fn set_org_attestation(&mut self, att: OrgAttestation) -> Result<(), Ctap2Response> {
        let mut probe = VendorState::default();
        probe.put_org(att)?;
        self.commit(|s| {
            let v = &mut s.store.get_auth_state_mut().vendor;
            v.secret.org_scalar = probe.secret.org_scalar;
            v.public.org_chain = probe.public.org_chain.take();
        })
    }
}

impl crate::vendor_backup::BackupWindow for KeystoreVendorOps<'_, '_, '_> {
    fn backup_sealed(&self) -> bool {
        self.ks.vendor.public.sealed
    }

    fn seal_backup(&mut self) -> Result<(), Ctap2Response> {
        if self.ks.vendor.public.sealed {
            // Monotonic, and already durable. Skip the write rather than
            // spending a flash cycle re-committing a value that cannot change.
            return Ok(());
        }
        let committed = commit(
            self.ks,
            self.store,
            |ks| ks.vendor.public.sealed = true,
            |_| {},
        );
        durable(committed, false)
    }
}

// `MemoryVendorOps` is the **host** half of the pair and is itself
// `#[cfg(feature = "host")]` (line 1130), so this impl has to carry the same
// gate or the `device` build — which compiles this file with `keystore` and
// `MemoryVendorOps` configured out — fails to resolve both. The four `impl`
// blocks immediately above it on the same two types all do carry it; this one
// was the odd case out, and it took the thumbv8m build down with
// `E0433`/`E0425` on both the struct and the `Keystore` bound.
#[cfg(feature = "host")]
impl<K: crate::keystore::Keystore> crate::vendor_backup::BackupWindow
    for MemoryVendorOps<'_, K>
{
    fn backup_sealed(&self) -> bool {
        self.store.get_auth_state().vendor.public.sealed
    }

    fn seal_backup(&mut self) -> Result<(), Ctap2Response> {
        if self.store.get_auth_state().vendor.public.sealed {
            return Ok(());
        }
        self.commit(|s| s.store.get_auth_state_mut().vendor.public.sealed = true)
    }
}
