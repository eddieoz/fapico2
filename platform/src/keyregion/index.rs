//! The verifiable index (US-1551, requirement **S1**).
//!
//! ```gherkin
//! Scenario: a flash dump is structurally checkable offline
//!   Given the key region written by a device with a PIN set
//!   And the OTP row read from the chip
//!   When the index is verified
//!   Then every entry authenticates under the device-rooted key
//!   And no payload is decrypted
//!   And no credential ID, RP name, user name or key material is recoverable
//! ```
//!
//! # What the index is, and the one key it uses
//!
//! The region is a flat grid of credential records (`mod.rs`), and every record
//! body is sealed under the **payload** key — which takes a PIN-derived secret
//! (`crypto::derive_payload_key`). So a credential cannot be *read* without the
//! PIN. It can still be **found** without it, and that is the whole job of this
//! module: given an `rp_id_hash` a browser has already computed in the clear
//! (CTAP 2.1 §6.1.1 — it is `SHA-256(rpId)`, and CTAP sends it to the device on
//! every `authenticatorMakeCredential`), say which slot holds that credential,
//! having opened nothing.
//!
//! So the index is a flat array of fixed-size entries, each authenticated by a
//! **truncated HMAC-SHA256 under the index key** and each carrying nothing but
//! what a match needs:
//!
//! ```text
//! off  width  field        why this width
//!   0     1   domain       KeyDomain::tag. FIDO and OATH share one slot grid
//!                         and one payload key, so without it an OATH entry
//!                         could answer a FIDO query.
//!   1     1   flags        bit0 = ENTRY_PRESENT, and only that bit. It is a
//!                         *presence* marker, not a policy: an erased cell is
//!                         0xFF, which clears the bit, so "this entry is
//!                         free" costs nothing to read.
//!   2     2   slot         u16 LE — the record slot this entry points at.
//!                         Slot::index() is a u16 (mod.rs, `Slot::index`), so
//!                         u16 carries the whole address space; and it is two
//!                         bytes here because the u32 generation after it has
//!                         to start 4-aligned.
//!   4     4   generation   u32 LE — the same width the record header and the
//!                         record AAD use (record.rs, "Why the generation is 32
//!                         bits"). 16 bits here would let "generation 65537"
//!                         alias to "generation 1" in a structure whose whole
//!                         job is to be un-rollbackable.
//!   8    16   rp_tag       truncated HMAC-SHA256(k_index, …)[..16]
//!  24     8   reserved     must be 0x00 — see "Why the entry is 32 bytes".
//! ```
//!
//! **That is the entire content.** No credential ID, no RP name, no user name,
//! no public key, not the `rp_id_hash` itself. A dump of this region yields a
//! table of pseudonymous 16-byte tags, slot numbers and generations.
//!
//! # What this defeats, and against what
//!
//! The contrast is with pico-fido, and it is deliberate rather than accidental.
//! pico-fido writes a resident credential's `rp_id_hash` and `client_data_hash`
//! as `FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC`
//! (`../pico-fido/src/fido/resident_container.c:324-327` and `:330-333`), and
//! its public key likewise (`…/resident_container.c:343-346`). That is the
//! right call *for that design* — the object container needs a searchable,
//! unencrypted index, and pico-fido buys lookup by publishing the account list.
//! The consequence is that **one flash dump enumerates every RP the owner has
//! registered with, and the client-data hashes that go with them**: the whole
//! account list of a hardware token, in the clear.
//!
//! Here the index is a **truncated MAC**, so the same dump yields 16-byte
//! pseudonyms. Recovering an RP name from one is a key-recovery problem against
//! a truncated HMAC-SHA256 keyed by the OTP root, not a read. The RP ID, the
//! user name and the credential private key stay sealed inside the record body
//! until a PIN-authenticated enumeration opens them.
//!
//! # Why a truncated HMAC and not an AEAD tag over the `rp_id_hash`
//!
//! Three properties, all of which the construction has to have at once:
//!
//! 1. **Deterministic**, so a query can *find* an entry instead of trying to
//!    open every slot. An AEAD over the `rp_id_hash` would be randomised and
//!    would have to be attempted once per slot — the decrypt-everything cost
//!    the index exists to avoid, with an AES operation per slot instead of a
//!    tag comparison.
//! 2. **Truncated to 16 bytes.** HMAC-SHA256 truncated to 128 bits keeps
//!    forgery probability at 2⁻¹²⁸ per attempt, which is below the birthday
//!    bound anyone would care about for a store of 960 entries; and 16 bytes of
//!    a *keyed* function leak nothing about its input without the key.
//! 3. **Domain-separated and identity-bound**, so an entry cannot be moved.
//!    See the next section.
//!
//! pico-hsm makes the same trade in a different encoding: it selects a file by a
//! **truncated** AID against a fixed table (`../pico-hsm/src/hsm/cmd_select.c:126-127`,
//! `file_search_by_name`), which is a searchable index whose entries are short
//! enough that the object behind one never has to be opened to find it.
//!
//! # What the MAC covers, and the attack that fixes it
//!
//! ```text
//! rp_tag = HMAC-SHA256( k_index,
//!                       "fapico2/keyregion/index/mac/v1"
//!                     ‖ aad(domain, slot, generation)   // crypto::RecordAad, 11 bytes
//!                     ‖ rp_id_hash )[ ..16 ]
//! ```
//!
//! S1 describes the tag as `HMAC(k_index, rp_id_hash)`. It is a **strict
//! widening**: the `rp_id_hash` is the message's only secret-bearing part, and
//! the prefix makes the tag a function of *which entry this is* as well as
//! *what it names*.
//!
//! **The attack:** an attacker with a dump who knows the `rp_id_hash` of RP A
//! — it is the domain they are phishing, and it appears in their own URL bar —
//! computes nothing, and simply *edits* the dump. If the tag covered only the
//! `rp_id_hash`, they could take A's entry and rewrite its `slot` field to point
//! at slot B. The tag still verifies, the index answers "A is in slot B", and
//! the device opens B — a credential for a **different** account, presented in
//! answer to a different site's ceremony. The record's own AAD does not catch
//! it: it binds slot B's record to slot B, which is exactly where that body
//! legitimately lives.
//!
//! Binding `(domain, slot, generation)` into the MAC input is what stops that,
//! and it reuses `crypto::RecordAad` rather than inventing a second encoder for
//! the same three values — one record format, one AAD (`AGENTS.md` §5).
//!
//! **What is deliberately *not* bound: the flags byte.** It carries exactly one
//! bit (`ENTRY_PRESENT`), it is checked structurally before the tag is, and
//! binding it would add a field to the message without closing anything: an
//! attacker who clears `ENTRY_PRESENT` can only *delete* an entry — never forge,
//! redirect or disclose one — and an attacker with write access to the index can
//! equally erase the whole region. `AGENTS.md` §5: name the attack the
//! complexity stops. There is no attack it stops, so it is not there.
//!
//! # Where the index lives, and what it costs
//!
//! **The tail of the region: the last [`INDEX_SLOT_COUNT`] slots
//! ([`INDEX_FIRST_SLOT`]..`TOTAL_SLOTS`), laid out as one flat array of
//! [`ENTRIES_PER_SLOT`] entries per slot.** Each index slot is an ordinary
//! 1 KiB slot, so the index is erased and programmed under the same sector
//! discipline as everything else (`commit.rs`), needs no address arithmetic the
//! region does not already have, and holds exactly [`INDEX_ENTRY_BYTES`]-aligned
//! entries — one shift, no multiply.
//!
//! *Why the tail and not the head.* The allocator's rule is "lowest free slot"
//! (`slotmap.rs`, `SlotAllocator::alloc`), so a reservation at the head would be
//! handed out on the **first** credential ever enrolled and the index would be
//! destroyed immediately. At the tail the reservation is only reached after 928
//! slots are full, so the failure mode of a caller that forgets the reservation
//! is "the index is destroyed when the store fills", not "the index is
//! destroyed on the first write". Both are bugs; one of them is survivable.
//!
//! **What it costs: [`INDEX_SLOT_COUNT`] = 32 slots out of 960.** Every slot in
//! the region can hold a record and every record needs an index entry, so the
//! entry array has to cover the whole capacity:
//!
//! ```text
//! 32 slots x 1,024 B / 32 B per entry = 1,024 entries >= 960 records
//! ```
//!
//! 30 slots would have been enough arithmetically but is not a whole number of
//! NOR sectors (`SLOTS_PER_SECTOR` = 4), and 28 slots = 896 entries is below the
//! region's 960 records, which would leave the last 64 credentials unfindable.
//! 32 is the smallest sector-aligned reservation that covers the region, and it
//! leaves 64 spare entries.
//!
//! **The other reservation has to stay out of the way, and cannot be checked
//! from here.** `commit.rs` (US-1544/1545) reserves a **scratchpad sector** of
//! 4 slots — [`super::SCRATCHPAD_SLOTS`] — and
//! `CommitPlan::new` takes the scratchpad slot as a *caller's* argument rather
//! than pinning one. A caller that hands it an index sector erases the index on
//! every commit, and `commit.rs` cannot refuse: from where it sits, every slot
//! in the region is legal. So [`is_index_slot`] is published here for the same
//! reason it is published for the allocator — the index owns the geometry that
//! creates the hazard, and a hazard nothing can ask about is a hazard nothing
//! will avoid. **It is a documented constraint on a file this story does not
//! own, not an enforced one.**
//!
//! **The capacity consequence, which `mod.rs` has to absorb and this module
//! cannot.** `mod.rs` derives
//! `FIDO_CAPACITY = TOTAL_SLOTS - OATH_CAPACITY - SCRATCHPAD_SLOTS`
//! = 960 - 68 - 4 = **888**, and it asserts at compile time that
//! `TOTAL_SLOTS == FIDO_CAPACITY + OATH_CAPACITY + SCRATCHPAD_SLOTS` —
//! "every slot must be accounted for, with nothing unclaimed and nothing
//! double-counted". That assertion is the right one and it is exactly what
//! makes this a **conflict rather than a rounding error**: as it stands, all
//! 960 slots are claimed, so the 32 the index needs are 32 slots of FIDO's
//! area double-counted.
//!
//! ```text
//! FIDO_CAPACITY as it stands:                        888
//! FIDO_CAPACITY once the index is charged to it:     888 - 32 = 856
//! OATH_CAPACITY unchanged:                            68
//! SCRATCHPAD_SLOTS unchanged:                          4
//! 856 + 68 + 4 + 32 (index) == 960                     ok
//! ```
//!
//! So `mod.rs` needs one more term in its partition — `index::INDEX_SLOT_COUNT`
//! — in both `FIDO_CAPACITY` and the accounting assertion. That file is not
//! this story's, so it has not been done here; until it is, `FIDO_CAPACITY`
//! over-claims by 32 and the index overlaps the top 32 FIDO slots. 856 is
//! comfortably above the 256 the acceptance criteria name
//! (`platform/tests/key_region_capacity.rs:56-60`), so the fix costs 3.2% of a
//! capacity that had a 3.4× margin.
//!
//! # Why the entry is 32 bytes, and why it is fixed
//!
//! The 24 bytes of content round to **32** for two reasons, both arithmetic:
//!
//! * a power-of-two stride turns an entry's address inside a slot into a
//!   shift, and makes [`ENTRIES_PER_SLOT`] = 1,024 / 32 = **32** exactly, so
//!   the array tiles the slot with no partial entry and no tail slack;
//! * the 8 reserved bytes are growth room, which is the same reasoning
//!   `SLOT_MARGIN_BYTES` applies to a slot (`mod.rs`): a future index field —
//!   a credential-ID tag for CTAP2 `getCredentialsByRID`, a per-entry version
//!   byte — is a widening of one constant rather than a re-layout of a region
//!   that already holds records.
//!
//! **Bounded and fixed is a boot-path constraint, not tidiness.** The RP2350
//! boot stack is 5,056 B (`commit.rs` "Footprint" tracks the same budget), and
//! this module is verified on the device. An index that could be materialised
//! would be 1,024 x 32 = **32 KiB** — more than six times the entire boot
//! stack. So nothing here ever holds the array: [`lookup`] streams one 1 KiB
//! `SlotImage` at a time and keeps a single 32-byte entry, and the worst-case
//! resident cost is
//!
//! ```text
//! 1,024 (one slot image) + 32 (one entry) + ~110 (one SHA-256 context) ≈ 1.2 KiB
//! ```
//!
//! against the 5,056 B budget. That is why the entry is fixed-size, why the
//! entry count is a compile-time constant, and why there is no `Vec` anywhere in
//! this module.
//!
//! # Why the whole index is not sealed as one AEAD blob
//!
//! `crypto::seal_index_record` exists and an index record *is* a record in this
//! region, so the question is fair: why not authenticate 1,024 entries with one
//! tag?
//!
//! * **It would not survive a single credential write.** A sector-atomic commit
//!   (`commit.rs`) rewrites one sector; a whole-index tag would have to be
//!   recomputed and rewritten on every enrolment, turning a 1 KiB write into a
//!   32 KiB write and a 1-sector erase into an 8-sector one — on a part whose
//!   NOR endurance is specified **per sector**.
//! * **It would hide the tags**, and the tags are the feature: the index is
//!   meant to be readable from a dump, so a user who has forgotten their PIN can
//!   still be told which slots hold records. A blob only opens if you already
//!   hold the OTP row, at which point the per-entry tags verify just as well.
//! * **It would add no protection.** One whole-index tag and 1,024 per-entry
//!   tags have the same forgery resistance against an attacker holding the OTP
//!   row, and equally none against one who does not.
//!
//! So integrity is per entry, and *which entries are live* is answered
//! structurally by [`ENTRY_PRESENT`] plus the tag. A torn index write therefore
//! **loses** entries and cannot **invent** them, which is the right direction: a
//! lost entry makes a credential unfindable, whereas an invented one would have
//! to carry a valid tag to be believed — which needs the index key. US-1544 /
//! US-1545's commit marker is what makes the sector holding a rewritten entry
//! atomic; this module adds nothing on top of it.
//!
//! # What "verified" means here, stated precisely
//!
//! A MAC is only checked against a message you have, and this message contains
//! the `rp_id_hash`. So there is **no** PIN-free operation that certifies an
//! entry *in the abstract*. There are two PIN-free operations, and both are what
//! the scenario needs:
//!
//! * [`inspect_region`] — structural. Every cell parses, every present entry
//!   has a known domain, only [`ENTRY_PRESENT`] is set, its slot is inside the
//!   region and its reserved tail is zero. No key, no message, no hash. It
//!   answers "is this region's index structurally intact".
//! * [`lookup`] / [`lookup_all`] / [`verify`] — authenticating. For an
//!   `rp_id_hash` the caller already holds in the clear, recompute the tag for
//!   each present entry and compare it in constant time. An entry that does not
//!   verify is not returned and is counted as [`Verification::rejected`].
//!
//! Neither opens a record body, because neither takes a payload key: the
//! signature of [`lookup`] is
//! `(&IndexKey, &mut dyn KeyRegion, KeyDomain, &RpIdHash)` and there is no
//! parameter through which a `PayloadKey` could arrive.
//! `platform/tests/key_region_index.rs` asserts that on the bytes rather than
//! in a comment — it runs a full verification against a region whose
//! credential slots carry real payload-sealed bodies, and checks both that the
//! verifying code read **only** index slots and that no payload plaintext is
//! recoverable from the resulting dump.
//!
//! # Footprint
//!
//! ~1.2 KiB of stack, constant, at every point in this module; zero heap; one
//! SHA-256 context at a time. See "Why the entry is 32 bytes" for the
//! arithmetic.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::crypto::{IndexKey, KeyDomain, RecordAad};
use super::slotmap::SlotImage;
use super::{FIDO_SLOT_BYTES, KeyRegion, Slot, SlotRead, SLOTS_PER_SECTOR, TOTAL_SLOTS};

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// `SHA-256(rpId)` — the width CTAP 2.1 stores in a credential and sends to the
/// device on every ceremony (§7.1), which is why [`RpIdHash`] can be taken
/// straight off the wire.
pub const RP_ID_HASH_LEN: usize = 32;

/// The truncated-MAC width: **16 bytes**, half of HMAC-SHA256's 32.
///
/// Stated here rather than reusing `crypto::TAG_LEN` even though it is the same
/// number, because it is *not* the same thing: `crypto::TAG_LEN` is an AEAD's
/// tag, checked inside a decryption and never a stored plaintext structure's
/// content. This one **is** the index's content — it sits in a table an
/// operator reads out of a dump — so naming it independently is what stops a
/// later change to the AEAD tag width from silently resizing the index.
pub const TAG_LEN: usize = 16;

/// Bytes of content in an index entry: `domain(1) + flags(1) + slot(2) +
/// generation(4) + tag(16)`.
pub const ENTRY_CONTENT_BYTES: usize = 8 + TAG_LEN;

/// The one defined flag bit: **this entry names a live record**.
///
/// Reads as `0` on an erased NOR cell (`0xFF` clears it), which is what makes
/// "this entry is free" a zero-cost structural answer, and what keeps
/// [`IndexEntry::is_erased`] the only thing that has to notice an erased cell
/// before the flags byte is read as anything else.
///
/// The bit is **not** bound into the MAC; see the module docs, "What the MAC
/// covers".
pub const ENTRY_PRESENT: u8 = 0x01;

/// Reserved bytes at the tail of an entry. Must read `0x00` in a present entry.
pub const ENTRY_RESERVED_BYTES: usize = 8;

/// **The index entry stride: 32 bytes.**
///
/// Power of two, so an entry's address inside a slot is a shift; and
/// `1,024 / 32 = 32` entries exactly, so the array tiles a slot with no partial
/// entry. The arithmetic and the boot-stack budget behind both are in the
/// module docs.
pub const INDEX_ENTRY_BYTES: usize = 32;

/// Index entries per 1 KiB slot.
pub const ENTRIES_PER_SLOT: u32 = (FIDO_SLOT_BYTES as usize / INDEX_ENTRY_BYTES) as u32;

/// The index is the **last** `INDEX_SLOT_COUNT` slots of the region.
///
/// The tail, not the head, because the allocator takes the lowest free slot
/// (`slotmap.rs`): a head reservation would be overwritten by the first
/// credential ever enrolled. See the module docs.
///
/// **Derived, not chosen.** This was a literal `32` until
/// `platform/tests/board_def.rs` built an 8 MiB probe board and the
/// compile-time assertion below refused to compile: 32 slots is 1,024 entries,
/// which covers the 4 MiB part's 960 slots and nothing more. On a larger part
/// the key region grows with it (`Board::key_region_kb`), and a fixed 32 would
/// have left thousands of credentials enrolled, durable and **unfindable** — a
/// failure with no error at enrollment time and a credential that simply stops
/// working.
///
/// So the count is solved for: enough slots that every record slot in the region
/// has an entry, rounded up to a whole NOR sector because a partial sector has
/// no commit unit. On the shipping 4 MiB part this is still 32 — the number
/// does not change, it stops being a coincidence.
pub const INDEX_SLOT_COUNT: u32 = {
    // Enough slots that the index holds at least one entry per slot in the
    // region: `I * ENTRIES_PER_SLOT >= TOTAL_SLOTS`, so `I >= TOTAL / E`,
    // rounded up to a whole NOR sector.
    //
    // It covers strictly more than it needs to: the commit scratchpad and the
    // index's own slots hold no records, so the entries for them are spare.
    // Overshooting is free and buys one thing worth having — the coverage
    // property is "one entry per slot in the region", which is a statement
    // that cannot go stale when another reservation is added later, rather
    // than a sum that has to be kept in step with every one of them.
    TOTAL_SLOTS
        .div_ceil(ENTRIES_PER_SLOT)
        .next_multiple_of(SLOTS_PER_SECTOR)
};

/// Index slots start here: `TOTAL_SLOTS - INDEX_SLOT_COUNT`.
pub const INDEX_FIRST_SLOT: u32 = TOTAL_SLOTS - INDEX_SLOT_COUNT;

/// Index entries the reserved slots hold in total: **1,024**, against the 960
/// records the region can hold. Pinned by a compile-time assertion below, and
/// it is that assertion rather than this comment which makes the number true.
pub const INDEX_CAPACITY: u32 = INDEX_SLOT_COUNT * ENTRIES_PER_SLOT;

/// HKDF-style label mixed in front of the index MAC's message.
///
/// Namespaced and versioned like `crypto::INDEX_KEY_INFO` and its siblings
/// (`crypto.rs`, "Labels"), and distinct from every one of them because it
/// separates a *different construction*: those separate two keys derived from
/// one IKM, this separates this MAC's message from a bare `rp_id_hash` hashed
/// under anything else. An unlabelled `HMAC(k_index, rp_id_hash)` would be
/// indistinguishable from any other use of the same key over the same input,
/// which is the class of defect `crypto.rs`'s label table exists to prevent.
pub const INDEX_MAC_INFO: &[u8] = b"fapico2/keyregion/index/mac/v1";

// Field offsets. Stated as constants so the layout table in the module docs and
// the codec cannot drift apart.
const OFF_DOMAIN: usize = 0;
const OFF_FLAGS: usize = 1;
const OFF_SLOT: usize = 2;
const OFF_GENERATION: usize = 4;
const OFF_TAG: usize = 8;
const OFF_RESERVED: usize = OFF_TAG + TAG_LEN;

// ---------------------------------------------------------------------------
// The rp_id_hash
// ---------------------------------------------------------------------------

/// `SHA-256(rpId)`, as an opaque type.
///
/// A newtype rather than `[u8; RP_ID_HASH_LEN]` for one reason that matters:
/// `rp_id_hash` is **not** a secret, and a type that looks like a key is exactly
/// how it ends up logged, compared with `==` on a timing path, or mistaken for
/// something the PIN protects. [`Self::as_bytes`] borrows and `Self` is `Copy`;
/// there is no accessor pretending it hides anything, because it does not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RpIdHash([u8; RP_ID_HASH_LEN]);

impl RpIdHash {
    /// Wrap the 32 bytes of a `SHA-256(rpId)`.
    pub const fn from_bytes(bytes: [u8; RP_ID_HASH_LEN]) -> Self {
        RpIdHash(bytes)
    }

    /// The 32 bytes, for hashing into the MAC.
    pub const fn as_bytes(&self) -> &[u8; RP_ID_HASH_LEN] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// One entry
// ---------------------------------------------------------------------------

/// One authenticated index entry: **which record, provably, and nothing about
/// what is in it.**
///
/// Private fields, because this structure carries the index's authenticity
/// argument and a field that could be edited after the tag was computed would
/// let a caller author an entry whose tag describes different bytes. The only
/// ways in are [`IndexEntry::build`] (which computes the tag) and
/// [`IndexEntry::decode`] (which parses stored bytes and refuses anything
/// malformed).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    domain: KeyDomain,
    flags: u8,
    slot: Slot,
    generation: u32,
    tag: [u8; TAG_LEN],
}

impl IndexEntry {
    /// Build a present entry for `(domain, slot, generation)`, tagged for
    /// `rp_id_hash`.
    ///
    /// Takes an [`IndexKey`] rather than raw bytes: the entry's whole security
    /// claim is that the tag was made under the device-rooted index key, and a
    /// constructor taking `[u8; 32]` would accept any key while still producing
    /// an `IndexEntry`.
    ///
    /// **No payload key is involved and none can be.** The tag is an HMAC over
    /// `rp_id_hash` and the entry's identity, so nothing here reads a record
    /// body. That is what lets the index be updated without the PIN being on
    /// the path: an entry describes *which slot*, never *what is in it*.
    pub fn build(
        key: &IndexKey,
        domain: KeyDomain,
        slot: Slot,
        generation: u32,
        rp_id_hash: &RpIdHash,
    ) -> Self {
        IndexEntry {
            domain,
            flags: ENTRY_PRESENT,
            slot,
            generation,
            tag: entry_tag(key, domain, slot, generation, rp_id_hash),
        }
    }

    /// Which applet's record this entry names.
    pub const fn domain(self) -> KeyDomain {
        self.domain
    }

    /// The raw flags byte. Only [`ENTRY_PRESENT`] is defined, and
    /// [`IndexEntry::decode`] refuses any other bit.
    pub const fn flags(self) -> u8 {
        self.flags
    }

    /// The record slot this entry points at.
    pub const fn slot(self) -> Slot {
        self.slot
    }

    /// The generation of the record this entry names — the same `u32` the record
    /// header and the record AAD carry.
    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// The truncated MAC. Not secret, and hiding nothing: it is a keyed
    /// function of an `rp_id_hash` that is itself public, and it is 16 bytes.
    pub const fn tag(&self) -> &[u8; TAG_LEN] {
        &self.tag
    }

    /// Does this entry's tag authenticate `rp_id_hash`?
    ///
    /// **Constant time**, via [`subtle::ConstantTimeEq`] — the same compare
    /// `platform/src/migration.rs` and `platform/src/fw_manifest.rs:76-93` use
    /// for MACs. The attacker this index is built against controls a flash
    /// image and can therefore submit chosen tags in bulk; a byte-at-a-time
    /// `==` on a 16-byte MAC leaks it a byte at a time.
    ///
    /// It answers for this entry's own `(domain, slot, generation)`, which is
    /// why a dump edit that moves an entry to another slot recomputes a
    /// different expected tag and fails here (module docs, "What the MAC
    /// covers").
    pub fn verify(&self, key: &IndexKey, rp_id_hash: &RpIdHash) -> bool {
        let expected = entry_tag(key, self.domain, self.slot, self.generation, rp_id_hash);
        bool::from(expected.ct_eq(&self.tag))
    }

    /// Serialize into exactly [`INDEX_ENTRY_BYTES`] bytes.
    pub fn encode(&self) -> [u8; INDEX_ENTRY_BYTES] {
        let mut out = [0u8; INDEX_ENTRY_BYTES];
        out[OFF_DOMAIN] = self.domain.tag();
        out[OFF_FLAGS] = self.flags;
        out[OFF_SLOT..OFF_SLOT + 2].copy_from_slice(&self.slot.index().to_le_bytes());
        out[OFF_GENERATION..OFF_GENERATION + 4].copy_from_slice(&self.generation.to_le_bytes());
        out[OFF_TAG..OFF_TAG + TAG_LEN].copy_from_slice(&self.tag);
        // The reserved tail is left zero and `encode` writes nothing there, so
        // `decode`'s requirement of zeros is checking a property the encoder
        // really does hold rather than a coincidence.
        out
    }

    /// Parse stored entry bytes.
    ///
    /// Checks, cheapest and most decisive first: length (a buffer shorter than
    /// an entry is a **transport** failure, not a fact about the data — that is
    /// the `Fault`/`Absent` split `SlotRead` exists for, `mod.rs`), then the
    /// flags byte in both directions (present-but-unflagged is an unfinished
    /// write; flagged with a bit this build does not know is a future format),
    /// then the domain, then the slot, then the reserved tail.
    ///
    /// **The tag is not checked here — it cannot be.** A MAC is only checked
    /// against a message, and the message contains the `rp_id_hash`, which is
    /// not in the entry. Authentication is [`IndexEntry::verify`], and it is a
    /// separate call so that "this parses" and "this is genuine" stay
    /// distinguishable in the counters [`Verification`] reports.
    pub fn decode(raw: &[u8]) -> SlotRead<Self> {
        if raw.len() < INDEX_ENTRY_BYTES {
            return SlotRead::Fault("index entry buffer shorter than one entry");
        }
        if Self::is_erased(raw) {
            // Not "present", and not corrupt either: a cell that was never
            // programmed. The caller counts it as free.
            return SlotRead::Absent;
        }
        let flags = raw[OFF_FLAGS];
        if flags & ENTRY_PRESENT == 0 || flags & !ENTRY_PRESENT != 0 {
            // Both directions, for the reasons on `record::FLAG_SEALED`: an
            // unflagged entry is an unfinished write and an over-flagged one is
            // a format this build does not know. Incomplete is not usable and
            // unknown is not readable.
            return SlotRead::Absent;
        }
        let Some(domain) = KeyDomain::from_tag(raw[OFF_DOMAIN]) else {
            return SlotRead::Absent;
        };
        // `Slot::new` bounds the index against `TOTAL_SLOTS` (`mod.rs`), so a
        // corrupt-but-well-formed entry cannot become a `Slot` a caller could
        // address with.
        let Some(slot) = Slot::new(u16::from_le_bytes([raw[OFF_SLOT], raw[OFF_SLOT + 1]])) else {
            return SlotRead::Absent;
        };
        if raw[OFF_RESERVED..OFF_RESERVED + ENTRY_RESERVED_BYTES]
            .iter()
            .any(|b| *b != 0)
        {
            // Unused bytes that are not zero mean the medium holds something
            // this format does not describe — a record written by a build with a
            // different layout, or a torn write. Either way: not readable under
            // v1 rules.
            return SlotRead::Absent;
        }
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&raw[OFF_TAG..OFF_TAG + TAG_LEN]);
        SlotRead::Present(IndexEntry {
            domain,
            flags,
            slot,
            generation: u32::from_le_bytes([
                raw[OFF_GENERATION],
                raw[OFF_GENERATION + 1],
                raw[OFF_GENERATION + 2],
                raw[OFF_GENERATION + 3],
            ]),
            tag,
        })
    }

    /// Whether these are a pristine `0xFF` cell — never programmed.
    ///
    /// The same test `slotmap::is_erased` makes for a slot, applied at entry
    /// granularity and for the same reason: an erased NOR byte reads `0xFF`, so
    /// this is the only honest way to say "there is no entry here" as distinct
    /// from "there is an entry I cannot read".
    pub fn is_erased(raw: &[u8]) -> bool {
        raw.iter().all(|b| *b == 0xFF)
    }
}

/// The truncated MAC for one entry: `HMAC-SHA256(k_index, label ‖ aad ‖
/// rp_id_hash)[..TAG_LEN]`.
///
/// The AAD is `crypto::RecordAad`'s — the tree's single encoder for `(domain,
///
/// slot, generation)` — rather than a second assembly of the same three values.
/// Two encoders of one triple is the defect `record.rs` already documents having
/// had ("Known conflict with `crypto.rs`").
///
/// **Truncation, and nothing else.** The full 32-byte MAC is computed and the
/// **first 16 bytes** are taken; it is not re-derived, re-keyed or hashed down,
/// so the stored tag is exactly the head of an HMAC-SHA256 that the holder of
/// the key can also compute and compare against.
fn entry_tag(
    key: &IndexKey,
    domain: KeyDomain,
    slot: Slot,
    generation: u32,
    rp_id_hash: &RpIdHash,
) -> [u8; TAG_LEN] {
    let aad = RecordAad::new(domain, slot, generation);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes())
        .expect("HMAC accepts a key of any length, including 32 bytes");
    mac.update(INDEX_MAC_INFO);
    mac.update(aad.as_bytes());
    mac.update(rp_id_hash.as_bytes());
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

impl fmt::Debug for IndexEntry {
    /// Prints the identity and **not** the tag.
    ///
    /// The tag is not secret — it is a keyed function of a value that is itself
    /// public — but it is a *stable per-RP pseudonymous identifier*, and a
    /// `Debug` that prints one puts "this user has a credential for that site"
    /// into a log buffer. Same rule and same reasoning as [`super::Sealed`]'s
    /// hand-written `Debug` (`mod.rs`) and `record::Plaintext`'s (`record.rs`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IndexEntry({:?}, slot {}, generation {}, tag <redacted>)",
            self.domain,
            self.slot.index(),
            self.generation
        )
    }
}

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

/// The [`SlotRead::Fault`] string this module reports when an index slot cannot
/// be read.
///
/// One named string rather than the region's own, because the distinction the
/// three-state read exists to make is "could not learn" and a caller should be
/// able to tell *this module* declined to answer from *the transport* declined
/// to answer. The region's `&'static str` is dropped here deliberately: it
/// describes a failure this module did not observe, and every
/// [`KeyRegion::read_slot`] in the tree already reports its own.
pub const E_INDEX_SLOT_UNREADABLE: &str = "key region index: an index slot could not be read";

/// Is this slot part of the reserved index?
///
/// The predicate the allocator must not cross: every scan that hands out a slot
/// has to stop before [`INDEX_FIRST_SLOT`]. It lives here rather than in
/// `slotmap.rs` because the index owns the geometry that creates the
/// reservation, and a reservation nothing can ask about is a reservation nothing
/// will respect.
pub const fn is_index_slot(slot: Slot) -> bool {
    let index = slot.index() as u32;
    index >= INDEX_FIRST_SLOT && index < INDEX_FIRST_SLOT + INDEX_SLOT_COUNT
}

/// The index slot holding entry `ordinal`, counted across the whole reserved
/// range from [`INDEX_FIRST_SLOT`].
///
/// `None` for an ordinal the reserved slots cannot hold — the bound is
/// [`INDEX_CAPACITY`], so a caller iterating `0..INDEX_CAPACITY` cannot get
/// `None`, and a caller that ignores the answer cannot walk off the end.
pub const fn entry_slot(ordinal: u32) -> Option<Slot> {
    if ordinal < INDEX_CAPACITY {
        Slot::new((INDEX_FIRST_SLOT + ordinal / ENTRIES_PER_SLOT) as u16)
    } else {
        None
    }
}

/// The byte offset of entry `ordinal` inside the slot [`entry_slot`] returns.
pub const fn entry_offset(ordinal: u32) -> u32 {
    (ordinal % ENTRIES_PER_SLOT) * INDEX_ENTRY_BYTES as u32
}

/// Total index entries the reserved slots hold, as a `u32` a runtime loop can
/// use directly.
pub const fn index_capacity() -> u32 {
    INDEX_SLOT_COUNT * ENTRIES_PER_SLOT
}

// ---------------------------------------------------------------------------
// Structural inspection — no key, no hash, no message
// ---------------------------------------------------------------------------

/// What one index slot's bytes say, without a key.
///
/// Three counters and no identities, because the whole point of this operation
/// is that it runs on a dump holding nothing but the OTP row and no `rp_id` to
/// offer: it answers "is this region's index structurally intact", which is the
/// question an operator triaging a dead board actually has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IndexSlotReport {
    /// Entries that are pristine `0xFF` — never programmed.
    pub free: u32,
    /// Entries that parse under v1 rules. **Not** authenticated — see
    /// [`Verification`] for the counter that means genuine.
    pub present: u32,
    /// Entries that are neither erased nor parseable under v1 rules.
    ///
    /// Reported rather than silently skipped, because a non-zero value here is
    /// the difference between "the index is intact" and "the index is intact
    /// except for the sector a power cut landed in" — and an index that quietly
    /// drops entries looks exactly like an index with fewer credentials.
    pub malformed: u32,
}

/// Inspect one index slot's bytes. No key, no MAC, no region access.
///
/// 32 parses of 32 bytes, no allocation, and no cell outside `raw` is read.
pub fn inspect_slot(raw: &SlotImage) -> IndexSlotReport {
    let mut report = IndexSlotReport::default();
    let mut n = 0u32;
    while n < ENTRIES_PER_SLOT {
        let at = entry_offset(n) as usize;
        match IndexEntry::decode(&raw[at..at + INDEX_ENTRY_BYTES]) {
            SlotRead::Present(_) => report.present += 1,
            SlotRead::Absent | SlotRead::Fault(_) => {
                if IndexEntry::is_erased(&raw[at..at + INDEX_ENTRY_BYTES]) {
                    report.free += 1;
                } else {
                    report.malformed += 1;
                }
            }
        }
        n += 1;
    }
    report
}

/// Inspect every reserved index slot.
///
/// Reads index slots **only**. There is nothing in a credential slot this
/// operation looks at, and the walk below is the only loop that performs a
/// region read in this module.
///
/// `Fault` if any index slot could not be read — never memoized as a clean
/// report, because a transport failure is not a fact about the data (US-1573).
pub fn inspect_region(region: &mut dyn KeyRegion) -> SlotRead<IndexSlotReport> {
    let mut total = IndexSlotReport::default();
    let mut s = 0u32;
    while s < INDEX_SLOT_COUNT {
        let slot = entry_slot(s * ENTRIES_PER_SLOT)
            .expect("s < INDEX_SLOT_COUNT, so this ordinal is inside the index");
        // A transport failure is a `Fault`, never folded into the counters: an
        // unreadable index slot must not be reported as a malformed entry, or
        // "the flash is failing" becomes "three entries are corrupt" and nobody
        // looks at the flash.
        let Ok(raw) = region.read_slot(slot) else {
            return SlotRead::Fault(E_INDEX_SLOT_UNREADABLE);
        };
        let one = inspect_slot(&raw);
        total.free += one.free;
        total.present += one.present;
        total.malformed += one.malformed;
        s += 1;
    }
    SlotRead::Present(total)
}

// ---------------------------------------------------------------------------
// Authentication — index key only, and no payload path anywhere
// ---------------------------------------------------------------------------

/// What an authenticating pass over the index found.
///
/// Three counters, and the split between [`Self::present`] and
/// [`Self::authenticated`] is the point of the module: an entry can parse
/// perfectly and still not be genuine, and a caller that only ever learned the
/// first number would treat a forged index as a good one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Verification {
    /// Entries in the index that parse and claim `ENTRY_PRESENT`.
    pub present: u32,
    /// Of those, how many carry a tag that authenticates one of the
    /// `rp_id_hash`es the caller supplied.
    pub authenticated: u32,
    /// Entries whose tag matched **no** supplied `rp_id_hash`.
    ///
    /// Not an error: an index legitimately holds entries for RPs this caller
    /// did not ask about. It is reported so that "verify with the full set
    /// before concluding" is *available* rather than assumed.
    pub rejected: u32,
}

/// Verify the index against a set of `rp_id_hash`es, with no PIN and no payload
/// key.
///
/// This is the scenario's "the index is verified", as a count: **every** entry
/// in the region is parsed and each is asked whether it authenticates one of
/// the supplied `rp_id_hash`es under the device-rooted index key. Nothing is
/// decrypted — see the module docs, "What *verified* means here".
///
/// `rp_id_hashes` is the caller's list, and it is not a secret: CTAP 2.1 sends
/// `rp_id_hash` to the device in the clear on every ceremony. The useful
/// property is that the *answer* needs no PIN even when the region was written
/// by a device that had one set.
pub fn verify(
    key: &IndexKey,
    region: &mut dyn KeyRegion,
    domain: KeyDomain,
    rp_id_hashes: &[RpIdHash],
) -> SlotRead<Verification> {
    let mut result = Verification::default();
    match walk_present(region, domain, |entry| {
        result.present += 1;
        if rp_id_hashes.iter().any(|rp| entry.verify(key, rp)) {
            result.authenticated += 1;
        } else {
            result.rejected += 1;
        }
        true
    }) {
        SlotRead::Fault(reason) => SlotRead::Fault(reason),
        _ => SlotRead::Present(result),
    }
}

/// The slot whose index entry authenticates `rp_id_hash` — the whole point of
/// the module, in one call.
///
/// **Reads index slots only.** No credential slot is opened, and no payload key
/// exists anywhere on this path: the parameter list is
/// `(&IndexKey, &mut dyn KeyRegion, KeyDomain, &RpIdHash)` and there is nowhere
/// for one to arrive.
///
/// The first match in index order wins, which makes the answer deterministic
/// for a given dump — a property a caller comparing two dumps needs.
///
/// [`SlotRead::Absent`] means no entry in this domain authenticates the hash.
/// That is a fact about the data, so it is `Absent` and not `Fault`; but see
/// [`SlotRead::present`]'s warning, because "no such credential" and "the index
/// is broken" are the same answer here and only [`verify`] separates them.
pub fn lookup(
    key: &IndexKey,
    region: &mut dyn KeyRegion,
    domain: KeyDomain,
    rp_id_hash: &RpIdHash,
) -> SlotRead<Slot> {
    let mut found: Option<Slot> = None;
    let outcome = walk_present(region, domain, |entry| {
        if entry.verify(key, rp_id_hash) {
            found = Some(entry.slot());
            return false;
        }
        true
    });
    match (outcome, found) {
        (_, Some(slot)) => SlotRead::Present(slot),
        (_, None) => SlotRead::Absent,
    }
}

/// Every slot whose index entry authenticates `rp_id_hash`, appended to `out`.
///
/// The enumeration shape, for an `rp_id_hash` with more than one resident
/// credential — the normal case for CTAP2 `authenticatorCredentialManagement`.
/// `out` is the caller's buffer, and it is why this does not allocate: a no_std
/// firmware with a 5,056 B boot stack has no business collecting hundreds of
/// slots into a `Vec`.
///
/// Returns the **total** number of matches, which may exceed `out.len()`, so a
/// caller can tell "that was all of them" from "that was all that fit".
///
/// Same properties as [`lookup`]: index slots only, no payload key, no
/// decryption.
pub fn lookup_all(
    key: &IndexKey,
    region: &mut dyn KeyRegion,
    domain: KeyDomain,
    rp_id_hash: &RpIdHash,
    out: &mut [Slot],
) -> SlotRead<usize> {
    let mut total = 0usize;
    match walk_present(region, domain, |entry| {
        if entry.verify(key, rp_id_hash) {
            if let Some(slot) = out.get_mut(total) {
                *slot = entry.slot();
            }
            total += 1;
        }
        true
    }) {
        SlotRead::Fault(reason) => SlotRead::Fault(reason),
        _ => SlotRead::Present(total),
    }
}

/// Stream every present entry of one `domain`, in index order, stopping early
/// when `visit` returns `false`.
///
/// The single loop every other function here is written on top of, which is what
/// makes "verification reads only index slots" a property of one piece of code
/// rather than a claim repeated at four call sites.
///
/// **Stack: one [`SlotImage`] (1 KiB) and one [`IndexEntry`] (32 B) at a time.**
/// The array is never materialised — see the module docs, "Why the entry is 32
/// bytes".
fn walk_present(
    region: &mut dyn KeyRegion,
    domain: KeyDomain,
    mut visit: impl FnMut(IndexEntry) -> bool,
) -> SlotRead<u32> {
    let mut visited = 0u32;
    let mut s = 0u32;
    while s < INDEX_SLOT_COUNT {
        let slot = entry_slot(s * ENTRIES_PER_SLOT)
            .expect("s < INDEX_SLOT_COUNT, so this ordinal is inside the index");
        let Ok(raw) = region.read_slot(slot) else {
            return SlotRead::Fault(E_INDEX_SLOT_UNREADABLE);
        };
        let mut n = 0u32;
        while n < ENTRIES_PER_SLOT {
            let at = entry_offset(n) as usize;
            if let SlotRead::Present(entry) = IndexEntry::decode(&raw[at..at + INDEX_ENTRY_BYTES])
            {
                if entry.domain() == domain {
                    visited += 1;
                    if !visit(entry) {
                        return SlotRead::Present(visited);
                    }
                }
            }
            n += 1;
        }
        s += 1;
    }
    SlotRead::Present(visited)
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

const _: () = {
    // The content and the stride must agree, or `encode` would write past the
    // entry or `decode` would read into the next one.
    assert!(
        INDEX_ENTRY_BYTES == ENTRY_CONTENT_BYTES + ENTRY_RESERVED_BYTES,
        "the index entry stride must be its content plus its reserved tail — a stride that is \
         neither is a stride that is not tiled"
    );

    // Every field lands inside the entry, in the order the layout table states.
    // The offsets are the contract between `encode` and `decode`, so they are
    // checked rather than trusted.
    assert!(OFF_DOMAIN == 0, "the domain opens the entry");
    assert!(OFF_FLAGS == OFF_DOMAIN + 1, "the flags follow the domain");
    assert!(OFF_SLOT == OFF_FLAGS + 1, "the slot follows the flags");
    assert!(
        OFF_GENERATION == OFF_SLOT + 2,
        "the u32 generation must start on a 4-byte boundary or it is unaligned in the buffer"
    );
    assert!(OFF_TAG == OFF_GENERATION + 4, "the tag follows the generation");
    assert!(
        OFF_RESERVED == OFF_TAG + TAG_LEN,
        "the reserved tail follows the tag"
    );
    assert!(
        OFF_RESERVED + ENTRY_RESERVED_BYTES == INDEX_ENTRY_BYTES,
        "the reserved tail must close the entry"
    );

    // The stride is a power of two, so an entry never straddles a flash page
    // and its address inside a slot is a shift.
    //
    // Stated as a power-of-two identity rather than `x % y == 0`: it says more,
    // and CI runs clippy with `-D warnings` where `manual_is_multiple_of`
    // rejects the `%` form — the same argument `mod.rs` gives for the slot
    // strides.
    assert!(
        INDEX_ENTRY_BYTES >= 32 && INDEX_ENTRY_BYTES & (INDEX_ENTRY_BYTES - 1) == 0,
        "the index entry stride must be a power of two, so entry addressing inside a slot is a \
         shift and 1,024 divides by it exactly"
    );

    // The array must tile the reserved slots exactly: no partial entry at the
    // end of a slot, and no unaccounted tail.
    assert!(
        ENTRIES_PER_SLOT * INDEX_ENTRY_BYTES as u32 == FIDO_SLOT_BYTES,
        "the index entries must tile an index slot exactly — a partial entry at the end of a slot \
         would be a torn-write hazard NOR cannot repair"
    );

    // The reservation must be a whole number of NOR sectors, and must start on
    // one. The sector is the erase and commit unit (`mod.rs`), so an index
    // spanning a partial sector would make "erase the sector holding this entry"
    // also erase a credential.
    assert!(
        INDEX_SLOT_COUNT == (INDEX_SLOT_COUNT / SLOTS_PER_SECTOR) * SLOTS_PER_SECTOR,
        "the index reservation must be a whole number of NOR sectors — the sector is the erase and \
         commit unit, so a partial-sector reservation has no valid erase"
    );
    assert!(
        INDEX_FIRST_SLOT.is_multiple_of(SLOTS_PER_SECTOR),
        "the index must start on a sector boundary, so erasing an index sector never touches a \
         credential"
    );
    assert!(
        INDEX_FIRST_SLOT == TOTAL_SLOTS - INDEX_SLOT_COUNT,
        "the index is the region's tail — if this moves, the allocator's lowest-free rule has to \
         be re-read against it"
    );
    assert!(
        INDEX_SLOT_COUNT > 0 && INDEX_SLOT_COUNT < TOTAL_SLOTS,
        "the index reservation must be a reservation and not the region"
    );

    // **The load-bearing one.** Every record the region can hold needs an index
    // entry or it can never be found, and this is the assertion that fails the
    // build if a future stride or a smaller reservation stops covering the
    // capacity. It is why `INDEX_SLOT_COUNT` is 32 and not 28: 28 slots is 896
    // entries against 960 records, so the last 64 credentials would be
    // unfindable — not a smaller index, a broken one.
    //
    // The bound is `TOTAL_SLOTS`, not `FIDO_CAPACITY + OATH_CAPACITY`: the
    // commit scratchpad holds no record and so needs no entry, and the two
    // reservations must tile the region between them (module docs, "Where the
    // index lives").
    assert!(
        INDEX_CAPACITY >= TOTAL_SLOTS,
        "the index cannot hold one entry per slot in the region — a credential with no entry \
         cannot be found. Raise INDEX_SLOT_COUNT (whole NOR sectors) or lower the entry stride. \
         Do not ship an index that does not cover the capacity"
    );

    // The tag is half an HMAC-SHA256 and nothing else: a "truncated" tag wider
    // than the MAC, or narrower than the 16 bytes the module docs state, would
    // make the docs a different design from the code.
    assert!(
        TAG_LEN == 16 && TAG_LEN < 32,
        "the index tag must be a truncation of HMAC-SHA256's 32-byte output"
    );
};
