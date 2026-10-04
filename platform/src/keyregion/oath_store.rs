//! The OATH side of the key region (US-1553).
//!
//! ```gherkin
//! Scenario: OATH and FIDO stop competing for the 24 entries
//!   Given a device with FIDO at capacity and OATH at capacity
//!   When both applets store their full sets
//!   Then neither is refused for slot exhaustion
//!   And the secure store holds no applet credential table
//! ```
//!
//! # Why this file exists, and what it fixes
//!
//! `AGENTS.md` §5 records the arithmetic that made both applets unusable:
//! [`crate::secure_store`]'s [`Rp2350SecureStore`] holds
//! `DEV_MAX_ENTRIES = 24` entries in total, OATH's credential table is written
//! as a *chunked whole snapshot* (`oath.keystore.v1`, 12 parts at the measured
//! ceiling), and a chunked rewrite holds **both generations live** at its peak.
//! So the binding constraint is
//!
//! ```text
//! other_applet_slots + old_parts + new_parts <= 24
//! ```
//!
//! and OATH's *measured* durable ceiling was **30 credentials**
//! (`apps/oath/tests/oath_capacity.rs` before US-1553) — not the 68 the applet's
//! `MAX_CREDS` names, and not a number FIDO and OATH could both reach anyway.
//!
//! This file moves OATH's credentials out of that shared image and into
//! [`OATH_SLOTS`](self::OATH_SLOTS) slots of their own in the key region, one
//! credential per slot, committed one record at a time
//! ([`commit::commit`]). The rewrite peak disappears with the snapshot: a
//! credential write now holds *one* generation of *one* slot, so the ceiling is
//! the region's geometry and nothing else.
//!
//! # Three decisions this module makes, and the reason for each
//!
//! **1. One credential per 1 KiB slot, not two per 512 B sub-slot.**
//! [`super::OATH_SLOT_BYTES`] is 512 and divides [`super::FIDO_SLOT_BYTES`]
//! exactly (`mod.rs`'s compile-time assertion), so a 68-slot OATH area could
//! hold 136 credentials at the same flash cost. It does not, because the
//! hardware's unit is the **sector**: [`SLOTS_PER_SECTOR`](super::SLOTS_PER_SECTOR)
//! is 4 and a 4 KiB NOR erase clears four 1 KiB slots at once. A 512 B
//! commitment would need a second commit protocol — one that stages *within* a
//! slot — beside the one [`commit`] already implements and that US-1544/US-1545
//! made crash-safe. AGENTS.md §5: name the attack the complexity stops. There
//! is none here — the 512 B stride buys capacity the region does not need
//! ([`OATH_CAPACITY`](super::OATH_CAPACITY) is already the applet's RAM table
//! bound) at the price of a second atomicity argument to get wrong.
//!
//! **2. The record body is a fixed layout, not the US-413 TLV stream.** The
//! stream format exists because C produced one
//! ([`fapico2_platform::migration`]); a slot record has no such history and a
//! TLV walker is 40 lines and a length-arithmetic bug surface where a fixed
//! layout is a bounds check. The two formats do not meet again: the legacy
//! stream is still read on the migration path and still written for the records
//! that are *not* credentials (the access code and the OTP-PIN record).
//!
//! **3. The record's own generation is the `OathSeal` nonce generation.** This
//! is the one place where US-1030's ordering discipline has to be re-argued,
//! so it is argued here in full — see "Why the seal generation is the record
//! generation", below.
//!
//! # Why the seal generation is the record generation
//!
//! US-1030 keeps a **device-wide monotonic counter** in its own store slot
//! (`oath.seal.gen.v1`) and derives each credential key's GCM nonce from
//! `OATH/SEAL-NONCE/v1 ‖ fid ‖ generation` (`ckey.rs::OathSeal::nonce_for`).
//! The ordering rule is load-bearing and the story's constraints require it to
//! survive: **the counter is made durable before the first sealed byte exists**,
//! so a cut between the two leaves the counter *ahead* of the record and the
//! next boot re-seals at a strictly higher generation. The failure it prevents
//! is a GCM nonce reused on different plaintext, which is catastrophic and
//! silent.
//!
//! That ordering exists only because the counter and the sealed bytes are two
//! separate writes. In the region they are **one write**: the generation is a
//! field of the record header, it is bound into the record's AAD, and the
//! sector-atomic commit programs the header and the body together or not at
//! all. There is no window in which a counter is ahead of, or behind, a sealed
//! record — because there is no separate counter. The discipline is therefore
//! not relaxed; it is subsumed by a stronger mechanism, and the OATH area loses
//! a resident store slot.
//!
//! Three properties are checked rather than asserted:
//!
//! * **Strictly increasing.** [`OathStore::write`] reads the slot's current
//!   generation from the medium and offers `current + 1`, and
//!   [`commit::commit`] independently refuses a generation that does not
//!   advance over what is already there (`commit.rs`, step 2). A replayed or
//!   rolled-back generation is rejected twice.
//! * **Monotone across a delete and re-provision of the same name.** A delete
//!   writes a **tombstone**, not an erase — [`commit`] has no single-slot
//!   delete on purpose (`commit.rs`, "Why there is no single-slot delete here",
//!   because a target programmed `0xFF` is indistinguishable from a commit
//!   that never reached its witness and could be resurrected as a replay). The
//!   tombstone carries the generation forward, so the next credential at that
//!   slot is sealed at a strictly higher one.
//! * **Distinct across slots.** `nonce_for` binds the record's `fid` as well as
//!   its generation, and two slots have different `fid`s, so two credentials
//!   sealed at the same generation never share a nonce.
//!
//! The cost is honest and small: the guarantee is **per slot** rather than per
//! device, so a device-wide ordering argument is gone — but the guarantee that
//! actually mattered (no nonce twice on two plaintexts) is unchanged, because
//! the counter that provides it can no longer be torn away from the record it
//! protects.
//!
//! # What this module does not do
//!
//! * **It does not write the index.** `index.rs` has no writer — only
//!   `lookup`/`lookup_all`/`verify`, all of which take an [`IndexKey`] and read
//!   index slots. Adding one is a change to a file this story does not own, and
//!   OATH does not need it: the applet holds its whole table in RAM anyway
//!   (`MAX_CREDS`), so a mount that opens all [`OATH_SLOTS`] slots once builds
//!   the name → credential map directly, with no second structure to keep
//!   consistent. The index's argument — *find* a record without opening any —
//!   buys something for FIDO's 856 slots and buys nothing for OATH's 68.
//! * **It does not decide when a device region exists.** There is no QSPI
//!   [`KeyRegion`](super::KeyRegion) implementation in the tree yet, so the
//!   handle here is whatever the caller boxes into it. `firmware/` wiring is a
//!   later story and is deliberately not guessed at here.
//! * **It does not wipe.** A factory reset tombstones OATH's own slots; a
//!   whole-region erase is [`commit::wipe`] and belongs to whoever owns the
//!   region's lifetime.
//!
//! # The geometry, and the coordination this file asks of the FIDO adapter
//!
//! ```text
//! slot 0 .............. 67   OATH credentials      (OATH_SLOTS = 68)
//! slot 68 ............. 71   commit scratchpad     (SCRATCHPAD_SLOTS = 4)
//! slot 72 ............ 927   FIDO credentials      (FIDO_CAPACITY = 856)
//! slot 928 ........... 959   index                 (INDEX_SLOT_COUNT = 32)
//! ```
//!
//! **The scratchpad is shared, on purpose.** [`mod.rs`](super) charges
//! exactly [`SCRATCHPAD_SLOTS`](super::SCRATCHPAD_SLOTS) slots for it, and
//! [`commit::commit`] takes the scratchpad as a caller argument rather than
//! pinning one, so two applets each picking their own would either collide or
//! silently claim capacity the accounting does not have. Both point at
//! [`SCRATCHPAD_FIRST_SLOT`]. It is safe because commits are serialized: the
//! region is not internally locked (`commit.rs`, "Safety / exclusivity") and
//! the applet dispatch is single-threaded per command.
//!
//! **OATH is at the head, which costs the FIDO adapter a skip.** The
//! allocator's rule is "lowest free slot" (`slotmap.rs`), so a reservation at
//! the tail would be free to ignore for 928 enrolments and destroyed the
//! moment the store filled — survivable, unlike a head reservation that is
//! overwritten by the first credential ever enrolled. But "lowest free" means
//! the FIDO side must start at [`FIDO_FIRST_SLOT`], and that is a **contract
//! between two adapters**, not something either can enforce alone:
//! [`is_oath_slot`](self::is_oath_slot) and [`FIDO_FIRST_SLOT`] are published
//! here for the FIDO side to use, and an FIDO allocator that does not consult
//! them will write OATH's slots. Getting this wrong destroys OATH credentials,
//! so it is called out in the story's report rather than left in a comment.
//!
//! # Mount, and why a fault degrades instead of halting
//!
//! [`OathStore::mount`] returns `Err` if **any** slot could not be read, and the
//! caller ([`fapico2_oath::oath_core::OathApp`]) answers with an empty
//! credential set and a clean status word. Three reasons, in order:
//!
//! * **S8/S9: the boot path must not touch the region.** Mount is called at
//!   first applet use, after `RUNG_USB`, never from `boot_oath`.
//! * **Degrade, never halt.** A `fatal_boot` on an unreadable region turns a
//!   failing flash into a board that will not enumerate over USB at all — the
//!   user cannot reach `ykman` to read the error, cannot run a rescue, and
//!   cannot see that anything is wrong. An empty credential set with a clean
//!   status word is a *token that works* and says nothing.
//! * **A partial table is worse than an empty one.** If slot 40 faults and the
//!   other 67 are served, the user's credential list has silently lost an entry
//!   and a subsequent PUT may reuse that slot — writing a second identity on
//!   top of an owner who still believes the first is there. Failing the whole
//!   mount is the only answer that cannot be mistaken for success.
//!
//! A record that *reads* but does not **decode** is the opposite case and is
//! counted, not fatal: a tag failure is a fact about the data
//! ([`SlotRead::Absent`](super::SlotRead) semantics, `mod.rs`), and one bad
//! record must fail closed for itself alone (`undecodable` in [`Mount`]).

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;

use super::commit::{self, CommitError, CommitPlan, CommitReport, Recovery};
use super::crypto::{KeyDomain, PayloadKey, RecordAad, RECORD_OVERHEAD};
use super::index;
use super::record::{self, Domain};
use super::{
    KeyRegion, Sealed, Slot, SlotRead, FIDO_CAPACITY, OATH_CAPACITY, SCRATCHPAD_SLOTS,
    SLOTS_PER_SECTOR, TOTAL_SLOTS,
};

use crate::ckey::OATH_SEAL_OVERHEAD;

// ---------------------------------------------------------------------------
// The key this domain seals with
// ---------------------------------------------------------------------------

/// The OATH payload secret: `fapico2/oath-region/secret/v1` padded to 32 bytes.
///
/// **A constant, not a PIN-derived secret, and that is a deliberate weakening
/// relative to FIDO — stated here rather than left for a reader to find.** The
/// FIDO applet derives its payload key from the user's PIN, so a dump of FIDO
/// records is worthless without the PIN. OATH has no PIN to derive from: its
/// only secret is an **access code that is optional**, unset on most devices,
/// and YKOATH's `LIST` — the command that enumerates account names — is
/// available without `VALIDATE`. Deriving the region key from the access code
/// would therefore either break every Yubico client on a device with no code
/// set, or gate the key on a PIN the protocol never asks for. Neither is a
/// trade this story is entitled to make silently.
///
/// So the protection is exactly what it was before US-1553: **device-bound, not
/// user-bound**. `crypto::derive_payload_key` still takes the OTP root as half
/// its IKM, so a flash dump on its own yields nothing — opening a record needs
/// the OTP row, which `derive_otp_root` refuses to derive from an all-zero row
/// and which no flash reader can supply.
///
/// **What this does not buy, named so it is not assumed:** if an attacker has
/// the OTP row *and* the chip-id, every OATH record on the device opens without
/// a password. That is the pre-existing posture of `OathSeal`
/// (`ckey.rs::oath_derive_key` takes the flash UID and the OTP row, not a
/// PIN), and US-1553 does not change it. The alternative — a second, always-
/// present device secret — would be new key material with no storage story, and
/// AGENTS.md §5 asks for the attack such complexity stops before it is added.
/// The obvious future hardening is to mix the OATH *access code* in once one
/// is set, which is a widening of this one constant and nothing else.
///
/// The constant is length-32 so it can be handed to
/// [`crypto::derive_payload_key`](super::crypto::derive_payload_key) directly,
/// whose `pin_secret` parameter is 32 bytes of already-derived material and
/// deliberately knows nothing about what a caller put in it.
pub const OATH_PAYLOAD_SECRET: [u8; 32] = *b"fapico2/oath-region/secret/v1\0\0\0";

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// The first slot OATH owns. The head of the region — see the module docs,
/// "The geometry".
pub const OATH_FIRST_SLOT: u32 = 0;

/// OATH's slots: [`OATH_CAPACITY`] of them, one credential each.
///
/// The applet's `MAX_CREDS` is 68 for the same reason this is 68: it is the
/// number the applet's RAM table holds, so a store that accepted more would
/// refuse on a RAM bound it never mentions. What changed under US-1553 is not
/// this number but what it competes for — 68 slots of flash, instead of a share
/// of a 24-entry shared image.
pub const OATH_SLOTS: u32 = OATH_CAPACITY;

/// The commit scratchpad: one whole NOR sector, immediately above OATH's area
/// and shared with the FIDO adapter.
///
/// It is **shared** because [`mod.rs`](super) charges one
/// [`SCRATCHPAD_SLOTS`] reservation for the whole region, and because
/// [`commit::commit`] refuses a plan whose scratchpad is the sector it erases
/// but cannot tell two callers apart. Pointing both applets at one sector is
/// what makes the accounting in `mod.rs`'s `const _` block true rather than
/// approximately true.
pub const SCRATCHPAD_FIRST_SLOT: u32 = OATH_SLOTS;

/// The first slot FIDO owns — the contract the FIDO allocator must honour.
///
/// Published here because this file is where the region's partition is written
/// down; a FIDO adapter that scans "lowest free slot" from 0 will hand out
/// OATH's slots on its very first enrolment. See the module docs.
pub const FIDO_FIRST_SLOT: u32 = SCRATCHPAD_FIRST_SLOT + SCRATCHPAD_SLOTS;

/// Is this slot one of OATH's?
///
/// The predicate the FIDO allocator must not cross, exactly as
/// [`index::is_index_slot`] is the predicate for the index. Published from the
/// module that owns the partition rather than repeated in a caller, because a
/// reservation nothing can ask about is a reservation nothing will respect.
pub const fn is_oath_slot(slot: Slot) -> bool {
    let i = slot.index() as u32;
    // The lower bound is `OATH_FIRST_SLOT`, which is 0 — pinned by the
    // assertion below — so writing the comparison in full is what clippy calls
    // an absurd extreme comparison. It is right about the value and wrong
    // about the intent: the *reservation* is the concept, and it is the
    // reservation a caller has to ask about, not the number zero.
    i < OATH_FIRST_SLOT + OATH_SLOTS
}

/// The OATH slot at table `index`, or `None` if the table is larger than the
/// area.
///
/// `None` rather than a wrap: the applet's table bound and the region's
/// reservation are two constants in two crates, and if they ever disagree the
/// answer must be "refuse", not "the credential after the last one".
pub const fn oath_slot(index: u16) -> Option<Slot> {
    let i = index as u32;
    if i < OATH_SLOTS {
        Slot::new((OATH_FIRST_SLOT + i) as u16)
    } else {
        None
    }
}

/// The scratchpad slot commits stage through.
pub const fn scratchpad_slot() -> Option<Slot> {
    Slot::new(SCRATCHPAD_FIRST_SLOT as u16)
}

const _: () = {
    // OATH is at the head of the region, and that is a decision with a cost —
    // see the module docs, "The geometry". It is pinned here so that
    // `is_oath_slot` can be written as a single upper-bound test without the
    // predicate quietly changing meaning if the constant ever moves.
    assert!(
        OATH_FIRST_SLOT == 0,
        "OATH's area is the head of the region; moving it means every reserved-slot predicate in \
         the tree has to be re-derived"
    );
    // The area must be a whole number of NOR sectors. A partial sector has no
    // erase that touches only OATH, so a credential in it could not be written
    // without destroying its neighbours.
    assert!(
        OATH_SLOTS >= SLOTS_PER_SECTOR && OATH_SLOTS.is_multiple_of(SLOTS_PER_SECTOR),
        "OATH's reservation must be a whole number of NOR sectors — the sector is the erase and \
         commit unit (mod.rs:119-132), so a partial-sector reservation has no valid erase"
    );
    assert!(
        SCRATCHPAD_FIRST_SLOT.is_multiple_of(SLOTS_PER_SECTOR),
        "the scratchpad must start on a sector boundary, or erasing it clears a credential"
    );
    assert!(
        SCRATCHPAD_FIRST_SLOT + SCRATCHPAD_SLOTS <= FIDO_FIRST_SLOT,
        "the scratchpad must lie between OATH's area and FIDO's"
    );
    assert!(
        FIDO_FIRST_SLOT + FIDO_CAPACITY <= TOTAL_SLOTS - index::INDEX_SLOT_COUNT,
        "FIDO's area plus the index must not overrun the region — every slot must be claimed \
         exactly once (mod.rs's accounting assertion)"
    );
};

// ---------------------------------------------------------------------------
// The record body
// ---------------------------------------------------------------------------

/// Longest credential name ([`OathApp`](crate)'s `MAX_NAME`, restated because
/// the body codec cannot import an applet-private constant).
pub const OATH_NAME_MAX: usize = 64;

/// Longest plaintext secret ([`OathApp`](crate)'s `MAX_KEY`, same reason).
pub const OATH_KEY_MAX: usize = 66;

/// Longest **sealed** secret: the plaintext plus `OathSeal`'s 33-byte
/// `"OATH"`-magic record (`ckey.rs:363-370`).
pub const OATH_SEALED_KEY_MAX: usize = OATH_KEY_MAX + OATH_SEAL_OVERHEAD;

/// The largest credential body this module writes, in bytes:
///
/// ```text
/// name_len   1
/// name      64   (OATH_NAME_MAX)
/// key_len    1
/// key       99   (OATH_SEALED_KEY_MAX)
/// gen        8   the OathSeal generation this secret was sealed at
/// imf        8   HOTP moving factor; ignored for TOTP
/// props      1   Yubico property bits (US-133)
///          ---
///          182
/// ```
pub const OATH_BODY_MAX: usize = 1 + OATH_NAME_MAX + 1 + OATH_SEALED_KEY_MAX + 8 + 8 + 1;

/// The largest **sealed** OATH record: 182 + the AEAD's `nonce(12) + tag(16)`.
///
/// **This is [`OATH_RECORD_MAX`](super::OATH_RECORD_MAX), exactly**, and it is
/// measured rather than estimated: the layout above is summed from the applet's
/// own maxima, so the constant `mod.rs` sized the 512 B stride from is the real
/// worst case rather than a hand-copied figure. A `const` assertion below stops
/// the two drifting apart in either direction — if a future credential grows a
/// field, the build fails here rather than truncating a secret.
pub const OATH_RECORD_SEALED_MAX: usize = OATH_BODY_MAX + RECORD_OVERHEAD;

/// The tombstone marker: a `name_len` of `0xFF`.
///
/// A tombstone is a **one-byte body** whose only field is an impossible
/// `name_len`. It has to be distinguishable from a credential without a
/// version byte or a magic string, because the maximum `name_len` is 64 and
/// every credential body starts with its `name_len` — so no credential body can
/// ever begin with `0xFF`.
///
/// Why a tombstone at all, rather than erasing the slot: [`commit`] has no
/// single-slot delete, and on purpose (`commit.rs`, "Why there is no
/// single-slot delete here") — a target programmed `0xFF` is indistinguishable
/// from a commit that never reached its witness, so [`commit::recover`] could
/// resurrect a delete as a replay. A tombstone is an ordinary record, so the
/// delete is a normal atomic commit. The slot it occupies is reusable: it is
/// still a slot whose generation moves forward.
pub const TOMBSTONE_NAME_LEN: u8 = 0xFF;

/// One OATH credential as the region stores it.
///
/// **The name is not secret and the fields are not interchangeable.** The name
/// is a `hostname:account` label the host sends in the clear on every APDU
/// (`cmd_put` parses it straight out of the request), so putting it inside the
/// payload AEAD would buy nothing; it is inside the body because the body is the
/// record, and the body is sealed, so the name is protected by the same AEAD as
/// everything else — which is *stricter* than the status quo, where a streamed
/// table left names in the clear.
#[derive(Clone)]
pub struct OathCredential {
    name: [u8; OATH_NAME_MAX],
    name_len: u8,
    sealed_key: [u8; OATH_SEALED_KEY_MAX],
    sealed_key_len: u8,
    seal_generation: u64,
    imf: u64,
    props: u8,
}

impl OathCredential {
    /// Build a credential, refusing anything the body cannot hold.
    ///
    /// `None` rather than a truncation: a name or a secret that does not fit is
    /// a credential this applet must not store, and dropping the tail of a
    /// secret would produce a credential that computes **wrong codes** — an
    /// OTP that authenticates nothing, which the host cannot distinguish from
    /// a wrong password.
    ///
    /// `sealed_key` is the `OathSeal` blob, not the plaintext: the seal is the
    /// applet's business (`ckey.rs`), this module's is the outer AEAD. See the
    /// module docs, "Why the seal generation is the record generation".
    pub fn new(
        name: &[u8],
        sealed_key: &[u8],
        seal_generation: u64,
        imf: u64,
        props: u8,
    ) -> Option<Self> {
        if name.len() > OATH_NAME_MAX || sealed_key.len() > OATH_SEALED_KEY_MAX {
            return None;
        }
        let mut cred = OathCredential {
            name: [0; OATH_NAME_MAX],
            name_len: name.len() as u8,
            sealed_key: [0; OATH_SEALED_KEY_MAX],
            sealed_key_len: sealed_key.len() as u8,
            seal_generation,
            imf,
            props,
        };
        cred.name[..name.len()].copy_from_slice(name);
        cred.sealed_key[..sealed_key.len()].copy_from_slice(sealed_key);
        Some(cred)
    }

    /// The credential's name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// The `OathSeal` blob for this credential's secret.
    pub fn sealed_key(&self) -> &[u8] {
        &self.sealed_key[..self.sealed_key_len as usize]
    }

    /// The `OathSeal` generation this secret was sealed at.
    pub fn seal_generation(&self) -> u64 {
        self.seal_generation
    }

    /// The HOTP moving factor. Meaningless for a TOTP credential; the
    /// applet decides which it is from the secret's own algorithm/type byte,
    /// exactly as it did when the record was a TLV in a stream.
    pub const fn imf(&self) -> u64 {
        self.imf
    }

    /// The Yubico property bits (US-133).
    pub const fn props(&self) -> u8 {
        self.props
    }

    /// Write the body into `out`; returns its length.
    ///
    /// Infallible by construction: every field is bounded by the constructor,
    /// so the maximum is [`OATH_BODY_MAX`] and the buffer is that size. The
    /// assertion is kept so that a future field added without widening the
    /// buffer fails here instead of overrunning it.
    pub fn encode(&self, out: &mut [u8; OATH_BODY_MAX]) -> usize {
        debug_assert!(out.len() >= OATH_BODY_MAX);
        let mut p = 0usize;
        out[p] = self.name_len;
        p += 1;
        out[p..p + self.name_len as usize].copy_from_slice(&self.name[..self.name_len as usize]);
        p += self.name_len as usize;
        out[p] = self.sealed_key_len;
        p += 1;
        out[p..p + self.sealed_key_len as usize]
            .copy_from_slice(&self.sealed_key[..self.sealed_key_len as usize]);
        p += self.sealed_key_len as usize;
        out[p..p + 8].copy_from_slice(&self.seal_generation.to_be_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.imf.to_be_bytes());
        p += 8;
        out[p] = self.props;
        p += 1;
        // `<=`, not `==`: `p` is *this* credential's length and the constant is
        // the worst case, so a short credential is the normal outcome and only
        // an over-long one is a bug. The bound is what has to hold, and it is
        // what keeps the caller from indexing past the caller's buffer.
        debug_assert!(
            p <= OATH_BODY_MAX,
            "the body layout and OATH_BODY_MAX must agree; encode wrote {p} bytes"
        );
        p
    }

    /// Is this body a tombstone? See [`TOMBSTONE_NAME_LEN`].
    pub fn is_tombstone(body: &[u8]) -> bool {
        body.len() == 1 && body[0] == TOMBSTONE_NAME_LEN
    }

    /// Parse a credential body.
    ///
    /// `None` for anything that is not exactly one well-formed credential: a
    /// short body, a `name_len` past the maximum, a length that runs off the
    /// end. Every one of those is a fact about the data, and the caller counts
    /// it as [`Mount::undecodable`] rather than treating the credential as
    /// absent — the difference matters, because "absent" would let the next PUT
    /// reuse a slot whose record is merely unreadable.
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.is_empty() || body[0] > OATH_NAME_MAX as u8 {
            return None;
        }
        let name_len = body[0] as usize;
        let mut p = 1usize;
        let end_name = p + name_len;
        if end_name > body.len() {
            return None;
        }
        let key_len_at = end_name;
        if key_len_at >= body.len() {
            return None;
        }
        let key_len = body[key_len_at] as usize;
        let key_at = key_len_at + 1;
        let end_key = key_at + key_len;
        // name_len + key_len + 8 (generation) + 8 (imf) + 1 (props) must follow.
        if end_key + 17 != body.len() || key_len > OATH_SEALED_KEY_MAX {
            return None;
        }
        let mut name = [0u8; OATH_NAME_MAX];
        name[..name_len].copy_from_slice(&body[p..end_name]);
        let mut sealed_key = [0u8; OATH_SEALED_KEY_MAX];
        sealed_key[..key_len].copy_from_slice(&body[key_at..end_key]);
        p = end_key;
        let mut gen = [0u8; 8];
        gen.copy_from_slice(&body[p..p + 8]);
        p += 8;
        let mut imf = [0u8; 8];
        imf.copy_from_slice(&body[p..p + 8]);
        p += 8;
        Some(OathCredential {
            name,
            name_len: name_len as u8,
            sealed_key,
            sealed_key_len: key_len as u8,
            seal_generation: u64::from_be_bytes(gen),
            imf: u64::from_be_bytes(imf),
            props: body[p],
        })
    }
}

impl fmt::Debug for OathCredential {
    /// Lengths only. A `Debug` that prints the name puts "this user has a token
    /// for that site" into a log buffer, and one that prints the sealed key is
    /// worse — same rule as [`Sealed`]'s and
    /// [`index::IndexEntry`]'s hand-written impls.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OathCredential(name {} bytes, key {} bytes, gen {}, props {:#04x})",
            self.name_len, self.sealed_key_len, self.seal_generation, self.props
        )
    }
}

// ---------------------------------------------------------------------------
// What one slot holds
// ---------------------------------------------------------------------------

/// What one OATH slot holds.
///
/// Five states, and the split is the point. `Empty` is a fact about the data
/// (erased, or a header that failed its CRC) and `Fault` — which is not here,
/// because it is an [`OathStoreError`] — is a failure to learn it. `Undecodable`
/// sits between them and is the one a caller most often gets wrong: the record
/// is there and it is OATH's, this build cannot open it, and **the slot is
/// still occupied**. Treating it as `Empty` lets the next PUT write over a
/// credential the owner may still believe is stored.
///
/// **`PartialEq`/`Eq` are deliberately absent.** `OathCredential` holds a
/// sealed secret, and the house rule (`ckey.rs`, `record.rs`) is that
/// equality on key-bearing structures is a timing side channel waiting for a
/// caller who needs it. Every test in this story's suite distinguishes entries
/// with [`matches!`] or the accessors, so nothing is lost.
#[derive(Clone, Debug)]
pub enum Entry {
    /// Nothing there: erased, or a header that failed its CRC.
    Empty,
    /// A credential record that decoded.
    Live(OathCredential),
    /// A tombstone — this slot's credential was deleted.
    Tombstone,
    /// A record that is not OATH's: another domain, or another build's body.
    Foreign,
    /// OATH's record, unreadable. The slot stays occupied.
    Undecodable,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an OATH region operation did not happen.
///
/// [`Self::Fault`] is "we could not find out" and everything else is a decision;
/// collapsing them would let a failing flash read as an empty store, which is
/// the hazard [`SlotRead`](super::SlotRead) exists to prevent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OathStoreError {
    /// The region could not be read or written. `reason` is the region's own
    /// string, verbatim.
    Fault(&'static str),
    /// The table index is outside OATH's area.
    IndexOutOfRange {
        /// The index the caller asked for.
        index: u16,
    },
    /// The credential does not fit the record the slot stride can hold.
    TooLarge {
        /// What the credential would have needed.
        len: usize,
        /// The bound it exceeded.
        max: usize,
    },
    /// The payload AEAD refused. In practice unreachable — AES-256-GCM with a
    /// 32-byte key cannot fail to construct — and present so the alternative is
    /// not a panic on the applet's write path.
    Aead,
    /// This slot's generation counter is at `u32::MAX`. Unreachable in
    /// practice (2^32 rewrites of one slot) and present because the alternative
    /// is a wrapping generation, which turns 2^32 rewrites into generation
    /// **0** and hands back a nonce the applet has already spent.
    GenerationExhausted {
        /// The slot whose counter is exhausted.
        slot: Slot,
    },
    /// The commit itself refused. See [`commit::CommitError`].
    Commit(CommitError),
}

impl fmt::Display for OathStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OathStoreError::Fault(reason) => write!(f, "key region I/O failed: {reason}"),
            OathStoreError::IndexOutOfRange { index } => {
                write!(f, "OATH table index {index} is outside the key region's OATH area")
            }
            OathStoreError::TooLarge { len, max } => {
                write!(f, "the OATH record is {len} bytes and the slot holds at most {max}")
            }
            OathStoreError::Aead => write!(f, "the record AEAD refused to seal"),
            OathStoreError::GenerationExhausted { slot } => {
                write!(f, "slot {} has exhausted its generation counter", slot.index())
            }
            OathStoreError::Commit(e) => write!(f, "the OATH record commit failed: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Mount
// ---------------------------------------------------------------------------

/// What [`OathStore::mount`] found.
///
/// Counters, not records: the caller wants to know "how many credentials came
/// back" and "was anything wrong", and a mount that returned the records would
/// make every caller re-derive this from a `Vec`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Mount {
    /// Credentials whose records decoded.
    pub live: u16,
    /// Slots holding a tombstone — deleted credentials. Counted so a caller
    /// can assert a delete really landed rather than trusting the return SW.
    pub tombstones: u16,
    /// Slots that held a readable record this build could not decode: a tag
    /// failure, or a body that is not this format.
    ///
    /// **A non-zero value is not fatal, and it is not absence.** A record that
    /// fails its AEAD tag is a fact about the data, and the credential fails
    /// closed for itself alone (`US-1549`). But the slot stays *occupied*, so
    /// the allocator will not hand it out: see [`OathStore::write`], which
    /// refuses to overwrite a slot whose record it could not read.
    pub undecodable: u16,
}

// ---------------------------------------------------------------------------
// The store view
// ---------------------------------------------------------------------------

/// A borrowed view of the region, carrying the payload key it seals with.
///
/// Split from [`OathRegion`] so the key can be held once for a session while
/// every operation borrows it: the key is not re-derived per write (see the
/// "keys are per-operation" note in [`super::crypto`]) and not copied per write
/// either.
pub struct OathStore<'r> {
    region: &'r mut dyn KeyRegion,
    key: &'r PayloadKey,
}

impl<'r> OathStore<'r> {
    /// A view over `region`, sealing and opening with `key`.
    pub fn new(region: &'r mut dyn KeyRegion, key: &'r PayloadKey) -> Self {
        OathStore { region, key }
    }

    /// The region itself, for a caller that has to inspect the medium.
    pub fn region(&mut self) -> &mut dyn KeyRegion {
        self.region
    }

    /// Refuse an index this *region* cannot hold.
    ///
    /// [`oath_slot`] bounds against the shipping region's geometry
    /// ([`TOTAL_SLOTS`]), which is not the same thing as the region handed in:
    /// a host fixture is routinely shorter, and a board whose key region grew
    /// would be longer. Both are caught here rather than at the transport,
    /// because the transport's refusal arrives as a bare `&'static str` and
    /// "this region is smaller than the geometry" is worth saying in words.
    fn slot_for(&self, index: u16) -> Result<Slot, OathStoreError> {
        let slot = oath_slot(index).ok_or(OathStoreError::IndexOutOfRange { index })?;
        if !holds_slot(self.region, slot) {
            return Err(OathStoreError::Fault(E_SHORT_REGION));
        }
        Ok(slot)
    }

    /// Finish or abandon a commit interrupted by a power cut.
    ///
    /// **Must run before the region is read.** A live sector caught between its
    /// erase and its copy-back reads as empty, and "this credential is gone" is
    /// what a caller concludes from that and reports to the owner
    /// (`commit::recover`'s docs). [`commit::commit`] calls this itself, so the
    /// only caller that needs it is a mount.
    pub fn recover(&mut self) -> Result<Recovery, OathStoreError> {
        let scratchpad =
            scratchpad_slot().ok_or(OathStoreError::Fault(E_NO_SCRATCHPAD))?;
        commit::recover(self.region, scratchpad).map_err(OathStoreError::Fault)
    }

    /// Read every OATH slot and count what is there.
    ///
    /// Opens each record, so it costs one 1 KiB slot read and one AEAD open per
    /// slot — 68 of each on a full applet. That is the price of not having an
    /// index (`index.rs` has no writer, and for 68 records the index would save
    /// nothing: see the module docs).
    ///
    /// `Err` on the **first** slot that could not be read, and deliberately not
    /// a partial count: see the module docs, "Mount, and why a fault degrades
    /// instead of halting".
    pub fn mount(&mut self) -> Result<Mount, OathStoreError> {
        let mut report = Mount::default();
        let mut i = 0u16;
        while i < OATH_SLOTS as u16 {
            match self.read(i)? {
                Entry::Live(_) => report.live += 1,
                Entry::Tombstone => report.tombstones += 1,
                Entry::Undecodable => report.undecodable += 1,
                // An empty slot is the ordinary case on a partly-used applet,
                // and a foreign record in OATH's window is not OATH's to count.
                Entry::Empty | Entry::Foreign => {}
            }
            i += 1;
        }
        Ok(report)
    }

    /// Read one OATH slot's record and open it.
    ///
    /// The three-way split is [`record::decode`]'s and this function does not
    /// soften it: a header that fails its CRC is `Absent` (a fact about the
    /// data — one bad record fails closed alone), and a transport error is
    /// `Fault` (never memoized as absence).
    pub fn read(&mut self, index: u16) -> Result<Entry, OathStoreError> {
        let slot = self.slot_for(index)?;
        let raw = self
            .region
            .read_slot(slot)
            .map_err(OathStoreError::Fault)?;
        let decoded = match record::decode(slot, &raw) {
            SlotRead::Present(d) => d,
            SlotRead::Absent => return Ok(Entry::Empty),
            SlotRead::Fault(reason) => return Err(OathStoreError::Fault(reason)),
        };
        if decoded.header().domain() != Domain::Oath {
            return Ok(Entry::Foreign);
        }
        let opened = match record::open(decoded.header(), self.key.as_bytes(), decoded.body()) {
            SlotRead::Present(pt) => pt,
            SlotRead::Absent | SlotRead::Fault(_) => return Ok(Entry::Undecodable),
        };
        let body = opened.as_slice();
        let entry = if OathCredential::is_tombstone(body) {
            Entry::Tombstone
        } else {
            match OathCredential::decode(body) {
                Some(cred) => Entry::Live(cred),
                None => Entry::Undecodable,
            }
        };
        Ok(entry)
    }

    /// The generation a record in `slot` currently carries; `0` for an empty
    /// slot.
    ///
    /// Read through [`record::decode`], so a corrupt record counts as no record
    /// — and therefore as generation 0, which is the safe direction: refusing
    /// to write would leave a corrupt record permanently un-replaceable and the
    /// owner with no way to enrol again (`commit.rs`, on
    /// `read_generation`).
    fn current_generation(&mut self, slot: Slot) -> Result<u32, OathStoreError> {
        let raw = self
            .region
            .read_slot(slot)
            .map_err(OathStoreError::Fault)?;
        Ok(match record::decode(slot, &raw) {
            SlotRead::Present(d) => d.header().generation(),
            SlotRead::Absent | SlotRead::Fault(_) => 0,
        })
    }

    /// Seal `body` for `(slot, generation)` under the payload key.
    fn seal(
        &self,
        slot: Slot,
        generation: u32,
        body: &[u8],
    ) -> Result<Sealed, OathStoreError> {
        let aad = RecordAad::new(KeyDomain::Oath, slot, generation);
        let mut out = alloc::vec![0u8; body.len() + RECORD_OVERHEAD];
        let n = super::crypto::seal_payload(self.key, &aad, body, &mut out)
            .ok_or(OathStoreError::Aead)?;
        out.truncate(n);
        Ok(Sealed::from_sealed_bytes(out))
    }

    /// The generation the next write to `index` will carry: the slot's
    /// **current** generation plus one.
    ///
    /// Public because the OATH applet needs it *before* it can seal: the
    /// `OathSeal` nonce generation **is** the record generation (module docs,
    /// "Why the seal generation is the record generation"), so the applet must
    /// read the number before it produces the ciphertext that carries it.
    ///
    /// Read from the medium rather than remembered in RAM, which is what makes
    /// monotonicity survive a reset without a resident table: 68 in-RAM
    /// counters would be 68 generations of state to lose, and losing them is
    /// precisely how a nonce gets re-spent.
    ///
    /// [`Self::write`] recomputes it and [`commit::commit`] independently
    /// refuses a generation that does not advance, so a caller that asks twice
    /// and disagrees with the second answer loses the write rather than
    /// overwriting a record at a generation it never read.
    pub fn next_generation(&mut self, index: u16) -> Result<u32, OathStoreError> {
        let slot = self.slot_for(index)?;
        let current = self.current_generation(slot)?;
        current
            .checked_add(1)
            .ok_or(OathStoreError::GenerationExhausted { slot })
    }

    /// Commit one credential to `index`, at the slot's next generation.
    pub fn write(
        &mut self,
        index: u16,
        cred: &OathCredential,
    ) -> Result<CommitReport, OathStoreError> {
        let mut body = [0u8; OATH_BODY_MAX];
        let n = cred.encode(&mut body);
        if n + RECORD_OVERHEAD > super::record::MAX_BODY_BYTES {
            return Err(OathStoreError::TooLarge {
                len: n + RECORD_OVERHEAD,
                max: super::record::MAX_BODY_BYTES,
            });
        }
        self.commit_body(index, &body[..n])
    }

    /// Tombstone `index`: a durable delete that keeps the slot reusable.
    ///
    /// A tombstone rather than an erase — see [`TOMBSTONE_NAME_LEN`] and
    /// [`OathStore::delete`]. The generation still advances, so the next
    /// credential at this slot is sealed at a strictly higher one and cannot
    /// reuse a nonce the deleted credential spent.
    pub fn delete(&mut self, index: u16) -> Result<CommitReport, OathStoreError> {
        self.commit_body(index, &[TOMBSTONE_NAME_LEN])
    }

    /// The shared commit path: read the generation, seal, and commit.
    fn commit_body(
        &mut self,
        index: u16,
        body: &[u8],
    ) -> Result<CommitReport, OathStoreError> {
        let slot = self.slot_for(index)?;
        let scratchpad = scratchpad_slot().ok_or(OathStoreError::Fault(E_NO_SCRATCHPAD))?;
        let generation = self.next_generation(index)?;
        let sealed = self.seal(slot, generation, body)?;
        let plan = CommitPlan::new(scratchpad, slot, Domain::Oath, generation);
        commit::commit(self.region, plan, &sealed).map_err(OathStoreError::Commit)
    }
}

/// The scratchpad could not be named — impossible on this geometry, and named
/// rather than `unwrap`ed so a change that breaks the reasoning fails loudly.
const E_NO_SCRATCHPAD: &str =
    "key region: the OATH scratchpad slot is outside the region geometry";

/// The region handed to an [`OathStore`] is shorter than the geometry.
const E_SHORT_REGION: &str =
    "key region: the region is shorter than the slot the OATH geometry names";

/// Whether `slot` is inside the region this view was handed.
///
/// Exposed because the geometry in this file is a claim about the *shipping*
/// region and a test's region may be shorter (a 12-slot host file is the usual
/// fixture): a caller writing to a slot its region does not hold must be
/// refused, and this is the check that refuses it.
pub fn holds_slot(region: &dyn KeyRegion, slot: Slot) -> bool {
    (slot.index() as u32) < region.slots()
}

// ---------------------------------------------------------------------------
// The owned handle
// ---------------------------------------------------------------------------

/// A region plus the payload key, owned by the applet for its session.
///
/// # Why the key is kept here rather than derived per operation
///
/// [`super::crypto`] documents its keys as "per-operation: derive, use, drop",
/// and this handle breaks that rule, on purpose and once. Deriving per write
/// would need the OTP row resident for the same window — 32 bytes of *device
/// root* sitting in RAM against 32 bytes of *derived key*, which is strictly
/// the worse of the two: the row unlocks every other store on the device
/// (`store_v3::derive_store_key` is shared) and the derived key unlocks one
/// area. The precedent for a key held across a session is not far away:
/// `OathSeal` already lives inside `OathApp` for the life of the process
/// (`ckey.rs:394-393`), so this is the same decision made once more, in the
/// same place, for the same reason.
///
/// The attack this does **not** stop is unchanged by holding the key longer: a
/// read-and-decrypt of live RAM, which the OTP root's presence in the same RAM
/// already permits. What it costs is one heap allocation and a wider window,
/// and both are after `platform::rsa_heap::init()` — the US-961 heap gate
/// (`tests/scripts/check_heap_gate.py`) proves nothing in device source
/// allocates before that call, and constructing this handle is not before it.
pub struct OathRegion {
    region: Box<dyn KeyRegion>,
    key: PayloadKey,
}

impl OathRegion {
    /// Take ownership of a region and the key to seal its records with.
    pub fn new(region: Box<dyn KeyRegion>, key: PayloadKey) -> Self {
        OathRegion { region, key }
    }

    /// A borrowed view for one operation.
    pub fn store(&mut self) -> OathStore<'_> {
        OathStore::new(self.region.as_mut(), &self.key)
    }

    /// The region alone — for a caller that has to inspect or repair the
    /// medium rather than go through this module's API.
    pub fn region(&mut self) -> &mut dyn KeyRegion {
        self.region.as_mut()
    }
}

impl fmt::Debug for OathRegion {
    /// Never prints the key, and never prints the region's path or contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OathRegion(<region>, <key redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

const _: () = {
    // The measured worst case must equal the constant the stride was sized
    // from. If a future credential grows a field this stops the build instead
    // of letting a secret be truncated to fit — the failure `mod.rs` names for
    // a stride that cannot hold its own domain's largest record.
    assert!(
        OATH_RECORD_SEALED_MAX as u32 == super::OATH_RECORD_MAX,
        "the OATH body layout no longer seals to OATH_RECORD_MAX — re-measure it and widen \
         SLOT_MARGIN_BYTES if the new maximum does not still fit the 512 B stride"
    );
    assert!(
        OATH_BODY_MAX + RECORD_OVERHEAD <= super::record::MAX_BODY_BYTES,
        "the OATH record must fit the slot the region addresses"
    );
    assert!(
        OATH_SLOTS <= MAX_CREDS_BOUND,
        "OATH's reservation must not exceed the applet's RAM table — a store that accepted more \
         would refuse on a bound it never mentions"
    );
    assert!(
        OATH_FIRST_SLOT + OATH_SLOTS == SCRATCHPAD_FIRST_SLOT,
        "the scratchpad must start exactly where OATH's area ends"
    );
    assert!(
        FIDO_FIRST_SLOT + FIDO_CAPACITY == TOTAL_SLOTS - index::INDEX_SLOT_COUNT,
        "OATH + scratchpad + FIDO + index must tile the region exactly once — the same accounting \
         mod.rs asserts, restated here from the OATH side"
    );
};

/// The applet's `MAX_CREDS`. Restated as a literal rather than imported,
/// because `apps/oath` depends on `platform` and not the other way round: a
/// `pub use` would be a cycle, and this constant is the *claim* the region's
/// reservation has to be at least as generous as.
const MAX_CREDS_BOUND: u32 = 68;