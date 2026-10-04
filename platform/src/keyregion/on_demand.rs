//! On-demand credential load (US-1554): **nothing is resident**.
//!
//! # What this story is for
//!
//! `apps/fido/src/device_keystore.rs:919` holds
//! `credentials: HeaplessVec<DeviceCredential, DEVICE_MAX_CREDS>` with
//! `DEVICE_MAX_CREDS = 12` (`device_keystore.rs:34`). `DeviceCredential`
//! measures **720 bytes** on this target's layout — six `HeaplessVec<u8, 64>`
//! fields at 72 B each, an 88 B COSE key, two 32-byte arrays and the scalar
//! flags — so the resident array is **12 × 720 = 8,640 B of `.bss`**.
//!
//! The derived capacity of this region is [`super::FIDO_CAPACITY`] (892 at the
//! shipping geometry). A resident array of *that* many credentials would be
//! `892 × 720 = 642,240 B`, and **the RP2350 has 532,480 bytes of RAM in
//! total**. So the capacity win and the RAM budget are in direct conflict, and
//! no amount of tuning resolves it: a resident array cannot be made to fit.
//!
//! This module is the mechanism that resolves it. The resident set is **one
//! credential**, held in a buffer of [`ON_DEMAND_WINDOW_BYTES`] (836 B), for
//! the duration of one operation. The other 891 live in flash, where they cost
//! nothing. The array's removal is US-1552's edit; this file is the part that
//! has to exist first, and it has to be provable on its own.
//!
//! # The rule: one AEAD operation per lookup
//!
//! [`load`] performs **exactly one** payload decryption, and this is the
//! property the whole design rests on, so it is stated as an obligation on
//! [`SlotLocator`] rather than as an optimisation:
//!
//! * locating a credential **must not open any payload**. The index
//!   (US-1551, `index.rs`) maps `rp_id_tag → slot` and is authenticated under
//!   the **index key** — which is deliberately PIN-free
//!   (`crypto.rs`, "Why the index key is not PIN-gated") so a flash dump can be
//!   triaged without the user's PIN. A locator that unsealed payloads to find a
//!   match would (a) make every lookup O(capacity) *payload* decryptions,
//!   which is precisely the cost this story exists to remove, and (b) require
//!   the PIN for something the index was designed so the PIN is not needed for;
//! * once a slot is named, it is read once and unsealed once. A tag failure is
//!   [`SlotRead::Absent`] for that record **alone** — US-1549's fail-closed
//!   property, inherited rather than reimplemented, because the unseal here is
//!   [`record::read`] and not a second AEAD call site.
//!
//! The cost of getting this wrong is not a slow lookup: it is a `bss` figure
//! that has not gone down, because a locator that needed the whole credential
//! set to answer one query would force the set to be resident.
//!
//! # Why the buffer is a type, not a call
//!
//! GCM decrypts *before* it verifies, so by the time a tag is checked the
//! buffer already holds — for a credential private key — attacker-chosen
//! bytes. `record::Plaintext` already makes the guarantee by type
//! (`record.rs`, "Why this type exists"); [`CredentialWindow`] makes the
//! **second** half by type: it zeroizes its bytes in [`Drop`], on top of the
//! explicit [`CredentialWindow::zeroize_now`] the applet calls the moment the
//! signature is produced. The buffer is bounded by construction (a fixed-size
//! array, not a `Vec`), and plaintext enters it through exactly one function —
//! [`load`] — because [`CredentialWindow`] exposes no mutable slice and no
//! constructor that takes bytes.
//!
//! # What US-1551 (`index.rs`) has to provide
//!
//! [`SlotLocator`] is the seam, and it is deliberately tiny so that the swap
//! from the stand-in in [`testing`] to the real index is a single `impl`:
//!
//! ```ignore
//! impl SlotLocator for Index {
//!     fn locate(&mut self, region: &mut dyn KeyRegion, want: &SlotQuery<'_>) -> Located;
//! }
//! ```
//!
//! See [`SlotLocator`]'s own docs for the full contract, including the two
//! rules a flash-backed index must not break: a **single** answer per query
//! (not a candidate list, so that "one decryption" is a structural property and
//! not a loop that might run twice), and [`Located::Fault`] rather than
//! [`Located::None`] for anything that went wrong reading the index — the
//! US-1573 distinction, which a locator is the first place able to get wrong.

extern crate alloc;

#[cfg(not(target_arch = "arm"))]
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::crypto::PayloadKey;
use super::record;
use super::{FIDO_RECORD_MAX, KeyRegion, Slot, SlotRead};

/// SHA-256 of a WebAuthn relying-party identifier — the `rp_id_tag` CTAP 2.1
/// §6.1.3 defines as the RP ID hash, and the value a credential ID embeds as
/// its first 32 bytes.
///
/// Fixed at 32 because it is a SHA-256 output and because the whole query
/// interface below is built on a comparison against it: a variable-width tag
/// would put an attacker-controlled length on the comparison the index
/// performs, and CTAP already fixes the width.
pub const RP_ID_TAG_LEN: usize = 32;

/// The on-flash size of one credential record, and therefore the size of the
/// single buffer an on-demand load decrypts into.
///
/// **This is [`FIDO_RECORD_MAX`] and it cannot be smaller.** `FIDO_RECORD_MAX`
/// (836 B, `mod.rs:67`) is the largest record the store can *write*, measured
/// against `device_core.rs`'s makeCredential path with the longest fields
/// CTAP 2.1 permits. A window smaller than the largest credential is not a
/// safety property, it is a capacity loss: the largest legitimate credential
/// would fail to load with an error that looks exactly like a corrupt record.
/// Sizing the window to the *typical* credential would be the same mistake
/// `DEVICE_MAX_CREDS = 12` was — a bound asserted from below rather than
/// derived from the largest thing the system can actually produce.
pub const ON_DEMAND_WINDOW_BYTES: usize = FIDO_RECORD_MAX as usize;

/// `SHA-256(rp_id)` — the tag [`SlotQuery`] matches on.
///
/// One definition, in the store, because a tag computed two ways is a tag that
/// will eventually disagree with itself: the applet computes it on the way in
/// (to seal) and the index compares it on the way out (to find). A mismatch
/// reads as "no such credential", which is silent and total.
///
/// If `index.rs` (US-1551) ends up defining its own, **delete this one and
/// call theirs** — two tag functions is the same defect as two AAD builders
/// (`record.rs`, "Why the AAD lives here and not in `crypto.rs`").
pub fn rp_id_tag(rp_id: &[u8]) -> [u8; RP_ID_TAG_LEN] {
    let digest = Sha256::digest(rp_id);
    let mut out = [0u8; RP_ID_TAG_LEN];
    out.copy_from_slice(&digest);
    out
}

/// What a lookup is asking for.
///
/// Two variants rather than a predicate, and the reason is a CTAP detail: two
/// credentials can share one RP (`example.com` with a passkey and a
/// passwordless u2f login), so "the credential for this RP" is not a question
/// with one answer. [`SlotQuery::RpIdTag`] is the enumeration / existence form
/// — which the applet uses to ask "does this RP have anything here?" — and
/// [`SlotQuery::RpIdTagAndCredentialId`] is the authentication form, where the
/// client has handed over the credential ID it was issued.
///
/// Neither variant carries the user handle. A resident key's `user.id` is not
/// needed to *find* the credential — the credential ID identifies it — and
/// adding it as a third selector would give a caller a way to ask a question
/// whose answer depends on two records rather than one, which is the shape a
/// "no such user" oracle wants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotQuery<'a> {
    /// Any credential stored for this RP. Answers with the index's choice of one.
    RpIdTag {
        /// `SHA-256(rp_id)`.
        tag: &'a [u8; RP_ID_TAG_LEN],
    },
    /// The specific credential of that RP.
    RpIdTagAndCredentialId {
        /// `SHA-256(rp_id)`.
        tag: &'a [u8; RP_ID_TAG_LEN],
        /// The credential ID, 16..=64 bytes as CTAP 2.1 §5.8.3 bounds it.
        credential_id: &'a [u8],
    },
}

impl SlotQuery<'_> {
    /// The RP tag this query is about, whichever variant it is.
    ///
    /// One accessor for both variants so a caller cannot handle them
    /// differently by accident, and so a future third variant has to be given
    /// a tag too.
    pub const fn tag(&self) -> &[u8; RP_ID_TAG_LEN] {
        match self {
            SlotQuery::RpIdTag { tag } => tag,
            SlotQuery::RpIdTagAndCredentialId { tag, .. } => tag,
        }
    }
}

/// Where a locator says the answer is — the three states, for the reason
/// [`super::SlotRead`] is three states.
///
/// The middle one is the load-bearing distinction. A flash transport error is
/// **not** the same fact as "no such credential", and collapsing them is how a
/// transient bus fault becomes a user's silently-un-authenticatable account
/// (US-1573: "a faulted read memoized as 'no credentials' makes the next
/// enrollment build a second identity on top of the owner's"). A locator is the
/// first component able to make that mistake, so the type refuses to let it
/// make it quietly: [`Located::Fault`] is a state a caller is expected to
/// match on, not an `Err` to be ignored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Located {
    /// The slot holding the record. Exactly one, deliberately.
    Found(Slot),
    /// The index was searched and it does not hold this query.
    None,
    /// The index could not be searched — a transport fault, not a fact about
    /// the data.
    Fault(&'static str),
}

/// The seam between "where does this credential live" and "open that one".
///
/// # The contract
///
/// An implementation MUST:
///
/// 1. **Answer without opening a payload.** One method, and the payload
///    decryption count is bounded at one by *this* signature alone — there is
///    no candidate list for a caller to iterate and no way for a "try the next
///    one" loop to grow here. A flash-backed implementation reads the index
///    records, which are sealed under the PIN-free **index key**
///    (`crypto.rs`), not the payload key; that is what makes the rule cheap to
///    honour rather than a discipline.
/// 2. **Return [`Located::Fault`], never [`Located::None`], for anything it
///    could not read.** A read that failed is not a record that does not exist.
/// 3. **Return a slot it owns.** The record's domain is authenticated, not
///    asserted by the locator ([`super::crypto::RecordAad`] binds it), so a
///    locator that returns an OATH slot for a FIDO query produces an OATH
///    plaintext that the FIDO caller will misparse. The locator's index is
///    domain-separated; that is where that separation has to hold.
/// 4. **Prefer a slot it has not already tried.** With one slot per query and
///    one decryption, "the record at that slot failed to open" is reported as
///    [`super::SlotRead::Absent`] — a fact about that record, which is the
///    whole of US-1549's fail-closed property. It is *not* a licence to widen
///    the search to a second slot: that would make one bad record cost the
///    lookup, and would let a caller distinguish "the index says slot 7"
///    from "slot 7 was unreadable".
///
/// # Why this trait and not a free function
///
/// The real implementation is US-1551's `index.rs`, which does not exist yet and
/// whose storage shape is still moving. A free function would bake *this
/// module's* guess at where the tag lives into a call site in an applet, and
/// changing it later would mean changing `apps/fido/src/device_core.rs` — where
/// two other agents are working. A trait with one method keeps the guess in
/// [`testing`] and makes the replacement an `impl` on a different file.
pub trait SlotLocator {
    /// Find the one slot holding `want`, searching the index.
    ///
    /// `region` is passed in rather than captured so that an implementation
    /// cannot hold a region handle of its own: `KeyRegion`'s methods take
    /// `&mut self`, and a locator that owned one would make "scan while
    /// writing" unrepresentable rather than merely discouraged.
    fn locate(&mut self, region: &mut dyn KeyRegion, want: &SlotQuery<'_>) -> Located;
}

/// The bounded buffer one credential is decrypted into.
///
/// # Size and what it buys
///
/// A fixed `[u8; ON_DEMAND_WINDOW_BYTES]` array, so the bound is a **type**
/// rather than a length check: there is no constructor that takes a capacity
/// from a caller, and therefore no caller that can raise it. 836 B is
/// [`FIDO_RECORD_MAX`] — see the constant's own docs for why the bound is the
/// largest record rather than a typical one.
///
/// `size_of::<CredentialWindow>()` is **838 bytes** on this target (the array
/// plus a `u16` length; both are 1-byte aligned, so there is no padding). That
/// is the entire resident cost of this story's mechanism, against the 8,640 B
/// of `.bss` the 12-entry array it replaces costs today. The test
/// `the_window_is_bounded_by_construction` in
/// `platform/tests/key_region_on_demand.rs` pins the number rather than leaving
/// it in a comment, because a number that only a comment asserts is a number
/// that drifts.
///
/// # Zeroization
///
/// [`Drop`] clears the bytes and, on host, records what was there *after* the
/// clear into a witness the test can read (`crypto.rs`'s
/// `testing::record_dropped_key` is the precedent, and it exists for the same
/// reason: "the key is cleared on drop" is a claim about bytes that have by
/// then been freed, and there is no sound way for a test to read them back).
///
/// Only [`load`] can write to it — there is no public `&mut [u8]` and no
/// constructor from bytes — so "the only way plaintext enters this buffer is
/// the AEAD" is structural.
pub struct CredentialWindow {
    bytes: [u8; ON_DEMAND_WINDOW_BYTES],
    len: u16,
}

impl CredentialWindow {
    /// A zero-filled window sized for the largest record the store can hold.
    ///
    /// Zero-filled rather than uninitialised for the reason `Plaintext::scratch`
    /// gives (`record.rs`): a buffer that starts at zero makes "no plaintext
    /// escaped" a checkable state instead of an accident of the heap.
    pub const fn new() -> Self {
        CredentialWindow { bytes: [0u8; ON_DEMAND_WINDOW_BYTES], len: 0 }
    }

    /// The decrypted credential, or nothing while it holds no plaintext.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Bytes of plaintext currently in the window.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the window holds no plaintext.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clear the window now, without waiting for [`Drop`].
    ///
    /// The applet calls this the moment the signature is produced. [`Drop`] is
    /// the backstop — it makes forgetting impossible — but the backstop fires
    /// when the enclosing frame ends, which for a long-lived window is later
    /// than the key material needs to exist. "After the signature" is the
    /// requirement, so the explicit call is the primary mechanism and the
    /// destructor is the reason a caller who forgets it is not a vulnerability.
    pub fn zeroize_now(&mut self) {
        self.bytes[..self.len as usize].zeroize();
        self.len = 0;
    }

    /// Copy an opened plaintext in, refusing one that does not fit.
    ///
    /// Private, and that is the point: it is the only way bytes enter the
    /// buffer, so there is exactly one audit site for "could plaintext arrive
    /// here without having been authenticated".
    fn adopt(&mut self, plaintext: &[u8]) -> bool {
        if plaintext.len() > ON_DEMAND_WINDOW_BYTES {
            return false;
        }
        // Anything past the new end was zeroed by `zeroize_now` in `load`, so a
        // shorter credential cannot leave the tail of a longer one readable —
        // the same rule `record::open_into` applies inside the unseal
        // (`record.rs`), repeated here because this buffer outlives one unseal.
        self.bytes[..plaintext.len()].copy_from_slice(plaintext);
        self.len = plaintext.len() as u16;
        true
    }
}

impl Default for CredentialWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CredentialWindow {
    fn drop(&mut self) {
        self.zeroize_now();
        #[cfg(not(target_arch = "arm"))]
        testing::record_dropped_window(&self.bytes);
    }
}

impl core::fmt::Debug for CredentialWindow {
    /// Never prints the bytes — `Sealed`'s and `Plaintext`'s rule
    /// (`mod.rs:363-369`, `record.rs:683-691`): a `Debug` that dumps a
    /// decrypted credential is a `Debug` that puts a private key in a log
    /// buffer.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CredentialWindow({} bytes)", self.len)
    }
}

/// What one successful on-demand load found, without the plaintext.
///
/// The plaintext stays in the caller's [`CredentialWindow`]; this is the
/// metadata an applet needs afterwards — which slot to log, which record an
/// error refers to — and it is deliberately not a second copy of the bytes.
///
/// It does **not** carry the record's generation. The generation is in the
/// header, and `record::read` returns only the plaintext; a caller that needs
/// it gets it from [`record::decode`] over the same slot, which is a header
/// parse and **no second AEAD operation**. Carrying it here would have meant
/// splitting [`record::read`] into `decode` + `open` at this call site — the
/// reassembly of a fail-closed composition that `record.rs` explicitly asks
/// callers not to perform.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OnDemandHit {
    slot: Slot,
    len: u16,
}

impl OnDemandHit {
    /// The slot the credential was read from.
    pub const fn slot(&self) -> Slot {
        self.slot
    }

    /// Bytes of plaintext now in the caller's window.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the window is unexpectedly empty — always false for a
    /// successful load, present so a caller cannot index `hit.len()` without
    /// the compiler reminding it the number can be checked.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Load exactly one credential into `out`.
///
/// # The contract, in order
///
/// 1. **`out` is cleared first.** Whatever the last operation left behind goes
///    before anything else happens, so a lookup that fails at step 2 or 3
///    cannot leave the *previous* credential sitting in the buffer. A window
///    that only gets cleared on success is a window that serves the wrong key.
/// 2. **Locate, without unsealing anything** — [`SlotLocator::locate`].
///    [`SlotRead::Absent`] for no match, [`SlotRead::Fault`] for a region that
///    could not be searched.
/// 3. **Read that one slot and open that one record.** [`record::read`] is the
///    whole read path — decode and unseal — so an erased slot, a bad header
///    CRC, a transplanted header and a failed AEAD tag all arrive as the same
///    [`SlotRead::Absent`], and one bad record costs itself alone (US-1549).
///
/// The result is `Absent` when nothing matched *or* when the one record that
/// matched would not open. Those are deliberately the same answer: a caller
/// that could tell them apart could use a corrupt record as an oracle, and
/// CTAP has no code for "the record you want is corrupt anyway".
///
/// # Cost
///
/// One `read_slot` (1,024 B, returned by value per [`KeyRegion::read_slot`]),
/// one AEAD operation, and one transient heap buffer of the record's plaintext
/// length — `record::read` allocates the `Plaintext` it returns, which is
/// zeroized on its own drop (`record.rs`) before this function returns. Nothing
/// in it is resident between calls.
pub fn load<L: SlotLocator + ?Sized>(
    region: &mut dyn KeyRegion,
    locator: &mut L,
    key: &PayloadKey,
    want: &SlotQuery<'_>,
    out: &mut CredentialWindow,
) -> SlotRead<OnDemandHit> {
    // Step 1, before anything can fail.
    out.zeroize_now();

    // Step 2. The scan; no payload is opened here, and the only thing it can
    // cost is a flash read of the index.
    let slot = match locator.locate(region, want) {
        Located::Found(slot) => slot,
        Located::None => return SlotRead::Absent,
        Located::Fault(why) => return SlotRead::Fault(why),
    };

    // Step 3. One read, one unseal.
    let raw = match region.read_slot(slot) {
        Ok(raw) => raw,
        Err(why) => return SlotRead::Fault(why),
    };
    #[cfg(not(target_arch = "arm"))]
    testing::record_unseal_attempt();
    match record::read(slot, &raw, key.as_bytes()) {
        SlotRead::Present(plaintext) => {
            let len = plaintext.len();
            // `Plaintext` is dropped here, zeroizing its own buffer
            // (`record.rs`, `impl Drop for Plaintext`) — before this function
            // returns, so there is never a moment with two plaintext copies of
            // a credential in the heap.
            if !out.adopt(plaintext.as_slice()) {
                // Unreachable: `FIDO_RECORD_MAX <= MAX_BODY_BYTES` is asserted
                // at compile time (`record.rs`), and the window is
                // `FIDO_RECORD_MAX`. Named rather than panicked so a device
                // build cannot abort inside an assertion path to defend a
                // condition its own constants exclude.
                return SlotRead::Absent;
            }
            SlotRead::Present(OnDemandHit { slot, len: len as u16 })
        }
        SlotRead::Absent => SlotRead::Absent,
        SlotRead::Fault(why) => SlotRead::Fault(why),
    }
}

// ---------------------------------------------------------------------------
// Compile-time assertions
// ---------------------------------------------------------------------------

const _: () = {
    // The window must hold the largest record the store can write, or the
    // largest legitimate credential would fail to load — with an error
    // indistinguishable from corruption, which is the worst possible failure
    // for the one record that is definitely not corrupt.
    assert!(
        ON_DEMAND_WINDOW_BYTES as u32 >= FIDO_RECORD_MAX,
        "the on-demand window cannot hold the largest FIDO record — raise ON_DEMAND_WINDOW_BYTES \
         or lower the measured record"
    );
    // A `u16` length is enough for the bound above (836 < 65,536), and the
    // `as u16` casts in `adopt` and `load` are only sound while that holds. If
    // a future stride ever put a record past 64 KiB, these would silently
    // truncate rather than fail.
    assert!(
        ON_DEMAND_WINDOW_BYTES < u16::MAX as usize,
        "the on-demand window's length field is u16; a record past 64 KiB would truncate"
    );
};

// ---------------------------------------------------------------------------
// Host-only: the stand-in locator and the decryption witness
// ---------------------------------------------------------------------------

/// Host-only support for proving this module's properties.
///
/// Gated exactly as `crypto.rs`'s and `record.rs`'s (`#[cfg(not(target_arch =
/// "arm"))]`): the *tests* run on the host, and the device build has no use
/// for a directory that stands in for something US-1551 will put in flash. The
/// decryption counter exists for the same reason `crypto::testing` does — the
/// property under test is about work performed inside a function, and there is
/// no way to observe that from outside without instrumenting the code path.
#[cfg(not(target_arch = "arm"))]
pub mod testing {
    use super::{KeyRegion, Located, Slot, SlotLocator, SlotQuery, Vec};
    use core::cell::Cell;

    /// `std::thread_local!`, as `crypto.rs`'s own witness uses — this module
    /// exists only off arm, where `lib.rs` has opted back into `std`.
    use std::thread_local;

    /// One line of a stand-in directory: the tag, the credential ID, and where
    /// the record is.
    ///
    /// This is the *shape* of a US-1551 index entry and deliberately not its
    /// *storage*. The real one lives in flash, sealed under the PIN-free index
    /// key, and is scanned by reading index slots — never by holding the set in
    /// RAM. Holding it in RAM here is what makes it a stand-in, and it is the
    /// one thing about this type that must not survive the swap.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DirectoryEntry {
        /// `SHA-256(rp_id)`.
        pub tag: [u8; super::RP_ID_TAG_LEN],
        /// The credential ID, or empty when the entry models a credential
        /// addressed by tag alone.
        pub credential_id: Vec<u8>,
        /// Where the record is.
        pub slot: Slot,
    }

    /// A linear-scan stand-in for the index (US-1551).
    ///
    /// Scans in insertion order and answers with the first match, which is the
    /// behaviour a flash-backed index will have to *choose* rather than inherit
    /// — so the choice is made here, where it is visible, and a test can assert
    /// on it.
    ///
    /// It counts [`Self::examined`], the number of entries compared, so
    /// "the index is scanned for the matching rp_id_tag" is an observable
    /// number rather than a claim about a loop someone read.
    #[derive(Default)]
    pub struct DirectoryLocator {
        entries: Vec<DirectoryEntry>,
        examined: Cell<u32>,
        fault: Option<&'static str>,
    }

    impl DirectoryLocator {
        /// An empty directory.
        pub fn new() -> Self {
            Self::default()
        }

        /// Add an entry.
        pub fn insert(&mut self, entry: DirectoryEntry) {
            self.entries.push(entry);
        }

        /// How many entries the directory holds.
        pub fn len(&self) -> usize {
            self.entries.len()
        }

        /// Whether the directory is empty.
        pub fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        /// Entries compared by the last [`SlotLocator::locate`].
        ///
        /// Reset by every call, so a test can measure one lookup rather than
        /// the accumulated total.
        pub fn examined(&self) -> u32 {
            self.examined.get()
        }

        /// Make every lookup answer [`Located::Fault`] with `why`, to exercise
        /// the US-1573 path without damaging a region on disk.
        pub fn inject_fault(&mut self, why: Option<&'static str>) {
            self.fault = why;
        }
    }

    impl SlotLocator for DirectoryLocator {
        fn locate(&mut self, _region: &mut dyn KeyRegion, want: &SlotQuery<'_>) -> Located {
            self.examined.set(0);
            if let Some(why) = self.fault {
                return Located::Fault(why);
            }
            let mut examined = 0u32;
            for entry in &self.entries {
                examined += 1;
                if entry.tag != *want.tag() {
                    continue;
                }
                if let SlotQuery::RpIdTagAndCredentialId { credential_id, .. } = want {
                    if entry.credential_id.as_slice() != *credential_id {
                        continue;
                    }
                }
                self.examined.set(examined);
                return Located::Found(entry.slot);
            }
            self.examined.set(examined);
            Located::None
        }
    }

thread_local! {
        /// Invocations of the read path by [`super::load`] on this thread.
        ///
        /// **One per record actually unsealed**, which is the quantity the
        /// gherkin's "exactly one record is decrypted" asks about. It is
        /// incremented immediately *before* `record::read`, so a record whose
        /// header CRC fails counts here without the AEAD ever running — the
        /// count is an upper bound on decryptions and exact when the record
        /// opened, which is what makes it useful as a witness. The exact count
        /// is established by pairing it with the region's `slot_reads`, since
        /// `record::read` cannot decrypt a record it was not handed a slot
        /// image for.
        ///
        /// Thread-local so the parallel test harness gives each `#[test]` its
        /// own count and no test can pass on another's work.
        static UNSEAL_ATTEMPTS: Cell<u32> = const { Cell::new(0) };
        /// Post-zeroize contents of every window dropped on this thread.
        static DROPPED_WINDOWS: std::cell::RefCell<Vec<[u8; super::ON_DEMAND_WINDOW_BYTES]>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    /// Called from [`super::load`] immediately before the one unseal it does.
    pub(super) fn record_unseal_attempt() {
        UNSEAL_ATTEMPTS.with(|c| c.set(c.get() + 1));
    }

    /// Called from [`super::CredentialWindow`]'s `Drop`, **after** the clear.
    pub(super) fn record_dropped_window(bytes: &[u8; super::ON_DEMAND_WINDOW_BYTES]) {
        DROPPED_WINDOWS.with(|d| d.borrow_mut().push(*bytes));
    }

    /// Read-path invocations this thread has performed since the last
    /// [`clear`].
    pub fn unseal_attempts() -> u32 {
        UNSEAL_ATTEMPTS.with(|c| c.get())
    }

    /// Post-zeroize contents of every window dropped since the last [`clear`].
    ///
    /// What a test reads to prove the drop really did clear the bytes, since
    /// by the time it could look the memory is freed and there is no sound way
    /// to read it.
    pub fn dropped_windows() -> Vec<[u8; super::ON_DEMAND_WINDOW_BYTES]> {
        DROPPED_WINDOWS.with(|d| d.borrow().clone())
    }

    /// Forget both records, so one test cannot make the next one pass.
    pub fn clear() {
        UNSEAL_ATTEMPTS.with(|c| c.set(0));
        DROPPED_WINDOWS.with(|d| d.borrow_mut().clear());
    }
}