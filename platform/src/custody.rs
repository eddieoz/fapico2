//! US-1712 — the custody ceremony: burn the 16-byte Nostr custody secret
//! into page 59 and lock the page, contents-authoritative and marker-last.
//!
//! The page constant is **US-1711's**, and no other (`docs/evidence/
//! otp-probe-us1711.md`, conclusions): page 58 is full and locked on every
//! pico-fido2-migrated board, and page 59 measured virgin and unlocked on
//! both probe populations. The lock row is the C's own formula, verified
//! against picotool's field naming on the probe board:
//! `OTP_DATA_PAGE0_LOCK0_ROW (0xF80) + page*2 + 1` — the LOCK1 row, the same
//! one `otp_lock_page` burns for page 58.
//!
//! Two rules carry the story:
//!
//! * **Contents-authoritative.** The custody secret is *what reads back*,
//!   never what was intended: torn resumes keep the words already burned
//!   (they are ours by construction — the ceremony is the page's only
//!   writer), each erased word is refilled with fresh entropy after `N`
//!   consistent erased-class reads, and every derivation input is the
//!   read-back row contents. The N-consistent-refill rule is the one the
//!   old all-ones API made unsatisfiable — US-1711 measured that erased
//!   rows read zero, so `Erased` is now a real class, not a refusal.
//! * **Marker-last.** The committed-marker word is written after the
//!   page-lock burn, so `burned+locked+complete` is distinguishable from
//!   every partial state by classification alone, and a torn burn (no
//!   marker) is always resumable. A word that reads back **other than the
//!   value just written or erased** aborts with no marker — the brick
//!   vector (R3) is spent on nothing user-visible.

use crate::otp_cus::{burn_ecc_word, classify_row, OtpAccess, OtpError, RowClass};

/// The custody page — US-1711's transcript is the only authority for this
/// number. Page 58 is taken (pico-fido2's key pages, post-lock); page 59
/// measured virgin and unlocked on both probe populations.
pub const CUSTODY_PAGE: usize = 59;

/// The 16-byte secret is eight 16-bit words, one OTP row each.
pub const SECRET_WORDS: usize = 8;

/// The page-lock word — the low 16 bits of the C's `0x3C3C3C`
/// (`LOCK_BL=3, LOCK_NS=3, LOCK_S=0`), the lock shape page 58 carries. The
/// raw view reads this back with ECC metadata above it; the lock fields
/// live in the low byte and are unaffected.
pub const LOCK_WORD: u16 = 0x3C3C;

/// The committed-marker word, written last. Any value that cannot be read
/// as erased and does not collide with the lock word would do; this one is
/// just "custody marker".
pub const MARKER_WORD: u16 = 0xC577;

/// A refill only fires after this many consistent erased-class reads —
/// the rule the old API could not express.
pub const REFILL_ERASED_READS: usize = 3;

/// Page 59's first row: `page * 64` (embassy's 64-rows-per-page model,
/// reconciled to picotool's naming by the probe).
pub const FIRST_SECRET_ROW: usize = CUSTODY_PAGE * 64;
/// The marker row, immediately above the secret.
pub const MARKER_ROW: usize = FIRST_SECRET_ROW + SECRET_WORDS;
/// Page 59's LOCK1 row: `0xF80 + page*2 + 1` — the row `otp_lock_page`
/// burns for page 58, at page 59's offset (picotool names 0xFF7
/// `OTP_DATA_PAGE59_LOCK1`).
pub const LOCK_ROW: usize = 0xF80 + CUSTODY_PAGE * 2 + 1;

/// Where the ceremony stands, decided by classification alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyState {
    /// Nothing of ours on the page: every row erased.
    Virgin,
    /// A torn burn — no marker, resumable. Some prefix of the secret words
    /// valid, the rest erased, the lock and marker both erased.
    Torn,
    /// All words valid, the lock burned, the marker not yet written. The
    /// next [`burn`] writes the marker and nothing else.
    Sealed,
    /// Burned, locked, marker present. Idempotent: [`burn`] returns
    /// immediately.
    Complete,
    /// An irregular page: a faulted row, a hole in the valid prefix, a
    /// foreign marker or lock, or a contradiction between the states the
    /// flow can produce. Never burn onto this.
    Abort,
}

/// Why a [`burn`] refused to continue. Every error leaves the marker
/// unwritten — the ceremony never completes partially by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyError {
    /// The refill's N consistent erased reads did not hold.
    NotErased(usize),
    /// A word read back other than the value just written or erased.
    /// Abort-with-no-marker: the one true brick vector is spent on nothing.
    Mismatch(usize),
    /// The lock row holds something other than [`LOCK_WORD`].
    LockMismatch(u16),
    /// The marker row holds something other than [`MARKER_WORD`].
    MarkerForeign(u16),
    /// `assess` found an irregular page — never burn onto [`CeremonyState::Abort`].
    Irregular,
    /// An OTP access failed outside the classification vocabulary.
    Bus(OtpError),
}

/// How many of the secret words read back `Valid`, as a strict prefix —
/// `None` when the page is irregular (a faulted row, or a valid word with
/// an erased word *before* it: the ceremony fills in order, so a hole is
/// not ours).
fn word_prefix<A: OtpAccess + ?Sized>(otp: &A) -> Option<usize> {
    let mut prefix = 0usize;
    for i in 0..SECRET_WORDS {
        match classify_row(otp, FIRST_SECRET_ROW + i) {
            RowClass::Valid(_) if prefix == i => prefix = i + 1,
            RowClass::Valid(_) => return None,
            RowClass::Erased => {}
            RowClass::Faulted => return None,
        }
    }
    Some(prefix)
}

/// Classify the page. Decides **only** from what the rows read back — the
/// same property that makes `burned+locked+complete` distinguishable from
/// every partial state.
pub fn assess<A: OtpAccess + ?Sized>(otp: &A) -> CeremonyState {
    let Some(prefix) = word_prefix(otp) else {
        return CeremonyState::Abort;
    };
    let lock_done = match classify_row(otp, LOCK_ROW) {
        RowClass::Valid(w) if w == LOCK_WORD => true,
        RowClass::Erased => false,
        _ => return CeremonyState::Abort,
    };
    let marker_done = match classify_row(otp, MARKER_ROW) {
        RowClass::Valid(w) if w == MARKER_WORD => true,
        RowClass::Erased => false,
        _ => return CeremonyState::Abort,
    };
    // The marker is written last: a marker without its prefix, or with the
    // lock missing, is a state the flow cannot produce — irregular.
    if marker_done && !(prefix == SECRET_WORDS && lock_done) {
        return CeremonyState::Abort;
    }
    if prefix == 0 && !lock_done && !marker_done {
        return CeremonyState::Virgin;
    }
    if prefix < SECRET_WORDS || !lock_done {
        return CeremonyState::Torn;
    }
    if !marker_done {
        return CeremonyState::Sealed;
    }
    CeremonyState::Complete
}

/// `N` consistent erased-class reads, or no refill. Through the old API the
/// word "erased" was indistinguishable from "refused", which is what made
/// this rule unsatisfiable there; US-1711's zero-bytes measurement is what
/// makes it expressible now.
fn erased_consistently<A: OtpAccess + ?Sized>(otp: &A, row: usize) -> Result<(), CeremonyError> {
    for _ in 0..REFILL_ERASED_READS {
        if classify_row(otp, row) != RowClass::Erased {
            return Err(CeremonyError::NotErased(row));
        }
    }
    Ok(())
}

/// Write one word and hold it to the intended-or-erased rule: the read-back
/// must be exactly what was written, or erased (a word that did not stick —
/// the torn state, resumable). Anything else is the abort.
fn write_verified<A: OtpAccess + ?Sized>(
    otp: &A,
    row: usize,
    word: u16,
) -> Result<Option<RowClass>, CeremonyError> {
    let class = burn_ecc_word(otp, row, word).map_err(CeremonyError::Bus)?;
    match class {
        RowClass::Valid(w) if w == word => Ok(Some(class)),
        // The write did not stick: leave it for the next run's refill.
        RowClass::Erased => Ok(None),
        _ => Err(CeremonyError::Mismatch(row)),
    }
}

/// Run the ceremony to completion, idempotently. `word_entropy` supplies a
/// fresh word for every erased-class row actually refilled — never for a
/// row that already reads back `Valid`, which is skipped untouched.
///
/// The returned state is what the page reads as **after** the run; on the
/// torn path (a word that read back erased after its write) the state is
/// the resumable [`CeremonyState::Torn`], and the caller retries.
pub fn burn<A: OtpAccess + ?Sized, W: FnMut() -> u16>(
    otp: &A,
    mut word_entropy: W,
) -> Result<CeremonyState, CeremonyError> {
    match assess(otp) {
        CeremonyState::Complete => return Ok(CeremonyState::Complete),
        CeremonyState::Abort => return Err(CeremonyError::Irregular),
        _ => {}
    }
    // The secret words: refill only erased-class rows, in order.
    for i in 0..SECRET_WORDS {
        let row = FIRST_SECRET_ROW + i;
        match classify_row(otp, row) {
            // Never rewritten — its read-back value is part of the secret.
            RowClass::Valid(_) => {}
            RowClass::Faulted => return Err(CeremonyError::Mismatch(row)),
            RowClass::Erased => {
                erased_consistently(otp, row)?;
                let word = word_entropy();
                if write_verified(otp, row, word)?.is_none() {
                    return Ok(assess(otp));
                }
            }
        }
    }
    // The page lock, before the marker.
    match classify_row(otp, LOCK_ROW) {
        RowClass::Valid(w) if w == LOCK_WORD => {}
        RowClass::Erased => {
            erased_consistently(otp, LOCK_ROW)?;
            if write_verified(otp, LOCK_ROW, LOCK_WORD)?.is_none() {
                return Ok(assess(otp));
            }
        }
        RowClass::Valid(w) => return Err(CeremonyError::LockMismatch(w)),
        RowClass::Faulted => return Err(CeremonyError::Mismatch(LOCK_ROW)),
    }
    // The committed marker, last — after the lock.
    match classify_row(otp, MARKER_ROW) {
        RowClass::Valid(w) if w == MARKER_WORD => {}
        RowClass::Erased => {
            erased_consistently(otp, MARKER_ROW)?;
            write_verified(otp, MARKER_ROW, MARKER_WORD)?;
        }
        RowClass::Valid(w) => return Err(CeremonyError::MarkerForeign(w)),
        RowClass::Faulted => return Err(CeremonyError::Mismatch(MARKER_ROW)),
    }
    Ok(assess(otp))
}

/// The custody secret as read back — the derivation input, deterministic
/// across boots and firmware generations because it is the silicon's
/// answer, never the intended one. Fails closed: erased and faulted rows
/// yield `None` (see [`RowClass::contents`]).
pub fn custody_words<A: OtpAccess + ?Sized>(otp: &A) -> Option<[u16; SECRET_WORDS]> {
    let mut out = [0u16; SECRET_WORDS];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = classify_row(otp, FIRST_SECRET_ROW + i).contents()?;
    }
    Some(out)
}

/// The secret as the 16 bytes the KDF consumes, big-endian per word.
pub fn custody_secret_bytes<A: OtpAccess + ?Sized>(otp: &A) -> Option<[u8; 16]> {
    let words = custody_words(otp)?;
    let mut bytes = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        bytes[i * 2] = (w >> 8) as u8;
        bytes[i * 2 + 1] = (w & 0xFF) as u8;
    }
    Some(bytes)
}
