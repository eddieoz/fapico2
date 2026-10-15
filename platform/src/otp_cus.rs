//! US-1710 — the OTP custody-row primitive: the three-way row classifier and
//! the ECC-word burn with a value-exact read-back.
//!
//! This is ADR 0002's recorded OTP prerequisite ("a real `Otp` implementation
//! … with ECC + raw write, blank-check, read-back verify, and a lock/raw-write
//! surface") landing at last. The seam follows [`crate::fused_key::FusedReader`]
//! — the real hardware sits behind an injected reader ([`RealOtp`] on the
//! arm build, a fixture in the host tests), because embassy-rp 0.10's public
//! API **cannot distinguish the two states this module exists to tell apart**:
//!
//! > `read_ecc_word` pre-checks permissions through the raw view and maps an
//! > all-ones row to `Err(InvalidPermissions)` — so through the current public
//! > API "reads back erased" and "read refused" are the same return value.
//!
//! (review fact F1, `embassy-rp-0.10.0/src/otp.rs:50-77`). The classifier
//! reads the **raw view first** — the raw view is contents-authoritative and
//! *answers* (`0xFFFF_FFFF` is an erased row, not a refusal) — and only then
//! consults the ECC view, whose refusal now means one thing instead of two.
//!
//! **No page constant lives here.** US-1711's two-population probe is the gate
//! that chooses the custody page; until that transcript exists, every caller
//! passes a row and the choice stays theirs.

/// The OTP error vocabulary, mapped from embassy's so the classifier can
/// separate "the controller refused" (the erased pre-check, a lock) from
/// "the access itself failed" (an unexpected bootrom return code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    /// The controller refused the access — embassy's `InvalidPermissions`.
    Refused,
    /// The access returned an unexpected failure code.
    Bus(i32),
    /// The row index is outside the declared row count.
    OutOfRange,
}

/// The three-way classification of one custody-class row. `Fault` is *never*
/// classified as erased, and erased is never classified as valid — by
/// construction, in [`classify_row`], in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowClass {
    /// The raw view is all-ones **and** the ECC view refuses with the
    /// permission error: the row has never been written.
    Erased,
    /// The ECC view opens; the corrected 16-bit word.
    Valid(u16),
    /// Uncorrectable ECC, a bus failure, or a contradiction between the two
    /// views. A fault is a fault: it must not be read as data and must not
    /// be read as emptiness.
    Faulted,
}

impl RowClass {
    /// The row's contents — `None` unless the row is [`RowClass::Valid`].
    /// Every consumer that would derive a key or touch a record goes through
    /// here: erased and faulted rows yield nothing, fail closed, and the
    /// caller's "else" branch is where the refusal lives.
    pub fn contents(&self) -> Option<u16> {
        match self {
            RowClass::Valid(w) => Some(*w),
            _ => None,
        }
    }
}

/// The OTP access seam. Three operations, because the classifier needs all
/// three views and embassy's ECC read cannot be asked to explain itself.
pub trait OtpAccess {
    /// The raw 24-bit view of one row (`0xFFFF_FFFF` when erased — the raw
    /// view answers, it does not refuse emptiness).
    fn raw_word(&self, row: usize) -> Result<u32, OtpError>;
    /// The ECC-corrected 16-bit view. [`OtpError::Refused`] is the same
    /// permission refusal embassy raises for an erased row's pre-check.
    fn ecc_word(&self, row: usize) -> Result<u16, OtpError>;
    /// Burn one ECC word. Once.
    fn write_ecc_word(&self, row: usize, data: u16) -> Result<(), OtpError>;
}

/// Classify one row, raw view first.
///
/// The load-bearing asymmetry: an all-ones **raw** view is necessary for
/// `Erased` but not sufficient — the ECC view must refuse *with the
/// permission error*, and any other answer from the ECC view (a bus fault, or
/// worse, an open read) demotes the row to [`RowClass::Faulted`]. A row whose
/// raw view bus-faults is `Faulted` outright; through embassy's public API
/// that state is indistinguishable from erased, which is exactly why the
/// raw view is read directly.
pub fn classify_row<A: OtpAccess>(otp: &A, row: usize) -> RowClass {
    match otp.raw_word(row) {
        Ok(0xFFFF_FFFF) => match otp.ecc_word(row) {
            // The erased confirmation: ECC refuses because the permission
            // pre-check saw the all-ones raw view.
            Err(OtpError::Refused) => RowClass::Erased,
            // Raw says erased but the ECC view faults or *opens* — the two
            // views disagree, and disagreement is a fault, never emptiness.
            _ => RowClass::Faulted,
        },
        Ok(raw) => match otp.ecc_word(row) {
            // Both views agree on the data: the raw low bits carry the same
            // 16-bit word the ECC view corrected.
            Ok(word) if (raw as u16) == word => RowClass::Valid(word),
            // The ECC view opens but disagrees with the raw view —
            // uncorrectable or inconsistent metadata.
            Ok(_) => RowClass::Faulted,
            Err(_) => RowClass::Faulted,
        },
        Err(_) => RowClass::Faulted,
    }
}

/// Burn one ECC word and verify it **value-exact against the raw view**.
///
/// Returns the **classified read-back** — the ceremony derives from what the
/// row reads back, never from what was intended (US-1712's
/// `derivation_uses_readback_contents`). The read-back is cross-checked
/// between the two views: a row whose ECC view opens but disagrees with its
/// own raw bits classifies `Faulted` and is surfaced as an error, not
/// returned as success. Whether the read-back matches the *intended* value is
/// the caller's comparison — a mismatch is the ceremony's abort-with-no-marker
/// case, and this primitive returns the evidence either way.
pub fn burn_ecc_word<A: OtpAccess>(
    otp: &A,
    row: usize,
    data: u16,
) -> Result<RowClass, OtpError> {
    otp.write_ecc_word(row, data)?;
    match classify_row(otp, row) {
        // A row we just wrote reading back erased is a contradiction — the
        // write did not stick. That is not emptiness; it is a fault, and the
        // never-erased property is preserved in this direction too.
        RowClass::Erased => Err(OtpError::Bus(-5)),
        class => Ok(class),
    }
}

// ---------------------------------------------------------------------------
// The real hardware, behind the same feature gate fused_key's arm code uses
// ---------------------------------------------------------------------------

#[cfg(all(feature = "device", target_arch = "arm"))]
mod real {
    use super::{OtpAccess, OtpError};

    /// The arm OTP, through embassy's driver. The mapping is the whole point
    /// of the seam: embassy's single `InvalidPermissions` is mapped to
    /// [`OtpError::Refused`] only where the *raw* view raised it (there it
    /// means all-ones — erased), and an ECC-view `UnexpectedFailure` stays a
    /// [`OtpError::Bus`].
    use embassy_rp::otp::Error as E;

    pub struct RealOtp;

    impl OtpAccess for RealOtp {
        fn raw_word(&self, row: usize) -> Result<u32, OtpError> {
            match embassy_rp::otp::read_raw_word(row) {
                Ok(v) => Ok(v),
                // The raw view reading all-ones is a *content* answer, not a
                // refusal — this mapping is the one public-API fact F1 turns on.
                Err(E::InvalidPermissions) => Ok(0xFFFF_FFFF),
                Err(E::InvalidIndex) => Err(OtpError::OutOfRange),
                Err(E::UnexpectedFailure(code)) => Err(OtpError::Bus(code)),
                Err(_) => Err(OtpError::Bus(-2)),
            }
        }

        fn ecc_word(&self, row: usize) -> Result<u16, OtpError> {
            match embassy_rp::otp::read_ecc_word(row) {
                Ok(v) => Ok(v),
                Err(E::InvalidPermissions) => Err(OtpError::Refused),
                Err(E::InvalidIndex) => Err(OtpError::OutOfRange),
                Err(E::UnexpectedFailure(code)) => Err(OtpError::Bus(code)),
                Err(_) => Err(OtpError::Bus(-3)),
            }
        }

        fn write_ecc_word(&self, row: usize, data: u16) -> Result<(), OtpError> {
            match embassy_rp::otp::write_ecc_word(row, data) {
                Ok(()) => Ok(()),
                Err(E::InvalidPermissions) => Err(OtpError::Refused),
                Err(E::InvalidIndex) => Err(OtpError::OutOfRange),
                Err(E::UnexpectedFailure(code)) => Err(OtpError::Bus(code)),
                Err(_) => Err(OtpError::Bus(-4)),
            }
        }
    }
}

#[cfg(all(feature = "device", target_arch = "arm"))]
pub use real::RealOtp;
