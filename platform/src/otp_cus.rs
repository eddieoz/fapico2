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
//! reads the **raw view first** and consults the ECC view second, because the
//! ECC view cannot be asked to explain a refusal.
//!
//! **What erased looks like is measured, not assumed** — US-1711's
//! two-population probe
//! (`docs/evidence/otp-probe-us1711.md`, conclusions, measured over BOOTSEL)
//! settled the register model: **an erased OTP row reads 0x000000 in the raw
//! view** (the same zero-bytes blank-check `is_empty_buffer` applies in
//! pico-fido2), because the ECC metadata of a burned word always sets raw
//! bits. All-ones in the raw view is the **debug-attachment artifact** — the
//! `OTP_DATA_RAW`-under-a-debugger pathology AGENTS.md records — and this
//! module classifies it `Faulted`, never `Erased`. The classifier is therefore
//! contents-authoritative in both directions: a faulted read is never read as
//! emptiness, and an erased row is never read as data.
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
    /// The raw view reads zero bytes **and** the ECC view agrees with `0`:
    /// the row has never been written (US-1711's measured blank-check).
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
    /// The raw 24-bit view of one row. Zero bytes are the erased mark
    /// (US-1711); an all-ones answer is the debug artifact, which
    /// [`classify_row`] reads as a fault.
    fn raw_word(&self, row: usize) -> Result<u32, OtpError>;
    /// The ECC-corrected 16-bit view. [`OtpError::Refused`] is the
    /// permission refusal embassy raises for a locked or debug-attached row.
    fn ecc_word(&self, row: usize) -> Result<u16, OtpError>;
    /// Burn one ECC word. Once.
    fn write_ecc_word(&self, row: usize, data: u16) -> Result<(), OtpError>;
}

/// Classify one row, raw view first.
///
/// The measured rules (US-1711's transcript is the authority for all three):
///
/// * **Zero raw bytes are the erased mark.** The ECC metadata of any burned
///   word sets raw bits, so an all-zero 24-bit raw row is never-written — the
///   ECC view must agree with `0`, and any other answer demotes the row to
///   [`RowClass::Faulted`] (a fault is never read as emptiness).
/// * **All-ones raw is the debug artifact, never a content answer** —
///   AGENTS.md's `OTP_DATA_RAW`-under-a-debugger pathology — and classifies
///   `Faulted` unconditionally.
/// * Otherwise both views must agree on the same 16-bit word, or the row is
///   `Faulted`. A raw view that itself bus-faults is `Faulted` outright.
pub fn classify_row<A: OtpAccess + ?Sized>(otp: &A, row: usize) -> RowClass {
    match otp.raw_word(row) {
        // The measured blank-check: zero bytes mean never-written. The ECC
        // view must agree with 0 — if it faults or opens with data, the two
        // views disagree, and disagreement is a fault, never emptiness.
        Ok(0) => match otp.ecc_word(row) {
            Ok(0) => RowClass::Erased,
            _ => RowClass::Faulted,
        },
        // All-ones is the debug-refusal artifact, not data and not emptiness.
        Ok(0xFFFF_FFFF) => RowClass::Faulted,
        Ok(raw) => match otp.ecc_word(row) {
            // Both views agree on the data: the raw low bits carry the same
            // 16-bit word the ECC view corrected. (A burned 0x0000 word has
            // non-zero ECC metadata, so this leg still distinguishes it from
            // the erased zero-row above.)
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
pub fn burn_ecc_word<A: OtpAccess + ?Sized>(
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
    /// of the seam: embassy's single `InvalidPermissions` on the raw view is
    /// surfaced as the all-ones answer ([`classify_row`] reads that as a
    /// fault — the debug artifact, never emptiness), and an ECC-view
    /// `UnexpectedFailure` stays a [`OtpError::Bus`].
    use embassy_rp::otp::Error as E;

    pub struct RealOtp;

    impl OtpAccess for RealOtp {
        fn raw_word(&self, row: usize) -> Result<u32, OtpError> {
            match embassy_rp::otp::read_raw_word(row) {
                Ok(v) => Ok(v),
                // A raw-view permission refusal is the debug-attachment /
                // lock state. Surfacing it as all-ones keeps the classifier's
                // fault path (never `Erased`) the single place the artifact
                // is interpreted.
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
