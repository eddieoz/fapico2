//! US-1710's acceptance tests, over an injected OTP fixture — the
//! [`fapico2_platform::fused_key`] seam pattern: the real hardware stays
//! behind the trait, and all three row classes are host-testable.
//!
//! The fixture's shapes are the ones US-1711's probe measured: erased rows
//! read **zero bytes** in the raw view (the ECC view answers `0` with no
//! error), and all-ones is the debug artifact — faulted, never erased.

use fapico2_platform::otp_cus::{burn_ecc_word, classify_row, OtpAccess, OtpError, RowClass};

/// The fixture: rows are `(raw, ecc)` pairs. A zero raw row's ECC view
/// answers `0` (the measured erased shape); an all-ones raw row's ECC view
/// refuses (the artifact embassy surfaces through the permission pre-check),
/// unless the test wants a fault.
struct Fixture {
    rows: [(u32, Result<u16, OtpError>); 4],
    ecc_fault_rows: &'static [usize],
}

const ERASED_ROW: usize = 0;
const VALID_ROW: usize = 1;
const ECC_FAULTED_ROW: usize = 2;
const ALL_ONES_ROW: usize = 3;

impl OtpAccess for Fixture {
    fn raw_word(&self, row: usize) -> Result<u32, OtpError> {
        match self.rows.get(row) {
            Some((raw, _)) => Ok(*raw),
            None => Err(OtpError::OutOfRange),
        }
    }
    fn ecc_word(&self, row: usize) -> Result<u16, OtpError> {
        if self.ecc_fault_rows.contains(&row) {
            return Err(OtpError::Bus(-7));
        }
        match self.rows.get(row) {
            // The all-ones artifact: the ECC view refuses (the permission
            // pre-check), and answers with the data otherwise.
            Some((0xFFFF_FFFF, _)) => Err(OtpError::Refused),
            Some((_, ecc)) => *ecc,
            None => Err(OtpError::OutOfRange),
        }
    }
    fn write_ecc_word(&self, _row: usize, _data: u16) -> Result<(), OtpError> {
        Ok(())
    }
}

fn fixture(rows: [(u32, Result<u16, OtpError>); 4], ecc_fault_rows: &'static [usize]) -> Fixture {
    Fixture { rows, ecc_fault_rows }
}

fn default_rows() -> [(u32, Result<u16, OtpError>); 4] {
    [
        (0x0000_0000, Ok(0)),        // erased: zero bytes, both views agree
        (0x0000_BEEF, Ok(0xBEEF)),   // valid
        (0x0000_DEAD, Ok(0xDEAD)),   // valid, but the ECC view faults below
        (0xFFFF_FFFF, Err(OtpError::Refused)), // the debug artifact
    ]
}

#[test]
fn row_classifies_erased_valid_faulted() {
    // Erased: raw zero bytes with the ECC view agreeing on 0 — the measured
    // blank-check, and neither answer alone suffices.
    let otp = fixture(default_rows(), &[ECC_FAULTED_ROW]);
    assert_eq!(classify_row(&otp, ERASED_ROW), RowClass::Erased);
    assert_eq!(classify_row(&otp, VALID_ROW), RowClass::Valid(0xBEEF));
    // Faulted, twice: the ECC view bus-faults on a row whose raw view is
    // readable, and the all-ones raw row is the debug artifact — faulted
    // even though its ECC view "refuses politely".
    assert_eq!(classify_row(&otp, ECC_FAULTED_ROW), RowClass::Faulted);
    assert_eq!(classify_row(&otp, ALL_ONES_ROW), RowClass::Faulted);
    // A raw view that itself bus-faults is faulted outright.
    struct RawFaults;
    impl OtpAccess for RawFaults {
        fn raw_word(&self, _row: usize) -> Result<u32, OtpError> {
            Err(OtpError::Bus(-8))
        }
        fn ecc_word(&self, _row: usize) -> Result<u16, OtpError> {
            Err(OtpError::Bus(-8))
        }
        fn write_ecc_word(&self, _row: usize, _data: u16) -> Result<(), OtpError> {
            Err(OtpError::Bus(-8))
        }
    }
    assert_eq!(classify_row(&RawFaults, 0), RowClass::Faulted);
}

#[test]
fn valid_zero_word_is_not_erased() {
    // A burned 0x0000 word: the ECC metadata sets raw bits, so the raw view
    // is non-zero and the row is Valid(0) — distinguished from the erased
    // zero-row by the full 24-bit blank-check, exactly the property the
    // ceremony's refill loop leans on.
    let otp = fixture(
        [
            (0x0000_0000, Ok(0)),
            (0x0055_0000, Ok(0x0000)), // data 0, ECC metadata in the upper bits
            (0x0000_DEAD, Ok(0xDEAD)),
            (0xFFFF_FFFF, Err(OtpError::Refused)),
        ],
        &[],
    );
    assert_eq!(classify_row(&otp, ERASED_ROW), RowClass::Erased);
    assert_eq!(classify_row(&otp, VALID_ROW), RowClass::Valid(0x0000));
    assert_eq!(classify_row(&otp, VALID_ROW).contents(), Some(0x0000));
}

#[test]
fn erased_row_agreement_is_required() {
    // Raw reads zero but the ECC view faults: disagreement is a fault, never
    // emptiness — the never-erased property in the direction a faulted ECC
    // view would otherwise leak emptiness through.
    let otp = fixture(default_rows(), &[ERASED_ROW]);
    assert_eq!(classify_row(&otp, ERASED_ROW), RowClass::Faulted);
    assert!(classify_row(&otp, ERASED_ROW).contents().is_none());
}

#[test]
fn faulted_row_is_never_erased() {
    // The artifact row: raw all-ones, which the old all-ones-means-erased
    // model would have read as emptiness. It is a fault — full stop.
    let otp = fixture(default_rows(), &[ERASED_ROW]);
    assert_eq!(classify_row(&otp, ALL_ONES_ROW), RowClass::Faulted);
    assert!(classify_row(&otp, ALL_ONES_ROW).contents().is_none());
    // And in the burn direction: burning onto a row whose ECC view faults
    // reads back `Faulted` — never `Erased`, never a `Valid` the ECC view
    // did not open.
    let ecc_faults = fixture(default_rows(), &[ERASED_ROW, ECC_FAULTED_ROW]);
    assert_eq!(
        burn_ecc_word(&ecc_faults, ERASED_ROW, 0x1234),
        Ok(RowClass::Faulted)
    );
    // The write-does-not-stick case: the row still reads back erased after a
    // "successful" write — an error, never a silent success.
    let unstuck = fixture(default_rows(), &[]);
    assert_eq!(burn_ecc_word(&unstuck, ERASED_ROW, 0x1234), Err(OtpError::Bus(-5)));
}

#[test]
fn faulted_row_never_derives_a_key() {
    // The ceremony derives from row contents and touches records only on
    // the Valid leg. A faulted (or erased) read feeds the KDF and fails
    // closed before any record is touched.
    let otp = fixture(default_rows(), &[ECC_FAULTED_ROW]);
    let mut touched = 0usize;
    {
        let mut derive_and_touch = |class: &RowClass| -> Option<u16> {
            let contents = class.contents()?; // faulted/erased stop here
            touched += 1; // the "KDF + record write" leg — only Valid reaches it
            Some(contents)
        };
        for row in [ERASED_ROW, ECC_FAULTED_ROW, ALL_ONES_ROW] {
            let class = classify_row(&otp, row);
            // All three refuse: no record was touched on an erased or faulted read.
            assert!(derive_and_touch(&class).is_none());
        }
        // The Valid leg still reaches it.
        assert_eq!(derive_and_touch(&classify_row(&otp, VALID_ROW)), Some(0xBEEF));
    }
    assert_eq!(touched, 1);
}
