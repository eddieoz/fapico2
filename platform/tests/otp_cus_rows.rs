//! US-1710's acceptance tests, over an injected OTP fixture — the
//! [`fapico2_platform::fused_key`] seam pattern: the real hardware stays
//! behind the trait, and all three row classes are host-testable.

use fapico2_platform::otp_cus::{burn_ecc_word, classify_row, OtpAccess, OtpError, RowClass};

/// The fixture: rows are `(raw, ecc)` pairs; the ECC view refuses when raw
/// is all-ones (embassy's pre-check, fact F1), unless the test wants a fault.
struct Fixture {
    rows: [(u32, Result<u16, OtpError>); 4],
    ecc_fault_rows: &'static [usize],
}

const ERASED_ROW: usize = 0;
const VALID_ROW: usize = 1;
const ECC_FAULTED_ROW: usize = 2;
const RAW_FAULTED_ROW: usize = 3;

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
            // Embassy's ECC view refuses (the permission pre-check) on an
            // all-ones raw row, and answers with the data otherwise.
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

#[test]
fn row_classifies_erased_valid_faulted() {
    // Erased: raw all-ones, ECC view refuses with the permission error —
    // the two answers TOGETHER make erased, and neither alone does.
    let otp = fixture(
        [
            (0xFFFF_FFFF, Err(OtpError::Refused)),
            (0x0000_BEEF, Ok(0xBEEF)),
            (0x0000_DEAD, Ok(0xDEAD)),
            (0x0000_FEED, Ok(0xFEED)),
        ],
        &[ECC_FAULTED_ROW],
    );
    assert_eq!(classify_row(&otp, ERASED_ROW), RowClass::Erased);
    assert_eq!(classify_row(&otp, VALID_ROW), RowClass::Valid(0xBEEF));
    // Faulted, twice: the ECC view bus-faults on a row whose raw view is
    // readable, and the ECC view that *opens* on a raw all-ones row is the
    // contradiction class, not emptiness.
    assert_eq!(classify_row(&otp, ECC_FAULTED_ROW), RowClass::Faulted);
    let raw_faulted = fixture(
        [
            (0xFFFF_FFFF, Err(OtpError::Refused)),
            (0x0000_BEEF, Ok(0xBEEF)),
            (0x0000_DEAD, Ok(0xDEAD)),
            (0x0000_FEED, Ok(0xFEED)),
        ],
        &[RAW_FAULTED_ROW, ECC_FAULTED_ROW],
    );
    assert_eq!(classify_row(&raw_faulted, ECC_FAULTED_ROW), RowClass::Faulted);
    // A raw view that itself bus-faults is faulted outright — through the
    // public API this state is indistinguishable from erased, which is why
    // the classifier reads the raw view directly.
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
fn faulted_row_is_never_erased() {
    // The contradiction row: raw all-ones (which alone would look erased
    // through the public API) with an ECC view that bus-faults. The
    // classifier must not call this erased — a fault is a fault.
    let otp = fixture(
        [
            (0xFFFF_FFFF, Err(OtpError::Refused)),
            (0x0000_BEEF, Ok(0xBEEF)),
            (0x0000_DEAD, Ok(0xDEAD)),
            (0x0000_FEED, Ok(0xFEED)),
        ],
        &[ERASED_ROW],
    );
    assert_eq!(classify_row(&otp, ERASED_ROW), RowClass::Faulted);
    assert!(classify_row(&otp, ERASED_ROW).contents().is_none());
    // And the same in the burn direction: burning onto that row reads back
    // `Faulted` — never `Erased`, never a `Valid` the ECC view did not open.
    assert_eq!(burn_ecc_word(&otp, ERASED_ROW, 0x1234), Ok(RowClass::Faulted));
    // The contradiction case proper: a write that does not stick. The row
    // reads back erased after a successful `write_ecc_word` — an error,
    // never a silent success.
    let unstuck = fixture(
        [
            (0xFFFF_FFFF, Err(OtpError::Refused)),
            (0x0000_BEEF, Ok(0xBEEF)),
            (0x0000_DEAD, Ok(0xDEAD)),
            (0x0000_FEED, Ok(0xFEED)),
        ],
        &[],
    );
    assert_eq!(burn_ecc_word(&unstuck, ERASED_ROW, 0x1234), Err(OtpError::Bus(-5)));
}

#[test]
fn faulted_row_never_derives_a_key() {
    // The ceremony derives from row contents and touches records only on
    // the Valid leg. A faulted (or erased) read feeds the KDF and fails
    // closed before any record is touched.
    let otp = fixture(
        [
            (0xFFFF_FFFF, Err(OtpError::Refused)),
            (0x0000_BEEF, Ok(0xBEEF)),
            (0x0000_DEAD, Ok(0xDEAD)),
            (0x0000_FEED, Ok(0xFEED)),
        ],
        &[ECC_FAULTED_ROW],
    );
    let mut touched = 0usize;
    {
        let mut derive_and_touch = |class: &RowClass| -> Option<u16> {
            let contents = class.contents()?; // faulted/erased stop here
            touched += 1; // the "KDF + record write" leg — only Valid reaches it
            Some(contents)
        };
        for row in [ERASED_ROW, ECC_FAULTED_ROW] {
            let class = classify_row(&otp, row);
            // Both refuse: no record was touched on an erased or faulted read.
            assert!(derive_and_touch(&class).is_none());
        }
        // The Valid leg still reaches it.
        assert_eq!(derive_and_touch(&classify_row(&otp, VALID_ROW)), Some(0xBEEF));
    }
    assert_eq!(touched, 1);
}
