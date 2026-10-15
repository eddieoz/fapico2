//! US-1712's acceptance tests, over an injected OTP fixture. The fixture is
//! mutable where US-1710's was not — the ceremony's rules are about what a
//! write does and what a refill may touch, so the fixture models both.
//!
//! Every row lives at its real absolute index (page 59's rows, the lock row
//! at `0xF80 + 59*2 + 1`), so the tests also pin the constants US-1711's
//! transcript chose.

use std::cell::RefCell;
use std::collections::BTreeMap;

use fapico2_platform::custody::{
    assess, burn, custody_secret_bytes, custody_words, CeremonyError, CeremonyState,
    FIRST_SECRET_ROW, LOCK_ROW, LOCK_WORD, MARKER_ROW, MARKER_WORD, SECRET_WORDS,
};
use fapico2_platform::otp_cus::{classify_row, OtpAccess, OtpError, RowClass};

const ECC_META: u32 = 0x5500_0000; // a burned word's ECC metadata, in the raw view
const ALL_SECRET_ROWS_END: usize = FIRST_SECRET_ROW + SECRET_WORDS;

/// Rows are `(raw, ecc)`; a raw of `0` is the erased mark (US-1711's
/// measured truth). `write_bias` is XORed into every write — `0` is the
/// faithful silicon, non-zero models hardware that sticks something other
/// than what was asked (the verify-mismatch vector).
struct Fixture {
    rows: RefCell<BTreeMap<usize, (u32, u16)>>,
    write_bias: u16,
    writes: RefCell<Vec<(usize, u16)>>,
}

impl Fixture {
    fn virgin() -> Self {
        Fixture {
            rows: RefCell::new(BTreeMap::new()),
            write_bias: 0,
            writes: RefCell::new(Vec::new()),
        }
    }

    /// Pre-burn rows as if a prior torn run had filled them in order.
    fn torn_prefix(words: &[u16]) -> Self {
        let fx = Fixture::virgin();
        for (i, w) in words.iter().enumerate() {
            fx.rows
                .borrow_mut()
                .insert(FIRST_SECRET_ROW + i, (ECC_META | *w as u32, *w));
        }
        fx
    }

    fn burn_row(&self, row: usize, word: u16) {
        self.rows
            .borrow_mut()
            .insert(row, (ECC_META | word as u32, word));
    }

    fn writes(&self) -> Vec<(usize, u16)> {
        self.writes.borrow().clone()
    }
}

impl OtpAccess for Fixture {
    fn raw_word(&self, row: usize) -> Result<u32, OtpError> {
        match self.rows.borrow().get(&row) {
            Some((raw, _)) => Ok(*raw),
            None => Ok(0), // erased: zero bytes
        }
    }
    fn ecc_word(&self, row: usize) -> Result<u16, OtpError> {
        match self.rows.borrow().get(&row) {
            Some((_, ecc)) => Ok(*ecc),
            None => Ok(0), // the erased row's ECC view answers 0, no error
        }
    }
    fn write_ecc_word(&self, row: usize, data: u16) -> Result<(), OtpError> {
        self.writes.borrow_mut().push((row, data));
        let stuck = data ^ self.write_bias;
        self.rows.borrow_mut().insert(row, (ECC_META | stuck as u32, stuck));
        Ok(())
    }
}

/// A rolling entropy source; `take` records the words it handed out.
struct Entropy(u16);

impl Entropy {
    fn take(&mut self) -> u16 {
        self.0 += 1;
        self.0 - 1
    }
}

#[test]
fn virgin_burn_reaches_complete_in_order() {
    let fx = Fixture::virgin();
    let mut ent = Entropy(0x4000);
    let state = burn(&fx, || ent.take()).expect("virgin page burns");
    assert_eq!(state, CeremonyState::Complete);
    // The words were written in page order, then the lock, then the marker —
    // the marker-last order the story pins.
    let touched: Vec<usize> = fx.writes().iter().map(|(r, _)| *r).collect();
    let expected: Vec<usize> = (FIRST_SECRET_ROW..ALL_SECRET_ROWS_END)
        .chain([LOCK_ROW, MARKER_ROW])
        .collect();
    assert_eq!(touched, expected);
    // And it is idempotent: a second burn writes nothing.
    let before = fx.writes().len();
    assert_eq!(burn(&fx, || 0xDEAD).unwrap(), CeremonyState::Complete);
    assert_eq!(fx.writes().len(), before);
}

#[test]
fn torn_burn_resumes_without_rewriting() {
    // A prior run filled words 0..3 and died. The resume keeps those values
    // (they are ours by construction) and refills only erased-class rows.
    let fx = Fixture::torn_prefix(&[0x1111, 0x2222, 0x3333]);
    let mut ent = Entropy(0x4000);
    let state = burn(&fx, || ent.take()).expect("torn page resumes");
    assert_eq!(state, CeremonyState::Complete);
    // Not one write landed on the pre-burned rows.
    let touched: Vec<usize> = fx.writes().iter().map(|(r, _)| *r).collect();
    let expected: Vec<usize> = (FIRST_SECRET_ROW + 3..ALL_SECRET_ROWS_END)
        .chain([LOCK_ROW, MARKER_ROW])
        .collect();
    assert_eq!(touched, expected);
    // The secret is the read-back whole: pre-burned words first, fresh
    // entropy after.
    assert_eq!(
        custody_words(&fx).unwrap(),
        [0x1111, 0x2222, 0x3333, 0x4000, 0x4001, 0x4002, 0x4003, 0x4004]
    );
}

#[test]
fn verify_mismatch_aborts_with_no_marker() {
    // Hardware that sticks the word with one bit flipped: the read-back is
    // neither the value written nor erased — the abort, with no marker.
    let mut fx = Fixture::virgin();
    fx.write_bias = 0x0001;
    let mut ent = Entropy(0x4000);
    let err = burn(&fx, || ent.take()).expect_err("mismatched read-back aborts");
    assert_eq!(err, CeremonyError::Mismatch(FIRST_SECRET_ROW));
    // The brick vector is spent on nothing: the lock and marker rows never
    // saw a write, and the marker still classifies erased.
    assert!(!fx.writes().iter().any(|(r, _)| *r == LOCK_ROW));
    assert!(!fx.writes().iter().any(|(r, _)| *r == MARKER_ROW));
    assert_eq!(classify_row(&fx, MARKER_ROW), RowClass::Erased);
    assert_eq!(assess(&fx), CeremonyState::Torn);
}

#[test]
fn derivation_uses_readback_contents() {
    // The pre-burned words were never an "intended" value of this run — the
    // entropy source never produced them — yet the derived secret carries
    // them, because the derivation input is what the rows read back.
    let fx = Fixture::torn_prefix(&[0x1111, 0x2222, 0x3333]);
    let mut ent = Entropy(0x4000);
    burn(&fx, || ent.take()).expect("burns to completion");
    let bytes = custody_secret_bytes(&fx).unwrap();
    assert_eq!(&bytes[..6], &[0x11, 0x11, 0x22, 0x22, 0x33, 0x33]);
    // The fresh words are in there too, big-endian per word.
    assert_eq!(&bytes[6..10], &[0x40, 0x00, 0x40, 0x01]);
}

#[test]
fn burned_and_locked_is_sealed_not_complete() {
    // All words valid, the lock burned, the marker absent: burned+locked is
    // distinguishable from complete, and the next run writes only the
    // marker.
    let fx = Fixture::torn_prefix(&[
        0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
    ]);
    fx.burn_row(LOCK_ROW, LOCK_WORD);
    assert_eq!(assess(&fx), CeremonyState::Sealed);
    let state = burn(&fx, || 0xDEAD).expect("sealed page completes");
    assert_eq!(state, CeremonyState::Complete);
    assert_eq!(fx.writes(), vec![(MARKER_ROW, MARKER_WORD)]);
}

#[test]
fn irregular_pages_are_never_burned() {
    // A hole in the valid prefix: the ceremony fills in order, so a valid
    // word with an erased word *before* it is not ours.
    let hole = Fixture::virgin();
    hole.burn_row(FIRST_SECRET_ROW, 0x1111);
    hole.burn_row(FIRST_SECRET_ROW + 2, 0x3333);
    assert_eq!(assess(&hole), CeremonyState::Abort);
    assert_eq!(burn(&hole, || 0).unwrap_err(), CeremonyError::Irregular);

    // A faulted secret row (raw view disagrees with the ECC view) aborts.
    let faulted = Fixture::virgin();
    faulted.burn_row(FIRST_SECRET_ROW, 0xBEEF);
    faulted.burn_row(FIRST_SECRET_ROW + 1, 0xDEAD);
    // raw disagrees with the ECC view on row 1: uncorrectable, Faulted.
    faulted
        .rows
        .borrow_mut()
        .insert(FIRST_SECRET_ROW + 1, (ECC_META | 0xBEE0, 0xBEEF));
    assert_eq!(assess(&faulted), CeremonyState::Abort);

    // A foreign lock word aborts — the page was locked by someone else's
    // config, and nothing of ours goes onto it.
    let foreign_lock = Fixture::torn_prefix(&[
        0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
    ]);
    foreign_lock.burn_row(LOCK_ROW, 0x1234);
    assert_eq!(assess(&foreign_lock), CeremonyState::Abort);
    assert_eq!(
        burn(&foreign_lock, || 0).unwrap_err(),
        CeremonyError::Irregular
    );

    // A foreign marker aborts: the marker written last means a marker we
    // did not write is a state the flow cannot produce.
    let foreign_marker = Fixture::torn_prefix(&[
        0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
    ]);
    foreign_marker.burn_row(LOCK_ROW, LOCK_WORD);
    foreign_marker.burn_row(MARKER_ROW, 0x99);
    assert_eq!(assess(&foreign_marker), CeremonyState::Abort);
}

#[test]
fn refill_requires_consistent_erased_reads() {
    // The row must read back erased REFILL_ERASED_READS times before a
    // refill word is spent on it. This fixture's row reads erased for its
    // first four ECC accesses and faults afterwards: one read inside
    // `assess`, then the refill's own classify and two consistent reads —
    // the third consistent read faults, so no word is ever written.
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    struct Flaky(RefCell<BTreeMap<usize, usize>>);
    impl OtpAccess for Flaky {
        fn raw_word(&self, _row: usize) -> Result<u32, OtpError> {
            Ok(0)
        }
        fn ecc_word(&self, row: usize) -> Result<u16, OtpError> {
            let mut map = self.0.borrow_mut();
            let n = map.entry(row).or_insert(0);
            *n += 1;
            if *n > 4 {
                Err(OtpError::Bus(-9))
            } else {
                Ok(0)
            }
        }
        fn write_ecc_word(&self, _row: usize, _data: u16) -> Result<(), OtpError> {
            Ok(())
        }
    }
    let flaky = Flaky(RefCell::new(BTreeMap::new()));
    let err = burn(&flaky, || 0x4000).expect_err("an inconsistent row is not refillable");
    assert_eq!(err, CeremonyError::NotErased(FIRST_SECRET_ROW));
}
