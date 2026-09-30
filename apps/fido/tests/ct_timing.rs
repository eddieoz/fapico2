//! US-703 TDD: the pinHash comparison must be constant-time (XOR-accumulate),
//! never an early-return `==`. Timing itself is not measurable in CI, so the
//! verification sites are refactored onto a shared, public helper
//! `crypto::ct_eq` and that helper's behavior is pinned here over equal and
//! unequal inputs of various lengths (including zero-length).

use fapico2_fido::crypto::ct_eq;

#[test]
fn pin_hash_compare_is_constant_time() {
    // Zero-length inputs are equal (the XOR accumulator starts at 0).
    assert!(ct_eq(&[], &[]));

    // pinHash-sized (16-byte) values: equal and single-byte differences.
    let mut other = [0x42u8; 16];
    assert!(ct_eq(&[0x42; 16], &[0x42; 16]));
    other[7] = 0x43;
    assert!(!ct_eq(&[0x42; 16], &other));

    // pinUvAuthParam-sized (32-byte) values: equal and trailing-byte diff.
    let mut tail = [0u8; 32];
    tail[31] = 1;
    assert!(ct_eq(&[0u8; 32], &[0u8; 32]));
    assert!(!ct_eq(&[0u8; 32], &tail));

    // Every-byte and first-byte differences are both unequal.
    assert!(!ct_eq(&[0xFF; 16], &[0x00; 16]));
    assert!(!ct_eq(&[0x01, 0x02, 0x03], &[0x01, 0x02, 0x04]));

    // Unequal lengths are never equal, in either direction.
    assert!(!ct_eq(&[0u8; 16], &[0u8; 17]));
    assert!(!ct_eq(&[0u8; 17], &[0u8; 16]));
    assert!(!ct_eq(&[1, 2, 3], &[1, 2]));

    // ct_eq must be length-agnostic (slice inputs), not fixed to one width.
    let mut a = [7u8; 5];
    let mut b = [7u8; 5];
    assert!(ct_eq(&a, &b));
    b[0] ^= 0x80;
    assert!(!ct_eq(&a, &b));
    a[4] ^= 0x01;
    assert!(!ct_eq(&a, &b));
}
