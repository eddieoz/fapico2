//! Tests for CBOR decoder robustness (FX-403).

use fapico2_fido::cbor::{decode, encode, Value};

#[test]
fn test_bstr_length_overflow_is_error() {
    // 9-byte header claiming a bstr of 2^64-1 bytes; only 5 bytes follow.
    // start + len must not overflow usize (debug panic) or truncate (32-bit).
    let mut bytes = vec![0x5B]; // major 2, minor 27 (u64 length)
    bytes.extend_from_slice(&u64::MAX.to_be_bytes());
    bytes.extend_from_slice(&[0xAA; 5]);
    assert!(decode(&bytes).is_err());
}

#[test]
fn test_tstr_length_overflow_is_error() {
    // tstr header claiming 2^32 bytes (u32 length, would truncate on 32-bit).
    let mut bytes = vec![0x7A]; // major 3, minor 26 (u32 length)
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    bytes.extend_from_slice(&[0x41; 5]);
    assert!(decode(&bytes).is_err());
}

#[test]
fn test_tstr_invalid_utf8_is_error() {
    // tstr of 2 bytes containing invalid UTF-8 (0xFF 0xFE).
    let bytes = vec![0x62, 0xFF, 0xFE];
    let err = decode(&bytes).expect_err("invalid UTF-8 must be rejected");
    let _ = err; // any error variant is fine; lossy replacement is not
}

#[test]
fn test_map_key_u64_max_roundtrip() {
    let v = Value::M(vec![(Value::U(u64::MAX), Value::U(1)), (Value::U(0), Value::U(2))]);
    let bytes = encode(&v);
    let (decoded, used) = decode(&bytes).expect("u64::MAX key must round-trip");
    assert_eq!(used, bytes.len());
    match decoded {
        Value::M(pairs) => {
            // Canonical ordering: U(0) encodes shorter, so it sorts first.
            assert_eq!(pairs[0].0, Value::U(0));
            assert_eq!(pairs[1].0, Value::U(u64::MAX));
        }
        other => panic!("expected map, got {:?}", other),
    }
}

#[test]
fn test_neg_int_u64_max_is_i64_min() {
    let bytes = [0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let (v, _) = decode(&bytes).expect("negative u64::MAX must decode");
    assert_eq!(v, Value::N(i64::MIN));
}

#[test]
fn test_bstr_exact_length_ok() {
    let bytes = vec![0x45, 1, 2, 3, 4, 5];
    let (v, used) = decode(&bytes).expect("exact-length bstr must decode");
    assert_eq!(v, Value::B(vec![1, 2, 3, 4, 5]));
    assert_eq!(used, bytes.len());
}

#[test]
fn test_truncated_bstr_is_error() {
    let bytes = vec![0x45, 1, 2, 3];
    assert!(decode(&bytes).is_err());
}
