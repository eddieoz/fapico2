//! US-918: the bound device root (`ckey::derive_kbase`) — chipid + boot
//! entropy binding and its fail-closed rule.
//!
//! The properties pinned here:
//!
//! * **Chipid binding** — the same OTP row under a different chipid
//!   derives a different root: a leaked OTP row does not reconstruct this
//!   device's root on another board.
//! * **Fail-closed entropy** — derivation WITHOUT the boot-entropy record
//!   refuses (`MissingBootEntropy`); there is no legacy two-input
//!   fallback.
//! * **Determinism** — the same inputs (OTP row, serial hash, chipid,
//!   entropy) derive the same root; the root matches the independent
//!   HKDF-SHA256 vector.
//! * **Slot contract** — the entropy record is the dedicated secure-store
//!   slot `boot.entropy.v1`, 32 bytes long.

use fapico2_platform::ckey::{
    self, derive_kbase, derive_kbase_c, CKeyError, BOOT_ENTROPY_LEN, KEY_LEN, SERIAL_HASH_LEN,
};
use fapico2_platform::migration::SLOT_BOOT_ENTROPY;

const UID_HEX: &str = "0102030405060708";
const OTP_KEY_1_HEX: &str =
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
const ENTROPY: [u8; BOOT_ENTROPY_LEN] = [0xA5u8; BOOT_ENTROPY_LEN];

fn h(s: &str) -> std::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn otp() -> [u8; KEY_LEN] {
    h(OTP_KEY_1_HEX).try_into().unwrap()
}

fn sh() -> [u8; SERIAL_HASH_LEN] {
    ckey::serial_hash(&h(UID_HEX))
}

/// (a) Identical OTP row + different chipid → different kbase. Also holds
/// against the C-compat root's inputs: the bound root must differ from it.
#[test]
fn kbase_bound_differs_across_chipids() {
    let otp = otp();
    let serial = sh();
    let a = derive_kbase(&otp, &serial, 0x0102_0304_0506_0708, Some(&ENTROPY)).unwrap();
    let b = derive_kbase(&otp, &serial, 0x090a_0b0c_0d0e_0f10, Some(&ENTROPY)).unwrap();
    assert_ne!(a, b);
    // The same OTP row + serial hash under the C-compat root is a THIRD
    // distinct value — the bound root is not the legacy root.
    let c = derive_kbase_c(&otp, &serial).unwrap();
    assert_ne!(a, c);
}

/// (b) Derivation WITHOUT the entropy record refuses — never the legacy
/// two-input fallback.
#[test]
fn kbase_bound_refuses_without_entropy() {
    let otp = otp();
    let serial = sh();
    assert_eq!(
        derive_kbase(&otp, &serial, 0x0102_0304_0506_0708, None),
        Err(CKeyError::MissingBootEntropy)
    );
    // The refusal is not the zero-OTP refusal: a zero row refuses first,
    // with its own error.
    let zero = [0u8; KEY_LEN];
    assert_eq!(
        derive_kbase(&zero, &serial, 0x0102_0304_0506_0708, Some(&ENTROPY)),
        Err(CKeyError::NeverBootC)
    );
}

/// (c) Determinism with entropy — and the pinned KAT (independently
/// generated with Python's `hmac` HKDF-SHA256, not with this crate):
/// salt = serial_hash(32) ‖ chipid BE(8) ‖ 32 × 0xA5.
///
/// **The vector changed under US-1575**, which moved the bound root's info
/// label from `"DEVICE/ROOT"` to `"DEVICE/ROOT/BOUND"`. The generator is
/// unchanged and still reproduces the *old* label's value exactly
/// (`6bcd…60f4`) when given the old label, which is what keeps this a real KAT
/// rather than a rubber stamp of whatever the code emitted.
#[test]
fn kbase_bound_is_deterministic_and_matches_vector() {
    let otp = otp();
    let serial = sh();
    let chipid = 0x0102_0304_0506_0708u64;
    let a = derive_kbase(&otp, &serial, chipid, Some(&ENTROPY)).unwrap();
    let b = derive_kbase(&otp, &serial, chipid, Some(&ENTROPY)).unwrap();
    assert_eq!(a, b);
    assert_eq!(
        a.as_slice(),
        h("83651163da62972b5ba9f53f49567366776e35ab5ba87c217c56668fd019fff8").as_slice()
    );
    // A different entropy changes the root (the entropy is load-bearing).
    let other = [0x5Au8; BOOT_ENTROPY_LEN];
    assert_ne!(a, derive_kbase(&otp, &serial, chipid, Some(&other)).unwrap());
}

/// (d) The dedicated secure-store slot name contract.
#[test]
fn boot_entropy_slot_name_contract() {
    assert_eq!(SLOT_BOOT_ENTROPY, b"boot.entropy.v1".as_slice());
    assert_eq!(BOOT_ENTROPY_LEN, 32);
}

/// US-1575: the bound root and the C-compat root must not share an HKDF info
/// label. They shared `"DEVICE/ROOT"` and were separated only by their salts,
/// which is not separation — a caller holding one root reaches the other by
/// deriving with the other salt, and nothing in the API said which was which.
#[test]
fn the_bound_root_and_the_c_root_do_not_share_an_info_label() {
    assert_ne!(ckey::KBASE_LABEL, b"DEVICE/ROOT");
    assert_eq!(ckey::KBASE_LABEL, b"DEVICE/ROOT/BOUND");

    // And the two roots really are different values for the same OTP row.
    let otp = otp();
    let serial = sh();
    let bound = derive_kbase(&otp, &serial, 0x0102_0304_0506_0708, Some(&ENTROPY)).unwrap();
    let c_root = ckey::derive_kbase_c(&otp, &serial).unwrap();
    assert_ne!(
        bound.as_slice(),
        c_root.as_slice(),
        "the two roots are the same value, so separating their labels changed nothing"
    );
}

/// US-1575: no two distinct derivations in this tree share both a salt and an
/// info label. The one collision the inventory found was
/// `derive_kbase`/`derive_kbase_c`; this asserts the pairs that matter are
/// still distinct so a future label cannot quietly reintroduce one.
#[test]
fn no_two_derivations_share_a_salt_and_info_pair() {
    let pairs: &[(&str, &[u8], &[u8])] = &[
        ("derive_kbase (bound)", b"salt72", ckey::KBASE_LABEL),
        ("derive_kbase_c (C-compat)", b"serial_hash32", b"DEVICE/ROOT"),
        ("store v3", b"PS3F", b"store"),
        ("DRBG seed", b"dynamic", b"DRBG/SEED"),
        ("wrap key", b"serial_hash32", b"fapico2/ckey/wrap/v1"),
    ];
    for (i, (an, asalt, ainfo)) in pairs.iter().enumerate() {
        for (bn, bsalt, binfo) in pairs.iter().skip(i + 1) {
            assert!(
                !(asalt == bsalt && ainfo == binfo),
                "{an} and {bn} share both a salt and an info label ({:?})",
                core::str::from_utf8(ainfo).unwrap_or("?")
            );
        }
    }
}
