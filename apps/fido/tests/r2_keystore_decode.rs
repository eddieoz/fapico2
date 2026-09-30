//! R2 diagnostic (RT-2 section 20.3): does the shipped fapico2 FIDO-keystore
//! decoder accept the bytes the firmware itself persists?
//!
//! Context (RT-2 section 22). A token that had been nuked, never had a FIDO
//! PIN re-set, and had an OATH credential added hangs at boot: solid LED, no
//! USB, no recovery by reflash. The boot path is
//! `DeviceKeystore::load` -> `from_cbor` -> `None` -> `Err(Corrupt)` ->
//! `fatal_boot("fido: keystore boot failed")` (`firmware/src/main.rs:143`).
//!
//! **Outcome: both decode.** The keystore decode is exonerated; the hang was
//! `fatal_boot("secure partition: OTP key row unavailable")` upstream of it.
//! `from_cbor` returning `None` — the path to that `fatal_boot` — was not
//! what was happening.
//!
//! # Why the fixtures are synthetic
//!
//! This test originally embedded two keystore snapshots lifted out of a real
//! device, together with the store key they had been sealed under. That made
//! the repository itself a copy of live key material: the snapshots carried a
//! real credential id, PIN salt and PIN verifier, and the key opened the real
//! secure store. It is a leak vector, and it was removed.
//!
//! The measurement the test exists for does not need a real device. What it
//! needs is the question "does `from_cbor` accept what `to_cbor` writes, with
//! and without a PIN set" — the shape the RT-2 hang turned on. So the fixtures
//! are now built here, at run time, from a fixed synthetic seed, and the test
//! still answers exactly that question.
//!
//! Run with:
//!   cargo test --target x86_64-unknown-linux-gnu -p fapico2-fido \
//!       --features host --test r2_keystore_decode -- --nocapture

use fapico2_fido::crypto;
use fapico2_fido::device_keystore::DeviceKeystore;
use heapless::Vec as HeaplessVec;

/// A fixed, obviously-synthetic store key. Test fixture, not a secret.
const KEY: [u8; 32] = [
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
];

/// A test PIN. A lab value for a synthetic keystore, not a credential.
const PIN: &str = "123456";

/// A keystore built from a fixed seed, with no PIN set — the shape the device
/// persisted after a nuke that left `pin_state` at its default.
fn without_pin() -> DeviceKeystore {
    let mut ks = DeviceKeystore::fresh(&mut FixedTrng).expect("synthetic TRNG cannot fail");
    ks.reset_from_seed([0x11; 32]);
    ks
}

/// The same, but with a PIN established, so the `pin_state` map entry the
/// decoder has to accept is actually present rather than default.
fn with_pin() -> DeviceKeystore {
    let mut ks = without_pin();
    ks.pin_state.pin_hash = Some(crypto::pin_hash(PIN.as_bytes()));
    ks
}

/// Deterministic TRNG so the test asserts on structure, not on entropy.
struct FixedTrng;

impl fapico2_platform::trng::Trng for FixedTrng {
    fn try_random_bytes(&mut self, dest: &mut [u8]) -> Result<(), fapico2_platform::trng::TrngError> {
        for (i, b) in dest.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        Ok(())
    }

    fn random_bytes(&mut self, dest: &mut [u8]) {
        for (i, b) in dest.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
    }
}

#[test]
fn both_persisted_shapes_decode() {
    let mut hang: HeaplessVec<u8, 1024> = HeaplessVec::new();
    without_pin()
        .to_cbor(Some(&KEY), &mut hang)
        .expect("a synthetic keystore must encode");
    let mut boots: HeaplessVec<u8, 1024> = HeaplessVec::new();
    with_pin()
        .to_cbor(Some(&KEY), &mut boots)
        .expect("a synthetic keystore with a PIN must encode");

    let hang_decoded = DeviceKeystore::from_cbor(&hang, Some(&KEY));
    let boots_decoded = DeviceKeystore::from_cbor(&boots, Some(&KEY));

    println!(
        "no-PIN snapshot ({} B) -> decoded: {}",
        hang.len(),
        hang_decoded.is_some()
    );
    println!(
        "PIN-set snapshot ({} B) -> decoded: {}",
        boots.len(),
        boots_decoded.is_some()
    );

    // A snapshot with a PIN set must decode. If this fails the fixtures are
    // wrong and nothing else in this test means anything.
    assert!(
        boots_decoded.is_some(),
        "a persisted snapshot with a PIN set must decode"
    );

    // R2 section 20.3: the boot-hang bisect cleared the FIDO keystore, and
    // this is the measurement that cleared it. The snapshot the firmware
    // itself persisted *without* a PIN also decodes cleanly, so `from_cbor`
    // returning `None` — the path to `fatal_boot("fido: keystore boot
    // failed")` at `firmware/src/main.rs:143` — is not what was happening.
    // The failure was `fatal_boot("secure partition: OTP key row
    // unavailable")` in `derive_boot_store_key`, reached before this code
    // ever runs.
    //
    // This assertion is deliberately the *opposite* of what the hypothesis
    // was when this test was written. It is kept because a regression here
    // would reintroduce a boot failure that is now known to have a different
    // cause, and because a test that documents an exoneration is worth more
    // than one that documents a suspicion.
    assert!(
        hang_decoded.is_some(),
        "a firmware-written snapshot without a PIN is now REFUSED - the FIDO \
         keystore decode has regressed, or the fixture is stale"
    );
}

#[test]
fn a_snapshot_sealed_under_another_key_is_refused() {
    // The counterpart to the exoneration above: the decoder must not accept
    // bytes it cannot authenticate. Without this, "both decode" would also be
    // satisfied by a decoder that accepts everything.
    let mut snap: HeaplessVec<u8, 1024> = HeaplessVec::new();
    without_pin()
        .to_cbor(Some(&KEY), &mut snap)
        .expect("a synthetic keystore must encode");

    let wrong_key = [0x00; 32];
    assert!(
        DeviceKeystore::from_cbor(&snap, Some(&wrong_key)).is_none(),
        "a snapshot sealed under a different key must be REFUSED"
    );
}
