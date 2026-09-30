//! US-1005 — the two `device_random` draws must **fail**, not fill with zeros.
//!
//! # What this file is for
//!
//! D-9 predicted one symptom and observed another, and the review that
//! followed established that *both* are real, depending on the caller shape:
//!
//! * A **rejection sampler** (`p256::SecretKey::random`, `try_fill_valid`)
//!   loops forever on a starved generator. The US-1007 work bounded and
//!   made that path fallible; `apps/fido/tests/keygen_bounded.rs` covers it.
//! * A **plain draw into a zero-initialised buffer** does not loop — it
//!   installs the zeros. That was `DeviceKeystore::fresh` and
//!   `DeviceKeystore::reset`, and the only guard on them was a
//!   `debug_assert!` inside `DrbgTrng::random_bytes`, which is compiled out
//!   of the release profile (`debug-assertions = false`, root
//!   `Cargo.toml`). On a shipped device the guard was absent.
//!
//! The second case is the worse of the two, because it is silent *and* it
//! lands on a long-lived secret. `device_random` is the HKDF `ikm` behind
//! `stateless::master_from_device_random` — the per-device U2F master. All
//! zeros there is not a stale value, it is a **constant**, so every U2F
//! key handle the token ever issued becomes computable by anyone who knows
//! the input.
//!
//! # What each test proves
//!
//! Each test below is written so that **reverting the fix makes it fail**.
//! That is the point: a test that stays green against the old code proves
//! nothing about the old code.

use fapico2_fido::device_keystore::DeviceKeystore;
use fapico2_platform::trng::{Trng, TrngError};

/// A `Trng` whose `try_random_bytes` always refuses, and whose
/// `random_bytes` — the infallible half — is the US-1007 behaviour: leave
/// the caller's buffer exactly as it was and say nothing.
///
/// This is the shape that produced the defect. The buffer starts as
/// `[0u8; 32]`, so "left exactly as it was" is indistinguishable from "filled
/// with zeros" unless a caller *checks*, which is the whole point of the
/// fix.
struct Starved;

impl Trng for Starved {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        // Deliberately silent, exactly as `DrbgTrng::random_bytes` is on a
        // release build: the buffer is not touched.
        let _ = buf;
    }

    fn try_random_bytes(&mut self, _buf: &mut [u8]) -> Result<(), TrngError> {
        Err(TrngError::Stalled)
    }
}

/// A `Trng` that works, so the "refusal is the only thing that changed"
/// control tests have something to contrast against.
struct Healthy(u8);

impl Trng for Healthy {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        buf.fill(self.0);
    }

    fn try_random_bytes(&mut self, buf: &mut [u8]) -> Result<(), TrngError> {
        self.random_bytes(buf);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The symptom itself, stated rather than assumed
// ---------------------------------------------------------------------------

/// D-9's amendment rests on an argument: "a plain draw into a
/// zero-initialised buffer yields all zeros on a starved generator." This is
/// the evidence for it, and it tests the **seam** rather than
/// `DeviceKeystore`, so it stays true if the keystore's draw path is
/// refactored again.
///
/// The sampler half of the amendment is deliberately *not* simulated here: it
/// is a loop, and a test that waits for a loop in order to prove it does not
/// finish is a test that hangs the suite. That case is covered where it can
/// terminate — `apps/fido/tests/keygen_bounded.rs`, by capping the attempts.
#[test]
fn a_starved_infallible_draw_into_a_zeroed_buffer_is_all_zeros() {
    // Exactly the construction the two `device_random` sites used: declare
    // zeroed, then ask the infallible half of the seam.
    let mut buffer = [0u8; 32];
    let mut trng = Starved;
    trng.random_bytes(&mut buffer);

    assert!(
        buffer.iter().all(|&b| b == 0),
        "this is D-9 item (1): a refused infallible draw into a zeroed buffer \
         leaves 32 zero bytes, with no error anywhere. If this assertion ever \
         fails, the seam's contract has changed and the D-9 amendment needs \
         re-deriving."
    );
}

/// And the reason that constant matters rather than merely being wrong: it is
/// the input to a KDF, so all-zero in is all-equal out across *every* device
/// that hit the bug, not merely predictable within one.
#[test]
fn an_all_zero_device_random_is_identical_on_every_device_that_hit_it() {
    // Two independent "devices", each drawing from its own generator that
    // both happen to be starved.
    let mut first = [0u8; 32];
    let mut t1 = Starved;
    t1.random_bytes(&mut first);

    let mut second = [0u8; 32];
    let mut t2 = Starved;
    t2.random_bytes(&mut second);

    assert_eq!(
        first, second,
        "two independent generators produced the same 'random' device secret. \
         That is the shape of a per-device key that is not per-device."
    );
}

// ---------------------------------------------------------------------------
// DeviceKeystore::fresh
// ---------------------------------------------------------------------------

/// **The test that would have caught this.** Before the fix,
/// `DeviceKeystore::fresh(&mut Starved)` returned `Ok`-shaped `Self` and the
/// keystore carried 32 zero bytes as its per-device secret.
#[test]
fn a_starved_generator_does_not_produce_a_fresh_keystore() {
    let mut trng = Starved;
    let err = DeviceKeystore::fresh(&mut trng).expect_err(
        "a refused draw must NOT yield a keystore: its device_random would be \
         32 zero bytes, and that value is the HKDF ikm for the device's U2F master",
    );
    assert_eq!(err, TrngError::Stalled);
}

/// Control: the control flow is unchanged on the healthy path — this is a
/// fallibility change, not a behaviour change.
#[test]
fn a_healthy_generator_still_produces_a_fresh_keystore() {
    let mut trng = Healthy(0xA5);
    let ks = DeviceKeystore::fresh(&mut trng).expect("a working generator is not a refusal");
    assert!(
        ks.device_random().iter().all(|&b| b == 0xA5),
        "the drawn bytes must reach device_random unchanged"
    );
}

// ---------------------------------------------------------------------------
// DeviceKeystore::reset
// ---------------------------------------------------------------------------

/// The reset arm has the extra weight that it **replaces** a good
/// `device_random` with the draw. A refusal that still wiped the table and
/// installed zeros would leave a device that looks factory-reset while every
/// U2F handle it ever issued is derivable.
#[test]
fn a_starved_reset_refuses_and_leaves_the_previous_secret_in_place() {
    let mut trng = Healthy(0x11);
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("healthy");

    let mut starved = Starved;
    let err = ks
        .reset(&mut starved)
        .expect_err("a refused draw must not be reported as a successful reset");
    assert_eq!(err, TrngError::Stalled);

    assert!(
        ks.device_random().iter().all(|&b| b == 0x11),
        "a refused reset must leave the previous device_random untouched — the \
         refusal is reported, not applied"
    );
}

/// Control: a healthy reset does install the new draw, so the test above is
/// pinning the refusal and not a no-op.
#[test]
fn a_healthy_reset_installs_the_new_draw() {
    let mut trng = Healthy(0x11);
    let mut ks = DeviceKeystore::fresh(&mut trng).expect("healthy");

    let mut healthy = Healthy(0x77);
    ks.reset(&mut healthy).expect("a working generator is not a refusal");

    assert!(
        ks.device_random().iter().all(|&b| b == 0x77),
        "a successful reset must actually install the new device_random"
    );
}
