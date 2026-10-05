//! US-1607 — the **device** build fails closed, proved rather than asserted.
//!
//! ```gherkin
//! Scenario: the device build cannot obtain a grant without a press
//!   When the device feature is enabled and no press source is wired
//!   Then reset answers the presence-required status
//! ```
//!
//! # Why this is here and not in `apps/fido/tests/`
//!
//! The property is a **build-configuration** property: `device_core`'s
//! `default_user_present()` has two arms, `false` under `#[cfg(feature =
//! "device")]` and `true` otherwise, and only the first is the one shipping.
//! Every test in `apps/fido/tests/` runs under that crate's `host` default, so
//! it can only ever see the auto-ack arm — and an auto-acking test suite is
//! exactly what must not be allowed to certify a device build as fail-closed.
//!
//! This module is reachable because `cargo test -p fapico2-firmware --lib
//! --features device,emulation` turns on **both** `fapico2-fido/device` and
//! `fapico2-fido/host` (`firmware/Cargo.toml`'s feature lists). `device_core`'s
//! `cfg(feature = "device")` arm therefore resolves to `false` *inside a host
//! test binary*, which is the only way to run this assertion without hardware.
//!
//! **That dual-feature build is load-bearing and is asserted below**, so this
//! test cannot quietly start passing for the wrong reason — which is the
//! failure mode of a test whose subject is a `cfg`.
//!
//! # What it is guarding
//!
//! US-1602 put a presence gate on CTAP2 `authenticatorReset`. A gate is only
//! worth what its default is worth: a gate that auto-acks when no button is
//! wired destroys the device on an unauthenticated frame, exactly as it did
//! before. This is the assertion that the default is `false` on the build that
//! ships.
//!
//! Note the asymmetry the whole epic rests on (`AGENTS.md` §4): **host and
//! emulation auto-ack on purpose** — roughly ten python suites call
//! `device.reset()` against the emulator — so this test deliberately does not
//! touch the host arm, and deliberately does not try to make the two agree.
//! They are not supposed to.

use super::TEST_LOCK;

use fapico2_fido::ctap2::Ctap2Response;
use fapico2_fido::FidoApp;
use fapico2_platform::secure_store::HostSecureStore;
use fapico2_platform::trng::HostTrng;
use heapless::Vec as HeaplessVec;

/// `CTAP2_ERR_UP_REQUIRED` — read from `fapico2_fido::ctap2`, **not** written
/// as a literal, because this test's subject is the gate's behaviour and a
/// hand-copied byte would let a status-table regression hide behind it.
fn up_required() -> u8 {
    Ctap2Response::UpRequired.code()
}

/// The precondition the whole module rests on.
///
/// Asserted rather than assumed, because a test that stops testing for the
/// reason it was written is worse than no test: if this ever reads `false`,
/// every assertion below is measuring the host auto-ack arm and passing for
/// the wrong reason — which is precisely the confusion this module exists to
/// rule out.
#[test]
fn this_binary_really_has_the_device_feature_on() {
    let _g = TEST_LOCK.lock().unwrap();

    // Booted with NO presence source at all, so the answer comes from the
    // build default and nothing else. On the host arm that is `true` and the
    // reset succeeds; here it must not.
    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot the device twin");
    let mut out = HeaplessVec::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_ctap2(0x07, &[], [1, 2, 3, 4], &mut out);

    assert_eq!(
        out[..n][0],
        up_required(),
        "a device-featured build with no presence source must NOT be able to obtain a grant. \
         It answered {:#04x} — the `#[cfg(not(feature = \"device\"))]` arm of \
         `device_core::default_user_present` is in force here, which means this test binary is \
         not the device build it claims to be and every assertion in this module is vacuous.",
        out[..n][0],
    );
}

/// **An `authenticatorReset` on the shipping build asks for a touch.**
///
/// The end-to-end statement of the same property, in the shape a reader cares
/// about: the command a red-team frame carries, on the build a board runs,
/// with no button wired, answers `UP_REQUIRED` and erases nothing.
#[test]
fn reset_on_the_device_build_is_refused_without_a_press_source() {
    let _g = TEST_LOCK.lock().unwrap();

    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store).expect("boot the device twin");

    let mut out = HeaplessVec::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_ctap2(0x07, &[], [1, 2, 3, 4], &mut out);
    let status = out[..n][0];

    assert_eq!(
        status,
        up_required(),
        "red-team F1, restated for the build that ships: opcode 0x07 with an empty body and no \
         pinUvAuthToken must not destroy the device. It answered {status:#04x}.",
    );

    // And the store is untouched — a refusal that had already wiped the
    // records would report the same status byte while lying about state that
    // is gone (this epic's constraint 4).
    let snapshot =
        fapico2_fido::device_keystore::DeviceKeystore::load(&mut store).expect("a readable store");
    assert!(
        snapshot.is_some(),
        "the refused reset must leave the durable snapshot in place",
    );
}

/// **The gate is the reason, not the build default leaking elsewhere.**
///
/// A reset that answers `UP_REQUIRED` for an unrelated reason would satisfy the
/// test above while leaving F1 wide open, so this one pins the mechanism: the
/// *same* binary, with a granting source attached, must be able to reset. The
/// two together say the gate consults a source, and that the source's default
/// on this build is `false` — rather than that `0x07` is simply broken here.
#[test]
fn the_same_binary_resets_once_a_press_source_is_wired() {
    let _g = TEST_LOCK.lock().unwrap();

    fn pressed(_tag: u32) -> bool {
        true
    }

    let mut trng = HostTrng::new();
    let mut store = HostSecureStore::new();
    let mut app = FidoApp::boot(&mut trng, &mut store)
        .expect("boot the device twin")
        .with_presence_grant(pressed);

    let mut out = HeaplessVec::<u8, { fapico2_fido::CTAP2_MAX_MSG }>::new();
    let n = app.process_ctap2(0x07, &[], [1, 2, 3, 4], &mut out);

    assert_eq!(
        out[..n][0],
        Ctap2Response::Ok.code(),
        "with a granting presence source attached, reset must succeed in this same binary. If \
         this fails, the refusal above is the command being broken rather than the gate doing \
         its job — and both readings would leave the epic's claim unproven.",
    );
}