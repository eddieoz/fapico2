//! US-104 (PICOForge-COMPAT) — the management capability word must mirror the
//! registered AID set.
//!
//! The management applet answers `READ_CONFIG` with a capability bitmask that
//! the host reads as "which applets are compiled in". That word and
//! `fapico2_apps::registry::CCID_AIDS` are maintained in two different crates
//! (`fapico2-mgmt` and `fapico2-apps`, and `apps` *depends on* `mgmt`, never the
//! reverse — a `const _: () = assert!(…)` in `mgmt` cannot see the registry and a
//! new dependency would be a cycle), so nothing but a test that imports *both*
//! can hold them together. That is why this test lives in `apps/tests/` and not
//! in the EPIC's nominal `apps/mgmt/tests/caps.rs`: `apps/mgmt` physically
//! cannot reach `CCID_AIDS`.
//!
//! The invariant under test, in both directions:
//!
//! * every AID in `CCID_AIDS` has an entry in [`AID_CAP_BITS`] — adding a
//!   sixth registered app without pairing it here fails;
//! * every capability bit **set** in `caps()` belongs to a registered AID (or
//!   to the HID transport, which is not AID-dispatched) — re-adding
//!   [`CAP_PIV`] while PIV is unregistered fails here.
//!
//! An entry's bit may be **0**, and that is a statement, not a gap: it means
//! the applet is deliberately *not* advertised through the capability word.
//! Three applets take that slot, for three different reasons:
//!
//! * `AID_MANAGEMENT` — it is the applet *doing* the reporting.
//! * `AID_VENDOR_LED` (US-160, PICOForge-COMPAT) — the client defines exactly
//!   six `USB_CAP_*` bits (`picoforge/src/hal/rescue/constants.rs:718-733`) and
//!   none of them names the LED applet. Advertising a seventh bit the client
//!   does not decode would be inventing protocol, and `write_management_config`
//!   echoes whatever mask it is handed into `USB_ENABLED`
//!   (`ops.rs:880-900`) — so a fabricated bit would be a host-settable bit with
//!   no meaning behind it. The LED applet is reachable by SELECT, not by a
//!   management toggle, and that is the honest shape of it.
//! * `AID_RESCUE` (US-161/162/163, PICOForge-COMPAT Phase H) — the same six
//!   `USB_CAP_*` bits apply and none of them names the Rescue applet either,
//!   for the same reason. A Rescue screen that is **off by default** and
//!   revealed by an explicit operator action is the intended shape: the applet
//!   is unauthenticated (threat model §1), so the capability word must not be
//!   what turns it on. It is reachable by SELECT, which is how the client
//!   reaches it.
//!
//! Device-vs-emulation. The device path registers six apps
//! (`register_ccid_apps`) and must not advertise PIV. The host emulation binary
//! registers **seven**, `PivApp` included (`firmware/src/emul_main.rs`), so it
//! *does* advertise it. `caps()` is shared by both, so the PIV bit is behind
//! the `piv` Cargo feature: on by default nowhere, enabled by the firmware's
//! `emulation` feature only. This test is built with the `apps` default
//! features (PIV off), i.e. it asserts the **device** word. Run it with
//! `cargo test -p fapico2-apps --features piv` to assert the emulation word.

use fapico2_apps::registry::{
    AID_MANAGEMENT, AID_OATH, AID_OPENPGP, AID_OTP, AID_RESCUE, AID_VENDOR_LED, CCID_AIDS,
};
use fapico2_mgmt::{caps, CAP_FIDO2, CAP_OATH, CAP_OPENPGP, CAP_OTP, CAP_PIV, CAP_U2F};

/// Every AID the device registers behind the CCID dispatcher, paired with the
/// **one** capability bit that advertises it to the host — or `0` when it is
/// deliberately unadvertised (see the module docs).
///
/// The bits are imported from `fapico2_mgmt` rather than re-spelled as literals,
/// so this map cannot drift from the constants `caps()` builds its word from.
const AID_CAP_BITS: [(&[u8], u16); 6] = [
    (AID_MANAGEMENT, 0),
    (AID_OATH, CAP_OATH),
    (AID_OTP, CAP_OTP),
    (AID_OPENPGP, CAP_OPENPGP),
    // No `CAP_VENDOR_LED`: the client decodes no such bit.
    (AID_VENDOR_LED, 0),
    // No `CAP_RESCUE` either, for the same reason — and additionally because
    // this applet is unauthenticated, so nothing in the capability word should
    // be what enables it.
    (AID_RESCUE, 0),
];

/// FIDO2/U2F ride the HID transport, not the AID dispatcher, so they have no
/// entry in `AID_CAP_BITS` — but they are real, always-compiled applets and must
/// always be advertised. Kept explicit here so the "expected word" is built
/// from named reasons rather than from a magic number.
const HID_CAP_BITS: u16 = CAP_FIDO2 | CAP_U2F;

/// The word the **host emulation** build advertises on top of the device word.
///
/// `CCID_AIDS` is the *device* AID set (it is what `register_ccid_apps` wires);
/// `firmware/src/emul_main.rs` registers a seventh app, `PivApp`, past it. So when
/// this test is built with the `piv` feature the PIV bit is expected, and it is
/// expected for the same reason as every other bit above: an applet that is
/// really registered. Naming the exception here — rather than letting the
/// feature float by — keeps the "advertise only what you serve" rule exact in
/// both configurations.
#[cfg(feature = "piv")]
const EMULATION_ONLY_CAP_BITS: u16 = CAP_PIV;
#[cfg(not(feature = "piv"))]
const EMULATION_ONLY_CAP_BITS: u16 = 0;

#[test]
fn caps_bits_match_registered_apps() {
    // Direction 1a: a registered AID with no entry in the map is an
    // unaccounted-for applet.
    for aid in CCID_AIDS {
        assert!(
            AID_CAP_BITS.iter().any(|(mapped, _)| *mapped == aid),
            "AID {aid:?} is in CCID_AIDS but has no entry in AID_CAP_BITS — \
             register a capability bit for it, or drop 0 with a stated reason \
             if it is deliberately not advertised"
        );
    }

    // Direction 1b: a cap bit for an AID that is not registered is exactly the
    // US-104 bug — the host is told about an applet the device cannot answer.
    for (aid, bit) in AID_CAP_BITS {
        assert!(
            CCID_AIDS.contains(&aid),
            "AID {aid:?} is mapped to cap bit 0x{bit:04X} in AID_CAP_BITS but is \
             not in CCID_AIDS — the applet is advertised but never registered"
        );
    }

    // The whole word, built from the reasons above.
    let registered_bits = AID_CAP_BITS.iter().fold(0u16, |acc, (_, bit)| acc | bit);
    let expected = HID_CAP_BITS | EMULATION_ONLY_CAP_BITS | registered_bits;
    assert_eq!(
        caps(),
        expected,
        "management caps word 0x{:04X} does not match the registered applet set \
         (expected 0x{expected:04X})",
        caps()
    );

    // Same invariant, spelled out for the bit this story is about so the failure
    // names PIV rather than two hex words.
    #[cfg(not(feature = "piv"))]
    assert_eq!(
        caps() & CAP_PIV,
        0,
        "PIV is not in CCID_AIDS (the device registers six apps) but CAP_PIV \
         (0x10) is advertised — the host would offer a PIV screen the device \
         cannot serve"
    );
    #[cfg(feature = "piv")]
    assert_eq!(
        caps() & CAP_PIV,
        CAP_PIV,
        "the `piv` feature is on (the emulation binary registers PivApp), so the \
         PIV bit must be advertised"
    );
}
