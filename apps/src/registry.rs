//! Device CCID app registry (US-386).
//!
//! The device wires exactly **six** CCID apps behind the AID dispatcher:
//! **Management, OATH, OTP, OpenPGP, the RS-Key vendor LED applet, and the
//! RS-Key Rescue applet**. FIDO2/U2F rides the separate HID transport (it is
//! not AID-dispatched), and PIV is deferred out of v1.0.0.
//!
//! US-160 (PICOForge-COMPAT) added the vendor LED applet, taking the set from
//! four to five. It is a *vendor* AID (`F0 00 00 00 01`,
//! `picoforge/src/hal/rescue/constants.rs:484`) rather than a standard one, but
//! it is reachable through the ordinary AID dispatcher with no special casing:
//! the client's SELECT is `00 A4 04 04 05 <AID>` and `platform::dispatch`
//! recognises an AID SELECT on P1 (`is_select_apdu` checks `P1 == 0x04` and
//! does not constrain P2), so the client's `P2 = 0x04` arrives as a plain
//! AID SELECT.
//!
//! US-161/162/163 (PICOForge-COMPAT, Phase H) added the **Rescue** applet, the
//! set's sixth member. Its AID `A0 58 3F C1 9B 7E 4F 21`
//! (`picoforge/src/hal/rescue/constants.rs:106`) is a standard one shared by
//! pico-fido's C `rescue.c` and the RS-Key Rust applet, and it is selected the
//! same ordinary way — the client's SELECT is `00 A4 04 04 08 <AID>`
//! (`picoforge/src/hal/transport/pcsc.rs:53-61`) and the dispatcher keys on P1
//! alone, so the client's `P2 = 0x04` again needs no special casing.
//!
//! It is registered on the **device**, not only in the emulator, and that is
//! the deliberate call: the client reaches it over CCID, which is a device
//! transport, and US-163's BOOTSEL reboot means nothing on a host process. The
//! risk of that choice — a permanent unauthenticated write path to a stored
//! record, an unauthenticated reboot primitive, and a widening of the chip-id
//! disclosure — is recorded in `docs/tasks/rescue-threat-model.md` §8 (R1, R2,
//! R3, R5) and in the applet's own module docs.
//!
//! This module is the single source of truth for "which AIDs the device
//! registers" and the registration helper the `firmware` device serve loop
//! calls. It is host-testable so the AID set is verified without hardware
//! (live `lsusb` + SELECT is Phase 6 acceptance).

use fapico2_platform::dispatch::{App, Dispatcher};

/// Management AID (matches `management.c` `man_aid`).
pub const AID_MANAGEMENT: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];
/// OATH AID.
pub const AID_OATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
/// OTP AID.
pub const AID_OTP: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];
/// OpenPGP card AID (spec §4.2.1: RID `D2 76`, `00 01 24 01`).
pub const AID_OPENPGP: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
/// RS-Key vendor LED AID (`picoforge/src/hal/rescue/constants.rs:484`).
/// Re-exported from `fapico2-vendor-led` so the constant has one owner; the
/// applet crate's own copy is what [`App::aid`] returns.
pub const AID_VENDOR_LED: &[u8] = fapico2_vendor_led::VENDOR_LED_AID;
/// RS-Key Rescue AID (`picoforge/src/hal/rescue/constants.rs:106`).
/// Re-exported from `fapico2-rescue` for the same reason as
/// [`AID_VENDOR_LED`]: one owner, and the applet crate's copy is what
/// [`App::aid`] returns.
pub const AID_RESCUE: &[u8] = fapico2_rescue::RESCUE_AID;

/// The six AIDs the device registers behind the CCID dispatcher, in
/// registration order.
pub const CCID_AIDS: [&[u8]; 6] = [
    AID_MANAGEMENT,
    AID_OATH,
    AID_OTP,
    AID_OPENPGP,
    AID_VENDOR_LED,
    AID_RESCUE,
];

/// Register the six device CCID apps into `d`.
///
/// Returns `true` only if **all six** register successfully — i.e. the AIDs
/// are distinct (the dispatcher rejects a duplicate AID) and the `N = 6`
/// capacity holds. A `false` return means the device would mis-wire an app
/// and must not boot into the serve loop.
///
/// The `Dispatcher<'a, N>` const generic and this signature move together:
/// `N` is the dispatcher's fixed registration capacity, so adding an app means
/// widening both. A `N` left at 4 would make the fifth `register` fail on the
/// full `Vec`, and the `&&` chain would short-circuit `false` — the device
/// would refuse to boot rather than half-wire, which is the intended failure
/// mode but for the wrong reason.
// US-939: `#[inline(never)]` -- async-main frame discipline.
#[inline(never)]
pub fn register_ccid_apps<'a>(
    d: &mut Dispatcher<'a, 6>,
    management: &'a mut dyn App,
    oath: &'a mut dyn App,
    otp: &'a mut dyn App,
    openpgp: &'a mut dyn App,
    vendor_led: &'a mut dyn App,
    rescue: &'a mut dyn App,
) -> bool {
    d.register(management)
        && d.register(oath)
        && d.register(otp)
        && d.register(openpgp)
        && d.register(vendor_led)
        && d.register(rescue)
}
