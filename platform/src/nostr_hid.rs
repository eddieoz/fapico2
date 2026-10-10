//! The Nostr vendor-HID class-control decisions (US-1657): descriptors +
//! class requests for the **third** HID interface on vendor usage page
//! `0xFF00` (design §A.8 / D23).
//!
//! # Why a third interface, and why this usage page
//!
//! No browser transport can reach any *existing* interface (§A.6): CCID is
//! kernel-claimed, HID-class is WebUSB-blocked, and Chrome hard-blocks the
//! FIDO usage page `0xF1D0` from WebHID at three independent layers
//! (`whatwg/hid/blocklist.txt`, `hid_chooser_context.cc::HasDevicePermission`,
//! `hid_service.cc`'s `allow_fido_reports=false`). The Trezor pattern — the
//! ecosystem's browser-first answer — is a vendor usage page (`trezord-go`
//! hardcodes `0xFF00`); the Ledger pattern is WebHID on it. This interface is
//! both: vendor usage page `0xFF00`, speaking CTAPHID framing (D23) with the
//! Nostr command set riding the spec-reserved vendor command range
//! `0x40–0x7F` (§A.8.2).
//!
//! The interface is **appended after OTP** (`usb.rs` builds it last) so no
//! earlier interface's number ever shifts — OTP's number is load-bearing for
//! yubikit's OTP transport, and PicoForge's PC/SC leg binds to the CCID one.
//!
//! # What it serves, honestly
//!
//! The class-control surface is deliberately minimal and mirrors the CTAP
//! interface's shape (so one `Handler` routes all three HID interfaces by
//! `wIndex`): the report descriptor on `GET_DESCRIPTOR(Report)`, the class
//! descriptor on `GET_DESCRIPTOR(HID)`, idle/protocol answered as "set but
//! never honoured" the way the CTAP interface does. There are no FEATURE
//! reports and no stateful report store: the transport is 64-byte interrupt
//! reports on the interface's IN/OUT endpoints, framed by
//! `firmware/src/ctap_hid.rs`. `SET_REPORT` is STALLed like the CTAP
//! interface's is (US-1515) — a class request whose data stage the device
//! would discard is a claim the device does not honour.
//!
//! This module holds the pure, host-testable decisions; `usb.rs` carries the
//! thin `Handler` glue.

/// The Nostr vendor-HID report descriptor (64-byte reports, vendor usage
/// page `0xFF00`, usage `0x01`).
///
/// The shape mirrors [`crate::hid_control::CTAP_REPORT_DESCRIPTOR`] — the
/// framing (D23) is CTAPHID and the report plumbing is shared — but the
/// usage page is deliberately **not** `0xF1D0`: that page is what Chrome's
/// WebHID blocklist keys on (§A.8.1). `0xFF00` is the vendor range the HID
/// spec reserves and the page Trezor ships; `requestDevice`'s filter
/// (`usagePage`/`usage`) hard-binds the extension to exactly this interface.
pub const NOSTR_HID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0x00, 0xFF, // Usage Page (Vendor 0xFF00)
    0x09, 0x01, // Usage (0x01)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

/// HID class descriptor for the Nostr interface, complete with its own
/// bLength/bDescriptorType prefix — `usb.rs` slices off the first two bytes
/// when embedding it in the configuration descriptor (the builder adds the
/// length/type itself), the same convention as
/// [`crate::hid_control::HID_CLASS_DESCRIPTOR`].
pub const NOSTR_HID_CLASS_DESCRIPTOR: &[u8] = &[
    0x09, // bLength
    0x21, // bDescriptorType (HID)
    0x11, 0x01, // bcdHID 1.11
    0x00, // bCountryCode (not supported)
    0x01, // bNumDescriptors
    0x22, // bDescriptorType2 (Report)
    (NOSTR_HID_REPORT_DESCRIPTOR.len() & 0xFF) as u8, // wDescriptorLength lo
    0x00, // wDescriptorLength hi
];

/// Standard request numbers (same set the CTAP interface answers).
const GET_DESCRIPTOR: u8 = 0x06;
const GET_IDLE: u8 = 0x02;
const GET_PROTOCOL: u8 = 0x03;
const SET_IDLE: u8 = 0x0A;
const SET_PROTOCOL: u8 = 0x0B;

/// The Nostr interface's decisions are typed with [`crate::hid_control`]'s
/// reply enums: one `Handler` routes all three HID interfaces, and three
/// twin types would be three conversions for no information.
pub use crate::hid_control::{InReply, OutReply};

/// Decide a control-IN request addressed to the Nostr interface.
pub fn control_in(request: u8, value: u16) -> InReply {
    match request {
        GET_DESCRIPTOR => match (value >> 8) as u8 {
            0x22 => InReply::Data(NOSTR_HID_REPORT_DESCRIPTOR),
            0x21 => InReply::Data(NOSTR_HID_CLASS_DESCRIPTOR),
            _ => InReply::Rejected,
        },
        // Idle/protocol: no report store and no protocol to switch into, so
        // the answers are the CTAP interface's "set but never honoured" —
        // silent acceptance on SET, a zero read-back on GET.
        SET_IDLE => InReply::Data(&[]),
        GET_IDLE => InReply::Data(&[0x00]),
        SET_PROTOCOL => InReply::Data(&[]),
        GET_PROTOCOL => InReply::Data(&[0x00]),
        _ => InReply::NotHandled,
    }
}

/// Decide a control-OUT request addressed to the Nostr interface.
///
/// No FEATURE reports exist on this interface — the transport is interrupt
/// reports on the endpoints — so every SET_REPORT is a STALL, exactly the
/// CTAP interface's US-1515 posture: an `Accepted` here would tell the host
/// a payload was applied that the device threw away.
pub fn control_out(request: u8, _value: u16, _data: &[u8]) -> OutReply {
    match request {
        0x09 => OutReply::Rejected, // SET_REPORT — no FEATURE reports here
        _ => OutReply::NotHandled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The usage page is the whole point of the interface (§A.8.1): Chrome's
    /// WebHID blocklist keys on `0xF1D0`, and the extension's `requestDevice`
    /// filter binds on `0xFF00`. First item is the Usage Page (0x06, 3-byte).
    #[test]
    fn usage_page_is_the_vendor_page_ff00() {
        assert_eq!(
            &NOSTR_HID_REPORT_DESCRIPTOR[..3],
            &[0x06, 0x00, 0xFF],
            "the first item must be Usage Page (Vendor 0xFF00)"
        );
        assert_eq!(&NOSTR_HID_REPORT_DESCRIPTOR[3..5], &[0x09, 0x01], "usage 0x01");
    }

    /// The descriptor is CTAPHID-shaped: one application collection with a
    /// 64-byte input and a 64-byte output report, matching what
    /// `firmware/src/ctap_hid.rs` frames.
    #[test]
    fn report_descriptor_is_the_ctaphid_shape() {
        // The collection body is byte-identical to the CTAP interface's —
        // only the usage page/usage differ (the first five bytes).
        assert_eq!(
            &NOSTR_HID_REPORT_DESCRIPTOR[5..],
            &crate::hid_control::CTAP_REPORT_DESCRIPTOR[5..]
        );
        assert_eq!(NOSTR_HID_REPORT_DESCRIPTOR.len(), crate::hid_control::CTAP_REPORT_DESCRIPTOR.len());
    }

    /// The class descriptor's wDescriptorLength must name the report
    /// descriptor's actual length — a host reads it to allocate before it
    /// asks, and a mismatch is a descriptor that lies about itself.
    #[test]
    fn class_descriptor_names_the_report_descriptor_length() {
        assert_eq!(NOSTR_HID_CLASS_DESCRIPTOR[0], 0x09);
        assert_eq!(NOSTR_HID_CLASS_DESCRIPTOR[1], 0x21);
        let wlen = u16::from_le_bytes([
            NOSTR_HID_CLASS_DESCRIPTOR[7],
            NOSTR_HID_CLASS_DESCRIPTOR[8],
        ]);
        assert_eq!(
            wlen as usize,
            NOSTR_HID_REPORT_DESCRIPTOR.len(),
            "wDescriptorLength must equal the report descriptor's length"
        );
    }

    /// GET_DESCRIPTOR(Report/HID) serve the two descriptors; the class
    /// request vocabulary matches the CTAP interface's surface so the single
    /// Handler routes by `wIndex` alone.
    #[test]
    fn control_requests_serve_the_descriptors() {
        assert_eq!(
            control_in(0x06, 0x2200),
            InReply::Data(NOSTR_HID_REPORT_DESCRIPTOR)
        );
        assert_eq!(
            control_in(0x06, 0x2100),
            InReply::Data(NOSTR_HID_CLASS_DESCRIPTOR)
        );
        assert_eq!(control_in(0x06, 0x2300), InReply::Rejected);
        assert_eq!(control_in(0x02, 0), InReply::Data(&[0x00]));
        assert_eq!(control_in(0x0A, 0), InReply::Data(&[]));
        // Not a HID request — invisible to this interface.
        assert_eq!(control_in(0x99, 0), InReply::NotHandled);
    }

    /// SET_REPORT is STALLed even with a data stage (US-1515: an ACK would
    /// claim a payload was applied that was discarded).
    #[test]
    fn set_report_stalls_with_a_data_stage() {
        assert_eq!(control_out(0x09, 0x0300, &[0u8; 8]), OutReply::Rejected);
        assert_eq!(control_out(0x99, 0, &[]), OutReply::NotHandled);
    }
}
