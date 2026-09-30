//! HID class-control decisions (US-391 E7): descriptors + class requests.
//!
//! The composite device serves CTAP-HID through manually built interfaces
//! (the endpoints are owned by the firmware serve loop), so the class
//! protocol that `embassy-usb`'s HID class would normally provide must be
//! answered here: `GET_DESCRIPTOR(Report)` `0x2200` / `GET_DESCRIPTOR(HID)`
//! `0x2100` (standard requests **to the interface** — without a registered
//! [`embassy_usb::Handler`] the stack rejects them and the descriptor STALLs,
//! which is exactly what blocked `usbhid` from binding on hardware, cycle
//! E6c), plus SET/GET_IDLE and SET/GET_PROTOCOL.
//!
//! This module holds the pure, host-testable decisions; `usb.rs` carries the
//! thin `Handler` glue that maps `embassy-usb` request types onto them.

/// CTAP-HID report descriptor (FIDO U2F, 64-byte reports).
/// Matches the C `desc_hid_report` in `pico-keys-sdk/src/usb/usb_descriptors.c`:
/// 64-byte input (usage 0x20) **and** 64-byte output (usage 0x21) reports.
pub const CTAP_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO)
    0x09, 0x01, // Usage (CTAP)
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

/// HID class descriptor (the `bDescriptorType = 0x21` descriptor referenced
/// from the interface's configuration blob and re-served on class
/// GET_DESCRIPTOR). Complete with its own bLength/bDescriptorType prefix —
/// `usb.rs` slices off the first two bytes when embedding it in the
/// configuration descriptor (the builder adds the length/type itself).
pub const HID_CLASS_DESCRIPTOR: &[u8] = &[
    0x09, // bLength
    0x21, // bDescriptorType (HID)
    0x11, 0x01, // bcdHID 1.11
    0x00, // bCountryCode (not supported)
    0x01, // bNumDescriptors
    0x22, // bDescriptorType2 (Report)
    (CTAP_REPORT_DESCRIPTOR.len() & 0xFF) as u8, // wDescriptorLength lo
    0x00, // wDescriptorLength hi
];

/// CCID class descriptor payload (52 bytes; the USB builder adds the bLength
/// and bDescriptorType bytes, completing the 54-byte `TUD_SMARTCARD_DESCRIPTOR`
/// the C firmware serves — `pico-keys-sdk/src/usb/usb_descriptors.c`). Mirrors
/// the C values field-for-field: without a real bcdCCID/dwFeatures, pcscd's
/// CCID driver rejects the interface outright (E7 blocker #2).
pub const CCID_CLASS_DESCRIPTOR: &[u8] = &[
    0x10, 0x01, // bcdCCID 1.10
    0x00, // bMaxSlotIndex
    0x01, // bVoltageSupport (5.0 V)
    0x03, 0x00, 0x00, 0x00, // dwProtocols (T=0 | T=1)
    0xFC, 0x0D, 0x00, 0x00, // dwDefaultClock (3580 kHz)
    0xFC, 0x0D, 0x00, 0x00, // dwMaximumClock
    0x00, // bNumClockSupported
    0x80, 0x25, 0x00, 0x00, // dwDataRate (9600 bps)
    0x80, 0x25, 0x00, 0x00, // dwMaxDataRate
    0x00, // bNumDataRatesSupported
    0xFE, 0x00, 0x00, 0x00, // dwMaxIFSD (254)
    0x00, 0x00, 0x00, 0x00, // dwSynchProtocols
    0x00, 0x00, 0x00, 0x00, // dwMechanical
    0x40, 0x08, 0x04, 0x00, // dwFeatures (short & extended APDU exchange)
    0x00, 0x08, 0x00, 0x00, // dwMaxCCIDMessageLength (2048)
    0xFF, // bClassGetResponse
    0xFF, // bClassEnvelope
    0x00, 0x00, // wLcdLayout
    0x00, // bPINSupport
    0x01, // bMaxCCIDBusySlots
];

/// Standard request numbers used here.
const GET_DESCRIPTOR: u8 = 0x06;
const GET_REPORT: u8 = 0x01;
const GET_IDLE: u8 = 0x02;
const GET_PROTOCOL: u8 = 0x03;
const SET_REPORT: u8 = 0x09;
const SET_IDLE: u8 = 0x0A;
const SET_PROTOCOL: u8 = 0x0B;

/// Reply for a control-IN (device → host) request on the HID interface.
#[derive(Debug, PartialEq, Eq)]
pub enum InReply {
    /// Serve these bytes.
    Data(&'static [u8]),
    /// This interface's request, but unfulfillable — STALL.
    Rejected,
    /// Not a HID request — let other handlers look at it.
    NotHandled,
}

/// Reply for a control-OUT (host → device) request on the HID interface.
#[derive(Debug, PartialEq, Eq)]
pub enum OutReply {
    /// Accept (data stage, if any, is consumed and ignored).
    Accepted,
    /// This interface's request, but unsupported — STALL.
    Rejected,
    /// Not a HID request — let other handlers look at it.
    NotHandled,
}

/// Decide a control-IN request addressed to the HID interface.
///
/// `request` is bRequest; `value` is wValue (for GET_DESCRIPTOR the high byte
/// carries the descriptor type; for GET_IDLE the low byte the report id).
pub fn control_in(request: u8, value: u16) -> InReply {
    match request {
        GET_DESCRIPTOR => match (value >> 8) as u8 {
            0x22 => InReply::Data(CTAP_REPORT_DESCRIPTOR),
            0x21 => InReply::Data(HID_CLASS_DESCRIPTOR),
            _ => InReply::Rejected,
        },
        GET_IDLE => InReply::Data(&[0]),
        GET_PROTOCOL => InReply::Data(&[1]), // report protocol (default)
        GET_REPORT => InReply::Rejected,     // no backing report data
        _ => InReply::Rejected,
    }
}

/// Decide a control-OUT request addressed to the HID interface.
pub fn control_out(request: u8) -> OutReply {
    match request {
        SET_IDLE | SET_PROTOCOL | SET_REPORT => OutReply::Accepted,
        _ => OutReply::Rejected,
    }
}

#[cfg(all(test, not(target_arch = "arm")))]
mod tests {
    use super::*;

    /// GET_DESCRIPTOR(Report) 0x2200 — the exact request that STALLed on
    /// hardware in E6c (usbhid could not bind) — must serve the CTAP
    /// report descriptor.
    #[test]
    fn report_descriptor_served_on_2200() {
        let reply = control_in(GET_DESCRIPTOR, 0x2200);
        let data = match reply {
            InReply::Data(d) => d,
            other => panic!("expected Data, got {:?}", other),
        };
        assert_eq!(data, CTAP_REPORT_DESCRIPTOR);
        assert_eq!(data.len(), 34); // TinyUSB FIDO U2F layout (input+output, 64 B each)
        assert_eq!(&data[..3], &[0x06, 0xD0, 0xF1]); // Usage Page (FIDO)
        assert_eq!(data[data.len() - 1], 0xC0); // End Collection
    }

    /// GET_DESCRIPTOR(HID) 0x2100 must serve a well-formed 9-byte HID class
    /// descriptor whose wDescriptorLength matches the report descriptor.
    #[test]
    fn hid_descriptor_served_on_2100() {
        let data = match control_in(GET_DESCRIPTOR, 0x2100) {
            InReply::Data(d) => d,
            other => panic!("expected Data, got {:?}", other),
        };
        assert_eq!(data, HID_CLASS_DESCRIPTOR);
        assert_eq!(data[0], 9);
        assert_eq!(data[1], 0x21);
        assert_eq!(&data[2..4], &[0x11, 0x01]); // bcdHID 1.11
        assert_eq!(data[6], 0x22); // report descriptor follows
        assert_eq!(
            data[7] as u16 | ((data[8] as u16) << 8),
            CTAP_REPORT_DESCRIPTOR.len() as u16
        );
    }

    /// Any other descriptor type is rejected (not passed through).
    #[test]
    fn unknown_descriptor_type_rejected() {
        assert_eq!(control_in(GET_DESCRIPTOR, 0x2300), InReply::Rejected);
    }

    /// GET_PROTOCOL must report the report-protocol mode (1) so the host
    /// doesn't force boot-protocol semantics.
    #[test]
    fn get_protocol_reports_report_mode() {
        assert_eq!(control_in(GET_PROTOCOL, 0), InReply::Data(&[1]));
    }

    /// GET_IDLE returns a zero duration (idle not supported).
    #[test]
    fn get_idle_returns_zero() {
        assert_eq!(control_in(GET_IDLE, 0), InReply::Data(&[0]));
    }

    /// GET_REPORT has no backing data — rejected.
    #[test]
    fn get_report_rejected() {
        assert_eq!(control_in(0x01, 0), InReply::Rejected);
    }

    /// Unknown IN requests on the HID interface are rejected, not ignored.
    #[test]
    fn unknown_control_in_rejected() {
        assert_eq!(control_in(0x7F, 0), InReply::Rejected);
    }

    /// SET_IDLE / SET_PROTOCOL / SET_REPORT complete without a data reply.
    #[test]
    fn set_requests_accepted() {
        assert_eq!(control_out(SET_IDLE), OutReply::Accepted);
        assert_eq!(control_out(SET_PROTOCOL), OutReply::Accepted);
        assert_eq!(control_out(SET_REPORT), OutReply::Accepted);
        assert_eq!(control_out(0x7F), OutReply::Rejected);
    }

    /// The CCID class descriptor payload mirrors the C firmware's
    /// `TUD_SMARTCARD_DESCRIPTOR` field-for-field (52 bytes + the 2 builder
    /// bytes = the 54-byte descriptor pcscd's driver parses).
    #[test]
    fn ccid_class_descriptor_matches_c_firmware() {
        assert_eq!(CCID_CLASS_DESCRIPTOR.len(), 52);
        assert_eq!(&CCID_CLASS_DESCRIPTOR[0..2], &[0x10, 0x01]); // bcdCCID 1.10
        assert_eq!(CCID_CLASS_DESCRIPTOR[3], 0x01); // bVoltageSupport (5.0 V)
        // dwProtocols = T0|T1
        assert_eq!(u32::from_le_bytes(CCID_CLASS_DESCRIPTOR[4..8].try_into().unwrap()), 0x03);
        // dwFeatures: short & extended APDU level exchange
        assert_eq!(u32::from_le_bytes(CCID_CLASS_DESCRIPTOR[38..42].try_into().unwrap()), 0x0004_0840);
        // dwMaxCCIDMessageLength = 2048 (C USB_BUFFER_SIZE)
        assert_eq!(u32::from_le_bytes(CCID_CLASS_DESCRIPTOR[42..46].try_into().unwrap()), 2048);
        // bMaxCCIDBusySlots = 1
        assert_eq!(CCID_CLASS_DESCRIPTOR[51], 1);
    }
}
