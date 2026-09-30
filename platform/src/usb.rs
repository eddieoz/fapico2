//! Composite USB device: CCID (smartcard) + HID (CTAP) interfaces.
//!
//! EPIC `RUST-MIGRATION` — Phase 0 Task 0.3 (US-303/304) + US-386 (serve loop).
//!
//! Builds an `embassy-usb` composite device with two interfaces:
//! * CCID (class 0x0B) — bulk IN/OUT endpoints for OATH/OTP/OpenPGP/mgmt.
//! * HID (class 0x03, interrupt IN **and OUT**) — CTAP1/2 FIDO.
//!
//! [`Usb::into_parts`] hands the firmware two groups of handles:
//!
//! * the [`UsbDevice`] — run in its own task; it services control transfers
//!   (enumeration, class requests) and schedules the data endpoints;
//! * the four data endpoints, polled by the serve-loop tasks:
//!
//!   | handle       | direction          | traffic                                          |
//!   |--------------|--------------------|--------------------------------------------------|
//!   | `ccid_in`    | bulk IN (dev→host) | CCID responses (APDU answers, ATR)               |
//!   | `ccid_out`   | bulk OUT (host→dev)| CCID requests (APDUs, ATR-reset 0x04)            |
//!   | `hid_in`     | interrupt IN       | CTAP HID reports (INIT/CBOR/ping replies)        |
//!   | `hid_out`    | interrupt OUT      | CTAP HID reports from the host (commands)        |
//!
//! The HID OUT endpoint mirrors the C SDK: CTAP commands arrive as HID
//! *output* reports (usage 0x21, `tud_hid_set_report_cb` on the OUT endpoint),
//! while device replies go out on the interrupt IN endpoint (usage 0x20).

use crate::hid_control::{CCID_CLASS_DESCRIPTOR, HID_CLASS_DESCRIPTOR};
use crate::usb_ident::SerialBuf;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::{Builder, Config as UsbConfig, Handler};

// Re-exports so the firmware serve loop can name the endpoint types, the
// device handle and the async read/write traits without duplicating the
// driver paths.
pub use embassy_rp::usb::{Endpoint, In, Out};
pub use embassy_usb::driver::{EndpointError, EndpointIn, EndpointOut};
pub use embassy_usb::UsbDevice;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

/// fapico2 USB identity (S-391-14): VID `0xFA20`, PID `0x0002`, manufacturer
/// "The BLOCO Community" (formerly "EddieOz"), product "fapico2". VID/PID were
/// bus-verified on the RP2350 board before the identity commit; the
/// manufacturer rename takes effect with the first build that carries it, so
/// units flashed earlier still enumerate under the old string.
///
/// Now the *default* rather than the only value: the descriptor takes its VID,
/// PID, manufacturer and product from [`crate::identity`], which resolves them
/// from the build-time identity block. A fork publishes under its own name
/// without editing this file, and a development build can pretend to be
/// something else without touching source. The constants are re-exported here
/// under their old names because the descriptor code below reads naturally
/// with them, and because anything else in the arm build that wants the
/// identity should go through [`crate::identity`] rather than duplicating it.
use crate::identity::usb_ident;

/// Answers the CTAP-HID interface's class protocol on the control endpoint.
///
/// Without a registered [`Handler`], embassy-usb only serves standard
/// device-level descriptors and **rejects GET_DESCRIPTOR(Report) 0x2200**
/// (a standard request *to the interface*), so the descriptor STALLed and
/// `usbhid` could never bind (hardware cycle E6c, US-391 E7 blocker #1).
/// The decisions live in [`crate::hid_control`] (host-tested); this glue
/// maps embassy types onto them.
struct HidControlHandler {
    /// HID interface number (the CTAP interface this handler answers).
    itf: u8,
}

impl Handler for HidControlHandler {
    fn control_in<'a>(&'a mut self, req: Request, _buf: &'a mut [u8]) -> Option<InResponse<'a>> {
        if req.index != self.itf as u16 {
            return None;
        }
        if !matches!(
            (req.request_type, req.recipient),
            (RequestType::Standard, Recipient::Interface)
        ) {
            return None;
        }
        match crate::hid_control::control_in(req.request, req.value) {
            crate::hid_control::InReply::Data(d) => Some(InResponse::Accepted(d)),
            crate::hid_control::InReply::Rejected => Some(InResponse::Rejected),
            crate::hid_control::InReply::NotHandled => None,
        }
    }

    fn control_out(&mut self, req: Request, _data: &[u8]) -> Option<OutResponse> {
        if req.index != self.itf as u16 {
            return None;
        }
        match (req.request_type, req.recipient) {
            (RequestType::Class, Recipient::Interface) => {
                match crate::hid_control::control_out(req.request) {
                    crate::hid_control::OutReply::Accepted => Some(OutResponse::Accepted),
                    crate::hid_control::OutReply::Rejected => Some(OutResponse::Rejected),
                    crate::hid_control::OutReply::NotHandled => None,
                }
            }
            _ => None,
        }
    }
}

/// Write-once slot for the handler (no heap on device; the handler must live
/// for the `'d` device lifetime).
static mut HID_CONTROL_HANDLER: core::mem::MaybeUninit<HidControlHandler> =
    core::mem::MaybeUninit::uninit();

/// US-103 (PICOForge-COMPAT): the 8-digit `iSerialNumber`, derived once from
/// the OTP chipid and lent to embassy-usb as `&'static str`.
///
/// This is the `no_std` answer to `Config::serial_number: Option<&'a str>`
/// for a value only known at runtime: no heap means no `String`, and the
/// device profile forbids `Box::leak` (nothing would ever reclaim it). Eight
/// bytes in `.bss`, written exactly once by [`Usb::new`] before the device is
/// built — therefore before the host can enumerate and read it — and never
/// touched again, so the `&'static str` embassy-usb holds is immutable for the
/// life of the process. [`SerialBuf::write`] panics on a second call, which is
/// what makes the loan sound rather than merely conventional.
///
/// Same write-once-`MaybeUninit`-static reasoning as
/// [`HID_CONTROL_HANDLER`] above; see `crate::usb_ident` for the full
/// rationale and the digit/collision rules.
static mut USB_SERIAL: SerialBuf = SerialBuf::new();

/// The four data endpoints of the composite device. Owned by the serve-loop
/// tasks (one group per transport); `device` is run in its own task.
pub struct UsbParts<'d> {
    /// Run with `device.run().await` in a dedicated task; never returns.
    pub device: UsbDevice<'d, Driver<'d, USB>>,
    /// CCID bulk IN — device→host (write CCID frames here).
    pub ccid_in: Endpoint<'d, USB, In>,
    /// CCID bulk OUT — host→device (read CCID frames from here).
    pub ccid_out: Endpoint<'d, USB, Out>,
    /// HID interrupt IN — device→host (write CTAP HID reports here).
    pub hid_in: Endpoint<'d, USB, In>,
    /// HID interrupt OUT — host→device (read CTAP HID reports from here).
    pub hid_out: Endpoint<'d, USB, Out>,
}

/// Builder for the composite device. Call [`new`], then [`into_parts`] to
/// split the `UsbDevice` from the data endpoints.
pub struct Usb<'d> {
    parts: UsbParts<'d>,
}

impl<'d> Usb<'d> {
    /// Create a new composite USB device.
    ///
    /// `config_descriptor_buf`, `bos_descriptor_buf`, `msos_descriptor_buf`,
    /// and `control_buf` must outlive the `Usb` instance (typically
    /// `'static` via leaked or static-lifetime buffers).
    ///
    /// `chipid` is the RP2350 OTP chipid (`embassy_rp::otp::get_chipid()`).
    /// It is **injected rather than read here** so the derivation stays in the
    /// host-testable [`crate::usb_ident`] module — `get_chipid()` is an
    /// arm-only OTP read that does not compile off-device, and the firmware
    /// (`main.rs`) already has the value in hand. It must be the *same* chipid
    /// the management applet is given, so the USB serial and `TAG_SERIAL`
    /// agree.
    ///
    /// **Every caller is on real silicon** and must read the real OTP row:
    /// `fapico2-firmware`, `bridge`, `bringup`, `hwtest`. The bring-up binaries
    /// are hardware diagnostics, not host builds, so they have a genuine OTP
    /// row and no excuse for a stand-in. The emulation transport
    /// (`emul_main.rs`) is TCP-based and never reaches this constructor, so
    /// [`crate::usb_ident::EMULATION_CHIPID`] has no USB caller at all — it
    /// exists for the emulated management `TAG_SERIAL` and the store key.
    /// Passing it here would make a physical board report a fleet-identical
    /// serial.
    ///
    /// # Panics
    ///
    /// Via [`SerialBuf::write`], if called twice in one process: the serial
    /// buffer is write-once because the `&'static str` it lends out must never
    /// observe a mutation.
    pub fn new(
        usb: embassy_rp::Peri<'d, USB>,
        config_descriptor_buf: &'d mut [u8],
        bos_descriptor_buf: &'d mut [u8],
        msos_descriptor_buf: &'d mut [u8],
        control_buf: &'d mut [u8],
        chipid: u64,
    ) -> Self {
        let driver = Driver::new(usb, Irqs);

        // US-103: derive the stable 8-digit serial before the config is built,
        // into the write-once static that lends it a `&'static str`. Done
        // first so a (would-be) panic happens before any USB state exists.
        let serial: &'static str = {
            // SAFETY: `USB_SERIAL` is written exactly once per process (this
            // is the only writer, and `Usb::new` runs once per boot, guarded
            // by `SerialBuf`'s write-once check) and is never read or written
            // again afterwards, so the `&'static str` handed out below is
            // immutable for the life of the process. Same pattern as
            // `HID_CONTROL_HANDLER`.
            let buf: &'static mut SerialBuf = unsafe { &mut *core::ptr::addr_of_mut!(USB_SERIAL) };
            buf.write(chipid);
            buf.as_str()
        };

        let ident = usb_ident();
        let mut config = UsbConfig::new(ident.vid, ident.pid);
        config.manufacturer = Some(ident.manufacturer);
        config.product = Some(ident.product);
        config.serial_number = Some(serial);
        config.max_power = 100;
        config.composite_with_iads = true;

        let mut builder = Builder::new(
            driver,
            config,
            config_descriptor_buf,
            bos_descriptor_buf,
            msos_descriptor_buf,
            control_buf,
        );

        // --- CCID interface (class 0x0B, bulk) ---
        let (ccid_in, ccid_out) = {
            let mut func = builder.function(0x0B, 0x00, 0x00);
            let mut iface = func.interface();
            let mut alt = iface.alt_setting(0x0B, 0x00, 0x00, None);
            // Class descriptor BEFORE the endpoints: the builder writes bytes
            // in call order, and a class descriptor written after the
            // endpoints is attributed to the last endpoint's `extra` field
            // instead of the interface's — pcscd's CCID driver reads the
            // 54-byte descriptor only from the interface extra and then
            // fails with "Unable to find the device descriptor" (E7).
            alt.descriptor(0x21, CCID_CLASS_DESCRIPTOR);
            let in_ep = alt.endpoint_bulk_in(None, 64);
            let out_ep = alt.endpoint_bulk_out(None, 64);
            (in_ep, out_ep)
        };

        // --- HID interface (CTAP, interrupt IN + OUT) ---
        let (hid_in, hid_out, hid_itf) = {
            let mut func = builder.function(0x03, 0x00, 0x00);
            let mut iface = func.interface();
            let hid_itf = iface.interface_number();
            let mut alt = iface.alt_setting(0x03, 0x00, 0x00, None);
            // Class descriptor BEFORE the endpoints (same interface-extra
            // discipline as the CCID block): usbhid's probe requires the
            // 9-byte HID class descriptor in the *interface* extra and fails
            // with "class descriptor not present" when it lands after the
            // endpoints (E7 — Driver=[none], no hidraw, no CTAP device).
            // The report descriptor itself is NOT embedded in the
            // configuration blob — it is served on GET_DESCRIPTOR(Report) by
            // [`HidControlHandler`].
            alt.descriptor(0x21, &HID_CLASS_DESCRIPTOR[2..]);
            let in_ep = alt.endpoint_interrupt_in(None, 64, 10);
            // Interrupt OUT: CTAP commands from the host (usage 0x21) — the
            // C SDK drives these through `tud_hid_set_report_cb`.
            let out_ep = alt.endpoint_interrupt_out(None, 64, 10);
            (in_ep, out_ep, u8::from(hid_itf))
        };

        // Register the HID class-control handler (GET_DESCRIPTOR(Report) etc.).
        let hid_handler: &'d mut HidControlHandler = unsafe {
            (&mut *core::ptr::addr_of_mut!(HID_CONTROL_HANDLER)).write(HidControlHandler { itf: hid_itf })
        };
        builder.handler(hid_handler);

        let device = builder.build();
        Self {
            parts: UsbParts {
                device,
                ccid_in,
                ccid_out,
                hid_in,
                hid_out,
            },
        }
    }

    /// Split the builder result into the [`UsbDevice`] (run it in its own
    /// task) and the four data endpoints (polled by the serve-loop tasks).
    pub fn into_parts(self) -> UsbParts<'d> {
        self.parts
    }
}
