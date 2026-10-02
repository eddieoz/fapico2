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
use crate::identity::MAX_IDENTITY_STRING;
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

/// Routes the two HID interfaces' class protocols on the control endpoint.
///
/// embassy-usb's `Builder` keeps a single [`Handler`], and this composite
/// device carries **two** HID interfaces with class behavior — CTAP-HID
/// (descriptor + idle/protocol requests) and the Yubico OTP interface
/// (descriptor + idle/protocol + stateful FEATURE reports). One handler,
/// routing by `wIndex`, is the shape the single-handler constraint forces.
/// All decisions live in [`crate::hid_control`] and [`crate::otp_hid`]
/// (host-tested); this glue maps embassy types onto them.
struct HidInterfacesHandler {
    /// CTAP-HID interface number.
    ctap_itf: u8,
    /// Yubico OTP interface number.
    otp_itf: u8,
}

impl HidInterfacesHandler {
    fn control_in_ctap<'a>(&'a mut self, req: Request) -> Option<InResponse<'a>> {
        if req.index != self.ctap_itf as u16 {
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

    fn control_in_otp<'a>(&'a mut self, req: Request, buf: &'a mut [u8]) -> Option<InResponse<'a>> {
        if req.index != self.otp_itf as u16 {
            return None;
        }
        match (req.request_type, req.recipient) {
            (RequestType::Standard, Recipient::Interface) => {
                match crate::otp_hid::control_in(req.request, req.value) {
                    crate::hid_control::InReply::Data(d) => Some(InResponse::Accepted(d)),
                    crate::hid_control::InReply::Rejected => Some(InResponse::Rejected),
                    crate::hid_control::InReply::NotHandled => None,
                }
            }
            // GET_REPORT(Feature) — the device→host half of the YK4 transport:
            // response chunks, then the terminator, then the idle status.
            (RequestType::Class, Recipient::Interface) if req.request == 0x01 => {
                if (req.value >> 8) as u8 != 3 || buf.len() < crate::otp_hid::FEATURE_REPORT_SIZE {
                    return Some(InResponse::Rejected);
                }
                let report: &mut [u8; crate::otp_hid::FEATURE_REPORT_SIZE] =
                    (&mut buf[..crate::otp_hid::FEATURE_REPORT_SIZE])
                        .try_into()
                        .expect("slice length checked above");
                crate::otp_hid::get_report(report);
                Some(InResponse::Accepted(&buf[..crate::otp_hid::FEATURE_REPORT_SIZE]))
            }
            _ => None,
        }
    }

    fn control_out_ctap(&mut self, req: Request, data: &[u8]) -> Option<OutResponse> {
        if req.index != self.ctap_itf as u16 {
            return None;
        }
        match (req.request_type, req.recipient) {
            (RequestType::Class, Recipient::Interface) => {
                // US-1515: `wValue` and the data stage are forwarded. This
                // arm used to match on `bRequest` alone and never look at
                // `data`, so a SET_REPORT's payload was dropped here — before
                // any decision saw it — while the request was still ACKed.
                // The CTAP decision now STALLs SET_REPORT
                // (`hid_control::control_out`); this note is the wiring half,
                // so a future servicing path gets the buffer from here.
                match crate::hid_control::control_out(req.request, req.value, data) {
                    crate::hid_control::OutReply::Accepted => Some(OutResponse::Accepted),
                    crate::hid_control::OutReply::Rejected => Some(OutResponse::Rejected),
                    crate::hid_control::OutReply::NotHandled => None,
                }
            }
            _ => None,
        }
    }

    fn control_out_otp(&mut self, req: Request, data: &[u8]) -> Option<OutResponse> {
        if req.index != self.otp_itf as u16 {
            return None;
        }
        match (req.request_type, req.recipient) {
            (RequestType::Class, Recipient::Interface) => {
                // SET_REPORT(Feature) — the host→device half: one 8-byte
                // report of the 70-byte YK4 frame, or the 0xFF reset.
                if req.request == 0x09 && (req.value >> 8) as u8 == 3 {
                    if let Ok(report) = <&[u8; crate::otp_hid::FEATURE_REPORT_SIZE]>::try_from(data)
                    {
                        crate::otp_hid::set_report(report);
                    }
                    return Some(OutResponse::Accepted);
                }
                match crate::otp_hid::control_out(req.request, req.value) {
                    crate::hid_control::OutReply::Accepted => Some(OutResponse::Accepted),
                    crate::hid_control::OutReply::Rejected => Some(OutResponse::Rejected),
                    crate::hid_control::OutReply::NotHandled => None,
                }
            }
            _ => None,
        }
    }
}

impl Handler for HidInterfacesHandler {
    fn control_in<'a>(&'a mut self, req: Request, buf: &'a mut [u8]) -> Option<InResponse<'a>> {
        match req.index {
            i if i == self.ctap_itf as u16 => self.control_in_ctap(req),
            i if i == self.otp_itf as u16 => self.control_in_otp(req, buf),
            _ => None,
        }
    }

    fn control_out(&mut self, req: Request, data: &[u8]) -> Option<OutResponse> {
        match req.index {
            i if i == self.ctap_itf as u16 => self.control_out_ctap(req, data),
            i if i == self.otp_itf as u16 => self.control_out_otp(req, data),
            _ => None,
        }
    }
}

/// Write-once slot for the handler (no heap on device; the handler must live
/// for the `'d` device lifetime).
static mut HID_INTERFACES_HANDLER: core::mem::MaybeUninit<HidInterfacesHandler> =
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

/// The operator-set USB identity a boot may override the build-time one with.
///
/// The FIDO keystore persists a `PhyConfig` (VID/PID, product and manufacturer
/// names) written by a configurator's `CONFIG_WRITE`; until now that record was
/// stored but never applied — the descriptors read only the compile-time
/// `identity` constants, which is why a saved identity change "succeeded" yet
/// never reached the bus. This type is the resolved snapshot `Usb::new` now
/// applies, field by field: a `Some` field replaces the build-time value, a
/// `None` leaves it alone — the same per-field precedence the C SDK's
/// `phy_data` boot override uses. The bytes are owned so the value can be
/// built from a keystore borrow that ends immediately (see [`StoredName`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredIdentity {
    /// `(vid << 16) | pid`, as `fapico2_fido::vendorff::pack_vidpid` stores it
    /// in the keystore; `None` keeps the build-time VID/PID.
    pub vid_pid: Option<u32>,
    /// The stored `iProduct`, or `None` to keep the build-time product.
    pub product: Option<StoredName>,
    /// The stored `iManufacturer`, or `None` to keep the build-time value.
    pub manufacturer: Option<StoredName>,
}

/// A stored identity string — a fixed copy of the keystore's `IdentityName`
/// bytes, owned so the borrow that produced it can end.
///
/// The width is [`MAX_IDENTITY_STRING`] minus the NUL the wire format carries,
/// the same bound `IdentityName` enforces at construction, so a value that
/// fits there always fits here and the copy cannot fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredName {
    bytes: [u8; MAX_IDENTITY_STRING - 1],
    len: u8,
}

impl StoredName {
    /// Copies a stored name out of the keystore's bytes.
    ///
    /// Panics if `bytes` exceeds [`MAX_IDENTITY_STRING`] - 1 — impossible for
    /// anything that came through `IdentityName::new`, and a caller that
    /// hand-rolls a longer slice has already violated the same wire bound the
    /// panic restates.
    pub fn new(bytes: &[u8]) -> Self {
        assert!(
            bytes.len() < MAX_IDENTITY_STRING,
            "stored identity name exceeds the wire bound"
        );
        let mut out = [0u8; MAX_IDENTITY_STRING - 1];
        out[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: out, len: bytes.len() as u8 }
    }
}

/// Reads a stored name back out of its write-once static as a `&'static str`.
///
/// The string must not borrow the local [`StoredName`] the bytes were built
/// from — the local dies at the end of [`Usb::new`], while the config holds
/// the string for the life of the device — so the read goes through the
/// static the bytes were copied into, which is why this is `unsafe`.
///
/// # SAFETY
///
/// The caller must have written `name_buf` and `len` earlier in the same
/// [`Usb::new`] call (the write-once discipline documented on the statics)
/// and must never call this again after that one write. `""` if the stored
/// bytes are not UTF-8 — the same fallback `IdentityName::as_str` uses, and
/// unreachable in practice because `IdentityName::new` takes a `&str`.
unsafe fn stored_name_str(
    name_buf: *const [u8; MAX_IDENTITY_STRING - 1],
    len_buf: *const u8,
) -> &'static str {
    let bytes: &'static [u8; MAX_IDENTITY_STRING - 1] = &*name_buf;
    let len = *len_buf as usize;
    core::str::from_utf8(&bytes[..len]).unwrap_or("")
}

// Write-once copies of the stored identity names. `UsbConfig` holds `&str`s
// for the life of the built device, and the keystore the names come from is a
// handle the boot hands on to the HID task afterwards — so the names must
// outlive that borrow: one `&'static` copy each, written here before the
// builder runs and never touched again. Same write-once-`MaybeUninit`-static
// reasoning as [`USB_SERIAL`].
static mut STORED_PRODUCT_NAME: [u8; MAX_IDENTITY_STRING - 1] = [0; MAX_IDENTITY_STRING - 1];
static mut STORED_PRODUCT_LEN: u8 = 0;
static mut STORED_MANUFACTURER_NAME: [u8; MAX_IDENTITY_STRING - 1] =
    [0; MAX_IDENTITY_STRING - 1];
static mut STORED_MANUFACTURER_LEN: u8 = 0;

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
    /// `stored` is the operator-set identity persisted in the FIDO keystore
    /// (`PhyConfig` via a configurator's `CONFIG_WRITE`), or `None` for the
    /// builds that have no store to consult (`bridge`, `bringup`, `hwtest`).
    /// Each `Some` field replaces the build-time value; `None` fields keep it.
    /// VID/PID can only change at enumeration, so an override takes effect on
    /// the next boot — the same one-reset delay the C SDK's `phy_data`
    /// override has.
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
        stored: Option<StoredIdentity>,
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

        // The operator-set identity overrides the build-time one, field by
        // field. The stored names are copied into the write-once statics so
        // the strings the config holds do not borrow the keystore.
        let mut product = ident.product;
        let mut manufacturer = ident.manufacturer;
        if let Some(stored) = stored {
            // SAFETY: the name statics are written exactly once per process —
            // this is the only writer and `Usb::new` runs once per boot,
            // before the device is built and therefore before the host can
            // read the strings they back — and are never written again, so
            // the `&'static str`s below are immutable for the life of the
            // process. Same pattern as `USB_SERIAL`.
            if let Some(name) = stored.manufacturer {
                unsafe {
                    *core::ptr::addr_of_mut!(STORED_MANUFACTURER_NAME) = name.bytes;
                    *core::ptr::addr_of_mut!(STORED_MANUFACTURER_LEN) = name.len;
                }
                manufacturer = unsafe {
                    stored_name_str(
                        core::ptr::addr_of!(STORED_MANUFACTURER_NAME),
                        core::ptr::addr_of!(STORED_MANUFACTURER_LEN),
                    )
                };
            }
            if let Some(name) = stored.product {
                unsafe {
                    *core::ptr::addr_of_mut!(STORED_PRODUCT_NAME) = name.bytes;
                    *core::ptr::addr_of_mut!(STORED_PRODUCT_LEN) = name.len;
                }
                product = unsafe {
                    stored_name_str(
                        core::ptr::addr_of!(STORED_PRODUCT_NAME),
                        core::ptr::addr_of!(STORED_PRODUCT_LEN),
                    )
                };
            }
        }
        let (vid, pid) = stored
            .and_then(|s| s.vid_pid)
            // A stored all-zero VID/PID is left unapplied: `0x0000:0000` would
            // make the device unenumerable — unreachable by any client,
            // including the one that wrote it. Treating zero as "no override"
            // keeps the record in the keystore while the bus keeps a device,
            // which is what the old store-without-apply behaviour guaranteed
            // for free.
            .filter(|packed| *packed != 0)
            .map_or((ident.vid, ident.pid), |packed| {
                ((packed >> 16) as u16, packed as u16)
            });

        let mut config = UsbConfig::new(vid, pid);
        config.manufacturer = Some(manufacturer);
        config.product = Some(product);
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
            // [`HidInterfacesHandler`].
            alt.descriptor(0x21, &HID_CLASS_DESCRIPTOR[2..]);
            let in_ep = alt.endpoint_interrupt_in(None, 64, 10);
            // Interrupt OUT: CTAP commands from the host (usage 0x21) — the
            // C SDK drives these through `tud_hid_set_report_cb`.
            let out_ep = alt.endpoint_interrupt_out(None, 64, 10);
            (in_ep, out_ep, u8::from(hid_itf))
        };

        // --- HID interface (Yubico OTP, keyboard-usage, feature reports) ---
        // The transport Yubico Authenticator/ykman uses to detect and drive
        // the OTP app (`yubikit/core/otp.py`): usage (0x0001, 0x0006) plus an
        // 8-byte FEATURE report; the frames travel on the control endpoint
        // ([`OtpHidControlHandler`]), never on this interrupt endpoint — the
        // IN endpoint exists because the C firmware's keyboard interface has
        // one (and a HID interface the host's class driver accepts binds
        // identically here), and is never written.
        let otp_itf = {
            let mut func = builder.function(0x03, 0x00, 0x00);
            let mut iface = func.interface();
            let otp_itf = iface.interface_number();
            let mut alt = iface.alt_setting(0x03, 0x00, 0x00, None);
            // Class descriptor BEFORE the endpoints — the interface-extra
            // discipline the CCID and CTAP blocks above document (E7).
            alt.descriptor(0x21, &crate::otp_hid::OTP_HID_CLASS_DESCRIPTOR[2..]);
            // Interrupt IN: part of the keyboard surface, never armed.
            let _otp_in = alt.endpoint_interrupt_in(None, 64, 10);
            u8::from(otp_itf)
        };
        // One composite handler answers both HID interfaces (see the struct
        // docs — embassy-usb keeps a single `Handler`).
        let hid_handler: &'d mut HidInterfacesHandler = unsafe {
            (&mut *core::ptr::addr_of_mut!(HID_INTERFACES_HANDLER)).write(HidInterfacesHandler {
                ctap_itf: hid_itf,
                otp_itf,
            })
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
