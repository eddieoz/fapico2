//! Yubico OTP HID transport — report descriptor, feature-report state machine.
//!
//! Yubico Authenticator (ykman/yubikit) detects the YubiOTP transport as a HID
//! interface with VID 0x1050 and usage `(page 0x0001, usage 0x0006)`
//! (`ykman/hid/base.py:38`, `ykman/hid/linux.py:121-124`) and then drives the
//! YK4 frame protocol entirely through **feature reports** on the control
//! endpoint — never an interrupt endpoint, never CCID. Without this interface
//! the device is invisible to the OTP panel even though the OTP app answers
//! over CCID.
//!
//! The frame layout is the YK4 one yubikit emits (`yubikit/core/otp.py`
//! `_format_frame`): a 70-byte frame of
//! `payload[64] || slot || crc16(payload) LE || zeros[3]`, carried in 8-byte
//! feature reports (7 payload bytes + 1 sequence byte each). The sequence byte
//! is `0x80 | seq` host→device, `0x40 | seq` device→host, `0xFF` alone means
//! reset. This is byte-for-byte the C firmware's protocol
//! (`pico-fido/src/fido/otp.c` `otp_hid_set_report_cb` / `otp_hid_get_report_cb`
//! / `otp_send_frame`), which is the reference this story mirrors.
//!
//! On an idle `GET_REPORT(Feature)` the device serves an 8-byte status report:
//! `[0, ver_major, ver_minor, 0, prog_seq, slot_flags, 0, status]` —
//! `yubikit` reads the version at `[1:4]` and the programming sequence at
//! `[4]` (`STATUS_OFFSET_PROG_SEQ`), and a configure success is detected by
//! that sequence incrementing between the command and the idle status (the C
//! serves *no* data frame for a configure; `res_APDU_size = 0` on the
//! `is_otp` path).
//!
//! The command half is delegated to an app-side handler pair installed once at
//! boot ([`install`]): a frame handler that runs one `INS 0x01` OTP APDU and a
//! status handler that fills the idle report. Both run strictly synchronously
//! inside the USB control transfer — the same cooperative discipline as every
//! persist gate in this firmware — so there is no cross-task state to protect
//! beyond what the handler itself owns.

use crate::hid_control::{InReply, OutReply};

/// Yubico OTP HID report descriptor — the C firmware's keyboard interface
/// (`pico-keys-sdk/src/usb/usb_descriptors.c` `desc_hid_report_kb` =
/// `TUD_HID_REPORT_DESC_KEYBOARD(...)` + the 8-byte FEATURE report), expanded
/// byte-for-byte. The *application collection* usage is
/// `(page 0x0001, usage 0x0006)`, which is what ykman's hidraw detection
/// matches; the `(page 0x0006)` block before the feature report mirrors the
/// C macro arguments (`HID_USAGE_PAGE(HID_USAGE_DESKTOP_KEYBOARD)` — the
/// upstream passes a *usage* value where a *page* is expected, and the quirk
/// is reproduced rather than corrected so the descriptor matches the
/// reference hardware's bit-for-bit).
pub const OTP_HID_REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    // --- the C macro's VA_ARGS: the YubiKey OTP feature report ---
    0x05, 0x06, //   Usage Page (0x0006 — C macro quirk, see above)
    0x19, 0x00, //   Usage Minimum (0)
    0x2A, 0xFF, 0x00, //   Usage Maximum (255)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x95, 0x08, //   Report Count (8)
    0x75, 0x08, //   Report Size (8)
    0xB1, 0x02, //   Feature (Data, Variable, Absolute)
    // --- the keyboard report the TUD macro wraps around them ---
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0xE0, //   Usage Minimum (224 — left Ctrl)
    0x29, 0xE7, //   Usage Maximum (231 — right GUI)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Variable, Absolute) — modifiers
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x03, //   Input (Constant) — reserved byte
    0x05, 0x08, //   Usage Page (LED)
    0x19, 0x01, //   Usage Minimum (1 — Num Lock)
    0x29, 0x05, //   Usage Maximum (5 — Kana)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x05, //   Report Count (5)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0x95, 0x01, //   Report Count (1)
    0x75, 0x03, //   Report Size (3)
    0x91, 0x03, //   Output (Constant) — LED padding
    0xC0, // End Collection
];

/// HID class descriptor for the OTP interface — same shape as
/// [`crate::hid_control::HID_CLASS_DESCRIPTOR`] but with this interface's
/// report descriptor length. Complete with its own bLength/bDescriptorType
/// prefix; `usb.rs` slices off the first two bytes when embedding it in the
/// configuration blob.
pub const OTP_HID_CLASS_DESCRIPTOR: &[u8] = &[
    0x09, // bLength
    0x21, // bDescriptorType (HID)
    0x11, 0x01, // bcdHID 1.11
    0x00, // bCountryCode (not supported)
    0x01, // bNumDescriptors
    0x22, // bDescriptorType2 (Report)
    (OTP_HID_REPORT_DESCRIPTOR.len() & 0xFF) as u8, // wDescriptorLength lo
    0x00, // wDescriptorLength hi
];

/// Feature-report size (7 payload bytes + the sequence byte).
pub const FEATURE_REPORT_SIZE: usize = 8;
/// Payload bytes per feature report.
pub const FEATURE_REPORT_DATA_SIZE: usize = FEATURE_REPORT_SIZE - 1;
/// A whole frame: 64-byte payload + slot + CRC + 3 zero bytes.
pub const FRAME_SIZE: usize = 70;
/// Payload bytes in a frame (the CRC covers exactly these).
pub const SLOT_DATA_SIZE: usize = 64;

/// Sequence/chunk constants (`yubikit/core/otp.py`, C `otp_hid_*_cb`).
const RESP_PENDING_FLAG: u8 = 0x40;
const SLOT_WRITE_FLAG: u8 = 0x80;
const RESET_REPORT: u8 = 0xFF;
const SEQUENCE_MASK: u8 = 0x1F;
/// 10 chunks of 7 bytes carry the 70-byte frame.
const MAX_SEQ: u8 = 10;

/// Standard + HID class request numbers (same set as `hid_control`).
const GET_DESCRIPTOR: u8 = 0x06;
const GET_REPORT: u8 = 0x01;
const GET_IDLE: u8 = 0x02;
const GET_PROTOCOL: u8 = 0x03;
const SET_REPORT: u8 = 0x09;
const SET_IDLE: u8 = 0x0A;
const SET_PROTOCOL: u8 = 0x0B;

/// HID report types (wValue high byte on GET/SET_REPORT).
const REPORT_TYPE_FEATURE: u8 = 3;

/// The Yubico CRC-16 (`yubikit` `calculate_crc`, poly 0x8408, init 0xFFFF).
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb == 1 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

/// Runs one Yubico OTP command: `slot` + 64-byte payload in, up to 64 bytes of
/// response data out (the return value is its length; 0 = no data frame —
/// the C firmware stages no frame when the APDU answers without data, which is
/// how configure/update/swap communicate "read the idle status instead").
///
/// Runs strictly synchronously inside the USB control transfer (see the module
/// docs): it may mutate the app and persist, but must not block on a future.
pub type FrameHandler = fn(slot: u8, payload: &[u8; SLOT_DATA_SIZE], resp: &mut [u8; SLOT_DATA_SIZE]) -> usize;

/// Fills the idle status report — `[0, ver[3], prog_seq, flags, 0, status]`.
pub type StatusHandler = fn(status: &mut [u8; FEATURE_REPORT_SIZE]);

// ---------------------------------------------------------------------------
// The frame state machine
// ---------------------------------------------------------------------------

static mut FRAME_RX: [u8; FRAME_SIZE] = [0; FRAME_SIZE];
static mut FRAME_TX: [u8; FRAME_SIZE] = [0; FRAME_SIZE];
static mut EXP_SEQ: u8 = 0;
static mut CURR_SEQ: u8 = 0;
/// Remaining TX payload bytes — the C's `send_buffer_size`.
static mut TX_REMAINING: u16 = 0;
static mut FRAME_HANDLER: Option<FrameHandler> = None;
static mut STATUS_HANDLER: Option<StatusHandler> = None;

/// Installs the app-side handlers. Called once on the boot path, before the
/// USB device is built and therefore before any host can reach the interface.
///
/// # Panics
///
/// On a second call — the install is write-once because the handlers run on
/// bare statics below and an instalment race would be a boot-ordering bug,
/// not a runtime condition to recover from.
pub fn install(frame: FrameHandler, status: StatusHandler) {
    // SAFETY: single write on the boot path; no task is running yet.
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(FRAME_HANDLER);
        assert!(slot.is_none(), "otp_hid handlers installed twice");
        *slot = Some(frame);
        *core::ptr::addr_of_mut!(STATUS_HANDLER) = Some(status);
    }
}

/// Test-only: clear the machine and handlers, so each test can install its
/// own pair. The device build never calls this — the install is write-once
/// there.
#[cfg(test)]
fn reset_for_tests() {
    // SAFETY: test-only; single-threaded under TEST_LOCK.
    unsafe {
        *core::ptr::addr_of_mut!(FRAME_HANDLER) = None;
        *core::ptr::addr_of_mut!(STATUS_HANDLER) = None;
        FRAME_RX = [0; FRAME_SIZE];
        FRAME_TX = [0; FRAME_SIZE];
        EXP_SEQ = 0;
        CURR_SEQ = 0;
        TX_REMAINING = 0;
    }
}

/// Accepts one host→device feature report (SET_REPORT, type FEATURE).
///
/// A `0xFF` sequence byte resets the transfer state (yubikit
/// `_reset_state` sends `0xFF` padded to the report size after every
/// completed read); `0x80 | seq` carries chunk `seq` of the frame. The frame
/// is processed once chunk 9 lands and the CRC over the 64-byte payload
/// matches the stored CRC — a bad CRC drops the frame silently, the same as
/// the C (`printf("[OTP] Bad CRC!")` and nothing else).
pub fn set_report(report: &[u8; FEATURE_REPORT_SIZE]) {
    let seq_byte = report[FEATURE_REPORT_DATA_SIZE];
    // SAFETY: strictly-synchronous USB control path, single core — the same
    // static discipline as every `boot::` slot in this firmware.
    let state = unsafe {
        &mut *core::ptr::addr_of_mut!(FRAME_RX)
    };
    if seq_byte == RESET_REPORT {
        // SAFETY: same synchronous-section discipline.
        unsafe {
            TX_REMAINING = 0;
            CURR_SEQ = 0;
            EXP_SEQ = 0;
            FRAME_TX = [0; FRAME_SIZE];
        }
        return;
    }
    if seq_byte & SLOT_WRITE_FLAG == 0 {
        return;
    }
    let rseq = seq_byte & SEQUENCE_MASK;
    if rseq >= MAX_SEQ {
        return;
    }
    if rseq == 0 {
        *state = [0; FRAME_SIZE];
    }
    let off = rseq as usize * FEATURE_REPORT_DATA_SIZE;
    state[off..off + FEATURE_REPORT_DATA_SIZE].copy_from_slice(&report[..FEATURE_REPORT_DATA_SIZE]);
    if rseq != MAX_SEQ - 1 {
        return;
    }
    // Frame complete: CRC over the payload, slot after it, CRC stored after
    // the slot — `yubikit` `_format_frame` and the C parser agree.
    // SAFETY: the same synchronous-section discipline as the reads below —
    // this firmware is single-core (RP2350 secure boot, one app running) and
    // these statics are touched only inside the HID frame handler, never
    // concurrently. E0133 requires the acknowledgement explicitly.
    let (stored, slot) = unsafe {
        (
            u16::from_le_bytes([FRAME_RX[65], FRAME_RX[66]]),
            FRAME_RX[SLOT_DATA_SIZE],
        )
    };
    if crc16(&state[..SLOT_DATA_SIZE]) != stored {
        return;
    }
    let handler = unsafe { *core::ptr::addr_of_mut!(FRAME_HANDLER) };
    let Some(handler) = handler else { return };
    let mut payload = [0u8; SLOT_DATA_SIZE];
    payload.copy_from_slice(&state[..SLOT_DATA_SIZE]);
    let mut resp = [0u8; SLOT_DATA_SIZE];
    let len = handler(slot, &payload, &mut resp);
    if len == 0 || len > SLOT_DATA_SIZE {
        return;
    }
    // Stage the response frame: data || ~crc LE (`otp_send_frame`).
    let crc = crc16(&resp[..len]);
    let mut frame = [0u8; FRAME_SIZE];
    frame[..len].copy_from_slice(&resp[..len]);
    frame[len..len + 2].copy_from_slice(&(!crc).to_le_bytes());
    // SAFETY: same synchronous-section discipline.
    unsafe {
        FRAME_TX = frame;
        let total = (len + 2) as u16;
        TX_REMAINING = total;
        EXP_SEQ = total.div_ceil(FEATURE_REPORT_DATA_SIZE as u16) as u8;
        CURR_SEQ = 0;
    }
}

/// Serves one device→host feature report (GET_REPORT, type FEATURE).
///
/// Pending response chunks go out first (`0x40 | seq`), then a single
/// terminator (`0x40`, sequence 0 — how yubikit detects "transmission
/// complete"), then the idle status report for as long as nothing else is
/// pending (`OtpProtocol` polls this at construction and after every write).
pub fn get_report(report: &mut [u8; FEATURE_REPORT_SIZE]) {
    // SAFETY: strictly-synchronous USB control path, single core.
    let (remaining, curr, exp) = unsafe {
        (
            *core::ptr::addr_of_mut!(TX_REMAINING),
            *core::ptr::addr_of_mut!(CURR_SEQ),
            *core::ptr::addr_of_mut!(EXP_SEQ),
        )
    };
    if remaining > 0 {
        let seq = curr;
        let off = seq as usize * FEATURE_REPORT_DATA_SIZE;
        let n = (remaining as usize).min(FEATURE_REPORT_DATA_SIZE);
        report[..FEATURE_REPORT_DATA_SIZE].fill(0);
        // SAFETY: same synchronous-section discipline as above.
        let tx = unsafe { &FRAME_TX[off..off + n] };
        report[..n].copy_from_slice(tx);
        report[FEATURE_REPORT_DATA_SIZE] = RESP_PENDING_FLAG | seq;
        // SAFETY: same synchronous-section discipline.
        unsafe {
            TX_REMAINING = remaining - n as u16;
            CURR_SEQ = curr + 1;
        }
        return;
    }
    if curr == exp && exp > 0 {
        // All data chunks served: one terminator, then back to idle.
        report.fill(0);
        report[FEATURE_REPORT_DATA_SIZE] = RESP_PENDING_FLAG;
        // SAFETY: same synchronous-section discipline.
        unsafe {
            CURR_SEQ = 0;
            EXP_SEQ = 0;
        }
        return;
    }
    let handler = unsafe { *core::ptr::addr_of_mut!(STATUS_HANDLER) };
    match handler {
        Some(handler) => handler(report),
        None => report.fill(0),
    }
}

/// Decide a control-IN request addressed to the OTP HID interface.
///
/// Descriptor requests are pure (returnable as [`InReply::Data`]); GET_REPORT
/// is *stateful* — the caller (the `usb.rs` handler) must call
/// [`get_report`] into its own buffer instead, so this helper rejects it and
/// the handler answers it before consulting here.
pub fn control_in(request: u8, value: u16) -> InReply {
    match request {
        GET_DESCRIPTOR => match (value >> 8) as u8 {
            0x22 => InReply::Data(OTP_HID_REPORT_DESCRIPTOR),
            0x21 => InReply::Data(OTP_HID_CLASS_DESCRIPTOR),
            _ => InReply::Rejected,
        },
        GET_IDLE => InReply::Data(&[0]),
        GET_PROTOCOL => InReply::Data(&[1]), // report protocol (default)
        GET_REPORT => InReply::Rejected,     // stateful — served by the caller
        _ => InReply::Rejected,
    }
}

/// Decide a control-OUT request addressed to the OTP HID interface.
///
/// SET_REPORT with a feature report has already been fed to [`set_report`]
/// by the caller; everything else classifies here.
pub fn control_out(request: u8, value: u16) -> OutReply {
    match request {
        SET_REPORT => {
            if (value >> 8) as u8 == REPORT_TYPE_FEATURE {
                OutReply::Accepted
            } else {
                OutReply::Rejected
            }
        }
        SET_IDLE | SET_PROTOCOL => OutReply::Accepted,
        _ => OutReply::Rejected,
    }
}

#[cfg(all(test, not(target_arch = "arm")))]
mod tests {
    use super::*;
    // The state machine lives in shared statics; the stateful tests must not
    // interleave, so every test that installs handlers holds this lock.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `crc16` must match yubikit's `calculate_crc` — the reference values are
    /// hand-computed with the same polynomial (ykpers `YK_CRC_OK_RESIDUAL`
    /// test: crc over `data || ~crc` must reach the 0xF0B8 residual).
    #[test]
    fn crc16_matches_yubikit() {
        // The residual identity: crc16(data ++ ~crc16(data) LE) must xor down
        // to the ykpers OK residual. Deriving: feed data, then ~crc, then
        // check the running crc of the concatenation equals 0xF0B8.
        let data = [0x01u8, 0x02, 0x03, 0x04];
        let c = crc16(&data);
        let mut check = 0xFFFFu16;
        for &b in data.iter().chain((!c).to_le_bytes().iter()) {
            check ^= u16::from(b);
            for _ in 0..8 {
                let lsb = check & 1;
                check >>= 1;
                if lsb == 1 {
                    check ^= 0x8408;
                }
            }
        }
        assert_eq!(check, 0xF0B8);
    }

    /// The report descriptor's application collection usage must be
    /// `(page 0x0001, usage 0x0006)` — ykman's OTP-transport filter.
    #[test]
    fn descriptor_usage_is_otp_keyboard() {
        assert_eq!(&OTP_HID_REPORT_DESCRIPTOR[..4], &[0x05, 0x01, 0x09, 0x06]);
        assert_eq!(OTP_HID_REPORT_DESCRIPTOR.last(), Some(&0xC0));
    }

    /// The class descriptor's wDescriptorLength must name the report
    /// descriptor's length (the field pcscd/usbhid probe).
    #[test]
    fn class_descriptor_names_report_length() {
        let len =
            OTP_HID_CLASS_DESCRIPTOR[7] as u16 | ((OTP_HID_CLASS_DESCRIPTOR[8] as u16) << 8);
        assert_eq!(len, OTP_HID_REPORT_DESCRIPTOR.len() as u16);
    }

    /// A no-op handler pair so the state machine below can run standalone.
    static NOOP_FRAME: fn(u8, &[u8; 64], &mut [u8; 64]) -> usize =
        |_slot, _payload, _resp| 0;

    /// Splits a frame into the 10 host chunks yubikit sends (`0x80 | seq`,
    /// skipping all-zero chunks except the first and last).
    fn host_chunks(frame: &[u8; 70]) -> [[u8; 8]; 10] {
        let mut chunks = [[0u8; 8]; 10];
        for (i, chunk) in chunks.iter_mut().enumerate() {
            chunk[..7].copy_from_slice(&frame[i * 7..i * 7 + 7]);
            chunk[7] = 0x80 | i as u8;
        }
        chunks
    }

    fn build_frame(slot: u8, payload: &[u8]) -> [u8; 70] {
        let mut frame = [0u8; 70];
        frame[..64].copy_from_slice(payload);
        frame[64] = slot;
        let crc = crc16(&frame[..64]);
        frame[65..67].copy_from_slice(&crc.to_le_bytes());
        frame
    }

    /// Full yubikit-style exchange: ping frame in, response frame out.
    #[test]
    fn ping_round_trip() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_for_tests();
        fn frame(slot: u8, _payload: &[u8; 64], resp: &mut [u8; 64]) -> usize {
            assert_eq!(slot, 0x01); // PING
            resp[..3].copy_from_slice(b"abc");
            3
        }
        fn status(report: &mut [u8; 8]) {
            *report = [0, 5, 1, 0, 0, 0, 0, 0];
        }
        install(frame, status);

        let payload = [0x42u8; 64];
        let f = build_frame(0x01, &payload);
        for chunk in host_chunks(&f) {
            set_report(&chunk);
        }

        // Host reads: 1 data chunk (3 bytes → 1 report), terminator, status.
        let mut report = [0u8; 8];
        get_report(&mut report);
        assert_eq!(report[7], 0x40); // RESP_PENDING | seq 0
        assert_eq!(&report[..3], b"abc");
        get_report(&mut report);
        assert_eq!(report[7], 0x40); // terminator (seq 0)
        get_report(&mut report);
        assert_eq!(report[..3], [0, 5, 1]); // idle status: version
        assert_eq!(report[7], 0);
    }

    /// A 64-byte response spans 10 chunks; the terminator lands after the
    /// tenth, and the reset report clears a mid-transfer state.
    #[test]
    fn full_frame_response_and_reset() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_for_tests();
        fn frame(_slot: u8, _payload: &[u8; 64], resp: &mut [u8; 64]) -> usize {
            resp.fill(0xAB);
            64
        }
        fn status(report: &mut [u8; 8]) {
            *report = [0; 8];
        }
        install(frame, status);

        let f = build_frame(0x30, &[0u8; 64]);
        for chunk in host_chunks(&f) {
            set_report(&chunk);
        }
        let mut report = [0u8; 8];
        for i in 0..10 {
            get_report(&mut report);
            assert_eq!(report[7], 0x40 | i);
        }
        get_report(&mut report);
        assert_eq!(report[7], 0x40); // terminator
        // Host resets state; the next read is idle status again.
        set_report(&{
            let mut r = [0u8; 8];
            r[7] = RESET_REPORT;
            r
        });
        get_report(&mut report);
        assert_eq!(report, [0; 8]);
    }

    /// A frame with a bad CRC is dropped — no response, no status change.
    #[test]
    fn bad_crc_drops_frame() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_for_tests();
        static CALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        fn frame(_slot: u8, _payload: &[u8; 64], _resp: &mut [u8; 64]) -> usize {
            CALLED.store(true, core::sync::atomic::Ordering::SeqCst);
            0
        }
        fn status(report: &mut [u8; 8]) {
            *report = [0; 8];
        }
        install(frame, status);

        let mut f = build_frame(0x01, &[0u8; 64]);
        f[66] ^= 0xFF; // corrupt the stored CRC
        for chunk in host_chunks(&f) {
            set_report(&chunk);
        }
        assert!(!CALLED.load(core::sync::atomic::Ordering::SeqCst));
        let mut report = [0u8; 8];
        get_report(&mut report);
        assert_eq!(report[7], 0); // straight to idle status
    }

    /// The idle status report is the yubikit layout: version at [1:4],
    /// programming sequence at [4].
    #[test]
    fn idle_status_layout() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_for_tests();
        fn status(report: &mut [u8; 8]) {
            *report = [0, 1, 0, 0, 7, 0x03, 0, 0];
        }
        install(NOOP_FRAME, status);
        let mut report = [0u8; 8];
        get_report(&mut report);
        assert_eq!(&report[1..4], &[1, 0, 0]);
        assert_eq!(report[4], 7);
        assert_eq!(report[7], 0); // not SLOT_WRITE_FLAG — ready to receive
    }

    /// GET_REPORT is not answerable from the pure decision table (the caller
    /// must serve it statefully); everything else classifies as in
    /// `hid_control`.
    #[test]
    fn control_classification() {
        assert_eq!(control_in(GET_DESCRIPTOR, 0x2200), InReply::Data(OTP_HID_REPORT_DESCRIPTOR));
        assert_eq!(control_in(GET_DESCRIPTOR, 0x2100), InReply::Data(OTP_HID_CLASS_DESCRIPTOR));
        assert_eq!(control_in(GET_DESCRIPTOR, 0x2300), InReply::Rejected);
        assert_eq!(control_in(GET_IDLE, 0), InReply::Data(&[0]));
        assert_eq!(control_in(GET_PROTOCOL, 0), InReply::Data(&[1]));
        assert_eq!(control_in(GET_REPORT, 0x0300), InReply::Rejected);
        assert_eq!(
            control_out(SET_REPORT, 0x0300),
            OutReply::Accepted
        );
        assert_eq!(control_out(SET_REPORT, 0x0200), OutReply::Rejected);
        assert_eq!(control_out(SET_IDLE, 0), OutReply::Accepted);
        assert_eq!(control_out(SET_PROTOCOL, 0), OutReply::Accepted);
        assert_eq!(control_out(0x7F, 0), OutReply::Rejected);
    }
}
