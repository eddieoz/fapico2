//! Yubico OTP HID transport wiring: the app-side handlers
//! [`fapico2_platform::otp_hid::install`] consumes.
//!
//! Yubico Authenticator drives the OTP app over the YK4 frame protocol on the
//! keyboard-usage HID interface's **feature reports** (see
//! [`fapico2_platform::otp_hid`] for the byte-level protocol). The platform
//! state machine reassembles frames and needs two callbacks:
//!
//! * [`frame`] — run one `INS 0x01` OTP APDU (the same APDU the CCID path
//!   carries at AID `A0000005272001`) through the OTP app, and stage a
//!   response only when the command answers *with data* (calculate). A
//!   configure/update/swap answers status-only, so no frame goes out and the
//!   host detects success by the programming-sequence increment on the idle
//!   status report — byte-for-byte the C firmware's HID behavior
//!   (`pico-fido/src/fido/otp.c` `otp_hid_set_report_cb`, where
//!   `otp_status(_is_otp)` resets `res_APDU_size` to 0).
//! * [`status`] — the idle status report: version, programming sequence,
//!   slot-configured flags.
//!
//! Both run strictly synchronously inside the USB control transfer (single
//! core, cooperative executor — no `.await`, so a CCID command can never
//! interleave), which is the same discipline the US-425 persist gates and the
//! shared store/flash handles in `tasks.rs` rest on. The OTP app itself lives
//! in `boot::OTP_APP`, written once on the boot path *before* the USB device
//! is built, so no host can reach a handler before the slot is initialized.
//!
//! Durable-before-ack: a frame that mutated OTP slots is persisted through
//! the same [`fapico2_platform::persist::persist_one`] gate the CTAP-HID path
//! uses, before the response frame is staged. A failed program leaves the app
//! dirty (the gate's contract), so the next CCID command's persist run
//! flushes the same state — the host saw the success, and the record still
//! lands; a flash failure here is of the fatal-boot class on this hardware,
//! not a condition to unwind out of a control callback.

use fapico2_oath::OtpApp;
use fapico2_platform::dispatch::{App, MAX_RESPONSE};

/// INS_OTP — the single instruction the OTP app answers (C `otp.c`).
const INS_OTP: u8 = 0x01;

/// The OTP app out of its write-once boot slot.
///
/// SAFETY: `boot::OTP_APP` is initialized on the boot path
/// (`boot::init_static_slot`) before `Usb::new` runs, so before any host can
/// reach the OTP interface; this module is its only runtime accessor outside
/// the CCID dispatcher (which received its own handle at registration and
/// only touches the app inside strictly-synchronous dispatch — as does this
/// handler, so the two cannot interleave on the single-core executor).
fn otp_app() -> &'static mut OtpApp {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(crate::boot::OTP_APP)).assume_init_mut()
    }
}

/// One YK4 frame → one OTP APDU → 0 or up-to-64 response bytes.
fn frame(slot: u8, payload: &[u8; 64], resp: &mut [u8; 64]) -> usize {
    let app = otp_app();
    let mut apdu = [0u8; 5 + 64];
    apdu[1] = INS_OTP;
    apdu[2] = slot;
    apdu[4] = 64; // Lc
    apdu[5..].copy_from_slice(payload);
    let mut out = heapless::Vec::<u8, MAX_RESPONSE>::new();
    app.process(&apdu, &mut out);
    let n = out.len();
    if n < 2 || out[n - 2..] != [0x90, 0x00] {
        return 0;
    }
    let data_len = (n - 2).min(64);
    resp[..data_len].copy_from_slice(&out[..data_len]);
    // Durable-before-ack (see module docs): flush a mutated slot table before
    // the response frame exists for the host to read.
    if App::is_dirty(app) {
        let mut store = crate::boot::store_handle();
        // SAFETY: FLASH_DEV is initialized on the boot path before any task
        // spawns (see `tasks.rs`); this synchronous section is its accessor.
        let flash = unsafe { (&mut *core::ptr::addr_of_mut!(crate::boot::FLASH_DEV)).as_mut_ptr() };
        let mut sink = crate::tasks::secure_slot_sink(unsafe { &mut *flash });
        let wrote = fapico2_platform::persist::persist_one(app, &mut store, &mut sink);
        if !wrote && App::is_dirty(app) {
            defmt::warn!("otp hid persist failed; app left dirty for next persist run");
        }
    }
    data_len
}

/// The idle status report: `[0, ver_major, ver_minor, 0, prog_seq, flags, 0,
/// 0]`. The version mirrors the management applet's `TAG_VERSION` (one
/// firmware, one version); `prog_seq` is the *read-only* programming sequence
/// (the C `config_seq` — bumped only by configure/update/swap, which is what
/// yubikit's `_is_sequence_updated` success detection requires).
fn status(report: &mut [u8; 8]) {
    let app = otp_app();
    *report = [
        0,
        fapico2_mgmt::VERSION_MAJOR,
        fapico2_mgmt::VERSION_MINOR,
        0,
        app.program_sequence(),
        app.flags(),
        0,
        0,
    ];
}

/// Install both handlers. Called once on the boot path after `boot::OTP_APP`
/// is initialized and before the USB device is built.
pub fn init() {
    fapico2_platform::otp_hid::install(frame, status);
}
