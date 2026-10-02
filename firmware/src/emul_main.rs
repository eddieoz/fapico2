//! Emulation entry point for the fapico2 firmware (US-304).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use fapico2_fido::app::FidoApp;
use fapico2_mgmt::{FactoryResetHandler, ManagementApp};
use fapico2_firmware::{oath_device_id, EMULATION_CHIPID};
use fapico2_oath::oath_core::OathApp;
use fapico2_oath::{OathSeal, OtpApp};
use fapico2_platform::secure_store::{HostSecureStore, SecureStore};
use fapico2_platform::store_v3::{boot_decision_sealed, SealedBootDecision};
use fapico2_platform::trng::HostTrng;
use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::trusted_backend::with_host_backend;
use fapico2_piv::PivApp;
use fapico2_vendor_led::VendorLedApp;
use fapico2_rescue::{
    FlashStats, PhySnapshot, PhyUpdate, RebootMode, RescueApp, RescueConfigHandler,
    RescueDeviceHandler,
};
use fapico2_fido::keystore::FileKeystore;
use fapico2_platform::dispatch::{App, Dispatcher, MAX_RESPONSE};
use fapico2_platform::persist::{
    persist_apps, persist_boot_change, persist_one, pull_image, ImageSink, Persist,
    WindowedImageSource,
};
use fapico2_platform::emulation::{EmulationTransport, DEFAULT_CCID_PORT, DEFAULT_HID_PORT};
use fapico2_firmware::presence::{TouchWindow, CTAP_TOUCH_WINDOW_MS};
use heapless::Vec as HeaplessVec;

const HID_REPORT_SIZE: usize = 64;

/// US-711 emulation parity: the emulation stand-in for the device's
/// `boot::RESET_GENERATION` counter (`firmware/src/boot.rs`). The factory
/// reset handler below bumps it; the serve loop observes it at the same
/// point the device's `ccid_task` does (`firmware/src/tasks.rs`: after the
/// dispatch, before the persist gate) and wipes the task-owned apps, so the
/// persist gate flushes their emptied state durable-before-ack.
static EMUL_RESET_GENERATION: AtomicU32 = AtomicU32::new(0);

/// US-711 emulation parity: the emulation stand-in for the device's
/// `DeviceFactoryResetHandler`. The device handler additionally deletes the
/// FIDO/OpenPGP secure-store slots so a power cut mid-reset boots
/// factory-fresh; in the emulation the durable media live in the owning
/// tasks' files (keystore file, partition file) and the serve loop wipes
/// them through the apps themselves before the persist gate, so there is
/// nothing for this handler to delete out from under a task. It only
/// signals the generation, exactly like the device handler's tail.
struct EmulFactoryResetHandler;

impl FactoryResetHandler for EmulFactoryResetHandler {
    fn factory_reset(&mut self) -> fapico2_platform::dispatch::Sw {
        EMUL_RESET_GENERATION.fetch_add(1, Ordering::AcqRel);
        fapico2_platform::dispatch::SW_OK
    }
}

// SAFETY: write-once `static mut` — initialized by the const initializer
// and never reassigned; the emulation is a single-threaded host task, so
// the `&mut` handed to the management app below cannot alias any other
// reference (US-905 aliasing discipline).
static mut EMUL_FACTORY_RESET_HANDLER: EmulFactoryResetHandler = EmulFactoryResetHandler;

/// US-161/162 (PICOForge-COMPAT Phase H): the emulation's owner of the Rescue
/// PHY record.
///
/// **On the device that record is the FIDO keystore's auth-map key 6**, reached
/// durable-before-ack through the secure store, with a generation counter
/// telling the HID task to catch up (`firmware/src/boot.rs`). The emulation
/// cannot mirror that arrangement: its FIDO app holds a `FileKeystore` on the
/// HID path, and reaching into it from the CCID path would alias a `&mut` the
/// HID loop owns — the same aliasing the device handler's own docs refuse, and
/// the emulation's store is a plain `main`-local rather than the
/// `SharedStore`/`static RefCell` pair the device uses.
///
/// So the emulation keeps the record in **its own small file**. That is a
/// stand-in, not a claim: it is written before the `9000` is answered
/// (durable-before-ack, so the harness test cannot pass against a persistence
/// bug) and it survives an emulator restart, so
/// `test_rescue_write.py::phy_write_roundtrips` exercises a real
/// write/restart/read round trip. It is not the slot the device uses. The
/// *protocol* — TLV parse, width rules, the seven undestined tags, the
/// CCID-mask guard, the merge — is the applet's own code and is exercised
/// identically here and on the device.
///
/// The file is a fixed nine bytes — `mask(1) ‖ vid_pid(4 BE) ‖
/// led_gpio+brightness(2) ‖ options(2 BE)` — so the **whole** record round-trips
/// and a blob from a build with a different field set is length-refused rather
/// than reinterpreted. Every field is stored at the width `PhySnapshot` types
/// it at, so nothing is truncated into a different value on the way through.
const EMUL_RESCUE_PHY_LEN: usize = 9;

struct EmulRescueConfig {
    cell: std::cell::RefCell<PhySnapshot>,
    path: std::path::PathBuf,
}

impl EmulRescueConfig {
    /// The record file: `FAPICO2_RESCUE_PHY`, else a fixed name in the temp
    /// directory. A private default so it cannot collide with the keystore or
    /// partition files the other suites clean up.
    fn default_path() -> std::path::PathBuf {
        match std::env::var("FAPICO2_RESCUE_PHY") {
            Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
            _ => std::env::temp_dir().join("fapico2_rescue_phy.bin"),
        }
    }

    fn new() -> Self {
        let path = Self::default_path();
        let mut snap = PhySnapshot::default();
        if let Ok(raw) = std::fs::read(&path) {
            if raw.len() == EMUL_RESCUE_PHY_LEN {
                snap.enabled_usb_itf = Some(u16::from(raw[0]));
                snap.vid_pid = Some(u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]));
                snap.led_gpio = opt_byte(raw[5]);
                snap.led_brightness = opt_byte(raw[6]);
                snap.options = Some(u16::from_be_bytes([raw[7], raw[8]]));
            }
        }
        Self {
            cell: std::cell::RefCell::new(snap),
            path,
        }
    }
}

fn opt_byte(b: u8) -> Option<u8> {
    if b == 0 {
        None
    } else {
        Some(b)
    }
}

impl RescueConfigHandler for EmulRescueConfig {
    fn snapshot(&self) -> PhySnapshot {
        *self.cell.borrow()
    }

    fn commit(&mut self, update: &PhyUpdate) -> fapico2_platform::dispatch::Sw {
        {
            let mut s = self.cell.borrow_mut();
            if update.vid_pid.is_some() {
                s.vid_pid = update.vid_pid;
            }
            if update.led_gpio.is_some() {
                s.led_gpio = update.led_gpio;
            }
            if update.led_brightness.is_some() {
                s.led_brightness = update.led_brightness;
            }
            if update.options.is_some() {
                s.options = update.options;
            }
            if update.enabled_usb_itf.is_some() {
                s.enabled_usb_itf = update.enabled_usb_itf;
            }
        }
        let s = *self.cell.borrow();
        let vid_pid = s.vid_pid.unwrap_or(0).to_be_bytes();
        let options = s.options.unwrap_or(0).to_be_bytes();
        let raw = [
            s.enabled_usb_itf.unwrap_or(0) as u8,
            vid_pid[0],
            vid_pid[1],
            vid_pid[2],
            vid_pid[3],
            s.led_gpio.unwrap_or(0),
            s.led_brightness.unwrap_or(0),
            options[0],
            options[1],
        ];
        if std::fs::write(&self.path, raw).is_err() {
            // Nothing is acknowledged when the record did not reach the
            // medium: a `9000` here would tell the operator a configuration
            // change is durable when it is not, and this applet exists for
            // recovery.
            return 0x6F00;
        }
        fapico2_platform::dispatch::SW_OK
    }
}

/// US-163 (PICOForge-COMPAT Phase H): the emulation's `REBOOT` / `SECURE`.
///
/// `SECURE` mirrors the device and **refuses every request** with `0x6A86`:
/// nothing in this firmware implements secure boot, so a lock would cost the
/// owner a permanent reconfiguration lockout and prevent no reflash
/// (threat model §0.3, §6.1 objection 1, R9).
///
/// `REBOOT` records the request on stderr and answers `9000` **without
/// rebooting**. The emulation process *is* the card: there is no bootrom, no
/// watchdog and no BOOTSEL mass-storage interface to enter, and a process that
/// actually exited would take the whole pytest session's emulator with it —
/// `run_openpgp_tests.sh`'s stale-port guard is precisely the shape of that
/// failure. The log line is what `test_rescue_reboot.py` asserts against, so
/// both modes are still exercised end to end over CCID.
struct EmulRescueDevice;

impl RescueDeviceHandler for EmulRescueDevice {
    fn reboot(&mut self, mode: RebootMode) -> fapico2_platform::dispatch::Sw {
        eprintln!(
            "rescue: REBOOT requested mode={} (normal=0 bootsel=1); \
             the emulation does not reboot the host process",
            mode.p1()
        );
        fapico2_platform::dispatch::SW_OK
    }

    fn set_secure_boot(&mut self, key_index: u8, lock: bool) -> fapico2_platform::dispatch::Sw {
        eprintln!(
            "rescue: SECURE key={} lock={} refused: this firmware implements \
             no secure boot",
            key_index, lock
        );
        0x6A86
    }
}

/// SAFETY: write-once `static mut`s, the same aliasing discipline as
/// `EMUL_FACTORY_RESET_HANDLER` above. The config handler is not
/// const-initializable (it reads its file in `new()`), so it is filled in by
/// the boot path through `emul_init_rescue_handler` before the serve loop.
static mut EMUL_RESCUE_CONFIG_HANDLER: Option<EmulRescueConfig> = None;
static mut EMUL_RESCUE_DEVICE_HANDLER: EmulRescueDevice = EmulRescueDevice;

/// Fill the config handler's write-once slot, on the boot path, before any
/// task exists — the same discipline as the device's
/// `boot::init_static_slot`. Private to this binary: nothing outside it has a
/// use for the handle.
///
/// # Safety
/// Single-threaded boot path; the returned `&'static mut` is the only handle
/// to the value afterwards.
fn emul_init_rescue_handler() -> &'static mut EmulRescueConfig {
    unsafe {
        let slot = &mut *core::ptr::addr_of_mut!(EMUL_RESCUE_CONFIG_HANDLER);
        *slot = Some(EmulRescueConfig::new());
        slot.as_mut().unwrap()
    }
}
const HID_FIRST_PAYLOAD: usize = HID_REPORT_SIZE - 7;
const HID_CONT_PAYLOAD: usize = HID_REPORT_SIZE - 5;

const CTAP_HID_INIT: u8 = 0x06;
const CTAP_HID_CBOR: u8 = 0x10;
const CTAP_HID_PING: u8 = 0x01;
const CTAP_HID_MSG: u8 = 0x03; // U2F (CTAP1) over HID
const CTAP_HID_WINK: u8 = 0x08;
const CTAP_HID_KEEPALIVE: u8 = 0x3B;
const CTAP_HID_ERROR: u8 = 0x3F;
const TYPE_INIT: u8 = 0x80;

/// US-1505: `CTAPHID_CANCEL` (`0x11`). Kept as a local constant beside the
/// six above because this file keeps its own copy of the command table —
/// US-1524 moves the whole emulator onto `hid_serve`'s dispatcher and
/// deletes the duplication. The *value* has one definition of record
/// elsewhere, [`fapico2_firmware::ctap_hid::CTAP_HID_CANCEL`], and
/// `hid_cancel_wins_over_the_unknown_command_arm` below asserts this copy
/// still agrees with it, so the two cannot drift apart in the meantime.
const CTAP_HID_CANCEL: u8 = fapico2_firmware::ctap_hid::CTAP_HID_CANCEL;

/// US-1505: the byte a cancelled consent window answers with, from the one
/// definition of record (`ctap_hid::CTAP2_ERR_KEEPALIVE_CANCEL`) rather than
/// a fourth local constant.
const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = fapico2_firmware::ctap_hid::CTAP2_ERR_KEEPALIVE_CANCEL;

/// US-1506: the keepalive status constants, from the one definition of
/// record rather than a fifth and sixth local constants.
const CTAPHID_KEEPALIVE_PROCESSING: u8 =
    fapico2_firmware::ctap_hid::CTAPHID_KEEPALIVE_PROCESSING;

/// US-1505: "a `CTAPHID_CANCEL` arrived while a consent window was open".
///
/// The emulator's consent loop is still the pre-US-1509 nested `loop` — a
/// `CTAPHID_CANCEL` dispatched on the next turn of the outer loop could not
/// reach it, which is the blackout `PendingUp` exists to end and US-1524
/// exists to finish here. The minimum that makes the command *do* something
/// on this path without pre-empting that migration is a latch the loop
/// polls, which is the same cross-task signal the device gets from the
/// serve loop simply observing the frame.
///
/// `swap`-and-clear rather than `load`: "observed at most once" is a property
/// of one function instead of a convention at three call sites.
static EMUL_CANCEL_PENDING: AtomicBool = AtomicBool::new(false);

/// Is a `CTAPHID_CANCEL` waiting to be acted on? Consumes the latch.
fn take_pending_cancel() -> bool {
    EMUL_CANCEL_PENDING.swap(false, Ordering::SeqCst)
}

/// US-1505: what one turn of an emulator consent window decided.
///
/// [`ConsentTick::Expired`] and [`ConsentTick::Cancelled`] both mean the
/// window is over, and both have already released the presence slot and the
/// prompt on the way out — so the two call sites cannot forget half the
/// teardown, which is the US-921 leak this pairing exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsentTick {
    /// Still waiting for a touch: re-assert the prompt and re-drive.
    KeepWaiting,
    /// The window ran out on its own deadline.
    Expired,
    /// The host sent `CTAPHID_CANCEL`.
    Cancelled,
}

/// One turn of an emulator consent window: the whole stop-condition, in one
/// place, for both the CBOR and the U2F loop.
///
/// Cancel is checked **before** expiry. When both are true — the deadline
/// passed on the same turn the host gave up — `Cancelled` is the honest
/// report: the host is not waiting for a timeout any more, and answering it
/// as though a touch window simply ran out describes a ceremony the host has
/// already abandoned.
fn emul_consent_tick(win: &TouchWindow) -> ConsentTick {
    let tick = if take_pending_cancel() {
        ConsentTick::Cancelled
    } else if win.expired(emul_now_ms()) {
        ConsentTick::Expired
    } else {
        return ConsentTick::KeepWaiting;
    };
    fapico2_firmware::presence::end_window(win.tag);
    fapico2_firmware::presence::touch_prompt(false);
    tick
}

/// US-1505: the emulator's own copy of the CTAPHID CANCEL rule — the one
/// sentence `hid_serve` and `pico-keys-sdk` both have to say the same way.
/// Named as a function so the dispatcher's arm and the test below are two
/// callers of one definition.
fn hid_is_cancel(cmd: u8) -> bool {
    cmd == CTAP_HID_CANCEL
}

// CTAPHID error codes (CTAP spec §11.2.4).
const HID_ERR_INVALID_CMD: u8 = 0x01;
const HID_ERR_INVALID_SEQ: u8 = 0x04;
const HID_ERR_TIMEOUT: u8 = 0x05;
const HID_ERR_CHANNEL_BUSY: u8 = 0x06;
const HID_ERR_INVALID_CHANNEL: u8 = 0x0B;
const HID_ERR_INVALID_LEN: u8 = 0x03;

/// Broadcast channel: only INIT may be issued from it.
const HID_CID_BROADCAST: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
/// Reserved channel: no commands accepted from it.
const HID_CID_RESERVED: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Maximum CTAPHID message size per the FIDO spec (7609 bytes).
const CTAPHID_MAX_MSG: usize = 7609;
/// Transaction idle timeout before a 0xBF/TIMEOUT error frame is sent.
const HID_TRANSACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Reassembles fragmented CTAP-HID frames.
struct HidAssembler {
    channel: [u8; 4],
    cmd: u8,
    total_len: usize,
    received: usize,
    payload: Vec<u8>,
    expecting_cont: bool,
    seq: u8,
    last_activity: std::time::Instant,
}

/// Result of feeding one 64-byte report to the assembler.
enum HidFeed {
    /// The frame is consumed; more continuation packets are needed.
    NeedMore,
    /// A complete message is ready for dispatch.
    Ready(u8, Vec<u8>),
    /// A framing error was detected; an 0xBF error frame must be sent
    /// to the given channel with the given error code.
    Err([u8; 4], u8),
}

impl HidAssembler {
    fn new() -> Self {
        Self {
            channel: [0; 4],
            cmd: 0,
            total_len: 0,
            received: 0,
            payload: Vec::new(),
            expecting_cont: false,
            seq: 0,
            last_activity: std::time::Instant::now(),
        }
    }

    /// If a transaction has been idling awaiting continuations for too
    /// long, emit a TIMEOUT error frame and reset the transaction.
    fn check_timeout(&mut self) -> Option<([u8; 4], u8)> {
        if self.expecting_cont && self.last_activity.elapsed() >= HID_TRANSACTION_TIMEOUT {
            self.expecting_cont = false;
            return Some((self.channel, HID_ERR_TIMEOUT));
        }
        None
    }

    /// Feed a raw HID frame (64 bytes after ccid decode).
    fn feed(&mut self, frame: &[u8]) -> HidFeed {
        if frame.len() < 5 {
            return HidFeed::NeedMore;
        }

        let channel: [u8; 4] = [frame[0], frame[1], frame[2], frame[3]];
        let cmd_byte = frame[4];

        if cmd_byte & TYPE_INIT != 0 {
            // Init (first) packet
            if frame.len() < 7 {
                return HidFeed::NeedMore;
            }
            let cmd = cmd_byte & 0x7F;
            let total_len = u16::from_be_bytes([frame[5], frame[6]]) as usize;

            if channel == HID_CID_RESERVED
                || (channel == HID_CID_BROADCAST && cmd != CTAP_HID_INIT)
            {
                // Channel 0 is reserved outright; from the broadcast channel
                // only INIT is legal.
                return HidFeed::Err(channel, HID_ERR_INVALID_CHANNEL);
            }

            if self.expecting_cont && channel != self.channel && cmd != CTAP_HID_INIT {
                // Another channel tried to start a transaction mid-flight.
                return HidFeed::Err(channel, HID_ERR_CHANNEL_BUSY);
            }
            if self.expecting_cont && channel == self.channel && cmd != CTAP_HID_INIT {
                // New init command on the transaction channel mid-flight.
                self.expecting_cont = false;
                return HidFeed::Err(channel, HID_ERR_INVALID_SEQ);
            }

            if total_len > CTAPHID_MAX_MSG {
                self.expecting_cont = false;
                return HidFeed::Err(channel, HID_ERR_INVALID_LEN);
            }

            let chunk = &frame[7..];
            let take = chunk.len().min(total_len);

            self.channel = channel;
            self.cmd = cmd;
            self.total_len = total_len;
            self.received = take;
            self.payload.clear();
            self.payload.extend_from_slice(&chunk[..take]);
            self.expecting_cont = true;
            self.seq = 0;
            self.last_activity = std::time::Instant::now();

            if self.received >= total_len {
                self.expecting_cont = false;
                return HidFeed::Ready(self.cmd, self.payload.clone());
            }
            HidFeed::NeedMore
        } else if self.expecting_cont {
            // Continuation packet — must match channel
            if channel != self.channel {
                return HidFeed::NeedMore;
            }
            let seq_byte = frame[4];
            if seq_byte != self.seq {
                self.expecting_cont = false;
                return HidFeed::Err(self.channel, HID_ERR_INVALID_SEQ);
            }
            let chunk = &frame[5..];
            let space_left = self.total_len.saturating_sub(self.received);
            let take = chunk.len().min(space_left);
            self.payload.extend_from_slice(&chunk[..take]);
            self.received += take;
            self.seq = self.seq.wrapping_add(1);
            self.last_activity = std::time::Instant::now();

            if self.received >= self.total_len {
                self.expecting_cont = false;
                return HidFeed::Ready(self.cmd, self.payload.clone());
            }
            HidFeed::NeedMore
        } else {
            // Stray continuation without an init — drop it
            HidFeed::NeedMore
        }
    }
}

fn send_hid_response(
    transport: &mut EmulationTransport,
    channel: &[u8; 4],
    cmd: u8,
    payload: &[u8],
) {
    let total_len = payload.len();
    if total_len <= HID_FIRST_PAYLOAD {
        let mut frame = vec![0u8; HID_REPORT_SIZE];
        frame[..4].copy_from_slice(channel);
        frame[4] = cmd | TYPE_INIT;
        frame[5..7].copy_from_slice(&(total_len as u16).to_be_bytes());
        frame[7..7 + total_len].copy_from_slice(payload);
        let _ = transport.write_hid(&frame);
    } else {
        let mut first = vec![0u8; HID_REPORT_SIZE];
        first[..4].copy_from_slice(channel);
        first[4] = cmd | TYPE_INIT;
        first[5..7].copy_from_slice(&(total_len as u16).to_be_bytes());
        first[7..7 + HID_FIRST_PAYLOAD].copy_from_slice(&payload[..HID_FIRST_PAYLOAD]);
        let _ = transport.write_hid(&first);

        let mut offset = HID_FIRST_PAYLOAD;
        let mut seq: u8 = 0;
        while offset < total_len {
            let end = (offset + HID_CONT_PAYLOAD).min(total_len);
            let mut cont = vec![0u8; HID_REPORT_SIZE];
            cont[..4].copy_from_slice(channel);
            cont[4] = seq;
            cont[5..5 + (end - offset)].copy_from_slice(&payload[offset..end]);
            let _ = transport.write_hid(&cont);
            offset = end;
            seq += 1;
        }
    }
}

/// US-921: the emulation's monotonic millis clock (the window machinery's
/// injected `now_ms`; std parity of the device's embassy millis).
fn emul_now_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64
}

fn main() {
    env_logger::init();
    // US-921: the emulation mirrors the device window machinery over the
    // same shared runtime. The auto-ack FIDO app makes every windowed
    // loop complete on iteration 1 — this only exercises the slot
    // lifecycle; replies stay byte-identical.
    assert!(
        fapico2_firmware::presence::init(emul_now_ms),
        "presence runtime double-init"
    );
    // FAPICO2_HID_PORT lets the restart tests run a private instance.
    let hid_port = std::env::var("FAPICO2_HID_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_HID_PORT);
    // FAPICO2_CCID_PORT lets a suite run a PRIVATE relay (e.g. the US-923
    // red-team suite on dedicated ports) instead of dialing the shared one.
    let ccid_port = std::env::var("FAPICO2_CCID_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(DEFAULT_CCID_PORT);
    let mut transport = EmulationTransport::new(
        std::net::SocketAddr::from(([127, 0, 0, 1], ccid_port)),
        hid_port,
    )
    .expect("failed to initialize emulation transport");

    // US-354 (S-711-2): the CCID apps share one secure-partition stand-in,
    // exactly as the board shares the RP2350 secure partition — every app
    // boots from it and persists through it. The partition image file
    // mirrors the device's flash snapshot (US-915: the sealed format-v3
    // layout, under the fixed emulation store key), so OATH/OTP/mgmt
    // durable state survives emulator restarts.
    // FAPICO2_SECURE_PARTITION overrides the shared temp path (FX-409).
    let partition_path = match std::env::var("FAPICO2_SECURE_PARTITION") {
        Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => std::env::temp_dir().join("fapico2_secure_partition.bin"),
    };
    eprintln!("secure partition: {}", partition_path.display());
    let mut store = HostSecureStore::new();
    // US-427 + US-915: the emulator's "primary slot" is the partition-file
    // content and its "shadow slot" is empty (the emulation has no second
    // slot). Boot runs the same sealed decision as the device: the file
    // must be a tag-verified v3 image under the emulation store key — a
    // present but corrupt/forged/legacy-v2 partition file is refused with
    // exit 2 (the FX-409 refuse-silently-reset discipline; a lone-v2 slot
    // is exactly the red-team forged-slot shape and is never loaded or
    // migrated in emulation — delete the file to start fresh) BEFORE any
    // app boots, and a missing or empty file is the legal Fresh (first
    // boot) path.
    let primary_img = match std::fs::read(&partition_path) {
        Ok(img) => img,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            eprintln!("fapico2: secure partition read failed ({e:?}); exiting");
            std::process::exit(2);
        }
    };
    let store_key = store.store_key().expect("the host store always has a key");
    match boot_decision_sealed(&primary_img, &[], &store_key) {
        SealedBootDecision::LoadPrimary => store.from_partition_image(&primary_img),
        SealedBootDecision::LoadShadow => {
            unreachable!("emulator shadow slot is the empty slice and cannot validate")
        }
        SealedBootDecision::Fresh => {}
        SealedBootDecision::MigratePrimary | SealedBootDecision::Refuse => {
            eprintln!(
                "fapico2: secure partition image is not a valid sealed v3 image \
                 (legacy v2 or forged); refusing to boot (US-915) — delete {} to \
                 start fresh; exiting",
                partition_path.display()
            );
            std::process::exit(2);
        }
    }
    // US-919: foreign-image boot admission (device parity, device main.rs).
    // The host has no XIP flash region to walk, so the "running image" hash
    // is a deterministic stand-in: FAPICO2_FW_HASH (64 hex chars) or the
    // fixed [`fw_manifest::EMUL_FAKE_FW_MANIFEST`] — both arms stay
    // exercisable in e2e. Same semantics as the device: the decision + log
    // run here, BEFORE any app boots; the wipe (feature
    // `FAPICO2_FOREIGN_IMAGE_WIPE`, ON by default in host builds) empties the
    // whole store; the stamp/write rides the boot persist gate below
    // (`persist_boot_change`).
    let fw_current: [u8; 32] = match std::env::var("FAPICO2_FW_HASH") {
        Ok(s) => fapico2_platform::fw_manifest::parse_manifest_hex(&s)
            .unwrap_or_else(|| {
                eprintln!(
                    "fapico2: FAPICO2_FW_HASH is not 64 hex chars; using the default \
                     fake manifest (US-919)"
                );
                fapico2_platform::fw_manifest::EMUL_FAKE_FW_MANIFEST
            }),
        Err(_) => fapico2_platform::fw_manifest::EMUL_FAKE_FW_MANIFEST,
    };
    let mut fw_buf = [0u8; 32];
    let fw_stored = match store.read(fapico2_platform::fw_manifest::SLOT_FW_MANIFEST, &mut fw_buf)
    {
        Ok(32) => Some(fw_buf),
        _ => None,
    };
    let fw_decision = fapico2_platform::fw_manifest::foreign_image_decision(fw_stored, fw_current);
    // The stamp rides `persist_boot_change` below (the boot_img snapshot is
    // taken after this point — writes before it would compare-equal and
    // never persist), so it is staged here and written next to the US-918
    // entropy slot's write.
    let mut fw_stamp: Option<[u8; 32]> = None;
    match fw_decision {
        fapico2_platform::fw_manifest::ForeignImageDecision::Load => {
            // Stamp when absent (first boot / pre-policy) or stale.
            fw_stamp = (fw_stored != Some(fw_current)).then_some(fw_current);
        }
        fapico2_platform::fw_manifest::ForeignImageDecision::WipeAndFresh => {
            #[cfg(FAPICO2_FOREIGN_IMAGE_WIPE)]
            {
                store.wipe_all().expect("host store wipe_all cannot fail");
                eprintln!(
                    "fapico2: foreign firmware image detected; secure slots wiped (US-919)"
                );
                // Fresh store: stamp so the next boot loads.
                fw_stamp = Some(fw_current);
            }
            #[cfg(not(FAPICO2_FOREIGN_IMAGE_WIPE))]
            {
                eprintln!(
                    "fapico2: foreign firmware image detected AND ADMITTED — this build has \
                     the wipe compiled out (FAPICO2_FOREIGN_IMAGE_WIPE=0), so the store was \
                     kept and the mismatch will re-decide on the next boot (US-919)"
                );
            }
        }
    }
    // US-429: the management app boots from the store (device parity,
    // main.rs:483) so its durable EF_DEV_CONF survives an emulator restart.
    let mut management_app = ManagementApp::boot(&mut store)
        // US-711 emulation parity with main.rs: the device-wide factory
        // reset hook — mgmt RESET (0x1E) wipes the OATH table and OTP
        // slots too (the emulation default user-presence auto-acks, same
        // as the host-tested fixture).
        // SAFETY: `EMUL_FACTORY_RESET_HANDLER` is a write-once `static mut`
        // (const-initialized, never reassigned) and the emulation is
        // single-threaded, so taking the one `&mut` here — before the serve
        // loop, within `ManagementApp::boot`'s registration — cannot alias
        // any other reference (US-905 aliasing discipline).
        .with_factory_reset(unsafe {
            &mut *core::ptr::addr_of_mut!(EMUL_FACTORY_RESET_HANDLER)
        });

    // Use a file-backed keystore so state survives emulator restarts (US-322).
    // FAPICO2_KEYSTORE overrides the shared temp path (FX-409).
    let kstore_path = match std::env::var("FAPICO2_KEYSTORE") {
        Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => std::env::temp_dir().join("fapico2_keystore.cbor"),
    };
    eprintln!("keystore: {}", kstore_path.display());
    let keystore = match FileKeystore::load_or_create(kstore_path) {
        Ok(ks) => ks,
        Err(e) => {
            // Refuse to silently reset over a corrupt snapshot (FX-409).
            eprintln!("fapico2: keystore load failed ({:?}); exiting", e);
            std::process::exit(2);
        }
    };
    let mut fido_app = FidoApp::with_keystore(keystore);

    // US-423: canonical post-load image (device parity) — the boot persist
    // gate compares the post-boot store against this.
    let boot_img: Vec<u8> = store.partition_image();

    // US-918: guarantee the boot-entropy slot (device parity with
    // `boot::ensure_boot_entropy`): absence → draw from the host TRNG. The
    // write sits AFTER the `boot_img` snapshot and BEFORE the boot persist
    // gate below, so `persist_boot_change` sees it as a change and seals it
    // into the v3 store image — placed any earlier, a fresh store would
    // compare equal and the entropy would never persist (redrawn every
    // boot, invalidating the bound root determinism).
    {
        use fapico2_platform::ckey;
        use fapico2_platform::migration::SLOT_BOOT_ENTROPY;
        let mut buf = [0u8; ckey::BOOT_ENTROPY_LEN];
        match store.read(SLOT_BOOT_ENTROPY, &mut buf) {
            Ok(n) if n == ckey::BOOT_ENTROPY_LEN => {}
            Ok(_) | Err(_) => {
                use fapico2_platform::trng::Trng;
                let mut trng = HostTrng::new();
                trng.random_bytes(&mut buf);
                if let Err(e) = store.write(SLOT_BOOT_ENTROPY, &buf) {
                    eprintln!("fapico2: boot entropy slot write failed ({:?}); bound-root derivations will refuse", e);
                }
            }
        }
    }

    // US-919: write the staged last-known-good manifest stamp (see the
    // decision site above) — it rides `persist_boot_change` below, the
    // same durability path the US-918 entropy record rides.
    if let Some(h) = fw_stamp {
        if let Err(e) = store.write(fapico2_platform::fw_manifest::SLOT_FW_MANIFEST, &h) {
            eprintln!("fapico2: fw manifest stamp write failed ({:?}); the next boot re-decides (US-919)", e);
        }
    }

    let mut trng = HostTrng::new();
    // The device-path OATH app (oath_core) — the same code the board runs —
    // booted from the store; a corrupt keystore stream refuses to boot
    // rather than silently reset (FX-409).
    //
    // US-130: the OATH device-id (the SELECT `TAG_NAME` TLV, and hence the
    // PBKDF2 salt for the access key) is a *required* constructor argument, so
    // the stand-in is stated here, in the open, rather than inherited from a
    // default nobody chose. The device path passes the real OTP chip-id; this
    // path passes `EMULATION_CHIPID` to keep the emulation suites
    // deterministic.
    let oath_device_id = oath_device_id(EMULATION_CHIPID);
    // US-1030: the credential-key seal context, from the emulation stand-ins
    // for the flash UID and the OTP row (`OathSeal::emul`). Required, for
    // the same reason it is required on the device: a migrated plaintext
    // OATH key is re-sealed during this boot, and the emulator must run
    // the same code path the device does.
    let mut oath_app =
        match OathApp::boot(&mut trng, &mut store, oath_device_id, OathSeal::emul()) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("fapico2: oath keystore boot failed ({:?}); exiting", e);
            std::process::exit(2);
        }
    };
    let mut otp_app = OtpApp::boot(&mut store);
    // US-423: persist boot-time store changes (device parity; idempotent).
    let mut boot_sink = FileImageSink::new(partition_path.clone());
    persist_boot_change(&mut store, &boot_img, &mut boot_sink);
    // PIV gets its own secure-store snapshot so objects/auth survive restarts
    // (US-373). FAPICO2_PIV_KEYSTORE overrides the shared temp path (FX-409).
    let piv_kstore_path = match std::env::var("FAPICO2_PIV_KEYSTORE") {
        Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => std::env::temp_dir().join("fapico2_piv_keystore.cbor"),
    };
    eprintln!("piv keystore: {}", piv_kstore_path.display());
    let mut piv_app = match PivApp::with_keystore(piv_kstore_path) {
        Ok(app) => app,
        Err(e) => {
            // Refuse to silently reset over a corrupt snapshot (FX-409).
            eprintln!("fapico2: piv keystore load failed ({:?}); exiting", e);
            std::process::exit(2);
        }
    };
    // US-160 (PICOForge-COMPAT): the RS-Key vendor LED applet, booted from the
    // same shared secure-partition stand-in as the other CCID apps so a
    // profile the host wrote survives an emulator restart — parity with the
    // device boot in `main.rs`.
    let mut vendor_led_app = VendorLedApp::boot(&mut store);
    // US-161/162/163 (PICOForge-COMPAT Phase H): the Rescue applet, served over
    // the same CCID transport the harness tests drive. The chip id is the
    // fixed emulation stand-in (no OTP row on a host), the flash figures are
    // derived from the emulated partition's live length, and the two owners are
    // the emulation stand-ins above. `with_secure_boot_status` is left at its
    // default of "both false", which is the truth on a host exactly as it is
    // on the device.
    let rescue_cfg = emul_init_rescue_handler();
    let partition_bytes = std::fs::metadata(&partition_path).map(|m| m.len()).unwrap_or(0);
    let mut rescue_app = RescueApp::new()
        .with_chipid(EMULATION_CHIPID)
        // The host store is an unbounded `BTreeMap` serialized whole, so it
        // has **no capacity to report**: `free` and `total` are 0 and only
        // `used` (the live partition image's length) is a real number. The
        // device build reports all three, computing `free` as
        // `SECURE_PARTITION_SIZE - used` (`firmware/src/main.rs`) against the
        // sealed partition's bound — a figure a host has no honest analogue
        // for, and duplicating the bound's formula here would be a second copy
        // free to drift.
        .with_flash_stats(FlashStats {
            free: 0,
            used: u32::try_from(partition_bytes).unwrap_or(u32::MAX),
            total: 0,
            nfiles: 0,
            // The stand-in for the device's 4 MiB QSPI part
            // (`firmware/src/boot.rs` `FLASH_SIZE`); a host has no flash, so
            // this is a fixture value and is documented as one — and it is
            // the one FlashInfo word the client actually shows
            // (`(chip_size > 0).then_some(chip_size)`, `ops.rs:425`).
            chip_size: 4 * 1024 * 1024,
        })
        .with_config_handler(rescue_cfg)
        .with_device_handler(unsafe {
            &mut *core::ptr::addr_of_mut!(EMUL_RESCUE_DEVICE_HANDLER)
        });
    // Registered apps must outlive the dispatcher, so it is declared last.
    // S-721-2 (D-D): the OpenPGP client is the S-721-1 no_std "call thyself"
    // `SyscallRunner` client on the host backend (option A — the same
    // `Client` type the device builds, same `OpenPgpApp`, same serve loop);
    // it only lives inside the closure, so the whole serve loop runs within
    // `with_host_backend`.
    with_host_backend("fapico2-openpgp", |client| {
        let mut openpgp_app = OpenPgpApp::new(client);
        // Seven registrations (management, OATH, OTP, OpenPGP, PIV, vendor
        // LED, Rescue) into a capacity-7 dispatcher — exactly full, so an
        // eighth registration would fail the `push` and be reported rather than
        // silently dropped. US-161/162/163 took this from six to seven; the
        // device path registers six (`apps::registry::CCID_AIDS`) because it
        // does not carry PIV.
        let mut dispatcher: Dispatcher<7> = Dispatcher::new();
        dispatcher.register(&mut management_app);
        dispatcher.register(&mut oath_app);
        dispatcher.register(&mut otp_app);
        dispatcher.register(&mut openpgp_app);
        dispatcher.register(&mut piv_app);
        dispatcher.register(&mut vendor_led_app);
        dispatcher.register(&mut rescue_app);
        serve_loop(
            &mut transport,
            &mut fido_app,
            &mut dispatcher,
            &mut store,
            &partition_path,
        );
    });
}

/// Host [`ImageSink`] (US-422): the partition image file, written atomically
/// (`<path>.tmp` + rename) — the emulation stand-in for the device's
/// secure-partition flash slots. Behavior-identical port of the deleted
/// `persist_partition_image`; the gate snapshots the store into the same
/// format-v2 bytes the old path wrote.
struct FileImageSink {
    path: std::path::PathBuf,
}

impl FileImageSink {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl ImageSink for FileImageSink {
    fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
        // US-715: pull the image through bounded windows (host build — the
        // emulation materializes only here, never on the device path), write
        // the temp file, then rename (crash-safe, behavior-identical).
        let img = pull_image(src);
        let tmp = self.path.with_extension("tmp");
        if let Err(e) =
            std::fs::write(&tmp, &img).and_then(|_| std::fs::rename(&tmp, &self.path))
        {
            eprintln!("secure partition persist failed: {e}");
            return false;
        }
        true
    }
}

/// US-424/US-427: durable-before-ack persist for the FIDO HID path —
/// emulation parity with the device's `persist_hid` (`firmware/src/tasks.rs`).
/// `persist_one`'s `false` covers BOTH "nothing was dirty" (a clean no-op —
/// the host keystore is the FIDO app's own durable medium and writes inline
/// on every mutation, so this gate leaves it neither dirty nor pending; see
/// `Persist for FidoApp` in `apps/fido`) and "a persist failed" (the app is
/// left dirty); `is_dirty` tells the two apart. Returns `true` iff the
/// command's durable state stands, so the dispatch arms answer the CTAP-HID
/// success reply only on `true` — a `false` gets the 0xBF /
/// INVALID_COMMAND error reply instead.
fn persist_hid<K: fapico2_fido::keystore::Keystore>(
    fido_app: &mut FidoApp<K>,
    store: &mut HostSecureStore,
    partition_path: &std::path::Path,
) -> bool {
    let ok = persist_one(
        fido_app,
        store,
        &mut FileImageSink::new(partition_path.to_path_buf()),
    );
    ok || !Persist::is_dirty(fido_app)
}

fn serve_loop<K: fapico2_fido::keystore::Keystore>(
    transport: &mut EmulationTransport,
    fido_app: &mut FidoApp<K>,
    dispatcher: &mut Dispatcher<7>,
    store: &mut HostSecureStore,
    partition_path: &std::path::Path,
) {
    let mut transport = &mut *transport;
    let mut resp_buf = HeaplessVec::<u8, MAX_RESPONSE>::new();
    let mut running = true;
    let mut assembler = HidAssembler::new();
    // US-711 emulation parity: the generation the serve loop last observed
    // (device `ccid_task` parity — `tasks.rs` seeds it from
    // `boot::RESET_GENERATION` at task start).
    let mut reset_gen = EMUL_RESET_GENERATION.load(Ordering::Acquire);

    while running {
        let new_client = match transport.accept_hid_client() {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("hid accept error: {}", e);
                running = false;
                continue;
            }
        };
        if new_client {
            fido_app.clear_session_state();
            eprintln!("hid client reconnect: cleared session state");
        }

        if let Some(frame) = transport.read_ccid() {
            if frame.len() == 1 && frame[0] == 0x04 {
                let atr: &[u8] = &[
                    0x3B, 0xDA, 0x18, 0xFF, 0x81, 0xB1, 0xFE, 0x75, 0x1F, 0x03, 0x00,
                    0x31, 0xF5, 0x73, 0xC0, 0x01, 0x60, 0x00, 0x90, 0x00, 0x1C,
                ]; // C parity: atr_openpgp (openpgp.c:294), T=1
                if let Err(e) = transport.write_ccid(atr) {
                    eprintln!("ccid write error: {}", e);
                    running = false;
                    continue;
                }
            } else {
                resp_buf.clear();
                dispatcher.dispatch(&frame, &mut resp_buf);
                // US-711 review fix (emulation parity with tasks.rs): a
                // management factory reset signalled since the last command
                // — wipe the OATH/OTP/OpenPGP/PIV apps through the
                // dispatcher (sole `&mut` per app, no aliasing) and
                // re-initialize the FIDO app in RAM (the CTAP2 Reset
                // primitive, device HID-task parity), all BEFORE the
                // persist gate so it flushes the emptied state
                // durable-before-ack and can never re-persist the pre-reset
                // snapshot.
                let gen = EMUL_RESET_GENERATION.load(Ordering::Acquire);
                if gen != reset_gen {
                    reset_gen = gen;
                    dispatcher.factory_wipe_apps();
                    // CTAP2 authenticatorReset (0x07) — the same primitive
                    // `FidoApp::factory_reset` drives on the device HID task.
                    let resp = fido_app.process_ctap2(0x07, &[], [0, 0, 0, 1]);
                    debug_assert_eq!(
                        resp.as_slice(),
                        [0x00],
                        "FIDO reset must not fail during factory wipe"
                    );
                    let _ = persist_hid(fido_app, store, partition_path);
                }
                // US-422: the persist gate — device ccid_task parity. Dirty
                // app store writes, partition-image snapshot, atomic write to
                // the partition file (the device's snapshot → flash step).
                // US-427: durable-before-ack — the gate's `false` covers BOTH
                // "nothing was dirty" (a clean no-op — SELECT/LIST/GET_DATA
                // and the like persist nothing, and the success reply may go
                // out) and "a persist failed" (the writing apps are re-marked
                // dirty); `is_dirty` tells the two apart. Only the second
                // answers the SW-only error DataBlock `6F 00` (the generic ICC
                // "unknown error" status word — the same one this transport's
                // CCID path uses for oversized input) instead of the APDU
                // response. The gate's own `persist_error` already logged the
                // cause.
                let mut sink = FileImageSink::new(partition_path.to_path_buf());
                let ok = persist_apps(dispatcher.apps_mut(), store, &mut sink);
                if ok || dispatcher.apps_mut().iter().all(|app| !App::is_dirty(&**app)) {
                    if let Err(e) = transport.write_ccid(&resp_buf) {
                        eprintln!("ccid write error: {}", e);
                        running = false;
                        continue;
                    }
                } else {
                    eprintln!("emulation: persist failed; answering 6F 00 (durable-before-ack)");
                    if let Err(e) = transport.write_ccid(&[0x6F, 0x00]) {
                        eprintln!("ccid write error: {}", e);
                        running = false;
                        continue;
                    }
                }
            }
        }

        if let Some((channel, code)) = assembler.check_timeout() {
            send_hid_response(&mut transport, &channel, CTAP_HID_ERROR, &[code]);
        }

        if let Some(frame) = transport.read_hid() {
            match assembler.feed(&frame) {
                HidFeed::NeedMore => {}
                HidFeed::Err(channel, code) => {
                    send_hid_response(&mut transport, &channel, CTAP_HID_ERROR, &[code]);
                }
                HidFeed::Ready(cmd, payload) => {
                let channel = assembler.channel;

                if cmd == CTAP_HID_INIT {
                    // INIT response: nonce(8) + cid(4) + ver_iface(1) +
                    //   ver_major(1) + ver_minor(1) + version_build(1) + cap_flags(1) = 17 bytes
                    let nonce = if payload.len() >= 8 {
                        &payload[..8]
                    } else {
                        &payload
                    };
                    let new_channel: [u8; 4] = [0, 0, 0, 1];
                    let mut inner = vec![0u8; 17];
                    inner[..nonce.len()].copy_from_slice(nonce);
                    inner[8..12].copy_from_slice(&new_channel);
                    inner[12] = 0x02; // versionInterface (2 = CTAP HID v2)
                    inner[13] = 0x02; // versionMajor (FIDO_2_2)
                    inner[14] = 0x01; // versionMinor
                    inner[15] = 0x00; // versionBuild
                    inner[16] = 0x04; // capFlags: CBOR supported
                    send_hid_response(&mut transport, &channel, 0x06, &inner);
                } else if cmd == CTAP_HID_CBOR {
                    // CTAP2 CBOR command
                    if !payload.is_empty() {
                        let ctap_cmd = payload[0];
                        // US-1506: the unconditional pre-dispatch `0x02`
                        // (UP NEEDED) is gone here for the same reason it is
                        // gone on the device — it claimed "waiting for your
                        // touch" before the command had been run, and the
                        // device emitted 301 of them in a 30 s window. The
                        // device's replacement is a `0x01` (PROCESSING) sent
                        // at the park; this binary's consent loop is still
                        // the pre-US-1509 nested `loop` and the park happens
                        // further down, so the single frame moves with it.
                        //
                        // **The cadence is not addressed here.** The loop
                        // below re-drives without emitting anything, and
                        // giving it a 250 ms `0x02` cadence means moving it
                        // onto `PendingUp` — which is US-1524's migration,
                        // and pre-empting it wholesale is out of scope. With
                        // the emulator's auto-ack FIDO app the window is
                        // granted on the first re-drive, so the loop is never
                        // observed repeating anyway.
                        if ctap_cmd == 0x01 || ctap_cmd == 0x02 {
                            send_hid_response(
                                &mut transport,
                                &channel,
                                CTAP_HID_KEEPALIVE,
                                &[CTAPHID_KEEPALIVE_PROCESSING],
                            );
                        }
                        let ctap_payload = &payload[1..];
                        // US-921 (device tasks.rs CBOR-arm parity): an
                        // UpRequired answer opens the cross-call consent
                        // window and the command is re-driven inside it.
                        // The emulation's FIDO app auto-acks presence, so
                        // the first retry already carries the grant — the
                        // loop completes on iteration 1 and the final
                        // reply is byte-identical to the no-window answer
                        // (the e2e suites stay green).
                        let mut ctap_response =
                            fido_app.process_ctap2(ctap_cmd, ctap_payload, channel);
                        // US-921 review (P0-1): the tag is domain-separated
                        // into the HID space (bit 31 set) — parity with the
                        // device tasks.rs CBOR arm.
                        let tag = fapico2_fido::presence_tag_from_channel(channel);
                        if (ctap_cmd == 0x01 || ctap_cmd == 0x02)
                            && ctap_response.len() == 1
                            && ctap_response[0]
                                == fapico2_fido::ctap2::Ctap2Response::UpRequired.code()
                            && fapico2_firmware::presence::begin_window(
                                tag,
                                CTAP_TOUCH_WINDOW_MS,
                            )
                        {
                            let win = TouchWindow::open(tag, emul_now_ms());
                            fapico2_firmware::presence::touch_prompt(true);
                            loop {
                                match emul_consent_tick(&win) {
                                    ConsentTick::KeepWaiting => {}
                                    ConsentTick::Expired => break,
                                    // US-1505: the host cancelled. Answer the
                                    // command as cancelled rather than let
                                    // the window run out to its 30 s
                                    // deadline and say something the host
                                    // has already given up on. The window is
                                    // released by `emul_consent_tick` itself,
                                    // so the CBOR and U2F loops cannot
                                    // disagree about that half.
                                    ConsentTick::Cancelled => {
                                        ctap_response = vec![CTAP2_ERR_KEEPALIVE_CANCEL];
                                        break;
                                    }
                                }
                                // Device parity: the keepalive yield lets
                                // the button task arm the grant; here the
                                // auto-ack default grants immediately, so
                                // no park is needed for correctness.
                                fapico2_firmware::presence::touch_prompt(true);
                                ctap_response =
                                    fido_app.process_ctap2(ctap_cmd, ctap_payload, channel);
                                if ctap_response.len() == 1
                                    && ctap_response[0]
                                        == fapico2_fido::ctap2::Ctap2Response::UpRequired.code()
                                {
                                    continue;
                                }
                                fapico2_firmware::presence::end_window(tag);
                                fapico2_firmware::presence::touch_prompt(false);
                                break;
                            }
                        }
                        // US-424/US-427: persist gate BEFORE the success
                        // reply (durable-before-ack, CCID-arm parity) — the
                        // success reply goes out only if the command's
                        // durable state stands; otherwise the reply is the
                        // closest existing CTAPHID error: 0xBF ERROR /
                        // INVALID_COMMAND (the CTAPHID set has no
                        // "authenticator internal failure" code;
                        // INVALID_COMMAND is the generic reject this module
                        // already uses).
                        if persist_hid(fido_app, store, partition_path) {
                            send_hid_response(
                                &mut transport,
                                &channel,
                                CTAP_HID_CBOR,
                                &ctap_response,
                            );
                        } else {
                            eprintln!("emulation: persist failed; CTAPHID ERROR/INVALID_COMMAND (durable-before-ack)");
                            send_hid_response(
                                &mut transport,
                                &channel,
                                CTAP_HID_ERROR,
                                &[HID_ERR_INVALID_CMD],
                            );
                        }
                    } else {
                        send_hid_response(&mut transport, &channel, CTAP_HID_CBOR, &[0x01]);
                    }
                } else if cmd == CTAP_HID_PING {
                    send_hid_response(&mut transport, &channel, CTAP_HID_PING, &payload);
                } else if cmd == CTAP_HID_WINK {
                    // WINK: acknowledge with an empty response frame.
                    send_hid_response(&mut transport, &channel, CTAP_HID_WINK, &[]);
                } else if hid_is_cancel(cmd) {
                    // US-1505 (CTAPHID §11.2.9). No reply frame of its own —
                    // the reasoning, and the client code that makes an
                    // acknowledgement harmful, are on the arm in
                    // `firmware/src/hid_serve.rs`, which is the shipped one.
                    // This binary's own consent loop observes the latch and
                    // answers `CTAP2_ERR_KEEPALIVE_CANCEL` for the command
                    // it was holding; with nothing in flight the latch is
                    // simply dropped, exactly as the reference drops it
                    // (`pico-keys-sdk/src/usb/hid/hid.c:395` — `return 0;`).
                    EMUL_CANCEL_PENDING.store(true, Ordering::SeqCst);
                } else if cmd == 0x41 && !payload.is_empty() && payload[0] == 0x05 {
                    // Vendor vault function (test_080 / pico-fido2 vendor protocol).
                    let resp = fido_app.process_vendor_vault(&payload[1..]);
                    // US-424/US-427: persist gate BEFORE the success reply
                    // (durable-before-ack; error reply = 0xBF /
                    // INVALID_COMMAND on a failed persist, as in the CBOR arm
                    // above).
                    if persist_hid(fido_app, store, partition_path) {
                        send_hid_response(&mut transport, &channel, 0x41, &resp);
                    } else {
                        eprintln!("emulation: persist failed; CTAPHID ERROR/INVALID_COMMAND (durable-before-ack)");
                        send_hid_response(
                            &mut transport,
                            &channel,
                            CTAP_HID_ERROR,
                            &[HID_ERR_INVALID_CMD],
                        );
                    }
                } else if cmd == CTAP_HID_MSG {
                    // U2F (CTAP1) APDU over HID. The payload is the raw APDU.
                    // US-921 (device tasks.rs MSG-arm parity): a bare UP
                    // refusal opens the cross-call consent window and the
                    // APDU is re-driven inside it. The emulation
                    // auto-acks, so the first response is never a refusal
                    // and the loop is never entered (replies byte-identical).
                    // US-921 review (P1-2): the window opens only for
                    // presence-gated commands — REGISTER (INS 0x01) or
                    // AUTHENTICATE enforce (INS 0x02, P1 != 0x07 check-only)
                    // — check-only answers 6985 by spec without a touch and
                    // never opens the 30 s window (device parity).
                    let mut u2f_response = fido_app.process_u2f(&payload);
                    let tag = fapico2_fido::presence_tag_from_channel(channel);
                    let presence_gated_u2f = payload.len() >= 3
                        && matches!(payload[1], 0x01 | 0x02)
                        && payload[2] != 0x07;
                    if presence_gated_u2f
                        && fapico2_firmware::presence::u2f_up_refusal(&u2f_response)
                        && fapico2_firmware::presence::begin_window(
                            tag,
                            CTAP_TOUCH_WINDOW_MS,
                        )
                    {
                        let win = TouchWindow::open(tag, emul_now_ms());
                        fapico2_firmware::presence::touch_prompt(true);
                        loop {
                            match emul_consent_tick(&win) {
                                ConsentTick::KeepWaiting => {}
                                // US-1505: CTAP1 has no cancel status word, so
                                // a cancelled window answers exactly what an
                                // expired one does — the refusal it was
                                // already sending. The window is released
                                // either way, inside `emul_consent_tick`.
                                ConsentTick::Expired | ConsentTick::Cancelled => break,
                            }
                            fapico2_firmware::presence::touch_prompt(true);
                            u2f_response = fido_app.process_u2f(&payload);
                            if fapico2_firmware::presence::u2f_up_refusal(&u2f_response) {
                                continue;
                            }
                            fapico2_firmware::presence::end_window(tag);
                            fapico2_firmware::presence::touch_prompt(false);
                            break;
                        }
                    }
                    // US-424/US-427: persist gate BEFORE the success reply
                    // (durable-before-ack; error reply = 0xBF /
                    // INVALID_COMMAND on a failed persist, as in the CBOR arm
                    // above).
                    if persist_hid(fido_app, store, partition_path) {
                        send_hid_response(&mut transport, &channel, CTAP_HID_MSG, &u2f_response);
                    } else {
                        eprintln!("emulation: persist failed; CTAPHID ERROR/INVALID_COMMAND (durable-before-ack)");
                        send_hid_response(
                            &mut transport,
                            &channel,
                            CTAP_HID_ERROR,
                            &[HID_ERR_INVALID_CMD],
                        );
                    }
                } else {
                    // Unknown init command — CTAPHID ERROR frame, INVALID_COMMAND
                    send_hid_response(
                        &mut transport,
                        &channel,
                        CTAP_HID_ERROR,
                        &[HID_ERR_INVALID_CMD],
                    );
                }
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[cfg(test)]
mod us1505_tests {
    //! US-1505, asserted **in the emulator's own dispatcher**.
    //!
    //! `hid_serve` is the shipped dispatcher; this binary keeps a second one
    //! until US-1524. A cancel arm that exists in only one of the two is half
    //! a fix, and the half that is missing is the half the e2e suites drive,
    //! so the emulator's copy gets its own assertions rather than an
    //! assumption that it "is the same code".
    //!
    //! Run with:
    //! `cargo test -p fapico2-firmware --no-default-features --features emulation --bins --target x86_64-unknown-linux-gnu`

    use super::*;

    /// The command constant this file keeps its own copy of must still be
    /// the one in `ctap_hid` — and, more to the point, `0x11` must be
    /// classified as a cancel and *not* fall through to the unknown-command
    /// arm, which is the whole defect (`0x3F` / `0x01 INVALID_CMD`).
    #[test]
    fn hid_cancel_wins_over_the_unknown_command_arm() {
        assert_eq!(CTAP_HID_CANCEL, 0x11, "§11.2.9's CANCEL is 0x11");
        assert_eq!(
            CTAP_HID_CANCEL,
            fapico2_firmware::ctap_hid::CTAP_HID_CANCEL,
            "the emulator's local copy has drifted from ctap_hid's"
        );
        assert!(hid_is_cancel(CTAP_HID_CANCEL));
        // None of the arms CANCEL must not be mistaken for may claim it —
        // in particular the ERROR byte, which is what a fall-through emits.
        for other in [
            CTAP_HID_INIT,
            CTAP_HID_PING,
            CTAP_HID_MSG,
            CTAP_HID_WINK,
            CTAP_HID_CBOR,
            CTAP_HID_ERROR,
            CTAP_HID_KEEPALIVE,
            0x41,
            0x42,
        ] {
            assert!(
                !hid_is_cancel(other),
                "{other:#04x} is not CTAPHID_CANCEL and must not be routed to the cancel arm"
            );
        }
    }

    /// The latch the emulator's consent loops poll: set by the dispatch arm,
    /// consumed by the loop, and consumed **once** — a latch that stayed
    /// raised would cancel whatever window opened next, which is exactly
    /// the shape of a cross-request defect.
    #[test]
    fn a_pending_cancel_is_observed_exactly_once() {
        EMUL_CANCEL_PENDING.store(false, Ordering::SeqCst);
        assert!(!take_pending_cancel(), "nothing was sent; nothing to observe");

        EMUL_CANCEL_PENDING.store(true, Ordering::SeqCst);
        assert!(take_pending_cancel(), "the loop must see the cancel");
        assert!(
            !take_pending_cancel(),
            "the latch must be consumed by the observation, not left set for the \
             next window"
        );
    }

    /// The stop condition itself, against the real presence runtime: a
    /// cancel ends the window, and the window's presence slot and prompt are
    /// both released — the pairing whose absence is a permanently held slot
    /// and a permanently lit LED.
    ///
    /// The slot is opened and released here, in the same order the CBOR arm
    /// opens one, because the presence runtime is a process-wide singleton.
    #[test]
    fn a_cancel_ends_the_emulator_consent_window() {
        // Write-once, exactly as `main()` does at boot; a second call returns
        // `false`, which is fine — only the first one installs the slot.
        fapico2_firmware::presence::init(emul_now_ms);
        let tag = 0x8000_00E5;
        EMUL_CANCEL_PENDING.store(false, Ordering::SeqCst);
        assert!(
            fapico2_firmware::presence::begin_window(tag, CTAP_TOUCH_WINDOW_MS),
            "the presence slot must be free before the test opens its window"
        );
        let win = TouchWindow::open(tag, emul_now_ms());

        assert_eq!(
            emul_consent_tick(&win),
            ConsentTick::KeepWaiting,
            "a live window with nothing sent keeps waiting"
        );

        EMUL_CANCEL_PENDING.store(true, Ordering::SeqCst);
        assert_eq!(
            emul_consent_tick(&win),
            ConsentTick::Cancelled,
            "a CTAPHID_CANCEL ends the window — and answers as cancelled, not \
             as the refusal the window was sending"
        );

        // The teardown is the part that is easy to get wrong: the slot is
        // free again, so the next `begin_window` (a CCID consent window, or
        // the next FIDO one) can have it.
        assert!(
            fapico2_firmware::presence::begin_window(tag, CTAP_TOUCH_WINDOW_MS),
            "a cancelled window must release the single presence slot"
        );
        fapico2_firmware::presence::end_window(tag);
    }
}
