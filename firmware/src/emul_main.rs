//! Emulation entry point for the fapico2 firmware (US-304).

use core::sync::atomic::{AtomicU32, Ordering};
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
use fapico2_firmware::ctap_hid::HID_REPORT_SIZE;
use fapico2_firmware::emul_hid::{serve_pass, HidLink, LinkDown};
use fapico2_firmware::hid_serve::{FidoDispatch, HidServe};
use fapico2_firmware::pending_up::PendingUp;
use heapless::Vec as HeaplessVec;
use fapico2_fido::CTAP2_MAX_MSG;

/// US-711 emulation parity: the emulation stand-in for the device's
/// `boot::RESET_GENERATION` counter (`firmware/src/boot.rs`). The factory
/// reset handler below bumps it; the serve loop observes it at the same
/// point the device's `ccid_task` does (`firmware/src/tasks.rs`: after the
/// dispatch, before the persist gate) and wipes the task-owned apps, so the
/// persist gate flushes their emptied state durable-before-ack.
///
/// US-1524: the FIDO half observes the same counter through
/// [`FidoDispatch::sync_generations`], which is where the device observes it
/// too (`tasks.rs::DeviceFido::sync_generations`). The two trackers are
/// separate on purpose — they are separate loops, exactly as `ccid_task` and
/// `hid_task` are separate tasks, each holding its own "generation I last
/// acted on".
static EMUL_RESET_GENERATION: AtomicU32 = AtomicU32::new(0);

/// The emulation's FIDO user-presence source: a touch that lands **during**
/// the consent window, not one already down when the command arrives.
///
/// US-1524 follow-up. Until this the host twin's `FidoApp` had no presence
/// gate at all (`apps/fido/src/app.rs`, the `presence` field), so
/// `process_ctap2` could never answer `UpRequired`, `hid_serve` never parked,
/// and the emulator put **no CTAPHID keepalive on the wire, ever** — not for
/// `makeCredential`, not for anything.
///
/// That is not a neutral simplification. On the board a `makeCredential`
/// with no touch pending answers `UpRequired`, parks, and emits a
/// `0x01 PROCESSING` keepalive before it can answer. So the double refuses
/// the **first** poll and grants the second: park, `0x01 PROCESSING`,
/// re-drive, grant, answer — the board's frame sequence minus the human.
/// `fetch_not` alternates rather than latching, so *every* presence-gated
/// command takes that shape and not merely the first one after boot; a
/// latching version would make the answer depend on how many commands
/// happened to precede it, which is the order-dependence this removes.
///
/// It lives here, in the emulation binary, rather than in the shared serve
/// loop on purpose: it is a property of the test double, not of the
/// firmware. Putting the equivalent frame in the device's dispatch instead
/// was measured at +164 B of `.text`, which is more than the flash ratchet
/// has left (the image already sits on 3072 of 3072 blocks), so the honest
/// place to stand in for a missing human is the emulator.
///
/// Consequences, both matching the board:
/// * U2F `REGISTER`/`AUTHENTICATE` also park for one pass. The MSG arm sends
///   no frame at the park (deliberately, US-1506 — a `PROCESSING` ahead of a
///   quick U2F response desyncs U2FHID hosts), so their observable frames
///   are unchanged; only one extra serve pass is added.
/// * Any command that consults presence more than once per call is granted
///   on the later poll, which is the old instant-grant behaviour.
static EMUL_TOUCH_LATE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

fn emul_touch_lands_in_window() -> bool {
    EMUL_TOUCH_LATE.fetch_not(Ordering::Relaxed)
}

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
/// The stand-in PHY record: nine fixed bytes, then two name slots of
/// `1 + MAX_NUL_STRING_LEN` each (a presence byte followed by the padded
/// name).
///
/// The nine are the fields `EmulRescueConfig::commit` has always written; the
/// two name slots were added with `product`/`manufacturer`, which the device
/// handler has always stored and this stand-in silently dropped. It is a
/// private per-test file and nothing depends on its shape.
const EMUL_RESCUE_PHY_LEN: usize = 9
    + 2 * (1 + fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN);

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
                let mut names = 9usize;
                for slot in [&mut snap.product, &mut snap.manufacturer] {
                    let present = raw[names] != 0;
                    let width = fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN;
                    let mut buf = [0u8; fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN];
                    buf.copy_from_slice(&raw[names + 1..names + 1 + width]);
                    if present {
                        *slot = Some(buf);
                    }
                    names += 1 + buf.len();
                }
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
            // US-1553 follow-through: the two identity names are stored by the
            // **device** handler (`boot.rs` writes `ks.phy.product` /
            // `.manufacturer`) and `cmd_write` accepts both tags — but this
            // stand-in dropped them, so on the emulator a product name vanished
            // on write and the PhyConfig READ never showed one. picoforge sends
            // `0x09` and `0x0F` on **every** save, so the stand-in was silently
            // discarding two records the compatibility work depends on.
            //
            // Found by `tests/harness/test_rescue_write.py::
            // test_no_tag_picoforge_can_emit_breaks_the_write`, which reads the
            // record back after writing all twelve tags.
            if update.product.is_some() {
                s.product = update.product;
            }
            if update.manufacturer.is_some() {
                s.manufacturer = update.manufacturer;
            }
        }
        // The stand-in's own medium. It is a private `/tmp` file per test, so
        // extending it costs nothing and buys a restart that actually restores
        // the names — the record above is not a device format and nothing
        // depends on its shape.
        let s = *self.cell.borrow();
        let vid_pid = s.vid_pid.unwrap_or(0).to_be_bytes();
        let options = s.options.unwrap_or(0).to_be_bytes();
        let name = |v: Option<[u8; fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN]>| {
            let mut out = [0u8; 1 + fapico2_platform::phy_tlv::MAX_NUL_STRING_LEN];
            match v {
                Some(n) => {
                    out[0] = 1;
                    out[1..].copy_from_slice(&n);
                }
                None => out[0] = 0,
            }
            out
        };
        let mut raw = vec![
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
        raw.extend_from_slice(&name(s.product));
        raw.extend_from_slice(&name(s.manufacturer));
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
    let mut fido_app =
        FidoApp::with_keystore(keystore).with_user_presence(emul_touch_lands_in_window);

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
    // US-132 harness hook: withhold the OATH user-presence grant.
    //
    // `oath_core::default_user_present()` returns `true` on a host build
    // (`#[cfg(not(feature = "device"))]`), so the emulator's presence source
    // auto-acks and the one consent gate that survives US-132 is
    // un-exercisable here — the exact hole US-923 left for the
    // `u2f-presence`/`mgmt-presence` cases. This env var closes it for OATH:
    // `FAPICO2_OATH_PRESENCE=deny` injects `|| false`, which is what the
    // device's fail-closed default already does, so a harness case can drive
    // the real 0x6985 refusal over CCID instead of asserting it in prose.
    //
    // Emulation-only: `emul_main` is a `required-features = ["emulation"]`
    // binary and is never part of the UF2, so this cannot weaken a device.
    // Unset (the default, and every value other than "deny") leaves the
    // auto-ack stand-in exactly as it was.
    if let Ok(v) = std::env::var("FAPICO2_OATH_PRESENCE") {
        if v == "deny" {
            oath_app = oath_app.with_user_presence(|| false);
            eprintln!("oath presence: denied (FAPICO2_OATH_PRESENCE=deny)");
        }
    }
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

/// US-1524: the emulator's [`HidLink`] over the TCP emulation transport.
///
/// The only device-shaped thing this binary still owns. `EmulationTransport`
/// speaks whole length-prefixed CTAP-HID *frames* over a socket and a HID
/// report is 64 bytes; both halves of that adaptation are here. Everything
/// above it — fragmentation, the reply deadline, the CTAPHID command table,
/// the consent window — is `hid_reply` and `hid_serve`, shared with the board.
struct EmulLink<'a> {
    transport: &'a mut EmulationTransport,
}

impl HidLink for EmulLink<'_> {
    fn take_report(&mut self, report: &mut [u8; HID_REPORT_SIZE]) -> Result<usize, LinkDown> {
        match self.transport.read_hid() {
            Some(frame) => {
                // A HID report is 64 bytes by definition; a longer "frame" is
                // malformed either way, and truncating here is what a real
                // interrupt endpoint would have done with it.
                let n = frame.len().min(HID_REPORT_SIZE);
                report[..n].copy_from_slice(&frame[..n]);
                Ok(n)
            }
            // No host, or nothing waiting. Deliberately **not** an error: the
            // emulator is one thread serving CCID and HID, so a parked read
            // would stop it answering CCID. The device's OUT endpoint parks
            // instead, and that is the one control-flow difference the two
            // builds keep — it changes no answer, which is what
            // `emul_hid`'s parity tests measure.
            None => Ok(0),
        }
    }

    fn put_report(&mut self, report: &[u8; HID_REPORT_SIZE]) -> Result<(), LinkDown> {
        self.transport.write_hid(report).map_err(|_| LinkDown)
    }
}

/// US-1524: the emulator's [`FidoDispatch`] — the twin of `tasks.rs`'s
/// `DeviceFido`.
///
/// The host `FidoApp` twin has no `_with_store` entry points and no
/// `set_channel`: its keystore *is* its durable medium (it writes the
/// keystore file inline on every mutation, which is why `App::is_dirty` is
/// `false` for it at `apps/fido/src/app.rs:396`) and its U2F entry takes the
/// presence probe directly rather than deriving a tag from a remembered
/// channel. Both differences are properties of the host app, not of this
/// adapter, and neither can be observed through the wire.
struct EmulFido<'a, K: fapico2_fido::keystore::Keystore> {
    app: &'a mut FidoApp<K>,
    store: &'a mut HostSecureStore,
    partition_path: &'a std::path::Path,
    /// US-711 (FIDO half): the reset generation this HID loop last acted on,
    /// seeded at boot exactly as `tasks.rs::hid_task` seeds
    /// `DeviceFido::reset_gen` from `boot::RESET_GENERATION`.
    reset_gen: u32,
}

impl<'a, K: fapico2_fido::keystore::Keystore> EmulFido<'a, K> {
    /// CTAP2 authenticatorReset (`0x07`) — the same primitive
    /// `DeviceFido::sync_generations` drives on the board, reached through the
    /// host twin's **management hook** rather than its command path.
    ///
    /// US-1603: this used to go through `process_ctap2(0x07, …)`, which is
    /// where the new presence gate lives. Going through the gated arm would ask
    /// the emulator for a second grant — and `emul_touch_lands_in_window`
    /// alternates by design (the documented double-poll stand-in), so the
    /// factory wipe would fail on alternate runs rather than consistently,
    /// which is the hardest shape of bug to notice.
    ///
    /// It is also simply wrong to ask twice: the management applet gated this
    /// operation first (`cmd_reset` → `user_present(INS_RESET)`), and presence
    /// is press→consume and one-shot, so the owner's touch is already spent.
    /// `app.rs::FidoApp::factory_reset` is the twin of
    /// `device_app::FidoApp::factory_reset`, and both twins now have the same
    /// shape: command path gated, management hook not.
    fn ctap2_factory_reset(&mut self) {
        self.app.factory_reset();
    }

    /// The CCID half of the serve loop needs the same secure store the HID half
    /// persists into. Handed out rather than held by the caller because the two
    /// halves are one thread: `&mut` to the app and the store have to stay
    /// inside one owner.
    fn store_mut(&mut self) -> &mut HostSecureStore {
        &mut *self.store
    }

    /// A new HID client is a power cycle for the host stack's volatile state
    /// (`apps/fido/src/app.rs::clear_session_state`).
    fn clear_session_state(&mut self) {
        self.app.clear_session_state();
    }
}

impl<K: fapico2_fido::keystore::Keystore> FidoDispatch for EmulFido<'_, K> {
    fn sync_generations(&mut self) {
        // US-711, FIDO half: a management factory reset committed on the CCID
        // task since the last HID command — re-initialize the FIDO app in RAM.
        // The durable flush is the persist gate's, on the next command, which
        // is the device's arrangement too (`DeviceFido::sync_generations`
        // resets in RAM and lets `persist` flush).
        let gen = EMUL_RESET_GENERATION.load(Ordering::Acquire);
        if gen != self.reset_gen {
            self.reset_gen = gen;
            self.ctap2_factory_reset();
        }
    }

    fn device_info_page(&self, _page: u8, out: &mut HeaplessVec<u8, MAX_RESPONSE>) {
        // US-1524: the emulator used to answer `0x42` (CTAP_READ_CONFIG) with
        // `0x3F`/`0x01 INVALID_CMD`, because its private dispatcher had no arm
        // for it. `AGENTS.md`'s three-`DeviceInfo`-interfaces table makes that
        // a real gap: the FIDO one is the interface `ykman fido info` reads,
        // and below 4.1 yubikit fabricates a "YubiKey 3.0 / no serial" record
        // with no FIDO2 bit — the `CTAP2: Not supported` symptom. Same
        // `default_config_tlv` the management applet serves over CCID, from the
        // same `serial_hash4(chipid)` derivation, with the documented
        // emulation chip-id standing in for the OTP row the board reads.
        let serial = fapico2_platform::usb_ident::serial_hash4(EMULATION_CHIPID);
        fapico2_mgmt::default_config_tlv(serial, out);
    }

    fn process_ctap2(
        &mut self,
        ctap_cmd: u8,
        payload: &[u8],
        channel: [u8; 4],
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> usize {
        let resp = self.app.process_ctap2(ctap_cmd, payload, channel);
        copy_answer(&resp, out)
    }

    fn process_vendor_vault(
        &mut self,
        payload: &[u8],
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> usize {
        let resp = self.app.process_vendor_vault(payload);
        copy_answer(&resp, out)
    }

    fn set_channel(&mut self, _channel: [u8; 4]) {
        // The host twin's `process_ctap2` stamps `current_channel` itself (it
        // takes the channel as an argument) and its `process_u2f` takes the
        // presence probe directly, so nothing reads a remembered channel on
        // this build. The device twin needs the explicit stamp — see
        // `hid_serve`'s MSG arm, which calls it for exactly that reason.
    }

    fn process_u2f(
        &mut self,
        apdu: &[u8],
        out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>,
    ) -> usize {
        let resp = self.app.process_u2f(apdu);
        copy_answer(&resp, out)
    }

    fn persist(&mut self) -> bool {
        persist_hid(self.app, self.store, self.partition_path)
    }
}

/// The host twin's answers are `Vec<u8>`; the serve loop's buffer is the
/// bounded CTAP-HID one (`CTAP2_MAX_MSG`, the same bound `boot::HID_RESP`
/// declares). Anything longer is truncated to the bound and reported at its
/// real length, which is what the device's `process_ctap2_with_store` does with
/// the same overflow — a reply the host could not have framed anyway.
fn copy_answer(resp: &[u8], out: &mut HeaplessVec<u8, CTAP2_MAX_MSG>) -> usize {
    out.clear();
    let n = resp.len().min(out.capacity());
    out.extend_from_slice(&resp[..n])
        .expect("n is bounded by the buffer's capacity");
    n
}

fn serve_loop<K: fapico2_fido::keystore::Keystore>(
    transport: &mut EmulationTransport,
    fido_app: &mut FidoApp<K>,
    dispatcher: &mut Dispatcher<7>,
    store: &mut HostSecureStore,
    partition_path: &std::path::Path,
) {
    let mut resp_buf = HeaplessVec::<u8, MAX_RESPONSE>::new();
    // US-1524: the shared serve loop's state. `HidServe` owns the CTAP-HID
    // assembler, the CID allocator and the reply buffer; `PendingUp` owns the
    // consent window. Both are the shipped types — the emulator used to carry
    // a private `HidAssembler` and three private consent loops.
    let mut ctap_out = HeaplessVec::<u8, CTAP2_MAX_MSG>::new();
    let mut srv = HidServe::new(emul_now_ms, &mut ctap_out);
    let mut slot = PendingUp::new();
    let mut app = EmulFido {
        app: fido_app,
        store,
        partition_path,
        reset_gen: EMUL_RESET_GENERATION.load(Ordering::Acquire),
    };
    let mut running = true;
    // US-711 emulation parity: the generation the **CCID** half last acted on
    // (device `ccid_task` parity — `tasks.rs` seeds its own tracker from
    // `boot::RESET_GENERATION` at task start, separately from `hid_task`'s).
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
            app.clear_session_state();
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
                //
                // US-1524: the FIDO half is now also the HID half's job
                // (`FidoDispatch::sync_generations`, the device's split). It
                // is left in place here as well because this flush is what
                // makes the CCID reply durable-before-ack, and the HID half's
                // flush is deferred to its next command — the device's
                // arrangement, where the two tasks each own their own share.
                let gen = EMUL_RESET_GENERATION.load(Ordering::Acquire);
                if gen != reset_gen {
                    reset_gen = gen;
                    dispatcher.factory_wipe_apps();
                    app.ctap2_factory_reset();
                    let _ = app.persist();
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
                let ok = persist_apps(dispatcher.apps_mut(), app.store_mut(), &mut sink);
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

        // US-1524: **one iteration of the shipped CTAP-HID serve loop.** This
        // is the whole CTAP-HID half of the emulator: the assembler, the
        // command table, the reply framing and the consent window all come
        // from `hid_serve` / `hid_reply`, which is what `tasks.rs::hid_task`
        // drives on the board. Before this story the same four things lived
        // in ~250 private lines here, and the 30 s consent blackout they
        // encoded was reproducible in the emulator and fixed only on the
        // device.
        serve_pass(&mut srv, &mut EmulLink { transport }, &mut app, &mut slot);

        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[cfg(test)]
mod us1524_tests {
    //! US-1524: what the emulator binary itself must still answer for, now
    //! that its CTAP-HID dispatch is `hid_serve`'s.
    //!
    //! The wire-level parity claims live in `emul_hid`'s tests, which drive the
    //! same [`serve_pass`] this binary calls. What is *here* is the wiring
    //! claim: that the emulator's adapters really are the shared seam's, and
    //! that the answers the board gives for the two interfaces this binary
    //! used to get wrong are now the board's.
    //!
    //! Run with:
    //! `cargo test -p fapico2-firmware --no-default-features --features emulation --bins --target x86_64-unknown-linux-gnu`

    use super::*;

    use fapico2_firmware::ctap_hid::{init_reply, CTAPHID_INIT_CAP_FLAGS};

    /// The emulator's CTAP-HID answers are produced by `hid_serve`, not by
    /// code in this file. There is no `HidAssembler`, no `HidFeed`, no
    /// `send_hid_response` and no consent `loop` left to find: the two
    /// constructors below have to name the shared seam's types, which is the
    /// strongest statement the compiler will make about it.
    #[test]
    fn the_emulator_builds_its_hid_state_from_the_shared_seam() {
        fn assert_shared(_: &HidServe<'_>, _: &PendingUp) {}
        let mut out = HeaplessVec::<u8, CTAP2_MAX_MSG>::new();
        let mut srv = HidServe::new(emul_now_ms, &mut out);
        assert_shared(&srv, &PendingUp::new());
    }

    /// US-1524: `CTAP_READ_CONFIG` (`0x42`) used to answer
    /// `0x3F`/`0x01 INVALID_CMD` on the emulator, because its private
    /// dispatcher had no arm for it. It now serves the same `DeviceInfo`
    /// body the management applet serves over CCID, from the same
    /// `serial_hash4` derivation.
    #[test]
    fn device_info_over_the_fido_interface_is_the_management_applets_body() {
        let mut via_hid = HeaplessVec::<u8, MAX_RESPONSE>::new();
        let mut app = FidoApp::with_keystore(fapico2_fido::keystore::MemoryKeystore::new());
        let app_ref = EmulFido {
            app: &mut app,
            store: &mut HostSecureStore::new(),
            partition_path: std::path::Path::new("/dev/null"),
            reset_gen: EMUL_RESET_GENERATION.load(Ordering::Acquire),
        };
        app_ref.device_info_page(0, &mut via_hid);

        let serial = fapico2_platform::usb_ident::serial_hash4(EMULATION_CHIPID);
        let mut via_ccid = HeaplessVec::<u8, MAX_RESPONSE>::new();
        fapico2_mgmt::default_config_tlv(serial, &mut via_ccid);

        assert_eq!(
            via_hid.as_slice(),
            via_ccid.as_slice(),
            "the FIDO and CCID DeviceInfo interfaces must return the same body \
             (AGENTS.md: ykman reads one and the other, and they have agreed \
             since US-1524)"
        );
        assert!(
            !via_hid.is_empty(),
            "an empty DeviceInfo page is what made ykman fabricate a \
             \"YubiKey 3.0 / U2F only / no serial\" record"
        );
    }

    /// The INIT reply is `ctap_hid::init_reply` — including `capFlags`, the
    /// one byte that decides whether a spec-reading host offers this key as a
    /// CTAP2 authenticator at all (US-1507). The emulator used to build its 17
    /// bytes inline with `capFlags = 0x04`, which reads as "CBOR: no" to a
    /// CTAP 2.1 spec reader; it now calls the shared builder.
    #[test]
    fn the_init_reply_is_the_shared_builder() {
        let nonce = [0x22u8; 8];
        let cid = [0u8, 0, 0, 2];
        let reply = init_reply(&nonce, &cid, fapico2_mgmt::VERSION_MAJOR, fapico2_mgmt::VERSION_MINOR, 0);
        assert_eq!(reply[16], CTAPHID_INIT_CAP_FLAGS);
        assert_eq!(reply[16] & 0x01, 0x01, "spec reader: CBOR");
        assert_eq!(reply[16] & 0x04, 0x04, "de-facto reader: CBOR");
    }
}