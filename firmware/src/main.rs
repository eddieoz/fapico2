//! fapico2 firmware entry point.
//!
//! EPIC `RUST-MIGRATION` — Phase 0 foundation (US-301/US-302) + Task 0.3
//! (US-303/304: composite USB CCID+HID) + US-386 (device integration):
//!
//! * four CCID apps (Management, OATH, OTP, OpenPGP) behind the AID
//!   dispatcher — registration via `fapico2_apps::registry`;
//! * the FIDO2/U2F app on the HID transport (TRNG-derived hkey + real
//!   `getInfo`);
//! * two serve-loop tasks driving the endpoints (`ccid_task`, `hid_task`),
//!   mirroring the emulation `serve_loop` in `emul_main.rs`;
//! * a `usb_task` running `UsbDevice::run()` for control transfers.
//!
//! PB-M6 (US-427) split: `main.rs` keeps the entry point + USB descriptor
//! statics + the two small tasks; the boot phase (secure-partition slot
//! selection, store/flash/migration statics, first-boot C→Rust migration,
//! app-static slots) lives in [`boot`]; the CCID/HID serve loops and their
//! dispatchers live in [`tasks`].
//!
//! Memory layout comes from the board file: `firmware/build.rs` generates
//! `memory.x` into the build directory (US-1080) and defmt RTT config lives in
//! `defmt.x`.

#![no_std]
#![no_main]

// US-1553: `Box::new` for `OathRegion::new`, which owns its `KeyRegion`.
extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

use defmt_rtt as _;
use embassy_executor::{main, task, Spawner};
use embassy_rp::bind_interrupts;
use embassy_rp::flash::Flash;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{TRNG, USB};
use embassy_rp::trng::Config;
use embassy_rp::usb::Driver;
use embassy_time::Timer;
use fapico2_apps::registry::register_ccid_apps;
use fapico2_fido::FidoApp;
use fapico2_mgmt::ManagementApp;
use fapico2_firmware::oath_device_id;
use fapico2_oath::{OathApp, OtpApp};
use fapico2_openpgp::OpenPgpApp;
use fapico2_platform::dispatch::Dispatcher;
use fapico2_platform::persist::{persist_boot_change_windowed, with_durable_boot_windowed, WindowedBootImage};
use fapico2_platform::trusted_backend::{DeviceBackend, take_client};
use fapico2_platform::trng::{Rp2350Probe, Rp2350Timer, Rp2350Trng, Trng, TrngConfig, TrngProbe};
use fapico2_platform::usb::{Usb, UsbDevice};
use fapico2_vendor_led::VendorLedApp;
// US-161/162/163 (PICOForge-COMPAT Phase H): the Rescue applet's two owners
// are wired in `boot.rs`; only the applet itself is constructed here.
use fapico2_rescue::RescueApp;

// Diagnostic event logging (`dbg-log` feature, off by default): in a
// diagnostic build the macro records `(task, event, a, b)` into the RAM
// ring in [`dbg`]; in the production build it compiles to nothing and its
// arguments are not even evaluated. Defined before the module decls so the
// serve-loop modules can call it.
//
// Two features arm it, for two different jobs. `dbg-log` is the original
// CCID-wedge channel and is debug-profile-only (US-922) — which, because
// dev-profile device images dark-boot pre-`main` (US-932), makes it
// unusable for anything that has to boot on hardware. `boot-timeline` is the
// same ring read by a release-profile image, for boot-phase timing. They
// share one ring and one drain command on purpose: two rings would be two
// things to keep in sync for no gain.
#[cfg(any(feature = "dbg-log", feature = "boot-timeline"))]
macro_rules! dlog {
    ($task:expr, $event:expr, $a:expr, $b:expr) => {
        crate::dbg::log($task, $event, $a, $b)
    };
}
#[cfg(not(any(feature = "dbg-log", feature = "boot-timeline")))]
macro_rules! dlog {
    ($task:expr, $event:expr, $a:expr, $b:expr) => {
    };
}

// Rate-limited variant (error-class events in back-off loops; see
// `dbg::log_throttled`). Same vanish-when-off contract as `dlog!`.
#[cfg(any(feature = "dbg-log", feature = "boot-timeline"))]
macro_rules! dlog_throttle {
    ($task:expr, $event:expr, $a:expr, $b:expr, $min_us:expr) => {
        crate::dbg::log_throttled($task, $event, $a, $b, $min_us)
    };
}
#[cfg(not(any(feature = "dbg-log", feature = "boot-timeline")))]
macro_rules! dlog_throttle {
    ($task:expr, $event:expr, $a:expr, $b:expr, $min_us:expr) => {
    };
}

// Boot-phase boundary marker. The id is one of `dbg::P_*`; the record's own
// `t_us` (stamped by `dbg::log`) is the measurement, so nothing else is
// carried. Like `dlog!` this vanishes entirely in a build with neither
// diagnostic feature — including the `crate::dbg::` path, so a production
// image has no reference to the ring at all.
//
// Kept as its own macro rather than a `dbg::phase()` fn so the call site can
// name a bare `P_*` constant; a fn would need `mod dbg` to exist, which is
// not true in a production build.
macro_rules! bphase {
    ($id:expr) => {
        dlog!(crate::dbg::T_MAIN, crate::dbg::E_PHASE, $id, 0)
    };
}

// Boot-phase **LED** marker (the `bootphase` ladder — ON in the default
// build, every profile, no feature and no rebuild). Unlike `bphase!`, which
// writes the RAM ring and therefore only exists in diagnostic builds, this
// resolves in every image: the ring needs the enumeration that failed on a
// dark board, and the LED is the one channel that does not.
//
// The encoding is one short pulse per boundary crossed, so the pulse count a
// frozen board shows is "how far did boot get" — and the 1 Hz heartbeat,
// which is unmistakable next to a 25 ms pulse, is what says "alive but USB
// dead". See `firmware/src/boot_led.rs` for the pin-sharing contract and
// `firmware/src/bootphase.rs` for the (host-tested) encoding.
//
// The call sites are the `RUNG_*` boundaries, which are a *subset* of the
// `P_*` ring boundaries: the LED gets the nine that localise a hang, the ring
// keeps all nineteen for a boot that enumerated and can be drained.
macro_rules! mark {
    ($rung:expr) => {
        crate::boot_led::mark($rung)
    };
}

mod boot;
mod boot_led;
mod button;
#[cfg(any(feature = "dbg-log", feature = "apdu-trace", feature = "boot-timeline"))]
mod dbg;
#[cfg(feature = "apdu-trace")]
mod apdu_trace;
mod tasks;
mod otp_hid;

// IRQ binding for the RP2350 hardware TRNG (the sole randomness source, US-380).
bind_interrupts!(struct TrngIrqs {
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<TRNG>;
});

/// Monotonic panic counter surfaced over defmt/RTT (US-385 soak). The 24-h soak
/// driver, attached to the debug probe's RTT stream, counts `SOAK-PANIC #N`
/// lines; zero panics over the soak window = pass. A panic also leaves the USB
/// stack hung (the `loop {}` below), which the driver independently sees as the
/// device going unresponsive. (On the host/emulation build the equivalent
/// detector is the process abort + the `panicked at` line in the emulator log.)
static SOAK_PANIC_COUNT: AtomicU32 = AtomicU32::new(0);

/// Panic handler: defmt-encoded over RTT so probe-rs / defmt-print can decode
/// a crash without a UART sink. Increments the US-385 soak panic counter and
/// emits it, so a soak driver reading RTT can count panics (zero = pass).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let n = SOAK_PANIC_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    defmt::error!("SOAK-PANIC #{}", n);
    loop {}
}

// USB descriptor buffers (must be `'static` for the builder).
static mut CONFIG_DESC: [u8; 256] = [0; 256];
static mut BOS_DESC: [u8; 256] = [0; 256];
static mut MSOS_DESC: [u8; 256] = [0; 256];
static mut CONTROL_BUF: [u8; 256] = [0; 256];


/// US-939: FIDO keystore boot behind an `#[inline(never)]` wall.
/// US-956: the wall now hands back the write-once `boot::FIDO_APP` slot's own
/// `&'static mut` instead of a by-value `FidoApp`. US-939's version still made
/// the 15,724 B app materialize in *this* frame as the
/// `Result<FidoApp, _>` sret destination and only then memcpy it into the
/// slot; `FidoApp::boot_in_place` constructs the fields directly in the slot,
/// so the app exists exactly once. The `Result` here is a
/// `Result<&'static mut FidoApp, _>` — 4 bytes, not 15,728.
#[inline(never)]
fn boot_fido<T: Trng>(
    trng: &mut T,
    store: &mut boot::DeviceStore,
) -> &'static mut FidoApp {
    // SAFETY: the `boot::FIDO_APP` write-once `static mut` slot, exactly as
    // `boot::init_static_slot` establishes for every sibling slot — written
    // here once on the boot path, before any task is spawned (single core, no
    // other accessor exists), and the returned `&'static mut` is the sole
    // handle for the rest of the boot.
    match unsafe {
        FidoApp::boot_in_place(core::ptr::addr_of_mut!(boot::FIDO_APP), trng, &mut *store)
    } {
        Ok(app) => app,
        Err(_) => boot::fatal_boot("fido: keystore boot failed"),
    }
}

/// US-939: OATH keystore boot behind the same wall (11.3 KiB `OathApp`);
/// US-956: in place, into `boot::OATH_APP` — same rationale as `boot_fido`.
///
/// US-130 (PICOForge-COMPAT): the applet's SELECT `TAG_NAME` (the OATH
/// device-id, i.e. the PBKDF2 salt for the access key) is derived from the
/// real OTP chip-id rather than a fleet-wide literal, so each unit has its
/// own. The chip-id is read once in `main` (fail-closed via `fatal_boot`)
/// and threaded in here — `apps/oath` must not depend on `embassy-rp`.
///
/// The device-id is passed **into the constructor** rather than assigned
/// afterwards, so the two cannot come apart: there is no way to build this
/// applet while forgetting which unit it belongs to.
///
/// US-1005: generic over [`Trng`], exactly as `boot_fido` is, and the call
/// site passes the DRBG. This is not cosmetic. `OathApp::new_in_place` calls
/// `fill_rng_pool` unconditionally — 8 x 64 B — and the SELECT challenge is
/// drawn from that pool. Behind an `Rp2350Trng` that is **24 unbounded
/// `blocking_wait_for_successful_generation` waits on every boot, before USB
/// enumerates**: the exact hazard US-1001/US-1005 exist to remove, still
/// reachable, and a transport whose nonce does not come from the conditioned
/// generator. The branch routed FIDO (`boot_fido(&mut *drbg, …)`) and left this
/// call site looking identical in a diff, which is why no name-based gate could
/// see it. `check_rng_path.py` now flags any `Rp2350Trng` named as a *type*
/// outside the declared construction sites, so the next app's boot helper has
/// to declare itself instead of compiling.
#[inline(never)]
/// US-1553: hand the OATH applet its key region.
///
/// A `fn` item, not a closure, because `oath_core::install_region_provider`
/// stores a **code address** in its `AtomicPtr` — the same constraint the FIDO
/// provider's comment above states.
///
/// Two orders inside, and the sequence is not incidental:
///
/// 1. **Derive the key first.** A derivation that fails (cold OTP row, or an
///    all-zero root) must leave the handle in place, so a later call can still
///    succeed. Taking the handle first and then failing would consume the only
///    one that exists and permanently pin OATH to the legacy path.
/// 2. **Then take the handle**, which is `Option` precisely so that only this
///    first successful call moves it (see `boot::take_oath_key_region`).
///
/// `None` in any case means "no region", and the applet answers APDUs from the
/// legacy chunked store — never `fatal_boot`. S10: degrade, never halt.
fn oath_region() -> Option<fapico2_oath::oath_core::OathRegion> {
    let key = boot::derive_oath_payload_key()?;
    let region = boot::take_oath_key_region()?;
    Some(fapico2_oath::oath_core::OathRegion::new(
        ::alloc::boxed::Box::new(region),
        key,
    ))
}

fn boot_oath<T: Trng>(
    trng: &mut T,
    store: &mut boot::DeviceStore,
    chipid: u64,
) -> &'static mut OathApp {
    // SAFETY: the `boot::OATH_APP` write-once `static mut` slot; see
    // `boot_fido`.
    match unsafe {
        OathApp::boot_in_place(
            core::ptr::addr_of_mut!(boot::OATH_APP),
            trng,
            &mut *store,
            oath_device_id(chipid),
            // US-1030: the credential-key seal context, from the flash UID +
            // the OTP row. A **required** argument (US-130's reasoning): the
            // migration stream's plaintext OATH keys are re-sealed under it
            // during this very boot, and an app that booted without it would
            // serve credentials this firmware cannot seal at all. A failure
            // to derive it, or to re-seal under it, is the `Err` arm below —
            // a refusal, not a fallback.
            boot::derive_oath_seal(),
        )
    } {
        Ok(app) => app,
        Err(_) => boot::fatal_boot("oath: keystore boot failed"),
    }
}

#[main]
async fn main(spawner: Spawner) -> ! {
    defmt::info!("fapico2 boot");
    dlog!(crate::dbg::T_MAIN, crate::dbg::E_BOOT, 1, 0);
    bphase!(crate::dbg::P_MAIN_ENTERED);

    let p = embassy_rp::init(Default::default());
    bphase!(crate::dbg::P_HAL_INIT);

    // Board LED (GPIO25) for the heartbeat task + the trussed backend UI
    // (S-721-2, shared pin — see `led_heartbeat_task`): the write-once
    // slot must be initialized before either driver touches it.
    boot::init_static_slot(core::ptr::addr_of_mut!(boot::LED_OUT), Output::new(p.PIN_25, Level::High));

    // The board LED is now usable by the boot-phase markers: the write-once
    // slot above is initialized, so the flag that gates them can be set.
    // `dbg-log` needs it for the US-929 ladder; `boot-timeline` needs it for
    // `phase_blinks`, which is the only channel that can report progress on a
    // device that never enumerates (see `dbg::phase_blinks`).
    #[cfg(any(feature = "dbg-log", feature = "boot-timeline"))]
    crate::dbg::mark_led_ready();
    // …and the boot-phase LED ladder, which is **not** feature-gated: the
    // dark-board case it exists for is a *shipping* image failing, so an
    // instrument behind `dbg-log` (release-forbidden, US-922) could never
    // answer it. One pulse per boundary from here on; see `boot_led.rs`.
    crate::boot_led::ready();
    mark!(fapico2_firmware::bootphase::RUNG_HAL);

    // US-929 boot ladder, stage 1 (dbg-log builds only): main entered /
    // `.bss` cleared, the embassy HAL initialized, and the board LED
    // mounted — emitted as a SECOND `a=1` record (the first fires at the top
    // of `main`, before `embassy_rp::init`; seeing only that one localizes a
    // hang in the HAL-init window) plus the stage-1 LED pattern (2 blinks, the n+1 pattern).
    // Pre-Rust startup stages (reset handler, `.data` copy, `.bss` clearing)
    // live in the cortex-m-rt startup path, unreachable from Rust — stage 1
    // is the earliest rung (see dbg.rs ladder doc).
    #[cfg(feature = "dbg-log")]
    {
        crate::dbg::boot_stage(1);
    }

    // US-921: the presence windows drive the shared LED as the touch
    // prompt (a 6985'd CCID command or a CTAP2 UpRequired keepalive loop
    // lights it until the window closes). Write-once at boot, before any
    // task runs — the hook slot refuses a second install (fail-loud).
    assert!(
        fapico2_firmware::presence::set_touch_prompt_hook(Some(button::set_touch_prompt_led)),
        "touch-prompt hook double-install"
    );
    // Boot-phase rung 2: everything from here to the store mount is TRNG /
    // clock bring-up (`Rp2350Trng::from_peri`, the `TIMER0` proof, the boot
    // sanity draw) — the first boundary that can catch a peripheral-level
    // hang. Emitted here so the rung covers the driver construction too, not
    // just the clock check below.
    mark!(fapico2_firmware::bootphase::RUNG_TRNG);

    // US-1020: the presence handshake's event sink — the presence runtime
    // stamps one event per press / arm / discard / window / grant, and this
    // is where they go: the US-922 diagnostic ring, drained over CTAPHID
    // vendor command 0x42. Write-once at boot, same discipline as the
    // touch-prompt hook above.
    //
    // **Diagnostic builds only.** `dbg-log` is release-forbidden (US-922) and
    // `apdu-trace` is a dedicated capture build, so a shipping image installs
    // no sink at all: the runtime's counters still accumulate (that is the
    // in-process measurement US-1022 reads) and the hook branch is dead code.
    // A production-readable counter would be a new RS-Key vendor
    // sub-command, which US-1020 explicitly does not add — see
    // `docs/erase-budget.md` §2.3 and the module doc in `presence.rs`.
    #[cfg(any(feature = "dbg-log", feature = "apdu-trace"))]
    assert!(
        fapico2_firmware::presence::set_presence_event_hook(Some(presence_event_to_dbg)),
        "presence-event hook double-install"
    );

    // Hardware TRNG (US-380): the sole randomness source on the device.
    // S-721-2 (D-E): the trussed backend (opcard's entropy path) needs a
    // second driver handle over the same peripheral. embassy-rp hands out
    // `Peri<'static, T>` wrappers (not `Copy`), so the HAL's documented
    // duplication is used:
    // SAFETY: `Peri::clone_unchecked` is embassy-hal-internal's documented
    // duplication for exactly this case — the `Trng` driver is stateless
    // (`PhantomData` + config; `new()`'s `initialize_rng()` is an
    // idempotent register setup), and the two handles are never driven
    // concurrently: this one serves the boot path (FIDO/OATH keygen,
    // pre-task) and the backend one serves trussed requests inside the
    // CCID task's synchronous sections — single-core, cooperative
    // executor.
    //
    // US-1005: `from_peri` (not a hand-built `embassy_rp` driver) is what
    // keeps this file clear of `Trng::new`; `tests/scripts/check_rng_path.py`
    // fails on that name anywhere in `firmware/`. This handle is the one
    // legitimate direct draw left on the boot path — it produces the
    // `boot.entropy.v1` record, which is an *input* to every DRBG seed, so a
    // DRBG cannot be the source of the material that seeds it. Everything
    // downstream of it goes through the DRBG.
    //
    // US-1005 (D-10): the handle cloned on the next line was, until this
    // change, a second `Rp2350Trng` — an *unbounded* peripheral driver used
    // from inside a live CCID request for the migration nonce. It is now the
    // `Rp2350Probe` built further down, which waits under the entropy budget.
    let mig_probe_peri = unsafe { p.TRNG.clone_unchecked() };
    // US-1005: the seed path's peripheral handle. A third duplication over
    // the same singleton, used only from inside `FuseSeedSource::seed` (a
    // bounded `probe_bytes`), never concurrently with the two below — same
    // single-core cooperative discipline. Constructed but not started: the
    // ring oscillator is enabled per draw, by `Rp2350Probe`.
    let seed_probe_peri = unsafe { p.TRNG.clone_unchecked() };
    // The unbounded driver is constructed for its side effect —
    // `from_peri` is `Trng::new`, whose `initialize_rng` writes
    // `RNG_IMR` / `TRNG_CONFIG` / `SAMPLE_CNT1` / `RND_DIAG` (the health-test
    // configuration the probe deliberately does not re-derive) and takes the
    // `Peri` ownership token. Its *handle* has no user in a shipping build:
    // after the boot-entropy draw was rerouted (see `boot::ensure_boot_entropy`
    // for why that was the last one), the only remaining callers are the
    // `dbg-log` channel draw and the `apdu-trace` session tag, neither of
    // which is compiled into this configuration. The `allow` says exactly
    // that, and only that — if a build without those features ever starts
    // drawing through this handle again, the warning comes back.
    #[cfg_attr(
        not(any(feature = "dbg-log", feature = "apdu-trace")),
        allow(unused_mut, unused_variables)
    )]
    let mut trng = Rp2350Trng::from_peri(p.TRNG, TrngIrqs, Config::default());
    // US-1005: the bounded probe is built HERE rather than further down,
    // because the boot sanity draw below is routed through it. The ordering
    // constraint that matters is the opposite one: the probe must be built
    // *after* `Rp2350Trng::from_peri`, because that constructor's
    // `initialize_rng` is what writes `trng_debug_control` (the health-test
    // configuration the probe deliberately does not touch). The peripheral
    // is initialized, then every draw in this file goes through the probe.
    //
    // D-12: the second argument is the load-bearing part. `Rp2350Probe::new`
    // takes a `ClockReady`, which nothing outside `platform::trng::rp2350`
    // can construct — the only way to hold one is to have called
    // `Rp2350Timer::require_advancing()` and had it observe `TIMER0`
    // counting. That turns the wait's wall-clock budget from an ordering
    // convention into something the compiler enforces: a session that moves
    // this construction, or the sanity draw, ahead of the check gets a build
    // failure rather than a device that boots dark. A refusal here is
    // `fatal_boot` for the same reason `init_drbg` is — without a counting
    // clock there is no bounded wait at all, and an unbounded wait on the
    // boot path before USB enumerates is the hang US-1001 exists to remove.
    let clock = match Rp2350Timer::require_advancing() {
        Ok(clock) => clock,
        Err(_) => boot::fatal_boot("trng: TIMER0 is not counting; the entropy wait has no deadline"),
    };
    // US-1005 fix: the third argument is the configuration the probe
    // re-applies after an autocorrelation error. It is the same value
    // `from_peri` was given above, from the same constant, so the probe
    // cannot be built against a configuration the entropy budget was not
    // calibrated for. See `platform::trng::TrngConfig` for why the budget is
    // only valid for one pair of register values, and D-8 for the window
    // this closes.
    let mut seed_probe = Rp2350Probe::new(seed_probe_peri, clock, TrngConfig::default());
    // US-1005: the boot sanity draw, now BOUNDED. It used to be
    // `trng.random_bytes(&mut seed)` — 16 bytes through the *unbounded*
    // `blocking_fill_bytes`, i.e. the same self-retrying wait US-1001 exists
    // to remove, reachable on every boot, and the only such site the
    // allowlist's "one sanity draw" reason never disclosed. `probe_bytes`
    // applies the wall-clock budget (`MAX_ENTROPY_WAIT`) and the hard poll
    // cap, so a wedged peripheral now produces a bounded, reported refusal
    // here instead of a silent hang before USB enumerates.
    //
    // US-1008 fix: **this refusal is no longer fatal.** It was, and the
    // justification was that "the very next thing boot does
    // (`boot::init_drbg`) is fatal on exactly that condition" — which is
    // true, and which is precisely the argument against: a *diagnostic* that
    // can kill the boot is a diagnostic in the wrong place. It turned a
    // question ("did the peripheral produce a block in 20 ms?") into a
    // verdict about whether the device would ever enumerate, and it did so
    // at the site whose whole purpose is to *ask*. The authority on this
    // condition is `init_drbg`, four lines below, which is fatal by design
    // and for a stated reason; a second, earlier, less-informed fatal site
    // can only pre-empt it.
    //
    // What this actually changes, stated precisely rather than hopefully:
    //
    //  * On a TRNG that is **truly dead**, the device still halts before USB
    //    enumerates — `init_drbg` refuses fatally on the same fact. The
    //    fail-closed property is unchanged, and it was never the property
    //    at risk; refusing to boot on a dead entropy source is correct.
    //  * What is now reachable is the case where the *sanity draw* misses
    //    and the *seed* does not: a marginal peripheral, a configuration or
    //    clock fault the budget is mis-sized against, or the D-8 void
    //    window. Before this change that case was indistinguishable from
    //    the dead one, because the diagnostic was the thing that killed it.
    //  * The diagnostic output changes shape, which is the part worth
    //    having: the refusal is now *printed* before anything halts, so an
    //    RTT capture shows a defmt line naming this site and then the
    //    `init_drbg` line — two distinct facts, in order. Before, a dark
    //    boot showed one line and the operator could not tell which of the
    //    two entropy sites had refused. `boot::fatal_boot` itself only does
    //    `defmt::error!` + `loop {}`, so a release build with no RTT probe
    //    attached shows nothing either way; this does not fix that, and
    //    nothing here claims to.
    //
    // The device remains parked-dark on this branch for an unexplained
    // reason. This change is not a fix for that and does not assert one; it
    // removes one of the two places that could have been the cause, and
    // makes the remaining one observable in the order it happens.
    {
        let mut seed = [0u8; 16];
        match seed_probe.probe_bytes(&mut seed) {
            // The TRNG must produce non-zero output; a wired ring oscillator
            // will. A `debug_assert` and not a check, because a block of
            // zeros that *passed* the health tests is not a state this
            // device has a recovery for, and the release profile compiles
            // the assert out anyway.
            Ok(()) => debug_assert!(seed.iter().any(|&b| b != 0)),
            Err(_) => defmt::warn!(
                "trng: boot sanity draw refused (no validated block in budget); \
                 continuing to init_drbg, which is the authority on this"
            ),
        }
    }
    defmt::info!("trng ready");
    bphase!(crate::dbg::P_TRNG_READY);
    // US-922: the diagnostic drain channel (dbg-log builds only) is per-boot
    // random — derived here from the hardware TRNG and printed to this RTT
    // console only, never over USB and not derivable from enumeration. The
    // host-side pull script reads it from the RTT stream. Release builds
    // cannot enable dbg-log at all (the compile_error! in lib.rs refuses).
    // US-933: the `apdu-trace` capture build (release-allowed) reuses the
    // same per-boot channel + CTAP-HID drain surface for its ring.
    #[cfg(feature = "dbg-log")]
    {
        // US-922: full 32-bit TRNG entropy — no fixed prefix byte; the two
        // degenerate CTAP-HID CIDs (broadcast 0xFFFFFFFF, reserved/all-zero
        // 0x00000000) are redrawn away, never patched over.
        crate::dbg::init_channel(fapico2_firmware::dbg_cid::dbg_cid_new(|| {
            let mut draw = [0u8; 4];
            trng.random_bytes(&mut draw);
            draw
        }));
    }
    // US-933 capture build: this transport has no RTT probe attached, so a
    // per-boot random channel is unreadable on the host side. The capture
    // build (inert unless `apdu-trace` is on; release and dbg-log builds are
    // unaffected) pins the drain CID so `us933_pull_trace.py --cid` can
    // drain the ring without a probe. The ring holds only debug trace data.
    #[cfg(all(feature = "apdu-trace", not(feature = "dbg-log")))]
    {
        crate::dbg::init_channel([0xA5, 0x5A, 0xA5, 0x5A]);
    }
    // `boot-timeline` capture build: same reason as the US-933 line above, and
    // a different constant so a timeline drain can never be answered by an
    // apdu-trace build left on the board. Pinned rather than per-boot
    // random, because reading a per-boot channel requires an RTT attach
    // through the probe — and attaching a probe during boot is exactly the
    // trap in AGENTS.md ("never run fapico2 with a debugger attached"): it
    // makes every OTP read return 0xFFFFFFFF and the boot then dies in
    // `fatal_boot` on a key row it can actually read. Draining over
    // CTAP-HID after enumeration sidesteps the probe entirely.
    #[cfg(all(feature = "boot-timeline", not(feature = "dbg-log")))]
    {
        crate::dbg::init_channel([0x7B, 0x07, 0xB0, 0x07]);
    }
    // US-933: per-boot session tag for the APDU trace (a second TRNG draw,
    // so the trace dump self-identifies which boot produced it).
    #[cfg(feature = "apdu-trace")]
    {
        let mut tag = [0u8; 4];
        trng.random_bytes(&mut tag);
        crate::apdu_trace::init(tag);
    }
    // US-1006: there is no longer a *backend* TRNG handle. The trussed
    // service's `Rng` used to be a second `Rp2350Trng` over this peripheral;
    // it now serves from the DRBG built below, so the request path no longer
    // needs a peripheral handle at all. That is the whole point of the
    // change: one peripheral touch now underwrites `RESEED_INTERVAL` of
    // requests instead of one request each.
    //
    // `TrngIrqs` is a `Copy` ZST (the `bind_interrupts!` binding); it is used
    // once now, by the single driver construction above.
    // US-1005 (D-10): the migration-completion nonce handle
    // (`boot::DeviceMigrationHandler`'s AEAD DEK rewrap) is the bounded probe,
    // not a second `Rp2350Trng`. That is the whole of this commit's device
    // side: the last unbounded `blocking_fill_bytes` on a *request* path is
    // gone, and `check_rng_path.py`'s `Rp2350Trng::from_peri` cap in this file
    // is 1 as a result.
    //
    // Same SAFETY discipline as the handles above — documented duplication,
    // single-core serialized use — and one property stricter than they carry:
    // this is a second copy of the *bounded* probe, not a second driver, so
    // the two handles that can be reached from a request are now the same
    // implementation. D-11's driver/probe interleaving is **not** thereby
    // gone — the boot-path driver above still alternates with the probes
    // during boot, exactly as D-11 describes — but no request can reach it
    // any more, which is the half of D-11 that was a request-path hazard.
    // It is a separate object rather than a second borrow of
    // `DRBG_SEED_PROBE` because `FuseSeedSource` holds that one for the life
    // of the generator; see `boot::MIG_PROBE`.
    //
    // A second `require_advancing` rather than a reuse of the token above: the
    // `ClockReady` is consumed by value (that is what makes it a proof), so
    // each probe must earn its own — and the check is a couple of register
    // reads, not something worth caching a proof for.
    let mig_clock = match Rp2350Timer::require_advancing() {
        Ok(clock) => clock,
        Err(_) => boot::fatal_boot("trng: TIMER0 is not counting; the migration entropy wait has no deadline"),
    };
    boot::init_static_slot(
        core::ptr::addr_of_mut!(boot::MIG_PROBE),
        Rp2350Probe::new(mig_probe_peri, mig_clock, TrngConfig::default()),
    );
    // US-1005: the bounded probe the DRBG's seed path draws through. Built
    // next to `Rp2350Trng::from_peri` (see the ordering note there), used
    // first for the boot sanity draw and afterwards for the DRBG's reseeds.
    // It is handed to `DeviceBackend::boot` below, once the secure store
    // exists and a seed record can be read.

    // US-387/US-388/US-391/US-427: the secure store — every app secret
    // persists through it (the RP2350 secure-partition region, reserved at
    // the end of flash), never plain app flash. Boot validates both image
    // slots and either loads a valid image or refuses (see
    // [`boot::boot_slot_decision`]). The store is a `static mut` (see
    // [`boot::STORE`]) so it does not bloat the async frame. US-715: the
    // winning slot is read through bounded volatile windows
    // ([`boot::SecureSlotReader`]) — no whole-image buffer exists on the
    // boot path any more.
    // US-915: derive the boot store key (OTP key row + chipid) and set it
    // on the store BEFORE the slots are read — the sealed slots restore
    // only under the key, and the store's serialization re-seals through
    // it. The decision itself is the sealed boot policy: a slot loads only
    // as a tag-verified v3 image; legacy v2 in both slots is the one-time
    // migration signature (the restore below loads the primary's v2 image
    // and the final boot persist re-seals it into v3).
    // Boot-phase rung 3: **immediately before** the OTP key-row read, so a
    // freeze inside `derive_boot_store_key` is attributable to the read and
    // not to the phase before it. This is the leading suspect for a
    // post-flash dark boot, and it is the one rung where the "could adding a
    // marker perturb what it measures" question is real — answered in
    // `boot_led.rs`: the pulse completes ~80 ms before the first `OTP_DATA`
    // read, touches only GPIO25 and a read-only TIMER0 counter, and runs with
    // interrupts enabled. Nothing the read depends on is written.
    mark!(fapico2_firmware::bootphase::RUNG_OTP);
    let store_key = boot::derive_boot_store_key();
    bphase!(crate::dbg::P_STORE_KEY);
    // US-918: best-effort software lock of the C key row's page (OTP 0xE90)
    // — idempotent, never fatal. RUNTIME-ONLY: it does not survive reset, so
    // it is not a durable write-lock (D-14); see `boot::otp_hw_write_lock_key_row`.
    boot::otp_hw_write_lock_key_row();
    unsafe {
        (&*core::ptr::addr_of!(boot::STORE))
            .borrow_mut()
            .set_store_key(store_key)
    }
    let boot_slot = boot::boot_slot_decision(&store_key);
    let mut slot_reader = match boot_slot {
        boot::BootSlot::Primary => boot::SecureSlotReader::primary(),
        boot::BootSlot::Shadow => boot::SecureSlotReader::shadow(),
        // Fresh: the erased primary window — the reader form rejects it
        // (invalid magic) exactly as the old slice path did, so the store
        // boots empty and a fresh device derives new keys.
        boot::BootSlot::Fresh => boot::SecureSlotReader::primary(),
    };
    // SAFETY: the store is a `static mut` (see [`boot::STORE`]) so it does
    // not bloat the async frame; this borrow is pre-task (no executor task
    // exists yet) and touches nothing else.
    unsafe {
        (&*core::ptr::addr_of!(boot::STORE)).borrow_mut()
            .from_partition_image_reader(&mut slot_reader)
    }
    bphase!(crate::dbg::P_STORE_MOUNTED);
    // Boot-phase rung 4: the slot is decided and the winning image is
    // restored into `STORE`. A freeze below this rung is *not* the OTP read.
    mark!(fapico2_firmware::bootphase::RUNG_STORE);

    // US-929 boot ladder, stage 2 (dbg-log builds only): the secure store is
    // mounted — the slot decision made and the winning image restored into
    // `STORE` (a `Fresh` boot restores the empty erased slot the same way).
    #[cfg(feature = "dbg-log")]
    crate::dbg::boot_stage(2);

    // Construct the four CCID applets and the FIDO app, then spawn the
    // serve-loop tasks. Every stateful app boots FROM the restored store
    // (US-387/US-388 constructors): `new()` hands the app factory state and
    // silently drops everything persisted — E10's Row 5 lost the WRITE_CONFIG
    // marker across a power cycle exactly this way (the image in flash was
    // correct; the app simply never loaded it). The store reference is
    // reborrowed (`&mut *store`) so `ccid_task` keeps its `'static mut`.
    // SAFETY: the store is a `static mut` (see [`boot::STORE`]) so it does
    // not bloat the async frame; this reborrow (`&mut *store`) is what
    // `ccid_task` keeps as its `'static mut`.
    let mut store_handle = boot::store_handle();
    let store = &mut store_handle;

    // US-918: guarantee the boot-entropy slot before ANY path that derives
    // the bound device root (first-boot C→Rust migration below, the
    // migration authority / capture restore, and every app boot). Absence →
    // draw from the TRNG; the write rides the boot persist gate so the
    // record lands inside the sealed v3 store image. Fail-closed: without
    // the slot, bound derivations refuse (never the legacy fallback).
    boot::ensure_boot_entropy(&mut seed_probe, store);
    bphase!(crate::dbg::P_BOOT_ENTROPY);

    // US-1005: the device DRBG. **After** `ensure_boot_entropy` — the seed
    // source reads the record that call writes, and a missing record is the
    // fail-closed `MissingBootEntropy` refusal. It takes the bounded probe
    // handle built at the top of `main` and hands back the sole `&'static
    // mut` the trussed backend serves nonces from. A refusal is fatal: see
    // `boot::init_drbg` for why there is deliberately no fallback.
    //
    // The boot-path `trng` above is still used directly for
    // `ensure_fw_manifest` — and, until the D-10 fix, for the migration
    // handler. The manifest is a bootstrap draw US-1005 cannot route (a DRBG
    // needs a seed record, and the first thing this firmware does with a
    // seed record is create it). The migration handler was *not* a bootstrap
    // draw — it ran inside a CCID request — and it now goes through the
    // bounded `boot::MIG_PROBE` instead, so nothing on the request path
    // touches this unbounded handle any more. **Both app boots
    // (`boot_fido`, `boot_oath`) are served from the DRBG**, FIDO since
    // US-1005 and OATH from this fix; the review that prompted it found the
    // two call sites identical in a diff and only one of them routed.
    // Once the DRBG exists, the *request* path (opcard's entropy, via
    // `DeviceBackend::boot` below) no longer touches the peripheral per
    // request: it stretches one block across `RESEED_INTERVAL` of them.
    let drbg = unsafe { boot::init_drbg(seed_probe) };
    bphase!(crate::dbg::P_DRBG);
    // Boot-phase rung 5: a DRBG exists. Everything below this rung draws
    // through it, so a freeze below it cannot be an unbounded-peripheral
    // draw (US-1001/US-1005).
    mark!(fapico2_firmware::bootphase::RUNG_DRBG);

    // US-919: foreign-image boot admission (EPIC `security-hardening`, R9):
    // hash the running image's flash region and compare against the
    // last-known-good manifest in the sealed store slot. On a mismatch the
    // secure-partition slots were wiped BEFORE any app loads (the
    // data-loss-over-implant policy; release builds — dev builds
    // `--no-default-features` run log-only), the US-918 entropy slot was
    // redrawn, and boot continues with a fresh store (never re-comparing
    // this boot). See [`boot::ensure_fw_manifest`].
    let fw_decision = boot::ensure_fw_manifest(store);
    bphase!(crate::dbg::P_FW_MANIFEST);

    // US-423: canonical post-load image — US-715: the winning flash slot
    // itself. The firmware only ever programs the store's own
    // serialization, so the slot bytes are the T0 snapshot; the windowed
    // boot gates compare the live store against the slot through bounded
    // volatile windows instead of holding a whole-image T0 buffer (the old
    // `BOOT_PARTITION_BUF` snapshot). A fresh board takes the `Fresh`
    // source: the gate programs iff the store is no longer empty — the same
    // outcome the old T0 compare had for a first-boot empty store. The
    // reader is reconstructed per gate call (a slot index, not a copy).
    let slot_reader_for = |slot: boot::BootSlot| match slot {
        boot::BootSlot::Shadow => boot::SecureSlotReader::shadow(),
        boot::BootSlot::Primary | boot::BootSlot::Fresh => boot::SecureSlotReader::primary(),
    };

    // US-921: boot the shared presence runtime (write-once, before any
    // task runs) — the embassy millis clock is the same monotonic source
    // the HID transaction timeout uses (tasks.rs `hid_now_ms`).
    assert!(
        fapico2_firmware::presence::init(|| embassy_time::Instant::now().as_millis()),
        "presence runtime double-init"
    );

    // US-413 S-413-5: re-seed from a C-firmware data partition on the first
    // Rust boot (no-op marker afterwards; strictly read-only on the C region).
    // US-919: skipped on the wipe boot — the policy boots a fresh store; the
    // genuine next boot re-runs the one-time migration from the C partition
    // (which only the C firmware ever wrote — no implanted secret can hide
    // there).
    if fw_decision == fapico2_platform::fw_manifest::ForeignImageDecision::Load {
        boot::run_first_boot_migration(store);
    } else {
        defmt::info!("booting with a fresh store; C→Rust migration deferred (US-919)");
    }
    bphase!(crate::dbg::P_MIGRATION);
    // Boot-phase rung 6: first-boot C→Rust migration finished.
    mark!(fapico2_firmware::bootphase::RUNG_MIGRATION);

    // US-387: a failed keystore boot is fatal — a silently re-derived hkey
    // would orphan every enrolled credential. US-939: the app is constructed
    // into its write-once static slot (the [`boot::FIDO_APP`] pattern shared
    // with the CCID applets) and handed to `hid_task` as the sole
    // `&'static mut`. US-956: `boot_fido` builds the fields **directly into**
    // that slot (`FidoApp::boot_in_place`) and returns the slot's own
    // reference, so the 15.7 KiB app never transits this frame at all — not
    // as the sret destination of a by-value `boot`, not as a memcpy source.
    // The `&mut self` setter keeps the rest off the frame too. The by-value
    // form (`FidoApp::boot(...).with_presence_grant(...)`) is what made the
    // app materialize in the async-main frame (part of the 95,232 B
    // async-frame dark-boot overflow) and, at the US-951 tip, still cost a
    // 117,828 B boot call chain against a 5,056 B stack zone.
    // US-1005: the FIDO app's boot-time keystore material comes from the
    // DRBG, not the peripheral. `boot_in_place` is already generic over
    // `Trng`, so this is a change of argument rather than of type — and it
    // matters, because this is the app whose credential keys are generated
    // here, on the boot path, before any request has arrived.
    let fido_app = boot_fido(&mut *drbg, store);
    bphase!(crate::dbg::P_BOOT_FIDO);
    // US-921: the shared presence runtime is the FIDO user-presence grant
    // path — one pending-request slot bound to the BOOTSEL latch; a press
    // with no pending request never arms anything. The gate is
    // join-only (`request_grant_in_window`): the HID task's UpRequired
    // keepalive loop owns the window lifecycle, and this closure only
    // consumes a grant armed for this command's tag inside it.
    fido_app.set_presence_grant(fapico2_firmware::presence::request_grant_in_window);

    // US-130 (PICOForge-COMPAT): the chip-id read feeds two applet identities —
    // the OATH device-id (the SELECT `TAG_NAME` TLV, and hence the PBKDF2 salt
    // for the access key) and the mgmt TAG_SERIAL (R12: fleet fingerprinting
    // closed). One read feeds both, so there is no reason for two reads of the
    // same OTP row to disagree. It is read HERE rather than down at the mgmt
    // app because the OATH boot below has to happen while the DRBG is still
    // in its static: `boot::take_drbg` hands the generator to the trussed
    // backend below and resets the slot, so after that point there is no
    // `&mut` left to boot an app from.
    let device_chipid = match embassy_rp::otp::get_chipid() {
        Ok(c) => c,
        Err(_) => boot::fatal_boot("device chipid unavailable"),
    };
    // US-354 (S-711-2): OATH boots from the secure store, the same discipline
    // as FIDO (US-387) and OTP (US-388) — a corrupt keystore stream is fatal;
    // a silently re-seeded app would orphan every persisted credential.
    // US-939: `init_static_slot_with` + the `&mut self` setter, FIDO parity —
    // the by-value builder put an 11.3 KiB `OathApp` on the async-main frame.
    // US-956: constructed in place, into the slot itself — `boot_fido` parity.
    // US-1005: from the DRBG, like FIDO. `OathApp::new_in_place` fills the
    // 512-B boot RNG pool unconditionally and the SELECT challenge is drawn
    // from it, so an `Rp2350Trng` here is 24 unbounded peripheral waits per
    // boot *and* a nonce that bypasses the conditioned generator. Ordering
    // note: this sits before the backend boot on purpose (see the chip-id
    // comment above) — after `boot::take_drbg` there is no DRBG borrow left.
    // Both app boots only *read* the store, so hoisting OATH next to FIDO
    // does not perturb the boot persist gate below.
    let oath_app = boot_oath(&mut *drbg, store, device_chipid);
    bphase!(crate::dbg::P_BOOT_OATH);
    // US-903/US-921: the board button is the user-presence source for
    // RESET (INS 0x04) and SET_CODE-clear (INS 0x03) — through the
    // shared presence runtime, the same fail-closed grant path the
    // mgmt/FIDO apps use (US-702). The grant binds to the command's
    // tag (`PRESENCE_TAG_RESET`): a press with no pending request is
    // discarded by the runtime and arms nothing (anti-harvest), so a
    // hostile host looping OATH RESET can no longer harvest an
    // unrelated press into the wipe. US-921: the gate is join-or-open
    // (`window_grant`, mgmt parity) — the first 6985 opens the
    // cross-call window for the retry's press.
    oath_app.set_presence_grant(fapico2_firmware::presence::window_grant);

    // S-721-2 (D-E): the trussed backend (littlefs2 internal FS on QSPI
    // flash) needs a second `Flash` handle over the same peripheral. The
    // driver is stateless (`dma: None` + `PhantomData`) and the two
    // handles program DISJOINT regions — this one (via the `FLASH_DEV`
    // slot) the secure image slots at `0x3F_0000+`, the backend one the
    // trussed FS window at `0x102_000 .. 0x202_000` (the const boundary
    // assert in `trusted_backend::device`) — and all access is
    // single-core-serialized (synchronous sections, no `.await` inside).
    // SAFETY: `Peri::clone_unchecked` — as for the TRNG above: stateless
    // driver, documented HAL duplication, disjoint-region single-core use.
    let backend_flash: boot::DevFlash = Flash::new_blocking(unsafe { p.FLASH.clone_unchecked() });

    // US-1559: the per-record key region needs a THIRD `Flash` handle over the
    // same peripheral, on exactly the terms `backend_flash` above sets out —
    // the driver is stateless (`dma: None` + `PhantomData`), and this one
    // addresses `flashmap::KEY_REGION_OFFSET .. +KEY_REGION_BYTES`, a window
    // `flashmap.rs:145-160` asserts is disjoint from both other consumers'
    // (the trussed FS window and the secure image slots).
    //
    // **Constructed here, released later.** `p.FLASH` is consumed on the next
    // line and a `Flash` cannot be built without a `Peri`, so this is the only
    // place the handle can be made. Nothing is read: `Flash::new_blocking`
    // stores `Option::None` plus a `PhantomData`
    // (`embassy-rp-0.10.0/src/flash.rs:255-260`) and `init_key_region` only
    // parks the value in its write-once slot. The handle stays unreachable
    // until `release_key_region` runs, below `mark!(RUNG_USB)` — which is the
    // S8/S9 guarantee, enforced at runtime rather than by source order.
    //
    // A third *handle* rather than a second `&mut` to `FLASH_DEV`: two `&mut`
    // to one object is UB whether or not the non-overlap argument holds (the
    // `DRBG_SEED_PROBE` doc in `boot.rs` says so), and the alternative to a
    // new handle was aliasing the secure-partition driver.
    //
    // SAFETY: `Peri::clone_unchecked` — as for the TRNG and for `backend_flash`
    // above: stateless driver, documented HAL duplication, disjoint-region
    // single-core use. `boot::init_key_region` — single-core boot path, before
    // any task exists; the slot is written exactly once here and not read until
    // `release_key_region`.
    unsafe {
        boot::init_key_region(boot::KeyRegionHandle::new(Flash::new_blocking(
            p.FLASH.clone_unchecked(),
        )))
    };

    // US-1553: OATH needs a **FOURTH** handle, not a second `&mut` to the one
    // above. `OathApp::attach_region` takes ownership and holds the handle for
    // the life of the process, while the FIDO accessor mints a fresh
    // `&'static mut` for every CTAP2 command — a permanent `&mut` beside a
    // stream of transient ones over one object is UB whether or not the
    // non-overlap argument holds, which is the `DRBG_SEED_PROBE` rule stated
    // twice in `boot.rs`.
    //
    // (`key_region_boot_gate.rs` scans this file for the FIDO accessor's
    // spelling and fails on any occurrence before `RUNG_USB` — *including
    // inside a comment*, which is how this sentence had to be written twice.)
    //
    // A second handle over the same physical window, with disjoint slot ranges:
    // OATH owns `[0, OATH_CAPACITY)` at the head and FIDO starts after the
    // scratchpad, asserted exact by `keyregion/mod.rs`'s compile-time tiling
    // check. Same serialization as every other handle here — single core, no
    // region method ever yields.
    //
    // SAFETY: as for the third handle above. `boot::init_oath_key_region` —
    // single-core boot path, before any task exists; the slot is written once
    // here and not read until `release_key_region`.
    unsafe {
        boot::init_oath_key_region(boot::KeyRegionHandle::new(Flash::new_blocking(
            p.FLASH.clone_unchecked(),
        )))
    };

    let flash: boot::DevFlash = Flash::new_blocking(p.FLASH);
    // S-701-3: hand the flash handle to the write-once static (single init,
    // boot path) so the HID task can persist FIDO keystore changes too.
    unsafe { (&mut *core::ptr::addr_of_mut!(boot::FLASH_DEV)).write(flash) };
    let flash: &'static mut boot::DevFlash =
        unsafe { (&mut *core::ptr::addr_of_mut!(boot::FLASH_DEV)).assume_init_mut() };

    // S-721-2 (D-E): boot the trussed backend (platform + stores + the one
    // client) and hand the client to the OpenPGP app (constructed into its
    // static below, with `take_client`).
    // SAFETY: the board LED pointer is the `LED_OUT` slot, initialized
    // exactly once at the top of `main`; sharing it with the 1 Hz
    // heartbeat task is the documented shared-pin contract on
    // `DeviceBackend::boot` (single-core serialized; the trussed UI
    // temporarily overrides the heartbeat inside a request).
    // SAFETY: `DeviceBackend::boot` — one-shot boot; the handles above are
    // the second (backend) TRNG/Flash and the shared LED pointer.
    let mut t0_reader = slot_reader_for(boot_slot);
    bphase!(crate::dbg::P_GATE1_PRE);
    if with_durable_boot_windowed(
        &mut *store,
        WindowedBootImage::Slot(&mut t0_reader),
        &mut tasks::secure_slot_sink(flash),
        || unsafe {
            // Inside the closure, so this marker is stamped *after* the
            // gate's compare-and-program has run: P_GATE1_PRE..P_GATE1_POST
            // is persist gate #1 alone, and P_GATE1_POST..P_BACKEND is
            // `DeviceBackend::boot` (the trussed mount, and the
            // `Filesystem::format` when the volume is not mountable).
            bphase!(crate::dbg::P_GATE1_POST);
            DeviceBackend::boot(
                backend_flash,
                // The one generator, moved out of its static by
                // `boot::take_drbg` (the same "take by value exactly once"
                // shape as `take_client`). Nothing holds a reference to it
                // after this point, so the CCID task's synchronous sections
                // are the only accessors — single-core, cooperative executor.
                boot::take_drbg(),
                (*core::ptr::addr_of_mut!(boot::LED_OUT)).as_mut_ptr(),
                boot::migration_authority(),
            )
        },
    ).is_none() {
        boot::fatal_boot("migration: capture persistence failed; backend not mounted");
    }
    bphase!(crate::dbg::P_BACKEND);
    // E6 (S-391-10): construct each CCID app once into its static slot and take
    // a `&'static mut`. The apps no longer live on the `ccid_task` spawn frame —
    // that move was the remaining frame bloat after E5's by-ref store fix.
    // US-413 S-413-6: device migration-completion handler — the mgmt
    // INS 0x1F APDU completes the passphrase-gated classes (FIDO keydev
    // PIN, OpenPGP PW1) against the C partition and the store.
    // R12: the mgmt TAG_SERIAL derives from the OTP chipid, so each device
    // presents a distinct serial (fleet fingerprinting closed). The chip-id
    // itself is read above, next to the OATH boot that shares it.
    // Publish the chipid-derived serial for the FIDO task's
    // `CTAP_READ_CONFIG` (`0x42`) answer. Same derivation as the applet's
    // TAG_SERIAL and the USB descriptor (`usb_ident::serial_hash4`), so all
    // three agree by construction.
    tasks::DEVICE_SERIAL.store(
        u32::from_be_bytes(fapico2_mgmt::serial_from_chipid(device_chipid)),
        core::sync::atomic::Ordering::Relaxed,
    );

    let management_app = boot::init_static_slot(
        core::ptr::addr_of_mut!(boot::MANAGEMENT_APP),
        ManagementApp::boot(&mut *store)
            .with_chipid(device_chipid)
            .with_migration_handler(unsafe {
                &mut *core::ptr::addr_of_mut!(boot::MIGRATION_HANDLER)
            })
        // US-702/US-921: the board button is the user-presence source for
        // WRITE_CONFIG / config-lock writes — through the shared presence
        // runtime (fail-closed without a press *while the request is
        // pending*; a stale latch never arms a grant). US-921: the gate is
        // join-or-open (`window_grant`) — a refused WRITE_CONFIG opens a
        // 15 s cross-call window and lights the touch prompt, so the
        // user's press on the RETRY is consent for the retry.
        .with_presence_grant(fapico2_firmware::presence::window_grant)
        // US-711: the device-wide factory-reset hook — RESET (0x1E) wipes
        // the FIDO keystore + hkey, OATH table and OTP slots too, behind
        // the same user-presence grant.
        .with_factory_reset(unsafe {
            &mut *core::ptr::addr_of_mut!(boot::FACTORY_RESET_HANDLER)
        }),
    );
    let otp_app =
        boot::init_static_slot(core::ptr::addr_of_mut!(boot::OTP_APP), OtpApp::boot(&mut *store));
    // US-143 (PICOForge-COMPAT): the board button is the user-presence
    // source for a `CFG_CHAL_BTN_TRIG` challenge-response slot — through
    // the same shared presence runtime, and with the same
    // `window_grant` join-or-open gate, the mgmt WRITE_CONFIG and OATH
    // RESET consumers use. The grant binds to the OTP applet's OWN tag
    // (`PRESENCE_TAG_CHAL_BTN_TRIG`, the tail of the OTP AID): the
    // runtime's single pending-request slot grants only an exact tag, so
    // a touch meant for an OATH RESET, an OpenPGP PSO:SIGN or a FIDO
    // touch cannot arm a challenge-response, and vice versa. The OTP tag
    // is bit-31 clear, so it stays clear of the HID/FIDO tag domain
    // (`presence_tag_from_channel`).
    //
    // NOTE: `picoforge::calculate_hmac` is a single `transceive_full` with
    // no retry, so a touch-gated slot the user programmed through the
    // reference client is refused (6985) and the client surfaces the
    // error rather than prompting. That is a property of the client, not
    // of this wiring; the gate is correct on its own terms and the
    // divergence is reported in the US-143 story notes.
    otp_app.set_presence_grant(fapico2_firmware::presence::window_grant);
    // US-OTP-HID: the Yubico OTP HID transport (keyboard-usage interface +
    // YK4 feature-report frames) drives this same app. The handlers read the
    // boot slot directly, so they must be installed AFTER it is initialized
    // (above) and BEFORE the USB device is built (further down).
    otp_hid::init();
    // S-721-2: the real OpenPGP app — opcard over the trussed client,
    // which the app owns by value (`take_client` moved it out of the
    // backend static after `DeviceBackend::boot` above). US-939: built
    // straight into its static slot, FIDO/OATH parity.
    let openpgp_app = boot::init_static_slot_with(
        core::ptr::addr_of_mut!(boot::OPENPGP_APP),
        || OpenPgpApp::new(take_client()),
    );
    // US-914: touch-to-sign — PSO:SIGN / PSO:DECIPHER / INT-AUTH
    // consume a presence grant from the shared presence runtime
    // (blocking BOOTSEL-edge wait while the request is pending;
    // the host/emulation default auto-acks).
    openpgp_app.set_presence_grant(button::pso_wait_grant);
    // A fresh handle (the handle is Copy): the long-lived `store` reborrow
    // above stays live for the boot persist below.
    boot::restore_openpgp_at_boot(openpgp_app, &mut boot::store_handle());

    // US-160 (PICOForge-COMPAT): the RS-Key vendor LED applet (AID
    // `F0 00 00 00 01`). Booted from the same shared secure partition as the
    // other four, so a LED profile the host wrote survives a reboot; there is
    // no injection to attach (the applet holds no presence source, no hardware
    // handler and no device identity — it stores a 17-byte block and serves it).
    let vendor_led_app = boot::init_static_slot(
        core::ptr::addr_of_mut!(boot::VENDOR_LED_APP),
        VendorLedApp::boot(&mut *store),
    );

    // US-161/162/163 (PICOForge-COMPAT Phase H): the Rescue applet
    // (AID `A0 58 3F C1 9B 7E 4F 21`, CLA `0x80`). It is registered on the
    // **device** and not only in the emulator: the client reaches it over
    // CCID, which is a device transport, and US-163's BOOTSEL reboot means
    // nothing on a host process. The threat model that justifies shipping an
    // unauthenticated surface this size is `docs/tasks/rescue-threat-model.md`;
    // the residual risks it accepts (R1 write path, R2/R3 disclosure, R5
    // reboot, R9 `SECURE`) are recorded there and in the applet's module docs.
    //
    // Three injections, and each is a fact the applet cannot know for itself:
    //
    // * the chip id, from the real OTP row (the SELECT block's bytes `[4..12]`
    //   are the full 8 raw bytes — a widening of what every other surface
    //   discloses, recorded as R3);
    // * the flash figures, which the applet cannot measure and the firmware
    //   can: the sealed secure partition's capacity and the live snapshot's
    //   length, against the chip's compile-time flash size;
    // * the two owners — the PHY record (the FIDO keystore's auth-map key
    //   6, reached durable-before-ack through the store) and the privileged
    //   `REBOOT` / `SECURE` actions.
    let rescue_app = boot::init_static_slot(
        core::ptr::addr_of_mut!(boot::RESCUE_APP),
        {
            let mut used = fapico2_platform::secure_store::SecureStore::snapshot_len(&*store);
            let total = boot::SECURE_PARTITION_SIZE;
            // `snapshot_len` can exceed the sealed bound only if a foreign
            // image wrote something this build would not have; clamp rather
            // than report `free` as a huge number wrapped through `u32`.
            if used > total {
                used = total;
            }
            // US-1080: the board file's flash size, the same value
            // `firmware/src/boot.rs` compiles its `Flash` handle from — so the
            // `READ FlashInfo` figures a Rescue client reads cannot disagree
            // with the part the image was linked for.
            let chip_size = fapico2_platform::board::FLASH_SIZE_BYTES;
            RescueApp::new()
                .with_chipid(device_chipid)
                .with_flash_stats(fapico2_rescue::FlashStats {
                    free: u32::try_from(total - used).unwrap_or(u32::MAX),
                    used: u32::try_from(used).unwrap_or(u32::MAX),
                    total: u32::try_from(total).unwrap_or(u32::MAX),
                    // `SecureStore` exposes `contains` but no enumeration, so
                    // the device cannot count live records; 0 is reported
                    // rather than a fabricated count (see `FlashStats::nfiles`).
                    nfiles: 0,
                    chip_size: u32::try_from(chip_size).unwrap_or(u32::MAX),
                })
                // Nothing in this firmware implements secure boot (threat
                // model §0.3), so the status this serves is the honest one.
                .with_secure_boot_status(fapico2_rescue::SecureBootStatus {
                    enabled: false,
                    locked: false,
                })
                .with_config_handler(unsafe {
                    &mut *core::ptr::addr_of_mut!(boot::RESCUE_CONFIG_HANDLER)
                })
                .with_device_handler(unsafe {
                    &mut *core::ptr::addr_of_mut!(boot::RESCUE_DEVICE_HANDLER)
                })
                // US-1536: `WRITE PhyConfig` rewrites the USB identity, so it
                // takes the same join-or-open touch window the OATH and mgmt
                // applets already use (`window_grant`, not
                // `request_grant_in_window` — the CCID task owns no window of
                // its own, so the gate opens one on demand). pico-keys-sdk
                // gates the same APDU on `rescue_require_user_presence()`;
                // RS-Key does the same. Without it this applet is an
                // unauthenticated, unattended rewrite of the device's VID/PID.
                .with_presence_grant(fapico2_firmware::presence::window_grant)
        },
    );

    // Build + register the dispatcher on the boot path so it too stays off the
    // task frame. Registration is a hard boot error (duplicate AID / capacity):
    // an assert parks here — equivalent to the old in-task parking guard.
    let mut dispatcher = Dispatcher::new();
    assert!(
        register_ccid_apps(
            &mut dispatcher,
            management_app,
            oath_app,
            otp_app,
            openpgp_app,
            vendor_led_app,
            rescue_app,
        ),
        "ccid app registration failed (duplicate AID or capacity)"
    );
    let dispatcher =
        boot::init_static_slot(core::ptr::addr_of_mut!(boot::CCID_DISPATCHER), dispatcher);
    bphase!(crate::dbg::P_DISPATCHER);
    // Boot-phase rung 7: every applet is constructed into its write-once slot
    // and registered. Placed *after* the trussed-UI window
    // (`DeviceBackend::boot`, which drives the same pin with
    // `set_status(Processing)`), so this pulse's "park the pin off" is the
    // last thing that happens to GPIO25 before the dispatcher boundary.
    mark!(fapico2_firmware::bootphase::RUNG_APPS);

    // S-722-6: final persistence after restore/registration, BEFORE serving.
    // The `persist_start` binding exists only to feed the `E_PSD` record's
    // `b` field, so it carries the same cfg as that `dlog!` — see the two-arm
    // `dlog!` definition at the top of this file.
    #[cfg(any(feature = "dbg-log", feature = "boot-timeline"))]
    let persist_start = embassy_time::Instant::now();
    dlog!(crate::dbg::T_MAIN, crate::dbg::E_PST, 0, 0);
    bphase!(crate::dbg::P_GATE2_PRE);
    let mut final_reader = slot_reader_for(boot_slot);
    let boot_persist = persist_boot_change_windowed(
        &mut *store,
        WindowedBootImage::Slot(&mut final_reader),
        &mut tasks::secure_slot_sink(flash),
    );
    dlog!(crate::dbg::T_MAIN, crate::dbg::E_PSD, 0, persist_start.elapsed().as_micros() as u32);
    bphase!(crate::dbg::P_GATE2_POST);
    if !boot_persist {
        boot::fatal_boot("secure partition: boot persist failed; serving suppressed");
    }

    // The stored physical configuration becomes the boot-time USB identity.
    // Until now `CONFIG_WRITE`-saved VID/PID/product/manufacturer were durable
    // but never applied — the descriptors read only the build-time constants,
    // so a configurator's identity change never reached the bus. Field-by-
    // field precedence: a stored field replaces its build-time counterpart, an
    // absent one leaves it (the C SDK's `phy_data` semantics). VID/PID can
    // only change at enumeration, so an identity change takes effect on the
    // next boot/re-plug. The borrow of `fido_app` ends here; `Usb::new` copies
    // the names into write-once statics.
    let stored_identity = {
        let phy = fido_app.phy();
        fapico2_platform::usb::StoredIdentity {
            vid_pid: phy.vid_pid,
            product: phy.product.map(|n| fapico2_platform::usb::StoredName::new(n.as_bytes())),
            manufacturer: phy
                .manufacturer
                .map(|n| fapico2_platform::usb::StoredName::new(n.as_bytes())),
        }
    };

    // SAFETY: USB descriptor buffers (must be `'static` for the builder).
    let usb = Usb::new(
        p.USB,
        unsafe { &mut *core::ptr::addr_of_mut!(CONFIG_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(BOS_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(MSOS_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(CONTROL_BUF) },
        device_chipid,
        Some(stored_identity),
    );
    let parts = usb.into_parts();

    spawner.spawn(usb_task(parts.device)).unwrap();
    bphase!(crate::dbg::P_USB_UP);
    // Boot-phase rung 8: the USB device is constructed and `usb_task`
    // spawned. This is the rung that answers the question the dark board
    // actually poses: a freeze *below* it never reached USB at all, a board
    // that reaches it and then stops enumerating is a different fault with
    // the same symptom.
    //
    // `spawner.spawn` only enqueues — the executor does not poll `usb_task`
    // until `main` awaits, so this marker and `release()` below still own the
    // pin.
    mark!(fapico2_firmware::bootphase::RUNG_USB);
    // US-1559: publish the per-record key region. **This is the wiring, and it
    // is deliberately the first thing after `RUNG_USB`.** The handle was built
    // up at the other `Flash::new_blocking` block (it has to be — `p.FLASH` dies
    // there) but stayed unreachable until this line: before it, `boot::
    // key_region()` answers `None`, so no boot-path caller can read the region
    // even if one appears (S8/S9). After it, the region belongs to the applets
    // and the first read happens in whichever applet operation runs first.
    //
    // Nothing here can fail: the release flips one flag. An applet that finds
    // the region unreadable gets an empty key set and a clean CTAP error (S10),
    // never a halt.
    boot::release_key_region();
    // US-1552: hand the region to the FIDO applet. **This is the line that makes
    // the migration take effect on hardware** — without it nothing calls the
    // region path, LTO proves `REGION_PROVIDER` is never written, and the whole
    // key-region implementation is linked out of the image.
    //
    // A `fn` pointer rather than a closure, because `REGION_PROVIDER` stores the
    // provider's code address (`device_app.rs::install_region_provider`) and a
    // capturing closure would not be one. It asks `boot::key_region()` at every
    // call, which is what makes "before RUNG_USB it answers None" a guarantee
    // rather than a comment.
    fapico2_fido::device_app::install_region_provider(|| {
        boot::key_region().map(|r| r as &'static mut dyn fapico2_platform::keyregion::KeyRegion)
    });
    // US-1553: the same line for OATH, and it is just as load-bearing — without
    // it nothing calls `attach_region`, LTO proves `REGION_PROVIDER` is never
    // written, and OATH's 68 reserved slots stay flash nothing reads.
    fapico2_oath::oath_core::install_region_provider(oath_region);
    // US-929 boot ladder, stage 3 (dbg-log builds only): the USB device is
    // constructed and `usb_task` spawned — configuration completes when the
    // executor first polls `usb_task` (stage 4's record proves that poll
    // happened). The LED pattern here is synchronous, so the actual bus
    // configuration still lands a few executor ticks later.
    #[cfg(feature = "dbg-log")]
    crate::dbg::boot_stage(3);
    spawner
        .spawn(tasks::ccid_task(
            parts.ccid_in,
            parts.ccid_out,
            boot::store_handle(),
            dispatcher,
            flash,
        ))
        .unwrap();
    // US-425: the HID task also persists the FIDO keystore to the flash
    // secure partition before every CTAP-HID reply (durable-before-ack —
    // the Token2 dark-data-loss fix). It needs the same store and flash
    // handles the `ccid_task` spawn above just took, so derive fresh
    // `&'static mut` handles from the same write-once statics.
    // SAFETY: these references alias the ones `ccid_task` owns, but the
    // device is a single-core cooperative executor and each task touches
    // the store/flash only inside strictly-synchronous sections (the persist
    // window — `persist_one`/`persist_apps` + `FlashSlotSink`, no `.await`
    // inside — plus, CCID side only, the migration-complete handler), so at
    // most one task can be inside a store/flash section at any moment.
    // Mirrors the `boot::FLASH_DEV` doc and the `DeviceMigrationHandler`
    // SAFETY rationale.
    let hid_store = boot::store_handle();
    let hid_flash: &'static mut boot::DevFlash =
        unsafe { (&mut *core::ptr::addr_of_mut!(boot::FLASH_DEV)).assume_init_mut() };
    spawner
        .spawn(tasks::hid_task(
            parts.hid_in,
            parts.hid_out,
            fido_app,
            hid_store,
            hid_flash,
        ))
        .unwrap();

    // The heartbeat must not block the executor: a busy-wait blink loop spun
    // the executor thread for seconds per burst, starving every serve-loop
    // poll — CTAP-HID replies lagged a full transaction behind and
    // python-fido2 timed out on stale INIT replies (E7c, ladder doc). The
    // LED runs on a Timer-driven task (C parity `led_blinking_task`, 1 Hz)
    // and main() parks while the serve loops run.
    spawner.spawn(led_heartbeat_task()).unwrap();
    // US-702: the button poll task latches short-presses for user presence.
    spawner.spawn(button::button_poll_task()).unwrap();

    // US-929 boot ladder, stage 4 (dbg-log builds only): all serve-loop
    // tasks are spawned and main() parks into the executor loop — the 1 Hz
    // heartbeat takes the LED over from here. The stages map to
    // `dbg::boot_stage` (E_BOOT records `a = 1..=4` == LED blink count − 1);
    // a missing stage-N record/pattern localizes the dark stage to the
    // window between stage N−1 and N.
    #[cfg(feature = "dbg-log")]
    crate::dbg::boot_stage(4);
    bphase!(crate::dbg::P_SERVING);
    // Boot-phase rung 9: every serve-loop task, including the 1 Hz heartbeat,
    // is spawned. A board that shows nine pulses and then settles into the
    // heartbeat booted fine — the fault is post-boot (USB enumeration), and
    // the two are now one glance apart.
    mark!(fapico2_firmware::bootphase::RUNG_SERVING);
    // Hand GPIO25 to the runtime drivers, and **park it dark**.
    //
    // This is the last statement before `main` parks into the executor, which
    // makes it the earliest instant at which any other owner of the pin can
    // exist: the heartbeat task (first polled only when `main` awaits), the
    // trussed `LedUi` (inside a serve task), and the touch-prompt hook
    // (inside a presence window). After `release()` the ladder is inert for
    // the rest of the run, so a boot-phase pulse can never leave GPIO25
    // latched on and read as an open consent window — see `boot_led.rs`.
    crate::boot_led::release();

    // Executor alive with the serve loops running.
    loop {
        Timer::after_secs(3600).await;
    }
}

/// US-391 E7c: 1 Hz heartbeat LED task (C parity, `led_blinking_task`).
///
/// Shares the board LED (the `LED_OUT` slot) with the trussed backend UI
/// (S-721-2, D-E.3): `Output` is not shareable by value, so the trussed
/// UI drives the same boot-constructed `Output` through a raw pointer
/// (see `trusted_backend::device::LedUi`). The two drivers never
/// interleave — the device is single-core and the executor cooperative:
/// the trussed UI runs only inside a synchronous request section (the
/// "call thyself" runner has no yield point), where it temporarily
/// overrides the heartbeat, and the heartbeat resumes between requests.
#[task]
async fn led_heartbeat_task() {
    // SAFETY: the `LED_OUT` slot is initialized exactly once at the top of
    // `main`; this `&'static mut` and the trussed UI's pointer (the
    // shared-pin contract, see above) are serialized single-core — the
    // UI only touches the pin inside synchronous trussed-request sections,
    // and the heartbeat only between them (its `await` points are the only
    // places a trussed request can run).
    let led: &'static mut Output<'static> =
        unsafe { (&mut *core::ptr::addr_of_mut!(boot::LED_OUT)).assume_init_mut() };
    loop {
        led.set_low(); // ON (active-low)
        Timer::after_millis(500).await;
        led.set_high(); // OFF
        Timer::after_millis(500).await;
    }
}

/// Run the USB device (control transfers + endpoint scheduling). Never
/// returns.
#[task]
async fn usb_task(mut device: UsbDevice<'static, Driver<'static, USB>>) {
    device.run().await;
}

/// US-1020: route one presence event into the US-922 diagnostic ring.
///
/// Installed as the presence runtime's event hook in `dbg-log` /
/// `apdu-trace` builds only (see the install in `main`). `T_HID` is reused
/// deliberately: `dbg::log_throttled` indexes a 3-task table, so a fourth
/// task id would index out of bounds — the presence records are told apart by
/// their event code, not by a task byte, and the ring already stamps its own
/// microsecond clock per record.
#[cfg(any(feature = "dbg-log", feature = "apdu-trace"))]
fn presence_event_to_dbg(ev: fapico2_firmware::presence::PresenceEvent) {
    use fapico2_firmware::presence::PresenceEventKind as K;
    let (event, b) = match ev.kind {
        K::Press => (crate::dbg::E_PRESS, ev.now_ms),
        K::Armed => (crate::dbg::E_PARM, ev.now_ms),
        K::Discarded => (crate::dbg::E_PDISCARD, ev.now_ms),
        K::Window => (crate::dbg::E_PWINDOW, ev.now_ms),
        // The grant record carries the touch→consent latency in `b`, not the
        // clock: the record already stamps its own microsecond time, and the
        // latency is the figure US-1022 is judged against.
        K::Grant => (crate::dbg::E_PGRANT, ev.delta_ms),
    };
    crate::dbg::log(crate::dbg::T_HID, event, ev.tag, b);
}

