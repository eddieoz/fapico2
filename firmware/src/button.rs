//! US-702: physical-button user presence (device build).
//!
//! The C firmware gates `WRITE_CONFIG` on the board button (`button.c`):
//! the BOOTSEL button, read through the QSPI-CS trick (Hi-Z the QSPI SS
//! pad, sample the pad input, restore — `picok_get_bootsel_button`). The
//! first Rust wiring polled SIO GPIO1 instead, which is an unconnected
//! header pin on a stock Pico 2, so real BOOTSEL presses never latched
//! (hardware-verified 2026-09-21: WRITE_CONFIG always returned 6985); it
//! now performs the same QSPI-CS read as the C.
//!
//! The button is polled by a cooperative task (10 ms), edge-detected, and
//! the short-press is latched. US-921: the latch is drained through the
//! shared presence runtime (`fapico2_firmware::presence`) — the sticky
//! latch alone is never a grant; it arms one only while a command's
//! request is pending, and a press with nothing pending is discarded
//! (anti-harvest). US-921 review: there is no legacy fall-through — the
//! OATH app (RESET / SET_CODE-clear) consumes its grants through the same
//! shared runtime (`with_presence_grant`), so a press with no pending
//! request arms nothing at all.

use core::sync::atomic::Ordering;

use embassy_executor::task;

use embassy_time::Timer;

/// RP2350 pad-CTRL layout (`GpioCtrl` in rp-pac `io/regs.rs` — differs
/// from RP2040, where OEOVER is at 12:13): OUTOVER 12:13, **OEOVER
/// 14:15**. OEOVER `0b10` = output drive disabled (pad floats; the
/// BOOTSEL button pulls it low). Poking 12:13 instead — the RP2040
/// layout — was the first wiring bug (it set OUTOVER=LOW, never Hi-Z'ing
/// the pad).
const OEOVER_DISABLE: u32 = 0b10 << 14;
const OEOVER_MASK: u32 = 0b11 << 14;
/// C parity: 1000-iteration settle loop (`button.c`).
const SETTLE_ITERATIONS: u32 = 1000;

/// US-914 hardware-debug fix: the RP2350 IO_QSPI bank **prepends the two
/// USBPHY pads** before the QSPI pads (rp235x SVD: USBPHY_DP at 0x00,
/// USBPHY_DM at 0x08, SCLK 0x10, **SS 0x18**, SD0..3 0x20..0x38 — the
/// RP2040 bank has SS at index 1). `IO_QSPI.gpio(1)` — the RP2040 index
/// the first wiring used — is USBPHY_DM on the RP2350, so every press
/// read was toggling and sampling the USB DM pad (zero edges ever seen
/// on hardware: the US-914 BDD touch windows were all refused). The C
/// SDK reads the level through SIO `GPIO_HI_IN` with the same `#else`
/// branch (`button.c`): on RP2350 QSPI_CSN is bit 27 (RP2040: bit 1).
const QSPI_SS_PAD_INDEX: usize = 3;
const SIO_GPIO_HI_IN_QSPI_CSN_BIT: u32 = 1 << 27;

/// Sample the BOOTSEL button with the QSPI-CS trick (C parity,
/// `picok_get_bootsel_button`): Hi-Z the QSPI SS pad, let the 1 kΩ
/// button pull-down win over the flash's drive, sample the SIO
/// `GPIO_HI_IN` QSPI_CSN bit, restore.
///
/// **Must run from RAM** (`__no_inline_not_in_flash_func` in the C;
/// embassy-rp's `read_cs_status` uses the same `.data.ram_func` trick):
/// while the pad floats, ANY XIP fetch through CS hangs the bus — the
/// first flash build of this read hard-hung the board on the first poll
/// (device frozen, LED stuck on). Interrupts stay disabled for the
/// settle window (µs), as in C.
#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
fn bootsel_pressed() -> bool {
    cortex_m::interrupt::free(|_| {
        let ss = rp_pac::IO_QSPI.gpio(QSPI_SS_PAD_INDEX);
        let orig = ss.ctrl().read().0;
        ss.ctrl().write(|w| w.0 = (orig & !OEOVER_MASK) | OEOVER_DISABLE);
        let mut settle = SETTLE_ITERATIONS;
        while settle > 0 {
            core::hint::black_box(&settle);
            settle -= 1;
        }
        let hi_in = rp_pac::SIO.gpio_in(1).read();
        let pressed = hi_in & SIO_GPIO_HI_IN_QSPI_CSN_BIT == 0;
        ss.ctrl().write(|w| w.0 = orig);
        pressed
    })
}

/// Poll the board BOOTSEL button (active low) and latch press edges.
///
/// US-921: every edge is latched into the shared runtime's press latch and
/// drained through it — the service arms a grant only while a command's
/// request is pending; a press with nothing pending is discarded without
/// arming anything (anti-harvest). US-921 review: the discarded press has
/// **no** legacy landing spot — the OATH app takes its grants from the
/// same shared runtime, so one physical press grants at most one command
/// and a press bound to no pending request expires with it.
#[task]
pub async fn button_poll_task() {
    let mut was_pressed = bootsel_pressed();
    loop {
        // US-914 review fix: a blocking presence wait (touch-to-sign) may
        // have sampled the pad between this task's polls — adopt its last
        // observed level as the edge baseline, so a press the wait
        // consumed is not re-detected as a fresh edge here (one physical
        // press grants at most one command).
        if let Some(level) = fapico2_firmware::presence::adopt_wait_level() {
            was_pressed = level;
        }
        let pressed = bootsel_pressed();
        let edge = pressed && !was_pressed;
        if edge {
            // US-921: the shared runtime's latch is the press's sole
            // landing spot; the drain decides its fate (armed vs discarded).
            fapico2_firmware::presence::PRESS_LATCH.store(true, Ordering::SeqCst);
        }
        was_pressed = pressed;
        // US-921 review: drain through the shared runtime. A press with no
        // pending request is discarded — it arms nothing, here or anywhere
        // else (the OATH legacy raw-latch fall-through is gone; OATH RESET
        // consumes grants from the same shared runtime, bound to its
        // PRESENCE_TAG_RESET tag).
        fapico2_firmware::presence::drain_press();
        Timer::after_millis(10).await;
    }
}

/// US-921: the touch prompt for the presence windows — the shared board
/// LED driven as ON while a consent window is open (a refused CCID
/// command or a CTAP2 UpRequired keepalive loop), OFF when it closes.
/// Registered as the presence runtime's touch-prompt hook at boot
/// (`main`: `presence::set_touch_prompt_hook`); the HID loop re-asserts
/// it each keepalive iteration and clears it at every exit path, and the
/// CCID path clears it on the grant — cheap mitigation for the heartbeat
/// flicker while the window is open.
///
/// SAFETY: the `LED_OUT` slot is initialized exactly once at the top of
/// `main` (before any task runs, so no hook can fire early); this access
/// is serialized against the heartbeat task and the trussed UI by the
/// shared-pin contract (single core, cooperative executor — the
/// heartbeat only runs at a task's `.await` points, the trussed UI only
/// inside synchronous request sections).
pub fn set_touch_prompt_led(on: bool) {
    let led: &mut embassy_rp::gpio::Output<'static> =
        unsafe { (&mut *core::ptr::addr_of_mut!(crate::boot::LED_OUT)).assume_init_mut() };
    if on {
        led.set_low(); // ON (active-low)
    } else {
        led.set_high(); // OFF
    }
}

/// US-914: touch-to-sign wait for the OpenPGP app — the device-build
/// presence gate for PSO:SIGN / PSO:DECIPHER / INT-AUTH. Blocks the CCID
/// serve task for at most [`PSO_TOUCH_WINDOW_MS`] while the shared
/// presence runtime holds the pending slot under the operation tag; a
/// BOOTSEL press *edge* inside the window arms and consumes exactly one
/// grant. The pad is sampled here directly (paced) because the button
/// poll task is starved while the serve task blocks; the steady ON light
/// for the whole window is the touch prompt (the heartbeat is starved
/// too, so this is the only driver during the wait).
///
/// No key material is ever logged — the operation tag only.
pub fn pso_wait_grant(tag: u32) -> bool {
    // US-906 window parity: 10 s, the same grant-expiry budget the
    // platform presence service uses (`PRESENCE_WINDOW_MS`). It must stay
    // under the host's T=1 transaction-abort ceiling (observed ~14.5 s
    // over libccid — US-920's WTX work owns longer waits) so the refusal
    // is observable as SW=6982 rather than a host-side transport abort.
    const PSO_TOUCH_WINDOW_MS: u64 = 10_000;
    // SAFETY: the `LED_OUT` slot is initialized exactly once at the top of
    // `main`; this access is serialized against the heartbeat task and the
    // trussed UI by the shared-pin contract (single core, cooperative
    // executor — the heartbeat only runs at this task's `.await` points,
    // the trussed UI only inside synchronous request sections; this whole
    // wait is one synchronous section inside the serve task).
    let led: &mut embassy_rp::gpio::Output<'static> =
        unsafe { (&mut *core::ptr::addr_of_mut!(crate::boot::LED_OUT)).assume_init_mut() };
    led.set_low(); // ON (active-low) — the touch prompt
    let granted = fapico2_firmware::presence::wait_grant(tag, PSO_TOUCH_WINDOW_MS, paced_bootsel);
    led.set_high(); // OFF — the heartbeat resumes at the next await
    if granted {
        defmt::info!("US-914: presence granted (op {=u32:x})", tag);
    } else {
        defmt::warn!("US-914: touch-to-sign refused, no press (op {=u32:x})", tag);
    }
    granted
}

/// One paced BOOTSEL level sample for [`pso_wait_grant`]: a ~5 ms busy
/// pause — interrupts stay enabled, so the USB driver keeps its IRQs (the
/// settle loop inside `bootsel_pressed` masks them for µs per read) — then
/// the pad level. The pause sets the wait's poll rate and keeps IRQ-on
/// time high while the serve task blocks. Every level is published to the
/// presence runtime so the button task can resync its edge baseline after
/// the wait (US-914 review fix — one press grants at most one command).
fn paced_bootsel() -> bool {
    let start = embassy_time::Instant::now();
    while start.elapsed() < embassy_time::Duration::from_millis(5) {}
    let pressed = bootsel_pressed();
    fapico2_firmware::presence::note_wait_level(pressed);
    // Re-assert the touch prompt every poll: concurrent CCID requests
    // (pcscd's GetSlotStatus polling) pass through trussed, whose
    // Processing→Idle bracketing flips the LED OFF mid-wait — the
    // hardware BDD caught the prompt showing as solid OFF (2026-09-23).
    // SAFETY: as `pso_wait_grant` — the shared `LED_OUT` slot, serialized
    // single-core; this runs inside the serve task's synchronous wait.
    unsafe { (&mut *core::ptr::addr_of_mut!(crate::boot::LED_OUT)).assume_init_mut() }
        .set_low();
    pressed
}
