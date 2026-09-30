//! HW bring-up bisect binary v3 (temporary, US-391 debugging).
//! LED tells the operator how far boot gets:
//!   * LED ON ~2 s            -> app started (flash boot + reset OK)
//!   * 3 quick blinks x2      -> embassy_rp::init + GPIO OK
//!   * 5 quick blinks x2      -> Usb::new + usb_task spawned OK
//!   * continuous 1 Hz blink  -> main task looping (executor alive)
//!
//! If the device ALSO enumerates (VID FA20 PID 0002), USB init works.
#![no_std]
#![no_main]

use defmt_rtt as _;
use embassy_executor::{main, task};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::USB;
use embassy_time::Timer;
use fapico2_platform::usb::{Usb, UsbDevice};

static mut CONFIG_DESC: [u8; 256] = [0; 256];
static mut BOS_DESC: [u8; 256] = [0; 256];
static mut MSOS_DESC: [u8; 256] = [0; 256];
static mut CONTROL_BUF: [u8; 256] = [0; 256];

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        cortex_m::asm::nop();
    }
}

#[main]
async fn main(spawner: embassy_executor::Spawner) -> ! {
    let p = embassy_rp::init(Default::default());
    let mut led = Output::new(p.PIN_25, Level::Low);

    // Stage 0: solid 2 s = we are executing.
    led.set_high();
    Timer::after_millis(2000).await;

    // Stage 1: 3 blinks.
    for _ in 0..6 {
        led.toggle();
        Timer::after_millis(120).await;
    }
    Timer::after_millis(600).await;
    for _ in 0..6 {
        led.toggle();
        Timer::after_millis(120).await;
    }

    // US-103: the real OTP chipid. These are bring-up binaries, but they run
    // on real silicon with a real OTP row, so injecting the fixed emulation
    // stand-in here would make every board flashed as this binary advertise
    // the *same* fleet-wide serial — the exact fingerprinting bug US-103
    // exists to remove. Read the chipid like `bridge.rs` does. (The emulation
    // path never reaches `Usb::new` at all — it is TCP-based — so
    // `EMULATION_CHIPID` has no USB caller.)
    let chipid = embassy_rp::otp::get_chipid().expect("chipid");

    // Stage 2: bring up the composite USB device (CCID + HID).
    let usb = Usb::new(
        p.USB,
        unsafe { &mut *core::ptr::addr_of_mut!(CONFIG_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(BOS_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(MSOS_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(CONTROL_BUF) },
        chipid,
        // Diagnostics: no keystore to consult, so the build-time identity stands.
        None,
    );
    let parts = usb.into_parts();
    spawner.spawn(usb_task(parts.device)).unwrap();

    // Stage 3: 5 blinks, then a 1 Hz heartbeat forever.
    for _ in 0..10 {
        led.toggle();
        Timer::after_millis(120).await;
    }
    loop {
        led.toggle();
        Timer::after_millis(500).await;
    }
}

#[task]
async fn usb_task(mut device: UsbDevice<'static, embassy_rp::usb::Driver<'static, USB>>) {
    device.run().await;
}
