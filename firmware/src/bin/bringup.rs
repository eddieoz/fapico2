//! Incremental bring-up binary (US-391 debugging).
//!
//! Starts from the known-good hwtest (composite USB + LED blink) and adds the
//! full app's initialization one piece at a time so we can isolate which step
//! dark-boots the board.
//!
//! Stage 0 (this file): USB + blink only. Confirmed-boots baseline.

#![no_std]
#![no_main]

use defmt_rtt as _;
use embassy_executor::{main, task};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{TRNG, USB};
use embassy_rp::trng::{Config, Trng as EmbTrng};
use embassy_rp::bind_interrupts;
use embassy_time::Timer;
use fapico2_platform::secure_store::Rp2350SecureStore;
use fapico2_platform::trng::{Rp2350Trng, Trng};
use fapico2_platform::usb::{Usb, UsbDevice};

bind_interrupts!(struct TrngIrqs {
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<TRNG>;
});

/// Erased-flash image (all 0xFF): invalid magic → from_partition_image boots
/// an empty store. Const so it lives in .rodata, not on the stack.
const EMPTY_IMAGE: [u8; Rp2350SecureStore::PARTITION_IMAGE_MAX] =
    [0xFF; Rp2350SecureStore::PARTITION_IMAGE_MAX];

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

    // Stage 1: TRNG init.
    let mut trng = Rp2350Trng::new(EmbTrng::new(p.TRNG, TrngIrqs, Config::default()));
    {
        let mut seed = [0u8; 16];
        trng.random_bytes(&mut seed);
        debug_assert!(seed.iter().any(|&b| b != 0));
    }
    defmt::info!("trng ready");

    // Stage 2c: secure store in a static (NOT in the async frame). Large
    // structs must live outside the future to avoid bloating it.
    static mut STORE: Rp2350SecureStore = Rp2350SecureStore::new();
    unsafe {
        (&mut *core::ptr::addr_of_mut!(STORE)).from_partition_image(&EMPTY_IMAGE);
    }
    defmt::info!("secure store in static");

    // Stage 0 marker: LED on for ~2s then blink. If this shows, embassy init works.
    let mut led = Output::new(p.PIN_25, Level::Low); // ON (active-low)
    Timer::after_millis(2000).await;

    // US-103: the real OTP chipid. These are bring-up binaries, but they run
    // on real silicon with a real OTP row, so injecting the fixed emulation
    // stand-in here would make every board flashed as this binary advertise
    // the *same* fleet-wide serial — the exact fingerprinting bug US-103
    // exists to remove. Read the chipid like `bridge.rs` does. (The emulation
    // path never reaches `Usb::new` at all — it is TCP-based — so
    // `EMULATION_CHIPID` has no USB caller.)
    let chipid = embassy_rp::otp::get_chipid().expect("chipid");

    // Bring up the composite USB device (CCID + HID), same as hwtest.
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

    // Blink loop = executor alive.
    loop {
        led.toggle();
        Timer::after_millis(500).await;
    }
}

#[task]
async fn usb_task(mut device: UsbDevice<'static, embassy_rp::usb::Driver<'static, USB>>) {
    device.run().await;
}
