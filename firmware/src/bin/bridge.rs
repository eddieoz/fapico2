//! E2 bridge — partition-read isolation (US-391, S-391-3).
//!
//! The known-good `bringup.rs` base (static-mut store + EMPTY image +
//! composite USB + stage LED pattern: LED on ~2 s → 500 ms toggle) with
//! exactly **one** delta: the real boot-time XIP read of the
//! `.secure_partition` flash region feeding
//! `STORE.from_partition_image(&…)` — the E1 TEMP DEBUG image's partition
//! read. If this blinks and enumerates, the real partition read is
//! exonerated as the E1 dark-boot cause; if dark, the read is implicated and
//! the E2+ raw 64-byte XIP-read stage runs.
//!
//! Reproducibility (the S-391-3 redo contract): this source and its
//! `firmware/bridge.uf2` artifact build from the **committed tree** — no
//! uncommitted platform code. USB identity stays at the committed
//! `20a0:42b2`; the `fa20:0002` rebrand is S-391-7's scope. The read lands in
//! a static buffer instead of the E1 image's stack temporary so the bridge
//! isolates the XIP read alone, not the E1 frame/stack hypothesis. See
//! `docs/tasks/us391-boot-ladder.md` (cycle E2) for the pre-registered
//! predictions and the recorded observation.

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

// --- The E2 delta: the real partition read, from the committed main.rs
// (single-slot `.secure_partition` image), so the bridge differs from
// bringup in exactly one variable.

/// Worst-case size of the serialized secure-partition image (see
/// [`Rp2350SecureStore::PARTITION_IMAGE_MAX`]).
const SECURE_PARTITION_SIZE: usize = Rp2350SecureStore::PARTITION_IMAGE_MAX;

/// Secure-partition image region (US-388): linked into the reserved
/// `.secure_partition` flash region (the generated `memory.x`), distinct from
/// the app text.
/// Boot reads the keystore directly from this image — erased flash is 0xFF
/// (an empty store), and app secrets never touch the plain app-flash region.
///
/// `#[used]` + the linker script's `KEEP` hold the section through LTO/gc;
/// the volatile boot read (see `read_secure_partition_image`) keeps the flash
/// content authoritative — without it, LTO const-folds the 0xFF initializer
/// and a later re-flash of the region would be ignored.
#[used]
#[link_section = ".secure_partition"]
static SECURE_PARTITION: [u8; SECURE_PARTITION_SIZE] = [0xFF; SECURE_PARTITION_SIZE];

/// Boot-time read buffer. Static, not stack — the image is ~9 KB and must not
/// land on the async main() future's stack; the E1 image read it through a
/// stack temporary, which is one of the hypotheses this bridge deliberately
/// does **not** test.
static mut BOOT_PARTITION_BUF: [u8; SECURE_PARTITION_SIZE] = [0; SECURE_PARTITION_SIZE];

/// Read the secure-partition flash image through volatile accesses so LTO
/// cannot const-fold the (future, driver-programmed) flash content, writing
/// into the static boot buffer. The committed main.rs returns the image by
/// value through a stack temporary — the only deliberate deviation, made so
/// the bridge isolates the XIP read as a single variable.
fn read_secure_partition_image() -> &'static [u8] {
    // SAFETY: `SECURE_PARTITION` is a `'static` flash-resident image of
    // exactly `SECURE_PARTITION_SIZE` bytes; the volatile reads stay in
    // bounds and race with nothing (pre-task boot path, single core).
    unsafe {
        let src = core::ptr::addr_of!(SECURE_PARTITION) as *const u8;
        let buf = &mut *core::ptr::addr_of_mut!(BOOT_PARTITION_BUF);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = core::ptr::read_volatile(src.add(i));
        }
        &*core::ptr::addr_of!(BOOT_PARTITION_BUF)
    }
}

/// US-915: the boot store key (OTP key row 0xE90 + chipid) — the same
/// derivation the production boot path runs (`main.rs` bin's
/// `boot::derive_boot_store_key`); inlined here because the bridge bin has
/// no `boot` module. `expect` (not a loop) keeps the bring-up LED markers
/// observable if identity reads fail.
fn bridge_store_key() -> [u8; 32] {
    let mut otp_key_1 = [0u8; 32];
    for i in 0..16u8 {
        let w = embassy_rp::otp::read_ecc_word(0xE90 + i as usize).expect("OTP key row 0xE90");
        otp_key_1[(i as usize) * 2..(i as usize) * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }
    let chipid = embassy_rp::otp::get_chipid().expect("chipid");
    fapico2_platform::store_v3::derive_store_key(&otp_key_1, &chipid.to_be_bytes())
}

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

    // Stage 1: TRNG init. (identical to bringup)
    let mut trng = Rp2350Trng::new(EmbTrng::new(p.TRNG, TrngIrqs, Config::default()));
    {
        let mut seed = [0u8; 16];
        trng.random_bytes(&mut seed);
        debug_assert!(seed.iter().any(|&b| b != 0));
    }
    defmt::info!("trng ready");

    // Stage 2 (the E2 delta): the real partition read. bringup used
    // `&EMPTY_IMAGE`; the E1 image used exactly this call. US-915: the
    // store is keyed at boot (OTP key row + chipid, the same derivation the
    // production boot path runs) so a sealed slot restores.
    static mut STORE: Rp2350SecureStore = Rp2350SecureStore::new();
    unsafe {
        (&mut *core::ptr::addr_of_mut!(STORE)).set_store_key(bridge_store_key());
        (&mut *core::ptr::addr_of_mut!(STORE)).from_partition_image(read_secure_partition_image());
    }
    defmt::info!("secure store from real partition");

    // Stage 0 marker: LED on for ~2s then blink. If this shows, embassy init
    // and the partition read both worked. (identical to bringup)
    let mut led = Output::new(p.PIN_25, Level::Low); // ON (active-low)
    Timer::after_millis(2000).await;

    // US-103: the real OTP chipid — the same value the store key above binds
    // to, so the USB serial and the store identity name the same board.
    let chipid = embassy_rp::otp::get_chipid().expect("chipid");

    // Bring up the composite USB device (CCID + HID), same as bringup/hwtest.
    let usb = Usb::new(
        p.USB,
        unsafe { &mut *core::ptr::addr_of_mut!(CONFIG_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(BOS_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(MSOS_DESC) },
        unsafe { &mut *core::ptr::addr_of_mut!(CONTROL_BUF) },
        chipid,
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
