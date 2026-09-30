//! The flash-slot [`ImageSink`] (US-422, EPIC `SECURE-PERSIST` Phase A).
//!
//! This is the behavior-identical port of the old `persist_secure_partition`
//! / `secure_slot_matches` pair (now deleted from `firmware/src/main.rs`):
//! the gate (`crate::persist`) hands this sink a windowed image source
//! (US-715), which programs it into the reserved on-flash image slots —
//! primary first, then shadow (the US-391 durability pair: a power loss
//! mid-program leaves at least one valid slot for the next boot).
//!
//! Compare-then-write per slot: a slot whose flash content already matches
//! the image is skipped (NOR erase cycles are wear-limited and persist is
//! rare — a `WRITE_CONFIG`-class admin APDU). A slot whose read fails is
//! reprogrammed (the safe side). Only the image's `image_len` bytes are
//! compared and programmed; the rest of each slot stays erased (0xFF)
//! padding, which boot reads back and ignores (self-delimiting format — see
//! `secure_store::partition_image_len`).
//!
//! No heap on the device path: the compare and the program walk the image
//! in 256-byte zeroized stack windows pulled from the source — no
//! whole-image buffer exists anywhere on this path (US-715).

use crate::persist::{ImageSink, WindowedImageSource};
use crate::secure_store::SecureStoreError;

/// Bounded stack window transiting serialized secret bytes — zeroized on
/// drop (US-704).
struct ProgWindow<const N: usize>([u8; N]);

impl<const N: usize> Default for ProgWindow<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for ProgWindow<N> {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

const WINDOW: usize = 256;

/// Blocking NOR-flash access the sink programs through (US-422).
///
/// Device: the embassy-rp QSPI `Flash` driver (the `DevSlotFlash` adapter in
/// `firmware/src/main.rs` — the orphan rule keeps it next to its local
/// struct). Host / tests: a `Vec`-backed NOR model (`tests/persist_sink.rs`).
/// Driver failures map to [`SecureStoreError::Flash`].
pub trait SlotFlash {
    /// Read `buf.len()` bytes at `addr`.
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), SecureStoreError>;
    /// Erase the `from..to` region (the caller passes the full slot window).
    fn erase(&mut self, from: u32, to: u32) -> Result<(), SecureStoreError>;
    /// Program `data` at `addr` (NOR: only clears bits).
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), SecureStoreError>;
}

/// Programs the partition image into two on-flash slots (primary + shadow),
/// compare-then-write (US-422).
pub struct FlashSlotSink<F> {
    flash: F,
    primary: u32,
    shadow: u32,
    slot_bytes: usize,
}

impl<F> FlashSlotSink<F> {
    /// Wrap a flash driver around the primary/shadow slot offsets. `slot_bytes`
    /// is each slot's on-flash size (rounded up to the NOR erase granularity).
    pub fn new(flash: F, primary: u32, shadow: u32, slot_bytes: usize) -> Self {
        Self {
            flash,
            primary,
            shadow,
            slot_bytes,
        }
    }

    /// Borrow the underlying flash driver. The host tests read the programmed
    /// bytes and the erase/write address log through this.
    pub fn flash_mut(&mut self) -> &mut F {
        &mut self.flash
    }
}

impl<F: SlotFlash> ImageSink for FlashSlotSink<F> {
    fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool {
        let len = src.image_len();
        let mut skipped = 0usize;
        for off in [self.primary, self.shadow] {
            if slot_matches(&mut self.flash, off, src, len) {
                skipped += 1;
                continue;
            }
            let to = off + self.slot_bytes as u32;
            if self.flash.erase(off, to).is_err() {
                log_erase_failed(off);
                return false;
            }
            if write_windowed(&mut self.flash, off, src, len).is_err() {
                log_write_failed(off);
                return false;
            }
            log_programmed(off, to);
        }
        if skipped == 2 {
            log_unchanged();
        }
        true
    }
}

/// Program `len` image bytes at `off`, pulling 256-byte windows from the
/// source (the embassy driver splits these into page-level flash ops
/// internally, exactly as it did for the old single contiguous slice). A
/// source underrun (short window) is a program failure — the safe side.
fn write_windowed(
    flash: &mut dyn SlotFlash,
    off: u32,
    src: &mut dyn WindowedImageSource,
    len: usize,
) -> Result<(), SecureStoreError> {
    let mut win = ProgWindow::<WINDOW>::default();
    let mut at = 0usize;
    while at < len {
        let n = core::cmp::min(WINDOW, len - at);
        if src.image_window(at, &mut win.0[..n]) != n {
            return Err(SecureStoreError::Corrupt);
        }
        flash.write(off + at as u32, &win.0[..n])?;
        at += n;
    }
    Ok(())
}

/// Compare the image against the current flash contents at `off` in
/// 256-byte windows pulled from the source (keeps the stack small — no heap
/// on the device path); true only when the whole image already matches (the
/// slot padding after the image is not compared). Any read failure returns
/// false — reprogram, the safe side. Behavior-identical port of the deleted
/// `secure_slot_matches` (`firmware/src/main.rs`).
fn slot_matches(
    flash: &mut dyn SlotFlash,
    off: u32,
    src: &mut dyn WindowedImageSource,
    len: usize,
) -> bool {
    let mut cur = ProgWindow::<WINDOW>::default();
    let mut img = ProgWindow::<WINDOW>::default();
    let mut at = 0usize;
    while at < len {
        let n = core::cmp::min(WINDOW, len - at);
        if src.image_window(at, &mut img.0[..n]) != n {
            return false;
        }
        match flash.read(off + at as u32, &mut cur.0[..n]) {
            Ok(()) if cur.0[..n] == img.0[..n] => {}
            Ok(()) => return false,
            Err(_) => return false, // unreadable flash: reprogram (safe side)
        }
        at += n;
    }
    true
}

// ---------------------------------------------------------------------------
// Logging — defmt on device, stderr in emulation / host tests (mirrors
// `persist::persist_error`). The offset-carrying lines carry the same
// wording as the deleted `main.rs` code.
// ---------------------------------------------------------------------------

fn log_erase_failed(off: u32) {
    #[cfg(all(feature = "device", target_arch = "arm"))]
    defmt::error!("secure partition: flash erase failed @ {=u32:x}", off);
    #[cfg(not(target_arch = "arm"))]
    std::eprintln!("secure partition: flash erase failed @ {off:#x}");
}

fn log_write_failed(off: u32) {
    #[cfg(all(feature = "device", target_arch = "arm"))]
    defmt::error!("secure partition: flash program failed @ {=u32:x}", off);
    #[cfg(not(target_arch = "arm"))]
    std::eprintln!("secure partition: flash program failed @ {off:#x}");
}

fn log_programmed(off: u32, to: u32) {
    #[cfg(all(feature = "device", target_arch = "arm"))]
    defmt::info!("secure partition: programmed {=u32:x}..{=u32:x}", off, to);
    #[cfg(not(target_arch = "arm"))]
    std::eprintln!("secure partition: programmed {off:#x}..{to:#x}");
}

/// The all-skipped report — US-422's "one skipped-slot report on the second
/// run" (an unchanged image programs nothing).
fn log_unchanged() {
    #[cfg(all(feature = "device", target_arch = "arm"))]
    defmt::info!("secure partition: image unchanged, slots skipped");
    #[cfg(not(target_arch = "arm"))]
    std::eprintln!("secure partition: image unchanged, slots skipped");
}
