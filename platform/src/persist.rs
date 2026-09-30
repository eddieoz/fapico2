//! Platform persist gate (US-421, EPIC `SECURE-PERSIST` Phase A).
//!
//! Contract (verbatim): *Transports MUST call the persist gate after every
//! dispatched command and BEFORE sending the success reply. Apps with
//! durable state MUST implement `persist_state`/`Persist`; apps that never
//! set dirty need nothing.*
//!
//! This module is the ONLY code path that sequences
//! persist-dirty-app-state → snapshot-partition-image → program-sink
//! ("durable-before-ack"). Transports (CCID task, HID task, emulation serve
//! loop, boot) call the gate with their [`ImageSink`]; they never touch the
//! snapshot/program sequence themselves.
//!
//! US-715 (windowed image I/O): the image never exists as a whole anywhere
//! on this path. The gate hands the sink a [`WindowedImageSource`] — a
//! random-access window reader over the store's serialized partition image
//! — and sinks (the flash slot sink, the host file sink, test recorders)
//! pull bounded windows (≤512 B) as they compare/program. The former
//! worst-case static scratch (`IMAGE_SCRATCH`, ~9 KiB of bss per the size
//! report) is gone; the host/test seam fns keep their scratch parameter as
//! a *budget* so their pinned fail-closed behavior survives.
//!
//! Error semantics (host-tested in `tests/persist_gate.rs`):
//! * an app whose store write fails stays dirty (retry on the next command)
//!   and the gate returns `false`;
//! * the sink is programmed only after at least one app wrote to the store;
//! * if the sink program fails after a successful store write, the gate
//!   re-marks exactly the writing apps dirty and returns `false` — the
//!   previous good image is untouched (a persist failure never corrupts it),
//!   and the change retries on the next command.

use crate::dispatch::App;
#[cfg(all(feature = "device", target_arch = "arm"))]
use crate::secure_store::ImageReader;
use crate::secure_store::SecureStore;

// Host (emulation / test) builds need a heap `Vec` to materialize an image
// (test sinks record whole images; the device path never does).
#[cfg(not(target_arch = "arm"))]
use std::vec::Vec;

use crate::secure_store::SecureStoreError;

/// US-715: bounded random-access window over a serialized partition image.
///
/// The persist gate no longer materializes whole images: sources expose the
/// exact image length plus windowed byte reads, and every consumer (sinks,
/// compares) walks the image in bounded chunks. `image_window` fills `buf`
/// with the image bytes at `off` and returns how many bytes it filled (0
/// once `off` reaches the end; short fills only at the image tail).
pub trait WindowedImageSource {
    /// Exact serialized image length (the walk bound).
    fn image_len(&self) -> usize;
    /// Fill `buf` with image bytes at `off`; returns the bytes filled.
    fn image_window(&self, off: usize, buf: &mut [u8]) -> usize;
}

/// [`WindowedImageSource`] over any [`SecureStore`] — the gate's device and
/// host path. The length is captured once at construction (the image cannot
/// change under the gate: single-core synchronous sections, no `.await`).
pub struct StoreImageSource<'a> {
    store: &'a dyn SecureStore,
    len: usize,
}

impl<'a> StoreImageSource<'a> {
    /// Wrap `store`; captures its snapshot length once.
    pub fn new(store: &'a dyn SecureStore) -> Self {
        Self {
            len: store.snapshot_len(),
            store,
        }
    }
}

impl WindowedImageSource for StoreImageSource<'_> {
    fn image_len(&self) -> usize {
        self.len
    }
    fn image_window(&self, off: usize, buf: &mut [u8]) -> usize {
        self.store.snapshot_window(off, buf)
    }
}

/// [`WindowedImageSource`] over a borrowed byte slice — the loaded-image
/// compare side (the host seam fns and the test harnesses).
pub struct BufferImageSource<'a> {
    img: &'a [u8],
}

impl<'a> BufferImageSource<'a> {
    pub fn new(img: &'a [u8]) -> Self {
        Self { img }
    }
}

impl WindowedImageSource for BufferImageSource<'_> {
    fn image_len(&self) -> usize {
        self.img.len()
    }
    fn image_window(&self, off: usize, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.img.len().saturating_sub(off));
        buf[..n].copy_from_slice(&self.img[off..off + n]);
        n
    }
}

/// Materialize a windowed image (host / test only): pulls the whole image
/// through bounded windows into a heap `Vec`. The device never calls this —
/// it is the test-sink convenience that replaces the old whole-image
/// hand-off (`sink.program(img, len)`).
#[cfg(not(target_arch = "arm"))]
pub fn pull_image(src: &mut dyn WindowedImageSource) -> Vec<u8> {
    let mut img: Vec<u8> = std::vec![0u8; src.image_len()];
    let mut at = 0;
    while at < img.len() {
        let n = core::cmp::min(512, img.len() - at);
        let filled = src.image_window(at, &mut img[at..at + n]);
        if filled == 0 {
            break; // underrun: cannot happen for a consistent source
        }
        at += filled;
    }
    img
}

/// A bounded stack window that transits serialized secret bytes — zeroized
/// on drop (the US-704 discipline, applied to the compare/program windows).
struct CmpWindow<const N: usize>([u8; N]);

impl<const N: usize> Default for CmpWindow<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for CmpWindow<N> {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Byte-compare a windowed image against raw bytes (a loaded-image slice)
/// in bounded, zeroized stack windows. `false` on any length mismatch or
/// underrun.
fn image_eq_slice(src: &dyn WindowedImageSource, img: &[u8]) -> bool {
    if src.image_len() != img.len() {
        return false;
    }
    let mut win = CmpWindow::<128>::default();
    let mut at = 0;
    while at < img.len() {
        let n = core::cmp::min(128, img.len() - at);
        let filled = src.image_window(at, &mut win.0[..n]);
        if filled != n || win.0[..n] != img[at..at + n] {
            return false;
        }
        at += n;
    }
    true
}

/// Byte-compare a windowed image against a second windowed image (the
/// device boot gate: the store's image vs the winning flash slot's raw
/// bytes, read volatile). `len` is the slot image's validated length; a
/// length mismatch (or any underrun) is a difference.
#[cfg(all(feature = "device", target_arch = "arm"))]
fn image_eq_reader(
    src: &dyn WindowedImageSource,
    reader: &mut dyn ImageReader,
    len: usize,
) -> bool {
    if src.image_len() != len {
        return false;
    }
    let mut a = CmpWindow::<256>::default();
    let mut b = CmpWindow::<256>::default();
    let mut at = 0;
    while at < len {
        let n = core::cmp::min(256, len - at);
        let fa = src.image_window(at, &mut a.0[..n]);
        let fb = reader.read_window(at, &mut b.0[..n]);
        if fa != n || fb != n || a.0[..n] != b.0[..n] {
            return false;
        }
        at += n;
    }
    true
}

/// Programs a serialized secure-partition image into a durable medium
/// (US-421). Device implementations wrap the flash image slots
/// ([`FlashSlotSink`](crate::persist_sink::FlashSlotSink), US-422); the host
/// implementation wraps a file buffer.
///
/// Implementations must be atomic with respect to the previous good image:
/// a failure may leave the old image in place but never garbage in its stead,
/// and MUST report the failure via the return value so the gate re-marks the
/// writing apps dirty (durable-before-ack: no success reply may go out for an
/// image that is not actually in the medium).
///
/// US-715: the image arrives as a [`WindowedImageSource`] — pull bounded
/// windows (`image_len` at most, e.g. 256 B chunks) instead of expecting a
/// whole-image slice. Host/test implementations materialize with
/// [`pull_image`].
pub trait ImageSink {
    /// Program the windowed image into the durable medium.
    ///
    /// Returns `true` iff the image is durable. On failure the previous good
    /// image must be left in place (never corrupted) and `false` returned.
    fn program(&mut self, src: &mut dyn WindowedImageSource) -> bool;
}

/// An app that persists its own dirty durable state (US-421).
///
/// `App` blanket-implements this via `App::persist_state`, and apps that are
/// not dispatcher members (the FIDO app on the HID path) implement it
/// directly — so [`persist_one`] serves both shapes.
pub trait Persist {
    /// Write the app's dirty durable state through `store`.
    ///
    /// Returns `true` iff bytes reached the store. On any failure the app
    /// MUST stay dirty (the gate's next run retries it); volatile session
    /// state is never persisted.
    fn persist_dirty(&mut self, store: &mut dyn SecureStore) -> bool;

    /// Re-mark the app's durable state dirty (the gate's failure path: the
    /// store write succeeded but the partition image could not be
    /// programmed — the change must be retried on the next command).
    fn mark_dirty(&mut self);

    /// Is the app left with dirty durable state that has not reached the
    /// store (US-427)? Transports call this **after** the gate to tell the
    /// two `false` outcomes apart (clean no-op → success reply; failed
    /// persist → error reply, durable-before-ack). Default: the app does
    /// not track dirtiness — it can never be left dirty.
    fn is_dirty(&self) -> bool {
        false
    }
}

impl<T: App + ?Sized> Persist for T {
    fn persist_dirty(&mut self, store: &mut dyn SecureStore) -> bool {
        self.persist_state(store)
    }
    fn mark_dirty(&mut self) {
        App::mark_dirty(self)
    }
    fn is_dirty(&self) -> bool {
        App::is_dirty(self)
    }
}

/// Persist every app in the dispatcher list (US-421): run each app's
/// dirty-gated store write, and **only if any wrote**, serialize the
/// partition image and program it into `sink`.
///
/// Returns whether the image was programmed. On a sink failure the writing
/// apps are re-marked dirty (see the module docs) and `false` is returned.
pub fn persist_apps(
    apps: &mut [&mut dyn App],
    store: &mut dyn SecureStore,
    sink: &mut dyn ImageSink,
) -> bool {
    persist_apps_with(apps, store, |store| snapshot_and_program(store, sink))
}

fn persist_apps_with(
    apps: &mut [&mut dyn App],
    store: &mut dyn SecureStore,
    program: impl FnOnce(&dyn SecureStore) -> bool,
) -> bool {
    let mut any_wrote = false;
    let mut wrote_mask: u64 = 0; // up to 64 dispatcher apps; more is not a thing
    for (i, app) in apps.iter_mut().enumerate() {
        if app.persist_state(store) {
            any_wrote = true;
            if i < 64 {
                wrote_mask |= 1u64 << i;
            }
        }
    }
    if !any_wrote {
        return false;
    }
    if !program(store) {
        for (i, app) in apps.iter_mut().enumerate() {
            if i < 64 && (wrote_mask >> i) & 1 != 0 {
                app.mark_dirty();
            }
        }
        return false;
    }
    true
}

/// Persist a single non-dispatcher app (US-421 — the FIDO app on the HID
/// path): same sequence as [`persist_apps`], one app.
pub fn persist_one(
    app: &mut dyn Persist,
    store: &mut dyn SecureStore,
    sink: &mut dyn ImageSink,
) -> bool {
    if !app.persist_dirty(store) {
        return false;
    }
    if !snapshot_and_program(store, sink) {
        app.mark_dirty();
        return false;
    }
    true
}

/// Persist a staged APDU reply using a caller-owned bounded budget. A failed
/// write/snapshot/program revokes the staged reply and returns Corrupt.
/// Clean no-ops succeed; partial app writes must not hide another dirty app.
/// This gate is synchronous and must run before the transport sends the reply.
///
/// US-715: `scratch` is now only a *budget* — the windowed snapshot never
/// materializes into it — but an undersized budget keeps the historical
/// fail-closed behavior (the device's old fixed scratch was exactly
/// `PARTITION_IMAGE_MAX`, so a `Full` snapshot there was a bug, not a
/// state; the pinned test uses `&mut []` to exercise the failure).
pub fn persist_reply_with_scratch(
    apps: &mut [&mut dyn App],
    store: &mut dyn SecureStore,
    sink: &mut dyn ImageSink,
    scratch: &mut [u8],
    reply: &mut heapless::Vec<u8, { crate::dispatch::MAX_RESPONSE }>,
) -> Result<(), SecureStoreError> {
    persist_apps_with(apps, store, |store| {
        if store.snapshot_len() > scratch.len() {
            persist_error("secure partition: snapshot failed");
            return false;
        }
        let mut src = StoreImageSource::new(store);
        sink.program(&mut src)
    });
    if apps.iter().any(|app| app.is_dirty()) {
        persist_error("secure partition: reply persist failed");
        reply.clear();
        reply.extend_from_slice(&[0x6f, 0x00]).ok();
        return Err(SecureStoreError::Corrupt);
    }
    Ok(())
}

/// US-715: the device transport's per-command gate —
/// [`persist_reply_with_scratch`] without the scratch (the windowed snapshot
/// needs none; same durable-before-ack semantics otherwise).
pub fn persist_reply_windowed(
    apps: &mut [&mut dyn App],
    store: &mut dyn SecureStore,
    sink: &mut dyn ImageSink,
    reply: &mut heapless::Vec<u8, { crate::dispatch::MAX_RESPONSE }>,
) -> Result<(), SecureStoreError> {
    persist_apps_with(apps, store, |store| {
        let mut src = StoreImageSource::new(store);
        sink.program(&mut src)
    });
    if apps.iter().any(|app| app.is_dirty()) {
        persist_error("secure partition: reply persist failed");
        reply.clear();
        reply.extend_from_slice(&[0x6f, 0x00]).ok();
        return Err(SecureStoreError::Corrupt);
    }
    Ok(())
}

/// Boot's fixed-buffer persist-before-serve boundary (host seam). No heap or
/// growing fallback: an undersized budget or failed program is a boot error.
///
/// US-715: `scratch` is a budget (see [`persist_reply_with_scratch`]) — the
/// device boot path uses [`persist_boot_change_windowed`] and has no buffer
/// at all.
pub fn persist_boot_change_with_scratch(
    store: &mut dyn SecureStore,
    loaded_img: &[u8],
    sink: &mut dyn ImageSink,
    scratch: &mut [u8],
) -> Result<(), SecureStoreError> {
    if store.snapshot_len() > scratch.len() {
        persist_error("secure partition: snapshot failed");
        return Err(SecureStoreError::Corrupt);
    }
    let mut src = StoreImageSource::new(store);
    if image_eq_slice(&src, loaded_img) || sink.program(&mut src) {
        Ok(())
    } else {
        persist_error("secure partition: boot persist failed");
        Err(SecureStoreError::Corrupt)
    }
}

// ---------------------------------------------------------------------------
// Snapshot + program — the one place the sequence lives
// ---------------------------------------------------------------------------

/// Hand the store's windowed image to `f` — the one place the snapshot
/// sequence lives (US-423 factored it out of [`snapshot_and_program`]).
/// US-715: windowed sources cannot fail (the length is captured once and
/// every window is a plain read), so the old scratch/`Full` failure paths
/// are gone; `f`'s own program result is the only outcome.
fn snapshot_and_run(
    store: &dyn SecureStore,
    f: impl FnOnce(&mut dyn WindowedImageSource) -> bool,
) -> bool {
    let mut src = StoreImageSource::new(store);
    f(&mut src)
}

/// Serialize the store's partition image and program it into `sink`.
/// Returns `false` (and logs) when the program cannot run.
pub fn snapshot_and_program(store: &dyn SecureStore, sink: &mut dyn ImageSink) -> bool {
    snapshot_and_run(store, |src| {
        let ok = sink.program(src);
        if !ok {
            persist_error("secure partition: program failed");
        }
        ok
    })
}

/// Persist boot-time store changes (US-423): compare the store's current
/// partition image with `loaded_img` (the canonical re-serialization taken
/// right after the boot load, before migration/boot mutated the store) and
/// program the sink only if they differ.
///
/// Returns `true` when the boot-time state is durable after the call
/// (unchanged from load, or programmed now); `false` on program failure
/// (logged).
///
/// Persist lifecycle (US-430 N3 — rewording the overstated
/// "in-RAM state survives to the first post-command persist" line):
/// boot-time store changes are persisted **at boot**, by this idempotent
/// compare against the canonical post-load image; in-RAM state produced
/// **after** boot persists at the **next persisting command** (the
/// transport's `persist_apps`/`persist_one` gate call); a failed persist
/// leaves the app dirty and the reply is an **error frame** (option (a) —
/// durable-before-ack: CCID SW-only `6F 00`, CTAP-HID
/// 0xBF/INVALID_COMMAND). The previous good image is never corrupted.
pub fn persist_boot_change(
    store: &mut dyn SecureStore,
    loaded_img: &[u8],
    sink: &mut dyn ImageSink,
) -> bool {
    let mut src = StoreImageSource::new(store);
    if image_eq_slice(&src, loaded_img) {
        persist_info("secure partition: boot persist: unchanged");
        true
    } else {
        let ok = sink.program(&mut src);
        if ok {
            persist_info("secure partition: boot persist: programmed");
        } else {
            persist_error("secure partition: boot persist: program failed");
        }
        ok
    }
}

/// US-715: the device boot gate's image source — the winning flash slot's
/// raw bytes (a volatile [`ImageReader`] over the slot, US-391 slot
/// selection) or nothing at all (a fresh board: both slots erased).
#[cfg(all(feature = "device", target_arch = "arm"))]
pub enum WindowedBootImage<'a> {
    /// The winning slot's raw bytes (the store was restored from it).
    Slot(&'a mut dyn ImageReader),
    /// Fresh first boot: both slots erased (the store booted empty).
    Fresh,
}

/// US-715 device form of [`persist_boot_change`]: the canonical post-load
/// image is the winning flash slot itself (the firmware only ever programs
/// the store's own serialization, so slot bytes ≡ the T0 snapshot), so the
/// whole-image T0 buffer is gone and the compare reads the slot through
/// bounded volatile windows instead.
///
/// On a fresh board (both slots erased) the gate programs iff the store is
/// no longer empty — exactly the old T0-compare outcome (a fresh store's
/// first-boot hkey derivation always makes it non-empty before the gate).
///
/// Known divergence (documented, US-715): a slot whose bytes are NOT the
/// canonical re-serialization of its loaded store (hand-crafted or
/// non-firmware image) now triggers a one-time repair program where the T0
/// compare would have skipped — strictly more correct, unreachable for
/// firmware-written images, and wear-neutral afterwards.
#[cfg(all(feature = "device", target_arch = "arm"))]
// US-939: `#[inline(never)]` -- async-main frame discipline (device boot
// path; the gate's internals stay in their own frame).
#[inline(never)]
pub fn persist_boot_change_windowed(
    store: &mut dyn SecureStore,
    boot_img: WindowedBootImage,
    sink: &mut dyn ImageSink,
) -> bool {
    use crate::secure_store::partition_image_len_reader;
    let mut src = StoreImageSource::new(store);
    let unchanged = match boot_img {
        WindowedBootImage::Slot(reader) => {
            // US-915: the slot's format follows the store's key state — a
            // keyed store's slots hold sealed format-v3 images, an unkeyed
            // store's hold the legacy format v2. Deterministic sealing makes
            // the byte-compare meaningful (same content ⇒ same sealed bytes).
            let len = match store.store_key() {
                Some(key) => crate::store_v3::sealed_image_len_reader(reader, &key),
                None => partition_image_len_reader(reader),
            };
            match len {
                Some(len) => image_eq_reader(&src, reader, len),
                None => false, // cannot happen: boot validated the winning slot
            }
        }
        WindowedBootImage::Fresh => matches!(store.is_empty(), Ok(true)),
    };
    if unchanged {
        persist_info("secure partition: boot persist: unchanged");
        true
    } else {
        let ok = sink.program(&mut src);
        if ok {
            persist_info("secure partition: boot persist: programmed");
        } else {
            persist_error("secure partition: boot persist: program failed");
        }
        ok
    }
}

/// US-715 device form of [`with_durable_boot`] (see
/// [`persist_boot_change_windowed`]).
#[cfg(all(feature = "device", target_arch = "arm"))]
// US-939: `#[inline(never)]` -- async-main frame discipline (device boot
// path; the gate's internals stay in their own frame).
#[inline(never)]
pub fn with_durable_boot_windowed<R>(
    store: &mut dyn SecureStore,
    boot_img: WindowedBootImage,
    sink: &mut dyn ImageSink,
    boot: impl FnOnce() -> R,
) -> Option<R> {
    if !persist_boot_change_windowed(store, boot_img, sink) {
        return None;
    }
    Some(boot())
}

/// Execute a potentially destructive backend boot only after captured state
/// is durable. Failure leaves the backend untouched and must stop device boot.
pub fn with_durable_boot<R>(
    store: &mut dyn SecureStore,
    loaded_img: &[u8],
    sink: &mut dyn ImageSink,
    boot: impl FnOnce() -> R,
) -> Option<R> {
    if !persist_boot_change(store, loaded_img, sink) {
        return None;
    }
    Some(boot())
}

/// Failure log for the gate (observable per the epic: defmt on device,
/// stderr in emulation / host tests). `pub` so the device boot path can log
/// its pre-gate snapshot failure (US-423) with the same wording discipline.
pub fn persist_error(msg: &str) {
    #[cfg(all(feature = "device", target_arch = "arm"))]
    defmt::error!("{}", msg);
    #[cfg(not(target_arch = "arm"))]
    std::eprintln!("{msg}");
}

/// Info log for the gate (US-423): the boot gate's observable outcome —
/// defmt on device, stderr in emulation / host tests.
fn persist_info(msg: &str) {
    #[cfg(all(feature = "device", target_arch = "arm"))]
    defmt::info!("{}", msg);
    #[cfg(not(target_arch = "arm"))]
    std::eprintln!("{msg}");
}
