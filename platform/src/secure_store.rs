//! Secure key / secret storage for fapico2 (US-380).
//!
//! All private keys, seeds, and PIN / attestation material MUST be persisted
//! through a [`SecureStore`]. The EPIC is explicit: keys go to the RP2350
//! secure partition / OTP and **never plain flash**.
//!
//! * **Device (RP2350)** — [`rp2350::Rp2350SecureStore`] backs the store in
//!   the secure memory region; the RP2350 secure partition is hardware-gated by
//!   the CryptoCell so non-secure code cannot read it. It is deliberately never
//!   backed by the plain application flash.
//! * **Host (emulation / tests)** — [`HostSecureStore`] (in-memory, with a
//!   serializable "partition image" for reboot simulation) and
//!   [`FileSecureStore`] (a file that stands in for the secure partition,
//!   written atomically) let the same app code and the keystore run on host.

use core::fmt;

// Host (emulation / tests) builds need a heap `Vec` for dynamic blobs; it is
// not in the `no_std` prelude. Device (arm) code in this module is core-only.
#[cfg(not(target_arch = "arm"))]
use std::vec::Vec;

/// Maximum key (identifier) length.
pub const MAX_KEY_LEN: usize = 48;
/// Maximum stored value length. Keystore snapshots can hold many credentials,
/// so this is generous; device stores may impose a tighter bound per slot.
pub const MAX_VALUE_LEN: usize = 16 * 1024;

/// Secure-partition image magic, format v2 (US-391; hardened per the C
/// secure-store review's publish-after-durable discipline): every image is
/// self-describing so a power-lost flash write is always *detected* and never
/// misparsed as a partial secret.
///
/// Layout (all little-endian):
/// `[magic u32][count u32] [key_len u32, key, val_len u32, val] ... [crc32 u32]`
/// where the trailing CRC-32 covers every byte before it.
pub const PARTITION_IMAGE_MAGIC: u32 = 0x4632_5350; // LE bytes: "PS2F"

/// CRC-32 (IEEE 802.3, reflected, poly 0xEDB8_8320). Tableless: the image is
/// at most a few KiB and this runs once per persist/boot — dependency-free
/// matters more than speed. `pub(crate)`: the v3 sealing layer
/// ([`crate::store_v3`]) shares it.
pub(crate) fn crc32(buf: &[u8]) -> u32 {
    !crc32_update(0xFFFF_FFFF, buf)
}

/// Incremental [`crc32`] state (US-715): the streaming image walks update
/// the CRC window by window instead of over a whole-image buffer.
pub(crate) fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// Windowed image I/O (US-715, POLISH-PUB).
//
// The partition image is walked through SMALL FIXED WINDOWS everywhere —
// snapshot (persist), validate/restore (boot), and slot compare — never
// through a whole-image buffer. On the device this reclaims the three
// `PARTITION_IMAGE_MAX` statics (`boot::BOOT_PARTITION_BUF`,
// `boot::BOOT_SHADOW_BUF`, `platform::persist::IMAGE_SCRATCH`; 27,300 B of
// bss at 16 entries) for the entry-capacity budget.
// ---------------------------------------------------------------------------

/// Window size for the streaming image walks. Small by design, with a
/// compile-time bound: a whole-image-sized "window" would silently
/// reintroduce the reclaimed bss.
pub const IMAGE_WINDOW: usize = 128;
const _: () = assert!(IMAGE_WINDOW <= 512, "US-715: image I/O window must stay small");

/// A random-access byte-window source over a stored format-v2 image (the
/// device's flash-resident secure-partition slot, a host slice, a file).
/// Every streaming consumer validates / restores / compares through small
/// windows — the whole-image-buffer-free read path (US-715).
pub trait ImageReader {
    /// Fill `buf` with the bytes at image offset `off`; returns the number
    /// of bytes filled (fewer than requested only at the end of the medium,
    /// `0` when `off` is at/after it). Implementations must not panic on
    /// any offset — a walk that runs off the medium ends via the short
    /// fill and fails validation.
    fn read_window(&mut self, off: usize, buf: &mut [u8]) -> usize;
}

/// Slice-backed [`ImageReader`] — the host/test shape of the windowed read
/// path (the device feeds a volatile flash-slot reader instead).
pub struct SliceReader<'a> {
    img: &'a [u8],
}

impl<'a> SliceReader<'a> {
    pub fn new(img: &'a [u8]) -> Self {
        Self { img }
    }
}

impl ImageReader for SliceReader<'_> {
    fn read_window(&mut self, off: usize, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.img.len().saturating_sub(off));
        buf[..n].copy_from_slice(&self.img[off..off + n]);
        n
    }
}

/// A fixed scratch window that zeroizes on drop — image bytes passing
/// through it include secret slot values (US-704 discipline). Child
/// modules (`rp2350`) reuse it for their walk windows.
struct ZeroWindow<const N: usize>([u8; N]);

impl<const N: usize> Drop for ZeroWindow<N> {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl<const N: usize> ZeroWindow<N> {
    fn new() -> Self {
        Self([0; N])
    }
}

/// Read exactly `buf.len()` bytes at `off`; `None` when the medium ends
/// first (the streaming walk's bound check — the analog of the slice
/// validator's `i + len > img.len()` checks).
pub(crate) fn read_exact_window(
    reader: &mut dyn ImageReader,
    off: usize,
    buf: &mut [u8],
) -> Option<()> {
    (reader.read_window(off, buf) == buf.len()).then_some(())
}

/// Stream `len` bytes at `off` through the CRC state in windows; returns
/// the offset after the region, or `None` on medium end.
fn stream_crc(
    reader: &mut dyn ImageReader,
    off: usize,
    len: usize,
    crc: &mut u32,
) -> Option<usize> {
    let mut win = ZeroWindow::<IMAGE_WINDOW>::new();
    let mut at = 0;
    while at < len {
        let n = IMAGE_WINDOW.min(len - at);
        read_exact_window(reader, off + at, &mut win.0[..n])?;
        *crc = crc32_update(*crc, &win.0[..n]);
        at += n;
    }
    Some(off + len)
}

/// Read the little-endian `u32` at `off`, folding it into the CRC state.
fn stream_u32(reader: &mut dyn ImageReader, off: usize, crc: &mut u32) -> Option<(u32, usize)> {
    let mut b = [0u8; 4];
    read_exact_window(reader, off, &mut b)?;
    *crc = crc32_update(*crc, &b);
    Some((u32::from_le_bytes(b), off + 4))
}

/// Streaming form of the private `partition_image_len` slice validator
/// (US-715): walk the format-v2 image
/// through `reader`'s windows, validating the structure and the CRC
/// without a whole-image buffer. Same validation and the same
/// `Some(exact_len)` / `None` outcomes as the slice form — a truncated or
/// corrupt image (bad magic, out-of-range length, medium end, CRC
/// mismatch) is rejected.
pub fn partition_image_len_reader(reader: &mut dyn ImageReader) -> Option<usize> {
    let mut crc = 0xFFFF_FFFF;
    let (magic, i) = stream_u32(reader, 0, &mut crc)?;
    if magic != PARTITION_IMAGE_MAGIC {
        return None;
    }
    let (n, mut i) = stream_u32(reader, i, &mut crc)?;
    if n > 1024 {
        return None;
    }
    for _ in 0..n {
        let (kl, j) = stream_u32(reader, i, &mut crc)?;
        if kl as usize > MAX_KEY_LEN {
            return None;
        }
        i = stream_crc(reader, j, kl as usize, &mut crc)?;
        let (vl, j) = stream_u32(reader, i, &mut crc)?;
        if vl as usize > MAX_VALUE_LEN {
            return None;
        }
        i = stream_crc(reader, j, vl as usize, &mut crc)?;
    }
    let mut b = [0u8; 4];
    read_exact_window(reader, i, &mut b)?;
    let stored = u32::from_le_bytes(b);
    (!crc == stored).then_some(i + 4)
}

/// Streaming [`partition_image_is_valid`] (US-715): the boot-time slot
/// selector over a windowed reader.
pub fn partition_image_is_valid_reader(reader: &mut dyn ImageReader) -> bool {
    partition_image_len_reader(reader).is_some()
}

/// Streaming form of the erased-flash check (US-715): every byte of the
/// first `len` bytes of the medium is erased flash (0xFF).
pub fn slot_is_erased_reader(reader: &mut dyn ImageReader, len: usize) -> bool {
    let mut win = ZeroWindow::<IMAGE_WINDOW>::new();
    let mut at = 0;
    while at < len {
        let n = IMAGE_WINDOW.min(len - at);
        let filled = reader.read_window(at, &mut win.0[..n]);
        if filled < n || win.0[..filled].iter().any(|&b| b != 0xFF) {
            return false;
        }
        at += n;
    }
    true
}

/// Copy the intersection of `seg` (located at global offset `*pos`) and
/// the window `[off, off + buf.len())` into `buf`, advancing `*pos`.
/// Segments are emitted in image order, so the window fills contiguously.
pub(crate) fn emit_window_seg(
    buf: &mut [u8],
    off: usize,
    end: usize,
    pos: &mut usize,
    filled: &mut usize,
    seg: &[u8],
) {
    let seg_end = *pos + seg.len();
    if *pos < end && seg_end > off {
        let lo = off.max(*pos);
        let hi = end.min(seg_end);
        let dst = lo - off;
        buf[dst..dst + (hi - lo)].copy_from_slice(&seg[lo - *pos..hi - *pos]);
        *filled = dst + (hi - lo);
    }
    *pos = seg_end;
}

/// The exact serialized length of the format-v2 image at the start of
/// `img` — magic(4) + count(4) + entries + CRC-32(4) — or `None` when the
/// image is corrupt. The image is **self-delimiting**: the entry walk ends
/// at the image's own trailing CRC, so bytes after it (the padding of a
/// fixed-size flash slot window) are not part of the image and do not
/// invalidate it — persist programs only the image, boot reads the whole
/// slot. Torn writes are still caught: a truncated image fails the walk or
/// the CRC check, a corrupted entry length fails the bounds checks, and a
/// wrong magic rejects the slot outright.
pub fn partition_image_len(img: &[u8]) -> Option<usize> {
    if img.len() < 12 {
        return None;
    }
    if u32::from_le_bytes([img[0], img[1], img[2], img[3]]) != PARTITION_IMAGE_MAGIC {
        return None;
    }
    let n = u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize;
    if n > 1024 {
        return None;
    }
    let mut i = 8usize;
    for _ in 0..n {
        if i + 4 > img.len() {
            return None;
        }
        let kl = u32::from_le_bytes([img[i], img[i + 1], img[i + 2], img[i + 3]]) as usize;
        i += 4;
        if kl > MAX_KEY_LEN || i + kl > img.len() {
            return None;
        }
        i += kl;
        if i + 4 > img.len() {
            return None;
        }
        let vl = u32::from_le_bytes([img[i], img[i + 1], img[i + 2], img[i + 3]]) as usize;
        i += 4;
        if vl > MAX_VALUE_LEN || i + vl > img.len() {
            return None;
        }
        i += vl;
    }
    let end = i + 4;
    if end > img.len() {
        return None; // CRC region truncated: torn write
    }
    let stored = u32::from_le_bytes([img[end - 4], img[end - 3], img[end - 2], img[end - 1]]);
    (crc32(&img[..end - 4]) == stored).then_some(end)
}

/// Validate a secure-partition image (format v2). Used by every restore
/// path (a corrupt image must never yield a partial secret) and by the
/// v2→v3 migration's pre-update signature check — the boot decision itself
/// is [`crate::store_v3::boot_decision_sealed`] (US-915: the sealed boot
/// policy, which supersedes the format-v2 four-way rule).
pub fn partition_image_is_valid(img: &[u8]) -> bool {
    partition_image_len(img).is_some()
}

/// Errors a secure store can surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureStoreError {
    /// The key (identifier) exceeds [`MAX_KEY_LEN`].
    KeyTooLong,
    /// The value exceeds the store's value bound.
    ValueTooLong,
    /// No entry exists for the key.
    NotFound,
    /// No free slot / the `out` buffer is too small.
    Full,
    /// The store has not been initialized.
    Uninitialized,
    /// The backing medium failed (host-only: file I/O).
    Io,
    /// A stored value failed validation (corrupt secret material).
    Corrupt,
    /// The secure-partition flash driver failed (slot read/erase/program,
    /// US-422 — the device `SlotFlash` adapter maps to it).
    Flash,
    /// **The randomness source could not produce, while the store itself is
    /// fine.** (US-1005 fix.)
    ///
    /// Deliberately *not* folded into [`Corrupt`](Self::Corrupt) or
    /// [`Flash`](Self::Flash): those say "the bytes I hold are not
    /// trustworthy", and their handling is a recovery or a wipe. This one
    /// says "I could not obtain bytes to store", and the only correct
    /// handling is to **stop** — the caller is on the boot path, and
    /// continuing would mean persisting a value derived from an unfilled
    /// zero-initialised buffer, which is how an all-zero device secret
    /// reaches flash. D-9 item (1) is exactly that failure; this variant
    /// exists so it is a value the boot path can propagate rather than a
    /// default it has to invent.
    Entropy,
}

impl fmt::Display for SecureStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecureStoreError::KeyTooLong => write!(f, "secure store key too long"),
            SecureStoreError::ValueTooLong => write!(f, "secure store value too long"),
            SecureStoreError::NotFound => write!(f, "no such secure store key"),
            SecureStoreError::Full => write!(f, "secure store full / buffer too small"),
        SecureStoreError::Uninitialized => write!(f, "secure store not initialized"),
        SecureStoreError::Io => write!(f, "secure store I/O failure"),
        SecureStoreError::Corrupt => write!(f, "stored value failed validation"),
            SecureStoreError::Flash => write!(f, "secure partition flash failure"),
            SecureStoreError::Entropy => write!(f, "randomness source refused to produce"),
        }

}
}

/// A persistent, secure key/value store.
///
/// Implementations must never place secrets in the plain application flash on
/// the device; the backing region is the secure partition (RP2350) or its host
/// stand-in.
pub trait SecureStore {
    /// Store `value` under `key`, overwriting any existing entry.
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError>;
    /// Copy the value stored under `key` into `out`; returns the value length.
    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError>;
    /// Remove the entry for `key`.
    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError>;
    /// Whether an entry exists for `key`.
    fn contains(&self, key: &[u8]) -> bool;
    /// Serialize the store's whole partition into `buf` (the format-v2
    /// partition image — the same layout the device programs into its
    /// on-flash slots); returns the image length. `Full` when `buf` is too
    /// small. The persist gate (`crate::persist`) uses this to build the
    /// image it hands to an [`crate::persist::ImageSink`].
    fn snapshot_partition(&self, buf: &mut [u8]) -> Result<usize, SecureStoreError>;
    /// US-715: exact serialized partition-image length — the bound the
    /// windowed persist path walks to (it never materializes the image).
    /// `0` on a conflicting runtime borrow (unreachable in the
    /// single-threaded persist gate) is indistinguishable from an empty
    /// snapshot and reads back as a no-op program.
    fn snapshot_len(&self) -> usize;
    /// US-715: fill `buf` with the serialized partition-image bytes at
    /// `off`; returns the number of bytes filled (`0` when `off` is at or
    /// after the end). The windowed twin of [`SecureStore::snapshot_partition`]
    /// — same bytes, arbitrary window.
    fn snapshot_window(&self, off: usize, buf: &mut [u8]) -> usize;
    /// Whether the store holds no entries at all. `Err` when occupancy
    /// cannot be determined right now — callers must treat "unknown" as
    /// occupied and never guess emptiness from a handful of known keys.
    fn is_empty(&self) -> Result<bool, SecureStoreError>;
    /// US-918: whether the store holds no entries other than `slot` — the
    /// "virgin except the boot-entropy record" shape the first-boot C→Rust
    /// migration must still treat as a verified-empty destination (the
    /// entropy slot is created before the migration boot path, but it must
    /// not push the destination onto the occupied two-generation budget).
    /// Vacuously `true` for an empty store. `Err` when occupancy cannot be
    /// determined right now — callers must treat "unknown" as occupied,
    /// exactly like [`SecureStore::is_empty`].
    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError>;
    /// US-919: erase **every** entry — the foreign-image wipe primitive.
    /// The boot path executes the data-loss-over-implant policy on a
    /// manifest-hash mismatch: no known-slot enumeration (a list goes stale
    /// the next slot is added), everything goes. Freed backing bytes are
    /// zeroized where the implementation holds them (the device store's
    /// US-704 discipline). `Err` only for a medium-level failure — an
    /// already-empty store wipes to `Ok`.
    fn wipe_all(&mut self) -> Result<(), SecureStoreError>;
    /// US-915: the AEAD key this store seals its partition image with,
    /// when it seals at all (device: OTP+chipid-derived, set once at boot;
    /// host: the fixed emulation key). `None` = the store serializes the
    /// legacy logical format-v2 image — the pre-US-915 behavior, kept for
    /// the device store before its boot key is set and for non-partition
    /// stores. Returned by copy (32 B) so borrow-wrapping stores can
    /// forward it without escaping a runtime guard.
    fn store_key(&self) -> Option<[u8; 32]> {
        None
    }
}

/// A single-core store handle with operation-scoped runtime borrows. Separate
/// app/auth handles share one store without retaining exclusive references
/// across synchronous callbacks into another handle.
#[derive(Clone, Copy)]
pub struct SharedStore<'a, K> {
    inner: &'a core::cell::RefCell<K>,
}

impl<'a, K> SharedStore<'a, K> {
    pub const fn new(inner: &'a core::cell::RefCell<K>) -> Self { Self { inner } }
}

impl<K: SecureStore> SecureStore for SharedStore<'_, K> {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        self.inner.try_borrow_mut().map_err(|_| SecureStoreError::Corrupt)?.write(key, value)
    }
    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.inner.try_borrow_mut().map_err(|_| SecureStoreError::Corrupt)?.read(key, out)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
        self.inner.try_borrow_mut().map_err(|_| SecureStoreError::Corrupt)?.delete(key)
    }
    fn contains(&self, key: &[u8]) -> bool {
        // A conflicting borrow must not masquerade as an empty destination.
        self.inner.try_borrow().map(|store| store.contains(key)).unwrap_or(true)
    }
    fn snapshot_partition(&self, out: &mut [u8]) -> Result<usize, SecureStoreError> {
        self.inner.try_borrow().map_err(|_| SecureStoreError::Corrupt)?.snapshot_partition(out)
    }
    fn snapshot_len(&self) -> usize {
        self.inner.try_borrow().map(|store| store.snapshot_len()).unwrap_or(0)
    }
    fn snapshot_window(&self, off: usize, buf: &mut [u8]) -> usize {
        self.inner.try_borrow().map(|store| store.snapshot_window(off, buf)).unwrap_or(0)
    }
    fn is_empty(&self) -> Result<bool, SecureStoreError> {
        self.inner.try_borrow().map_err(|_| SecureStoreError::Corrupt)?.is_empty()
    }
    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError> {
        // A conflicting borrow must not masquerade as a virgin destination.
        self.inner.try_borrow().map_err(|_| SecureStoreError::Corrupt)?.is_empty_except(slot)
    }
    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        // A conflicting borrow must not let a wipe pass unnoticed.
        self.inner.try_borrow_mut().map_err(|_| SecureStoreError::Corrupt)?.wipe_all()
    }
    fn store_key(&self) -> Option<[u8; 32]> {
        // A conflicting borrow must not leak a key guess: `None` (the
        // legacy unsealed serialization) is the fail-closed shape.
        self.inner.try_borrow().map(|store| store.store_key()).unwrap_or(None)
    }
}

// ---------------------------------------------------------------------------
// Host (emulation / tests): in-memory secure partition + reboot simulation.
// ---------------------------------------------------------------------------

/// Host stand-in for the RP2350 secure partition: an in-memory map plus a
/// serializable "partition image" (for reboot simulation) and a separate
/// plain-flash region that secrets must **never** touch.
///
/// US-915: the partition image is the **format-v3 sealed image**
/// ([`crate::store_v3`]) — every entry encrypted, whole image MAC'd under
/// the fixed emulation store key (the emulation partition holds no real
/// secrets, but its format is the real one so the host paths exercise the
/// exact on-flash layout). `Debug` redacts nothing here because the map
/// holds the plaintexts by design (the in-RAM "secure partition"); the
/// sealed image is what crosses a serialize boundary.
#[cfg(not(target_arch = "arm"))]
#[derive(Debug)]
pub struct HostSecureStore {
    secure: std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
    plain_flash: Vec<u8>,
    key: [u8; 32],
}

#[cfg(not(target_arch = "arm"))]
impl Default for HostSecureStore {
    fn default() -> Self {
        Self {
            secure: std::collections::BTreeMap::new(),
            plain_flash: Vec::new(),
            key: crate::store_v3::emulation_store_key(),
        }
    }
}

#[cfg(not(target_arch = "arm"))]
impl HostSecureStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The logical (format-v2) serialization of the map — the sealing
    /// input of [`Self::partition_image`] and the migration helper's shape.
    fn logical_image(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&PARTITION_IMAGE_MAGIC.to_le_bytes());
        out.extend_from_slice(&(self.secure.len() as u32).to_le_bytes());
        for (k, v) in &self.secure {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k);
            out.extend_from_slice(&(v.len() as u32).to_le_bytes());
            out.extend_from_slice(v);
        }
        let crc = crc32(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    /// Serialize the secure partition to a byte image (power-down snapshot,
    /// format v3 — the sealed form the device programs into its on-flash
    /// slots: every entry encrypted, whole image MAC'd under the store
    /// key, trailing CRC for torn-write detection).
    pub fn partition_image(&self) -> Vec<u8> {
        let logical = self.logical_image();
        crate::store_v3::heap::seal_image(&logical, &self.key)
            .expect("the store's own logical image is valid by construction")
    }

    /// Restore the store from a partition image (reboot). US-915: dispatch
    /// on the image magic — a sealed format-v3 image unseals under the
    /// store key; a legacy format-v2 image (the migration's load step)
    /// restores through the logical path; anything else leaves the store
    /// empty rather than restoring a partial or attacker-controlled
    /// secret. The sealed image is self-delimiting, so a fixed-size slot
    /// window with padding after the CRC restores fine.
    pub fn from_partition_image(&mut self, img: &[u8]) {
        self.secure.clear();
        let logical = match crate::store_v3::heap::sealed_image_len(img) {
            // Sealed (v3): recover the exact length (strip any erased
            // padding) and unseal — tags verify or the store stays empty.
            Some(len) => {
                let Some(logical) =
                    crate::store_v3::heap::unseal_image(&img[..len], &self.key).ok()
                else {
                    return;
                };
                logical
            }
            // Legacy (v2): the migration load step — restore the entries.
            None => {
                if partition_image_len(img).is_none() {
                    return; // forged / torn: never restore a partial secret
                }
                img.to_vec()
            }
        };
        let img = logical.as_slice();
        let n = u32::from_le_bytes([img[4], img[5], img[6], img[7]]) as usize;
        let mut i = 8;
        for _ in 0..n {
            let kl = u32::from_le_bytes([img[i], img[i + 1], img[i + 2], img[i + 3]]) as usize;
            i += 4;
            let k = img[i..i + kl].to_vec();
            i += kl;
            let vl = u32::from_le_bytes([img[i], img[i + 1], img[i + 2], img[i + 3]]) as usize;
            i += 4;
            let v = img[i..i + vl].to_vec();
            i += vl;
            self.secure.insert(k, v);
        }
    }

    /// Contents of the *plain* flash region. Secrets must never appear here.
    pub fn plain_flash_dump(&self) -> Vec<u8> {
        self.plain_flash.clone()
    }

    /// Test helper: seed the plain-flash region. The store itself never writes
    /// here — this only exists to prove a secret placed in the secure partition
    /// does not leak into plain flash.
    pub fn set_plain_flash(&mut self, data: Vec<u8>) {
        self.plain_flash = data;
    }
}

#[cfg(not(target_arch = "arm"))]
impl SecureStore for HostSecureStore {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        if key.len() > MAX_KEY_LEN {
            return Err(SecureStoreError::KeyTooLong);
        }
        if value.len() > MAX_VALUE_LEN {
            return Err(SecureStoreError::ValueTooLong);
        }
        self.secure.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        let v = self.secure.get(key).ok_or(SecureStoreError::NotFound)?;
        if v.len() > out.len() {
            return Err(SecureStoreError::Full);
        }
        out[..v.len()].copy_from_slice(v);
        Ok(v.len())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
        if self.secure.remove(key).is_none() {
            return Err(SecureStoreError::NotFound);
        }
        Ok(())
    }
    fn contains(&self, key: &[u8]) -> bool {
        self.secure.contains_key(key)
    }
    fn is_empty(&self) -> Result<bool, SecureStoreError> {
        Ok(self.secure.is_empty())
    }
    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError> {
        Ok(self.secure.keys().all(|k| k.as_slice() == slot))
    }
    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        // Host stand-in: plaintexts by design (see the struct docs) — the
        // map drops with its values.
        self.secure.clear();
        Ok(())
    }
    fn store_key(&self) -> Option<[u8; 32]> {
        Some(self.key)
    }
    fn snapshot_partition(&self, buf: &mut [u8]) -> Result<usize, SecureStoreError> {
        let img = self.partition_image();
        if img.len() > buf.len() {
            return Err(SecureStoreError::Full);
        }
        buf[..img.len()].copy_from_slice(&img);
        Ok(img.len())
    }
    fn snapshot_len(&self) -> usize {
        self.partition_image().len()
    }
    fn snapshot_window(&self, off: usize, buf: &mut [u8]) -> usize {
        // Host stand-in: the image is small and heap-backed, so each window
        // re-serializes (the device store derives its windows for real).
        let img = self.partition_image();
        let n = buf.len().min(img.len().saturating_sub(off));
        buf[..n].copy_from_slice(&img[off..off + n]);
        n
    }
}

// ---------------------------------------------------------------------------
// Host (emulation / tests): file-backed secure partition (keystore).
// ---------------------------------------------------------------------------

/// Host stand-in for the secure partition, backed by a **file**. The file is
/// the secure partition: it holds the raw stored value for the (single)
/// keystore slot and is written atomically (`<path>.tmp` + rename) so a crash
/// mid-write never corrupts it.
///
/// This keeps the keystore's on-disk layout byte-identical to the pre-US-380
/// `std::fs` path while routing all secret persistence through the
/// [`SecureStore`] abstraction.
#[cfg(not(target_arch = "arm"))]
#[derive(Debug)]
pub struct FileSecureStore {
    path: std::path::PathBuf,
}

#[cfg(not(target_arch = "arm"))]
impl FileSecureStore {
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }

    /// The backing file path (the host's secure-partition stand-in).
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Read the full raw value for `key` (host convenience for dynamic-sized
    /// blobs such as a keystore snapshot).
    pub fn read_all(&self, key: &[u8]) -> Result<Vec<u8>, SecureStoreError> {
        let _ = key;
        std::fs::read(&self.path).map_err(|_| SecureStoreError::Io)
    }

    /// Atomically write the raw value for `key` to the secure-partition file:
    /// write to `<path>.tmp` then rename over `<path>` (crash-safe).
    pub fn write_all(&self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        let _ = key;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, value).map_err(|_| SecureStoreError::Io)?;
        std::fs::rename(&tmp, &self.path).map_err(|_| SecureStoreError::Io)
    }
}

#[cfg(not(target_arch = "arm"))]
impl SecureStore for FileSecureStore {
    fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
        if value.len() > MAX_VALUE_LEN {
            return Err(SecureStoreError::ValueTooLong);
        }
        self.write_all(key, value)
    }
    fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
        let v = self.read_all(key)?;
        if v.len() > out.len() {
            return Err(SecureStoreError::Full);
        }
        out[..v.len()].copy_from_slice(&v);
        Ok(v.len())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
        let _ = key;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SecureStoreError::NotFound),
            Err(_) => Err(SecureStoreError::Io),
        }
    }
    fn contains(&self, key: &[u8]) -> bool {
        let _ = key;
        self.path.exists()
    }
    fn is_empty(&self) -> Result<bool, SecureStoreError> {
        // Even a zero-length value occupies this single-slot store.
        match std::fs::metadata(&self.path) {
            Ok(_) => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(_) => Err(SecureStoreError::Io),
        }
    }
    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError> {
        // Single-slot store: the key is not retained, so the held entry
        // cannot be attributed to `slot` — any existing entry counts as
        // occupied (the conservative "treat unknown as occupied" answer).
        let _ = slot;
        self.is_empty()
    }
    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        // Single-slot store: removing the backing file IS the wipe.
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }
    fn snapshot_partition(&self, buf: &mut [u8]) -> Result<usize, SecureStoreError> {
        // The file IS this store's partition (its raw keystore bytes are the
        // image — no v2 framing for the single-slot file layout).
        let data = std::fs::read(&self.path).map_err(|_| SecureStoreError::Io)?;
        if data.len() > buf.len() {
            return Err(SecureStoreError::Full);
        }
        buf[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
    fn snapshot_len(&self) -> usize {
        std::fs::metadata(&self.path).map(|m| m.len() as usize).unwrap_or(0)
    }
    fn snapshot_window(&self, off: usize, buf: &mut [u8]) -> usize {
        // Windowed file read (seek + read): the window never materializes
        // the whole file.
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut file) = std::fs::File::open(&self.path) else { return 0 };
        if file.seek(SeekFrom::Start(off as u64)).is_err() {
            return 0;
        }
        let mut filled = 0;
        while filled < buf.len() {
            match file.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => return 0,
            }
        }
        filled
    }
}

// ---------------------------------------------------------------------------
// Device (RP2350): secure memory backing.
// ---------------------------------------------------------------------------

/// RP2350 secure key store.
///
/// Secrets live in the RP2350 secure memory and are persisted to the
/// hardware-gated secure partition (CryptoCell) — **never plain flash**. This
/// is the device-side binding of the [`SecureStore`] trait.
///
/// The secure-partition flash-persistence seam (US-387) is
/// [`partition_image`](rp2350::Rp2350SecureStore::partition_image) /
/// [`from_partition_image`](rp2350::Rp2350SecureStore::from_partition_image):
/// the store snapshots into (and restores from) a caller-supplied image
/// buffer, which the firmware backs with the reserved secure-partition
/// region (`firmware/src/main.rs`). The module is pure static memory (no
/// arm-specific code), so the same serialization is host-testable.
///
/// Slot values are bounded for small secrets (keys, hashes, seeds); a full
/// keystore snapshot uses the host file-backed store.
#[cfg(feature = "device")]
pub mod rp2350 {
    use super::{
        crc32_update, emit_window_seg, partition_image_len_reader, read_exact_window, ImageReader,
        SecureStore, SecureStoreError, SliceReader, ZeroWindow, MAX_KEY_LEN,
        PARTITION_IMAGE_MAGIC,
    };
    #[cfg(test)]
    use super::partition_image_is_valid;

    /// 16 entries — the DARK-BOOT-1 bound. A 32-entry variant of this store
    /// was built (S-731-2 review round 2) and **hardware-rejected**: its
    /// 36,288 B of extra bss (three `PARTITION_IMAGE_MAX`-sized image
    /// buffers plus the `[Slot; 32]` store static) moved `MSPLIM` — which
    /// the bootrom lays out at the bss end — up by exactly that delta and
    /// shrank the main stack region from ~127 KiB to ~85 KiB; the boot path
    /// overflowed it (STKOF) and the board dark-locked (LED solid ON, no
    /// USB, on a freshly nuked flash). The identical fix code with 16
    /// entries boots (validated on hardware, 2026-09-19). RAM is the
    /// binding constraint — statics are 439 KiB of the 520 KiB, so the
    /// stack cannot be bought back — and the capacity consequence is owned
    /// by the layers below: chunked rewrites self-clean a failed part
    /// write, growth mutations are transactional
    /// (`store_credential_checked` / `grow_checked`) and counter bumps
    /// revert (`bump_credential_counter_checked`), so every capacity
    /// failure is clean and retryable, never a latch. The capacity
    /// arithmetic (steady state `other_slots + parts ≤ 16`; every chunked
    /// rewrite — counter bumps included — transiently needs
    /// `other_slots + old_parts + new_parts ≤ 16` or the mutation rejects /
    /// reverts cleanly) is recorded in
    /// `docs/known-gate-divergences.md` (SF-1).
    /// Fit (US-1010 — the arithmetic here was wrong in two directions and
    /// is restated from the constants below, not from memory): the **v2**
    /// bound `PARTITION_IMAGE_MAX` = 8 + DEV_MAX_ENTRIES × 568 + 4 (24 →
    /// 13,644 B), where 568 is the per-entry v2 cost (4 key_len + 48 key +
    /// 4 val_len + 512 val). The **sealed** bound
    /// `SEALED_PARTITION_IMAGE_MAX` adds the 12-byte image nonce and one
    /// 16-byte GCM tag per entry: 13,644 + 12 + 24 × 16 = **14,040 B** — the
    /// number the assertion below actually constrains. (The old comment said
    /// `× 584 → 14,028`: 584 is the *sealed* per-entry cost, 568 + 16, so it
    /// was quoting the sealed per-entry figure against the v2 header and got
    /// both the total and the ceiling wrong.) `SECURE_SLOT_BYTES` is
    /// `SEALED_PARTITION_IMAGE_MAX` rounded up to the 4 KiB NOR erase
    /// granularity = **16 KiB**, so 2 × 16 KiB = 32 KiB of the 64 KiB region,
    /// 18,728 B spare — one more entry would still fit (25 → 14,608 → still
    /// 16 KiB). Flash downgrade: an image with more entries than this build
    /// is all-or-nothing refused here (`n > DEV_MAX_ENTRIES` → reset), never
    /// partially restored.
    ///
    /// US-715 (POLISH-PUB): the three `PARTITION_IMAGE_MAX`-sized image
    /// statics (`boot::BOOT_PARTITION_BUF`, `boot::BOOT_SHADOW_BUF`,
    /// `persist::IMAGE_SCRATCH` — 27,300 B of bss) are gone; image I/O is
    /// windowed (`partition_image_window` /
    /// `from_partition_image_reader`). Final raise: 16 → 24
    /// (hardware-verified 2026-09-21: boots, identity `fa20:0002`,
    /// persisted store served). 32 was ALSO dark-booted on hardware after
    /// the reclaim (LED solid, no USB) — the binding resource is the
    /// bss→MSPLIM stack distance (boot-time decode stack scales with the
    /// entry count, ~2.3 KiB/entry overall), not bss alone; 24 is the
    /// hardware-pinned ceiling. No further raises without a per-entry
    /// stack audit.
    /// US-1010: made `pub` so the capacity invariant below can name *this*
    /// constant from a test instead of restating its value. A test that
    /// hardcodes `24` is a test that keeps passing when this moves.
    pub const DEV_MAX_ENTRIES: usize = 24;
    const DEV_MAX_VALUE_LEN: usize = 512;

    #[derive(Clone, Copy)]
    struct Slot {
        key: [u8; MAX_KEY_LEN],
        key_len: u8,
        val: [u8; DEV_MAX_VALUE_LEN],
        val_len: u16,
        used: bool,
    }

    pub struct Rp2350SecureStore {
        slots: [Slot; DEV_MAX_ENTRIES],
        n: usize,
        /// US-915: the store-key AEAD key, set once at boot (OTP row +
        /// chipid via [`crate::store_v3::derive_store_key`]). `None` keeps
        /// the legacy logical format-v2 serialization — the boot path
        /// always sets the key before any persist or restore.
        key: Option<[u8; 32]>,
    }

    impl Rp2350SecureStore {
        pub const fn new() -> Self {
            Self {
                slots: [
                    Slot {
                        key: [0; MAX_KEY_LEN],
                        key_len: 0,
                        val: [0; DEV_MAX_VALUE_LEN],
                        val_len: 0,
                        used: false,
                    };
                    DEV_MAX_ENTRIES
                ],
                n: 0,
                key: None,
            }
        }

        /// US-915: configure the store-key AEAD key (boot derives it from
        /// the OTP row + chipid). Must be called before any restore or
        /// snapshot; the boot path sets it once, before the slots are read.
        pub fn set_store_key(&mut self, key: [u8; 32]) {
            self.key = Some(key);
        }
    }

        impl Default for Rp2350SecureStore {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Rp2350SecureStore {
            /// Test helper (host builds only): full key/value backing bytes
            /// of every slot, so tests can assert secrets are zeroized once
            /// a slot is freed (US-704).
            #[cfg(not(target_arch = "arm"))]
            pub fn slot_bytes_dump(
                &self,
            ) -> std::vec::Vec<([u8; MAX_KEY_LEN], [u8; DEV_MAX_VALUE_LEN])> {
                self.slots.iter().map(|s| (s.key, s.val)).collect()
            }
        }

    impl Rp2350SecureStore {
        /// Worst-case serialized partition-image size (format v2): 4-byte
        /// magic + 4-byte entry count, every slot at its maximum key/value
        /// lengths, and a trailing 4-byte CRC-32.
        pub const PARTITION_IMAGE_MAX: usize =
            8 + DEV_MAX_ENTRIES * (4 + MAX_KEY_LEN + 4 + DEV_MAX_VALUE_LEN) + 4;

        /// US-915: worst-case **sealed** (format-v3) partition-image size —
        /// the v2 bound plus the image nonce (12 bytes in the header) and
        /// one GCM tag (16 bytes) per entry. The on-flash slots are sized
        /// for this bound; the SECURE-region assertion below covers it.
        pub const SEALED_PARTITION_IMAGE_MAX: usize = Self::PARTITION_IMAGE_MAX
            + crate::store_v3::V3_NONCE_LEN
            + DEV_MAX_ENTRIES * crate::store_v3::V3_TAG_LEN;

        /// Serialize the secure partition into `buf` (power-down snapshot —
        /// the byte-binding point for the secure-partition flash persistence).
        /// US-915: a keyed store seals the image (format v3, encrypt-then-MAC);
        /// an unkeyed store keeps the legacy logical format v2. Returns the
        /// number of bytes written, or [`SecureStoreError::Full`]
        /// if `buf` is too small.
        pub fn partition_image(&self, buf: &mut [u8]) -> Result<usize, SecureStoreError> {
            let len = self.partition_image_len();
            if len > buf.len() {
                return Err(SecureStoreError::Full);
            }
            let filled = self.partition_image_window(0, &mut buf[..len]);
            debug_assert_eq!(filled, len);
            Ok(filled)
        }

        /// US-715: exact serialized image length — the windowed persist
        /// producer's bound, sized by the same walk [`Self::partition_image`]
        /// uses. Keyed (v3 sealed): the v2 length plus the image nonce and
        /// one tag per entry (GCM ciphertext is plaintext-length).
        pub fn partition_image_len(&self) -> usize {
            let n = self.slots.iter().filter(|s| s.used).count();
            let mut size = 8usize;
            for s in self.slots.iter().filter(|s| s.used) {
                size += 4 + s.key_len as usize + 4 + s.val_len as usize;
            }
            let logical = size + 4; // trailing CRC-32
            match self.key {
                Some(_) => {
                    logical + crate::store_v3::V3_NONCE_LEN
                        + n * crate::store_v3::V3_TAG_LEN
                }
                None => logical,
            }
        }

        /// US-715: fill `buf` with the serialized image bytes at `off` — the
        /// windowed persist producer, the twin of [`Self::partition_image`]
        /// (byte-identical output at every offset). One walk emits the
        /// window's intersection with each segment while folding the running
        /// CRC for the tail. Returns the number of bytes filled. US-915: a
        /// keyed store emits the sealed format v3.
        pub fn partition_image_window(&self, off: usize, buf: &mut [u8]) -> usize {
            let end = off.saturating_add(buf.len());
            let mut pos = 0usize;
            let mut filled = 0usize;
            let mut crc = 0xFFFF_FFFF_u32;
            // Segment emit = CRC fold + window intersection, in image order.
            // `&$bytes` coerces both `[u8; 4]` temporaries and unsized
            // sub-slice places to the `&[u8]` parameter.
            macro_rules! seg {
                ($bytes:expr) => {{
                    crc = crc32_update(crc, &$bytes);
                    emit_window_seg(buf, off, end, &mut pos, &mut filled, &$bytes);
                }};
            }
            match self.key {
                Some(key) => {
                    // Sealed emission (format v3). Deterministic nonce: the
                    // same store content re-seals byte-identically, so the
                    // persist gate's compare-then-write stays quiet.
                    let n = self.slots.iter().filter(|s| s.used).count();
                    // Shared with the heap `seal_image` path so the framing
                    // cannot drift; see `store_v3::entries_digest` for why it
                    // is framed rather than a bare `key ‖ val`.
                    let digest = crate::store_v3::entries_digest(
                        self.slots
                            .iter()
                            .filter(|s| s.used)
                            .enumerate()
                            .map(|(i, s)| {
                                (
                                    i as u32,
                                    s.key_len as u32,
                                    &s.key[..s.key_len as usize],
                                    s.val_len as u32,
                                    &s.val[..s.val_len as usize],
                                )
                            }),
                    );
                    let image_nonce = crate::store_v3::nonce_for(&key, &digest);
                    seg!(crate::store_v3::PARTITION_IMAGE_MAGIC_V3.to_le_bytes());
                    seg!((n as u32).to_le_bytes());
                    seg!(image_nonce);
                    for (i, s) in self.slots.iter().filter(|s| s.used).enumerate() {
                        let kl = s.key_len as usize;
                        let vl = s.val_len as usize;
                        // The plaintext entry transits one bounded stack
                        // window (US-704/US-715 discipline), encrypted in
                        // place — it never lands in memory unencrypted.
                        let mut win = [0u8; MAX_KEY_LEN + DEV_MAX_VALUE_LEN];
                        win[..kl].copy_from_slice(&s.key[..kl]);
                        win[kl..kl + vl].copy_from_slice(&s.val[..vl]);
                        // Unreachable failure: the window length matches the
                        // declared entry bounds and the key is always 32
                        // bytes — the only `seal_entry` failure modes.
                        let tag = crate::store_v3::seal_entry(
                            &key,
                            &image_nonce,
                            n,
                            i,
                            kl,
                            vl,
                            &mut win[..kl + vl],
                        )
                        .expect("seal_entry on an in-bounds entry cannot fail");
                        seg!((kl as u32).to_le_bytes());
                        seg!((vl as u32).to_le_bytes());
                        seg!(win[..kl + vl]);
                        seg!(tag);
                    }
                }
                None => {
                    // Legacy logical emission (format v2) — the unkeyed
                    // store's serialization (host-only shape in practice).
                    seg!(PARTITION_IMAGE_MAGIC.to_le_bytes());
                    seg!((self.slots.iter().filter(|s| s.used).count() as u32).to_le_bytes());
                    for s in self.slots.iter().filter(|s| s.used) {
                        seg!((s.key_len as u32).to_le_bytes());
                        seg!(s.key[..s.key_len as usize]);
                        seg!((s.val_len as u32).to_le_bytes());
                        seg!(s.val[..s.val_len as usize]);
                    }
                }
            }
            // The trailing CRC-32 closes the image (it covers every byte
            // before it and is not itself folded).
            let tail = (!crc).to_le_bytes();
            emit_window_seg(buf, off, end, &mut pos, &mut filled, &tail);
            filled
        }

        /// Restore the secure partition from a serialized image (reboot).
        /// The slice form of [`Self::from_partition_image_reader`].
        pub fn from_partition_image(&mut self, img: &[u8]) {
            let mut reader = SliceReader::new(img);
            self.from_partition_image_reader(&mut reader);
        }

        /// Restore from a serialized image pulled through `reader`'s
        /// windows — the device boot path's form (a volatile flash-slot
        /// reader); no whole-image buffer exists anywhere on this path.
        /// US-915: dispatch on the slot magic — a sealed format-v3 image
        /// (tags verified before any slot is touched) or a legacy format-v2
        /// image (the pre-update signature / an unkeyed store). Semantics
        /// are identical in both shapes: all-or-nothing, a failed validation
        /// leaves the store empty rather than restoring a partial secret.
        // US-939: `#[inline(never)]` -- async-main frame discipline.
    #[inline(never)]
    pub fn from_partition_image_reader(&mut self, reader: &mut dyn ImageReader) {
            let mut magic = [0u8; 4];
            match read_exact_window(reader, 0, &mut magic) {
                None => self.reset(), // short slot: nothing to restore
                Some(()) => match u32::from_le_bytes(magic) {
                    crate::store_v3::PARTITION_IMAGE_MAGIC_V3 => self.restore_v3(reader),
                    PARTITION_IMAGE_MAGIC => self.restore_v2(reader),
                    _ => self.reset(),
                },
            }
        }

        /// Legacy format-v2 restore (the pre-US-915 discipline). The image
        /// is self-delimiting, so a fixed-size slot window with padding
        /// after the CRC restores fine.
        fn restore_v2(&mut self, reader: &mut dyn ImageReader) {
            // Pass 0 — the shared streaming validator (structure + CRC,
            // host-wide bounds): the reader form of the slice path's
            // `partition_image_len` call.
            if partition_image_len_reader(reader).is_none() {
                self.reset();
                return;
            }
            // Pass 1 — validate the whole image against the device slot
            // bounds before touching any slot (the shared check above uses
            // the looser host-wide `MAX_VALUE_LEN`).
            let mut lens = [(0u16, 0u16); DEV_MAX_ENTRIES];
            let n = {
                let mut hdr = [0u8; 8];
                if read_exact_window(reader, 0, &mut hdr).is_none() {
                    self.reset();
                    return;
                }
                let count = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
                if count > DEV_MAX_ENTRIES {
                    self.reset();
                    return;
                }
                count
            };
            let mut i = 8usize;
            for slot in &mut lens[..n] {
                let Some((kl, j)) = next_len_u32(reader, i) else {
                    self.reset();
                    return;
                };
                i = j;
                if kl as usize > MAX_KEY_LEN {
                    self.reset();
                    return;
                }
                i += kl as usize;
                let Some((vl, j)) = next_len_u32(reader, i) else {
                    self.reset();
                    return;
                };
                i = j;
                if vl as usize > DEV_MAX_VALUE_LEN {
                    self.reset();
                    return;
                }
                i += vl as usize;
                *slot = (kl as u16, vl as u16);
            }
            // Pass 2 — image is well-formed; replace the slots. Values are
            // read directly into the target slot (no intermediate buffer);
            // the key must be complete before the duplicate/update-vs-
            // allocate decision, so it transits a zeroized key window.
            self.reset();
            i = 8;
            for &(kl, vl) in &lens[..n] {
                let (kl, vl) = (kl as usize, vl as usize);
                i += 4; // skip the key_len header (validated in pass 1)
                let mut key = ZeroWindow::<MAX_KEY_LEN>::new();
                if read_exact_window(reader, i, &mut key.0[..kl]).is_none() {
                    return; // unreachable after pass 1 — never partial
                }
                i += kl;
                // A duplicated key in a (corrupt) image is an update, not a
                // second slot.
                let slot = if let Some(s) = self
                    .slots
                    .iter_mut()
                    .find(|s| s.used && s.key[..s.key_len as usize] == key.0[..kl])
                {
                    s.val_len = vl as u16;
                    s
                } else if let Some(s) = self.slots.iter_mut().find(|s| !s.used) {
                    s.key[..kl].copy_from_slice(&key.0[..kl]);
                    s.key_len = kl as u8;
                    s.val_len = vl as u16;
                    s.used = true;
                    self.n += 1;
                    s
                } else {
                    continue; // unreachable: pass 1 bounds the occupancy
                };
                i += 4; // skip the val_len header
                if read_exact_window(reader, i, &mut slot.val[..vl]).is_none() {
                    return; // unreachable after pass 1 — never partial
                }
                i += vl;
            }
        }

        /// US-915: sealed format-v3 restore. Pass 0 validates the WHOLE
        /// image (every entry tag + the trailing CRC) before touching any
        /// slot; pass 1 walks the validated entries and loads the slots.
        /// A forged or torn v3 image (bad tag, bad CRC, bad structure)
        /// never yields a partial secret — the store stays empty.
        fn restore_v3(&mut self, reader: &mut dyn ImageReader) {
            let Some(key) = self.key else {
                // A sealed image with no key configured cannot validate —
                // all-or-nothing: the store stays empty.
                self.reset();
                return;
            };
            if crate::store_v3::sealed_image_len_reader(reader, &key).is_none() {
                self.reset();
                return;
            }
            let mut hdr = [0u8; crate::store_v3::V3_HEADER_LEN];
            if read_exact_window(reader, 0, &mut hdr).is_none() {
                self.reset();
                return; // unreachable: pass 0 read the header
            }
            let count = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
            let mut image_nonce = [0u8; crate::store_v3::V3_NONCE_LEN];
            image_nonce.copy_from_slice(&hdr[8..]);
            self.reset();
            let mut i = crate::store_v3::V3_HEADER_LEN;
            let mut kbuf = [0u8; MAX_KEY_LEN];
            let mut vbuf = [0u8; DEV_MAX_VALUE_LEN];
            for idx in 0..count {
                let Some((kl, vl, next)) = crate::store_v3::sealed_next_entry(
                    reader,
                    &key,
                    &image_nonce,
                    count,
                    idx,
                    i,
                    &mut kbuf,
                    &mut vbuf,
                ) else {
                    break; // unreachable: pass 0 verified every entry
                };
                i = next;
                // A duplicated key in a (corrupt) image is an update, not a
                // second slot — the v2 restore discipline.
                let slot = if let Some(s) = self
                    .slots
                    .iter_mut()
                    .find(|s| s.used && s.key[..s.key_len as usize] == kbuf[..kl])
                {
                    s.val_len = vl as u16;
                    s
                } else if let Some(s) = self.slots.iter_mut().find(|s| !s.used) {
                    s.key[..kl].copy_from_slice(&kbuf[..kl]);
                    s.key_len = kl as u8;
                    s.val_len = vl as u16;
                    s.used = true;
                    self.n += 1;
                    s
                } else {
                    continue; // unreachable: the validator bounds occupancy
                };
                slot.val[..vl].copy_from_slice(&vbuf[..vl]);
            }
            // The plaintext windows transited secrets — zeroize (US-704).
            kbuf.fill(0);
            vbuf.fill(0);
        }

        /// Clear every slot (used by [`from_partition_image`] validation).
        /// The freed slot key/value bytes are zeroized (US-704) so a secret
        /// cannot be read out of RAM after the entry is gone.
        fn reset(&mut self) {
            for s in &mut self.slots {
                s.used = false;
                s.key.fill(0);
                s.val.fill(0);
                s.key_len = 0;
                s.val_len = 0;
            }
            self.n = 0;
        }
    }

    // US-715 pass-1 helper: plain little-endian `u32` read at `off` (no CRC
    // fold — pass 1 re-reads the length fields the validator already walked).
    fn next_len_u32(reader: &mut dyn ImageReader, off: usize) -> Option<(u32, usize)> {
        let mut b = [0u8; 4];
        read_exact_window(reader, off, &mut b)?;
        Some((u32::from_le_bytes(b), off + 4))
    }

    // Two image slots must fit the reserved 64 KiB secure-partition flash
    // region (the generated memory.x's `SECURE`, @ 0x103F0000 on the `pico2`
    // board; the firmware's
    // `SECURE_SLOT_BYTES` rounds this up to NOR erase granularity and links
    // two slots into it). US-915: the SEALED bound is the sizing gate.
    const _: () = assert!(
        Rp2350SecureStore::SEALED_PARTITION_IMAGE_MAX <= 32_768,
        "two sealed secure-partition slots no longer fit the 64 KiB SECURE region",
    );

    impl SecureStore for Rp2350SecureStore {
        fn write(&mut self, key: &[u8], value: &[u8]) -> Result<(), SecureStoreError> {
            if key.len() > MAX_KEY_LEN {
                return Err(SecureStoreError::KeyTooLong);
            }
            if value.len() > DEV_MAX_VALUE_LEN {
                return Err(SecureStoreError::ValueTooLong);
            }
            // Update in place if the key already exists.
            for s in &mut self.slots {
                if s.used && &s.key[..s.key_len as usize] == key {
                    s.val[..value.len()].copy_from_slice(value);
                    s.val_len = value.len() as u16;
                    return Ok(());
                }
            }
            // Otherwise allocate a fresh slot.
            for s in &mut self.slots {
                if !s.used {
                    s.key[..key.len()].copy_from_slice(key);
                    s.key_len = key.len() as u8;
                    s.val[..value.len()].copy_from_slice(value);
                    s.val_len = value.len() as u16;
                    s.used = true;
                    self.n += 1;
                    return Ok(());
                }
            }
            Err(SecureStoreError::Full)
        }
        fn read(&mut self, key: &[u8], out: &mut [u8]) -> Result<usize, SecureStoreError> {
            let s = self
                .slots
                .iter()
                .find(|s| s.used && &s.key[..s.key_len as usize] == key)
                .ok_or(SecureStoreError::NotFound)?;
            let n = s.val_len as usize;
            if n > out.len() {
                return Err(SecureStoreError::Full);
            }
            out[..n].copy_from_slice(&s.val[..n]);
            Ok(n)
        }
        fn delete(&mut self, key: &[u8]) -> Result<(), SecureStoreError> {
            if let Some(s) = self
                .slots
                .iter_mut()
                .find(|s| s.used && &s.key[..s.key_len as usize] == key)
            {
                // Zeroize the freed slot (US-704): no stale secret bytes are
                // left in the static backing memory.
                s.key.fill(0);
                s.key_len = 0;
                s.val.fill(0);
                s.val_len = 0;
                s.used = false;
                self.n = self.n.saturating_sub(1);
                Ok(())
            } else {
                Err(SecureStoreError::NotFound)
            }
        }
        fn contains(&self, key: &[u8]) -> bool {
            self.slots.iter().any(|s| s.used && &s.key[..s.key_len as usize] == key)
        }
        fn snapshot_partition(&self, buf: &mut [u8]) -> Result<usize, SecureStoreError> {
            self.partition_image(buf)
        }
        fn snapshot_len(&self) -> usize {
            self.partition_image_len()
        }
        fn snapshot_window(&self, off: usize, buf: &mut [u8]) -> usize {
            self.partition_image_window(off, buf)
        }
    fn is_empty(&self) -> Result<bool, SecureStoreError> {
        Ok(!self.slots.iter().any(|slot| slot.used))
    }
    fn is_empty_except(&self, slot: &[u8]) -> Result<bool, SecureStoreError> {
        Ok(self.slots.iter().all(|s| {
            !s.used || &s.key[..s.key_len as usize] == slot
        }))
    }
    fn wipe_all(&mut self) -> Result<(), SecureStoreError> {
        // US-919: the internal all-slots clear (validation-failed restores
        // already use it) — the freed slot key/value bytes are zeroized
        // (US-704), so no stale secret survives in the static backing.
        self.reset();
        Ok(())
    }
    fn store_key(&self) -> Option<[u8; 32]> {
        self.key
    }
}

    // US-387 TDD: the partition-image seam (the secure-partition flash
    // persistence binding). Host-runnable: the store is pure static memory.
    #[cfg(all(test, not(target_arch = "arm")))]
    mod tests {
        extern crate std;

        use super::*;

        const SECRET: &[u8] = b"fido-hkey-SECRET-32-bytes-00000000";

        /// Write → power-down snapshot → reboot (restore) → read back
        /// identical (the US-387 device-side mirror of the US-380 host test).
        #[test]
        fn write_reboot_read_back_partition_image() {
            let mut store = Rp2350SecureStore::new();
            store.write(b"fido.hkey", SECRET).unwrap();

            let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
            let n = store.partition_image(&mut img).unwrap();
            // (power cycle: `store` goes out of scope here)

            let mut restored = Rp2350SecureStore::new();
            restored.from_partition_image(&img[..n]);
            let mut out = [0u8; DEV_MAX_VALUE_LEN];
            let m = restored.read(b"fido.hkey", &mut out).unwrap();
            assert_eq!(
                &out[..m],
                SECRET,
                "secret must survive a reboot from the secure partition"
            );
        }

        /// S-701-2: a chunked logical slot persisted through the partition
        /// image survives a reboot (the device-image seam the FIDO/OATH/
        /// OpenPGP keystores rely on).
        #[test]
        fn chunked_slot_survives_partition_image_reboot() {
            use super::super::chunked;

            let mut store = Rp2350SecureStore::new();
            // 800 B over two 400-B logical halves → 2 parts, 4 physical
            // entries with both buffers counted (well within the 16-entry
            // device store).
            let mut value = [0u8; 800];
            for (i, b) in value.iter_mut().enumerate() {
                *b = (i & 0xFF) as u8;
            }
            chunked::write_chunked(&mut store, b"fido.keystore.v1", &value).unwrap();

            let mut img = [0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
            let n = store.partition_image(&mut img).unwrap();
            let mut restored = Rp2350SecureStore::new();
            restored.from_partition_image(&img[..n]);

            let mut out = [0u8; chunked::MAX_LOGICAL_LEN];
            let m = chunked::read_chunked(&mut restored, b"fido.keystore.v1", &mut out).unwrap();
            assert_eq!(m, value.len());
            assert_eq!(&out[..m], &value, "chunked slot bytes identical after reboot");
        }

        /// A corrupted (truncated) partition image must not yield a partial
        /// secret — the restore is all-or-nothing.
        #[test]
        fn truncated_partition_image_restores_empty() {
            let mut store = Rp2350SecureStore::new();
            store.write(b"seed", b"0123456789abcdef").unwrap();
            let mut img = std::vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
            let n = store.partition_image(&mut img).unwrap();

            let mut restored = Rp2350SecureStore::new();
            restored.from_partition_image(&img[..n - 1]); // truncate the last byte
            assert!(
                !restored.contains(b"seed"),
                "a truncated partition image must not restore a partial secret"
            );
        }

        /// The store is bounded: DEV_MAX_ENTRIES entries, DEV_MAX_VALUE_LEN
        /// bytes per value, MAX_KEY_LEN per key.
        #[test]
        fn slot_bounds() {
            let mut store = Rp2350SecureStore::new();
            for i in 0..DEV_MAX_ENTRIES {
                let mut k = [0u8; 8];
                k[4..].copy_from_slice(&(i as u32).to_le_bytes());
                store.write(&k, b"v").unwrap();
            }
            assert!(
                matches!(store.write(b"overflow", b"v"), Err(SecureStoreError::Full)),
                "entry 17 must be rejected (DEV_MAX_ENTRIES={DEV_MAX_ENTRIES})"
            );
            let big = [0u8; DEV_MAX_VALUE_LEN + 1];
            assert!(
                matches!(store.write(b"k", &big), Err(SecureStoreError::ValueTooLong)),
                "values are bounded to DEV_MAX_VALUE_LEN bytes"
            );
            let long_key = [0u8; MAX_KEY_LEN + 1];
            assert!(
                matches!(store.write(&long_key, b"v"), Err(SecureStoreError::KeyTooLong)),
                "keys are bounded to MAX_KEY_LEN bytes"
            );
        }

        /// An undersized image buffer is a clean error (never a panic, never
        /// a partial write).
        #[test]
        fn partition_image_buffer_too_small() {
            let mut store = Rp2350SecureStore::new();
            store.write(b"k", b"0123456789").unwrap();
            let mut tiny = [0u8; 4];
            assert!(matches!(
                store.partition_image(&mut tiny),
                Err(SecureStoreError::Full)
            ));
        }

        /// A fresh partition image (all 0xFF, as erased flash) restores to an
        /// empty store without panicking.
        #[test]
        fn erased_flash_image_restores_empty() {
            let mut store = Rp2350SecureStore::new();
            let img = [0xFFu8; 64];
            store.from_partition_image(&img);
            assert!(!store.contains(b"fido.hkey"));
        }

        /// A power-lost write that corrupts one payload byte (the CRC must
        /// catch it) restores to an empty store, never a partial secret.
        #[test]
        fn bad_crc_partition_image_restores_empty() {
            let mut store = Rp2350SecureStore::new();
            store.write(b"seed", b"0123456789abcdef").unwrap();
            let mut img = std::vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
            let n = store.partition_image(&mut img).unwrap();
            img[10] ^= 0x01; // flip one payload byte (past magic+count)

            let mut restored = Rp2350SecureStore::new();
            restored.from_partition_image(&img[..n]);
            assert!(
                !restored.contains(b"seed"),
                "a CRC-mismatched partition image must not restore a partial secret"
            );
        }

        /// A wrong magic (e.g. leftover C-image flash-pool data in the
        /// region) restores to an empty store.
        #[test]
        fn wrong_magic_partition_image_restores_empty() {
            let mut store = Rp2350SecureStore::new();
            store.write(b"seed", b"0123456789abcdef").unwrap();
            let mut img = std::vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
            let n = store.partition_image(&mut img).unwrap();
            img[0] ^= 0xFF;

            let mut restored = Rp2350SecureStore::new();
            restored.from_partition_image(&img[..n]);
            assert!(!restored.contains(b"seed"));
        }

        /// `partition_image_is_valid` (the boot-time slot selector): accepts
        /// a written image, rejects torn (truncated), bit-flipped and
        /// erased-flash content.
        #[test]
        fn partition_image_is_valid_selects_good_slots() {
            let mut store = Rp2350SecureStore::new();
            store.write(b"k1", b"v1").unwrap();
            store.write(b"k2", b"v2v2").unwrap();
            let mut img = std::vec![0u8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
            let n = store.partition_image(&mut img).unwrap();

            assert!(partition_image_is_valid(&img[..n]), "written image must validate");
            assert!(
                !partition_image_is_valid(&img[..n - 1]),
                "a torn (truncated) image must not validate"
            );
            let mut flipped = img[..n].to_vec();
            flipped[9] ^= 0x80;
            assert!(!partition_image_is_valid(&flipped), "a bit-flip must not validate");
            assert!(
                !partition_image_is_valid(&[0xFFu8; 64]),
                "erased flash (0xFF) must not validate"
            );
        }

        /// The on-flash slot is a fixed-size window: persist programs only
        /// the image, boot reads the whole slot — the erased-flash (0xFF)
        /// padding after the image's own CRC must not invalidate the slot
        /// (the image is self-delimiting). Without this, every real persist
        /// would read back invalid and the store would boot empty forever.
        #[test]
        fn slot_window_padding_does_not_invalidate_image() {
            let mut store = Rp2350SecureStore::new();
            store.write(b"seed", b"0123456789abcdef").unwrap();
            let mut slot = [0xFFu8; Rp2350SecureStore::PARTITION_IMAGE_MAX];
            let n = store.partition_image(&mut slot).unwrap();
            assert!(n < slot.len(), "the image must be shorter than the slot window");

            assert!(
                partition_image_is_valid(&slot),
                "a slot window with 0xFF padding after the CRC must validate"
            );
            let mut restored = Rp2350SecureStore::new();
            restored.from_partition_image(&slot);
            let mut out = [0u8; DEV_MAX_VALUE_LEN];
            let m = restored.read(b"seed", &mut out).unwrap();
            assert_eq!(&out[..m], b"0123456789abcdef");
        }
    }
}

#[cfg(feature = "device")]
pub use rp2350::Rp2350SecureStore;

// ---------------------------------------------------------------------------
// Chunked logical slots (S-701-2, US-324).
//
// [`SecureStore`] implementations cap a single value (the device store at 512
// B, `DEV_MAX_VALUE_LEN`), but FIDO credential snapshots, OATH credential
// streams, and OpenPGP DO streams are larger. This layer spans a logical slot
// over a *family* of physical part slots, each well under the device value
// cap.
//
// Design (torn-write safe, no extra flash buffers):
//
// * a logical slot is double-buffered: part sets are generation-tagged and
//   live in buffer 0 (`<key>.p0NN`) or buffer 1 (`<key>.p1NN`). A write goes
//   to the buffer **not** holding the current set, so a power loss mid-write
//   can never touch the last valid set — the reader picks the complete,
//   CRC-valid set with the highest generation ("last valid part set wins").
// * part record (the physical slot value, ≤ 512 B on device):
//   `[gen u32][part u16][count u16][total_len u32][crc32 u32][payload ≤ 496]`
//   where the CRC covers part/count/total_len + payload.
// * part 0 of a set is the *commit marker* and is written last.
//
// A logical slot may span up to [`chunked::MAX_PARTS`] parts per buffer
// (payload capacity [`chunked::MAX_LOGICAL_LEN`] = 12 × 496 = 5,952 B) at up
// to `2 × MAX_PARTS` physical entries per logical slot — and the second
// number is the one that binds, because the two generations are live
// simultaneously. See the assertion below.
pub mod chunked {
    use super::{crc32, SecureStore, SecureStoreError, MAX_KEY_LEN};

    /// Part-record header length: gen(4) + part(2) + count(2) + total_len(4)
    /// + crc32(4).
    pub const PART_HEADER_LEN: usize = 16;
    /// Maximum payload bytes per part (keeps the physical record ≤ 512 B —
    /// the device store's `DEV_MAX_VALUE_LEN`).
    pub const PART_PAYLOAD_MAX: usize = 512 - PART_HEADER_LEN;
    /// Maximum number of parts per buffer (payload capacity 12 × 496 = 5,952 B).
    ///
    /// US-1010: this was 17 (8,432 B) while the device store held 24 entries,
    /// and those two numbers contradicted each other for as long as both
    /// existed. `write_chunked` writes a new generation into the buffer *not*
    /// holding the current set and retires the old buffer's parts only
    /// afterwards, so a rewrite of a maximum-width value transiently needs
    /// `2 × MAX_PARTS` physical entries. `2 × 17 = 34 > 24`, so the
    /// documented 8,432 B was **unreachable**: the first full-width rewrite
    /// returned `SecureStoreError::Full`, and the docs, the OATH module
    /// comments and this module's own round-trip test all described a
    /// capacity the device never served.
    ///
    /// 12 is the largest value that satisfies the invariant at **zero RAM
    /// cost** — the store static is `[Slot; DEV_MAX_ENTRIES]`, and this
    /// constant is not a type parameter anywhere, so lowering it changes no
    /// allocation and no image byte. Raising `DEV_MAX_ENTRIES` instead would
    /// cost 568 B of partition image **and** ~580 B of bss *per entry* on a
    /// build with 0 B of unallocated RAM (see `docs/size-report.md`), so it is
    /// not the cheap direction.
    ///
    /// The 5,952 B figure is a *true* ceiling now, not a ceiling the store
    /// would refuse to meet — with the caveat the invariant below spells out:
    /// it is the ceiling for a store whose **only** resident entries are the
    /// chunked table's. Consumers: the FIDO keystore snapshot
    /// (`DEVICE_MAX_CREDS = 12` credentials + a 1,024-B large-blob array,
    /// ~4.1 KB worst case → 9 parts) fits; the OATH table
    /// (`MAX_CREDS = 68` × ~195 B ≈ 13.3 KB) never did and is documented as
    /// such.
    ///
    /// The OATH app's real durable ceiling is **30** maximal credentials
    /// (`apps/oath/tests/oath_capacity.rs`, measured), not the `~29` this
    /// comment carried for one commit. It is set by the rewrite *peak*, and
    /// that app holds one entry outside the chunked table — the US-1030 seal
    /// high-water mark — so its arithmetic is `parts_live + parts_being_written
    /// + 1`, not `2 × parts`. See `oath_core.rs` for the derivation; the
    /// short form is that 30 is the largest count whose *growth* into 12 parts
    /// rewrites from 11 (`11 + 12 + 1 = 24`), while a 12-part value that is
    /// rewritten at the same width peaks at `12 + 12 + 1 = 25` and is refused.
    pub const MAX_PARTS: usize = 12;
    /// Maximum logical value length.
    pub const MAX_LOGICAL_LEN: usize = MAX_PARTS * PART_PAYLOAD_MAX;

    /// US-1010: the capacity invariant, as a compile error rather than a
    /// field failure. Kept as a `_` item, so it costs nothing in the image.
    ///
    /// The two constants were independent literals for the life of the
    /// chunked layer, and nothing in the type system, the build, or the test
    /// suite noticed that they disagreed. This is the assertion that makes
    /// the disagreement a *build* failure: whoever next raises
    /// `DEV_MAX_ENTRIES` past `2 × MAX_PARTS` (or lowers it below
    /// `MAX_PARTS`) has to read this and decide about the 568 B + ~580 B per
    /// entry, rather than shipping a store whose documented capacity its own
    /// rewrite path cannot meet.
    ///
    /// **What this does and does not cover.** It is the *resident-free* form:
    /// it bounds the peak of a store that holds nothing but the chunked table.
    /// An app that keeps an entry of its own alongside the table has to check
    /// `parts + parts + resident` for itself, and `2 × MAX_PARTS` alone will
    /// not catch it — at `MAX_PARTS = 12` this assertion holds with the
    /// resident-free peak exactly on the 24-entry limit, so there is no margin
    /// left to give away. The OATH app is the worked example: it holds the
    /// US-1030 seal high-water mark, so its ceiling is derived from
    /// `parts_live + parts_being_written + 1` and lands at 30 maximal
    /// credentials (`apps/oath/tests/oath_capacity.rs`). Lowering
    /// `DEV_MAX_ENTRIES` is still the trade this assertion exists to surface.
    const _: () = {
        assert!(
            2 * MAX_PARTS <= crate::secure_store::rp2350::DEV_MAX_ENTRIES,
            "a chunked rewrite transiently holds both generations: 2 x MAX_PARTS physical \
             entries must fit the device store's DEV_MAX_ENTRIES, or MAX_LOGICAL_LEN is a \
             documented number the device never serves (the first full-width rewrite returns \
             SecureStoreError::Full)"
        );
        assert!(
            MAX_PARTS >= 2,
            "a logical slot needs at least two parts to exercise the double-buffer commit \
             discipline",
        );
    };

    /// Build the physical key of part `index` in buffer `buffer` (`0`/`1`):
    /// `<key>.p<b><NN>` (NN = two lowercase hex digits). Returns the key
    /// buffer and its length, or `None` when the family key is too long.
    pub fn physical_part_key(key: &[u8], buffer: u8, index: usize) -> Option<([u8; MAX_KEY_LEN], usize)> {
        if key.len() + 5 > MAX_KEY_LEN || index >= MAX_PARTS || buffer > 1 {
            return None;
        }
        let mut k = [0u8; MAX_KEY_LEN];
        k[..key.len()].copy_from_slice(key);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let base = key.len();
        k[base] = b'.';
        k[base + 1] = b'p';
        k[base + 2] = b'0' + buffer;
        k[base + 3] = HEX[index >> 4];
        k[base + 4] = HEX[index & 0xF];
        Some((k, base + 5))
    }

    /// Encode one part record (see the module docs for the layout).
    /// `crc32` covers part/count/total_len + payload.
    pub fn encode_part_record(
        gen: u32,
        index: usize,
        count: usize,
        total_len: usize,
        payload: &[u8],
        out: &mut [u8; PART_HEADER_LEN + PART_PAYLOAD_MAX],
    ) -> Result<usize, SecureStoreError> {
        if index >= count || count > MAX_PARTS || payload.len() > PART_PAYLOAD_MAX {
            return Err(SecureStoreError::ValueTooLong);
        }
        let mut crc_input = [0u8; 8 + PART_PAYLOAD_MAX];
        crc_input[0..2].copy_from_slice(&(index as u16).to_le_bytes());
        crc_input[2..4].copy_from_slice(&(count as u16).to_le_bytes());
        crc_input[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
        crc_input[8..8 + payload.len()].copy_from_slice(payload);
        let crc = crc32(&crc_input[..8 + payload.len()]);
        out[0..4].copy_from_slice(&gen.to_le_bytes());
        out[4..6].copy_from_slice(&(index as u16).to_le_bytes());
        out[6..8].copy_from_slice(&(count as u16).to_le_bytes());
        out[8..12].copy_from_slice(&(total_len as u32).to_le_bytes());
        out[12..16].copy_from_slice(&crc.to_le_bytes());
        out[PART_HEADER_LEN..PART_HEADER_LEN + payload.len()].copy_from_slice(payload);
        Ok(PART_HEADER_LEN + payload.len())
    }

    /// Decode a part record header; returns `(gen, index, count, total_len)`
    /// after verifying the CRC over part/count/total_len + payload.
    pub fn decode_part_record(rec: &[u8]) -> Result<(u32, usize, usize, usize), SecureStoreError> {
        if rec.len() < PART_HEADER_LEN {
            return Err(SecureStoreError::Corrupt);
        }
        let gen = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
        let index = u16::from_le_bytes([rec[4], rec[5]]) as usize;
        let count = u16::from_le_bytes([rec[6], rec[7]]) as usize;
        let total_len = u32::from_le_bytes([rec[8], rec[9], rec[10], rec[11]]) as usize;
        let stored_crc = u32::from_le_bytes([rec[12], rec[13], rec[14], rec[15]]);
        let payload = &rec[PART_HEADER_LEN..];
        let mut crc_input = [0u8; 8 + PART_PAYLOAD_MAX];
        crc_input[0..2].copy_from_slice(&(index as u16).to_le_bytes());
        crc_input[2..4].copy_from_slice(&(count as u16).to_le_bytes());
        crc_input[4..8].copy_from_slice(&(total_len as u32).to_le_bytes());
        let mut input_len = 8usize;
        if payload.len() > PART_PAYLOAD_MAX {
            return Err(SecureStoreError::Corrupt);
        }
        crc_input[8..8 + payload.len()].copy_from_slice(payload);
        input_len += payload.len();
        if crc32(&crc_input[..input_len]) != stored_crc {
            return Err(SecureStoreError::Corrupt);
        }
        Ok((gen, index, count, total_len))
    }

    /// Read one physical part into `rec`; `Ok(None)` when absent.
    fn read_part<S: SecureStore + ?Sized>(
        store: &mut S,
        key: &[u8],
        buffer: u8,
        index: usize,
        rec: &mut [u8; PART_HEADER_LEN + PART_PAYLOAD_MAX],
    ) -> Result<Option<usize>, SecureStoreError> {
        let (pk, pklen) = physical_part_key(key, buffer, index).ok_or(SecureStoreError::KeyTooLong)?;
        let n = match store.read(&pk[..pklen], rec) {
            Ok(n) => n,
            Err(SecureStoreError::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(Some(n))
    }

    /// Write `value` as the chunked logical slot `key`.
    pub fn write_chunked<S: SecureStore + ?Sized>(
        store: &mut S,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), SecureStoreError> {
        if value.len() > MAX_LOGICAL_LEN {
            return Err(SecureStoreError::ValueTooLong);
        }
        // Locate the current (highest-generation complete) set and write the
        // new generation into the *other* buffer, so a torn write can never
        // destroy the last valid set.
        let mut rec = [0u8; PART_HEADER_LEN + PART_PAYLOAD_MAX];
        let mut gens = [None::<u32>; 2];
        for buf in 0..2u8 {
            if let Some(n) = read_part(store, key, buf, 0, &mut rec)? {
                if let Ok((gen, 0, count, total_len)) = decode_part_record(&rec[..n]) {
                    if complete_set_present(store, key, buf, gen, count, total_len)? {
                        gens[buf as usize] = Some(gen);
                    }
                }
            }
        }
        let (target_buf, next_gen) = match (gens[0], gens[1]) {
            (None, None) => (0u8, 1u32),
            (Some(g0), None) => (1u8, g0.saturating_add(1)),
            (None, Some(g1)) => (0u8, g1.saturating_add(1)),
            (Some(g0), Some(g1)) => {
                if g0 >= g1 {
                    (1u8, g0.saturating_add(1))
                } else {
                    (0u8, g1.saturating_add(1))
                }
            }
        };

        let count = value.len().div_ceil(PART_PAYLOAD_MAX).max(1);
        // Parts 1.. are written first; part 0 is the commit marker, last.
        // Self-cleaning (S-731-2 review): part keys are generation-
        // independent, so a part written into the target buffer before a
        // failure is an ORPHAN that every retry overwrites in place — but
        // part 0 always needs a fresh slot the orphans deny it, and the
        // retirement pass only runs after a fully successful write. Without
        // the cleanup below, one transient-occupancy failure leaves the
        // logical slot permanently unwritable. Delete the parts written by
        // THIS call (best effort) so the store returns to its pre-write
        // occupancy; the previous complete generation in the other buffer
        // was never touched.
        let mut written: heapless::Vec<([u8; MAX_KEY_LEN], usize), MAX_PARTS> =
            heapless::Vec::new();
        for index in (0..count).rev() {
            let payload = &value[index * PART_PAYLOAD_MAX..((index + 1) * PART_PAYLOAD_MAX).min(value.len())];
            let n = encode_part_record(next_gen, index, count, value.len(), payload, &mut rec)?;
            let (pk, pklen) = physical_part_key(key, target_buf, index).ok_or(SecureStoreError::KeyTooLong)?;
            if let Err(e) = store.write(&pk[..pklen], &rec[..n]) {
                for (k, kl) in &written {
                    let _ = store.delete(&k[..*kl]);
                }
                return Err(e);
            }
            let _ = written.push((pk, pklen));
        }
        // Retire the other buffer's stale parts (best effort — the reader
        // always prefers the highest complete generation anyway).
        let other = 1 - target_buf;
        for index in 0..MAX_PARTS {
            if let Some((pk, pklen)) = physical_part_key(key, other, index) {
                let _ = store.delete(&pk[..pklen]);
            }
        }
        Ok(())
    }

    /// Whether every part 0..count of buffer `buf` exists with `gen` and the
    /// expected total length (the "complete set" test).
    fn complete_set_present<S: SecureStore + ?Sized>(
        store: &mut S,
        key: &[u8],
        buf: u8,
        gen: u32,
        count: usize,
        total_len: usize,
    ) -> Result<bool, SecureStoreError> {
        let mut rec = [0u8; PART_HEADER_LEN + PART_PAYLOAD_MAX];
        for index in 0..count {
            let Some(n) = read_part(store, key, buf, index, &mut rec)? else {
                return Ok(false);
            };
            match decode_part_record(&rec[..n]) {
                Ok((g, i, c, t)) if g == gen && i == index && c == count && t == total_len => {}
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Read the chunked logical slot `key` into `out`; returns its length.
    /// Among complete, CRC-valid part sets the highest generation wins.
    pub fn read_chunked<S: SecureStore + ?Sized>(
        store: &mut S,
        key: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SecureStoreError> {
        let mut rec = [0u8; PART_HEADER_LEN + PART_PAYLOAD_MAX];
        let mut found_any = false;
        let mut best: Option<(u32, usize, usize)> = None; // (gen, count, total_len)
        for buf in 0..2u8 {
            let Some(n) = read_part(store, key, buf, 0, &mut rec)? else {
                continue;
            };
            found_any = true;
            let Ok((gen, 0, count, total_len)) = decode_part_record(&rec[..n]) else {
                continue;
            };
            if count <= MAX_PARTS
                && total_len <= out.len()
                && complete_set_present(store, key, buf, gen, count, total_len)?
            {
                let better = match best {
                    None => true,
                    Some((g, _, _)) => gen > g,
                };
                if better {
                    best = Some((gen, count, total_len));
                }
            }
        }
        let Some((gen, count, total_len)) = best else {
            return Err(if found_any {
                SecureStoreError::Corrupt
            } else {
                SecureStoreError::NotFound
            });
        };
        for index in 0..count {
            let (pk, pklen) = physical_part_key(key, gen_buffer(best, key, store, gen)?, index)
                .ok_or(SecureStoreError::KeyTooLong)?;
            let n = store.read(&pk[..pklen], &mut rec)?;
            let (g, i, c, t) = decode_part_record(&rec[..n])?;
            debug_assert_eq!((g, i, c, t), (gen, index, count, total_len));
            let start = index * PART_PAYLOAD_MAX;
            let end = ((index + 1) * PART_PAYLOAD_MAX).min(total_len);
            out[start..end].copy_from_slice(&rec[PART_HEADER_LEN..PART_HEADER_LEN + (end - start)]);
        }
        Ok(total_len)
    }

    /// The buffer holding the winning generation (part 0 of that buffer
    /// carries it — re-derive instead of threading the buffer index through
    /// the `best` tuple).
    fn gen_buffer<S: SecureStore + ?Sized>(
        _best: Option<(u32, usize, usize)>,
        key: &[u8],
        store: &mut S,
        gen: u32,
    ) -> Result<u8, SecureStoreError> {
        let mut rec = [0u8; PART_HEADER_LEN + PART_PAYLOAD_MAX];
        for buf in 0..2u8 {
            if let Some(n) = read_part(store, key, buf, 0, &mut rec)? {
                if let Ok((g, 0, _, _)) = decode_part_record(&rec[..n]) {
                    if g == gen {
                        return Ok(buf);
                    }
                }
            }
        }
        Err(SecureStoreError::NotFound)
    }

    /// Delete every physical part of the logical slot `key`.
    pub fn delete_chunked<S: SecureStore + ?Sized>(
        store: &mut S,
        key: &[u8],
    ) -> Result<(), SecureStoreError> {
        let mut deleted = false;
        for buf in 0..2u8 {
            for index in 0..MAX_PARTS {
                if let Some((pk, pklen)) = physical_part_key(key, buf, index) {
                    if store.delete(&pk[..pklen]).is_ok() {
                        deleted = true;
                    }
                }
            }
        }
        if deleted {
            Ok(())
        } else {
            Err(SecureStoreError::NotFound)
        }
    }

    /// Whether a readable chunked logical slot exists for `key`.
    pub fn contains_chunked<S: SecureStore + ?Sized>(store: &mut S, key: &[u8]) -> bool {
        for buf in 0..2u8 {
            if let Some((pk, pklen)) = physical_part_key(key, buf, 0) {
                if store.contains(&pk[..pklen]) {
                    return true;
                }
            }
        }
        false
    }
}
