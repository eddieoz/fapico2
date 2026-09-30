//! C-firmware data-partition location (US-413 S-413-2).
//!
//! The C firmware (`pico-fido2`) keeps its file system in RP2350 flash
//! partition 1 ("PicoKeys Data", `pico-keys-sdk/config/rp2350/pt.json`:
//! start 1032 K, size 3064 K — flash-relative `0x102000..0x400000`).
//! The partition bounds must be resolved at runtime the same way the C
//! firmware does (`pico-keys-sdk/src/fs/low_flash.c:200-229`): decode the
//! PICOBIN partition-table location word of partition 1 with the bootrom's
//! sector-bit encoding, then add `XIP_BASE` — the C file-system records and
//! the rom-pool head pointer live at **absolute XIP addresses**
//! (`low_flash.c:228-229`, `flash_read` dereferences them directly).
//!
//! All public addresses here are absolute XIP. The module is `no_std`,
//! heap-free, and splits into a host-testable pure core (word decode,
//! PT-block scan, validation, tail reservation) and a thin arm-only FFI
//! layer that mirrors the C call sequence and falls back to the `pt.json`
//! constants when the ROM table is unavailable (`low_flash.c:210-212`
//! fallback).

/// XIP base of the QSPI flash window (`low_flash.c:228`).
pub const FLASH_XIP_BASE: u32 = 0x1000_0000;
/// The C firmware's data-partition window, which is what this figure bounds.
///
/// **Deliberately NOT the board's flash size** (US-1080 made the rest of the
/// tree board-parameterised; this one is not, and the reason is that it is a
/// different fact). This constant sizes the region the *C* firmware laid down —
/// `pt.json` partition 1 runs `0x102000..0x400000`, and the C code detects the
/// part with SFDP and then clamps to the partition table that was flashed with
/// it. Those two agree on a 4 MiB Pico 2 and are not required to: a board with
/// more flash carries a C partition table that still ends at `0x400000`, and
/// reading past that boundary is walking outside the migration window, not
/// "more flash". Deriving it from `flash_size_kb` would silently widen the C
/// window on a larger part and hand the migration reader bytes the C firmware
/// never wrote. Revisit with the C partition table, not with the board.
pub const FLASH_BOARD_SIZE: u32 = 4 * 1024 * 1024;
pub const FLASH_SECTOR_SIZE: u32 = 4_096;
/// C `low_flash.c:222`: `data_end_addr -= 2 * FLASH_SECTOR_SIZE` — the
/// 8 KB rom-pool head region the C firmware reserves below the partition
/// end. The reader must not walk past it.
pub const TAIL_RESERVATION_BYTES: u32 = 2 * FLASH_SECTOR_SIZE;
/// `pt.json` partition 1 ("PicoKeys Data"): start 1032 K (flash-relative).
pub const PT_JSON_DATA_START: u32 = 0x102_000;
/// `pt.json` partition 1: size 3064 K.
pub const PT_JSON_DATA_SIZE: u32 = 3064 * 1024;
/// Minimum sane data region (guards against a bogus ROM table pointing at
/// a sliver; C has no equivalent check but clamps to the detected size).
pub const MIN_DATA_REGION: u32 = 16 * 1024;

/// PICOBIN block marker start (pico-sdk `boot/picobin.h:25`).
pub const PICOBIN_BLOCK_MARKER_START: u32 = 0xffff_ded3;
/// PICOBIN partition-table item id (`boot/picobin.h:42`).
pub const PICOBIN_ITEM_PARTITION_TABLE: u32 = 0x0a;

/// PICOBIN partition flags (`boot/picobin.h`).
const PART_FLAGS_HAS_ID: u32 = 0x0000_0001;
const PART_FLAGS_NUM_EXTRA_FAMILIES_SHIFT: u32 = 7;
const PART_FLAGS_NUM_EXTRA_FAMILIES_BITS: u32 = 0x0000_0180;
const PART_FLAGS_HAS_NAME: u32 = 0x0000_1000;

/// Resolved C data region in absolute XIP addresses. `end` is exclusive;
/// the resolved region is **after** the 8 KB tail reservation (mirroring
/// the C `data_end_addr` that `flash_set_bounds` receives).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPartition {
    pub start: u32,
    pub end: u32,
}

impl DataPartition {
    /// Region size in bytes (after any applied tail reservation).
    pub fn size_bytes(&self) -> u32 {
        self.end - self.start
    }
}

/// Decode one PICOBIN partition location word into a **flash-relative**
/// byte range: `first = w & 0x1fff` (FIRST_SECTOR_LSB 0),
/// `last = (w >> 13) & 0x1fff` (LAST_SECTOR_LSB 13, inclusive) —
/// `low_flash.c:214-219`, cross-checked against picotool's partition
/// decode (`first * 4096 .. (last + 1) * 4096`). No XIP base, no tail
/// reservation.
pub fn decode_partition_location(word: u32) -> Option<(u32, u32)> {
    let first = word & 0x1fff;
    let last = (word >> 13) & 0x1fff;
    if last < first {
        return None;
    }
    Some((first * FLASH_SECTOR_SIZE, (last + 1) * FLASH_SECTOR_SIZE))
}

/// Validate an absolute-XIP region: inside the board flash window,
/// non-degenerate, and at least [`MIN_DATA_REGION`].
pub fn validate(start: u32, end: u32) -> Option<DataPartition> {
    if start < FLASH_XIP_BASE || end > FLASH_XIP_BASE + FLASH_BOARD_SIZE || end <= start {
        return None;
    }
    if end - start < MIN_DATA_REGION {
        return None;
    }
    Some(DataPartition { start, end })
}

/// Apply the C 8 KB tail reservation to a validated region.
pub fn reserved(part: DataPartition) -> DataPartition {
    DataPartition {
        start: part.start,
        end: part.end - TAIL_RESERVATION_BYTES,
    }
}

/// `pt.json` partition 1 constants in absolute XIP addresses — the
/// unreserved partition range `[0x10102000, 0x10400000)`. Callers apply
/// the tail reservation on top. This is the device resolver's fallback
/// when the ROM table is unavailable (the C fallback `low_flash.c:210-212`
/// is "half the flash", which on this pt.json layout is not where the C
/// data actually lives; the constants are strictly more correct).
pub fn fallback_partition() -> DataPartition {
    DataPartition {
        start: FLASH_XIP_BASE + PT_JSON_DATA_START,
        end: FLASH_XIP_BASE + PT_JSON_DATA_START + PT_JSON_DATA_SIZE,
    }
}

/// Fallback with the tail reservation applied — what the device resolver
/// returns when the ROM table is unavailable.
pub fn fallback_partition_reserved() -> DataPartition {
    reserved(fallback_partition())
}

/// Scan a raw flash image for the first valid PICOBIN partition-table
/// block (marker + item `0x0a`) and return the location word of
/// `partition` (0-based). The block layout mirrors picotool's
/// `partition_table_item` (`metadata.h`): header word
/// `(count << 24) | (size << 8) | 0x0a`, then the unpartitioned-flags
/// word, then per partition: location word, flags word, optional 64-bit
/// id, extra-family words, optional packed name.
pub fn partition_location_word(flash: &[u8], partition: usize) -> Option<u32> {
    if flash.len() < 8 || partition >= 16 {
        return None;
    }
    let word = |i: usize| -> u32 {
        u32::from_le_bytes([flash[i * 4], flash[i * 4 + 1], flash[i * 4 + 2], flash[i * 4 + 3]])
    };
    let nwords = flash.len() / 4;
    for i in 0..nwords {
        if word(i) != PICOBIN_BLOCK_MARKER_START {
            continue;
        }
        // One word of headroom for at least the item header.
        if i + 1 >= nwords {
            return None;
        }
        let hdr = word(i + 1);
        if hdr & 0xff != PICOBIN_ITEM_PARTITION_TABLE {
            continue;
        }
        // Single-byte-size item: size = (hdr >> 8) & 0xff (type 0x0a has
        // bit 7 clear, so the double-size flag cannot be set here).
        let item_size = ((hdr >> 8) & 0xff) as usize;
        let count = ((hdr >> 24) & 0x0f) as usize;
        let item_end = i + 1 + item_size;
        if item_size < 3 || item_end > nwords {
            continue; // malformed block; keep scanning
        }
        // words[i+2] = unpartitioned flags; partition words follow.
        let mut j = i + 3;
        for p in 0..count {
            if j + 1 >= item_end {
                break; // truncated block
            }
            let permissions_locations = word(j);
            let flags = word(j + 1);
            j += 2;
            if flags & PART_FLAGS_HAS_ID != 0 {
                j += 2; // 64-bit id
            }
            let n_extra = ((flags & PART_FLAGS_NUM_EXTRA_FAMILIES_BITS)
                >> PART_FLAGS_NUM_EXTRA_FAMILIES_SHIFT) as usize;
            j += n_extra;
            if flags & PART_FLAGS_HAS_NAME != 0 && j < item_end {
                // First name byte = length; encoder pads (len + 1) to a
                // 4-byte multiple, so the words consumed are 1 + len/4.
                let name_len = (word(j) & 0xff) as usize;
                j += 1 + name_len / 4;
            }
            if p == partition {
                return Some(permissions_locations);
            }
        }
        // Block parsed to the end without the requested index.
        return None;
    }
    None
}

/// Resolve the data partition from a bootrom
/// `rom_get_partition_table_info` reply
/// (`PT_INFO_PARTITION_LOCATION_AND_FLAGS | PT_INFO_SINGLE_PARTITION |
/// (partition << 24)`): word 0 = the flags the ROM returned, word 1 = the
/// partition location word. Mirrors the C sequence
/// (`low_flash.c:214-229`): decode the sector bits, add the XIP base,
/// clamp to the board flash size, apply the 8 KB tail reservation.
/// Returns `None` when the info words do not decode to a valid region
/// (caller falls back).
pub fn resolve_from_info_words(info: &[u32]) -> Option<DataPartition> {
    if info.len() < 2 {
        return None;
    }
    let (start, end) = decode_partition_location(info[1])?;
    let part = validate(
        FLASH_XIP_BASE + start,
        (FLASH_XIP_BASE + end).min(FLASH_XIP_BASE + FLASH_BOARD_SIZE),
    )?;
    Some(reserved(part))
}

// ---------------------------------------------------------------------------
// Device FFI (arm only). Host builds never link the bootrom calls.
// ---------------------------------------------------------------------------
#[cfg(all(feature = "device", target_arch = "arm"))]
mod device {
    use super::*;

    /// Bootrom work area: 3264 bytes currently required
    /// (pico-sdk `pico/bootrom.h` `rom_load_partition_table` docs), kept
    /// 4-byte aligned and word-sized for `rom_get_partition_table_info`.
    const WORKAREA_WORDS: usize = 816; // 3264 bytes

    /// PT_INFO flags, pico-sdk `boot/bootrom_constants.h:226,231`.
    const PT_INFO_PARTITION_LOCATION_AND_FLAGS: u32 = 0x0010;
    const PT_INFO_SINGLE_PARTITION: u32 = 0x8000;
    /// Boot partition the C firmware uses for its data (`low_flash.c:206`).
    const BOOT_PARTITION: u32 = 1;

    const FUNC_ARM_SEC: u32 = 0x0004; // embassy-rp rom_data::rt_flags

    type LoadPartitionTableFn = unsafe extern "C" fn(*mut u8, u32, bool) -> i32;
    type GetPartitionTableInfoFn = unsafe extern "C" fn(*mut u32, u32, u32) -> i32;

    /// Resolve the C data region on hardware: bootrom ROM table first
    /// (exactly the C `low_flash.c:200-222` call sequence), `pt.json`
    /// constants as fallback. Never fails.
    pub fn data_partition() -> DataPartition {
        // Static work area, 4-byte aligned; safe single-threaded boot-time
        // use (the orchestrator calls this once, before app spawn).
        #[repr(align(4))]
        struct WorkArea([u32; WORKAREA_WORDS]);
        static mut WORKAREA: WorkArea = WorkArea([0; WORKAREA_WORDS]);

        unsafe {
            // SAFETY: WORKAREA is 'static, word-aligned, and only touched by
            // this function before the executor starts.
            let wa = (*core::ptr::addr_of_mut!(WORKAREA)).0.as_mut_ptr();

            let load: LoadPartitionTableFn =
                core::mem::transmute(embassy_rp::rom_data::rom_table_lookup(*b"LP", FUNC_ARM_SEC));
            if load(wa as *mut u8, (WORKAREA_WORDS * 4) as u32, false) != 0 {
                return super::fallback_partition_reserved();
            }

            let get_info: GetPartitionTableInfoFn = core::mem::transmute(
                embassy_rp::rom_data::rom_table_lookup(*b"GP", FUNC_ARM_SEC),
            );
            let mut info = [0u32; 8];
            let rc = get_info(
                info.as_mut_ptr(),
                info.len() as u32,
                PT_INFO_PARTITION_LOCATION_AND_FLAGS
                    | PT_INFO_SINGLE_PARTITION
                    | (BOOT_PARTITION << 24),
            );
            if rc <= 0 {
                return super::fallback_partition_reserved();
            }
            super::resolve_from_info_words(&info)
                .unwrap_or_else(super::fallback_partition_reserved)
        }
    }
}

#[cfg(all(feature = "device", target_arch = "arm"))]
pub use device::data_partition;

#[cfg(test)]
mod tests {
    use super::*;

    /// The PICOBIN partition-table block picotool embedded in the C
    /// firmware image (`pico-fido2/build_pico2/pico_fido2.bin` at
    /// 0x80974, 180 bytes) — the byte-exact encoding of
    /// `pico-keys-sdk/config/rp2350/pt.json`, bootrom-proven on the
    /// target board. uf2gen.py embeds these same bytes into the Rust
    /// image (S-413-2).
    const PT_BLOB: &[u8] = include_bytes!("../../firmware/picobin_pt.bin");

    #[test]
    fn parse_pt_blob_fido_data_partition() {
        // Partition 1 = "PicoKeys Data" per pt.json: 1032K..4096K.
        let word = partition_location_word(PT_BLOB, 1).expect("data partition in PT blob");
        let (start, end) = decode_partition_location(word).expect("location word decodes");
        assert_eq!((start, end), (0x102_000, 0x400_000));
    }

    #[test]
    fn parse_pt_blob_firmware_and_binding_partitions() {
        // Partition 0 = firmware 0..1024K, partition 2 = binding 1024K..1032K.
        let fw = decode_partition_location(partition_location_word(PT_BLOB, 0).unwrap()).unwrap();
        assert_eq!(fw, (0x000_000, 0x100_000));
        let bind = decode_partition_location(partition_location_word(PT_BLOB, 2).unwrap()).unwrap();
        assert_eq!(bind, (0x100_000, 0x102_000));
    }

    #[test]
    fn decode_partition_location_sector_bits() {
        // first = w & 0x1fff (LSB 0), last = (w >> 13) & 0x1fff (inclusive),
        // per low_flash.c:214-219 / picotool partition decode.
        // Sectors 258..1023 -> 0x102000..0x400000.
        let w = (258u32) | (1023u32 << 13);
        assert_eq!(decode_partition_location(w), Some((0x102_000, 0x400_000)));
        // last < first is malformed.
        assert_eq!(decode_partition_location((5u32) | (2u32 << 13)), None);
        // Single-sector partition.
        assert_eq!(decode_partition_location(7u32 | (7u32 << 13)), Some((0x7000, 0x8000)));
    }

    #[test]
    fn validate_region_rules() {
        // Inside the board window, >= 16 KiB: ok.
        assert!(validate(FLASH_XIP_BASE + 0x102_000, FLASH_XIP_BASE + 0x400_000).is_some());
        // Below XIP base / past the board window: reject.
        assert!(validate(0x0, 0x400_000).is_none());
        assert!(
            validate(FLASH_XIP_BASE + 0x102_000, FLASH_XIP_BASE + FLASH_BOARD_SIZE + 1).is_none()
        );
        // Degenerate / too small (< 16 KiB): reject.
        assert!(validate(FLASH_XIP_BASE + 0x102_000, FLASH_XIP_BASE + 0x102_000).is_none());
        assert!(
            validate(FLASH_XIP_BASE + 0x102_000, FLASH_XIP_BASE + 0x102_000 + 4_096).is_none()
        );
    }

    #[test]
    fn resolve_applies_xip_base_and_tail_reservation() {
        // The ROM info path: word 0 = returned PT_INFO flags, word 1 =
        // partition location (PT_INFO_PARTITION_LOCATION_AND_FLAGS |
        // PT_INFO_SINGLE_PARTITION | (1 << 24), low_flash.c:206-221).
        // C adds XIP_BASE (low_flash.c:228-229) and subtracts the 8 KB
        // tail reservation (low_flash.c:222): resolved end = 0x103FE000.
        let info = [0x0010u32, 258u32 | (1023u32 << 13)];
        let part = resolve_from_info_words(&info).expect("resolves");
        assert_eq!(part.start, 0x1010_2000);
        assert_eq!(part.end, 0x1000_0000 + 0x400_000 - TAIL_RESERVATION_BYTES);
    }

    #[test]
    fn resolve_rejects_garbage_info_words() {
        // Garbage info words (undecodable / out of flash / too small) are
        // rejected; the caller falls back to the pt.json constants.
        for info in [[0u32; 2], [0x0010, 5], [0x0010, 0xffff_ffff]] {
            assert_eq!(resolve_from_info_words(&info), None);
        }
        // The device-path fallback always yields the constants, reservation
        // applied.
        let part = fallback_partition_reserved();
        assert_eq!(part.start, FLASH_XIP_BASE + PT_JSON_DATA_START);
        assert_eq!(
            part.end,
            FLASH_XIP_BASE + PT_JSON_DATA_START + PT_JSON_DATA_SIZE - TAIL_RESERVATION_BYTES
        );
    }

    #[test]
    fn fallback_partition_matches_pt_json() {
        let p = fallback_partition();
        assert_eq!(p.start, 0x1010_2000);
        assert_eq!(p.end, 0x1040_0000);
        assert_eq!(p.end - p.start, 3064 * 1024);
    }
}
