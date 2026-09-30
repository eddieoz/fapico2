#![no_main]
//! US-1051 — `fapico2_platform::persist_sink::FlashSlotSink`, the two-slot
//! secure-partition programmer (the US-391 durability pair).
//!
//! Absence of panic proves nothing here. The sink has two failure modes that
//! are both silent:
//!
//! * **losing the wear optimisation.** `slot_matches` exists because NOR
//!   erase cycles are finite and persist is rare. A build that always
//!   erases still returns `true`, still leaves a valid image, still boots —
//!   it just spends two sector erasures per `WRITE_CONFIG`-class APDU and
//!   wears the token out. The regression is invisible to any return-value
//!   assertion; only the *flash operation log* sees it.
//! * **losing the durability pair.** `program` programs the primary first and
//!   returns `false` on the first failure. If that contract slipped, a power
//!   loss mid-program could leave *neither* slot bootable — which is a brick,
//!   and is exactly what `ImageSink::program`'s "on failure the previous good
//!   image must be left in place" clause forbids.
//!
//! So this target asserts three properties against a NOR model that records
//! every erase and every program:
//!
//! 1. **a matching slot is skipped** — re-programming the byte-identical
//!    image performs **zero** flash operations on either slot;
//! 2. **a read-failing slot is always reprogrammed** — an unreadable slot is
//!    the safe side, never the skip side;
//! 3. **a partial program leaves the previous good image bootable** — a
//!    program that dies mid-write returns `false` and the other slot still
//!    loads through `boot_decision_sealed`.
//!
//! # Red-under-mutation (the evidence that these assertions bite)
//!
//! Deleting the `slot_matches` skip (the pre-compare-then-write behaviour)
//! turns assertion 1 red; treating a read error as "matches" turns
//! assertion 2 red. See `.superpowers/sdd/report-P6.md`.

use std::vec::Vec;

use fapico2_platform::persist::{ImageSink, WindowedImageSource};
use fapico2_platform::persist_sink::{FlashSlotSink, SlotFlash};
use fapico2_platform::secure_store::{SecureStoreError, PARTITION_IMAGE_MAGIC};
use fapico2_platform::store_v3::{
    boot_decision_sealed, emulation_store_key, seal_image, SealedBootDecision,
};

/// Slot geometry. `SLOT_BYTES` is a rounded erase window, as on the device.
const SLOT_BYTES: usize = 1024;
const PRIMARY: u32 = 0x1_0000;
const SHADOW: u32 = 0x1_1000;

/// One flash operation, as the wear argument actually sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Erase { from: u32, to: u32 },
    Write { at: u32, len: usize },
}

/// A NOR flash model over one flat byte array, with an operation log and two
/// injectable faults:
///
/// * `fail_read_at` — every read window covering that address fails (an
///   unreadable slot: the safe side is to reprogram, never to skip);
/// * `torn_write_at` — a program that dies when it reaches that address,
///   having already programmed the bytes *before* it (a real page program
///   that loses power partway leaves the earlier bytes written).
///
/// Reads outside the modelled array return `0xFF` rather than panicking: a
/// read past the end of a NOR device is erased flash, not a fault, and
/// modelling it as a fault would report the model's limits as the sink's.
struct Nor {
    bytes: Vec<u8>,
    ops: Vec<Op>,
    fail_read_at: Option<u32>,
    torn_write_at: Option<u32>,
}

impl Nor {
    fn new() -> Self {
        let size = (SHADOW as usize) + SLOT_BYTES;
        Self {
            bytes: vec![0xFF; size],
            ops: Vec::new(),
            fail_read_at: None,
            torn_write_at: None,
        }
    }

    fn slot(&self, base: u32) -> Vec<u8> {
        let o = base as usize;
        self.bytes[o..o + SLOT_BYTES].to_vec()
    }
}

impl SlotFlash for Nor {
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), SecureStoreError> {
        let end = addr as usize + buf.len();
        if let Some(fail) = self.fail_read_at {
            if (addr..end as u32).contains(&fail) {
                return Err(SecureStoreError::Flash);
            }
        }
        for (i, b) in buf.iter_mut().enumerate() {
            let a = addr as usize + i;
            // Erased flash past the modelled array, not a fault.
            *b = self.bytes.get(a).copied().unwrap_or(0xFF);
        }
        Ok(())
    }

    fn erase(&mut self, from: u32, to: u32) -> Result<(), SecureStoreError> {
        self.ops.push(Op::Erase { from, to });
        for a in from as usize..(to as usize).min(self.bytes.len()) {
            self.bytes[a] = 0xFF;
        }
        Ok(())
    }

    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), SecureStoreError> {
        let end = addr as usize + data.len();
        if let Some(torn) = self.torn_write_at {
            if (addr..end as u32).contains(&torn) {
                // Everything strictly before the torn byte lands; the write
                // then fails and the sink abandons the slot.
                let cut = (torn as usize).saturating_sub(addr as usize);
                for i in 0..cut {
                    let a = addr as usize + i;
                    if let Some(slot) = self.bytes.get_mut(a) {
                        // NOR: programming can only clear bits.
                        *slot &= data[i];
                    }
                }
                self.ops.push(Op::Write {
                    at: addr,
                    len: cut,
                });
                return Err(SecureStoreError::Flash);
            }
        }
        self.ops.push(Op::Write {
            at: addr,
            len: data.len(),
        });
        for (i, b) in data.iter().enumerate() {
            let a = addr as usize + i;
            if let Some(slot) = self.bytes.get_mut(a) {
                *slot &= *b; // NOR: only clears bits
            }
        }
        Ok(())
    }
}

/// `&mut` adapter: `FlashSlotSink` owns its driver, so the harness lends the
/// model in and reads the log back off the same object afterwards.
struct Borrowed<'a>(&'a mut Nor);

impl SlotFlash for Borrowed<'_> {
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), SecureStoreError> {
        self.0.read(addr, buf)
    }
    fn erase(&mut self, from: u32, to: u32) -> Result<(), SecureStoreError> {
        self.0.erase(from, to)
    }
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), SecureStoreError> {
        self.0.write(addr, data)
    }
}

/// A `WindowedImageSource` over a byte slice — the shape the persist gate
/// hands the sink on the device (256-byte stack windows, no whole image).
struct Image<'a>(&'a [u8]);

impl WindowedImageSource for Image<'_> {
    fn image_len(&self) -> usize {
        self.0.len()
    }
    fn image_window(&self, off: usize, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.0.len().saturating_sub(off));
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        n
    }
}

/// CRC-32 mirrored from `secure_store::crc32` (`pub(crate)` there), used only
/// to build the logical image `seal_image` takes. The result is cross-checked
/// against the platform's own `seal_image`, so a drift here fails loudly.
fn crc32(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A well-formed sealed (format-v3) partition image over attacker-chosen
/// bytes plus a tag that keeps two images distinct. Sealing through the real
/// `seal_image` is what makes the durability assertions below meaningful: a
/// "previous good image" the real boot loader would reject would prove
/// nothing.
fn sealed_image(seed: &[u8], tag: u8) -> Vec<u8> {
    let mut value = seed.to_vec();
    value.push(tag);
    let mut logical = Vec::new();
    logical.extend_from_slice(&PARTITION_IMAGE_MAGIC.to_le_bytes());
    logical.extend_from_slice(&1u32.to_le_bytes());
    logical.extend_from_slice(&2u32.to_le_bytes());
    logical.extend_from_slice(b"ks");
    logical.extend_from_slice(&(value.len() as u32).to_le_bytes());
    logical.extend_from_slice(&value);
    let crc = crc32(&logical);
    logical.extend_from_slice(&crc.to_le_bytes());
    seal_image(&logical, &emulation_store_key()).expect("a valid logical image seals")
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let key = emulation_store_key();
    // Bounded: the target is about the sink's decisions, not about image
    // size, and this runs in a 15-minute CI smoke.
    let seed: Vec<u8> = data.iter().copied().take(96).collect();
    let image_a = sealed_image(&seed, 0x00);
    let image_b = sealed_image(&seed, 0x01);
    assert_ne!(image_a, image_b, "the two programmed images must differ");
    assert!(image_a.len() < SLOT_BYTES && image_b.len() < SLOT_BYTES);

    let program = |flash: &mut Nor, img: &[u8]| -> bool {
        let mut sink = FlashSlotSink::new(Borrowed(flash), PRIMARY, SHADOW, SLOT_BYTES);
        sink.program(&mut Image(img))
    };

    // ---- 1. a matching slot is skipped (the wear optimisation) -----------
    let mut nor = Nor::new();
    assert!(program(&mut nor, &image_a), "the first program must succeed");
    let after_first = nor.ops.len();
    assert!(after_first > 0, "the first program must have erased and written");
    assert!(program(&mut nor, &image_a), "re-programming the same image must succeed");
    assert_eq!(
        nor.ops.len(),
        after_first,
        "a byte-identical image was reprogrammed: the compare-then-write skip is gone \
         (flash operations {:?} -> {:?})",
        &nor.ops[..after_first],
        &nor.ops[after_first..],
    );
    // Both slots still hold exactly the programmed image.
    assert_eq!(nor.slot(PRIMARY)[..image_a.len()], image_a[..]);
    assert_eq!(nor.slot(SHADOW)[..image_a.len()], image_a[..]);

    // A *different* image must NOT be skipped — the complement of the
    // assertion above, so a mutation that skips unconditionally also fails.
    assert!(program(&mut nor, &image_b), "the changed image must program");
    assert!(nor.ops.len() > after_first, "a changed image was skipped");
    assert!(program(&mut nor, &image_b), "the settled image must re-succeed");
    let settled = nor.ops.len();
    assert!(program(&mut nor, &image_b));
    assert_eq!(nor.ops.len(), settled, "the settled image was reprogrammed");

    // ---- 2. a read-failing slot is always reprogrammed ---------------------
    let mut nor = Nor::new();
    assert!(program(&mut nor, &image_a));
    let quiet = nor.ops.len();
    nor.fail_read_at = Some(SHADOW);
    assert!(program(&mut nor, &image_a), "a read-failing slot must still succeed");
    assert!(
        nor.ops.iter().skip(quiet).any(|op| *op == Op::Erase {
            from: SHADOW,
            to: SHADOW + SLOT_BYTES as u32,
        }),
        "the unreadable shadow slot was skipped instead of reprogrammed",
    );
    // The primary was readable and unchanged, so it was skipped — the sink
    // must not have spent an erase there either.
    assert!(
        !nor.ops[quiet..].iter().any(|op| *op == Op::Erase {
            from: PRIMARY,
            to: PRIMARY + SLOT_BYTES as u32,
        }),
        "the readable primary was erased even though it already matched",
    );
    assert_eq!(nor.slot(SHADOW)[..image_a.len()], image_a[..]);

    // ---- 3. a partial program leaves the previous good image bootable -----
    // The tear point must land inside the window the sink actually writes,
    // which is the image's own length.
    let tear = |base: u32, img: &[u8]| base + (img.len() / 2).max(1) as u32;

    // (a) torn on the SHADOW: the primary is programmed first and survives.
    let mut nor = Nor::new();
    assert!(program(&mut nor, &image_a));
    nor.torn_write_at = Some(tear(SHADOW, &image_b));
    assert!(
        !program(&mut nor, &image_b),
        "a torn program must report failure, not success",
    );
    nor.torn_write_at = None;
    let primary = nor.slot(PRIMARY);
    let shadow = nor.slot(SHADOW);
    assert_eq!(
        boot_decision_sealed(&primary, &shadow, &key),
        SealedBootDecision::LoadPrimary,
        "a torn shadow write destroyed the only bootable slot",
    );

    // (b) torn on the PRIMARY: the shadow still holds the previous good
    // image, which is the whole point of the two-slot discipline.
    let mut nor = Nor::new();
    assert!(program(&mut nor, &image_a));
    nor.torn_write_at = Some(tear(PRIMARY, &image_b));
    assert!(
        !program(&mut nor, &image_b),
        "a torn program must report failure, not success",
    );
    nor.torn_write_at = None;
    let primary = nor.slot(PRIMARY);
    let shadow = nor.slot(SHADOW);
    assert_eq!(
        boot_decision_sealed(&primary, &shadow, &key),
        SealedBootDecision::LoadShadow,
        "a torn primary write left neither slot bootable",
    );
    assert_eq!(shadow[..image_a.len()], image_a[..], "the shadow lost the previous good image");
});
