//! Stable USB identity (US-103, PICOForge-COMPAT): the chip-id derivation
//! behind the device's `iSerialNumber` string descriptor.
//!
//! # Why this module is separate from [`crate::usb`]
//!
//! `usb.rs` is gated `#[cfg(all(feature = "device", target_arch = "arm"))]`
//! (every embassy dependency in it is arm-only), so a host `cargo test` never
//! compiles it and the derivation could not be tested. This module is ungated
//! and holds *all* of the logic; `usb.rs` only calls it — the same extraction
//! pattern as [`crate::hid_control`] (US-391 E7).
//!
//! It also owns the **single source of truth for the chip-id derivation**.
//! `fapico2_mgmt::serial_from_chipid` (R12, `TAG_SERIAL` 0x02) delegates to
//! [`serial_hash4`] here rather than hashing the chipid a second time, so the
//! management applet's serial and the USB serial cannot drift apart. The two
//! have *different encodings* on purpose — the applet answers with a 4-byte
//! TLV value, USB needs an 8-character ASCII string — but they are the same
//! hash of the same input.
//!
//! # The digit rule, and its collisions
//!
//! [`serial_digits`] renders the 32-bit hash prefix into 8 decimal digits by
//! **scaled truncation**:
//!
//! ```text
//! n    = u32::from_be_bytes(SHA-256(chipid.to_be_bytes())[..4])   // 0 ..= 2^32-1
//! v    = (n * 10^8) >> 32                                        // 0 ..= 99_999_999
//! ascii(v)                                                       // 8 chars, '0'-padded
//! ```
//!
//! Properties, stated honestly:
//!
//! * **Deterministic and float-free.** Integer multiply and shift only, so
//!   the device (`thumbv8m`) and the host produce bit-identical results, and
//!   no rounding-mode or libc difference can move the digits.
//! * **Fixed width.** `v <= 99_999_999` always, so 8 digits exactly; there is
//!   no 9th-digit overflow and no `None` for a "0" serial.
//! * **NOT injective.** 2^32 inputs map onto 10^8 outputs — about 43 input
//!   values per output on average. Two devices *can* share a serial, and under
//!   the birthday bound a fleet reaches a ~50% chance of one collision at
//!   roughly `sqrt(2 * 10^8 * ln 2) ≈ 1.2e4` devices. The mapping is
//!   deliberately lossy in the low bit-density range (the hash is uniform, so
//!   this is uniform truncation, not a hotspot).
//!
//!   That is acceptable *for this use*: the serial's job is to let a host tell
//!   *its own* token apart from other tokens, and the flash-UID serial the C
//!   firmware used is worse (identical on every unit). It is **not** a
//!   security identifier and must not be used as one — the device-bound keys
//!   ([`crate::ckey::derive_kbase`], [`crate::store_v3::derive_store_key`])
//!   are. If a fleet ever needs a globally unique identity, widen the input
//!   (8 hash bytes → 8 digits is injective to 2^64→10^8, still lossy but
//!   4.3e11 times finer), not the collision tolerance.
//!
//! # `&'static str` without an allocator
//!
//! [`SerialBuf`] is the answer to the one genuinely awkward part of US-103:
//! `embassy_usb::Config::serial_number` is `Option<&'a str>`, but the value is
//! only known at runtime (it is a SHA-256 of the OTP chipid) and the device
//! profile is `no_std` with no heap — so there is no `String` to move and no
//! `Box::leak` to reach for (the device profile forbids it, and it would grow
//! unboundedly if the derivation were ever re-run).
//!
//! Instead the crate keeps one **write-once, `static` 8-byte buffer**
//! ([`SerialBuf`]) and lends it out with a `'static` borrow. That is sound
//! because:
//!
//! * the buffer is filled exactly once, from `Usb::new`, before the USB
//!   device is built and therefore before the host can enumerate it —
//!   [`SerialBuf::write`] *panics* on a second call rather than handing out a
//!   second `&str` that would alias-and-mutate the first;
//! * after that write the buffer is never touched again, so the `&'static str`
//!   embassy-usb holds (and copies into the configuration descriptor during
//!   `Builder::build`) is immutable for the rest of the process;
//! * 8 bytes in `.bss`, no allocation, no leak, nothing to reclaim.
//!
//! This mirrors the crate's existing `HID_CONTROL_HANDLER` write-once
//! `MaybeUninit` slot in `usb.rs` — same reasoning, same hazard, and that one
//! has shipped on hardware.
//!
//! Coverage: the derivation and the digit rule are covered by the integration
//! test `tests/usb.rs`; the write-once `SerialBuf` contract is covered by this
//! module's inline `#[cfg(test)]` unit tests (below), because it needs no
//! cross-crate surface. The arm-gated `usb.rs` wiring is **not** covered by
//! any host test — that file is never compiled off-device — so it rests on the
//! `thumbv8m` build plus review of the single assignment line.

use crate::ckey::serial_hash;

/// Number of ASCII characters in the rendered USB serial.
pub const SERIAL_DIGITS: usize = 8;

/// Upper bound (exclusive) of the rendered serial's numeric value — 10^8, the
/// size of the 8-decimal-digit space.
pub const SERIAL_MODULUS: u64 = 100_000_000;

/// Fixed emulation chipid — host/emulation builds have no OTP row, so a
/// fixed stand-in (ASCII `"fapico2"` + `0x00`) keeps the derived serial
/// deterministic, matching the fixed emulation store key
/// ([`crate::store_v3::emulation_store_key`]) and `EMULATION_CHIPID` in
/// `fapico2_mgmt`. Both identities — USB `iSerialNumber` and management
/// `TAG_SERIAL` — are derived from this one value, so they agree there too.
///
/// **Who uses it, precisely.** The emulation transport (`emul_main.rs`) is
/// TCP-based and never constructs a USB device, so it has *no* `Usb::new` call
/// and no use for this constant on the USB side; it matters there only because
/// `fapico2_mgmt` derives the emulated `TAG_SERIAL` from the same value. Every
/// binary that *does* call `Usb::new` — `fapico2-firmware`, `bridge`,
/// `bringup`, `hwtest` — runs on real silicon with a real OTP row and reads
/// the true chipid instead. Do not pass this to `Usb::new` on hardware: a board
/// reporting the stand-in would advertise the same fleet-wide serial as every
/// other board, which is the fingerprinting bug US-103 exists to remove.
pub const EMULATION_CHIPID: u64 = 0x6661_7069_636F_3200;

/// `SHA-256(chipid big-endian)[..4]` — the codebase's device-bound derivation
/// (`ckey::serial_hash` is SHA-256 over the flash UID; this feeds it the OTP
/// chipid), truncated to the 4 bytes the management `TAG_SERIAL` TLV carries.
///
/// **Single source of truth.** `fapico2_mgmt::serial_from_chipid` calls this,
/// so the applet's serial and the USB serial are the same hash by
/// construction.
pub fn serial_hash4(chipid: u64) -> [u8; 4] {
    let h = serial_hash(&chipid.to_be_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// The scaled-truncation step: the 32-bit hash prefix mapped onto
/// `0 ..= 99_999_999` (see the module docs for the rule and its collision
/// behaviour). Exposed so the mapping can be asserted directly rather than
/// re-derived by the test.
pub fn serial_value(chipid: u64) -> u64 {
    let n = u32::from_be_bytes(serial_hash4(chipid)) as u64;
    // (n * 10^8) fits a u64 with room to spare: max 2^32 * 10^8 ≈ 4.3e17
    // against u64::MAX ≈ 1.8e19. The shift is exact integer arithmetic.
    (n * SERIAL_MODULUS) >> 32
}

/// Render `value` as exactly 8 zero-padded ASCII decimal digits.
///
/// Takes any `u64` but saturates at [`SERIAL_MODULUS`]; callers in this module
/// never exceed it by construction.
pub fn decimal8(value: u64) -> [u8; SERIAL_DIGITS] {
    let v = if value >= SERIAL_MODULUS {
        SERIAL_MODULUS - 1
    } else {
        value
    };
    let mut out = [0u8; SERIAL_DIGITS];
    let mut n = v;
    // Least-significant digit first, then reverse in place — a plain
    // divide-by-ten loop, no `format!`, no float, no allocator, so it is
    // identical on `thumbv8m` and the host.
    for slot in out.iter_mut().rev() {
        *slot = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out
}

/// The device's USB serial: [`serial_hash4`]'s hash prefix rendered as 8
/// decimal digits. Stable across reboots (pure function of the OTP chipid) and
/// distinct per device up to the documented collision budget.
pub fn serial_digits(chipid: u64) -> [u8; SERIAL_DIGITS] {
    decimal8(serial_value(chipid))
}

/// A write-once, fixed-capacity holder for the 8-digit USB serial — the
/// `'static str` bridge on a no-allocator device (see the module docs).
///
/// Lives in a `static` in the arm-gated `usb.rs`; ungated and unit-testable
/// here.
#[derive(Clone, Copy)]
pub struct SerialBuf {
    bytes: [u8; SERIAL_DIGITS],
    written: bool,
}

// No `Default`: `Default::default()` is not a `const fn`, so it cannot
// initialise the `static mut` this type exists to inhabit. A `Default` impl
// would be both dead code (nothing wants it — the only caller wants `new`,
// which *is* const) and a trap, because it looks like a valid way to declare
// the static and silently isn't one.
#[allow(clippy::new_without_default)]
impl SerialBuf {
    /// An empty buffer. `const` so the caller's `static mut` needs no runtime
    /// initialiser and lands in `.bss`.
    pub const fn new() -> Self {
        Self {
            bytes: [0; SERIAL_DIGITS],
            written: false,
        }
    }

    /// Derive and store the serial for `chipid`, if not already written.
    ///
    /// Returns `false` on a second call rather than panicking, so the
    /// write-once contract is testable on a `panic = abort` profile (the
    /// device release profile) as well as under a test harness. The `&'static
    /// str` already lent out by [`Self::as_str`] must never observe a
    /// mutation, so the write is *refused*, not applied.
    pub fn try_write(&mut self, chipid: u64) -> bool {
        if self.written {
            return false;
        }
        self.bytes = serial_digits(chipid);
        self.written = true;
        true
    }

    /// Derive and store the serial for `chipid`. **Write-once**: a second call
    /// panics, because the `&'static str` already lent out by [`Self::as_str`]
    /// must never observe a mutation.
    ///
    /// # Panics
    ///
    /// If called more than once. `Usb::new` is the sole caller and runs once
    /// per boot.
    pub fn write(&mut self, chipid: u64) {
        assert!(
            self.try_write(chipid),
            "SerialBuf is write-once; Usb::new ran twice"
        );
    }

    /// The serial as a string slice. NUL-filled until [`Self::write`] has
    /// run; that state is never observable on the bus, because the write
    /// happens before the USB device is built.
    pub fn as_str(&self) -> &str {
        // The bytes are ASCII digits by construction (see `decimal8`), so this
        // cannot fail; the `unwrap` costs nothing on device.
        core::str::from_utf8(&self.bytes).expect("SerialBuf holds ASCII digits")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_buf_is_write_once() {
        let mut b = SerialBuf::new();
        // Before the first write the buffer is NUL-filled, not "00000000" —
        // a pre-enumeration zero-length-ish placeholder. This state is never
        // observable on the bus: `Usb::new` writes before building the device.
        assert_eq!(b.as_str().as_bytes(), [0u8; SERIAL_DIGITS]);
        assert!(b.try_write(0x0102_0304_0506_0708));
        assert_eq!(b.as_str().as_bytes(), serial_digits(0x0102_0304_0506_0708));

        // The write-once guard is the soundness hinge for the `&'static str`
        // loan: the second write must be *refused*, leaving the already-lent
        // value untouched. (Asserted through `try_write` rather than by
        // catching `write`'s panic, which a `panic = abort` profile cannot
        // catch.)
        assert!(!b.try_write(0xDEAD_BEEF_CAFE_0001), "second write must fail");
        assert_eq!(
            b.as_str().as_bytes(),
            serial_digits(0x0102_0304_0506_0708),
            "a refused write must not mutate the lent-out serial"
        );
    }

    #[test]
    fn serial_buf_loan_survives_and_matches_platform_width() {
        let mut b = SerialBuf::new();
        b.write(0xDEAD_BEEF_CAFE_0001);
        let s: &str = b.as_str();
        assert_eq!(s.len(), SERIAL_DIGITS);
        assert!(s.bytes().all(|c| c.is_ascii_digit()));
    }
}
