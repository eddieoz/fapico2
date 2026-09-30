//! Firmware-manifest boot admission (US-919, EPIC `security-hardening`).
//!
//! Root cause (finding **R9** / R6): BOOTSEL accepts an unsigned reflash, so
//! an implanted firmware image boots and the secure store loads from it —
//! nothing detects the implant. US-919 closes the loop at boot: the running
//! firmware's flash-image manifest hash is compared against the
//! last-known-good hash persisted at the previous successful boot
//! ([`SLOT_FW_MANIFEST`]); on a mismatch (a foreign image) the secure
//! partition slots are wiped **before** any app loads — the deliberate
//! data-loss-over-implant policy. The device-side wiring (region bounds from
//! the linker symbols, XIP streaming reads, the wipe execution and its
//! compile-time dev knob) lives in `firmware/src/boot.rs` (`ensure_fw_manifest`);
//! this module holds the pure, host-testable halves: the decision function
//! ([`foreign_image_decision`]) and the streaming hash ([`hash_region`]).
//!
//! # Storage deviation (documented, story-wise)
//!
//! The story's literal wording ("last-known-good hash persisted at every
//! successful boot" in the "store header") is realized as a **dedicated
//! secure-store slot** ([`SLOT_FW_MANIFEST`], 32-byte SHA-256), exactly like
//! US-918's `boot.entropy.v1` (commit `757dab3`): the record rides the
//! sealed format-v3 store image, so it is authenticated by the v3 AEAD tag —
//! an attacker re-flashing the plain slot region cannot forge it, and the
//! store-image format never churns. Same property the header field wanted,
//! no format cost.

use crate::secure_store::{ImageReader, IMAGE_WINDOW};

/// US-919: the last-known-good firmware-manifest hash — a dedicated
/// secure-store slot (32-byte SHA-256, [`fw_manifest::hash_region`])
/// following the [`crate::migration::SLOT_BOOT_ENTROPY`] pattern
/// (`boot.entropy.v1`, US-918): it rides the v3-AEAD-sealed store image, so
/// it is authenticated (a forged slot fails the unseal tag → refuse) and is
/// written through the same compare-then-program persist gate as every
/// other slot at the successful boot it records. Deviation from the story's
/// literal "store header" wording: same property (a last-known-good value
/// an implanted image cannot forge), no v3-format churn; see the module
/// docs. A wrong-length record is treated as absent (pre-policy).
pub const SLOT_FW_MANIFEST: &[u8] = b"boot.fwmanifest.v1";

/// US-919: the emulation's stand-in "running image" hash (the host has no
/// XIP flash region to walk). A fixed constant so e2e runs are
/// deterministic; `FAPICO2_FW_HASH` (64 hex chars) overrides it to steer
/// the emulation into either decision arm.
pub const EMUL_FAKE_FW_MANIFEST: [u8; 32] = [
    0x22, 0xc1, 0xf4, 0x89, 0x99, 0x79, 0xd2, 0xc5, 0xd7, 0x4a, 0x35, 0xd4,
    0xb9, 0x0d, 0x63, 0x56, 0xb6, 0x7d, 0x93, 0xaa, 0x30, 0x1a, 0xa7, 0x14,
    0x23, 0xa5, 0xa2, 0x83, 0xef, 0x6b, 0x07, 0xae,
];

/// US-919 boot admission outcome (pure): what the boot path must do with
/// the secure partition before any app loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignImageDecision {
    /// The manifest slot is absent (first boot / pre-policy device — stamp
    /// the current hash and continue) or it equals the running image's
    /// hash (the image is the last-known-good one). Load the store as-is.
    Load,
    /// The stored hash differs from the running image's hash: the running
    /// firmware is foreign (an implanted image, R9). Boot must wipe every
    /// secure-partition slot BEFORE loading (data-loss-over-implant,
    /// deliberate and documented) and log the event. After the wipe the
    /// boot continues with a fresh store and never re-compares this boot.
    WipeAndFresh,
}

/// US-919 (pure, host-testable): decide the boot admission from the stored
/// last-known-good manifest hash and the running image's manifest hash.
///
/// * `None` (slot absent: first boot / pre-policy device) →
///   [`ForeignImageDecision::Load`] — the caller stamps the current hash
///   (the write rides the boot persist gate) and loads.
/// * `Some(h) == current` → [`ForeignImageDecision::Load`].
/// * `Some(h) != current` → [`ForeignImageDecision::WipeAndFresh`] (R9).
///
/// The equality compare is constant-time ([`subtle::ConstantTimeEq`] — the
/// same helper the platform already uses in [`crate::migration`]; the
/// `ct_eq` in `apps/fido/src/crypto.rs` is app-crate-local and cannot be
/// reached from here). A manifest hash comparison is not expected to be
/// secret-dependent, but the policy branch (wipe vs load) must not be
/// microarchitecturally steerable by attacker-controlled bytes either, so
/// the fold is kept constant-time on principle.
pub fn foreign_image_decision(
    stored: Option<[u8; 32]>,
    current: [u8; 32],
) -> ForeignImageDecision {
    match stored {
        None => ForeignImageDecision::Load,
        Some(h) => {
            use subtle::ConstantTimeEq;
            // `ct_eq` folds every byte difference into one flag; the
            // compiler cannot short-circuit on an early divergent byte.
            if bool::from(h.ct_eq(&current)) {
                ForeignImageDecision::Load
            } else {
                ForeignImageDecision::WipeAndFresh
            }
        }
    }
}

/// US-919: SHA-256 over the running firmware's occupied flash region,
/// streamed through `reader` in [`IMAGE_WINDOW`]-sized windows (the
/// stack-friendly windowed-read discipline — no whole-image buffer). The
/// reader's short-fill-at-end semantics close the stream: the hash covers
/// exactly the first `region_len` bytes the device's region-bound
/// computation selected (see `firmware/src/boot.rs` for the linker-symbol
/// bounds and why the secure-partition origin caps them).
pub fn hash_region(reader: &mut dyn ImageReader, region_len: usize) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    let mut win = [0u8; IMAGE_WINDOW];
    let mut off = 0usize;
    while off < region_len {
        let n = reader.read_window(off, &mut win);
        if n == 0 {
            // The medium ended early (a misbounded region on a non-device
            // build would otherwise hash a zero-window forever).
            break;
        }
        hasher.update(&win[..n]);
        off += n;
    }
    hasher.finalize().into()
}

/// US-919: the emulation's 64-hex-char → 32-byte manifest parser
/// (`FAPICO2_FW_HASH`), so a malformed value fails loudly at boot instead
/// of silently steering the wipe policy.
#[cfg(not(target_arch = "arm"))]
pub fn parse_manifest_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = s[2 * i..2 * i + 2].chars().next()?;
        let lo = s[2 * i + 1..].chars().next()?;
        *b = (hi.to_digit(16)? as u8) << 4 | lo.to_digit(16)? as u8;
    }
    Some(out)
}

// US-930: the decision trace's host-testable seam. The on-device decision
// path (`boot::ensure_fw_manifest`) is device-only (XIP flash + the secure
// store), so the D7 replay is proven by the trace itself (the dbg-log ring,
// US-922 drain); this module's pure halves are what the trace reports, so
// their arms are pinned here — the trace's E_FWDECIDE `a` field encodes
// exactly these outcomes (0 = Load, 1 = WipeAndFresh).
#[cfg(all(test, not(target_arch = "arm")))]
mod tests {
    use super::*;

    const H_A: [u8; 32] = [1; 32];
    const H_B: [u8; 32] = [2; 32];

    #[test]
    fn absent_slot_loads_and_stamps() {
        // First boot / pre-policy: Load (the caller stamps, E_FWSTAMP).
        assert_eq!(
            foreign_image_decision(None, H_A),
            ForeignImageDecision::Load
        );
    }

    #[test]
    fn equal_hash_loads() {
        assert_eq!(
            foreign_image_decision(Some(H_A), H_A),
            ForeignImageDecision::Load
        );
    }

    #[test]
    fn mismatched_hash_wipes() {
        assert_eq!(
            foreign_image_decision(Some(H_B), H_A),
            ForeignImageDecision::WipeAndFresh
        );
    }

    #[test]
    fn manifest_hex_roundtrip_rejects_malformed() {
        let hex = "ab".repeat(32);
        assert_eq!(parse_manifest_hex(&hex), Some([0xab; 32]));
        assert_eq!(parse_manifest_hex(&"ab".repeat(31)), None);
        assert_eq!(parse_manifest_hex(&"zz".repeat(32)), None);
    }
}
