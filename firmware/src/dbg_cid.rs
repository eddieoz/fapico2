//! US-922: per-boot debug-drain channel selection (host-testable core).
//!
//! The `dbg-log` diagnostic ring (`main.rs`'s `dbg` module, device bin only)
//! is drained over a CTAP-HID vendor command accepted on a *per-boot random*
//! channel instead of the historical fixed one, so the channel is not
//! derivable from anything the host sees over USB. This module is the pure
//! selection logic the device bin seeds from the hardware TRNG (US-380) at
//! boot; the device prints the value only to the SWD/RTT console (`defmt`),
//! never over USB.
//!
//! Entropy: the channel uses **all four bytes** of the TRNG draw (32 bits of
//! per-boot entropy). An earlier design burned one byte on a fixed `0xDB`
//! prefix, leaving only 24 bits — brute-forceable by a hostile host
//! enumerating CIDs against a response oracle in minutes-to-hours. There is
//! no fixed byte any more: every byte position carries TRNG entropy.

/// CTAP-HID channels the HID/CTAPHID layer treats specially
/// (`firmware/src/ctap_hid.rs`): the broadcast channel (only INIT is
/// accepted from it) and the reserved channel (nothing is accepted from
/// it). The drain channel must never collide with either — the same two
/// rejections [`CidAllocator`](crate::ctap_hid::CidAllocator) applies — so
/// broadcasting at the drain or hitting the reserved slot is impossible.
pub const HID_CID_BROADCAST: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
pub const HID_CID_RESERVED: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Pure acceptance test over one 4-byte TRNG draw: the channel is the draw
/// itself (full 32-bit entropy), unless the draw is one of the degenerate
/// values the CTAP-HID layer treats specially — the broadcast channel
/// (`0xFFFFFFFF`, an attacker cannot target the drain by broadcasting) and
/// the reserved / all-zero channel (`0x00000000`, the device bin's "channel
/// not initialized" sentinel stays unrepresentable, so the drain opens only
/// after the TRNG ran). Degenerate draws are handled by *redrawing* (see
/// [`dbg_cid_new`]), never by overwriting a byte — a fixed byte would
/// collapse the entropy budget again.
///
/// The channel is a pure function of the draw and nothing else: no USB
/// enumeration data (serial number, MAC, boot count) feeds it.
pub fn dbg_cid_checked(draw: [u8; 4]) -> Option<[u8; 4]> {
    if draw == HID_CID_BROADCAST || draw == HID_CID_RESERVED {
        None
    } else {
        Some(draw)
    }
}

/// Draw until the draw is non-degenerate ([`dbg_cid_checked`]), and return
/// the accepted channel. `draw` is the randomness boundary: on device this
/// closes over the hardware TRNG handle (see `main.rs`, US-380 — the sole
/// randomness source); in tests any deterministic sequence can be
/// injected.
pub fn dbg_cid_new(mut draw: impl FnMut() -> [u8; 4]) -> [u8; 4] {
    loop {
        if let Some(cid) = dbg_cid_checked(draw()) {
            return cid;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The channel is the raw draw (deterministic mapping, full 32-bit
    /// entropy — no prefix byte anywhere) and the two degenerate values the
    /// CTAP-HID layer treats specially are rejected for redrawing.
    #[test]
    fn deterministic_full_entropy_mapping() {
        assert_eq!(
            dbg_cid_checked([0x12, 0x34, 0x56, 0x78]),
            Some([0x12, 0x34, 0x56, 0x78])
        );
        // Neither the historical `0xDB` prefix nor any other byte is fixed:
        // byte 0 carries entropy like every other position.
        assert_eq!(dbg_cid_checked([0xDB, 0x12, 0x34, 0x56]), Some([0xDB, 0x12, 0x34, 0x56]));
        assert_eq!(dbg_cid_checked(HID_CID_BROADCAST), None);
        assert_eq!(dbg_cid_checked(HID_CID_RESERVED), None);
    }

    /// Degenerate TRNG draws (all-zero, broadcast) are REDRAWN, not patched
    /// with a fixed prefix byte: the loop keeps drawing until a non-degenerate
    /// channel appears, preserving the full 32-bit entropy budget.
    #[test]
    fn degenerate_draws_are_redrawn() {
        let seq: [[u8; 4]; 3] = [
            [0x00, 0x00, 0x00, 0x00], // reserved / sentinel — redraw
            [0xFF, 0xFF, 0xFF, 0xFF], // broadcast — redraw
            [0x00, 0xFF, 0x00, 0xFF], // a degenerate-looking *hybrid* is accepted
        ];
        let mut i = 0usize;
        let cid = dbg_cid_new(|| {
            let d = seq[i];
            i += 1;
            d
        });
        assert_eq!(i, 3);
        assert_eq!(cid, [0x00, 0xFF, 0x00, 0xFF]);
        assert_eq!(dbg_cid_checked(cid), Some(cid));
    }

    /// Every drawn channel is non-degenerate: the selection can never emit
    /// the broadcast or reserved channel, so the host-side enumeration
    /// space excludes exactly the two special CIDs (US-922).
    #[test]
    fn trng_draws_never_degenerate_and_differ_per_boot() {
        let a = dbg_cid_new(fapico2_platform::trng::random_bytes::<4>);
        let b = dbg_cid_new(fapico2_platform::trng::random_bytes::<4>);
        assert_ne!(a, HID_CID_BROADCAST);
        assert_ne!(a, HID_CID_RESERVED);
        assert_ne!(b, HID_CID_BROADCAST);
        assert_ne!(b, HID_CID_RESERVED);
        // Two boots derive their channels from independent entropy draws
        // (`fapico2_platform::trng` — the sole randomness source boundary;
        // on the host this is OS entropy, the documented stand-in). With the
        // full 32 bits in play, collision odds are 2^-32 per pair — a
        // per-boot diagnostic channel, so cross-boot collisions are
        // harmless by construction anyway.
        assert_ne!(a, b);
    }

    /// No fixed prefix byte across many draws (entropy spread): with the
    /// historical design byte 0 was constant (`0xDB`); now every byte
    /// position moves. 64 draws over byte 0 must yield a healthy number of
    /// distinct values (uniform bytes: expected ≈ 56 distinct, failure
    /// bound far below any realistic fluctuation).
    #[test]
    fn no_fixed_prefix_byte_across_draws() {
        let mut seen = [false; 256];
        for _ in 0..64 {
            let cid = dbg_cid_new(fapico2_platform::trng::random_bytes::<4>);
            seen[cid[0] as usize] = true;
        }
        let distinct = seen.iter().filter(|s| **s).count();
        assert!(distinct >= 16, "byte 0 not spread: {distinct} distinct");
    }
}
