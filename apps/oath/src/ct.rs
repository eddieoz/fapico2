//! Constant-time comparison, shared by every applet in this crate that
//! authenticates a caller (US-131, `PICOForge-COMPAT`).
//!
//! **Why this lives in its own module.** There was exactly one correct
//! implementation — the XOR-accumulate `ct_eq` in `otp.rs`, added for
//! `VERIFY_PIN` and documented as "mirroring `ct_eq` in the piv/fido apps" —
//! and the OATH applet's `cmd_set_code`/`cmd_validate` were not using it. They
//! compared a caller-supplied response against the expected MAC with the slice
//! `PartialEq`, i.e. a `memcmp`, which returns at the first differing byte. The
//! EPIC requires `VALIDATE` to check the response *in constant time*; that is
//! a property of the comparison, not of one applet, so the helper is promoted
//! here and both `otp.rs` and `oath_core.rs` (plus the legacy `oath.rs`) call
//! it. One implementation, four callers.
//!
//! **What "constant time" means here.** The byte loop is XOR-accumulated and
//! has no early exit, so the work performed is a function of the slice
//! *lengths* only — never of where (or whether) the contents differ. The
//! length check is a deliberate early return and is **not** a leak: both
//! operands' lengths are already public on the wire (the TLV length byte), and
//! no caller is expected to hide them. What must never be inferred is *which*
//! byte differed, and that is what the loop protects.

/// Constant-time equality: XOR-accumulate every byte difference, then test
/// the accumulator once (C `mbedtls_ct_memcmp`, `otp.c:712/724`).
///
/// Returns `false` for unequal lengths without reading the contents. This is
/// the length-tolerant entry point; callers that have already established a
/// length (as `cmd_set_code` and `cmd_validate` have, to slice the MAC buffer)
/// keep their explicit length guard in front of the call.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::ct_eq;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    /// Byte-exactness, so the constant-time property is not bought by
    /// weakening the comparison into something that returns `true` early.
    #[test]
    fn ct_eq_matches_slice_equality_on_equal_and_unequal_inputs() {
        assert!(ct_eq(&[], &[]));
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[0, 0, 0], &[1, 0, 0]));
        assert!(!ct_eq(&[0, 0, 0], &[0, 0, 1]));
        assert!(!ct_eq(&[0, 0], &[0, 0, 0]));
        assert!(!ct_eq(&[0, 0, 0], &[0, 0]));
        assert!(!ct_eq(&[0xFF; 20], &[0xFF; 21]));
    }

    /// **The guard.** `ct_eq` must cost the same whether the inputs differ in
    /// the first byte or the last.
    ///
    /// A `memcmp` (or any `==` on a slice) returns at the first difference, so
    /// the first case would measure ~0 ns and the last case a full scan — an
    /// unbounded, unmistakable ratio. To make the signal deterministic rather
    /// than flaky, the measurement runs over 1 MiB and takes the **minimum** of
    /// nine runs: interference can only ever make a sample slower, so the
    /// minimum is the least-disturbed estimate available, and the unoptimised
    /// (test-profile) XOR loop is three orders of magnitude slower per byte
    /// than a SIMD `memcmp` — the separation is structural, not a race.
    #[test]
    fn ct_eq_cost_does_not_depend_on_the_divergence_point() {
        const N: usize = 1 << 20;

        let equal = vec![0x5Au8; N];
        let mut diverges_first = equal.clone();
        diverges_first[0] ^= 0x01;
        let mut diverges_last = equal.clone();
        diverges_last[N - 1] ^= 0x01;

        // Minimum of nine, so one scheduling hiccup cannot decide the test.
        let best = |f: &mut dyn FnMut() -> bool| -> Duration {
            let mut best = Duration::MAX;
            for _ in 0..9 {
                let t = Instant::now();
                let r = f();
                let d = t.elapsed();
                // `black_box` on the *result* keeps the optimiser from
                // constant-folding or hoisting the call out of the loop.
                black_box(r);
                if d < best {
                    best = d;
                }
            }
            best
        };

        let t_equal = best(&mut || ct_eq(black_box(&equal), black_box(&equal)));
        let t_first = best(&mut || !ct_eq(black_box(&equal), black_box(&diverges_first)));
        let t_last = best(&mut || !ct_eq(black_box(&equal), black_box(&diverges_last)));

        // The first divergent byte must not be special-cased. Half the
        // equal-input cost is a very loose floor: the correct implementation
        // measures the two within noise of each other, while a `memcmp` makes
        // `t_first` essentially zero and fails this by ~6 orders of magnitude.
        assert!(
            t_first * 2 > t_equal,
            "ct_eq returned early on a first-byte difference ({t_first:?} vs \
             {t_equal:?} for equal inputs) — it is a memcmp, not constant time"
        );
        assert!(
            t_last * 2 > t_equal,
            "ct_eq did less work for a last-byte difference ({t_last:?} vs \
             {t_equal:?})"
        );
    }
}
