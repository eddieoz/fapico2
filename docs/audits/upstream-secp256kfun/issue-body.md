*Companion fix PR (`secp256kfun: fix truncating From<u64> in the 32-bit scalar backend`): link to follow in the comments. Full technical report: <GIST-URL>.*

## Context

While adopting `secp256kfun 0.12.1` as the signing primitive layer of a `no_std`
embedded secp256k1 product (BIP-340 signing and NIP-44 v2 encryption over
its primitive API — `Scalar`, `Point`, `op::scalar_mul_point`, the `s!` macro,
and `G` only), we ran an independent security audit of the crate's primitive-API surface and wrote
an executable evidence harness for it. This issue records the outcome for the
project's benefit, since one actionable finding came out of it.

## What was audited, and how

- **Line-by-line review** of every module reachable from the primitive API:
  both field backends (`field_10x26.rs`, `field_5x52.rs`), both scalar backends
  (`scalar_8x32.rs`, `scalar_4x64.rs`), `affine.rs`, `projective.rs`, `mul.rs`
  (GLV + radix-16 ladder), `op.rs`, the backend dispatch, the marker system,
  and the `secp256kfun_arithmetic_macros` proc-macro expansion.
- **Constants verified from first principles** with an independent pure-python
  secp256k1/BIP-340 oracle: p, n, n/2, 2^256−n, both backends' limb
  decompositions and negate minuends, the 0x1000003D1 fold, G, the GLV
  constants (λ, β, the EEA identity a₁b₂ − b₁a₂ = n), and both sqrt-chain
  exponents. All match.
- **Differential testing of the 32-bit backends on a 64-bit host**: the vendored
  `field_10x26.rs` and `scalar_8x32.rs` were compiled verbatim and exercised
  against 508 oracle cases (edges around p and n, doubling, cross products,
  range gates, mod-order folds). All match — including the in-file regression
  test for the historical `get_overflow` bug.
- **BIP-340 conformance**: a consumer-side signer built only on the primitive
  API reproduces every signable row of the 19-row BIP-340 reference vector set
  byte-for-byte, and an in-audit verifier agrees with all 19 verify verdicts.
- **Supply chain**: lockfile checksums vs. cached `.crate` tarballs, RustSec
  sweep, and a check that the feature surface used (`default-features = false`)
  compiles no RNG machinery at all.

## Result

No exploitable cryptographic weakness was found. The arithmetic is a faithful
Bitcoin-Core lineage port, the group law uses the complete
Renes–Costello–Batina formulas, constant-time discipline holds by construction
on every `Secret` path, and the marker/zero-choice algebra is sound.

## The one actionable finding: truncating `From<u64>` in the 32-bit scalar backend

the `From<u64> for Scalar8x32` impl (vendored copy, master:
`secp256kfun/src/vendor/k256/scalar/scalar_8x32.rs`) masks its input with
`0xFFFF` instead of `0xFFFF_FFFF`, silently dropping bits 16–31:

```rust
Self([(k & 0xFFFF) as u32, (k >> 32) as u32, 0, 0, 0, 0, 0, 0])
```

Demonstrated against the shipped implementation (backend included verbatim on a
host, compared to plain modular arithmetic):

- `From(0x1_0000u64)` produces **0**
- `From(0x1234_5678_9ABC_DEF0u64)` produces `0x1234_5678_0000_DEF0`-shaped wrong
  value (bits 16–31 lost)
- `From(0xFFFF_FFFF_FFFF_FFFFu64)` likewise wrong

**Severity: latent, not live.** The impl has no callers inside the crate — the
public integer conversions on the API `Scalar` take the range-checked
byte-array path (`impl_scalar_conversions!`), the only internal chain into it
(`From<u32> → From<u64>` on the vendored wrapper) is itself uncalled, and
`mod vendor` / `mod backend` are private, so the type is unreachable from
outside the crate.

**Lineage:** the identical mask is present in k256's `scalar_8x32.rs` as of
its last state before removal — commit `9748fd9853` in the
RustCrypto/elliptic-curves monorepo, where k256 then lived; the backend was
deleted by PR #409 in September 2021 when `Scalar` moved to `U256` (squash
commit `4eed022587`) — so this code vendored the bug rather than introducing
it, and current k256 releases are unaffected.

**Proposed fix** (companion pull request, linked in the comments): one line, `0xFFFF` → `0xFFFF_FFFF`, plus a
unit test in the file's own `#[cfg(test)]` module — which your `armv7`
CI leg (`cross test --all-features`) actually compiles and runs. Verified
fails-before / passes-after on the host.

## Minor observations (no action expected)

- The field backends' magnitude contracts (`max_magnitude`, "mul inputs ≤ 8")
  are `debug_assertions`-gated or doc-only; release builds enforce nothing.
  Current call paths respect them.
- `ConstantTime::scalar_invert` unwraps a `CtOption` and panics on a zero
  scalar; unreachable while the `NonZero` marker discipline holds.
- The `Secret`/`Public` marker docs say `Public` values may run in variable
  time, but in 0.12.1 every `op::*` function dispatches unconditionally to
  `ConstantTime` — the docs over-promise speed in the safe direction.

Full details, methodology, and the complete evidence tables are in the linked
gist report. The audit harness (26 Rust probes + two python oracle scripts,
all green against 0.12.1) is available on request — happy to publish it as a
follow-up gist.
