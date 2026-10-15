# Independent security audit — `secp256kfun` 0.12.1

**Auditor:** independent third party (eddieoz)
**Date:** 2026-10-14
**Scope:** the complete cryptographic surface of `secp256kfun 0.12.1` (crates.io,
checksum-verified) reachable from its primitive API, as consumed by a `no_std`
embedded secp256k1 product using BIP-340 signing (hand-rolled on the crate's
`Scalar`/`Point`/`op` primitives) and NIP-44 v2 encryption (ECDH + ChaCha20 +
HMAC-SHA256 on the same primitives).
**Out of scope:** the feature-gated `libsecp_compat` backends, serde/bincode
paths, FROST/MuSig protocol crates (`schnorr_fun`, `frost`, …), silicon-level
fault injection.

**Verdict: no exploitable cryptographic weakness found.** One latent
correctness defect in dead code was identified (§5.1) and reported upstream
with a fix. Everything else in this report is a verification record.

---

## 1. The audited configuration

| Component | Version | Integrity check |
|---|---|---|
| `secp256kfun` | 0.12.1 | lockfile checksum matches cached `.crate` tarball (SHA-256) |
| `subtle-ng` | 2.5.0 | checksum verified |
| `secp256kfun_arithmetic_macros` | 0.2.0 | checksum verified |
| `sha2` / `hmac` / `chacha20` (consumer side) | 0.10.9 / 0.12.1 / 0.9.1 | checksums verified |

Supply-chain results: `default-features = false` compiles no `std`/`alloc`/serde
and no `libsecp_compat` backends; `rand_core` stays a hard dependency but is
featureless in this configuration, so `getrandom` does not enter the graph at
all — the crate's RNG machinery is inert when only the primitive API is used.
RustSec sweep over the crypto set: no applicable advisories. Upstream issue
tracker: no open security issues for 0.12.x at audit time; the one adjacent
historical defect (`Point::from_bytes_uncompressed` on-curve validation, fixed
2025) predates 0.12.0 and is an API this consumer never calls.

**Backend selection by target** (the two backends are different code paths compiled per target):

| Target | Field backend | Scalar backend |
|---|---|---|
| 32-bit (`thumbv8m`, `armv7`, …) | `field_10x26.rs` (u32 limbs) | `scalar_8x32.rs` (u32 limbs) |
| 64-bit hosts | `field_5x52.rs` (u64 limbs) | `scalar_4x64.rs` (u64 limbs) |

Host test suites never execute the 32-bit backends; this audit did (§3) —
the host/32-bit-target backend divergence means the two backends are
different code paths validated by different evidence.

## 2. Primitive review

### 2.1 Field

p = 2²⁵⁶ − 2³² − 977, verified from both backends' limb decompositions **and**
from the `negate` minuend constants (which are p's limbs, not p−1's).
Multiplication is the Bitcoin-Core Solinas fold (2²⁵⁶ ≡ 0x1000003D1);
`normalize` performs the correction unconditionally and selects with
`conditional_select` — constant time. `normalizes_to_zero` tracks both 0 and p
with bit-ORs — constant time. `from_bytes` rejects x ≥ p via `CtOption`.
Inversion is a fixed addition chain ending at exponent p−2 (hand-derived and
oracle-verified). Field `sqrt` is the p ≡ 3 (mod 4) chain at exponent
(p+1)/4 with a final `res² == input` verification, so point decompression
cannot accept a non-residue. Both backends carry a regression test for a
historical `get_overflow` bug, fixed in this version.

### 2.2 Scalar

n verified from both backends' little-endian limb tables; `NEG_MODULUS` =
2²⁵⁶−n and `FRAC_MODULUS_2` = n/2 likewise. `from_bytes` accepts iff w < n
(constant-time underflow check); `from_bytes_mod_order` is one conditional
subtract — the standard ~2⁻¹²⁸ reduction bias, the same reduction BIP-340
itself prescribes for nonces and challenges. `add`/`sub` are correct single
conditional corrections (carried cases hand-verified); `mul` uses the
Bitcoin-Core three-step 512→258-bit reduction; `conditional_negate`,
`is_high`, `is_zero` are branch-free. Scalar inversion is the fixed
briansmith.org addition chain — constant time in the value. Scalar `sqrt`
(Tonelli–Shanks, S = 6, exponent (t−1)/2) branches only on a
compile-time-constant exponent; not on any audited consumer path in any case.

### 2.3 Point

G is the canonical generator (oracle-checked on-curve, n·G = ∞). The group law
uses the **complete** Renes–Costello–Batina 2015 formulas (alg. 7/8/9) — no
special cases — which structurally removes the incomplete-addition exception
attack class. x-only decompression: x ≥ p refused, x³+7 non-residues refused
(CT sqrt + final verification), y parity chosen by `conditional_select`.
Equality is cross-multiplied projective `ct_eq`; normalization handles the
identity in constant time (z⁻¹ fall-back to ONE plus conditional z
assignment). Scalar multiplication is GLV (λ, β, and the EEA identity
a₁b₂ − b₁a₂ = n all oracle-verified) over a constant-time 8-entry
`LookupTable::select` and a signed radix-16 ladder with fixed structure.
`VariableTime` delegates everything to `ConstantTime` except
`point_x_eq_scalar`, an ECDSA-only helper gated to `Public` scalars.

### 2.4 Expression macros

The proc-macro (`secp256kfun_arithmetic_macros` 0.2.0) lowers `s!(a + b * c)`
to `op::scalar_add(a, op::scalar_mul(b, c))` — precedence unit-tested
upstream, no aliasing, both ops constant-time. Integer literals are
constructed safely; division lowers through `scalar_invert` (panics on zero —
see §5.3).

## 3. Runtime verification of the 32-bit backends

The vendored `field_10x26.rs` and `scalar_8x32.rs` were compiled **verbatim**
on a 64-bit host (only glue: the `FieldBytes` alias and the two 3-line
`adc32`/`sbb32` helpers without the pointer-width cfg gate) and
differential-tested against expected values computed by plain modular
arithmetic in python — an implementation the crate code never consults. Cases
cover edges around p and n (0, 1, 2, p−2, p−1, n−2, n−1, n/2, 2¹²⁸, 2²⁵⁵,
2²⁵⁶−1), doubling, cross products, from-bytes range gates, and mod-order
folds:

| Suite | Cases | Result |
|---|---|---|
| `FieldElement10x26` mul / square / add / negate / is_odd / round-trip | 314 | all match |
| `FieldElement10x26` `from_bytes` range gate | 4 refusals | all refused |
| `Scalar8x32` add / sub / mul / negate / is_high / round-trip | 182 | all match |
| `Scalar8x32` `from_bytes` gate + `from_bytes_reduced` fold | 4 + 4 | all correct |

Both backends' in-crate regression tests also pass. This is the strongest
evidence available short of hardware that the shipped 32-bit arithmetic is
correct.

## 4. Consumer-level conformance

A signer written only on the crate's primitive API (the shape any BIP-340
consumer has) was checked line-by-line against the BIP-340 pseudocode — d′
bounds via `from_bytes`, even-y negation of d before nonce derivation,
tag-hashed aux XOR, `k′ = 0` refusal, even-y negation of k, challenge over
`R.x ‖ px ‖ msg`, `s = k + e·d` — and reproduces **every signable row of the
19-row BIP-340 reference vector set byte-for-byte**, with an in-audit
verifier (cross-checked against an independent python implementation of the
spec) agreeing with all 19 verify verdicts. Scalar and x-only edge inputs
behave exactly at the spec's bounds. A 2000-signature sweep with per-signature aux drawn from a fixed pool
produced no repeated R.

The consumer's NIP-44 v2 layer (conversation key as `HKDF-Extract` over the
raw shared x, HKDF-Expand(76), MAC-verify-before-decrypt) was exercised
against the full published vector set plus truncation/bit-flip sweeps — all
inputs refused cleanly, no panic, no partial plaintext.

## 5. Findings

### 5.1 Low (latent, dead code): the `From<u64> for Scalar8x32` impl truncates to 16 bits

```rust
impl From<u64> for Scalar8x32 {
    fn from(k: u64) -> Self {
        Self([(k & 0xFFFF) as u32, (k >> 32) as u32, 0, 0, 0, 0, 0, 0])  // mask must be 0xFFFF_FFFF
    }
}
```

Bits 16–31 are dropped: `From(0x1_0000)` → 0, `From(0x1234_5678_9ABC_DEF0)` →
wrong (bits 16–31 lost), demonstrated against the shipped implementation. The
64-bit backend's equivalent (`From<u64> → [k, 0, 0, 0]`) is correct, so
host-side tests cannot see the defect.

**Reachability: none.** No caller exists in the crate: the API-level integer
conversions (`impl_scalar_conversions!(u8, u16, u32, u64, usize, u128)`) go
through the byte-array path with range checks; the only internal chain into
the impl (the vendored wrapper's `From<u32> → From<u64>`) is itself uncalled;
`mod vendor` and `mod backend` are private, so the type is unreachable from
outside the crate.

**Lineage: inherited.** The identical mask is present in k256's
`scalar_8x32.rs` at its final pre-removal state (commit `9748fd9853` in the
RustCrypto/elliptic-curves monorepo, where k256 then lived); k256 deleted the
backend in September 2021 (PR #409, `U256` refactor, squash commit
`4eed022587`), so current k256 is unaffected.

**Reported upstream with a proposed fix:** one line plus a unit test in the
file's own `#[cfg(test)]` module (compiled and run by the project's armv7
CI leg); see the companion issue and pull request linked there.

### 5.2 Low (structural): magnitude contracts unenforced in release

The field backends' `max_magnitude()` and the "mul inputs ≤ 8" contract are
`debug_assertions`-gated or documentation-only; a future caller passing an
over-magnitude element would get silent wrong answers in release with no
signal. All audited call paths respect the contracts.

### 5.3 Info: `scalar_invert` panics on a zero scalar

`ConstantTime::scalar_invert` unwraps the backend `CtOption`. Unreachable
while `op::scalar_invert` requires `NonZero` markers and the audited paths
never invert, but worth knowing under `panic = "abort"`-style deployments.

### 5.4 Info: marker docs over-promise variable time

The `Secret`/`Public` marker documentation says `Public` values may run in
variable time; in 0.12.1 every `op::*` function dispatches unconditionally to
`ConstantTime`. The mismatch is in the safe direction.

### 5.5 Info: constant-time by construction, not by proof

CT rests on `subtle` primitives, fixed iteration counts, and branch-free
boolean arithmetic. No data-dependent early exits, secret-indexed table
lookups, or secret-dependent loop bounds exist on any `Secret` path
(file-by-file enumeration performed). No formal CT verification tooling was
applied.

## 6. Verdict

The vendored arithmetic is a faithful Bitcoin-Core-lineage port with correct
constants, complete group formulas, and consistent constant-time discipline.
The single actionable defect is unreachable dead code; a one-line fix and
regression test have been reported upstream (companion issue and pull
request). The crate is assessed fit for
its primitive-API role in the audited consumer configuration.

*Evidence harness: 26 Rust probes + two python oracle scripts, all green
against 0.12.1; available to the maintainers on request.*
