# Security audit — `secp256kfun` 0.12.1 as used by the Nostr applet

**Date:** 2026-10-14 · **Auditor role:** red team / security auditor
**Scope:** the complete cryptographic surface of `secp256kfun 0.12.1` reachable
from the fapico2 Nostr applet, its direct consumers (`apps/nostr/src/crypto.rs`,
`apps/nostr/src/nip44.rs`), the applet's entropy chain, and the identity-record
storage crypto it sits on.
**Out of scope:** `trussed-secp256k1`/`k256` (OpenPGP's backend — it never
touches Nostr keys, ADR 0005), the bech32 `npub` encoder beyond key-material
leakage (none), hardware fault-injection on silicon.
**Evidence harness:** `audit-secp256kfun/` (repo root, detached workspace) —
26 Rust probes + two python oracles. All green as of this date; rerun
instructions in its `README.md`.

---

## Executive summary

**No exploitable cryptographic weakness was found.** Every primitive on the
Nostr path was read line-by-line, every hardcoded constant was verified
against first-principles values with an independent implementation, the
hand-rolled BIP-340 signer reproduces the full reference vector set
byte-for-byte, and — the item host tests cannot see — the **32-bit arithmetic
that actually ships on the RP2350** was differential-tested against a python
oracle and matches on 496 edge and randomized cases.

The findings below are one latent defect in dead code (worth an upstream
report), structural observations, and threat-model notes. Nothing requires a
code change in this repository to keep the shipped configuration sound.

| # | Severity | Finding |
|---|---|---|
| F-1 | Low (latent, dead code) | `Scalar8x32::From<u64>` masks with `0xFFFF` — drops bits 16–31 |
| F-2 | Low (structural) | Field magnitude contracts unenforced in release builds |
| F-3 | Info | `scalar_invert` panics on a zero scalar (marker-disciplined) |
| F-4 | Info | Doc/behavior mismatch: `Public` markers no longer switch to variable time |
| F-5 | Info | CT is bool-arithmetic, not formally verified |
| F-6 | Info | Entropy: 2048-bit boot pool, hash-chain stretch, no runtime reseed |
| F-7 | Info | `EXPORT_KEY`/`IMPORT_KEY` are standing threat-model downgrades |

---

## 1. The audited configuration

| Component | Version | Provenance |
|---|---|---|
| `secp256kfun` | 0.12.1 | crates.io, checksum `ca6e7ba8…` verified against `Cargo.lock` **and** the cached `.crate` tarball |
| `subtle-ng` | 2.5.0 | checksum verified |
| `secp256kfun_arithmetic_macros` | 0.2.0 | checksum verified (proc-macro behind `s!`/`g!`) |
| `sha2` / `hmac` / `chacha20` | 0.10.9 / 0.12.1 / 0.9.1 | checksums verified |
| `aes-gcm` (storage) | 0.10.3 | checksum verified |

Supply-chain checks: all 14 crypto-set tarballs hash-match the lock;
`default-features = false` leaves the crate with no `std`/`alloc`/`serde` and
no `libsecp_compat` backends; `rand_core`/`getrandom` are **not in the device
graph** (the crate's RNG machinery is not even compiled — the applet brings
its own entropy). RustSec sweep: `RUSTSEC-2021-0100` (sha2, 0.9.7 only),
`RUSTSEC-2019-0029` (chacha20, <0.2.3), `RUSTSEC-2023-0096` (aes-gcm,
fixed in exactly our 0.10.3) — **none applicable**. Upstream tracker: no open
security issues for 0.12.x; the one adjacent historical bug
(`from_bytes_uncompressed` on-curve validation, issue #212) was fixed before
0.12.0 and is an API the applet never calls.

Which code ships where (the twin trap, AGENTS §1, at the arithmetic level):

| Target | Field backend | Scalar backend |
|---|---|---|
| `thumbv8m.main-none-eabi` (device) | `field_10x26.rs` (u32 limbs) | `scalar_8x32.rs` (u32 limbs) |
| `x86_64` (host tests, emulator) | `field_5x52.rs` (u64 limbs) | `scalar_4x64.rs` (u64 limbs) |

Host tests therefore never execute the device field/scalar. This audit did
(§3), which no prior test in the repository had.

## 2. Primitive-by-primitive review (Phase 1)

**Field** (`vendor/k256/field.rs`, `field_10x26.rs`, `field_5x52.rs`).
p = 2²⁵⁶ − 2³² − 977 verified from the limb decompositions of both backends
and from the negate minuends (python oracle, first principles). Multiplication
is the Bitcoin-Core Solinas fold (2²⁵⁶ ≡ 0x1000003D1); `normalize` does the
correction unconditionally and selects with `conditional_select` — constant
time. `normalizes_to_zero` tracks both 0 and p with bit-ORs — constant time.
`from_bytes` rejects x ≥ p via `CtOption`. Inversion is a fixed addition
chain ending at exponent p−2 (hand-verified; oracle-checked); field `sqrt`
is the p ≡ 3 (mod 4) chain at exponent (p+1)/4 with a final `res² == input`
check, so decompression cannot accept a non-residue. The 10×26 backend
carries a regression test for a real historical `get_overflow` bug — fixed
in this version.

**Scalar** (`vendor/k256/scalar.rs`, `scalar_8x32.rs`, `scalar_4x64.rs`).
n verified from the little-endian limb tables of both backends;
`NEG_MODULUS = 2²⁵⁶−n` and `FRAC_MODULUS_2 = n/2` likewise. `from_bytes`
accepts iff w < n (CT underflow check); `from_bytes_mod_order` is one
conditional subtract — the standard ~2⁻¹²⁸ reduction bias, which is the
same reduction BIP-340 itself prescribes for the nonce and challenge.
`add`/`sub`/`mul` (Bitcoin-Core three-step wide reduction) and
`conditional_negate` are branch-free; `is_high` is an n/2 subtraction.
Scalar inversion is the fixed briansmith.org addition chain — CT in the
value (F-3 covers its zero panic). Scalar `sqrt` (Tonelli–Shanks, S = 6)
is not on any applet path; its `pow_vartime` branches only on a
compile-time-constant exponent.

**Point** (`affine.rs`, `projective.rs`, `mul.rs`). G coordinates are the
canonical secp256k1 generator (oracle: on curve, n·G = ∞). The group law is
the **complete** Renes–Costello–Batina 2015 formulas (alg. 7/8/9) — no
special cases, which removes the incomplete-addition exception attack class
structurally. x-only decompression: x ≥ p refused, x³+7 non-residue refused
(CT sqrt + verification), y parity chosen with `conditional_select`.
Equality is cross-multiplied projective `ct_eq`; normalization handles the
identity CT (z⁻¹ fall-back to ONE, conditional z assignment). Scalar
multiplication is GLV (λ, β, and the EEA identity a₁b₂ − b₁a₂ = n all
oracle-verified) over a CT 8-entry `LookupTable::select` and a signed
radix-16 ladder with fixed structure — constant time in the scalar.
`VariableTime` delegates everything to `ConstantTime` except
`point_x_eq_scalar` (an ECDSA-only helper the applet never calls).

**Expression macros** (`secp256kfun_arithmetic_macros 0.2.0`). The applet's
`s!(k + e * d)` expands to
`op::scalar_add(k, op::scalar_mul(e, d))` — parser precedence unit-tested
upstream (`a + b * c`), no aliasing, both ops dispatch to `ConstantTime`.
`LitInt` constants are constructed safely. Division lowers to
`scalar_mul(a, scalar_invert(b))` — not used by the applet.

**Markers.** `Secret`/`Public` are phantom types; in 0.12.1 every
`op::*` function dispatches to `ConstantTime` regardless (see F-4).
`Zero`/`NonZero` bookkeeping is compile-time (`DecideZero`), and the
applet's `crypto.rs:86` re-typing of `k0` is sound because every
`add`/`mul` output is fully reduced, so `to_bytes` is canonical and the
`from_bytes` re-validation is a genuine re-check, not an assumption.

## 3. The device arithmetic, runtime-verified (the audit's core evidence)

The probe crate includes `field_10x26.rs` and `scalar_8x32.rs` **verbatim**
(the only glue: `FieldBytes` aliased to the upstream `GenericArray`, and the
two 3-line `adc32`/`sbb32` helpers restated without the 32-bit cfg gate so
they compile on a 64-bit host). `tools/gen_device_vectors.py` generates
expected values from plain modular arithmetic — an implementation the device
code never consults — over edge inputs (0, 1, 2, p−2, p−1, n−2, n−1, n/2,
2¹²⁸, 2²⁵⁵, doubling, cross products) plus seeded randoms:

| Suite | Cases | Result |
|---|---|---|
| `FieldElement10x26` mul / square / add / negate / is_odd / round-trip | 314 | **all match** |
| `FieldElement10x26` `from_bytes` range gate | 4 refusals | **all refused** |
| `Scalar8x32` add / sub / mul / negate / is_high / round-trip | 182 | **all match** |
| `Scalar8x32` `from_bytes` gate + `from_bytes_reduced` fold (n, n+1, 2²⁵⁶−1, n+2⁶⁴) | 4 + 4 | **all correct** |

Both backends' own in-crate regression tests also run in the probe suite and
pass. This is the strongest available evidence short of hardware that the
shipped 32-bit arithmetic is correct; the one residual gap is recorded in §6
(recommendation R-3).

## 4. Consumer review (Phase 2)

**`apps/nostr/src/crypto.rs` — the hand-rolled BIP-340 signer.** Checked
line-by-line against the BIP-340 pseudocode: d′ bounds via
`from_bytes` (rejects 0 and ≥ n); even-y negation of d **before** nonce
derivation; `t = bytes(d) ⊕ hashBIP0340/aux(aux)` with the tag-hashed aux;
`rand = hashBIP0340/nonce(t ‖ px ‖ msg)`; `k′ = 0` refusal; even-y negation
of k; challenge over `R.x ‖ px ‖ msg`; `s = k + e·d`; 64-byte `R.x ‖ s`
serialization. It matches. **Byte-for-byte proof:** every signable row of the
19-row reference vector set reproduces the expected signature exactly
(`every_valid_row_reproduces_the_reference_signature_byte_for_byte`), and an
in-probe verifier (cross-checked against the python oracle's independent
implementation) agrees with all 19 verify verdicts. Edge scalars (0, 1, n−1,
n, n+1, 2²⁵⁶−1) behave exactly at the spec's d′ bounds. The spike↔applet
twin (the AGENTS §1 hazard) was diffed: **the sign cores are line-for-line
identical** — only the error plumbing (`Result<_, Error>` vs `Option`)
differs.

**`apps/nostr/src/nip44.rs` — NIP-44 v2.** Conversation key
`HMAC-SHA256(key = raw shared x, msg = "nip44-v2")` is exactly the spec's
`HKDF-Extract`; keys via HKDF-Expand(76); MAC over `nonce ‖ ct` verified
**constant-time and before any unpadding**; version byte 0x02 enforced
explicitly; padding (`calc_padded_len`) cross-checked against an
independently formulated implementation over the entire 0..=65640 domain,
and the compile-time twin matches everywhere (the 1792→2048 chunk jump the
wire cap hangs on is asserted). All published vectors pass, including the
65535-byte long-message rows (payload digests are over the base64 text, as
the reference computes them). Adversarial sweep: truncation at every offset
and every single-bit flip of every region of a valid payload — all refused
with a clean `Error`, never a panic, never a partial plaintext. Failure
statuses collapse to a single `6A80`/`6B00` vocabulary, so no padding-oracle
distinguisher exists (and the MAC-first order means an attacker without the
key never even reaches the padding branch).

**Command arms (`lib.rs`).** Validation-before-touch orderings hold for every
mutating command; `IMPORT_KEY` validates the scalar before anything else;
`SIGN`/`NIP44_ENCRYPT` draw their aux/nonce **on-device** and refuse
(`6F00`) when the RNG seam is unwired — never fabricate; the NIP-44 nonce
cannot be supplied or replayed by the host; peer keys are lifted (curve +
non-zero, cofactor-1 argument documented) **before** any scalar
multiplication (US-1656). The `NostrViaMutex` proxy forwards every `App`
trait method including `factory_wipe` (the F-A3 lesson, fixed and commented
at `firmware/src/nostr_shared.rs:120-127`).

**Entropy chain.** RP2350 TRNG (health tests on, bypass register never
written, all-zero draws refused) → HMAC-DRBG seeded per boot from
`otp_key_1 ‖ chipid ‖ boot.entropy.v1` **plus a fresh TRNG draw** (all-zero
record and all-zero draw refused; wedged peripheral = hard failure, no
fuse-only fallback) → 256-byte boot pool → `stretch_pool` byte drain.
`stretch_pool` re-keys the pool with `SHA-256(pool)` on exhaustion — a pure
hash chain. Consequences, argued: (a) within a boot session the 32-byte
output blocks are `pool[0..256]`, `H¹(pool)[0..32]`, `H²(pool)[0..32]`, … —
**distinct by construction** (a SHA-256 chain cannot revisit a block without
a collision), so NIP-44 nonce reuse within a session is excluded;
(b) unpredictability to an attacker without RAM access is preserved by the
one-way stretch; (c) BIP-340's aux is defense-in-depth only — the nonce
`t‖px‖msg` remains deterministic-sound even with public aux, so the pool is
never the sole line of defense for signatures; (d) the honest tradeoff is
recorded as F-6. The 2000-signature sweep found no repeated R.

**Storage.** Identity records are AES-256-GCM under a device-bound key
(HKDF over `otp_key_1 ‖ chipid`); the deterministic record nonce
`SHA-256(key ‖ SHA-256(aad ‖ pt))[..12]` digests the full plaintext under
the key, so `(key, nonce)` never encrypts two plaintexts (the GCM reuse
hazard), and the 96-bit truncation's birthday bound is irrelevant at the
region's ~tens-of-writes scale. `open_with` **zeroizes the buffer on tag
failure** — defense in depth against exactly the pattern of
RUSTSEC-2023-0096 (whose fixed version is in use anyway). AAD binds domain,
slot and generation, so records cannot be transplanted between slots or
domains. `EXPORT_KEY` returns the raw scalar behind a touch — a permanent,
documented threat-model downgrade (F-7).

## 5. Findings

### F-1 — Low (latent; dead code): `Scalar8x32::From<u64>` truncates to 16 bits
`field_10x26`'s sibling at
`vendor/k256/scalar/scalar_8x32.rs:597-601`:

```rust
impl From<u64> for Scalar8x32 {
    fn from(k: u64) -> Self {
        Self([(k & 0xFFFF) as u32, (k >> 32) as u32, 0, 0, 0, 0, 0, 0])
    }
}
```

The mask must be `0xFFFF_FFFF`; as written, bits 16–31 of `k` are dropped
(`65536 → 0`). The 4×64 backend's equivalent (`From<u64> → [k, 0, 0, 0]`) is
correct, so host tests cannot see this. **Reachability: none** — no caller
exists anywhere in the crate (the API-level integer conversions go through
the byte-array path with range checks; `libsecp_compat` is feature-gated off
in our build; grep over the whole crate found no call site). It is a
correctness bug in vendored code waiting for a caller, not an exploitable
defect. **Remediation:** report upstream (LLFourn/secp256kfun); on the next
dependency bump, re-run `audit-secp256kfun`. The differential harness would
catch it if it ever becomes reachable (add a `From<u64>` probe then).

### F-2 — Low (structural): magnitude contracts are unenforced in release
The field backends' `max_magnitude()` (31 for 10×26, 2047 for 5×52) and the
"mul inputs ≤ 8" contract are `#[cfg(debug_assertions)]`-gated or doc-only;
`debug_assert`s peppered through `mul_inner` vanish in release. The shipped
call paths (the fixed inversion/sqrt chains, the RCB formulas) respect the
contracts, and the differential testing of §3 plus the vector conformance
give strong evidence nothing violates them — but a future caller passing an
over-magnitude element would get silent wrong answers on hardware with no
release-mode signal. **Remediation:** none required now; note for reviewers
that any new direct caller of the vendored `FieldElement` API needs the
magnitude discipline, and that `audit-secp256kfun` is the regression harness
to extend first.

### F-3 — Info: `scalar_invert` panics on a zero scalar
`ConstantTime::scalar_invert` → `scalar.invert().unwrap()` (backend
`CtOption::unwrap`). Marker discipline (`Scalar<_, NonZero>`) makes this
unreachable from `op::scalar_invert`, and the applet never inverts (BIP-340
needs no inversion; NIP-44 neither). Recorded because under
`panic = "abort"` it would be a device reboot if a future change inverted a
zero-typed scalar.

### F-4 — Info: doc/behavior mismatch on secrecy markers
The `Secret`/`Public` marker docs promise variable-time execution for
`Public` values; in 0.12.1 the dispatch is unconditionally `ConstantTime`
(`op.rs` ignores the marker; `VariableTime` is a vestigial alias). The
mismatch is in the **safe** direction (everything is CT), and it also means
the applet's `e.set_secrecy::<Public>()` is purely documentation. Worth
knowing when reading upstream issues that discuss marker-driven
optimizations.

### F-5 — Info: constant-time is by construction, not by proof
CT is achieved with `subtle` primitives, fixed iteration counts, and
branch-free boolean arithmetic (`ct_less`, `get_overflow`'s boolean
expressions). No data-dependent early exits, table lookups, or
secret-indexed accesses exist anywhere on the Secret paths (enumerated
file-by-file in Phase 1). No formal CT verification (e.g. haybale-pitchfork,
upstream issue #4, still open) was applied. The RP2350 threat model —
single-user token, no hostile co-tenant process, attacker at the USB
interface or with physical access between sessions — has no local timing
adversary; a remote timing channel through APDU latency is not a known
secp256k1 leak class. Accepted as adequate for this project.

### F-6 — Info: entropy budget and forward secrecy
2048 bits of DRBG-grade entropy at boot; `stretch_pool`'s hash chain never
repeats an output block within a session (argued in §4) and never grows the
entropy budget; there is **no runtime reseed** from the TRNG. An adversary
who reads RAM mid-session can compute all *future* pool outputs but not past
ones (one-way chain). Consequences in the applet's terms: session nonce
uniqueness — sound; BIP-340 aux — defense-in-depth only; NIP-44 nonces —
unpredictable to the USB-side adversary, unique in-session; key generation —
backed by the full DRBG seed chain. Cross-boot repetition would require the
DRBG seed to repeat, which the fresh per-boot TRNG draw makes negligible.
Accepted; the sizing rationale now lives in this report and
`platform/src/trng.rs`.

### F-7 — Info: standing threat-model downgrades (documented, deliberate)
`EXPORT_KEY` hands out the raw identity scalar behind one touch (permanently
usable by the host afterwards), and `IMPORT_KEY` accepts host-generated
scalars (so a weak host RNG can mint a Nostr identity). Both are recorded
product decisions (US-1676, D12) with the mitigation that they are
touch-gated and that `GENERATE_KEY` exists as the on-device alternative.
Nothing to fix; listed so the boundary is explicit in the audit trail.

*Disposition, 2026-10-15:* the export half of F-7 is retired on this branch —
US-1699 deletes `EXPORT_KEY` outright (the byte answers `6D00` on every
transport), making custody import-only under [ADR 0006](../adr/0006-nostr-pin-custody.md).
`IMPORT_KEY` remains, with the PIN custody gate and the sealing ceremony now
between a stolen board and the identity set.

## 6. Recommendations

- **R-1 (upstream):** report F-1 (`Scalar8x32::From<u64>` mask) to
  LLFourn/secp256kfun with the one-line fix; reference that the vendored copy
  deviates from the 4×64 backend's semantics.
- **R-2 (process):** pin the audit harness: re-run `audit-secp256kfun`
  (`cargo test` + the two python tools) on any `secp256kfun` version bump —
  the `#[path]` includes fail loudly if the registry source moves, which is
  the intended tripwire.
- **R-3 (gap, accepted):** the device backends are now differentially proven
  on-host, but no on-hardware vector run exists. When a hardware probe
  session next happens, replay one BIP-340 sign vector and one NIP-44 vector
  through the real device (`scripts/nostr_probe.py` covers the CCID arm) to
  close the last silicon gap.
- **R-4 (optional hardening):** zeroize `crypto.rs`'s stack scalars
  (`d`, `k`) on scope exit. secp256kfun 0.12.1 does not zeroize its `Scalar`s
  (ADR 0005's amendment already accepts the scalar's RAM lifetime); this
  would only shrink the window against a RAM-scraping attacker with code
  execution, which the threat model treats as game over anyway.

## 7. Coverage checklist (objective → evidence)

| Objective item | Evidence |
|---|---|
| Every crypto primitive evaluated | §2 (field, scalar, point, GLV, macros, markers) — all read line-by-line |
| Calculations correct | §3 differential tables (496 cases), §4 vector conformance, python constant oracle (all pass) |
| Curve parameters correct | oracle §constants: p, n, n/2, 2²⁵⁶−n, G, β, λ, EEA identity — all first-principles matches |
| Entropy use | §4 entropy chain + F-6; DRBG seed freshness (`drbg_seed.rs` fresh draw, all-zero refusals); TRNG health tests on |
| Side channels | §2 CT enumeration + F-5; complete addition formulas remove exception attacks |
| Supply chain | §1: 14/14 checksums match lock; advisories N/A; feature surface minimal; no upstream security issues |
| Decisive consumer paths | §4: BIP-340 signer (byte-exact vs 19 reference rows), NIP-44 v2 (all vectors + adversarial sweep), command arms, storage AEAD |
| Reproducibility | `audit-secp256kfun/README.md` — 26 Rust probes + 2 python oracles, all green 2026-10-14 |
