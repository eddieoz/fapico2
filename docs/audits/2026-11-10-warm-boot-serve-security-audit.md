# Security audit: EPIC `WARM-BOOT-SERVE` — the entropy bring-up and its warming posture

**Scope:** `628fa07..4a725e6` on `fix/darkboot` (US-1820…US-1830/1833/1834 + the review and audit follow-up fixes).
**Method:** static analysis adapted from the security-audit workflow (scope → automated gates → targeted entropy-source hunts → new-surface review), with every claim pinned to a grep, a gate run, or a hardware probe. The audit's primary mandate: **the TRNG is the sole entropy source and is never bypassed or substituted with software entropy, for every applet that creates keys or generates randomness.**

**Date:** 2026-11-10. **Auditor:** harness session (all findings reproducible from the cited commands).

---

## 1. The randomness chain — verified end to end

Every shipped randomness consumer traces to exactly one chain, with no software substitution at any hop:

```
RP2350 TRNG (peripheral, health-configured, bounded Rp2350Probe — US-1802 budget)
  → FuseSeedSource: otp_row ⊕ serial_hash ⊕ chipid ⊕ boot.entropy.v1 record  (fuse half, deterministic)
                   + a FRESH 32-byte probe draw per seed/re-seed             (TRNG half, never a counter)
  → LazyDrbg cell (seed-ONCE; NotSeeded refusal before any output exists)
      → Rp2350Rng (trussed backend: OpenPGP/PIV/opcard; three distinct rand_core codes,
        NotSeeded → RNG_ERR_NOT_SEEDED, consumed as status 0x6400 by opcard — never fabricated bytes)
      → boot pools (FIDO 512 B / OATH 512 B / Nostr 256 B), filled from the SEEDED cell only,
        capacity-refilled exactly once at Ready, SHA-256-stretched on exhaustion
```

**Evidence per hop:**

| Claim | Evidence |
|---|---|
| No software-entropy substitutions (`thread_rng` / `OsRng` / `getrandom` / `rand::rngs` / entropy-from-time) in shipped code | `grep -rn` over `firmware/src`, `apps/*/src`, `platform/src`, `vendor/opcard/src` — only doc comments name them |
| No unvalidated DRBG constructor reachable from shipped code | `Drbg::new` confined to `#[cfg(test)]` KATs in `platform/src/drbg.rs`; `Drbg::new_device`'s one allowlisted caller is a host test (`drbg_reseed_policy.rs`); `LazyDrbg::new` is the empty cell, not a generator |
| Host-entropy fallbacks cannot reach the device build | `platform::trng::random_bytes*` are `#[cfg(not(target_arch = "arm"))]`; `apps/fido::crypto::random_bytes` is `#[cfg(feature = "host")]`; **the whole `u2f` module is host-gated** (`apps/fido/src/lib.rs:59`) — the U2F stateless-handle draw never compiles on device; Nostr's `platform_random` arm returns `None` on arm (refuse) |
| The standing one-path gate | `tests/scripts/check_rng_path.py` PASS (incl. `check_seam_cfg`: the starvation seam is emulation-only and non-arm); boot.rs's `Trng::random_bytes` cap remains **0** |
| No DRBG output before the TRNG-nonce seed | `LazyDrbg` refuses `NotSeeded`; the infallible seam leaves the buffer untouched (D-9), pinned by `platform/tests/lazy_drbg.rs` |
| Pools are never filled from anything but the seeded cell | `refill_rng_pool_if_below_capacity` (FIDO/OATH) and `draw_boot_pool` (Nostr) take the cell handle; the fill's first chunk probes the fallible seam and leaves the pool empty on `NotSeeded` |
| Warming-window pool constants never reach a dangerous consumer | The gates below; the accepted residuals are recorded (D-WB1) |

## 2. The warming gates — who may draw what, and when

| Operation | Warming behavior | Where pinned |
|---|---|---|
| makeCredential (whole command) | refuse `0x7F` | `device_core.rs` gate; `consumer_map.rs::make_credential_carries_the_warming_gate` |
| clientPIN **token mint** (0x05/0x09) | refuse `0x7F` | `consumer_map.rs::client_pin_gates_the_token_mint_and_the_persisted_salts` |
| clientPIN **persisted salts** (0x03/0x04) | refuse `0x7F` | same pin |
| clientPIN getRetries / getKeyAgreement | serve (deterministic) | same pin (negative assertion: not gated) |
| OATH VALIDATE / SET_CODE | refuse `0x6985` | `consumer_map.rs::oath_validate_and_set_code_carry_the_warming_gates` |
| Nostr GENERATE / SIGN / NIP-44 | refuse via the `None` provider arm | `consumer_map.rs::nostr_provider_is_option_gated` |
| **Nostr custody CEREMONY (OTP burn)** | refuse `0x6985` — **found by this audit, fixed** (§3 A1) | `consumer_map.rs::nostr_ceremony_start_gates_the_otp_burn` |
| OpenPGP GET CHALLENGE / keygen (opcard) | `NotSeeded` → `0x6400` retryable (US-1006 mapping), never fabricated bytes | `platform/src/trusted_backend/device.rs`, `vendor/opcard/src/command.rs` |
| getAssertion / PIN verification / OATH codes / OpenPGP-PIV signing | serve — deterministic, no draw | `consumer_map.rs::the_get_assertion_path_draws_no_randomness` |

## 3. Findings

### A1 — HIGH → **fixed during this audit** (`4a725e6`)
**The custody ceremony burned OTP rows during a warming window.** `ceremony_start` draws its burn words from the pool via `ceremony_entropy_word`, which **discards the draw result**; on the warming path the draw refuses → word = 0 → `custody::burn` verify-fails into **torn custody rows**. Recoverable (the ceremony resumes over torn rows) but a destructive side effect reachable through a normal command sequence, and zero words served to an OTP burn violates the epic's own no-zeros invariant. **Fix:** `ceremony_start` refuses `0x6985` while the provider is `None` (the device warming posture), before any OTP leg; the ceremony re-runs once Ready. Host builds unaffected (`None` there means the OS fallback). Pinned in source order (gate before burn).

### A2 — LOW/MEDIUM, decision recorded, accepted for now
**`TAG_ENTROPY_STATE` (0x0B) is unauthenticated information disclosure.** `READ_CONFIG` (0x1D), CTAPHID 0x42 and OTP 0x13 serve it without auth. The `row_unfused` bit tells a holder of the device that the at-rest seal is degenerate (`{0³², chipid}`-derived). **Assessment:** the chipid itself is *not* exposed by the TLV, so the bit grants no key material and no new capability; the warming/ready bit leaks nothing sensitive. The bit's purpose is owner-visible state, which is inherently unauthenticated. **Recommendation:** accept, and note in the book's interop docs that the flag is advisory status, not a security boundary. Revisit only if a future TLV carries more than advisory state.

### A3 — LOW, recorded (D-WB1)
The makeCredential warming gate precedes the PIN-auth-failure latch, so bad-token attempts during a warming window do not advance the latch. Deliberate: nothing behind the gate can succeed during the window.

### A4 — LOW, doc debt (pre-existing, out of epic scope)
`stretch_pool`'s doc says "stretched **keyed** hash"; the implementation is plain `SHA-256` over the pool remainder (`platform/src/trng.rs:1148`, mirrored in `oath_core::draw_random`). Not a break — the stretched input is secret DRBG output and SHA-256 preimage resistance preserves its secrecy — but the doc claims a property the code does not have. The OATH-local stretch copy is also an AGENTS §5 duplication. Both predate the epic; filed here so they are not lost.

### A5 — INFO
The `.retain (NOLOAD)` section (`platform/board_def.rs:719`) is vestigial after the bounded-reboot machinery's deletion — an empty, harmless section kept with its recorded history. Remove only with the COLD-BOOT-ENTROPY-WINDOW postmortem.

### A6 — LATENT, for the CTAP1 epic
`u2f.rs` (stateless U2F key handles) is host-gated today and unreachable on device — the device advertises `U2F_V2` but does not serve CTAP1 (`tests/u2f_v2_advertisement.rs::ctap1_is_not_servable_yet`). **When CTAP1 lands, its key-handle draws must route through the cell/pool with a warming gate** — the current host-only draw would otherwise compile into a warming bypass. This is the audit's one forward obligation.

### A7 — recorded residuals (D-WB1, accepted with analysis)
getInfo's `enc_identifier`/`enc_cred_store_state` IVs, hmac-secret v2 IVs, keyregion record-write GCM nonces (bump/migration/deleteAll), and vendor backup's EXPORT nonce serve during a warming window from computable-but-unique keystream windows. No GCM reuse (the cursor advances; distinct stretch constants per exhaustion), secret keys, no oracle reopened. Full analysis in `docs/known-gate-divergences.md` §D-WB1.

## 4. Verified clean

- No `thread_rng` / `OsRng` / `getrandom` / time-seeded PRNG anywhere in shipped code.
- Every pool fill, every seed, every re-seed routes through the TRNG via the bounded probe; the fuse half is deterministic by design and always combined with the fresh TRNG nonce (no counter fallback exists in the seed path).
- `LazyDrbg` makes "deterministic-sequence randomness served as randomness" structurally impossible pre-seed; the cross-boot nonce-repetition defect US-1003/C-1 closed remains closed under the new architecture.
- Secrets in logs: none (the throttled warming warns carry attempt counts only; `defmt` strings audited).
- Zeroization: seed halves in `Zeroizing`; `Drbg`'s `Debug` opaque; the buffer-untouched refusal contract pinned against the seam.
- CI-shaped gates green at audit time: clippy, 7 gate scripts (incl. rng-path + seam-cfg), 202 host suites, firmware release build.

## 5. Hardware probes (this board, `fa20:0002`)

- Status TLV live: `ready=True, row_unfused=False` over CCID (three-interface parity by construction).
- Full MC+GA ceremony served post-Ready (real attestation + assertion signatures).
- OATH challenge = DRBG output; the empty-pool constant (`SHA-256("")` windows) absent post-fix.
- wrong-PIN `getPinToken` → `0x32` (reached PIN verification, past the warming gate — gate open at Ready).
- One probe inconclusive: `CEREMONY_START` over plain CCID answered `6E00` (INS routing detail of the vendor dispatch, pre-existing); the ceremony gate itself is source-pinned and suite-green.

## 6. Residual obligations

1. US-1831/1832: the cold-episode hardware validation (filming) — the audit's warming-gate closed-state evidence is host-side + source-pinned until that run.
2. A6: the CTAP1/U2F landing checklist must include the entropy routing.
3. A2/A4/A5: recorded; no action required now.
