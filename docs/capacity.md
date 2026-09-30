# Capacity — hardware-verified ceilings

Every number here was measured on the RP2350 part, not derived from a bound in
source. Where a compile-time constant *looks* like a capacity claim and is not,
it is called out; that gap is how the `MAX_CREDS = 68` misreading survived.

- **FIDO2 resident credentials: 12** (`DEVICE_MAX_CREDS`); U2F are stateless.
- **OATH credentials: 30 maximal** — measured (US-1010), not derived. The
  ceiling is the chunked **part count under the double-buffered rewrite**, not
  bytes: 31 credentials fits the 5,952 B logical bound and still cannot be made
  durable. `MAX_CREDS = 68` is a `heapless` table bound, never a capacity claim.
- **The store holds 24 entries** (`DEV_MAX_ENTRIES`), hardware-pinned: 32
  dark-boots, because the bss→MSPLIM stack distance scales with the count
  (DARK-BOOT-1; the reasoning and the bss ceiling that enforces it are in
  [`docs/size-report.md`](size-report.md)).
- **The compiled-in FIDO attestation key is a public, self-signed development
  key**; production devices generate per-device keys via TRNG.

Related: the keystore capacity layers and the durable-ack latch are recorded in
[`docs/known-gate-divergences.md`](known-gate-divergences.md) under SF-1
(including the US-1010 amendment that supersedes the earlier `≤ 16` figure).
