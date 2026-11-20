# The retail first-boot dark park: fresh installs never lost the pre-epic boot

**Date:** 2026-11-19
**Recording:** `fapico2-boot-0100-discord.mp4` (406×720, 30 fps, 73.8 s) — a
Discord re-encode filmed by a **customer**, of a **v0.7.0 board bought at
Robocore**. The customer's report (translated): *"Testei nos 2 o fapico2
v0.7.0 comprada na Robocore e acontece a situação acima, fica piscando
rapido por 60s e para. Não chega ao passo do fa20"* — fast blink ~60 s,
then it stops, and the device never enumerates (two units, same result).
**Predecessors:** [`2026-10-31-boot-dark-trng-refused.md`](2026-10-31-boot-dark-trng-refused.md),
[`2026-11-09-cold-boot-entropy-window.md`](2026-11-09-cold-boot-entropy-window.md),
[`2026-11-10-warm-boot-serve-security-audit.md`](2026-11-10-warm-boot-serve-security-audit.md),
EPIC `WARM-BOOT-SERVE` (US-1820…US-1836).

## Verdict

**Not a regression.** The WARM-BOOT-SERVE series works for its scope. What
failed is its **scope boundary**: the fresh-install path kept the entire
pre-epic blocking bring-up, by explicit design, and every retail unit is
born on that path.

The discriminator is `boot::boot_needs_legacy_bringup`
(`firmware/src/boot.rs:1202`):

```rust
pub fn boot_needs_legacy_bringup(store: &mut DeviceStore) -> bool {
    !(boot_entropy_record_present(store) && hkey_present(store))
```

A board with **no entropy record or no persistent hkey** is a fresh
install, and main.rs runs the legacy inline sequence for it
(`firmware/src/main.rs:786-834`):

1. `ensure_boot_entropy_blocking` (`boot.rs:1214`) — record-absent draw,
   400 ms notice, **60 s** `otp_retry` budget with the wait-blink, park
   `0011` (`Reason::TrngRefused`) on refusal.
2. `init_drbg_cell` (identity reads inside keep the OTP budget).
3. `seed_drbg_blocking` (`boot.rs:1124`) — **another 60 s** budget with the
   wait-blink, park **`0100`** (`Reason::DrbgRefused`) on refusal.
4. Only then applet construction, `RUNG_USB` (`main.rs:1442`), serving.

USB comes up **only after** both windows. A TRNG stalled by a long-dwell
cold episode — and retail storage is the longest dwell a board ever
experiences (weeks in a warehouse, then a store shelf) — consumes the
budget(s), the board blinks fast for ~60 s (or ~120 s if the record draw
succeeds and the seed refuses), parks once with a legible signature, and
**never enumerates**. That is the customer's report, word for word.

## Why the warm-boot fix did not hold

It did hold — for the boards it covers. The bring-up task
(`main.rs:1650`) retries forever, never parks, and serves USB first; but
its first line is:

```rust
if boot::entropy_ready() {
    return;   // legacy path: seeding happened inline on the boot path
}
```

and on a fresh install the boot path never gets that far — the task is
spawned only after `RUNG_USB`, which the legacy window precedes. The
epic's own file says the quiet part out loud in `boot.rs:1110-1118`:

> the pre-epic `init_drbg` body, **retained for the first-install path
> only**. A fresh board's construction draws (hkey, attestation, keystore)
> still need a live generator before the applets can boot, so this path
> blocks on the [`otp_retry`] budget exactly as the pre-epic boot did.

The construction draws that force this are pinned:

- `apps/fido/src/device_app.rs:422` and `:593` — `p256::SecretKey::random`
  for the hkey when `HKEY_KEY` is absent (construction-time),
- `apps/fido/src/device_app.rs:579` — `attestation::provision` (fresh TRNG
  key + self-signed cert) on a fresh store, also construction-time.

The original epic plan (US-1822) had already moved these into the bring-up
sequence — *"record → DRBG seed → hkey draw → persist — in that order"* as
**bring-up steps** — but the implementation kept them pre-USB. US-1831
(the cold-morning validation) was filmed on the owner's board and **the
fresh-install-on-a-cold-stalled-TRNG case was never hardware-validated** —
the epic marks it `[~]` "the long-dwell film remains". The two Robocore
units are that missing film.

## What the video establishes

Handheld, re-encoded, continuously micro-drifting — a frame-perfect decode
is not tractable (five tracker attempts failed; the button-hole tracking
holds only around t≈16 s). What it does establish:

- The LED **blinks** (clean on/off captures at ~6.5 s, ~15.5 s, ~66 s;
  the LED site sits ~22 px above the button hole, saturated ≥200 vs board
  ~150);
- **No 1 Hz heartbeat anywhere in 73.8 s** — the board never reached
  serving;
- the rhythm segments are aliased fragments of a continuing fast blink,
  consistent with the customer's "piscando rapido por 60s e para";
- the signature is not inside the recording (the board was still in the
  blink window when filming stopped); the `0100` in the filename is the
  owner's decode of the customer's longer take, and names
  `seed_drbg_blocking`'s park (`Reason::DrbgRefused`) — meaning the record
  draw's window **succeeded** first, and the very next draw's window
  refused. That marginality matches the 2026-11-09/10 measurements: the
  stall is attempt-dependent, not a hard wedge.

## Falsifiable predictions

1. **LED script of the failing unit:** ladder → (400 ms draw notice on a
   never-booted unit) → fast blink ≤ 60 s → **signature `0011`** → dark;
   or if the record draw succeeded: second blink ≤ 60 s → **`0100`** →
   dark. No USB at any point.
2. **Recovery:** unplug, wait ≥ 5 s, replug — VBUS removal is the
   2026-11-10 measured fix. A long-dwell episode may need several
   attempts (2026-11-10: repeated windows, reboots bought nothing); once
   ONE boot completes, record + hkey persist and the board is on the
   serve-while-warming path forever. The defect is strictly a
   **first-boot** defect.
3. **No tool ever sees either unit** — no `lsusb` entry, no PicoForge
   pairing — because the park is pre-USB.
4. **Host-side:** `boot_needs_legacy_bringup` on an empty store returns
   `true`; after one successful boot's writes it returns `false`. No host
   test pins this today (grep: the only call site is `main.rs:786`).

## Fix direction (not implemented here)

Finish what US-1822 planned: move the fresh-install construction draws out
of the pre-USB boot path.

- **Firmware:** the hkey draw (`device_app.rs:422/:593`) and
  `attestation::provision` (`:579`) become bring-up-task steps on the
  fresh arm — record → seed → hkey → attestation, in that order, behind
  the same Warming gate; `boot_needs_legacy_bringup` and both
  `*_blocking` sites die with the change. Fresh boards then take the
  provisioned posture: enumerate ~7 s, refuse creation-class operations
  (and PIN mint/salts) with the warming answer until Ready — the refusal
  classes US-1823/US-1826 already tabulate, extended to the fresh board.
- **Production (immediate, zero code):** QC at Robocore/production powers
  each unit once before sale. One completed boot writes record + hkey and
  permanently converts the unit to the safe path. A "pre-warmed at the
  factory" unit cannot reproduce this park, whatever the shelf dwell.
- **Customer-facing (interim):** the book's first-install row should say
  what this board actually does on day one: fast blink **up to ~2 min**
  (two windows) is *working*; a signature followed by darkness means
  *unplug 5 s, replug, repeat* — VBUS clears the episode.

## Residuals

- The video cannot confirm the signature bits or whether the record draw
  ran (the draw notice is not visible through the drift) — the `0100`
  filename carries that reading, and predictions 1–3 are checkable on the
  customer's units with one longer recording.
- `boot_needs_legacy_bringup` has no host test (prediction 4) — the
  discriminator that decides between "serving while warming" and "parking
  in the dark" is currently unpinned.
- The 2026-11-10 decode showed `sys_reset` clears nothing and only VBUS
  removal helps; this audit inherits that measurement unchanged.

## The reference boot sequences, decoded (2026-11-20)

Phase 2 of the debugging discipline: the two C/Rust firmwares that do not
dark-boot were traced completely — `../pico-fido` (C, `pico-keys-sdk`
vendored) and `../RS-Key` (Rust) — every entropy call site, wait loop and
park site read at file:line. Three structural differences, in increasing
order of actionability:

**1. pico-fido: there is no boot-blocking entropy acquisition at all.**
Its generator is pico-sdk's xoroshiro128** + TRNG re-mix into a 256-byte
ring buffer — **no DRBG object, no entropy record, no park state machine on
the RNG path**. The entire pre-USB entropy work is a bounded 32-iteration
mixer warm-up (`pico-keys-sdk/src/main.c:171` → `rng/random.c:27-33`,
sub-millisecond) plus a first-boot-only OTP MKEK/DEVK provisioning draw
(`otp/otp_rp2350.c:262-293`). Keys are either derived
(HKDF(otp_key_1, serial_hash) — `crypto_utils.c:34-42`, the deterministic
seal role) or **generated lazily on the first AID select over USB**
(`fido.c:393-511`). USB enumerates immediately after the bounded block
(`tusb_init`, `main.c:217`), and `hwrng_task` refills the pool
interleaved with `tud_task()` in one superloop (`main.c:133-145`) — a slow
TRNG throttles refill throughput instead of gating enumeration. Its wait
loops are unbounded-but-always-progressing spins (`random.c:57-72`) that
cannot emit a "give up" outcome; identity/OTP read failures are graceful
default arms (`serial.c:261-264`, `otp_rp2350.c:266-268`), and the only
hard park is a partition-table parse failure → BOOTSEL
(`low_flash.c:203-205`).

**2. RS-Key: they had our exact stall — and fixed it at the peripheral,
not the architecture.** Their whole pre-USB entropy path is one stateless
48-byte TRNG draw seeding an HMAC-DRBG (`firmware/src/main.rs:611` →
`handler.rs:63-67`); no persisted entropy record, no read-back gate. Their
driver's wait loop is embassy-rp's retry-forever soft-reset-on-autocorr-err
spin (`trng.rs:220-243`) — no timeout, no park. And the decisive fact:
`firmware/src/main.rs:601-609` carries `sample_count = 1000` with a comment
describing our failure mode verbatim — at the driver default 25, the NIST
autocorrelation health check failed, the hardware soft-reset and re-sampled
in a loop, and the 48-byte seed **blocked 30–105 s on every boot** on one
Waveshare RP2350 unit. Raising `sample_count` to 1000 decorrelates the ROSC
samples so the health check passes on the first generation: ~1.5 s boot,
hardware-verified, entropy quality unchanged (the health tests stay
enabled). USB attach is sequenced after the (now-bounded) entropy work by
a documented invariant (`main.rs:593-600`), and every boot-time identity
failure fails safe to a default arm — OTP fault → pre-OTP kbase
(`kdf.rs:86`), phy fault → default descriptors (`rsk-phy/lib.rs:411-427`).

**3. The park is uniquely ours.** Both references' worst case on the
entropy path is *wait* (pico-fido: throttle; RS-Key: wait inside the
driver) — neither has a "give up after 60 s" outcome, a blink-then-park,
or a pre-USB signature. Our `0011`/`0100` parks have no analog in either
tree.

**And the stress-test finding on our own driver**
(`platform/src/trng.rs`): we ship `TrngConfig::default()` =
`sample_cnt1: 25`, `rnd_src_sel: 1` (`trng.rs:276-286`) — **the exact
configuration RS-Key identified as the health-test-failure stall** — with
`MAX_ENTROPY_WAIT_MS = 20` calibrated to its ~2 ms datasheet average
(`trng.rs:225`, `:249-254`). Our own doc names the void
(`trng.rs:256-267`): the budget is only valid *for this configuration*, and
a health-test re-sample loop makes the hardware blow through it →
`TrngError::Stalled` on a **healthy** TRNG → the software retry loop →
the park. The dwell correlation in our measurements (stall after long
unpowered storage) is the same mechanism family as RS-Key's per-unit
finding: the autocorrelation health test failing while the ROSC/TRNG
analog state is unsettled. **The experiment this epic never ran is RS-Key's
fix**: raise `sample_cnt1` (they used 1000) and re-measure the cold-dwell
episode. If it collapses the settling from minutes to ~1.5 s, the warming
window becomes near-invisible on both arms — the serve-while-warming
architecture remains correct for the residual, but the user-visible wait
shrinks by two orders of magnitude. Budget interplay: at
`sample_cnt1: 1000` one 24-byte EHR block takes ~0.75 s (RS-Key's 48 B ≈
1.5 s), so `MAX_ENTROPY_WAIT_MS` must be re-sized together with the config
— our own "the budget is only valid for this configuration" rule, applied
to ourselves. Filed as US-1926 (EPIC `FRESH-BOOT-SERVE`), runnable
independently and early — it does not gate the architecture work and does
not gate on it.
