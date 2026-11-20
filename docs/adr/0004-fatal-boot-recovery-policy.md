# ADR 0004 — The recovery policy for a fatal boot: refuse, and say so

- **Status:** Decided
- **Date:** 2026-10-01
- **Owner:** BOOT-FREEZE-POST-FLASH epic (US-1309; implemented by US-1310)
- **Supersedes:** —
- **Superseded by:** —
- **Governs:** `firmware/src/boot.rs::fatal_boot`, every pre-USB refusal site in
  `firmware/src/{boot,main}.rs`, and the reason ids in
  `firmware/src/fatal_sig.rs`.

---

## Context

The device has a failure mode with no recovery path. Every pre-USB refusal is a
`fatal_boot` — `defmt::error!` then `loop {}` — and there is no watchdog anywhere
in `firmware/`, `platform/` or `apps/`, so every park is permanent until VBUS is
removed. The panic handler is the same shape.

That makes one decision unavoidable and currently unmade: **when the OTP key row
cannot be read, what should the firmware do?**

The decision is forced into the open by a measured fact rather than a
hypothetical one. `SECURITY-ASSESSMENT-ROUND2.md` §22 (R2-26, reproduced on
hardware 2026-09-28) captured the OTP `SW_LOCK` registers over SWD on a core
halted in `fatal_boot`:

| register | healthy | after SWD access, **system** reset | after **power** cycle |
|---|---|---|---|
| `SW_LOCK[0]` | `0x05` | `0x0D` | `0x05` |
| `SW_LOCK[1]` | `0x04` | `0x0C` | `0x04` |

Every ECC read of rows `0xE90`–`0xE9F` then returns the all-ones sentinel.
`read_raw_word` maps exactly that value to `Err(Error::InvalidPermissions)`;
`read_otp_key_1()` treats any `Err` as "key absent" and returns `None`;
`derive_boot_store_key()` then calls `fatal_boot`. So a board in this state does
not come back from a reset — only from removing power.

Two properties of the code make the decision sharper:

1. The key is **bound to the hardware**. `boot.rs` states the reason for reading
   it at all as *"a leaked flash image does not decrypt on another board"*. The
   store key is not merely a secret; it is a device identity check.
2. A refusal is **not** currently distinguishable from any other refusal. A
   chipid refusal, a TRNG refusal, a refused DRBG seed and an OTP key-row refusal
   all presented as the same silent park.

---

## Options considered

### 1. Accept and signal — **CHOSEN**

Keep the refusal, and make it legible: a distinct LED signature per cause, plus
documented operator guidance ("power cycle after a BOOTSEL session or a debugger
attach").

*Cost:* zero security cost, zero new risk. It converts an inscrutable brick into
a diagnosable one. The device is still unavailable until someone unplugs it —
that is unchanged behaviour, honestly reported rather than hidden.

### 2. Fall back to a non-OTP store key

A device with an unreadable row boots with a fallback key.

**This weakens the hardware binding of the store key** — the exact property
`boot.rs` gives as the reason for reading OTP at all. A leaked flash image would
then decrypt on a board whose hardware identity could not be verified. That is a
security regression bought for availability, and per the epic's scope boundary it
would have to be chosen with that sentence attached, not as a side effect of a
freeze fix.

### 3. Detect the lock and distinguish it from an absent key

Sound in principle: treat only a genuinely absent key as unrecoverable, and let
a locked-but-present key through a different path.

**Not selected**, and the reason is a measurement rather than a preference: §22
found the escalation indistinguishable from a healthy read *at the register the
firmware can see*. The software has no bit that says "this row is locked" — it
sees `Err(InvalidPermissions)`, which is the same value a genuinely unprovisioned
row returns. So option 3 may not be separable in practice from option 1, and
shipping it would mean shipping a distinction the hardware does not offer.

---

## Decision

**Option 1, decided 2026-10-01.**

The firmware refuses to serve when it cannot read its hardware identity, and it
says so on the LED before parking. No fallback key. No lock/absence
distinction.

Concretely:

- `fatal_boot` takes a `fatal_sig::Reason` and emits that reason's LED signature
  before parking (US-1306). The OTP key-row refusal is its own reason — id 1 —
  distinct from the chipid, TRNG, DRBG, untrusted-image, persist, backend,
  keystore, migration and panic refusals.
- The signature is emitted **once** and the board parks. No watchdog (US-1311,
  which refuses one with its reasoning recorded).
- The store-key derivation is **unchanged**. No code path weakens the hardware
  binding.

## Consequences

**Accepted:**

- A device in the locked state stays unusable until its USB cable is removed.
  This is a real availability cost and it is the honest one: the alternative is
  serving with an unverified identity.
- The operator has to know that a power cycle is the fix. That guidance lives in
  `docs/boot-freeze.md` and the release notes (US-1312), not in a sign-off step
  they will skip.

**Rejected and recorded so they are not re-proposed:**

- A fallback store key (option 2) — a security regression, not a fix.
- Lock-vs-absent detection (option 3) — no register bit distinguishes them from
  where the software stands.

**Reversal cost:** if silicon evidence ever shows the lock state is readable,
option 3 becomes available and this ADR should be superseded, not edited.

---

## What this decision does NOT claim

US-1309 is a decision about **recovery policy**, and it rests on the §22
measurement of the locked mode. It does **not** rest on the freeze's *trigger*:
no board was available when this was written, so whether the freeze reproduces
with zero SWD involvement is US-1301, and US-1301 is **BLOCKED** — see the epic's
measurement block.

Choosing option 1 is safe under either answer. If the debugger is the trigger,
the policy is unchanged and the guidance ("do not attach a probe") is what
matters. If the freeze is a reset-property bug, the policy is likewise unchanged,
because the decision is about an unreadable key row rather than about how the
board got there. This is deliberate: the decision does not wait on the
measurement, and does not pretend to have preceded it.

---

## Amendment 2026-10-11 — the refusal is deadline-bounded, not single-shot

**Unchanged:** the decision. No fallback key, no lock/absence distinction, the
signature, the park, the watchdog refusal.

**New measurement** (2026-10-11, board with a pico-fido2 history — full record
in `docs/pico-fido2-to-fapico2-migration.md`): OTP reads fail *intermittently*
in the first seconds of a power episode, and the failing read migrated later
into boot across attempts — the key row one session (signature id 1), the
chipid the next (id 2, at the rung-6 window) — which is what a slowly settling
read-voltage rail looks like from a series of fixed read sites (errata E16's
shape). The bootrom read the same rows cleanly later in the same power
episode; and 10 s of power-off did not reliably clear it, so the earlier
dwell guidance is not a dependable operator fix on this board.

**Refinement:** every boot-path OTP read (`read_otp_key_1`, `read_chipid`) is
retried on a 250 ms step within a 20 s budget (`firmware/src/otp_retry.rs`)
before its caller degrades or emits its signature. This is option 1 with a
later giving-up point, not a new option: the device still refuses on a
genuinely unreadable row, still emits the same signature, still never serves
with an unverified identity — and §22's escalated-lock mode does not recover
by retry any more than by dwell, so it still parks, ~20 s later.

**Costs accepted:** up to ~20 s of silent boot before a refusal on a board
whose row is truly unreadable (documented in `docs/boot-freeze.md`); a
degrading site (the OATH region, the migration skips) spends its own budget
before degrading. A healthy board pays nothing — the first attempt succeeds.

**Structural alternative, recorded not chosen:** RS-Key (same A2 stepping)
never reads its key row at boot — `read_mkek` is handed to the applets and
called per operation ("Reading it late", `firmware/src/otp_keys.rs:36-47`) —
and tolerates a failed chipid read (`get_chipid().unwrap_or(0)`,
`firmware/src/main.rs:541`), so it structurally cannot hit these parks.
Moving fapico2's boot-time store-key derivation to that shape is a larger
architectural change than this fix needs; if the retry budget ever proves
insufficient on real boards, that is the direction, and this ADR should be
superseded for it.

## Amendment 2, 2026-10-11 — root cause of the intermittent id-1/id-2 parks: removed, not retried

The same-day retry amendment stood on a mechanism hypothesis that the evening's
A/B disproved and replaced:

- **With the retry alone**, the board parked again: the rung-6 chipid read
  failed ~80 consecutive times (20 s budget exhausted) in a boot whose rung-3
  chipid read had passed — so the failure was never a settling rail; something
  between rungs 3 and 6 broke page-0 reads dynamically.
- **The only OTP-controller register write in that window was this tree's own**
  `otp_hw_write_lock_key_row()` (the US-918/D-14 runtime `sw_lock` write at
  `main.rs`, immediately after the store-key derivation).
- **A/B, 2026-10-11:** shipping image (write in) parked reproducibly with
  signature id 2; `fapico2-nolockwrite.uf2` (write out) — 15 power cycles
  across timings, zero parks, and the operator's normal FIDO use in between.
- **The write is removed.** It was D-14's runtime-only half of a lock whose
  durable half never shipped; the residual it mitigated is the D-14 status
  quo, and the durable mitigation remains US-924. The retry
  (`firmware/src/otp_retry.rs`) stays: it is the belt under whichever read
  next proves marginal, and the earlier id-1 episode (one observation, at
  rung 3, *before* the write window) remains a single unexplained data point
  that only the retry covers.

Honest bookkeeping: the E16 "settling rail" narrative in this file's first
amendment and in `docs/pico-fido2-to-fapico2-migration.md` was the
best-supported hypothesis of its afternoon and is now **retracted** as the
cause of the recurring parks; the settling-read *observation* (bootrom reads
healthy later in the same episode) stands as data, unexplained. The
`otp_hw_write_lock_key_row` register model ("256 pages of 16 rows, one
register per 4 pages") also disagrees with both `pico-keys-sdk` and the RP2350
register map (64 pages of 64 rows, one register per page) — a reconciliation
that is now academic but belongs in any future reinstatement review.

---

## Amendment 3, 2026-11-09 — the transient-stall carve-out is exercised: the entropy sites reboot, bounded

**Unchanged:** the decision. No fallback key, no lock/absence distinction, the
signature, the park, the watchdog refusal. What changes is *where* the park is
reached, at exactly two sites, and why.

**The measurement** ([`docs/audits/2026-11-09-cold-boot-entropy-window.md`](../audits/2026-11-09-cold-boot-entropy-window.md)):
the first hardware data for the TRNG wait budget. A cold power episode (board
unconnected for a long time — the established trigger) settles the TRNG at
**≥ 20.4 s**: a recorded boot consumed the entire 20 s `otp_retry` budget
inside `init_drbg`'s TRNG nonce draw and the draw succeeded on the deadline's
final attempts. Three parked episodes (the 2026-10-31 `0011` and `0100`
incidents, plus the owner's repeated post-unplug failures) bound the same
phenomenon from the other side. A settling stall is a **transient hang mode —
one a reset actually clears** — the exact shape the watchdog refusal in
`docs/boot-freeze.md` wrote its carve-out for, and the exact shape an
immediate park turns into a brick only the owner's power cycle fixes.

**The carve-out, exercised narrowly.** A refusal at the two boot-entropy
sites (`ensure_boot_entropy`'s record draw, `init_drbg`'s DRBG seed nonce) no
longer parks on the spot: the board reboots (`SCB::sys_reset`) and re-rolls
the draw from the top of boot, bounded by a magic-guarded counter in a
`.retain (NOLOAD)` SRAM section (`firmware/src/entropy_reset.rs`,
`MAX_REFUSED_BOOTS = 3`). At the bound the board parks via the **same**
`fatal_boot(msg, reason)` path — signature `0011`/`0100`, emitted once,
permanent — so the park stays legible, which is this ADR's whole concern. The
counter clears only after `init_drbg` returns, the first point at which both
entropy sites have succeeded in one boot.

**Why this is not the watchdog, and not a reversal.** The refusal stands for
hangs a reset does *not* clear; the carve-out applies to one that does. The
mechanism is deliberately not a watchdog: it is a decision at the refusal
site, made with memory (`entropy_reset::decide`, pure and host-tested), so
the bound is reasoned about in one place rather than armed in boot-progress
feed points. The signature is still emitted exactly once — at the bound —
and never in the reboot loop, so the loop is legible as work (each rebooted
boot re-runs the ladder from the top) rather than as a stuck signal.

**Why the OTP sites keep the immediate park.** `read_otp_key_1` /
`read_chipid` refusals still park after their 20 s budget, blink-free and
without a reboot: they guard against §22's escalated `SW_LOCK` mode, which
the ADR's own measurement established recovers by neither retry nor dwell —
and a reboot re-runs the reads against the same locked rows. There is nothing
for a reset to re-roll. Their budget, their silence, and their park are
unchanged, and the reboot loop is scoped to `TrngRefused` and `DrbgRefused`
and to nothing else.

**The open question, answered by the hardware leg** (US-1813, 2026-11-10 —
decode in the audit doc's validation section): **`sys_reset` does not clear
the settling.** A long-dwell cold episode ran four ~63 s blinking windows
with three bounded reboots between them, and every window refused its whole
budget — the rebooted boots' windows were the same length as the first.
Only VBUS removal cleared the episode (the owner's power cycles). The
bound is therefore not an optimization but the load-bearing half of the
design: on this hardware the reboot buys re-rolls, not warmth, and the
third refused re-roll is what turns an interminable blink into a legible
park. This is exactly the case the bound exists for.

## Amendment 4, 2026-11-10 — the park domain shrinks to identity: freshness degrades, it does not park (WARM-BOOT-SERVE, US-1829)

**Decision:** entropy-*freshness* failures no longer park, and no longer
exist on the boot path at all. The boot completes to serving with the TRNG
unstarted-or-unverified; a background bring-up task warms the TRNG, draws
the boot-entropy record (if absent), seeds the DRBG cell and publishes
**Ready**. Until Ready, creation-class operations refuse with one honest,
pollable answer (`TAG_ENTROPY_STATE` in the shared config TLV, US-1827) —
*the randomness source is warming — retry* — while every deterministic
operation (assertions, PIN verification, OATH codes, OpenPGP/PIV signing)
serves. **Identity failures park as before**: `OtpKeyRow`/`ChipId`/store/
manifest refusals keep their budget, silence and immediate park. The
carve-out ADR 0004 amendment 3 made for entropy is superseded: freshness
degrades, identity parks.

**Citation.** The 2026-11-10 measurement (US-1813's consumer-map audit,
[`docs/audits/2026-11-09-cold-boot-entropy-window.md`](../audits/2026-11-09-cold-boot-entropy-window.md)
§6) proved the bounded reboot bought nothing: four refused windows across
three reboots, every window refusing its whole budget, `sys_reset` clearing
nothing — and, decisive for this amendment, **the board was one signature
away from fully functional**: OTP identity reads succeeded, the store
mounted, the ladder ran. The stall touches only *freshness* (the DRBG seed
nonce, the record draw) — and every serving-path operation a cold morning
needs is deterministic (US-1821's consumer map). Blocking USB enumeration
on freshness was spending the epic's most expensive currency — a dark
board — on the one failure the board can ride out.

**The interim design is deleted with honor.** The bounded-reboot machinery
(`entropy_reboot_or_park`, the `.retain` refusal counter, `MAX_REFUSED_BOOTS`)
was `COLD-BOOT-ENTROPY-WINDOW`'s answer, and the 2026-11-10 decode
(**US-1813**) is why it is superseded: the measurement showed the reboots
bought nothing, and the bring-up task's post-boot retry has no reboot to
re-roll *because there is nothing left to reboot past* — the board is
already serving. The task retries forever (no bound: a wedged TRNG keeps
the board Warming and serving deterministic operations; the owner's power
cycle is the recovery, and the pollable status says so). `entropy_reset.rs`
remains in the tree as the recorded decision arithmetic of the interim
design; its device-side callers are gone.

**Fresh installs keep a blocking boot, deliberately staged.** A fresh board
(record absent or hkey absent) runs the legacy inline sequence — same
budgets, same blink window, same legible park — because its construction
itself draws randomness (hkey, keystore, attestation). Deferring the
fresh-install serving story (a fresh board enumerating *warming* and
provisioning through PicoForge) is recorded in the epic as the follow-up;
US-1827's status TLV and the refusals are this amendment's whole wire
obligation to it today.

**The park domain after this amendment:** OTP rows, chipid, store mount,
manifest, keystore boot — identity and integrity. Not freshness. A cold
morning can no longer make the device invisible; it can only make it
wait for randomness, visibly, while serving everything deterministic.

## Amendment 5, 2026-11-19 — the retail incident: the fresh-install carve-out is the last freshness park, and it is the bug

*(Written as the record of the incident that forced amendment 6; the
policy change itself is amendment 6.)*

Two v0.7.0 boards bought at Robocore blinked fast ~60 s, stopped, and
never enumerated — a customer's first contact with the product was a
dark device. The diagnosis
([`docs/audits/2026-11-19-retail-first-boot-dark-park.md`](../audits/2026-11-19-retail-first-boot-dark-park.md))
pinned the exact path this file's amendment 4 deliberately kept: a
never-booted board takes `boot_needs_legacy_bringup == true` and runs
the pre-epic blocking bring-up **before USB**, and on a TRNG stalled by
a long-dwell cold episode the two 60 s budgets expire and the board
parks — signature `0011` (`TrngRefused`) then, on a later window,
`0100` (`DrbgRefused`). Warehouse + shelf storage is the longest dwell
a board ever experiences, and the hardware validation of
WARM-BOOT-SERVE (US-1831/1832) never covered a fresh install on a
stalled TRNG. The two Robocore units are that missing film.

## Amendment 6, 2026-11-20 — freshness failures never park at boot, on any arm (FRESH-BOOT-SERVE Phase 0, US-1929)

**Decision:** the fresh-install carve-out's parks are removed entirely.
`boot.rs::seed_drbg_blocking` and `boot.rs::ensure_boot_entropy_blocking`
— the two blocking sites amendment 4 retained "deliberately staged" for
first installs — now **re-arm their retry loop forever** at a budget
expiry: no `fatal_boot`, no signature, no give-up. A budget sizes one
step of the wait; it is not an outcome. Amendment 4's sentence "fresh
installs keep a blocking boot" survives as behaviour (the bring-up still
precedes enumeration on a fresh board), but its parks do not — the
carve-out's legibility obligation is discharged by the **progress
bursts** (US-1928: every 5 s of waiting adds one pulse naming the
waiting site by its on-time, 120 ms = record, 300 ms = seed), which is
what the park used to buy minus the dark board.

**The park domain is now identity plus clock-liveness, and nothing
else.** `TrngRefused`/`DrbgRefused` remain reachable only through the
TIMER0 clock-liveness parks in `main.rs` — a clock that is not counting
is infrastructure, not freshness, and keeps its signature. The halt-site
count moves 23 → 21 (`apps/fido/tests/region_degradation.rs`, delta
commented). Every identity park (`OtpKeyRow`/`ChipId`, the store key,
the OATH seal, the migrations) is untouched.

**Citations.** (1) The 2026-11-19 retail incident (amendment 5's
diagnosis): the park is the outcome the customer saw, and the outcome is
the bug. (2) The RS-Key finding: the reference firmware that had the
same stall fixed it at the peripheral layer
(`sample_count = 1000`, **48 B ≈ 1.5 s** measured, health check passing
on the first generation) and has **no** "give up" outcome on the entropy
path — neither has pico-fido. US-1927 adopts the measured-good tuning
and re-anchors the budget to the measurement; the hardware re-validation
of the tuned numbers is US-1926's owner-run decode (**measured pending**
— the 2026-11-09 ≥ 20.4 s settle and the 2026-11-10 > 4.4 min
four-window refusal are the stock-config baseline until then). (3) The
bounded-reboot machinery of amendment 3 was already unwired dead code
since US-1825; this amendment supersedes its mechanism permanently, and
`entropy_reset.rs` carries the superseded-mechanism note.

**The honest ceiling moves into the docs.** A warming wait can run
minutes (measured > 4.4 min on a long-dwell board at the stock
configuration); unplug/wait-5-s/replug is safe on a fresh board and is
the measured accelerator for a stalled episode. `docs/boot-freeze.md`
and the book's troubleshooting page own the reading tables; the v0.7.0
field-unit row (which still parks) stays live there, annotated, until
those units are reflashed or pre-warmed (US-1922's QC pre-warm).

## Amendment 7, 2026-11-20 — permanent seed refusals park again; the zero row is a supported boot state (US-1931/US-1932)

Amendment 6's symmetry held the domain on the assumption that every seed
refusal is freshness. The third field video (and the owner's own fresh-board
reproduction) broke that assumption: the retail boards were refusing
**permanently** — `derive_drbg_seed`'s migration-era `NeverBootC` guard fired
on the factory-zero OTP key row before the TRNG was ever touched — and
amendment 6's variant-erasing retry loop answered a permanent state fault
with a silent infinite blink where the pre-1929 code had parked legibly. A
park is not only the outcome being a bug; **losing the park on a permanent
fault is also a bug** — it is the difference between a diagnosable board and
a blinking one.

The domain is now three-way, classified by
`drbg_seed::refusal_is_freshness` (host-pinned):

* **Freshness** (`SeedError::Trng(_)`): re-arms forever, never parks —
  amendment 6 stands for exactly this class (US-1929).
* **Permanent seed-state faults** (`CKey`/`Store`/`DepletedBootEntropy`/
  `AlreadySeeded`): park with the existing `DrbgRefused` signature, on both
  arms (the legacy `seed_drbg_blocking` and the bring-up task). Halt sites
  21 → 23, delta recorded in `region_degradation.rs`. These are identity-
  domain faults that waiting cannot clear. *(US-1935 refinement: a fault in
  the record itself — the slot unreadable, the drawn record refused for
  persistence — parks at the record site under its own `EntropyRecord`
  signature, so the pin names the store-record fault instead of
  misattributing it to the seed; halt sites 23 → 25.)*
* **Identity and clock-liveness**: unchanged — and `NeverBootC` leaves the
  *seed* path entirely: the zero OTP row is a supported boot state (the
  documented `store_v3` residual; US-1030's argument), advertised by
  `ENTROPY_FLAG_ROW_UNFUSED`, and refusing it bricked every factory board.
  `derive_kbase`/`derive_kbase_c` keep the guard where migration semantics
  actually apply.

**Citations.** [`2026-11-20-retail-virgin-otp-row-brick.md`](../audits/2026-11-20-retail-virgin-otp-row-brick.md)
— three field units + the owner's A/B reproduction (pico-fido/RS-Key burn the
row on their own first boot; the same board then boots our firmware);
AGENTS.md §5 (the guard stopped no attack the record refusals and the fresh
draw do not already stop).
