# ADR 0002 — The recovery policy for a fatal boot: refuse, and say so

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
