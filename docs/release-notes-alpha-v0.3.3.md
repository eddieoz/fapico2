# fapico2-release-alpha-v0.3.3 — Release Notes

**Date:** 2026-10-31 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Theme:** the second entropy site (PR
[#23](https://github.com/eddieoz/fapico2/pull/23)) — the dark-boot fix of
v0.3.2 moved the finish line, and this release closes the race behind it.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## What changed

### The DRBG seed draw now retries, like every other boot-fatal entropy site

Four hours into v0.3.2's life, a board that had been unplugged for a while
refused to boot again — with a *different* fatal signature. The incident
([audit §7](audits/2026-10-31-boot-dark-trng-refused.md)) decoded from video:
10 ladder pulses (store mounted, intact), **no** draw notice, then signature
`0100` = **`DrbgRefused`** — a site one step past the one v0.3.2 fixed.

The mechanism: guaranteeing the store's entropy record is not the boot's only
touch of the hardware TRNG. The DRBG's seed (`FuseSeedSource::seed`) draws
its own 32-byte fresh nonce from the same peripheral — single-shot, fatal on
one missed 20 ms-per-block budget. On an established store that record draw
is skipped entirely, so this seed draw was the boot's first fatal-eligible
roll of the dice — and a cold power episode (the long-unplug trigger) is
exactly where this board's peripherals draw marginally, the same settling
behaviour its OTP reads already exhibit (errata E16 precedent). v0.3.2's fix
removed site one; this release removes site two by the same treatment:
`init_drbg` retries the whole seed construction on the stepped `otp_retry`
budget (250 ms steps, 20 s). Each attempt takes a **fresh** peripheral draw;
the deterministic derivation re-runs per attempt, so success changes no seed
content.

With this, **every entropy site that can park the boot is retried.** The
remaining peripheral draws refuse their *request*, not the boot, by design:
the non-fatal sanity draw, the migration nonce inside a management request,
and DRBG re-seeds inside requests (S10 degrade, never halt). A systematic
audit of all `fatal_boot` sites against the TRNG consumer inventory confirmed
no un-retried boot-fatal draw remains.

## Upgrading from v0.3.2

**Reflash.** v0.3.2 has a known residual dark-boot mode: after the board has
been unplugged for a while, a cold boot could park with LED signature `0100`
(reason 4 — the same power-cycle-recoverable refusal as `0011`, one site
later). v0.3.3 removes it. No data-format change, no storage migration —
flash and go; credentials, PIN and identities are untouched.

Reading the LED is unchanged from
[v0.3.2](release-notes-alpha-v0.3.2.md) and the
[troubleshooting chapter](../book/troubleshooting/index.md): the book's
reason table now covers `0100` and notes it is power-cycle recoverable.

## Verification

All twelve CI checks green on the exact content this tag names, including
both clippy gates (`-D warnings`), the full host suite, the emulator suites,
the six structural gates, cargo-deny/cargo-vet, and the device-integration
gate (boot chain 93,764 B ≤ 98,304 B; task-arena demand re-measured and
re-stamped, per-task sizes unchanged). The boot-path audit (all
`fatal_boot` sites × all TRNG consumers) is recorded in
[audit §7](audits/2026-10-31-boot-dark-trng-refused.md). Hardware leg
pending the next session: a cold boot that previously produced `0100`
should now either boot or — worst case — emit `0100` ~20 s later.
