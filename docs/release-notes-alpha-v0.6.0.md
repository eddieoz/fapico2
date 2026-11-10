# fapico2-release-alpha-v0.6.0 — Release Notes

**Date:** 2026-11-11 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Theme:** the board stops guessing about its own randomness (PR
[#30](https://github.com/eddieoz/fapico2/pull/30), EPICs
`COLD-BOOT-ENTROPY-WINDOW` + `WARM-BOOT-SERVE`, US-1801..1834): a cold boot
used to draw from a TRNG that had not finished settling, and the firmware's
answer was a silent wait nobody could see. This release makes the entropy
state a first-class, observable, boot-owned resource — with hardware evidence
behind every reading.

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## The feature: entropy becomes a state machine, not a hope

The long-dwell episode (a board that dark-booted after days unplugged) was
decoded first ([the
audit](audits/2026-11-09-cold-boot-entropy-window.md)), and the finding was
structural: the boot path blocked on a freshness test the TRNG could not
satisfy yet, with no signal and no bound. The series replaces that with:

- **A 60 s deadline on every entropy draw** (US-1802) and a **bounded-reboot
  refusal decision** (US-1804) as a pure, testable core: an entropy site that
  cannot serve blinks a collision-tested rhythm (US-1803) and reboots on
  refusal — never parks silently (US-1806..1810).
- **The entropy bring-up state machine** (US-1822/1825): a dedicated task
  fills the pool; the boot path stops blocking on freshness. `LazyDrbg`
  (US-1824) seeds once, then serves; the legacy path's uninitialized cell is
  gone (US-1826 fallout).
- **Warming is observable**: a pollable entropy status over the shared config
  TLV (US-1827), quarantine refusals and a warming heartbeat (US-1826/1828),
  and the book's boot chapter now documents six post-boot readings including
  *reads-work-creation-waits* (US-1833/1834).
- **Refusals propagate to the ceremonies**: the clientPIN token mint and the
  persisted PIN salts refuse while Warming, and — the audit's A1 — the OTP
  custody ceremony refuses while Warming, because zero-entropy words must
  never reach an OTP burn.
- **Provisioned boards stop shipping an empty pool**: the FIDO pool fill is
  unconditional and tolerant, OATH's bring-up refill is capacity-based (the
  construction draw used to stretch the pool into 32 constant bytes that
  defeated `is_empty`).
- **The randomness consumer map is pinned as a test** (US-1821), and the
  hardware evidence is banked: the validation probe is turnkey, timestamped
  and film-correlatable (US-1831/1832), and the long-dwell finding is on the
  record — the bounded reboot ran exactly as designed; `sys_reset` does not
  clear the settle.

## Also in this release

- **Rescue WRITE has a presence gate — Shape A** (US-1759..1766): the rescue
  applet's WRITE now blocks for the press, with the timing variant pinned
  (US-1761), BDD scenarios red-first and green, and the full regression
  contract. The US-922 HID drain bug it surfaced (never served on the
  dual-serve loop) is fixed. **PicoForge classifies fapico2 out of the box**
  (US-1758, PF-FAPICO2), and the GUI-driven SAME-KEY proof closes the
  seed-restore story end to end.
- **Serial surfaces share one 26-bit value** (D-WB2): picoforge's CCID
  pairing works again — the two serial surfaces had drifted, and the
  divergence is documented so it cannot come back quietly.
- **CI: twelve jobs become five** ([the write-up](ci-evaluation-2026-11.md),
  PR [#31](https://github.com/eddieoz/fapico2/pull/31)): rust-cache and
  concurrency land on every job, `cargo-vet` stops compiling from source per
  push, the full 26-gate mutation harness leaves the branch-push path
  (nightly + main-push + dispatch), and `scripts/pre_push_check.sh` catches
  the flash-budget ratchet and the task-arena stamp locally — in two minutes
  instead of a twelve-minute CI round trip. The failure taxonomy behind it:
  four causes, each named with its run IDs.
- **Red-team round 3**: a working F4 exploit with CI proofs for F4/F8; the
  dead-imports sweep is pyflakes clean.

## Review record

The WARM-BOOT-SERVE [security
audit](audits/2026-11-10-warm-boot-serve-security-audit.md) verified the TRNG
chain end to end and
found the ceremony-warming gate (A1) before it shipped; the harness reviewer's
rounds covered COLD-BOOT-ENTROPY-WINDOW and RESCUE-WRITE-PRESENCE, and the
EPIC-wide review's follow-ups (the row-unfused bit reading the boot-owned OTP
slot, the throttled warming retries) are in the series. Residuals are recorded
in the audits rather than re-argued here: the long-dwell film slot stays open
pending correlation, and the session-banked claims in the hardware evidence
table are marked as session-banked.

**Full Changelog**: https://github.com/eddieoz/fapico2/compare/fapico2-release-alpha-v0.5.0...fapico2-release-alpha-v0.6.0
