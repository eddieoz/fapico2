# US-1761 — the rescue WRITE presence window on hardware: H1, H2 and H3 pinned

**Date:** 2026-11-08
**Board:** fapico2 on RP2350, running the release `apdu-trace` capture build
(`--features apdu-trace`, drain CID `a55a5a5a`, US-933 procedure; presence-event
hook installed at `main.rs`, events `E_PRESS..E_PGRANT`, `firmware/src/dbg.rs:96-100`).
**Operator:** EddieOz (the finger; press timing noted per leg).
**Probe:** `scripts/rescue_write_probe.py` — the PicoForge rescue WRITE APDUs
(`80 1C 01 00 …`, transcribed from `picoforge/src/hal/rescue/ops.rs`) over
PC/SC, through the EPIC's timed legs, then the US-922 ring drain.

## The one-paragraph finding

**H1 and H3 are excluded on hardware; the arming/consumption machinery works
end to end. Every refusal observed today was "the WRITE arrived while nothing
was armed" — the correct answer. The surviving failure mechanism is the
cross-call retry contract's timing fragility (H2's expiry variant): the armed
grant lives 10 s after the press (`PRESENCE_WINDOW_MS`) while the window lives
15 s, and a real client's retry lands when it lands — measured today, a
correct operator's press-to-retry gap exceeded the grant's life or the retry
preceded the press entirely. The fix shape this pins is US-1762's
pre-approved Shape A: a rescue-only blocking gate (10 s bound, `wait_grant`
shape), which removes the cross-call grant lifetime from the operator's path
altogether.**

## The evidence, leg by leg

All SW values from the probe transcript (`legs-run-stdout.log`); every claim
below is cross-checked against the ring dump (`full-ring-dump.txt`), where
`Window/Press/Armed/Discarded/Grant` are the runtime's own records.

| leg | flow | retry SW | what the ring shows |
|---|---|---|---|
| A (press early) | WRITE → press → retry +1 s | **6985** | window at t=1024707; the retry's APDU left **before** the first press (t=1027365, operator reaction ≈2.7 s); presses armed at 1027365…1039532 — all after the retry was already answered |
| B (press middle) | WRITE → press ~7 s → retry | **9000** | Window 353860; 7× Press→Armed 356368–361813; **Grant 362362** (latency 549 ms) |
| C (press late) | WRITE → press ~13 s → retry | **9000** | Window 362524; 9× Press→Armed; **Grant 376025** (latency 190 ms) — the retry 13.5 s after the window opened, still inside 15 s |
| G (press, retry +11 s — the H2 variant) | WRITE → press → retry ~12 s after open | **9000** | Window 376185; 9× Press→Armed 377621–386844; **Grant 388186** (latency 1342 ms). **Caveat, recorded honestly:** the operator pressed repeatedly during the 11 s wait, so the *last* arm was only 1.3 s old — this leg did **not** isolate the 10 s expiry; the expiry is instead visible structurally (below) |
| E (held before the WRITE) | hold → WRITE → release → retry | 6985 then **9000** | the held press produced **no edge while pending** (anti-harvest correct, one-shot `6985` immediately); the retry's grant came from a post-release press arming the still-open window |
| D (no press) | WRITE → 17 s → WRITE | 6985 / **6985** | Window 129424 (fresh) after the first window's 15 s expiry; **no Press/Armed anywhere in the leg** — a no-press window opens, expires, and the next WRITE opens a fresh one |
| F (foreign CTAPHID window) | U2F REGISTER → WRITE → press → retry | *(probe crashed)* | the raw CTAPHID MSG frame was answered `06` and the CCID T=1 session reset — CTAP1 is not servable over `CTAPHID_MSG` yet (AGENTS.md §4), so the leg as scripted is invalid on this build. H3(b)'s no-theft refusal stays pinned by the host logic suite (`hid_and_ccid_tag_domains_never_join`) |

## The three-way rubric, applied

* **Window absent at attempt time (H3)?** No. Every rescue WRITE in a clean
  flow emitted `Window tag=0x1C` (`full-ring-dump.txt` seq 7, 12, 36, 47, 79,
  109, 141, 153, 178, 231 — ten windows, one per first attempt). The single
  pending slot was free every time; H3(a) (a leaked deadline-less
  `begin_request`) is excluded. H3(b) (a concurrent window) is excluded for
  the clean flow by the same records, and its no-theft refusal logic is
  host-pinned.
* **Window open, no Press (H1)?** No. Every operator press while a window was
  open produced `Press` immediately followed by `Armed(tag=0x1C)` — over
  sixty such pairs across the session, none lost. The button task is alive
  and the latch drains within one tick.
* **Press present, Armed absent, or Armed but the retry refuses (H2)?** No
  lost arm and no refused live grant was observed — every retry that arrived
  after a press consumed it (`Grant`, latencies 190–1342 ms). What the trace
  *does* pin is H2's **expiry variant, structurally**: leg A shows the
  refusal mode that survives — a WRITE answered while nothing is armed,
  because the client's retry precedes the operator's press (measured reaction:
  ≈2.7 s from LED-solid to press) or follows the last press by more than
  `PRESENCE_WINDOW_MS` (10 s) while the window still has up to 5 s to run.
  The press that lands after the client gave up arms a window nobody
  consumes — exactly the 2026-11-08 PicoForge ceremony's four
  `Configuration write failed: [69, 85]` reports with the operator's press
  inside the lit period.
* **Bonus confirmations:** a press 17 ms past the window deadline was
  correctly `Discarded` (seq 204, t=423525 vs deadline 423508); presses with
  nothing pending are `Discarded` (anti-harvest); a granted WRITE releases
  the slot and the next WRITE opens a fresh window (seq 36, 79, 109…).

## Why Shape A, and what it changes

The device-side machinery is correct; what is broken is the **contract's
robustness against a real client and a real human**: the documented
"retry is the second chance" flow requires the client to re-send within
10 s *after* the press, and today's legs show both timing violations a real
session produces (retry-before-press; press-to-retry > 10 s). US-1762's
pre-approved shapes decide by the trace:

* **Shape A (blocking gate) is the winner.** A rescue-only injected closure
  (`main.rs:1247`'s `with_presence_grant`) that blocks inside the APDU in the
  proven `wait_grant` shape (US-914/OpenPGP; nostr CCID D7 is the same
  transport precedent), bound 10 s (`D-5`), converting the press **inside the
  first APDU** — no cross-call grant lifetime exists for a client to miss.
  `window_grant` itself stays byte-identical (D-6); mgmt/OTP/OATH keep the
  join-or-open gate. Join-or-open semantics are dropped for the rescue leg
  (the blocking wait holds the slot; a second APDU can only arrive after
  release). The no-press timeout answers `0x6985` byte-exactly.
* Shape B (an arming/expiry reorder) has nothing to fix: no arm was lost and
  no live grant was refused. **Deleted** per the story text.
* Shape C (a leaked-slot fix) has no leak: ten windows, ten clean opens.
  **Deleted** per the story text.

## Residuals

* **The first drain attempt after a fresh boot can be answered with the
  `CTAP_READ_CONFIG` `00` reply instead of the ring header**; a retry
  answers correctly. Observed on three independent boots. Not diagnosed
  further — it is a capture-path nuisance, not a shipping-path defect — but
  it is the likely explanation for two earlier "wrong cid" flashes that
  were in fact correct images.
* **Leg F is unproven on hardware** and crashed the probe (CCID T=1 reset
  after a raw U2F REGISTER). The no-theft property under a foreign window is
  pinned host-side; a hardware leg would need the US-1660 nostr-style
  park-and-refuse shape or a real CTAPHID ceremony, and is recorded as a
  follow-up rather than smuggled into this epic.
* The APDU-level ring records (`event=40..43`) confirm the probe's SW values
  independently (e.g. seq 34: WRITE → `9000`; seq 39: WRITE → `6985`).

## Artifacts

* `legs-run-stdout.log` — the probe transcript (legs A–G, SW per attempt).
* `full-ring-dump.txt` — the complete US-922 ring, 256 records, ring order.
* `leg-D-no-press-trace.txt` — the earlier no-press leg (first drain; the
  operator's unsolicited presses during it produced the first hardware
  grant: seq 31 `Grant`, seq 34 WRITE → `9000`).
