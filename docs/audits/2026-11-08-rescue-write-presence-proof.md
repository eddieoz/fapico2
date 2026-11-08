# US-1766 — hardware re-ceremony: the config save that failed four times now passes in one attempt

**Date:** 2026-11-08
**Board:** fapico2 on RP2350, running the fixed firmware in the `apdu-trace`
capture build (release profile, `--features apdu-trace` — the shipping image
plus the US-922 trace ring; every US-1762 fix is in it). Reflashed to the
clean release image after the ceremony.
**Operator:** EddieOz — drove PicoForge and provided every press.
**Firmware lineage:** `fix/config-save` @ US-1762 (Shape A blocking rescue
gate, 10 s) + the US-922 drain restored on `serve_loop_dual`.

## The ceremony

The 2026-11-08 operation that this EPIC exists for — **PicoForge's
rescue-route configuration save** on the fapico2 board, the flow that
answered `Configuration write failed: [69, 85]` four times
(12:24:02, 12:26:59, 12:29:27, 12:30:31) with the operator's press inside
the lit period — was repeated with the fixed firmware:

**The save succeeded on the first attempt.** The operator ran the PicoForge
GUI config save, pressed BOOTSEL when the LED went solid, and PicoForge
reported success — no retry, no second manual attempt, no `[69, 85]`. The
operator's confirmation: *"I just tested the configuration save through
picoforge and it worked as intended."*

The presence-event trace records what the fix promised
(`final-ring-dump.txt`, seq 205/206):

```
seq=  205  t=  170678ms  Armed  tag=0x0000001C  b=170678
seq=  206  t=  170678ms  Grant  tag=0x0000001C  b=0
```

One press, armed under the rescue WRITE tag (`INS_WRITE` = 0x1C) and
consumed **inside the same APDU** — zero latency between arm and grant, and
**no `Window` event at all**: the blocking shape opens no cross-call window.
That pair is the PicoForge save. Under the old contract the same ceremony
produced a `Window`, a press that armed a window the client's retry had
already missed, and a final `6985`.

## The supporting legs (same session, same build)

* **Probe verification before the GUI run** — the PicoForge rescue WRITE
  APDUs over PC/SC: the WRITE blocked **2.4 s** for the operator's press and
  answered `9000` inside the same APDU; the written brightness round-trips
  through `READ PhyConfig` (`shape-a-first-press-trace.txt`: `Armed` +
  `Grant` back-to-back, no `Window`).
* **US-1765's matrix** ran on the same build (both transports, all four
  tier rows — see `docs/client-compatibility.md` and the EPIC's US-1765
  record). The FIDO-route benign leg's trace shows the other contract
  working as designed: `Window(0x8000_0013) → Press → Armed → Grant`
  (84 ms latency), the keepalive-windowed path.
* **Anti-harvest holds on the fixed build:** the two matrix attempts where
  no press landed answered `6985` after the full 10 s (the D-5 bound on the
  wire, never a transport abort), and a stray press with nothing pending was
  `Discarded` (seq 317/318).

## What changed, in one line each

* `button::rescue_wait_grant` — the rescue applet's gate is now the US-914
  blocking wait (10 s, `presence::RESCUE_WRITE_WAIT_MS`), replacing the
  join-or-open cross-call window whose retry timing no real client and no
  real operator could satisfy (US-1761's diagnosis).
* `serve_loop_dual` — the US-922 drain check restored on the FIDO arm
  (found during this epic; the capture drain had been dead on hardware
  since US-1660 while every host test stayed green).

## Residuals

* The board ran the **capture build** during the ceremony (release profile,
  trace ring attached); the clean release image was flashed back afterwards.
  The shipping image differs from the ceremony image only by the ring and
  the drain surface — both cfg'd out without the feature.
* The first drain attempt after a fresh boot can be answered by the
  `CTAP_READ_CONFIG` `00` reply (a retry answers correctly) — recorded in
  the US-1761 audit, unchanged here.
* The PicoForge session log excerpt for the successful save lives in the
  operator's PicoForge profile (`picoforge.log`); the trace record above is
  the device-side half of the same event, and the operator's statement is
  recorded verbatim as the client-side half.

## Verification record (EPIC §Verification record)

| field | value |
|---|---|
| date | 2026-11-08 |
| board | fapico2 RP2350, capture build @ US-1762 tip, then clean release reflashed |
| operator | EddieOz |
| ceremony | PicoForge rescue-route config save: **4 × `[69, 85]` (2026-11-08 morning) → 1 attempt, success** |
| device-side trace | seq 205/206: `Armed(0x1C) → Grant(0x1C)` at t=170678 ms, same millisecond, no `Window` |
| EPIC status | **Complete** — US-1759…US-1766 all executed; stories committed individually on `fix/config-save` |
