# US-1503 — does a real button press complete a parked request, on real hardware?

**Verdict: yes.** A deliberate press of the button on board A landed the grant,
the parked `authenticatorClientPIN 0x06 / sub 0x06` request completed on its own
channel, **no other channel saw that answer**, and the board was left
answerable. The no-press control did not complete and ended on the window's own
30 s deadline.

Branch `fix/passkey-discovery`. Probe: `scripts/probe_us1503_press.py`.
Raw measurements: `docs/evidence/us1503/*.json`. No firmware was changed.

---

## 1. Which board, and how it was identified

Node numbers on this machine have moved more than once, so the probe selects by
**USB descriptor identity** and refuses to guess. `probe_ab_devices.py`'s
existing `enumerate_devices` / `pick` helpers are imported and reused; nothing
new was written for discovery. Re-read live at run time, not taken from any
earlier brief:

```
/dev/hidraw9     iManufacturer='EddieOz'         iSerial='94746395'          <- OURS
/dev/hidraw13    iManufacturer='Pol Henarejos'  iSerial='7C36644DFF8A74C7'   <- reference, never opened
```

**Ours was `/dev/hidraw9` during these runs** — consistent with the most recent
note in the story, but re-derived rather than assumed. `/dev/hidraw13` was the
pico-fido2 C reference; the probe enumerates it to print its identity and then
never opens its node.

## 2. What opens the window

`authenticatorClientPIN` — **CTAP2 opcode `0x06`** in the `python-fido2` 2.2.1
dialect this firmware deliberately speaks (AGENTS.md §2; the CTAP 2.1 spec's
`0x04` would be rejected here) — sub-command **`0x06`
`getPinUvAuthTokenUsingUvWithPermissions`**, permissions `mc`, with a real P-256
COSE key on a throwaway fixed point. That path needs only a touch, never a PIN
entry. `hid_serve.rs` lists `0x06` in `presence_windowed` and converts the
one-byte `UpRequired` (`0x3B`) into a parked `WindowTicket` plus a
`CTAP_TOUCH_WINDOW_MS` (30 s) keepalive window.

Sent payload, verbatim:

```
06a40102020603a5010203381820012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50904
```

No credential is created, moved or deleted. No PIN is set, changed or read. The
`pinUvAuthToken` that comes back is **never printed** — only its shape.

## 3. The three runs

All three: channel A carries the parked request, channel B is a second CTAPHID
channel used to generate competing traffic.

| | **press (labelled)** | **press, after competing traffic** | **control, no press** |
|---|---|---|---|
| channel A (parked) | `0x00000034` | `0x0000002e` | `0x00000031` |
| channel B | `0x00000035` | `0x0000002f` | `0x00000032` |
| answer on A | `0x00 CTAP2_OK` + `{2: bstr(48)}` | `0x00 CTAP2_OK` + `{2: bstr(48)}` | `0x2d CTAP2_ERR_KEEPALIVE_CANCEL` |
| **cue → grant** | **0.216 s** | **25.360 s** | n/a (no grant) |
| keepalives on A | 1 (`0x01`) | 100 (`0x01`,`0x02`) | 119 (`0x01`,`0x02`) |
| saw the answer on another channel | **no** | **no** | **no** |
| token minted on channel B | **no** | **no** | **no** |
| OUT write stalls | 0 | 0 | 0 |
| board left answerable | **yes** | **yes** | **yes** |

### Run A — the press (`docs/evidence/us1503/press-final.json`)

```
>>> PRESS AND HOLD THE BUTTON ON BOARD A NOW <<<
  >>> EddieOz / Fapico2 / serial 94746395 on /dev/hidraw9 <<<
  The window is 30 s long and is OPEN NOW.
...
ANSWER on channel A 0x00000034: status 0x00 (CTAP2_OK) + 2: bstr(48) [not printed]
cue -> answer: 0.216s (window had 30s)
```

The operator already had the button down when the window opened, so the grant
landed in 216 ms — faster than a re-drive pass, which is the expected shape for a
press that is already down. The parked request completed **on its original
channel A**, and every frame in the arm is logged, so "no other channel saw it"
is an observation over the full frame log rather than an assumption.

### Run B — the press, with competing traffic *already refused* (`press-after-competing-traffic.json`)

This is the run that actually exercises the anti-harvest rule. The grant landed
at t+25.360 s; every competing request had been written **and answered** more
than 24 s earlier:

```
t+0.108  MakeCredential on channel B   -> 0x24 CTAP2_ERR_OPERATION_PENDING
t+0.294  the same 0x06 on channel B    -> 0x24 CTAP2_ERR_OPERATION_PENDING
t+0.412  authenticatorGetInfo on B     -> 0x00 CTAP2_OK (non-windowed, still served)
t+0.588  PING on channel B              -> echoed
t+0.708  PING on channel A              -> echoed
t+25.360 ANSWER on channel A            -> 0x00 CTAP2_OK + {2: bstr(48)}
         seen on no other channel: YES
```

So the press satisfied **only** the parked request. The competing
`MakeCredential` and the competing `0x06` on channel B were refused, not queued
(US-1510 single-occupancy), no second window opened, no second token was minted,
and the bus stayed live on both channels throughout — neither the parked channel
nor the competing one was blacked out.

**Provenance note, stated plainly:** this run was *launched* as `--arm control`
and the operator tapped during it. The operator confirmed this when asked. It is
the press evidence for the anti-harvest property and it is filed under a name
that says so; the `arm` field inside the JSON still reads `control` because that
is literally what was invoked. Run C below is the genuine no-press control.

### Run C — the no-press control (`docs/evidence/us1503/control-no-press.json`)

Identical probe, nobody touching anything:

```
ANSWER on channel A 0x00000031: status 0x2d (CTAP2_ERR_KEEPALIVE_CANCEL)
cue -> answer: 30.032s (window had 30s)
KEEPALIVE frames on channel A: 119 ['0x01', '0x02']
The parked request's answer was seen on NO other channel: YES
Competing 0x06 on channel B: answered status 0x24 (CTAP2_ERR_OPERATION_PENDING)
board left answerable: YES
```

**It did not complete, and it ended on the window's own deadline** — 30.032 s
against `CTAP_TOUCH_WINDOW_MS = 30_000 ms`. `0x2D` is
`CTAP2_ERR_KEEPALIVE_CANCEL`, which `hid_serve.rs` sends at the close of an
unanswered CTAP2 window; the expired command is deliberately *not* re-driven one
last time, so a press landing on the closing tick cannot retroactively authorise
what the window already refused (US-921's rule in the time dimension).

Without this control, "the request completed" would prove nothing. With it, the
two arms differ in exactly one input — whether a finger was on the button.

## 4. Board left answerable

After every arm, a **fresh** CTAPHID INIT on broadcast plus a PING on the
newly-assigned channel, on a brand-new connection:

```
CTAPHID INIT on broadcast: OK, new channel 0x00000036
  reply: 83f0abb101876794000000360205040005
  bytes 13..15 (YubiKey firmware version, per AGENTS.md): 5.4.0
CTAPHID PING on 0x00000036: echo OK in 16.0 ms
```

Nothing is left parked. `CTAPHID_CANCEL` is written on the parked channel at the
end of each arm and drained for 2 s; no acknowledgement is owed and none is
claimed — the firmware answers a cancelled command's refusal, not an ack.

## 5. Findings that contradict earlier claims on this branch

These are the ones worth carrying forward.

1. **"During the consent window the device does not read the HID OUT endpoint
   at all, the kernel's output buffer fills, and the host blocks."**
   (`docs/webauthn-discovery-baseline.md`, US-1501.) **No longer true.** Every
   run above wrote five competing frames into a live window with **zero** write
   stalls and no `ETIMEDOUT`, and all five were answered in 23–300 ms. This is
   what US-1509's reworked serve loop buys: `read_one` is bounded at one
   `CTAP_KEEPALIVE_PERIOD_MS` while the slot is occupied, so the loop keeps
   asking the OUT endpoint instead of disappearing inside the consent wait. Any
   downstream reasoning that assumes a host blocks for 30 s — including the
   baseline doc's conclusion that `CTAPHID_CANCEL` "cannot reach the device at
   all" — no longer holds.

2. **A CTAPHID INIT written *into* a live window is slow; one written *before*
   it is not.** Measured 0.3–0.6 s for the in-window INIT versus **0.016 s** for
   the same INIT on an idle bus. The reason is the same bounded read: one
   message per serve pass while a window is occupied. The probe now allocates
   channel B *before* opening the window, which is what makes it possible to have
   competing traffic on the wire within ~110 ms of the window opening.

3. **Cross-channel traffic must be ordered by its WRITE, not by its round
   trip.** Four earlier press runs answered at t+0.216 s, t+1.032 s, t+1.688 s
   and t+2.856 s — faster than any "press after N seconds" cue could be relied
   on, and the first two of them landed *before* a step that waited for its own
   reply had even been written. The probe now fires each competing request as a
   write and resolves its reply out of the shared frame log afterwards, so the
   guarantee "all competing traffic is on the wire before the grant" is a
   property of the schedule rather than of the operator's reaction time.

## 6. Two harness defects found and fixed, worth recording

Both produced a run that looked like a valid result and was not. On a branch
where eleven prior claims inverted when executed rather than read, they are the
interesting part.

* **The cue never reached the operator.** The first press run was piped through
  `tail -60`, so the `>>> PRESS AND HOLD THE BUTTON <<<` banner was buffered and
  only appeared after the run ended. The operator pressed nothing, and the run
  came back `0x2d` at 30.080 s — byte-for-byte the shape of a control. Taken at
  face value that reads as "the press does not work". It proved nothing at all.
  `--lead-in` now opens with an explicit stand-by, and the instruction is to
  press for the whole window rather than to react to a banner.

* **`RawCtap._write` delegates to `connection.write_packet`, and the Linux
  backend prepends a report ID to every OUT write.** An override that called
  `os.write` directly dropped it. The symptom was diagnostic: CTAPHID INIT on
  broadcast still answered, because the reply's first CID byte gets eaten as the
  report ID — but the self-test PING on the assigned channel never echoed. INIT
  alone is not a sufficient framing test; that is why `RawCtap.selftest` exists.

## 7. Reproducing

```bash
PYTHON=/home/eddieoz/Projects/git/pico/pico-fido2/.test-venv/bin/python \
    scripts/probe_us1503_press.py --arm press --lead-in 25 --json out.json
PYTHON=... scripts/probe_us1503_press.py --arm control --json out.json
```

Exit codes: `0` every measurement observed, `1` an arm's outcome did not match
its expectation, `2` the board could not be identified by USB identity, `3` the
final INIT+PING failed.

## 8. Scope of this evidence

What this does **not** establish, and should not be read as establishing:

* It exercises **one** consent-window path — `clientPIN 0x06 / sub 0x06` — which
  was chosen because it needs only a touch. `MakeCredential` (0x01) and
  `GetAssertion` (0x02) are the browser paths and were exercised here only as
  *refused* cross-channel traffic, never as the parked request.
* Single operator, single press, on one board, on one day. 216 ms and 25.360 s
  are two samples of cue→grant, not a distribution.
* The board carries no credential created by this work; nothing was flashed,
  reset, or re-provisioned, so any regression in credential-bearing paths is
  outside what was touched.
* US-1503's premise is now satisfied: US-1509's parked slot is not merely a
  host-side story. A finger on real hardware is what releases it, and nothing
  else does.