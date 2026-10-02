# WebAuthn / passkey discovery — hardware baseline

Task **US-1501**. Measured on a physical fapico2 board over the CTAP FIDO
interface. Produced by `scripts/probe_webauthn_discovery.py`, which is
committed alongside this file and is repeatable and non-interactive for parts
(a), (b) and (c).

**No debugger was attached, the board was not reflashed, no management factory
reset was sent, BOOTSEL was not triggered and the rescue applet was not
entered.** The probe is read-and-CBOR against `/dev/hidraw10` only. The board
was left answering: the run ends with a clean `CTAPHID_INIT` + `CTAPHID_PING`
round-trip, recorded in *Final state* below.

## Board under test

| field | value | how it was read |
|---|---|---|
| `idVendor:idProduct` | `1050:0407` | `lsusb`, and the `HID_ID` in the hidraw node's `uevent` |
| `manufacturer` | `EddieOz` | USB descriptor string `iManufacturer` (`lsusb -v`) |
| `product` | `Fapico2` | USB descriptor string `iProduct` (`lsusb -v`) |
| `serial` | `94746395` | USB descriptor string `iSerial` (`lsusb -v`); matches `HID_UNIQ` in `/sys/class/hidraw/hidraw10/device/uevent` |
| `bcdDevice` | `0x10` → `0010` | `lsusb -v`, `bcdDevice 0.10` |
| FIDO interface | `/dev/hidraw10` | `fido2.hid.list_descriptors()`, the node whose report descriptor is usage page `0xF1D0` |
| CTAPHID firmware version | **5.4.0** | `CTAPHID_INIT` reply bytes 13..15 |
| `capFlags` (INIT byte 16) | **0x04** | `CTAPHID_INIT` reply byte 16 — see finding **F1** |

Note the `lsusb` summary line renders the *default* VID/PID string
(`Yubico.com Yubikey 4/5 OTP+U2F+CCID`); the actual identity strings in the
descriptor are `EddieOz` / `Fapico2`, as the table shows.

The board runs firmware **older than the tip of this branch**. `capFlags` is
`0x04` on the wire; commit `63e2bcf` ("fix(US-1507): capFlags 0x05") is what
changes it to `0x05`, and it is already in this branch's history. Per the task
brief the board was deliberately not reflashed, so it still carries the old
byte. Every other number below is a property of the shipped firmware and is
unaffected; **F1** is the exception and is called out as such.

### Dialect note (read before re-running)

This firmware speaks the `python-fido2` 2.2.1 dialect, so
`authenticatorGetInfo` is CTAP2 opcode **`0x04`**, not the CTAP 2.1 spec's
`0x03` (AGENTS.md §2). Probing `0x03` returns `INVALID_COMMAND` and makes a
healthy device look broken. The frame command is `TYPE_INIT | CBOR` = `0x90`.

---

## (a) Cold-boot `CTAPHID_INIT` + `authenticatorGetInfo` latency

Command:

```bash
/home/eddieoz/Projects/git/pico/pico-fido2/.test-venv/bin/python \
    scripts/probe_webauthn_discovery.py --unanswered-observe 3.0
```

Date: **2026-10-02**, 12:20:08 +0300 to 12:21:10 +0300.

### (a1) `CTAPHID_INIT` on the broadcast channel

Frame command `0x06`, 8-byte nonce, sent on `[FF FF FF FF]`. Latency is
send → arrival of the reply's first byte.

| sample | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| latency (ms) | 11.9 | 2.7 | 7.9 | 8.0 | 8.0 |

- **min 2.7 ms, median 8.0 ms, max 11.9 ms** (n=5, same process).
- A second, independent process invocation measured 11.0 ms for its first
  sample. The 8 ms floor is the USB interrupt-IN polling interval.

Raw INIT reply payload (17 bytes), from the run above:

```
3e1eb0085cf16b600000003f0205040004
```

Decoded per CTAPHID §11.2.1.1 (nonce 8, CID 4, interface 1, version 3, capFlags 1):

| byte(s) | value | meaning |
|---|---|---|
| 0..7 | `3e1eb0085cf16b60` | nonce, **echoed correctly** |
| 8..11 | `0000003f` | allocated channel ID |
| 12 | `02` | CTAPHID protocol version 2 |
| 13..15 | `05 04 00` | **YubiKey firmware version 5.4.0** |
| 16 | **`04`** | **capFlags** |

#### capFlags decoded under both bit conventions

Two incompatible assignments for this one byte are live at once, and they
disagree about what `0x04` means:

| bit | CTAP 2.1 spec §11.2.1.1 | de-facto (`pico-keys-sdk`, Yubico `fido2` `CAPABILITY`) |
|---|---|---|
| `0x01` | **CBOR** | **WINK** |
| `0x02` | NMSG | LOCK (unused) |
| `0x04` | **WINK** | **CBOR** |

For the measured `capFlags = 0x04`:

- **SPEC convention: CBOR = NO**, NMSG = no, WINK = yes.
  → *A spec-reading host concludes this device has no CTAP2 support.*
- **DE-FACTO convention: CBOR = yes**, WINK = no, LOCK = no, NMSG = no.
  → *A `fido2`-library host concludes CTAP2 is supported — and is right.*

**CBOR is therefore supported under exactly one of the two conventions.** The
device serves CTAP2 perfectly well; the byte simply fails to say so to a
spec-conforming reader. This is finding **F1** and is the most likely direct
cause of the reported symptom.

### (a2) `authenticatorGetInfo`

CTAP2 opcode `0x04`, frame `0x90`, on the channel from (a1).

- **Latency: 74.1 ms** in the run above (a second invocation measured 96.7 ms).
  The response is a 527-byte body spanning 10 HID packets, so this is the
  first-packet latency, not a whole-response time.
- CTAP2 status byte `0x00` (SUCCESS); the body is 527 bytes.

`versions` (getInfo key 1):
`['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']`
`maxMsgSize` (key 5): `7609`

`options` (getInfo key 4) as decoded:

```python
{'rk': True, 'alwaysUv': False, 'credMgmt': True, 'authnrCfg': True,
 'clientPin': True, 'largeBlobs': True, 'pinUvAuthToken': True,
 'setMinPINLength': True, 'makeCredUvNotRqd': True,
 'enterpriseAttestation': True}
```

The four the brief asks about, read from that map:

| requested | value | how it is spelled in this getInfo |
|---|---|---|
| `clientPin` | **supported (True)** | option id `0x06` |
| `pinUvAuthToken` | **supported (True)** | option id `0x0C` |
| `uv` | **`alwaysUv` = False**, `makeCredUvNotRqd` = True | ids `0x03` / `0x0E`; there is no option literally named `uv` |
| `up` | **not an option id in CTAP2** | user presence is implied; there is no `up` key to read |

The library cross-check in the script (`fido2.hid.CtapHidDevice` on the same
descriptor) independently read `capabilities=0x04`, `version=2`,
`device_version=(5, 4, 0)` — agreeing with the hand-rolled framing.

---

## (b) The consent-window blackout

Sequence per run, on one open channel, with **the button never touched**:

1. Send `MakeCredential` (CTAP2 `0x01`, frame `0x90`) for the throwaway RP id
   `baseline-probe.invalid`, with `options: {uv: false}`.
2. Without touching the button, immediately send a `CTAPHID_INIT` (`0x06`) on
   the **broadcast** channel and a `CTAPHID_PING` (`0x01`) on the **open**
   channel. Run 2 additionally sends `CTAPHID_CANCEL` (`0x11`).
3. Observe for the full window. The probe declares a frame unanswered after
   `--unanswered-observe` seconds of silence (3.0 s here) but keeps reading
   until the window actually expires, so the "unanswered for N s" figure is
   bounded by the window rather than by when the probe stopped looking.
4. Record what the `MakeCredential` finally gets back, and the total wall time.
5. Repeat once, for reproducibility and variance.

### Results — run 1 and run 2, and a second independent process invocation

| | run 1 | run 2 | 2nd process, run 1 / run 2 |
|---|---|---|---|
| MC final reply (wall) | **30.11 s** | **30.11 s** | 30.11 s / 30.11 s |
| MC final CTAP2 status | `0x3B` `UP_REQUIRED` | `0x3B` `UP_REQUIRED` | `0x3B` / `0x3B` |
| keepalives during window | 301 | 301 | 301 / 301 |
| broadcast `INIT` written? | **yes**, 7.7 ms | **yes**, 7.8 ms | yes 7.1 ms / yes 7.6 ms |
| broadcast `INIT` answered? | **NO** | **NO** | **NO** / **NO** |
| open-channel `PING` written? | **NO** — write blocked | **NO** — write blocked | **NO** / **NO** |
| open-channel `PING` answered? | **NO** | **NO** | **NO** / **NO** |
| `CANCEL` (run 2 only) written? | — | **NO** — write blocked | — / **NO** |
| `CANCEL` answered during window? | — | **NO** | — / **NO** |

- **Neither the broadcast `INIT` nor the open-channel `PING` is answered, for
  the whole 30.11 s window.** Both runs, and both runs of a second independent
  process, agree to within 10 ms. **The epic's prediction is confirmed.**
- The broadcast `INIT` reply does eventually arrive, but only **after** the
  window closes: `+30080.4 ms` after it was sent (`+30120.1 ms` after the MC),
  i.e. ~7 ms after the `UP_REQUIRED` reply went out. It is not lost, it is
  queued behind a single-tasked command loop.
- The `MakeCredential` gets `0x3B` `UP_REQUIRED` at 30.11 s — a clean,
  spec-shaped "the user did not touch the button in time".
- The keepalive stream is unbroken: 301 frames of status `0x02`
  (`UP_NEEDED`) at 10 Hz across 29.97 s. **The device is alive and talking
  the entire time it is ignoring everything else.** This is the crux of the
  discovery problem: from a browser's point of view the key is neither
  responsive nor absent, and it fails differently depending on timing.

### The `PING` and `CANCEL` writes never completed — this is a distinct, stronger failure

`CTAPHID_PING` and `CTAPHID_CANCEL` could not even be **written** during the
window. The write blocked and was abandoned at its 3 s deadline:

```
open-channel PING  NEVER WRITTEN — the write blocked and gave up after its 3.0 s deadline: [Errno 110] Connection timed out
CTAPHID_CANCEL     NEVER WRITTEN — the write blocked and gave up after its 3.0 s deadline: [Errno 110] Connection timed out
```

The one `INIT` that did get written (7.7 ms) went into a buffer the device
never drained. So the measured behaviour is worse than "the device reads the
request and ignores it": during the consent window **the device does not read
the HID OUT endpoint at all**, the kernel's output buffer fills, and the
*host* blocks. A real browser that tries to cancel, re-negotiate, or fall back
to a second authenticator during those 30 s will block on the write, not just
fail to get a reply. Probe writes are serialised on the fd so this is the
device's behaviour and not two threads interleaving reports.

---

## (c) `CTAPHID_CANCEL`

Frame command **`0x11`**, sent on the open channel with a zero-byte payload.

### (c1) With no consent window open

```
sent CTAPHID_CANCEL frame cmd 0x11 on channel 0000003f, 0-byte payload
reply: cmd=0x3F len=1 latency=12.3 ms
```

Raw reply frame (full 64-byte report):

```
0000003fbf0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Decoded: channel `0000003f`, command `0x3F` (`CTAPHID_ERROR`), length `0x0001`,
error byte `0x01` (`INVALID_CMD`).

**The verified source state is confirmed on the wire.** `0x11` has no dispatch
arm and falls through to the `else` at `firmware/src/tasks.rs:983`, answering
`CTAPHID_ERROR` / `INVALID_CMD`.

**This is not the correct answer.** CTAPHID §11.2.9 requires a zero-length
`0x11` frame. Latency 12.3 ms (and 11.9 / 12.5 ms in other runs).

### (c2) While a consent window is open

**Not answerable — the frame could not be delivered.** See part (b): during the
window the `CANCEL` write blocked and timed out with `ETIMEDOUT` after its
3 s deadline, in every run. It was never placed on the wire, so there is no
reply to record and none is claimed here.

Consequence worth stating plainly: because the device is not reading the OUT
endpoint during the window, `CTAPHID_CANCEL` — the one CTAPHID command whose
entire purpose is to abort a pending operation — **cannot reach the device at
all**. Even if a dispatch arm for `0x11` were added, the abort would still not
arrive. That is a transport-level problem underneath the missing-arm problem,
and fixing only the dispatch arm would not fix cancellation.

---

## (d) The deliberate touch / BOOTSEL press

**NOT MEASURED — requires human.**

No finger was placed on the board, nothing was simulated, and no number is
reported here. A script cannot press a physical button and a synthesised
result would be worse than no result.

### Procedure for a human

The board under test is already attached and verified. Do **not** attach an SWD
debugger (AGENTS.md: it makes `OTP_DATA_RAW` read `0xFFFFFFFF` and `fatal_boot`
fires before USB is constructed). Do not reflash, do not send a management
factory reset.

1. Make sure nothing else holds the FIDO interface. Yubico Authenticator and
   `ykman` take an exclusive handle on the reader; with one open, other tools
   fail. Quit them first.
2. Record the start state:
   ```bash
   lsusb | grep 1050:0407
   ```
   Confirm `1050:0407` and that `/dev/hidraw10` is the FIDO node.
3. Run the probe up to the point where the consent window opens. Part (b) does
   this automatically and then waits 30 s without pressing anything. Leave it
   running:
   ```bash
   /home/eddieoz/Projects/git/pico/pico-fido2/.test-venv/bin/python \
       scripts/probe_webauthn_discovery.py --unanswered-observe 3.0
   ```
4. Within ~1 s of the line
   `+NN ms  KEEPALIVE status=0x02 (UP_NEEDED) — consent window opening`,
   **press and hold the physical button on the board.** The prompt (LED) is lit
   at that point; that is the cue.
5. Record, from the probe output:
   - whether the press was seen at all (the only observable is whether the MC
     final reply changes);
   - the CTAP2 status byte of the `MakeCredential` final reply — `0x00`
     (SUCCESS) if the grant landed, still `0x3B` `UP_REQUIRED` if it did not;
   - the total wall time from MC send to final reply. **A press that lands
     should end the window early, so a total well under 30.11 s is the signal
     that presence was granted**;
   - whether a credential for RP id `baseline-probe.invalid` was created. If it
     was, it is disposable and identifiable by that RP id; it can be removed
     with the authenticator's own credential management.
6. Repeat three times to separate "the press works" from "it worked once".
7. Confirm the board is left answerable: the script's `FINAL STATE CHECK`
   section must show a broadcast `INIT` and a `PING` both answered.

**Optional extra — the real browser symptom.** With the button-press path
working, open a site that does *not* currently offer the key as a passkey
provider and check whether it appears. That is the end-to-end confirmation
that F1 (below) is what browsers are keying off, and it is the only test that
distinguishes "the byte says no CTAP2" from "something else says no".

---

## Final state

The device was left in a normal, answerable state. Recorded at the end of the
run, on a freshly allocated channel:

```
broadcast INIT: answered in 10.5 ms, payload 197c79f4b886159d000000470205040004
    nonce match=True  capFlags=0x04  fw=5.4.0
PING on the fresh channel: answered in 15.9 ms, echo 55532d313530312d66696e616c (matches: True)
```

The script exits non-zero if this final round-trip fails.

---

## Findings

**F1 — `capFlags` is `0x04`, and that alone can hide the key from a
spec-reading browser.** INIT byte 16 reads `0x04` on the wire. Under the
CTAP 2.1 spec that bit means "WINK, and *not* CBOR"; under the de-facto
`fido2` convention it means "CBOR". So a host reading the spec concludes the
device has no CTAP2 and never offers it as a passkey authenticator, while a
host reading `fido2` finds CTAP2 works. The device is not broken; it is
**misdescribed**. This is exactly the "works on some sites, never offered on
others" shape of the reported symptom.

The fix is already in this branch: commit `63e2bcf` sets the byte to `0x05`,
which reads as CBOR + WINK under *both* conventions. The board measured here
predates that commit (`git show 63e2bcf -- firmware/src/tasks.rs` shows the
old line `inner[16] = 0x04; // capFlags: CBOR supported`), which is expected
under a brief that forbids reflashing. **Flashing `63e2bcf` and re-running this
script is the single highest-value next action**, and the re-run should show
`capFlags = 0x05`.

**F2 — During the 30 s consent window the device stops reading the HID OUT
endpoint entirely.** The `PING` and `CANCEL` writes *blocked* and timed out
(`ETIMEDOUT`); they were never delivered. The single-tasked consent loop in
`firmware/src/tasks.rs` only writes keepalives and never reads, so the OUT
buffer fills. Consequences: the host blocks rather than merely going
unanswered, and `CTAPHID_CANCEL` — the command whose only job is to abort a
pending operation — cannot reach the device at all.

**F3 — `CTAPHID_CANCEL` (`0x11`) has no dispatch arm.** With no window open it
answers `CTAPHID_ERROR` / `INVALID_CMD` (`0x3F` / `0x01`) in ~12 ms, where
CTAPHID §11.2.9 requires a zero-length `0x11` frame. Confirmed as predicted.
Note F2 is underneath this: adding the arm alone would not make cancellation
work, because the frame still cannot be written during a window.

**F4 — a PIN is set on this board, and it is not discoverable from `getInfo`.**
A `MakeCredential` with no `pinUvAuthParam` is answered `0x36`
(`PUAT_REQUIRED`) even though `getInfo` advertises `clientPin: true` and
`pinUvAuthToken: true` — those two say the authenticator *supports* the
options, not that a PIN is currently set, so this is not a contradiction in
the advertisement, but it does mean the probe must send `options: {uv: false}`
to reach the presence gate. Any future probe that omits it will measure a
rejection rather than the consent window, and will silently conclude there is
no blackout.

### A methodological note

Three bugs in the first draft of the probe each produced a confident, wrong
number, and all three are worth recording because they are easy to repeat:

1. **CTAP2 map keys were wrong.** Key 1 is `clientDataHash` (a 32-byte bstr),
   2 is `rp` (a map with an `"id"` key), 3 is `user`, 4 is
   `pubKeyCredParams`. Putting the RP id under key 1 yields `0x12`
   `INVALID_CBOR` before the presence gate is ever reached — a measurement of
   nothing that looks exactly like "the device ignored me".
2. **A CTAP2 response body starts with a status byte.** Decoding the `getInfo`
   body as CBOR from offset 0 silently yields a wrong map, because `0x00` is a
   valid CBOR integer and the following `0xa0` a valid empty map. The reported
   latency was 0.1 ms, against a frame log showing the reply ~480 ms later —
   the two disagreed, which is what exposed it.
3. **Latency must come from the frame's arrival timestamp**, not from how long
   the read loop was on the stack, or a reply already sitting in the event log
   reports as instant.
