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

## Which runs back the numbers in this document

Two independent process invocations, **both with their full output retained**:

| | run id | window | archived output |
|---|---|---|---|
| process A | `ac058e1a-269c-4772-a1ae-7e32a5039f7f` | 2026-10-02 12:20:08 → 12:21:10 +0300 | `.superpowers/sdd/report-us1501-script-output.txt` |
| process B | `c8edac85-4077-4472-824c-e95465dea5cf` | 2026-10-02 12:37:53 → 12:38:56 +0300 | `.superpowers/sdd/report-us1501-script-output-run2.txt` |

(`.superpowers/` is gitignored, so those two files are local. Every figure in
this document is quoted from one of them, and the run id is printed in each
so a figure can be traced to its source. **There is no number in this
document from a run whose output was not kept** — an earlier draft had some,
and they have been removed or replaced.)

Each process ran part (b) twice, so part (b) has four backing runs in total.
Part (d) has none, by design: it requires a human and a finger.

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

Date: **2026-10-02**, process A 12:20:08 +0300, process B 12:37:53 +0300.

### (a1) `CTAPHID_INIT` on the broadcast channel

Frame command `0x06`, 8-byte nonce, sent on `[FF FF FF FF]`. Latency is
send → arrival of the reply's first byte. Five samples per process, first
sample first.

| sample | 1 | 2 | 3 | 4 | 5 | min | median | max |
|---|---|---|---|---|---|---|---|---|
| process A (`ac058e1a`) | 11.9 | 2.7 | 7.9 | 8.0 | 8.0 | **2.7** | **8.0** | **11.9** |
| process B (`c8edac85`) | 15.4 | 7.9 | 8.0 | 8.0 | 8.0 | **7.9** | **8.0** | **15.4** |

All ten samples, n=10 across both processes: **min 2.7 ms, median 8.0 ms,
max 15.4 ms.**

#### Observation

Four of five samples land on exactly 8.0 ms in *both* processes. The first
sample of each process is an outlier high (11.9 ms, 15.4 ms) — that is the
first frame a fresh process sends, so cold-start cost is the obvious
candidate. One sample in process A is an outlier low (2.7 ms), and it does
not repeat.

#### Open question — the earlier "8 ms floor" claim was not supported

An earlier draft of this file said "the 8 ms floor is the USB interrupt-IN
polling interval". Neither half of that survives the data, so it is recorded
here as a **hypothesis with an open question**, not as a result:

- **It is not a floor.** Process A recorded 2.7 ms, below 8.
- **The polling interval is not 8.** The FIDO interface (interface 1, which
  is `/dev/hidraw10`) declares `bInterval = 10` on its interrupt-IN endpoint
  `0x82` — `lsusb -v -d 1050:0407`. `bInterval` is a *maximum* service
  interval for the host, so it bounds latency from above; it does not fix a
  value, and it is 10, not 8.

Nothing in this run separates USB scheduling from the device's own
processing, so the exact 8.0 ms clustering is unexplained and left as such.
Measuring it needs a different experiment: many more idle `PING` samples
with a distribution rather than five values, compared against the same host's
other interrupt endpoints. Until then the only honest statement is the one
above — the median is 8.0 ms, and why is open.

Raw INIT reply payloads (17 bytes), one per archived process:

```
process A: 3e1eb0085cf16b600000003f0205040004
process B: dbcbeb04e9448ef4000000510205040004
```

Decoded per CTAPHID §11.2.1.1 (nonce 8, CID 4, interface 1, version 3, capFlags 1),
using process A; process B is identical apart from the nonce and CID:

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

- **Latency: 74.1 ms** (process A) / **77.3 ms** (process B).
  The response is a 527-byte body spanning 10 HID packets, so this is the
  first-packet latency, not a whole-response time.
- CTAP2 status byte `0x00` (SUCCESS); the body is 527 bytes.

`versions` (getInfo key 1):
`['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']`
`maxMsgSize` (key 5): `7609`

`options` (getInfo key 4) as decoded. **The keys are text, not integer
option ids** — this device emits `{"rk": true, "clientPin": true, …}` and the
probe reads them by name:

```python
{'rk': True, 'alwaysUv': False, 'credMgmt': True, 'authnrCfg': True,
 'clientPin': True, 'largeBlobs': True, 'pinUvAuthToken': True,
 'setMinPINLength': True, 'makeCredUvNotRqd': True,
 'enterpriseAttestation': True}
```

The four the brief asks about, read from that map by key name. **Every row
is observed** — it is the value the device sent, not a translation:

| requested | observed key in this getInfo | observed value |
|---|---|---|
| `clientPin` | `clientPin` (text key) | **True — supported** |
| `pinUvAuthToken` | `pinUvAuthToken` (text key) | **True — supported** |
| `uv` | not sent as `uv`; `alwaysUv` and `makeCredUvNotRqd` are what govern a MakeCredential's UV requirement | **`alwaysUv` = False**, `makeCredUvNotRqd` = True |
| `up` | **not sent.** CTAP2 has no `up` option — user presence is implied, not optional | n/a — nothing to read |

> **Correction, recorded because it is the kind of error worth catching.**
> An earlier draft of this table carried a third column naming integer option
> ids (`clientPin` = `0x06`, `pinUvAuthToken` = `0x0C`, `uv` = `0x03`/`0x0E`).
> Those ids were **not observed in any run of this probe** — the device's
> options map has no integer keys at all, and the first draft of the probe
> looked them up with integer ids, which returned `<absent>` for all seven and
> was not treated as a fault. The column was filled in from spec knowledge
> because the probe had reported nothing, which is precisely the failure this
> document is supposed to make visible. The probe now prints the keys it
> actually received, looks options up by name, and exits `4` with a loud
> ANOMALY block if every requested option comes back absent.

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

### Results — four runs, two processes, all four archived

| | A run 1 | A run 2 | B run 1 | B run 2 |
|---|---|---|---|---|
| MC final reply (wall) | **30.11 s** | **30.11 s** | **30.15 s** | **30.14 s** |
| MC final CTAP2 status | `0x3B` `UP_REQUIRED` | `0x3B` `UP_REQUIRED` | `0x3B` `UP_REQUIRED` | `0x3B` `UP_REQUIRED` |
| keepalives during window | 301 | 301 | 301 | 301 |
| broadcast `INIT` written? | **yes**, 7.7 ms | **yes**, 7.8 ms | **yes**, 47.8 ms | **yes**, 47.7 ms |
| broadcast `INIT` answered? | **NO** | **NO** | **NO** | **NO** |
| open-channel `PING` written? | **NO** — write blocked | **NO** — write blocked | **NO** — write blocked | **NO** — write blocked |
| open-channel `PING` answered? | **NO** | **NO** | **NO** | **NO** |
| `CANCEL` (run 2 only) written? | — | **NO** — write blocked | — | **NO** — write blocked |
| `CANCEL` answered during window? | — | **NO** | — | **NO** |

Sub-second detail, from the same four archived runs:

| | A run 1 | A run 2 | B run 1 | B run 2 |
|---|---|---|---|---|
| observation length after MC | 30.11 s | 30.11 s | 30.15 s | 30.14 s |
| MC final reply, exact wall | +30112.6 ms | +30105.2 ms | +30151.5 ms | +30138.9 ms |
| late broadcast `INIT` reply, after send | +30080.4 ms | +30079.9 ms | +30084.4 ms | +30080.8 ms |
| late broadcast `INIT` reply, after MC | +30120.1 ms | +30112.7 ms | +30164.2 ms | +30146.4 ms |

- **Neither the broadcast `INIT` nor the open-channel `PING` is answered, for
  the whole window, in all four runs.** The MC wall times span 30.105–30.152 s,
  a 47 ms range. **The epic's prediction is confirmed.**
- The broadcast `INIT` reply does eventually arrive, but only **after** the
  window closes — ~30.08 s after it was sent in all four runs, i.e. ~7 ms
  after the `UP_REQUIRED` reply went out. It is not lost, it is queued behind
  a single-tasked command loop.
- The `MakeCredential` gets `0x3B` `UP_REQUIRED` — a clean, spec-shaped "the
  user did not touch the button in time".
- The keepalive stream is unbroken in every run: 301 frames of status `0x02`
  (`UP_NEEDED`) at 10 Hz across 29.97 s. **The device is alive and talking
  the entire time it is ignoring everything else.** This is the crux of
  the discovery problem: from a browser's point of view the key is neither
  responsive nor absent, and it fails differently depending on timing.
- The one figure that *moved* between processes is how long the broadcast
  `INIT` **write** took: 7.7 / 7.8 ms in process A, 47.8 / 47.7 ms in process
  B. Still far inside its 3 s deadline, still written, still never answered —
  so it does not change the finding — but it is a 6× difference across two
  identical processes and is not explained by anything measured here.

### The `PING` and `CANCEL` writes never completed — this is a distinct, stronger failure

`CTAPHID_PING` and `CTAPHID_CANCEL` could not even be **written** during the
window. The write blocked and was abandoned at its 3 s deadline, in all four
runs:

```
open-channel PING  NEVER WRITTEN — the write blocked and gave up after its 3.0 s deadline: [Errno 110] Connection timed out
CTAPHID_CANCEL     NEVER WRITTEN — the write blocked and gave up after its 3.0 s deadline: [Errno 110] Connection timed out
```

The one `INIT` that did get written (7.7–47.8 ms) went into a buffer the
device never drained. So the measured behaviour is worse than "the device
reads the request and ignores it": during the consent window **the device
does not read the HID OUT endpoint at all**, the kernel's output buffer
fills, and the *host* blocks. A real browser that tries to cancel,
re-negotiate, or fall back to a second authenticator during those 30 s will
block on the write, not just fail to get a reply. Probe writes are serialised
on the fd so this is the device's behaviour and not two threads interleaving
reports.

---

## (c) `CTAPHID_CANCEL`

Frame command **`0x11`**, sent on the open channel with a zero-byte payload.

### (c1) With no consent window open

Process A, verbatim:

```
sent CTAPHID_CANCEL frame cmd 0x11 on channel 0000003f, 0-byte payload
reply: cmd=0x3F len=1 latency=12.3 ms
```

Process B, verbatim:

```
sent CTAPHID_CANCEL frame cmd 0x11 on channel 00000051, 0-byte payload
reply: cmd=0x3F len=1 latency=51.1 ms
```

Raw reply frames (full 64-byte report), one per process — identical apart
from the channel:

```
0000003fbf0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
00000051bf0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Decoded: command `0x3F` (`CTAPHID_ERROR`), length `0x0001`, error byte `0x01`
(`INVALID_CMD`).

**The verified source state is confirmed on the wire, in both processes.**
`0x11` has no dispatch arm and falls through to the `else` in
`firmware/src/tasks.rs`, answering `CTAPHID_ERROR` / `INVALID_CMD`.

**This is not the correct answer.** CTAPHID §11.2.9 requires a zero-length
`0x11` frame. Latency 12.3 ms (process A) and 51.1 ms (process B). The reply
*shape* is identical in both; only the latency differs, and 51.1 ms is the
third frame process B sent — the same cold-start pattern as (a1)'s first
sample, so it is most likely host-side, but nothing here proves that.

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

The device was left in a normal, answerable state. Recorded at the end of each
run, on a freshly allocated channel — process A:

```
broadcast INIT: answered in 10.5 ms, payload 197c79f4b886159d000000470205040004
    nonce match=True  capFlags=0x04  fw=5.4.0
PING on the fresh channel: answered in 15.9 ms, echo 55532d313530312d66696e616c (matches: True)
```

process B:

```
broadcast INIT: answered in 8.4 ms, payload 99bad0d77cd16156000000590205040004
    nonce match=True  capFlags=0x04  fw=5.4.0
PING on the fresh channel: answered in 15.9 ms, echo 55532d313530312d66696e616c (matches: True)
```

Both runs exited `0`. The script exits non-zero if this final round-trip
fails.

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
answers `CTAPHID_ERROR` / `INVALID_CMD` (`0x3F` / `0x01`) — in 12.3 ms in
process A and 51.1 ms in process B — where CTAPHID §11.2.9 requires a
zero-length `0x11` frame. Confirmed as predicted, in both processes.
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

Four bugs in the first draft of the probe each produced a confident, wrong
number, and all four are worth recording because they are easy to repeat:

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
4. **The options map is text-keyed, and indexing it with integer option ids
   returns seven `<absent>` rows that read as a device finding.** This one
   survived into a first draft of *this document*: the probe reported all
   absent, nobody treated seven-of-seven as a fault, and the option-id column
   got filled in from spec knowledge instead. The general lesson is the one
   worth keeping: **an all-`-absent` result is a probe bug until proven
   otherwise.** The probe now prints the keys it received, looks options up by
   name, and exits `4` with a loud ANOMALY block rather than printing a tidy
   row of misses.

And one about this document rather than the probe: an earlier draft quoted
latencies from a third process invocation whose output was never retained, and
an "8 ms floor" with a causal explanation attached to it. Both are gone. The
latencies are either quoted from an archived run or not present at all, and
the 8 ms clustering is recorded as an observation with an open question (see
(a1)), because the endpoint's declared `bInterval` is 10 and 2.7 ms was
measured below the claimed floor.
