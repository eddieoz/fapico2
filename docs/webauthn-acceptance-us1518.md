# US-1518 — scripted acceptance results

**Run date:** 2026-10-02
**Board under test:** `EddieOz / Fapico2`, iSerial **`94746395`**, bcdDevice
`0x10`, at `/dev/hidraw10` — our Rust firmware.
**Reference board (present, never opened):** `Pol Henarejos / Fapico2`,
iSerial `7C36644DFF8A74C7`, at `/dev/hidraw13` — the pico-fido2 C reference.
**Firmware on the board:** CTAPHID INIT reports firmware `5.4.0`, CTAPHID
protocol version 2, capFlags `0x05` — **the post-fix build**.

> **These results are against the FIXED firmware, flashed on the board.** This
> supersedes the earlier table in this file, which was measured against the
> pre-fix build and therefore could only report 6/10 with three regression
> cases failing. Those three FAILs were real at the time. They were also, on
> analysis, the *harness* being wrong rather than the device — and that is what
> this revision fixes. Nothing was weakened to make the run green; every
> assertion below is falsifiable and five of them are demonstrated to fail
> when their precondition is removed.

## How to reproduce

```bash
python3 scripts/acceptance/run_acceptance.py --json-out acceptance.json
python3 scripts/acceptance/run_acceptance.py --run-browser --browser-autorun \
        --json-out acceptance.json     # includes headless Chrome
```

`scripts/acceptance/README.md` has the full run guide, the browser trust step,
and the human/machine split. Exit `0` = all machine cases passed, `1` = a
machine case failed, `2` = the harness could not run.

## The pass condition

**A machine case PASSES only if every assertion in it held.** For this suite
that means, concretely:

1. **Nothing vacuous.** A case that could not exercise its scenario FAILS
   rather than passing quietly. Specifically: if the device never parked in a
   consent window, all three `abandoned-attempt-*` cases FAIL
   ("never parked"). Previously the enumerability case recorded this as a
   `note` and passed anyway — a case that measured nothing reported success.
2. **Echoes must be exact.** A PING must return its own payload byte-for-byte.
   A fast round trip carrying the wrong bytes is a FAIL, not a PASS.
3. **The latency bound is derived, not chosen.** `bound = max(250 ms floor,
   10 × the worst idle PING of this same run on this same device)`. Both
   numbers are printed every run. The bound is never widened to accommodate a
   result.
4. **The regression claim is the claim, not a proxy.** After an abandoned
   attempt the device must still answer INIT/PING/GetInfo *within the bound*
   on fresh channels, throughout the drain. Anything less (e.g. merely "not
   dead") would pass on the pre-fix device and prove nothing.
5. **Designed refusals are asserted, not tolerated.** A second ceremony while
   the slot is held must be answered `0x24 CTAP2_ERR_OPERATION_PENDING`. A
   device that *queued* it instead fails — that is US-1510.
6. **The run must be reproducible.** Two consecutive runs give the same
   verdicts, because each case returns the device's slot before finishing.

`scripts/acceptance/run_acceptance.py` exits non-zero if any machine case
failed **or** if one was in scope and did not report. `page:` cases are
flagged `out_of_scope` (and excluded from the tally) on a board-only run, so
exit 0 never means "the browser-discovery DoD was verified".

## Results as measured

### Machine-checkable — no human, no browser

| case | verdict | observed |
|---|---|---|
| `ctap-identity-is-ours` | **PASS** | target re-identified as `/dev/hidraw10` (`EddieOz`, `94746395`); this run opened only its own node; the reference board was present at `/dev/hidraw13` and never opened |
| `device-enumerates` | **PASS** | INIT ok in 9.7 ms, cid `0x00000478`, firmware `5.4.0`, CTAPHID v2, capFlags **`0x05`** |
| `device-answers-ping` | **PASS** | 5 pings, **all echoes correct**, worst 16.1 ms, median 16.0 ms, floor 250 ms |
| `get-info-answers` | **PASS** | GetInfo status `0x00`, 21 top-level keys, 0 trailing bytes |
| `get-info-options` | **PASS** | options map: 10 entries, key type(s) **`['str']`**, 0 trailing bytes |
| `abandoned-attempt-leaves-device-enumerable` | **PASS** | re-enumerated in 15.6 ms, PING in 15.9 ms (bound 561 ms = 10× the 56.1 ms idle baseline; ratio 0.3×) |
| `abandoned-attempt-does-not-block-host` | **PASS** | write completed in 7.6 ms, was answered in 7.9 ms, further PING correct in 16.0 ms |
| `abandoned-attempt-next-ceremony-engages` | **PASS** | 24 probes over 28.1 s of drain, all INIT/PING/GetInfo answered (worst PING 64.0 ms); all 23 second ceremonies refused `0x24`; released at 31.1 s by deadline and 0.06 s by cancel |

**Machine-checkable total: 8/8 pass, 0 fail, 0 not run. Exit code 0.**

Verified twice, back to back, with identical verdicts — the second run started
0.1 s after the first finished.

### Human-gated — each needs a physical touch (US-907)

Not run in this session: there was no operator at the button. These are
reported as `NOT RUN`, which is **not a pass**.

| case | shape |
|---|---|
| `uv_required` | `userVerification: required` |
| `uv_preferred` | `userVerification: preferred` |
| `attachment_cross` | `authenticatorAttachment: cross-platform` |
| `attestation_none` | `attestation: none` |
| `attestation_direct` | `attestation: direct` |
| `rk_required` | `residentKey: required` |
| `get_uv_required` | `userVerification: required` (assertion) |

### Page cases — no chromium on this host

`page:enumerates` and `page:answers_after_abandon` are **NOT RUN** and marked
`out_of_scope`. There is no chromium/chrome on this machine (only
`chromium-ffmpeg` codec libraries and firefox), so no browser could be
launched. They are named in the run output and excluded from the machine tally;
they are **not** evidence for the browser-discovery DoD item 8.

## The derived latency bound

```
idle baseline (worst of 5 pings) : 56.1 ms
bound = max(250 ms floor, 10 × baseline) = 561.0 ms
```

Derived from this run's own healthy measurement, not chosen to pass. The floor
prevents a pathologically fast baseline from producing a sub-millisecond bound;
the factor absorbs scheduler jitter. Both numbers are printed every run so the
judgement is auditable.

Note the floor is load-bearing on this hardware: idle PINGs measure ~16 ms on a
quiet box and ~56 ms when the host is busy, so a 10× factor off a 16 ms
baseline would yield 160 ms — below the jitter the device actually shows. The
250 ms floor is what makes the bound stable across runs, and it is still three
orders of magnitude below the pre-fix 30047.7 ms.

For scale: the C reference answered 4 pings in **8.0 ms** each over the same
window. This firmware, before the fix, answered one at **30047.7 ms** while its
host's writes blocked to `ETIMEDOUT`.

## What the regression cases actually measured

Each regression case opens a real consent window and confirms it **parked**
(keepalives with status `0x02` = `CTAP2_UP_REQUIRED`, every 248 ms) before
walking away: no touch, no `CTAPHID_CANCEL`, stop reading.

**Which request parks the window** was verified empirically from a
verified-idle slot, not assumed:

| request | result |
|---|---|
| `authenticatorGetNextAssertion` (0x02), throwaway RP | **PARKS** (25 keepalives, 0x01/0x02) |
| `MakeCredential` (0x01), throwaway RP | `0x12 INVALID_CBOR`, no window |
| `authenticatorClientPIN` (0x06) sub-command 0x06 | `0x02 INVALID_PARAMETER`, no window |

The MakeCredential answer is not a defect: US-1530 established that a
throwaway-RP MakeCredential is rejected at the CBOR layer on this firmware
**and on the C reference alike** (`CBOR_FIELD_GET_BYTES` at the same key),
because the request is not grammatical. A PIN is set on this board, so a
well-formed MakeCredential is refused `0x36 PIN_POLICY_VIOLATION` before the
presence gate. `GetNextAssertion` is the one shape that reaches the gate here,
so it is what parks the window.

### How the slot is released — both measured

| mechanism | measured release | notes |
|---|---|---|
| `CTAPHID_CANCEL` | **0.06 s** (0.04–0.56 s across runs) | deliberately **not acknowledged** — the original channel emitted no frame within 4 s |
| the device's own window deadline | **29.78–31.1 s** | no cancel at all; the true "user walked away" path |

`CTAPHID_CANCEL` producing no reply is correct per CTAPHID and matches both
references — a cancel reply makes `fido2`'s inbound packet matcher raise. So
the harness verifies a cancel by observing that the slot then *accepts* a new
ceremony, never by waiting for an ack.

### The rewritten `abandoned-attempt-next-ceremony-engages`

The old assertion was "after an abandoned ceremony, a new ceremony engages".
That **encoded the pre-fix world**. Before the fix the device went dark for the
whole window; anything sent during that period got nothing back, so "a new
ceremony engages immediately" could only have been satisfied by a device that
was *not holding a slot* — the assertion and the fix pulled in opposite
directions.

`0x24 CTAP2_ERR_OPERATION_PENDING` is the **designed** behaviour:

- US-1510 specifies that a second user-presence request arriving while the slot
  is occupied is **refused, not queued** — single-occupancy, fail-closed.
- An abandoned attempt therefore holds the slot for the remainder of its ~30 s
  window, so an immediate re-ceremony is *correctly* refused.
- The pico-fido2 C reference does the same; the sibling A/B probe recorded it
  "STILL PARKED" under the same conditions.

The case now asserts three decided things:

1. **Answerable throughout the drain** — INIT, PING and GetInfo on fresh
   channels, within the derived bound, at ~1 s intervals across the window.
   This is the actual DoD-8 claim: the blackout is gone.
2. **Refused, not queued, while occupied** — every second ceremony sent during
   the drain must answer `0x24`. A device that queued instead fails here.
3. **Engaged once released** — by the device's own deadline, and separately by
   `CTAPHID_CANCEL`, both timed in-run.

### Observed liveness during a drain (24 probes, 28.1 s)

Every probe answered: PING 15.8–64.0 ms (bound 561 ms), GetInfo `0x00` with 21
keys, every second ceremony `0x24`. Sample:

```
t+  0.00s  ping=16.0ms  info=0x00  second=0x24 CTAP2_ERR_OPERATION_PENDING
t+ 14.57s  ping=15.9ms  info=0x00  second=0x24 CTAP2_ERR_OPERATION_PENDING
t+ 26.82s  ping=16.0ms  info=0x00  second=0x24 CTAP2_ERR_OPERATION_PENDING
t+ 28.14s  ping=15.9ms  info=0x00  second=PARKED   <- slot released on its own
```

The device is fully alive for the entire 30 s the slot is held. That is the
blackout regression, closed.

## Falsification

Every assertion added or tightened here was checked to be able to fail:

| injected fault | result |
|---|---|
| bound tightened to 5 ms | **FAIL** — "24 of 24 liveness probes exceeded the 5 ms bound" |
| device never parks (no keepalives) | **FAIL** in all three `abandoned-attempt-*` cases |
| options map keyed by ints | **FAIL** — "keyed by ['int'], expected ['str']" |
| capFlags `0x04` (the pre-fix byte) | **FAIL** — "capFlags 0x04, expected 0x05" |
| a PING echoing the wrong bytes | **FAIL** — "5 of 5 PINGs echoed the wrong bytes" |

## Not certified by this run

- The two `page:` cases — no chromium on this host.
- The seven human-gated ceremony shapes — no operator at the button.
- Therefore **DoD item 8's browser-facing half is not discharged by this run**.
  What this run discharges is the wire-level claim: the device stays
  enumerable, answerable and write-drainable throughout an abandoned ceremony,
  refuses a queued second ceremony as designed, and resumes service once the
  slot drains.