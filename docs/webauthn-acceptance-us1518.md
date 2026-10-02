# US-1518 — scripted acceptance results

**Run date:** 2026-10-02
**Board under test:** `EddieOz / Fapico2`, iSerial **`94746395`**, bcdDevice
`0.10`, at `/dev/hidraw10` — our Rust firmware.
**Reference board (present, never opened):** `Pol Henarejos / Fapico2`,
iSerial `7C36644DFF8A74C7`, at `/dev/hidraw13` — the pico-fido2 C reference.
**Firmware on the board:** CTAPHID INIT reports firmware `5.4.0`, capFlags
`0x04`.

> **These results are against firmware flashed *before* this epic's fixes.**
> The consent-window fix, the `authenticatorSelection` fix and the capFlags fix
> are committed but not yet on the board. The three `abandoned-attempt-*` cases
> and the page-side `answers_after_abandon` case are **expected to fail**, and
> they do. That is the regression this story exists to assert, caught rather
> than assumed. Nothing here was weakened to make the run green.

## How to reproduce

```bash
python3 scripts/acceptance/run_acceptance.py --json-out acceptance.json
python3 scripts/acceptance/run_acceptance.py --run-browser --browser-autorun \
        --json-out acceptance.json     # includes headless Chrome
```

`scripts/acceptance/README.md` has the full run guide, the browser trust step,
and the human/machine split. Exit `0` = all machine cases passed, `1` = a
machine case failed, `2` = the harness could not run.

## Results as measured

### Machine-checkable — no human, no browser

| case | verdict | observed |
|---|---|---|
| `ctap-identity-is-ours` | **PASS** | target re-identified as `/dev/hidraw10` (`EddieOz`, `94746395`); this run opened only its own node; the reference board was present and never opened |
| `device-enumerates` | **PASS** | INIT ok, cid `0x00000086`, firmware `5.4.0`, capFlags `0x04` |
| `device-answers-ping` | **PASS** | 5 pings, worst **55.9 ms**, median **16.0 ms**, floor 250 ms |
| `get-info-answers` | **PASS** | GetInfo status `0x00`, 21 top-level keys, 0 trailing bytes |
| `get-info-options` | **PASS** | options map: 10 entries, key type(s) **`['str']`** |
| `abandoned-attempt-leaves-device-enumerable` | **FAIL** | no re-enumeration within 12 s of abandoning |
| `abandoned-attempt-does-not-block-host` | **FAIL** | host write failed with **`ETIMEDOUT`** |
| `abandoned-attempt-next-ceremony-engages` | **FAIL** | no new user-presence window within 12 s |
| `page:enumerates` | **PASS** | real Chrome 145, `secureContext=true`, `conditionalCreate=true` |
| `page:answers_after_abandon` | **FAIL** | post-abandon ceremony did not settle in **30001 ms** |

**Machine-checkable total: 6/10 pass.**

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

## The derived latency bound

```
idle baseline (worst of 5 pings) : 55.9 ms
bound = max(250 ms floor, 10 × baseline) = 559.0 ms
```

Derived from this run's own healthy measurement, not chosen to pass. The floor
prevents a pathologically fast baseline from producing a sub-millisecond bound;
the factor absorbs scheduler jitter on a loaded box. Both numbers are printed
every run so the judgement is auditable.

For scale: the C reference answered 4 pings in **8.0 ms** each over the same
window. This firmware answered one at **30047.7 ms** while its host's writes
blocked to `ETIMEDOUT`.

## What the regression cases actually measured

Each regression case opens a real consent window
(`authenticatorGetNextAssertion` to a throwaway `.invalid` RP id — a
`MakeCredential` to a throwaway RP is rejected at the CBOR layer on this
firmware and never parks anything), confirms the device parked
(**31 KEEPALIVE frames, status `0x02` = `CTAP2_UP_REQUIRED`, in 3012 ms**), then
walks away: no touch, no `CTAPHID_CANCEL`, stops reading.

`abandoned-attempt-leaves-device-enumerable` — a **fresh handle** issued a
broadcast-channel INIT and waited 12 s. It skipped **120 frames on foreign
channel 138** and still received no reply to its own INIT.

That detail is worth stating precisely, because it refines the defect: **the
device is not dead.** It is still streaming KEEPALIVE frames on the channel the
abandoned ceremony owns. What it will not do is answer a *new* request on a new
channel. "Enumerates" is therefore the right word for the assertion, and it is
the one that fails.

`abandoned-attempt-does-not-block-host` — the write on the handle that issued
the ceremony completed in 19.2 ms, but the **next** write failed with
`ETIMEDOUT`: *"the device is not draining its OUT endpoint"*. This is the second
half of the defect, and it is a distinct failure mode from the first: the device
can still answer on a fresh handle while a blocked write on the old one wedges
the host.

`abandoned-attempt-next-ceremony-engages` — after recovering, a fresh
`authenticatorGetNextAssertion` on a new channel produced no user-presence
window within 12 s.

### Recovery between cases

The device recovers **on its own**, unattended, once its own ~30 s window timer
expires. The runner waits for that and records it, so the three regression
failures are independently attributable rather than three symptoms of the first
one:

| before | recovered in | attempts | ping after recovery |
|---|---|---|---|
| `…-leaves-device-enumerable` | 16.9 s | 4 | 56.0 ms |
| `…-does-not-block-host` | 21.6 s | 4 | 55.9 ms |

This is the loop closing on DoD item 8: the device is left answerable, just not
answerable *quickly* and not answerable on a new channel.

## The browser's view corroborates

The page-side `answers_after_abandon` case — real Chrome, real
`https://localhost`, real WebAuthn — opened a ceremony, let it park, aborted it
via `AbortSignal` (the platform's own "walk away"), and then started a fresh
ceremony. It did not settle in **30001 ms**.

Two independent vantage points, one regression.

A note on the page's "abandon": simply not awaiting a pending `create()` is not
something WebAuthn permits — the browser refuses a second ceremony with
`OperationError: A request is already pending.` Aborting through
`AbortController` is what a real dismissal does at the WebAuthn layer, and it
leaves the authenticator holding a ceremony whose host went away, which is the
state under test.

## Pass condition

The four failing cases pass when firmware containing the epic's consent-window
and `authenticatorSelection` fixes is flashed to the board, with no change to
the harness. Concretely:

- `abandoned-attempt-leaves-device-enumerable` — a fresh INIT is answered and a
  PING echoes within the derived bound (≤ 559 ms with the bound this run
  measured; lower on a clean run).
- `abandoned-attempt-does-not-block-host` — a write issued after an abandoned
  ceremony completes, and the device still answers.
- `abandoned-attempt-next-ceremony-engages` — a fresh `authenticatorGet-
  Assertion` produces a user-presence window (KEEPALIVE `0x02`).
- `page:answers_after_abandon` — the browser's post-abandon ceremony settles.

Until that reflash, a green run from this harness would mean the harness was
broken, not that the device was fixed.

## A note on the GetInfo options map

`get-info-options` records the options map **with its key types**, because the
epic's fixes touch `authenticatorSelection` and capFlags and a run that does not
print the map cannot show whether a fix landed. As measured on this board the
map has **10 entries keyed by `str`**, not by integer option id. An earlier
probe in this epic reported a column of integer option ids for this device and
had to be retracted; this case is built so that cannot recur quietly — if the
key type ever changes, `option_key_types` in the JSON changes with it.