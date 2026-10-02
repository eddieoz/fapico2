# US-1518 — scripted acceptance harness

A repeatable acceptance page served over HTTPS that drives the request shapes
US-1521 identified, plus a runner that asserts the epic's headline regression —
the **abandoned-attempt** case — on the wire, where it is actually measurable.

```
scripts/acceptance/
  ctap.py            CTAPHID wire layer (stdlib only) + device identification
  server.py          HTTPS origin for the page (self-signed, generated locally)
  page.html          the acceptance page: the request shapes, one verdict each
  run_acceptance.py  the runner: machine cases, browser launch, report
```

## Quick start

```bash
# machine-checkable half only; needs no human and no browser
python3 scripts/acceptance/run_acceptance.py

# everything, including the page's machine-gated cases in headless Chrome
python3 scripts/acceptance/run_acceptance.py --run-browser --browser-autorun

# save the report
python3 scripts/acceptance/run_acceptance.py --json-out /tmp/us1518.json
```

Exit code `0` = every machine case passed, `1` = at least one machine case
failed, `2` = the harness could not run (no board, ambiguous identity, no
browser).

## Requirements

- Python 3.8+ (standard library only — **no `fido2`, no `pip install`**). The
  machine half is deliberately dependency-free so it can run in a bare CI
  container with a board plugged in.
- A board attached on USB as `/dev/hidraw*`, reachable by the invoking user.
- Chrome or Chromium, only for `--run-browser`. The runner finds
  `chromium`/`google-chrome` on `$PATH` and falls back to Playwright's bundled
  Chrome for Testing under `~/.cache/ms-playwright`.

## Which board does this talk to?

Two boards are attached and **both enumerate as `1050:0407`**. They differ only
in USB identity strings:

| iManufacturer | iSerial | what it is |
|---|---|---|
| `EddieOz` | `94746395` | our Rust firmware — the board under test |
| `Pol Henarejos` | `7C36644DFF8A74C7` | the pico-fido2 C reference — **never driven** |

Selection is by `iManufacturer` **and** `iSerial` read from the USB descriptors,
and it demands exactly one match, so an unplugged or duplicated board fails
loudly instead of silently testing the wrong one. Override with
`--manufacturer` / `--serial`.

Each board also exposes a **YubiOTP** HID interface carrying the *same* VID/PID
and the *same* iSerial, so identity alone is not enough. The two are separated
by the HID usage page of the top-level collection: `0xF1D0` (FIDO Alliance) is
CTAPHID, `0x0001` (generic desktop) is the OTP node. Only CTAPHID nodes are
ever eligible.

The harness asserts on which nodes it *opened*, not on which boards happen to
be attached — the reference board is expected to be plugged in the whole time,
and the `ctap-identity-is-ours` case fails the run if a handle was ever opened
on it. The selected board is named in the report and in `--json-out`.

## The browser trust step

WebAuthn requires a secure context, so the page is served over real TLS on
`https://localhost:<port>/`. The certificate is generated on first run into
`scripts/acceptance/.cert/` (gitignored — a committed private key in a repo
would be worse than useless).

`localhost`, not `127.0.0.1`, is load-bearing: the page derives its RP ID from
`location.hostname`, and WebAuthn rejects an IP literal with
`SecurityError: This is an invalid domain`.

To run unattended, the default `--browser-args` passes
`--ignore-certificate-errors`, which bypasses **only** the TLS trust decision —
WebAuthn is unaffected. For a manual run, trust the certificate properly:

```bash
openssl x509 -in scripts/acceptance/.cert/localhost.pem -inform PEM \
  -trustout cacert -out local-ca.pem
# then add local-ca.pem to your OS / browser trust store
```

`mkcert` is used instead when it is installed, since that also installs the CA.

## The human/machine split

This is the important part, and it is visible in the output: every case is
labelled `machine` or `human`.

**Machine-checkable — no human, no browser, fully unattended.** These are the
ones CI can gate on:

| case | asserts |
|---|---|
| `ctap-identity-is-ours` | the run targets the intended board and never opened the reference |
| `device-enumerates` | the board answers CTAPHID INIT on a fresh handle |
| `device-answers-ping` | the idle device answers within the floor; this is the baseline the bound derives from |
| `get-info-answers` | GetInfo answers and its CBOR body decodes |
| `get-info-options` | the options map is recorded, **with key types** |
| `abandoned-attempt-leaves-device-enumerable` | **REGRESSION** — after walking away from a ceremony, the device still enumerates and answers within the derived bound |
| `abandoned-attempt-does-not-block-host` | **REGRESSION** — the host's write is not blocked |
| `abandoned-attempt-next-ceremony-engages` | **REGRESSION** — the device still engages a fresh user-presence window |
| `page:enumerates` | WebAuthn is usable in a real browser at a real secure context |

**Human-gated — each needs a physical touch of the button.** The device enforces
user presence (US-907) and this epic does not relax it:

| case | shape |
|---|---|
| `uv_required` | `userVerification: required` |
| `uv_preferred` | `userVerification: preferred` |
| `attachment_cross` | `authenticatorAttachment: cross-platform` |
| `attestation_none` | `attestation: none` |
| `attestation_direct` | `attestation: direct` |
| `rk_required` | `residentKey: required` |
| `get_uv_required` | `userVerification: required` (assertion) |

Run them with a human present:

```bash
python3 scripts/acceptance/run_acceptance.py --run-browser --headed
```

Leave the browser up and touch the button when the page prompts. A case that
does not report before its deadline is a **FAIL**, never a skip — an
unresponsive device and an unwatched device must not look the same.

### The harness does not fake user presence

Chrome's CDP virtual authenticator (`WebAuthn.addCredential`) and Playwright's
`setAutomaticPresenceSimulation` are deliberately **not used**. A harness that
stubs the touch cannot observe the thing this epic exists to observe, so a green
run from one would be evidence of nothing. There is no flag to turn this on.

## Why the regression lives on the wire, not in the page

The browser cannot measure the thing the epic is about:

- WebAuthn exposes **no way to enumerate authenticators** from script.
- It reports **no latency budget**, so the page cannot tell "answered in 16 ms"
  from "answered in 30 s".
- The browser owns the hidraw node exclusively while a ceremony is in flight,
  so a page cannot ping the device during the very window where the defect
  appears.

The page-side `answers_after_abandon` case is therefore a **corroborating**
signal — it observes the same regression from the browser's own vantage point
(a fresh ceremony after an abort does not settle) — but the assertion with a
defensible number is the one the runner makes on the wire.

## How the latency bound is derived

The bound is **not picked to pass**. It is computed at run time from the
device's own healthy PING round trip in the same run:

```
idle baseline   = worst of 5 PINGs on the idle device
bound           = max(--bound-floor-ms, --bound-factor × idle baseline)
```

Defaults: floor `250 ms`, factor `10`. With a measured baseline of ~16 ms the
bound is the 250 ms floor.

The floor stops a pathologically fast baseline from producing a
sub-microsecond bound that would fail on scheduler jitter alone. The factor
absorbs jitter on a loaded CI box. Both the baseline and the derived bound are
printed, so the judgement is auditable rather than asserted.

For scale: the C reference answered 4 pings in **8.0 ms** each over the same
window. This firmware, before the fix, answered one at **30047.7 ms** while its
host's writes blocked to `ETIMEDOUT`.

## Safety

- **No writes that mutate device state.** The harness never sets a PIN, never
  creates a real credential on a real RP (the ceremonies run against a
  throwaway `.invalid` RP id), never sends a management or reset command. The
  ceremonies that need a touch create a discoverable credential for the
  *harness's own* `localhost` origin, which is disposable.
- **No SWD debugger.** Per `AGENTS.md`, attaching one makes `OTP_DATA_RAW` read
  `0xFFFFFFFF` and `fatal_boot` fires before USB is constructed, producing a
  false failure on a healthy board. Never run this with a probe attached.
- **No reflash, no factory reset, no BOOTSEL.**
- **The C reference board is never opened** — asserted, not just intended.
- Every hidraw **write** runs under a hard SIGALRM watchdog, and kernel
  `ETIMEDOUT` is mapped to a distinct exception. The defect under test makes
  the host's writes block, so without this the harness itself would hang
  instead of recording a failure.
- Between the regression cases the runner **waits for the device to recover**
  and records how long that took. Without it, the first case's damage would be
  misattributed to the second and third, turning one real failure into three
  misleading ones.

## CI

```bash
python3 scripts/acceptance/run_acceptance.py --json-out acceptance.json
```

Gate on the exit code. For a job with no board attached the harness exits `2`,
which is distinguishable from a real failure. The browser half needs a board and
a human, so it belongs on a self-hosted runner or a hardware bench, not in
GitHub-hosted CI.