# Token2 hardware validation — post-flash acceptance procedure

**Purpose:** validate that a flashed fapico2 token serves the
`www.token2.com` FIDO2 sign-in flow correctly — before and after touching
the device CBOR code. This is the flow that exposed the canonical-CBOR bug
([`fido2-canonical-cbor-fix.md`](fido2-canonical-cbor-fix.md)): Chrome
rejected every getAssertion response whose credential descriptor carried
`"type"` before `"id"` with `kCtap2ErrInvalidCBOR`
(`DecoderError::OUT_OF_ORDER_KEY`), while all emulation tests passed.

The procedure checks the property Chromium enforces — **strict canonical
CBOR on every authenticator response** — directly against the hardware,
using python-fido2's `Ctap2` transport (strict by default: each response is
re-encoded and must match its canonical form byte-for-byte, else
`ValueError`).

## Prerequisites

- fapico2 firmware flashed and running (device enumerates as
  `fa20:0002 "EddieOz" "fapico2"`; flashing paths in
  [`bootsel.md`](bootsel.md)).
- Host with python-fido2 ≥ 2.0. The project venv works:
  `~/Projects/git/pico/pico-fido2/.test-venv/bin/python`.
- The token plugged into USB. Touch = BOOTSEL button on the Pico 2.

## Procedure

### 1. Automated check (the script)

```bash
cd ~/Projects/git/pico/fapico2
timeout 120 ~/Projects/git/pico/pico-fido2/.test-venv/bin/python \
    scripts/token2_validate.py
```

Options: `--rp-id <id>` (default `www.token2.com`), `--no-register` (probe
only, mints nothing).

What it does, in order:

| Step | Command | Strict-parse gate |
|------|---------|-------------------|
| 1 | `getInfo` | full response map |
| 2 | `getAssertion` probe (rpId, no allowList) | error-status framing + any CBOR response |
| 3 | `makeCredential` (rk=false) — needs a touch | full response map, incl. attested credential data |
| 4 | `getAssertion` with the step-3 allowList — needs a touch | full response map, incl. the credential descriptor that used to be mis-ordered |

Step 3 mints one **throwaway non-resident** credential for the RP (the same
thing a browser registration does; no resident state is created). Skip it
with `--no-register`.

### 2. Expected output

With no PIN set on the token (fresh flash):

```
1. getInfo               OK (strict canonical parse)
2. getAssertion probe    OK … NO_CREDENTIALS: no resident credential … Not a failure.
3. makeCredential        OK (strict canonical parse)
4. getAssertion          OK (strict canonical parse) — the exact command class Chromium
                         rejected before docs/fido2-canonical-cbor-fix.md

PASS: the firmware's CTAP2 responses parse under strict canonical CBOR …
```

With a **PIN set** (`clientPin=set` in the getInfo options), step 3
answers `PUAT_REQUIRED (0x36)` — expected without pinUvAuth, not a
failure. The script reports `PASS (probe-only)`: steps 1–2 still prove the
serializer, and the full ceremony must then be run from the browser (step 3
below) or with a PIN-aware harness.

### 3. Browser end-to-end (final acceptance)

The script proves wire correctness; the last mile is Chrome itself:

1. Open <https://www.token2.com> and start a passkey registration/login.
2. Chrome must **not** fail with `SecurityError`/`NotAllowedError`
   underneath `kCtap2ErrInvalidCBOR`. `chrome://device-log` shows
   `CBOR parse error 'OUT_OF_ORDER_KEY'` lines when this class of bug is
   present; their absence during the ceremony is the acceptance signal.

## Interpreting outcomes

| Outcome | Meaning |
|---|---|
| `PASS` (all 4 steps) | Firmware responses are canonical; sign-in path healthy |
| `PASS (probe-only)` + `PUAT_REQUIRED` | Serializer healthy; PIN is set — finish validation in the browser or with a PIN-aware harness |
| `NO_CREDENTIALS` on the probe | Informational: no resident credential for the RP yet; Chrome registers on first login |
| `FAIL: … non-canonical` | **The pre-fix regression class.** python-fido2 raised `ValueError` — Chromium would reject the same bytes. Bisect the device serializer (`apps/fido/src/device_core.rs`, `ctap2.rs`) and run `cargo test -p fapico2-fido --target x86_64-unknown-linux-gnu --test canonical_device` |
| `environment: no CTAP-HID device` | Token not plugged in / not running fapico2 (check `lsusb` for `fa20:0002`) |

## Why this exists

The emulation suite can never catch canonical-order regressions: the host
CBOR encoder sorts every map before writing, so emulated responses are
always canonical regardless of the device code's insertion order. Only a
strict parser pointed at the **hardware** (or the device-path regression
test `apps/fido/tests/canonical_device.rs`) exercises the real bytes.
Run this procedure after any change to the device CBOR writers, and after
every flash, before trusting the token for sign-in.

## Persistence acceptance (US-428)

**Purpose:** prove that the FIDO2 durable state — a configured PIN
(including the key-agreement key behind pinAuth tokens) and a resident
credential — survives a manual power cycle of the physical token. That is
the SECURE-PERSIST epic's hardware acceptance: **durable-before-ack** (a
success reply is only sent after the state is in the secure partition)
plus **boot-from-store** (`FidoApp::boot` restores the PIN and resident
credentials from the secure partition). The procedure above checks wire
correctness only; ≥ 2 consecutive power cycles is the epic's DoD.

### Prerequisites

- A build from this branch, flashed and running; `lsusb` shows
  `fa20:0002 "EddieOz" "fapico2"`.
- The project venv on the host:
  `~/Projects/git/pico/pico-fido2/.test-venv/bin/python`.
- The token plugged in; touch = BOOTSEL button on the Pico 2. A power
  cycle = unplug USB, wait ~2 s, replug — the host re-enumerates the
  token a few seconds after replug, and the script retries discovery.

### How to run

```bash
cd ~/Projects/git/pico/fapico2
~/Projects/git/pico/pico-fido2/.test-venv/bin/python \
    scripts/token2_persistence.py            # defaults: --cycles 2 --pin 1234
```

Options: `--rp-id <id>` (default `www.token2.com`), `--cycles N` (default
2), `--pin <pin>` (default `1234` — if the token already has a different
PIN, pass it here; it is verified by the first pinAuth token fetch).

The script is a single invocation: it sets up the state (steps 2–3), then
pauses once per power cycle ("POWER CYCLE i: unplug and replug the
token, then press Enter") and runs the per-cycle assertions after each
replug.

### What each scenario asserts

| Scenario | Assertion | Proves |
|---|---|---|
| (a) PIN durability | `getInfo` shows `clientPin: true` after `set_pin` (setup) and **after every power cycle**; the pre-cycle pinAuth token is still accepted | the PIN state — including the key-agreement key — was written to the secure partition before the success reply, and is restored from it at boot |
| (b) resident-credential durability | after every power cycle, `getAssertion` with the pre-cycle resident credential id in the allowList answers the **same credential id**, UP flag set, and the signature verifies under the strict canonical parse | the resident keystore (credential + private key) is durable-before-ack and bootable; the assertion ceremony still passes the strict canonical check Chromium enforces |
| (c) browser login (manual) | the Chrome `www.token2.com` passkey login repeated after the power cycles succeeds; no `kCtap2ErrInvalidCBOR` in `chrome://device-log` | end-to-end acceptance with the real relying party (not scripted) |

Script protocol behavior:

- `makeCredential`/`getAssertion` are probed **without** pinUvAuth
  first; with a PIN set the firmware answers `PUAT_REQUIRED` (0x36) —
  expected, not a failure — and the script retries with the PIN token.
- The cycle loop reuses the PIN token fetched **before** the first power
  cycle: if the key-agreement key had not survived, the pre-cycle token
  would be rejected (0x31/0x33) and scenario (b) fails.
- Any non-canonical CBOR anywhere raises in python-fido2's strict parser
  (`ValueError`) → exit 1, the same regression class as
  `token2_validate.py`.

Exit codes: 0 = every cycle passed every assertion; 1 = an assertion
mismatch (the persistence regression signal, with detail); 2 =
environment problem (no library / no device / discovery timeout / abort).

If repeated runs fill the resident store (`KEY_STORE_FULL`, 0x28), clear
the token's FIDO state (CTAP2 reset or a full re-flash) and re-run.

### Manual checklist — scenario (c)

After the script prints `PASS: N consecutive power cycles survived`:

1. Open <https://www.token2.com> in Chrome and complete the passkey
   login with the token (touch on the prompt).
2. Unplug the token, wait ~2 s, replug it (one further power cycle,
   not counted by the script).
3. Repeat the login. It must succeed without re-registering — the
   resident credential is offered by the token.
4. Open `chrome://device-log` and confirm there is **no**
   `kCtap2ErrInvalidCBOR` (no `CBOR parse error` line) during either
   login.

### Evidence (US-428)

**Run date:** 2026-09-14. **Token:** `fa20:0002` "EddieOz fapico2"
(RP2350 board). **Firmware:** `firmware/fapico2.uf2` at
`feature/phase7` (the US-427 build; US-428a/US-429 changed no device
code), sha256 `516fd79cf6233596be389d8db7e64a8a61d43ae11a9afa65effbccd28fa70e1b`
(295,424 B / 577 blocks). Flashed via BOOTSEL mass storage; the image
programs only the first ~288 KiB of flash, so the secure partition is
untouched by the flash itself.

**Script bug found and fixed during the run (US-428b).** The first
hardware run of the US-428a script failed at makeCredential with CTAP
0x33: it sent the raw PIN token as `pinUvAuthParam`; CTAP2 requires the
per-command `HMAC-SHA256(token, clientDataHash)` (the token is the HMAC
key and is never sent). Fixed in `379fe93`
(`test(hardware): derive per-command pinUvAuth HMAC in power-cycle BDD`)
and re-run. The firmware's 0x33 was correct behavior, not a regression.
Note: this firmware build auto-satisfies user presence (no button UV
path yet), so no physical touch was required; the script's touch
banners were corrected in the same commit.

**Scripted run** — `scripts/token2_persistence.py --cycles 2 --pin 1234`
(project venv), full output:

```
0. discover device     (fa20:0002; retrying up to 60s)
   device: CtapHidDevice('/dev/hidraw7')
1. getInfo             OK (strict canonical parse)
   versions: U2F_V2, FIDO_2_0, FIDO_2_1, FIDO_2_2, FIDO_2_3
   options: clientPin=set, residentKeys=None, pinUvAuthToken=True
   pinUvProtocols: [1, 2]
2. set PIN             already set — the PIN is verified by the token fetch below
   PIN OK (protocol v2); token cached for the cycle loop
3. makeCredential      (rpId=www.token2.com, rk=True — resident credential)
   (user presence: auto-satisfied by this firmware build — no touch needed)
   CTAP 0x36 (pinUvAuth required) — retrying with the PIN token
   (user presence: auto-satisfied by this firmware build — no touch needed)
   OK (strict canonical parse) — credential id 7d72807c83e70c84a81c42bb65b55db4… (32 bytes)

POWER CYCLE 1/2: unplug and replug the token, then press Enter
   re-discovered: CtapHidDevice('/dev/hidraw8')
   cycle 1/2: clientPin still set            PASS (scenario (a))
   (user presence: auto-satisfied by this firmware build — no touch needed)
   cycle 1/2: same credential + valid sig    PASS (scenario (b))  (UP set, counter=2)

POWER CYCLE 2/2: unplug and replug the token, then press Enter
   re-discovered: CtapHidDevice('/dev/hidraw7')
   cycle 2/2: clientPin still set            PASS (scenario (a))
   (user presence: auto-satisfied by this firmware build — no touch needed)
   cycle 2/2: same credential + valid sig    PASS (scenario (b))  (UP set, counter=3)

PASS: 2 consecutive power cycles survived
   the PIN state and the resident credential survived every
   power cycle, and every response parsed under strict
   canonical CBOR (the property Chromium enforces).
```

Exit code 0. The pre-cycle PIN token was accepted on every cycle
(scenario a + the key-agreement-key half of b) and the pre-cycle
resident credential asserted with the same id and a verifying
signature under strict canonical parsing (scenario b). The assertion
counter incremented 2→3 across the final cycle, as expected. Between
the script's setup and its cycle-1 resume the operator also
power-cycled the token twice more and ran the manual flow below, so the
scripted assertions additionally covered a browser registration and
login performed in between.

**Scenario (c) — manual Chrome flow (www.token2.com), operator-run
2026-09-14.** The token already held the BDD's PIN (1234) after the
flash. The full flow was repeated twice, each run preceded by a power
cycle:

1. Power-cycle the device.
2. Open `https://www.token2.com/tools/fido2-demo`.
3. "Register key" → PIN prompt → enter 1234 → `Registration completed
   successfully. You can now log in.`
4. "Log in with key" → enter 1234 → **login completed successfully**.

The PIN was not reset by any power cycle or by the firmware flash. The
strict-canonical-CBOR property itself is enforced by the scripted run
on every response; the browser's successful registration/login is the
end-to-end confirmation with the real relying party.

**Acceptance.** US-428 DoD met: ≥2 power cycles with PIN + resident
credential survival (scripted, scenarios a+b) plus the real relying
party (scenario c).
