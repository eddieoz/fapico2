# US-1520 — which row of the §1.2 failure table does the browser select?

**Run date:** 2026-10-02 22:27–22:44 UTC (2026-10-03 01:27–01:44 EEST, local)
**Browser:** `Chrome/145.0.7632.6` — Google Chrome for Testing, Playwright cache
(`~/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome`), **headed** on
`DISPLAY=:0`, no feature flags touching WebAuthn, stock `--no-sandbox`.
**UA:** `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36`
**OS:** Ubuntu 24.04.4 LTS, Linux 6.8.0-142-generic x86_64, X11 session on `DISPLAY=:0`.

Everything below was **executed**, not inferred. Harness lives in `/tmp/wa1520/`
(driver + six passes + raw JSON dumps); no firmware was touched, no repo file was
modified except this document.

---

## 0. Two preconditions that change what this document can claim

### 0.1 Our board was not attached

The brief says our board is `/dev/hidraw10` (`EddieOz`, serial `94746395`). It was
not present:

```
$ ls -l /dev/hidraw10
ls: cannot access '/dev/hidraw10': No such file or directory

$ lsusb | grep -i yubi
Bus 001 Device 099: ID 1050:0407 Yubico.com Yubikey 4/5 OTP+U2F+CCID

$ lsusb -v -d 1050:0407 | grep -iE 'iProduct|iSerial'
  iProduct                2 Fapico2
  iSerial                 3 7C36644DFF8A74C7
```

Only the **pico-fido2 C reference board** (`Pol Henarejos` / `7C36644DFF8A74C7`,
`1050:0407`) was plugged in. Per `scripts/acceptance/README.md` that board's
identity strings are the reference; ours are `EddieOz` / `94746395` on
`fa20:0002`. No entry for `EddieOz` or `fa20:0002` appears anywhere in `lsusb`,
`chrome://device-log`, or `/sys/class/hidraw/*`.

**Consequence: the reported failure could not be reproduced at all.** Every
firmware-side row of the table is untestable in this run. What *was* measurable is
the browser's behaviour — which is what the gate actually turns on, and it turns
out to be the more consequential half.

### 0.2 A stale browser from a previous run held the reference board

```
$ fuser -v /dev/hidraw13
/dev/hidraw13:  eddieoz  176255  F....  chrome

$ ps -o pid,lstart,cmd -p 176255
176255  okt 3 00:28:30  chrome --headless=new ... --user-data-dir=/tmp/abandon2/udd9
                          ... https://localhost:54211/
```

A headless Chrome left over from an earlier abandoned-attempt experiment on this
branch had `/dev/hidraw13` (the reference board's CTAPHID node) open for the whole
session. That is not a neutral condition for a discovery measurement, so the
device-enumeration readings below should be re-taken with that process gone. It
was **not** killed here — it belongs to another session, not this one. All
browsers started by this investigation were terminated afterwards; verified with
`pgrep -af wa1520-udd-` (0 left) and `fuser -v /dev/hidraw13` (only PID 176255
remains).

Confirmed CTAPHID node, read from the report descriptor without opening it:

```
$ cat /sys/class/hidraw/hidraw13/device/report_descriptor | xxd | head -1
00000000: 06d0 f109 01a1 0109 2015 0026 ff00 7508      .... ..&..u.
#              ^^^^^^^^  Usage Page 0xF1D0 (FIDO Alliance), Usage 0x01, Application
$ cat /sys/class/hidraw/hidraw14/device/report_descriptor | xxd | head -1
00000000: 0501 0906 a101 0506 1900 2aff 0015 0026     ..%....&..F&.
#              ^^^^^  Usage Page 0x0001 — the YubiOTP node, not CTAPHID
```

---

## 1. The headline result: the DOMException **name does not discriminate**

The epic's gate rests on "the one line that partitions the failure space is the
DOMException name". **That premise is false for this browser.** Across every
failure context exercised, Chrome 145 returned `NotAllowedError`. `SecurityError`
appeared exactly once, and only in a deliberate control that the real passkey
flow cannot produce (an IP-literal RP ID).

### 1.1 The four controlled cells

Each cell is a real `navigator.credentials.create()` in a real browser, with a
real user activation (`Runtime.evaluate` with `userGesture: true` on a `<button>`
handler). **A/B differ by one response header; C/D differ by one iframe
attribute. Nothing else differs.**

| cell | context | effective allowlist for `publickey-credentials-create` | DOMException | `elapsedMs` | message |
|---|---|---|---|---|---|
| **A** | top-level, **no** `Permissions-Policy` header | `["http://localhost:8831"]` | **`NotAllowedError`** | **10002** (= the full `timeout: 10000`) | "The operation either timed out or was not allowed. See: …#sctn-privacy-considerations-client." |
| **B** | top-level, `Permissions-Policy: publickey-credentials-create=()` | `[]` | **`NotAllowedError`** | **1** | "The 'publickey-credentials-create' feature is not enabled in this document. Permissions Policy may be used to delegate Web Authentication capabilities to cross-origin child frames." |
| **C** | **cross-origin iframe**, no `allow=` | not delegated | **`NotAllowedError`** | **1** | *identical to B* |
| **D** | **cross-origin iframe**, `allow="publickey-credentials-create"` | delegated | **`NotAllowedError`** | **1** | "A user activation is required to create a credential in a cross-origin iframe." |
| ctrl | top-level, `rp.id` forced to the IP literal `127.0.0.1` | — | **`SecurityError`** | **1** | "This is an invalid domain." |

The code that produced these (`create()` in every cell):

```js
await navigator.credentials.create({ publicKey: {
  challenge: pk,                                  // 32 random bytes
  rp: { name: 'probe', id: location.hostname },
  user: { id: uid, name: 'p@p', displayName: 'p' },
  pubKeyCredParams: [ {type:'public-key',alg:-7}, {type:'public-key',alg:-257} ],
  timeout: 10000, attestation: 'none', excludeCredentials: [] } });
```

**What this changes.** Row 2 of the §1.2 table says the third-party-iframe case
surfaces as `SecurityError`. Executed, Chrome 145 surfaces it as
`NotAllowedError` with the *same message as a top-level Permissions-Policy
denial*. Anyone following the epic's stated method — catch the exception, read
`.name`, pick the row — would read a cross-origin-iframe block as
"NotAllowedError → device-level → go fix the firmware", and chase a firmware bug
that does not exist. That is the same failure mode as the five earlier
inverted claims on this branch.

### 1.2 What actually discriminates: latency, plus the message

The name is constant; **the elapsed time and the message text are not.**

- **≈1 ms, "feature is not enabled in this document"** → the request was refused
  by policy **before any authenticator was consulted**. Page-side. No firmware
  change can affect this, because the USB device is never addressed.
- **elapsed ≈ the full `timeout`** → the request *did* reach authenticator
  selection and sat there waiting for a user/device. Device-side. Firmware can
  affect this.

A 10 000-fold latency gap separates the two, and it is available from any
`catch` block without a debugger:

```js
const t0 = performance.now();
try   { await navigator.credentials.create(pk); }
catch (e) { console.log(e.name, Math.round(performance.now() - t0), e.message); }
// "NotAllowedError 1 The 'publickey-credentials-create' feature is not enabled…"
// "NotAllowedError 10002 The operation either timed out or was not allowed…"
```

**Recommendation:** replace the gate's "read the DOMException name" with
"name + elapsedMs + message". The name carries no information here.

---

## 2. The real sites

Identical probe, identical browser, `timeout: 8000`, `rp.id = location.hostname`:

| site | secure ctx | `PublicKeyCredential` | DOMException | `elapsedMs` |
|---|---|---|---|---|
| `https://webauthn.io/` | yes | present | `NotAllowedError` | 8001 |
| `https://www.token2.com/tools/fido2-demo` (user reports **working**) | yes | present | `NotAllowedError` | 8002 |
| `https://x.com/` (user reports **failing**) | yes | present | `NotAllowedError` | 8002 |
| `https://twitter.com/` (redirects to `x.com`) | yes | present | `NotAllowedError` | 8002 |

Message in all four: *"The operation either timed out or was not allowed. See:
https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client."*

**Every one of them landed on the full timeout** — i.e. all four reached
authenticator selection, and none of them was policy-blocked. The reported-working
site and the reported-failing site are **indistinguishable** on this axis. So the
difference the user sees is *not* in this code path.

### 2.1 Effective permissions policy, as the browser reports it

`document.featurePolicy.getAllowlistForFeature(...)` — note that
`document.permissionsPolicy` is **`undefined`** in Chrome 145 and
`document.featurePolicy.toJSON` / `.forFeature` **do not exist**; only
`allowedFeatures`, `allowsFeature`, `features`, `getAllowlistForFeature` are on
the prototype. Any tooling reading `document.permissionsPolicy` against this
browser silently gets `undefined` and must not conclude "no policy".

| site | `publickey-credentials-create` | `publickey-credentials-get` | `geolocation` |
|---|---|---|---|
| `x.com` | `["https://x.com"]` | `["https://x.com"]` | `["https://x.com"]` |
| `token2 demo` | `["https://www.token2.com"]` | `["https://www.token2.com"]` | `[]` |
| `webauthn.io` | `["https://webauthn.io"]` | `["https://webauthn.io"]` | `["https://webauthn.io"]` |
| local, no header | `["http://localhost:8877"]` | `["http://localhost:8877"]` | `["http://localhost:8877"]` |
| local, `publickey-credentials-create=()` | **`[]`** | `["http://localhost:8877"]` | `["http://localhost:8877"]` |

This independently confirms the epic's header finding **through the browser**, not
through `curl`: x.com sends no `Permissions-Policy` header at all (verified:
`curl -sI https://x.com/` returns `x-frame-options: SAMEORIGIN` and a large CSP,
no `Permissions-Policy`), and the default allowlist therefore applies, and that
allowlist is `['self']`. **A top-level ceremony on x.com is permitted.**
token2's header (`permissions-policy: geolocation=(), microphone=(), camera=()`)
does not mention the feature, so its default allowlist also applies.

### 2.2 Client capabilities, as the browser reports them

`PublicKeyCredential.getClientCapabilities()` — **byte-identical on x.com, token2
and webauthn.io**:

```json
{"conditionalCreate": true, "conditionalGet": true, "hybridTransport": true,
 "passkeyPlatformAuthenticator": true, "userVerifyingPlatformAuthenticator": false,
 "relatedOrigins": true, "extension:prf": true, "extension:largeBlob": true,
 "extension:credProps": true, "extension:credBlob": true, "extension:payment": false,
 "extension:hmacCreateSecret": true, "extension:minPinLength": true,
 "extension:appid": true, "extension:appidExclude": true,
 "extension:credentialProtectionPolicy": true, "extension:enforceCredentialProtectionPolicy": true,
 "extension:getCredBlob": true,
 "signalAllAcceptedCredentials": true, "signalCurrentUserDetails": true,
 "signalUnknownCredential": true}
```

- **Transport, as far as the browser will report it:** `hybridTransport: true`
  (phone-as-authenticator is available). `passkeyPlatformAuthenticator: true` with
  `userVerifyingPlatformAuthenticator: false` — the browser supports passkeys but
  this Linux host has no built-in platform authenticator, which is expected.
- `PublicKeyCredential.getTransports` **does not exist** in this build
  (`TypeError: PublicKeyCredential.getTransports is not a function`), so the
  transport list the epic asked for could not be read from JS. See §5.
- `isUserVerifyingPlatformAuthenticatorAvailable()` → `false` on all three sites.
- `isConditionalMediationAvailable()` → `false` on the first probe run, `true` on
  a later run. **Not stable across calls in this browser**; do not treat a single
  reading as evidence either way.

---

## 3. Device discovery — what Chrome itself logged

`chrome://device-log` **is** drivable over CDP (unlike `webauthn-internals`, §5)
and accepts `?types=FIDO,USB,HID`. Loaded at
`chrome://device-log/?types=FIDO,USB,HID&refresh=5`. Verbatim, deduplicated:

```
[01:27:49] USB device added: path=/dev/bus/usb/001/099 vendor=4176 "Pol Henarejos",
           product=1031 "Fapico2", serial="7C36644DFF8A74C7",
           guid=7f423f1a-ac92-417f-8533-37dc0f7eaa75
[01:27:49] USB device added: path=/dev/bus/usb/001/007 vendor=1133 "Logitech", … "USB Receiver" …
[01:27:49] USB device added: path=/dev/bus/usb/001/013 vendor=6940 "Corsair", … "K95 RGB PLATINUM" …
… (13 USB devices total)
```

**Reading:** Chrome's USB layer *does* enumerate the reference Fapico2 board, by
the same identity strings `scripts/acceptance/ctap.py` selects on. There is **no
entry for our board** — consistent with §0.1. Of the 42 timestamped lines in the
FIDO/USB/HID filter, every one is `USB device added` (or a
`Failed to open /dev/bus/usb/…: Permission denied (13)` for an unrelated webcam
and DisplayLink adapter); **there is not a single FIDO-category line.** So this
run establishes USB-level discovery of the reference board and says nothing about
whether the WebAuthn layer adopted it.

---

## 4. The comparison that was actually available

The brief asked for the two-board control. **It was not available** — our board is
absent (§0.1), so "ours vs the C reference" degenerated to "reference only". The
comparison actually run was **context-vs-context on the reference board**, which
turned out to be the more useful one because it isolates the page-side variable
from the device-side one.

Every cell below ran in the same browser process, same origin-independent page,
`create()` with a 32-byte random challenge, `timeout: 10000`, real user activation:

| # | what was varied | result |
|---|---|---|
| A | top-level, no PP header | `NotAllowedError` @ 10002 ms — **reached selection** |
| B | **+ `Permissions-Policy: publickey-credentials-create=()`** | `NotAllowedError` @ **1 ms** — **blocked pre-device** |
| C | **cross-origin iframe** (`localhost:8844` inside `localhost:8845`), no `allow=` | `NotAllowedError` @ **1 ms** — **blocked pre-device** |
| D | **+ `allow="publickey-credentials-create"`** | `NotAllowedError` @ 1 ms, but a *different* message: user activation required — **policy check passed**, activation did not |
| ctrl | `rp.id` = IP literal | `SecurityError` @ 1 ms |

A → B changes **one response header**. C → D changes **one attribute**. A vs C
changes **only the frame relationship**. In all three the name stayed
`NotAllowedError` and only latency and message moved.

Cell D is worth separating out: with delegation the frame gets *past* the policy
gate and fails one step later on user activation. That is a distinct stage, and it
is still reported as `NotAllowedError`. Three different failure stages, one name.

---

## 5. What was NOT determined

Stated plainly, each with the reason.

| # | not determined | why |
|---|---|---|
| 1 | **The reported failure itself.** No capture of the user's actual symptom on x.com. | Our board was not attached (§0.1); nothing to fail with. |
| 2 | **X's real passkey registration flow.** The federated cross-origin iframe that the epic hypothesises was never reached. | X's passkey entry point is behind a logged-in account. Not attempted — no credentials were used, requested, or sought. Only the logged-out top-level origin was reachable. |
| 3 | **Whether the device appears in the picker.** | The authenticator-selection bubble is browser chrome; CDP `Page.captureScreenshot` renders page content only. The X display was **locked** — `xwininfo -root -tree` shows `i3lock` mapped at `5944x2560+0+0`, and every Chrome top-level window was unrealized (`10x10+10+10`), so `import -window root` captured solid black. Not fabricable; not guessed. |
| 4 | **`chrome://webauthn-internals`.** | Not reachable. `Page.navigate` lands on `chrome-error://chromewebdata/` with `ERR_INVALID_URL` for `chrome://webauthn-internals/` and `chrome://usb-devices/`. Its contents are **not** reproduced anywhere in this document. `chrome://device-log` was reachable and is quoted verbatim in §3. |
| 5 | **Per-device transport (`usb`/`nfc`/`ble`/`hybrid`) as selected for a ceremony.** | No API exposes the chosen transport to JS. `PublicKeyCredential.getTransports` is absent from this build. Only the *platform* capability (`hybridTransport: true`) is readable, §2.2. |
| 6 | **The exact transport of the X failure** | Depends on 1–3. |
| 7 | **Whether the stale holder (§0.2) suppressed FIDO adoption** | Not testable without killing another session's process. The reference board's FIDO-level enumeration is therefore unconfirmed. |
| 8 | **The other two rows of the table** — `InvalidStateError` (`excludeCredentials`), `AbortError` (client cancel) | Neither is reachable without a live RP with a stored credential for this authenticator, i.e. 1 and 2. |
| 9 | **Which of row 1 vs row 5 applies to the real failure** | Depends on 1 and 3. |

---

## 6. Answer to the epic's question

> Which row of the §1.2 table does the evidence select, and does it say the cause
> is in the firmware or in the page?

**First, the table's own key is wrong for Chrome 145 and must be fixed before it is
used as a gate.** Row 2's prediction — third-party iframe without delegation ⇒
`SecurityError` — is falsified by cell C: Chrome 145 raises **`NotAllowedError`
in 1 ms**. The table's "client reports" column cannot distinguish a page-side
policy block from a device-level timeout, because both report `NotAllowedError`.
Dispatching on the name sends page-side failures to the firmware owner.

**Second, with the corrected discriminator (elapsed time + message), the top-level
x.com ceremony selects the device-side region — rows 1 or 5, not row 2.**
Evidence: on x.com the effective allowlist for `publickey-credentials-create` is
`["https://x.com"]` (§2.1), and the synthetic `create()` ran for the **full
8002 ms timeout** before rejecting (§2). A policy-blocked request rejects in 1 ms
(cells B and C). x.com did not do that. So on the path that was reachable, the
request cleared the policy gate and reached authenticator selection.

**Third: the cause is therefore not in the page.** Every page-side mechanism the
table blames was measured and found open on x.com: the feature is enabled by
policy, the origin is a secure context, `PublicKeyCredential` is present, and the
client capabilities are identical to the site the user reports as working. The
failure, whatever it is, lives on the device/discovery side.

**Fourth — and this is the honest limit — "device-side" does not yet mean
"firmware".** Rows 1 and 5 are not separated by anything measured here, and the
board that fails is not attached, so the firmware-side rows are simply untested in
this run. What this investigation establishes is narrower and firmer than the
original gate asked for:

1. **Not the page.** The page-side explanation is excluded by measurement for the
   reachable path.
2. **Not the top-level Permissions-Policy.** Confirmed through the browser's own
   allowlist, not just by reading headers.
3. **The epic's diagnostic method is unsafe as written** and would misroute a
   genuine iframe-block into a firmware bug. Fix the discriminator first
   (`elapsedMs` + `message`), then re-run.

**The federated-iframe hypothesis is still live and still untested.** It cannot be
reached without a logged-in session, and the brief's constraint on credentials
was respected. But note what §1.1 changes for it: if X's real flow *does* run in
an undelegated third-party iframe, it will surface as **`NotAllowedError` at ~1 ms
with "feature is not enabled in this document"** — cell C, exactly. The
measurement to take when someone with a session runs it is therefore *not* the
exception name; it is **whether the rejection arrives in ~1 ms or after the full
timeout.** That single number cleanly separates "X's page blocked it" from "our
device did not answer", and it is cheap to collect from a `catch` block in the
browser console.

---

## Appendix — reproducing this

Harness (not committed; `/tmp/wa1520/`): `cdp.py` (Chrome DevTools Protocol driver
over `websocket-client`, stdlib otherwise), `probe.py`, `pass2.py`–`pass7.py`,
`final.py`; raw output in `probe-results.json`, `pass2.json` … `pass7.json`,
`final.json`.

Launch flags actually used — nothing WebAuthn-related:

```
chrome --no-first-run --no-default-browser-check \
       --user-data-dir=<temp> --remote-debugging-port=9333 \
       --no-sandbox --disable-dev-shm-usage --disable-features=Translate \
       --remote-allow-origins=http://127.0.0.1:9333
```

The `chrome-devtools-mcp` plugin in this environment could not be used: it is
pinned to `/opt/google/chrome/chrome`, which does not exist, and the only Chrome
present is the Playwright Chrome for Testing build.

The repo's own `scripts/acceptance/` harness was read for the pattern but not
reused: its `/results` POST trick needs a page we control, and the targets here
(x.com and friends) are not ours. The `Runtime.evaluate` + `userGesture: true`
activation is the CDP equivalent, and it is a *real* user activation — the
cross-origin-iframe cell D message ("A user activation is required…") proves the
gate is live and unsatisfied rather than silently absent.

Nothing in this repository was modified except this file.
