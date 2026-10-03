# US-1521 — the two-board control: does the picker difference follow the firmware?

**Run date:** 2026-10-03 09:16–10:30 EEST (UTC 06:16–07:30)
**Browser:** `Chrome/145.0.7632.6` — Google Chrome for Testing, Playwright cache
(`~/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome`), **headed** on
`DISPLAY=:0` under i3, isolated on workspace 8. No WebAuthn-related feature flags.
**UA:** `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36`
**OS:** Ubuntu 24.04.4 LTS, Linux 6.8.0-142-generic x86_64, X11 on `:0` (4920x2560 virtual desktop).

This is the run `docs/webauthn-browser-failure-class-us1520.md` could not make: that
one collapsed to reference-only because our board was off USB. Both boards were
present for this one, each was run **alone**, and the result is the opposite of the
expected shape.

No firmware was changed. Nothing in the repository was modified except this
document and `docs/evidence/us1521/`.

---

## 0. Preconditions, and one correction to the brief

### 0.1 The hidraw node numbers in the brief are stale

The brief gives ours as `/dev/hidraw8` and the reference as `/dev/hidraw13`.
Measured from sysfs at the start of this run, selecting by USB identity:

```
$ for n in $(ls /sys/class/hidraw/); do ... readlink -f .../device ... done
hidraw9  -> 1-1     1050:0407  EddieOz          94746395      rd=06d0f10901a1  (FIDO)
hidraw10 -> 1-1     1050:0407  EddieOz          94746395      rd=05010906a101  (OTP)
hidraw13 -> 1-4.2   1050:0407  Pol Henarejos   7C36644DFF8A74C7  rd=06d0f10901a1  (FIDO)
hidraw14 -> 1-4.2   1050:0407  Pol Henarejos   7C36644DFF8A74C7  rd=05010906a101  (OTP)

$ udevadm info -q path -n /dev/hidraw8
Unknown device "/dev/hidraw8": No such device
```

**`/dev/hidraw8` exists as a device node but has no sysfs backing.** Ours is
`hidraw9`/`hidraw10`; the reference is `hidraw13`/`hidraw14`, as the brief says.
This is exactly the failure the brief's own warning ("select by USB identity,
never by node order") exists to prevent, and following the brief literally would
have measured nothing.

USB topology, for the record: ours is on port `1-1` (root hub, bus 001 device
`111`); the reference is behind a VIA hub at `1-4.2` (bus 001 device `099`).

### 0.2 The isolation mechanism: a mount namespace, not `unbind`

The brief suggests unbinding the reference from `/sys/bus/usb/devices/1-4.2/driver/unbind`.
**That is not available here** — the file is `--w------- root root` and `sudo -n`
requires a password:

```
$ ls -l /sys/bus/usb/devices/1-4.2/driver/unbind
--w------- 1 root root 4096 ... /sys/bus/usb/devices/1-4.2/driver/unbind
$ sudo -n true
sudo: a password is required
```

What *is* available is an unprivileged user namespace
(`/proc/sys/kernel/unprivileged_userns_clone = 1`, `max_user_namespaces = 255248`).
Chrome is launched inside `unshare --map-root-user --mount`, with the board being
hidden shadowed by bind mounts that exist **only in that process tree**:
its sysfs device directory (`/sys/bus/usb/devices/<port>`) over an empty dir, plus
`/dev/hidrawN` and `/dev/bus/usb/001/NNN` over `/dev/null`.

**Shadowing `/dev` alone is not enough — measured.** First attempt hid only the
device nodes; Chrome still listed the board:

```
### REFERENCE HIDDEN (hidraw13/14 + usb/001/099) -> 2 Fapico2 USB entries
     USB device added: path=/dev/bus/usb/001/099 ... "Pol Henarejos" ... "7C36644DFF8A74C7"
     USB device added: path=/dev/bus/usb/001/111 ... "EddieOz"        ... "94746395"
```

Chrome enumerates through udev, which reads `/sys`. With the sysfs directory
shadowed as well, the board disappears:

```
### BOTH VISIBLE (control)                                  -> 2 entries (099 Pol Henarejos, 111 EddieOz)
### REFERENCE HIDDEN (+ sysfs 1-4.2)                        -> 1 entry  (111 EddieOz)
### OURS HIDDEN     (+ sysfs 1-1)                           -> 1 entry  (099 Pol Henarejos)
```

This is strictly safer than the `unbind` the brief suggests: it cannot leave a
board unbound if a run dies, it cannot race another session, and it needs no
root. **Nothing global was modified at any point in this run** — the boards were
never unbound, and `lsusb` output is byte-identical before and after.

### 0.3 Human input

The user is present and was asked. During a preliminary local smoke test both
boards were attached, Chrome raised a PIN prompt, and the ceremony completed in
7982 ms. **The user confirmed they entered the PIN and touched a board.** That
run is therefore contaminated and is discarded as a control; it is not cited
below. For the four measured cells the user was asked to keep hands off and
confirmed they would. No PIN was entered, no button was touched, and no
credential was created on either board during the measured cells.

**This is a PIN-prompt experiment, not a ceremony.** No cell reached a completed
registration. Nothing here should be read as "registration works" or "registration
fails on X".

---

## 1. Method

One board visible at a time. Real page, real origin, real trusted input:

- Chrome navigated to the live origin (`https://x.com/` or
  `https://www.token2.com/tools/fido2-demo`).
- `document.featurePolicy.getAllowlistForFeature('publickey-credentials-create')`
  and `PublicKeyCredential.getClientCapabilities()` read on that origin.
- A `WACREATE` button injected; the ceremony started with **CDP
  `Input.dispatchMouseEvent`** — a genuine trusted click, not a
  `Runtime.evaluate` user-gesture flag.
- Root-window screenshot every second (i3 fullscreen on a dedicated workspace),
  so browser chrome — which `Page.captureScreenshot` cannot see — is on record.
- `chrome://device-log/?types=FIDO,USB,HID` read before and after, walked through
  shadow DOM (the log body reads as empty to `document.body.innerText`).

The ceremony, identical in all four cells:

```js
await navigator.credentials.create({ publicKey: {
  challenge: <32 random bytes>, rp: { name: location.hostname, id: location.hostname },
  user: { id: <32 random bytes>, name: 'probe@example.invalid', displayName: 'probe' },
  pubKeyCredParams: [{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
  timeout: 12000, attestation: 'none', excludeCredentials: [] }});
```

---

## 2. The four cells

### 2.1 The head result

**Both boards appear in Chrome's authenticator UI on both sites.** In all four
cells Chrome raised its security-key dialog and reached PIN entry. The cell that
had never been observed — "does the device appear in the picker" — is answered
**YES for all four**, and it does not separate the boards.

| | **x.com** (reported failing) | **token2 demo** (reported working) |
|---|---|---|
| **OURS** `EddieOz/94746395` | device **offered**; PIN dialog; promise pending at 95 s | device **offered**; PIN dialog; promise pending at 40 s |
| **REFERENCE** `Pol Henarejos/7C36644DFF8A74C7` | device **offered**; PIN dialog; promise pending at 40 s | device **offered**; PIN dialog; promise pending at 40 s |

Screenshots: `docs/evidence/us1521/ours__x-picker.png`,
`reference__x-picker.png`, `ours__token2-picker.png`,
`reference__token2-picker.png`. All four show the same dialog, byte-for-byte in
structure:

```
┌──────────────────────────────────┐
│              [key glyph]         │
│ PIN required                     │
│ Enter the PIN for your security  │
│ key                              │
│ PIN  ______________________      │
│ [Save another way] [Cancel] [Next]│
└──────────────────────────────────┘
```

### 2.2 Full cell table

`elapsedMs` is the JS-measured time to rejection. Two different numbers appear and
they mean different things; §3 explains why.

| cell | board | site | picker visible | exception | `elapsedMs` | message | natural unattended outcome |
|---|---|---|---|---|---|---|---|
| 1 | ours | x.com | **yes** | `NotAllowedError` | **14 427** | "The operation either timed out or was not allowed. See: …#sctn-privacy-considerations-client." | none — pending at 95 s |
| 2 | reference | x.com | **yes** | `NotAllowedError` | **14 403** | identical | none — pending at 40 s |
| 3 | ours | token2 | **yes** | `NotAllowedError` | **14 413** | identical | none — pending at 40 s |
| 4 | reference | token2 | **yes** | `NotAllowedError` | **14 396** | identical | none — pending at 40 s |

Plus one uncontrolled run, cell 1 repeated, in which **no dialog appeared at all**
and the promise settled on its own:

```
SETTLED at 10.1s: {"outcome":"REJECTED","name":"NotAllowedError","ms":9428,
 "message":"The operation either timed out or was not allowed. See:
 https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client."}
```

Spread across the four cells: 31 ms on a 14.4 s base, i.e. **0.2 %**. There is no
separation between the boards on the page-side axis, and none on the device-side
axis.

### 2.3 Environment, as the browser reports it

| | x.com | token2 demo |
|---|---|---|
| `final URL` | `https://x.com/` | `https://www.token2.com/tools/fido2-demo` |
| `isSecureContext` | `true` | `true` |
| `PublicKeyCredential` | present | present |
| allowlist `publickey-credentials-create` | `["https://x.com"]` | `["https://www.token2.com"]` |
| allowlist `publickey-credentials-get` | `["https://x.com"]` | `["https://www.token2.com"]` |
| `typeof document.permissionsPolicy` | `undefined` | `undefined` |
| transport, per GetInfo | `["usb"]` | `["usb"]` |
| transport in device-log | `Discovery started for transport 0` (0 = USB) | same |

`PublicKeyCredential.getClientCapabilities()` returned **`{}`** in every cell
this run, where US-1520 recorded a full capability object. Combined with US-1520's
own note that `isConditionalMediationAvailable()` "is not stable across calls",
this is **NOT DETERMINED** — recorded as observed, not interpreted.

Both sites clear the policy gate. The request is not blocked before the device is
consulted; the ~14 s and the visible dialog both happen after selection.

---

## 3. The elapsed-time number needs a caveat, and it breaks the gate's discriminator

The four `elapsedMs` values are real but **they are not a device timeout**. In
each of those runs the promise was still pending when the harness pressed Escape
at t≈13 s to dismiss Chrome's dialog; the rejection that followed is the
consequence of that dismissal, not of the `timeout: 12000` that was requested.
14 427 ms is "13 s of waiting, then a client cancel", not "the device took 14 s".

The honest characterisation of the natural unattended state, measured:

1. With Chrome's PIN dialog up, `create()` **does not settle**. Observed pending
   at **40 s** (four cells), **95 s**, **286 s** and **335 s** in dedicated runs.
   The JS `timeout: 12000` does **not** fire while that dialog is open.
2. Around **70–80 s** Chrome replaces the PIN dialog with its own error dialog
   (`docs/evidence/us1521/timeout-dialog.png`):

   ```
   Something went wrong
   The request timed out
   [Close]
   ```
   Frames from `ours__x`: PIN dialog at t=10/40/60/70 s, "Something went wrong"
   first at t=80 s. **The JS promise still does not settle** while that dialog is
   up either — it is pending at 95 s.
3. Only when something dismisses the dialog does JS see a rejection.

So in this configuration the ceremony produces **no DOMException at all** to a
passive observer, for minutes. US-1520's proposed discriminator — "≈1 ms =
rejected pre-device; ≈ full `timeout` = selection reached, nothing answered" — does
not survive this either: here the elapsed-to-rejection is 14 s, or ~75 s, or never,
against a requested `timeout` of 12 000 ms, and the two boards are indistinguishable
throughout. **The discriminator needs a third state, "pending behind a browser
dialog", and that state is not in the epic's table.**

One further observation, recorded because it contradicts an expectation rather than
supporting it: re-running with `userVerification: 'discouraged'` **still produced
the PIN dialog**. Chrome 145 asks for the PIN even when the RP discourages UV, on a
key that has one set. That is one more instance of the rule this epic keeps
relearning — claims about what the client does have to be executed.

---

## 4. Wire correlation (`chrome://device-log`)

Each cell adopted exactly the intended board. Verbatim HID lines:

```
ours__x:      HID device detected: vendorId=4176, productId=1031,
              name='EddieOz Fapico2', serial='94746395'      -> .../hidraw9
ours__token2: (identical)
reference__x: HID device detected: vendorId=4176, productId=1031,
              name='Pol Henarejos Fapico2', serial='7C36644DFF8A74C7' -> .../hidraw13
reference__token2: (identical)
```

So the isolation was verified at the level that matters — not only that a board
vanished from a USB line, but that Chrome's HID layer opened the right node and
talked CTAP to it.

The CTAP trace for each board is structurally identical. Verbatim, ours:

```
FIDO Event  [09:35:12] UI step: kUsbInsertAndActivate
FIDO Debug  [09:35:12] Transport availability checks done
FIDO Debug  [09:35:12] Discovery started for transport 0
FIDO Debug  [09:35:12] Sending CTAP2 AuthenticatorGetInfo request to authenticator.
FIDO Debug  [09:35:13] -> {1: ["U2F_V2", "FIDO_2_0", "FIDO_2_1", "FIDO_2_2", "FIDO_2_3"],
             2: ["credBlob","credProtect","hmac-secret","largeBlobKey","minPinLength"],
             3: h'66617069636F32000000000000000002',
             4: {"rk":true,"alwaysUv":false,"credMgmt":true,"authnrCfg":true,
                 "clientPin":true,"largeBlobs":true,"pinUvAuthToken":true,
                 "setMinPINLength":true,"makeCredUvNotRqd":false,
                 "enterpriseAttestation":true},
             ... 9: ["usb"] ... 31: [1,2,3,255]}
FIDO Debug  [09:35:13] Unexpected protocol version received.
FIDO Debug  [09:35:13] The device supports the CTAP2 protocol.
FIDO Debug  [09:35:13] -> {3: 8}
FIDO Debug  [09:35:13] <- 0x6 (kAuthenticatorClientPin) {1: 2, 2: 1}
FIDO Event  [09:35:13] UI step: kClientPinEntry
```

and the reference:

```
... -> {1: ["FIDO_2_0","FIDO_2_1","FIDO_2_2","FIDO_2_3"],
        2: [...,"uvm",...,"hmac-secret-mc","thirdPartyPayment"],
        3: h'89FB94B706C936739B7E30526D968145',
        4: {"rk":true,"alwaysUv":true,"credMgmt":true,"authnrCfg":true,
            "clientPin":true,"largeBlobs":true,"perCredMgmtRO":true,
            "pinUvAuthToken":true,"setMinPINLength":true,"makeCredUvNotRqd":false},
        ... 5:1024, 7:16, 8:1024 ...}
... -> {3: 2, 4: true}
... <- 0x6 (kAuthenticatorClientPin) {1: 2, 2: 1}
... UI step: kClientPinEntry
```

Both boards reach `kClientPinEntry`. Both answer `authenticatorClientPin` (opcode
`0x6` — the fido2 2.2.1 dialect, not the CTAP 2.1 `0x04`, as `AGENTS.md` requires).
`Unexpected protocol version received.` appears **once per cell on both boards**,
consistent with the INIT version bytes carrying the YubiKey firmware version rather
than the CTAPHID protocol version.

### 4.1 The one real firmware-attributable wire difference

Chrome's PIN probe is `getPinRetries` — `{1: 2, 2: 1}` = protocol 2, sub-command 1.
The two boards answer differently:

| | response | reading |
|---|---|---|
| ours | `{3: 8}` | `pinRetries = 8`, no power-cycle flag |
| reference | `{3: 2, 4: true}` | `pinRetries = 2`, `powerCycleState = true` |

This decode is not guessed. `apps/fido/src/device_core.rs:1632-1644` emits exactly
this shape for sub-command `0x01`:

```rust
no_heap::push_map_header(out, if power { 2 } else { 1 }).ok();
no_heap::push_uint(out, 3).ok();
no_heap::push_uint(out, retries as u64).ok();
if power { no_heap::push_uint(out, 4).ok(); no_heap::push_bool(out, true).ok(); }
```

with `retries: 8` as the shipped default (`apps/fido/src/device_keystore.rs:733`,
`MAX_PIN_RETRIES = 8` in `apps/fido/src/pin.rs:51`, matching
`picoforge/src/hal/fido/constants.rs:799`). So ours reports a full, un-latched
retry budget; the reference reports two retries left and a latched power-cycle
state.

**Neither value blocked discovery or the offer.** Both boards reached the picker
and `kClientPinEntry` regardless.

### 4.2 The site makes no difference on the wire

With timestamps stripped, the device-log of ours-on-x.com and
ours-on-token2 are **byte-identical**, and likewise for the reference:

```
$ diff <(sed 's/\[[0-9:]*\]//' devlog-ours-x.txt) \
       <(sed 's/\[[0-9:]*\]//' devlog-ours-token2.txt)      # no output, rc=0
$ diff <(sed 's/\[[0-9:]*\]//' devlog-reference-x.txt) \
       <(sed 's/\[[0-9:]*\]//' devlog-reference-token2.txt) # no output, rc=0
$ diff <(sed 's/\[[0-9:]*\]//' devlog-ours-x.txt) \
       <(sed 's/\[[0-9:]*\]//' devlog-reference-x.txt) | wc -l
127
```

The reported-working site and the reported-failing site produce an identical
device-side trace. Whatever differs between them is not visible to the
authenticator.

---

## 5. Which row does each board select?

**Both boards select the same row, and it is row 1.**

- **Row 2 (`SecurityError`, page-side)** — excluded by measurement. Both origins
  are secure contexts with the feature enabled in the effective allowlist, and the
  request ran for seconds and raised a real dialog. US-1520 already showed the name
  `NotAllowedError` is reported even for a page-side block, so the exclusion here
  rests on the allowlist and the elapsed time, not on the name.
- **Row 3 (`InvalidStateError`)** — not observed.
- **Row 4 (`AbortError`)** — not observed spontaneously. The only cancellations in
  this run were ones the harness performed deliberately, and those surface as
  `NotAllowedError`, not `AbortError`.
- **Row 5 (device never appears in the picker)** — **excluded by direct
  observation for both boards on both sites.** This is the cell US-1520 could not
  reach and the one this run was built for. Both boards were offered.
- **Row 1 (`NotAllowedError`, device-level)** — selected by both boards.

Row 1's own sub-mechanism is not separated. The honest statement is: both boards
fail in the device-level region, and the discriminator that was supposed to
separate row 1 from row 5 is not needed here because **row 5 was directly excluded
instead**.

---

## 6. Does the difference follow the firmware? (DoD item 1)

**No — and the premise that there is a difference to follow does not survive the
measurement.**

The reported control is: *the C reference board IS recognised by X; ours is NOT.*
Same browser, same page, same OS, same policy, only the firmware differs. Run
identically against both boards, on both sites, with each board alone on the bus:

- Both boards are enumerated by Chrome's HID layer, by name and serial.
- Both boards answer `AuthenticatorGetInfo`.
- Both boards are **offered to the user** — Chrome's dialog names a "security key"
  and asks for its PIN in all four cells.
- Both reach `kClientPinEntry`.
- Both reject with `NotAllowedError` and the same message, within 31 ms of each
  other on a 14.4 s base.
- The device-side wire trace is identical between the two sites.

There is no discovery, offer, or protocol difference between the boards. **The
symptom did not reproduce on the path that was reachable**, so this run does not
support a firmware cause — and, equally, it does not exonerate the firmware,
because it did not exercise the path where the symptom was reported (§7).

The firmware-attributable differences that *were* found — `pinRetries = 8` with no
power-cycle latch versus `pinRetries = 2` with `powerCycleState = true`; `alwaysUv:
false` versus `true`; `enterpriseAttestation: true` and `perCredMgmtRO: true`; a
der-encoded AAGUID (`h'66617069636F32…'` is ASCII `fapico2` padded); different
`maxCredBlob`/`maxCredentialIdLength`/`maxCredCountInList`; `U2F_V2` advertised by
ours and not by the reference — **had no effect on whether Chrome offered the
device.** None of them is a plausible cause for "the device does not appear".

---

## 7. NOT DETERMINED

| # | not determined | why |
|---|---|---|
| 1 | **X's real passkey registration flow.** | Behind a logged-in account. Not attempted — no login, no credential, no credential requested or sought. Only the logged-out top-level origin was reachable. Everything above is about a synthetic `create()` on `https://x.com/`, which is **not** the flow the user reports failing. |
| 2 | **The reported symptom itself.** | Did not reproduce. The measurement above rules out a firmware-caused discovery failure *for the top-level logged-out ceremony*; it says nothing about the federated / logged-in flow. |
| 3 | **Whether either board can complete a registration on either site.** | Needs a PIN entry and a touch, both declined for this run by agreement. **No ceremony was completed and none is claimed.** |
| 4 | **Whether the reference's `powerCycleState = true` is pre-existing.** | Present on the first read of that board, before any run in this session touched it. Not caused by this investigation; cause unknown. |
| 5 | **Whether the ~70–80 s figure is stable.** | Sampled on one cell (frames at 70 s and 80 s bracketing the transition). The 40/95/286/335 s pending observations are likewise point samples of "still pending". |
| 6 | **`PublicKeyCredential.getClientCapabilities()` contents.** | Returned `{}` in all four cells, against a full object in US-1520. Unexplained; recorded, not interpreted. |
| 7 | **Per-device transport as actually selected for a ceremony.** | No JS API exposes it. Only the authenticator-advertised `transports: ["usb"]` and `Discovery started for transport 0`. |
| 8 | **Rows 3 and 4 as they occur in practice.** | `InvalidStateError` needs an RP with a stored credential for this authenticator; `AbortError` needs a client cancel. Neither is reachable without 1 and 3. |
| 9 | **Whether Chrome's PIN dialog or its 12 s `timeout` behaves differently on a machine with a built-in platform authenticator.** | This host has none (`passkeyPlatformAuthenticator: true`, `userVerifyingPlatformAuthenticator: false`). |

---

## 8. Reproduction

Harness in `/tmp/warows/` (not committed): `cdp.py` (CDP driver),
`wm.py` (i3/X helpers), `measure.py` (four cells + device-log), `settle.py`
(exception capture), `isolation_check.py` (the isolation proof in §0.2).
Artifacts committed under `docs/evidence/us1521/`.

Launch flags — nothing WebAuthn-related:

```
chrome --no-first-run --no-default-browser-check \
       --user-data-dir=<fresh> --remote-debugging-port=<port> \
       --remote-allow-origins=http://127.0.0.1:<port> \
       --no-sandbox --disable-dev-shm-usage --disable-features=Translate \
       --window-position=0,0 --window-size=1200,900 \
       --password-store=basic --use-mock-keychain about:blank
```

Board isolation, per cell, inside `unshare --map-root-user --mount`:

```sh
mount --make-rprivate /
mount --bind <emptydir> /sys/bus/usb/devices/1-4.2      # hide the reference
mount --bind /dev/null  /dev/hidraw13
mount --bind /dev/null  /dev/hidraw14
mount --bind /dev/null  /dev/bus/usb/001/099
# ... exec chrome
```

Realism note: the picker screenshots are root-window grabs (`import -window
root`) of an i3-fullscreen Chrome, not CDP screenshots — CDP cannot see browser
chrome, which is why US-1520 recorded that cell as unreachable.

## 9. Boards restored

Both boards were left exactly as found. They were never unbound, never
re-enumerated, never reset; the hiding was namespace-local and died with Chrome.

```
$ lsusb | grep 1050
Bus 001 Device 099: ID 1050:0407 Yubico.com Yubikey 4/5 OTP+U2F+CCID
Bus 001 Device 111: ID 1050:0407 Yubico.com Yubikey 4/5 OTP+U2F+CCID

$ python3 scripts/acceptance/ctap.py
  /dev/hidraw13  Pol Henarejos  Fapico2  7C36644DFF8A74C7  bcdDevice 9.00  CTAPHID
  /dev/hidraw9   EddieOz        Fapico2  94746395        bcdDevice 0.10  CTAPHID
```

No process holds either CTAPHID node. `/dev/hidraw13` was never opened by this
investigation; it was read only through sysfs, `chrome://device-log`, and the
repo's own descriptor-sniffing enumerator.
