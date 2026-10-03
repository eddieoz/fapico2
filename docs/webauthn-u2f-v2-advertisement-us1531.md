# US-1531 / US-1532 / US-1533 — why browser registration failed, and what fixed it

**Status:** all three fixed and verified on hardware (`8853f88`, `b807547`,
`f5910d0`).
**Devices:** fapico2 `/dev/hidraw8` (serial `94746395`), pico-fido2 reference `/dev/hidraw10`.

## The report

Registration fails on `https://demo.yubico.com/webauthn-technical/registration`,
`x.com`, and `proton.me`: a QR-code popup appears, the board's LED blinks
quickly waiting for a touch, and pressing the button does nothing. The same
board registers fine on `https://www.token2.com/tools/fido2-demo`, which
prompts for the PIN.

## What the page asks

Captured by hooking `navigator.credentials.create` on the live page:

```json
{"attestation":"direct",
 "authenticatorSelection":{"requireResidentKey":false,"residentKey":"discouraged",
                          "userVerification":"discouraged"},
 "excludeCredentials":[], "rp":{"id":"demo.yubico.com"}, "timeout":600000}
```

`userVerification:"discouraged"` means Chrome sends `authenticatorMakeCredential`
with **no `pinUvAuthToken`**.

## What the device answers — and why that is correct

Measured on `/dev/hidraw8` with a clean consent slot:

| request | answer |
|---|---|
| `makeCredential`, no token, options absent | `0x36 PUAT_REQUIRED` |
| `makeCredential`, no token, `{rk:false}` | `0x36 PUAT_REQUIRED` |
| `makeCredential`, no token, `{rk:false, uv:false}` | `0x36 PUAT_REQUIRED` |
| `makeCredential`, no token, `{rk:true}` | `0x36 PUAT_REQUIRED` |
| `clientPIN 0x09` with the full ECDH+PIN handshake | token minted (32 B) |
| `clientPIN 0x05` with the full ECDH+PIN handshake | token minted (32 B) |
| `clientPIN 0x06` (`UsingUvWithPermissions`) | `0x3E INVALID_SUBCOMMAND` |

`0x36` is right. We advertise `makeCredUvNotRqd: false`, and CTAP 2.1 §6.1.3
then obliges the platform to acquire a token — which is why token2.com (whose
stack prompts) works. The token legs behind it both mint on hardware.

## Where it actually dies

`chrome://device-log/` is empty: the DevTools MCP browser is launched without
`--enable-logging` (`chrome://version` confirms). Relaunching Chrome with it
(`scripts/drive_logging_chrome.py`) against `/dev/hidraw8`:

```text
authenticator_request_dialog_model.cc:158 UI step: kCableV2QRCode
fido_device.cc:38 Sending CTAP2 AuthenticatorGetInfo request to authenticator.
device_response_converter.cc:403 -> {1: ["U2F_V2","FIDO_2_0","FIDO_2_1",
                                "FIDO_2_2","FIDO_2_3"],
                                4: {..., "alwaysUv": false,
                                    "makeCredUvNotRqd": false, ...}, ...}
device_response_converter.cc:426 Unexpected protocol version received.
fido_device.cc:70 The device supports the CTAP2 protocol.
fido_hid_device.cc:455            Unknown CTAPHID command: 59 02
u2f_register_operation.cc:195     Unexpected status 27264 from U2F device
fido_device_authenticator.cc:1505 CTAP error response code 127 from usb-1050:407
make_credential_request_handler.cc:825 Ignoring status 1
```

27264 == `0x6A80` == U2F `SW_WRONG_DATA`.

Reading it in order: seeing `U2F_V2` in the versions list, Chrome entered a
**U2F register**. That answered wrongly, and Chrome abandoned the **whole CTAP2
makeCredential** — `Ignoring status 1` — leaving the UI on `kCableV2QRCode`,
which is the QR-code popup. The board's consent window, opened by Chrome's own
`authenticatorSelection` probe, kept the LED blinking until it expired.

The CTAP2 path was never broken and was never reached.

## Why the reference is unaffected

`pico-fido2/src/fido/cbor_get_info.c:95-99`:

```c
bool alwaysUv = (get_opts() & FIDO2_OPT_AUV) || (file_has_data(ef_pin) && !keydev_unlocked);
CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrayEncoder, 4 + !alwaysUv));
if (!alwaysUv) {
    CBOR_CHECK(cbor_encoder_encode_text_stringz(&arrayEncoder, "U2F_V2"));
}
```

`alwaysUv` is true whenever a PIN is set and the keydev is locked — the state a
PIN-set board boots into. Measured A/B on the reference: its `versions` is
`["FIDO_2_0" … "FIDO_2_3"]` with **no `U2F_V2`**, and `alwaysUv: true`. It never
enters the failing path.

This twin has no `keydev_unlocked` concept, so `pin_set` is the faithful
equivalent of the reference's condition.

## The fix

`ctap2::u2f_v2_advertised(pin_set) = !pin_set`, applied by both twins through
`Ctap2Info::set_u2f_v2`. The seed was made fail-closed, like
`makeCredUvNotRqd` already was.

## Known gap, deliberately not hidden

With **no** PIN set, `U2F_V2` is re-advertised and CTAP1 is still broken. One
defect, one place:

U2F reaches this firmware in two framings — APDUs over CCID, and **raw U2F
messages** over `CTAPHID_MSG`. `hid_serve.rs:1089` hands the `CTAPHID_MSG`
payload straight to `process_u2f_apdu`, which needs ≥5 bytes and parses
`CLA INS P1 P2 LC` (`u2f.rs:89-112`). A raw U2F version request is the single
byte `0x05`.

| probe | answer | should be |
|---|---|---|
| U2F VERSION over `CTAPHID_MSG` (`0x05`) | `0x6700` | `U2F_V2` |
| U2F REGISTER over `CTAPHID_MSG` | `0x6E00` | key handle + cert |

Pinned by `tests/u2f_v2_advertisement.rs::ctap1_is_not_servable_yet`, so the
gap cannot be forgotten. **When that test starts failing, CTAP1 works** and
`u2f_v2_advertised` should be revisited.

`tests/device_full_set.rs:452-456` asserts `process_u2f(b"\x00\x03\x00\x00\x00")`
returns `U2F_V2\x90\x00` and passes — because it calls `app.process_u2f()`
directly, bypassing `hid_serve`. A green parity test over a path the wire does
not take: the twin trap of AGENTS.md §1 in a new place.

## Is `userVerification: discouraged` supposed to skip the PIN or the touch?

No, on both counts, and they are orthogonal:

- **Presence** (the touch) is required for every `makeCredential` regardless of
  `uv`. Both boards reject `options.up = false` (`cbor_make_credential.c:387`;
  ours at `device_core.rs:896`). No `uv` value switches it off.
- **Verification** (the PIN — something you *know*) is what `userVerification`
  governs. `discouraged` says the RP does not *require* it; it does not forbid
  the authenticator asking.
- Because we advertise `makeCredUvNotRqd: false`, `0x36 PUAT_REQUIRED` is
  mandatory, so **the PIN prompt is correct and should appear** once U2F stops
  hijacking the flow.
- The only way `discouraged` would skip the PIN is advertising
  `makeCredUvNotRqd: true` and serving a token-less makeCredential with
  presence alone — the reference's `FIDO2_OPT_MCUV_NOTRQD` mode. That leaves
  every credential on the device UV-unprotected and is not needed here.

## US-1532 — `pubKeyCredParams` was capped at 8 on the device twin

The first fix moved the failure but did not end it. With `U2F_V2` gone Chrome
reached the CTAP2 path properly — PIN prompt, token, `kClientPinTapAgain` — and
then:

```text
<- 0x1 (kAuthenticatorMakeCredential) {..., 4: [
     {"alg": -7}, {"alg": -8}, {"alg": -35}, {"alg": -36}, {"alg": -37},
     {"alg": -257}, {"alg": -47}, {"alg": -48}, {"alg": -49}, {"alg": -50}], ...}
-> (CTAP2 error code 0x15 (kCtap2ErrLimitExceeded))
```

`McReq::algs` was `HeaplessVec<i32, 8>` and `parse_mc` answers
`CTAP2_ERR_LIMIT_EXCEEDED` on overflow (`device_core.rs:340`). CTAP 2.1 §6.1.2
caps that array at nothing. Reproduced on hardware: Chrome's ten entries give
`0x15` with zero keepalives and no presence window; one algorithm arms
normally. `app.rs` keeps the same list in an unbounded `Vec`, so the whole host
suite stayed green — AGENTS.md §1's twin trap on the request parser. Capacity
is now 16, tested in both directions.

Note this is **not** a storage limit. `DEVICE_MAX_CREDS = 12`
(`device_keystore.rs:34`) is the real bound, set by the chunked snapshot slot
(12 parts x 496 B). `exclude` (capacity 8) is the per-request excludeList,
also an input, not storage; and `maxCredentialCountInList` (19) is read by
`tests/pico-fido/test_022_discoverable.py` as resident-key capacity per RP, so
lowering it to match would be a functional regression rather than a fix.

## Correction: authentication without a PIN prompt is correct

An earlier revision of this file recorded the reference's PIN-free completion on
this page as unexplained. That was wrong: the MakeCredential gate was
over-generalised to GetAssertion. The reference's rule is
`cbor_get_assertion.c:265`:

```c
if (options.uv == NULL || pinUvAuthParam.present == true) {
    uv = false;      // the platform did not ask for UV -> presence is enough
}
```

Ours matches: `device_core.rs:1242` refuses only when `req.uv == Some(true)`
and UV was not performed. So when a site asks for
`userVerification: "discouraged"`, one touch is enough with no PIN, on both
devices. token2's demo differs only in asking for `required`.

## US-1533 — `alwaysUv` must follow the PIN state, or authentication skips the PIN

With US-1532 shipped, registration prompted for the PIN and succeeded, but
`demo.yubico.com/webauthn-technical/login` still authenticated on presence
alone: no PIN prompt, LED armed, touch, done. The reference prompts there.

The gate was never the problem. Both twins already refused a token-less
`getAssertion` when `alwaysUv` was set (`app.rs:1741`,
`device_core.rs:1245`) — but `alwaysUv` was read **only** from the Config `0x02`
toggle, which defaults off. So a PIN-set device advertised `alwaysUv: false`, a
platform read false, sent a token-less assertion, and got served on presence
alone. We were refusing token-less makeCredential while advertising `false`:
the same advertisement-does-not-match-implementation class as US-1529, one
level down.

The reference derives it (`pico-fido2/src/fido/cbor_get_info.c:95`):

```c
bool alwaysUv = (get_opts() & FIDO2_OPT_AUV) || (file_has_data(ef_pin) && !keydev_unlocked);
```

— true from boot on a PIN-set device, from the same branch that drops
`U2F_V2` (US-1531). This twin has no `keydev_unlocked` concept, so `pin_set` is
the faithful second term and the Config bit stays as the first: a way to force
`alwaysUv` **on** for a PIN-less device, never to turn it **off** on one that
has a PIN. `getInfo` and the gate now read one accessor (`always_uv_effective`)
so they cannot drift again.

After flashing, the login trace on the same page:

```text
{1: 2, 2: 1}    getPINRetries
{1: 2, 2: 2}    getKeyAgreement
{1: 2, 2: 9}    getPinUvAuthTokenUsingPinWithPermissions
authenticator_request_dialog_model.cc:158 UI step: kClientPinEntry
authenticator_request_dialog_model.cc:158 UI step: kClientPinTapAgain
```

Three tests asserted the old behaviour and now state the new — two of them had
started passing **for the wrong reason**, reaching their subject through a
token-less request that is now gated earlier:

* `uv.rs::always_uv_is_advertised_true_when_a_pin_is_set` (new) — the
  advertisement itself, with no toggle involved. Without it nothing asserted
  the claim Chrome actually reads.
* `uv.rs::test_always_uv_gates_mc_and_ga` — "alwaysUv off must not gate" was
  only ever true for a PIN-less device.
* `uv.rs::test_discoverable_skips_cred_protect_2_without_uv` and
  `credmgmt.rs::test_u2f_registration_not_discoverable` — both reached their
  real subject through a token-less request; they now carry a properly scoped
  `pinUvAuthParam` (key `0x06`, which both twins use — `0x04` is `extensions`).

Falsified by reverting `always_uv_advertised` to the config bit alone: three
of them fail, including the advertisement test.

## Verification

| | result |
|---|---|
| demo.yubico.com registration | succeeds — PIN prompt, touch, registered |
| demo.yubico.com authentication | succeeds — touch only, authenticated |
| token2.com registration | succeeds — `User verification: required`, AAGUID `66617069-...` |
| token2.com login | **"Login successful v"**, "Credential matched the registered key" |
| demo.yubico.com end-to-end | registration > PIN > touch > authentication > **PIN** > touch > authenticated |
| token2.com under US-1533 | registers and logs in; "Login successful v" |
| `alwaysUv` on hardware | `true`; a token-less `getAssertion` answers `0x36` |
| authData from demo.yubico.com | `rpIdHash` = SHA-256("demo.yubico.com"), flags `0x45` (UP+UV+AT), signCount 328 |
| Chrome's U2F lines after the fix | zero `u2f_register` / `Ignoring status` |
| wrong PIN | refused `0x31`; empty PIN refused `0x31` |
| fido suite | 54 suites, 0 failures |
| UF2 | 1,572,352 B = 1535.5 KiB, slack 512 B, ratchet unchanged |

## Known gaps, deliberately not hidden

* **CTAP1 over `CTAPHID_MSG`** — raw U2F messages are fed to the APDU parser,
  so a U2F version request answers `0x6700` instead of `"U2F_V2"`. Unreachable
  from a browser while a PIN is set, because `U2F_V2` is withheld. Pinned by
  `tests/u2f_v2_advertisement.rs::ctap1_is_not_servable_yet`.
* **GetInfo key `0x1D`** carries `max_pin_length` (`ctap2.rs:392`), but CTAP 2.1
  assigns that key to `remainingDiscoverableCredentials`. A conformant client
  reads 63 free discoverable slots where the device holds 12. Same
  advertisement-does-not-match-implementation class as `makeCredUvNotRqd`.
* **`u2f_v2_advertised` keys on `pin_set` alone**, so a PIN-less board with
  Config `0x02` set would advertise `alwaysUv: true` *and* `U2F_V2`, where the
  reference withholds the latter. Unreachable through any client (the toggle
  needs a `PERM_ACFG` token, which needs a PIN).