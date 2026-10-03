# US-1531 — a PIN-set device must not advertise `U2F_V2`

**Status:** fixed (`8853f88`), hardware verification pending a power cycle.
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

## Unresolved

The reference was observed completing this page with **no PIN prompt**, yet it
returns `0x36` to a token-less makeCredential exactly as we do, which obliges
Chrome to prompt. Not reproduced; not rewritten. It does not change the fix —
either way the reference does not enter the failing U2F path — but it would be
settled by one confirmation run with both boards attached.