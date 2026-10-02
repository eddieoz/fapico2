
# How to read the two option asymmetries (US-1529)

Everything below is a raw, unedited `scripts/probe_ab_devices.py` transcript
taken against both boards. The transcript is evidence; it is not a
conclusion. Two `getInfo` differences between **A** (this firmware) and **B**
(the C reference) have been read as "ours is more permissive, so ours should
work at least as well". That reading was wrong in both directions, and US-1529
is what established it. Re-run the probe before quoting a line from here: the
option values below are from the **pre-fix** firmware.

| option | A (ours, then) | B (C reference) | verdict |
|---|---|---|---|
| `makeCredUvNotRqd` | `true` | `false` | **A was lying.** A hard-coded `true` claimed a UV relaxation A does not implement; with a PIN set A answers `0x36` to the very request the claim licenses. Fixed: it is now derived (`!pin_set && !always_uv`), so A reports `false` with a PIN set — matching B, and matching what A actually does. |
| `alwaysUv` | `false` | `true` | **Not an asymmetry to fix.** B advertises the *more* restrictive value, so this difference cannot explain A failing where B succeeds. A's `alwaysUv` was already derived from the same config bit its gate reads. It is kept here only because §6.1.3 makes `alwaysUv: true` force `makeCredUvNotRqd: false` — the two options are coupled, so they must now be read together. |

## Why the `makeCredUvNotRqd` value mattered

The installed client decides whether to ask for a PIN before a
`makeCredential` **from this option by name**
(`fido2/client/__init__.py::_should_use_uv`):

```python
elif mc and uv_configured and not info.options.get("makeCredUvNotRqd"):
    return True
```

A read `true`, it declines to request UV; `make_credential` then sends
`opts = None` (`fido2/client/__init__.py:833`) — a `makeCredential` with no
options map and no `pinUvAuthParam` — which A answered `0x36`. B, reporting
`false`, sends the client down the PIN path and succeeds. So the asymmetry was
not "A is laxer": it was A advertising a capability in order to be handed a
request it refuses.

## The remaining unexplained difference

Neither board was probed with a `makeCredential` that differs only in its UV
handling, because both answer `0x36` to a bare one — **for different reasons**,
which is worth stating so the next reader does not repeat the shortcut:

* **A** refuses at `device_core.rs::make_credential_inner`, the 8.1 gate
  (`pin_set && pinUvAuthParam absent && uv != false`). It is the
  *PIN-set* rule, and a PIN-less A answers `0x00`.
* **B** refuses at `pico-fido/src/fido/cbor_make_credential.c:393`, the
  `FIDO2_OPT_AUV` branch, which is unconditional once `alwaysUv` is set — it
  fires *even with no PIN file present*. B's `alwaysUv: true` is therefore a
  stronger claim than "a PIN is set".

So "both answer 0x36, because a PIN is set on both" conflates two different
mechanisms. Do not use that sentence as a shared explanation.

**Not determined:** whether the `makeCredUvNotRqd` lie was *the* cause of the
reported browser symptom (a device not offered as a passkey authenticator on
some sites). The mechanism above is real and is in the create path, but no
browser source was read and no browser was driven; the board's flashed image is
still the pre-fix one. Treat it as a fixed wire-level incoherence of the same
class as US-1512, not as a confirmed root cause.

---

```text
python  : 3.12.3
fido2   : 2.2.1

==============================================================================
PROBE 0 — device inventory and positive identification
==============================================================================
  2 FIDO CTAPHID device(s) with 1050:0407 found.
    /dev/hidraw10: iManufacturer='EddieOz' iProduct='Fapico2' iSerial='94746395' bcdDevice=None hidName='EddieOz Fapico2' hidUniq='94746395'
    /dev/hidraw13: iManufacturer='Pol Henarejos' iProduct='Fapico2' iSerial='7C36644DFF8A74C7' bcdDevice=None hidName='Pol Henarejos Fapico2' hidUniq='7C36644DFF8A74C7'
  DEVICE A (our Rust firmware): iManufacturer='EddieOz' iProduct='Fapico2' iSerial='94746395' bcdDevice=None -> /dev/hidraw10 (usb ('1', '104'))
  DEVICE B (pico-fido2 C reference): iManufacturer='Pol Henarejos' iProduct='Fapico2' iSerial='7C36644DFF8A74C7' bcdDevice=None -> /dev/hidraw13 (usb ('1', '099'))
  Identified by USB iManufacturer, NOT by hidraw node number.

==============================================================================
PROBE 0b — framer self-test on each device (before any reading is trusted)
==============================================================================
  A CTAPHID frame written to /dev/hidrawN WITHOUT the leading hidraw report-id
  byte still produces a plausible INIT reply on the broadcast channel, because
  the first channel-id byte gets consumed as the report id. Only a PING on the
  assigned non-broadcast channel proves the framer. An earlier revision of this
  script got this wrong and reported a column of bogus timeouts.

  [A] framer self-test PASSED on /dev/hidraw10 (iManufacturer='EddieOz'): INIT ok, PING echoed on cid 0x00000002

  [B] framer self-test PASSED on /dev/hidraw13 (iManufacturer='Pol Henarejos'): INIT ok, PING echoed on cid 0x63000000

==============================================================================
PROBE 1 — CTAPHID_INIT (0x06), broadcast channel, fixed 8-byte nonce
==============================================================================
  Random-nonce re-check (confirms the echo tracks the request):

         de-facto column source: fido2.hid.CAPABILITY in /home/eddieoz/Projects/git/pico/pico-fido2/.test-venv/lib/python3.12/site-packages/fido2/hid/__init__.py -> {'WINK': '0x1', 'LOCK': '0x2', 'CBOR': '0x4', 'NMSG': '0x8'}

  [A] CTAPHID_INIT reply in 9.9 ms
      nonce sent      : 0102030405060708
      full payload hex: 0102030405060708000000030205040004  (17 bytes)
      SEND ffffffff860008010203040506070800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      RECV ffffffff860011010203040506070800000003020504000400000000000000000000000000000000000000000000000000000000000000000000000000000000
      echo nonce      : 0102030405060708  match=True
      byte 8  cid     : 0x00000003
      byte 12 verIf   : 2  (CTAPHID protocol version)
      bytes 13..15 fw : 5.4.0  (YubiKey firmware version field, NOT a CTAP version)
      BYTE 16 capFlags: 0x04
         spec CTAP 2.1 : WINK(0x04)
         de-facto sdk  : CBOR(0x04)
         -> spec convention (CTAP 2.1) concludes CBOR supported? NO  (tests bit 0x01)
         -> de-facto convention (pico-keys-sdk/fido2) concludes CBOR supported? YES  (tests bit 0x04)

         de-facto column source: fido2.hid.CAPABILITY in /home/eddieoz/Projects/git/pico/pico-fido2/.test-venv/lib/python3.12/site-packages/fido2/hid/__init__.py -> {'WINK': '0x1', 'LOCK': '0x2', 'CBOR': '0x4', 'NMSG': '0x8'}

  [B] CTAPHID_INIT reply in 372.3 ms
      nonce sent      : 0102030405060708
      full payload hex: 0102030405060708640000000208000005  (17 bytes)
      SEND ffffffff860008010203040506070800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      RECV ffffffff860011010203040506070864000000020800000500000000000000000000000000000000000000000000000000000000000000000000000000000000
      echo nonce      : 0102030405060708  match=True
      byte 8  cid     : 0x64000000
      byte 12 verIf   : 2  (CTAPHID protocol version)
      bytes 13..15 fw : 8.0.0  (YubiKey firmware version field, NOT a CTAP version)
      BYTE 16 capFlags: 0x05
         spec CTAP 2.1 : CBOR(0x01) + WINK(0x04)
         de-facto sdk  : WINK(0x01) + CBOR(0x04)
         -> spec convention (CTAP 2.1) concludes CBOR supported? YES  (tests bit 0x01)
         -> de-facto convention (pico-keys-sdk/fido2) concludes CBOR supported? YES  (tests bit 0x04)



==============================================================================
PROBE 2 — authenticatorGetInfo (opcode 0x04, fido2 dialect)
==============================================================================

      (GetInfo answered on the last of 3 attempts after 0 failure(s); failures: [])

  [A] authenticatorGetInfo (opcode 0x04, fido2 dialect) in 79.9 ms
      full payload hex: 00b50185665532465f5632684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302856863726564426c6f626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e677468035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f468637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f575656e74657270726973654174746573746174696f6ef505191db90682010207130818800981637573620a84a263616c672664747970656a7075626c69632d6b6579a263616c672764747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b65790b1904000cf40d040e010f182010187815861b6fcb19b0cbe3acfa1b7b392a394de9f9481b76a85945985d02fd1b269f3b09eceb805f1b0004e532e1feb2fd1b0005961ecba040f91819582027ae41e4649b934ca495991b7852b855829904101e37120b4ce26dfd9b252b1c181d183f181e5820e3b0c44298fc1c149afbf4c8996fb924b5d2a3f122fbfc9155a89edb0f922eee181f8401020318ff  (527 bytes)
      SEND 00000005900001040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      RECV 0000000590020f00b50185665532465f5632684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302856863726564426c6f
      RECV 0000000500626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e677468035089fb94b706c9
      RECV 000000050136739b7e30526d96814504aa62726bf568616c776179735576f468637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a
      RECV 00000005026c61726765426c6f6273f56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f7452
      RECV 00000005037164f575656e74657270726973654174746573746174696f6ef505191db90682010207130818800981637573620a84a263616c672664747970656a
      RECV 00000005047075626c69632d6b6579a263616c672764747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c
      RECV 000000050567382364747970656a7075626c69632d6b65790b1904000cf40d040e010f182010187815861b6fcb19b0cbe3acfa1b7b392a394de9f9481b76a859
      RECV 000000050645985d02fd1b269f3b09eceb805f1b0004e532e1feb2fd1b0005961ecba040f91819582027ae41e4649b934ca495991b7852b855829904101e3712
      RECV 00000005070b4ce26dfd9b252b1c181d183f181e5820e3b0c44298fc1c149afbf4c8996fb924b5d2a3f122fbfc9155a89edb0f922eee181f8401020318ff0000
      status byte     : 0x00
      CBOR decoded OK: 21 top-level keys, key type(s) present = ['int']
      RAW DECODED TOP-LEVEL MAP (every key, key type shown):
                 1  (key type=  int)  = ['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']
                 2  (key type=  int)  = ['credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength']
                 3  (key type=  int)  = b'\x89\xfb\x94\xb7\x06\xc96s\x9b~0Rm\x96\x81E'
                 4  (key type=  int)  = {'rk': True, 'alwaysUv': False, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': True, 'enterpriseAttestation': True}
                 5  (key type=  int)  = 7609
                 6  (key type=  int)  = [1, 2]
                 7  (key type=  int)  = 19
                 8  (key type=  int)  = 128
                 9  (key type=  int)  = ['usb']
                10  (key type=  int)  = [{'alg': -7, 'type': 'public-key'}, {'alg': -8, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}]
                11  (key type=  int)  = 1024
                12  (key type=  int)  = False
                13  (key type=  int)  = 4
                14  (key type=  int)  = 1
                15  (key type=  int)  = 32
                16  (key type=  int)  = 120
                21  (key type=  int)  = [8055560605607898362, 8879174565946325320, 8550182048006734589, 2783008008553857119, 1377906609533693, 1572433893015801]
                25  (key type=  int)  = b"'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U\x82\x99\x04\x10\x1e7\x12\x0bL\xe2m\xfd\x9b%+\x1c"
                29  (key type=  int)  = 63
                30  (key type=  int)  = b'\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$\xb5\xd2\xa3\xf1"\xfb\xfc\x91U\xa8\x9e\xdb\x0f\x92.\xee'
                31  (key type=  int)  = [1, 2, 3, 255]

      TOP-LEVEL MEMBER LOOKUP (text key first, then spec integer key; UNAVAILABLE = genuinely absent from the reply):
        versions                           = ['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']   [via integer key 1 (0x01)]
        extensions                         = ['credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength']   [via integer key 2 (0x02)]
        aaguid                             = b'\x89\xfb\x94\xb7\x06\xc96s\x9b~0Rm\x96\x81E'   [via integer key 3 (0x03)]
        options                            = {'rk': True, 'alwaysUv': False, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': True, 'enterpriseAttestation': True}   [via integer key 4 (0x04)]
        maxMsgSize                         = 7609   [via integer key 5 (0x05)]
        pinUvAuthProtocols                 = [1, 2]   [via integer key 6 (0x06)]
        maxCredentialCountInList           = 19   [via integer key 7 (0x07)]
        maxCredentialIdLength              = 128   [via integer key 8 (0x08)]
        transports                         = ['usb']   [via integer key 9 (0x09)]
        algorithms                         = [{'alg': -7, 'type': 'public-key'}, {'alg': -8, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}]   [via integer key 10 (0x0a)]
        maxSerializedLargeBlobArray        = 1024   [via integer key 11 (0x0b)]
        forcePINChange                     = False   [via integer key 12 (0x0c)]
        minPINLength                       = 4   [via integer key 13 (0x0d)]
        firmwareVersion                    = 1   [via integer key 14 (0x0e)]
        maxCredBlobLength                  = 32   [via integer key 15 (0x0f)]
        maxRPIDsForSetMinPINLength         = 120   [via integer key 16 (0x10)]
        preferredPlatformUvAttempts        = UNAVAILABLE (neither 'preferredPlatformUvAttempts' nor integer key 0x11 present)
        uvModality                         = UNAVAILABLE (neither 'uvModality' nor integer key 0x12 present)
        certifications                     = UNAVAILABLE (neither 'certifications' nor integer key 0x13 present)
        remainingDiscoverableCredentials   = UNAVAILABLE (neither 'remainingDiscoverableCredentials' nor integer key 0x14 present)
        vendorPrototypeConfigCommands      = [8055560605607898362, 8879174565946325320, 8550182048006734589, 2783008008553857119, 1377906609533693, 1572433893015801]   [via integer key 21 (0x15)]
        attestationFormats                 = b"'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U\x82\x99\x04\x10\x1e7\x12\x0bL\xe2m\xfd\x9b%+\x1c"   [via integer key 25 (0x19)]
        uvCountSinceLastPinEntry           = UNAVAILABLE (neither 'uvCountSinceLastPinEntry' nor integer key 0x1b present)
        longTouchForReset                  = 63   [via integer key 29 (0x1d)]
        encIdentifier                      = b'\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$\xb5\xd2\xa3\xf1"\xfb\xfc\x91U\xa8\x9e\xdb\x0f\x92.\xee'   [via integer key 30 (0x1e)]
        transportsForReset                 = [1, 2, 3, 255]   [via integer key 31 (0x1f)]

      OPTIONS MAP (member present=True, found via integer key 4 (0x04)):
        options key type(s) present = ['str']
        RAW OPTIONS MAP (every key, key type shown):
                'rk'  (key type=  str)  = True
          'alwaysUv'  (key type=  str)  = False
          'credMgmt'  (key type=  str)  = True
          'authnrCfg'  (key type=  str)  = True
          'clientPin'  (key type=  str)  = True
          'largeBlobs'  (key type=  str)  = True
          'pinUvAuthToken'  (key type=  str)  = True
          'setMinPINLength'  (key type=  str)  = True
          'makeCredUvNotRqd'  (key type=  str)  = True
          'enterpriseAttestation'  (key type=  str)  = True

      OPTION-MEMBER LOOKUP (inside the options map; text key first, then spec integer option id):
        rk                           = True   [via text key 'rk']
        up                           = UNAVAILABLE (neither 'up' nor integer option id 0x03 present)
        uv                           = UNAVAILABLE (neither 'uv' nor integer option id 0x04 present)
        plat                         = UNAVAILABLE (neither 'plat' nor integer option id 0x05 present)
        clientPin                    = True   [via text key 'clientPin']
        credMgmt                     = True   [via text key 'credMgmt']
        bioEnroll                    = UNAVAILABLE (neither 'bioEnroll' nor integer option id 0x08 present)
        pinUvAuthToken               = True   [via text key 'pinUvAuthToken']
        noMcGaPermissionsWithClientPin = UNAVAILABLE (neither 'noMcGaPermissionsWithClientPin' nor integer option id 0x0a present)
        largeBlobs                   = True   [via text key 'largeBlobs']
        ep                           = UNAVAILABLE (neither 'ep' nor integer option id 0x0d present)
        authnrCfg                    = True   [via text key 'authnrCfg']
        uvBioEnroll                  = UNAVAILABLE (neither 'uvBioEnroll' nor integer option id 0x0f present)
        uvToken                      = UNAVAILABLE (neither 'uvToken' nor integer option id 0x14 present)
        alwaysUv                     = False   [via text key 'alwaysUv']
        makeCredUvNotRqd             = True   [via text key 'makeCredUvNotRqd']

      THE THREE QUESTIONS THE BRIEF ASKS DIRECTLY:
        clientPin      = True  (True means SUPPORTS a PIN, not that one is set)
        pinUvAuthToken = True
        -> pinUvAuthToken:true ALONGSIDE clientPin:false ? NO (per the observed values above; UNAVAILABLE does not count)
        uv             = 'UNAVAILABLE'   <-- built-in UV advertised?
        up             = 'UNAVAILABLE'
        rk             = True
        credMgmt       = True
        largeBlobs     = True
        top-level `transports` (0x09) = ['usb']  [via integer key 9 (0x09)]

      (GetInfo answered on the last of 3 attempts after 0 failure(s); failures: [])

  [B] authenticatorGetInfo (opcode 0x04, fido2 dialect) in 447.8 ms
      full payload hex: 00b40184684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302886375766d6863726564426c6f626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e6774686e686d61632d7365637265742d6d6371746869726450617274795061796d656e74035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f568637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56d706572437265644d676d74524ff56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f405190400068201020710081904000a83a263616c672664747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b65790b1908000cf40d040e1908000f188010187818195820d1194f02e0309541c39bf308a48281e416a93cf8b217095170c5c51173467a08181bf4181d183f181e582056d37c2433ac6c7ec2a67b2ede9b3d0fef2cda63c5e8accb2a4b0c238cae2958181f8401020318ff  (471 bytes)
      SEND 66000000900001040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      RECV 66000000bb0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x01
      RECV 660000009001d700b40184684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302886375766d6863726564426c6f626b63
      RECV 660000000072656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e6774686e686d61632d7365637265
      RECV 6600000001742d6d6371746869726450617274795061796d656e74035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f5686372
      RECV 660000000265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56d706572437265644d676d74524ff56e7069
      RECV 66000000036e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f40519040006820102071008
      RECV 66000000041904000a83a263616c672664747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c6738236474
      RECV 66000000057970656a7075626c69632d6b65790b1908000cf40d040e1908000f188010187818195820d1194f02e0309541c39bf308a48281e416a93cf8b21709
      RECV 66000000065170c5c51173467a08181bf4181d183f181e582056d37c2433ac6c7ec2a67b2ede9b3d0fef2cda63c5e8accb2a4b0c238cae2958181f8401020318
      RECV 6600000007ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte     : 0x00
      CBOR decoded OK: 20 top-level keys, key type(s) present = ['int']
      RAW DECODED TOP-LEVEL MAP (every key, key type shown):
                 1  (key type=  int)  = ['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']
                 2  (key type=  int)  = ['uvm', 'credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength', 'hmac-secret-mc', 'thirdPartyPayment']
                 3  (key type=  int)  = b'\x89\xfb\x94\xb7\x06\xc96s\x9b~0Rm\x96\x81E'
                 4  (key type=  int)  = {'rk': True, 'alwaysUv': True, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'perCredMgmtRO': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': False}
                 5  (key type=  int)  = 1024
                 6  (key type=  int)  = [1, 2]
                 7  (key type=  int)  = 16
                 8  (key type=  int)  = 1024
                10  (key type=  int)  = [{'alg': -7, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}]
                11  (key type=  int)  = 2048
                12  (key type=  int)  = False
                13  (key type=  int)  = 4
                14  (key type=  int)  = 2048
                15  (key type=  int)  = 128
                16  (key type=  int)  = 120
                25  (key type=  int)  = b'\xd1\x19O\x02\xe00\x95A\xc3\x9b\xf3\x08\xa4\x82\x81\xe4\x16\xa9<\xf8\xb2\x17\tQp\xc5\xc5\x11sFz\x08'
                27  (key type=  int)  = False
                29  (key type=  int)  = 63
                30  (key type=  int)  = b'V\xd3|$3\xacl~\xc2\xa6{.\xde\x9b=\x0f\xef,\xdac\xc5\xe8\xac\xcb*K\x0c#\x8c\xae)X'
                31  (key type=  int)  = [1, 2, 3, 255]

      TOP-LEVEL MEMBER LOOKUP (text key first, then spec integer key; UNAVAILABLE = genuinely absent from the reply):
        versions                           = ['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']   [via integer key 1 (0x01)]
        extensions                         = ['uvm', 'credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength', 'hmac-secret-mc', 'thirdPartyPayment']   [via integer key 2 (0x02)]
        aaguid                             = b'\x89\xfb\x94\xb7\x06\xc96s\x9b~0Rm\x96\x81E'   [via integer key 3 (0x03)]
        options                            = {'rk': True, 'alwaysUv': True, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'perCredMgmtRO': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': False}   [via integer key 4 (0x04)]
        maxMsgSize                         = 1024   [via integer key 5 (0x05)]
        pinUvAuthProtocols                 = [1, 2]   [via integer key 6 (0x06)]
        maxCredentialCountInList           = 16   [via integer key 7 (0x07)]
        maxCredentialIdLength              = 1024   [via integer key 8 (0x08)]
        transports                         = UNAVAILABLE (neither 'transports' nor integer key 0x09 present)
        algorithms                         = [{'alg': -7, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}]   [via integer key 10 (0x0a)]
        maxSerializedLargeBlobArray        = 2048   [via integer key 11 (0x0b)]
        forcePINChange                     = False   [via integer key 12 (0x0c)]
        minPINLength                       = 4   [via integer key 13 (0x0d)]
        firmwareVersion                    = 2048   [via integer key 14 (0x0e)]
        maxCredBlobLength                  = 128   [via integer key 15 (0x0f)]
        maxRPIDsForSetMinPINLength         = 120   [via integer key 16 (0x10)]
        preferredPlatformUvAttempts        = UNAVAILABLE (neither 'preferredPlatformUvAttempts' nor integer key 0x11 present)
        uvModality                         = UNAVAILABLE (neither 'uvModality' nor integer key 0x12 present)
        certifications                     = UNAVAILABLE (neither 'certifications' nor integer key 0x13 present)
        remainingDiscoverableCredentials   = UNAVAILABLE (neither 'remainingDiscoverableCredentials' nor integer key 0x14 present)
        vendorPrototypeConfigCommands      = UNAVAILABLE (neither 'vendorPrototypeConfigCommands' nor integer key 0x15 present)
        attestationFormats                 = b'\xd1\x19O\x02\xe00\x95A\xc3\x9b\xf3\x08\xa4\x82\x81\xe4\x16\xa9<\xf8\xb2\x17\tQp\xc5\xc5\x11sFz\x08'   [via integer key 25 (0x19)]
        uvCountSinceLastPinEntry           = False   [via integer key 27 (0x1b)]
        longTouchForReset                  = 63   [via integer key 29 (0x1d)]
        encIdentifier                      = b'V\xd3|$3\xacl~\xc2\xa6{.\xde\x9b=\x0f\xef,\xdac\xc5\xe8\xac\xcb*K\x0c#\x8c\xae)X'   [via integer key 30 (0x1e)]
        transportsForReset                 = [1, 2, 3, 255]   [via integer key 31 (0x1f)]

      OPTIONS MAP (member present=True, found via integer key 4 (0x04)):
        options key type(s) present = ['str']
        RAW OPTIONS MAP (every key, key type shown):
                'rk'  (key type=  str)  = True
          'alwaysUv'  (key type=  str)  = True
          'credMgmt'  (key type=  str)  = True
          'authnrCfg'  (key type=  str)  = True
          'clientPin'  (key type=  str)  = True
          'largeBlobs'  (key type=  str)  = True
          'perCredMgmtRO'  (key type=  str)  = True
          'pinUvAuthToken'  (key type=  str)  = True
          'setMinPINLength'  (key type=  str)  = True
          'makeCredUvNotRqd'  (key type=  str)  = False

      OPTION-MEMBER LOOKUP (inside the options map; text key first, then spec integer option id):
        rk                           = True   [via text key 'rk']
        up                           = UNAVAILABLE (neither 'up' nor integer option id 0x03 present)
        uv                           = UNAVAILABLE (neither 'uv' nor integer option id 0x04 present)
        plat                         = UNAVAILABLE (neither 'plat' nor integer option id 0x05 present)
        clientPin                    = True   [via text key 'clientPin']
        credMgmt                     = True   [via text key 'credMgmt']
        bioEnroll                    = UNAVAILABLE (neither 'bioEnroll' nor integer option id 0x08 present)
        pinUvAuthToken               = True   [via text key 'pinUvAuthToken']
        noMcGaPermissionsWithClientPin = UNAVAILABLE (neither 'noMcGaPermissionsWithClientPin' nor integer option id 0x0a present)
        largeBlobs                   = True   [via text key 'largeBlobs']
        ep                           = UNAVAILABLE (neither 'ep' nor integer option id 0x0d present)
        authnrCfg                    = True   [via text key 'authnrCfg']
        uvBioEnroll                  = UNAVAILABLE (neither 'uvBioEnroll' nor integer option id 0x0f present)
        uvToken                      = UNAVAILABLE (neither 'uvToken' nor integer option id 0x14 present)
        alwaysUv                     = True   [via text key 'alwaysUv']
        makeCredUvNotRqd             = False   [via text key 'makeCredUvNotRqd']

      THE THREE QUESTIONS THE BRIEF ASKS DIRECTLY:
        clientPin      = True  (True means SUPPORTS a PIN, not that one is set)
        pinUvAuthToken = True
        -> pinUvAuthToken:true ALONGSIDE clientPin:false ? NO (per the observed values above; UNAVAILABLE does not count)
        uv             = 'UNAVAILABLE'   <-- built-in UV advertised?
        up             = 'UNAVAILABLE'
        rk             = True
        credMgmt       = True
        largeBlobs     = True
        top-level `transports` (0x09) = 'UNAVAILABLE'  [via None]

==============================================================================
PROBE 2b — cross-check with fido2's own high-level client
==============================================================================


  [A] CROSS-CHECK with fido2's own stack, on /dev/hidraw10 product_name='EddieOz Fapico2' serial='94746395'
      fido2 parsed this device as: device_version=(5, 4, 0) capabilities=0x04
      fido2 CtapHidDevice.call(CBOR, 0x04) raw hex: 00b50185665532465f5632684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302856863726564426c6f626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e677468035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f468637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f575656e74657270726973654174746573746174696f6ef505191db90682010207130818800981637573620a84a263616c672664747970656a7075626c69632d6b6579a263616c672764747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b65790b1904000cf40d040e010f182010187815861b6fcb19b0cbe3acfa1b7b392a394de9f9481b76a85945985d02fd1b269f3b09eceb805f1b0004e532e1feb2fd1b0005961ecba040f9181958200381534545f55cf43e41983f5d4c9456829904101e37120b4ce26dfd9b252b1c181d183f181e58205df6e0e2761359d30a8275058e299fccb5d2a3f122fbfc9155a89edb0f922eee181f8401020318ff
      fido2 Ctap2.get_info() OK
        info.__repr__ = Info(versions=['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3'], extensions=['credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength'], aaguid=AAGUID(89fb94b7-06c9-3673-9b7e-30526d968145), options={'rk': True, 'alwaysUv': False, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': True, 'enterpriseAttestation': True}, max_msg_size=7609, pin_uv_protocols=[1, 2], max_creds_in_list=19, max_cred_id_length=128, transports=['usb'], algorithms=[{'alg': -7, 'type': 'public-key'}, {'alg': -8, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}], max_large_blob=1024, force_pin_change=False, min_pin_length=4, firmware_version=1, max_cred_blob_length=32, max_rpids_for_min_pin=120, preferred_platform_uv_attempts=0, uv_modality=0, certifications={}, remaining_disc_creds=None, vendor_prototype_config_commands=[8055560605607898362, 8879174565946325320, 8550182048006734589, 2783008008553857119, 1377906609533693, 1572433893015801], attestation_formats=['packed'], uv_count_since_pin=None, long_touch_for_reset=False, enc_identifier=b'\xb9\xb3\xed\xd1\x7ft\xb5\xbfB,\xca\xbb\xd7S~\x1a\x82\x99\x04\x10\x1e7\x12\x0bL\xe2m\xfd\x9b%+\x1c', transports_for_reset=[], pin_complexity_policy=None, pin_complexity_policy_url=None, max_pin_length=63, enc_cred_store_state=b'u\xd7h,\x8bYUU{.\xf36T\xf3\x15\x12\xb5\xd2\xa3\xf1"\xfb\xfc\x91U\xa8\x9e\xdb\x0f\x92.\xee', authenticator_config_commands=[1, 2, 3, 255])
        info.versions = ['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']


  [B] CROSS-CHECK with fido2's own stack, on /dev/hidraw13 product_name='Pol Henarejos Fapico2' serial='7C36644DFF8A74C7'
      fido2 parsed this device as: device_version=(8, 0, 0) capabilities=0x05
      fido2 CtapHidDevice.call(CBOR, 0x04) raw hex: 00b40184684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302886375766d6863726564426c6f626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e6774686e686d61632d7365637265742d6d6371746869726450617274795061796d656e74035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f568637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56d706572437265644d676d74524ff56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f405190400068201020710081904000a83a263616c672664747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b65790b1908000cf40d040e1908000f188010187818195820ce92d3d582f6a24de6895dfa6b2493146f0d8d722dcdf083cf01762fdf31f415181bf4181d183f181e5820fd9206dad2a73d95a2ca8199fd9ea6123d8775623b7e11b5f976af4cf1177724181f8401020318ff
      fido2 Ctap2.get_info() OK
        info.__repr__ = Info(versions=['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3'], extensions=['uvm', 'credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength', 'hmac-secret-mc', 'thirdPartyPayment'], aaguid=AAGUID(89fb94b7-06c9-3673-9b7e-30526d968145), options={'rk': True, 'alwaysUv': True, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'perCredMgmtRO': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': False}, max_msg_size=1024, pin_uv_protocols=[1, 2], max_creds_in_list=16, max_cred_id_length=1024, transports=[], algorithms=[{'alg': -7, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}], max_large_blob=2048, force_pin_change=False, min_pin_length=4, firmware_version=2048, max_cred_blob_length=128, max_rpids_for_min_pin=120, preferred_platform_uv_attempts=0, uv_modality=0, certifications={}, remaining_disc_creds=None, vendor_prototype_config_commands=[], attestation_formats=['packed'], uv_count_since_pin=None, long_touch_for_reset=False, enc_identifier=b'\xe2\x9f\x11\xc8\xa6\xdb\x98D\xf3z\x93\xc4x\xf5\xc9\\\xce\xabd/;\x81\xe0\xa9\x80\xe3\n|\xc2\xcf\x8a\xd2', transports_for_reset=[], pin_complexity_policy=False, pin_complexity_policy_url=None, max_pin_length=63, enc_cred_store_state=b"\xd6\xb0\xd32\r\xc6\xa8\xc8*\xde\xb0\xdd\x90\x80\xe4=\xc5\xa2\xa7;'\xd0\xb0\xf4\x19\xbc`\xe0,j8m", authenticator_config_commands=[1, 2, 3, 255])
        info.versions = ['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']

==============================================================================
PROBE 2c — authenticatorGetNextAssertion (opcode 0x08)
==============================================================================


  [A] authenticatorGetNextAssertion (opcode 0x08), timeout 35.0s
      sent payload hex : 02a1017061622d70726f62652e696e76616c6964  (20 bytes)
      reply payload hex: 3b  (1 bytes)
      SEND 0000000890001402a1017061622d70726f62652e696e76616c696400000000000000000000000000000000000000000000000000000000000000000000000000
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 00000008bb0001020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x02
      RECV 000000089000013b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte      : 0x3b  (CTAP2_ERR_UV_BLOCKED)


  [B] authenticatorGetNextAssertion (opcode 0x08), timeout 35.0s
      sent payload hex : 02a1017061622d70726f62652e696e76616c6964  (20 bytes)
      reply payload hex: 14  (1 bytes)
      SEND 6800000090001402a1017061622d70726f62652e696e76616c696400000000000000000000000000000000000000000000000000000000000000000000000000
      RECV 68000000bb0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x01
      RECV 68000000900001140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte      : 0x14  (CTAP2_ERR_MISSING_PARAMETER)

==============================================================================
PROBE 3 — authenticatorSelection (opcode 0x0B)
==============================================================================


  [A] authenticatorSelection (opcode 0x0B) in 15.9 ms
      sent payload hex : 0ba2627570f4627576f4
      reply payload hex: 01  (1 bytes)
      SEND 0000000990000a0ba2627570f4627576f40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      RECV 00000009900001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte      : 0x01  (NOT CTAP2_OK / CTAP1_ERR_INVALID_COMMAND)


  [B] authenticatorSelection (opcode 0x0B) in 424.0 ms
      sent payload hex : 0ba2627570f4627576f4
      reply payload hex: 00  (1 bytes)
      SEND 6900000090000a0ba2627570f4627576f40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      RECV 69000000bb0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x01
      RECV 69000000900001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte      : 0x00  (CTAP2_OK / CTAP2_OK)

==============================================================================
PROBE 4 — authenticatorClientPIN 0x06 sub-command 0x06 (getPinUvAuthTokenUsingUvWithPermissions)
==============================================================================


  [A] clientPIN subCmd 0x06 (getPinUvAuthTokenUsingUvWithPermissions) variant=uv_false
      sent payload hex : 0606a3627576f464727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380
      sent CBOR params : permissions=[] rpId='ab-probe.invalid' uv=False
      replied in 15.9 ms
      SEND 0000000a90002a0606a3627576f464727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380000000000000000000000000000000
      RECV 0000000a900001120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte      : 0x12  (CTAP2_ERR_INVALID_CBOR)
      CTAPHID_CANCEL sent: CtapHidError: CTAPHID error 0x01

  [A] clientPIN subCmd 0x06 (getPinUvAuthTokenUsingUvWithPermissions) variant=uv_true
      sent payload hex : 0606a3627576f564727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380
      sent CBOR params : permissions=[] rpId='ab-probe.invalid' uv=True
      replied in 15.6 ms
      SEND 0000000b90002a0606a3627576f564727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380000000000000000000000000000000
      RECV 0000000b900001120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte      : 0x12  (CTAP2_ERR_INVALID_CBOR)
      CTAPHID_CANCEL sent: CtapHidError: CTAPHID error 0x01


  [B] clientPIN subCmd 0x06 (getPinUvAuthTokenUsingUvWithPermissions) variant=uv_false
      sent payload hex : 0606a3627576f464727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380
      sent CBOR params : permissions=[] rpId='ab-probe.invalid' uv=False
      replied in 383.9 ms
      SEND 6a00000090002a0606a3627576f464727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380000000000000000000000000000000
      RECV 6a000000bb0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x01
      RECV 6a000000900001110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte      : 0x11  (CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
      CTAPHID_CANCEL sent: Timeout: no packet within 5.0s

  [B] clientPIN subCmd 0x06 (getPinUvAuthTokenUsingUvWithPermissions) variant=uv_true
      sent payload hex : 0606a3627576f564727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380
      sent CBOR params : permissions=[] rpId='ab-probe.invalid' uv=True
      replied in 423.0 ms
      SEND 6b00000090002a0606a3627576f564727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380000000000000000000000000000000
      RECV 6b000000bb0001010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      KEEPALIVE status=0x01
      RECV 6b000000900001110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      status byte      : 0x11  (CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
      CTAPHID_CANCEL sent: Timeout: no packet within 5.0s

==============================================================================
PROBE 5 — user-presence window; does the channel stay answerable?
==============================================================================


  [A] CTAPHID_WINK replied in 16.0 ms
      reply payload hex: ''  (empty payload = success)
      SEND 0000000c880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      RECV 0000000c880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      PING after WINK #0: 16.7 ms, echo_ok=True
      PING after WINK #1: 14.5 ms, echo_ok=True
      PING after WINK #2: 16.0 ms, echo_ok=True
      PING after WINK #3: 16.0 ms, echo_ok=True
      PING after WINK #4: 15.9 ms, echo_ok=True
      PING after WINK #5: 16.0 ms, echo_ok=True

  [A] MakeCredential to throwaway RP id 'ab-probe.invalid' (never confirmed, never completed)
      sent payload hex : 01a701a26269647061622d70726f62652e696e76616c6964646e616d657061622d70726f62652e696e76616c696402a263616c672664747970656a7075626c69632d6b65790381a263616c672664747970656a7075626c69632d6b65790481a263616c672664747970656a7075626c69632d6b6579055820000000000000000000000000000000000000000000000000000000000000000006a007a0  (156 bytes)
      outcome          : replied
      reply payload hex: 12
      status byte      : 0x12 (CTAP2_ERR_INVALID_CBOR)
      PING #0: 15.9 ms, echo_ok=True
      keepalive frames   : 1, statuses [2]
      CTAPHID_CANCEL sent: CtapHidError: CTAPHID error 0x01
      PING after cancel  : echo_ok=True in 15.9 ms


  [B] CTAPHID_WINK replied in 1016.0 ms
      reply payload hex: ''  (empty payload = success)
      SEND 6c000000880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      RECV 6c000000880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
      PING after WINK #0: 15.9 ms, echo_ok=True
      PING after WINK #1: 15.9 ms, echo_ok=True
      PING after WINK #2: 15.9 ms, echo_ok=True
      PING after WINK #3: 15.9 ms, echo_ok=True
      PING after WINK #4: 64.1 ms, echo_ok=True
      PING after WINK #5: 56.0 ms, echo_ok=True

  [B] MakeCredential to throwaway RP id 'ab-probe.invalid' (never confirmed, never completed)
      sent payload hex : 01a701a26269647061622d70726f62652e696e76616c6964646e616d657061622d70726f62652e696e76616c696402a263616c672664747970656a7075626c69632d6b65790381a263616c672664747970656a7075626c69632d6b65790481a263616c672664747970656a7075626c69632d6b6579055820000000000000000000000000000000000000000000000000000000000000000006a007a0  (156 bytes)
      outcome          : STILL PARKED when the probe budget ran out
      reply payload hex: None
      PING #0: 16.0 ms, echo_ok=False
      PING #1: 8.0 ms, echo_ok=True
      PING #2: 8.0 ms, echo_ok=True
      PING #3: 8.0 ms, echo_ok=True
      PING #4: 8.0 ms, echo_ok=True
      keepalive frames   : 1, statuses [1]
      CTAPHID_CANCEL sent: Timeout: no packet within 5.0s
      PING after cancel  : echo_ok=True in 21.0 ms

==============================================================================
PROBE 5c — REAL user-presence window (GetAssertion); does the channel stay open?
==============================================================================


  [A] opening a REAL user-presence window with an authenticatorGetNextAssertion to 'ab-probe.invalid'
      sent payload hex : 02a2017061622d70726f62652e696e76616c69640258200000000000000000000000000000000000000000000000000000000000000000  (55 bytes)
      outcome            : replied
      reply payload hex  : 3b
      status byte        : 0x3b (CTAP2_ERR_UV_BLOCKED)
      keepalive frames   : 301, statuses [2] (0x02 = CTAP2_UP_REQUIRED = waiting for a touch)
      PING during window #0: 30047.7 ms, echo_ok=True
      elapsed            : 30063.5 ms
      CTAPHID_CANCEL sent: CtapHidError: CTAPHID error 0x01
      PING after cancel  : echo_ok=True in 15.9 ms


  [B] opening a REAL user-presence window with an authenticatorGetNextAssertion to 'ab-probe.invalid'
      sent payload hex : 02a2017061622d70726f62652e696e76616c69640258200000000000000000000000000000000000000000000000000000000000000000  (55 bytes)
      outcome            : STILL PARKED when the probe budget ran out
      reply payload hex  : None
      keepalive frames   : 1, statuses [1] (0x02 = CTAP2_UP_REQUIRED = waiting for a touch)
      PING during window #0: 15.9 ms, echo_ok=False
      PING during window #1: 8.0 ms, echo_ok=True
      PING during window #2: 8.0 ms, echo_ok=True
      PING during window #3: 8.0 ms, echo_ok=True
      PING during window #4: 8.0 ms, echo_ok=True
      elapsed            : 576.1 ms
      CTAPHID_CANCEL sent: Timeout: no packet within 5.0s
      PING after cancel  : echo_ok=True in 67.2 ms

==============================================================================
FINAL — leave both devices in a normal, answerable state
==============================================================================


  [A] FINAL INIT+PING: INIT ok (cid 0x0000000f), PING echo_ok=True in 15.8 ms


  [B] FINAL INIT+PING: INIT ok (cid 0x6f000000), PING echo_ok=True in 16.0 ms

==============================================================================
MACHINE-READABLE RESULTS
==============================================================================
{
  "inventory": [
    {
      "path": "/dev/hidraw10",
      "usb_addr": "('1', '104')",
      "manufacturer": "EddieOz",
      "product": "Fapico2",
      "serial": "94746395",
      "bcdDevice": "None",
      "hid_product_name": "EddieOz Fapico2",
      "hid_serial": "94746395"
    },
    {
      "path": "/dev/hidraw13",
      "usb_addr": "('1', '099')",
      "manufacturer": "Pol Henarejos",
      "product": "Fapico2",
      "serial": "7C36644DFF8A74C7",
      "bcdDevice": "None",
      "hid_product_name": "Pol Henarejos Fapico2",
      "hid_serial": "7C36644DFF8A74C7"
    }
  ],
  "selftest_a": {
    "path": "/dev/hidraw10",
    "manufacturer": "EddieOz",
    "selftest": "PASS",
    "cid": "0x00000002"
  },
  "selftest_b": {
    "path": "/dev/hidraw13",
    "manufacturer": "Pol Henarejos",
    "selftest": "PASS",
    "cid": "0x63000000"
  },
  "init_a": {
    "label": "A",
    "path": "/dev/hidraw10",
    "manufacturer": "EddieOz",
    "serial": "94746395",
    "latency_ms": 9.9,
    "payload_hex": "0102030405060708000000030205040004",
    "echo_ok": true,
    "cid": "0x00000003",
    "version_interface": 2,
    "firmware_version": "5.4.0",
    "cap_flags": "0x04",
    "cap_flags_int": 4,
    "cap_flags_spec": [
      "WINK(0x04)"
    ],
    "cap_flags_defacto": [
      "CBOR(0x04)"
    ],
    "spec_says_cbor": false,
    "defacto_says_cbor": true
  },
  "init_b": {
    "label": "B",
    "path": "/dev/hidraw13",
    "manufacturer": "Pol Henarejos",
    "serial": "7C36644DFF8A74C7",
    "latency_ms": 372.3,
    "payload_hex": "0102030405060708640000000208000005",
    "echo_ok": true,
    "cid": "0x64000000",
    "version_interface": 2,
    "firmware_version": "8.0.0",
    "cap_flags": "0x05",
    "cap_flags_int": 5,
    "cap_flags_spec": [
      "CBOR(0x01)",
      "WINK(0x04)"
    ],
    "cap_flags_defacto": [
      "WINK(0x01)",
      "CBOR(0x04)"
    ],
    "spec_says_cbor": true,
    "defacto_says_cbor": true
  },
  "init_random_a": {
    "nonce": "6e81ab7d0f6b4099",
    "echo": "6e81ab7d0f6b4099",
    "match": true
  },
  "init_random_b": {
    "nonce": "c535a2ad78bde946",
    "echo": "c535a2ad78bde946",
    "match": true
  },
  "getinfo_a": {
    "label": "A",
    "status": "0x00",
    "payload_hex": "00b50185665532465f5632684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302856863726564426c6f626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e677468035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f468637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f575656e74657270726973654174746573746174696f6ef505191db90682010207130818800981637573620a84a263616c672664747970656a7075626c69632d6b6579a263616c672764747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b65790b1904000cf40d040e010f182010187815861b6fcb19b0cbe3acfa1b7b392a394de9f9481b76a85945985d02fd1b269f3b09eceb805f1b0004e532e1feb2fd1b0005961ecba040f91819582027ae41e4649b934ca495991b7852b855829904101e37120b4ce26dfd9b252b1c181d183f181e5820e3b0c44298fc1c149afbf4c8996fb924b5d2a3f122fbfc9155a89edb0f922eee181f8401020318ff",
    "payload_len": 527,
    "latency_ms": 79.9,
    "top_level_key_types": [
      "int"
    ],
    "top_level_keys": [
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9",
      "10",
      "11",
      "12",
      "13",
      "14",
      "15",
      "16",
      "21",
      "25",
      "29",
      "30",
      "31"
    ],
    "raw_map": {
      "1": "['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']",
      "2": "['credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength']",
      "3": "b'\\x89\\xfb\\x94\\xb7\\x06\\xc96s\\x9b~0Rm\\x96\\x81E'",
      "4": "{'rk': True, 'alwaysUv': False, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': True, 'enterpriseAttestation': True}",
      "5": "7609",
      "6": "[1, 2]",
      "7": "19",
      "8": "128",
      "9": "['usb']",
      "10": "[{'alg': -7, 'type': 'public-key'}, {'alg': -8, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}]",
      "11": "1024",
      "12": "False",
      "13": "4",
      "14": "1",
      "15": "32",
      "16": "120",
      "21": "[8055560605607898362, 8879174565946325320, 8550182048006734589, 2783008008553857119, 1377906609533693, 1572433893015801]",
      "25": "b\"'\\xaeA\\xe4d\\x9b\\x93L\\xa4\\x95\\x99\\x1bxR\\xb8U\\x82\\x99\\x04\\x10\\x1e7\\x12\\x0bL\\xe2m\\xfd\\x9b%+\\x1c\"",
      "29": "63",
      "30": "b'\\xe3\\xb0\\xc4B\\x98\\xfc\\x1c\\x14\\x9a\\xfb\\xf4\\xc8\\x99o\\xb9$\\xb5\\xd2\\xa3\\xf1\"\\xfb\\xfc\\x91U\\xa8\\x9e\\xdb\\x0f\\x92.\\xee'",
      "31": "[1, 2, 3, 255]"
    },
    "top_level_resolved": {
      "versions": {
        "value": "['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']",
        "via": "integer key 1 (0x01)",
        "present": true
      },
      "extensions": {
        "value": "['credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength']",
        "via": "integer key 2 (0x02)",
        "present": true
      },
      "aaguid": {
        "value": "b'\\x89\\xfb\\x94\\xb7\\x06\\xc96s\\x9b~0Rm\\x96\\x81E'",
        "via": "integer key 3 (0x03)",
        "present": true
      },
      "options": {
        "value": "{'rk': True, 'alwaysUv': False, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': True, 'enterpriseAttestation': True}",
        "via": "integer key 4 (0x04)",
        "present": true
      },
      "maxMsgSize": {
        "value": "7609",
        "via": "integer key 5 (0x05)",
        "present": true
      },
      "pinUvAuthProtocols": {
        "value": "[1, 2]",
        "via": "integer key 6 (0x06)",
        "present": true
      },
      "maxCredentialCountInList": {
        "value": "19",
        "via": "integer key 7 (0x07)",
        "present": true
      },
      "maxCredentialIdLength": {
        "value": "128",
        "via": "integer key 8 (0x08)",
        "present": true
      },
      "transports": {
        "value": "['usb']",
        "via": "integer key 9 (0x09)",
        "present": true
      },
      "algorithms": {
        "value": "[{'alg': -7, 'type': 'public-key'}, {'alg': -8, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}]",
        "via": "integer key 10 (0x0a)",
        "present": true
      },
      "maxSerializedLargeBlobArray": {
        "value": "1024",
        "via": "integer key 11 (0x0b)",
        "present": true
      },
      "forcePINChange": {
        "value": "False",
        "via": "integer key 12 (0x0c)",
        "present": true
      },
      "minPINLength": {
        "value": "4",
        "via": "integer key 13 (0x0d)",
        "present": true
      },
      "firmwareVersion": {
        "value": "1",
        "via": "integer key 14 (0x0e)",
        "present": true
      },
      "maxCredBlobLength": {
        "value": "32",
        "via": "integer key 15 (0x0f)",
        "present": true
      },
      "maxRPIDsForSetMinPINLength": {
        "value": "120",
        "via": "integer key 16 (0x10)",
        "present": true
      },
      "preferredPlatformUvAttempts": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "uvModality": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "certifications": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "remainingDiscoverableCredentials": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "vendorPrototypeConfigCommands": {
        "value": "[8055560605607898362, 8879174565946325320, 8550182048006734589, 2783008008553857119, 1377906609533693, 1572433893015801]",
        "via": "integer key 21 (0x15)",
        "present": true
      },
      "attestationFormats": {
        "value": "b\"'\\xaeA\\xe4d\\x9b\\x93L\\xa4\\x95\\x99\\x1bxR\\xb8U\\x82\\x99\\x04\\x10\\x1e7\\x12\\x0bL\\xe2m\\xfd\\x9b%+\\x1c\"",
        "via": "integer key 25 (0x19)",
        "present": true
      },
      "uvCountSinceLastPinEntry": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "longTouchForReset": {
        "value": "63",
        "via": "integer key 29 (0x1d)",
        "present": true
      },
      "encIdentifier": {
        "value": "b'\\xe3\\xb0\\xc4B\\x98\\xfc\\x1c\\x14\\x9a\\xfb\\xf4\\xc8\\x99o\\xb9$\\xb5\\xd2\\xa3\\xf1\"\\xfb\\xfc\\x91U\\xa8\\x9e\\xdb\\x0f\\x92.\\xee'",
        "via": "integer key 30 (0x1e)",
        "present": true
      },
      "transportsForReset": {
        "value": "[1, 2, 3, 255]",
        "via": "integer key 31 (0x1f)",
        "present": true
      }
    },
    "options_present": true,
    "options_via": "integer key 4 (0x04)",
    "options_key_types": [
      "str"
    ],
    "options_raw": {
      "'rk'": "True",
      "'alwaysUv'": "False",
      "'credMgmt'": "True",
      "'authnrCfg'": "True",
      "'clientPin'": "True",
      "'largeBlobs'": "True",
      "'pinUvAuthToken'": "True",
      "'setMinPINLength'": "True",
      "'makeCredUvNotRqd'": "True",
      "'enterpriseAttestation'": "True"
    },
    "options_resolved": {
      "rk": {
        "value": "True",
        "via": "text key 'rk'",
        "present": true
      },
      "up": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "uv": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "plat": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "clientPin": {
        "value": "True",
        "via": "text key 'clientPin'",
        "present": true
      },
      "credMgmt": {
        "value": "True",
        "via": "text key 'credMgmt'",
        "present": true
      },
      "bioEnroll": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "pinUvAuthToken": {
        "value": "True",
        "via": "text key 'pinUvAuthToken'",
        "present": true
      },
      "noMcGaPermissionsWithClientPin": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "largeBlobs": {
        "value": "True",
        "via": "text key 'largeBlobs'",
        "present": true
      },
      "ep": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "authnrCfg": {
        "value": "True",
        "via": "text key 'authnrCfg'",
        "present": true
      },
      "uvBioEnroll": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "uvToken": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "alwaysUv": {
        "value": "False",
        "via": "text key 'alwaysUv'",
        "present": true
      },
      "makeCredUvNotRqd": {
        "value": "True",
        "via": "text key 'makeCredUvNotRqd'",
        "present": true
      }
    },
    "advertises_puat_with_clientpin_false": false
  },
  "getinfo_b": {
    "label": "B",
    "status": "0x00",
    "payload_hex": "00b40184684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302886375766d6863726564426c6f626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e6774686e686d61632d7365637265742d6d6371746869726450617274795061796d656e74035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f568637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56d706572437265644d676d74524ff56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f405190400068201020710081904000a83a263616c672664747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b65790b1908000cf40d040e1908000f188010187818195820d1194f02e0309541c39bf308a48281e416a93cf8b217095170c5c51173467a08181bf4181d183f181e582056d37c2433ac6c7ec2a67b2ede9b3d0fef2cda63c5e8accb2a4b0c238cae2958181f8401020318ff",
    "payload_len": 471,
    "latency_ms": 447.8,
    "top_level_key_types": [
      "int"
    ],
    "top_level_keys": [
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "10",
      "11",
      "12",
      "13",
      "14",
      "15",
      "16",
      "25",
      "27",
      "29",
      "30",
      "31"
    ],
    "raw_map": {
      "1": "['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']",
      "2": "['uvm', 'credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength', 'hmac-secret-mc', 'thirdPartyPayment']",
      "3": "b'\\x89\\xfb\\x94\\xb7\\x06\\xc96s\\x9b~0Rm\\x96\\x81E'",
      "4": "{'rk': True, 'alwaysUv': True, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'perCredMgmtRO': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': False}",
      "5": "1024",
      "6": "[1, 2]",
      "7": "16",
      "8": "1024",
      "10": "[{'alg': -7, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}]",
      "11": "2048",
      "12": "False",
      "13": "4",
      "14": "2048",
      "15": "128",
      "16": "120",
      "25": "b'\\xd1\\x19O\\x02\\xe00\\x95A\\xc3\\x9b\\xf3\\x08\\xa4\\x82\\x81\\xe4\\x16\\xa9<\\xf8\\xb2\\x17\\tQp\\xc5\\xc5\\x11sFz\\x08'",
      "27": "False",
      "29": "63",
      "30": "b'V\\xd3|$3\\xacl~\\xc2\\xa6{.\\xde\\x9b=\\x0f\\xef,\\xdac\\xc5\\xe8\\xac\\xcb*K\\x0c#\\x8c\\xae)X'",
      "31": "[1, 2, 3, 255]"
    },
    "top_level_resolved": {
      "versions": {
        "value": "['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']",
        "via": "integer key 1 (0x01)",
        "present": true
      },
      "extensions": {
        "value": "['uvm', 'credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength', 'hmac-secret-mc', 'thirdPartyPayment']",
        "via": "integer key 2 (0x02)",
        "present": true
      },
      "aaguid": {
        "value": "b'\\x89\\xfb\\x94\\xb7\\x06\\xc96s\\x9b~0Rm\\x96\\x81E'",
        "via": "integer key 3 (0x03)",
        "present": true
      },
      "options": {
        "value": "{'rk': True, 'alwaysUv': True, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'perCredMgmtRO': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': False}",
        "via": "integer key 4 (0x04)",
        "present": true
      },
      "maxMsgSize": {
        "value": "1024",
        "via": "integer key 5 (0x05)",
        "present": true
      },
      "pinUvAuthProtocols": {
        "value": "[1, 2]",
        "via": "integer key 6 (0x06)",
        "present": true
      },
      "maxCredentialCountInList": {
        "value": "16",
        "via": "integer key 7 (0x07)",
        "present": true
      },
      "maxCredentialIdLength": {
        "value": "1024",
        "via": "integer key 8 (0x08)",
        "present": true
      },
      "transports": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "algorithms": {
        "value": "[{'alg': -7, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}]",
        "via": "integer key 10 (0x0a)",
        "present": true
      },
      "maxSerializedLargeBlobArray": {
        "value": "2048",
        "via": "integer key 11 (0x0b)",
        "present": true
      },
      "forcePINChange": {
        "value": "False",
        "via": "integer key 12 (0x0c)",
        "present": true
      },
      "minPINLength": {
        "value": "4",
        "via": "integer key 13 (0x0d)",
        "present": true
      },
      "firmwareVersion": {
        "value": "2048",
        "via": "integer key 14 (0x0e)",
        "present": true
      },
      "maxCredBlobLength": {
        "value": "128",
        "via": "integer key 15 (0x0f)",
        "present": true
      },
      "maxRPIDsForSetMinPINLength": {
        "value": "120",
        "via": "integer key 16 (0x10)",
        "present": true
      },
      "preferredPlatformUvAttempts": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "uvModality": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "certifications": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "remainingDiscoverableCredentials": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "vendorPrototypeConfigCommands": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "attestationFormats": {
        "value": "b'\\xd1\\x19O\\x02\\xe00\\x95A\\xc3\\x9b\\xf3\\x08\\xa4\\x82\\x81\\xe4\\x16\\xa9<\\xf8\\xb2\\x17\\tQp\\xc5\\xc5\\x11sFz\\x08'",
        "via": "integer key 25 (0x19)",
        "present": true
      },
      "uvCountSinceLastPinEntry": {
        "value": "False",
        "via": "integer key 27 (0x1b)",
        "present": true
      },
      "longTouchForReset": {
        "value": "63",
        "via": "integer key 29 (0x1d)",
        "present": true
      },
      "encIdentifier": {
        "value": "b'V\\xd3|$3\\xacl~\\xc2\\xa6{.\\xde\\x9b=\\x0f\\xef,\\xdac\\xc5\\xe8\\xac\\xcb*K\\x0c#\\x8c\\xae)X'",
        "via": "integer key 30 (0x1e)",
        "present": true
      },
      "transportsForReset": {
        "value": "[1, 2, 3, 255]",
        "via": "integer key 31 (0x1f)",
        "present": true
      }
    },
    "options_present": true,
    "options_via": "integer key 4 (0x04)",
    "options_key_types": [
      "str"
    ],
    "options_raw": {
      "'rk'": "True",
      "'alwaysUv'": "True",
      "'credMgmt'": "True",
      "'authnrCfg'": "True",
      "'clientPin'": "True",
      "'largeBlobs'": "True",
      "'perCredMgmtRO'": "True",
      "'pinUvAuthToken'": "True",
      "'setMinPINLength'": "True",
      "'makeCredUvNotRqd'": "False"
    },
    "options_resolved": {
      "rk": {
        "value": "True",
        "via": "text key 'rk'",
        "present": true
      },
      "up": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "uv": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "plat": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "clientPin": {
        "value": "True",
        "via": "text key 'clientPin'",
        "present": true
      },
      "credMgmt": {
        "value": "True",
        "via": "text key 'credMgmt'",
        "present": true
      },
      "bioEnroll": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "pinUvAuthToken": {
        "value": "True",
        "via": "text key 'pinUvAuthToken'",
        "present": true
      },
      "noMcGaPermissionsWithClientPin": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "largeBlobs": {
        "value": "True",
        "via": "text key 'largeBlobs'",
        "present": true
      },
      "ep": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "authnrCfg": {
        "value": "True",
        "via": "text key 'authnrCfg'",
        "present": true
      },
      "uvBioEnroll": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "uvToken": {
        "value": "'UNAVAILABLE'",
        "via": null,
        "present": false
      },
      "alwaysUv": {
        "value": "True",
        "via": "text key 'alwaysUv'",
        "present": true
      },
      "makeCredUvNotRqd": {
        "value": "False",
        "via": "text key 'makeCredUvNotRqd'",
        "present": true
      }
    },
    "advertises_puat_with_clientpin_false": false
  },
  "getinfo_hl_a": {
    "ok": true,
    "fido2_parsed_device_version": "(5, 4, 0)",
    "fido2_parsed_capabilities": "0x04",
    "fido2_raw_payload_hex": "00b50185665532465f5632684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302856863726564426c6f626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e677468035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f468637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f575656e74657270726973654174746573746174696f6ef505191db90682010207130818800981637573620a84a263616c672664747970656a7075626c69632d6b6579a263616c672764747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b65790b1904000cf40d040e010f182010187815861b6fcb19b0cbe3acfa1b7b392a394de9f9481b76a85945985d02fd1b269f3b09eceb805f1b0004e532e1feb2fd1b0005961ecba040f9181958200381534545f55cf43e41983f5d4c9456829904101e37120b4ce26dfd9b252b1c181d183f181e58205df6e0e2761359d30a8275058e299fccb5d2a3f122fbfc9155a89edb0f922eee181f8401020318ff",
    "fido2_info_repr": "Info(versions=['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3'], extensions=['credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength'], aaguid=AAGUID(89fb94b7-06c9-3673-9b7e-30526d968145), options={'rk': True, 'alwaysUv': False, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': True, 'enterpriseAttestation': True}, max_msg_size=7609, pin_uv_protocols=[1, 2], max_creds_in_list=19, max_cred_id_length=128, transports=['usb'], algorithms=[{'alg': -7, 'type': 'public-key'}, {'alg': -8, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}], max_large_blob=1024, force_pin_change=False, min_pin_length=4, firmware_version=1, max_cred_blob_length=32, max_rpids_for_min_pin=120, preferred_platform_uv_attempts=0, uv_modality=0, certifications={}, remaining_disc_creds=None, vendor_prototype_config_commands=[8055560605607898362, 8879174565946325320, 8550182048006734589, 2783008008553857119, 1377906609533693, 1572433893015801], attestation_formats=['packed'], uv_count_since_pin=None, long_touch_for_reset=False, enc_identifier=b'\\xb9\\xb3\\xed\\xd1\\x7ft\\xb5\\xbfB,\\xca\\xbb\\xd7S~\\x1a\\x82\\x99\\x04\\x10\\x1e7\\x12\\x0bL\\xe2m\\xfd\\x9b%+\\x1c', transports_for_reset=[], pin_complexity_policy=None, pin_complexity_policy_url=None, max_pin_length=63, enc_cred_store_state=b'u\\xd7h,\\x8bYUU{.\\xf36T\\xf3\\x15\\x12\\xb5\\xd2\\xa3\\xf1\"\\xfb\\xfc\\x91U\\xa8\\x9e\\xdb\\x0f\\x92.\\xee', authenticator_config_commands=[1, 2, 3, 255])",
    "fido2_versions": "['U2F_V2', 'FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']"
  },
  "getinfo_hl_b": {
    "ok": true,
    "fido2_parsed_device_version": "(8, 0, 0)",
    "fido2_parsed_capabilities": "0x05",
    "fido2_raw_payload_hex": "00b40184684649444f5f325f30684649444f5f325f31684649444f5f325f32684649444f5f325f3302886375766d6863726564426c6f626b6372656450726f746563746b686d61632d7365637265746c6c61726765426c6f624b65796c6d696e50696e4c656e6774686e686d61632d7365637265742d6d6371746869726450617274795061796d656e74035089fb94b706c936739b7e30526d96814504aa62726bf568616c776179735576f568637265644d676d74f569617574686e72436667f569636c69656e7450696ef56a6c61726765426c6f6273f56d706572437265644d676d74524ff56e70696e557641757468546f6b656ef56f7365744d696e50494e4c656e677468f5706d616b654372656455764e6f74527164f405190400068201020710081904000a83a263616c672664747970656a7075626c69632d6b6579a263616c67382264747970656a7075626c69632d6b6579a263616c67382364747970656a7075626c69632d6b65790b1908000cf40d040e1908000f188010187818195820ce92d3d582f6a24de6895dfa6b2493146f0d8d722dcdf083cf01762fdf31f415181bf4181d183f181e5820fd9206dad2a73d95a2ca8199fd9ea6123d8775623b7e11b5f976af4cf1177724181f8401020318ff",
    "fido2_info_repr": "Info(versions=['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3'], extensions=['uvm', 'credBlob', 'credProtect', 'hmac-secret', 'largeBlobKey', 'minPinLength', 'hmac-secret-mc', 'thirdPartyPayment'], aaguid=AAGUID(89fb94b7-06c9-3673-9b7e-30526d968145), options={'rk': True, 'alwaysUv': True, 'credMgmt': True, 'authnrCfg': True, 'clientPin': True, 'largeBlobs': True, 'perCredMgmtRO': True, 'pinUvAuthToken': True, 'setMinPINLength': True, 'makeCredUvNotRqd': False}, max_msg_size=1024, pin_uv_protocols=[1, 2], max_creds_in_list=16, max_cred_id_length=1024, transports=[], algorithms=[{'alg': -7, 'type': 'public-key'}, {'alg': -35, 'type': 'public-key'}, {'alg': -36, 'type': 'public-key'}], max_large_blob=2048, force_pin_change=False, min_pin_length=4, firmware_version=2048, max_cred_blob_length=128, max_rpids_for_min_pin=120, preferred_platform_uv_attempts=0, uv_modality=0, certifications={}, remaining_disc_creds=None, vendor_prototype_config_commands=[], attestation_formats=['packed'], uv_count_since_pin=None, long_touch_for_reset=False, enc_identifier=b'\\xe2\\x9f\\x11\\xc8\\xa6\\xdb\\x98D\\xf3z\\x93\\xc4x\\xf5\\xc9\\\\\\xce\\xabd/;\\x81\\xe0\\xa9\\x80\\xe3\\n|\\xc2\\xcf\\x8a\\xd2', transports_for_reset=[], pin_complexity_policy=False, pin_complexity_policy_url=None, max_pin_length=63, enc_cred_store_state=b\"\\xd6\\xb0\\xd32\\r\\xc6\\xa8\\xc8*\\xde\\xb0\\xdd\\x90\\x80\\xe4=\\xc5\\xa2\\xa7;'\\xd0\\xb0\\xf4\\x19\\xbc`\\xe0,j8m\", authenticator_config_commands=[1, 2, 3, 255])",
    "fido2_versions": "['FIDO_2_0', 'FIDO_2_1', 'FIDO_2_2', 'FIDO_2_3']"
  },
  "assertion_a": {
    "label": "A",
    "status": "0x3b",
    "status_name": "CTAP2_ERR_UV_BLOCKED",
    "payload_hex": "3b"
  },
  "assertion_b": {
    "label": "B",
    "status": "0x14",
    "status_name": "CTAP2_ERR_MISSING_PARAMETER",
    "payload_hex": "14"
  },
  "authsel_a": {
    "label": "A",
    "status": "0x01",
    "status_name": "CTAP1_ERR_INVALID_COMMAND",
    "ctap2_ok": false,
    "payload_hex": "01",
    "latency_ms": 15.9
  },
  "authsel_b": {
    "label": "B",
    "status": "0x00",
    "status_name": "CTAP2_OK",
    "ctap2_ok": true,
    "payload_hex": "00",
    "latency_ms": 424.0
  },
  "pin_a": {
    "uv_false": {
      "status": "0x12",
      "status_name": "CTAP2_ERR_INVALID_CBOR",
      "payload_hex": "12",
      "sent_payload_hex": "0606a3627576f464727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380",
      "latency_ms": 15.9,
      "cancelled": "CtapHidError: CTAPHID error 0x01"
    },
    "uv_true": {
      "status": "0x12",
      "status_name": "CTAP2_ERR_INVALID_CBOR",
      "payload_hex": "12",
      "sent_payload_hex": "0606a3627576f564727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380",
      "latency_ms": 15.6,
      "cancelled": "CtapHidError: CTAPHID error 0x01"
    }
  },
  "pin_b": {
    "uv_false": {
      "status": "0x11",
      "status_name": "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
      "payload_hex": "11",
      "sent_payload_hex": "0606a3627576f464727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380",
      "latency_ms": 383.9,
      "cancelled": "Timeout: no packet within 5.0s"
    },
    "uv_true": {
      "status": "0x11",
      "status_name": "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
      "payload_hex": "11",
      "sent_payload_hex": "0606a3627576f564727049647061622d70726f62652e696e76616c69646b7065726d697373696f6e7380",
      "latency_ms": 423.0,
      "cancelled": "Timeout: no packet within 5.0s"
    }
  },
  "window_a": {
    "wink": {
      "reply_hex": "",
      "wink_latency_ms": 16.0,
      "pings": [
        {
          "i": 0,
          "latency_ms": 16.7,
          "echo_ok": true
        },
        {
          "i": 1,
          "latency_ms": 14.5,
          "echo_ok": true
        },
        {
          "i": 2,
          "latency_ms": 16.0,
          "echo_ok": true
        },
        {
          "i": 3,
          "latency_ms": 16.0,
          "echo_ok": true
        },
        {
          "i": 4,
          "latency_ms": 15.9,
          "echo_ok": true
        },
        {
          "i": 5,
          "latency_ms": 16.0,
          "echo_ok": true
        }
      ],
      "any_ping_timeout": false
    },
    "make_credential": {
      "sent_payload_hex": "01a701a26269647061622d70726f62652e696e76616c6964646e616d657061622d70726f62652e696e76616c696402a263616c672664747970656a7075626c69632d6b65790381a263616c672664747970656a7075626c69632d6b65790481a263616c672664747970656a7075626c69632d6b6579055820000000000000000000000000000000000000000000000000000000000000000006a007a0",
      "outcome": "replied",
      "payload_hex": "12",
      "status": "0x12",
      "long_error": null,
      "pings": [
        {
          "i": 0,
          "latency_ms": 15.9,
          "echo_ok": true
        }
      ],
      "keepalive_statuses": [
        2
      ],
      "keepalive_frames": 1,
      "elapsed_ms": 47.9,
      "any_ping_timeout": false,
      "ping_after_cancel": {
        "ok": true,
        "latency_ms": 15.9
      },
      "cancelled": "CtapHidError: CTAPHID error 0x01"
    }
  },
  "window_b": {
    "wink": {
      "reply_hex": "",
      "wink_latency_ms": 1016.0,
      "pings": [
        {
          "i": 0,
          "latency_ms": 15.9,
          "echo_ok": true
        },
        {
          "i": 1,
          "latency_ms": 15.9,
          "echo_ok": true
        },
        {
          "i": 2,
          "latency_ms": 15.9,
          "echo_ok": true
        },
        {
          "i": 3,
          "latency_ms": 15.9,
          "echo_ok": true
        },
        {
          "i": 4,
          "latency_ms": 64.1,
          "echo_ok": true
        },
        {
          "i": 5,
          "latency_ms": 56.0,
          "echo_ok": true
        }
      ],
      "any_ping_timeout": false
    },
    "make_credential": {
      "sent_payload_hex": "01a701a26269647061622d70726f62652e696e76616c6964646e616d657061622d70726f62652e696e76616c696402a263616c672664747970656a7075626c69632d6b65790381a263616c672664747970656a7075626c69632d6b65790481a263616c672664747970656a7075626c69632d6b6579055820000000000000000000000000000000000000000000000000000000000000000006a007a0",
      "outcome": "STILL PARKED when the probe budget ran out",
      "payload_hex": null,
      "status": null,
      "long_error": null,
      "pings": [
        {
          "i": 0,
          "latency_ms": 16.0,
          "echo_ok": false
        },
        {
          "i": 1,
          "latency_ms": 8.0,
          "echo_ok": true
        },
        {
          "i": 2,
          "latency_ms": 8.0,
          "echo_ok": true
        },
        {
          "i": 3,
          "latency_ms": 8.0,
          "echo_ok": true
        },
        {
          "i": 4,
          "latency_ms": 8.0,
          "echo_ok": true
        }
      ],
      "keepalive_statuses": [
        1
      ],
      "keepalive_frames": 1,
      "elapsed_ms": 623.5,
      "any_ping_timeout": false,
      "ping_after_cancel": {
        "ok": true,
        "latency_ms": 21.0
      },
      "cancelled": "Timeout: no packet within 5.0s"
    }
  },
  "presence_a": {
    "outcome": "replied",
    "payload_hex": "3b",
    "status": "0x3b",
    "long_error": null,
    "pings": [
      {
        "i": 0,
        "latency_ms": 30047.7,
        "echo_ok": true
      }
    ],
    "keepalive_statuses": [
      2
    ],
    "keepalive_frames": 301,
    "elapsed_ms": 30063.5,
    "any_ping_timeout": false,
    "cancel": "CtapHidError: CTAPHID error 0x01",
    "ping_after_cancel": {
      "ok": true,
      "latency_ms": 15.9
    }
  },
  "presence_b": {
    "outcome": "STILL PARKED when the probe budget ran out",
    "payload_hex": null,
    "status": null,
    "long_error": null,
    "pings": [
      {
        "i": 0,
        "latency_ms": 15.9,
        "echo_ok": false
      },
      {
        "i": 1,
        "latency_ms": 8.0,
        "echo_ok": true
      },
      {
        "i": 2,
        "latency_ms": 8.0,
        "echo_ok": true
      },
      {
        "i": 3,
        "latency_ms": 8.0,
        "echo_ok": true
      },
      {
        "i": 4,
        "latency_ms": 8.0,
        "echo_ok": true
      }
    ],
    "keepalive_statuses": [
      1
    ],
    "keepalive_frames": 1,
    "elapsed_ms": 576.1,
    "any_ping_timeout": false,
    "cancel": "Timeout: no packet within 5.0s",
    "ping_after_cancel": {
      "ok": true,
      "latency_ms": 67.2
    }
  },
  "final_a": {
    "init_ok": true,
    "ping_echo_ok": true,
    "ping_ms": 15.8
  },
  "final_b": {
    "init_ok": true,
    "ping_echo_ok": true,
    "ping_ms": 16.0
  }
}
```
