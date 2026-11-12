NIP-XX
======

`draft` `optional`

Hardware signing transport for Nostr identities
-----------------------------------------------

This NIP defines a USB HID transport and command protocol by which a hardware
device (a dedicated signer, a security key, or an authenticator applet) holds
Nostr identities (BIP-340/secp256k1 keypairs) and performs signing and
NIP-44 encryption/decryption on the device, exposing a NIP-07-compatible
surface to web clients through a browser extension.

The transport is a profile of the CTAPHID framing used by FIDO authenticators,
carried on a vendor-usage HID interface so it can coexist with FIDO on the
same physical device without the browser treating the interface as a WebAuthn
authenticator.

*Note*: the number `XX` is a placeholder, assigned when this draft is proposed
as a pull request to `nostr-protocol/nips`.

Two layers are specified:

1. **Transport** — CTAPHID framing on a dedicated HID interface (usage page
   `0xFF00`, usage `0x01`), with a vendor command range `0x40`–`0x7F`.
2. **Command set** — a CBOR request/response envelope, a mandatory method set
   (identity read, signing, NIP-44 v2 encrypt/decrypt, identity enumeration)
   and optional method groups (key management, PIN custody, touch policy).

A NIP-07 bridge layer maps `window.nostr` calls onto the command set; it is a
recommended client architecture, not a normative part of the transport.

## Motivation

- **Key custody.** NIP-07 signers hold keys in browser-extension storage; a
  compromised page, a malicious extension, or a stolen laptop yields the
  identity. NIP-46 moves the key to a remote signer, which remains software
  custody on a server the user does not control. No current NIP specifies a
  transport for hardware custody, where the key stays sealed on a device the
  user physically confirms. (A local NIP-46 bunker daemon fronting such a
  device is possible today; [Relation to other NIPs](#relation-to-other-nips)
  answers why this NIP does not take that route.)
- **One transport, no new stack.** CTAPHID packetization (64-byte reports,
  channel IDs, INIT handshake, keepalives, CANCEL) is specified and widely
  implemented across FIDO authenticators. The framing code is reusable; the
  discovery code is not — CTAP host stacks enumerate the FIDO usage page and
  will not find this interface, so a client writes its own discovery arm.
- **Coexistence with FIDO.** Chromium blocks WebHID access to interfaces
  whose top-level collection uses the FIDO usage page `0xF1D0`, and
  additionally gates FIDO-reported collections behind protections web pages
  cannot obtain. A separate vendor-usage interface (`0xFF00`) escapes both
  gates, so the same physical device serves WebAuthn and Nostr. Two caveats
  bind: Chromium also blocklists specific VID/PID pairs regardless of usage
  page, so a device MUST NOT enumerate under a blocklisted identity; and
  `0xFF00` is shared by other vendor peripherals (headsets, hardware
  wallets), so clients MUST confirm they are talking to a signer — via
  `get_info` — and not to another `0xFF00` device.
- **Consent and exfiltration resistance.** The command set includes touch
  consent as a protocol element (keepalives, an explicit touch window,
  channel-bound consent). What the device guarantees is that key material
  never crosses the wire and that no signature is produced without a
  device-level consent event. The device does not display or verify content
  — it signs the hash the client computed — so the semantic check ("what am
  I signing?") lives in client UI, under
  [Client consent requirements](#client-consent-requirements).
- **Reach, stated plainly.** WebHID is Chromium-only on desktop: no Firefox,
  no Safari, no mobile browser, and Linux requires a udev rule for hidraw
  access. Web Serial now reaches more browsers, and a consent-bearing
  command set could ride it. This NIP accepts the narrower reach
  deliberately, for the framed, interface-routed, consent-capable channel
  its command set assumes; deployments that need broader reach can front the
  same device with a NIP-46 bunker.

This NIP is **optional**: clients and devices that do not implement it
continue to interoperate; a client that does implement it can use any
compliant device, and a device that implements it works with any compliant
client.

### Relation to other NIPs

- **NIP-07** defines the page-facing `window.nostr` API. This NIP defines the
  device transport behind it and changes nothing on that surface.
- **NIP-46** moves signing to a remote signer reachable over Nostr relays.
  This NIP moves it to a device reachable over a local USB link: no relay,
  server, or network participates, and no encrypted bearer protocol is
  needed because the transport itself carries no key material. The obvious
  alternative — a local NIP-46 bunker daemon fronting a USB device, giving
  existing bunker clients hardware custody without a transport NIP — works,
  and this NIP does not pretend otherwise. What it removes is the trusted
  middleman process, the relay dependence, and the event-JSON contract:
  NIP-46's `sign_event` carries event JSON and the signer computes the id,
  while this transport carries a 32-byte hash, so the device never parses
  event content at all.
- **NIP-55** defines a signer interaction model for Android applications on
  the same device; it does not cover external hardware.
- **NIP-BE** defines BLE communication in the relay/client shape; it is not a
  signing-device protocol.
- No merged NIP defines a transport or command set for hardware signing
  devices. An open draft proposal does ([nostr-protocol/nips#1706](https://github.com/nostr-protocol/nips/pull/1706),
  BLE); this NIP covers USB HID with a different security model, described
  under [Prior art](#prior-art-web-serial-and-ble-signers). The evidence
  base for expectations cuts both ways: #1706 has been open and unmerged
  since January 2025, and no device-transport NIP has been merged to date —
  the process has not yet shown that it accepts this class of proposal.

### Prior art: Web Serial and BLE signers

Browser-to-hardware signing exists today over Web Serial.
[`horse`](https://github.com/lnbits/horse) (fiatjaf, later maintained by
LNBits) is a NIP-07 bridge that forwards `window.nostr` calls to a hardware
signer over Web Serial, and the
[`nostr-signing-device`](https://github.com/lnbits/nostr-signing-device) (NSD)
is the signer it drives: an ESP32 device that receives plain ASCII commands
(`/sign-message`, `/add-key`, `/wipe`) over a serial line, holds keys as
plaintext hex in flash, and implements no pairing or authentication on the
channel. Its README describes the transport as "not the most secure data
transmission method, but x1000 better than storing the privatekey on a
computer". Both projects demonstrate the value of moving the key off the
general-purpose computer.

Web Serial, however, is a plaintext, unauthenticated byte pipe whose
OS-level port is first-come-first-served: any process claiming the device
between sessions speaks with the user's full authority, and the device cannot
determine which process is talking. Custody mechanisms layered on such a
channel (plaintext key import, secret-bearing reads, an unconfirmed wipe)
inherit the assumption that the host is honest. Stated honestly: the
consent-bearing parts of this NIP's command set — no export, PIN session,
refusal status words — are command-set design and could in principle be
carried over Web Serial. What the transport choice changes is narrower but
load-bearing: CTAPHID supplies framing, channel multiplexing, keepalives and
CANCEL that a touch-consent model needs regardless, and interface routing
gives clients a stable, browser-mediated handle on the signer. This NIP
takes that trade; its reach cost is stated under [Motivation](#motivation).

This NIP therefore specifies a transport under the assumption that the host
is hostile: the channel is framed and interface-routed so protocols cannot
collide or be mistaken for one another; every secret operation requires
PIN-session and touch consent as applicable; no method carries or returns key
material; and the consent mechanics (keepalives, a per-identity touch
binding, refusal status words) are part of the wire contract rather than
host-rendered UI. The command set in [Methods](#methods) provides the same
functionality as horse and NSD under these constraints. A detailed security
comparison of the two designs — written by this draft's author, and readable
as the argument this NIP abbreviates — is available at
https://www.eddieoz.com/fapico2-vs-nsd-the-signer-and-the-serial-cable/.

Two further data points complete the picture. An open draft proposal,
[nostr-protocol/nips#1706](https://github.com/nostr-protocol/nips/pull/1706),
extends the same serial command dialect to BLE (`/add-key` with a plaintext
hex private key, `/shared-secret`, an unconfirmed `/wipe`), with no
authentication layer, no consent vocabulary, and no refusal status words. The
[Passport nostr signer](https://github.com/BitcoinQnA/passport-nostr-signer)
(Foundation Devices) exchanges newline-delimited JSON over a vendor-class
WebUSB interface and publishes no transport specification. As of this draft,
no merged NIP — and no published proposal with a transport specification —
specifies a hardware signing-device protocol in which key material never
crosses the wire and consent is part of the wire contract. The Passport
signer claims key sealing in its repository description, but the claim rests
on reading its implementation, not its documentation.

## Terminology

- **device** — a hardware Nostr signer implementing this NIP.
- **client** — host software (typically a browser extension) speaking the
  transport on behalf of web applications.
- **identity** — a BIP-340 secp256k1 keypair resident on the device, selected
  by an index.
- **slot** — the index of an identity. `get_info` reports the number of
  identities currently stored; it does not report capacity, so clients MUST
  treat a full key set (`0x6A88`) as the only authoritative capacity signal
  and MUST NOT assume any particular slot count.

## Transport

The device exposes a USB HID interface with usage page `0xFF00` and usage
`0x01`. Its HID report descriptor defines a 64-byte input report and a 64-byte
output report. Reports are exchanged over interrupt endpoints; there are no
feature reports (a `SET_REPORT` control request MAY be answered with STALL).

Framing follows the CTAPHID conventions (CTAP2 §4, and the framing the FIDO
client ecosystem already implements):

| Frame | Layout |
|---|---|
| Initialization | `cid(4) ‖ cmd‖0x80 ‖ len(2 BE) ‖ payload ≤57` |
| Continuation   | `cid(4) ‖ seq(1, from 0) ‖ payload ≤59` |

- **INIT** (`cmd = 0x06`): sent with a random 8-byte nonce on the broadcast
  channel `0xFFFFFFFF`. The device replies — 17 bytes, the CTAPHID INIT
  layout —
  `nonce(8) ‖ new_cid(4) ‖ protocol_version(1) ‖ version_major(1) ‖
  version_minor(1) ‖ version_build(1) ‖ capFlags(1)`.
  `protocol_version` MUST be `0x02` (CTAPHID). The three version bytes have
  vendor-defined meaning per the CTAP specification; the reference
  implementation sends `0x00 0x02 0x00`, and devices SHOULD bump them on
  wire-visible changes. `capFlags` MUST be `0x00` so that browsers and
  generic CTAPHID clients do not mistake the vendor interface for a FIDO
  authenticator. Under the CTAP 2.1 bit assignment (`CAPABILITY_NMSG =
  0x08` = "does not implement"), `0x00` reads as "MSG implemented"; devices
  answer `CTAPHID_MSG` with an ERROR frame regardless — the convention
  followed is the de-facto one of existing vendor-usage devices, and no
  known client acts on the bit here. Clients MUST NOT reuse a channel
  across close; every session re-runs INIT.
- **PING** (`0x01`), **WINK** (`0x08`), **CANCEL** (`0x11`), **ERROR**
  (`0x3F`), **KEEPALIVE** (`0x3B`): as in CTAPHID. An idle mid-transaction
  device SHOULD answer a stalled transaction with an ERROR frame
  (`error = 0x05`, timeout) and reset its channel state. The device serves
  one transaction at a time. A frame from another channel arriving while a
  transaction is awaiting continuation packets is answered with an ERROR
  frame (`error = 0x06`, channel busy); a complete second vendor request
  arriving while a touch window is pending is instead refused in band
  (`0x6985`), per [Presence semantics](#presence-semantics).
- **KEEPALIVE** payload during a pending operation: `0x01` = processing,
  `0x02` = user presence needed (the touch prompt). Devices SHOULD send
  `0x01` when an operation starts and switch to `0x02` while the touch is
  owed. Devices SHOULD send keepalives at least every 100 ms while an
  operation is pending (the CTAPHID cadence); the reference sends every
  250 ms. Clients SHOULD surface both states to the user; `0x02` is the
  signal to render "touch your device".
- **CANCEL**: while a touch window is pending, a CANCEL arriving from
  **any** channel closes the window; the device then answers the pending
  command's own channel with the refusal it would have given at window
  expiry (see [Methods](#methods)) — the vendor vocabulary answers a stored
  refusal envelope rather than the standard cancel semantics. This is a
  deliberate divergence from CTAPHID, which scopes cancellation to the
  CANCEL's own channel; it is fail-closed (a cross-channel CANCEL costs a
  retryable `0x6985`, nothing more). CANCEL sent when nothing is pending is
  ignored silently.

**Channel allocation.** The device allocates channel IDs from a free-running
counter per interface. Devices that fold the channel into a presence tag
(see [Security Considerations](#security-considerations)) MUST bound their
allocator below the tag prefix region; the reference implementation wraps the
Nostr interface's allocator at `0x20000000`; on wrap it MAY reissue a
channel's ID (the reference cannot distinguish open from closed). The CTAP
specification requires system-wide channel uniqueness, so a wrapping device
SHOULD skip the IDs of channels it believes are still open.

## Methods

Vendor commands occupy the CTAPHID-reserved vendor range `0x40`–`0x7F`. The
command byte identifies the method; the CTAPHID payload carries one CBOR item.

| Byte | Method | Touch | Description |
|---|---|---|---|
| `0x40` | `get_info` | no | Device capabilities and state |
| `0x41` | `get_public_key` | no | Public key of an identity |
| `0x45` | `list_identities` | no | Enumerate identities and labels |
| `0x42` | `sign_schnorr` | yes* | BIP-340 signature over a 32-byte hash |
| `0x43` | `nip44_encrypt` | yes* | NIP-44 v2 encrypt to a peer |
| `0x44` | `nip44_decrypt` | yes* | NIP-44 v2 decrypt from a sender |
| `0x46` | `generate_identity` | yes | Generate a keypair into a slot |
| `0x47` | `import_private_key` | yes | Import a 32-byte scalar into a slot |
| `0x49` | `delete_identity` | yes | Destroy an identity; echo its pubkey |
| `0x4A` | `set_label` | yes | Set a ≤32-byte UTF-8 label |
| `0x4B` | `verify_pin` | no | Open the PIN session |
| `0x4C` | `set_pin` | no | Set (`idx=0`) or change (`idx=1`) the PIN |
| `0x4D` | `lock` | no | Close the PIN session (idempotent) |
| `0x4E` | `start_ceremony` | no | Custody-migration ceremony (see below) |
| `0x4F` | `set_touch_policy` | see text | Re-enable (`idx=0`) or consent-exempt (`idx=1`) the touch |

\* touch may be exempted by an armed [touch-policy bypass](#touch-policy-and-bypass-0x4f);
the bypass covers only `sign_schnorr`, `nip44_encrypt` and `nip44_decrypt`.

Bytes `0x48` (`export_private_key`) and `0x50`–`0x7F` are **reserved**.
Devices MUST answer them in band with `0x6D00` (see status words) and MUST
NOT add an export command: private keys are import-only. Future methods are
allocated upward from `0x50` and MUST keep the "unsupported byte answers
`0x6D00` in band" contract so clients can probe.

The interoperability core a conforming device MUST implement is `0x40`–
`0x45` (`get_info`, `get_public_key`, `list_identities`, `sign_schnorr`,
`nip44_encrypt`, `nip44_decrypt`); every other method group above is
optional and advertised through `caps`. A second device implementation can
conform by implementing only the core.

### Envelope

**Request** — the CTAPHID payload of a vendor command is a CBOR array of two
elements:

```
[idx: unsigned, arg: byte string]
```

- `idx` is the identity slot the method applies to, or `0` where unused.
  A `idx` that is well-shaped but names an unoccupied slot is answered
  `0x6A82` by the touch-free reads and by every idx-taking method; a `idx`
  that cannot be encoded in one byte (above `255`) is a malformed envelope
  and answers `0x6A80`.
- `arg` is the method's argument (possibly empty). An *empty CTAPHID payload*
  is itself valid and is equivalent to `[0, h'']` — this is how `get_info` is
  called. Methods that take no argument accept `[idx, h'']` for any
  applicable `idx`; the method byte, not the payload, discriminates between
  commands.
- The argument MUST be at most **1891 bytes**; larger arguments are refused
  in band. This cap derives from the largest NIP-44 v2 ciphertext the
  reference transport can answer (see `max_plaintext` in GET_INFO). The cap
  binds this transport revision and all its methods, present and reserved;
  a revision that raises it MUST bump `applet_version`.
- Malformed envelopes (wrong array head, non-byte-string arg, trailing bytes,
  over-cap arg, unencodable `idx`) are refused in band with `0x6A80`.

**Response** — the device answers on the request's own command byte with a
CBOR map:

```
{1: sw: unsigned, 2?: data: byte string}
```

`sw` is a 16-bit status word. `data` is present only when the method returns
a body. A response frame that does not arrive on the request's own command
byte is a framing error, not a method result. There are no request IDs and
no pipelining: a CTAPHID transaction is atomic — one request, one response
on the same channel and command byte — and the client matches responses by
channel. A second request that arrives while the first is still being
assembled is answered with an ERROR frame (`0x06`, channel busy); once the
first is parked awaiting touch, a second request is refused in band
`0x6985` instead.

### Status words

Clients MUST render the status word to the user rather than swallowing it.
`0x9000` is success; everything else is a refusal, in band — a refused method
is never a CTAPHID ERROR frame.

| SW | Meaning |
|---|---|
| `0x9000` | Success |
| `0x6A80` | Wrong data — malformed envelope, bad argument, invalid decrypt payload (wrong version byte or bad MAC) |
| `0x6A82` | Context-dependent: no such identity (idx-taking methods, where a gate applies) / PIN not set (`start_ceremony` without a PIN) / PIN already set (`set_pin` idx=0 on a PIN-set device). Clients disambiguate via `get_info` flags. |
| `0x6A84` | Slot occupied — generate/import never overwrite |
| `0x6A86` | Incorrect P1-like parameter |
| `0x6A87` | Invalid peer key (not a valid secp256k1 x-only point) |
| `0x6A88` | Key set full — all slots committed |
| `0x6B00` | Unsupported curve form (NIP-44 v1 compressed-ECC peer key or payload) |
| `0x6D00` | Method not supported (reserved/unknown command byte) |
| `0x6982` | PIN session required — an identity-touching method refused |
| `0x6985` | Touch required — window expired, or a request arrived while a window was pending. During `start_ceremony` on devices that must warm their entropy source, this same word is answerable and retryable (no touch owed). |
| `0x63C0` | PIN locked — retry counter exhausted |
| `0x63CX` | Wrong PIN, `X` attempts remaining (`X` = 1–3) |
| `0x6F00` | Store fault (device-side storage error) |
| `0x6F01` | Sealed storage unavailable (persistent until next power cycle) |
| `0x6F02` | Ceremony not needed |

### `get_info` (`0x40`)

Sent with the empty-payload form. Response body:

```
applet_version(2) ‖ caps(2 BE) ‖ max_plaintext(2 BE) ‖ n_identities(1) ‖ flags(1)
```

- `applet_version` — wire-layout version; bumps when the envelope or a body
  layout changes, not when methods are added.
- `caps` — bit field:
  - `0x0001` key management (generate/import/delete/label/list)
  - `0x0002` NIP-44 v2 encrypt/decrypt
  - `0x0004` PIN custody (verify/set/lock)
  - `0x0008` custody ceremony
  - `0x0010` touch policy
- `max_plaintext` — the largest NIP-44 v2 *plaintext* the device will accept
  for encryption (1792 in the reference implementation). Clients SHOULD read
  this and size their payloads to it; payloads above it are refused.
- `n_identities` — the number of identities **currently stored** (not the
  capacity; a fresh device reports `0`).
- `flags` — bit field:
  - `0x01` PIN is set
  - `0x02` a PIN session is currently open
  - `0x04` custody ceremony pending
  - `0x08` touch bypass armed

`get_info` is the health check: clients SHOULD call it at connect time and
derive the whole UI (PIN offer, session state, capabilities) from it.

### `get_public_key` (`0x41`) and `list_identities` (`0x45`)

`get_public_key` takes `arg` empty and returns
`xonly_pubkey(32) ‖ bech32_npub(63)`. Clients use the first 32 bytes as the
hex pubkey; the bech32 form is the NIP-19 `npub` rendering, provided so thin
clients need no bech32 codec. An `idx` naming an unoccupied slot answers
`0x6A82`.

`list_identities` ignores `idx` and returns:

```
count(1) ‖ [ idx(1) ‖ flags(1) ‖ xonly_pubkey(32) ‖ label_len(1) ‖ label ] × count
```

Both are touch-free: public data cannot consent to anything. That is also
the privacy cost — any connected client can silently enumerate the identity
set and its user-chosen labels, which enables cross-site identity linkage.
See [Client consent requirements](#client-consent-requirements).

### `sign_schnorr` (`0x42`)

`arg` is the 32-byte message hash (for Nostr events, the NIP-01 event id —
see [Client requirements](#client-requirements)). Response body:
`xonly_pubkey(32) ‖ bip340_signature(64)`.

The device signs the hash it is given; it does **not** parse events and does
**not** verify that the hash is the id of any event. Correct id computation
is the client's obligation (verified against the returned pubkey in a
well-formed client). This division is deliberate: event parsing on-device
would couple the device to every future event kind and grow its attack
surface without adding custody.

The returned pubkey echo lets the client detect a slot mismatch
(`signed ≠ requested`) without a second round trip.

### `nip44_encrypt` (`0x43`) / `nip44_decrypt` (`0x44`)

`arg` is `peer_xonly_pubkey(32) ‖ payload`. For encrypt, `payload` is the
plaintext; the response is a NIP-44 v2 payload
`0x02 ‖ nonce(32) ‖ ciphertext ‖ mac(32)`. For decrypt, `payload` is the
received v2 payload; the response is the plaintext.

**Encoding contract.** The device exchanges raw bytes, not the base64
strings NIP-44 payloads use on the network. A client bridging to NIP-07 or
NIP-44 MUST: UTF-8-encode the plaintext string before encrypting;
base64-encode (with padding) the raw response before returning it as a
NIP-44 payload; base64-decode a received payload before decrypting; and
UTF-8-decode the decrypted plaintext. Plaintext is at least 1 byte — an
empty string is refused `0x6A80` — and the `max_plaintext` cap binds
decryption too: a peer who sends the ciphertext of a larger message sends
something no conforming device can decrypt. Chunking large conversations at
the application layer is the client's remedy, as anywhere else in the
ecosystem.

The device validates the peer key (`lift_xonly`) before any scalar
multiplication and refuses the NIP-44 v1 compressed-ECC peer form with
`0x6B00`. Only v2 is implemented: the version byte in a decrypt payload MUST
be `0x02` — a payload with any other version byte, or one whose MAC fails,
answers `0x6A80`; a payload carrying the v1 compressed-ECC prefix answers
`0x6B00`.

### Key management (`0x46`, `0x47`, `0x49`, `0x4A`)

- `generate_identity` (`idx` = slot, empty arg) → `xonly_pubkey(32)`.
  Refuses an occupied slot (`0x6A84`) and a full key set (`0x6A88`); never
  overwrites.
- `import_private_key` (`idx` = slot, arg = scalar(32)) → `xonly_pubkey(32)`.
  Same refusal rules. The scalar is never returned afterward — see
  `export_private_key` above.
- `delete_identity` (`idx` = slot, empty arg) → the **deleted** identity's
  pubkey, echoed so the client can confirm what was destroyed.
- `set_label` (`idx` = slot, arg = UTF-8 ≤ 32 bytes) → empty success.

All four require the touch.

### PIN custody (`0x4B`, `0x4C`, `0x4D`)

A device MAY implement PIN custody (advertised by `caps & 0x0004`). When a
PIN is set, every identity-touching method other than the PIN verbs themselves
answers `0x6982` until `verify_pin` opens a session. The gate sits *after*
envelope-shape validation and *before* any state read or touch prompt, so a
refusal never consumes a touch and never leaks identity state.

- `verify_pin` (`arg` = PIN bytes, 6–64 UTF-8): success is the **only**
  setter of the open-session state. Wrong PIN answers `0x63C0|remaining`
  (durable across power cycles); `0x63C0` alone means locked out.
- `set_pin` (`idx=0`, arg = PIN): establishes custody. **Setting is not
  unlocking** — a successful `set_pin` leaves the session closed. On a
  PIN-set device it is refused (`0x6A82`).
- `set_pin` (`idx=1`, arg = `len(1) ‖ current ‖ new`): change; a wrong
  current burns the same durable retry counter as a failed verify.
- `lock`: closes the session. Any **well-formed** request answers `0x9000`,
  whether or not a session was open — a discriminating LOCK would leak
  session state to a host-side observer. (`0x6A80`/`0x6A86` for malformed
  shapes are framing-level, not state leaks.)

The session is device-global, not per-channel: it spans transports and
client reconnects, and dies on power cycle. Clients re-read `get_info` after
every PIN operation rather than caching flags.

There is no PIN recovery. A locked-out device is recovered by a factory
reset that destroys all identities; clients MUST say so before arming the
last attempt.

### `start_ceremony` (`0x4E`)

Optional (`caps & 0x0008`). Devices whose identity records predate PIN
custody advertise `flags & 0x04`; `start_ceremony` migrates them in place
under a burned, content-derived custody key. The verb itself is the consent:
it is not touch- or session-gated (nothing secret is opened), but it DOES
require a PIN to exist (`0x6A82` when none is set) — an irreversible
operation is not offered to a custody-less board. Devices MUST make it the
*only* command that writes irreversible state. Response body:
`migrated(2 BE) ‖ already(2 BE)`.

Refusals: `0x6F02` when there is nothing to migrate (no identity records,
or the marker already stands — a missing PIN answers `0x6A82`, above);
`0x6F00` on any fault during the
burn/reseat run, leaving the migration resumable after a power cycle; and
`0x6985` on devices that warm their entropy source before the run — retryable,
with no touch owed.

This method is specified so PIN-custody devices have one recognizable shape
for irreversible upgrades; devices that never needed a migration simply omit
the capability. It is implementation-lifecycle surface, not
interoperability surface: no client behavior depends on it beyond the
`flags & 0x04` and `caps & 0x0008` bits.

### Touch policy and bypass (`0x4F`)

Optional (`caps & 0x0010`).

- `idx=0` (enable): touch is required again for signing/encryption. No
  session needed — the button can always be had back friction-free.
- `idx=1` (disable): arms a bypass exempting exactly `sign_schnorr`,
  `nip44_encrypt` and `nip44_decrypt` from the touch. Arming requires
  **both** an open PIN session **and** one physical press. The press consents
  to the identity (the `idx` slot), not to the opcode or any payload.

The bypass is RAM-only: it is cleared by `lock`, by a failed `verify_pin`,
and by every power cycle. It can never survive unplug, and a device with no
PIN can never arm it. Key management (generate/import/delete/label) is never
exempt. Devices advertise the armed state via `flags & 0x08` so the user's
UI can show that touches are currently exempted.

### Presence semantics

Touch-gated methods use the standard keepalive flow: the device sends
`KEEPALIVE` frames (`0x3B`) — first `0x01` (processing) when the window
opens, then `0x02` (user presence needed) while the touch is owed — and
answers within its touch window (15000 ms in the reference implementation;
clients MUST tolerate at least 30 s so that devices with longer windows
interoperate). Consent binds to the **pending request**, and through it to
the identity: the device parks the request that opened the window, tags the
window with `prefix | channel`, and answers only by replaying the parked
request verbatim. A press can therefore satisfy only the command currently
pending — a press armed for one command must never satisfy a command for
another. (Devices that tag consent state with `prefix | channel` MUST bound
their allocator so the fold stays injective; see
[Security Considerations](#security-considerations).)

**Park, don't queue.** While a touch window is pending on the vendor
interface, any second vendor request on that interface — any channel — MUST
be refused immediately in band (`0x6985`) without running the method. The
device does not queue; the client does. Clients MUST serialize their own
requests (a FIFO in client code, one outstanding transaction per
interface). A `0x6985` can still arise in normal flow: a second conforming
client on another connection, or another process claiming the interface,
shares the single pending window. Arbitration between clients is out of
scope; clients MUST surface the refusal to the user rather than retrying.

A touch window may also be pre-empted by another transport or another
interface on a multi-transport device; the pending request is then answered
`0x6985` as well. Clients MUST treat any `0x6985` as a retryable refusal and
MUST NOT automatically re-drive the request.

## Client requirements

- **Serialize.** One outstanding request per interface; queue everything
  else client-side. A second request that arrives while the first is being
  assembled is answered with an ERROR frame (`0x06`, channel busy); one
  that arrives while the first waits for touch is refused in band
  (`0x6985`).
- **Drain on refusal.** A queued request whose predecessor ended in a
  refusal MUST be discarded or re-presented to the user before execution;
  work the user believes died with a touch window must not execute silently
  afterward.
- **Compute ids yourself.** For Nostr events, the client builds the event per
  NIP-01, computes the id, sends the 32-byte id to `sign_schnorr`, and fills
  `pubkey`, `id` and `sig` from the reply. A well-formed client also checks
  the device's pubkey echo against the requested slot's key.
- **Render status words.** Map each SW in the table above to a sentence; in
  particular `0x6985` (touch), `0x6982` (PIN session), and `0x63C0|X`
  (attempts remaining) are user-facing, not error codes to retry over.
- **PIN entry belongs to the client UI, never to a web page.** PIN verbs are
  privileged: a conforming bridge exposes only the page-safe methods
  (`get_public_key`, `sign_schnorr`, `list_identities`, `nip44_encrypt`,
  `nip44_decrypt`) to pages, and keeps key management and PIN behind
  extension-trusted UI.
- **Time budget.** A whole-ceremony client timeout of 30 s fits the
  reference device's 15 s touch window with margin; on `signal.abort`, send
  CANCEL and wait for the refusal rather than abandoning the channel.

### Client consent requirements

The device boundary and the effective consent boundary are different
objects. `get_public_key` and `list_identities` are touch-free, so for them
the only consent that exists lives in client UI — and a client MAY persist
user approvals indefinitely. The following requirements bind conforming
clients:

- **Grant scope.** A client MAY remember a user approval per (origin,
  method). Persisted grants MUST be clearable by the user, and the client
  MUST provide a view of the grants it holds.
- **Bypass visibility.** While `get_info` reports `flags & 0x08` (touch
  bypass armed), the client MUST render that state wherever it shows grants
  or prompts, and MUST NOT grant a page silent signing — a persisted signing
  grant honored while the bypass is armed — unless the user approved that
  combination explicitly.
- **Enumeration is sensitive.** `list_identities` and `get_public_key`
  enable cross-site identity linkage. Clients MUST treat the identity list
  and its labels as sensitive data, SHOULD restrict `list_identities` to
  trusted UI or per-session confirmation rather than a persistent page
  grant, and MUST disclose the linkage risk when offering a persistent
  grant for it.
- **The trusted layer is the attack surface.** The client (extension) is
  the root of trust: it computes event ids, holds grants, and drives the
  privileged methods. Against a compromised client, this transport delivers
  key non-extractability only — arbitrary signing and arbitrary NIP-44
  operations remain available. The residual security anchor is the client's
  publisher and update channel; conforming documentation MUST say so.

### The NIP-07 bridge

A conforming client exposes `window.nostr` per NIP-07 on top of this
transport:

| NIP-07 call | Device commands | Conversion owed by the client |
|---|---|---|
| `getPublicKey()` | `get_public_key` (active slot) | — |
| `signEvent(event)` | `sign_schnorr(id)` | compute the NIP-01 id client-side; verify pubkey echo |
| `nip44.encrypt(peer, plaintext)` | `nip44_encrypt` | UTF-8-encode plaintext; base64-encode the raw response |
| `nip44.decrypt(sender, payload)` | `nip44_decrypt` | base64-decode the payload; UTF-8-decode the plaintext |

Fidelity notes, stated rather than implied: `nip44.encrypt`/`decrypt` are
**optional** methods in NIP-07 — pages MUST feature-detect them, and a
minimal conforming bridge may omit them. NIP-04 (`nip04.*`, deprecated)
cannot be served at all: the device has no NIP-04 verbs, and pages depending
on it break against a device-backed bridge exactly as they break against
NIP-07 providers that dropped it. A `listKeys()`-style picker is
client-defined, not part of NIP-07; pages coding against it are not
portable. Slot selection (which identity a page is acting as) is client
policy; `list_identities` backs the picker. For the methods a device
supports, the NIP-07 surface a page sees is unchanged from a software-key
extension — the backwards-compatibility story of this NIP.

## Rationale

- **Why a new transport instead of the established Web Serial one?** The
  Web Serial designs' weakness is that custody mechanisms layered on their
  channel inherit the honest-host assumption (see
  [Prior art](#prior-art-web-serial-and-ble-signers)). A consent-bearing
  command set over Web Serial is possible; this NIP chose CTAPHID anyway,
  for the framing, multiplexing, keepalives and CANCEL a touch model needs
  regardless, and accepts the narrower browser reach that choice costs. The
  profile preserves the useful property of those designs — a low-cost,
  one-cable device that keeps the `nsec` off the computer.
- **Why CTAPHID framing rather than a new protocol?** The framing is already
  specified, already implemented in host stacks, and carries keepalives and
  CANCEL, which a touch-based consent model requires regardless. A new
  protocol would have to re-derive the same mechanics.
- **Why not NIP-46's method vocabulary?** NIP-46's `sign_event` carries
  event JSON and the signer computes the id; this device takes a 32-byte
  hash and never parses event content. Reusing the names would buy
  familiarity with different semantics, and bunker clients could not talk
  to the device without a relay stack regardless.
- **Why a separate `0xFF00` interface?** WebHID cannot open a FIDO interface
  (browser policy blocks usage page `0xF1D0`). `0xFF00` is the vendor-usage
  interface hardware-wallet tooling already uses for the same reason, and it
  lets one physical device serve FIDO and Nostr with independent channel
  spaces.
- **Why in-band status words instead of CTAPHID ERROR frames?** A refused
  method ("PIN required", "no such slot") is a protocol result, not a
  transport fault. ERROR frames would lose the status vocabulary and force
  clients to guess.
- **Why park-not-queue on the device?** Queueing touch windows on a device
  with one button makes it ambiguous which of the queued requests a press
  consents to. With a single pending window and immediate refusal otherwise,
  the consented request is always the one currently pending.
- **Why the 1891-byte argument cap?** It is derived from the largest NIP-44
  v2 plaintext whose padded ciphertext fits the device's response frame
  budget, plus the peer key and version overhead. Reporting `max_plaintext`
  in GET_INFO lets clients size payloads deterministically instead of
  probing. The cap is a transport-revision constant (see
  [Envelope](#envelope)); raising it requires an `applet_version` bump.
- **Why no export?** An export command re-exposes key material to the host
  and requires a consent model of its own. Import-only custody (the OpenPGP
  card 3.4 precedent) removes the wire path — it does not undo the fact
  that an imported key existed in software before import. The cost is also
  stated: a device-generated identity has no backup, and a dead device
  takes it with it. Backup of an imported identity is performed by
  importing the same scalar into a second device at provisioning time.

## Security Considerations

- **Event-id trust.** The device signs any 32 bytes. A malicious client can
  obtain a signature over an id computed from content the user never saw.
  This is inherent to hash-then-sign hardware and is the same trust boundary
  as NIP-07 software signers; the device's contribution is that the *key*
  never leaves, not that the *meaning* is checked. UIs should display the
  event the client claims is being signed.
- **Presence-tag domains.** Devices that tag consent state with
  `prefix | channel` MUST keep the prefixes disjoint per transport and MUST
  bound channel allocation so the fold stays injective (reference: Nostr
  channels below `0x20000000` under the `0x60000000` prefix; FIDO's separate
  bit-31 domain). A folded tag means one press grants two transports.
- **capFlags = 0.** Advertising CTAP2 capability on the vendor interface
  would let browsers bind it as a WebAuthn authenticator and route
  cross-origin ceremonies to a device that answers Nostr methods. Devices
  claim no capability, so the interface is not bindable.
- **PIN session breadth.** The session is deliberately device-global so
  there is exactly one unlock state to reason about. Clients wanting
  per-page isolation get it from the page/extension boundary, not from the
  device.
- **Bypass scope.** The armed bypass covers the three secret-using,
  non-destructive operations. It never covers key management, and it never
  persists. The `flags & 0x08` advertisement is mandatory so software cannot
  silently hold an armed device. The composition to watch is bypass +
  persisted client grant: together they yield silent signing for the life
  of the session, and
  [Client consent requirements](#client-consent-requirements) forbid clients
  from assembling it without explicit user approval.
- **The client boundary.** Grants, prompt UI, and slot selection live
  client-side; the device cannot see them. For the touch-free methods the
  only consent that exists is client-side. The requirements of
  [Client consent requirements](#client-consent-requirements) are what keep
  the effective consent boundary from being weaker than the device boundary.
- **Custody is per-implementation.** This NIP specifies the wire. At-rest
  custody — sealed storage, an unexportable root, a closed debug port — is
  an implementation property, and "no method returns key material" says
  nothing about what a physical attacker with a debug probe can do. The
  reference implementation's published alpha images ship with the SWD debug
  port open; while it is open, every key on the board is extractable with
  brief physical access, and the implementation's own risk record says so.
  Custody claims apply to images where that closure has actually fired.
- **Status-word side channels.** Refusal order is fixed (shape → PIN gate →
  state → touch), and `lock` always succeeds for well-formed requests, so
  refusal timing and codes do not leak more than the protocol's own
  semantics require.

## Reference implementations

- **Device:** [fapico2](https://github.com/eddieoz/fapico2) — RP2350
  firmware; `firmware/src/nostr_wire.rs` (transport dialect), `apps/nostr`
  (applet), `firmware/src/ctap_hid.rs` (framing/CID allocator),
  `firmware/src/hid_serve.rs` (dual-interface serving). 8 identities,
  NIP-44 v2, PIN custody, ceremony, touch policy.
- **Client:** [fapico2-nostr-extension](https://github.com/eddieoz/fapico2-nostr-extension)
  — browser extension speaking this transport over WebHID and exposing
  NIP-07 (plus a `listKeys()` picker defined by this ecosystem, not by
  NIP-07); its protocol fixture test pins the wire bytes byte-for-byte
  against the device's transcribed constants.

This draft currently has one device implementation and one client
implementation, both by the same author. The NIP acceptance bar
("implemented in at least two clients") requires a second independent
implementation on each side before it can leave draft.

## Compatibility

The transport reuses CTAPHID mechanics without modifying them; the command
range `0x40`–`0x7F` is the CTAP specification's vendor space, so a conforming
device and a FIDO authenticator can share a USB composite device with
independent interfaces. No relay or event-format change is involved: every
event produced through this transport is a plain NIP-01 event, and every
encrypted payload is a plain NIP-44 v2 payload.

Why a NIP and not a library spec: this document normatively binds any
conforming client/device pair, not one library's users. On the "no more
than one way of doing the same thing" criterion: the three
client-to-external-signer protocols differ by medium and security model —
NIP-46 for remote signers over relays, #1706 (draft) for BLE, this NIP for
consent-bearing local USB HID — and they are not interchangeable for the
custody properties above. NIP-46 remains the right choice for deployments
that want the signer off-site; this NIP covers the one-cable local case.
