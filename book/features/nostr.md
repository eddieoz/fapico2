# The Nostr applet

The board signs and encrypts for **Nostr identities** — up to eight BIP-340 (Schnorr) key pairs held on the chip, sealed in flash like every other key the device owns. Signatures and NIP-44 v2 ciphertexts are computed on the RP2350; the private keys never leave the board except through one deliberate, touch-gated export. This page is the implementation tour: what was built, how the transports work, where the keys live, and which decisions are deliberate. The user-facing walk is the [Nostr how-to](../how-to/nostr.md).

## Why an applet for a social identity

A Nostr identity is a **publishing identity: non-revocable and recoverable by no one**. Whoever holds the secret key *is* the identity — there is no customer support. That makes it the same class of secret as a bitcoin key, and the board's whole design premise ([why self-custody](../getting-started/index.md)) applies verbatim: keys generated on the device, sealed at rest under a chip-unique root, used only on the chip, and gated by a physical press.

Two consequences shaped the design, both recorded in [ADR 0005](https://github.com/eddieoz/fapico2/blob/main/docs/adr/0005-nostr-key-storage.md):

- **Keys are device-bound, not PIN-bound.** The record key derives from the OTP row plus the chip ID — nothing `authenticatorReset` or management `RESET` can destroy — so a forgotten-PIN recovery cannot strand the records sealed under a key that no longer exists. (The derivation deliberately takes no PIN input; the ADR records the two bad outcomes that killed the user-bound draft.)
- **A second secp256k1 implementation ships on purpose.** BIP-340 signing and the NIP-44 ECDH run on `secp256kfun` beside the platform-owned curve code, because routing through the trussed client would drag in the heap and a backend crate the applet may not name. The decision is gated on a measurement (25,046 B of `text` against 44 KB of deliberate headroom), not a projection.

## The command surface

One applet, two transports. Over **CCID** the applet is selected by AID `F0 00 00 00 02` and speaks plain ISO-7816 APDUs — the `INS` column below. Over **USB HID** it answers a third interface (interface 3, vendor usage page `0xFF00`) speaking CTAPHID framing with vendor command bytes `0x40`–`0x4A` and a CBOR payload — the byte column. Same applet, same consent rules, two clients:

| Command | CCID `INS` | HID vendor byte | Touch? | Request → response |
|---|---|---|---|---|
| `GET_INFO` | `0x10` | `0x40` (PING) | no | — → version, caps, max plaintext, live count |
| `LIST_KEYS` | `0x11` | `0x45` | no | — → `n`, then per identity: idx, flags, npub, label |
| `GET_PUBKEY` | `0x12` | `0x41` | no | — → npub(32) + bech32 `npub1…`(63) |
| `GENERATE_KEY` | `0x13` | `0x46` | **touch** | — → npub(32) |
| `IMPORT_KEY` | `0x14` | `0x47` | **touch** | scalar(32) → npub(32) |
| `SIGN` | `0x15` | `0x42` | **touch** | sighash(32) → npub(32) ‖ sig(64) |
| `NIP44_ENCRYPT` | `0x16` | `0x43` | **touch** | peer_x(32) ‖ plaintext → `0x02` ‖ nonce(32) ‖ ct ‖ mac(32) |
| `NIP44_DECRYPT` | `0x17` | `0x44` | **touch** | sender_x(32) ‖ payload → plaintext |
| `SET_LABEL` | `0x18` | `0x4A` | **touch** | utf8(≤32) → — |
| `DELETE_KEY` | `0x19` | `0x49` | **touch** | — → the destroyed identity's npub(32) |
| `EXPORT_KEY` | `0x1A` | `0x48` | **touch** | — → scalar(32) |

The command surface is fixed in `apps/nostr/src/lib.rs:106-134`; the HID vendor-byte mapping is `firmware/src/nostr_wire.rs:40-61`. `SIGN` answers with the npub *alongside* the signature (`apps/nostr/src/lib.rs:721-726`) — a host that signed against the wrong identity cannot paper over it, because the answer names the key that produced the signature.

Three touch-free reads, and only three. An npub is public; a label is owner-authored text — listed without a touch, so a label is part of the public surface by definition. Everything that uses or changes the private set presses the button, and **no config bit turns that off**.

```text
                ┌────────────────────────── one NostrApp ──────────────────────────┐
                │                                                                  │
 Chrome / WebHID│  CTAPHID vendor commands 0x40–0x4A          CCID APDUs by AID    │  PC/SC, scripts
   extension ───┤  (CBOR [idx, arg] payloads)                  (00 1x P1 P2 Lc …)  ├─── ykman-style tools
                │        │                                            │            │
                │  firmware/src/nostr_wire.rs               platform/src/dispatch.rs │
                │  decode_request → build_apdu ──────────────►  App::process(data‖sw) │
                │        │                                            │            │
                │        └────────────┬───────────────────────────┘            │
                │                     ▼                                        │
                │  NostrViaMutex (firmware/src/nostr_shared.rs)                │
                │  one embassy Mutex around the applet; touch wait OUTSIDE it  │
                │                     │                                        │
                │                     ▼                                        │
                │  NostrRegion store (platform/src/keyregion/nostr_store.rs)   │
                └──────────────────────────────────────────────────────────────────┘
```

## The touch, in three tag domains

The applet's consent model is the device's usual one — a press — extended to a board with **two Nostr transports and a FIDO interface on the same USB device**. The rule that makes one button safe across all three: every pending touch is tagged with the *domain* it belongs to, and a grant can only be consumed by its own domain. The domains are disjoint by construction (`apps/nostr/src/lib.rs:1362-1400`):

| Domain | Tag | Bound to |
|---|---|---|
| Nostr over CCID | `0x4000_0000 ‖ idx` | the identity index — a press consents to *this identity's* command |
| Nostr over HID | `0x6000_0000 ‖ CID` | the extension's CTAPHID channel (allocator clamped below `0x2000_0000` so the OR-fold stays injective, `firmware/src/ctap_hid.rs:503-514`) |
| FIDO | `0x8000_0000 ‖ CID` | the CTAP-HID channel, untouched |

```text
 press ──► PresenceService (single pending slot, anti-harvest discard)
             │
             ├── CCID arm: blocking wait under the command's own tag (~15 s window)
             │    └─ steady LED for the whole wait; sampled in-line at ~5 ms
             ├── Nostr-HID arm: park the request, keepalives (250 ms, "up needed"),
             │    └─ press consumed by the next re-drive; refusal envelope on expiry
             └── grant dies with its request — CANCEL and expiry drop an armed press
                  (a press made for a cancelled command authorizes nothing)
```

Three behaviours are worth knowing because audits found them missing once (`docs/nostr-presence-audit.md`, 2026-10-12):

1. **An armed grant dies with its request.** A press made while command A was pending does not survive A's cancellation to authorize a later command B on the same channel (the audit's one Critical finding, PoC-confirmed; fixed in `platform/src/presence.rs:122-169`).
2. **The domain check is exact, not a mask.** The Nostr grant accepts only tags whose top three bits are exactly `0x6000_0000` (`firmware/src/presence.rs:839-841`) — a folded FIDO tag must never pass as a Nostr grant.
3. **The HID arm refuses, it does not queue.** A second vendor command while a touch window is open answers the touch status word immediately, without running the applet (`firmware/src/hid_serve.rs:1747-1755`). The extension does its own FIFO queuing on top.

The windows: **15 s** for the Nostr HID window (`NOSTR_TOUCH_WINDOW_MS`, `firmware/src/hid_serve.rs:166-178` — deliberately shorter than CTAP2's 30 s, so a flappy browser tab cannot hold the single consent slot against a WebAuthn ceremony), and a ~10 s blocking wait on CCID in the OpenPGP PSO shape (`firmware/src/button.rs:154-159`). A press is what consents to the **identity**, not to the opcode — the design accepts that a confused press can turn a "sign" into an "export", and answers it by making export a two-consent act (checkbox in the extension, then the press) rather than by weakening the tag.

## Where the keys live

Eight slots carved **from the top of what was FIDO's range**, so every existing passkey's address stays stable while the region remains fully tiled (`platform/src/keyregion/mod.rs:184-249`):

| Quantity | Value | Notes |
|---|---|---|
| Nostr slots | 8 | `NOSTR_CAPACITY` |
| Record body | 97 B | scalar(32) ‖ npub(32) ‖ label(32) ‖ flags(1), fixed width |
| Sealed record | ≤ 125 B | AEAD overhead included |
| FIDO capacity impact | 856 → **848** | measured to refusal at the carved geometry (`docs/capacity.md:144-148`) |

Each identity is one AEAD-sealed record whose additional authenticated data binds **domain, slot and generation** — a Nostr record physically cannot open as a FIDO or OATH record, and a record from another board cannot open here (`platform/src/keyregion/nostr_store.rs:26-50`). The store is stricter than OATH's for one reason: Nostr's slots *were FIDO's* until the carve, so **every write runs an occupancy guard** — a slot that is not virgin must open successfully as a Nostr record before it is reused. A stale FIDO passkey sitting in the carved range is refused as occupied (`6A84`), not silently overwritten. Deletes commit tombstones (one zero byte — never a valid scalar), and a slot that carries the Nostr tag but will not open is deletable through a force-tombstone, so one corrupt byte cannot strand 12.5 % of the set.

## The crypto, and the one cap that surprises people

- **Signatures** are BIP-340 over the raw 32-byte sighash — the extension hashes the NIP-01 event in the browser and sends only the hash; the board returns `(R.x ‖ s)` plus the npub. The implementation is ported from a measured spike and pinned against the BIP-340 reference vectors and NIP-44's own published vector set (`apps/nostr/src/crypto.rs:1-12`, `spike-secp256kfun/vectors/`).
- **NIP-44 v2** follows the spec's byte shapes exactly: conversation key `HMAC-SHA256(x(a·B), "nip44-v2")`, message keys `HKDF-expand(ck, nonce, 76)`, ChaCha20 + HMAC-SHA256 with the nonce as AAD. Decryption verifies the MAC **constant-time before any length parsing** (`apps/nostr/src/nip44.rs:238-244`).
- **The encryption nonce is generated on the device** from the applet's RNG source — the host cannot supply it, so no host bug can reuse one (`apps/nostr/src/lib.rs:765-770`).
- **Plaintext cap: 1,792 bytes.** This is derived, not chosen: the largest response the wire can carry (2,074 B over CCID) bounds the *chunk-rounded* padded ciphertext, and NIP-44's padding jumps 1792 → 2048 at plaintext 1793 — so a naive 1900-byte cap would produce a response the device drops with no frame and no status word. 1,792 is the largest plaintext whose padded length fits (`apps/nostr/src/lib.rs:211-227`). The same arithmetic is asserted at compile time by the wire tests, so the cap and the refusal cannot drift.

## Status words

The device has no screen, so every refusal is a status word the host must render. The vocabulary (`apps/nostr/src/lib.rs:136-201`):

| SW | Meaning | Who it names |
|---|---|---|
| `6A80` | wrong data / bad index / malformed payload | your request |
| `6A82` | no such identity at `idx` | the slot is empty |
| `6985` | touch required / not granted / window expired | press the button |
| `6A84` | identity index occupied — never overwritten | pick another slot or delete |
| `6A88` | key set full (all 8 committed) | delete something first |
| `6A86` | wrong P1/P2 | your request |
| `6A87` | peer/sender key not a valid curve point | the counterparty's npub is corrupt |
| `6B00` | ECC key form (`f9308a…`, NIP-44 v1 x25519) unsupported | the counterparty's client |
| `6F00` | store fault — boot degraded or a slot that would not open | the device |
| `6D00` | unknown command | your request |

`6A87`/`6B00` are deliberately distinct from `6A80`: "your counterparty's client is broken" is a different fact from "your bytes are corrupt", and both are settled before the touch so a user is never asked to press to learn their paste was garbage.

## What management RESET does (and what it spares)

- **Management `RESET`** (the CCID management applet, INS `0x1E`) destroys **all eight Nostr identities** with everything else. The Nostr wipe is forwarded through the CCID proxy (`firmware/src/nostr_shared.rs:91-137`), and the host's pre-flight duty — enumerate with `LIST_KEYS`, show what will be destroyed, refuse without acknowledgement — belongs to the client driving the reset.
- **CTAP2 `authenticatorReset`** (what a browser or `ykman fido reset` triggers) wipes **only FIDO's slot range**; Nostr records survive sealed and recoverable, because nothing the FIDO reset destroys is an input to their key.

That split is the resolution of an audit finding, not an accident: "reset" meaning two different things is the divergence a user cannot see, so reset was made to mean what its own documents say (`docs/nostr-presence-audit.md` F-A3/D6).

## References

- The user's guide: [Nostr identities](../how-to/nostr.md)
- [ADR 0005 — Nostr key storage](https://github.com/eddieoz/fapico2/blob/main/docs/adr/0005-nostr-key-storage.md): the device-bound decision, the occupancy guard, the two-implementation measurement, the RAM-lifetime amendment
- [`docs/nostr-presence-audit.md`](https://github.com/eddieoz/fapico2/blob/main/docs/nostr-presence-audit.md): the adversarial audit of the touch gate — findings F-A1…F-A16, the hardware acceptance pass
- [`docs/archive/SECURITY-ASSESSMENT-NOSTR.md`](https://github.com/eddieoz/fapico2/blob/main/docs/archive/SECURITY-ASSESSMENT-NOSTR.md): the red-team pass over the whole arc (firmware + extension)
- [`docs/capacity.md`](https://github.com/eddieoz/fapico2/blob/main/docs/capacity.md): the carved geometry, measured
- The browser surface: [fapico2-nostr-extension](https://github.com/eddieoz/fapico2-nostr-extension) — NIP-07 `window.nostr` over WebHID; its error map is the plain-words rendering of the status-word table above
