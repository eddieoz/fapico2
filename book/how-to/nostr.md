# Nostr identities

The board holds up to **eight Nostr identities** and signs with them: BIP-340 (Schnorr) event signatures and NIP-44 v2 encryption, computed **on the chip**. The private keys never leave the device except through one deliberate, touch-gated export — the same posture the rest of the board applies to passkeys and PGP keys, applied to a social identity that cannot be revoked by anyone.

This guide walks the whole journey through the **fapico2 Nostr extension** — the browser extension that speaks the board's vendor protocol over WebHID and exposes the standard NIP-07 `window.nostr` API to web pages. Any Nostr web client that consumes `window.nostr` can sign through the board.

The companion pages: [what the applet is and how it works](../features/nostr.md) (architecture, commands, storage), and the book's general [using-the-device](../using/index.md) rules, which the Nostr applet follows for the touch.

## 0. What you need

- A fapico2 board on the `feat/nostr` firmware or later (the applet ships in the same UF2 as everything else — no separate image).
- Chrome, Chromium, Edge or another Chromium-browser version **116 or newer** — the extension is MV3 and talks WebHID, which Firefox does not ship.
- **Linux only, once:** a udev rule so Chrome's WebHID chooser can see the board's vendor HID interface. A custom VID owns no `uaccess` by default, and without the rule the device is absent from Chrome's chooser *before any extension code runs*. The rule ships in the repo:

```bash
sudo cp platform/udev/70-fapico2-nostr.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```

The rule is scoped to the `fa20` vendor ID and deliberately does **not** match a PID — the board's VID/PID is runtime-writable, and a PID-bound rule would silently stop working after you re-identify the board. The discriminating check: `lsusb` sees the device but Chrome's chooser does not ⇒ this rule is missing.

## 1. Install the extension

The extension ships its built `dist/` in the repository, so the short path is to load it directly:

```bash
git clone https://github.com/eddieoz/fapico2-nostr-extension.git
```

Then in Chrome: `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the **`dist/` folder** (not the repo root — the manifest lives in `dist/`). Pin the "fapico2" action icon to the toolbar.

If you build the extension from source instead, `npm ci && npm run build` regenerates `dist/` (esbuild; target Chrome 116).

> **Windows/macOS:** no udev rule is needed — WebHID grants work from the browser's own permission flow.

## 2. Connect the board

Click the toolbar icon → **Connect**. The extension opens a real browser tab for the chooser, because Chromium cancels a device chooser anchored to an action popup. Click **Connect** there, pick the **fapico2** entry, confirm. One thing the connect page says that is worth repeating: the board's *security-key* interfaces are hidden by the browser's chooser — the **fapico2** entry (the vendor interface) is the right one.

![The connect tab: chooser guidance and the no-board state](../img/nostr-connect-tab.png)

- **First run, no keys yet:** the page stays open and says *connected — open the fapico2 toolbar icon to create your first key*.
- **Returning user:** the page closes itself after a moment and the popup shows the Keys screen.

The popup's home state mirrors the board honestly: **fapico2 board connected**, **no fapico2 board granted — connect it**, **device error — try again** (with a Try-again button), or **busy — retrying in a second**. Until a board is granted, the home screen is the *Your first key* ritual — *Plug in your fapico2, click Connect, and it asks for a touch whenever something needs signing* — and key operations stay out of reach; the extension never fakes readiness.

![The extension popup on first run, before any board is connected](../img/nostr-popup-first-run.png)

## 3. Create your first key — the choice that matters

There are two paths, and the README states the trade plainly. Read this before clicking either:

- **Recommended — generate in software, write the nsec down, then Import.** The paper copy exists *before* the board is involved, so a lost, bricked or wiped board does not cost the identity. Generate an `nsec1…` with any offline Nostr tool, then use **Import**.
- **Generate on the device** is for a user who has decided the board is the only copy. **Export** exists as the escape hatch — it is touch-gated and hands the nsec to the browser, which downgrades the threat model to include the machine the board is plugged into. Take it only if you accept that trade: a key nobody can back up is not a security property, it is a single point of failure.

### Generate (on the board)

Keys screen → **Generate** → pick one of the **8 slots** → **Generate &amp; touch** → touch the board's BOOTSEL button when the amber bar says *touch your device*. The popup confirms `key generated in slot N`. If no active key is set yet it adds: *no active key is set yet; pick it on the Keys screen to sign with it*.

### Import (from software)

Keys screen → **Import** → paste an `nsec1…` bech32 key or a 64-hex scalar into the password field → **Check secret** (validated locally — the paste is scrubbed from the page the moment it is checked) → the confirm step shows *This imports the key that publishes as npub1…* and the slot picker → **Import &amp; touch** → touch the board.

The board derives and echoes the public key (npub) before it accepts the write; an invalid scalar is refused without a touch.

## 4. The Keys screen

Every identity is listed as its label (or *slot N*) with a clipped npub. The radio picks the **active key** — the identity `window.nostr` publishes as — instantly and without a touch; the notice reads *active key is now slot N — sites that cached your other npub will need to reconnect*. An occupancy strip (**N/8 slots ■■···**) shows how much of the set is committed.

Per-key actions live on each row: **copy** the npub, **label** it, **export**, **delete**.

### Label

*Set label* accepts up to **32 UTF-8 bytes** with a live byte counter (`N/32 bytes`), gated by **Set label &amp; touch**. Labels are stored on the board and listed touch-free afterwards — which is why a label is part of the public surface: anything listed without a touch is public.

### Delete

*Delete key* names exactly what it destroys — *This destroys **name** — npub1… (slot N). The key is gone from the device.* — and requires the confirmation checkbox *I understand this is permanent — the key is destroyed on the device* before **Delete &amp; touch** lights up. After the touch, the board answers with the destroyed identity's npub and the extension verifies the echo — a mismatch is reported as a store fault, never a green checkmark. If you are deleting the active key, the popup warns *This is your active key — after deleting, the active key resets to slot 0.*

### Export

*Export key* says what it does in the first sentence: *Export shows the secret scalar once, in this window only.* Checkbox (*I understand this reveals the secret.*) → **Reveal &amp; touch** → the scalar is shown as bech32 `nsec1…` with a **Copy** button, and dropped when the popup closes. One press buys one reveal; the board holds no "exported" state afterwards.

## 5. Sign from a web page (NIP-07)

Any page can ask the standard API:

```js
const pubkey   = await window.nostr.getPublicKey();
const signed   = await window.nostr.signEvent(event);   // NIP-01 event object
const ciphertext = await window.nostr.nip44.encrypt(peerNpub, plaintext);
const plaintext  = await window.nostr.nip44.decrypt(senderNpub, payload);
const keys     = await window.nostr.listKeys();
```

The extension deliberately implements **no `nip04` and no `getRelays`** — it delivers a signer, not a Nostr client. There is no relay pool to configure; publish the signed event with any client or relay library you already use.

**What a signature request looks like.** The first time a site calls a method, the extension opens a small approval window: the site's host, a chip naming the action (*signs events*, *encrypts for a peer*…), a preview of the payload, the identity line (*with npub1… (slot N)*), the hint *Nothing is signed, encrypted or decrypted until you approve*, **Deny** / **Approve** buttons, and a *Remember this choice* checkbox. After you approve, the window flips to the amber state — *touch your fapico2 board* — and **the physical press is the final consent**. The footnote says it outright: the window approves the request; the touch signs it.

Three properties worth knowing:

- **The event is hashed in the browser; only the 32-byte sighash reaches the board.** The device returns the 64-byte BIP-340 signature and the npub that produced it — the extension verifies the npub echo, so a board signed with the wrong identity cannot paper over as success.
- **The nonce for NIP-44 encryption is generated on the device**, never supplied by the host, so no browser bug can reuse one.
- **Grants are per site and per action.** *Remember* on "signs events" for `example.com` says nothing about `other.net`, or about "encrypts for a peer" on the same site. Session grants die with the browser session. Manage them on the popup's **Sites** screen, which lists each host's remembered actions (*reads your public key, signs events — 2026-10-13*) with per-host revoke and a two-step **Revoke all** (**Confirm revoke all** holds for five seconds before it acts).

## 6. The touch, timeouts, and what the errors mean

The board asks for the BOOTSEL press on every command that uses or changes the private key set — sign, encrypt, decrypt, generate, import, label, delete, export. The three reads (public key, list, ping) are touch-free. There is **no config bit** that turns the touch off.

The amber touch bar appears the moment the board asks; keepalives keep it live while the board waits. If no press comes, the device refuses with its touch status word and the extension reports it in plain words:

| The popup says | What actually happened | What to do |
|---|---|---|
| *touch timed out — the device asked for a touch and none came* | the board's touch window expired (`6985`) | try again; press when the amber bar pulses |
| *that slot is occupied — delete it first* | generate/import onto a live slot (`6A84`) | pick another slot, or delete the occupant |
| *that identity is not on the device* | the slot is empty or tombstoned (`6A82`) | check the Keys screen |
| *the device refused the data — it could not read the request* | malformed payload (`6A80`) | check what you pasted / the request shape |
| *the device refused the command length* | the counterparty's key is not a valid curve point (`6A87` on the device — the extension's map words it as a length refusal) | check the counterparty's npub |
| *the device could not complete the operation — its store faulted* | the store refused (`6F00`) — boot degraded or a slot that would not open | reflash/recovery; see [troubleshooting](#9-troubleshooting) |
| *the device does not serve that command* | unknown command (`6D00`) — usually a firmware older than the extension | update the board's firmware |
| *ceremony interrupted — the worker restarted mid-operation; try again* | the extension's background worker restarted | retry once |
| *no Fapico board connected — connect it and try again* | no granted device at all | Connect first |

There is **no silent retry loop** for the touch: a refused request stays refused, and a second request waits its turn in a queue instead of stampeding the board.

## 7. Retiring a compromised key — the order is load-bearing

If an `nsec` leaks:

1. **Publish the NIP-09 (or kind-0) retirement event signed by the old key first.** It may be the last thing that key ever signs.
2. **`EXPORT_KEY`** — only if you still need something from the key, and only while it is still on the board.
3. **`DELETE_KEY`** on the Keys screen, touch-gated.

Delete first and the retirement event can never be signed by anyone — the identity is stranded, not revoked. The board has no networking stack and cannot do this for you (NIP-46 remote signing is rejected by design).

## 8. What management RESET does

The management applet's **RESET destroys all eight Nostr identities along with FIDO, OATH and OpenPGP** — "reset" means empty, and the host is obligated to enumerate (LIST_KEYS) and show what will be destroyed before you acknowledge. The scoped CTAP2 `authenticatorReset` (the one a browser or `ykman fido reset` triggers) wipes **only FIDO's range** and leaves Nostr records sealed and intact — the device-bound key derivation depends on nothing the FIDO reset destroys.

## 9. Troubleshooting

**The board does not appear in Chrome's chooser.** Linux: the udev rule from step 0 is missing (or not reloaded). Check `lsusb` shows `fa20:` and re-run the `udevadm` lines.

**The chooser shows the board but Connect fails.** Another app may hold the interface; close Yubico Authenticator/`ykman` for the moment. Then **Try again** on the popup's device card.

**Every touch-gated command answers the touch-timeout sentence.** The press went to the wrong interface or nothing was listening — confirm the amber bar was actually pulsing when you pressed. On boards flashed before the presence fixes, the CCID prompt can sit dark while the window is open; re-flash the current image.

**Sites cached an old npub after I switched the active key.** Expected — the notice said so at switch time. Reconnect the site (re-grant it) and it picks up the new active identity.

**"device error — try again" right after unplugging.** The next request reopens the transport; one Try-again is usually enough.

**The board answers but the extension cannot find it after a reflash.** If you changed the board's VID/PID, only the PID is allowed to differ from the rule's expectations — the udev rule keys on the vendor ID alone, so a custom **VID** is the one change that strands the chooser. Restore `fa20` with `scripts/fix_usb_identity.py`.
