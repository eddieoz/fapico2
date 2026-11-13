# passport-nostr-signer vs fapico2 — security comparison

**Scope.** A systematic security analysis of
[`BitcoinQnA/passport-nostr-signer`](https://github.com/BitcoinQnA/passport-nostr-signer) —
the Foundation Devices Passport Prime (KeyOS) Nostr signer — against the fapico2
Nostr applet and its browser extension. Companion to
`docs/nostr-signing-device-comparison.md` (the LNBits SNSD, an ESP32 Arduino
sketch); that comparison was about a hostile implementation. This one is about a
competent one, which changes what the argument is: the Passport signer's crypto
is clean and its policy model is genuinely thoughtful. The differences that
matter are **architectural** — what the trust boundary is, what can speak to the
device, and what happens when the power is cut.

**Method.** Every claim below is read out of source at pinned commits:

| tree | commit | read |
|---|---|---|
| `passport-nostr-signer` | `238e265bc1019f8d2dacb7b7243f5c2a736d51` (HEAD, 2026-11-12) | directly, all security-relevant files |
| `fapico2` | `9788b70` (alpha-v0.6.0 worktree) | via a citation sweep over applet, wire, platform |
| `fapico2-nostr-extension` | v0.5.0 | per `docs/nostr-signing-device-comparison.md` |

Citations are `file:line` in the respective tree. Where a finding is a
concession to the Passport signer rather than a gap, it says so.

---

## 1. The two devices at a glance

| | **Passport Prime / passport-nostr-signer** | **fapico2 (RP2350)** |
|---|---|---|
| What it is | A Foundation SDK app (Rust + Slint) running on Passport Prime under KeyOS, plus a Chromium NIP-07 extension | One firmware on a $4 RP2350 board; the Nostr applet is the seventh CCID applet and the third HID interface |
| Status | **Proof-of-concept.** Browser signing works only against the hosted simulator; on real hardware the host link is offline | Ships today: vendor WebHID (interface 3) + CCID, NIP-07 via the extension |
| Identities | Unbounded list (JSON `Vec`), generate (NIP-06 from app seed) or import by QR | 8 device-sealed identities (`NOSTR_CAPACITY`, `platform/src/keyregion/mod.rs:202`), generate or import raw scalar |
| Transport | WebSocket `ws://127.0.0.1:9876` (simulator); WebUSB retained as design history, **not compiled into the SDK app** | CTAPHID-framed vendor interface on usage page `0xFF00` (`platform/src/nostr_hid.rs:52-73`), CBOR `[idx, arg]` wire, plus CCID APDUs |
| Approval | On-device screen: origin, kind, content preview (140 chars), tag count, key label; 5-minute timeout | Physical button press + LED prompt; **blind** — the device never sees the event, only a 32-byte sighash (`firmware/src/nostr_wire.rs:7-8`) |
| At rest | JSON keystore, per-record AES-256-GCM keyed by HKDF from the KeyOS app seed (`logic/keystore/src/lib.rs:186-198`) | Keyregion AES-256-GCM records, AAD binds magic‖domain‖slot‖generation, root = `otp_key_1 ‖ chipid` (`platform/src/keyregion/crypto.rs:89-98, 501-507`) |
| Key custody | nsec revealable by design (`src/engine.rs:123-127`) | Import-only; EXPORT retired, `6D00` in band on every transport (`apps/nostr/src/lib.rs:130-136`) |
| No-swipe signing | Persistent per-origin/per-kind rules with expiry, hourly cap, audit log (`src/autosign.rs`) | PIN-session-scoped touch bypass; RAM-only, dies on lock, failed verify, or power cycle (`apps/nostr/src/lib.rs:1749-1813`) |
| DM crypto | NIP-44 v2 **and** NIP-04 (legacy AES-256-CBC) | NIP-44 v2 only; NIP-04 deliberately absent |

The honest headline is in the second row: **the Passport signer cannot reach a
browser from real hardware**. Its own README concedes it ("Hardware browser
signing is pending a public KeyOS host transport", `README.md:29-30`), and
`docs/HARDWARE.md:8-16` explains why: Foundation SDK 1.4 exposes no raw USB and
no QuantumLink app API to third-party apps, so the app requests neither
`os/usbdev` nor a transport and its on-device status banner reports the host
link as offline. The extension's WebUSB client (`extension/webusb-transport.js`)
is prototype material retained "for a future public KeyOS host transport"
(`docs/HARDWARE.md:15-16`). Everything else in this document is secondary to
that: fapico2's vendor HID works in a browser today; the Passport signer's
NIP-07 surface works only against `ws://127.0.0.1:9876` on a laptop.

---

## 2. The communication channel

### 2.1 What each side actually speaks

**Passport.** The wire is JSON over WebSocket (`src/transport/websocket.rs`), one
text frame per message, `ws://127.0.0.1:9876` by default (`docs/PROTOCOL.md:29-33`).
The historical WebUSB framing (newline-delimited JSON across 64-byte interrupt
transfers, 16 KiB line cap, `docs/PROTOCOL.md:35-52`) exists as a spec but has
no device-side implementation. The protocol surface mirrors NIP-46 vocabulary
(`docs/PROTOCOL.md:128-130`): `ping`, `list_keys`, `select_key`,
`get_public_key`, `sign_event`, `nip04_encrypt/decrypt`, `nip44_encrypt/decrypt`.

**fapico2.** The vendor interface is routed **by USB interface**, and the
contract is asserted in code: `assert_eq!((hid_itf, otp_itf, nostr_itf), (1, 2,
3), …)` (`platform/src/usb.rs:570-592`). A frame that arrived on the Nostr
interface never reaches the FIDO dispatch and vice versa — pinned by
`us1660_a_nostr_command_is_refused_loudly_and_never_reaches_fido`
(`firmware/src/hid_serve.rs:4031`). Request caps are decode-time and
chunk-rounded against the NIP-44 padding curve (`MAX_PLAINTEXT = 1792` chosen
because padding jumps 1792 → 2048, `apps/nostr/src/lib.rs:293-325`), so no
request can produce a response the device would itself drop. Errors are typed
status words answered **in band**, on the method's own channel
(`firmware/src/nostr_wire.rs:21-24`).

### 2.2 Who can speak? The pairing question

This is where the two designs part ways, and it is subtler than the SNSD
comparison's "no pairing at all" finding, because the Passport signer *claims*
a permission model — it just puts the parts of it in the wrong places.

**The extension-side gate is real but browser-local.**
`ensureOriginAuthorized` (`extension/background.js:54-77`) normalizes the
origin, checks `chrome.storage.local.originPermissions`, and blocks calls from
sites the user has not allowed. That is a proper NIP-07 gate — against the
*browser*. It guards nothing about who reaches the device.

**The device-side gate is an unauthenticated TCP listener.** The simulator
transport accepts any connection and spawns a per-client handler with no token,
no origin check, no pairing (`src/transport/websocket.rs:32-41`). Any process on
the laptop that can open a TCP socket to `127.0.0.1:9876` can call every method:
`list_keys` returns uuid, label and pubkey of every identity with no prompt
(`docs/PROTOCOL.md:138-139`; `src/engine.rs:295-309`), and `select_key` switches
the active identity with no user prompt either (`docs/PROTOCOL.md:154-160`). The
device cannot distinguish the extension from any other JSON-speaking process —
and, critically, it has no independent evidence of the requesting origin.

**The consequence lands on auto-sign.** The auto-sign rule matches on the
`origin` field of the `sign_event` request — which is **client-asserted**.
`docs/PROTOCOL.md:179` says it plainly: `"origin": "https://nostrudel.ninja",
// optional, surfaced in prompt`. The engine matches policy on exactly that
string (`src/engine.rs:349-358`, `reserve_auto_sign` →
`store.reserve_match(key_uuid, origin, kind)` at `src/autosign.rs:243-268`). So
a malicious local process that knows a rule exists — and the rules' origins are
readable from the audit-adjacent UI state and, on the simulator, from the
plaintext JSON at `.passport-nostr-signer-keyos/autosign.json`
(`docs/AUTO-SIGN.md:35-36`) — can sign arbitrary events of the permitted kind
under the permitted origin with **no user interaction**, up to the rule's
hourly cap. The doc's security claim ("the browser extension cannot create or
edit them", `docs/AUTO-SIGN.md:5-7`) is true and does not close this: the
extension cannot create rules, but any WebSocket client can *wear* one. The
extension-side allowlist never enters the device's decision.

fapico2's equivalent surface is harder, not because of cryptography but because
of shape. The vendor HID channel requires the browser's per-device permission
grant (WebHID's own model) and a CTAPHID CID allocation; there is no
always-listening TCP port on the host side, and the CCID path is bound to
pcscd's reader discipline. And the identity of "what is being authorized" never
comes from the host: the device signs a bare 32-byte sighash and the *only*
consent artifact is the physical press (`apps/nostr/src/lib.rs:1108-1110`),
whose tag is device-generated (`0x4000_0000 ‖ idx` over CCID, `0x6000_0000 ‖
CID` over HID — `apps/nostr/src/lib.rs:2393-2430`), domain-checked exactly
(`tag & 0xE000_0000 == 0x6000_0000`), and consumed by its request — CANCEL and
expiry drop it (`docs/nostr-presence-audit.md` F-A1's fix). There is no
origin string anywhere on that wire to impersonate.

### 2.3 The trust boundary, stated by each project

Both projects draw the boundary at the cable and neither encrypts the wire.
The Passport signer's own `docs/PROTOCOL.md:235-238`: *"The USB cable is the
trust boundary. The transport layer has no encryption; an attacker with
physical access to both the device and a malicious host can observe
signing-request contents (though not the nsec)."* fapico2 agrees — the WebHID
channel is plaintext too, and `AGENTS.md` §8 names the extension as the
dialect's definer, not the spec. This is a point of **agreement**, recorded so
it is not mistaken for a differentiator: on both devices, the host sees what is
being signed. The difference is what happens after the host is hostile — which
is the next section.

---

## 3. Key material at rest

### 3.1 Passport: a good keystore, escrowed one level up

`logic/keystore/src/lib.rs` is competent code: per-identity AES-256-GCM keys
derived by HKDF-Expand from the 32-byte app seed with per-record random nonces
(`keystore/src/lib.rs:183-198`), the derivation key zeroized after use
(`keystore/src/lib.rs:205-209`), atomic write via temp file + rename
(`keystore/src/lib.rs:333-342`), a version field that refuses unknown formats
(`keystore/src/lib.rs:132-134`), and the scalar zeroized on drop
(`nostr-core/src/keys.rs:12-13`). The auto-sign policy store is separately
HMAC-authenticated with a key derived from the app seed and a domain-separated
MAC (`src/autosign.rs:24, 353-361`), tamper-refusing at load
(`src/autosign.rs:126-130`).

The security of all of it rests on one primitive: `security.app_seed()` —
KeyOS's per-app 32-byte key, "only accessible when the user is logged in with
PIN" (`logic/keystore/src/lib.rs:10-12`). The app wisely never asks for the
device master seed (`docs/HARDWARE.md:10-11`). Two observations, neither a
flaw in their code:

1. **The custody story is the OS's, not the applet's.** Whether the app seed is
   hardware-rooted, how it responds to a bootloader-level attack, and whether
   it can be extracted by a compromised KeyOS are properties of a platform
   whose source is not public. fapico2's root is the RP2350 OTP page
   (`derive_payload_key(otp_key_1, chipid, …)`,
   `platform/src/keyregion/crypto.rs:501-507`), and the *entire* chain below it
   — record format, AAD, occupancy guard, custody ceremony — is in this
   repository, auditable line by line (`platform/src/keyregion/record.rs:6-42`,
   `crypto.rs:89-98`). One design trusts an opaque OS service; the other owns
   the whole stack and can prove what it does.

2. **The simulator leaks a deterministic seed by design.** In hosted mode,
   "the security server returns a deterministic seed derived from the app id
   even when not logged in (with a warning)" (`src/master_key.rs:7-10`). A
   simulator keystore is dev-only state, and the file-backed
   `InMemoryMasterKey`/`FileMasterKey` paths are labelled dev-only
   (`keystore/src/lib.rs:281-291, 300-319`). Still: identities created in the
   simulator — the only mode in which browser signing works — live under a
   seed anyone can re-derive from the app id `0x1f8f092a…` (`AGENTS.md:24`
   of that repo: "stable and seed-deriving"). Identities generated in the
   simulator are not meaningfully secret. fapico2's emulator has no Nostr HID
   interface at all (`firmware/src/emul_main.rs:37, 895` — CCID only), so the
   browser never reaches emulator-held keys, and hardware keys are sealed under
   silicon fuses the emulator does not possess.

### 3.2 fapico2: the keyregion and the custody ceremony

The fapico2 Nostr store is one AEAD record per identity with an AAD that binds
magic, domain, slot and generation (`platform/src/keyregion/crypto.rs:89-98,
210-211`); the domain tag `KeyDomain::Nostr = 3` means a Nostr record
"physically cannot open as a FIDO or OATH record"
(`docs/adr/0005-nostr-key-storage.md:19-22`). The store's admission runs an
occupancy guard: a non-virgin slot that opens as something else is refused
(`6A84`) rather than overwritten (`platform/src/keyregion/nostr_store.rs:33-48,
598-626`; `apps/nostr/src/lib.rs:2471-2477`) — the stale-passkey case is named
in code at `nostr_store.rs:405-408`. Capacity is 8 identities carved from the
top of FIDO's range so existing passkeys keep their addresses
(`platform/tests/key_region_capacity.rs:95`).

Two fapico2-specific mechanisms have no Passport counterpart:

- **The custody ceremony** (`apps/nostr/src/lib.rs:1834-1985`,
  `platform/src/custody.rs`): the one command that burns OTP — the 16-byte
  custody secret into RP2350 OTP page 59, page-locked via LOCK1 row `0xFF7`
  (`custody.rs:36-58`) — after which every record is reseated off the legacy
  constant-KDF onto a key derived from **what the burned page reads back**
  (`crypto.rs:666-700`, contents-authoritative). A faulted custody-page read
  refuses every command with `6F01` — the store "cannot guess at a key, so it
  refuses" (`apps/nostr/src/lib.rs:265-273, 2095-2097`). This is the
  downgrade-is-destruction property: there is no window in which the records
  are readable under an old key once the marker stands.
- **Import-only custody** (`AGENTS.md` §8, US-1689..1706): the applet imports
  scalars (`INS_IMPORT_KEY = 0x14`, `lib.rs:116-117`) and never returns one.
  EXPORT is retired — no dispatcher arm exists, `0x1A` answers `6D00` on every
  transport (`apps/nostr/src/lib.rs:130-136`, `firmware/src/nostr_wire.rs:57-63,
  155`). The Passport signer has `reveal_nsec` in its engine
  (`src/engine.rs:121-127`) and an `on_reveal_nsec` UI callback
  (`src/main.rs:341-348`) — "Callers are responsible for gating this behind a
  user confirmation." The gate is their own UI; the capability is in the API.
  That is a defensible product choice (their README: "for transferring the
  identity to another signer", `README.md:122-124`) — but it is a choice
  fapico2 has made the opposite way, on the ground that a key-exfiltration verb
  converts every future UI bug into a key-theft bug. It is also the honest
  trade-off to record against our own ledger: a dead fapico2 board takes
  imported identities with it, where a Passport Prime restores them from the
  device backup (see §6).

Worth stating plainly: **both projects store the scalar, not a derivation**.
Passport's records hold the nsec ciphertext; fapico2's records hold the raw
scalar (`nostr_store.rs:80-90`, per ADR 0005) — fapico2's *FIDO* applet derives
residents from `froot` and never trusts stored keys, but the Nostr applet's
records are sealed scalars. The asymmetry with the FIDO side is deliberate
(device-bound sealing vs seed-restorable derivation), and the Passport signer's
NIP-06 derivation (`nostr-core/src/nip06.rs:27-46`) is the property fapico2
gave up — see the honest ledger.

---

## 4. The approval gate — where the Passport signer wins

Credit where it is due, ungrudgingly: **the Passport signer's approval screen
is strictly better than fapico2's blind touch, and this is the one security
axis where their design beats ours.** Every sign/encrypt/decrypt request
carries origin, key label, peer pubkey and a content preview
(`src/approval.rs:14-47`); the engine truncates content to 140 characters
(`src/engine.rs:32-37, 590-598`); the Slint approver drives a real on-device
approve/reject page and resolves on the physical tap (`src/main.rs:95-113,
578-620`); unanswered requests time out after five minutes (`src/main.rs:37`).
The user reads *what they are signing* before consenting.

fapico2's device has no screen (`apps/nostr/src/lib.rs:226-228`): every
refusal is a status word the host must render, the touch prompt is an LED
(`firmware/src/button.rs:134-141`), and signing is blind by construction —
SIGN takes a 32-byte sighash and the applet never parses JSON
(`firmware/src/nostr_wire.rs:7-8`). The press consents to *an identity*, not
to content. Our prior presence audit named the cost of this directly: the
per-message press rhythm "trains touch-without-reading"
(`docs/nostr-presence-audit.md` F-A12). A hostile host that controls the
display of what was signed can show the user one message and deliver another
sighash; nothing on the device can contradict it. The Passport signer closes
exactly that hole for event content (the preview is rendered by the device,
from the payload, after the transport). We cannot match this on hardware that
has no display, and it is the single strongest argument for the Passport Prime
as a signing device — when the transport works, which today it does not
(§1).

The one qualification: the preview is a *preview*. 140 characters of content
plus a tag count is not the signed payload; the sighash covers tags the user
never saw. It narrows the blind-signing gap enormously and does not close it —
the fully honest framing, which their own approval page cannot claim either
without rendering the event id itself.

---

## 5. The no-swipe path: two bypasses, opposite lifetimes

Both projects eventually had to answer the same UX question — a hardware
key press per NIP-42 auth event makes the app feel broken — and answered it
with mechanisms whose threat properties are nearly inverted.

| | **Passport auto-sign** | **fapico2 touch bypass** |
|---|---|---|
| Scope | Exact key UUID + exact normalized HTTP(S) origin + exact event kind (`src/autosign.rs:324-351`) | Exactly SIGN, NIP-44 ENC, NIP-44 DEC (`apps/nostr/src/lib.rs:1108, 1179, 1286`) |
| Arming | On-device UI only; the wire cannot create rules (`docs/PROTOCOL.md:195-197`) | Open PIN session + physical press (`lib.rs:1780-1790`) |
| Limits | Per-rule expiry (`0` = never expires) + hourly cap ≤ 1000 + 24 rules/key (`src/autosign.rs:20, 187-192`) | **255 exempt operations or 10 minutes per session** (US-1848/1855: sized from the measured ~8 exempt ops per user-visible action) |
| Persistence | **Persistent file**, HMAC-authenticated (`src/autosign.rs:363-379`) | **RAM-only**: cleared by power cycle, LOCK, failed verify, factory wipe (`lib.rs:1698-1702, 1734-1736, 2078`) |
| Accounting | Audit log: last 100 signed event ids with origin/kind/timestamp (`src/autosign.rs:270-292`) | A 16-deep RAM audit ring — one 22-byte record per exempt op, `GET_AUDIT` (INS `0x20`) inside the open session (US-1841/1842) |
| Origin evidence | Client-asserted `origin` field (§2.2) | No origin concept at all |
| Affects decrypt | Never — decrypt always requires approval (`docs/AUTO-SIGN.md:21-22`) | Yes — NIP-44 ENC/DEC are in scope |
| Re-enable | Toggle in UI | Friction-free `P1=0x00` (`lib.rs:1774-1778`) |

Neither mechanism crosses its own trust boundary in the SNSD sense — both
require device-local consent to arm, and the Passport signer's rule store
cannot be rewritten by the browser (the MAC would fail, `src/autosign.rs:126-130`).
The trade is about *lifetime and evidence*: fapico2's bypass cannot survive an
unplug, which makes it impossible to forget you own it — the same principle the
custody rows and the PIN session (`pin_unlocked` is a RAM cache, deselect is a
no-op, `lib.rs:511-516, 2016`) express everywhere else. The Passport signer's
rules are durable, auditable, bounded per hour, and keyed to a
(per-origin/kind) *policy* rather than a session — a genuinely better model for
the threat "a user armed a bypass and forgot", which was fapico2's residual —
now answered outright by the accounting (US-1837..1856): the budget, the
deadline, the ring and the sampled-age countdown bound what an armed-and-
forgotten session costs.
But their model inherits the §2.2 hole: the durable grant is matched against a
string the transport client supplies, and its expiry can be "never."
On the simulator transport — the only transport there is — that combination is
the highest-value target in the design.

---

## 6. The honest ledger

Per this repository's convention, the advantages that are real.

**Where the Passport signer is genuinely ahead:**

1. **The approval screen** (§4). Content-aware consent beats blind touch. Full
   stop. If fapico2 ever ships a display variant, this is the model.
2. **The auto-sign policy model's shape** (§5): exact matching, rate limiting,
   expiry, audit trail, MAC-authenticated storage, and a hard rule that decrypt
   is never auto-covered. fapico2's bypass shipped unaccounted — closed by
   this branch (cap 255, 10-minute deadline, ring, `GET_AUDIT`). Passport
   still accounts per *rule* where fapico2 accounts per *session*; the model
   is richer, and the honest gap is narrower than it was.
3. **NIP-04 support** (`nostr-core/src/nip04.rs`): legacy DM interop fapico2
   deliberately lacks. Clients that still speak NIP-04 work with them and not
   with us.
4. **NIP-06 recoverability** (`nostr-core/src/nip06.rs`): identities derive
   deterministically from the app seed, so a restored device backup reinstates
   the same Nostr identity set (`README.md:128-131`). fapico2's device-bound
   sealing means a dead board takes imported identities with it — the trade
   recorded in ADR 0006, real and acknowledged.
5. **Identity management depth**: label, colour, archive/restore, delete, QR
   import (`src/main.rs:194-260`) — on-device, versus fapico2's label-and-colour
   over a status-word-only channel.
6. **Engineering quality.** The `logic/` workspace is KeyOS-free and
   host-testable (55 tests, `README.md:44-49`); NIP-44 is spec-correct with
   proper padding validation and constant-time compares
   (`nostr-core/src/nip44.rs:99-174`); zeroization is systematic. Nothing in
   their crypto tree embarrasses them. That is not true of the SNSD, and it is
   why this document argues architecture rather than implementation.

**Where fapico2 is ahead, and the Passport signer cannot close it without
Foundation's platform moving:**

1. **A working host transport** (§1). Their browser story ends at the
   simulator; ours ships.
2. **A device the browser cannot impersonate the origin for** (§2.2). Their
   policy matching consumes a client-asserted string; our consent artifact is
   device-generated, domain-checked, and dies with its request.
3. **Auditable custody end-to-end** (§3.1): the OTP root, record format, AEAD,
   occupancy guard and ceremony are all in-tree and testable; their root is an
   opaque OS service from a non-public platform.
4. **No key-exfiltration verb** (§3.2): import-only vs `reveal_nsec`.
5. **Bypasses that die with the power** (§5): RAM-only session and bypass
   versus persistent rules with `expires_at = 0`.
6. **Capacity honesty**: 8 identities is a deliberate floor
   (`keyregion/mod.rs:202`), stated and test-pinned
   (`key_region_capacity.rs:95`); their store is unbounded, which is a
   capability we deliberately traded for a single-record guarantee — recorded,
   not hidden.

**fapico2 residuals this comparison re-confirms** (all tracked, none new):
blind signing as a structural limit (F-A12's touch-rhythm concern); the
CCID-arm prompt visibility gap (F-A16, recorded); 8-identity capacity; no
NIP-04/NIP-06; and the extension's own known gaps, carried over from
`docs/nostr-signing-device-comparison.md` §7.

---

## 7. Closing

The LNBits SNSD comparison ended with a one-line thesis: they move the key onto
a device the computer fully commands; fapico2 moves the computer's authority
onto the device, then locks it. The Passport signer complicates the dichotomy
in the most interesting way: **it locks the device beautifully and then leaves
the door's address plate where anyone on the host can read it.** The approval
screen, the MAC'd policy store, the audited rule engine — all of it sits behind
a transport whose only implementation trusts a client-asserted origin over an
unauthenticated local socket, on a platform that today exposes no hardware
transport at all.

fapico2's argument against the Passport signer is therefore not "our crypto is
better" — it demonstrably is not; their nostr-core is clean. The argument is:
consent is only as strong as the evidence it is granted on. Their evidence is a
string from the host and a screen the host's payload populates, delivered over
a channel that works only in simulation. Ours is a physical press on a
device-generated tag, a PIN session that dies with the power, and a custody
root burned into silicon the host never sees. Where the Passport signer is
ahead — the screen, the policy accounting, the recoverability — the gaps are
product decisions fapico2 can revisit (a display variant, an audit ring, a
seed-derived identity mode) without touching the trust architecture. Where
fapico2 is ahead, closing the gap requires Foundation to ship a platform
capability they have explicitly not shipped, or a redesign of the policy
matcher around something other than client-asserted origins.
