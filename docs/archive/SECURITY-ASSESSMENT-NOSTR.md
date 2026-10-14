# fapico2 Security Assessment — Nostr Applet Red Team Report (final)

**Date:** 2026-10-10
**Targets:**
- firmware: `fapico-nostr` worktree, branch `feat/nostr` @ `9dc3a1f` (the post-US-1687 tip; the reviewed tip `c0fffec` plus US-1678…US-1688)
- extension: `openxrypt`, branch `fix/review` @ `d431b00`

**Scope:** the two Nostr EPICs — `docs/tasks/EPIC-nostr-applet.md` and
`docs/tasks/EPIC-nostr-review-fixes.md` — as a combined implementation.
Attack surface measured at 3,212 lines of Rust (`apps/nostr/src/lib.rs` 1419,
`nip44.rs` 290, `crypto.rs` 98, `firmware/src/nostr_wire.rs` 588,
`nostr_shared.rs` 289, `platform/src/keyregion/nostr_store.rs` 528) plus the
HID arms in `firmware/src/hid_serve.rs` and 1,228 lines of extension
JavaScript (`src/nostr/{ctaphid,seams,window_nostr,batch,content_entry,loudness}.js`).

**Attacker model:** USB access (physical or compromised host), **no PIN / no
touch / no lab equipment** — the ROUND3 model — extended where the touch
exists: the device has **no screen**, so a press is consent the user cannot
inspect (D13). For the extension: a malicious website is the attacker.

**Method:** one reviewer, five domains (wire/transport, crypto, storage,
extension, review-fix verification), each read line-by-line against the
design doc (`docs/tasks/nostr-applet-design.md`), followed by an
adversarial pass over every finding. A multi-agent wave was planned; the
provider rate-limited every launch, so all five domains were executed inline
sequentially instead — same prompts, one at a time.

---

## Executive summary

**The Nostr arc is clean.** Across the whole surface I could not panic the
device from a USB frame, forge a signature, bypass a touch, build a decrypt
oracle, or write a slot that is not ours. The US-1678 P0 (an oversized vendor
argument overflowing the APDU scratch through a `build_apdu` `unwrap`, USB-
reachable, `panic = "abort"` ⇒ reboot) is fixed at three independent layers
and pinned by a red test that drives all 64 vendor commands with a 3,000-byte
argument. Every other finding is a design-level residual, not a code defect.

| # | Severity | Finding |
|---|---|---|
| F1 | P2 (accepted, documented) | A touch is not operation-specific — local malware can turn a "sign" touch into an `EXPORT_KEY` |
| F2 | P3 | `LIST_KEYS`/`GET_PUBKEY` leak owner-authored labels with no touch |
| F3 | info (accepted) | `window.nostr` installs on every page (`<all_urls>`) |
| F4 | info | One report pump per device — a second ceremony starves the first |
| F5 | info | `parse_data`'s extended-Lc form can misread trailing bytes — refused honestly, no unsafety |
| F6 | info (documented) | Touch-free commands are refused `6985` while any window is parked |

**Verification evidence (all green, this tip):**
- `cargo test -p fapico2-nostr --target x86_64-unknown-linux-gnu` — 56 passed (keymgmt 18, nip44 9, nip44_commands 9, presence 5, wire 14, unit 1).
- `cargo test -p fapico2-firmware --lib --features device,emulation` (nostr filter) — 11 passed, including `an_argument_above_the_wire_cap_is_refused_in_band`, `every_derived_capacity_refuses_above_itself`, `nostr_cid_allocator_is_clamped_and_tags_injective`, `us1660_a_nostr_command_is_refused_loudly_and_never_reaches_fido`, `us1663_nostr_window_open_refuses_a_fido_ceremony`.
- `npm test` (openxrypt) — 78 passed.
- Residual `unwrap`/`expect` scan over every device-compiled path in the
  arc: every hit is either test-only, or mathematically unreachable
  (`d·G ≠ ∞` for a validated scalar; HMAC accepts any key length;
  `payload[1..33]` behind the ≥ 99-byte length gate).

---

## Findings

### F1 — P2 · A touch is not operation-specific: `EXPORT_KEY` is one confused press away from key exfiltration (accepted risk, documented)

**`apps/nostr/src/lib.rs:1040` (`export_key`), `lib.rs:1332` (`presence_tag`).**

The presence tag binds a press to an **identity**, not to an opcode — §2.3.1
requirement 3, deliberately ("the identity is what a press consents to", the
INS is absent from the tag). The device has no screen; the consent surface is
one LED. Any local process with USB access can open the Nostr HID interface
or SELECT the AID over CCID and issue:

```
SELECT AID  F0 00 00 00 02
EXPORT_KEY  00 1A <idx> 00 00        → 6985, touch prompt lights
                                              (user presses, believing
                                               they are signing something)
            → 9000 ‖ scalar(32)      the BIP-340 private key, in the clear
```

The identical press authorizes `SIGN`, `DELETE_KEY` or `EXPORT_KEY` on the
same slot. One signature's worth of consent buys the permanent key.

**Why it stands:** this is D12's documented trade — "a key nobody can back up
is a single point of failure" — named in §2.2.0a as the threat-model
downgrade it is, warned in the README (US-1676), and gated (touch, permanent)
more than the alternative (a key stranded in a dead board). The web path
cannot reach it: the page-visible surface is sign-and-prompt only
(`window_nostr.js:26-30`), the popup exposes no key-management UI, and the
`EXPORT_KEY`/`IMPORT_KEY`/`DELETE_KEY` constants in `ctaphid.js:47-49` have
**no caller** in the extension. The attacker needs local malware, which in
the ROUND3 model already owns the machine.

**What would narrow it:** a press pattern EXPORT requires that SIGN does not
(e.g. a ≥ 3 s hold, or a two-press arm-confirm). §5 asks to name the attack a
mechanism stops before adding it — the attack is named here, but the marginal
benefit over the status quo is small: malware that can phish one touch for
EXPORT can equally phish one touch for a SIGN of attacker-chosen content.
Recorded as accepted; revisit if the no-screen constraint ever lifts.

### F2 — P3 · Owner-authored labels leave the device with no touch

**`apps/nostr/src/lib.rs:504` (`list_keys`), `nostr_store.rs:82`
(`NOSTR_LABEL_MAX`).**

`LIST_KEYS` and `GET_PUBKEY` are touch-free by design — "npubs are public"
(§2.3). But `LIST_KEYS`' per-entry body is `idx ‖ flags ‖ npub(32) ‖
label_len(1) ‖ label`, and the label is **user-written text** (SET_LABEL,
touch-gated to write). An attacker with seconds of unsupervised USB access —
the exact ROUND3 attacker — enumerates every identity *and* its annotations:

```
SELECT AID  F0 00 00 00 02
LIST_KEYS   00 11 00 00 00           → 9000, no touch, no prompt
```

The npubs confirm the device is a Nostr holder; the labels can carry what the
npubs alone cannot (which identity is the "main", which the "burner"). No key
material is at risk; the leak is pseudonym linkage the owner never consented
to. Suggested (not required) remediation: cap or drop the label field in the
touch-free enumeration and serve it behind SET_LABEL's own gate, or state in
the design doc that labels inherit npub's "public" classification.

### F3 — info · `window.nostr` installs on every page (`<all_urls>`, accepted)

**`openxrypt/manifest.json` (two `<all_urls>` content-script entries),
`content_entry.js:73`.**

Every page the user visits gets `window.nostr` at `document_start`. A
malicious page can call `signEvent` and light the touch prompt. This is the
standard NIP-07 model (Alby and every browser signer does the same), the
surface is deliberately narrow — `getPublicKey`/`signEvent`/`listKeys` only,
`nip04` and key management refused by name (`window_nostr.js:26-30`) — and
US-1671's loudness indicator names which signer produced the last signature.
Device-side, each `signEvent` is one touch-gated ceremony; there is no
batching. Accepted.

### F4 — info · One report pump per device: a second ceremony starves the first

**`openxrypt/src/nostr/ctaphid.js:233` (`dev.oninputreport = …`).**

Each `CtapVendorTransport` overwrites `dev.oninputreport` at construction, so
two transports on one `HIDDevice` leave the second's pump owning all frames;
the first's `vendor()` waits out its full timeout and dies with
`CtapError(TIMEOUT)`. Availability only — the device contract is one
transaction per interface (§A.8.3 #9) and the parked-window refusal
(`6985` without running the applet, `hid_serve.rs:1747`) already serializes
ceremonies at the device. Two transports arise only from two tabs each
holding a chooser-granted handle.

### F5 — info · `parse_data`'s extended-Lc form can misread trailing bytes (refused honestly)

**`apps/nostr/src/lib.rs:1161` (`parse_data`).**

A short-form `Lc = 0` frame followed by two trailing bytes (`00 INS P1 00 00
XX YY`) is read as extended form with `Lc = XXYY` — the `apdu[4] == 0x00`
extended-form check runs before any length accounting. Every outcome is a
refusal (`SW_WRONG_LENGTH` if the declared length exceeds the bytes present —
the US-1685 fix; `SW_WRONG_DATA` via `refuse_payload` or the arm's own shape
gate otherwise). No memory unsafety, no oracle: the misparse cannot make a
command *accept* data it should refuse. Pinned by
`tests/wire.rs::a_truncated_extended_lc_form_is_refused`.

### F6 — info · Touch-free commands are refused `6985` while any window is parked (documented)

**`firmware/src/hid_serve.rs:1747` (the slot-occupied guard, inside the
vendor arm).**

While a consent window is parked, **every** vendor command — including the
touch-free `GET_PUBKEY`/`LIST_KEYS` — is refused `6985` without running the
applet. This is US-1510's conservative rule carried to the vendor arm
deliberately ("running it could only produce another touch request, or worse,
let a second command reach for the same button"), bounded by the 15 s window.
Documented trade; noting it so a future "why did my npub read fail" is
answerable.

---

## Verified clean (evidence per claim)

**US-1678 — the P0, verified fixed at three layers.**
`nostr_wire.rs:159` refuses any argument above `NOSTR_REQ_ARG_MAX` (1,891) at
the parse layer, so every arm inherits the cap; `nostr_wire.rs:327` is
`build_apdu`'s explicit overflow arm (`None`, never a panic); the refusal is
`SW_WRONG_DATA` **in band** on the method's own channel
(`process_vendor_through`, `nostr_wire.rs:363-377`). The red test
`an_argument_above_the_wire_cap_is_refused_in_band` drives all 64 vendor
commands with a hand-built 3,000-byte argument and asserts the refusal — and
panics the suite if an over-cap argument ever reaches the applet. Direct
callers bypassing the parser still get `None`
(`every_derived_capacity_refuses_above_itself`).

**The wire cap is derived from chunk-rounded padding, not naive arithmetic.**
`MAX_PLAINTEXT = 1792` because `calc_padded_len` jumps 1792 → 2048 at n = 1793
— a naive cap would answer an ENCRYPT with a 2,115-byte frame the transport
drops *silently* while GET_INFO still advertises the larger value
(`lib.rs:205-221`; `tests/wire.rs::wire_fits_max_wire` asserts the arithmetic
against the device's `MAX_WIRE`). This is the AGENTS §4 failure mode
pre-empted, and it is the reason the original 1900 was wrong.

**NIP-44 v2 has no oracle and no padding panic.**
`nip44.rs:240-244`: MAC verified **constant-time** (`verify_slice`) before
any length/padding parsing; every malformed payload is one word (`6A80`,
`lib.rs:929-931`) — no distinguishable failure classes. `calc_padded_len`
returns `None` at `len == 0` (US-1653 — the `log2(0)` transcription would
have rebooted the device on a one-byte plaintext under `panic = "abort"`),
and the const/runtime forms are pinned in lockstep. The version byte is
refused explicitly for every non-2 value; the v1 ECC form (`f9308a…`) gets
its own user-actionable word (`6B00`).

**BIP-340 follows the spec's two transcription traps.** The aux is
tag-hashed **before** the XOR with the parity-fixed scalar, and `d` is
negated to even-y **before** nonce derivation (`crypto.rs:66-88`); the
reference vectors run through the APDU path (`tests/keymgmt.rs`, 18 green).

**Peer keys are validated before any scalar multiplication** (US-1656):
`validate_peer_key` lifts the x-only key (zero and off-curve → `6A87`) and
refuses the ECC form (`6B00`) before the state and the touch — a corrupted
counterparty key costs no press (`lib.rs:893-895`, `:1201-1209`).

**The device generates every nonce and aux.** `NIP44_ENCRYPT`'s nonce is
drawn on-device (`lib.rs:808-812`) — no host can supply or reuse one;
`SIGN`'s aux likewise. A RNG source that is absent refuses `6F00` rather
than fabricating (`draw_random`, `lib.rs:1277`).

**Presence cannot be joined, pre-harvested, or cross-used.** Three disjoint
tag domains — CCID `0x4000_0000 | idx`, Nostr-HID `0x6000_0000 | CID`, FIDO
`0x8000_0000 | CID` — with the Nostr CID allocator clamped below
`0x2000_0000` so the OR-fold stays injective
(`ctap_hid.rs:501-514`; `nostr_cid_allocator_is_clamped_and_tags_injective`).
The device injects the strict one-shot `request_grant`, never
join-or-open (`lib.rs:1359-1369`); a press predating the request has no
edge and never grants (anti-harvest, `presence.rs`); a press landing on the
closing tick does not re-drive the command (`redrive_vendor_window`,
`hid_serve.rs:674-678`); a window open on one interface refuses a ceremony
on the other (US-1663 test green); and the in-window routing
(`presence.rs:857`) honors only `0x6000_0000`-domain tags and answers
`false` when no window is open.

**A second request is refused, never queued, and the applet never runs under
a parked window** (`hid_serve.rs:1747-1755`) — the US-1510 rule, so the
button cannot be claimed by two ceremonies.

**Storage cannot be transplanted or replayed across slots.** Every record's
AAD binds `(KeyDomain::Nostr, slot, generation)` (`nostr_store.rs:382`), so a
sealed blob moved between slots fails the AEAD open. The occupancy guard
runs virgin → header-domain → AEAD-open in that order (`nostr_store.rs:346-378`)
— a stale FIDO record in a carved slot is refused before anything touches it
(the US-1641 guard), and a tag without a valid open is `OccupiedForeign` too
("the tag is one header byte; the AEAD is the part that cannot be forged").
The carve comes off FIDO's range **top**, leaving every deployed record's
address unchanged (`mod.rs:242-248`). `factory_wipe` tombstones through the
full commit path, so a RESET leaves nothing sealed-under-a-live-key and
indistinguishable from valid data (`lib.rs:1096-1109`). `NostrIdentity`'s
`Debug` redacts the scalar (`nostr_store.rs:174-191`).

**The two transports share one applet without sharing a race.** The applet
sits behind the first device-code blocking mutex (`nostr_shared.rs:53`),
locked only inside synchronous `.await`-free critical sections; the touch
wait happens outside the lock by construction (the grant is poll-once);
snapshots and flash commits stay under it. The `Send` promise for the
non-`Send` region handle is made once, scoped, and written down
(`nostr_shared.rs:36-51`).

**Response truncation keeps the status word.** An oversized reply truncates
to `NOSTR_RESP_MAX` (2,048) with valid-but-short CBOR, the `sw` field never
pushed out (`nostr_wire.rs:208-240`, test pinned) — the vocabulary field is
the one thing that must survive the transport.

**The extension's isolation boundary is the `ev.source` check and it holds.**
`window_nostr.js:100` answers same-frame traffic only; a cross-frame caller
has `ev.source !== win` and is dropped (US-1684, documented as the boundary
at `d431b00`). The page already owns the narrow surface, so a page speaking
the marker directly gains nothing beyond `window.nostr`. Reply shapes are
validated **before slicing** on all five hardware paths (US-1683,
`seams.js:74-81`), and the signer checks the device's signed pubkey against
the requested one (`seams.js:207-213`) — a host cannot paper over signing
under the wrong identity.

**Review fixes US-1678…US-1688 all landed.** Confirmed per-commit on
`feat/nostr` (`94d2088`…`9dc3a1f`: 1678 in-band refusal, 1679 derived
capacities, 1680 presence-gate re-anchor, 1681 reasm timeout isolation, 1685
`parse_data` refusal, 1686 scalar-RAM ADR, 1687 size measurement, 1688
hardware-matrix) and on `openxrypt` (`615bf33`…`d431b00`: 1682 batch
remainder naming, 1683 typed reply-shape errors, 1684 `ev.source`
documentation). US-1683/1684 were verified at code level above; US-1680's
re-anchored gate is the `presence.rs` shape quoted there; US-1681 is
test-harness-only (no security surface).

---

## Coverage statement

Reviewed line-by-line: `nostr_wire.rs`, `nostr_shared.rs`,
`apps/nostr/src/{lib,nip44,crypto}.rs`, `keyregion/nostr_store.rs`, the
keyregion geometry constants (`mod.rs`), the Nostr arms of `hid_serve.rs`
(`serve_once_dual`, `nostr_dispatch`, `redrive_vendor_window`,
`nostr_tag_from_channel`, `frame_cmd`, `close_window`), the Nostr wiring in
`tasks.rs` and `usb.rs` (third interface, interface-order asserts), the CID
clamp and `nostr_init_reply` in `ctap_hid.rs`, the presence routing
(`nostr_grant`, `request_grant_in_window`, `request_grant`'s anti-harvest
prologue), and all six extension modules plus the manifest. Compile-time
assert blocks in `keyregion/mod.rs` and `nostr_store.rs` read and accepted.

Not exercised this round (recorded for the next one): hardware re-verification
of the round's tests on a board (the US-1677 acceptance remains pending board
access per `docs/hardware-matrix`), and the CCID reassembly module
(`ccid_reasm.rs`) was read only where the Nostr arc depends on it
(`MAX_WIRE` 2074 fit) — its own timeout machinery is US-1681's, tested green.
