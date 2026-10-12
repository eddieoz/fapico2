# Nostr presence-gate adversarial audit — findings, arbitration, fix design

**Date:** 2026-10-12 · **Branch:** `feat/nostr` @ `a795d0d` (clean) · **Method:** multi-agent
structured review (skeptic + constraint guardian in parallel, user advocate sequential, arbiter
consolidated), adversarial plays + conformance ledger per the approved audit design.

**Disposition: REVISE.** The prior red-team report's headline ("the arc is clean — bypass a
touch: no") does not survive re-derivation. One Critical finding is confirmed by an executed
PoC against the shipped `PresenceService`; three High findings are confirmed by code reading
with the load-bearing claims independently re-verified by the arbiter. The gate's foundations
(carve enforcement, occupancy guard, anti-harvest, tag injectivity, park-not-queue,
state-before-touch ordering) re-verified clean. The defects are at the edges: grant lifetime,
tag-domain precision, the device proxy, and the two failure modes of "refuse" (forever, and
strand). Fixes land in-session on `feat/nostr`, red-then-green, per the approved fix policy.

---

## 1. Findings (namespaced S- = skeptic, G- = constraint guardian, UF- = user advocate)

### F-A1 · CRITICAL — CANCEL-repark grant replay (S-F1, PoC-confirmed; UF-1 UX-confirmed)

`PresenceService::end_request` (`platform/src/presence.rs:141-146`) clears the pending slot
but never the armed grant, and the Nostr HID tag is channel-derived
(`0x6000_0000 | cid`, `firmware/src/hid_serve.rs:1663-1665, 1756`). A hostile script cycling
CANCEL/re-park on one channel keeps the touch prompt lit; a press made while command A was
pending survives A's CANCEL (post-press) and is consumed, within its 10 s, by the re-drive of
a *different* command B parked later on the same channel — with no new press. The PoC
executed against the shipped service confirms W2's re-drive consumed W1's press. A secondary
race-free variant: a press in the final ~250 ms of an expired window — the expiry path
deliberately refuses without re-driving (US-1663 no-late-grant) but leaves the grant armed
for the next same-tag window. Payoff includes `EXPORT_KEY` (the raw scalar). This crosses the
threat model's line: the pending command was cancelled *after* the press, so the press was
never made "for" command B. Violates the module's own anti-harvest charter
(`platform/src/presence.rs:16-17`). No test covers arm→`end_request`→re-begin-same-tag. The
FIDO HID arm carries the identical pre-existing shape (S-F7) with channel-derived tags.

**Ruling (D4):** an armed grant dies with the request that owns it. In `PresenceService`,
both `end_request(tag)` and `expire_pending(now)` drop `self.armed` when it is bound to the
dying tag. All current callers either consume before ending or hold the slot across retries,
so no legitimate path loses a grant (skeptic's analysis; arbiter concurs). Fix once in the
service — covers the Nostr CCID arm, the Nostr HID arm, and the FIDO arm alike. Pinning
tests: arm→end→re-begin-same-tag→request is `None`; press-in-final-moment→expiry→next-window
consumes nothing.

### F-A2 · HIGH — `nostr_grant`'s domain check admits folded FIDO tags (S-F2; UF-3 UX-confirmed)

`firmware/src/presence.rs:860` tests `t & 0x6000_0000 == 0x6000_0000` — a mask, not a domain
check. FIDO tags are `0x8000_0000 | cid` and the FIDO CID allocator wraps at `0x8000_0000`
unclamped (`firmware/src/ctap_hid.rs:287, 494-496, 548-567`), so FIDO tags pass through
`[0x6000_0000, 0x7FFF_FFFF]` in the allocator's lifetime; any such tag folds to `0xE000_xxxx`
and passes the mask. Under a ~19-day silent INIT-flood precondition (estimate, labelled),
a FIDO login press is consumable by a Nostr command. The OR-fold hazard was fixed for the
Nostr allocator and tag injectivity (US-1663) but the consumer-side check was left a mask.

**Ruling (D5):** exact-domain check — `(t & 0xE000_0000) == 0x6000_0000` — plus a us1663-style
test with a folded FIDO tag. The FIDO allocator clamp is recorded as a follow-up (FIDO-side,
out of this epic per §6 "Nostr must not make it worse"; the Nostr-side check becomes exact,
which closes the Nostr exposure completely).

### F-A3 · HIGH — management RESET never wipes Nostr on device (G-F1; UF-4)

The device registers the `NostrViaMutex` proxy (`firmware/src/main.rs:1260-1277`); the proxy
implements `aid/select/deselect/process/select_apdu` and **not** `factory_wipe`
(`firmware/src/nostr_shared.rs:93-122`), so the trait's default no-op
(`platform/src/dispatch.rs:104`) swallows the wipe. The real wipe exists
(`apps/nostr/src/lib.rs:1096-1109`) and is dead code on device. The emulator registers the
inner app (`emul_main.rs:749`) so every test passes — the AGENTS §1 twin trap. Consequence:
mgmt RESET (0x1E) destroys FIDO/OATH/OpenPGP/trussed and silently preserves all 8 usable
Nostr identities, contradicting the mgmt doc ("full factory reset"), the handover contract
(`firmware/src/boot.rs:1236` "I reset it, it is clean"), US-1650's device acceptance, and the
applet's own comment — while ADR 0005 simultaneously markets reset-survival as a feature.

**Ruling (D6, arbiter per recommendation — user veto open at spec review):** RESET wipes
Nostr. Forward `factory_wipe` through the proxy (one impl-block addition), so 0x1E means what
its own documents say. CTAP2 `authenticatorReset` (0x07) stays Nostr-preserving — verified
(wipes only `[FIDO_FIRST_SLOT, FIDO_SLOT_LIMIT)`; the derivation depends on nothing it
destroys) — that is the scoped reset, and ADR 0005's survival sentence is reworded to name it.
The alternative (keep survival, announce a distinct wire notice) was rejected: more code, and
"reset" meaning two things is the divergence the user cannot see.

### F-A4 · HIGH — the CCID arm can never grant on hardware (S-F3; UF-2)

The strict one-shot `request_grant` holds the pending slot for microseconds inside a
synchronous, non-preemptive CCID dispatch; the button task latches and drains a press within
one 10 ms tick and can never run inside the slot. Every touch-gated Nostr command over
CCID/PC/SC answers `6985` forever, no prompt, while GET_INFO advertises the capabilities —
the repo's §4 "wire claim the device does not honour" class, inverted onto the user. The
design's own Phase-1 client (OpenXrypt over CCID, and any PC/SC tool) cannot manage keys.

**Ruling (D7, arbiter per recommendation — user veto open at spec review):** give the CCID
arm the proven OpenPGP wait shape: `wait_grant(tag, timeout, sample)` under the command's own
request-bound tag (~15 s), touch prompt lit, pad sampled in-line (paced BOOTSEL read — the
mechanism `apps`' OpenPGP `pso_wait_grant` already uses on this executor). The single-pending
slot discipline means no other command can join the wait; with F-A1's fix, a grant cannot
outlive the wait. Trade, accepted as OpenPGP precedent: the CCID task blocks up to 15 s
(HID/FIDO tasks stall during the wait). Alternative rejected for now: honest-refusal-only
("use HID") — it leaves the design's own Phase-1 path dead; revisit if the hardware pass
shows the blocking wait starves concurrent FIDO traffic unacceptably.

### F-A5 · MEDIUM — factory_wipe strands undecodable slots; DELETE cannot clear them (S-F4; UF-5)

`factory_wipe` deletes only slots whose `read_identity` succeeds; `Undecodable` maps to
`SW_STORE_FAULT`, so a corrupted-body record survives the wipe, is `occupied` to every writer
(`6A84`), and `DELETE_KEY` refuses *before the touch* (`6F00`) — the user cannot spend a press
on the only remedy. One corrupt byte = permanent 12.5 % capacity loss diagnosed as a device
fault. US-1650's own acceptance ("afterwards every slot is reusable") is unmet for this class.

**Ruling (D8):** store-level force-tombstone (re-seal at generation+1) reachable from
`DELETE_KEY` and `factory_wipe` for slots the store itself classifies `Undecodable`. The
occupancy guard exists to protect *live* records; a slot that cannot open is by definition
not one. Test: hand-built valid-CRC foreign-slot header via `record::testing`, red-then-green.

### F-A6 · MEDIUM — flash ratchet over budget, re-baseline skipped (G-F2)

Shipping UF2 at HEAD: 3,346 blocks = 1,713,152 B vs `FIRMWARE_FLASH_BUDGET_BYTES` 1,703,936 —
9,216 B over; US-1675's entry itself (3,344) was already 8,192 B over. The sanctioned path
(US-1675's acceptance; ADR 0005's provisional clause: "re-baselined with the reason written,
not silently") was not run. The machine-parsed tables and the dated ledger prose also
contradict each other at `docs/size-report.md:1-10` after `a795d0d`.

**Ruling (D9):** run `raise_flash_budget.py` with the recorded reason; add the dated ledger
entry for the post-merge re-measure. Not a security control — a deliberate-act constraint
currently bypassed by omission.

### Small fixes (accepted)

- **F-A7 (G-F3):** `unreachable!` in `nostr_store.rs` admission → typed
  `NostrStoreError::OccupiedForeign` + pinning test (valid-CRC transplanted header).
- **F-A8 (G-F4):** refuse `idx > 0xFF` in `nostr_wire::decode_request_inner` (in-band `6A80`)
  + test — the envelope honours only what the device honours.
- **F-A9 (S-F6):** stale capacity prose in `fido_store.rs:245, 449` (856 → the carved 848).
- **F-A10 (G-F5):** `docs/erase-budget.md` §4c.5 names the Nostr store as a budget
  consumer (2 of 3 erases per Nostr commit land on the shared scratchpad sector).
  Scope corrected in execution: §3.1a is the *secure-partition* persist budget and
  Nostr is not a consumer there — only §4c.5 (the keyregion) gets the line.

### Recorded, no code (accepted risks / out of scope)

- **F-A11 (S-F5):** residual scalar in scratch statics after EXPORT/DECRYPT — inside ADR
  0005's US-1686 amendment with named revisit conditions (first `-release` tag). Tracked
  there.
- **F-A12 (UF-Q5):** per-message NIP-44 decrypt press rhythm trains touch-without-reading;
  the OpenXrypt `decryptBatch` path exists but has no production caller. Extension-side
  story, not firmware. Recommendation: wire the batch path before shipping touch-gated
  auto-decrypt.
- **F-A13 (S-F7):** FIDO arm's CANCEL-repark shape — closed by F-A1's service-level fix;
  noted so the FIDO-side test gains the same pinning case.
- **F-A14:** prior-assessment items left open there and not contradicted here: `nostr_init_reply`
  capFlags honesty (US-1661) not re-derived; FIDO-allocator flood-cost figure unmeasured.

### Found by the hardware pass (2026-10-12)

- **F-A15 — FIXED (`be886fc`):** `paced_bootsel`'s per-poll "re-assert" drove the
  active-high touch prompt LOW, holding it dark for the whole blocking wait — observed
  live ("led was solid dark for this last touch", the user, during a Nostr CCID wait),
  on the OpenPGP PSO wait too. Re-assert HIGH; the source gate pins the polarity.
- **F-A16 — RECORDED, not fixed:** the **windowed** CCID prompt (mgmt/OATH) is dark on
  this board — it lights only at window-open, then trussed's Processing→Idle bracketing
  per pcscd poll flips it off (the documented 2026-09-23 class; its fix covered only
  the blocking wait). The user pressed blind and the RESET completed. Fix shape: the
  button task's tick re-asserts the prompt HIGH while `pending_tag()` is `Some` —
  broader than F-A15 (every CCID window's heartbeat interplay), its own decision.

### Hardware acceptance (the D2 leg — `docs/evidence/nostr-presence-audit/hardware.md`)

Verified on the post-audit tip with the user's finger: D7 (the CCID blocking wait
grants — `9000` + npub after a 5.1 s press; the untouched control refused `6985` after
the full 10.0 s window), the delete flow (the destroyed npub named, then `6A82`), F-A1
(six rounds of the park/CANCEL hammer with many presses — **zero** orphan consumptions,
no command ever ran without a matching fresh press), and D6 (mgmt RESET: first leg
`6985` instantly, the retry consumed the press at t+8 s, `LIST_KEYS` answered **n=0**).

### Verified clean (re-derived at this tip, not inherited)

Carve enforced at all guard sites (`fido_store.rs:506, 1103, 1340, 1454`; allocator scan
range; tiling asserts); occupancy guard order virgin→header-domain→AEAD with AAD binding
domain/slot/generation; anti-harvest discard; single pending slot; tag injectivity and the
mgmt/rescue 0x1C collision unreachable from Nostr; park-not-queue; second-command-while-parked
refusal without running the applet; state-before-touch ordering on every mutating command;
commit atomicity and boot-time recovery; touch-free read surface exactly as §2.3 promised (no
scalar on any read path, foreign slots indistinguishable from empty); D13 status-word
vocabulary complete and distinct; wire-cap arithmetic closed with drift tests; NF1–NF6
constraints hold as amended (fail-closed defaults, per-record commits not whole-store
rewrites, zeroization per US-1686, no applet-level heap, no reachable panics except F-A7,
size gates green apart from F-A6's ratchet).

---

## 2. Decision Log

| # | Decision | Alternatives considered | Objections | Resolution & rationale |
|---|---|---|---|---|
| D1 | Audit = adversarial plays + conformance ledger | Conformance-only; delta-since-last-report | — | User selected. Delta rejected: inherits the prior report's blind spots; conformance folded in as the claim ledger. |
| D2 | Evidence: emulator audit now; one hardware touch pass on the final tip | Audit directly on hardware; emulator-only forever | — | User connected board `fa20:0002`; arbiter scheduled HW after fixes so presses are not spent on pre-fix states. User provides the finger. |
| D3 | Fix policy: (a) fix now red-then-green / (b) record with reason / (c) EPIC story | — | — | User approved in the audit design. |
| D4 | F-A1: grant dies with its request (`end_request` + `expire_pending` drop armed bound to the dying tag) | Close-path-only fix in `hid_serve`; FIDO-arm separate fix | Skeptic: no legitimate caller loses a grant — checked, concurred | Service-level: one rule covers all three arms and both orphan paths (CANCEL and expiry). |
| D5 | F-A2: exact-domain check + folded-tag test | Clamp FIDO CID allocator too | — | Nostr-side exactness closes the Nostr exposure; allocator clamp is FIDO-side, recorded as follow-up (§6 scope). |
| D6 | F-A3: RESET wipes Nostr (proxy forwards `factory_wipe`) | Keep survival + distinct wire notice; ADR rewrite | **User veto open at spec review** | mgmt doc, `boot.rs:1236` contract, US-1650 acceptance and the applet comment all already say wipe; CTAP2 0x07 remains the Nostr-preserving scoped reset; ADR 0005's survival sentence reworded to name 0x07. |
| D7 | F-A4: CCID arm uses `wait_grant` (OpenPGP shape, request-bound tag, ~15 s, prompt lit) | Honest-refusal-only; full park/redrive on CCID | **User veto open at spec review** | Makes the Phase-1 path real with a proven mechanism; blocking trade = OpenPGP precedent; revisit if HW pass shows FIDO starvation. |
| D8 | F-A5: store-level force-tombstone from DELETE + wipe for `Undecodable` slots | New recovery command; wipe-only escape hatch | — | DELETE is the remedy a user already has; no new surface (§5 simplicity). |
| D9 | F-A6: run `raise_flash_budget.py` + ledger prose fix | Leave to Phase 5 | — | US-1675's acceptance names exactly this; silence is the violation. |
| D10 | F-A11/F-A12/F-A13/F-A14 recorded, not fixed here | — | — | US-1686 amendment; extension-side story; D4 covers F-A13; open items named. |

---

## 3. Fix plan (order matters)

1. **F-A1** first (PresenceService + pinning tests, red-then-green) — every later grant path
   depends on the orphan being dead.
2. **F-A2** exact-domain check + test (same `presence` test families).
3. **F-A3** proxy `factory_wipe` forward + text-gate test beside
   `apps/nostr/tests/presence.rs:120` + device-path test driving the proxy + ADR 0005 wording.
4. **F-A4** CCID `wait_grant` arm + prompt + tests (strict-path refusal tests updated).
5. **F-A5** force-tombstone + DELETE/wire wiring + tests.
6. **F-A6, F-A7–F-A10** small items, batched.
7. **Hardware acceptance pass** on the final tip (board `fa20:0002`): one press per gated
   command family over CCID *and* HID, untouched-control refusals, window-expiry timing,
   mgmt RESET → `LIST_KEYS` returns 0 (D6), CCID touch grant observable (D7). This closes
   what US-1677 named for this arc.

## 4. Conformance ledger note

The full requirement→enforcement→test table was produced during the audit and its "verified
clean" column is summarized in §1; it travels with the fix commits as test names rather than
as a separate document, per the repo's red-then-green convention.
