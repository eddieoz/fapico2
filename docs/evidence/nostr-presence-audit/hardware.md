# The presence-gate fixes on hardware — the 2026-10-12 acceptance pass

**Board:** `fa20:0002 The BLOCO Community fapico2` · **Image:** the post-audit tip
(`be886fc`, UF2 3,349 blocks, sha256 `eb185598…` for the pre-F-A15 build; the F-A15
build re-flashed via rescue `REBOOT` at the end). **The finger was the user's;** every
press below is theirs. This is the audit's D2 hardware leg (`docs/nostr-presence-audit.md`),
closing what US-1677 named for this arc.

The board entered BOOTSEL by hand and by the rescue applet's `REBOOT`
(`80 1F 01 00 00` after SELECT `A0 58 3F C1 9B 7E 4F 21`); re-enumeration took
10–20 s both times. The board carried **two real Nostr identities (idx 0, 1)** at the
start; the management RESET at the end destroyed them with the user's explicit
acknowledgement ("identities are expendable") — the ADR 0005 host pre-flight duty,
discharged.

## D7 — the CCID arm's touch gate actually grants (the F-A4 fix, observed)

- `GENERATE_KEY idx6` with no press: the CCID call **blocked the full 10.0 s** window
  and answered `6985` — an honest refusal as a status word, not a transport abort and
  not the microseconds-dead one-shot the arm had before the fix. Untouched control.
- Same command with a press: **`9000` + 32-byte npub granted after 5.1 s** — the
  blocking wait held the slot, the press armed, the grant consumed, the command ran.
  A PC/SC client can now do key management with a touch.

## The delete flow (D12's answer observed)

- `DELETE_KEY idx6` (no payload): `9000` + the destroyed identity's 32-byte npub
  after a 5.0 s press — the answer names what was destroyed.
- Second `DELETE_KEY idx6`: `6A82` — the slot reads empty afterwards.

## F-A1 — the CANCEL-repark replay does not survive on hardware

Two runs of the adversarial hammer over the vendor HID interface (`/dev/hidraw13`,
usage page `0xFF00`; channel `01020304`), six rounds total, **the user pressed many
times** per run while the script strobed park/CANCEL cycles (`GENERATE idx7` parked,
CANCEL, re-park — a window open essentially continuously):

- **Zero completions across every round.** Every press that armed a grant was killed
  by the next CANCEL — the armed grant dies with its window (the F-A1 fix), and the
  post-hammer free-index command always demanded a fresh press.
- **No command ever executed without a matching fresh press.** The regression signal
  (an instant `9000` on a free index with no press) never appeared. Pre-fix, the
  skeptic's PoC replayed one of these presses into `EXPORT_KEY` within ~200 ms.
- A press on a **fresh** window still grants honestly (one of the user's presses
  landed outside the hammer and legitimately completed a `GENERATE idx3` — consent
  works, and the created identity was deleted with its own touch).
- An occupied index refuses `6A84` **instantly, before any touch** (state-before-touch).

## F-A15 — found live on hardware, fixed in the same pass

**"led was solid dark for this last touch"** (the user, during a Nostr CCID wait). The
LED is active-high (`set_touch_prompt_led`: `set_high` = ON), but `paced_bootsel`'s
per-poll "re-assert" drove it **LOW** — the prompt was dark for the whole blocking
wait, on the Nostr CCID arm and the OpenPGP PSO wait alike. The user's presses in the
steps above were made on timing, not on the light. Fixed in `be886fc` (re-assert
HIGH; the source gate pins the polarity both ways), re-flashed via rescue `REBOOT`,
and the prompt verified lit during the RESET probe below.

## D6 — management RESET wipes Nostr (observed)

- First leg: `RESET` (INS `0x1E` over mgmt's AID) answered `6985` **instantly** — the
  windowed gate opened its window (how mgmt/OATH work over CCID; the retry is the
  second chance).
- With the window open, a press landed at t+8 s in the retry loop; the retry consumed
  it and answered `9000`. **`LIST_KEYS` after the RESET: `n=0`.** The Nostr identities
  were destroyed with FIDO/OATH/OpenPGP — mgmt RESET means empty, as its doc and the
  handover contract say.

## F-A16 — recorded, not fixed: the windowed CCID prompt is dark on this board

The windowed path (mgmt/OATH over CCID) lights the prompt only at window-open; the
serve task then resumes and trussed's Processing→Idle bracketing per pcscd poll flips
the LED off — the documented 2026-09-23 defect (`firmware/src/button.rs`'s comment),
whose fix (`paced_bootsel`'s re-assert) covers only the **blocking** wait. During the
RESET probe the LED was dark and the user pressed blind. Fix shape, not implemented:
the button task's tick re-asserts the prompt HIGH while `pending_tag()` is `Some` (the
prompt outranks the heartbeat while a window is open) — broader than F-A15 (it touches
every CCID window's heartbeat interplay), so it is recorded as its own decision rather
than riding this pass.
