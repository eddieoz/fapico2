# Troubleshooting Nostr

The board is alive (the [boot page](./boot.md)'s heartbeat is running) and the Nostr applet is refusing — or agreeing when you expected a refusal. Nostr errors arrive as **status words** the extension renders as sentences, so every failure below starts from what you saw, names the word behind it, and says what actually happened. If your symptom is not here, [the how-to's error table](../how-to/nostr.md#7-the-touch-timeouts-and-what-the-errors-mean) carries the full vocabulary.

## First: which consent are you missing?

The applet asks for exactly two kinds of consent, and every gated refusal is one of them. The two sentences tell you which:

- ***your PIN is needed first*** (`6982`) — the **PIN session** is closed. The session opens at connect-time verify, and closes on LOCK, on a power cycle, and on a failed verify. Verify and retry; the interrupted operation resumes.
- ***touch timed out — the device asked for a touch and none came*** (`6985`) — the **touch** was owed and the press did not land inside the window (~15 s). The amber bar pulses while the board waits; if you pressed and it still refused, the press went to a different interface than the one asking — see [the press landed but was refused](#the-press-landed-but-was-refused) below.

Everything else is a data, state or firmware answer, not a consent answer.

## The touch bypass — errors and misuse

The [touch bypass](../features/nostr.md#the-touch-bypass-consented-session-bound-ram-only) exempts sign, NIP-44 encrypt and NIP-44 decrypt from the button; everything below is about that feature failing — or working when you did not expect it to.

| What you see | The word | What actually happened | What to do |
|---|---|---|---|
| The checkbox is **disabled**: *firmware does not support touch bypass* | caps bit 4 absent | the board predates `SET_TOUCH_POLICY` (US-1742) — its GET_INFO does not advertise caps `0x0010` | re-flash the current image over BOOTSEL; the verb ships in the same UF2 as everything else |
| Unchecking answers *your PIN is needed first* and the box snaps back checked | `6982` | the disable leg is a **session privilege** — the session is closed (fresh power-up, LOCK, or a failed verify) | verify the PIN, then uncheck again; the consent press is asked only after the gate passes |
| Unchecking answers *that identity is not on the device* (or another `6A82`-worded refusal) | `6A82` | no PIN record exists — **a board with no PIN can never arm the bypass** | set a PIN first (the how-to's [PIN section](../how-to/nostr.md#5-the-board-pin--session-custody)), then disarm the touch |
| Unchecking lights the LED, then *touch timed out* and the box snaps back checked | `6985` | the **consent press** never landed inside the window | press again — unchecking is the dangerous direction, and the board never half-applies a policy: no press, no bypass, box back to checked |
| The checkbox is unchecked but **signs still ask for the touch** | flags bit 3 clear | the bypass was cleared since you armed it: **LOCK, a failed verify, or a power cycle** clear it — the button coming back is the feature working | re-open the session and uncheck again; the press is one per session, not one per day |
| The checkbox is checked (touch *required*) but **a signature just ran without a press** | flags bit 3 set at sign time | you are still inside the session you armed the bypass in — this is the feature, not a fault | check the box again (friction-free) to get the button back; **Lock** on the popup also closes the bypass with the session |
| *The device does not serve that command* after you sent `0x4F` from a custom tool | `6D00` | the vendor byte or INS is not served by this firmware — usually a pre-US-1742 image, or the byte sent outside the Nostr interface's method table | update the firmware; CCID tools send INS `0x1F`, HID tools send vendor byte `0x4F` with the leg in the envelope's idx field |

Two misuse patterns worth naming because they look like bugs:

- **"I unplugged to clear the bypass and it is still off after replugging"** — that is the design, not a failure. The bypass is RAM-only: a bypass that survives unplug is a bypass the user forgot they owned. The durable things (identities, PIN) survive; the bypass does not.
- **"I armed the bypass and now the board signs when a site asks — is that a leak?"** — no. The bypass was armed by a physical press inside a verified session, and every page request still crosses the extension's approval window and its per-site grants; what went away is only the *second* consent (the button) for the three signing commands, until LOCK, a failed verify or power takes it back.

**Board-side sanity check** (CCID, no extension involved): `GET_INFO` answers `caps = 0x001F` (bit 4 = the verb exists) and `flags` bit 3 = `0x08` while the bypass is armed, clear when it is not. The scripted walk — advertisement, closed-session refusal, consent press, ten-signature chain, LOCK, enable, power cycle — is `scripts/nostr_probe.py --touch-bypass` from the firmware repo, which narrates each leg and asserts the expected word.

## The press landed but was refused

A press that is consumed by nothing is the most confusing failure in the inventory, because the finger was real. The board's rule: **a press arms a grant for the request that asked, on the interface that asked, and dies with that request.** So:

- **A press while no window is open** is simply ignored — the button is free, and pressing it consents to nothing. If a refusal arrives *after* you pressed, the press probably landed before the request reached the touch check (e.g. the PIN gate refused first and ate nothing because no grant existed yet). Read the sentence: the gate word (`6982`) means the session, not the finger.
- **A press for one request cannot pay for another.** Grants are request-bound — a second pending request is refused outright rather than queued onto the same window, and the extension queues its side so clients never provoke it. If a chain of signs keeps refusing `6985`, the window is closing before each press: slow the chain down or (deliberately) arm the bypass.
- **The CCID and HID interfaces do not share presses.** A press observed by the vendor-HID arm cannot satisfy a CCID command and vice versa; the tag domains are disjoint by construction. If you are driving CCID tools (`ykman`-style, `scripts/nostr_probe.py`) while the extension holds the board, close the other client — two holders of one board makes every reading ambiguous.

## Beyond consent: data, state and firmware answers

| The popup says | The word | What to do |
|---|---|---|
| *that slot is occupied — delete it first* | `6A84` | pick another of the 8 slots, or delete the occupant (a slot may be held by a record that is not a Nostr identity — the refusal is the same and so is the remedy) |
| *that identity is not on the device* | `6A82` | empty or tombstoned slot — check the Keys screen; on a PIN verb the same word means *no PIN is set* |
| *the device refused the data — it could not read the request* | `6A80` | the payload was malformed or over the applet's caps — re-check what you pasted (an `nsec`/hex paste for import, a peer npub for encrypt) |
| *the device refused the command length* | `6A87` on the device | the counterparty's key is not a valid curve point — the failure is in the *other* party's npub, not your board |
| *the device could not complete the operation — its store faulted* | `6F00` | the boot degraded or a slot would not open — reflash over BOOTSEL; if it persists, [the boot page](./boot.md)'s fatal signatures say whether the store itself is being refused |
| *the device is locked — too many wrong PINs…* | `63C0` | the durable three-attempt budget is spent; recovery is management RESET, which destroys every identity — the deliberate-act-only path ([what RESET does](../how-to/nostr.md#9-what-management-reset-does)) |
| *ceremony interrupted — the worker restarted mid-operation; try again* | — | the extension's background worker restarted; retry once |
| *no Fapico board connected — connect it and try again* | — | no granted device at all — [connect first](../how-to/nostr.md#2-connect-the-board) |

## The chooser and the udev rule (Linux)

The board never reaching Chrome's chooser is the one Nostr failure that happens **before any applet code runs** — the applet cannot be at fault, and its status words cannot help. The two cases:

- **`lsusb` shows `fa20:` but the chooser does not** — the udev rule is missing or not reloaded. Re-run the two `udevadm` lines from [step 0 of the how-to](../how-to/nostr.md#0-what-you-need).
- **The chooser shows the board but Connect fails** — another client holds the interface: close Yubico Authenticator / `ykman` / any PC-SC tool, then **Try again** on the popup's device card. A custom **VID** (changed via [the USB identity](../how-to/usb-identity.md)) strands the chooser entirely — the udev rule keys on the vendor ID; restore `fa20` with `scripts/fix_usb_identity.py`.
