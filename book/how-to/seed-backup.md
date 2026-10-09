# Backing up the FIDO seed

The FIDO side of the board runs on a 32-byte master seed, and the firmware can export it **once** as a 24-word BIP-39 phrase. Write the phrase down and the FIDO identity survives the board; install it on a spare board and it is the same identity again. PicoForge drives the whole ceremony over the vendor channel — nothing to install on the board, nothing to build.

<div class="security-callout">

**The phrase is the FIDO identity.** PicoForge's own export dialog puts it plainly: anyone with it can clone this FIDO identity. Give it the discipline you give a wallet seed phrase — written on paper on an offline machine, never a photo, never a cloud note, never a chat window.

</div>

## What the phrase does and does not carry

- **It carries the FIDO identity** — the master seed the board's FIDO applet runs on. Restoring it makes the restored board's FIDO identity match the backup.
- **It carries nothing for the other applets.** OpenPGP, OATH and OTP records exist only on the board's flash store; there is no phrase for them. Their backup plan is the keys themselves, exported where they can be, and the spare-board procedure.
- **Verify a restore before you rely on it.** After installing the phrase on a board, run `ykman fido cred list` and confirm what the restored board actually serves before you retire the original.

## The export window is one-shot

Exporting opens a window, and **sealing it is final**: the device permanently refuses further exports — no protocol path clears the flag, and only a FIDO factory reset reopens the possibility. That is deliberate. An export that can happen again whenever the holder asks is not a backup control, it is a leak. So the sequence below ends with sealing, and the order matters: **paper first, seal second.**

## The procedure

PicoForge connected to the board, and the [FIDO PIN set](../using/index.md#set-the-pin-first) — the dialogs below ask for it.

1. **Open Backup** in PicoForge's sidebar. The screen reports the current state: whether a seed exists, whether the export window is still open, whether the board is soft-locked.

2. **Export.** The dialog asks for the FIDO PIN — leave it blank and touch instead if no PIN is set. Touch the **BOOTSEL button** when the status line asks for it. The phrase appears once in the window.

3. **Write the 24 words on paper, now, on a machine that is not online.** Then clear the dialog — the view model holds the phrase only until you dismiss it, but the window you are reading this on should not outlive the step.

4. **Seal the export window.** The confirm dialog repeats the warning: no further exports until a FIDO factory reset. Touch the button to confirm. This step is the point of the whole design — do it even if you are sure you'll never need a second export, because the board that *can* always export is the board someone else can always export.

5. **Check the state.** The Backup screen should now read sealed, with a seed present. If it does not, stop and find out why before walking away from the machine.

6. **Restoring** (the day you need it, on the spare board): PicoForge → Backup → **Restore**, enter the 24 words and the PIN (or touch if none is set). The board answers "Seed restored — the FIDO identity now matches the backup." Unplug, run the verification from above, and only then decide what happens to the damaged original.

## Storing the phrase

Paper, away from the machine it guards; stamped metal if the threat includes fire; a second copy in a different building if the threat includes the building. You already know how to store a seed phrase — this one is a seed phrase, with your entire FIDO identity as its wallet.
