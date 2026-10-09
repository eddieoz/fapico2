# Using the device

The whole operating model in one paragraph: a board with a PIN set asks for **the PIN and a touch on every operation**, and nothing in a WebAuthn request can switch either off. That is deliberate — a board that leaves your pocket opens nothing by itself. Everything below is the daily consequence of that one decision.

## Set the PIN first

Before anything else: `ykman fido access change-pin`, or accept the PIN prompt the first time a browser enrols the board. The PIN guards every applet's token — makeCredential, getAssertion, credential management, configuration — and derives the permission rules those tokens carry.

## Passkeys

Enroll on any WebAuthn site — `webauthn.io` is the usual first test. The site asks for a touch, the LED confirms, and the credential is generated on the board and stays there. There is room for 856 of them. Sites that offer "sync with your phone" are offering a cloud copy; this board is the non-synced answer.

## Managing credentials

Resident keys can be enumerated, renamed and deleted from `ykman`'s `fido cred` commands or PicoForge's credential manager. Resident SSH keys re-download to any machine with `ssh-keygen -K` — the key-handle file that lands on disk is a pointer, not a secret. Losing the board means re-enrolling; the credentials were never backed up anywhere else.

## TOTP and HOTP

Add accounts in Yubico Authenticator or `ykman oath accounts`. The codes are computed on the board when you ask, touch-gated on a PIN-set board — the phone or the laptop holds none of them, which is the point of moving 2FA off an online machine.

## The OpenPGP card

`gpg --card-status` to meet the card, `gpg --card-edit` then `generate` to create the three key slots (sign, encrypt, authenticate) on the chip — the keys are born there and never leave. `gpg --change-pin` changes the card's PIN. Encrypt directly to the recipient's key and the message is unreadable to everyone but the holder — no screenshot of a "secure" note, no trusting the channel. Full walks: [git commit signing](../how-to/git-signing.md) and [encrypted mail and files](../how-to/mail-encryption.md).

## OTP slots

`ykman otp` programs the YubiKey-protocol slots, including challenge-response with a touch-gated challenge. Same board, same rule: the secret never leaves.

## The LED

Slot and status behavior is configurable from PicoForge. The LED is the only output the board has — worth making it say what you expect.

## Factory reset

`ykman fido reset` wipes the FIDO credentials and the FIDO PIN, and nothing else: the OATH, OTP and OpenPGP applets keep their records. After a reset, the OpenPGP card's serial changes and your host's keyring stubs will point at a card that no longer exists — delete the stale stubs (see [what it works with](../interop/index.md)).

## No board yet?

The same applet code runs on the host with `--features emulation` over TCP sockets — it is how every test in `./run_tests.sh` exercises FIDO2, OpenPGP and OATH without hardware. It is a test harness, not a polished window, but it answers "does this thing behave as advertised" before any money is spent.
