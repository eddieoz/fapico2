# Troubleshooting

Two diagnostic surfaces cover the two ways a fapico2 board fails, plus one single-symptom page for the most common host-side failure. Pick by symptom, not by guess:

- **[Troubleshooting the boot](./boot.md)** — the board will not come up, or came up but USB is dead. The instrument is the **LED**: a boot ladder you count, fatal signatures you read as four bits, and a heartbeat that means "look at the host side instead".
- **[Troubleshooting Nostr](./nostr.md)** — the board is alive and serving, but the Nostr applet refuses a command: the extension shows an error sentence, a touch does not light, the signing chain asks for the button when you expected it silent, or the button is silent when you expected it back. Every refusal is a status word, and the word names the remedy.
- **[Making the smartcard reader appear](../how-to/smartcard-allowlist.md)** — the board is enumerated and FIDO2 works, but the host sees *no smartcard reader at all*: `ykman list` without `+OCARD`, `gpg --card-status` empty, PicoForge's yellow "Online - FIDO" badge. The one-time libccid allowlist edit fixes it.

Everything else — choosers that hide the device, USB identities a host will not bind, tool version quirks — starts at [What it works with](../interop/index.md) and [Changing the USB identity](../how-to/usb-identity.md); the Nostr page cross-links the chooser-specific cases it shares.
