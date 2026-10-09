# Unlocking disk encryption with the board

Your disk key should not live on the disk it protects. With LUKS and systemd's FIDO2 support, the volume's unlock secret is derived on the board through the `hmac-secret` extension: the board is present, the PIN is typed, the button is touched — or the disk stays encrypted. A stolen drive without the board is inert, the same property the key store itself is built on.

## What you need

- A Linux host with systemd 249 or newer (`systemd-cryptenroll`), and the drive already LUKS-encrypted.
- The board set up as in [Getting Started](../getting-started/index.md), with a PIN.

## Enroll the board on a volume

```bash
systemd-cryptenroll --fido2-device=auto --fido2-with-client-pin=yes /dev/sdXN
```

`--fido2-device=auto` finds the board among your HID devices; the PIN flag matters because this firmware requires the PIN on every operation of a PIN-set board — enrollment ends with a touch on the LED.

Then make systemd ask for the board at boot, in `/etc/crypttab`:

```text
luks-volume  UUID=<uuid>  none  fido2-device=auto,fido2-with-client-pin=yes
```

Rebuild your initramfs the way your distribution documents, and unlock once from the console to confirm.

## Keep a way back

Enroll a **recovery passphrase slot** alongside the board and store it offline — `systemd-cryptenroll --recovery-key` prints one. The board is the fast, strong factor; the recovery key is what turns a lost or dead board into an afternoon, not a destroyed disk. Do not skip this: a resident credential on a dead board was never backed up anywhere, and neither is your disk's only other slot.

## What the ceremony looks like

Boot or `cryptctl` asks for the PIN, then waits at the LED for the touch. There is no "tap once and forget" mode on this firmware — the touch is the physical proof that the person holding the disk also holds the board, and it happens every single unlock.
