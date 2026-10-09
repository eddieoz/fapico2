# How-tos

End-to-end guides for the things people actually do with the device. Every command here runs against real hardware.

- [SSH keys](./ssh.md) — FIDO2 resident keys for OpenSSH: the private key never leaves the device.
- [Linux local authentication](./linux-auth.md) — require the device at login with PAM.
- [Unlocking disk encryption](./disk-encryption.md) — LUKS volumes whose secret is derived on the board.
- [Signing git commits](./git-signing.md) — signatures from a key that was born on the chip.
- [Encrypting to the recipient](./mail-encryption.md) — mail and files sealed for one reader, with the card.
- [Backing up the FIDO seed](./seed-backup.md) — the one-shot 24-word phrase that carries the FIDO identity off the board.
- [Changing the USB identity](./usb-identity.md) — swap the VID:PID from PicoForge or the CLI, without stranding the CCID reader.
- [Signed secure boot](./secure-boot.md) — sign the firmware and burn the fuse, with every irreversible step named first.

More guides land as they are validated on hardware.
