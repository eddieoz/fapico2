# Changing the USB identity (VID:PID)

Out of the box the board enumerates as **`FA20:0002`**. That vendor ID is not USB-IF-registered, so Linux and macOS need a one-time libccid allowlist edit before the smartcard applets appear. Registering your own identity — or adopting a preset your host already knows — removes that step. You can set it from PicoForge's Configuration screen or from the command line; both write the same record on the device, the change **survives a reflash**, and it applies at the **next** USB enumeration.

## Before you choose: this is a one-way door

The stored VID:PID overrides the build-time default at enumeration. If you pick a pair your host's CCID driver cannot bind:

- the board still enumerates, but produces **no CCID reader at all** — OpenPGP, OATH and OTP go quiet, and so does the Rescue applet, the one surface that needs no PIN. The device loses its recovery route.
- **PicoForge will not report an error.** FIDO keeps working; the badge just turns yellow "Online - FIDO" while the broken thing is the invisible one.
- **Reflashing does not undo it.** The stored record survives a reflash and wins over the build default.

So check before writing:

```bash
python3 scripts/fix_usb_identity.py --list-known
```

This prints the pairs the local CCID driver can actually bind, read from libccid's own table. On a stock Ubuntu host, for example, only `2E8A:10FF` binds out of that vendor's four presets — `2E8A:10FE` writes cleanly, persists, and strands the device.

## Option 1: PicoForge

1. Connect the board and open **Configuration**.
2. Pick an identity — presets include LibreKeys One (`1D50:619B`), the Pico Keys family (`2E8A:10FD/10FE/10FF`, `2E8A:0003`) and Yubico's (`1050:0407` and friends).
3. Apply. PicoForge asks for the device PIN — the identity write is gated behind an admin-permission token, so a borrowed board cannot retarget its own identity.
4. Unplug and replug. Verify with `lsusb`.

## Option 2: the CLI

[`scripts/fix_usb_identity.py`](https://github.com/eddieoz/fapico2/blob/main/scripts/fix_usb_identity.py) needs `python-fido2` and talks over the FIDO carrier, so it works even when CCID is the thing that is broken:

```bash
# diagnose: reads the stored record and warns if it is unbindable (no PIN needed)
python3 scripts/fix_usb_identity.py

# repair / set: needs the device PIN
python3 scripts/fix_usb_identity.py --set 1D50:619B
# then unplug and replug — the change applies at the next enumeration
```

## After the change

- **Check the host sees it:** `lsusb` should show the new pair.
- **If the new pair is not in libccid's table**, do the [PC/SC allowlist edit](https://github.com/eddieoz/fapico2/blob/main/docs/identity.md#pcsc-allowlist-libccid) for it — the reader stays invisible to `pcscd` otherwise.
- **To go back:** `--set FA20:0002` restores the build default.

## Phones need a Yubico identity

Phone apps reach the board over a USB OTG cable — the same CCID surface as the desktop; a Pico 2 has no radio. The Android clients worth using are built around YubiKeys, and several only open readers that claim Yubico's identity: **Yubico Authenticator on Android will not talk to a board enumerating as `FA20:0002`**, and the OpenPGP apps are written to the same expectation. So the phone is the reason to do this deliberately:

```bash
python3 scripts/fix_usb_identity.py --set 1050:0407
```

or PicoForge → Configuration → the **YubiKey 5** preset (it asks for the device PIN and a touch). Unplug, replug, and the phone — OTG cable attached — sees a YubiKey. `1050:0407` is in libccid's table on every mainstream desktop, so unlike the bare default this pair needs **no allowlist edit anywhere**: the identity swap is what makes both the phone and a stock Linux desktop work with zero host changes.

The rule from below still applies with force: it is Yubico's identity, borrowed for interop on your own board — never in anything you ship.

## Which identity to pick

- **A vendor ID registered to you** (pid.codes and OpenMoko allocate one to open-source projects) is the right answer for anything you distribute.
- **Another project's preset** is fine for a private board — you inherit whatever allowlist entries that pair already has, and the name that goes with them.
- **Yubico's IDs** make `ykman` and Yubico Authenticator work with zero host edits, but it is their identity, not ours: use it for interop on your own board, never in anything you ship.
