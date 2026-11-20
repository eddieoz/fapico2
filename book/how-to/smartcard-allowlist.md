# Making the smartcard reader appear (Linux & macOS)

**Use this page when OpenPGP, OATH or OTP do not work, while FIDO2 does.**
`ykman list` shows `+U2F` but no `+OCARD` (or shows nothing at all), `gpg --card-status` reports no reader, PicoForge says it cannot find the device — and `lsusb` (Linux) or System Information (macOS) **does** show the board as `FA20:0002 "fapico2"`. FIDO2 passkeys work everywhere in the meantime.

One deliberate, one-time host edit fixes it. It takes five minutes and never needs to be repeated.

## Why this is needed

The board's USB identity is `FA20:0002`, and `0xFA20` is not a USB-IF-registered vendor ID. The CCID driver (`libccid`) keeps its own table of known reader identities in an `Info.plist` file, and that table **has no wildcard**: a reader whose identity is not in it is simply invisible to `pcscd`, the daemon every smartcard application talks to. The board is enumerated, healthy, and serving FIDO2 the whole time — the smartcard half just never appears.

The fix is to add three lines to that table: the vendor ID, the product ID, and a friendly name. Then restart the daemon.

The full mechanism — including what happens if you later change the board's identity to a pair your host does not know — is in [`docs/identity.md`](https://github.com/eddieoz/fapico2/blob/main/docs/identity.md#pcsc-allowlist-libccid). If you would rather **change the board's identity to a pair your host already knows** (for example a YubiKey 5 preset, which needs no allowlist edit anywhere), see [Changing the USB identity](./usb-identity.md).

## Step 1 — find the driver's `Info.plist`

**Linux.** The file lives inside the CCID driver bundle. On Debian and Ubuntu it is a symlink to a writable copy in `/etc`; on other distributions look under the pcsc drivers directory:

```bash
PLIST=$(readlink -f /usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist \
        2>/dev/null || \
        find /usr/lib /usr/lib64 /usr/local -path "*ifd-ccid.bundle/Contents/Info.plist" 2>/dev/null | head -1)
echo "$PLIST"
```

Expected results: `/etc/libccid_Info.plist` (Debian, Ubuntu) or `/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist` (Fedora, Arch, most others). If the command prints nothing, install the driver first (`sudo apt install libccid`, `sudo dnf install pcsc-lite-ccid`, `sudo pacman -S ccid`).

**macOS.** The path is fixed by the system:

```bash
PLIST=/usr/libexec/SmartCardServices/drivers/ifd-ccid.bundle/Contents/Info.plist
ls -l "$PLIST"
```

## Step 2 — back it up

```bash
sudo cp "$PLIST" "$PLIST.backup-$(date +%Y%m%d)"
```

Restoring is then one copy command, in case an edit goes wrong.

## Step 3 — add the three entries

Open the file with an editor:

```bash
sudo nano "$PLIST"        # Linux; on macOS: sudo nano "$PLIST"
```

Inside it, find these three keys (each is followed by an `<array>` of `<string>` entries):

- `<key>ifdVendorID</key>`
- `<key>ifdProductID</key>`
- `<key>ifdFriendlyName</key>`

Add **one** entry to the **end of each** of the three arrays — the three arrays are paired by position, so each gets exactly one new line and all three stay the same length. Use the tab character, matching the file's existing lines:

```xml
	<string>0xFA20</string>
```
inside `ifdVendorID`'s array,

```xml
	<string>0x0002</string>
```
inside `ifdProductID`'s array, and

```xml
	<string>fapico2 (The BLOCO Community)</string>
```
inside `ifdFriendlyName`'s array.

Save and exit. (On macOS, if you prefer a graphical editor: `sudo open -e "$PLIST"` opens it in TextEdit — but plain `nano` keeps the file's formatting intact.)

## Step 4 — restart the smartcard daemon

**Linux:**

```bash
sudo systemctl restart pcscd
```

If `pcscd` is socket-activated on your distribution, restarting both units is harmless:

```bash
sudo systemctl restart pcscd.socket pcscd.service
```

**macOS:**

```bash
sudo launchctl kickstart -k system/com.apple.pcscd
```

On macOS versions where that command errors, a reboot achieves the same thing.

## Step 5 — verify

Any one of these is enough:

```bash
ykman list                # should now show +OCARD alongside +U2F
gpg --card-status         # should print a card (OpenPGP)
pcsc_scan                 # from the pcsc-tools package; should list "fapico2"
```

A helper in this repository reads the plist back rather than trusting anything hardcoded, and prints every identity pair your host can now bind:

```bash
python3 scripts/fix_usb_identity.py --list-known
```

`FA20:0002` should be in its output. OpenPGP, OATH and OTP work from here on; the edit survives driver updates only if the file you edited is the persistent copy — on Debian/Ubuntu the `/etc/libccid_Info.plist` symlink is exactly that, so a package upgrade keeps your entries; on other systems, keep the `.backup-` file and re-run Step 3 after a driver upgrade if the table was reset.

## If the reader still does not appear

Work down this list; each item is a different failure with a different fix.

1. **Is the board enumerated at all?** `lsusb` (Linux) or System Information → USB (macOS) must show `FA20:0002`. If the board is not on the USB bus, this page is not your problem — see [Troubleshooting the boot](../troubleshooting/boot.md).
2. **Did you edit the file the symlink really points to?** `readlink -f "$PLIST"` (Linux) prints it. Editing the symlink path itself works on most editors, but verify the target changed: the three entries must appear in the file `readlink -f` names.
3. **Are the three arrays still the same length?** The driver pairs `ifdVendorID[n]` with `ifdProductID[n]` and `ifdFriendlyName[n]`. One array with an extra entry can take the whole table down. Count them, or restore the backup and redo Step 3.
4. **Is the stored identity still the default?** The board's identity is runtime-writable: a board set to `2E8A:10FF` (or any other pair) needs *that* pair in the table, not `FA20:0002` — or its identity repaired back. The [USB identity how-to](./usb-identity.md) diagnoses and repairs this; a reflash does **not** undo a stored identity.
5. **Is another application holding the reader?** Some clients open an exclusive connection; close them and re-run the verify step. On Linux, if `pcscd` keeps disappearing between operations, it may be running with `--auto-exit` — making the service persistent fixes that (see the PicoForge section of the README).
6. **macOS permissions**: after editing, the file should still be owned by root with mode 644 (`sudo chmod 644 "$PLIST"; sudo chown root:wheel "$PLIST"`).
7. **PicoForge specifically shows a yellow "Online - FIDO" badge?** That is the PC/SC leg failing while FIDO works — the same allowlist fix, plus the reader-ordering note in the README, is the whole story.
