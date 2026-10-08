# Linux local authentication with fapico2

PAM can require the device at login: plug in, enter the PIN, touch — no password. The key is checked **first**, so a valid touch + PIN is sufficient on its own, and the password line below it is only reached without the device.

## What you need

- A fapico2 board, flashed and working, with a **FIDO2 PIN set**.
- `libpam-u2f` (provides both `pam_u2f.so` and `pamu2fcfg`):

```bash
sudo apt install libpam-u2f
```

## Register the key

```bash
sudo mkdir -p /etc/fapico2
pamu2fcfg -r -u "$USER" -N | sudo tee /etc/fapico2/u2f_mappings
```

Touch the device and enter your PIN. The mapping file records your username and the key's credential ID — one line per user. To add a second key for the same user, run `pamu2fcfg` again and append both handles on that line, comma-separated.

`-r` stores a resident (discoverable) credential on the device; `-N` skips the user-verification request during registration.

## Require the key at login

Add this to `/etc/pam.d/common-auth`, **above** the existing `pam_unix.so` line:

```text
# 1. Check FIDO2 key first
auth sufficient pam_u2f.so authfile=/etc/fapico2/u2f_mappings cue pinverification=1 nodetect
```

What the line does:

- `sufficient` — a valid touch + PIN authenticates on its own; without the device, the password is still accepted.
- `authfile=` — where the mappings live.
- `pinverification=1` — the PIN is required, so a stolen or borrowed key alone is not enough.
- `cue` — prints the touch prompt.
- `nodetect` — skips the key-presence pre-check and always runs the full authentication.

## Test it

```bash
su "$USER"        # PIN → touch
```

You should be asked for the PIN and a touch — no password.

**Keep a root shell open while you test.** A broken `common-auth` can lock you out of the machine; with a root shell open you can revert the edit. To revert, remove the line you added.

## sudo too

To require the device at `sudo` the same way, add the same line to `/etc/pam.d/sudo`. Test it with a second terminal before closing one that holds a root shell.
