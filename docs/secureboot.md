# Enabling RP2350 signed secure boot on fapico2

This is the procedure that closes the hole the round-2 assessment opened. The
board accepted arbitrary firmware, which is how every secret on it was
recovered — see `docs/SECURITY-ASSESSMENT-ROUND2.md` §16 and §18.

There is no key material in this document. Everything below is either
produced by `build-signed.sh` or is public.

---

## What this does, and what it does not

**Does:** makes the RP2350 bootrom refuse any image not signed by the key
whose fingerprint is in OTP. Firmware substitution — the exact technique used
in the assessment — stops working.

**Does not:** stop an attacker who has the flash and can run code that
reaches the OTP. The OTP still stores the signing-key fingerprint, and §18.3
of the assessment establishes that a secret firmware must read cannot be
hidden from a same-domain attacker. Signed boot is the control that matters
because it removes that attacker's ability to *get code onto the chip* in the
first place.

It is also not a guarantee against physical attack. Errata **E16** (no
workaround) can revert `CRIT1` effects via `USB_OTP_VDD` corruption, and
**E24** (no workaround on A2/A3) achieves unsigned code execution on a
secured device via QSPI flash-swap plus a glitch. This is a strong control,
not an absolute one.

---

## What `build-signed.sh` produces

| File | What it is |
|---|---|
| `firmware/fapico2.signed.uf2` | the sealed image — **flash this** |
| `firmware/otp_config.json` | OTP rows to program: `bootkey0`, `boot_flags1.key_valid`, `crit1.secure_boot_enable` |
| `firmware/secureboot_public.pem` | the public key (safe to publish) |
| `firmware/secureboot_fingerprint.txt` | the fingerprint and what the device needs |

The fingerprint the bootrom stores is:

```
bootkey0 = SHA-256( X || Y )
```

over the **64 raw coordinate bytes** of the verifying key — note there is
**no `0x04` uncompressed-point prefix** in the hashed input. This is
non-obvious enough that `build-signed.sh` recomputes it independently and
fails the build if it disagrees with picotool's own output, because programming the
wrong value would brick the board's own firmware.

For a release, publish `secureboot_public.pem` and the fingerprint alongside
the image. Anyone can then verify the image and provision a device without
your key.

---

## Procedure

### 1. Build (signed)

```bash
./build-signed.sh
```

Use `build-signed.sh`, not `build.sh` — the plain build does not sign.
It generates `secrets/secureboot_key.pem` if absent and signs regardless. Three gates must pass or the build fails:

```
signature: verified
fingerprint cross-check OK (...)
PICOBIN block loop OK (offset 276 < 4096)
```

That third one matters more than it looks: the RP2350 bootrom only scans the
**first 4 KiB** of flash for the PICOBIN block loop. Sealing adds a metadata
block; if the loop leaves that window the image is **silently refused by
BOOTSEL** and just sits on the drive. A signed image that won't install is
worse than no signature, so the build checks it.

### 2. Flash

Hold BOOTSEL, connect, copy `firmware/fapico2.signed.uf2` to the mounted
drive. It should eject the drive when done. If it does not, stop — that is
the block-loop failure, and the image will never boot.

### 3. Program the OTP

From `firmware/otp_config.json`, write `bootkey0` and set
`boot_flags1.key_valid = 1`.

### 4. Set the fuse

**This is one-way. There is no way back.**

Set `OTP CRIT1.secure_boot_enable = 1`.

From this point the board boots **only** images signed by the key whose
fingerprint is in `bootkey0`. Consequences:

- If you lose the private key, **the board is unbootable.** Not recoverable
  by reflashing, by BOOTSEL, or by anyone.
- An image signed by any *other* key will not boot — including one you build
  later with a fresh key, and including `firmware/fapico2.uf2`.
- `firmware/fapico2.uf2` remains useful only for a board whose fuse is
  **not** set.

### 5. Verify

Rebuild and flash the signed image; it should boot. Then confirm the board
refuses an unsigned one — flash `firmware/fapico2.uf2` and check it does
**not** boot. A negative test is worth doing once: it is the only way to
confirm the fuse took, and a fuse that silently did not set leaves you with
the assessment's exposure and none of the protection.

---

## Before you do any of this

**Test on a spare Pico 2.** Walk all five steps, then set that board's fuse.
Keep the key on a different machine from the one that builds.

**Back the key up before step 4**, not after. Know where it is *before* the
fuse is set.

**Expect the unsigned path to break.** Anything in your bring-up or CI flow
that flashes `fapico2.uf2` to a provisioned board will stop working.
`./build.sh` still produces that unsigned image — it is simply the wrong
artifact for a provisioned board. That is
the point, but it will surface as a confusing "board is dead" if nobody
expects it.

**Rotation:** the RP2350 has four key slots. A new image can be signed with a
different key while older fingerprints remain accepted, which gives you an
overlap window for rotation. A leaked signing key is a fleet-wide compromise
— batch your rotations rather than doing them reactively.

---

## Key handling

`secrets/secureboot_key.pem` is git-ignored and must stay that way. But note
the honest limitation: a developer running `build-signed.sh` on a branch they just
checked out is running that code with your signing key in reach. A hardware
token, an HSM, or a dedicated signing host is the right answer for anything
you actually care about. A file in a git-ignored directory is a
convenience for development, not a key store.
