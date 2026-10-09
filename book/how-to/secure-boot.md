# Signed secure boot, end to end

Signed boot makes the RP2350's bootrom refuse any image that is not signed with **your** key. Firmware substitution — the technique that recovered every secret in the [round-2 red-team assessment](https://github.com/eddieoz/fapico2/blob/main/docs/archive/SECURITY-ASSESSMENT-ROUND2.md) — stops working, because an attacker can no longer get code onto the chip. It is opt-in (`./build-signed.sh`), and parts of enabling it burn one-way fuses. Read the disclosures before the commands; the fuses do not read them back.

## What it does not do

- **It does not stop an attacker who can read the OTP itself.** The signing-key fingerprint lives in OTP, and [the threat model](../threat-model.md) lists the lab-level attacks (E16, E24) that reach it with no mitigation in current silicon. Signed boot is a strong control, not an absolute one.
- **It does not close the debug port.** These are two different fuses with two different triggers: `SECURE_BOOT_ENABLE` stops firmware substitution, and does nothing to someone attaching a debugger to your firmware. While the debug port is open — on every image published today, by [policy](https://github.com/eddieoz/fapico2/blob/main/docs/adr/0002-provisioning-policy.md) until the first `-release` tag — an attacker with a probe extracts every key the device holds, signed boot or not.
- **It does not make the board a secure element.** It raises the bar; the ceiling is on the [threat model](../threat-model.md) page.

## What is irreversible, stated plainly

- `CRIT1.secure_boot_enable` is a one-way OTP fuse. **There is no way back** — not by reflashing, not through BOOTSEL, not by anyone.
- From the moment the fuse is set, the board boots **only** images signed by the key whose fingerprint is in OTP. If you lose that private key, **the board is unbootable**, permanently.
- The plain unsigned `fapico2.uf2` stops booting on that board — including fresh builds of your own. Anything in your workflow that flashes it will surface as a confusing "board is dead". That is the control working.
- **Key rotation:** the RP2350 has four key slots, and a new image can be signed with a different key while older fingerprints remain accepted — an overlap window. A leaked signing key is a fleet-wide compromise; batch rotations rather than doing them reactively.

## Before you start

- **Use a spare Pico 2.** Walk all five steps on it, and only then set its fuse. Do not learn what step 4 feels like on the board you use daily.
- **Back the key up before the fuse, not after.** Know where `secrets/secureboot_key.pem` lives *before* `secure_boot_enable` is burned; the backup is worthless afterwards.
- **Never run this firmware with an SWD debugger attached.** A probe that runs (`probe-rs run`, `gdb … load`) makes OTP reads return garbage, and the firmware parks the board on boot. Use the probe to **read**, never to run — over BOOTSEL if you must validate.
- **A git-ignored key file is a convenience, not a key store.** Anyone who builds on that machine has the signing key in reach. A hardware token, an HSM, or a dedicated signing host is the right answer for keys that guard real boards.

## The procedure

### 1. Build signed

```bash
./build-signed.sh
```

The script generates `secrets/secureboot_key.pem` if absent (needs `picotool` on `PATH` or at `PICOTOOL=`), signs the image, and fails hard unless three gates pass:

```
signature: verified
fingerprint cross-check OK (...)
PICOBIN block loop OK (offset ... < 4096)
```

The third gate matters: the bootrom only scans the **first 4 KiB** of flash for the PICOBIN block loop, and sealing adds a metadata block — an image whose loop leaves that window is *silently refused by BOOTSEL* and just sits on the drive. A signed image that won't install is worse than no signature, so the build refuses to produce one.

Outputs: `firmware/fapico2.signed.uf2` (**this** is what you flash), `firmware/otp_config.json` (the OTP rows to program), `firmware/secureboot_public.pem` (publishable), `firmware/secureboot_fingerprint.txt`.

### 2. Flash the signed image

Hold **BOOTSEL**, connect, copy `firmware/fapico2.signed.uf2` to the mounted `RP2350` drive. The drive should eject when the write completes. **If it does not, stop** — that is the block-loop failure, and the image will never boot.

### 3. Program the key fingerprint

Write `bootkey0` and set `boot_flags1.key_valid = 1`, both from `firmware/otp_config.json`, using picotool. The fingerprint is `SHA-256` over the 64 raw coordinate bytes of the verifying key — no `0x04` uncompressed-point prefix — which is non-obvious enough that the build recomputes it independently and fails if it disagrees with picotool, because programming the wrong value bricks the board's own firmware. [The full detail](https://github.com/eddieoz/fapico2/blob/main/docs/secureboot.md) is in the repository.

At this point the board still boots anything; only the fingerprint is recorded.

### 4. Set the fuse

**This is one-way. There is no way back.**

Set `OTP CRIT1.secure_boot_enable = 1`. From this point the board boots only images signed by the key whose fingerprint is in `bootkey0`.

### 5. Verify — both directions

Rebuild and flash the signed image; it boots. Then flash the unsigned `firmware/fapico2.uf2` and confirm it **does not** boot. The negative test is the only way to confirm the fuse took: a fuse that silently failed to set leaves you with the assessment's exposure and none of the protection.

## For a release

Per [ADR 0002](https://github.com/eddieoz/fapico2/blob/main/docs/adr/0002-provisioning-policy.md), alpha and beta images keep the debug port available and burn nothing; the closure applies at the first `-release` tag. Before tagging, against a board flashed from the image being released:

```bash
./scripts/check_release_debug_state.sh --class release   # must exit 0
```

A release must read `secure boot: 1`, `debug enable: 0`, `secure debug enable: 0`. The script gates both directions — a pre-release image that reads as closed fails too.
