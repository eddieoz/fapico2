# `secrets/` — signed-boot key material

This directory is **git-ignored except for this README**. Nothing you put
here should ever be committed. If you add real key files and `git status`
still shows them, stop and fix the ignore rule before doing anything else.

## Why this exists

RP2350 signed secure boot is enforced by the **bootrom**: a signing-key
fingerprint is programmed into OTP, and `CRIT1.SECURE_BOOT_ENABLE` is a
**one-way fuse**. Without it, any image boots — which is exactly how
`redteam/` recovered every key on the assessment board (see
`docs/archive/SECURITY-ASSESSMENT-ROUND2.md` §16).

## Two build scripts, and which to use

| Script | What it does |
|---|---|
| `./build.sh` | the original **unsigned** build. No key, no `picotool`, nothing to think about. |
| `./build-signed.sh` | the **signed** build. Generates a key here if absent, seals the image, gates it. Use this when the artifact is going anywhere real. |

Both are maintained and neither calls the other. If you do not want a
signing key on your machine, use `./build.sh` and accept that the image is
unsigned.

## You do not have to create the key

`build-signed.sh` generates one for you on the first run if `secrets/` is
empty, and signs either way. This project is open source and people are
expected to build their own firmware, so "no key yet" must never quietly
mean "unsigned" — that is the state the assessment broke.

To bring your own, or to use one you already trust:

```bash
mkdir -p secrets
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 \
  -out secrets/secureboot_key.pem
chmod 600 secrets/secureboot_key.pem
```

`build-signed.sh` reads `secrets/secureboot_key.pem` by default; override the
path with `SECUREBOOT_KEY=/path/to/key.pem ./build-signed.sh`.

**Use EC or RSA.** `picotool` does not accept Ed25519 ("only RSA and EC are
supported") and fails with an unhelpful error.

### What a locally generated key means

It is **your** key, not the project's. An image you build will only boot on
a device whose OTP holds *your* fingerprint — the one in
`secrets/otp_config.json` that the build produces. That is the intended
behaviour: a self-hosted build, signed by you, for hardware you own.

## What lands here

| File | |
|---|---|
| `secureboot_key.pem` | the private key — **never committed** |
| `secureboot_public.pem` | public key; safe to publish |
| `otp_config.json` | OTP rows to program (`bootkey0`, `boot_flags1.key_valid`, `crit1.secure_boot_enable`) |
| `secureboot_fingerprint.txt` | the fingerprint, how it is derived, and the exact rows the device needs |

The public key, OTP config and fingerprint are **not secret** — they are a
public fingerprint. They are co-located with the private key on purpose: a
stale fingerprint beside a new public key is exactly how you brick a board
with its own firmware. They are git-ignored because `build-signed.sh`
auto-generates a per-developer key; a **release** should publish them
deliberately alongside the image.

`build-signed.sh` independently recomputes the fingerprint and **fails the
build** if it disagrees with `picotool`. The derivation is
`SHA-256(X || Y)` over the raw coordinates — no `0x04` prefix — which is
non-obvious enough to be worth a gate.

## The full enablement procedure

Flash, program the OTP, set the one-way fuse, and verify with a negative
test — step by step in [`docs/secureboot.md`](../docs/secureboot.md). Read it
before setting the fuse; that step is irreversible.

## Opting out

`./build-signed.sh --no-sign` builds the unsigned image only. It is there for
recovering a device whose fuse is already set, and for debugging. Do not
mistake it for a release build.

## Before you set the fuse

1. **The fuse is one-way.** There is no way back. If you enable secure boot
   and lose the private key, **the board is unbootable** — unrecoverable,
   not a reflash.
2. **Test on a spare Pico 2 first**, keeping the key on a different machine
   from the one that builds. Walk the whole flow before doing it to a board
   with keys on it.
3. **Back the key up somewhere you will not lose it**, and know where it is
   *before* the fuse is set.
4. **Rotate with the 4 OTP key slots.** A new image can be signed with a
   different key while the old one is still accepted. A leaked key is a
   fleet-wide compromise — batch your rotations.

## A note on where the key should live

Ideally the private key should not sit on the same machine that builds
untrusted pull requests. A developer running `build-signed.sh` on a branch
they just checked out is running that code with your signing key in reach. A
hardware token, an HSM, or a dedicated signing host is the right answer for
anything you actually care about. This directory is a convenience for
development and small fleets, not a production key store.
