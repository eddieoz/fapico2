# fapico2

**The F\*\*king Authenticator.** Your passkeys, PGP keys and 2FA tokens — on hardware you own.

fapico2 turns a ~$5 [Raspberry Pi Pico 2](https://www.raspberrypi.com/products/raspberry-pi-pico-2/) into a multi-applet hardware authenticator: FIDO2/U2F passkeys, OpenPGP 3.4, OATH (TOTP/HOTP) and YubiKey-protocol OTP served by **one firmware, one binary**, over one USB composite device. No vendor account, no cloud, no subscription. Written in Rust, licensed AGPLv3, built from source — or download the alpha image below.

[![CI](https://github.com/eddieoz/fapico2/actions/workflows/ci.yml/badge.svg)](https://github.com/eddieoz/fapico2/actions/workflows/ci.yml)

## Why

- **Self-custody for credentials.** Keys are generated on the device and never leave it. Everything at rest is sealed under a root key derived from a chip-unique OTP row — a flash dump lifted off your board is inert somewhere else. The same reasoning that keeps bitcoin keys off internet-connected machines applies to the keys that guard your email, your code and your accounts.
- **The whole bill of materials is one Pico 2.** No proprietary secure element to trust, no sealed hardware to return to a vendor. If you can read this, you can rebuild the device from source.
- **No network.** The device build has no network stack at all — the only networked code in the tree is the host-side emulator used for testing.
- **Works with the tooling you already have.** Chrome, `ykman`, Yubico Authenticator and GnuPG are verified against real hardware (see the table below); the CTAP dialect targets Yubico's own client stack.
- **Replaces a drawer of tokens.** One board carries your FIDO2 passkeys, your OpenPGP identity, your TOTP codes and your YubiKey-protocol OTP slots.
- **Its failures are published.** A red-team assessment of an earlier build ships in full in this repository — the findings are more useful than the reassurance would be.

## What it does

| App | What you use it for | Transport | AID | Verified with |
|---|---|---|---|---|
| FIDO2/U2F | passkeys, WebAuthn; CTAP2.1 incl. credProtect, credMgmt, largeBlobs, hmac-secret | CTAP-HID | n/a (HID) | Chrome, python-fido2 2.2.1, ykman |
| OpenPGP 3.4 | PGP signing/encryption, SSH auth | CCID | `D2 76 00 01 24 01` | gpg / scdaemon 2.4.4 (on-card ECC key generation) |
| OATH (YKOATH) | TOTP/HOTP codes | CCID | `A0 00 00 05 27 21 01` | ykman, Yubico Authenticator |
| OTP | YubiKey-slot OTP | CCID | `A0 00 00 05 27 20 01` | ykman otp |
| Management | device config, rescue surface | CCID | `A0 00 00 05 27 47 11 17` | ykman, PicoForge |
| PIV | smartcard login | — | `A0 00 00 03 08` | **deferred — post-v1.0.0** |

Hardware acceptance was run against all three headline command sets (FIDO2/U2F, OpenPGP 3.4, OATH); the full matrix — USB IDs, algorithms, per-device results — is [`docs/hardware-matrix.md`](docs/hardware-matrix.md).

## Capacity

- **FIDO2 resident passkeys: 856** — measured to refusal on current builds (a CI test enrols until the store refuses and checks the count against the derived geometry). The `v1.0.0` release image predates the per-record store and holds a handful; capacity is a reason to track main, not a reason to trust the old image.
- **OATH credentials: 68 slots reserved** in the key store. No enrolment has been run to that boundary yet; a build whose region does not mount falls back to the legacy ceiling of 30.
- For scale: a YubiKey 5 holds 100 resident passkeys.

Every ceiling's derivation — and which numbers are measured versus reserved — is in [`docs/capacity.md`](docs/capacity.md).

## Security model, in plain terms

- **Keys are generated on the device** from the RP2350's hardware TRNG and used only there — signing happens on the chip.
- **At rest, everything is sealed.** Records are AEAD-encrypted under a root key derived from `otp_key_1` (a one-way-fused OTP row) plus the chip's own identity. The firmware **refuses to boot** if that row is unavailable — there is no public-constant fallback. A flash dump alone does not open the store; the store key is not in it.
- **One bad record is not a bad day.** The per-record store commits a single credential per write, survives torn writes, and a FIDO reset cannot take OATH's credentials with it.
- **Signed secure boot is available** (`./build-signed.sh`): the bootrom refuses unsigned images. Opt-in, and off by default in the alpha.
- What the above does *not* protect against today is the next section.

## What this is not

1. **Not safe from someone who holds it.** Until the first `vX.Y.Z-release` tag, the SWD debug port is open on every published image — deliberate, so alpha boards stay recoverable ([ADR 0002](docs/adr/0002-provisioning-policy.md)). Anyone with brief physical access and a debug probe can extract every key the device holds; while that port is open, every other control is a delay, not a barrier ([`docs/debug-access-risk.md`](docs/debug-access-risk.md)). Until it closes, this is evaluation hardware: do not make it the only key to anything.
2. **Not independently audited.** The published [red-team assessment](docs/SECURITY-ASSESSMENT-ROUND2.md) is of an earlier build; some of it has been addressed, not all. No warranty.
3. **Not certified and not ruggedized.** No FIPS/Common Criteria evaluation, and no NFC — a Pico 2 has no radio.
4. **Not anonymously attributable.** Default builds carry a public development attestation key, so their attestation proves nothing about key provenance.
5. **Not finshed on every front.** PIV is deferred; Brainpool P-384r1 is absent from OpenPGP; CTAP1/U2F register attestation fails client-side verification (CTAP2 is unaffected); a known RSA timing advisory (RUSTSEC-2023-0071) has no upstream fix ([`docs/supply-chain.md`](docs/supply-chain.md)).

## Getting started

**0. What you need:** one Raspberry Pi Pico 2 (RP2350). That is the whole shopping list.

**1. Get an image.** Either download the prebuilt [`fapico2.uf2`](https://github.com/eddieoz/fapico2/releases) from the alpha release (sha256 in its release notes) or build from source — see [For developers](#for-developers). A first build takes tens of minutes on Linux/macOS/WSL.

**2. Flash it.** Hold **BOOTSEL**, plug the board in, copy the UF2 onto the `RP2350` drive that mounts, and wait — re-enumeration can take up to a minute and that is normal. The Rust build supports **physical BOOTSEL** only (hold BOOTSEL while plugging in, or BOOTSEL + tap RESET); the C firmware additionally accepts a programmatic rescue APDU via `scripts/bootsel.py`. Full procedure, both firmwares, recovery paths: [`docs/bootsel.md`](docs/bootsel.md).

**3. Use it.** The board enumerates as `fa20:0002` "fapico2", a composite CCID + CTAP-HID device. FIDO2 works everywhere, immediately. **Linux/macOS only:** OpenPGP and OATH need a one-time libccid allowlist edit — without it your host sees *no smartcard reader at all*, which looks like broken hardware and is not. See [`docs/identity.md`](docs/identity.md#pcsc-allowlist-libccid).

## USB identity (provisional)

The firmware enumerates as **`fa20:0002`** — manufacturer "The BLOCO Community", product "fapico2". `0xFA20` is **not** a USB-IF-registered vendor ID, so this identity is provisional: production needs a registered VID, and until then Linux and macOS need the libccid `Info.plist` allowlist edited before `pcscd` sees the CCID reader (CTAP-HID is unaffected everywhere). The procedure is in [`docs/identity.md`](docs/identity.md#pcsc-allowlist-libccid).

AAGUID, USB strings and VID:PID are one build-time identity block (`platform/src/identity.rs`); every override requires an explicit acknowledgement or the build hard-fails — an image cannot quietly serve a different identity from the rest of the checkout. The identity is also **runtime-writable** from the token itself, and a stored value wins over the build-time default: **only pick a VID/PID pair your host's CCID driver knows.** A pair it does not know silently disables OpenPGP/OATH while FIDO keeps working — nothing looks broken, and reflashing does not undo it. Diagnose and repair with `scripts/fix_usb_identity.py`; the mechanism is in [`docs/identity.md`](docs/identity.md#the-vidpid-is-writable-at-runtime-and-a-value-libccid-does-not-know-is-a-silent-lockout).

## PicoForge compatibility

PicoForge's PC/SC client takes the **first** reader `list_readers()` returns — never iterating, filtering by name, or falling back to a second (`picoforge/src/hal/transport/pcsc.rs:37-43`, identically `ccid.rs:38-42`). Where another PC/SC reader is enumerated first, every SELECT — Rescue, vendor LED, Management — goes to the **wrong card**, answers `6A82`, and the client returns `Err("Rescue Applet not found...")` rather than `None` (`pcsc.rs:66-71`): the token is healthy and the client simply talked to a different card. `write_led_config` opens a **fresh PC/SC connection per LED slot** (`picoforge/src/hal/io.rs:199-205`), so the same misordering yields a **silently half-written LED profile with every call reporting success**.

**Mitigation is client-side: keep the token as the only reader on the host, or report this upstream — it is not fixable from the firmware**, since nothing in the image changes which reader the client picks. The `0xFA20` / `0x0002` `libccid_Info.plist` allowlist in [USB identity](#usb-identity-provisional) is a `pcscd` gate, so it binds any PC/SC application, not just PicoForge.

### AAGUID note

fapico2's default AAGUID is **fapico2's own** (`66617069636F3200…0002`, ASCII `fapico2`) rather than the borrowed RS-Key `2479C7BF6B3056839EC80E8171A918B7` (risk R-3's borrow is over) — but until PicoForge adds it to `firmwares/mod.rs`, a default build is **unclassifiable by the app** and lands on the pico-fido profile. Flash with `FAPICO2_IDENTITY_OVERRIDE_ACK=1 FAPICO2_AAGUID_HEX=2479C7BF6B3056839EC80E8171A918B7` to test PicoForge features — the acknowledgement is required, so an override cannot arrive by accident. The block's `DEFAULT_AAGUID` rules and the one-way-door warning live in `platform/src/identity.rs` and [`docs/identity.md`](docs/identity.md).

## Migration from the C firmware

On the first boot after cutover from the C `pico-fido2` firmware, the Rust image detects the C data partition and **re-seeds the Rust keystore from it** (read-only, idempotent).

- **Silent (no user input):** FIDO keydev + resident credentials, OATH credentials, OTP slots, Management config, PIV objects (re-seeded, serving deferred), OpenPGP public keys / certs / DOs / PIN hashes.
- **One-time PW1/PIN step:** OpenPGP **private keys** and PIN-wrapped FIDO keydevs need the passphrase **once**; a wrong passphrase returns `NEEDS_PASSPHRASE` (constant-time) and the C retry counters are untouched.
- **Not migratable:** the vendor ChaChaPoly keydev.

Byte formats and per-class verdicts: [`us413-migration-feasibility.md`](docs/migration-feasibility.md).

## For developers

```bash
# Device build (release firmware, size-gate + defmt path) -> RP2350 ELF
cargo build --release --target thumbv8m.main-none-eabi

# Host tests (the workspace default target is the device one; override it)
cargo test --target x86_64-unknown-linux-gnu --exclude fapico2-firmware

# Emulation: CCID + HID over TCP sockets, driving the same app stacks
cargo build -p fapico2-firmware --no-default-features --features emulation

# Lint
cargo clippy --target x86_64-unknown-linux-gnu --exclude fapico2-firmware --all-targets -- -D warnings
cargo clippy --target thumbv8m.main-none-eabi -- -D warnings
```

The device build links an `arm-none-eabi` ELF gated at `text` ≤ 3.5 MiB (CI-enforced, measured against the C baseline in [`docs/size-report.md`](docs/size-report.md)). The image is trimmed via cargo features, not code edits: `emulation` swaps the transports for host TCP sockets, and per-app features mean an app crate absent from the firmware's device list is absent from the ELF. `./build.sh` produces `firmware/fapico2.uf2` through `firmware/uf2gen.py` (plain `elf2uf2` output silently does nothing on this bootrom).

**Testing** is three layers: host unit tests; the *same* black-box pytest suites that gate the C build (`tests/pico-fido/`, `tests/openpgp/`, `tests/harness/`) over the emulator; and the hardware matrix. `./run_tests.sh` runs clippy + gates + pytest. Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md); CI gates: `.github/workflows/ci.yml`.

## Documentation

[`docs/INDEX.md`](docs/INDEX.md) maps everything, but the short list:

- **Start here:** USB identity and the host allowlist — [identity.md](docs/identity.md) · what fits — [capacity.md](docs/capacity.md) · flashing and recovery — [Getting started](#getting-started) above
- **Trust it:** [`SECURITY.md`](SECURITY.md) · [`docs/debug-access-risk.md`](docs/debug-access-risk.md) · [`docs/supply-chain.md`](docs/supply-chain.md) · [ADRs](docs/adr/README.md)
- **Client behaviour:** [`docs/hardware-matrix.md`](docs/hardware-matrix.md) · [`docs/client-compatibility.md`](docs/client-compatibility.md)
- **Design records and past investigations:** [`docs/INDEX.md`](docs/INDEX.md) → the archive

## License and security

GNU AGPLv3 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

**Not independently audited; no warranty is offered.** Read [`SECURITY.md`](SECURITY.md) before trusting this with anything you cannot afford to lose, and report vulnerabilities there rather than in a public issue.
