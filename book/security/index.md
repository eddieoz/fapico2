# Security

## The model, in plain terms

- **Keys are generated on the device** from the RP2350's hardware TRNG and used only there — signing happens on the chip.
- **At rest, everything is sealed.** Records are AEAD-encrypted under a root key derived from `otp_key_1` (a one-way-fused OTP row) plus the chip's own identity. The firmware **refuses to boot** if that row is unavailable — there is no public-constant fallback. A flash dump alone does not open the store; the store key is not in it.
- **One bad record is not a bad day.** The per-record store commits a single credential per write, survives torn writes, and a FIDO reset cannot take OATH's credentials with it.
- **No network.** The device build has no network stack at all — nothing to attack remotely, no channel to exfiltrate through.

## The decisions that matter

1. **The store key is derived from one-way-fused silicon, never stored.** An attacker who dumps the flash has ciphertext and no key. The firmware parks the board rather than falling back to a public constant.
2. **One credential per write.** Every record is committed on its own, so a torn write or a corrupt byte costs one credential, not the whole set — and a neighbour's update never touches the other credentials in its sector.
3. **Applet isolation in the store.** FIDO, OATH, PIV and OpenPGP share one key hierarchy but scoped writes: a FIDO reset wipes FIDO's sectors and nothing else.
4. **PIN and touch are always required on a PIN-set board.** Nothing in the WebAuthn options can switch either off. A stolen key alone opens nothing; a stolen key plus a stolen laptop still needs the PIN.
5. **Signed secure boot is opt-in** (`./build-signed.sh`): the bootrom refuses unsigned images — a one-way OTP fuse, burned once, at your decision.
6. **The debug port closes at the first release tag.** Alpha and beta images keep SWD open so boards stay recoverable; `-release` images are the boundary where it stops.

## Practices

- **Encrypt directly to the recipient.** Instead of a note, a screenshot and trusting the channel — encrypt it with the PGP key that never leaves the device. The message is unreadable to everyone but the holder of the other key.
- **Keep passkeys on hardware, not in someone's cloud.** A passkey synced to a phone vendor's account lives on every device signed into it. A resident passkey on fapico2 exists on one board you own.
- **Keep TOTP codes off the online machine.** The authenticator app on the phone that reads your mail shares one compromise domain. The codes on the offline board do not.
- **Require the PIN everywhere.** Create SSH keys with `-O verify-required` and log in with `pinverification=1` — the device asks every time, and a borrowed key is not enough.
- **Travel with the device, not with key files.** Resident credentials re-download to any machine with `ssh-keygen -K`; a key-handle file left on a laptop is a pointer, not a secret.

## What this is not

1. **Not safe from someone who holds it.** Until the first `vX.Y.Z-release` tag, the SWD debug port is open on every published image. Anyone with brief physical access and a debug probe can extract every key the device holds; while that port is open, every other control is a delay, not a barrier. Do not make it the only key to anything. The [threat model](../threat-model.md) covers what else is possible against the chip itself.
2. **Not independently audited.** A [red-team assessment](https://github.com/eddieoz/fapico2/blob/main/docs/SECURITY-ASSESSMENT-ROUND2.md) of an earlier build is published in full in the repository — some of it has been addressed, not all. No warranty is offered.
3. **Not certified, and no NFC.** No FIPS/Common Criteria evaluation, and a Pico 2 has no radio.

## Reporting vulnerabilities

Report vulnerabilities privately — see [`SECURITY.md`](https://github.com/eddieoz/fapico2/blob/main/SECURITY.md). Do not open public issues for security reports.
