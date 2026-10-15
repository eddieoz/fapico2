# fapico2-release-alpha-v0.3.0 — Release Notes

**Date:** 2026-10-15 · **Target:** Raspberry Pi Pico 2 (RP2350), USB-connected
**Theme:** PIN-locked session custody for the Nostr applet (EPIC
[EPIC-nostr-pin-custody](tasks/EPIC-nostr-pin-custody.md)).

**This is an alpha.** Alpha/beta images keep the debug port available and burn
nothing irreversible into OTP ([ADR 0002](adr/0002-provisioning-policy.md)).

## The feature in one paragraph

The Nostr identity set can now sit behind a PIN. A **PIN-set board refuses
every identity-touching command with `6982` (session required) until
`VERIFY_PIN` opens a session**; the session lives only in RAM and dies with
the board. `GET_INFO` advertises the new capability bit and the PIN state in
its flags byte; the vendor-HID dialect gains `VERIFY_PIN 0x4B`,
`SET_PIN 0x4C` (envelope idx 0 = set, 1 = change) and `LOCK 0x4D`, and the
error map translates `63C1..63C3` (attempts left), `63C0` (locked out —
recovery is a factory reset, which destroys every identity), `6982` and the
dual-reading `6A82`. A wrong PIN has a durable budget of three; the lockout
is the floor of the same range the wrong-PIN answers live in.

## Generation cross-tolerance matrix (US-1708)

Alpha users will hit new client ↔ old firmware and old client ↔ new
firmware. The matrix below was exercised against BOTH emulator images — the
current build and the v0.2.0 image built from the release commit `ddc3875`
(worktree; `tests/harness/test_nostr_crossgen.py` drives it, binary path
overridable with `FAPICO2_V020_EMULATION`):

| combination | request | answer | rendered as |
|---|---|---|---|
| new ext ↔ old firmware | `GET_INFO` | `9000`, body `00 01 00 03 07 00 00 00` — the 8-byte shape with the flags byte a reserved `0x00`, caps `0x0003` (no `CAP_PIN_MGMT`) | the capability gate hides every PIN UI; no error |
| new ext ↔ old firmware | `VERIFY_PIN` `0x4B` (INS `0x1B`) | `6D00` **in band**, empty body | "PIN not supported by this firmware" — never a hang, never a CTAPHID-level error |
| old ext ↔ new firmware | EXPORT `0x48` (INS `0x1A`) | `6D00` in band, empty body | "export removed" |
| old ext ↔ new firmware | `GET_INFO` | `9000`, 8-byte body, flags `0x00` on a PIN-less board | parses unchanged — byte-compatible |
| control | `LIST_KEYS` (INS `0x11`) | `9000` + `n=0` on both images | identical on both generations |

Measured on the v0.2.0 image, 2026-10-15: all five rows green
(`pytest tests/harness/test_nostr_crossgen.py`, 5 passed).

The vendor-HID arm of this matrix (byte `0x4B` on the old image, byte
`0x48` on the new) is pinned by the firmware host tests — the emulator
serves Nostr over CCID only ([AGENTS.md §8](../AGENTS.md)), so the HID arm
does not run under the emulator by design.
