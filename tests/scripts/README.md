# tests/scripts — hardware acceptance probes

- `yubico-piv-test.sh` (US-377): runs `yubico-piv-tool -a status` against the
  connected device and asserts a PIV applet answers (a `Version:` line).
  Exits 0 with `SKIP:` when `yubico-piv-tool` is not installed on the host.

**When it will actually pass:** only after Phase 6 lands the device app wiring —
today the `device` feature (see `firmware/Cargo.toml`) carries only
`fapico2-platform`, so a flashed device enumerates USB but no PIV applet
answers. Emulator-side PIV coverage lives in `tests/piv/` (US-378 gate).

**Host requirement:** `yubico-piv-tool` (apt: `yubico-piv-tool`).
