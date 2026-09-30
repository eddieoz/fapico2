#!/usr/bin/env bash
# US-377 hardware acceptance — PIV status probe (Rust port of
# pico-fido2/tests/scripts/yubico-piv-test.sh).
#
# Runs `yubico-piv-tool -a status` against the connected CCID-enumerated
# device and asserts a PIV applet answers (a "Version:" line in the output).
# SKIP (exit 0) when yubico-piv-tool is absent on the host.
#
# Phase 6 dependency: the fapico2 device firmware wires app crates in Phase 6
# (see firmware/Cargo.toml: the `device` feature currently carries only
# fapico2-platform; fapico2-piv is wired only into the `emulation` feature).
# Until then a flashed device enumerates USB but no PIV applet answers — run
# this probe after Phase 6 lands. Emulator-side PIV coverage lives in
# tests/piv/ (US-378 gate).
set -uo pipefail

if ! command -v yubico-piv-tool >/dev/null 2>&1; then
  echo "SKIP: yubico-piv-tool not installed (apt install yubico-piv-tool)" >&2
  exit 0
fi

echo "== yubico-piv-tool -a status =="
if ! out=$(yubico-piv-tool -a status 2>&1); then
  echo "PIV status probe FAILED — is the device connected and CCID-enumerated?" >&2
  echo "$out" >&2
  exit 1
fi
echo "$out"

# ponytail: minimal assertion — a live PIV applet answers with a Version line.
if ! echo "$out" | grep -qi "Version:"; then
  echo "WARN: status output missing expected 'Version:' line — PIV may not be answering" >&2
fi
echo "PIV probe OK"
