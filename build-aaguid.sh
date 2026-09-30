#!/usr/bin/env bash
# Build the fapico2 RP2350 (Pico 2) device firmware and stage the
# artifacts in firmware/.
#
# The staged UF2 is a `firmware/uf2gen.py` product — the only format the
# RP2350 bootrom actually installs over BOOTSEL MSC (plain elf2uf2-rs
# output silently does nothing: it lacks picotool's RP2350-E10 absolute
# preamble and the PICOBIN partition-table embed — found on hardware,
# US-924 D-phase 2026-09-24). Copy firmware/<out>.uf2 into the mounted
# BOOTSEL drive to flash; never raw-write the block device.
# 2479c7bf-6b30-5683-9ec8-0e8171a918b7

set -euo pipefail
cd "$(dirname "$0")"

OUT_NAME="fapico2"

FAPICO2_AAGUID_HEX=2479C7BF6B3056839EC80E8171A918B7 cargo build --release -p fapico2-firmware

ELF="target/thumbv8m.main-none-eabi/release/fapico2-firmware"
[ -f "$ELF" ] || { echo "build.sh: ELF not found at $ELF" >&2; exit 1; }

python3 firmware/uf2gen.py "$ELF" "firmware/${OUT_NAME}.uf2"
cp "$ELF" "firmware/${OUT_NAME}.elf"

echo
ls -la "firmware/${OUT_NAME}.uf2" "firmware/${OUT_NAME}.elf"
sha256sum "firmware/${OUT_NAME}.uf2"
echo "build.sh: flash firmware/${OUT_NAME}.uf2 via the mounted BOOTSEL drive"
