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

set -euo pipefail
cd "$(dirname "$0")"

OUT_NAME="fapico2"

# US-919 foreign-image wipe: OFF by default for a device build, and named
# here so the artefact's provenance is in the build line rather than implied
# by an omission. Set FAPICO2_FOREIGN_IMAGE_WIPE=1 in the environment to get
# the data-loss-over-implant behaviour instead. The consequence of leaving it
# off is that flashing a DIFFERENT image keeps this device's keystore rather
# than destroying it — which is what neither RS-Key nor pico-fido2 does either,
# and what the RP2350 bootrom's signed secure boot would have prevented
# outright had this board's one-way fuse been burned.
FAPICO2_FOREIGN_IMAGE_WIPE="${FAPICO2_FOREIGN_IMAGE_WIPE:-0}"
export FAPICO2_FOREIGN_IMAGE_WIPE

cargo build --release -p fapico2-firmware

ELF="target/thumbv8m.main-none-eabi/release/fapico2-firmware"
[ -f "$ELF" ] || { echo "build.sh: ELF not found at $ELF" >&2; exit 1; }

python3 firmware/uf2gen.py "$ELF" "firmware/${OUT_NAME}.uf2"
cp "$ELF" "firmware/${OUT_NAME}.elf"

echo
ls -la "firmware/${OUT_NAME}.uf2" "firmware/${OUT_NAME}.elf"
sha256sum "firmware/${OUT_NAME}.uf2"
echo "build.sh: flash firmware/${OUT_NAME}.uf2 via the mounted BOOTSEL drive"
