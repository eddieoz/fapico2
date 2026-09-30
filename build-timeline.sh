#!/usr/bin/env bash
# Build the `boot-timeline` capture image — a RELEASE-profile device firmware
# carrying the US-922 RAM event ring and the `E_PHASE` boot-boundary markers,
# and nothing else.
#
# Staged as firmware/fapico2.timeline.uf2. Flash it over BOOTSEL, let the
# device enumerate, then drain the ring over CTAP-HID:
#
#   python3 tests/scripts/pull_boot_timeline.py --cid 7b07b007
#
# Why this exists and why it is not ./build.sh + dbg-log
# ------------------------------------------------------
# The question is "where does the 22 s / 30 s / >90 s first boot go?", and the
# measurement has to come off an image that differs from the shipping one as
# little as possible. Two things rule out the obvious tool:
#
#   1. `dbg-log` is debug-profile-only (US-922), and a **dev-profile device
#      image does not boot at all** — US-932, 10/10 + 11/11 + 1/1 repros,
#      every miss before `main()`. An instrumented build that dark-boots
#      cannot time a boot.
#   2. A debug image is 3.5 MB and reaches 0x101AE700, which **overwrites
#      ~706 KB of the trussed littlefs2 window** (0x102000..0x202000, blocks
#      0 and 1 included) and so manufactures a `Filesystem::format` that the
#      release image never performs. The instrument would create the very
#      cost centre it is looking for.
#
# So this is `--release` with one extra feature. Unlike `apdu-trace` it does
# NOT pull in `apdu_trace`, so the ring cannot record APDU bytes — VERIFY /
# CHANGE REFERENCE DATA carry PIN material in the clear (see the apdu-trace
# warning in firmware/Cargo.toml). Boot phase ids and timestamps only.
#
# The drain channel is pinned, not per-boot random: reading a per-boot channel
# needs an RTT attach through the probe, and **attaching a probe during boot is
# the trap documented in AGENTS.md** — it makes every OTP read return
# 0xFFFFFFFF and the boot then dies in `fatal_boot` on a key row it can read
# perfectly well unattached. Draining over CTAP-HID after enumeration never
# touches the probe.
#
# This is a capture build. It is not a shipping configuration; reflash
# firmware/fapico2.uf2 when the capture is done.

set -euo pipefail
cd "$(dirname "$0")"

# Named for the wipe setting, not for the script. Two capture images that
# differ only in one cfg are exactly the pair you do NOT want to
# disambiguate by memory before flashing — the whole experiment rests on
# knowing which of the two is on the board.
WIPE="${FAPICO2_FOREIGN_IMAGE_WIPE:-0}"
OUT_NAME="fapico2.timeline.w${WIPE}"

# US-919: the wipe arm is chosen HERE, and the two settings produce two
# images that differ in manifest hash — which is exactly the experiment.
# Flashing either over a store stamped with a third image's hash makes one
# of them take the WipeAndFresh arm and the other the Load arm, and both
# are readable by the same ring. `WIPE=${FAPICO2_FOREIGN_IMAGE_WIPE:-0}`
# builds the shipping default; `WIPE=1 ./build-timeline.sh` builds the
# wipe arm.
export FAPICO2_FOREIGN_IMAGE_WIPE="$WIPE"
echo "build-timeline.sh: FAPICO2_FOREIGN_IMAGE_WIPE=$WIPE (1 = wipe a foreign image, 0 = admit it)"

cargo build --release -p fapico2-firmware --features boot-timeline

ELF="target/thumbv8m.main-none-eabi/release/fapico2-firmware"
[ -f "$ELF" ] || { echo "build-timeline.sh: ELF not found at $ELF" >&2; exit 1; }

python3 firmware/uf2gen.py "$ELF" "firmware/${OUT_NAME}.uf2"
cp "$ELF" "firmware/${OUT_NAME}.elf"

echo
ls -la "firmware/${OUT_NAME}.uf2" "firmware/${OUT_NAME}.elf"
sha256sum "firmware/${OUT_NAME}.uf2"
echo
echo "build-timeline.sh: flash firmware/${OUT_NAME}.uf2 over BOOTSEL, then"
echo "  python3 tests/scripts/pull_boot_timeline.py --cid 7b07b007"
echo "build-timeline.sh: this is a capture image — reflash firmware/fapico2.uf2 after."
