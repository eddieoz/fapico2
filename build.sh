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

# US-1517: this script sets **no** identity variable, and that is the point.
# The single source of truth for the AAGUID, USB manufacturer/product and
# VID:PID is the set of DEFAULT_* constants in `platform/src/identity.rs`;
# `build-signed.sh` and `build-timeline.sh` agree, and
# `apps/fido/tests/aaguid_build.rs::no_tracked_build_script_overrides_the_identity`
# fails if any of the three ever grows an assignment.
#
# Why it is a rule and not a preference: the AAGUID is the leading 16 bytes of
# every attested credential blob, so two images built from this repository
# under two different identities are two authenticators sharing no passkeys —
# and the only record of which was which is somebody's flash log. The drift
# that prompted the rule was a git-ignored `build-custom.sh` that set
# FAPICO2_AAGUID_HEX to pico-fido2's own value; see the module docs on
# `platform::identity`.
#
# An override is still available for development, and now needs two deliberate
# variables (the build fails with one):
#
#   FAPICO2_IDENTITY_OVERRIDE_ACK=1 FAPICO2_AAGUID_HEX=89FB94B7... ./build.sh
#
# Say which identity this build will serve, before it spends a minute
# compiling one. The acknowledgement warning from `platform/build.rs` repeats
# it during the build; this line is here because it is the thing an operator
# reads when they are about to flash the result.
if [ -n "${FAPICO2_AAGUID_HEX:-}${FAPICO2_MANUFACTURER:-}${FAPICO2_PRODUCT:-}${FAPICO2_VID_PID:-}" ]; then
    echo "build.sh: IDENTITY OVERRIDE in effect — this image will NOT serve fapico2's published AAGUID." >&2
    if [ -z "${FAPICO2_IDENTITY_OVERRIDE_ACK:-}" ]; then
        echo "build.sh: ... and there is no FAPICO2_IDENTITY_OVERRIDE_ACK=1, so the build below will FAIL. That is deliberate (US-1517)." >&2
    else
        echo "build.sh:   FAPICO2_AAGUID_HEX=${FAPICO2_AAGUID_HEX:-<unset>}" >&2
        echo "build.sh:   FAPICO2_MANUFACTURER=${FAPICO2_MANUFACTURER:-<unset>} FAPICO2_PRODUCT=${FAPICO2_PRODUCT:-<unset>}" >&2
        echo "build.sh:   FAPICO2_VID_PID=${FAPICO2_VID_PID:-<unset>}" >&2
    fi
else
    echo "build.sh: identity: the published defaults in platform/src/identity.rs (fapico2's own AAGUID, board-file USB strings)"
fi

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
