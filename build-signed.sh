#!/usr/bin/env bash
# Build the fapico2 RP2350 (Pico 2) device firmware AND seal it for RP2350
# signed secure boot, staging the artifacts in firmware/ and secrets/.
#
# This is the secure-capable build. The plain unsigned build lives in
# ./build.sh and is unchanged — use it when you do not want a signing key on
# the machine, and use this one when the image is going anywhere real.
#
# The staged UF2 is a `firmware/uf2gen.py` product — the only format the
# RP2350 bootrom actually installs over BOOTSEL MSC (plain elf2uf2-rs
# output silently does nothing: it lacks picotool's RP2350-E10 absolute
# preamble and the PICOBIN partition-table embed — found on hardware,
# US-924 D-phase 2026-09-24). Copy firmware/<out>.uf2 into the mounted
# BOOTSEL drive to flash; never raw-write the block device.
#
# Why two scripts
# --------------
# ./build.sh is the original unsigned build: no key, no picotool, nothing to
# think about. This one is for when the artifact matters. Both are maintained;
# neither calls the other.
#
# SIGNED BUILD (RP2350 signed secure boot, red-team round 2 §18)
# ------------------------------------------------------------
# The assessment board accepted arbitrary firmware, which is how every
# secret was recovered (docs/SECURITY-ASSESSMENT-ROUND2.md §16). The fix is
# the bootrom's own signed secure boot. This script signs the image when —
# and only when — a key is present:
#
#   secrets/secureboot_key.pem   the private key (git-ignored; see
#                                secrets/README.md for how to create it)
#
# Signing happens AFTER uf2gen.py, because only uf2gen products install.
#
# This project is open source and people are expected to build their own
# firmware, so signing CANNOT be gated behind a key someone has to already
# have — that would just mean every contributor and every CI run silently
# produces an unsigned image, which is precisely the state the assessment
# broke (docs/SECURITY-ASSESSMENT-ROUND2.md §16). So:
#
#   no key  ->  build.sh GENERATES one (EC secp256k1) and signs anyway
#
# Outputs:
#   firmware/fapico2.signed.uf2    SEALED — the release artifact, flash this
#   firmware/fapico2.uf2           unsigned base, kept for recovery/debug
#   firmware/fapico2.elf           the linked image
#
#   The key and everything derived from it are co-located in secrets/ so
#   they cannot drift apart — a stale fingerprint next to a new public key
#   is exactly how you brick a board with its own firmware:
#     secrets/secureboot_key.pem         private, never committed
#     secrets/secureboot_public.pem      public
#     secrets/otp_config.json            OTP rows to program
#     secrets/secureboot_fingerprint.txt the fingerprint + what the device needs
#
# A locally generated key is YOUR key, not the project's: an image you build
# will only boot on a device whose OTP holds YOUR fingerprint. That is the
# intended behaviour for a self-hosted build.
#
# Env:
#   SECUREBOOT_KEY   path to the signing key (default secrets/secureboot_key.pem)
#   PICOTOOL         path to picotool (default: found on PATH, then ~/.pico-sdk)
#
# Flags:
#   --no-sign    build the unsigned image only (explicit opt-out; for
#                recovery and debugging a device whose fuse is already set)

set -euo pipefail
cd "$(dirname "$0")"
# Announce ourselves by our actual filename, not a hardcoded one.
SELF="$(basename "$0")"

OUT_NAME="fapico2"
KEY="${SECUREBOOT_KEY:-secrets/secureboot_key.pem}"
OTP_CONFIG="secrets/otp_config.json"
PUBKEY_PEM="secrets/secureboot_public.pem"
FP_TXT="secrets/secureboot_fingerprint.txt"
DO_SIGN=1

for arg in "$@"; do
    case "$arg" in
        --no-sign) DO_SIGN=0 ;;
        -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
        *) echo "$SELF: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# --- locate picotool ------------------------------------------------------
# Signing is done by picotool (it owns the RP2350 block format and the
# bootrom's signature scheme). Signing is pointless with a different tool, so
# we never silently skip it: a missing picotool is a hard error.
find_picotool() {
    if [ -n "${PICOTOOL:-}" ]; then echo "$PICOTOOL"; return 0; fi
    if command -v picotool >/dev/null 2>&1; then command -v picotool; return 0; fi
    for c in "$HOME"/.pico-sdk/picotool/*/picotool/picotool /usr/local/bin/picotool; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    return 1
}

# --- build ----------------------------------------------------------------
cargo build --release -p fapico2-firmware

ELF="target/thumbv8m.main-none-eabi/release/fapico2-firmware"
[ -f "$ELF" ] || { echo "$SELF: ELF not found at $ELF" >&2; exit 1; }

python3 firmware/uf2gen.py "$ELF" "firmware/${OUT_NAME}.uf2"
cp "$ELF" "firmware/${OUT_NAME}.elf"

SIGNED_UF2=""

if [ "$DO_SIGN" -eq 0 ]; then
    cat >&2 <<EOF

  ${SELF}: --no-sign — producing an UNSIGNED image.
  Any firmware will boot on it. This is only for recovery/debugging a
  device whose CRIT1.SECURE_BOOT_ENABLE fuse is already set.

EOF
elif [ ! -f "$KEY" ]; then
    # Auto-provision. Never let "I don't have a key" mean "unsigned".
    mkdir -p "$(dirname "$KEY")"
    if command -v openssl >/dev/null 2>&1; then
        # EC/RSA only — picotool rejects Ed25519. secp256k1 is what the
        # RP2350 bootrom signature scheme is built around.
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 \
            -out "$KEY" 2>/dev/null
        chmod 600 "$KEY"
        cat >&2 <<EOF

  ${SELF}: no signing key at $KEY — generated one.
            This key is yours alone; it is git-ignored and never committed.
            An image you build will only boot on a device whose OTP holds
            YOUR fingerprint (firmware/otp_config.json).
            See secrets/README.md.

EOF
    else
        echo "$SELF: no openssl to generate a key, and none at $KEY." >&2
        echo "           Install openssl, supply SECUREBOOT_KEY, or pass" >&2
        echo "           --no-sign if you really want an unsigned image." >&2
        exit 3
    fi
fi

if [ "$DO_SIGN" -eq 1 ] && [ -f "$KEY" ]; then
    PICOTOOL_BIN="$(find_picotool)" || {
        echo "$SELF: found $KEY but no picotool." >&2
        echo "           Install it, or set PICOTOOL=/path/to/picotool." >&2
        echo "           Re-run with --no-sign if that is intended." >&2
        exit 3
    }
    if [ -n "${PICOTOOL_BIN:-}" ]; then
        # A key readable by everyone defeats the point of having one.
        KEY_MODE="$(stat -c '%a' "$KEY")"
        if [ "$KEY_MODE" != "600" ] && [ "$KEY_MODE" != "400" ]; then
            echo "$SELF: WARNING $KEY is mode $KEY_MODE (expected 600)." >&2
        fi

        echo "$SELF: sealing with $KEY"
        # picotool treats the <otp> argument as "edit this JSON if it already
        # exists" — so a leftover or truncated file makes it fail with an
        # opaque JSON parse error. Start from a clean slate every build.
        rm -f "$OTP_CONFIG"
        # picotool rejects Ed25519; EC/RSA only. Fail loudly rather than
        # emit an image that silently is not signed.
        if ! "$PICOTOOL_BIN" seal \
                "firmware/${OUT_NAME}.uf2" \
                "firmware/${OUT_NAME}.signed.uf2" \
                "$KEY" "$OTP_CONFIG" \
                --sign --hash; then
            echo "$SELF: seal FAILED." >&2
            echo "           Ed25519 keys are not supported by picotool —" >&2
            echo "           use EC (secp256k1) or RSA. See secrets/README.md." >&2
            exit 4
        else
            SIGNED_UF2="firmware/${OUT_NAME}.signed.uf2"

            # Publishable copies of everything the OTP step needs. The
            # private key stays in secrets/; these are derived from it and
            # are public by definition, but they are per-key so they are
            # generated rather than committed.
            openssl pkey -in "$KEY" -pubout -out "$PUBKEY_PEM" 2>/dev/null || true
            # Independently recompute the fingerprint picotool just wrote and
            # cross-check it. If these ever diverge, the OTP step would
            # program a value the bootrom does not expect and the board would
            # refuse its own firmware — a provisioning brick that is easy to
            # miss and very annoying to debug.
            FPR="$(python3 firmware/bootkey_fp.py "$PUBKEY_PEM" 2>/dev/null || true)"
            BOOTKEY0="$(python3 -c 'import json,sys;print("".join("%02x"%b for b in json.load(open("'"$OTP_CONFIG"'")).get("bootkey0",[])))' 2>/dev/null || true)"
            if [ -n "$FPR" ] && [ -n "$BOOTKEY0" ] && [ "$FPR" != "$BOOTKEY0" ]; then
                echo "$SELF: FAIL computed fingerprint != picotool bootkey0" >&2
                echo "           computed: $FPR" >&2
                echo "           picotool: $BOOTKEY0" >&2
                echo "           Programming OTP from otp_config.json would brick" >&2
                echo "           the board's own firmware. Not continuing." >&2
                exit 8
            fi
            if [ -n "$FPR" ]; then
                echo "$SELF: fingerprint cross-check OK (${FPR:0:16}...)"
            fi
            {
                echo "# RP2350 signed-secure-boot material for THIS key"
                echo "# Regenerated by build.sh on every signed build."
                echo "#"
                echo "# Public key:        $PUBKEY_PEM"
                echo "# Image:             firmware/fapico2.signed.uf2"
                echo "# OTP rows to write: $OTP_CONFIG"
                echo
                echo "## Fingerprint derivation"
                echo "  bootkey0 = SHA-256( X || Y )   <- 64 raw coordinate bytes,"
                echo "            NO 0x04 uncompressed-point prefix."
                echo "  Cross-checked against picotool's otp_config.json at build time."
                echo
                echo "## What the device needs"
                echo "  1. flash  firmware/fapico2.signed.uf2"
                echo "  2. write  firmware/otp_config.json  -> OTP"
                echo "           (bootkey0 = the fingerprint above,"
                echo "            boot_flags1.key_valid = 1)"
                echo "  3. set    OTP CRIT1.secure_boot_enable = 1"
                echo "           *** ONE-WAY FUSE — no way back ***"
                echo "           A board with this set will NOT boot an image"
                echo "           signed by any other key."
                echo
                echo "## This key's fingerprint (bootkey0, as written to OTP)"
                echo "  ${FPR:-<not computed>}"
                echo
                echo "  Derived as SHA-256(X || Y) over the raw coordinates of"
                echo "  secureboot_public.pem."
            } > "$FP_TXT"

            # Gate 1: the signature must actually verify.
            if ! "$PICOTOOL_BIN" info -m "$SIGNED_UF2" 2>/dev/null | grep -q "signature: *verified"; then
                echo "$SELF: signed image did not report 'signature: verified'." >&2
                exit 5
            fi

            # Gate 2: the RP2350 bootrom only scans the FIRST 4 KiB of flash
            # for the PICOBIN block loop. Sealing adds a metadata block and
            # moves the chain; if the loop leaves that window the image is
            # silently refused by BOOTSEL (the US-924 D1 failure mode). This
            # is the single most valuable check in the script.
            #
            # picotool prints XIP addresses (0x10000114), so compare the
            # flash-relative offset against 0x1000 — comparing the raw
            # address would reject every image.
            if [ -n "$SIGNED_UF2" ]; then
                BLOCK1="$("$PICOTOOL_BIN" info -m "$SIGNED_UF2" 2>/dev/null \
                          | awk '/Metadata Block 1/{f=1} f&&/address:/{print $NF; exit}')"
                BLOCK1="${BLOCK1#0x}"
                if [ -z "$BLOCK1" ]; then
                    echo "$SELF: could not locate Metadata Block 1 — cannot check" >&2
                    echo "           the PICOBIN scan window. Verify by hand." >&2
                else
                    OFF=$(( 0x$BLOCK1 - 0x10000000 ))
                    if [ "$OFF" -lt 0 ] || [ "$OFF" -ge 4096 ]; then
                        echo "$SELF: FAIL Metadata Block 1 at 0x$BLOCK1 (flash" >&2
                        echo "           offset $OFF) is outside the 4 KiB bootrom" >&2
                        echo "           scan window; BOOTSEL would refuse it." >&2
                        exit 6
                    else
                        echo "$SELF: PICOBIN block loop OK (offset $OFF < 4096)"
                    fi
                fi
            fi
        fi
    fi
fi

# --- summary --------------------------------------------------------------
echo
ls -la "firmware/${OUT_NAME}.uf2" "firmware/${OUT_NAME}.elf" ${SIGNED_UF2:+"$SIGNED_UF2"} 2>/dev/null
echo
sha256sum "firmware/${OUT_NAME}.uf2" ${SIGNED_UF2:+"$SIGNED_UF2"} 2>/dev/null
echo
if [ -n "$SIGNED_UF2" ]; then
    echo "$SELF: FLASH $SIGNED_UF2   <-- signed"
    echo "         program the OTP from $OTP_CONFIG, then set"
    echo "         CRIT1.SECURE_BOOT_ENABLE (ONE-WAY fuse)."
    echo "         ${OUT_NAME}.uf2 is kept unsigned as a recovery path only."
else
    echo "$SELF: flash firmware/${OUT_NAME}.uf2  (UNSIGNED)"
fi
