#!/bin/bash
# Pre-push parity check — the local half of what CI fails on.
#
# WHY THIS EXISTS (docs/ci-evaluation-2026-11.md, cause #1 and #2)
# ------------------------------------------------------------------
# The three things that most often turn a green-looking PR red on GitHub are
# exactly the three this tree's own local loop (run_tests.sh) never exercises:
#
#   1. the flash-budget ratchet  — "shipping UF2 exceeds the N KiB ratchet"
#   2. the task-arena stamp      — the demand constant's fingerprint over the
#                                  firmware source closure, staled by ANY edit
#                                  under firmware/ (comment-only edits included)
#   3. the device-side size gates — text/bss budgets over the release ELF
#
# run_tests.sh (by design) runs host tests + emulator suites only; build.sh
# builds the device image but gates nothing. A push in between costs a 12-minute
# CI round trip to learn what this script says in two.
#
# Usage:
#   scripts/pre_push_check.sh            # --quick (default, ~2 min, no device build)
#   scripts/pre_push_check.sh --quick    # same
#   scripts/pre_push_check.sh --full     # adds the device build + size/ratchet
#                                        # gates + the emulator suites (~10 min
#                                        # cold, minutes warm)
#
# The ratchet arithmetic below mirrors ci.yml's device job (US-1043) on
# purpose: the same UF2, the same ceiling, the same comparison — so a --full
# pass here means the device job's ratchet step passes there. The one thing it
# does NOT replicate is the reproducible-build double build (a second full
# release build from a copied tree); run one locally when touching anything
# build-nondeterministic, or let CI say so.

set -e

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if [ ! -f "$ROOT/Cargo.toml" ] || ! grep -q 'name = "fapico2-fido"' "$ROOT/apps/fido/Cargo.toml" 2>/dev/null; then
    echo "ERROR: resolved root '$ROOT' is not the fapico2 workspace." >&2
    exit 1
fi

MODE=quick
if [ "${1:-}" = "--full" ]; then
    MODE=full
elif [ -n "${1:-}" ] && [ "$1" != "--quick" ]; then
    echo "usage: $0 [--quick|--full]" >&2
    exit 2
fi

FAILED=0
check() {
    echo ""
    echo "== $* =="
    if ! "$@"; then
        echo "PRE-PUSH CHECK FAILED at: $*" >&2
        FAILED=1
    fi
}

echo "=== pre-push parity check ($MODE) on $ROOT ==="

# --- 1. Task-arena stamp (no build, no nightly) — cause #2 ----------------
# Any edit under the firmware source closure stales this. CI's boot-chain
# gate fails on it; this catches it in ~1 s.
check python3 tests/scripts/measure_task_arena.py --check

# --- 2. Structural gates that are plain python3 over the checkout ---------
# The same list ci.yml's gates-py job runs (US-1042), so a gate red here is a
# red there.
for g in \
    tests/scripts/check_flash_budget.py \
    tests/scripts/check_acceptance_exit_code.py \
    tests/scripts/check_boot_clock_order.py \
    tests/scripts/check_dbg_release_gate.py \
    tests/scripts/check_debug_strip.py \
    tests/scripts/check_foreign_image_wipe.py \
    tests/scripts/check_led_polarity.py \
    tests/scripts/check_otp_provisioning_precondition.py \
    tests/scripts/check_picoforge_compat_docs.py \
    tests/scripts/check_readme.py \
    tests/scripts/check_release_notes.py \
    tests/scripts/check_us413_feasibility.py \
    tests/scripts/check_heap_gate.py \
    tests/scripts/check_persist_gate.py \
    tests/scripts/check_attestation_gate.py \
    tests/scripts/check_rng_path.py
do
    check python3 "$g"
done

# --- 3. clippy — the workspace lint gate (host target) --------------------
check cargo clippy --workspace --target x86_64-unknown-linux-gnu --exclude fapico2-firmware --all-targets -- -D warnings

# --- 4. --full: the device-side gates that need a build -------------------
if [ "$MODE" = full ]; then

    # text/bss budgets over the rebuilt ELF (US-382/1010). This step BUILDS
    # the release image (cargo build --release --target thumbv8m...) — that
    # is the ~minutes cost of --full.
    check python3 tests/scripts/check_size_report.py

    # Flash-budget ratchet (US-1043): the same arithmetic as ci.yml's device
    # job — UF2 size vs FIRMWARE_FLASH_BUDGET_KIB. The budget is read from
    # ci.yml's env line (the same line CI itself uses).
    echo ""
    echo "== flash-budget ratchet (US-1043, mirrored from ci.yml) =="
    BUDGET_KIB=$(grep -E '^[[:space:]]+FIRMWARE_FLASH_BUDGET_KIB:' "$ROOT/.github/workflows/ci.yml" | tail -1 | awk '{print $2}')
    if [ -z "$BUDGET_KIB" ]; then
        echo "PRE-PUSH CHECK FAILED: could not read FIRMWARE_FLASH_BUDGET_KIB from ci.yml" >&2
        FAILED=1
    else
        ELF=target/thumbv8m.main-none-eabi/release/fapico2-firmware
        if [ ! -f "$ELF" ]; then
            echo "PRE-PUSH CHECK FAILED: $ELF missing (check_size_report should have built it)" >&2
            FAILED=1
        else
            python3 firmware/uf2gen.py "$ELF" /tmp/fapico2-prepush.uf2 >/dev/null
            SHIPPING=$(stat -c %s /tmp/fapico2-prepush.uf2)
            BUDGET_BYTES=$(( BUDGET_KIB * 1024 ))
            echo "shipping UF2 = ${SHIPPING} B ($(( SHIPPING / 1024 )) KiB), ratchet ${BUDGET_KIB} KiB"
            if [ "$SHIPPING" -gt "$BUDGET_BYTES" ]; then
                echo "PRE-PUSH CHECK FAILED: shipping UF2 ${SHIPPING} B exceeds the ${BUDGET_KIB} KiB (${BUDGET_BYTES} B) ratchet." >&2
                echo "  Raise it deliberately: python3 tests/scripts/raise_flash_budget.py <new KiB> --reason \"...\"" >&2
                echo "  (or shrink the growth — the ratchet doing its job)" >&2
                FAILED=1
            fi
        fi
    fi

    # The emulator suites, as the pytest-gate job runs them.
    check ./run_tests.sh --suites-only
fi

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "=== RESULT: FAIL — push would go red on at least one gate above ==="
    exit 1
fi
echo "=== RESULT: PASS — the gates above are the ones CI would run ==="
exit 0
