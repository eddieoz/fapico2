#!/bin/bash
# Phase 3 integration gate (US-360): run every Phase 3 suite against ONE Rust
# emulation binary in a single job.
#
# Model: build the emulator once, then run each suite against its own fresh
# instance of that binary (isolated — one suite's failure never cascades into
# another). Per-suite PASS/FAIL is reported; the gate exits non-zero if any
# suite fails so CI turns red until the firmware is fully ported.
#
# Suites:
#   oath-otp  cargo host unit tests (fapico2-oath covers OATH + OTP) + platform
#             (dispatcher / US-359 app-switching parity). No emulator needed.
#   fido      pico-fido2/tests/pico-fido   (pytest, HID transport)
#   openpgp   pico-fido2/tests/openpgp     (pytest, CCID transport)
#   merged    pico-fido2/tests/merged      (pytest, interleaved cross-app)
#
# Usage: ./run_all_tests.sh [suite...]   # e.g. ./run_all_tests.sh fido openpgp
set -uo pipefail

# ROOT is overridable so the same script works on this dev box (absolute paths)
# and in CI (both repos checked out as siblings under $GITHUB_WORKSPACE).
ROOT=${PICO_ROOT:-$HOME/Projects/git/pico}
FAPICO2=$ROOT/fapico2
TESTS=$ROOT/pico-fido2/tests
VENV=$ROOT/pico-fido2/.test-venv/bin/python
EMU_BIN=$FAPICO2/target/x86_64-unknown-linux-gnu/debug/fapico2-emulation

pass=0
fail=0
declare -a failed_suites=()
lint_ok=true

cleanup() {
    # Kill any stray emulator/relay left running from a previous invocation.
    pkill -f 'fapico2-emulation' 2>/dev/null || true
    pkill -f 'pico-fido2/build/pico_fido2' 2>/dev/null || true
    pkill -f 'ccid_relay.py' 2>/dev/null || true
}
trap cleanup EXIT

run_suite() {
    local name="$1"; shift
    echo ""
    echo "============================================================"
    echo "== SUITE: $name"
    echo "============================================================"
    if "$@" >>"/tmp/fapico2_gate_${name}.log" 2>&1; then
        echo ">>> RESULT $name: PASS"
        pass=$((pass + 1))
    else
        echo ">>> RESULT $name: FAIL  (tail -> /tmp/fapico2_gate_${name}.log)"
        tail -n 15 "/tmp/fapico2_gate_${name}.log"
        failed_suites+=("$name")
        fail=$((fail + 1))
    fi
}

# --- 0. lint gate (FX-416): clippy must be warning-free for the fido crate ---
# Reported as a precondition; it is orthogonal to US-360's five-suite metric, so
# a pre-existing clippy failure here does not mask suite pass/fail below.
echo ""
echo "============================================================"
echo "== PRECONDITION: clippy -D warnings (fapico2-fido)"
echo "============================================================"
if cargo clippy --manifest-path "$FAPICO2/Cargo.toml" \
        -p fapico2-fido --target x86_64-unknown-linux-gnu --all-targets -- -D warnings \
        >>"/tmp/fapico2_gate_lint.log" 2>&1; then
    echo ">>> CLIPPY: PASS"
else
    echo ">>> CLIPPY: FAIL (see /tmp/fapico2_gate_lint.log)"
    tail -n 12 "/tmp/fapico2_gate_lint.log"
    lint_ok=false
fi

# --- 1. build the emulation binary ONCE ---
echo ""
echo "============================================================"
echo "== BUILD: fapico2-emulation (host target)"
echo "============================================================"
cargo build --manifest-path "$FAPICO2/Cargo.toml" \
    --bin fapico2-emulation --no-default-features --features emulation \
    --target x86_64-unknown-linux-gnu || { echo "BUILD FAILED"; exit 1; }

# The merged suite's EmulatorSession locates the binary at <cwd>/build/pico_fido2
# (cwd == $TESTS while pytest runs), so install it there.
mkdir -p "$TESTS/build"
cp "$EMU_BIN" "$TESTS/build/pico_fido2"
chmod +x "$TESTS/build/pico_fido2"

# --- 2. cargo host unit tests (OATH + OTP + platform) ---
run_suite "oath-otp-platform" \
    bash -c "cd '$FAPICO2' && cargo test --target x86_64-unknown-linux-gnu -p fapico2-oath -p fapico2-platform"

# --- 3. pytest suites, each against its own emulator instance ---
run_suite "fido" \
    bash -c "cd '$TESTS' && '$VENV' -m pytest pico-fido/ -q"
run_suite "openpgp" \
    bash -c "cd '$TESTS' && '$VENV' -m pytest openpgp/ -q"
run_suite "merged" \
    bash -c "cd '$TESTS' && '$VENV' -m pytest merged/ -q"

# --- 4. summary ---
echo ""
echo "============================================================"
echo "== PHASE 3 GATE SUMMARY"
echo "============================================================"
echo "Clippy (FX-416): $([ "$lint_ok" = true ] && echo PASS || echo 'FAIL - precondition')"
echo "Suites passed: $pass    failed: $fail"
if [ "$fail" -ne 0 ]; then
    echo "Red suites: ${failed_suites[*]}"
    echo "See /tmp/fapico2_gate_*.log for per-suite detail."
    echo "(US-360 goal: all five suites green vs one Rust emulation binary.)"
    exit 1
fi
echo "ALL SUITES GREEN"
exit 0
