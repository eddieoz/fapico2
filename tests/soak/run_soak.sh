#!/bin/bash
# US-385 — 24-h soak runner.
#
# Builds the emulator (emu transport), then runs the soak and reports. All
# arguments pass through to soak.py:
#
#   ./run_soak.sh                                   24-h emu soak (default)
#   ./run_soak.sh --max-cycles 200                  short emu verification
#   ./run_soak.sh --duration-hours 1                1-h emu soak
#   ./run_soak.sh --transport usb --firmware-elf X  24-h bench run on RP2350 HW
#
# PICO_ROOT (default: two dirs up) is the dir that holds fapico2/ and
# pico-fido2/, matching run_all_tests.sh. SOAK_PYTHON overrides the interpreter
# (default: the test venv, which has python-fido2).
set -uo pipefail

# Resolve paths from this script's own location (works from any CWD):
#   <pico>/fapico2/tests/soak/run_soak.sh  ->  FAPICO2 = two up,  ROOT = three up.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FAPICO2=$(cd "$SCRIPT_DIR/../.." && pwd)
ROOT=${PICO_ROOT:-$(cd "$FAPICO2/.." && pwd)}
SOAK=$FAPICO2/tests/soak
EMU_BIN=$FAPICO2/target/x86_64-unknown-linux-gnu/debug/fapico2-emulation
PYTHON=${SOAK_PYTHON:-$ROOT/pico-fido2/.test-venv/bin/python}
[ -x "$PYTHON" ] || PYTHON=python3

# --- emu transport: build the emulator if it's not there yet ----------------
# (the usb transport needs a separately built device ELF, not the emulator)
if [ "${1:-}" != "--transport" ]; then
  if [ ! -x "$EMU_BIN" ]; then
    echo ">> building fapico2-emulation (emu transport) ..."
    (cd "$FAPICO2" && cargo build --bin fapico2-emulation \
        --no-default-features --features emulation \
        --target x86_64-unknown-linux-gnu) || { echo ">> emulator build failed"; exit 2; }
  fi
fi

# --- run the soak; cleanup touches only PIDs THIS script spawned -------------
# EPIC HW-LANE-CONSENT US-1905: the old pre-run block pattern-pkilled
# 'fapico2-emulation|fapico2/build/pico_fido2', which also killed the SHARED
# emulator that other suites keep running. Killing by name is gone entirely:
# cleanup below is scoped to the PIDs this run recorded spawning — the soak
# process ($SOAK_PID, captured with $!) and, while it is still alive so they
# are still attributable to it, its own children (the emulator / probe-rs
# relay soak.py started).
"$PYTHON" "$SOAK/soak.py" "$@" &
SOAK_PID=$!

on_signal() {
  # Snapshot the soak's live children BEFORE killing it: once the soak
  # process dies, its children reparent to init and can no longer be
  # attributed to this run.
  local kids
  kids=$(ps -o pid= --ppid "$SOAK_PID" 2>/dev/null | tr -d ' \t')
  [ -n "$kids" ] && kill $kids 2>/dev/null
  kill "$SOAK_PID" 2>/dev/null
  # Wait for the recorded PIDs to actually go, then force any straggler.
  for pid in $kids "$SOAK_PID"; do
    for _ in 1 2 3 4 5; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    kill -9 "$pid" 2>/dev/null
  done
}
trap on_signal INT TERM

wait "$SOAK_PID"
status=$?
trap - INT TERM
exit "$status"
