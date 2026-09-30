#!/bin/bash
# US-385 — 24-h soak runner.
#
# Builds the emulator (emu transport), frees any *leaked* emulator from a prior
# run, then runs the soak and reports. All arguments pass through to soak.py:
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

# --- free leaked emulators from a prior run ---------------------------------
# The emulator's TCP ports (HID 35962 / CCID 35963) are hardcoded, so a leaked
# instance blocks the next soak. Kill ONLY orphaned ones (PPID=1: their
# controlling shell is gone — a leak), never a live process.
for pid in $(pgrep -f 'fapico2-emulation|fapico2/build/pico_fido2' 2>/dev/null); do
  ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
  if [ "$ppid" = "1" ]; then
    kill "$pid" 2>/dev/null && echo ">> killed orphaned (leaked) emulator pid $pid"
  fi
done
sleep 1

echo "======================================================================"
echo " US-385 soak"
echo "   interpreter : $PYTHON"
echo "   command     : soak.py $*"
echo "======================================================================"
exec "$PYTHON" "$SOAK/soak.py" "$@"
