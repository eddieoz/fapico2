#!/bin/bash
# Run OpenPGP-suite tests against the fapico2 (Rust) emulation binary.
#
# Usage: ./run_openpgp_tests.sh [pytest args...]
#   e.g. ./run_openpgp_tests.sh tests/openpgp/001_initial_check/ -q
#
# Starts the CCID relay + emulation binary, runs pytest, tears down.
set -e

# Code under test = the tree this script lives in (BASH_SOURCE, not
# `git rev-parse`: a worktree's .git is a file, and the parent of that file is
# the worktree root). `cd "$(dirname "$0")"` was relative, so it broke when
# invoked as a bare name / via a relative path from elsewhere.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"

# Guard against silently testing a different tree and reporting success.
if [ ! -f "$ROOT/Cargo.toml" ] || ! grep -q 'name = "fapico2-fido"' "$ROOT/apps/fido/Cargo.toml" 2>/dev/null; then
    echo "ERROR: resolved root '$ROOT' is not the fapico2 workspace." >&2
    echo "       Expected: $ROOT/Cargo.toml and \$ROOT/apps/fido/Cargo.toml declaring fapico2-fido." >&2
    echo "       Refusing to run: continuing here would test a different tree and report a misleading result." >&2
    exit 1
fi

# The pytest interpreter lives in the sibling pico-fido2 repo, so it cannot be
# derived from this script's location; override it the same way run_all_tests.sh
# overrides PICO_ROOT. Fail clearly instead of deep inside a run.
VENV=${PICO_FIDO2_VENV:-$HOME/Projects/git/pico/pico-fido2/.test-venv/bin/python}
if [ ! -x "$VENV" ]; then
    echo "ERROR: pytest interpreter not found or not executable: $VENV" >&2
    echo "       Override with PICO_FIDO2_VENV=/path/to/python (see run_all_tests.sh's PICO_ROOT convention)." >&2
    exit 1
fi

cargo build -p fapico2-firmware --bin fapico2-emulation --no-default-features --features emulation --target x86_64-unknown-linux-gnu

CCID_PORT=${FAPICO2_CCID_PORT:-35963}
RELAY_LOG=/tmp/fapico2_relay.log
EMUL_LOG=/tmp/fapico2_emul.log

# A stale emulator left over from an earlier run holds 35963. The one we start
# below then dies on AddrInUse, and pytest silently drives the *stale* binary —
# reporting a full suite of results for code that is not on disk. That failure
# is invisible in the pytest output, so refuse to start instead.
if ss -ltn 2>/dev/null | grep -q ":$CCID_PORT"; then
    echo "ERROR: port $CCID_PORT is already listening before this run started." >&2
    echo "       A stale fapico2-emulation or ccid_relay is holding it; pytest would" >&2
    echo "       silently test that stale binary instead of the one just built." >&2
    echo "       Find it with:  ss -ltnp | grep $CCID_PORT" >&2
    echo "       Then kill it, or re-run with FAPICO2_CCID_PORT=<free port>." >&2
    exit 1
fi

rm -f /tmp/fapico2_openpgp_keystore
: >"$RELAY_LOG"
python3 tests/harness/ccid_relay.py --ccid-port "$CCID_PORT" >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!
# The emulator dials the relay once at startup — make sure the relay is bound first.
for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ":$CCID_PORT" && break; sleep 0.1; done
FAPICO2_KEYSTORE=/tmp/fapico2_openpgp_keystore FAPICO2_CCID_PORT="$CCID_PORT" \
    ./target/x86_64-unknown-linux-gnu/debug/fapico2-emulation >"$EMUL_LOG" 2>&1 &
EMU_PID=$!
trap 'kill $EMU_PID $RELAY_PID 2>/dev/null || true' EXIT

# Wait for the emulator to actually attach to *this* relay, rather than
# sleeping a fixed interval and hoping. Dying is the common case (AddrInUse,
# a bad keystore) and must be reported here, not as 179 mystery timeouts later.
emulator_connected=0
for _ in $(seq 1 100); do
    if ! kill -0 "$EMU_PID" 2>/dev/null; then
        echo "ERROR: fapico2-emulation exited during startup." >&2
        sed -n '1,20p' "$EMUL_LOG" >&2
        exit 1
    fi
    if grep -q "emulator connected" "$RELAY_LOG" 2>/dev/null; then
        emulator_connected=1
        break
    fi
    sleep 0.1
done
if [ "$emulator_connected" -ne 1 ]; then
    echo "ERROR: fapico2-emulation is running but never attached to the relay on $CCID_PORT." >&2
    exit 1
fi

# Default to the whole OpenPGP suite only when the caller named no test path.
# Passing a path used to be *appended* to tests/openpgp/, so narrowing the run
# silently widened it — a 470s full-suite run where a 1-test run was asked for.
#
# A "test path" is a non-option argument that names something on disk. Testing
# `$#` instead would read `-q` as a path and hand pytest the whole tests/ tree,
# which fails collection in tests/piv and tests/openpgp/020_kdffull. Testing
# "any non-option argument" instead would read `-k test_verify` the same way,
# since the value of `-k` is not itself an option.
have_path=0
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        *)
            # Strip a pytest node id's `::Class::test` tail before testing for
            # existence: `path/to/f.py::test_name` is not itself a file.
            probe="${arg%%::*}"
            if [ -e "$probe" ]; then have_path=1; break; fi
            ;;
    esac
done
if [ "$have_path" -eq 0 ]; then
    set -- tests/openpgp/ "$@"
fi
"$VENV" -m pytest "$@"
