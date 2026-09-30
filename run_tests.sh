#!/bin/bash
# Run fapico2 tests with the emulator

set -e

# The code under test is the tree this script lives in. Derive it from
# BASH_SOURCE (not `git rev-parse`: in a worktree .git is a file, and the parent
# of that file is the worktree root) so running this from a worktree or any
# other clone tests THAT tree. Previously this was a hardcoded
# $HOME/Projects/git/pico/fapico2, which silently ran the main checkout's tests
# and reported success.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"

# Guard against the "wrong tree, green result" failure mode: assert the resolved
# directory really is the fapico2 workspace before doing anything expensive or
# reporting on it. Re-deriving the path correctly is not enough — a future
# edit that re-hardcodes something must fail loudly here, not quietly test a
# different tree.
if [ ! -f "$ROOT/Cargo.toml" ] || ! grep -q 'name = "fapico2-fido"' "$ROOT/apps/fido/Cargo.toml" 2>/dev/null; then
    echo "ERROR: resolved root '$ROOT' is not the fapico2 workspace." >&2
    echo "       Expected: $ROOT/Cargo.toml and \$ROOT/apps/fido/Cargo.toml declaring fapico2-fido." >&2
    echo "       Refusing to run: continuing here would test a different tree and report a misleading result." >&2
    exit 1
fi

# The pytest interpreter lives in a sibling repo (pico-fido2), which this script
# cannot derive from its own location, so it is overridable — same convention
# as run_all_tests.sh's PICO_ROOT (absolute paths on this dev box, siblings in
# CI). Fail clearly here rather than with a confusing "command not found" from
# deep inside a run.
VENV=${PICO_FIDO2_VENV:-$HOME/Projects/git/pico/pico-fido2/.test-venv/bin/python}
if [ ! -x "$VENV" ]; then
    echo "ERROR: pytest interpreter not found or not executable: $VENV" >&2
    echo "       Override with PICO_FIDO2_VENV=/path/to/python (see run_all_tests.sh's PICO_ROOT convention)." >&2
    exit 1
fi

# Lint gate (FX-416): clippy must be warning-free for the fido crate.
cargo clippy -p fapico2-fido --target x86_64-unknown-linux-gnu --all-targets -- -D warnings

# Release-forbidden diagnostic gate (US-922, Phase E): the dbg-log channel
# must be impossible to enable in a release build (compile_error! guard +
# manifest reachability); emulation keeps it.
python3 tests/scripts/check_dbg_release_gate.py

# Attestation-provisioning gate (US-916, Phase C; extended by US-175, Phase I):
# per-device attestation material is minted on-device — no committed key/cert
# blobs, no compiled-in statics — and the org-attestation identity that US-175
# adds must stay separate from it, in storage, in reach, and in provisioning.
python3 tests/scripts/check_attestation_gate.py

# PicoForge-compatibility docs gate (US-164, Phase G; EPIC §8 gate 4): the
# single-reader caveat, the libccid allowlist and the AAGUID-collision note are
# operator-facing contract, not prose. This runs standalone *and* as
# tests/harness/test_docs_gate.py, because a README rewrite should not need the
# emulator to be caught.
python3 tests/scripts/check_picoforge_compat_docs.py

# One-randomness-path gate (US-1005, RS-KEY-ADOPT Phase 1): no transport may
# name a raw peripheral draw (`blocking_fill_bytes` / `EmbTrng::new` /
# `Trng::new`). Every nonce comes from `platform::trng::DrbgTrng`; the
# allowlist is the handful of bootstrap draws, each carrying its reason, and
# is short enough to read in one screen. It runs here, before the suites, so a
# bypass is reported even when a later gate is also red.
python3 tests/scripts/check_rng_path.py

# Flash-erase budget gate (US-1010, RS-KEY-ADOPT Phase 2): re-measures what
# `FlashSlotSink::program` asks the driver to erase per persist and fails while
# `docs/erase-budget.md` disagrees. It runs here, before the suites, because the
# assertion ceiling it publishes is the finding Phase 2 is scoped against — and
# because the instrument's unchanged-image control means the gate also goes red
# if the sink ever loses its compare-then-write, not only if the prose drifts.
python3 tests/scripts/check_erase_budget.py

# Red-team regression suite (US-923, Phase F): passed as a tests/harness/
# path below, or runs as part of the default pytest discovery.

# Build the emulator
cargo build -p fapico2-firmware --bin fapico2-emulation --no-default-features --features emulation --target x86_64-unknown-linux-gnu 2>&1 | tail -3

# Tests under tests/harness/ (test_restart.py, test_boot_refuse.py, ...)
# manage their OWN relay + emulator instances on DEDICATED ports (see the
# harness port map in tests/harness/ccid_relay.py) disjoint from the shared
# pair below — each suite's emulator is pointed at its private dial-in via
# FAPICO2_CCID_PORT, so they coexist with the shared instance. Skip the
# shared pair for harness-only runs anyway (nothing here needs it).
if printf '%s\n' "$@" | grep -q "tests/harness/"; then
    "$VENV" -m pytest "$@"
    exit 0
fi

# Start the CCID relay first (the emulator dials 127.0.0.1:35963 at startup)
python3 tests/harness/ccid_relay.py >/tmp/fapico2_relay.log 2>&1 &
RELAY_PID=$!

# Gate runs start from a fresh store, and the store is TWO files, not one.
#
# The secure partition: the emulator refuses to boot on a legacy-v2 / forged
# partition image by design (US-915 — refuse, never re-seed), so a stale /tmp
# partition from an older run would fail every device fixture.
#
# The keystore: `emul_main.rs:414-416` defaults it to
# `std::env::temp_dir().join("fapico2_keystore.cbor")` and deliberately
# persists it across restarts (US-322). It carries the PIN and credential
# store between emulator instances, so a second run does not start from the
# state the first one left behind.
#
# Measured 2026-09-27: with a keystore carried over from the previous run the
# pico-fido suite still reports `3 failed, 289 passed, 4 skipped` — identical
# to a clean run, and the same three known failures. So this is NOT a fix for
# an observed failure. It is hermeticity: the harness already promises a fresh
# store for one of its two persistent files, and a future test that assumes a
# fresh PIN or credential store would otherwise inherit whatever the previous
# run happened to leave. Clear it so that assumption holds by construction
# rather than by the current tests happening not to depend on it.
#
# `FAPICO2_KEYSTORE` overrides the path (FX-409), so honour it: deleting only
# the default would silently no-op under the override. The suites in
# tests/harness/ set it to a per-test `tmp_path` and manage their own state, so
# the shared pair started below is the case that matters.
KEYSTORE=${FAPICO2_KEYSTORE:-${TMPDIR:-/tmp}/fapico2_keystore.cbor}
rm -f "${TMPDIR:-/tmp}/fapico2_secure_partition.bin" "$KEYSTORE"

# The emulator dials the relay once at startup (no retry), so wait until the
# relay reports READY before launching it.
for _ in $(seq 1 50); do
    grep -q READY /tmp/fapico2_relay.log && break
    sleep 0.1
done

# Start the emulator in the background
./target/x86_64-unknown-linux-gnu/debug/fapico2-emulation &
EMULATOR_PID=$!

# Wait for the emulator to start
sleep 1

# Run the tests. Bare runs invoke pytest once per suite directory: pytest's
# conftest import is a single module name, so a full-discovery run lets
# tests/piv/conftest.py (or any sibling) shadow tests/conftest.py and break
# `from conftest import ...` in the suites (US-923 review 2026-09-24). One
# invocation per directory keeps every suite's conftest resolution correct.
# tests/hardware/ and tests/soak/ are device-only (live board / 24 h soak)
# and are not part of the emulator gate.
cleanup() {
    kill $EMULATOR_PID 2>/dev/null || true
    kill $RELAY_PID 2>/dev/null || true
}
trap cleanup EXIT

PYTEST="$VENV -m pytest"
SUITE_FAILURES=0
if [ $# -gt 0 ]; then
    # Explicit args (single file/dir): one invocation keeps the caller's
    # conftest resolution intact — do not split.
    if ! $PYTEST "$@" -q; then
        SUITE_FAILURES=1
    fi
else
    for suite in tests/pico-fido tests/piv tests/openpgp tests/harness \
                 tests/test_openpgp_genkey.py tests/test_openpgp_kdf.py \
                 tests/test_openpgp_key_import.py tests/test_openpgp_lifecycle.py \
                 tests/test_openpgp_pso.py tests/test_openpgp_security_dos.py \
                 tests/test_openpgp_verify.py; do
        if ! $PYTEST "$suite" -q; then
            SUITE_FAILURES=1
        fi
    done
fi

# Kill the emulator and the relay
cleanup

exit $SUITE_FAILURES
