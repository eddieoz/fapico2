#!/usr/bin/env python3
"""dbg-log release-forbidden gate for US-922 (EPIC SEC-HARDEN Phase E).

Host-only, stdlib only (no third-party imports; python >= 3.9). TDD
red/green gate:

  red   = the release profile can enable the `dbg-log` diagnostic feature
          (the feature builds cleanly under `--release`), so the fixed-
          channel CTAP-HID log drain (dbg.rs, vendor cmd 0x42) can ship in
          a production binary
  green = two defenses hold:
          1. manifest — `dbg-log` is reachable only through an explicit
             `--features dbg-log` (never via `default`/`device`/
             `emulation`, so no ordinary release invocation picks it up);
          2. build assertion — `cargo check --lib --release --features
             dbg-log` FAILS with the US-922 `compile_error!` guard
             (firmware/src/lib.rs, wired by firmware/build.rs from the
             cargo PROFILE), so even the explicit invocation is refused.

  positive control — emulation keeps the ability: `cargo check --lib
  --release --no-default-features --features emulation,dbg-log` must
  SUCCEED (host builds have no device USB surface to protect).

Exit status: 0 when all checks hold (green), 1 otherwise (red, with a
per-check report).

Usage:
    python3 tests/scripts/check_dbg_release_gate.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# fapico2/tests/scripts/check_dbg_release_gate.py -> parents[2] == fapico2/
REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "firmware" / "Cargo.toml"

HOST_TARGET = "x86_64-unknown-linux-gnu"

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"  [FAIL] {msg}")


def ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def feature_ref(feat: str) -> str:
    """The feature a manifest entry enables: `"f/x"` enables `f` too."""
    return feat.split("/")[0].strip().strip('"')


def feature_list(manifest: str, name: str) -> list[str]:
    """Extract the (possibly multiline) `name = [...]` feature array."""
    m = re.search(rf"^{re.escape(name)}\s*=\s*\[(.*?)\]\s*$", manifest, re.M | re.S)
    if not m:
        return []
    return [feature_ref(f) for f in m.group(1).split(",") if f.strip()]


def cargo(args: list[str]) -> tuple[bool, str]:
    """Run a cargo check; return (succeeded, stderr tail)."""
    cmd = ["cargo", "check", "--quiet", "-p", "fapico2-firmware",
           f"--target={HOST_TARGET}"] + args
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    return proc.returncode == 0, (proc.stderr or "")[-2000:]


# --- check 5 (structural): a feature that fills the ring can drain it ----
#
# `mod dbg` decides whether the RAM ring exists. The `DBG_CMD` dispatch in
# `tasks.rs` decides whether anything can read it back. Those are two
# separate `#[cfg]` attributes in two files, and nothing in the type system
# connects them.
#
# The failure this catches is silent and total. A feature that names itself
# in `mod dbg` and in the `dlog!` arms compiles perfectly, the ring fills
# with exactly the records the capture build exists to collect, and the
# drain command falls through to the FIDO dispatcher, which answers a
# one-byte unknown-command error on EVERY channel. From the host the only
# visible symptom is a pull script reporting "wrong cid" for a device whose
# cid is correct — which is exactly what happened the first time the
# `boot-timeline` image was flashed, and cost a hardware cycle to find.
#
# So: the two cfg feature sets must be EQUAL. A feature in one and not the
# other is either a ring nobody can read or a drain for a ring that is not
# there, and both are wrong.

RING_MOD_RE = re.compile(
    r'#\[cfg\((any\()([^\]]*?)\)\)\]\s*\n\s*mod\s+dbg\s*;')
DRAIN_RE = re.compile(
    r'#\[cfg\((any\()([^\]]*?)\)\)\]\s*\n\s*if\s+cmd\s*==\s*'
    r'crate::dbg::DBG_CMD')


def _cfg_features(blob: str) -> set[str]:
    return set(re.findall(r'feature\s*=\s*"([a-z0-9-]+)"', blob))


def check_ring_is_drainable(root: Path) -> None:
    main_rs = (root / "firmware" / "src" / "main.rs").read_text(encoding="utf-8")
    tasks_rs = (root / "firmware" / "src" / "tasks.rs").read_text(encoding="utf-8")

    m = RING_MOD_RE.search(main_rs)
    if not m:
        fail("could not find the `mod dbg;` declaration in firmware/src/main.rs —"
             " this gate cannot verify the ring is drainable, and a gate that"
             " cannot check its own subject is not a gate")
        return
    d = DRAIN_RE.search(tasks_rs)
    if not d:
        fail("could not find the `DBG_CMD` dispatch in firmware/src/tasks.rs —"
             " same reason: the check below would be vacuous")
        return

    ring = _cfg_features(m.group(2))
    drain = _cfg_features(d.group(2))
    if ring == drain:
        ok(f"ring features == drain features ({', '.join(sorted(ring))}) —"
           " every feature that allocates the ring can also read it back")
    else:
        only_ring = sorted(ring - drain)
        only_drain = sorted(drain - ring)
        fail(f"the RAM ring and its drain are gated on different features.\n"
             f"        in `mod dbg` only (ring exists, unreachable): {only_ring}\n"
             f"        in the `DBG_CMD` dispatch only: {only_drain}\n"
             "        A build in the first group compiles, fills the ring, and"
             " answers every drain with a one-byte unknown-command error.")



def main() -> int:
    print(f"US-922 dbg-log release gate ({REPO_ROOT})\n")

    # --- check 1: manifest reachability ---------------------------------
    manifest = MANIFEST.read_text(encoding="utf-8")
    implicit = ["default", "device", "emulation"]
    found: list[str] = []
    for feat in implicit:
        if "dbg-log" in feature_list(manifest, feat):
            found.append(feat)
    if found:
        fail(f"dbg-log is an implicit member of: {', '.join(found)}"
             " — an ordinary release invocation would enable it")
    else:
        ok("dbg-log is not in default/device/emulation (explicit --features only)")

    # --- check 2: build assertion (release + dbg-log must be refused) ---
    held, stderr = cargo(["--release", "--lib", "--features", "dbg-log"])
    if held:
        fail("cargo check --release --features dbg-log SUCCEEDED —"
             " the release profile can enable the debug channel"
             " (US-922 compile_error! guard missing or bypassed)")
    elif "US-922" not in stderr:
        fail("cargo check --release --features dbg-log failed, but NOT via the"
             f" US-922 guard (unrelated build error?):\n{stderr}")
    else:
        ok("release + dbg-log refused by the US-922 compile_error! guard")

    # --- check 3: plain release build is healthy -------------------------
    # An implicit dbg-log leak (check 1's blind spot is covered there, but
    # this is the belt to those braces) would make the PLAIN release build
    # fail on the US-922 guard — the gate must notice that, not just the
    # explicit `--features dbg-log` invocation.
    held, _ = cargo(["--release", "--lib"])
    if held:
        ok("plain `cargo check --release` builds (no implicit dbg-log leak)")
    else:
        fail("plain `cargo check --release` FAILED — the release build is"
             " broken (suspect an implicit dbg-log leak)")

    # --- check 4: positive control (emulation keeps the ability) --------
    held, _ = cargo(
        ["--release", "--lib", "--no-default-features",
         "--features", "emulation,dbg-log"])
    if held:
        ok("emulation + release + dbg-log still builds (host builds keep it)")
    else:
        fail("emulation + release + dbg-log failed to build —"
             " the US-922 guard is over-broad")

    # --- check 5: structural, reachability (see the helper) --------------
    check_ring_is_drainable(REPO_ROOT)

    print()
    if failures:
        n = len(failures)
        print(f"RESULT: FAIL ({n} check(s) — dbg-log is not release-closed)")
        return 1
    print("RESULT: PASS (dbg-log is release-forbidden; emulation keeps it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
