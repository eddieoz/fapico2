#!/usr/bin/env python3
"""Re-measure the Embassy task-arena demand and stamp it into `firmware/src/lib.rs`.

What this replaces (US-964)
---------------------------
The demand used to be a number someone copied out of one
`RUSTFLAGS=-Zprint-type-sizes cargo +nightly build` by hand, into a comment,
with a "re-measure whenever a spawned task's future grows" instruction nobody
could fail. `check_boot_chain.py` compared that number against the ELF and
published a headroom figure from it. The measurement is now a command:

    python3 tests/scripts/measure_task_arena.py [--check]

* without `--check` it runs the measurement, rewrites the constant, the
  per-task table in the doc comment and the stamp in `firmware/src/lib.rs`;
* with `--check` it recomputes the stamp only and exits non-zero if the
  constant in the tree is not the one the current sources measure to — the
  same check `check_boot_chain.py` makes, runnable without a build.

The stamp (`tests/scripts/arena_stamp.py`) is what makes the number
non-stale: the gate refuses to report headroom from a demand whose
measurement inputs have moved, and says so instead of passing.

Requires a nightly toolchain — `-Zprint-type-sizes` has no stable equivalent,
and the futures' types are anonymous (`{async fn body of …}`), so their sizes
are not readable from the ELF on stable. That is why the stamp-and-fail
approach is used rather than a compile-time re-derivation.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from arena_stamp import (  # noqa: E402  (path set up above)
    DEMAND_CONST,
    FIRMWARE_PACKAGE,
    STAMP_CONST,
    dependency_closure,
    fingerprint,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
LIB = ROOT / "firmware/src/lib.rs"
TARGET = "thumbv8m.main-none-eabi"

# `print-type-size type: `embassy_executor::raw::TaskPool<{async fn body of
# tasks::__ccid_task_task()}, 1>`: 8600 bytes, alignment: 8 bytes`
#
# Anchored on the bare `embassy_executor::raw::TaskPool<` so the wrappers the
# same monomorphisation appears inside — `MaybeUninit<…>`,
# `ManuallyDrop<…>`, `MaybeDangling<…>` — are not counted twice, and so a
# `TaskPool` from anywhere but this firmware's spawn sites is not silently
# added to (or missed from) the total.
SIZE_LINE = re.compile(
    r"^print-type-size type: `embassy_executor::raw::TaskPool<(?P<what>[^>]*)>`:\s+"
    r"(?P<size>\d+) bytes, alignment: (?P<align>\d+) bytes$"
)
# `{async fn body of tasks::__ccid_task_task()}` -> `ccid_task`
TASK_NAME = re.compile(r"async fn body of (?:\w+::)*(?P<name>\w+)_task\(\)")


def measure() -> list[tuple[str, int]]:
    """The `(task, bytes)` of every `TaskPool` this firmware spawns."""
    proc = subprocess.run(
        [
            "cargo", "+nightly", "build", "--release", "--target", TARGET,
            "-p", FIRMWARE_PACKAGE, "--bin", "fapico2-firmware",
        ],
        cwd=ROOT,
        env={**os.environ, "RUSTFLAGS": "-Zprint-type-sizes"},
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            "the -Zprint-type-sizes build failed:\n"
            + "\n".join((proc.stdout + proc.stderr).splitlines()[-25:])
        )
    pools: list[tuple[str, int]] = []
    for line in proc.stdout.splitlines():
        found = SIZE_LINE.match(line.strip())
        if found is None:
            continue
        named = TASK_NAME.search(found.group("what"))
        if named is None:
            # A `TaskPool<…, N>` in this build whose future is not one of the
            # firmware's spawn sites. Silently dropping it would under-count
            # the arena; silently adding it would over-count. Refuse.
            raise SystemExit(
                f"unattributed task pool in the measurement: {line.strip()}\n"
                "Refusing to guess — extend TASK_NAME in this script if the "
                "firmware's spawn sites have been renamed."
            )
        # `__ccid_task_task` -> `ccid_task`: the macro's mangling leading
        # underscores are noise in a table a human reads.
        pools.append((named.group("name").lstrip("_"), int(found.group("size"))))
    if not pools:
        raise SystemExit(
            "no `embassy_executor::raw::TaskPool<…>` in the -Zprint-type-sizes "
            "output — the measurement is not reading what it claims to read"
        )
    return sorted(pools)


def table(pools: list[tuple[str, int]], total: int) -> str:
    rows = ["| task | `TaskPool<F, 1>` |", "|---|---:|"]
    for name, size in pools:
        rows.append(f"| `{name}` | {size:,} |")
    rows.append(f"| **total** | **{total:,}** |")
    return "\n".join(rows)


def write_measurement(pools: list[tuple[str, int]], total: int) -> None:
    """Write the demand constant and the per-task table. Not the stamp."""
    text = LIB.read_text(encoding="utf-8")

    const = re.compile(
        rf"pub const {DEMAND_CONST}: usize = [0-9_]+;", re.M
    )
    if not const.search(text):
        raise SystemExit(f"{LIB} no longer declares `{DEMAND_CONST}`")
    text = const.sub(f"pub const {DEMAND_CONST}: usize = {total:,};".replace(",", "_"), text)

    # The per-task table sits inside the doc comment, between its header row
    # and the blank `///` line that ends it.
    table_span = re.search(r"/// \| task \|.*?///\n", text, re.S)
    if table_span is None:
        raise SystemExit(f"{LIB} no longer carries the per-task arena table")
    replacement = "".join(f"/// {row}\n" for row in table(pools, total).splitlines()) + "///\n"
    text = text[: table_span.start()] + replacement + text[table_span.end() :]
    LIB.write_text(text, encoding="utf-8")


def write_stamp(stamp: str) -> None:
    """Write the stamp. Done *after* the measurement, because the stamp is a
    digest of `firmware/src/lib.rs` as it now stands (minus the stamp line
    itself — see `arena_stamp._normalised`), so writing the measurement first
    and hashing second is what makes the result a fixed point."""
    text = LIB.read_text(encoding="utf-8")
    stamp_const = re.compile(
        rf"pub const {STAMP_CONST}: &str = \"[0-9a-f]{{64}}\";", re.M
    )
    if stamp_const.search(text):
        text = stamp_const.sub(f'pub const {STAMP_CONST}: &str = "{stamp}";', text)
    else:
        anchor = re.search(rf"pub const {DEMAND_CONST}: usize = [0-9_]+;\n", text)
        if anchor is None:
            raise SystemExit(f"{LIB} no longer declares `{DEMAND_CONST}`")
        text = (
            text[: anchor.end()]
            + f'pub const {STAMP_CONST}: &str = "{stamp}";\n'
            + text[anchor.end() :]
        )
    LIB.write_text(text, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--check",
        action="store_true",
        help="recompute the stamp only; exit non-zero if the constant in the "
             "tree does not match the current sources (no build, no nightly)",
    )
    args = ap.parse_args()

    stamp = fingerprint(ROOT)
    if args.check:
        from arena_stamp import declared_stamp

        declared = declared_stamp(ROOT)
        if declared != stamp:
            print(
                "FAIL: check_task_arena_measurement (US-964) — the demand constant's\n"
                "stamp does not match the sources it was measured from.\n"
                f"  declared {declared}\n"
                f"  current  {stamp}\n"
                "Re-measure:  python3 tests/scripts/measure_task_arena.py"
            )
            return 1
        print(f"ok: task-arena measurement is current ({stamp[:16]}…)")
        return 0

    pools = measure()
    total = sum(size for _, size in pools)
    # Measurement first, stamp second: the stamp is a digest of the tree as the
    # measurement left it, so hashing before writing it would be self-defeating.
    write_measurement(pools, total)
    stamp = fingerprint(ROOT)
    write_stamp(stamp)
    print(f"measured {len(pools)} task pools, {total:,} B total, stamp {stamp[:16]}…")
    for name, size in pools:
        print(f"  {name}: {size:,}")
    print(f"dependency closure: {len(dependency_closure(ROOT))} packages")
    print(f"written to {LIB.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
