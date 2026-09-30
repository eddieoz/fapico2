#!/usr/bin/env python3
"""The fingerprint that ties `TASK_ARENA_DEMAND_B` to what it was measured from.

Why this exists (US-964)
------------------------
`firmware/src/lib.rs` carries the Embassy task-arena demand as a constant
copied out of one `-Zprint-type-sizes` run, and `check_boot_chain.py` compares
that constant against the `ARENA` symbol in the release ELF. Nothing tied the
number to the build that produced it: a contributor could grow `ccid_task`'s
future (8,600 B of the 17,744 B today) and the gate would go on reporting
`1.85x, floor 1.25x` — PASS — from a number that no longer described anything,
while the device would panic `"task arena is full"` at the first spawn that no
longer fits. That is a gate measuring an assumption, which is the failure class
this epic keeps paying for.

The fix is a stamp: the measurement is only believed while the inputs it was
taken from are unchanged.

* `measure_task_arena.py` computes the measurement, computes this fingerprint,
  and writes both into `firmware/src/lib.rs`.
* `check_boot_chain.py` recomputes the fingerprint from the tree as it stands
  and **fails** if it no longer matches — loudly, naming the command to
  re-measure. It never publishes a headroom figure from an unverified number.

The fingerprint covers exactly what can move the number:

1. the firmware's own sources and manifests — `firmware/Cargo.toml`,
   `firmware/build.rs`, and every `.rs` under `firmware/src/`. The spawned
   futures are declared there, and this is where `ccid_task` and `hid_task`
   (8,600 B and 8,136 B of the total) live;
2. the resolved version of every package in the firmware's dependency closure,
   read from `Cargo.lock`. A bumped `embassy-executor` can change a future's
   size as surely as a source edit can, and nothing in the workspace would
   otherwise say so. Scoped to the firmware's closure on purpose: an unrelated
   host-only dev-dependency bump must not demand a device re-measure.

Deliberately *not* covered, and why: a change in a workspace crate's source
that is not on the firmware's own task path. The task futures are constructed
in `firmware/src`, and the boot and per-APDU frame growth that such a change
would cause is measured by the two other gates that do read the ELF
(`check_async_frame.py`, US-939, and the boot-chain call-chain analysis,
US-957). This stamp is the arena's own coverage, not the workspace's.

The known limitation: the stamp cannot tell a comment from code
----------------------------------------------------------------
**This fingerprint is byte-exact over the file text, so an edit that changes no
demand -- a doc comment, a reworded string, a comment-only commit --
invalidates it and turns the gate red.** That is not hypothetical. `dac66b5`
on `feat/rskey-adopt` corrected OTP comment wording inside `firmware/src/`, the
stamp went stale, and `check_boot_chain.py` failed saying "a task future grew,
or a dependency in the firmware's closure moved" -- neither of which was true.
The demand was 17,768 B before and after; only the stamp moved. This branch is
documentation-heavy, so it will keep tripping.

**This is deliberate, and the reason is the direction of the error.** The
stamp's whole job is to make a *stale* number a FAIL. Byte-exact hashing can
only over-invalidate -- red when nothing changed -- never under-invalidate --
green when something changed. Making it comment-aware would trade that
guaranteed-safe direction for a possible false negative: a text filter that
mis-strips real code (inside a raw string, a macro body, a `#[cfg]`'d block)
would let genuine future growth through silently, which is the exact failure
this module was written to prevent. A red gate that costs one command beats a
green gate that can be fooled.

So the cost of a docs-only commit is a re-measure:

    python3 tests/scripts/measure_task_arena.py

The measurement is the authority. The stamp only records which tree the
measurement was taken from; when the two disagree, the measurement wins and
the stamp is rewritten.

The structural fix, and why it is not in this change
------------------------------------------------------
The correct fingerprint is one taken over the **measured type sizes** -- the
`-Zprint-type-sizes` output the demand is actually read out of -- rather than
over the source text. That is comment-blind by construction, because a comment
is not a type size.

It is not done here because it is a larger change than the limitation warrants
on its own, and the reasons are structural rather than cosmetic:

1. it needs **nightly on every gate run**, not only on every re-measure, which
   is a new CI requirement for a gate that currently needs only a build;
2. it needs the `-Zprint-type-sizes` parse that `measure_task_arena.py`
   already owns to be factored out and re-run, so the two never disagree about
   how a `TaskPool<...>` line is read;
3. it still has to cover `Cargo.lock` and the manifests, which **do not appear
   in the type-size output at all** -- so the result is a two-part stamp
   (sizes for the sources, versions for the closure), not a replacement.

The byte-exact stamp stays until that is done deliberately.
"""
from __future__ import annotations

import hashlib
import pathlib
import re

FIRMWARE = pathlib.Path("firmware")
LOCKFILE = pathlib.Path("Cargo.lock")
FIRMWARE_PACKAGE = "fapico2-firmware"

# Where the measurement landed in `firmware/src/lib.rs`.
DEMAND_CONST = "TASK_ARENA_DEMAND_B"
STAMP_CONST = "TASK_ARENA_DEMAND_B_STAMP"


def measurement_files(root: pathlib.Path) -> list[pathlib.Path]:
    """The tree the demand is measured from, as **root-relative** paths.

    Root-relative on purpose: the digest is written into the source tree and
    re-derived by the gate and by CI, from three different absolute paths. A
    label that carried the checkout path would make the same tree hash three
    different ways — and on this host, where `/home/…` and `/mnt/tools/…` are
    the same directory behind a bind mount, would disagree with itself
    depending on which spelling the caller used.
    """
    files = [FIRMWARE / "Cargo.toml"]
    build_rs = FIRMWARE / "build.rs"
    if (root / build_rs).exists():
        files.append(build_rs)
    files.extend(sorted(path.relative_to(root) for path in (root / FIRMWARE / "src").rglob("*.rs")))
    return files


def _lock_packages(lock: pathlib.Path) -> dict[tuple[str, str], list[str]]:
    """`Cargo.lock` as `(name, version) -> [dependency specs]`.

    Hand-parsed rather than `tomllib`, which the gate's Python does not have.
    The lockfile's `[[package]]` blocks are flat: a `name = "..."`, a
    `version = "..."`, and optionally a `dependencies = [ ... ]` list of
    `"name version"` strings.
    """
    packages: dict[tuple[str, str], list[str]] = {}
    for block in re.split(r"^\[\[package\]\]\s*$", lock.read_text(encoding="utf-8"), flags=re.M):
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        version = re.search(r'^version = "([^"]+)"', block, re.M)
        if not name or not version:
            continue
        deps: list[str] = []
        listed = re.search(r"^dependencies = \[(.*?)\]", block, re.M | re.S)
        if listed:
            deps = re.findall(r'"([^"]+)"', listed.group(1))
        packages[(name.group(1), version.group(1))] = deps
    return packages


def _resolve(spec: str, by_name: dict[str, list[tuple[str, str]]]) -> tuple[str, str] | None:
    """One `"name version"` dependency spec to the key it names in the lock.

    `None` when the spec names a package that appears at two versions and
    carries no version of its own — the lockfile's way of saying "ambiguous".
    Such a package is not in the closure. That is the one way this fingerprint
    can under-cover, so it is stated here rather than left as a silent skip.
    """
    parts = spec.split()
    if len(parts) >= 2 and re.match(r"^\d", parts[1]):
        key = (parts[0], parts[1])
        return key
    candidates = by_name.get(spec, [])
    return candidates[0] if len(candidates) == 1 else None


def dependency_closure(root: pathlib.Path) -> list[tuple[str, str]]:
    """`(name, version)` for every package the device firmware resolves to."""
    packages = _lock_packages(root / LOCKFILE)
    by_name: dict[str, list[tuple[str, str]]] = {}
    for key in packages:
        by_name.setdefault(key[0], []).append(key)

    seen: set[tuple[str, str]] = set()
    queue = [key for key in packages if key[0] == FIRMWARE_PACKAGE]
    if not queue:
        raise LookupError(
            f"{LOCKFILE} has no `{FIRMWARE_PACKAGE}` package — the workspace lock is "
            "not the one this stamp was computed from"
        )
    while queue:
        key = queue.pop()
        if key in seen or key not in packages:
            continue
        seen.add(key)
        for spec in packages[key]:
            resolved = _resolve(spec, by_name)
            if resolved is not None:
                queue.append(resolved)
    return sorted(seen)


def _normalised(path: pathlib.Path) -> bytes:
    """The file's content with the stamp *declaration* line removed.

    The stamp is written *into* `firmware/src/lib.rs`, so hashing that file
    verbatim would make every stamp invalidate the one before it — a
    fixed-point the measurement could never satisfy. Exactly the declaration
    line is excluded (a doc comment that merely names the constant is hashed
    like any other prose), which leaves every source file otherwise fully
    covered and makes a re-run on an unchanged tree reproduce the digest.
    """
    raw = path.read_bytes()
    if path.suffix != ".rs":
        return raw
    kept = [
        line
        for line in raw.splitlines(keepends=True)
        if not re.search(rf"^\s*pub const {STAMP_CONST}:", line.decode("utf-8", "replace"))
    ]
    return b"".join(kept)


def fingerprint(root: pathlib.Path) -> str:
    """sha256 over the measurement inputs, as a hex digest.

    Deterministic across machines and checkouts: file *contents* and resolved
    versions only, never absolute paths, timestamps or line endings beyond
    what is in the blob.
    """
    digest = hashlib.sha256()
    for rel in measurement_files(root):
        path = root / rel
        if not path.exists():
            continue
        digest.update(f"file {rel.as_posix()} ".encode("utf-8"))
        digest.update(hashlib.sha256(_normalised(path)).digest())
    for name, version in dependency_closure(root):
        digest.update(f"dep {name} {version}\n".encode("utf-8"))
    return digest.hexdigest()


def declared_stamp(root: pathlib.Path) -> str | None:
    """`TASK_ARENA_DEMAND_B_STAMP` as written in `firmware/src/lib.rs`."""
    text = (root / FIRMWARE / "src/lib.rs").read_text(encoding="utf-8")
    found = re.search(
        rf'pub const {STAMP_CONST}:\s*&str\s*=\s*"([0-9a-f]{{64}})"\s*;', text
    )
    return found.group(1) if found else None
