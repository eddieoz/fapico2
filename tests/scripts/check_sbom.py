#!/usr/bin/env python3
"""US-1062: the CycloneDX SBOM, cross-checked against the locked graph.

Two reds, both required by the story:

  * a release run with no SBOM attached fails.  Without `--artifacts` the
    gate checks the committed `supply-chain/sbom.cdx.json`; with
    `--artifacts DIR` it requires an SBOM to be present IN that directory,
    because that is the mode the release job runs in, and "the SBOM is in
    the repository" is not the same claim as "the SBOM is attached to the
    artefacts being published".
  * the SBOM's component count is cross-checked against `Cargo.lock`, and a
    mismatch fails.

How the cross-check works, and why it is two-directional
--------------------------------------------------------

`cargo cyclonedx` produces the component set; `cargo metadata` produces the
dependency closure of `fapico2-firmware`. The gate requires the two to be
EQUAL as sets of (name, version):

  * a component in the SBOM that is not in the closure is a fabricated or
    hand-edited SBOM — the failure mode where the document reassures and
    the graph disagrees;
  * a package in the closure that is not in the SBOM is a component the
    published document silently omits — the failure mode where nobody
    notices a new dependency at all.

A one-directional check catches the first and not the second, and the second
is the one an SBOM exists to prevent.

The count recorded in `docs/supply-chain.md` is compared too. A count in a
document is a number nobody re-checks; this derives it and fails on drift,
which is the whole `properties.toml` lesson from RS-Key's own header.

What is deliberately NOT claimed
--------------------------------

* `serialNumber` is a fresh random UUID per generation and
  `metadata.timestamp` is the wall clock, so regenerating the SBOM always
  produces a byte-different file. The gate therefore compares the COMPONENT
  SET and never the file bytes. A diff in this file means "regenerated",
  not "the supply chain changed" — and the component-set comparison is what
  tells you which.
* The SBOM is generated with `--target all`, so it lists every crate the
  firmware crate can reach on ANY target. That is a deliberate
  over-approximation: over-inclusion in an SBOM is the safe direction. The
  narrower figure — what is actually in the RP2350 image — is the 276-crate
  device closure, derived separately by `check_supply_chain.py`.
* cargo-cyclonedx omits dev-dependencies, and so does this gate's closure
  walk. The two agree by construction rather than by luck.

Regenerate with:

    cargo cyclonedx --format json --all-features --target all --spec-version 1.5
    mv firmware/fapico2-firmware.cdx.json supply-chain/sbom.cdx.json

Usage:
    python3 tests/scripts/check_sbom.py
    python3 tests/scripts/check_sbom.py --artifacts DIR   # release mode
Exit 0 on PASS, 1 on FAIL.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from minitoml import TomlError, read_toml  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SBOM = ROOT / "supply-chain" / "sbom.cdx.json"
DOC = ROOT / "docs" / "supply-chain.md"
ROOT_CRATE = "fapico2-firmware"
EXPECTED_SPEC = "1.5"

# Roots whose appearance in a published SBOM means the builder's filesystem
# layout leaked into the artefact. Crate descriptions do not mention these.
ABSOLUTE_ROOTS = ("/home/", "/Users/", "/root/", "/mnt/", "/opt/", "/tmp/",
                  "/var/folders/")


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)


def metadata() -> dict:
    for extra in ([], ["--offline"]):
        r = run(["cargo", "metadata", "--format-version", "1", "--all-features",
                 *extra])
        if r.returncode == 0:
            return json.loads(r.stdout)
    raise RuntimeError("`cargo metadata` failed (also with --offline)")


def firmware_closure(meta: dict) -> set[tuple[str, str]]:
    """(name, version) of every non-dev package reachable from the firmware.

    Dev-dependencies are excluded because cargo-cyclonedx excludes them, and
    the point of the check is that both sides walk the same edges. Build
    dependencies ARE included: a proc-macro that runs during the build is
    code this project executes, and cargo-cyclonedx lists it.
    """
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    ident = {p["id"]: (p["name"], p["version"]) for p in meta["packages"]}
    roots = [p["id"] for p in meta["packages"] if p["name"] == ROOT_CRATE]
    if not roots:
        raise RuntimeError(f"no package named {ROOT_CRATE} in the metadata")
    seen: set[str] = set()
    out: set[tuple[str, str]] = set()
    stack = list(roots)
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        if node not in roots:
            out.add(ident[node])
        info = nodes.get(node)
        if info is None:
            continue
        for dep in info["deps"]:
            kinds = {k.get("kind") for k in dep.get("dep_kinds") or [{}]}
            if kinds == {"dev"}:
                continue
            stack.append(dep["pkg"])
    return out


def load_sbom(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--artifacts", metavar="DIR",
                    help="release mode: require an SBOM in DIR and check that one")
    args = ap.parse_args(argv[1:])

    err: list = []
    out: list = []

    path = SBOM
    if args.artifacts:
        path = Path(args.artifacts) / "sbom.cdx.json"
        if not path.is_file():
            print(
                f"FAIL: a release cannot be published without an SBOM, and "
                f"{path} does not exist.\n"
                f"  This is the US-1062 red: the SBOM is generated from the "
                f"locked graph and travels WITH the artefacts, not merely "
                f"lives in the repository where somebody can find it if they "
                f"know to look."
            )
            print("\nRESULT: FAIL")
            return 1
        out.append(f"release mode: checking the attached SBOM at {path}")

    if not SBOM.is_file():
        print("FAIL: supply-chain/sbom.cdx.json is missing. Generate it with:\n"
              "        cargo cyclonedx --format json --all-features "
              "--target all --spec-version 1.5\n"
              "        mv firmware/fapico2-firmware.cdx.json "
              "supply-chain/sbom.cdx.json")
        print("\nRESULT: FAIL")
        return 1

    try:
        sbom = load_sbom(path)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: {path} is not readable JSON: {exc}")
        print("\nRESULT: FAIL")
        return 1

    if sbom.get("bomFormat") != "CycloneDX":
        err.append(f"{path.name}: bomFormat is {sbom.get('bomFormat')!r}, not "
                   f"'CycloneDX' — this gate reads a CycloneDX document.")
    if str(sbom.get("specVersion")) != EXPECTED_SPEC:
        err.append(f"{path.name}: specVersion is {sbom.get('specVersion')!r}, "
                   f"expected {EXPECTED_SPEC}. A different spec version may "
                   f"move where components live, and this gate would then be "
                   f"comparing the wrong field.")
    root = sbom.get("metadata", {}).get("component", {}).get("name")
    if root != ROOT_CRATE:
        err.append(f"{path.name}: metadata.component is {root!r}, expected "
                   f"{ROOT_CRATE!r}. The release publishes the firmware UF2; "
                   f"an SBOM for a different crate would be a true document "
                   f"about the wrong thing.")

    # A published SBOM must not carry the builder's filesystem layout. The
    # raw `cargo cyclonedx` output does — every `path+file://` bom-ref is
    # absolute — so the committed file is normalised to `path+file://./…` at
    # generation time and this check is what keeps it that way. A diff that
    # reintroduces /home/<someone>/ is a leak into a published artefact, and
    # it also makes the file mean nothing on another machine.
    raw = path.read_text(encoding="utf-8")
    leaked = sorted({m for root in ABSOLUTE_ROOTS
                     for m in re.findall(re.escape(root) + r"[^\s\"]*", raw)})
    if leaked:
        err.append(
            f"{path.name}: contains {leaked[0]!r}, an absolute filesystem path.\n"
            f"  `cargo cyclonedx` writes absolute `path+file://` bom-refs. The "
            f"committed SBOM is normalised to `path+file://./…`; a published "
            f"SBOM should not carry the builder's home directory, and a file "
            f"whose bom-refs are absolute means nothing on another machine."
        )

    sbom_set = {(c.get("name"), c.get("version")) for c in sbom.get("components", [])}
    if None in {n for n, _ in sbom_set}:
        err.append(f"{path.name}: at least one component has no name or no "
                   f"version, so it cannot be cross-checked against the lock "
                   f"file.")

    try:
        meta = metadata()
    except (RuntimeError, json.JSONDecodeError) as exc:
        print(f"FAIL: the dependency graph could not be read: {exc}")
        print("\nRESULT: FAIL")
        return 1
    closure = firmware_closure(meta)

    for extra in sorted(sbom_set - closure):
        err.append(
            f"{path.name}: component `{extra[0]} {extra[1]}` is not in the "
            f"non-dev dependency closure of {ROOT_CRATE} in the locked graph.\n"
            f"  An SBOM that lists something the build does not contain is a "
            f"document that has drifted from the artefact it describes — and "
            f"the direction that matters is the one that makes a reader "
            f"trust the list."
        )
    for missing in sorted(closure - sbom_set):
        err.append(
            f"{path.name}: `{missing[0]} {missing[1]}` is in the non-dev "
            f"dependency closure of {ROOT_CRATE} but is NOT a component of "
            f"the SBOM.\n"
            f"  Regenerate the SBOM. A published SBOM that silently omits a "
            f"dependency is the failure this document exists to prevent, and "
            f"a one-directional check would not notice it."
        )

    # The count, cross-checked against the document.
    try:
        doc_text = DOC.read_text(encoding="utf-8")
    except OSError as exc:
        doc_text = ""
        err.append(f"docs/supply-chain.md could not be read: {exc}")
    m = re.search(r"\|\s*SBOM components\s*\|\s*\*\*(\d+)\*\*", doc_text)
    if not m:
        err.append(
            f"docs/supply-chain.md does not state the SBOM component count.\n"
            f"  The gate derives it on every run; the document is a copy, and "
            f"a copy of a count is a number nobody re-checks. The row to add "
            f"is:  | SBOM components | **{len(sbom_set)}** |"
        )
    elif int(m.group(1)) != len(sbom_set):
        err.append(
            f"docs/supply-chain.md states {int(m.group(1))} SBOM components, "
            f"the document has {len(sbom_set)}.\n"
            f"  Either the SBOM was regenerated without the document being "
            f"updated, or the document is describing a different SBOM. Both "
            f"mean a published figure that does not match the published file."
        )

    def _shown(p: Path) -> str:
        try:
            return str(p.relative_to(ROOT))
        except ValueError:
            return str(p)

    out.append(f"SBOM: {_shown(path)}")
    out.append(f"  spec {sbom.get('specVersion')}, root {root}, "
               f"components {len(sbom_set)}")
    out.append(f"  non-dev closure of {ROOT_CRATE} in the locked graph: "
               f"{len(closure)} — set equality {'holds' if sbom_set == closure else 'DOES NOT HOLD'}")
    out.append("  serialNumber and metadata.timestamp are generation artefacts "
               "(random UUID, wall clock) and are deliberately not compared; "
               "the component set is the evidence.")

    print("US-1062 CycloneDX SBOM (cross-checked against the locked graph)")
    for line in out:
        print(f"  {line}")
    if err:
        print()
        for e in err:
            print(f"  FAIL: {e}")
        print("\nRESULT: FAIL")
        return 1
    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
