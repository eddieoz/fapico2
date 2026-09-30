#!/usr/bin/env python3
"""US-1060: the crate-graph assertions cargo-deny cannot express.

`deny.toml` is the resolved-third-party half of the supply-chain story: sources,
licences, advisories, duplicated versions, and the named `wrappers` allowlist
that `cargo deny check --deny unused-wrapper` keeps honest. This script is the
other half — the rules about the *edges between the workspace's own crates*,
which cargo-deny has no setting for in any version (0.20.2 hard-errors on an
unknown top-level key rather than ignoring it, so they live in the sibling
`deny-graph.toml`).

What it asserts, and what it deliberately does not
--------------------------------------------------

G1  R1 — no applet crate may depend on another applet crate. The one
    sanctioned aggregator (`fapico2-apps`, the AID registry) has every edge it
    holds listed by name in `deny-graph.toml`.
G2  R2 — only `fapico2-platform` may name a hash/signature *backend*.
G3  R3 — every backend in the list is actually named by its owner, and no
    crate other than the owner names one. Both directions.
G4  — no wildcard (`= "*"`) version requirement in a workspace-owned manifest.
G5  — the duplicated-crate set in `Cargo.lock` is exactly the set recorded in
    `deny-graph.toml`. cargo-deny reports each duplicate as a *warning* and
    exits 0; this turns that half of the signal into a red.

Every list is checked in BOTH directions. An edge that appears without being
listed is a red, and a listed edge that no longer exists is *also* a red. The
second direction is the one that matters: an allowlist that only ever grows is
a list of stale promises nobody re-reads, which is the rot the epic's
"so the lists cannot rot" is aimed at.

What this is not
----------------

G1 is not applet isolation, and the difference is not academic. fapico2 builds
ONE trussed `Client` and hands the same service set to every applet, so which
key material an applet can reach is decided by the service-set split in
`platform/src/trusted_backend/`, not by any manifest edge. G1 buys the weaker,
still-useful property: an applet cannot import another applet's code, and the
one crate that does is named and counted. Isolation itself is architecture; it
is recorded as a known divergence in `docs/supply-chain.md` and is not claimed
here. A config that read as though it enforced isolation would be worse than
one that says what it does.

Stdlib only (the house rule for `tests/scripts/`), Python 3.8+. The TOML
reader lives in `tests/scripts/minitoml.py` and is the ONLY one in the
repository: two readers of the same file is how a gate and its own copy of the
rules drift apart. It handles exactly the subset `deny-graph.toml` uses and
raises on anything else rather than guessing — a parse failure is a RED.

Usage:
    python3 tests/scripts/check_crate_graph.py
Exit 0 on PASS, 1 on FAIL.
"""

from __future__ import annotations

import collections
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from minitoml import TomlError, read_toml  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "deny-graph.toml"
DENY = ROOT / "deny.toml"
LOCK = ROOT / "Cargo.lock"

# A workspace member whose manifest is at `apps/<name>/Cargo.toml` is an
# applet. `apps/Cargo.toml` (the AID registry, `fapico2-apps`) is one level up
# and is therefore NOT an applet — see deny-graph.toml's R1 comment.
APPLET_RE = re.compile(r"^apps/[^/]+/Cargo\.toml$")


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------


def cargo_metadata() -> dict:
    """`cargo metadata --no-deps`, from cargo itself.

    Cargo is asked rather than a manifest parser of our own because cargo is
    the authority on what the graph is: a second reader of Cargo.toml in this
    repository is a second opinion nobody asked for, and the two would agree
    until the day they did not.

    `--no-deps` is sufficient and is the right scope: every rule here is about
    edges the workspace *declares*, and a rule about transitive edges would be
    a rule about crates.io.
    """
    last = ""
    for extra in ([], ["--offline"]):
        r = subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1", *extra],
            cwd=str(ROOT), capture_output=True, text=True,
        )
        if r.returncode == 0:
            return json.loads(r.stdout)
        last = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
        last = last[0]
    raise RuntimeError(
        f"`cargo metadata --no-deps` failed (also with --offline): {last}\n"
        f"The gate cannot read the graph, and a gate that cannot read the "
        f"graph cannot be anything but green."
    )


def build_graph(meta: dict) -> dict:
    """name -> {"manifest": relpath, "normal": [...], "dev": [...], "build": [...]}"""
    members = set(meta["workspace_members"])
    graph = {}
    for pkg in meta["packages"]:
        if pkg["id"] not in members:
            continue
        rel = _rel(pkg["manifest_path"])
        buckets = {"normal": [], "dev": [], "build": []}
        for dep in pkg["dependencies"]:
            kind = dep.get("kind") or "normal"
            buckets[kind if kind in buckets else "normal"].append(dep["name"])
        graph[pkg["name"]] = {
            "manifest": rel,
            **{k: sorted(set(v)) for k, v in buckets.items()},
        }
    return graph


def _rel(manifest_path: str) -> str:
    """Manifest path -> repo-relative, with the /mnt bind-mount made a non-issue."""
    real = Path(manifest_path).resolve()
    for base in (ROOT.resolve(),):
        try:
            return str(real.relative_to(base))
        except ValueError:
            continue
    # Fall back to the last few components; the gate only ever compares
    # repo-relative shapes, and refusing to run over a path spelling is not a
    # safety property, it is an annoyance with one.
    parts = real.parts
    for anchor in ("rskey-adopt",):
        if anchor in parts:
            i = len(parts) - 1 - parts[::-1].index(anchor)
            return str(Path(*parts[i + 1:])).replace("\\", "/")
    return str(real).replace("\\", "/")


def applets(graph: dict) -> dict:
    return {n: g for n, g in graph.items() if APPLET_RE.match(g["manifest"])}


def registry_crate(graph: dict) -> str | None:
    """The AID registry: the one non-applet crate under `apps/`."""
    for name, g in graph.items():
        if g["manifest"] == "apps/Cargo.toml":
            return name
    return None


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------


def g1_applet_edges(graph: dict, policy: dict, out: list, err: list) -> None:
    """No applet may depend on another applet, except through the registry."""
    applet = applets(graph)
    reg = registry_crate(graph)
    allow = set(policy.get("applet_edges_allow", []))
    if not allow:
        err.append("deny-graph.toml: applet_edges_allow is empty or absent — the "
                   "rule would accept every edge.")
    seen: set[str] = set()
    # The registry is a source as well as a target: it is the one crate
    # allowed to hold applet edges, and its edges have to be counted too, or
    # every allowlist entry for it reads as stale.
    sources = dict(applet)
    if reg:
        sources[reg] = graph[reg]
    for name, g in sorted(sources.items()):
        for dep in g["normal"]:
            if dep not in applet:
                continue
            edge = f"{name} -> {dep}"
            seen.add(edge)
            if edge not in allow:
                err.append(
                    f"{g['manifest']}: crate `{name}` takes a normal "
                    f"dependency on applet crate `{dep}` and the edge is not in "
                    f"deny-graph.toml's applet_edges_allow.\n"
                    f"  Applets must reach each other only through "
                    f"fapico2-platform. Add the edge deliberately, with a "
                    f"reason, or route the call through the platform seam."
                )
    for edge in sorted(allow - seen):
        err.append(
            f"deny-graph.toml: applet_edges_allow lists `{edge}`, which is not "
            f"an applet-to-applet normal edge in the current graph.\n"
            f"  A stale allowlist entry is a promise about a graph that no "
            f"longer exists. Delete it, or restore the edge it describes."
        )
    devs = sorted(
        f"{n} -> {d}" for n, g in applet.items() for d in g["dev"] if d in applet
    )
    out.append(f"G1 applet-to-applet normal edges: {len(seen)} (allowlist "
               f"{len(allow)}), all sanctioned")
    out.append(f"G1 applet-to-applet DEV edges (never linked into the image, "
               f"reported so they are not a surprise): {len(devs)}"
               + (f" — {', '.join(devs)}" if devs else ""))


def g2_backend_owner(graph: dict, policy: dict, out: list, err: list) -> None:
    """Only `backend_owner` may name a backend crate."""
    backends = set(policy.get("backend_crates", []))
    owner = policy.get("backend_owner")
    if not backends:
        err.append("deny-graph.toml: backend_crates is empty or absent — the "
                   "rule would name nothing and enforce nothing.")
    if not isinstance(owner, str) or not owner:
        err.append("deny-graph.toml: backend_owner is absent or not a string.")
        return
    if owner not in graph:
        err.append(f"deny-graph.toml: backend_owner `{owner}` is not a workspace "
                   f"member — the rule names a crate that does not exist.")
        return
    for name, g in sorted(graph.items()):
        for dep in g["normal"] + g["build"]:
            if dep in backends and name != owner:
                err.append(
                    f"{g['manifest']}: crate `{name}` names backend crate "
                    f"`{dep}`, and only `{owner}` may.\n"
                    f"  A second crate that can name an implementation backend "
                    f"is a second place the trusted-backend dispatch can be "
                    f"decided. Move the dependency to {owner}."
                )
    owned = [b for b in sorted(backends) if b in graph[owner]["normal"] + graph[owner]["build"]]
    for stale in sorted(backends - set(owned)):
        err.append(
            f"deny-graph.toml: backend_crates lists `{stale}`, which "
            f"`{owner}` does not name any more.\n"
            f"  The list is meant to be the set of backends the platform owns; "
            f"an entry that matches nothing is a rule about a crate that is no "
            f"longer in the build."
        )
    out.append(f"G2 backend crates: {len(backends)} declared, {len(owned)} named "
               f"by {owner}, 0 named by anything else")


def g4_wildcards(graph: dict, policy: dict, out: list, err: list) -> None:
    """No `= "*"` in a workspace-owned manifest."""
    owned_globs = policy.get("owned_manifest_globs", [])
    exempt = policy.get("wildcard_exempt", [])
    if not owned_globs:
        err.append("deny-graph.toml: owned_manifest_globs is empty — the "
                   "wildcard rule would scan nothing.")
        return
    for path in exempt:
        if not (ROOT / path).is_dir():
            err.append(f"deny-graph.toml: wildcard_exempt names `{path}`, which "
                       f"is not a directory in this tree — a stale exemption.")
    # The globs are a statement of intent about which manifests the rule
    # covers, so they are checked in both directions too: a glob that matches
    # nothing has stopped describing the tree, and a workspace member the
    # globs do not cover is a hole in the statement.
    covered: set[str] = set()
    for pattern in owned_globs:
        hits = {str(p.relative_to(ROOT)).replace("\\", "/")
                for p in sorted(ROOT.glob(pattern))
                if p.is_file()}
        if not hits:
            err.append(f"deny-graph.toml: owned_manifest_globs entry `{pattern}` "
                       f"matches no file in this tree — a stale scope.")
        covered |= hits
    uncovered = sorted({g["manifest"] for g in graph.values()} - covered
                       - {f"{p}/Cargo.toml" for p in exempt})
    for rel in uncovered:
        err.append(
            f"deny-graph.toml: {rel} is a workspace member manifest that no "
            f"owned_manifest_globs entry covers, so the wildcard rule skips it.\n"
            f"  Either add a glob for it, or move the crate under "
            f"wildcard_exempt with a reason."
        )
    found = 0
    for rel in sorted(covered):
        if rel in exempt:
            continue
        hits = count_wildcards((ROOT / rel).read_text(encoding="utf-8"))
        found += hits
        if hits:
            err.append(
                f"{rel}: {hits} wildcard version requirement(s) (`= \"*\"`).\n"
                f"  A wildcard resolves to whatever is newest at build time, "
                f"which is a different review problem from a pinned version. "
                f"Pin it, or add a stated exemption."
            )
    out.append(f"G4 wildcard version requirements in workspace-owned manifests: "
               f"{found} (across {len(covered)} manifest(s); "
               f"{len(exempt)} vendored tree(s) exempt)")
    for path in exempt:
        total = 0
        for manifest in sorted((ROOT / path).rglob("Cargo.toml")):
            total += count_unversioned_paths(
                manifest.read_text(encoding="utf-8"))
        if total == 0:
            err.append(
                f"deny-graph.toml: wildcard_exempt lists `{path}`, but it has no "
                f"unversioned path requirement left.\n"
                f"  The exemption exists because a crates.io-published crate "
                f"cannot carry a version on a path dependency. Drop the entry; "
                f"the rule can cover that tree again."
            )
        out.append(f"G4   exempt `{path}`: {total} unversioned path "
                   f"requirement(s) — the reason it is exempt is in "
                   f"deny-graph.toml, not here")


_VERSION_REQ = re.compile(r'^\s*(?:[A-Za-z0-9_-]+\s*=\s*)?\{[^}]*version\s*=\s*"\*"')
_PATH_REQ = re.compile(r'^\s*(?:[A-Za-z0-9_-]+\s*=\s*)?\{[^}]*path\s*=\s*"')


def count_wildcards(text: str) -> int:
    """Count `version = "*"` requirements, comment-aware.

    A path dependency that carries no version inherits the workspace version —
    that is pinned, not a wildcard, and counting it would make the rule cry
    wolf on forty entries. A path dependency inside a *published* crate is a
    different animal (see `count_unversioned_paths`), and that is what the
    `wildcard_exempt` entry is about.
    """
    n = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not _VERSION_REQ.match(raw):
            continue
        if "path" in raw and "version" not in raw:
            continue
        n += 1
    return n


def count_unversioned_paths(text: str) -> int:
    """Count `{ path = "..." }` requirements that carry no version."""
    n = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _PATH_REQ.match(raw) and "version" not in raw:
            n += 1
    return n


def g5_duplicates(policy: dict, out: list, err: list) -> None:
    """The duplicated-crate set in Cargo.lock is the recorded set, exactly."""
    recorded = set(policy.get("duplicate_crates", []))
    if not recorded:
        err.append("deny-graph.toml: duplicate_crates is empty — the rule would "
                   "accept any number of duplicated crates.")
        return
    counts = collections.Counter()
    text = LOCK.read_text(encoding="utf-8")
    for name in re.findall(r'^\[\[package\]\]\nname = "([^"]+)"', text, re.M):
        counts[name] += 1
    actual = {n for n, k in counts.items() if k > 1}
    for new in sorted(actual - recorded):
        err.append(
            f"Cargo.lock: crate `{new}` now resolves to more than one version "
            f"and is not in deny-graph.toml's duplicate_crates.\n"
            f"  cargo-deny reports this as warning[duplicate] and exits 0, so "
            f"nothing else in CI turns it red. Decide deliberately: accept the "
            f"second version and add the name, or unify the pin."
        )
    for gone in sorted(recorded - actual):
        err.append(
            f"deny-graph.toml: duplicate_crates lists `{gone}`, which is no "
            f"longer duplicated in Cargo.lock.\n"
            f"  The entry now describes a lock file that does not exist. "
            f"Delete it (this is a good outcome: a version collapsed)."
        )
    out.append(f"G5 duplicated crates in Cargo.lock: {len(actual)} "
               f"(recorded {len(recorded)}), set matches")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    out: list = []
    err: list = []

    if not DENY.is_file():
        err.append("deny.toml is missing — the cargo-deny half of US-1060 is "
                   "not in the tree.")
    if not POLICY.is_file():
        err.append("deny-graph.toml is missing — the graph half of US-1060 is "
                   "not in the tree.")
    if err:
        print("\n".join(err))
        print("\nRESULT: FAIL")
        return 1

    try:
        policy = read_toml(POLICY)[""]
    except (TomlError, OSError) as exc:
        print(f"deny-graph.toml could not be read: {exc}\n"
              f"A policy this gate cannot read is a policy it cannot enforce.")
        print("\nRESULT: FAIL")
        return 1

    try:
        graph = build_graph(cargo_metadata())
    except (RuntimeError, json.JSONDecodeError, KeyError) as exc:
        print(f"the crate graph could not be read: {exc}")
        print("\nRESULT: FAIL")
        return 1

    print("US-1060 crate-graph assertions "
          "(cargo-deny handles the resolved third-party graph; this handles "
          "the workspace's own edges)")
    print(f"  workspace members: {len(graph)}; applet crates: "
          f"{len(applets(graph))}; AID registry: {registry_crate(graph)}")

    for rule in (g1_applet_edges, g2_backend_owner):
        try:
            rule(graph, policy, out, err)
        except (TomlError, KeyError) as exc:
            err.append(f"{rule.__name__}: policy shape is wrong ({exc})")
    try:
        g4_wildcards(graph, policy, out, err)
        g5_duplicates(policy, out, err)
    except OSError as exc:
        err.append(f"could not read a manifest or the lock file: {exc}")

    print()
    for line in out:
        print(f"  {line}")
    print()
    print("  KNOWN DIVERGENCE (RS-Key R2, applet isolation): one trussed "
          "`Client` is shared\n  by every applet, so reachable key material is "
          "a service-set split, not a manifest\n  edge. G1 proves applets do not "
          "import each other's code; it does not\n  and cannot prove isolation. "
          "See docs/supply-chain.md.")

    if err:
        print()
        for e in err:
            print(f"  FAIL: {e}")
        print("\nRESULT: FAIL")
        return 1
    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
