#!/usr/bin/env python3
"""US-1061: the cargo-vet supply-chain audit, and an honest account of it.

What it asserts
---------------

S1  `cargo vet` passes on the locked graph. A crate in the graph that is
    neither audited nor exempted is a RED — that is cargo-vet's own exit 255,
    not this script's opinion, and it is the epic's first US-1061 red.
S2  Every `[[exemptions.NAME]]` in `supply-chain/config.toml` has a stated
    reason in `supply-chain/exemption-reasons.toml`. This is the epic's
    second red: "a gate fails if a new exemption is added without a stated
    reason".
S3  Every stated reason corresponds to a real exemption (a stale reason is a
    red, for the same reason a stale allowlist entry is).
S4  The crates in `bespoke_required` have a reason that is not the
    boilerplate. The crates that carry key material, parse
    attacker-adjacent input, or are a known accepted advisory do not get a
    sentence that says only "unreviewed".
S5  `docs/supply-chain.md` records the self-declared / third-party-audited
    counts, and they are DERIVED here and compared. A hand-written count in
    a document is a number nobody re-checks; this is the
    `properties.toml` lesson from RS-Key's own header — anything derivable
    is derived, and drift fails the build.
S6  Every accepted advisory in `deny.toml` carries a stated reason comment
    above it. The advisory ignore list is an exemption list wearing a
    different hat, and it rots the same way.

Why the reasons are not in `supply-chain/config.toml`
-----------------------------------------------------

Because `cargo vet fmt` on cargo-vet 0.10.2 silently DELETES the `reason`
field from an exemption (verified — the transcript is in the header of
`supply-chain/exemption-reasons.toml`). A reason stored in a field the tool's
own reformatter erases is not a reason. So the pairing is enforced from a
file this repository owns, and `cargo vet fmt` can be run without thinking
about it.

Stdlib only, Python 3.8+ (the house rule). `cargo` and `cargo-vet` are
invoked as subprocesses; if either is missing the gate says so and goes RED
rather than reporting a clean run it did not perform.

Usage:
    python3 tests/scripts/check_supply_chain.py
Exit 0 on PASS, 1 on FAIL.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from minitoml import TomlError, read_toml  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SUPPLY = ROOT / "supply-chain"
VET_CONFIG = SUPPLY / "config.toml"
REASONS = SUPPLY / "exemption-reasons.toml"
DOC = ROOT / "docs" / "supply-chain.md"
DENY = ROOT / "deny.toml"
DEVICE_ROOT = "fapico2-firmware"

# The two vendored crypto crates that cargo-vet cannot see: they are
# `[patch.crates-io]` PATH replacements, and cargo-vet audits by registry
# identity, so they appear in no audit list and no exemption. They are in the
# shipped image, and they differ from crates.io. Named on every run so the
# gap is a printed fact rather than an absence.
OUTSIDE_VET = ("ed448-goldilocks", "x448")

EXEMPTION_RE = re.compile(
    r'^\[\[exemptions\.(?P<name>[A-Za-z0-9_.+-]+)\]\]\s*$'
    r'(?P<body>(?:^[a-z_]+ = .*\n?)*)',
    re.M,
)


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)


def vet_json() -> dict | None:
    """`cargo vet --output-format json`, or None with the reason printed."""
    r = run(["cargo", "vet", "--output-format", "json"])
    if r.returncode != 0:
        print("cargo vet FAILED — the locked graph has a crate that is neither "
              "audited nor exempted:")
        tail = [ln for ln in (r.stderr or r.stdout).splitlines() if ln.strip()]
        for ln in tail[-40:]:
            print(f"  {ln}")
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as exc:
        print(f"cargo vet produced output this gate cannot read: {exc}")
        return None


def device_closure() -> set[str]:
    """Crate names reachable from the firmware by NORMAL edges, device target.

    `cargo tree` rather than a graph walk of `cargo metadata`, because the
    question is "what is in the RP2350 image", and only the tree for
    `--target thumbv8m.main-none-eabi --edges normal` answers that. It costs
    under a second.
    """
    r = run(["cargo", "tree", "--target", "thumbv8m.main-none-eabi",
             "--edges", "normal", "--prefix", "none", "--no-dedupe",
             "--all-features", "-p", DEVICE_ROOT])
    if r.returncode != 0:
        return set()
    return {ln.split(" ")[0].strip() for ln in r.stdout.splitlines() if ln.strip()}


def exemptions() -> list[tuple[str, str]]:
    """(name, version) for every [[exemptions.NAME]] in the vet config."""
    text = VET_CONFIG.read_text(encoding="utf-8")
    out = []
    for m in EXEMPTION_RE.finditer(text):
        ver = re.search(r'^version = "([^"]+)"', m.group("body"), re.M)
        if ver:
            out.append((m.group("name"), ver.group(1)))
    return out


def doc_counts(text: str) -> dict:
    """The four figures docs/supply-chain.md is required to state."""
    want = {
        "third_party_total": r"\|\s*third-party crates cargo-vet sees\s*\|\s*\*\*(\d+)\*\*",
        "third_party_audited": r"\|\s*carrying a third-party audit\s*\|\s*\*\*(\d+)\*\*",
        "self_declared_exemptions": r"\|\s*self-declared exemptions\s*\|\s*\*\*(\d+)\*\*",
        "device_closure_audited": r"device closure \([^)]*\), audited\s*\|\s*\*\*(\d+)\*\*",
        "device_closure_exempted": r"device closure, exempt\s*\|\s*\*\*(\d+)\*\*",
    }
    found = {}
    for key, pat in want.items():
        m = re.search(pat, text)
        if m:
            found[key] = int(m.group(1))
    return found


def main() -> int:
    err: list = []
    out: list = []

    for path, what in ((VET_CONFIG, "cargo-vet config"),
                       (REASONS, "exemption reasons"),
                       (DENY, "deny.toml"),
                       (DOC, "supply-chain document")):
        if not path.is_file():
            print(f"FAIL: {what} is missing at {path.relative_to(ROOT)}")
            print("\nRESULT: FAIL")
            return 1

    # --- S1: cargo vet itself ---------------------------------------------
    vet = vet_json()
    if vet is None:
        print("\nRESULT: FAIL")
        return 1
    audited = [(p["name"], p["version"]) for p in vet.get("vetted_fully", [])]
    partial = [(p["name"], p["version"]) for p in vet.get("vetted_partially", [])]
    exempt = [(p["name"], p["version"]) for p in vet.get("vetted_with_exemptions", [])]
    third_party = len(audited) + len(partial) + len(exempt)

    # --- S2/S3/S4: the stated reasons -------------------------------------
    try:
        reasons_doc = read_toml(REASONS)
        flat = reasons_doc[""]
        reasons = reasons_doc.get("reasons", {})
        bespoke_required = set(flat.get("bespoke_required", []))
    except (TomlError, OSError) as exc:
        print(f"{REASONS.relative_to(ROOT)} could not be read: {exc}")
        print("\nRESULT: FAIL")
        return 1

    exempt_keys = {f"{n}@{v}" for n, v in exempt}
    reason_keys = set(reasons)

    for key in sorted(exempt_keys - reason_keys):
        err.append(
            f"cargo-vet exemption `{key}` has NO stated reason in "
            f"supply-chain/exemption-reasons.toml.\n"
            f"  This is the US-1061 rule: a new exemption has to arrive with a "
            f"reason saying why it is acceptable. `cargo vet add-exemption` "
            f"writes the block and nothing else, and cargo-vet itself does not "
            f"require the reason — so without this check an exemption list "
            f"grows by accretion and nobody ever reads it again."
        )
    for key in sorted(reason_keys - exempt_keys):
        err.append(
            f"supply-chain/exemption-reasons.toml states a reason for `{key}`, "
            f"which is not an exemption in the locked graph any more.\n"
            f"  A stale reason is a claim about a dependency set that has "
            f"changed. Delete it, or restore the exemption it describes."
        )
    boiler = "SELF-DECLARED, not human-reviewed: no imported third-party audit"
    for key in sorted(bespoke_required & reason_keys):
        if reasons[key].startswith(boiler):
            err.append(
                f"`{key}` is in bespoke_required but its reason is the "
                f"generated boilerplate.\n"
                f"  The crates that carry key material, parse "
                f"attacker-adjacent input, or are a known accepted advisory "
                f"have to say WHICH of those they are and what was decided. "
                f"The sentence is the decision record."
            )
    for key in sorted(bespoke_required - reason_keys):
        err.append(f"bespoke_required names `{key}`, which has no reason at all.")

    # --- S5: the document's figures, derived -------------------------------
    dev = device_closure()
    dev_audited = sum(1 for n, _ in audited if n in dev)
    dev_exempt = sum(1 for n, _ in exempt if n in dev)
    dev_total = dev_audited + dev_exempt
    counts = {
        "third_party_total": third_party,
        "third_party_audited": len(audited),
        "self_declared_exemptions": len(exempt),
        "device_closure_audited": dev_audited,
        "device_closure_exempted": dev_exempt,
    }
    if not dev:
        err.append("`cargo tree --target thumbv8m.main-none-eabi` produced "
                   "nothing, so the device-closure figures cannot be derived. "
                   "Refusing to print numbers this gate did not measure.")
    recorded = doc_counts(DOC.read_text(encoding="utf-8"))
    missing = sorted(set(counts) - set(recorded))
    if missing:
        err.append(
            f"docs/supply-chain.md does not state {missing}.\n"
            f"  The five figures the gate derives are: {counts}. A number "
            f"that lives only in prose is a number nobody re-checks — which is "
            f"the rot this whole file exists to prevent."
        )
    for key, value in sorted(counts.items()):
        if key in recorded and recorded[key] != value:
            err.append(
                f"docs/supply-chain.md states {key} = {recorded[key]}, but the "
                f"locked graph gives {value}.\n"
                f"  Re-derive it: this gate measures the graph on every run, "
                f"the document is a copy. Update the document."
            )

    # --- S6: accepted advisories carry a reason ---------------------------
    deny_text = DENY.read_text(encoding="utf-8")
    for m in re.finditer(r'^\s*"(RUSTSEC-[0-9]{4}-[0-9]+)",\s*$', deny_text, re.M):
        above = deny_text[:m.start()].rstrip("\n").splitlines()
        comment = [ln.strip() for ln in above[-14:]
                   if ln.strip().startswith("#")]
        if not any(m.group(1) in c for c in comment):
            err.append(
                f"deny.toml ignores advisory {m.group(1)} with no stated "
                f"reason in a comment above it.\n"
                f"  An advisory ignore list is an exemption list wearing a "
                f"different hat. Every entry says what it is and why it was "
                f"accepted; the two that matter most are the Marvin attack "
                f"against `rsa` (unpatched, in the shipped image) and the "
                f"unmaintained crates behind embassy-rp."
            )

    # --- the report --------------------------------------------------------
    pct = (100.0 * len(audited) / third_party) if third_party else 0.0
    dev_pct = (100.0 * dev_audited / dev_total) if dev_total else 0.0
    print("US-1061 supply-chain audit (cargo-vet)")
    print(f"  third-party crates cargo-vet sees: {third_party}")
    print(f"  carrying a third-party audit:      {len(audited)}  "
          f"({pct:.1f}% — RS-Key's own config is ~17%)")
    print(f"  partially audited:                 {len(partial)}  "
          f"({', '.join(f'{n} {v}' for n, v in partial) or 'none'})")
    print(f"  self-declared exemptions:          {len(exempt)}  "
          f"({100.0 * len(exempt) / third_party:.1f}%)")
    print(f"  of those, in the RP2350 device closure: {dev_exempt} "
          f"({dev_total} third-party crates are)")
    print(f"  device closure audited:            {dev_audited}/{dev_total} "
          f"({dev_pct:.1f}%)")
    print(f"  exemptions with a stated reason:   {len(exempt_keys & reason_keys)}"
          f"/{len(exempt_keys)} ({len(bespoke_required)} of them bespoke)")
    print()
    print("  NOT COVERED BY cargo-vet AT ALL (path-patched, so outside its "
          "registry view):")
    for name in OUTSIDE_VET:
        print(f"    {name} — vendored, MODIFIED from crates.io, and in the "
              f"shipped image")
    print("  No exemption on this list has been read by a human on this "
          "project. The number above is the whole claim.")

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
