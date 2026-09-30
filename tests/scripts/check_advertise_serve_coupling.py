#!/usr/bin/env python3
"""Gate: the OpenPGP card's advertised algorithm set and its served
mechanism set cannot diverge (US-962, finding I2).

What the defect was
-------------------
GET DATA FA (`AllowedAlgorithms::default_gen()` in the vendored opcard) and
the mechanism table the RP2350 actually runs (`BACKENDS` in
`platform/src/trusted_backend/dispatch.rs`) were wired to *different* Cargo
switches: opcard's own `secp256k1-backend` / `brainpool-backend` / `rsa*-gen`
features on one side, the platform's `secp256k1-backend` /
`brainpool-backend` / `rsa-backend` on the other. Build with a platform
backend off and the card still advertised the algorithm in FA *and* still
accepted the attribute with `9000` (the PUT DATA gate consults the same
allow-list), while every request fell through to trussed Core, which has no
such mechanism. The US-950 FA test could not see it: it runs on the default
feature set, where advertise and serve agree by construction.

Why a build-and-run gate rather than a grep
------------------------------------------
A grep would have to encode which feature gates which backend — a second copy
of the wiring under test, free to drift the moment someone adds an algorithm.
This gate instead *builds both configurations* and reads the real
advertisement off the card and the real serving table off the dispatch, then
requires them to be equal. The measurement lives in
`apps/openpgp/tests/advertise_serve.rs`, which compares each algorithm group
against `BACKENDS` directly — including the "no untracked record" check, so an
algorithm added to FA without a row in the table fails too.

Two configurations, both required:

1. **default** — the production configuration. Must serve and advertise all
   three switched groups (10 FA records per usage tag, 30 total), and must
   still advertise everything it served before US-962: the story is not
   allowed to buy honesty by dropping a capability.
2. **reduced** (`--no-default-features --features "virt,device"`) — no
   backends at all. Must advertise none of them, and the PUT DATA gate must
   answer `6A80` for each rather than accepting an algorithm nothing serves.

The reduced build is the one that discriminates. In the default build both
sides are on and the test passes whether or not the coupling exists; that is
why configuration 2 is not optional.

US-964 — what this gate was missing
----------------------------------
The reviewer changed one line in `apps/openpgp/Cargo.toml`, re-acquiring
`fapico2-platform` with default features, and got exit 0 from this script,
`ok: reduced build` included, while the reduced build carried six rows in
`BACKENDS` and advertised only the four trussed-Core groups. Two holes, both
now closed and both re-demonstrable by re-applying that one line:

* the manifest check read the `[features]` table and never `[dependencies]`,
  which is where `default-features = false` lives — so the reduced build it
  measures did not exist, silently. `check_platform_edge_is_not_defaulted`
  asserts the edge in both `[dependencies]` and `[dev-dependencies]`;
* the measurement line was parsed for `N FA records` only, so
  `BACKENDS.len()` — the number that mutation moved from 3 to 6 — was
  printed by the test and thrown away. The gate now requires the count, and
  requires it to equal the three unswitched rows plus one per switch that is
  on. The test itself (`apps/openpgp/tests/advertise_serve.rs`) also derives
  `served` from `BACKENDS` by name in *every* configuration and cross-checks
  it against `cfg!`, so a backend in the table with its switch off fails the
  build that discriminates.

And this gate is wired into CI (the `advertise-serve-gate` job). It was
referenced by nothing outside its own docstring: the default half ran only by
accident, through `cargo test --workspace` picking up the test, and the half
that discriminates was never run by anything.

US-966 — the deferred groups
---------------------------
US-966 (2026-09-27) took Brainpool P-384r1 out of the served set and left
P-256r1 in. That is a *removal*, and the naive way to accommodate a removal in
this gate is to delete the group from the table and say nothing — after which
the gate has no opinion about the curve at all, and the next person to re-add
it gets a green board. This gate instead treats the deferred curves as a
third category with its own assertion:

* `SWITCHED_GROUPS` — a group with a switch. Advertised in the default build,
  absent in the reduced one.
* `CORE_GROUPS` — served by trussed Core in every build; always advertised.
* `DEFERRED_GROUPS` — deliberately never served and never advertised, in
  *every* configuration. The test measures this off the parsed FA records and
  reports it (`US-966 deferred/never-served: NAME=advertised:BOOL`); this gate
  parses that line and requires every value to be `false`, in both
  configurations. A group is not added to this list by being forgotten about
  it; it is added by a story that says why, and the assertion then keeps it out
  until a later story takes it out of this list.

P-384r1 joined this list in US-966 (deferred for want of deployment pull: the
OpenPGP card spec v3.4 §4.4.3.10 only requires "at least one of this curves
shall be supported", RFC 8734 deprecated Brainpool for TLS 1.3 "because they
had little usage", and no OpenPGP-card user was found). P-512r1 has been in it
since US-944 (no `bp512` crate exists). Note that the reported booleans are
read off the FA records by the test, not printed as constants — a report line
that printed `advertised:false` regardless would be this epic's recurring
failure mode (US-961, US-964) wearing a new hat.

Usage:
    python3 tests/scripts/check_advertise_serve_coupling.py
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET = "x86_64-unknown-linux-gnu"
PKG = "fapico2-openpgp"
TEST = "advertise_serve"

APP_CARGO = ROOT / "apps/openpgp/Cargo.toml"
FIRMWARE_CARGO = ROOT / "firmware/Cargo.toml"
OPCARD_CARGO = ROOT / "vendor/opcard/Cargo.toml"

# The groups that have a switch, and the number of FA records each contributes
# (one per usage tag: C1, C2, C3).
#
# US-966: BRAINPOOL_P384R1 used to be here. It is now in `DEFERRED_GROUPS` —
# see the docstring. It is *not* simply absent: a gate that has forgotten a
# group cannot tell a deliberate removal from a regression.
SWITCHED_GROUPS = ("SECP256K1", "BRAINPOOL_P256R1",
                   "RSA_2048", "RSA_3072", "RSA_4096")
# The groups served by trussed Core, which both manifests enable
# unconditionally — present in every configuration.
CORE_GROUPS = ("P_256", "P_384", "P_521", "ED_25519")
# US-966: the curves this card deliberately does not serve, in ANY
# configuration. Each must be absent from FA and refused `6A80` at PUT DATA, in
# both builds. P-384r1 was deferred for deployment pull; P-512r1 never had a
# crate behind it.
DEFERRED_GROUPS = ("BRAINPOOL_P384R1", "BRAINPOOL_P512R1")

REPORT = re.compile(
    r"US-962 advertise/serve: (?P<records>\d+) FA records; "
    r"C1 advertises \[(?P<groups>[^\]]*)\]; "
    r"served secp256k1=(?P<secp>\w+) brainpool=(?P<bp>\w+) rsa=(?P<rsa>\w+)"
)

# US-966: the test's measured "is this deferred curve in the FA reply?" line.
# One `NAME=advertised:BOOL` pair per deferred group, in the order the test
# prints them. This is the line that makes the *removal* an assertion instead
# of a deletion: it is computed from the parsed FA records, so it can only say
# `true` if the card really is advertising the curve.
DEFERRED_LINE = re.compile(r"US-966 deferred/never-served: (?P<body>.+)$")
DEFERRED_ENTRY = re.compile(r"(?P<name>[A-Z0-9_]+)=advertised:(?P<advertised>true|false)")

# The second test's line: how many rows the serving table actually has in this
# build, next to what the app's switches say. US-964: the gate used to parse
# only the `N FA records` line above, so `BACKENDS.len()` — the number the
# reviewer's mutation moved from 3 to 6 — was printed and then ignored.
CONFIG = re.compile(
    r"US-962 advertise/serve: secp256k1-backend=(?P<secp>\w+) "
    r"brainpool-backend=(?P<bp>\w+) rsa-backend=(?P<rsa>\w+) "
    r"\(backends in the table: (?P<table>\d+)\)"
)

# The three rows every configuration of this workspace carries: trussed-staging,
# trussed-auth and trussed Core. None of them has an algorithm switch.
UNSWITCHED_BACKENDS = 3


def fail(msg: str) -> None:
    print(f"FAIL: check_advertise_serve_coupling (US-962) — {msg}")


def run(label: str, features: list[str]) -> tuple[str, str, str, list[str]]:
    cmd = ["cargo", "test", "-p", PKG, "--target", TARGET, "--test", TEST]
    if features:
        cmd += ["--no-default-features", "--features", ",".join(features)]
    cmd += ["--", "--nocapture"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        return "", "", "", [
            f"{label}: `{' '.join(cmd)}` failed (exit {proc.returncode})\n"
            + "\n".join((proc.stdout + proc.stderr).splitlines()[-25:])
        ]
    match = None
    config = None
    deferred = None
    for line in proc.stdout.splitlines():
        found = REPORT.search(line)
        if found and "FA records" in line:
            match = found
        found = CONFIG.search(line)
        if found:
            config = found
        found = DEFERRED_LINE.search(line)
        if found:
            deferred = found
    if match is None:
        return "", "", "", [
            f"{label}: the test passed but printed no measurement line — the gate "
            "refuses to report green on a test that is not reporting what it "
            "measured (the US-961 failure mode)"
        ]
    if config is None:
        return "", "", "", [
            f"{label}: the test passed but printed no serving-table line — the gate "
            "refuses to report green without the count of rows in `BACKENDS`, which "
            "is the one number the US-964 reviewer's manifest mutation moved"
        ]
    if deferred is None:
        return "", "", "", [
            f"{label}: the test passed but printed no `US-966 deferred/never-served:` "
            "line — the gate has no measurement of whether a deferred curve is in the "
            "FA reply, so it cannot tell a deliberate removal from a regression. "
            "Absence of the line is treated as a failure, not as a pass"
        ]
    return match.group(0), config.group(0), deferred.group("body"), []


def check_configuration(label: str, features: list[str], *,
                        want_switched: bool) -> list[str]:
    """Build `label` and require FA to match what the dispatch serves there."""
    line, config_line, deferred_body, errs = run(label, features)
    if errs:
        return errs
    found = REPORT.search(line)
    cfg_found = CONFIG.search(config_line)
    assert found is not None and cfg_found is not None
    records = int(found.group("records"))
    groups = {g.strip() for g in found.group("groups").split(",") if g.strip()}
    served = {
        "secp256k1": found.group("secp") == "true",
        "brainpool": found.group("bp") == "true",
        "rsa": found.group("rsa") == "true",
    }

    # The build's own switches must agree with what it serves. `served` is read
    # off `BACKENDS` by the test and re-checked against `cfg!` there, so this
    # is the same measurement restated where the gate can see it: a mismatch
    # means the two halves of the US-962 coupling came apart inside one build.
    switched_cfg = {
        "secp256k1": cfg_found.group("secp") == "true",
        "brainpool": cfg_found.group("bp") == "true",
        "rsa": cfg_found.group("rsa") == "true",
    }
    if switched_cfg != served:
        errs.append(
            f"{label}: this build's switches say {switched_cfg} but the dispatch "
            f"serves {served} — the app crate is the only place that can see both "
            "sides, so they cannot be allowed to disagree inside one build"
        )

    # …and the serving table must hold exactly the unswitched rows plus one per
    # enabled switch. This is the number the reviewer's one-line manifest
    # mutation changed from 3 to 6 in the reduced build while every other
    # signal stayed green.
    table = int(cfg_found.group("table"))
    expected_table = UNSWITCHED_BACKENDS + sum(1 for on in switched_cfg.values() if on)
    if table != expected_table:
        errs.append(
            f"{label}: the serving table has {table} rows, {expected_table} expected "
            f"(the {UNSWITCHED_BACKENDS} unswitched rows — staging, auth, Core — plus "
            f"one per switch that is on: {switched_cfg}). A build whose table grew a "
            "backend its switches do not name serves algorithms FA never advertises; "
            "the usual cause is a manifest that re-acquires fapico2-platform with "
            "default features, which silently restores all three backends"
        )

    # Nothing core may go missing: those five groups are served by trussed
    # Core in every configuration of this workspace.
    missing_core = set(CORE_GROUPS) - groups
    if missing_core:
        errs.append(
            f"{label}: FA stopped advertising the trussed-Core groups "
            f"{sorted(missing_core)} — no switch exists for them, so this is a "
            "regression, not a coupling fix"
        )

    switched_present = sorted(set(SWITCHED_GROUPS) & groups)
    if want_switched:
        missing = set(SWITCHED_GROUPS) - groups
        if missing:
            errs.append(
                f"{label}: the production build must still advertise every group it "
                f"serves, but FA is missing {sorted(missing)} (served: {served}). "
                "US-962 must not buy honesty by withdrawing a capability"
            )
    else:
        if switched_present:
            errs.append(
                f"{label}: the dispatch serves {served} (no software backend in "
                f"this configuration) yet FA still advertises {switched_present}. "
                "This is the US-962 defect: a host reads the capability, trusts it, "
                "and every request then falls through to trussed Core and fails"
            )
    if not served["secp256k1"] and not served["brainpool"] and not served["rsa"] and records != len(CORE_GROUPS) * 3:
        errs.append(
            f"{label}: with no software backend the reply must carry exactly the "
            f"{len(CORE_GROUPS) * 3} trussed-Core records, got {records}"
        )

    # US-966: FA must name *exactly* the expected set in this configuration —
    # no more (a deferred or unserved curve sneaking back in) and no less (a
    # served group silently dropped, which the "must still advertise" arm above
    # only catches for the switched groups).
    expected_groups = set(CORE_GROUPS)
    if want_switched:
        expected_groups |= set(SWITCHED_GROUPS)
    unexpected = groups - expected_groups
    missing_groups = expected_groups - groups
    if unexpected or missing_groups:
        errs.append(
            f"{label}: C1 advertises {sorted(groups)}, but this configuration is "
            f"required to advertise exactly {sorted(expected_groups)}"
            + (f" — unexpected {sorted(unexpected)}" if unexpected else "")
            + (f" — missing {sorted(missing_groups)}" if missing_groups else "")
            + ". The exact set is the assertion; a subset check would let a group "
            "drop out of FA, or a deferred curve come back, without the gate "
            "noticing"
        )

    # US-966: every deferred group must measure as unadvertised. The booleans
    # are read off the FA records by the test, not printed as constants.
    measured = {
        m.group("name"): m.group("advertised") == "true"
        for m in DEFERRED_ENTRY.finditer(deferred_body)
    }
    unmeasured = sorted(set(DEFERRED_GROUPS) - set(measured))
    if unmeasured:
        errs.append(
            f"{label}: the test's deferred-curve line did not report {unmeasured} — "
            f"it reported {sorted(measured)}. A group the gate cannot see is a group "
            "the gate cannot hold out; add it to `DEFERRED` in the test as well as "
            "here, or the removal is unpinned"
        )
    came_back = sorted(n for n, adv in measured.items() if adv)
    if came_back:
        errs.append(
            f"{label}: FA advertises the deferred group(s) {came_back}. "
            + "; ".join(
                f"{n} is "
                + ("deferred to a follow-up release by US-966 — no OpenPGP-card user "
                   "was found, and the IETF deprecated Brainpool for TLS 1.3 (RFC 8734)"
                   if n == "BRAINPOOL_P384R1" else
                   "unserved since US-944 — no bp512 crate exists")
                for n in came_back
            )
            + ". Either take it out of `DEFERRED_GROUPS` in a story that says so, or "
            "take it back out of the build"
        )
    print(f"  {label}: {records} FA records, C1 advertises {sorted(groups)}, "
          f"served {served}, {table} rows in the serving table, "
          f"deferred measured {measured}")
    return errs


def feature_table(path: pathlib.Path) -> dict[str, list[str]]:
    """The `[features]` table of a manifest as `feature -> edges`.

    Python 3.9 here, so no `tomllib`. The `[features]` table is a flat list of
    `name = [...]` (or `name = ["a", "b"]` spanning lines) and nothing else in
    the file looks like that, so a bounded scan of the section is enough.
    Comments are stripped first: these manifests document the wiring in prose
    right next to the wiring, and prose must not be read as wiring.
    """
    text = re.sub(r"^\s*#.*$", "", path.read_text(encoding="utf-8"), flags=re.M)
    section = re.search(r"^\[features\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if section is None:
        return {}
    table: dict[str, list[str]] = {}
    for name, body in re.findall(r"^([\w-]+)\s*=\s*\[(.*?)\]", section.group(1), re.M | re.S):
        table[name] = re.findall(r'"([^"]+)"', body)
    return table


def dependency_entry(path: pathlib.Path, section: str, name: str) -> str | None:
    """The one-line `name = { ... }` entry of `name` inside `[section]`.

    Sections are scanned to the next `[`, comments stripped first: these
    manifests document the wiring in prose right beside the wiring.
    """
    text = re.sub(r"^\s*#.*$", "", path.read_text(encoding="utf-8"), flags=re.M)
    body = re.search(
        rf"^\[{re.escape(section)}\]\n(.*?)(?=^\[|\Z)", text, re.M | re.S
    )
    if body is None:
        return None
    found = re.search(
        rf"^{re.escape(name)}\s*=\s*(\{{[^}}]*\}})", body.group(1), re.M
    )
    return found.group(1) if found else None


def check_platform_edge_is_not_defaulted() -> list[str]:
    """`fapico2-platform` must be acquired with `default-features = false`.

    US-964. The reduced configuration this gate measures is only a reduced
    configuration because of this one edge: with the platform's defaults on,
    `cargo test --no-default-features --features "virt,device"` re-enables
    every backend through the dependency, and the build under test has three
    backends in `BACKENDS` with all three app switches off. That is not a
    hypothetical: the reviewer made this exact one-line change and every
    signal stayed green — the manifest check included, because it read the
    `[features]` table and never `[dependencies]`, which is where this edge
    lives.

    The dev-dependency is checked symmetrically: it is the edge the *tests*
    get their platform from, so re-enabling defaults there would restore the
    backends for the reduced test build the same way.
    """
    errs: list[str] = []
    for section in ("dependencies", "dev-dependencies"):
        entry = dependency_entry(APP_CARGO, section, "fapico2-platform")
        if entry is None:
            errs.append(
                f"apps/openpgp/Cargo.toml no longer acquires `fapico2-platform` in "
                f"`[{section}]` — the reduced configuration this gate measures is "
                "built from that edge"
            )
            continue
        if 'path = "../../platform"' not in entry:
            errs.append(
                f"apps/openpgp's `fapico2-platform` in `[{section}]` is {entry}: the "
                'path edge must stay `path = "../../platform"`'
            )
        if "default-features = false" not in entry:
            errs.append(
                f"apps/openpgp's `fapico2-platform` in `[{section}]` is {entry}: it "
                "must carry `default-features = false`. The platform's default "
                "features turn on all three software backends, so a build with this "
                "edge defaulted serves every group regardless of the switches below, "
                "advertises none of them in the reduced configuration, and still "
                "passes every check that only reads `[features]` — the US-964 "
                "reviewer's mutation, verbatim"
            )
    return errs


# The opcard feature each app switch turns on for the *advertisement* half.
# (`virt` needs none of these — it only builds the dispatch type.)
ADVERTISEMENT_EDGE = {
    "rsa-backend": "opcard?/rsa4096-gen",
    "secp256k1-backend": "opcard?/secp256k1-backend",
    "brainpool-backend": "opcard?/brainpool-backend",
}


def check_one_switch_per_group() -> list[str]:
    """Each algorithm group must be reachable through exactly one switch.

    `fapico2-openpgp` is the only crate that can see both sides, so it is the
    only place allowed to name either. Anything else that turns a backend on
    is a way to move one side without the other — the wiring this story
    exists to make singular.
    """
    errs: list[str] = []
    errs.extend(check_platform_edge_is_not_defaulted())
    app = feature_table(APP_CARGO)
    firmware = feature_table(FIRMWARE_CARGO)

    for backend, advert_edge in ADVERTISEMENT_EDGE.items():
        serving_edge = f"fapico2-platform/{backend}"
        if backend not in app:
            errs.append(
                f"apps/openpgp declares no `{backend}` feature — the app crate is the "
                "only crate that can see the serving side and the advertising side, so "
                "it must carry the switch that moves them together"
            )
            continue
        edges = app[backend]
        for required in (serving_edge, advert_edge):
            if required not in edges:
                errs.append(
                    f"apps/openpgp's `{backend}` does not forward to `{required}`; "
                    f"its edges are {edges}"
                )

    # No *other* app feature may reach a backend, from either side.
    for name, edges in app.items():
        if name in ADVERTISEMENT_EDGE:
            continue
        for edge in edges:
            if re.search(r"fapico2-platform/(rsa|secp256k1|brainpool)-backend", edge):
                errs.append(
                    f"apps/openpgp's `{name}` reaches `{edge}` directly; the "
                    f"{name} group must be reachable only through its own switch"
                )
            if re.search(r"opcard\?/(rsa|secp256k1|brainpool)-backend|opcard\?/rsa\d+-gen", edge):
                errs.append(
                    f"apps/openpgp's `{name}` reaches `{edge}` directly; the "
                    "advertisement half must be reachable only through its own switch"
                )

    # The firmware must go through the app's switch, never the platform's.
    for name, edges in firmware.items():
        for edge in edges:
            if re.search(r"fapico2-platform/(rsa|secp256k1|brainpool)-backend", edge):
                errs.append(
                    f"firmware's `{name}` names `{edge}` directly — the device build "
                    "must select the OpenPGP algorithm groups through "
                    "`fapico2-openpgp/<group>`, which is the switch that couples "
                    "advertise and serve"
                )
    # …and it must take all three in both of the configurations it builds.
    for name in ("device", "emulation"):
        if name not in firmware:
            errs.append(f"firmware no longer declares a `{name}` feature")
            continue
        for backend in ADVERTISEMENT_EDGE:
            edge = f"fapico2-openpgp/{backend}"
            if edge not in firmware[name]:
                errs.append(
                    f"firmware's `{name}` build does not enable `{edge}` — the "
                    "production configuration must keep serving and advertising every "
                    "group it had before US-962"
                )

    # opcard's `virt` must not smuggle a backend back in: that is how the
    # advertisement used to be switched on implicitly.
    opcard = re.sub(r"^\s*#.*$", "", OPCARD_CARGO.read_text(encoding="utf-8"), flags=re.M)
    virt = re.search(r"^virt\s*=\s*\[(.*?)\]", opcard, re.M | re.S)
    if virt is None:
        errs.append("vendor/opcard/Cargo.toml no longer declares a `virt` feature")
    else:
        for backend in ("secp256k1-backend", "brainpool-backend"):
            if backend in virt.group(1):
                errs.append(
                    f"opcard's `virt` feature still force-enables `{backend}`: the "
                    "advertisement would then be switched on by something other than "
                    "the switch that turns on the backend"
                )
    return errs


def main() -> int:
    print("check_advertise_serve_coupling (US-962 I2)")
    failures: list[str] = []
    errs = check_one_switch_per_group()
    failures.extend(errs)
    print(("FAIL: one switch per algorithm group" if errs else "ok: one switch per algorithm group"))

    for label, features, want in (
        ("default build", [], True),
        ("reduced build (no backends)", ["virt", "device"], False),
    ):
        errs = check_configuration(label, features, want_switched=want)
        failures.extend(errs)
        print(("FAIL: " if errs else "ok: ") + label)

    if failures:
        for f in failures:
            fail(f)
        return 1
    print("ok: FA advertises exactly what the dispatch serves, in both the "
          "production and the backend-free configuration, and the deferred "
          "curves are absent from both")
    return 0


if __name__ == "__main__":
    sys.exit(main())
