#!/usr/bin/env python3
"""US-1518 gate: the acceptance runner's exit-code contract.

`scripts/acceptance/run_acceptance.py` needs a board, a browser and (for the
human half) a finger, so nothing in `run_tests.sh` can execute it end to end.
That is exactly why its exit code drifted: the one-liner
`return 1 if machine_fail else 0` sat unexercised while the README told callers
to gate on it, and a **browser-less run exited 0** with `page:enumerates` and
`page:answers_after_abandon` never executed. `88d31cd` fixed the summary count
for the same defect and left the exit code alone.

This gate imports `classify_cases` — the pure function that now *is* the
contract — and pins all four branches, with no hardware:

  * every in-scope machine case PASS               -> 0
  * one machine case FAIL                         -> 1
  * one machine case in scope, no verdict          -> 1   (the fixed defect)
  * machine all PASS + page cases out of scope    -> 0, with the page cases
                                                      still NAMED in
                                                      `out_of_scope`, so a
                                                      board-only run cannot be
                                                      mistaken for a DoD run
  * human-gated cases never move the exit code, in either direction

It also cross-checks the README, because the contract is documented in two
places and the failure this guards was a documentation/code disagreement: the
README's exit-code table must exist, must carry all three codes, and must not
regress to the old bare "Exit code 0 = every machine case passed" phrasing that
`88d31cd` left in place.
"""

import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "acceptance" / "run_acceptance.py"
README = ROOT / "scripts" / "acceptance" / "README.md"


def _load_runner():
    """Import run_acceptance.py by path.

    The module runs its work under `if __name__ == "__main__"`, so importing it
    has no side effects: no board is enumerated, no browser is launched.
    """
    spec = importlib.util.spec_from_file_location("_us1518_runner", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _case(cid, gate, verdict, out_of_scope=False):
    return {"case": cid, "title": cid, "gate": gate, "verdict": verdict,
            "observed": "", "evidence": {}, "out_of_scope": out_of_scope}


def main():
    failures = []
    runner = _load_runner()
    classify = runner.classify_cases

    # --- branch 1: everything in scope passed -> 0 -------------------------
    cases = [_case(f"machine-{i}", "machine", "PASS") for i in range(8)]
    cases += [_case(f"human-{i}", "human", "NOT RUN") for i in range(7)]
    t = classify(cases)
    if t["exit_code"] != 0:
        failures.append(f"all machine PASS -> exit {t['exit_code']}, want 0")
    if not t["complete"]:
        failures.append("all machine PASS -> complete=False")

    # --- branch 2: a machine FAIL -> 1 --------------------------------------
    cases = [_case(f"machine-{i}", "machine", "PASS") for i in range(7)]
    cases += [_case("machine-bad", "machine", "FAIL")]
    t = classify(cases)
    if t["exit_code"] != 1:
        failures.append(f"one machine FAIL -> exit {t['exit_code']}, want 1")
    if t["complete"]:
        failures.append("one machine FAIL -> complete=True")

    # --- branch 3 (THE FIXED DEFECT): in scope, no verdict -> 1 ------------
    # This is the shape the old one-liner got wrong. The page was launched
    # (`--run-browser`), so `page:enumerates` is machine-gated for this run,
    # and it stayed silent. Old code: `machine_fail` empty -> exit 0.
    cases = [_case(f"machine-{i}", "machine", "PASS") for i in range(8)]
    cases += [_case("page:enumerates", "machine", "NOT RUN")]
    cases += [_case("page:answers_after_abandon", "machine", "NOT RUN")]
    t = classify(cases)
    if t["exit_code"] == 0:
        failures.append(
            "in-scope machine cases with no verdict -> exit 0; an unexecuted "
            "case reported SUCCESS (the US-1518 exit-code defect)")
    if t["exit_code"] != 1:
        failures.append(
            f"in-scope not-run machine case -> exit {t['exit_code']}, want 1")
    if len(t["machine_notrun"]) != 2:
        failures.append(
            f"expected 2 not-run machine cases, got {len(t['machine_notrun'])}")

    # A BLOCKED verdict (what page.html reports when WebAuthn is unavailable)
    # is likewise not a pass, and must not slip through as one.
    cases = [_case(f"machine-{i}", "machine", "PASS") for i in range(8)]
    cases += [_case("page:enumerates", "machine", "BLOCKED")]
    t = classify(cases)
    if t["exit_code"] != 1:
        failures.append(f"a BLOCKED machine case -> exit {t['exit_code']}, want 1")

    # --- branch 4: board-only run is green but NAMES what it skipped -------
    # The shape the old code filed under gate="machine" unconditionally.
    cases = [_case(f"machine-{i}", "machine", "PASS") for i in range(8)]
    cases += [_case("human-uv_required", "human", "NOT RUN")]
    cases += [_case("page:enumerates", "browser", "NOT RUN", out_of_scope=True)]
    cases += [_case("page:answers_after_abandon", "browser", "NOT RUN",
                    out_of_scope=True)]
    t = classify(cases)
    if t["exit_code"] != 0:
        failures.append(
            f"board-only run, all 8 machine PASS -> exit {t['exit_code']}, "
            f"want 0")
    if len(t["machine"]) != 8:
        failures.append(
            f"out-of-scope page cases leaked into the machine tally: "
            f"{len(t['machine'])} machine cases, want 8")
    named = {c["case"] for c in t["out_of_scope"]}
    for cid in ("page:enumerates", "page:answers_after_abandon"):
        if cid not in named:
            failures.append(
                f"{cid} is out of scope but not named in out_of_scope, so a "
                f"board-only run would not say what it skipped")

    # --- branch 5: human-gated never moves the exit code ------------------
    for verdict in ("NOT RUN", "PASS", "FAIL"):
        cases = [_case(f"machine-{i}", "machine", "PASS") for i in range(8)]
        cases += [_case("human-uv_required", "human", verdict)]
        t = classify(cases)
        if t["exit_code"] != 0:
            failures.append(
                f"a human-gated case with verdict {verdict} changed the exit "
                f"code to {t['exit_code']}; human-gated cases need a physical "
                f"touch and must never gate an unattended run")

    # --- the two page cases really are the machine-gated pair --------------
    if list(runner.MACHINE_PAGE_CASES) != ["enumerates", "answers_after_abandon"]:
        failures.append(
            f"MACHINE_PAGE_CASES changed shape: {runner.MACHINE_PAGE_CASES}")

    # --- README must state the contract the code now implements ------------
    readme = README.read_text()
    if "## Exit codes" not in readme:
        failures.append("README has no '## Exit codes' section")
    for code in ("`0`", "`1`", "`2`"):
        if code not in readme.split("## Requirements")[0]:
            failures.append(f"README's exit-code table does not document {code}")
    # The exact sentence the defect lived in. It must not come back.
    stale = re.search(r"Exit code `0`\s*=\s*every machine case passed", readme)
    if stale:
        failures.append(
            "README still claims 'Exit code 0 = every machine case passed' — "
            "the claim that was false while two machine-gated cases could go "
            "unexecuted")
    if "NOT CERTIFIED BY THIS RUN" not in readme:
        failures.append(
            "README does not say that a browser-less run does not certify the "
            "browser-discovery DoD")

    # --- and the runner's own banner text the README quotes ---------------
    runner_src = RUNNER.read_text()
    if "NOT CERTIFIED BY THIS RUN" not in runner_src:
        failures.append(
            "the runner no longer prints the NOT CERTIFIED banner the README "
            "and the report's out_of_scope list describe")

    if failures:
        print("FAIL: check_acceptance_exit_code (US-1518)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        "PASS: check_acceptance_exit_code (US-1518) — exit 0 only on an "
        "all-PASS in-scope machine tally; in-scope not-run -> 1; "
        "out-of-scope page cases named, not counted; human-gated cases never "
        "gate; README's contract matches the code"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
