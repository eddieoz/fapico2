#!/usr/bin/env python3
"""US-919: the foreign-image wipe is a build parameter with a pinned default.

The control used to be a cargo feature in `default`. It fired on every
legitimate firmware update, because the manifest hash changes when the
image changes, and it destroyed the keystore every time — the operator
experience that motivated this change. It is now the environment variable
`FAPICO2_FOREIGN_IMAGE_WIPE`, resolved in `firmware/build.rs`.

The resolution has three moving parts, and a default that is merely
"intended" is one refactor away from being wrong in the direction that
destroys data or the direction that quietly drops a control. So this
gate reads the ACTUAL cfg the compiler is given, with `cargo rustc --
--print cfg`, rather than re-deriving the rule in Python: a second
implementation of the rule is a second thing to be wrong, and this one
would still pass while `build.rs` said the opposite.

  device build, unset      -> OFF   (the shipping default)
  device build, =1         -> ON    (data-loss-over-implant)
  device build, =0         -> OFF
  host build,   unset      -> ON    (the e2e arms that PROVE the wipe)
  host build,   =0         -> OFF
  any build,  =banana      -> BUILD FAILS

The last one is the one a boolean-getter would get wrong. This variable
decides whether an image mismatch DESTROYS every credential, so an
unrecognised value must stop the build rather than pick a side.

Also asserted structurally:

  * the `foreign-image-wipe` cargo feature is GONE — a feature that
    silently still exists is a second way to select the wipe, and the two
    would disagree;
  * every gate is `cfg(FAPICO2_FOREIGN_IMAGE_WIPE)`, not a feature cfg,
    so there is exactly one selector;
  * the disabled arm's log line no longer claims "(dev build)", which it
    did while the device default was ON and is now the shipping path.

Stdlib only, python >= 3.9. Usage:
    python3 tests/scripts/check_foreign_image_wipe.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HOST_TARGET = "x86_64-unknown-linux-gnu"
CFG = "FAPICO2_FOREIGN_IMAGE_WIPE"

failures: list[str] = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"  [FAIL] {msg}")


def ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def _build_script_binary(tmp: Path) -> Path | None:
    """Compile `firmware/build.rs` once, so the checks below run the REAL
    build script rather than a re-implementation of its rule.

    A second implementation of the default is a second thing to be wrong,
    and it would keep passing while `build.rs` said the opposite. The
    script is std-only and takes its inputs from the environment, so this
    costs one `rustc` and nothing else.

    (The first version of this gate asked cargo instead — `cargo rustc --
    --print cfg`. That is unreliable: when cargo considers the unit fresh
    it does not re-invoke rustc, so `--print cfg` prints nothing at all and
    a build that really did set the cfg reads as one that did not.)
    """
    bin = tmp / "fapico2-build-script"
    src = REPO_ROOT / "firmware" / "build.rs"
    proc = subprocess.run(
        ["rustc", "--edition", "2021", "-o", str(bin), str(src)],
        capture_output=True, text=True)
    if proc.returncode != 0:
        tail = (proc.stderr or "")[-500:]
        fail("firmware/build.rs does not compile standalone, so this gate cannot "
             "test the production rule:\n  " + tail + "\n  The gate compiles it "
             "directly rather than re-implementing the default in Python; if "
             "build.rs grows a dependency, fix the gate, do not delete the check.")
        return None
    return bin


def _run_build_script(bin: Path, tmp: Path, *, device: bool,
                      value: str | None) -> tuple[bool | None, str]:
    """(does it emit the cfg?, output). None = the script refused to run."""
    out_dir = tmp / ("device-out" if device else "host-out")
    out_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    # `CARGO_FEATURE_*` is how cargo tells a build script which optional
    # features are on. Cargo sets it; a bare shell does not, so the device
    # rows have to set it explicitly or they would silently be host builds.
    for stale in [k for k in env if k.startswith("CARGO_FEATURE_")]:
        del env[stale]
    if device:
        env["CARGO_FEATURE_DEVICE"] = "1"
    env["CARGO_MANIFEST_DIR"] = str(REPO_ROOT / "firmware")
    env["OUT_DIR"] = str(out_dir)
    env.pop(CFG, None)
    if value is not None:
        env[CFG] = value
    proc = subprocess.run([str(bin)], capture_output=True, text=True, env=env)
    combined = (proc.stdout or "") + (proc.stderr or "")
    if "is not a yes/no value" in combined:
        return None, combined
    if proc.returncode != 0:
        return None, combined
    return f"rustc-cfg={CFG}" in proc.stdout, combined


def expect(tmp: Path, bin: Path, label: str, want: bool, *,
           device: bool, value: str | None) -> None:
    got, out = _run_build_script(bin, tmp, device=device, value=value)
    if got is None:
        fail(f"{label}: the build script refused to run\n{out[-400:]}")
    elif got is want:
        ok(f"{label}: cfg {'SET' if got else 'not set'} (as required)")
    else:
        fail(f"{label}: expected cfg {'SET' if want else 'NOT set'}, "
             f"got {'SET' if got else 'not set'}")


def check_invalid_value_stops_the_build(tmp: Path, bin: Path) -> None:
    out_dir = tmp / "device-out"
    out_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["CARGO_FEATURE_DEVICE"] = "1"
    env["CARGO_MANIFEST_DIR"] = str(REPO_ROOT / "firmware")
    env["OUT_DIR"] = str(out_dir)
    env[CFG] = "banana"
    proc = subprocess.run([str(bin)], capture_output=True, text=True, env=env)
    combined = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        fail(f"{CFG}=banana was ACCEPTED — an unrecognised value must stop the "
             "build, not pick a side on a decision that destroys credentials")
    elif "is not a yes/no value" not in combined:
        fail(f"{CFG}=banana failed, but not via the guard (unrelated error?)\n"
             f"{combined[-600:]}")
    else:
        ok(f"{CFG}=banana refused by the build.rs guard (as required)")


def check_feature_is_gone() -> None:
    hits: list[str] = []
    me = Path(__file__).resolve()
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or "target" in path.parts or ".git" in path.parts:
            continue
        # This file necessarily contains the literals it searches for.
        if path.resolve() == me:
            continue
        if path.suffix not in (".rs", ".toml", ".sh", ".py", ".md"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # Only the flag name, not the prose that explains its removal.
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("!'") or \
               stripped.startswith('"') or stripped.startswith("'"):
                continue
            if 'feature = "foreign-image-wipe"' in line or \
               line.strip() == "foreign-image-wipe = []" or \
               '"foreign-image-wipe"' in line:
                hits.append(f"{path.relative_to(REPO_ROOT)}:{i}: {stripped[:80]}")
    if hits:
        fail("the `foreign-image-wipe` cargo feature is still selectable, so two "
             "mechanisms can turn the wipe on and they will disagree:\n  "
             + "\n  ".join(hits))
    else:
        ok("the `foreign-image-wipe` cargo feature is gone — the env var is the "
           "only selector")


def check_gates_are_the_cfg() -> None:
    bad: list[str] = []
    for f in ("firmware/src/boot.rs", "firmware/src/emul_main.rs"):
        text = (REPO_ROOT / f).read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            if "#[cfg(" in line and "FOREIGN_IMAGE_WIPE" in line and \
               "feature =" in line:
                bad.append(f"{f}:{i}: {line.strip()[:80]}")
    if bad:
        fail("a wipe gate still mixes the cfg with a feature:\n  " + "\n  ".join(bad))
    else:
        ok("every wipe gate is cfg(FAPICO2_FOREIGN_IMAGE_WIPE)")


def _strip_line_comments(text: str) -> str:
    """Drop `//` comments, keeping line count (no `//` appears in a Rust
    string literal on these lines, which is the same documented limitation
    check_rng_path.py's lexer has)."""
    out = []
    for line in text.splitlines():
        i = line.find("//")
        out.append("" if i < 0 else line[:i])
    return "\n".join(out)


def check_disabled_arm_log_is_honest() -> None:
    # Comments are stripped first: the reason the old wording is wrong is
    # written in a comment right next to the fix, and a check that cannot
    # tell its own explanation from the code it polices will forbid the
    # explanation too.
    text = _strip_line_comments(
        (REPO_ROOT / "firmware" / "src" / "boot.rs").read_text(encoding="utf-8"))
    if "wipe disabled (dev build)" in text:
        fail("the disabled arm's log still says \"(dev build)\". That was true "
             "when only emulation could reach it; the device default is now OFF, "
             "so a release image logs it and tells the operator the wrong thing "
             "about what they flashed.")
    else:
        ok("the disabled arm no longer mislabels itself a dev build")


def main() -> int:
    print(f"US-919 foreign-image wipe build parameter ({REPO_ROOT})\n")

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bin = _build_script_binary(tmp)
        if bin is None:
            print("\nRESULT: FAIL (the build script could not be exercised)")
            return 1

        print("  resolution (the REAL build script, compiled and run directly)")
        expect(tmp, bin, "device build, unset", False, device=True, value=None)
        expect(tmp, bin, "device build, =1", True, device=True, value="1")
        expect(tmp, bin, "device build, =0", False, device=True, value="0")
        expect(tmp, bin, "host build,   unset", True, device=False, value=None)
        expect(tmp, bin, "host build,   =0", False, device=False, value="0")

        print("\n  input handling")
        check_invalid_value_stops_the_build(tmp, bin)

    print("\n  structure")
    check_feature_is_gone()
    check_gates_are_the_cfg()
    check_disabled_arm_log_is_honest()

    print()
    if failures:
        n = len(failures)
        print(f"RESULT: FAIL ({n} check(s) — the wipe parameter does not resolve "
              f"the way the security documentation says it does)")
        return 1
    print(f"RESULT: PASS (wipe is a build parameter: device OFF by default, "
          f"host ON; {CFG}=1 selects it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
