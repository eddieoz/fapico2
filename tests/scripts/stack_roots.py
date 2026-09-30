"""Shared, **mangling-independent** root selection for the two stack gates.

US-961. Why this module exists
------------------------------
`check_boot_chain.py` (US-956/US-957) and `check_async_frame.py`
(US-939/US-951) select their root symbols with hard-coded rustc **legacy**
(`_ZN...$LT$...$GT$`) mangling fragments. Since rustc switched the default to
**v0** mangling (`_RNv...`, length-prefixed identifiers) those patterns match
**nothing**: the boot-chain gate was finding 4 "roots" instead of the 6 task
polls the ELF actually contains, and **zero** of the 18
`dispatch::App` vtable shims — the class US-957 added specifically to cover
the request-serving path. It still exited 0 with a reassuring `PASS`, because
the degradation was only visible in a `--json` field nobody reads. A large
future frame on the CCID path would have merged behind a green gate.

Two rules fix that, and both live here so the two gates cannot drift apart
again (a third variant of "two gates, two root sets" is the same defect):

1. **Match on identifiers that survive both mangling schemes.** A v0
   mangled path prints every module as `<len><name>` and every method as
   `<len><name>`, dropping a crate prefix once it has already been printed
   (`…NtNtB28_8dispatch3App7process…` — the `fapico2_platform` is gone but
   `dispatch` / `App` / `process` remain). Legacy prints `..` separators and
   the `$GT$` turbofish. The matchers below accept either spelling of the
   separator (`(?:\.{1,2}|3)` = `..` legacy, `<len>` v0) and never anchor on a
   crate name, because path compression legitimately removes it.

2. **Assert the root set is complete, from a source-derived floor, or the
   gate FAILS.** `expected_task_roots()` counts the `#[task]` / `#[main]`
   declarations in the *device binary's own module tree* and
   `expected_vtable_roots()` counts the apps the device actually registers
   behind the AID dispatcher. Neither number comes from the ELF, so a
   mangling change that blinds a matcher shows up as a mismatch instead of a
   silent PASS. A floor that cannot be derived is itself a FAIL — a gate that
   quietly stops having a floor is the same defect one level up.

Usage:
    import stack_roots
    roots = [s for s in symbols if stack_roots.is_task_poll(s)]
    ... stack_roots.check_root_coverage(found, class) -> list[str] of failures
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The device binary: `firmware/Cargo.toml` `[[bin]] name = "fapico2-firmware",
# path = "src/main.rs"`. Tasks live in that binary's module tree (main.rs +
# `tasks.rs` + `button.rs`); the sibling binaries under `firmware/src/bin/`
# (bringup / bridge / hwtest) are separate crates and are deliberately not
# walked.
DEVICE_BIN = ROOT / "firmware/src/main.rs"

# The single source of truth for the device's AID-dispatched app set
# (`apps/src/registry.rs` doc comment: "The device wires exactly four CCID
# apps behind the AID dispatcher").
APP_REGISTRY = ROOT / "apps/src/registry.rs"

# --- matchers -------------------------------------------------------------
#
# An Embassy task poll is `<TaskStorage<F>>::poll`, a monomorphised
# instantiation of `embassy_executor::raw::TaskStorage::poll`. The two
# components that never change are the `embassy_executor` crate, the `raw`
# module, the `TaskStorage` type, and the `poll` method; only the separators
# between them differ between mangling schemes.
TASK_POLL = re.compile(
    r"embassy_executor(?:\.{1,2}|3)raw"   # legacy `..raw` / v0 `3raw`
    r".*TaskStorage"                        # the type, verbatim in both
    r".*(?:4|\.\.)poll"                    # legacy `..poll` / v0 `4poll`
)

# The `App` vtable shims the dispatcher reaches through `Vec<&mut dyn App, N>`.
# `platform/src/dispatch.rs` module path, the `App` trait, and the five
# request-path methods; every one of them is length-prefixed on the method
# side, and `App` carries the `$GT$` turbofish under legacy mangling.
APP_SHIM = re.compile(
    r"dispatch(?:\.{1,2}|3)App(?:\$GT\$|E)?"          # legacy `..App$GT$` / v0 `3App`
    r"\d+(?:select_apdu|factory_wipe|deselect|process|select)h?"
)

# `App::process` on its own: the per-APDU entry point the US-957 surcharge
# exists to cover. Counted separately because a matcher that finds the other
# four methods but not `process` is still blind to the request path.
APP_PROCESS_SHIM = re.compile(
    r"dispatch(?:\.{1,2}|3)App(?:\$GT\$|E)?\d+processh?"
)


def is_task_poll(sym: str) -> bool:
    return bool(TASK_POLL.search(sym))


def is_app_shim(sym: str) -> bool:
    return bool(APP_SHIM.search(sym))


def is_app_process_shim(sym: str) -> bool:
    return bool(APP_PROCESS_SHIM.search(sym))


# --- source-derived floors ------------------------------------------------

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
                       re.M)
# `#[task]` / `#[main]` attributes. Both embassy spellings and the fully
# qualified forms are accepted; `#[embassy_executor::task]`.
_TASK_ATTR = re.compile(r"#\[\s*(?:embassy_executor\s*::\s*)?(?:task|main)\s*\]")
# `d.register(<app>)` inside `register_ccid_apps` — one vtable-carrying app
# per call, since `Dispatcher::register` takes `&'a mut dyn App`.
_REGISTER_CALL = re.compile(r"\.\s*register\s*\(")


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", text))


def _read(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def declared_task_roots() -> int | None:
    """`#[task]` / `#[main]` declarations in the device binary's module tree.

    Walks `mod NAME;` out of `firmware/src/main.rs` so the count is the tasks
    that are *actually* compiled into the release ELF, not every task-shaped
    attribute in the repository (the `firmware/src/bin/*` bring-up binaries
    each carry their own `#[main]` and one `#[task]`, and none of them is the
    device image).

    Returns `None` if the tree cannot be read — callers MUST treat that as a
    FAIL, not as "no floor".
    """
    if not DEVICE_BIN.exists():
        return None
    seen: set[pathlib.Path] = set()
    pending = [DEVICE_BIN]
    total = 0
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        text = _read(path)
        if not text:
            return None
        stripped = _strip_comments(text)
        total += len(_TASK_ATTR.findall(stripped))
        for name in _MOD_DECL.findall(stripped):
            for cand in (path.parent / f"{name}.rs", path.parent / name / "mod.rs"):
                if cand.exists():
                    pending.append(cand)
                    break
            else:
                return None
    return total


def registered_ccid_apps() -> int | None:
    """Apps registered behind the AID dispatcher, from the registry source.

    `apps/src/registry.rs` is documented as the single source of truth for the
    device's CCID app set; each `d.register(…)` inside `register_ccid_apps` is
    one `&mut dyn App` coercion and therefore one vtable in the ELF. `None`
    when the registry cannot be read or the helper cannot be found — again a
    FAIL for the caller, not a skipped floor.
    """
    text = _strip_comments(_read(APP_REGISTRY))
    if not text:
        return None
    start = text.find("pub fn register_ccid_apps")
    if start < 0:
        return None
    body = text[start:]
    # The helper is the last function in the file today; bound the scan to its
    # body so a *test* module that registers more apps cannot inflate the
    # floor (platform/src/dispatch.rs has exactly this hazard, which is why the
    # count is taken from the registry and not from a `.register(` grep).
    end = body.find("\n}\n")
    if end < 0:
        return None
    n = len(_REGISTER_CALL.findall(body[:end]))
    return n or None


# --- coverage assertion ---------------------------------------------------

def check_root_coverage(
    task_roots: list[str],
    shim_roots: list[str],
) -> list[str]:
    """Return the list of coverage failures. Empty list == coverage is complete.

    Deliberately a *hard* gate, not a warning: the whole failure this exists
    to prevent is a root set that quietly shrinks while the gate keeps
    exiting 0.
    """
    failures: list[str] = []
    want_tasks = declared_task_roots()
    if want_tasks is None:
        failures.append(
            "could not derive the expected task-root count from "
            f"{DEVICE_BIN.relative_to(ROOT)} — the floor itself is gone, so a "
            "root set that silently shrinks to one entry would pass. Restore "
            "the source scan (tests/scripts/stack_roots.py) before trusting a "
            "PASS."
        )
    elif len(task_roots) != want_tasks:
        failures.append(
            f"task-root coverage: the ELF yields {len(task_roots)} Embassy "
            f"task-poll root(s) but the device binary declares {want_tasks} "
            f"`#[task]`/`#[main]` task(s) in its module tree. Either the matcher "
            "has stopped seeing tasks it used to see (a rustc mangling-scheme "
            "change is the usual cause, and it silently turns this gate back "
            "into a partial measurement while still printing PASS), or a "
            "declared task is not linked (never spawned, or eliminated by LTO). "
            "Found: " + ", ".join(sorted(s[-48:] for s in task_roots))
        )

    want_shims = registered_ccid_apps()
    if want_shims is None:
        failures.append(
            "could not derive the expected vtable-root count from "
            f"{APP_REGISTRY.relative_to(ROOT)} — the vtable floor is gone, so "
            "an empty request-serving root set would pass. Restore the source "
            "scan (tests/scripts/stack_roots.py)."
        )
    else:
        n_process = sum(1 for s in shim_roots if is_app_process_shim(s))
        if n_process < want_shims:
            failures.append(
                f"vtable-root coverage: only {n_process} `App::process` "
                f"vtable root(s) for {want_shims} registered CCID app(s) "
                f"({len(shim_roots)} request-path shim(s) in total). The "
                "request-serving path — where RSA, secp256k1 and Brainpool all "
                "live — is no longer measured, and the gate would still report "
                "the unchanged *boot* chain as the worst case."
            )
    return failures
