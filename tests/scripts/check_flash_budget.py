#!/usr/bin/env python3
"""US-1534 gate: the flash budget may not reach a data region.

The defect this closes
----------------------

`.github/workflows/ci.yml` carries `FIRMWARE_FLASH_BUDGET_KIB: 1536`, a ratchet
that refuses a shipping UF2 larger than 1,536 KiB. The trussed internal
filesystem started at flash offset `0x102_000` — **1,032 KiB**. So the ratchet
sat 504 KiB *above* the first byte of a region holding every OpenPGP and PIV key
on a provisioned board, and an image the gate accepted could link straight over
it.

Nothing related the two numbers. `check_size_report.py` compared the image
against the budget. The anonymous `const _` block in
`platform/src/trusted_backend/device.rs` compared the trussed window against the
C data partition and the secure slots. Neither read the other, because there was
nothing to read — two correct assertions with no third assertion joining them.

US-1536 fixed the geometry (the window moved to `0x200_000`, above the budget,
with a compile-time assertion in `platform/src/flashmap.rs`). This gate keeps it
correct.

Why this is a separate script and not a line in `check_size_report.py`
--------------------------------------------------------------------------

Two reasons, one of which is the load-bearing one.

* **Fail fast.** `check_size_report.py` runs at `ci.yml:309`, inside the
  device-build job, after a full release build of the ELF. A pull request that
  raises the budget would burn the whole build before anything complained. This
  gate parses two text files, so it belongs in the `gates:` job
  (`ci.yml:636`) — the "structural, no device build" job that exists precisely
  for checks of this kind.
* **No ELF, no coupling.** The invariant is between three *constants*. Reading
  them needs no build output, and importing `check_size_report.py` would drag a
  `subprocess` cargo build into a check that is pure parsing.

What it checks
--------------

1. `ci.yml`'s `FIRMWARE_FLASH_BUDGET_KIB` and `platform/src/flashmap.rs`'s
   `FIRMWARE_FLASH_BUDGET_BYTES` state the same number. A workflow file cannot
   import a Rust constant, so the two must be written down twice — which is
   exactly the shape of drift this gate exists to catch. The code is the source
   of truth; `ci.yml` is what has to follow it.
2. The budget's end offset is at or below the start of every data region the
   flash map declares.
3. The budget is at or below `FIRMWARE_GROWTH_END`, so the 512 KiB of headroom
   that makes raising it a deliberate act still exists.
4. Every data region the flash map declares is inside the board's flash, and
   the regions do not overlap the secure partition.

What it deliberately does not check
-----------------------------------

Whether the shipping UF2 is within the budget — that is the ratchet itself
(`ci.yml:402`), and duplicating it here would create the second number this
gate exists to prevent. Nor does it check the *measured* image size: the size
gate owns that, and `check_size_report.py` already fails on it.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
FLASHMAP = ROOT / "platform" / "src" / "flashmap.rs"
BOARD_DEF = ROOT / "platform" / "board_def.rs"

# --- the three statements of the same number -------------------------------
#
# Three, not two, since 2026-10-07. `platform/board_def.rs` carries a mirror of
# the ratchet — it is compiled into the build scripts without the `platform`
# crate, so it cannot import `flashmap`'s constant — and it is read by
# `Board::validate` and printed into the generated linker script while **no gate
# compared it to anything**. It had already drifted: 1,536 KiB in board_def.rs
# against 1,621 KiB in ci.yml and flashmap.rs. That is the exact failure this
# gate's docstring says it exists to prevent, sitting in a file the gate never
# opened. A mirror is fine; an uncompared mirror is a second source of truth.

CI_BUDGET_RE = re.compile(
    r"^\s*FIRMWARE_FLASH_BUDGET_KIB\s*:\s*([0-9]+)\s*$", re.M
)

# `pub const FIRMWARE_FLASH_BUDGET_BYTES: u32 = 1536 * 1024;` — the expression
# form is accepted so the constant can be written in KiB (which is how it is
# reasoned about) rather than as a hex offset, and the type covers `usize`
# because the block sizes are `usize`.
RUST_CONST_RE = r"^\s*(?:pub\s+)?const\s+{name}\s*:\s*(?:u\d+|usize)\s*=\s*([^;]+);"
HEX_RE = re.compile(r"^0x[0-9A-Fa-f_]+$")
ARITH_RE = re.compile(r"^[0-9_]+(?:\s*\*\s*[0-9_]+)*$")
IDENT_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _read(path: pathlib.Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"FAIL: check_flash_budget (US-1534) — cannot read {path}: {e}")
        return None


def _const(src: str, name: str, seen: frozenset[str] = frozenset()) -> int | None:
    """Evaluate one `const NAME: uN = <expr>;` out of Rust source.

    Deliberately tiny. It understands hex literals, `a * b` products, and — the
    case that matters here — an **identifier** on the right-hand side, resolved
    by reading that constant too. `TRUSSED_FS_OFFSET` is written
    `= FIRMWARE_GROWTH_END` precisely because the layout is single-source; a gate
    that transcribed the resulting number instead of following the reference
    would be a second copy of the answer, and would keep passing if the link
    were ever cut.

    Anything it does not understand returns `None` and the caller reports it,
    rather than the gate silently skipping a constant it could not read. A gate
    that cannot read the number it exists to check has to say so, not pass.

    `seen` guards against a cycle of identifiers, which would otherwise
    recurse until the interpreter gave up.
    """
    if name in seen:
        return None
    m = re.search(RUST_CONST_RE.format(name=re.escape(name)), src, re.M)
    if not m:
        return None
    expr = m.group(1).strip()
    if HEX_RE.match(expr):
        return int(expr.replace("_", ""), 16)
    if ARITH_RE.match(expr):
        return eval(expr.replace("_", ""))  # noqa: S307 - digits, `*` and spaces only
    if IDENT_RE.match(expr):
        return _const(src, expr, seen | {name})
    return None


def main() -> int:
    failures: list[str] = []

    ci = _read(CI)
    flashmap = _read(FLASHMAP)
    if ci is None or flashmap is None:
        return 1

    # --- 1. the two statements of the budget agree -------------------------

    ci_m = CI_BUDGET_RE.search(ci)
    if ci_m is None:
        failures.append(
            f"{CI.relative_to(ROOT)}: FIRMWARE_FLASH_BUDGET_KIB not found. The ratchet step "
            f"reads it with `:?` and would fail confusingly; this gate cannot check what "
            f"it cannot find"
        )
        ci_bytes = None
    else:
        ci_bytes = int(ci_m.group(1)) * 1024

    code_bytes = _const(flashmap, "FIRMWARE_FLASH_BUDGET_BYTES")
    if code_bytes is None:
        failures.append(
            f"{FLASHMAP.relative_to(ROOT)}: FIRMWARE_FLASH_BUDGET_BYTES not found, or written "
            f"in a form this gate cannot evaluate. The gate refuses to pass a constant it "
            f"could not read — that is the drift it exists to catch, wearing a disguise"
        )

    if ci_bytes is not None and code_bytes is not None and ci_bytes != code_bytes:
        failures.append(
            f"budget disagreement: ci.yml says {ci_bytes} B "
            f"(FIRMWARE_FLASH_BUDGET_KIB), flashmap.rs says {code_bytes} B "
            f"(FIRMWARE_FLASH_BUDGET_BYTES). One of them was edited without the other. "
            f"The Rust constant is the source of truth — a workflow file cannot import it"
        )

    # --- 1b. …and the board_def mirror agrees with them --------------------
    #
    # The mirror exists because `build.rs` compiles without the `platform`
    # crate. It feeds `Board::validate` and the generated linker script's
    # headroom comment, so a stale mirror means the board validates against a
    # budget nobody enforces and the linker script prints a headroom figure
    # that is not the ratchet's. Nothing compared it until this check.
    board_bytes = None
    board = _read(BOARD_DEF)
    if board is None:
        failures.append(f"{BOARD_DEF.relative_to(ROOT)}: unreadable")
    else:
        board_kib = _const(board, "FIRMWARE_FLASH_BUDGET_KIB")
        if board_kib is None:
            failures.append(
                f"{BOARD_DEF.relative_to(ROOT)}: FIRMWARE_FLASH_BUDGET_KIB not found, or "
                f"written in a form this gate cannot evaluate. The mirror is read by "
                f"`Board::validate` and the generated linker script; a mirror this gate "
                f"cannot read is a second source of truth again"
            )
        else:
            board_bytes = board_kib * 1024
            if code_bytes is not None and board_bytes != code_bytes:
                failures.append(
                    f"budget disagreement: board_def.rs mirrors {board_bytes} B "
                    f"(FIRMWARE_FLASH_BUDGET_KIB) while flashmap.rs owns {code_bytes} B "
                    f"(FIRMWARE_FLASH_BUDGET_BYTES). Raise both in one step: "
                    f"`python3 tests/scripts/raise_flash_budget.py <KiB> --reason \"...\"` "
                    f"does it for you. A stale mirror is what this check was added for — "
                    f"board_def.rs had drifted 1,536 vs 1,621 KiB while nothing read it"
                )

    budget = code_bytes if code_bytes is not None else ci_bytes

    # --- 2. the budget stops above every data region -----------------------

    growth_end = _const(flashmap, "FIRMWARE_GROWTH_END")
    trussed = _const(flashmap, "TRUSSED_FS_OFFSET")
    blocks = _const(flashmap, "TRUSSED_FS_BLOCKS")
    block_size = _const(flashmap, "BLOCK_SIZE")

    # Regions are derived here rather than parsed as literals, because in
    # flashmap.rs they are *expressions of each other* — that is the property
    # that makes the layout single-source. The gate re-derives the arithmetic
    # instead of transcribing the answers.
    regions: list[tuple[str, int]] = []
    if trussed is not None and blocks is not None and block_size is not None:
        regions.append(("trussed internal FS (OpenPGP/PIV)", trussed))
        regions.append(("trussed internal FS end", trussed + blocks * block_size))
    else:
        failures.append(
            "flashmap.rs: TRUSSED_FS_OFFSET / TRUSSED_FS_BLOCKS / BLOCK_SIZE not all found "
            "or not evaluable; the data-region check cannot run"
        )

    if budget is not None:
        for name, start in regions:
            if budget > start:
                failures.append(
                    f"the budget ends at {budget:#x} but {name} starts at {start:#x}: an image "
                    f"the ratchet accepts could link over it. Raise FIRMWARE_FLASH_BUDGET_KIB "
                    f"only up to FIRMWARE_GROWTH_END; if that is not enough, move the data "
                    f"regions in platform/src/flashmap.rs deliberately — a provisioned "
                    f"unit's keys are in the region being moved"
                )

        # --- 3. the headroom still exists ---------------------------------
        if growth_end is not None:
            if budget > growth_end:
                failures.append(
                    f"the budget ({budget:#x}) is above FIRMWARE_GROWTH_END ({growth_end:#x}): "
                    f"the 512 KiB of headroom that makes raising the budget a deliberate act "
                    f"is gone"
                )
            elif trussed is not None and trussed < growth_end:
                failures.append(
                    f"the trussed window ({trussed:#x}) starts below FIRMWARE_GROWTH_END "
                    f"({growth_end:#x}); flashmap.rs's own compile-time assertion should have "
                    f"stopped this — is the device build actually running?"
                )

        # --- 4. the regions are inside the part --------------------------
        # The secure partition is top-anchored: 64 KiB below the top of flash.
        # FLASH_SIZE_KB is 4096 on the only board that ships.
        secure_start = (4096 - 64) * 1024
        for name, offset in regions:
            if offset >= secure_start:
                failures.append(
                    f"{name} at {offset:#x} is inside or past the secure partition "
                    f"({secure_start:#x}); an overlap there is not a link error, it is an "
                    f"unreadable keystore discovered at BOOTSEL"
                )

    if failures:
        print("FAIL: check_flash_budget (US-1534)")
        for f in failures:
            print(f"  - {f}")
        return 1

    region_desc = ", ".join(f"{n} @ {o:#x}" for n, o in regions)
    print(
        f"PASS: check_flash_budget (US-1534) — budget {budget} B ({budget:#x}) "
        f"ci.yml = flashmap.rs, ends at or below every data region ({region_desc}); "
        f"headroom intact to FIRMWARE_GROWTH_END {growth_end:#x}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())