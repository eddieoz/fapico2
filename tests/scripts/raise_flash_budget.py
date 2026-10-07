#!/usr/bin/env python3
"""Raise the CI flash-budget ratchet — one command, all the sites, one reason.

    python3 tests/scripts/raise_flash_budget.py 1664 \
        --reason "the region walk and the credMgmt 0x41 route: ~8 features of growth"

WHY THIS EXISTS
---------------
The ratchet is stated in more places than a developer can find by reading the
error message that tells them to raise it. Before this script a deliberate
raise was a five-edit, four-red sequence discovered one job at a time:

  1. `.github/workflows/ci.yml`  `FIRMWARE_FLASH_BUDGET_KIB` — the step's own
     message names this one, and only this one;
  2. `platform/src/flashmap.rs`  `FIRMWARE_FLASH_BUDGET_BYTES` — the source of
     truth; `check_flash_budget.py` fails if it disagrees with (1), so the
     first red after editing (1) names it;
  3. `platform/board_def.rs`     `FIRMWARE_FLASH_BUDGET_KIB` — a mirror that
     `build.rs` compiles without the platform crate, read by `Board::validate`
     and printed into the generated linker script. **It was gated by nothing**
     and had already drifted (1536 while ci.yml and flashmap.rs said 1621) —
     see the note in `check_flash_budget.py`, which now checks it;
  4. `platform/tests/flash_map.rs` — two expectations that used to pin the
     literal; they are value-agnostic since 2026-10-06, so a raise no longer
     touches them, but a developer looking for "where else is this number"
     still lands here first;
  5. `docs/size-report.md` — the recorded figure and the argument for it.

That is a manual decision a tool can make, and this is the tool. It is still a
*deliberate* act: `--reason` is required, the new value is checked against the
geometry, and the reason is written into the workflow next to the number, so
the next reader sees why the ceiling moved rather than a bare integer.

WHAT IT REFUSES TO DO
---------------------
* Raise past `FIRMWARE_GROWTH_END` (the trussed filesystem's first byte): past
  that line an image the ratchet accepts could link over every OpenPGP and PIV
  key on the part. `check_flash_budget.py` enforces the same bound; this is the
  earlier, louder refusal.
* Raise *below* the shipping image this tree currently produces — the raise
  would fail the next CI run, which is not a raise.
* Lower the ratchet. Shrinking a budget is a different change with a different
  review question ("which credentials did we decide to give up?"), and doing it
  silently through a script written for raises is how a safety number gets
  moved without an argument.
* Guess a reason. A raise with no recorded reason is the failure mode the
  ratchet exists to prevent.
"""
from __future__ import annotations

import argparse
import datetime
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
FLASHMAP = ROOT / "platform" / "src" / "flashmap.rs"
BOARD_DEF = ROOT / "platform" / "board_def.rs"
REPORT = ROOT / "docs" / "size-report.md"
UF2GEN = ROOT / "firmware" / "uf2gen.py"
ELF = ROOT / "target" / "thumbv8m.main-none-eabi" / "release" / "fapico2-firmware"

CI_RE = re.compile(r"^(  FIRMWARE_FLASH_BUDGET_KIB:\s*)(\d+)\s*$", re.M)
FLASHMAP_RE = re.compile(
    r"(pub const FIRMWARE_FLASH_BUDGET_BYTES:\s*u32\s*=\s*)(\d+)(\s*\*\s*1024\s*;)", re.M
)
BOARD_RE = re.compile(
    r"(pub const FIRMWARE_FLASH_BUDGET_KIB:\s*u32\s*=\s*)(\d+)(\s*;)", re.M
)
GROWTH_END_RE = re.compile(
    r"pub const FIRMWARE_GROWTH_END:\s*u32\s*=\s*(0x[0-9a-fA-F_]+)\s*;"
)


def shipping_bytes() -> int | None:
    """The shipping UF2 size this tree produces, or None if it is not built.

    Computed from the release ELF the same way CI does (`firmware/uf2gen.py`),
    because the ratchet compares against the *image*, not against `text`.
    """
    if not ELF.exists():
        return None
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "fapico2.uf2"
        subprocess.run(
            [sys.executable, str(UF2GEN), str(ELF), str(out)],
            check=True, capture_output=True,
        )
        return out.stat().st_size


def read_int(pattern: re.Pattern, path: pathlib.Path, what: str) -> int:
    m = pattern.search(path.read_text(encoding="utf-8"))
    if m is None:
        raise SystemExit(
            f"{path.relative_to(ROOT)}: {what} not found in the shape this script "
            f"edits. Fix the pattern rather than editing the file by hand: this "
            f"script's whole purpose is that the sites cannot drift apart."
        )
    return int(m.group(2))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("kib", type=int, help="the new budget, in KiB")
    ap.add_argument("--reason", required=True,
                    help="why the ceiling is moving — written into ci.yml beside "
                         "the number and into the report's dated entry")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the edits without writing them")
    args = ap.parse_args()

    if len(args.reason.strip()) < 20:
        print("refusing: --reason must say why the ceiling is moving (>= 20 chars).\n"
              "  A raise with no recorded reason is what the ratchet exists to stop.",
              file=sys.stderr)
        return 2

    growth_end = int(GROWTH_END_RE.search(
        FLASHMAP.read_text(encoding="utf-8")).group(1).replace("_", ""), 16)
    ci_now = read_int(CI_RE, CI, "FIRMWARE_FLASH_BUDGET_KIB")
    # FLASHMAP_RE's group(2) is already the KiB multiplier (`1621 * 1024`), so
    # it is compared as-is; dividing here was the first draft's bug and it
    # reported the source of truth as "1 KiB".
    map_now = read_int(FLASHMAP_RE, FLASHMAP, "FIRMWARE_FLASH_BUDGET_BYTES")
    board_now = read_int(BOARD_RE, BOARD_DEF, "FIRMWARE_FLASH_BUDGET_KIB")
    new_bytes = args.kib * 1024

    # --- refusals, before anything is written ------------------------------
    if args.kib * 1024 > growth_end:
        print(
            f"refusing: {args.kib} KiB = {new_bytes} B is past FIRMWARE_GROWTH_END "
            f"({growth_end} B). The trussed filesystem — every OpenPGP and PIV key "
            f"on the part — starts there, so a budget above it could accept an image "
            f"that links over them. Moving the filesystem is a layout change with "
            f"its own review, not a budget raise.",
            file=sys.stderr,
        )
        return 2
    if args.kib <= max(ci_now, map_now):
        print(
            f"refusing: {args.kib} KiB does not raise the budget "
            f"(ci.yml {ci_now} KiB, flashmap.rs {map_now} KiB). This script raises; "
            f"shrinking a budget is a different decision and must be made in the open.",
            file=sys.stderr,
        )
        return 2
    ship = shipping_bytes()
    if ship is not None and new_bytes < ship:
        print(
            f"refusing: {args.kib} KiB = {new_bytes} B is below this tree's shipping "
            f"image ({ship} B). The raise would fail the next CI run.",
            file=sys.stderr,
        )
        return 2

    today = datetime.date.today().isoformat()
    drift = ""
    if board_now != ci_now or board_now != map_now:
        drift = (f"\n  NOTE: the sites had already drifted — ci.yml {ci_now} KiB, "
                 f"flashmap.rs {map_now} KiB, board_def.rs {board_now} KiB. "
                 f"board_def.rs is a mirror `check_flash_budget.py` now checks; "
                 f"all three are set to {args.kib} KiB.")

    # --- the edits ---------------------------------------------------------
    ci_text = CI.read_text(encoding="utf-8")
    entry = (
        "".join(
            f"  # {line}\n"
            for line in _wrap(
                f"{today} raised this from {ci_now} to {args.kib} KiB, on purpose, "
                f"with the reason recorded here because the number is the layout's "
                f"argument: {args.reason.strip()}",
                74,
            )
        )
    )
    ci_new = CI_RE.sub(
        lambda m: entry + f"{m.group(1)}{args.kib}", ci_text, count=1
    )
    map_new = FLASHMAP_RE.sub(
        lambda m: f"{m.group(1)}{args.kib}{m.group(3)}",
        _refresh_figure(FLASHMAP.read_text(encoding="utf-8"), map_now, args.kib),
        count=1,
    )
    board_new = BOARD_RE.sub(
        lambda m: f"{m.group(1)}{args.kib}{m.group(3)}",
        _refresh_figure(BOARD_DEF.read_text(encoding="utf-8"), board_now, args.kib),
        count=1,
    )
    report_entry = _report_entry(today, ci_now, args.kib, ship, args.reason.strip())
    report_new = _insert_entry(REPORT.read_text(encoding="utf-8"), report_entry)

    targets = [
        (CI, ci_new, "FIRMWARE_FLASH_BUDGET_KIB + the dated reason"),
        (FLASHMAP, map_new, "FIRMWARE_FLASH_BUDGET_BYTES + its doc figure"),
        (BOARD_DEF, board_new, "the board_def mirror + its doc figure"),
        (REPORT, report_new, "a dated entry in the report"),
    ]
    # Validate the harness anchor BEFORE writing anything: a refusal after four
    # files had been rewritten would leave the tree half-raised, which is worse
    # than not starting. Silent here; the announce/write happens once, below.
    _reanchor_harness(ci_now, args.kib, dry_run=False, write=False)
    for path, text, what in targets:
        if args.dry_run:
            print(f"would write {path.relative_to(ROOT)}: {what}")
            continue
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}: {what}")

    ship_line = f"{ship} B ({ship // 1024} KiB)" if ship else "not built in this tree"
    print(
        f"\nratchet {ci_now} -> {args.kib} KiB ({new_bytes} B; "
        f"FIRMWARE_GROWTH_END is {growth_end} B, {growth_end - new_bytes} B above it)\n"
        f"  shipping image: {ship_line}\n"
        f"  headroom after the raise: "
        + (f"{new_bytes - ship} B" if ship else "unknown (build the device ELF)")
        + drift
    )
    _reanchor_harness(ci_now, args.kib, args.dry_run)
    print(
        "\nnext, and this is the part a script cannot do for you:\n"
        "  1. finish the dated entry in docs/size-report.md — the stub carries the\n"
        "     numbers and your reason; the argument for the growth is yours to write.\n"
        "  2. review the prose the raise touched: any sentence that stated the image\n"
        "     size and the budget as the SAME number is now false (they are only equal\n"
        "     at a zero-headroom ratchet), and this script deliberately does not guess\n"
        "     which sentences those are. `git diff platform/src/flashmap.rs` first.\n"
        "  3. re-run the gates that read the number:\n"
        "       python3 tests/scripts/check_flash_budget.py\n"
        "       python3 tests/scripts/check_size_report.py\n"
        "       python3 tests/scripts/test_gates.py --workflows-only\n"
        "       cargo test -p fapico2-platform --target x86_64-unknown-linux-gnu --test flash_map"
    )
    return 0


def _wrap(text: str, width: int) -> list[str]:
    words, lines, line = text.split(), [], ""
    for w in words:
        if len(line) + len(w) + 1 > width and line:
            lines.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return lines


def _refresh_figure(text: str, old_kib: int, new_kib: int) -> str:
    """Keep the *KiB* figures and the budget's offset honest when it moves.

    Deliberately narrow. A bare byte count is NOT rewritten, because the same
    number can mean two different things in these files — `1,659,904 B` was the
    *image* in one sentence and the *budget* in another, and a blind replace
    turned "the image is 1,659,904 B" into a claim about a number the image
    does not have. The offset is rewritten only where it equals the old budget
    end, which is the one place a byte-valued spelling of the budget appears in
    a machine-checkable position (the flash-map diagram).
    """
    old_bytes = old_kib * 1024
    text = text.replace(f"{old_kib:,} KiB", f"{new_kib:,} KiB")
    text = text.replace(f"({old_kib} KiB)", f"({new_kib} KiB)")
    text = text.replace(f"{old_kib} KiB", f"{new_kib} KiB")
    text = text.replace(_offset(old_bytes), _offset(new_kib * 1024))
    return text


def _offset(value: int) -> str:
    """`0x195_400`-style flash offset, the spelling `flashmap.rs`'s map uses."""
    return f"0x{value >> 12:03X}_{value & 0xFFF:03X}"


def _reanchor_harness(old_kib: int, new_kib: int, dry_run: bool, write: bool = True) -> None:
    """Re-point the mutation harness's ratchet break at the new value.

    The harness's `_B_FLASH_BUDGET` anchor is a literal ci.yml line, so it
    carries the number — and a raise that forgets it leaves the harness with a
    rotted anchor and `check_flash_budget.py` reported as a HARNESS-ERROR
    instead of mutation-covered. That is the same rot this script exists to
    stop, one level up, so the raise owns it too.

    Called twice: once with `write=False` to validate before anything is
    rewritten (a refusal must not leave a half-raised tree), then to write.
    """
    path = ROOT / "tests" / "scripts" / "test_gates.py"
    text = path.read_text(encoding="utf-8")
    old = f'  FIRMWARE_FLASH_BUDGET_KIB: {old_kib}'
    new = f'  FIRMWARE_FLASH_BUDGET_KIB: {new_kib}'
    found = text.count(old)
    if found != 1:
        print(
            f"refusing: the harness anchor {old!r} occurs {found} time(s) in "
            f"tests/scripts/test_gates.py, expected exactly one. Re-nominate it by hand "
            f"rather than leaving the harness pointing at a number that is gone.",
            file=sys.stderr,
        )
        raise SystemExit(3)
    if dry_run or not write:
        if dry_run:
            print(f"would write {path.relative_to(ROOT)}: the _B_FLASH_BUDGET anchor")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}: the _B_FLASH_BUDGET anchor")


def _insert_entry(doc: str, entry: str) -> str:
    """Put the new entry with the other dated entries, not at the file's end.

    `docs/size-report.md` opens with the current artifact and its measured
    blocks, then runs newest-entry-first through the dated history. Appending
    would bury a raise below a year of archaeology, which is how a record stops
    being read. The insertion point is the generated summary block's terminator
    — a delimiter the size gate already maintains, so it cannot rot.
    """
    marker = "<!-- END measured ELF summary -->"
    if marker not in doc:
        raise SystemExit(
            f"--update: {REPORT} has no {marker!r}; refusing to guess where the "
            f"dated entry belongs"
        )
    at = doc.index(marker) + len(marker)
    return doc[:at] + "\n" + entry + doc[at:]


def _report_entry(today: str, old_kib: int, new_kib: int, ship: int | None, reason: str) -> str:
    ship_txt = (
        f"{ship} B = {ship // 512} blocks = {ship // 1024} KiB"
        if ship else "not built in this tree"
    )
    return (
        f"\n**Date: {today} (flash ratchet raised {old_kib} → {new_kib} KiB, by "
        f"`raise_flash_budget.py`).**\n\n"
        f"Reason recorded with the number: {reason}\n\n"
        f"Shipping image at the raise: {ship_txt}. Budget {new_kib} KiB = "
        f"{new_kib * 1024} B, which is "
        + (f"{new_kib * 1024 - ship} B of headroom.\n" if ship else "headroom unknown.\n")
        + "\nThe ratchet is the only *near-term* bound on the shipping image: the "
        "3.5 MiB text ceiling is ~2 MB above the current build and cannot fire on "
        "ordinary growth, and the flash-map geometry (`FIRMWARE_GROWTH_END`) is the "
        "hard limit past which the image would link over the trussed filesystem. "
        "Headroom here is deliberate and finite — the next raise is a decision, not "
        "an accident, which is why the reason is recorded next to the number in "
        "`.github/workflows/ci.yml` and in `platform/src/flashmap.rs`.\n"
    )


if __name__ == "__main__":
    sys.exit(main())
