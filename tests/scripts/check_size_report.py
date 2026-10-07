#!/usr/bin/env python3
"""S-392-2 gate: size budgets over the rebuilt device ELF (US-392; RAM US-1010).

Rebuilds the device ELF (default = device target), re-measures
`arm-none-eabi-size` (+ `-A` and the RAM symbols), recomputes the shipping UF2
sha256/block count, and enforces the two *budgets* that decide whether the
board boots and fits.

Modes
-----

    check_size_report.py                budgets only — what CI runs on a PR
    check_size_report.py --check-doc    also: docs/size-report.md must equal
                                        the build (mutation harness; release)
    check_size_report.py --update       rewrite the doc's generated block and
                                        headline figures from the build

What blocks a pull request, and what deliberately does not
----------------------------------------------------------

**Blocking:**

* ``text <= CEILING`` (3.5 MiB flash) — a coarse backstop. It is ~2.8 MiB
  above the current build, so it cannot fire on ordinary growth; the flash
  ratchet in ``.github/workflows/ci.yml`` and the geometry in
  ``platform/src/flashmap.rs`` are the near-term bounds.
* ``bss <= RAM_BYTES - CHAIN_CEILING`` — the dark-boot-class check (below).

**Not blocking: the document-equality checks.** Until 2026-10-07 this script
also failed unless ``docs/size-report.md`` contained the build's exact text,
UF2 sha256, block count, section table and summary. That made every codegen
change red for a reason unrelated to the change — a measured +56 B or −1,204 B
was enough — and it was *weak* as well as churny: the presence checks were
whole-document substring scans over a 3,400-line file carrying ~99 historical
sha/block figures, and only the first of the document's two delimited copies
was validated. Enforcing documentation freshness by failing the build is the
defect; the numbers a reader needs are printed here and written by --update.
The equality checks are kept, behind ``--check-doc``, for the two callers that
want them: the mutation harness (which must prove they bite) and the release
refresh. Nothing in the PR path reads ``docs/size-report.md``.

What US-1010 changed
--------------------

**`bss` is now gated, not printed.** Before, this script measured `bss` and
put it in the PASS line, and the only ceiling it enforced was ``CEILING``,
which is a **flash** budget (``text``). So the number that actually decides
whether the firmware boots — static RAM — was the one figure with no ceiling
at all. `RAM_CEILING` below closes that.

**The interior detail tables are generated, not hand-copied.** The headline
`text` figure the gate compared was current while the per-section tables under
it were one re-measurement behind (8 B stale on `.bss` and the `__sheap` /
stack-zone lines at the time of writing). The measured blocks are delimited
and rendered by :func:`render_sections` / :func:`render_summary` — one
renderer, shared by ``--check-doc`` and ``--update``, so the two cannot drift.

The RAM ceiling, and where it comes from
----------------------------------------

    RAM_CEILING = RAM_BYTES - CHAIN_CEILING
                = 532,480  -  98,304   =  434,176 B

* ``RAM_BYTES`` is read out of the **generated `memory.x`**, which is the one
  artifact that says how much SRAM this build's linker reserved. It is not
  hardcoded, so a different board moves the ceiling instead of leaving a
  4 MiB number behind.
* ``CHAIN_CEILING`` is **imported from `check_boot_chain.py`**, the module
  that enforces it, so the two gates cannot drift into disagreeing about what
  the stack is owed.

The reasoning: `bss` is static RAM, and the main stack zone is whatever is
left between the top of the statics and the top of SRAM. `check_boot_chain.py`
requires that zone to be at least ``CHAIN_CEILING`` (it binds on
``min(CHAIN_CEILING, zone)``). So the largest `bss` this build can carry and
still boot is exactly ``RAM_BYTES - CHAIN_CEILING`` — and a statics change
that pushes past it is not a link error, it is a board that dark-locks. That
is precisely what happened to the 32-entry secure store (DARK-BOOT-1, in
`docs/known-gate-divergences.md` SF-1): +36,288 B of bss moved `MSPLIM`
up, shrank the stack region from ~127 KiB to ~85 KiB, and the boot path
overflowed it.

The comparison is deliberately against Berkeley `bss` (which folds `.uninit`
in) rather than the address-to-address figure, because Berkeley `bss` is the
*larger* of the two and a ceiling should be checked against the pessimistic
number. On this build the two differ by 200 B (`.data` plus 4 B of alignment
slack ahead of `__sheap`), so the check is conservative by that much.
"""
import argparse
import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from check_boot_chain import CHAIN_CEILING  # noqa: E402  (path is set above)

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "size-report.md"
UF2GEN = ROOT / "firmware" / "uf2gen.py"
ELF = (ROOT / "target/thumbv8m.main-none-eabi/release/fapico2-firmware")
CEILING = 3_670_016

# The measured blocks. Delimiters, not a heading: a heading a later edit can
# reword is a marker that can go missing, and a missing marker here is a FAIL
# (below) rather than a silent skip.
SECTIONS_BEGIN = "<!-- BEGIN measured ELF sections (check_size_report.py) -->"
SECTIONS_END = "<!-- END measured ELF sections -->"
SUMMARY_BEGIN = "<!-- BEGIN measured ELF summary (check_size_report.py) -->"
SUMMARY_END = "<!-- END measured ELF summary -->"

# Per-section editorial notes. The *numbers* are generated; only the prose is
# authored, so a new section shows up as a row with a default note rather than
# silently going unchecked.
RAM_NOTE = "**yes** — RAM"
FLASH_NOTE = "no (flash)"
NOTES = {
    ".secure_partition": "**no** — NOLOAD flash address space",
    ".vector_table": FLASH_NOTE,
    ".start_block": FLASH_NOTE,
    ".text": FLASH_NOTE,
    ".rodata": FLASH_NOTE,
    ".gnu.sgstubs": "non-alloc, not in Berkeley `text`",
    ".data": "**yes** — initialized, copied from flash by crt0",
    ".bss": "**yes** — zeroed by crt0",
    ".uninit": "yes",
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, **kw)


def measure_elf():
    r = run(["cargo", "build", "--release", "--target", "thumbv8m.main-none-eabi"])
    if r.returncode != 0:
        print("FAIL: device build failed\n" + r.stderr[-2000:])
        sys.exit(1)
    r = run(["arm-none-eabi-size", str(ELF)])
    if r.returncode != 0 or not r.stdout.strip():
        print("FAIL: arm-none-eabi-size unavailable: " + r.stderr)
        sys.exit(1)
    cols = r.stdout.strip().splitlines()[-1].split()
    return int(cols[0]), int(cols[1]), int(cols[2])


def measure_sections():
    """`arm-none-eabi-size -A` -> [(name, size, addr)], alloc sections only."""
    r = run(["arm-none-eabi-size", "-A", str(ELF)])
    if r.returncode != 0:
        print("FAIL: arm-none-eabi-size -A unavailable: " + r.stderr)
        sys.exit(1)
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0].startswith("."):
            out.append((parts[0], int(parts[1]), int(parts[2])))
    return out


def symbols(*names):
    r = run(["arm-none-eabi-nm", str(ELF)])
    if r.returncode != 0:
        print("FAIL: arm-none-eabi-nm unavailable: " + r.stderr)
        sys.exit(1)
    found = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in names:
            found[parts[2]] = int(parts[0], 16)
    missing = [n for n in names if n not in found]
    if missing:
        print(f"FAIL: ELF is missing symbol(s) {missing}")
        sys.exit(1)
    return found


def ram_bytes():
    """Total SRAM this build's linker reserved, from the generated `memory.x`.

    Read from the build artefact rather than hardcoded, so a board with
    different SRAM moves `RAM_CEILING` instead of leaving a number behind that
    was true for whichever part was current when it was written.
    """
    pat = "target/thumbv8m.main-none-eabi/release/build/fapico2-firmware-*/out/memory.x"
    scripts = sorted(ROOT.glob(pat))
    if not scripts:
        print(f"FAIL: no generated memory.x under {pat}; build the firmware first")
        sys.exit(1)
    # Every copy is rendered from the same board file; take the newest and say
    # so rather than picking one silently.
    script = max(scripts, key=lambda p: p.stat().st_mtime)
    text = script.read_text(encoding="utf-8")
    m = re.search(r"RAM\s*:\s*ORIGIN\s*=\s*(0x[0-9a-fA-F]+)\s*,\s*LENGTH\s*=\s*(\d+)([KM])?", text)
    if not m:
        print(f"FAIL: no RAM region in the generated memory.x ({script})")
        sys.exit(1)
    n = int(m.group(2))
    mult = {"K": 1024, "M": 1024 * 1024, None: 1}[m.group(3)]
    return int(m.group(1), 16), n * mult, script


def fmt(n):
    return f"{n:,}"


def render_sections(sections, ram_origin, ram_size):
    rows = ["| section | bytes | addr | in RAM? |", "|---|---:|---:|:---:|"]
    for name, size, addr in sections:
        if name in NOTES:
            note = NOTES[name]
        elif addr == 0:
            note = "non-alloc, not in Berkeley `text`"
        elif ram_origin <= addr < ram_origin + ram_size:
            note = RAM_NOTE
        else:
            note = FLASH_NOTE
        rows.append(f"| `{name}` | {fmt(size)} | `{addr:#010x}` | {note} |")
    return "\n".join(rows)


def render_summary(sections, text, data, bss, syms, ram_origin, ram_size):
    by = {n: (s, a) for n, s, a in sections}
    statics = sum(s for n, s, _a in sections if n in (".data", ".bss", ".uninit"))
    addr_to_addr = syms["__sheap"] - ram_origin
    zone = syms["_stack_start"] - syms["_stack_end"]
    lines = [
        f"**Rust device `text` = {fmt(text)} B** · **`.data` = {fmt(by['.data'][0])} B** "
        f"· **`.bss` = {fmt(bss)} B** · **`.uninit` = {fmt(by['.uninit'][0])} B**",
        "",
        f"**RAM statics = {fmt(statics)} B** "
        f"({fmt(addr_to_addr)} B address-to-address: `__sheap` "
        f"`{syms['__sheap']:#010x}` − RAM origin `{ram_origin:#010x}`). "
        f"`_stack_start` `{syms['_stack_start']:#010x}`, `_stack_end` "
        f"`{syms['_stack_end']:#010x}` → **main stack zone = {fmt(zone)} B** of "
        f"{fmt(ram_size)} B of SRAM.",
        "",
        f"`bss + stack zone + .data = {fmt(bss + zone + by['.data'][0])} B` against "
        f"{fmt(ram_size)} B of RAM, leaving {fmt(ram_size - bss - zone - by['.data'][0])} B "
        f"of alignment slack: **there is no unallocated SRAM.** Every byte is a static or "
        f"the stack, so the only thing that catches a regression is the linker refusing to "
        f"place `.bss` — and the ceiling that turns that from a link error into a dark "
        f"board is the one this gate enforces.",
    ]
    return "\n".join(lines)


def check_block(doc, begin, end, expected, label, failures):
    """The document's copy of a generated block must equal the measurement.

    `--check-doc` only. The PR path does not read the document at all.
    """
    if begin not in doc:
        failures.append(f"doc: missing the generated block {label} (no {begin!r})")
        return
    start = doc.index(begin) + len(begin)
    if end not in doc:
        failures.append(f"doc: the generated block {label} has no {end!r} terminator")
        return
    got = doc[start:doc.index(end, start)].strip()
    want = expected.strip()
    if got != want:
        failures.append(
            f"doc: the generated block {label} disagrees with the rebuilt ELF — it is a "
            f"hand-copied interior that has gone stale. Run "
            f"`python3 tests/scripts/check_size_report.py --update` to rewrite it from "
            f"this build.\n"
            f"--- measured ---\n{want}\n--- in the document ---\n{got}"
        )


def write_block(doc: str, begin: str, end: str, body: str, label: str) -> str:
    """Replace the generated block between `begin`/`end` with `body`.

    `--update` only. Refuses to guess: a missing delimiter is an error, not a
    place to append, because appending is how a document ends up with the
    generated block somewhere nobody reads it.
    """
    if begin not in doc or end not in doc:
        raise SystemExit(
            f"--update: {label} delimiters are missing from {DOC} "
            f"(need {begin!r} and {end!r}); refusing to guess where to write"
        )
    start = doc.index(begin) + len(begin)
    stop = doc.index(end, start)
    return doc[:start] + "\n" + body.strip() + "\n" + doc[stop:]


def doc_checks(doc, text, sha, blocks, sections, data, bss, syms,
               ram_origin, ram_total, ram_ceiling, failures):
    """Every comparison against `docs/size-report.md`. `--check-doc` only."""
    m = re.search(r"Rust[^*\n]*text[^0-9\n]*([\d,]+)\s*B", doc)
    if not m:
        failures.append("doc: no Rust text measurement found")
    elif int(m.group(1).replace(",", "")) != text:
        failures.append(
            f"doc Rust text {m.group(1)} != measured {text} "
            f"(run `check_size_report.py --update` to refresh the document)"
        )
    if f"{sha[:12]}" not in doc and sha not in doc:
        failures.append(f"doc: shipping UF2 sha256 ({sha[:12]}…) not recorded")
    if not re.search(rf"\b{blocks}\s+blocks?\b", doc):
        failures.append(f"doc: UF2 block count ({blocks}) not recorded")
    if "3670016" not in doc.replace(",", "") and "3,670,016" not in doc:
        failures.append("doc: size-gate ceiling (3,670,016) not noted")
    if "530,980" not in doc and "530980" not in doc:
        failures.append("doc: C baseline text (530,980) not recorded")
    # The RAM ceiling is a derived number; a reader who cannot see it has to
    # take the "no unallocated SRAM" claim on trust, which is how the 8,432 B
    # and "~42 credentials" claims survived as long as they did.
    if fmt(ram_ceiling) not in doc and str(ram_ceiling) not in doc.replace(",", ""):
        failures.append(
            f"doc: the RAM ceiling ({fmt(ram_ceiling)} B = {fmt(ram_total)} B SRAM − "
            f"{fmt(CHAIN_CEILING)} B chain ceiling) is not recorded"
        )

    check_block(
        doc, SECTIONS_BEGIN, SECTIONS_END,
        render_sections(sections, ram_origin, ram_total),
        "ELF section table", failures,
    )
    check_block(
        doc, SUMMARY_BEGIN, SUMMARY_END,
        render_summary(sections, text, data, bss, syms, ram_origin, ram_total),
        "ELF summary", failures,
    )


def update_doc(text, data, bss, sections, syms, ram_origin, ram_total):
    """Rewrite the generated blocks and the figures they carry. (changed, text)."""
    doc = DOC.read_text(encoding="utf-8")
    out = write_block(
        doc, SECTIONS_BEGIN, SECTIONS_END,
        render_sections(sections, ram_origin, ram_total),
        "ELF section table",
    )
    out = write_block(
        out, SUMMARY_BEGIN, SUMMARY_END,
        render_summary(sections, text, data, bss, syms, ram_origin, ram_total),
        "ELF summary",
    )
    return out != doc, out


def uf2_facts():
    """sha256 + block count of the shipping image, generated from the build.

    The UF2 is a build artifact and is not committed (see .gitignore), so it is
    regenerated here from the release ELF exactly as CI does. That keeps the
    recorded hash a function of the source rather than of a binary someone had
    to remember to refresh.
    """
    if not ELF.exists():
        raise SystemExit(
            f"check_size_report: {ELF} is missing. Build the device image first:\n"
            "  cargo build --release --target thumbv8m.main-none-eabi"
        )
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "fapico2.uf2"
        subprocess.run(
            [sys.executable, str(UF2GEN), str(ELF), str(out)],
            check=True, capture_output=True,
        )
        data = out.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data) // 512


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--check-doc", action="store_true",
        help="also require docs/size-report.md to equal this build (mutation "
             "harness, release refresh). NOT run on the PR path — see the "
             "module docstring for why.",
    )
    mode.add_argument(
        "--update", action="store_true",
        help="rewrite the document's generated blocks from this build and exit "
             "(unless a budget is exceeded)",
    )
    args = ap.parse_args()

    text, data, bss = measure_elf()
    sections = measure_sections()
    syms = symbols("__sheap", "_stack_start", "_stack_end")
    ram_origin, ram_total, memory_x = ram_bytes()
    ram_ceiling = ram_total - CHAIN_CEILING
    sha, blocks = uf2_facts()

    failures = []
    if text > CEILING:
        failures.append(f"size gate exceeded: text {text} > {CEILING}")
    if bss > ram_ceiling:
        failures.append(
            f"RAM gate exceeded: bss {bss} > {ram_ceiling} "
            f"(= {ram_total} B of SRAM from {memory_x.name} − the {CHAIN_CEILING} B "
            f"main-stack ceiling check_boot_chain.py enforces). A static that pushes past "
            f"this does not fail the link; it shrinks the main stack region until the boot "
            f"path overflows it and the board dark-locks (DARK-BOOT-1)."
        )

    if args.update:
        if not DOC.exists():
            print(f"FAIL: {DOC} is missing")
            return 1
        changed, out = update_doc(text, data, bss, sections, syms, ram_origin, ram_total)
        if changed:
            DOC.write_text(out, encoding="utf-8")
            print(f"updated: {DOC.relative_to(ROOT)} "
                  f"(text={text} bss={bss} uf2={blocks} blocks sha256={sha[:12]}…)")
        else:
            print(f"unchanged: {DOC.relative_to(ROOT)} already matches this build")
        _print_facts(text, bss, ram_ceiling, blocks, sha, ram_total, memory_x)
        if failures:
            print("FAIL: check_size_report (US-392 / US-1010) — a budget is exceeded")
            for f in failures:
                print(f"  - {f}")
            return 1
        return 0

    if args.check_doc:
        if not DOC.exists():
            print("FAIL: docs/size-report.md missing")
            return 1
        doc_checks(
            DOC.read_text(encoding="utf-8"),
            text, sha, blocks, sections, data, bss, syms, ram_origin, ram_total, ram_ceiling,
            failures,
        )

    if failures:
        print("FAIL: check_size_report (US-392 / US-1010)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"PASS: check_size_report (US-392 / US-1010) — text={text} "
        f"({CEILING - text} B of the {CEILING} B flash ceiling) bss={bss} "
        f"({ram_ceiling - bss} B of the {ram_ceiling} B RAM ceiling) "
        f"uf2={blocks} blocks"
    )
    _print_facts(text, bss, ram_ceiling, blocks, sha, ram_total, memory_x)
    return 0


def _print_facts(text, bss, ram_ceiling, blocks, sha, ram_total, memory_x):
    """The numbers a reader or a log wants, independent of any document.

    Printed unconditionally: the document is no longer a gate, so this line is
    what makes the measurements visible on every run (CI includes it in the job
    log and the step summary).
    """
    print(
        f"  - facts: text={fmt(text)} B bss={fmt(bss)} B "
        f"RAM ceiling={fmt(ram_ceiling)} B (of {fmt(ram_total)} B SRAM, memory.x "
        f"{memory_x.name}) shipping uf2={blocks} blocks sha256={sha}"
    )
    print(
        f"  - refresh the record with: python3 tests/scripts/check_size_report.py --update"
    )


if __name__ == "__main__":
    sys.exit(main())
