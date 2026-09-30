#!/usr/bin/env python3
"""S-392-2 gate: size report consistency (US-392; RAM figures US-1010).

Rebuilds the device ELF (default = device target), re-measures
`arm-none-eabi-size` (+ `-A` and the RAM symbols), recomputes the shipping UF2
sha256/block count, and fails while `docs/size-report.md` disagrees (or lacks
the numbers).

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
stack-zone lines at the time of writing). A gate that checks the headline and
ignores the detail will happily pass over a stale interior, because the detail
is prose-shaped and there was nothing to compare it against. The measured
blocks are now delimited, and this script **regenerates them from the ELF and
fails if the document differs** — so a stale interior is a FAIL, not a thing a
reader has to notice.

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
    """The document's copy of a generated block must equal the measurement."""
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
            f"hand-copied interior that has gone stale. Re-run ./build.sh and paste the "
            f"measured block (the gate prints it below).\n"
            f"--- measured ---\n{want}\n--- in the document ---\n{got}"
        )


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
    if not DOC.exists():
        print("FAIL: docs/size-report.md missing")
        return 1
    text, data, bss = measure_elf()
    sections = measure_sections()
    syms = symbols("__sheap", "_stack_start", "_stack_end")
    ram_origin, ram_total, memory_x = ram_bytes()
    ram_ceiling = ram_total - CHAIN_CEILING
    sha, blocks = uf2_facts()
    doc = DOC.read_text(encoding="utf-8")

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
    m = re.search(r"Rust[^*\n]*text[^0-9\n]*([\d,]+)\s*B", doc)
    if not m:
        failures.append("doc: no Rust text measurement found")
    elif int(m.group(1).replace(",", "")) != text:
        failures.append(f"doc Rust text {m.group(1)} != measured {text}")
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
    print(
        f"  - RAM ceiling derived: {fmt(ram_total)} B SRAM (memory.x {memory_x.name}) "
        f"− {fmt(CHAIN_CEILING)} B chain ceiling (check_boot_chain.CHAIN_CEILING) "
        f"= {fmt(ram_ceiling)} B"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
