#!/usr/bin/env python3
"""US-1010 gate: the flash erase budget.

Re-measures what `FlashSlotSink::program` asks the flash driver to erase
(the host instrument in `platform/tests/persist_sink.rs::erase_budget_figures`)
and fails while `docs/erase-budget.md` disagrees — on a stale figure, on a
missing figure, or on an internally inconsistent arithmetic.

Two things are checked, and the difference matters:

  * MEASURED. How many `SlotFlash::erase` calls a persist issues, how many
    4 KiB NOR sectors those calls cover, and — the figure the lifetime is
    actually derived from — how those sector erasures are *distributed*:
    how many distinct sectors they land on, and how many of them the
    busiest single sector collects. This is a property of the sink, and
    the host NOR model can answer it exactly.
  * ARITHMETIC. The assertion ceiling the document derives from those
    figures and from the published cycles-per-sector figure. The gate
    re-derives it and refuses a document whose own numbers do not add up.

On which divisor the ceiling uses. Endurance is specified per **sector**,
so the lifetime is `cycles_per_sector / (erases a persist lands on ONE
sector)`. A persist issues `changed_sector_erasures_per_persist` erase
operations, but the instrument measures that they land on
`changed_distinct_sectors_erased_per_persist` *different* sectors, each
collecting `changed_max_erases_per_sector_per_persist` of them. Dividing
by the total would charge one sector for all 8 erases — a double-count,
and the reason the first published ceiling read 12,500 instead of 100,000.
The gate refuses any document whose `distinct == total` premise does not
hold, and derives the ceiling from the per-sector rate.

The gate deliberately asserts nothing about how the RP2350 bootrom splits a
range into hardware erase commands: `docs/erase-budget.md` carries that as a
HAL-source argument, and the hardware leg is stated there as not measured on
this part. A gate that pinned an unmeasured number could not fail honestly.

The batched constants (US-1011)
-------------------------------

`COUNTER_PERSIST_INTERVAL` and `batched_assertion_ceiling` are checked in
**both** directions, which is the part the review found missing. Before this,
`cycles_per_sector` was gated and the interval was not: the only coupling was
a `PINNED_INTERVAL` constant in two test files plus a sentence in a doc
comment telling a developer to keep three files in step by hand. A developer
editing the interval in `apps/fido/src/device_keystore.rs` was under no
obligation to move `docs/erase-budget.md` §4a, and nothing would have said so.

So the gate now:

* reads the constant **out of the source**, not out of a duplicate in a test
  (`COUNTER_PERSIST_INTERVAL: u16 = 32`);
* refuses the document if its `COUNTER_PERSIST_INTERVAL` figure is missing;
* re-derives `batched_assertion_ceiling` from the *code's* interval and the
  already-measured `cycles_per_sector` and `per_sector`, and refuses the
  document if its published figure disagrees.

That last one is the load-bearing check and it is arithmetic, not a
string-match, so editing the constant in either place without the other is a
red gate rather than a stale sentence. The derivation is the document's own:
`ceiling x interval / per-sector-erases-per-persist`.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "erase-budget.md"

# Where the constant actually lives. The gate reads the number from HERE, so
# the code is the single source of truth and the document is what has to
# follow it — not the other way round.
INTERVAL_SRC = ROOT / "apps" / "fido" / "src" / "device_keystore.rs"
INTERVAL_RE = re.compile(
    r"^pub\s+const\s+COUNTER_PERSIST_INTERVAL\s*:\s*u\d+\s*=\s*([0-9]+)\s*;",
    re.M,
)

# The figure the EPIC quotes for NOR flash endurance. NOT measured on this
# part — it is a literature value, the document says so, and the gate checks
# only that the document records it and does its own arithmetic with it.
LITERATURE_CYCLES_PER_SECTOR = 100_000

HARNESS = [
    "cargo",
    "test",
    "-p",
    "fapico2-platform",
    "--target",
    "x86_64-unknown-linux-gnu",
    "--test",
    "persist_sink",
    "erase_budget_figures",
    "--",
    "--exact",
    "--nocapture",
]

# key -> whether the key must be present in BOTH the harness output and the
# document. Every key is mandatory; a key that appears in only one side is
# drift in the same sense a value mismatch is.
FIGURE_RE = re.compile(r"^ERASE_BUDGET\s+([a-z_]+)=(\d+)\s*$", re.M)


def measure():
    """Run the host instrument and return its `key -> value` figures."""
    r = subprocess.run(HARNESS, capture_output=True, text=True, cwd=ROOT)
    out = r.stdout + r.stderr
    figures = {m.group(1): int(m.group(2)) for m in FIGURE_RE.finditer(out)}
    if r.returncode != 0 or not figures:
        print("FAIL: the erase-budget instrument did not run clean")
        print(out[-3000:])
        sys.exit(1)
    return figures


def doc_figures(doc):
    return {m.group(1): int(m.group(2)) for m in FIGURE_RE.finditer(doc)}


def doc_int(doc, key):
    """First `key = <number>` in `doc`, commas stripped.

    A bare integer only. `doc_expr` is the one that copes with the document
    writing its figures as the arithmetic that produced them
    (`batched_assertion_ceiling = 100000 * 32 / 1 = 3200000`), which is the
    form §4a uses and the form a reader is meant to check.
    """
    m = re.search(rf"^\s*{key}\s*=\s*([0-9][0-9_,]*)", doc, re.M)
    return int(m.group(1).replace(",", "")) if m else None


def doc_expr(doc, key):
    """`(evaluated, published)` for `key = <expr> [= <result>]`, or (None, None).

    `evaluated` is the arithmetic the document wrote, `published` is the
    result it states beside it (None when the line is a bare number). A
    document that prints both and gets them wrong is contradicting itself
    about the figure the interval choice is argued from, which is worth a
    failure of its own — `doc_int` cannot see this, because on an arithmetic
    line it returns the *first* term, not the result.

    Division is integer division, matching how the document computes the
    ceilings.
    """
    m = re.search(
        rf"^\s*{key}\s*=\s*([0-9][0-9_,]*(?:\s*[+*/-]\s*[0-9][0-9_,]*)*)"
        r"\s*(?:=\s*([0-9][0-9_,]*))?\s*(?:#.*|[A-Za-z_]\w*)?\s*$",
        doc,
        re.M,
    )
    if not m:
        return None, None
    body = m.group(1).replace(",", "").replace(" ", "")
    try:
        # Only digits and the four operators are reachable through the regex,
        # so this is arithmetic on literals, not an eval of tree content.
        if not re.fullmatch(r"[0-9+*/-]+", body):
            return None, None
        value = eval(body, {"__builtins__": {}}, {})  # noqa: S307 - literals only
    except (ArithmeticError, SyntaxError, ValueError):
        return None, None
    published = m.group(2)
    return int(value), (int(published.replace(",", "")) if published else None)


def code_interval():
    """`COUNTER_PERSIST_INTERVAL` as the SOURCE declares it, or None."""
    if not INTERVAL_SRC.exists():
        return None
    m = INTERVAL_RE.search(INTERVAL_SRC.read_text(encoding="utf-8"))
    return int(m.group(1)) if m else None


def main() -> int:
    if not DOC.exists():
        print("FAIL: docs/erase-budget.md missing")
        return 1
    doc = DOC.read_text(encoding="utf-8")
    measured = measure()
    published = doc_figures(doc)

    failures = []

    # --- the measurement must be recorded, and recorded correctly ----------
    for key, want in sorted(measured.items()):
        if key not in published:
            failures.append(f"doc: no `{key}` figure recorded (measured {want})")
        elif published[key] != want:
            failures.append(f"doc: {key} = {published[key]}, measured {want}")
    for key in sorted(set(published) - set(measured)):
        failures.append(f"doc: `{key}` is not a figure the instrument emits — stale")

    # --- the document's own arithmetic must hold ---------------------------
    gran = published.get("sector_granularity_bytes")
    slot_bytes = published.get("slot_bytes")
    sectors_per_slot = published.get("sectors_per_slot")
    slots = published.get("slots")
    per_persist = published.get("changed_sector_erasures_per_persist")
    distinct = published.get("changed_distinct_sectors_erased_per_persist")
    per_sector = published.get("changed_max_erases_per_sector_per_persist")

    if None not in (gran, slot_bytes, sectors_per_slot):
        if slot_bytes % gran:
            failures.append(f"doc: slot_bytes {slot_bytes} is not a multiple of the {gran}-byte sector")
        if sectors_per_slot != slot_bytes // gran:
            failures.append(
                f"doc: sectors_per_slot {sectors_per_slot} != {slot_bytes} / {gran} "
                f"= {slot_bytes // gran}"
            )
    if None not in (sectors_per_slot, slots, per_persist):
        if per_persist != sectors_per_slot * slots:
            failures.append(
                f"doc: changed_sector_erasures_per_persist {per_persist} != "
                f"{slots} slots x {sectors_per_slot} sectors = {slots * sectors_per_slot}"
            )

    # --- the distribution: the premise the ceiling rests on ----------------
    # `distinct == total` is what says the persist's erases do NOT pile onto
    # one sector. Without it the per-sector divisor is unknown and the
    # lifetime cannot be derived at all, so it is checked, not assumed.
    if None not in (per_persist, distinct) and distinct != per_persist:
        failures.append(
            f"doc: changed_distinct_sectors_erased_per_persist {distinct} != "
            f"changed_sector_erasures_per_persist {per_persist} — the persist's "
            f"sector erases no longer land on distinct sectors, so the per-sector "
            f"wear rate the ceiling is derived from has changed shape"
        )
    if None not in (per_persist, distinct, per_sector):
        if per_sector * distinct != per_persist:
            failures.append(
                f"doc: changed_max_erases_per_sector_per_persist {per_sector} x "
                f"{distinct} distinct sectors = {per_sector * distinct} != "
                f"{per_persist} sector erasures per persist — the per-sector "
                f"distribution does not add up"
            )
    if per_sector is not None and per_sector < 1:
        failures.append(
            f"doc: changed_max_erases_per_sector_per_persist {per_sector} < 1 — "
            f"every persist erases at least one sector, so the rate cannot be zero"
        )

    cycles = doc_int(doc, "cycles_per_sector")
    ceiling = doc_int(doc, "assertion_ceiling")
    if cycles is None:
        failures.append("doc: no `cycles_per_sector` figure recorded")
    elif cycles != LITERATURE_CYCLES_PER_SECTOR:
        failures.append(
            f"doc: cycles_per_sector {cycles} is not the literature NOR figure "
            f"the EPIC quotes ({LITERATURE_CYCLES_PER_SECTOR})"
        )
    if ceiling is None:
        failures.append("doc: no `assertion_ceiling` figure recorded")
    elif cycles and per_sector:
        # Per SECTOR, not per persist: this is the corrected derivation. The
        # old per-persist divisor is 8x too small and is what produced the
        # withdrawn 12,500.
        want = cycles // per_sector
        if ceiling != want:
            failures.append(
                f"doc: assertion_ceiling {ceiling} != {cycles} cycles / "
                f"{per_sector} sector erases per sector per persist = {want}"
            )

    # The superseded figure must not creep back in as a bare `assertion_ceiling`
    # line; the document may discuss it, but only under another name. Caught
    # structurally above (`doc_int` takes the FIRST match), stated here so the
    # reason is on the record.
    if re.search(r"^\s*assertion_ceiling\s*=\s*12[,_]?500", doc, re.M):
        failures.append(
            "doc: assertion_ceiling = 12500 is the withdrawn double-count "
            "(cycles / total sector erasures per persist). It may be discussed "
            "in prose under another key, but not as the ceiling."
        )

    # The endurance figure is a literature value; the document has to say so.
    if "literature" not in doc.lower():
        failures.append(
            "doc: the ~100k cycles-per-sector figure is a literature value for "
            "NOR flash, not measured on this part — the document must label it"
        )

    # --- US-1011: the batched constants, doc <-> code, BOTH directions ------
    # The code is the source of truth (read above); the document follows. Both
    # a stale document and a missing one are failures, and the ceiling is
    # re-derived rather than string-matched, so a one-sided edit cannot pass.
    interval = code_interval()
    doc_interval = doc_int(doc, "COUNTER_PERSIST_INTERVAL")
    doc_batched, doc_batched_says = doc_expr(doc, "batched_assertion_ceiling")
    if interval is None:
        failures.append(
            f"code: no `pub const COUNTER_PERSIST_INTERVAL: uN = <n>;` found in "
            f"{INTERVAL_SRC.relative_to(ROOT)} — the gate reads the interval "
            f"from the source, so a rename or a type change has to be "
            f"reflected here rather than silently ungating it"
        )
    else:
        if doc_interval is None:
            failures.append(
                "doc: no `COUNTER_PERSIST_INTERVAL` figure recorded — the "
                f"code says {interval} and the document has to agree with it"
            )
        elif doc_interval != interval:
            failures.append(
                f"doc: COUNTER_PERSIST_INTERVAL {doc_interval} != code "
                f"{interval} (apps/fido/src/device_keystore.rs) — the batched "
                f"ceiling below is derived from the code's value, so the "
                f"document's lifetime arithmetic is not the one the device "
                f"runs"
            )
        if doc_batched is None:
            failures.append(
                "doc: no `batched_assertion_ceiling` figure recorded"
            )
        elif cycles and per_sector:
            # The document's own derivation, §4a:
            #   batched = cycles_per_sector x interval / per-sector rate
            want_batched = cycles * interval // per_sector
            if doc_batched != want_batched:
                failures.append(
                    f"doc: batched_assertion_ceiling {doc_batched} != "
                    f"{cycles} x {interval} (COUNTER_PERSIST_INTERVAL) / "
                    f"{per_sector} = {want_batched}"
                )
            elif doc_batched_says is not None and doc_batched_says != doc_batched:
                # The document publishes both the arithmetic and a result, and
                # the two disagree — so a reader who checks the arithmetic
                # gets a different lifetime from the one in the prose.
                failures.append(
                    f"doc: batched_assertion_ceiling's own arithmetic evaluates "
                    f"to {doc_batched} but the line states {doc_batched_says} — "
                    f"the document contradicts itself on the figure the interval "
                    f"choice is argued from"
                )
    # A 0 or 1 interval would make the batching vacuous or a no-op and is
    # never deliberate; the constant is `u16` so the type will not catch it.
    if interval is not None and interval < 2:
        failures.append(
            f"code: COUNTER_PERSIST_INTERVAL = {interval} — batching a persist "
            f"at fewer than 2 assertions buys nothing and the batching stories' "
            f"claims do not hold"
        )

    if failures:
        print("FAIL: check_erase_budget (US-1010/1011)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        f"PASS: check_erase_budget (US-1010/1011) — {per_persist} sector "
        f"erasures per persist across {distinct} distinct sectors, {per_sector} "
        f"per sector, ceiling {ceiling} assertions (per-sector model); "
        f"COUNTER_PERSIST_INTERVAL {interval} (code) = {doc_interval} (doc), "
        f"batched ceiling {doc_batched}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
