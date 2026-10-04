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

The per-record constants (US-1561, US-1562)
--------------------------------------------

The key region replaced the whole-snapshot store for FIDO credentials, so a
signature-counter bump is now a **record commit plus an index rewrite**
(`FidoRecordStore::update`) rather than a whole-image persist. That is a
different write pattern with a different cost, and §4c of the document is where
it is priced.

So the gate does for it exactly what it did for `COUNTER_PERSIST_INTERVAL`: it
**reads the constants out of the source** and refuses a document that disagrees.

* `SCRATCHPAD_ERASES_PER_COMMIT` and `LIVE_ERASES_PER_COMMIT` are read by regex
  from `platform/src/keyregion/commit.rs`. Those are the only two literals in
  the derivation — everything else in `commit.rs` and `fido_store.rs` is
  *derived* from them, which is the point, and a gate that read four derived
  numbers would be reading four restatements of two.
* Every derived figure is then **re-derived here from those two literals, with
  the source's own formulas**, and each one is compared against what
  `platform/tests/key_region_counter_budget.rs` measured over the real store.
  Three parties, one number: the literal, the measurement, and the document.
* The lifetime is re-derived per **sector**, as before, and the divisor is the
  *busiest* sector rather than a per-write operation count — the mistake §3.4
  withdrew. The gate refuses a document whose per-record divisor is not the
  measured maximum.

The negative test (`--self-test`)
---------------------------------

A gate nobody has watched fail is a gate nobody knows works. `--self-test`
re-runs the evaluator against deliberately broken copies of the document and
the sources and asserts that each named check fires — a stale interval, a
flipped divisor, a removed figure, a document that has stopped labelling the
100,000 as literature. It prints which check each mutation tripped, so a
reviewer can see that the checks are load-bearing rather than merely present.
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

# The per-record instrument and its own prefix. A SEPARATE prefix, not a
# different value for the same key: the two measurements are of different code
# paths over different media, and a document figure set that could describe
# either is a document nobody can check.
RECORD_HARNESS = [
    "cargo",
    "test",
    "-p",
    "fapico2-platform",
    "--target",
    "x86_64-unknown-linux-gnu",
    "--test",
    "key_region_counter_budget",
    "erase_budget_record_figures",
    "--",
    "--exact",
    "--nocapture",
]
RECORD_FIGURE_RE = re.compile(r"^ERASE_BUDGET_RECORD\s+([a-z_]+)=(\d+)\s*$", re.M)

# The two literals the per-record wear derivation is built from. Read by regex
# out of the source for the same reason `COUNTER_PERSIST_INTERVAL` is: the code
# is the single source of truth and the document is what has to follow it.
COMMIT_SRC = ROOT / "platform" / "src" / "keyregion" / "commit.rs"
SCRATCHPAD_ERASES_RE = re.compile(
    r"^pub\s+const\s+SCRATCHPAD_ERASES_PER_COMMIT\s*:\s*u\d+\s*=\s*([0-9]+)\s*;",
    re.M,
)
LIVE_ERASES_RE = re.compile(
    r"^pub\s+const\s+LIVE_ERASES_PER_COMMIT\s*:\s*u\d+\s*=\s*([0-9]+)\s*;",
    re.M,
)

# The keys the per-record document block must carry. Every one is mandatory in
# both the instrument output and the document, for the same reason the snapshot
# figures are.
RECORD_REQUIRED = (
    "sector_erases_per_record_commit",
    "scratchpad_erases_per_record_commit",
    "live_erases_per_record_commit",
    "sector_erases_per_index_entry_write",
    "sector_erases_per_counter_write",
    "measured_sector_erases_per_counter_write",
    "live_sector_erases_per_counter_write",
    "live_slot_programs_per_counter_write",
    "distinct_sectors_erased_per_counter_write",
    "max_erases_per_sector_per_counter_write",
    "unchanged_sector_erases",
    "second_update_sector_erases",
    "measured_slot_programs_per_counter_write",
    "slots_per_sector",
)


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


def measure_record():
    """Run the per-record instrument and return its `key -> value` figures."""
    r = subprocess.run(RECORD_HARNESS, capture_output=True, text=True, cwd=ROOT)
    out = r.stdout + r.stderr
    figures = {m.group(1): int(m.group(2)) for m in RECORD_FIGURE_RE.finditer(out)}
    if r.returncode != 0 or not figures:
        print("FAIL: the per-record erase-budget instrument did not run clean")
        print(out[-3000:])
        sys.exit(1)
    return figures


def doc_figures(doc):
    return {m.group(1): int(m.group(2)) for m in FIGURE_RE.finditer(doc)}


def doc_record_figures(doc):
    return {m.group(1): int(m.group(2)) for m in RECORD_FIGURE_RE.finditer(doc)}


def record_constants():
    """The two wear literals out of `commit.rs`, or `None` if either is gone.

    Read from **source text**, not from a duplicate here, and `None` rather than
    a default when a regex stops matching: a rename or a type change has to be
    reflected in this script rather than silently ungating the derivation.
    """
    if not COMMIT_SRC.exists():
        return None
    text = COMMIT_SRC.read_text(encoding="utf-8")
    scratch = SCRATCHPAD_ERASES_RE.search(text)
    live = LIVE_ERASES_RE.search(text)
    if not scratch or not live:
        return None
    return int(scratch.group(1)), int(live.group(1))


def derive_record(scratchpad, live):
    """The per-record wear figures, from the source's own formulas.

    Written out rather than imported so a reader can check that this script and
    `keyregion/{commit,fido_store}.rs` are doing the same arithmetic; the gate's
    job is to notice when they stop.

    | figure | formula | why |
    |---|---|---|
    | `sector_erases_per_record_commit` | `scratchpad + live` | `commit.rs`: prepare + retire, then the live erase |
    | `sector_erases_per_index_entry_write` | `scratchpad + live` | the same three-phase shape, run over an index sector |
    | `sector_erases_per_counter_write` | the two above, added | a durable counter write is a record commit *and* an index rewrite |
    | `max_erases_per_sector_per_counter_write` | `scratchpad + scratchpad` | **both writes stage through the same scratchpad sector**, so it collects both prepare-and-retire pairs |
    """
    return {
        "sector_erases_per_record_commit": scratchpad + live,
        "sector_erases_per_index_entry_write": scratchpad + live,
        "sector_erases_per_counter_write": 2 * (scratchpad + live),
        "max_erases_per_sector_per_counter_write": scratchpad + scratchpad,
    }


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


def evaluate(doc, measured, interval, measured_record, record_figs):
    """Every check the gate makes, as a list of human-readable failures.

    Split out from `main` so `--self-test` can run the *same* code against
    deliberately broken inputs. A gate whose checks only exist inside a function
    that also touches the filesystem cannot be tested, and a gate that has never
    been tested is a gate nobody knows fails.

    `interval` is the code's `COUNTER_PERSIST_INTERVAL` (or `None` if the regex
    stopped matching) and `record_figs` is the pair of wear literals out of
    `commit.rs` (or `None`), so this function reads nothing itself and every
    input a mutation can reach is a parameter.
    """
    failures = []
    published = doc_figures(doc)

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

    failures.extend(
        record_failures(doc, measured_record, record_figs, cycles, interval)
    )
    return failures


def record_failures(doc, measured, record_figs, cycles, interval):
    """The US-1561/US-1562 half: the per-record counter write's budget.

    Three sources have to agree — the literals in `commit.rs`, the measurement
    over the real store, and the document's own arithmetic — and this checks all
    three against each other. The interesting property is not that they agree
    today but that any one of them moving makes the gate red.
    """
    failures = []
    published = doc_record_figures(doc)

    # --- the measurement must be recorded, and recorded correctly ----------
    for key in RECORD_REQUIRED:
        want = measured.get(key)
        if want is None:
            failures.append(
                f"record: the instrument did not emit `{key}` — §4c's figures cannot be checked"
            )
        elif key not in published:
            failures.append(f"record: doc: no `{key}` figure recorded (measured {want})")
        elif published[key] != want:
            failures.append(f"record: doc: {key} = {published[key]}, measured {want}")
    for key in sorted(set(published) - set(measured)):
        failures.append(
            f"record: doc: `{key}` is not a figure the per-record instrument emits — stale"
        )

    # --- the literals in the source, and what they derive ------------------
    if record_figs is None:
        failures.append(
            f"code: no `SCRATCHPAD_ERASES_PER_COMMIT` / `LIVE_ERASES_PER_COMMIT` literal found "
            f"in {COMMIT_SRC.relative_to(ROOT)} — the gate derives the per-record budget from "
            f"those two, so a rename or a type change has to be reflected here rather than "
            f"silently ungating it"
        )
        return failures

    scratchpad, live = record_figs
    derived = derive_record(scratchpad, live)

    # Literal against measurement: the source says what the protocol issues, the
    # instrument says what it issued. If the commit path grows a fourth erase,
    # this is where it shows.
    for key, want in sorted(derived.items()):
        got = measured.get(key)
        if got is not None and got != want:
            failures.append(
                f"record: measured {key} = {got}, but commit.rs's literals "
                f"(scratchpad {scratchpad}, live {live}) derive {want} — the protocol changed "
                f"and docs/erase-budget.md §4c is now a stale measurement"
            )
    # And the document has to carry the derived value, not just the measured
    # one, so a reader can check the arithmetic.
    for key, want in sorted(derived.items()):
        if key in published and published[key] != want:
            failures.append(
                f"record: doc: {key} = {published[key]}, derived {want} from commit.rs"
            )

    # --- the distribution, which is where this path differs ---------------
    #
    # The snapshot path's premise was `distinct == total`: uniform, one erase
    # per sector. This path is **not** uniform — both the record commit and the
    # index rewrite stage through the same scratchpad — so the check that matters
    # is that the sum adds up and that the divisor is the maximum, which is the
    # mistake §3.4 of the document withdrew.
    per_write = measured.get("sector_erases_per_counter_write")
    busiest = measured.get("max_erases_per_sector_per_counter_write")
    distinct = measured.get("distinct_sectors_erased_per_counter_write")
    live_sector = measured.get("live_sector_erases_per_counter_write")
    slots = measured.get("slots_per_sector")
    if per_write is None or busiest is None or distinct is None:
        return failures
    if busiest > per_write:
        failures.append(
            f"record: max_erases_per_sector_per_counter_write {busiest} exceeds the total "
            f"{per_write} — one sector cannot take more erases than the write issues"
        )
    if busiest * distinct < per_write:
        failures.append(
            f"record: the distribution does not add up: {busiest} erases on each of {distinct} "
            f"sectors is at least {busiest * distinct}, more than the {per_write} the write issues"
        )
    if live_sector is not None and live_sector != live:
        failures.append(
            f"record: live_sector_erases_per_counter_write {live_sector} != LIVE_ERASES_PER_COMMIT "
            f"{live} — the acceptance criterion counts one erase of the record's own sector"
        )
    if slots is not None:
        programs = measured.get("live_slot_programs_per_counter_write")
        if programs is not None and programs != slots:
            failures.append(
                f"record: live_slot_programs_per_counter_write {programs} != slots_per_sector "
                f"{slots} — 'one program' is one sector reprogram, which is this many slot programs"
            )

    # --- the controls that make the measurement able to fail ---------------
    unchanged = measured.get("unchanged_sector_erases")
    if unchanged is not None and unchanged != 0:
        failures.append(
            f"record: unchanged_sector_erases = {unchanged}; reading a record must erase nothing, "
            f"and this is the control that proves there is a path that touches no medium"
        )
    second = measured.get("second_update_sector_erases")
    if second is not None and per_write is not None and second != per_write:
        failures.append(
            f"record: second_update_sector_erases {second} != "
            f"sector_erases_per_counter_write {per_write} — a durable counter write must cost the "
            f"same every time, or the per-write rate published below is not the rate"
        )

    # --- the lifetime, per sector, exactly as §3.3 does it ----------------
    doc_record_ceiling = doc_int(doc, "per_record_counter_write_ceiling")
    if doc_record_ceiling is None:
        failures.append("record: doc: no `per_record_counter_write_ceiling` figure recorded")
    elif cycles and busiest:
        want = cycles // busiest
        if doc_record_ceiling != want:
            failures.append(
                f"record: doc: per_record_counter_write_ceiling {doc_record_ceiling} != "
                f"{cycles} cycles / {busiest} erases on the busiest sector per write = {want}"
            )

    # `doc_expr`, not `doc_int`, for the same reason §4a's batched ceiling uses
    # it: the document writes this figure as the arithmetic that produced it,
    # and `doc_int` on that line returns the *first term* (100,000), not the
    # result. Evaluating the line and comparing the published result separately
    # is what catches a document whose own arithmetic disagrees with its own
    # headline.
    doc_batched_record, doc_batched_record_says = doc_expr(
        doc, "batched_per_record_assertion_ceiling"
    )
    if doc_batched_record is None:
        failures.append("record: doc: no `batched_per_record_assertion_ceiling` figure recorded")
    elif cycles and busiest and interval:
        want = cycles * interval // busiest
        if doc_batched_record != want:
            failures.append(
                f"record: doc: batched_per_record_assertion_ceiling {doc_batched_record} != "
                f"{cycles} x {interval} (COUNTER_PERSIST_INTERVAL) / {busiest} = {want}"
            )
        elif doc_batched_record_says is not None and doc_batched_record_says != doc_batched_record:
            failures.append(
                f"record: doc: batched_per_record_assertion_ceiling's own arithmetic evaluates to "
                f"{doc_batched_record} but the line states {doc_batched_record_says} — the document "
                f"contradicts itself about the figure the interval is argued from"
            )

    # The withdrawn 12,500 must not reappear under the per-record key either.
    for key in ("per_record_counter_write_ceiling", "batched_per_record_assertion_ceiling"):
        if re.search(rf"^\s*{key}\s*=\s*12[,_]?500", doc, re.M):
            failures.append(
                f"record: {key} = 12500 is the withdrawn double-count under a new name"
            )
    return failures


# The mutations `self_test` applies. Each is `(name, doc-edit, expected
# substring in the failure)`: a broken input, and the failure that broken input
# must produce. A mutation that produces no failure fails the self-test, which
# is the point — it is how a check that has stopped checking is caught.
def _mutate_interval(doc):
    """The document's interval is stale — the code moved, the prose did not."""
    return re.sub(r"(?m)^(COUNTER_PERSIST_INTERVAL\s*=\s*)32", r"\g<1>16", doc)


def _mutate_batched(doc):
    """The batched ceiling was recomputed with the old divisor."""
    return re.sub(
        r"(?m)^(batched_assertion_ceiling\s*=\s*)100000 \* 32",
        r"\g<1>100000 * 64",
        doc,
    )


def _mutate_record_divisor(doc):
    """The per-record lifetime divided by the per-write **total** (6) rather than
    by the busiest sector (4) — §3.4's withdrawn double-count under a new key.

    `100000 / 6 = 16,666`, which is what a reader who copied §3.3's shape
    without re-deriving the divisor would publish.
    """
    return re.sub(
        r"(?m)^per_record_counter_write_ceiling = 25000$",
        "per_record_counter_write_ceiling = 16666",
        doc,
    )


def _mutate_record_measured(doc):
    """A measured per-record figure the instrument does not emit."""
    return re.sub(
        r"(?m)^(ERASE_BUDGET_RECORD\s+max_erases_per_sector_per_counter_write=)\d+",
        r"\g<1>2",
        doc,
    )


def _mutate_record_missing(doc):
    """A required per-record figure removed from the document entirely."""
    return re.sub(r"(?m)^ERASE_BUDGET_RECORD\s+live_slot_programs_per_counter_write=\d+\n", "", doc)


def _mutate_no_literature(doc):
    """The document drops the word entirely."""
    return re.sub(r"(?i)literature", "a figure", doc)


# name -> (doc edit, source edit or None, expected substring in the failures)
MUTATIONS = (
    ("stale COUNTER_PERSIST_INTERVAL in the doc", _mutate_interval, "COUNTER_PERSIST_INTERVAL"),
    ("batched ceiling computed with the wrong interval", _mutate_batched, "batched_assertion_ceiling"),
    (
        "per-record lifetime divided by the per-write total",
        _mutate_record_divisor,
        "per_record_counter_write_ceiling",
    ),
    (
        "per-record figure that contradicts the measurement",
        _mutate_record_measured,
        "max_erases_per_sector_per_counter_write",
    ),
    (
        "required per-record figure missing from the doc",
        _mutate_record_missing,
        "live_slot_programs_per_counter_write",
    ),
    ("the word 'literature' removed from the doc", _mutate_no_literature, "literature"),
)


def self_test() -> int:
    """Prove the gate fails when it should, and passes when it should.

    The mutations below each break one thing in the document and assert that the
    named check fires. A check that cannot be made to fire is a check that is
    not load-bearing, and this is how that is discovered.
    """
    doc = DOC.read_text(encoding="utf-8")
    measured = measure()
    measured_record = measure_record()
    interval = code_interval()
    record_figs = record_constants()

    base = evaluate(doc, measured, interval, measured_record, record_figs)
    if base:
        print("FAIL: self-test — the unmutated document does not pass, so every mutation below")
        print("       would 'fail' for the wrong reason:")
        for f in base:
            print(f"  - {f}")
        return 1
    print(f"  baseline: PASS (interval {interval}, record figures {record_figs})")

    bad = 0
    for name, doc_edit, expect in MUTATIONS:
        mutated = doc_edit(doc)
        if mutated == doc:
            print(f"FAIL: self-test — mutation `{name}` did not change the document at all, so")
            print("       it is testing nothing")
            bad += 1
            continue
        failures = evaluate(mutated, measured, interval, measured_record, record_figs)
        if not failures:
            print(f"FAIL: self-test — `{name}` produced NO failure; that check is not load-bearing")
            bad += 1
        elif not any(expect in f for f in failures):
            print(f"FAIL: self-test — `{name}` failed, but not for the expected reason")
            print(f"       (expected a failure mentioning {expect!r}; got)")
            for f in failures:
                print(f"         - {f}")
            bad += 1
        else:
            print(f"  tripped: {name}")

    # The source-side check: if the literals in commit.rs stop matching, the gate
    # must notice rather than keep dividing by a remembered 2 and 1.
    none_figs = evaluate(doc, measured, interval, measured_record, None)
    if not any("SCRATCHPAD_ERASES_PER_COMMIT" in f for f in none_figs):
        print("FAIL: self-test — removing the source literals produced no failure; the gate")
        print("       would silently keep using the last constants it read")
        bad += 1
    else:
        print("  tripped: source literals missing from commit.rs")

    if bad:
        print(f"FAIL: check_erase_budget self-test — {bad} mutation(s) not caught")
        return 1
    print("PASS: check_erase_budget self-test — every mutation tripped its named check")
    return 0


def main() -> int:
    if not DOC.exists():
        print("FAIL: docs/erase-budget.md missing")
        return 1
    doc = DOC.read_text(encoding="utf-8")
    measured = measure()
    measured_record = measure_record()
    interval = code_interval()
    record_figs = record_constants()

    failures = evaluate(doc, measured, interval, measured_record, record_figs)

    if failures:
        print("FAIL: check_erase_budget (US-1010/1011/1561/1562)")
        for f in failures:
            print(f"  - {f}")
        return 1

    pub = doc_figures(doc)
    rpub = doc_record_figures(doc)
    print(
        f"PASS: check_erase_budget (US-1010/1011/1561/1562)"
        f"\n  snapshot persist: {pub['changed_sector_erasures_per_persist']} sector erasures across "
        f"{pub['changed_distinct_sectors_erased_per_persist']} distinct sectors, "
        f"{pub['changed_max_erases_per_sector_per_persist']} on the busiest, "
        f"ceiling {doc_int(doc, 'assertion_ceiling')} assertions; "
        f"COUNTER_PERSIST_INTERVAL {interval}, batched ceiling "
        f"{doc_expr(doc, 'batched_assertion_ceiling')[0]}"
        f"\n  per-record counter write: {rpub['sector_erases_per_counter_write']} sector erasures "
        f"across {rpub['distinct_sectors_erased_per_counter_write']} distinct sectors, "
        f"{rpub['max_erases_per_sector_per_counter_write']} on the busiest (the scratchpad), "
        f"ceiling {doc_int(doc, 'per_record_counter_write_ceiling')} durable writes; batched "
        f"{doc_expr(doc, 'batched_per_record_assertion_ceiling')[0]} assertions"
    )
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(main())
