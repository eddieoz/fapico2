#!/usr/bin/env python3
"""Gate: worst-case main-stack CALL CHAIN vs the RP2350 stack zone (US-956).

`check_async_frame.py` (US-939/US-951) bounds ONE frame: the largest Embassy
`TaskStorage::<F>::poll` instantiation. That was necessary but nowhere near
sufficient — on a Cortex-M every Embassy task, the trussed runner and every
interrupt handler share the single MSP stack, so the linker-leftover stack
zone has to survive a whole *call chain*, not one frame. US-951 measured the
worst boot-path chain at 117,828 B against a 5,056 B zone (23.3x over): the
async frame (18,288 B) was the smallest part of it.

Nothing in the gate set measured that. A future `FidoApp::boot` reserving
63,000 B in a single frame would pass every existing gate. This one does.

Method (the US-951 method, kept deliberately mechanical and deterministic —
no sampling, no heuristics):

1. `arm-none-eabi-objdump -d` the release ELF; parse every function label and
   its *frame reservation* = `push {…}` words + `sub.w sp, sp, #N` +
   `sub sp, #N` (both folds summed, exactly as `check_async_frame.py` does).
2. Parse the call graph from `bl` / `blx <label>` edges between known
   functions. Tail calls (`b.w`) are NOT edges: a `b.w` to a symbol reuses the
   caller's frame, so charging the callee's frame on top would over-count.
   **Register-indirect calls (`blx rN`) are not edges either** — see US-957
   step 5, which is how the vtable hop is accounted for.
3. Condense the graph with Tarjan's SCC (iterative — a 300k-line
   disassembly blows a recursive implementation's stack) and take the longest
   path over the condensation. Tarjan emits components in reverse topological
   order, so the longest path is one reverse pass over the emission order.
4. Roots are the Embassy `TaskStorage::<F>::poll` instantiations (the same
   set `check_async_frame.py` bounds): every task runs on the one stack, so
   the gate is `max over roots`, not per-root.
5. US-957: a **second root class** — the `fapico2_platform::dispatch::App`
   trait impls (`process`, `select`, `select_apdu`, `deselect`,
   `factory_wipe`). `platform/src/dispatch.rs` holds the registered apps as
   `Vec<&mut dyn App, N>` and reaches them through the vtable, so the
   per-APDU request-serving path is entered by a `blx rN`, not a `bl`. Before
   US-957 the gate was blind to it: it saw only the boot chain, and *all* of
   RSA, secp256k1 and Brainpool sit on the request path, not the boot path.
   Because the connecting edge is invisible, a vtable root is charged
   `chain(root) + max own frame over the task-poll roots` — the deepest
   possible caller frame stacked on the indirect callee's own chain. That is
   an upper bound on `task poll frame + … + vtable callee chain`, which is
   what actually executes.
6. US-957: the count of `blx rN` sites is reported, so the remaining blind
   spot is visible in the output rather than silent.

7. US-961: steps 4 and 5 were **measuring nothing** on the current toolchain.
   Both selected their roots with rustc *legacy* mangling fragments, and the
   toolchain now emits **v0** — so the gate found 4 task "roots" instead of
   the 6 in the ELF, and **zero** of the 18 `dispatch::App` vtable shims, i.e.
   none of the request-serving path US-957 built this gate to certify. It
   still exited 0, because the degradation only appeared in a `--json` field
   nobody reads. Root selection now lives in `tests/scripts/stack_roots.py`
   and matches mangling-independent identifiers, and the root set is
   **asserted against a floor derived from source** (`firmware/src/main.rs`'s
   `#[task]`/`#[main]` declarations; `apps/src/registry.rs`'s registered CCID
   apps). A shortfall is a hard FAIL. Both gates share that module so they
   cannot drift into measuring different things again.

Exit 0 when the root set is complete AND the worst chain fits
`limit = min(CEILING, stack_zone)`.

Usage:
    python3 tests/scripts/check_boot_chain.py [--no-build] [--json]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import arena_stamp  # noqa: E402  (path is set above)
import stack_roots  # noqa: E402  (path is set above)

ROOT = pathlib.Path(__file__).resolve().parents[2]
ELF = ROOT / "target/thumbv8m.main-none-eabi/release/fapico2-firmware"

# Absolute regression ceiling for a single task's worst-case chain.
#
# US-956 derived it as "~0.8x the 119,744 B stack zone" (and ~1.46x the then
# measured 67,288 B boot-only chain). US-957 did NOT change the number: the
# "~0.8x the real zone" derivation is independent of the measurement and is
# still the tighter of the two criteria. What changed is the measurement it
# is compared against — and, in US-961, whether the measurement is taken at
# all: for ~30 commits this gate's root selection matched nothing under v0
# mangling, so the chain it published was the boot chain alone.
#
# US-1010 corrected the *advertised* margin, which had drifted into advertising
# a number this gate never enforced. The gate binds on
# `limit = min(CHAIN_CEILING, stack_zone)`, and on this build the **ceiling is
# the smaller term** (98,304 vs a 111,804 B zone), so the ceiling decides. The
# honest margin is `CHAIN_CEILING - worst_chain` = 98,304 − 91,964 = **6,340 B
# (6.5 %)**, not the "~35 KiB (29.5 %)" this comment used to carry and not the
# `zone - top_chain` (19,840 B, 17.7 %) the PASS line prints. Two different
# quantities were being called "the margin", and the one in this comment was
# neither. The zone figure is the right one to print *only* while the zone is
# the binding term; the binding term is the smaller of the two, so the gate
# prints both and this comment states which is which.
#
# The *binding* limit flips, and deliberately: if the statics grow back the
# zone shrinks and `min()` drops to the zone, at which point this ceiling
# stops mattering — which is the failure mode the US-951 `check_async_frame`
# ceiling had inverted. `check_size_report.py` gates the statics against
# `RAM_BYTES - CHAIN_CEILING` (US-1010) precisely so that flip is visible
# before it happens, rather than after.
CHAIN_CEILING = 96 * 1024

# US-956: the Embassy task arena is a fixed-size bump reservoir; a task that
# does not fit panics "task arena is full" at spawn — a dark boot that
# nothing in the suite measures. `fapico2_firmware::TASK_ARENA_DEMAND_B`
# records the measured demand (see its doc comment for the command); this
# gate checks it still fits the linked `ARENA` with headroom.
#
# US-964: it also checks the demand is *believable*. The number used to be
# hand-copied from one `-Zprint-type-sizes` run, so a grown `ccid_task` future
# left the gate publishing a margin computed from a figure that no longer
# described the build. The constant now carries a stamp over the sources it
# was measured from, and a mismatch is a hard FAIL — never a pass with a
# stale number in it.
ARENA_MIN_HEADROOM_X1000 = 1250

# US-961: root selection moved to `tests/scripts/stack_roots.py`, shared with
# `check_async_frame.py`. The patterns that used to live here matched rustc
# *legacy* mangling and therefore matched **zero** roots under the v0 scheme
# the current toolchain emits: 4 "roots" instead of the 6 task polls, and 0 of
# the 18 `dispatch::App` vtable shims — the class US-957 added for the
# request-serving path. The gate still exited 0, because the degradation was
# only visible in a `--json` field nobody reads. Two changes fix it:
#   * `stack_roots` matches mangling-independent identifiers (`dispatch` /
#     `App` / `process`, `embassy_executor` / `raw` / `TaskStorage` / `poll`),
#     which both schemes print, and never anchors on a crate name (v0 path
#     compression legitimately drops `fapico2_platform`).
#   * `stack_roots.check_root_coverage` FAILS when the found root set is
#     short of a floor derived from *source* (the `#[task]`/`#[main]`
#     declarations in the device binary's module tree, and the apps the
#     device registers behind the dispatcher). A future mangling change is a
#     hard failure, not a quiet PASS.

LABEL = re.compile(r"^([0-9a-f]+) <([^+>]+)>:")
PUSH = re.compile(r"\bpush\s+\{([^}]*)\}")
SUB_SP = re.compile(r"\bsub\.[wbn]*\s*sp, sp, #(\d+)")
SUB_SP_NARROW = re.compile(r"\bsub\s+sp, #(\d+)")
BL = re.compile(r"\b(?:bl|blx)\s+[0-9a-f]+ <([^+>]+)>")
# US-957: a `blx` through a register — a vtable, a function pointer, a trait
# object method. Counted, never resolved (see the docstring).
BLX_REG = re.compile(r"\bblx\s+r[0-9a-f]+")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, **kw)


def build() -> None:
    r = run(["cargo", "build", "--release", "--target", "thumbv8m.main-none-eabi"])
    if r.returncode != 0:
        print("FAIL: device build failed\n" + r.stderr[-2000:])
        sys.exit(1)
    if not ELF.exists():
        print(f"FAIL: release ELF missing: {ELF}")
        sys.exit(1)


def stack_zone() -> int:
    r = run(["arm-none-eabi-nm", str(ELF)])
    if r.returncode != 0 or not r.stdout.strip():
        print("FAIL: arm-none-eabi-nm unavailable: " + r.stderr)
        sys.exit(1)
    vals = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in ("_stack_start", "_stack_end", "__sheap"):
            vals[parts[2]] = int(parts[0], 16)
    for sym in ("_stack_start", "_stack_end"):
        if sym not in vals:
            print(f"FAIL: check_boot_chain (US-956) — {sym} not in the ELF symbol table")
            sys.exit(1)
    return vals["_stack_start"] - vals["_stack_end"]


def parse_disassembly() -> tuple[dict[str, int], dict[str, list[str]], int]:
    r = run(["arm-none-eabi-objdump", "-d", str(ELF)])
    if r.returncode != 0 or not r.stdout.strip():
        print("FAIL: arm-none-eabi-objdump unavailable: " + r.stderr)
        sys.exit(1)

    frames: dict[str, int] = {}
    edges: dict[str, list[str]] = {}
    indirect = 0
    cur = None
    for line in r.stdout.splitlines():
        m = LABEL.match(line)
        if m:
            cur = m.group(2)
            frames.setdefault(cur, 0)
            edges.setdefault(cur, [])
            continue
        if cur is None:
            continue
        p = PUSH.search(line)
        if p:
            words = len([x for x in p.group(1).split(",") if x.strip()])
            frames[cur] = max(frames[cur], 4 * words)
            continue
        m2 = SUB_SP.search(line) or SUB_SP_NARROW.search(line)
        if m2:
            frames[cur] += int(m2.group(1))
            continue
        m3 = BL.search(line)
        if m3 and m3.group(1) != cur:
            edges[cur].append(m3.group(1))
            continue
        if BLX_REG.search(line):
            indirect += 1
    return frames, edges, indirect


def scc_components(frames, edges):
    """Iterative Tarjan. Returns (comp_of, comp_weight, order) where `order`
    lists component ids in reverse topological order (sinks first)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    comp_of: dict[str, int] = {}
    comp_weight: dict[int, int] = {}
    order: list[int] = []
    counter = 0

    for root in list(frames):
        if root in index:
            continue
        work: list[list] = [[root, 0]]
        while work:
            frame = work[-1]
            v, pi = frame[0], frame[1]
            if pi == 0:
                index[v] = low[v] = counter
                counter += 1
                stack.append(v)
                on_stack.add(v)
            succs = edges.get(v, ())
            recursed = False
            while pi < len(succs):
                w = succs[pi]
                pi += 1
                if w not in frames:
                    continue
                if w not in index:
                    frame[1] = pi
                    work.append([w, 0])
                    recursed = True
                    break
                if w in on_stack:
                    low[v] = min(low[v], index[w])
            if recursed:
                continue
            frame[1] = pi
            work.pop()
            if low[v] == index[v]:
                cid = len(comp_weight)
                total = 0
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp_of[w] = cid
                    total += frames[w]
                    if w == v:
                        break
                comp_weight[cid] = total
                order.append(cid)
            if work:
                pv = work[-1][0]
                low[pv] = min(low[pv], low[v])
    return comp_of, comp_weight, order


def condensation(frames, edges):
    """Condense once, then solve once. Returns `(comp_of, best)`.

    `best[cid]` is the longest path *starting at* component `cid` over the
    condensation, so the chain from any root is a single dict lookup.

    US-961: the root set went from 4 (what the broken legacy-mangling matcher
    found) to 24, and this analysis used to re-run Tarjan + the longest-path
    pass once per root — 24 traversals of a 4,176-function / 17,860-edge graph
    for 24 roots. The condensation is root independent, so it is computed
    once and every root is a dict lookup. Same answer, one traversal.
    """
    comp_of, comp_weight, order = scc_components(frames, edges)
    comp_edges: dict[int, list[int]] = {c: [] for c in comp_weight}
    for src, dsts in edges.items():
        cs = comp_of.get(src)
        if cs is None:
            continue
        for d in dsts:
            cd = comp_of.get(d)
            if cd is not None and cd != cs and cd not in comp_edges[cs]:
                comp_edges[cs].append(cd)
    # Longest path over the condensation. `order` is reverse-topological, so
    # a successor's best value is already final when its predecessors run.
    best: dict[int, int] = {}
    for cid in order:
        best[cid] = comp_weight[cid] + max(
            (best[d] for d in comp_edges[cid]), default=0
        )
    return comp_of, best


def longest_chain(comp_of, best, root: str) -> int:
    return best[comp_of[root]]


def arena_symbol_size() -> int | None:
    """`embassy_executor::_export::ARENA` size out of the ELF, or None.

    Note: `nm -S` prints the size field zero-padded **decimal**, not hex
    (it is padded to the address width, which is why it looks hex-ish)."""
    r = run(["arm-none-eabi-nm", "--size-sort", "-S", "-td", str(ELF)])
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 4 and "_export5ARENA" in parts[3]:
            return int(parts[1], 10)
    return None


def arena_demand() -> int | None:
    """`TASK_ARENA_DEMAND_B` as declared in `firmware/src/lib.rs`."""
    src = ROOT / "firmware/src/lib.rs"
    try:
        text = src.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(
        r"pub const TASK_ARENA_DEMAND_B:\s*usize\s*=\s*([0-9_]+)\s*;", text
    )
    return int(m.group(1).replace("_", "")) if m else None


def check_arena() -> tuple[bool, str]:
    demand = arena_demand()
    size = arena_symbol_size()
    if demand is None or size is None:
        return True, "  - task arena: not checked (demand constant or ARENA symbol absent)"

    # US-964: the demand is only evidence if it was measured from the tree as
    # it stands. `TASK_ARENA_DEMAND_B_STAMP` is a sha256 over the firmware's
    # sources and its resolved dependency closure (tests/scripts/arena_stamp.py);
    # a contributor who grows a task's future, or bumps a dependency, invalidates
    # it. Refusing here — loudly, with the command — is the whole point: the
    # alternative is a gate reporting "1.85x, floor 1.25x" from a number that
    # stopped describing anything while the device panics "task arena is full".
    declared = arena_stamp.declared_stamp(ROOT)
    if declared is None:
        return False, (
            "  - task arena: `TASK_ARENA_DEMAND_B_STAMP` is missing from "
            "firmware/src/lib.rs, so the demand constant below is not stamped and "
            "this gate cannot tell a current measurement from a stale one. "
            "Re-measure:  python3 tests/scripts/measure_task_arena.py"
        )
    current = arena_stamp.fingerprint(ROOT)
    if declared != current:
        return False, (
            f"  - task arena: the demand constant's stamp no longer matches the "
            f"sources it was measured from (declared {declared[:16]}…, current "
            f"{current[:16]}…). Either a task future grew, or a dependency in the "
            "firmware's closure moved, since the last measurement — so the "
            f"{demand} B below is stale and the headroom figure it produces is "
            "meaningless. It is also what a documentation commit does: the stamp "
            "is byte-exact over the source text and cannot tell a comment from "
            "code (see the limitation documented in tests/scripts/arena_stamp.py). "
            "Re-measure either way (needs nightly) — the measurement is the "
            "authority, not the stamp:  "
            "python3 tests/scripts/measure_task_arena.py"
        )

    if demand > size:
        return False, (
            f"  - task arena: measured demand {demand} B does NOT fit the linked "
            f"ARENA ({size} B) — the first spawn that overflows panics 'task arena "
            f"is full' and the device dark-boots. Re-measure "
            f"TASK_ARENA_DEMAND_B in firmware/src/lib.rs and raise "
            f"embassy-executor's task-arena-size feature if the statics allow it."
        )
    if demand * 1000 > size * ARENA_MIN_HEADROOM_X1000:
        return False, (
            f"  - task arena: headroom fell below "
            f"{ARENA_MIN_HEADROOM_X1000 / 1000}x — demand {demand} B in a {size} B "
            f"arena ({size / max(demand, 1):.2f}x)."
        )
    return True, (
        f"  - task arena: demand {demand} B fits ARENA {size} B "
        f"({size / max(demand, 1):.2f}x, floor {ARENA_MIN_HEADROOM_X1000 / 1000}x; "
        f"measurement stamp {declared[:16]}… verified against the current sources)"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not args.no_build:
        build()
    zone = stack_zone()
    frames, edges, indirect = parse_disassembly()

    task_roots = [s for s in frames if stack_roots.is_task_poll(s)]
    vtable_roots = [s for s in frames if stack_roots.is_app_shim(s)]
    # US-961: the root set is asserted against a source-derived floor BEFORE
    # anything is measured. A gate that cannot see the request-serving path
    # must not get to publish a margin number as though it did — that is
    # exactly the failure this story exists to close.
    coverage = stack_roots.check_root_coverage(task_roots, vtable_roots)
    if coverage:
        for line in coverage:
            print(f"FAIL: check_boot_chain (US-961) — {line}")
        print("  - root selection lives in tests/scripts/stack_roots.py; it "
              "matches mangling-independent identifiers and is floored against "
              "firmware/src/main.rs (the `#[task]`/`#[main]` declarations) and "
              "apps/src/registry.rs (the registered CCID apps).")
        return 1
    if not task_roots:
        # Unreachable while the floor is derived (an empty task set is a
        # shortfall against any non-zero declared count); kept as the US-956
        # backstop so the gate can never fall through to `rows[0]`.
        print("FAIL: check_boot_chain (US-956) — no Embassy task poll root found")
        return 1
    comp_of, best = condensation(frames, edges)
    task_rows = sorted(
        ((longest_chain(comp_of, best, r), frames[r], r) for r in task_roots), reverse=True
    )
    # The gate cannot see the `blx rN` that connects a task to an app, so it
    # charges the deepest possible task frame on top of the app's own chain.
    task_own_max = max(f for _c, f, _r in task_rows)
    vtable_rows = sorted(
        (
            (longest_chain(comp_of, best, r) + task_own_max, frames[r], r)
            for r in vtable_roots
        ),
        reverse=True,
    )

    rows = sorted(task_rows + vtable_rows, reverse=True)
    top_chain, top_frame, top_root = rows[0]
    boot_chain = task_rows[0][0]
    limit = min(CHAIN_CEILING, zone)
    detail = ", ".join(f"{c} B" for c, _f, _r in rows[:6])
    arena_ok, arena_line = check_arena()

    if args.json:
        print(json.dumps({
            "stack_zone": zone,
            "chain_ceiling": CHAIN_CEILING,
            "limit": limit,
            "margin": limit - top_chain,
            # US-1010: `margin` above is against the BINDING limit
            # (`min(CHAIN_CEILING, zone)`). `zone_margin` is the other
            # quantity, which is the more comfortable number and is only the
            # enforced one while the zone is the smaller term. Both are
            # published so a JSON consumer cannot silently read the wrong one.
            "zone_margin": zone - top_chain,
            "binding": "chain_ceiling" if limit == CHAIN_CEILING else "stack_zone",
            "worst_chain": top_chain,
            "worst_frame": top_frame,
            "worst_root": top_root,
            "boot_chain": boot_chain,
            "task_own_frame_max": task_own_max,
            # US-961: the root counts are the measurement's own coverage
            # report. `task_root_count` must equal the number of `#[task]` /
            # `#[main]` tasks in firmware/src/main.rs's module tree, and
            # `app_process_root_count` must be at least the number of apps
            # apps/src/registry.rs registers — a shortfall is a hard FAIL
            # above, not a number for a reader to notice.
            "task_root_count": len(task_roots),
            "expected_task_root_count": stack_roots.declared_task_roots(),
            "vtable_root_count": len(vtable_roots),
            "app_process_root_count": sum(
                1 for s in vtable_roots if stack_roots.is_app_process_shim(s)
            ),
            "expected_registered_ccid_apps": stack_roots.registered_ccid_apps(),
            "blx_reg_sites": indirect,
            "arena_ok": arena_ok,
            "chains": [
                {
                    "chain": c,
                    "own_frame": f,
                    "root": r,
                    "class": "vtable" if stack_roots.is_app_shim(r) else "task",
                }
                for c, f, r in rows
            ],
        }, indent=2))

    failed = False
    if top_chain > limit:
        failed = True
        if not args.json:
            for c, f, r in rows[:6]:
                print(f"  {c:>8} B  (own frame {f} B)  {r[-56:]}")
        print(f"FAIL: check_boot_chain (US-957) — worst call chain {top_chain} B "
              f"exceeds the {limit} B limit")
        print(f"  - limit = min({CHAIN_CEILING} B chain ceiling, {zone} B main stack zone "
              f"read from _stack_start - _stack_end)")
        print(f"  - worst root: {top_root} (own frame {top_frame} B)")
        print("  - per-root chains: " + detail)
        print("  - see docs/size-report.md ('Main-stack demand') and "
              "docs/tasks/us956-ram-right-sizing.md")
    else:
        print(f"PASS: check_boot_chain (US-957) — worst call chain {top_chain} B <= "
              f"{limit} B (main stack zone {zone} B, {CHAIN_CEILING} B chain ceiling)")
        print(f"  - boot chain (task poll roots, `bl`/`blx <label>` edges only): "
              f"{boot_chain} B")
        print(f"  - request-serving chain (App vtable roots + the "
              f"{task_own_max} B task frame the invisible `blx rN` hides): "
              f"{top_chain} B")
        # US-1010: print the margin against the term that BINDS. `limit` is
        # `min(CHAIN_CEILING, zone)`, so `zone - top_chain` is not the margin
        # whenever the ceiling is the smaller term — which it is today. Both
        # are printed, and which one is binding is named, so a reader cannot
        # take the more comfortable number for the enforced one.
        binding = ("the chain ceiling" if limit == CHAIN_CEILING else "the main stack zone")
        print(f"  - margin against the binding limit ({binding}, {limit} B): "
              f"{limit - top_chain} B ({(limit - top_chain) / limit * 100:.1f} %)"
              + (f"; {zone - top_chain} B ({100.0 * (zone - top_chain) / zone:.1f} %) "
                 f"of the {zone} B zone" if limit != zone else ""))
        print("  - per-root chains: " + detail)
    if not args.json:
        # US-961: print what was actually measured, in the human-readable
        # output CI reads. A PASS that does not say how many roots it saw is
        # how the v0-mangling regression stayed invisible for 30 commits.
        print(f"  - roots measured: {len(task_roots)} Embassy task poll(s) "
              f"(floor {stack_roots.declared_task_roots()}, from the "
              f"`#[task]`/`#[main]` declarations in firmware/src/main.rs's module "
              f"tree) + {len(vtable_roots)} `dispatch::App` vtable shim(s), of "
              f"which "
              f"{sum(1 for s in vtable_roots if stack_roots.is_app_process_shim(s))} "
              f"are `App::process` (floor "
              f"{stack_roots.registered_ccid_apps()}, the apps "
              f"apps/src/registry.rs registers). A shortfall in any of these is a "
              f"FAIL, not a note.")
        print(f"  - {indirect} register-indirect `blx rN` call sites in the ELF: "
              f"not resolved into edges. The `App` vtable hop — the one on the "
              f"request-serving path — is covered by the surcharge above; every "
              f"other indirect target is still an uncharged blind spot.")
    if not arena_ok:
        failed = True
        print("FAIL: check_boot_chain (US-956) — task arena")
        print(arena_line)
    elif not args.json:
        print(arena_line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
