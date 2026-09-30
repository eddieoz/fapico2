#!/usr/bin/env python3
"""Gate: Embassy task-poll stack frames vs the RP2350 main stack (US-939, US-951).

Rebuilds the device ELF (default = device target) and measures, from the
disassembly, every Embassy `TaskStorage::<F>::poll` instantiation's frame
reservation (`push {…}` + `sub.w sp, sp, #N` + `sub sp, #N`). Under fat LTO
the `#[main]` future's `poll` is inlined into one of those instantiations —
`#[embassy_executor::main]` expands to `#[task] async fn __embassy_main`, and
the *state* of that future lives in a static `TaskPool` inside the 64 KiB
`.bss` task arena, but the async body's non-crossing locals live in the
**poll's stack frame**. The frame is therefore real stack usage: a frame that
does not fit faults on the first poll of the task, before `main` returns.

US-951 fix to this gate: it used to compare the frame against a hard-coded
24,576 B ceiling that was **larger than the entire stack the linker actually
leaves** (5,056 B at the US-951 tip) — a ceiling that could not fail, so a
3.6x overflow sat behind a green gate. The primary bound is now the *real*
stack zone, read from the ELF's `_stack_start` / `_stack_end` symbols
(`cortex-m-rt`'s `link.x`: `_stack_start = _ram_end`, `_stack_end = __sheap`
after `.uninit`). The 24 KiB absolute ceiling is kept as a secondary
regression guard for the US-939 fix.

US-961 fix to this gate: the task-poll matcher selected roots with rustc
*legacy* mangling (`TaskStorage$LT$F$GT$4poll`), which the current toolchain's
**v0** scheme does not emit — so only the `embassy_main_task` substring still
matched and `ccid_task`, `hid_task`, `usb_task`, `led_heartbeat_task` and
`button_poll_task` were not measured. The gate reported
`async-task frame 9208 B`, the `#[main]` poll, while `hid_task` alone reserves
**9,928 B** — the gate was reporting a frame 720 B smaller than one it should
have bounded, and the docstring's claim that it bounds "the MAX over these"
had quietly become false. Root selection and the completeness floor now live
in `tests/scripts/stack_roots.py` (shared with `check_boot_chain.py`, so the
two gates cannot measure different root sets), and a root set that does not
cover every `#[task]`/`#[main]` task in the device binary's module tree is a
**FAIL**, not a quiet PASS.

Note: the gate reads frame RESERVATIONS, not live usage, and it bounds the
per-poll frame only. US-951 additionally measured the worst-case *call-chain*
depth from the async-main poll at 117,828 B (poll 18,288 + `boot_fido` 15,744
+ `FidoApp::boot` 63,000 + `DeviceKeystore::persist` 19,440 + leaves) — the
chain, not the frame, is what the 5,056 B zone has to survive. See
`docs/size-report.md` ("Main-stack demand").
"""
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import stack_roots  # noqa: E402  (path is set above)

ROOT = pathlib.Path(__file__).resolve().parents[2]
ELF = ROOT / "target/thumbv8m.main-none-eabi/release/fapico2-firmware"
CEILING = 24 * 1024  # 24,576 B (story US-939: async-main frame <= 24 KiB)

# A task poll/closure frame reservation: `sub.w sp, sp, #N` (T32 wide) or
# `sub sp, #N` (T16 narrow) — objdump prints decimal immediates with an
# optional hex annotation comment.
SUB_SP = re.compile(r"\bsub\.[wbn]*\s*sp, sp, #(\d+)")
SUB_SP_NARROW = re.compile(r"\bsub\s+sp, #(\d+)")
PUSH = re.compile(r"\bpush\s+\{([^}]*)\}")
LABEL = re.compile(r"^[0-9a-f]+ <([^+]+)>:")

# US-961: task-poll selection moved to `stack_roots` (shared with
# `check_boot_chain.py`). The old `INTERESTING` tuple here matched rustc
# *legacy* mangling, which the v0 scheme the toolchain now emits does not
# produce — see the module docstring.


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
    """Usable main-stack bytes: `_stack_end` (low) .. `_stack_start` (high)."""
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
            print(f"FAIL: check_async_frame (US-951) — {sym} not in the ELF symbol table")
            sys.exit(1)
    return vals["_stack_start"] - vals["_stack_end"]


def measure_frames() -> dict:
    r = run(["arm-none-eabi-objdump", "-d", str(ELF)])
    if r.returncode != 0 or not r.stdout.strip():
        print("FAIL: arm-none-eabi-objdump unavailable: " + r.stderr)
        sys.exit(1)

    frames = {}
    sym = None
    for line in r.stdout.splitlines():
        m = LABEL.match(line)
        if m:
            sym = m.group(1)
            if not stack_roots.is_task_poll(sym):
                sym = None
            continue
        if sym is None:
            continue
        p = PUSH.search(line)
        if p:
            # callee-saved + lr spill; the low bits of the frame are pushed
            # before the `sub sp` reservation, so fold them in for a total.
            frames[sym] = max(frames.get(sym, 0), 4 * len([x for x in p.group(1).split(",") if x.strip()]))
            continue
        m = SUB_SP.search(line) or SUB_SP_NARROW.search(line)
        if m:
            frames[sym] = frames.get(sym, 0) + int(m.group(1))
    return frames


def main() -> int:
    build()
    zone = stack_zone()
    frames = measure_frames()
    # US-961: every task poll in the ELF must be a measured root. This gate
    # only bounds the per-poll frame, but an unmeasured task is still an
    # unmeasured stack consumer, and the previous matcher silently left four
    # of the six unmeasured while the gate printed PASS.
    want = stack_roots.declared_task_roots()
    if want is None:
        print("FAIL: check_async_frame (US-961) — could not derive the expected "
              "task-root count from firmware/src/main.rs's module tree; the "
              "coverage floor itself is gone, so a matcher that stops finding "
              "tasks would pass.")
        return 1
    if len(frames) != want:
        print(f"FAIL: check_async_frame (US-961) — task-root coverage: the ELF "
              f"yields {len(frames)} Embassy task-poll root(s) but the device "
              f"binary declares {want} `#[task]`/`#[main]` task(s). Either the "
              f"matcher has stopped seeing tasks it used to see (a rustc "
              f"mangling-scheme change is the usual cause) or a declared task is "
              f"not linked; either way the per-poll max below is being published "
              f"as if it covered them. Measured: "
              + ", ".join(sorted(s[-48:] for s in frames)))
        return 1
    if not frames:
        # Unreachable while the floor is derived (an empty set is a shortfall
        # against any non-zero declared count); kept as the US-939 backstop.
        print("FAIL: check_async_frame (US-939) — no async-task frame found")
        return 1
    frame = max(frames.values())
    top = max(frames, key=lambda k: frames[k])
    detail = ", ".join(f"{v} B" for v in sorted(frames.values(), reverse=True))

    limit = min(CEILING, zone)
    if frame > limit:
        print("FAIL: check_async_frame (US-951)")
        print(f"  - async-task frame {frame} B ({top[-24:]}) > limit {limit} B")
        print(f"  - limit = min(24 KiB absolute ceiling, {zone} B main stack zone "
              f"read from _stack_start - _stack_end)")
        print(f"  - per-task-poll frames: {detail}")
        if frame <= CEILING and frame > zone:
            print("  - the frame fits the 24 KiB ceiling but NOT the stack the linker "
                  "actually leaves: the whole zone is smaller than the ceiling, which "
                  "is why the US-939-only gate stayed green through a 3.6x overflow.")
        print("  - see docs/size-report.md ('Main-stack demand') and "
              "docs/tasks/us939-async-frame-fix.md")
        return 1
    print(f"PASS: check_async_frame (US-951) — async-task frame {frame} B <= {limit} B "
          f"(main stack zone {zone} B, 24 KiB absolute ceiling {CEILING} B)")
    print(f"  - per-task-poll frames: {detail}")
    print(f"  - roots measured: {len(frames)} of {want} declared tasks "
          f"(floor from firmware/src/main.rs's module tree); a shortfall is a "
          f"FAIL, not a note.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
