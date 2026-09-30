#!/usr/bin/env python3
"""Gate: the device heap is either absent or *exactly* the one sanctioned
static allocator — and nothing may allocate before it is live.

Replaces the `no-heap` CI grep (US-961).

Why the grep had to be replaced rather than waived
--------------------------------------------------
The original gate was a token grep for `#[global_allocator]` across
`firmware/ apps/ platform/`, written in US-383 when the device build was
heap-free. US-938 added the one sanctioned allocator
(`platform/src/rsa_heap.rs`, a 48 KiB `linked_list_allocator::LockedHeap`
backing the software-RSA backend) and the grep — which nothing had re-run
because CI had never run on this branch — went red. The two easy resolutions
were both wrong:

* delete the allocator — that discards the 48 KiB static heap US-956/US-957
  right-sized *from measurement*, and the software-RSA path
  (`rsa`/`num-bigint-dig`) allocates with infallible `Vec`, so it cannot
  simply be rewritten to be allocation-free;
* widen the grep to "allow any `#[global_allocator]`" — that throws away the
  only property the gate had, namely that a *second*, unsanctioned heap (or a
  `std` heap dragged into the `no_std` device build) is caught.

This gate keeps the teeth and states the exemption precisely:

1. **Exactly one global allocator in device source, and it is the sanctioned
   one.** Every `#[global_allocator]` in `firmware/ apps/ platform/` must be in
   `platform/src/rsa_heap.rs` and must attribute a `LockedHeap` over the
   fixed-size `RSA_HEAP` static. Any other hit fails; a *missing* sanctioned
   allocator also fails, because the heap is load-bearing and its silent
   deletion is a linker error the moment an RSA request allocates.
2. **The device firmware is still `#![no_std]`.**
3. **The heap is actually in the device image.** `rsa-backend` must be in
   `fapico2-platform`'s default feature set and the `firmware` crate must not
   opt out of it, so the cfg'd `rsa_heap` module cannot quietly vanish from the
   release image.
4. **The pre-boot allocation ordering invariant is enforced, not just
   commented** (US-961 — the reviewer's second finding). With a
   `#[global_allocator]` linked, allocation-capable code now *links* where it
   previously could not, and the load-bearing invariant is "nothing allocates
   before `crate::rsa_heap::init()` inside `DeviceBackend::boot`". Violating it
   is a `LockedHeap::empty()` -> `handle_alloc_error` -> `panic = "abort"`
   dark boot, indistinguishable on the bench from the stale-store hang. This
   gate proves, from source:
     * `rsa_heap::init()` has exactly one call site in the whole repo, and it
       is inside `DeviceBackend::boot`;
     * inside `DeviceBackend::boot`, the region *before* that call contains
       nothing but non-allocating `assert!`s, attributes and comments — so no
       constructor call (which is what could allocate) can creep above it;
     * `DeviceBackend::boot` has exactly one device-path call site
       (`firmware/src/main.rs`), so there is no second boot path that skips
       the init.

   What this does **not** cover, recorded rather than left ambiguous: the
   region of `async fn main` that runs *before* `DeviceBackend::boot` is not
   statically analysable here, and the runtime failure mode of a pre-init
   allocation is still an abort. See `docs/known-gate-divergences.md`.

Usage:
    python3 tests/scripts/check_heap_gate.py
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Device-relevant source trees (mirrors the US-383 grep).
SOURCE_DIRS = ("firmware", "apps", "platform")
EXEMPT_DIRS = ("tests", "benches", "examples")

SANCTIONED_ALLOCATOR = ROOT / "platform/src/rsa_heap.rs"
DEVICE_BACKEND = ROOT / "platform/src/trusted_backend/device.rs"
DEVICE_FIRMWARE = ROOT / "firmware/src/main.rs"
PLATFORM_CARGO = ROOT / "platform/Cargo.toml"
FIRMWARE_CARGO = ROOT / "firmware/Cargo.toml"

GLOBAL_ALLOCATOR = re.compile(r"#\[\s*global_allocator\s*\]")
LOCKED_HEAP = re.compile(r"static\s+\w+\s*:\s*LockedHeap\s*=\s*LockedHeap::empty\(\)")
# The static region the allocator hands out: fixed size, statically named.
FIXED_HEAP = re.compile(r"static\s+mut\s+RSA_HEAP\s*:\s*\[u8;\s*RSA_HEAP_SIZE\s*\]")
HEAP_INIT_CALL = re.compile(r"crate::rsa_heap::init\s*\(\s*\)")
HEAP_INIT_DEF = re.compile(r"pub\s+unsafe\s+fn\s+init\s*\(")

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
# String literals. The boot-path assertions quote the very symbol this gate
# greps for ("…DeviceBackend::boot() has not run yet"), so a call-site count
# taken over raw text counts panic *messages* as call sites.
_STRING = re.compile(r'r?#*"(?:\\.|[^"\\])*"#*', re.S)
# `assert!` / `assert_eq!` / `assert_ne!` — non-allocating on the success path
# (and, on the failure path, a `panic = "abort"` device: exactly the outcome we
# want if the once-only invariant is violated).
_ASSERT = re.compile(r"\bassert(?:_eq|_ne)?!\s*\(")
_ATTR = re.compile(r"#!?\s*\[[^\]]*\]", re.S)


def fail(msg: str) -> None:
    print(f"FAIL: check_heap_gate (US-961) — {msg}")


def rust_files():
    for d in SOURCE_DIRS:
        for path in sorted((ROOT / d).rglob("*.rs")):
            if any(part in EXEMPT_DIRS for part in path.parts):
                continue
            yield path


def strip_comments(text: str) -> str:
    """Blank out comments and string literals, preserving line structure so
    reports stay readable. Both matter: comments are where a deleted invariant
    is most often left behind as prose, and string literals are where a
    symbol's *name* is most often quoted."""
    def blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    text = _LINE_COMMENT.sub(blank, _BLOCK_COMMENT.sub(blank, text))
    return _STRING.sub(blank, text)


def check_single_sanctioned_allocator() -> list[str]:
    errs: list[str] = []
    hits: list[tuple[pathlib.Path, int]] = []
    for path in rust_files():
        for n, line in enumerate(strip_comments(path.read_text(encoding="utf-8")).splitlines(), 1):
            if GLOBAL_ALLOCATOR.search(line):
                hits.append((path, n))
    if not hits:
        errs.append(
            "no `#[global_allocator]` in device source — but the sanctioned one "
            f"({SANCTIONED_ALLOCATOR.relative_to(ROOT)}) must still be there. The "
            "48 KiB static RSA heap is load-bearing: `rsa`/`num-bigint-dig` "
            "allocate with infallible `Vec`, so deleting the allocator turns "
            "every software-RSA request into a link error or a runtime abort. "
            "If the heap is genuinely gone, delete US-938's software-RSA backend "
            "with it — do not leave the gate green over a missing heap."
        )
        return errs
    for path, n in hits:
        rel = path.relative_to(ROOT)
        if path != SANCTIONED_ALLOCATOR:
            errs.append(
                f"unsanctioned `#[global_allocator]` at {rel}:{n}. Device code "
                "must be heap-free (static / fixed-size buffers) except for the "
                f"one sanctioned allocator in {SANCTIONED_ALLOCATOR.relative_to(ROOT)}. "
                "A second heap is an unreviewed RAM claim."
            )
    if len(hits) > 1:
        errs.append(
            f"{len(hits)} `#[global_allocator]` declarations in device source; "
            "exactly one is sanctioned."
        )
    body = strip_comments(SANCTIONED_ALLOCATOR.read_text(encoding="utf-8"))
    if not LOCKED_HEAP.search(body):
        errs.append(
            f"{SANCTIONED_ALLOCATOR.relative_to(ROOT)}: the sanctioned allocator "
            "must be a `linked_list_allocator::LockedHeap::empty()` (the only "
            "allocator whose `init` the `rsa_heap` pre-boot invariant is written "
            "against)."
        )
    if not FIXED_HEAP.search(body):
        errs.append(
            f"{SANCTIONED_ALLOCATOR.relative_to(ROOT)}: the sanctioned allocator "
            "must hand out the fixed-size `RSA_HEAP` static, not a growable or "
            "externally-supplied region (the 48 KiB budget is the RAM claim the "
            "whole static-sizing exercise rests on)."
        )
    return errs


def check_no_std() -> list[str]:
    text = DEVICE_FIRMWARE.read_text(encoding="utf-8")
    if "#![no_std]" not in text:
        return [
            "firmware/src/main.rs must be `#![no_std]` — a std heap in the "
            "device build defeats the whole gate."
        ]
    return []


def check_heap_is_in_the_device_image() -> list[str]:
    """`rsa-backend` must survive into the release image.

    `platform/src/lib.rs` gates the whole heap module on
    `all(feature = "rsa-backend", target_arch = "arm")`. If the feature were
    dropped, every check above would still pass on a device image with no
    heap at all — the "exact one sanctioned allocator" reading would be true of
    the *source* and false of the *binary*.
    """
    errs: list[str] = []
    platform = PLATFORM_CARGO.read_text(encoding="utf-8")
    m = re.search(r"^default\s*=\s*\[(.*?)\]", platform, re.M | re.S)
    if not m:
        return ["platform/Cargo.toml: could not read the `default` feature list."]
    if '"rsa-backend"' not in m.group(1):
        errs.append(
            'platform/Cargo.toml: "rsa-backend" is no longer in the default '
            "feature set, so `platform::rsa_heap` is cfg'd out of the device "
            "image and the sanctioned allocator does not exist on the part."
        )
    firmware = FIRMWARE_CARGO.read_text(encoding="utf-8")
    for line in firmware.splitlines():
        if "fapico2-platform" in line and "default-features" in line:
            errs.append(
                f"firmware/Cargo.toml: `{line.strip()}` opts the platform crate "
                "out of its default features, which drops the `rsa-backend` "
                "feature (and the heap) from the device image."
            )
    return errs


def _function_body(text: str, header: str) -> tuple[str, str] | None:
    """(body, tail-after-body) for the first `header` in `text`, brace-matched."""
    i = text.find(header)
    if i < 0:
        return None
    j = text.find("{", i + len(header) - 1)
    if j < 0:
        return None
    depth = 0
    for k in range(j, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return text[j + 1:k], text[k + 1:]
    return None


def check_preboot_allocation_invariant() -> list[str]:
    """Nothing may allocate before `rsa_heap::init()` goes live.

    Three structural facts, all checked from source:
      (a) `rsa_heap::init()` has exactly one call site, inside
          `DeviceBackend::boot` — so there is no second, un-initing path;
      (b) the region of `DeviceBackend::boot` before that call holds nothing
          but non-allocating `assert!`s, attributes and comments;
      (c) `DeviceBackend::boot` itself has exactly one device-path call site.
    """
    errs: list[str] = []

    # (a) one call site, in DeviceBackend::boot.
    call_sites: list[str] = []
    for path in rust_files():
        for n, line in enumerate(strip_comments(path.read_text(encoding="utf-8")).splitlines(), 1):
            if HEAP_INIT_CALL.search(line):
                call_sites.append(f"{path.relative_to(ROOT)}:{n}")
    body = strip_comments(DEVICE_BACKEND.read_text(encoding="utf-8"))
    found = _function_body(body, "pub unsafe fn boot(")
    if found is None:
        return [
            "platform/src/trusted_backend/device.rs: `DeviceBackend::boot` not "
            "found — the pre-boot allocation invariant is anchored to that "
            "function, so it cannot be checked. Treat this as a FAIL, not as "
            "'nothing to check'."
        ]
    boot_body, _tail = found
    if not HEAP_INIT_CALL.search(boot_body):
        errs.append(
            "platform/src/trusted_backend/device.rs: `DeviceBackend::boot` no "
            "longer calls `crate::rsa_heap::init()`. The software-RSA backend "
            "allocates, so the first RSA request would hit an empty "
            "`LockedHeap` — a dark boot."
        )
    if len(call_sites) != 1:
        errs.append(
            f"`rsa_heap::init()` is called from {len(call_sites)} site(s) "
            f"({', '.join(call_sites) or 'none'}). It must have exactly one, "
            "inside `DeviceBackend::boot`: a second caller can initialise the "
            "heap late, or a caller can reach allocation first."
        )

    # (b) nothing but assertions before the init call.
    idx = boot_body.find("crate::rsa_heap::init()")
    if idx >= 0:
        pre = boot_body[:idx]
        pre = _BLOCK_COMMENT.sub(" ", _LINE_COMMENT.sub(" ", pre))
        pre = _ATTR.sub(" ", pre)
        # Drop every `assert*!( ... );` invocation, brace/paren matched.
        while True:
            m = _ASSERT.search(pre)
            if not m:
                break
            depth, end = 0, -1
            for k in range(m.end() - 1, len(pre)):
                if pre[k] == "(":
                    depth += 1
                elif pre[k] == ")":
                    depth -= 1
                    if depth == 0:
                        end = k
                        break
            if end < 0:
                break
            pre = pre[: m.start()] + " " + pre[end + 1:]
        offenders = [ln.strip() for ln in pre.splitlines() if ln.strip() and ln.strip() != ";"]
        if offenders:
            errs.append(
                "`DeviceBackend::boot` runs code before `rsa_heap::init()`: "
                + "; ".join(offenders[:4])
                + ". Any call there can allocate, and an allocation before the "
                "heap is live is a `LockedHeap::empty()` abort — a dark boot. "
                "Only non-allocating assertions may precede the init call."
            )

    # (c) one device-path call site for `DeviceBackend::boot`.
    dev_calls = [
        f"{p.relative_to(ROOT)}:{n}"
        for p in rust_files()
        for n, line in enumerate(strip_comments(p.read_text(encoding="utf-8")).splitlines(), 1)
        if re.search(r"DeviceBackend::boot\s*\(", line)
    ]
    if len(dev_calls) != 1:
        errs.append(
            f"`DeviceBackend::boot` has {len(dev_calls)} call site(s) "
            f"({', '.join(dev_calls)}). It must have exactly one, on the device "
            "boot path, so there is no route to a mounted client that skipped "
            "`rsa_heap::init()`."
        )
    return errs


def main() -> int:
    checks = (
        ("sanctioned heap", check_single_sanctioned_allocator),
        ("no_std device firmware", check_no_std),
        ("heap in the device image", check_heap_is_in_the_device_image),
        ("pre-boot allocation invariant", check_preboot_allocation_invariant),
    )
    failures: list[str] = []
    for name, fn in checks:
        errs = fn()
        if errs:
            failures.extend(errs)
            print(f"FAIL: check_heap_gate (US-961) — {name}")
            for e in errs:
                print(f"  - {e}")
        else:
            print(f"ok: check_heap_gate — {name}")
    if failures:
        return 1
    print("ok: exactly one sanctioned global allocator "
          f"({SANCTIONED_ALLOCATOR.relative_to(ROOT)}), #![no_std] device "
          "firmware, and nothing allocates before it is live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
