#!/usr/bin/env python3
"""One-randomness-path name gate for RS-KEY-ADOPT Phase 1 (US-1005).

Host-only, stdlib only (no third-party imports). TDD red/green script for the
"every nonce comes from the DRBG" invariant (the EPIC's Phase 1 outcome):

    the code that turns a *peripheral draw* into a *nonce* lives ONCE, in
    ``platform/src/trng.rs`` (the ``DrbgTrng`` type) and ONCE in
    ``platform/src/drbg_seed.rs`` (the fresh-draw half of ``SeedMaterial``).
    A transport may not reach past them and call the RP2350 TRNG driver
    directly.

Why a name gate at all
----------------------
US-1005's change is visible in a diff exactly once: the ``EmbTrng::new``
construction sites in ``firmware/src/main.rs`` (plus two in
``firmware/src/bin/``) stop calling ``embassy_rp::trng::Trng::blocking_fill_bytes``
and start taking their bytes from the DRBG, and the *app boot helpers* start
being handed the DRBG instead of the peripheral handle. A later session that
"just needs a nonce" will reach for ``Rp2350Trng`` again, because it still
compiles, it is still ``#[inline]`` away from a working driver, and nothing
in the type system stops it. This gate is that stop.

The flags below are every way the tree reaches a raw peripheral draw, names a
peripheral-handle *type*, reaches randomness through a seam that cannot
report a refusal, or builds a generator without a validated seed.

``blocking_fill_bytes``
    The unbounded, self-retrying wait (US-1001's whole subject). Naming it
    outside ``platform/src/trng.rs`` means a caller is one unbounded wait away
    from a hang it cannot report — and after US-1005 that is no longer a
    latent hazard, it is a live one on *every* nonce (see
    ``known-gate-divergences.md``).

``EmbTrng::new`` / ``trng::Trng::new``
    The construction of the ``embassy-rp`` driver. A site that calls it is a
    site that has a peripheral handle, and therefore a site that can draw from
    it — the flag is the *earliest* point at which a bypass is visible, long
    before a ``blocking_fill_bytes`` shows up in the same file.

``Rp2350Trng::from_peri`` / ``Rp2350Trng::new``
    The *platform's own* constructors (US-1005 moved driver construction
    behind them so this tree would stop naming ``embassy_rp`` directly).
    Flagged because the doc on ``from_peri`` argues the driver is
    "unreachable to a caller except through here" — true of the *driver*, and
    not of the *public constructor*. A caller that reaches for
    ``Rp2350Trng::from_peri`` has a working, unbounded-peripheral TRNG in
    hand, and the first two patterns would never see it. This was confirmed by
    mutation: adding a function that calls ``from_peri`` in
    ``firmware/src/main.rs`` left the pre-fix gate **green**.

``Rp2350Trng`` in a *type* position (``Rp2350Trng type``)
    The gap the final review found, and the one this flag exists for.
    ``fill_rng_pool<R: Trng>`` is generic, so a boot helper may be written
    against *any* ``Trng`` impl, and the two patterns above only ever see a
    **construction** — never a **use**. A helper whose signature pins
    ``trng: &mut Rp2350Trng<'static>`` holds a peripheral handle with no
    ``from_peri`` anywhere near it, so every other flag scored it green.
    That is not hypothetical: it is exactly the ``boot_oath`` defect this
    gate now catches (24 unbounded ``blocking_wait_for_successful_generation``
    waits per boot, and an OATH nonce that bypasses the conditioned
    generator), and the FIDO sibling of the same call was routed in the same
    commit, so the diff looked clean.

    The pattern is the bare type name with a negative lookahead for ``::``,
    so a legitimate ``Rp2350Trng::from_peri`` construction is *not* matched —
    that stays the earlier flag's business, and the two never double-count.

``boot_* fed the raw handle`` (``boot_\w+\(\s*&mut trng\b``)
    The same defect reached the other way round: no type is named, but the
    positional argument hands a boot-path app constructor the boot-path
    peripheral handle. A generic ``boot_x`` would compile with it, so the
    type-position flag cannot see it. Together the two flags cover both
    shapes of the mistake — pin the type, or pass the value — and either one
    alone would be a gate with a hole the width of the other.

    What neither flag can see, stated rather than implied: a caller that
    aliases the handle into a differently-named binding first
    (``let boot: &mut _ = &mut trng;``) defeats a name gate. That is a
    deliberate obfuscation rather than the natural shape of the mistake, and
    the fix for it is a type-level one (a distinct boot-path TRNG type whose
    only ``Trng`` impl is the bounded one), which is US-1013's territory and
    deliberately not grown here.

``Drbg::new`` / ``Drbg::new_device``
    The unvalidated constructors. ``Drbg::new`` is ``pub(crate)``, so within
    the platform only its own unit tests can reach it — but ``Drbg::new_device``
    is fully ``pub``, and a firmware call site passing a *constant* there
    produces a perfectly well-formed generator with no entropy in it, which
    is the one failure mode the whole epic exists to prevent and which no
    other flag on this list can see: it is a legitimate type, a legitimate
    constructor, and a completely wrong value. The device path is required to
    use ``Drbg::seed_from_device`` (via ``DrbgTrng::try_new``), which is the
    only constructor that can refuse.

    This flag is what makes the two "``check_rng_path.py`` enforces the
    device path uses ``seed_from_device``" claims in
    ``platform/src/drbg.rs`` and ``docs/tasks/rskey-adopt-context.md`` true
    rather than documentary. Before it landed, both sentences described a rule
    no pattern enforced.

``.random_bytes(``
    The platform ``Trng`` trait's infallible method, and — through
    ``crypto::TrngAdapter`` — the sharp end of ``rand_core::RngCore``
    ``fill_bytes``: on a starved generator it leaves the caller's buffer
    untouched, so ``p256::SecretKey::random`` would hand the FIDO boot path
    an all-zero persistent ``hkey`` with no error anywhere. Flagging every
    call site turns that from a silent footgun into a declared one: a caller
    has to be allowlisted, with a reason, to reach an infallible draw.
    (Two families of false positive are allowlisted for exactly this reason
    and say so in their own entries: the *trussed service* ``random_bytes``
    syscall is a different API entirely, and the platform trait method is
    legitimately called on non-device hosts.)

``entropy_starve`` — the US-1007 seam, and a DIFFERENT KIND OF INVARIANT
-----------------------------------------------------------------------

Every flag above is a *name* rule: they say which call sites may exist.
The seam needs a *reachability* rule as well, and it is enforced as a
second, separate check (``check_seam_cfg``) rather than as another name.

``platform/src/entropy_starve.rs`` is a control file whose existence makes
the host entropy path refuse every draw. It exists so US-1007's "starve,
observe, recover on a running device" sequence is expressible on a host at
all. A hook that can wedge randomness is a denial of service if it can
reach a shipping build, so two things are enforced:

1. **No undeclared reference.** Three flags — the module path, the
   ``starved()`` accessor, and the ``FAPICO2_ENTROPY_STARVE_FILE`` env var
   — each per-flag count-capped in the single file that may name it.
2. **The ``cfg`` is intact.** The seam module is declared under
   ``#[cfg(all(feature = "emulation", not(target_arch = "arm")))]``, and
   ``check_seam_cfg`` walks back from the ``mod`` line and requires that
   exact attribute to be the last thing governing it.

(2) is the one that matters, and the name flags cannot substitute for it:
deleting the ``#[cfg]`` leaves every seam name exactly where it was and
still compiles, because the module is ``pub`` and everything it depends on
is unconditional. That edit alone is what would put a wedge into shipping
firmware, so it is checked as a property of the file rather than inferred
from a count. Proven to bite: hoisting the ``mod`` line out from under the
``cfg`` turns this gate red — see the report for the transcript.

Per-flag, count-capped allowlisting
-----------------------------------

An allowlist entry names **which flags** it excuses and **how many times**,
not merely which file. Both halves are load-bearing:

* *Per-flag* — a file-wide entry would let a new ``Rp2350Trng::from_peri``
  ride in on an allowlist that exists for ``.random_bytes(``.
* *Per-count* — ``firmware/src/main.rs`` legitimately builds two
  ``Rp2350Trng::from_peri`` handles, so a *bare* file+flag entry cannot catch
  a third one added beside them. The review's own bypass — a function
  appended to ``main.rs`` that calls ``from_peri`` — is exactly that case, and
  against a file+flag allowlist it still scored green. The count is what turns
  it red, and it is robust to line movement, which an exact-line allowlist
  would not be.

Every entry is ``(path tail, {flag: max occurrences}, reason)`` and every one
of them prints on every run, **whether or not it currently has a hit**: an
allowlist entry that can exist without ever being surfaced is how a gate rots.
A flag not named in an entry's counts is not excused at all in that file.

Comment-aware (mandatory, same lexer discipline as ``check_persist_gate.py``):
Rust line comments (``//``, ``///``, ``//!``) and block comments (``/* */``,
nestable) are stripped BEFORE matching, and the lexer PRESERVES LINE NUMBERS
so a report points at the right line. Doc comments in ``firmware/src/main.rs``
and ``firmware/src/boot.rs`` name ``blocking_fill_bytes`` while explaining the
design; a comment-only mention is legal, a code-level occurrence is not.

String-literal caveat (documented limitation, identical to
``check_persist_gate.py``): ordinary string literals (``"..."`` with ``\\``
escapes) are tracked so a ``//`` inside a URL is not mistaken for a comment,
and the string *body* is dropped so a name inside a literal is not treated as
code. Raw string literals (``r#"..."#``) and char literals are not modelled;
no ``.rs`` file in this tree uses them, so PASS/FAIL behaviour is unaffected.

Exit status: 0 when no code-level occurrence is found (green), 1 otherwise
(red, with a per-file report). Same output shape as ``check_persist_gate.py``.

Usage:
    python3 tests/scripts/check_rng_path.py [scan-root-dir]

``scan-root-dir`` defaults to the repository root (the parent of the
``tests/`` directory). The ``.git``/``target``/venv cruft dirs are skipped.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# tests/scripts/check_rng_path.py -> parents[2] == fapico2/
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT

# The ways this tree reaches a raw peripheral draw, or reaches randomness
# through a seam that cannot report a refusal. Each is a separate *named*
# pattern rather than one alternation, because the report line names which one
# tripped, the allowlist names which flag each entry excuses, and a maintainer
# needs to know *which* invariant was broken.
#
# `blocking_fill_bytes`  the unbounded, self-retrying wait (US-1001's subject).
# `EmbTrng::new`         construction of the `embassy-rp` driver, under the
#                        alias `firmware/src/main.rs` imports it as. A gate
#                        matching only the qualified path would score this tree
#                        green while the bypass is present.
# `trng::Trng::new`      the qualified spelling of the same thing.
# `Rp2350Trng::from_peri`
# `Rp2350Trng::new`      the platform's own public constructors. The
#                        `(?<![A-Za-z0-9_])` lookbehind on the pattern above
#                        deliberately does *not* straddle the `0` of
#                        `Rp2350`, which is what keeps `Rp2350Trng::new` out
#                        of that pattern — and is exactly why the two need
#                        patterns of their own.
# `.random_bytes(`       the platform `Trng` trait's infallible method, and
#                        through `crypto::TrngAdapter` the `RngCore`
#                        `fill_bytes` sharp end described in the module doc.
# `Rp2350Trng` in a TYPE position — the bare name not followed by `::`. The
#                        negative lookahead is what keeps this disjoint from
#                        the two constructor flags above: a legitimate
#                        `Rp2350Trng::from_peri` is construction, not use, and
#                        counting it twice would make the two caps mean
#                        different things in the same file.
# `boot_x fed raw`       a boot-path helper handed the boot-path peripheral
#                        handle positionally: `\bboot_\w+\(\s*&mut trng\b`.
#                        The mirror of the flag above — this one sees a
#                        mistake that pins no type, and that one sees a
#                        mistake that names no value.
# `Drbg::new`            the unvalidated DRBG constructors. `Drbg::new` is
# `Drbg::new_device`     `pub(crate)`; `Drbg::new_device` is `pub`, and a
#                        firmware caller passing a constant to that builds a
#                        working generator with no entropy in it.
# `entropy_starve` *     the US-1007 starvation-injection seam. A hook that
#                        can make the device's randomness refuse is a denial
#                        of service if it can reach a shipping build, so
#                        "it must not exist in production" is a claim this
#                        gate has to ENFORCE rather than one a doc comment
#                        makes. Three names, because the seam is reachable by
#                        three routes and a gate watching one has a hole the
#                        width of the other two: the module path, the
#                        accessor, and the env var naming the control file.
RNG_PATTERNS = (
    ("blocking_fill_bytes", re.compile(r"\bblocking_fill_bytes\b")),
    ("EmbTrng::new", re.compile(r"\bEmbTrng::new\b")),
    ("trng::Trng::new", re.compile(r"(?<![A-Za-z0-9_])Trng::new\b")),
    ("Rp2350Trng::from_peri", re.compile(r"\bRp2350Trng::from_peri\b")),
    ("Rp2350Trng::new", re.compile(r"\bRp2350Trng::new\b")),
    (
        "Rp2350Trng type",
        # `Rp2350Trng` as a bare type name, i.e. NOT `Rp2350Trng::…`.
        re.compile(r"(?<![A-Za-z0-9_])Rp2350Trng\b(?!\s*::)"),
    ),
    (
        "boot helper fed raw",
        re.compile(r"\bboot_\w+\(\s*&mut\s+trng\b"),
    ),
    ("Drbg::new_device", re.compile(r"(?<![A-Za-z0-9_])Drbg::new_device\b")),
    ("Drbg::new", re.compile(r"(?<![A-Za-z0-9_])Drbg::new\b(?!_)")),
    ("Trng::random_bytes", re.compile(r"\.random_bytes\(")),
    # The seam is nameable three ways; all three are watched, because a
    # gate that watches one of them has a hole the width of the other two.
    ("entropy_starve module", re.compile(r"\bentropy_starve\b")),
    ("entropy_starve accessor", re.compile(r"\bstarved\s*\(\s*\)")),
    # The env var is matched by its Rust CONSTANT name as well as the
    # literal. The literal alone is nearly useless here: this gate's lexer
    # drops string bodies (a `//` inside a URL must not read as a comment),
    # so a second `env::var("FAPICO2_ENTROPY_STARVE_FILE")` elsewhere would
    # leave no code-level trace. Naming the constant catches a second
    # *reader*, which is the reachable mistake.
    ("entropy_starve env var",
     re.compile(r"\bFAPICO2_ENTROPY_STARVE_FILE\b|\bSTARVE_FILE_ENV\b")),
)

# The seam's module declaration and the EXACT cfg attribute that must
# immediately govern it in `platform/src/lib.rs`.
#
# Two independent conditions, both required:
#
#   feature = "emulation"      the platform crate's own `emulation` feature,
#                               which only `fapico2-firmware`'s `emulation`
#                               feature turns on and which the device build
#                               (`--features device`, thumbv8m.main-none-eabi)
#                               does not; and
#   not(target_arch = "arm")   belt and braces, and the same guard every
#                               other host-only seam in this crate carries
#                               (`HostTrng`, `trusted_backend::host`).
#
# This is a SEPARATE, STRUCTURAL check and it is the one that matters. The
# name flags above are necessary but not sufficient: deleting the `#[cfg]`
# line leaves every seam name in place and still compiles, because the
# module is `pub` and everything it depends on is unconditional. Hoisting
# the `mod` line out from under the `cfg` is the only edit that could put
# the seam into a device build, and this check is what makes it go red.
SEAM_MOD_FILE = ("platform", "src", "lib.rs")
SEAM_MOD_DECL = "pub mod entropy_starve;"
SEAM_REQUIRED_CFG = '#[cfg(all(feature = "emulation", not(target_arch = "arm")))]'

# Directories that never hold hand-written Rust source.
SKIP_DIRS = {".git", "target", ".test-venv", ".serena", "node_modules", ".cargo"}

# The ONLY (file, flag) pairs where a peripheral draw or an infallible
# randomness call may be named, each with the reason it is there.
#
# Each entry is (path tail tuple, flags excused, reason). Two rules make this
# table hold up:
#
# * **Per-flag, not per-file.** A file-wide entry would let a new
#   `Rp2350Trng::from_peri` ride in on an allowlist that exists for
#   `.random_bytes(`, which is the false green this gate was extended to
#   close.
# * **A reason is not decoration.** It is the answer to "why is this not the
#   defect the gate exists to catch", and a future session that cannot restate
#   it should delete the entry and fix the code instead. Every entry prints on
#   every run, hit or no hit.
#
# Within a file the two `.random_bytes(` sites are told apart by their reasons
# rather than by line numbers (which rot on any edit above them): one is a
# bootstrap draw, one is inside a CCID request.
_ALLOWED = (
    (
        ("platform", "src", "trng.rs"),
        {
            "blocking_fill_bytes": 1,   # the `Trng` impl's one call
            "trng::Trng::new": 1,       # inside `from_peri`
            # US-1007 defect fix: 1 -> 3. Two of the three are the FALLIBLE
            # half delegating to the infallible one, which is the point of
            # the split rather than an exception to it:
            #   (1) `Trng::try_random_bytes`'s DEFAULT body, which delegates
            #       so a `Trng` that genuinely cannot fail (Rp2350's bounded
            #       peripheral wait) needs no code;
            #   (2) `HostTrng::try_random_bytes`, which screens the seam and
            #       then defers to the infallible draw for the real bytes;
            #   (3) the host free function `random_bytes_into`.
            # All three are the *reporting* path calling through, never a
            # caller bypassing it. A FOURTH would be a new consumer
            # reaching randomness the fallible way around them.
            "Trng::random_bytes": 3,
            "Rp2350Trng type": 4,       # the struct, its two inherent/trait
                                        # impl headers, and the `pub use`
            # US-1007: both seam names on ONE site — the consult, now behind
            # the `host_starved()` helper that `HostTrng`'s infallible AND
            # fallible draws share, so the two cannot disagree about whether
            # the peripheral is producing. The consult returns WITHOUT
            # writing, the same choice `DrbgTrng::random_bytes` makes on a
            # starved generator, and for the same reason: a filled buffer
            # that is not fresh entropy is a predictable value a caller
            # cannot tell from a real one. One occurrence of each is the cap
            # that matters — a second consult in this file is a second way to
            # wedge the infallible half. The helper re-states the seam's
            # `cfg`, so a device build does not even resolve the name.
            "entropy_starve module": 1,
            "entropy_starve accessor": 1,
        },
        "the one implementation: Rp2350Trng wraps the embassy-rp driver, "
        "Rp2350Probe is the bounded device probe, and DrbgTrng is the one "
        "consumer the gate routes everything else through. Every flag is "
        "excused here, once each, because this file is the definition of all "
        "of them — a second occurrence of any one is a duplicate definition, "
        "not a second caller, and the gate should say so. The FOUR type "
        "mentions are the definition itself (struct, `impl`, `impl Trng for`) "
        "plus the re-export; naming a type you are defining is not a use of "
        "it, and a fifth would be a second type wearing the same name.",
    ),
    (
        ("platform", "src", "drbg.rs"),
        {"Drbg::new": 6},
        "the six are all inside `#[cfg(test)] mod tests` (the KATs and the "
        "re-seed-interval clamp tests) and exercise `pub(crate)` "
        "instantiation with NIST's published vectors, which is the only way "
        "to run the standard's known-answer traces at all — they have no "
        "entropy source to draw from, which is the entire point of a KAT. "
        "NOT shipped code, and NOT reachable from `Drbg::new_device`, which "
        "the separate flag covers: the hazard this file has to avoid is a "
        "*shipped* caller reaching the unvalidated constructors, and a unit "
        "test that deliberately pins a constant is the opposite of that.",
    ),
    (
        ("platform", "tests", "drbg_reseed_policy.rs"),
        {"Drbg::new_device": 1},
        "host test target. The one legitimate caller of the public "
        "unvalidated constructor, and it is a test: what it pins is that "
        "`new_device` applies NO reseed interval of its own and defers to "
        "whatever the policy layer built — which is only observable by "
        "reading `RESEED_INTERVAL` back off a generator built without one. "
        "A firmware call site here is the defect the flag is for, and this "
        "entry is scoped to the test target so it cannot shelter one.",
    ),
    (
        ("firmware", "src", "main.rs"),
        {
            # US-1005: 2 -> 1. The second construction was the MIG_TRNG
            # migration-nonce handle, and it was the last unbounded
            # `blocking_fill_bytes` on a REQUEST path (D-10). The migration
            # nonce now comes from a bounded `Rp2350Probe::probe_bytes`, so
            # this file constructs exactly ONE unbounded driver handle — the
            # one the boot-entropy record and the firmware manifest are drawn
            # through, which a DRBG cannot seed. A second here is a new
            # bypass, not a new legitimate caller.
            "Rp2350Trng::from_peri": 1,
            "Rp2350Trng type": 1,
            "Trng::random_bytes": 2,
        },
        "bootstrap, pre-task, and COUNTED. ONE from_peri site and ONE bare "
        "type name (the `use` that brings the type into scope). A second of "
        "either in this file is a new bypass, not a new legitimate caller.\n"
        "  from_peri (1): this one now exists for its SIDE EFFECT and has no "
        "user. `Trng::new` is `initialize_rng`, which writes `RNG_IMR` / "
        "`TRNG_CONFIG` / `SAMPLE_CNT1` / `RND_DIAG` — the health-test "
        "configuration `Rp2350Probe` deliberately does not re-derive — and it "
        "consumes the `Peri` ownership token. The `cfg_attr` on the binding "
        "says so in as many words, and the two remaining `random_bytes` calls "
        "are both behind a feature a shipping build cannot enable. It is kept "
        "because the ordering of this constructor relative to the probe "
        "construction is load-bearing history (US-1005), not because anything "
        "draws through it any more. The migration-completion nonce used to be "
        "the second user (D-10 closed), then the boot-entropy draw, and the "
        "handle is now empty — which is what this cap is for: restoring "
        "either use puts a second `from_peri` in this file and the gate goes "
        "red on its own.\n"
        "  type (1): the import. ZERO type mentions in a signature or a body "
        "is the cap that matters — `boot_fido` and `boot_oath` are both "
        "generic over `Trng` and both are called with `&mut *drbg`. This "
        "cap is what the review's OATH finding needed and did not have: "
        "before it, `fn boot_oath(trng: &mut Rp2350Trng<'static>, …)` was "
        "invisible to every flag here, because none of them look at a type "
        "*use*, only at construction. Reverting the OATH routing puts that "
        "signature back and the gate goes red on the second type mention.\n"
        "  random_bytes (2): both are per-boot diagnostic channels — the "
        "dbg-log RTT channel, which no release build can enable (the "
        "compile_error! in lib.rs refuses it), and the apdu-trace session "
        "tag, which is release-ALLOWED but carries debug trace data only "
        "and is inert without the `apdu-trace` feature. The boot sanity "
        "draw used to be the third; it is now a bounded `probe_bytes` on "
        "`Rp2350Probe`, so it is no longer an unbounded wait and no longer "
        "belongs on this list.",
    ),
    (
        ("firmware", "src", "boot.rs"),
        # US-1005 took this 2 -> 1, and it is now **0**. The last site was
        # `ensure_boot_entropy` drawing the boot.entropy.v1 record through
        # the unbounded `Rp2350Trng`; it goes through the bounded
        # `TrngProbe` now (see `boot::ensure_boot_entropy` for why that
        # mattered), so this file contains no infallible draw at all.
        #
        # A cap of 0 is deliberate, not an oversight. Every occurrence of
        # this flag in this file is a defect: `Trng::random_bytes` cannot
        # report a refusal, so a site using it is a site that has already
        # given up the ability to stop. The flag is still declared, at zero,
        # rather than dropped — a dropped flag would leave a future draw as
        # a bare FAIL with no explanation, where a zero cap says "this file
        # is expected to have none" and points here.
        {"Trng::random_bytes": 0},
        "ZERO random_bytes sites, and the cap is zero on purpose. This file "
        "is the device boot path, and `Trng::random_bytes` is the method that "
        "cannot say \"I produced nothing\" — the one a caller reaches once it "
        "has handed itself an unbounded peripheral wait.\n"
        "  The count was 2 until D-10 closed the migration nonce, then 1 "
        "until the boot-entropy draw moved to the bounded probe. Both were "
        "real unbounded waits on paths that run before USB enumerates. What "
        "is worth recording about the last one is WHEN it was reached: the "
        "boot.entropy.v1 slot is absent only after US-919 has wiped the "
        "store — the first boot after a reflash of a different image — and "
        "`embassy-rp` answers a peripheral in that state by soft-resetting "
        "and retrying forever (`while !success`, `trng.rs:220-243`). A boot "
        "that can only wedge on that one boot, and that a power cycle "
        "clears, is a signature no amount of reading the flash layout "
        "produces.\n"
        "  Zero is the cap that catches putting any of it back, whatever it "
        "is called: the count, not a name.\n"
        "  The `Rp2350Trng` type mention used to be the `MigrationTrng` alias "
        "for that slot. There is no cap for it any more because the alias is "
        "gone with the handle — a peripheral-driver type named in this file at "
        "all is now undeclared, and therefore a gate failure. The migration "
        "nonce is drawn through a bounded `Rp2350Probe`; see "
        "known-gate-divergences.md D-10.",
    ),
    (
        ("firmware", "src", "bin", "bringup.rs"),
        {
            "EmbTrng::new": 1,
            "Rp2350Trng::new": 1,
            "Rp2350Trng type": 1,
            "Trng::random_bytes": 1,
        },
        "hardware bring-up binary: stages peripherals one at a time and runs "
        "before the secure store exists, so there is no seed record for a DRBG "
        "to be built from. Not a request path. The one type mention is the "
        "`use`; the construction is the `Rp2350Trng::new` flag's business.",
    ),
    (
        ("firmware", "src", "bin", "bridge.rs"),
        {
            "EmbTrng::new": 1,
            "Rp2350Trng::new": 1,
            "Rp2350Trng type": 1,
            "Trng::random_bytes": 1,
        },
        "E2 bring-up binary over the C-firmware partition, same rationale as "
        "bringup.rs: pre-store, no DRBG seed source exists yet. The one type "
        "mention is the `use`.",
    ),
    (
        ("firmware", "src", "emul_main.rs"),
        {"Trng::random_bytes": 1},
        "host emulation binary: the device is a host, so this is HostTrng "
        "reading OS entropy, not a peripheral draw. Declared so the entry is "
        "visible rather than merely absent.",
    ),
    (
        ("apps", "fido", "src", "crypto.rs"),
        {"Trng::random_bytes": 3},
        "TrngAdapter: the rand_core adapter the FIDO curve crates' ::random() "
        "constructors go through. THIS is the site the .random_bytes( flag "
        "exists for — on a starved generator p256::SecretKey::random gets an "
        "untouched buffer. Declared because the adapter itself is correct; "
        "what must not happen is a NEW caller appearing without an entry here "
        "(device_app.rs, device_keystore.rs, vendor_backup.rs).",
    ),
    (
        ("apps", "fido", "src", "device_app.rs"),
        {"Trng::random_bytes": 1},
        "the ONE `.random_bytes(` in this file is `FidoApp::fill_rng_pool` "
        "(`device_app.rs:267`): the 512-B boot RNG pool, 8 x 64 B through the "
        "generic `&mut R: Trng`. This entry previously described the "
        "persistent device hkey and the attestation identity — but neither "
        "is a `.random_bytes(` call *here*. The hkey is reached "
        "indirectly, through `crypto::TrngAdapter`'s `RngCore::fill_bytes` "
        "in `crypto.rs`, which is its own entry; naming it here was a "
        "description of a different file's line.\n"
        "  Why this site is not the defect: the pool is filled from whatever "
        "the boot path threads in, and US-1005 (plus this branch's I-1 fix) "
        "threads the DRBG into BOTH `boot_fido` and `boot_oath` — so this is "
        "the conditioned generator, not a peripheral draw. The one residual "
        "is the infallible-seam one D-9 names: on a starved generator the "
        "8 x 64 B `chunk` is left untouched and the pool becomes 512 zero "
        "bytes, which `draw_random` then serves as the CTAP challenge. "
        "Practically unreachable for the reason D-9 gives (`init_drbg` "
        "refuses fatally at boot; `RESEED_INTERVAL` is 256) — declared, not "
        "hidden.",
    ),
    (
        ("apps", "fido", "src", "device_keystore.rs"),
        {"Trng::random_bytes": 2},
        "per-credential and per-device random material for the FIDO keystore, "
        "through the same TrngAdapter. Request-adjacent, so the same D-9 "
        "residual applies; declared for the same reason.",
    ),
    (
        ("apps", "fido", "src", "vendor_backup.rs"),
        {"Trng::random_bytes": 1},
        "nonce for the FIDO vendor-backup blob, through the same TrngAdapter. "
        "Declared for the same reason.",
    ),
    (
        ("apps", "oath", "src", "oath_core.rs"),
        {"Trng::random_bytes": 1},
        "DECLARED, because before this entry the OATH pool was an *omission* "
        "rather than a decision — which is the shape of the review's I-1 "
        "finding. The one `.random_bytes(` here is `OathApp::fill_rng_pool` "
        "(`oath_core.rs:1016`): the same 512-B boot pool the FIDO app fills, "
        "8 x 64 B. (This entry previously said \"through the same "
        "TrngAdapter\"; it is not. This is a plain generic `&mut R: Trng` "
        "parameter, and the `TrngAdapter` callers are the `apps/fido` ones.)\n"
        "  Why this site is not the defect: the OATH SELECT challenge, the "
        "SET_CODE challenge and every credential response draw from this "
        "pool, and the pool is filled from whatever the boot path threads "
        "into `boot_oath`. That is now the DRBG — `boot_oath` is generic "
        "over `Trng` and is called with `&mut *drbg`, exactly as `boot_fido` "
        "is. Behind the peripheral handle it used to take, this was 24 "
        "unbounded `blocking_wait_for_successful_generation` waits per boot "
        "and a nonce that never passed through the conditioned generator. "
        "The same D-9 residual as the FIDO pool applies: a starved generator "
        "leaves the 512 B untouched and the pool is all zeros, served as a "
        "predictable challenge. Recorded, not hidden.",
    ),
    (
        ("apps", "openpgp", "src", "device_shell.rs"),
        {"Trng::random_bytes": 1},
        "FALSE POSITIVE, declared as such: this is the trussed SERVICE "
        "random_bytes syscall (client.random_bytes(n) inside try_syscall!), "
        "not the platform Trng trait. Different API, different failure "
        "semantics — it returns Err and the card maps that to a status word. "
        "Listed so a reader can see the name match was considered and "
        "dismissed, rather than discovered later as an unexplained exemption.",
    ),
    (
        ("vendor", "opcard", "src", "command.rs"),
        {"Trng::random_bytes": 1},
        "FALSE POSITIVE, declared as such: the trussed service random_bytes "
        "syscall in get_challenge, patched by US-1006 to try_syscall! so a "
        "refusal becomes status word 0x6400 rather than a panic. Not the "
        "platform seam.",
    ),
    (
        ("apps", "fido", "tests", "keygen_bounded.rs"),
        {"Trng::random_bytes": 1},
        "host test target for the US-1007 defect fix. The ONE site is the "
        "test's OWN Trng impl: `CountingTrng::try_random_bytes` calls "
        "`self.random_bytes` so the healthy and silent cases share one draw "
        "path, exactly as the production adapters do. It is not a caller "
        "reaching randomness — it is a test *defining* a source whose whole "
        "purpose is to refuse, and the draw count it records is what the "
        "boundedness assertions are made against. Declared so the entry is "
        "visible rather than absent; a second occurrence in this file would "
        "be a second constructed source, not a second consumer.",
    ),
    (
        ("apps", "fido", "tests", "device_random_fallible.rs"),
        {"Trng::random_bytes": 4},
        "host test target for the I-4 defect fix (US-1005). The FOUR sites are "
        "not callers reaching randomness — they are the test DEFINING the two "
        "sources the assertions are made against: `Starved::random_bytes` is "
        "the infallible half of a refusing generator (it leaves the caller's "
        "buffer exactly as it was, silently, which is the behaviour under "
        "test), and `Healthy::random_bytes` is its control. Two of the four "
        "are called directly by the tests to pin the all-zeros symptom "
        "AGAINST THE SEAM rather than against the keystore, so the property "
        "survives a refactor of the draw path. Declared with a count of four "
        "so a fifth occurrence here would be a new constructed source rather "
        "than a new consumer — the same cap the keygen_bounded.rs entry uses, "
        "for the same reason.",
    ),
    (
        ("platform", "tests", "trng.rs"),
        {"Trng::random_bytes": 7},
        "host test target exercising the Trng trait contract directly. Tests "
        "are not shipped code and the trait method is what is under test.",
    ),
    (
        ("platform", "tests", "drbg_trng.rs"),
        {"Trng::random_bytes": 2},
        "host test target: the two sites are the tests that pin the infallible "
        "seam's own behaviour (it fills when healthy, leaves the buffer alone "
        "when starved). Declared so the test suite is visible in the "
        "inventory rather than silently exempt.",
    ),
    (
        ("platform", "tests", "ckey_aead.rs"),
        {"Trng::random_bytes": 1},
        "host test target: a per-test HostTrng salt. Not shipped code.",
    ),
    (
        ("platform", "tests", "trusted_backend.rs"),
        {"Trng::random_bytes": 1},
        "FALSE POSITIVE, declared as such: the trussed service random_bytes "
        "syscall, on the host twin. Not the platform seam.",
    ),
    # --- US-1007: the starvation seam, declared file by file -----------------
    (
        ("platform", "src", "entropy_starve.rs"),
        {
            "entropy_starve accessor": 1,  # `pub fn starved()`'s definition
            "entropy_starve env var": 2,   # `STARVE_FILE_ENV`'s definition
                                            # and its one read in `control_path`
        },
        "THE SEAM ITSELF (US-1007). The only file permitted to name it, and "
        "per-flag counted so a second accessor or a second env-var reader "
        "here is a new bypass rather than a longer doc comment. It is inert "
        "unless FAPICO2_ENTROPY_STARVE_FILE names a control file, and even "
        "then only while that file exists — `starved()` returns false for an "
        "unset var, a missing file, or an unstattable path, so a "
        "malfunctioning test hook cannot itself become a denial of service. "
        "Its reachability is a `cfg` question, and the STRUCTURAL check "
        "(`check_seam_cfg`) is what enforces it.",
    ),
    (
        ("platform", "src", "lib.rs"),
        {"entropy_starve module": 1},  # the `mod` declaration itself
        "the `mod entropy_starve;` declaration, and the single place the seam "
        "becomes reachable at all. ONE occurrence is the cap that matters: a "
        "second `use` or re-export path here would be a second way in, and "
        "the flags are per-file so a new `.random_bytes(` could not hide on "
        "this entry. The cfg above this line is checked separately and "
        "structurally — see `check_seam_cfg`.",
    ),
    (
        ("platform", "src", "trusted_backend", "host.rs"),
        {
            "entropy_starve module": 1,     # `crate::entropy_starve::starved()`
            "entropy_starve accessor": 1,  # the same line's `starved()` call
        },
        "`HostRng::try_fill_bytes` — the FALLIBLE half, and the only place a "
        "request can be told entropy is gone instead of silently handed an "
        "untouched buffer. `starvation_active()` re-states the seam's exact "
        "`cfg` pair and resolves to a constant `false` on a device build. "
        "ONE occurrence of each: a second call site in this file would be a "
        "second way for a request to be refused, which is the defect, not a "
        "fix.",
    ),
)


def _allowlist_for(path: Path) -> tuple[dict, str] | None:
    """(flag -> max occurrences, reason) for `path`, or None if not allowlisted."""
    parts = path.parts
    for tail, flags, reason in _ALLOWED:
        if parts[-len(tail):] == tail:
            return dict(flags), reason
    return None


def strip_comments(src: str) -> str:
    """Strip Rust line and block comments (and ordinary string contents).

    Line numbers are preserved for all ordinary comments and strings: every
    newline outside a line comment is re-emitted, and ordinary string literals
    cannot span newlines, so ``splitlines()`` on the result aligns with the
    original line numbers. Block-comment nesting (a Rust extension) is
    tracked.

    Limitation: raw string literals (``r#"..."#``) are not stripped — a
    multi-line raw string's inner newlines would be dropped, desynchronizing
    the line numbering. No ``.rs`` file in this tree uses raw strings, so
    PASS/FAIL behaviour is unaffected. This is the same documented limitation
    ``check_persist_gate.py`` carries, and the two lexers are kept identical on
    purpose: a gate that scans differently from its sibling is a gate whose
    report cannot be compared against the sibling's.
    """
    out: list[str] = []
    i = 0
    n = len(src)
    in_line = False
    in_block = 0  # block-comment nesting depth
    in_string = False
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
            i += 1
            continue
        if in_block:
            if c == "/" and nxt == "*":
                in_block += 1
                i += 2
                continue
            if c == "*" and nxt == "/":
                in_block -= 1
                i += 2
                continue
            if c == "\n":
                out.append(c)  # preserve line numbering across multi-line blocks
            i += 1
            continue
        if in_string:
            # Drop the string body; a name inside a literal is not code.
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "/" and nxt == "/":
            in_line = True
            i += 2
            continue
        if c == "/" and nxt == "*":
            in_block = 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _rs_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".rs"):
                yield Path(dirpath) / name


def check_seam_cfg(root: Path) -> tuple[bool, str]:
    """The structural half of the US-1007 gate: the seam's `cfg` is intact.

    Walks backwards from the `pub mod entropy_starve;` line in
    `platform/src/lib.rs`, over any attribute or doc-comment lines, and
    requires the last such line to be EXACTLY `SEAM_REQUIRED_CFG`.

    Why this is separate from the name flags
    -----------------------------------------
    The name flags catch a *new* reference to the seam from an undeclared
    file. They cannot catch the edit that actually matters: deleting or
    narrowing the `#[cfg]` leaves every seam name exactly where it was and
    still compiles, because the module is `pub` and everything it depends
    on (`std::env`, `std::path`, `OnceLock`) is unconditional. That edit
    alone would put a hook that can wedge the device's randomness into a
    shipping firmware. So the invariant "the `mod` line sits under exactly
    this attribute" is checked as a property of the FILE, not inferred
    from a count.

    Returns (ok, detail). `detail` names the line found, or explains what
    is missing, so a red report points at the edit rather than at the file.
    """
    path = root.joinpath(*SEAM_MOD_FILE)
    if not path.is_file():
        return False, f"{'/'.join(SEAM_MOD_FILE)} not found under {root}"
    lines = path.read_text(encoding="utf-8").splitlines()
    try:
        decl_idx = next(
            i for i, ln in enumerate(lines) if ln.strip() == SEAM_MOD_DECL
        )
    except StopIteration:
        return False, (
            f"{'/'.join(SEAM_MOD_FILE)} declares no `{SEAM_MOD_DECL}` line — "
            "the seam has been removed (fine) or renamed (then this gate's "
            "anchors are stale and must be updated with it)"
        )
    # Walk back over attributes AND doc comments to the last line that
    # actually governs the declaration. Doc comments are skipped rather
    # than accepted: the seam's own module doc is a dozen lines long, so
    # treating the nearest `///` as the governing attribute would let the
    # `#[cfg]` be deleted with the gate still green — which is precisely
    # the edit this check exists to catch.
    governing = None
    for i in range(decl_idx - 1, -1, -1):
        s = lines[i].strip()
        if not s:
            continue
        if s.startswith("//"):
            continue  # doc or line comment: carries no cfg
        if s.startswith("#["):
            governing = (i + 1, s)
            continue
        break
    if governing is None:
        return False, (
            f"`{SEAM_MOD_DECL}` (line {decl_idx + 1}) has no attribute above "
            f"it; it must be governed by `{SEAM_REQUIRED_CFG}`"
        )
    lineno, found = governing
    if found == SEAM_REQUIRED_CFG:
        return True, (
            f"line {lineno}: {found} — seam is emulation-only and "
            f"non-arm, so a device build cannot compile it"
        )
    return False, (
        f"`{SEAM_MOD_DECL}` (line {decl_idx + 1}) is governed by line "
        f"{lineno}: {found!r}, but must be governed by exactly "
        f"{SEAM_REQUIRED_CFG!r}. A hook that can make the device's entropy "
        f"refuse must not be reachable from a shipping build."
    )


def scan_file(path: Path) -> list[tuple[int, str, str]]:
    """Return (lineno, flag_name, matched_text) for each code-level occurrence.

    Every flag that matches on a line is reported, not just the first: the
    allowlist excuses *flags*, so a line carrying two of them needs to say
    which is which. The one-match-per-line rule the sibling gates use would
    let `Rp2350Trng::new(EmbTrng::new(..))` report only the inner one and
    leave the outer flag invisible — which is exactly the kind of shadowing
    that made the pre-fix gate score a live bypass green.
    """
    text = path.read_text(encoding="utf-8")
    code = strip_comments(text)
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        for name, pat in RNG_PATTERNS:
            m = pat.search(line)
            if m:
                hits.append((lineno, name, m.group(0)))
    return hits


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else DEFAULT_ROOT
    print(f"scanning: {root}")
    if not root.is_dir():
        print("RESULT: FAIL (scan root missing)")
        return 1

    offenders: list[tuple[Path, int, str]] = []
    declared: list[tuple[Path, str, list[str]]] = []
    scanned = 0
    for path in sorted(_rs_files(root)):
        hits = scan_file(path)
        entry = _allowlist_for(path)
        if entry is None:
            scanned += 1
            for lineno, name, _text in hits:
                offenders.append((path, lineno, name))
            continue
        caps, reason = entry
        # Every declared entry is reported, hit or no hit. An allowlist entry
        # that can exist without ever being surfaced is how a gate rots, and
        # D-8's "printed on every run" claim was false for exactly that reason
        # until this changed.
        seen: dict[str, int] = {}
        for _lineno, name, _text in hits:
            if name not in caps:
                offenders.append((path, _lineno, name))
            else:
                seen[name] = seen.get(name, 0) + 1
        # Over-cap: report at the line of the (cap + 1)-th occurrence, so the
        # report points at the site that actually broke the budget. The count
        # and the line of the FIRST occurrence go in the message too, because
        # a count cap alone names the wrong line: with a cap of 1 the report
        # lands on the legitimate draw while the offender is the one above it,
        # and a reader who does not go looking for the *other* occurrence reads
        # a false accusation. That is exactly what tightening boot.rs to 1
        # (D-10) produces, so the message has to survive being tightened.
        nth: dict[str, int] = {}
        first: dict[str, int] = {}
        total: dict[str, int] = {}
        for lineno, name, _text in hits:
            if name in caps:
                nth[name] = nth.get(name, 0) + 1
                total[name] = nth[name]
                first.setdefault(name, lineno)
                if nth[name] == caps[name] + 1:
                    offenders.append(
                        (
                            path,
                            lineno,
                            f"{name} (allowlist allows {caps[name]} in this file; "
                            f"{total[name]} occurrences, first at line {first[name]})",
                        )
                    )
        declared.append(
            (path, reason, [f"{n} x{c}" for n, c in sorted(seen.items())])
        )

    # The structural half of the US-1007 gate, run unconditionally and
    # reported whether it passes or not — a structural check that only
    # prints on failure is a check nobody notices has stopped running.
    seam_ok, seam_detail = check_seam_cfg(root)

    def _rel(p: Path) -> Path:
        try:
            return p.relative_to(REPO_ROOT)
        except ValueError:
            return p

    print(f"  scanned {scanned} .rs file(s) under {root}")
    print("  --- allowlist (every declared entry, whether or not it has a hit) ---")
    for path, reason, used in declared:
        seen = ", ".join(used) if used else "(no current hit)"
        print(f"  [ALLOW] {_rel(path)} [{seen}]: {reason}")
    if seam_ok:
        print(f"  [SEAM-CFG OK] {'/'.join(SEAM_MOD_FILE)}: {seam_detail}")
    else:
        offenders.append((root.joinpath(*SEAM_MOD_FILE), 0,
                          f"seam cfg: {seam_detail}"))
    for path, lineno, sym in offenders:
        if lineno:
            print(f"  [FAIL] {_rel(path)}:{lineno}: {sym}")
        else:
            print(f"  [FAIL] {_rel(path)}: {sym}")
    if offenders:
        n = len(offenders)
        print(
            f"\nRESULT: FAIL ({n} flagged occurrence(s) — a caller is drawing from "
            "the TRNG instead of the DRBG, or reached randomness through an "
            "infallible seam; or the US-1007 starvation seam lost its cfg and "
            "could reach a device build. Take bytes from "
            "platform::trng::DrbgTrng, or add a reasoned allowlist entry naming "
            "the flag)"
        )
        return 1
    print(
        "  [PASS] no code-level blocking_fill_bytes / EmbTrng::new / Trng::new / "
        "Rp2350Trng::{from_peri,new} / Rp2350Trng in a type position / a boot "
        "helper fed the raw handle / Drbg::{new,new_device} / .random_bytes( / "
        "entropy_starve reference outside the allowlist"
    )
    print("\nRESULT: PASS (one-randomness-path gate green)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
