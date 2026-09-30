#!/usr/bin/env python3
"""US-1040/US-1041: the mutation harness for the gate scripts.

RS-Key's discipline, stated in the epic: *a gate that cannot fail is a defect
class.* A gate nobody has ever seen go red is indistinguishable, to the next
person who reads its green, from a gate that is working. So this harness does
one thing, for every gate in ``tests/scripts/check_*.py``:

    copy the repository to a temp directory, apply a **nominated break** to the
    copy, run the gate against the copy, and require a non-zero exit.

The baseline run matters as much as the mutated one. A gate whose *unmodified*
copy is already red has not demonstrated anything by going red again, so the
harness runs the gate twice per entry and only counts ``MUTATED`` when the
first run exited 0 and the second did not. A gate with no nominated break at
all is reported as ``UNTESTED`` and **fails the harness** — that is the
property US-1040 asks for.

How the copy is made, and why it is not ``cp -r``
--------------------------------------------------

The epic's wording is "copy the repo to a temp dir", and the copy is load
bearing: a break applied to the real tree would be a mutation test that
destroys the thing it is testing. But ``cp -r`` of this workspace is not an
option — ``target/`` alone is 22 GB and there is a second one under
``apps/``. What the harness copies is the **tracked file set**, obtained from
``git ls-files`` (18 MB, 0.13 s), which is exactly the set the CI checkout
would have. ``target/``, ``__pycache__/`` and every other build artifact are
absent, which is the *correct* shape for a mutation test: the gates that need
a device build build one themselves, cold, inside the copy.

Cost, measured on this tree (2026-09-29, RP2350 release build, 5 cores):

    cold device release build        ~45 s
    pure-Python source-scan gates     < 1 s each

Most gates are pure source scans and need no build at all. The handful that
build (``check_size_report``, ``check_async_frame``, ``check_boot_chain``) pay
the cold build once each. A full run is therefore minutes, not hours, but it is
*not* something to put on every push; ``--only NAME`` runs one entry.

The container

-------------

``check_wrapup.py`` is the odd one out: it does ``parents[3]``, so it gates a
document that lives in the **container** repository (``git/pico``), not in
``fapico2``. The harness reproduces that shape by materialising the copy at
``<tmp>/container/fapico2`` and, when it can find a container, copying the one
document that lives there. When it cannot — a standalone checkout, which is what
CI has — the gate is covered by an explicit **waiver** rather than by a
nominated break, and the waiver is itself checked: see ``Waiver.verify``.

Usage:
    python3 tests/scripts/test_gates.py                 # everything
    python3 tests/scripts/test_gates.py --list
    python3 tests/scripts/test_gates.py --only check_rng_path
    python3 tests/scripts/test_gates.py --keep           # leave the temp tree
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent

# Directories that never hold a tracked source file, used only by the
# non-git fallback for building the file list.
SKIP_DIRS = {
    ".git", "target", ".test-venv", ".serena", "node_modules", ".cargo",
    "__pycache__", ".superpowers", ".idea", ".vscode", "build",
}

# Per-gate wall-clock ceiling. The cold device build is ~45 s; the two
# cargo-test gates are the slow ones. Generous, because a timeout that fires
# mid-build leaves a half-populated target directory and reports a red that
# means nothing.
DEFAULT_TIMEOUT = 2400


# ---------------------------------------------------------------------------
# A nominated break
# ---------------------------------------------------------------------------


class Break:
    """One edit, applied to the COPY, that the gate under test must notice.

    ``old`` must occur exactly ``count`` times in the file (default 1). That
    strictness is not pedantry: an edit that matches the wrong occurrence
    produces a *different* break than the one nominated, and the harness would
    then be reporting a red for a defect nobody chose. Anchors are therefore
    chosen to be unique in their file, and a count mismatch is a harness error,
    never a silent success.
    """

    def __init__(self, path: str, old: str, new: str, why: str, count: int = 1):
        self.path = path
        self.old = old
        self.new = new
        self.why = why
        self.count = count

    def apply(self, root: Path) -> None:
        target = root / self.path
        try:
            text = target.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - harness plumbing
            raise HarnessError(f"{self.path}: cannot read for the break ({exc})")
        found = text.count(self.old)
        if found != self.count:
            raise HarnessError(
                f"{self.path}: the nominated anchor occurs {found} time(s), "
                f"expected {self.count}. The anchor has moved or rotted; "
                f"re-nominate the break rather than letting it edit the wrong "
                f"place.\n  anchor: {self.old[:90]!r}"
            )
        target.write_text(text.replace(self.old, self.new, self.count), encoding="utf-8")


class HarnessError(Exception):
    """A defect in the harness itself (bad anchor, unreadable file, ...)."""


class Waiver:
    """A gate that cannot be mutation-tested *here*, with the claim checked.

    The waiver is not an exemption. ``verify`` runs the gate and requires it to
    be red **and** to be red for the recorded reason, so a waiver that stops
    describing reality fails the harness exactly like a stale nominated anchor
    does. The alternative — leaving the gate out of the table — is the failure
    mode this whole story exists to prevent.
    """

    def __init__(self, reason: str, must_mention: tuple[str, ...]):
        self.reason = reason
        self.must_mention = must_mention

    def verify(self, rc: int, output: str) -> tuple[bool, str]:
        if rc == 0:
            return False, (
                "the gate is GREEN, so the recorded waiver is stale — this gate "
                "is mutation-testable after all (or the container document it "
                "reads has been vendored). Remove the waiver and nominate a break."
            )
        missing = [m for m in self.must_mention if m not in output]
        if missing:
            return False, (
                "the gate is red, but not for the recorded reason (its output "
                f"does not mention {missing!r}). A waiver that has stopped "
                "describing why the gate cannot be mutated here is worse than "
                "no waiver, because it hides a different defect behind a "
                "familiar one."
            )
        return True, "red for the recorded reason, exactly as the waiver states"


# ---------------------------------------------------------------------------
# A gate under test
# ---------------------------------------------------------------------------


class Gate:
    def __init__(
        self,
        name: str,
        argv: tuple[str, ...] = (),
        breaks: tuple[Break, ...] | None = None,
        container_files: tuple[str, ...] = (),
        waiver: Waiver | None = None,
        note: str = "",
    ):
        self.name = name
        self.argv = argv
        self.breaks = breaks
        self.container_files = container_files
        self.waiver = waiver
        self.note = note


# --- the nominated breaks ---------------------------------------------------
#
# One per gate. Each is the smallest edit that reproduces the defect class the
# gate exists to catch, chosen so the edit is (a) deterministic, (b) anchored
# on text unique to its file, and (c) inside the file the gate actually reads.

_B_PERSIST = Break(
    "apps/fido/src/device_app.rs",
    "    fn select(&mut self, _internal: bool) -> fapico2_platform::dispatch::Sw {",
    "    fn select(&mut self, _internal: bool) -> fapico2_platform::dispatch::Sw {\n"
    "        // US-1041 nominated break: a transport re-sequencing persistence.\n"
    "        let _ = persist_secure_partition as *const ();",
    "a transport names one of the deleted pre-split persist implementations "
    "outside the two platform files that own it (the US-429 invariant)",
)

_B_ATTESTATION = Break(
    "apps/fido/src/attestation.rs",
    "//! Per-device attestation identity provisioning (US-916).",
    "// US-1041 nominated break: repo-committed attestation material.\n"
    "static SHIPPED_KEY: &[u8] = include_bytes!(\"attestation_key.bin\");\n"
    "//! Per-device attestation identity provisioning (US-916).",
    "a module under apps/fido/src calls include_bytes! again and names the "
    "deleted repo-committed blob — the US-916/US-925 invariant that the "
    "attestation identity is minted on device and never shipped",
)

_B_DBG_RELEASE = Break(
    "firmware/Cargo.toml",
    'dbg-log = []\n',
    'dbg-log = []\n# US-1041 nominated break: dbg-log becomes an ordinary release feature.\n'
    'foreign-image-wipe = ["dbg-log"]\n',
    "`dbg-log` becomes an implicit member of a feature an ordinary release "
    "invocation turns on (US-922: the fixed-channel CTAP-HID log drain ships "
    "in a production binary)",
)

_B_DEBUG_STRIP = Break(
    "firmware/src/tasks.rs",
    "pub async fn ccid_task(",
    "// US-1041 nominated break: S-391-13 debug machinery is still present.\n"
    "fn clean_slate() {}\n\npub async fn ccid_task(",
    "bring-up scaffolding (`clean_slate`) is back in a device source, so the "
    "flashed image no longer matches a clean tree (S-391-13)",
)

_B_README = Break(
    "README.md",
    "[`docs/bootsel.md`](docs/bootsel.md)",
    "[`docs/bootsel`](docs/bootsel)",
    "the README loses the pointer to docs/bootsel.md, so the flashing "
    "contract is prose with nothing behind it (US-392)",
)

_B_RELEASE_NOTES = Break(
    "docs/release-notes-v1.0.0.md",
    "fa20:0002",
    "fa20:0003",
    "the release notes stop recording the USB identity the device actually "
    "enumerates as (US-393)",
)

_B_PICOFORGE = Break(
    "README.md",
    "not fixable from the firmware",
    "fixable from the firmware",
    "the PicoForge-compatibility section loses the explicit "
    "'not fixable from the firmware' statement — the client-side constraint "
    "that is a lie if it is not written down (US-164)",
)

_B_US413 = Break(
    "docs/migration-feasibility.md",
    "PKOC/manifest/v1",
    "PKOC/manifest/v2",
    "the feasibility document drops a required anchor (`PKOC/manifest/v1`), "
    "so the C-side layout it is the record of is no longer documented (S-413-1)",
)

_B_WRAPUP = Break(
    "docs/bootsel.md",
    "**no rescue APDU in v1.0.0**",
    "**rescue APDU works in v1.0.0**",
    "docs/bootsel.md claims the C firmware's rescue APDU works on the Rust "
    "build — it does not (the C firmware entered BOOTSEL with no button "
    "press, verified 2026-09-08; the Rust build is physical BOOTSEL+RESET "
    "only), and the claim is the one an operator acts on while holding a "
    "dark board (US-392)",
)

_B_ASYNC_FRAME = Break(
    "tests/scripts/stack_roots.py",
    '_TASK_ATTR = re.compile(r"#\\[\\s*(?:embassy_executor\\s*::\\s*)?(?:task|main)\\s*\\]")',
    '_TASK_ATTR = re.compile(r"#\\[\\s*(?:embassy_executor\\s*::\\s*)?main\\s*\\]")',
    "the task-root matcher stops seeing `#[task]` and only counts `#[main]` — "
    "the US-961 regression, where a rustc mangling-scheme change silently "
    "left five of six task polls unmeasured while the gate still printed "
    "PASS. The source-derived floor is what turns that into a FAIL. NOTE: this "
    "break is on the MATCHER, not on the device source; see the report — a "
    "large-array mutation of a task poll does not survive this toolchain's "
    "LTO (three variants were folded away), so the frame half of this gate is "
    "covered by the boot-chain break's arena stamp rather than by a frame.",
)

_B_BOOT_CHAIN = Break(
    "firmware/src/tasks.rs",
    "    let mut ccid_in = ccid_in;\n",
    "    /// US-1041 nominated break: device-side static growth, with the\n"
    "    /// task-arena demand constant left exactly as it was measured.\n"
    "    static __US1041_ARENA_GROWTH: [u8; 512] = [0u8; 512];\n"
    "    let _ = __US1041_ARENA_GROWTH[0];\n"
    "    let mut ccid_in = ccid_in;\n",
    "the inputs `TASK_ARENA_DEMAND_B` was measured from have changed and the "
    "measurement was not redone, so the headroom figure the gate would "
    "publish describes a build that no longer exists (US-964). A statics or "
    "task-future change is the same class: the stamp is a proxy for 'the "
    "measurement still describes this tree', and its whole job is to make a "
    "stale number a FAIL instead of a reassuring ratio",
)

_B_SIZE_REPORT = Break(
    "docs/size-report.md",
    # Re-nominated FOUR times, and the recurrence is the finding:
    #   1. 2026-09-29 (US-1080) — the anchor tracked a measured figure and had
    #      rotted through earlier re-measurements.
    #   2. 2026-09-29 (I-1/I-4/US-1008/US-1083 fix pass) — it rotted AGAIN,
    #      because that pass re-measured the report (+8 B text, +8 B .bss).
    #   3. 2026-09-29 (US-1010, the MAX_PARTS fix) — re-measured again
    #      (text 811,976 → 811,956, bss unchanged).
    #   4. 2026-09-29 (US-1010, the RAM-gating pass) — the anchor MOVED, not
    #      because a number rotted but because the headline text line it
    #      pointed at was replaced by a *generated block*, which is what
    #      fixes the recurrence for good (see below).
    #
    # US-1010 also fixed the underlying problem for the **interior**: the
    # per-section table and the summary are now delimited
    # (`<!-- BEGIN measured ELF sections -->`) and `check_size_report.py`
    # regenerates them from the ELF and fails on any difference. A stale
    # interior is now a FAIL rather than something a reader has to notice.
    # So this break no longer needs the headline line *or* a hand-copied
    # figure: it perturbs one number **inside the generated block**, which is
    # precisely the class of edit that used to pass silently.
    #
    # The recurrence cost is still real and still recurring for the *headline*
    # line, and is still not fixed here: `Break` is a literal string-replace
    # with an "exactly one occurrence" anchor, and the thing this break needs
    # to perturb is by definition a measured number. Making the anchor a regex
    # would relax the "matches exactly one place" discipline every other break
    # relies on, and `Break` has no way to express "same line, different
    # number" without it. That is a Phase 5 (US-1040/US-1041) change to a
    # mutation harness, not a drive-by edit inside a fix pass — and a wrong
    # edit here is a gate weakening, which is the one outcome to avoid.
    # Re-nominating is the honest cost; the harness says so out loud rather
    # than passing quietly.
    "| `.text` | 759,928 | `0x10000200` | no (flash) |",
    "| `.text` | 759,929 | `0x10000200` | no (flash) |",
    "the generated ELF section table in docs/size-report.md is one byte out — "
    "the interior was hand-copied and re-measured without the headline, so the "
    "gate passed over a stale detail. The report is the RAM/flash argument; a "
    "detail that under-states growth is the same class as a gate that "
    "under-measures (US-392/US-957/US-1010)",
)

_B_RNG_PATH = Break(
    "firmware/src/main.rs",
    "    let mut trng = Rp2350Trng::from_peri(p.TRNG, TrngIrqs, Config::default());",
    "    let mut trng = Rp2350Trng::from_peri(p.TRNG, TrngIrqs, Config::default());\n"
    "    // US-1041 nominated break: a second raw peripheral handle in the one\n"
    "    // file the allowlist counts to exactly one.\n"
    "    let _extra_bypass = Rp2350Trng::from_peri(p.TRNG, TrngIrqs, Config::default());",
    "a second `Rp2350Trng::from_peri` in firmware/src/main.rs — one caller past "
    "the per-flag count cap, so a site holding an unbounded peripheral draw "
    "reaches production beside the single legitimate bootstrap handle. This is "
    "the exact bypass the reviewer's `from_peri` flag and the per-count cap "
    "exist for, and a bare file+flag allowlist would have scored it green "
    "(US-1005). The cap was 2 until D-10 closed; the break is the same edit "
    "either way, because what it has to beat is 'one past the cap', not a "
    "particular number.",
)

_B_ERASE_BUDGET = Break(
    "apps/fido/src/device_keystore.rs",
    "pub const COUNTER_PERSIST_INTERVAL: u16 = 32;",
    "pub const COUNTER_PERSIST_INTERVAL: u16 = 64;",
    "the code's COUNTER_PERSIST_INTERVAL is moved without moving "
    "docs/erase-budget.md, so the document's lifetime arithmetic is not the "
    "one the device runs. Before US-1011 the two were coupled only by a "
    "comment telling a developer to keep three files in step by hand; the gate "
    "reads the number out of the source and re-derives the ceiling from it "
    "(US-1010/US-1011)",
)

_B_HEAP = Break(
    "platform/Cargo.toml",
    'default = ["device", "host-backend", "rsa-backend", "secp256k1-backend", "brainpool-backend"]',
    'default = ["device", "host-backend", "secp256k1-backend", "brainpool-backend"]',
    '"rsa-backend" leaves the platform default feature set, so platform::rsa_heap '
    "is cfg'd out of the device image. Every other heap check still passes — "
    "exactly one sanctioned `#[global_allocator]` in the SOURCE, which is true, "
    "and false of the BINARY, where the allocator does not exist and every "
    "software-RSA request aborts. The source/binary gap is the US-961 blind "
    "spot this assertion closes",
)

_B_CLOCK_ORDER = Break(
    "firmware/src/main.rs",
    "    let mut seed_probe = Rp2350Probe::new(seed_probe_peri, clock, TrngConfig::default());",
    "    let mut seed_probe = Rp2350Probe::new(seed_probe_peri, seed_probe_peri, TrngConfig::default());",
    "Rp2350Probe::new stops being given the ClockReady proof and is handed "
    "the peripheral token twice instead. The arity is unchanged, which is "
    "why this break had to be re-nominated after US-1005's TRNG-config fix "
    "gave the constructor a third argument: the old one-argument mutation "
    "left the gate green, because a comma count cannot tell a missing proof "
    "from a different value of the right arity. The gate now asserts the "
    "proof is NAMED in the argument list. The defect is the D-12 shape — the "
    "bounded entropy wait measured against a TIMER0 nobody has checked, the "
    "budget unreachable, the probe degenerating to its poll cap, and the "
    "device refusing to seed and halting before USB enumerates (the "
    "2026-09-29 hardware finding). The ordering stays textually correct and the bounded "
    "entropy wait goes back to being measured against a TIMER0 nobody has "
    "checked — the D-12 shape, where the budget is unreachable and the probe "
    "degenerates to its poll cap, and the device refuses to seed and halts "
    "before USB enumerates (the 2026-09-29 hardware finding)",
)

_B_OTP_PRECONDITION = Break(
    "platform/src/boot_key.rs",
    "        self.check_lock_state(\n"
    "            otp,\n"
    "            &[self.layout.key_row(slot), self.layout.version_row],\n"
    "        )?;",
    "        // US-1083 nominated break: the lock-state assertion removed.",
    "the OTP provisioning path stops refusing a non-nominal lock state. The "
    "one-shot pre-flight that remains is a blank-row READ, and a READ_ONLY "
    "page lets that read succeed — so on a device whose page 0 was locked by "
    "the C stack (pico-keys-sdk/src/otp/otp_rp2350.c:88-95 writes 0b1100 to "
    "sw_lock, and every row Layout::rp2350() names is inside page 0) the row "
    "reads virgin, the presence grant is spent, and the failure lands at "
    "program_row instead. That is the burn the epic calls the difference "
    "between a recoverable mistake and a permanently mis-provisioned token, "
    "and US-1083 blocks US-1081 precisely because it does",
)

_B_ADVERTISE = Break(
    "apps/openpgp/Cargo.toml",
    'fapico2-platform = { path = "../../platform", default-features = false }',
    'fapico2-platform = { path = "../../platform" }',
    "the platform edge is re-acquired with default features, so the reduced "
    "(backend-free) build this gate measures silently does not exist: the "
    "default half still passes because both sides are on, and the reduced "
    "build would carry six backends while advertising four groups. This is "
    "the one-line US-964 mutation, verbatim",
)

_B_CRATE_GRAPH = Break(
    "apps/fido/Cargo.toml",
    'fapico2-platform = { path = "../../platform" }',
    'fapico2-platform = { path = "../../platform" }\n'
    "# US-1041 nominated break (US-1060): an applet reaching another applet.\n"
    'fapico2-oath = { path = "../oath" }',
    "apps/fido takes a normal dependency on the apps/oath applet, so one "
    "applet's code ends up inside another's link — the US-1060 R1 rule. Every "
    "applet->applet edge the policy knows about belongs to the AID registry "
    "(fapico2-apps), which holds AID constants and no card logic; an edge "
    "between two applets is the shape the rule exists to refuse, and it "
    "reaches the shipped binary rather than only the test graph",
)

_B_SUPPLY_CHAIN = Break(
    "supply-chain/exemption-reasons.toml",
    '"rsa@0.9.10" = "SELF-DECLARED, not human-reviewed, and ACCEPTED WITH A KNOWN',
    '# US-1041 nominated break (US-1061): the stated reason is gone.\n'
    '# "rsa@0.9.10" = "SELF-DECLARED, not human-reviewed, and ACCEPTED WITH A KNOWN',
    "an exemption in supply-chain/config.toml loses its stated reason. This is "
    "the US-1061 rule — a new exemption must arrive with a reason, and "
    "cargo-vet itself does not require one — and the crate that loses it here "
    "is the worst possible one to lose it for: the unpatched Marvin advisory "
    "against `rsa`, which is the single accepted VULNERABILITY in this "
    "firmware's dependency set. A reason list is a decision record; the "
    "record can be deleted silently, and only a gate notices",
)

_B_SBOM = Break(
    "supply-chain/sbom.cdx.json",
    '      "name": "opcard",\n',
    '      "name": "opcard-not-the-one-we-build",\n',
    "the published SBOM no longer describes the shipped artefact: a "
    "component is renamed so the document lists a crate the build does not "
    "contain AND silently omits one it does. opcard is the OpenPGP card "
    "implementation itself — the crate the whole OpenPGP applet is — so this "
    "is the shape of failure an SBOM exists to make impossible, and it is "
    "invisible to a one-directional 'is every listed component in the "
    "lock?' check, which is why the gate compares the two sets for EQUALITY",
)

# `built-elsewhere.json` is refused by TWO independent rules — the one in
# `externalParameters.workflow` (P3) and the one in `runDetails.builder.id`
# (P4) — which is the point: an attacker who forges an attestation has to
# get both halves right. The break therefore removes BOTH, because removing
# one would leave the fixture refused and the gate would look unbreakable
# for the wrong reason.
_B_PROVENANCE_PATH = Break(
    "tests/scripts/check_release_provenance.py",
    "    if wf_path != expected_workflow:",
    "    if False:  # US-1041 nominated break (US-1063): the check is gone",
    "the policy stops requiring the attestation's externalParameters to name "
    "the reusable release workflow (see the companion break on the builder "
    "id); between them the two let `built-elsewhere.json` through",
)
_B_PROVENANCE_BUILDER = Break(
    "tests/scripts/check_release_provenance.py",
    "    if repo != expected_repo:",
    "    if False:  # US-1041 nominated break (US-1063): the check is gone",
    "the policy stops requiring the attestation to name the reusable release "
    "workflow, so `built-elsewhere.json` — a release produced by another "
    "repository's rogue.yml — is ACCEPTED. This is the story's own red and "
    "the distinction it exists to draw: \"CI passed\" is not \"the release "
    "workflow built this\". A maintainer's ad-hoc workflow_dispatch, a fork, "
    "or a one-off YAML file elsewhere in the repository all satisfy the "
    "first claim and fail the second; a gate that only checks the first is "
    "a gate that cannot tell a release from a build",
)

_B_AGREEMENT = Break(
    "tests/scripts/check_artefact_agreement.py",
    "        if claimed != actual:",
    "        if False:  # US-1041 nominated break (US-1064): the check is gone",
    "the subject-digest comparison is removed, so a UF2 changed AFTER it was "
    "signed is accepted. Every other rule still passes: the SBOM can be "
    "rewritten to match the mutated image, the artefact directory is "
    "complete, and the statement is well-formed. That is exactly the state "
    "this story exists to refuse — three internally valid documents, two of "
    "them describing a build that was never signed",
)

GATES: tuple[Gate, ...] = (
    Gate(
        "check_persist_gate.py",
        breaks=(_B_PERSIST,),
        note="name-forbiddance archetype (comment-aware)",
    ),
    Gate(
        "check_attestation_gate.py",
        breaks=(_B_ATTESTATION,),
        note="name-forbiddance archetype (blob + include_bytes! bans)",
    ),
    Gate(
        "check_dbg_release_gate.py",
        breaks=(_B_DBG_RELEASE,),
        note="manifest reachability + a build assertion",
    ),
    Gate(
        "check_debug_strip.py",
        breaks=(_B_DEBUG_STRIP,),
    ),
    Gate(
        "check_readme.py",
        breaks=(_B_README,),
        note="doc-agreement archetype",
    ),
    Gate(
        "check_release_notes.py",
        breaks=(_B_RELEASE_NOTES,),
        note="doc-agreement archetype",
    ),
    Gate(
        "check_picoforge_compat_docs.py",
        breaks=(_B_PICOFORGE,),
        note="doc-agreement archetype, section-scoped",
    ),
    Gate(
        "check_us413_feasibility.py",
        breaks=(_B_US413,),
        note="doc-agreement archetype",
    ),
    Gate(
        "check_wrapup.py",
        breaks=(_B_WRAPUP,),
        container_files=("docs/tasks/EPIC-merged-firmware.md",),
        waiver=Waiver(
            reason=(
                "check_wrapup.py reads parents[3] — the CONTAINER repository "
                "(git/pico), not fapico2 — so one of the two documents it gates "
                "(docs/tasks/EPIC-merged-firmware.md) is not part of the tree "
                "this harness copies. Where a container can be found the "
                "harness materialises it and the break above is applied and "
                "verified like any other; where it cannot (a standalone "
                "checkout, which is what CI has), the gate is red for that "
                "one reason and the waiver is checked against it."
            ),
            must_mention=("EPIC-merged-firmware.md",),
        ),
        note="container-scoped: the second subject is outside this repository",
    ),
    # --- US-1041: the structural gates. Each break is the edit that
    # --- reproduces the defect class its gate was written for.
    Gate(
        "check_async_frame.py",
        breaks=(_B_ASYNC_FRAME,),
        note="ELF frame measurement (needs a build) + source-derived root floor",
    ),
    Gate(
        "check_boot_chain.py",
        breaks=(_B_BOOT_CHAIN,),
        note="ELF call-chain condensation + arena-stamp staleness (needs a build)",
    ),
    Gate(
        "check_size_report.py",
        breaks=(_B_SIZE_REPORT,),
        note="doc-agreement over a rebuilt ELF (needs a build)",
    ),
    Gate(
        "check_rng_path.py",
        breaks=(_B_RNG_PATH,),
        note="name-forbiddance, per-flag count-capped",
    ),
    Gate(
        "check_erase_budget.py",
        breaks=(_B_ERASE_BUDGET,),
        note="doc-agreement over a host measurement (needs a cargo test)",
    ),
    Gate(
        "check_heap_gate.py",
        breaks=(_B_HEAP,),
        note="structural source proof, plus the source-vs-binary heap check",
    ),
    Gate(
        "check_boot_clock_order.py",
        breaks=(_B_CLOCK_ORDER,),
        note="ordering over source: the entropy clock proof before the wait",
    ),
    Gate(
        "check_otp_provisioning_precondition.py",
        breaks=(_B_OTP_PRECONDITION,),
        note="source order + decoding, over a one-shot burn",
    ),
    Gate(
        "check_advertise_serve_coupling.py",
        breaks=(_B_ADVERTISE,),
        note="build-and-run, two configurations",
    ),
    Gate(
        "check_crate_graph.py",
        breaks=(_B_CRATE_GRAPH,),
        note="graph assertions cargo-deny cannot express (US-1060 R1/R2)",
    ),
    Gate(
        "check_supply_chain.py",
        breaks=(_B_SUPPLY_CHAIN,),
        note="cargo-vet coverage, stated exemption reasons, derived doc counts",
    ),
    Gate(
        "check_sbom.py",
        breaks=(_B_SBOM,),
        note="doc-vs-derived agreement, two-directional set equality",
    ),
    Gate(
        "check_release_provenance.py",
        breaks=(_B_PROVENANCE_PATH, _B_PROVENANCE_BUILDER),
        note="attestation policy against committed fixtures (US-1063)",
    ),
    Gate(
        "check_artefact_agreement.py",
        breaks=(_B_AGREEMENT,),
        note="UF2 / SBOM / attestation agreement against fixtures (US-1064)",
    ),
)


# ---------------------------------------------------------------------------
# The copy
# ---------------------------------------------------------------------------


def _git_tracked_files() -> list[str] | None:
    """Tracked paths, or None when this is not a git checkout."""
    try:
        r = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
            capture_output=True,
        )
    except OSError:
        return None
    if r.returncode != 0:
        return None
    return [p for p in r.stdout.decode("utf-8", "replace").split("\0") if p]


def _walk_files() -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith((".pyc", ".pyo")):
                continue
            out.append(
                str((Path(dirpath) / name).relative_to(REPO_ROOT)).replace(os.sep, "/")
            )
    return out


def copy_repo(dst: Path) -> int:
    """Materialise the repository's source tree at ``dst``. Returns file count.

    Tracked files only where git can tell us, so the copy is the same tree CI
    would check out — no ``target/``, no venv, no editor droppings. The fallback
    walk exists so the harness still runs from a tarball or a partial clone; it
    applies the same directory exclusions.
    """
    names = _git_tracked_files()
    source = "git ls-files"
    if names is None:
        names, source = _walk_files(), "directory walk (no git)"
    for rel in names:
        src = REPO_ROOT / rel
        if not src.is_file():
            continue
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)
    print(f"  copied {len(names)} file(s) via {source} -> {dst}")
    return len(names)


def container_candidates() -> list[Path]:
    """Where the CONTAINER repository (``git/pico``) might live.

    ``check_wrapup.py``'s second subject is one file in it. In the normal
    layout the container is the parent of this repo; in a worktree of
    ``git/pico-wt/<name>`` it is a sibling of the worktree root. Both are
    probed, and ``FAPICO2_CONTAINER`` overrides.
    """
    out: list[Path] = []
    env = os.environ.get("FAPICO2_CONTAINER")
    if env:
        out.append(Path(env))
    out.append(REPO_ROOT.parent)
    out.append(REPO_ROOT.parent.parent / "pico")
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def materialise_container(dest: Path, rels: tuple[str, ...]) -> list[str]:
    """Copy the container-scoped documents this gate reads into ``dest``.

    Returns the list of container-relative paths that could NOT be found, so
    the caller can fall back to the waiver and say so in the report.
    """
    missing: list[str] = []
    for rel in rels:
        for cand in container_candidates():
            src = cand / rel
            if src.is_file():
                out = dest / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, out)
                print(f"  container document: {src} -> {out}")
                break
        else:
            missing.append(rel)
    return missing


# ---------------------------------------------------------------------------
# Running one gate
# ---------------------------------------------------------------------------


def run_gate(copy_root: Path, gate: Gate, timeout: int) -> tuple[int, str]:
    script = copy_root / "tests" / "scripts" / gate.name
    cmd = [sys.executable, str(script), *gate.argv]
    try:
        r = subprocess.run(
            cmd,
            cwd=str(copy_root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def first_lines(output: str, n: int = 3) -> str:
    keep = [ln for ln in output.splitlines() if ln.strip()][:n]
    return " | ".join(keep)[:220]


# ---------------------------------------------------------------------------
# The mutation check
# ---------------------------------------------------------------------------


def check_gate(gate: Gate, slot: Path, timeout: int) -> dict:
    """Baseline run + (nominated break or waiver check). Returns a result row.

    `slot` is a per-gate scratch directory. It MUST be unique per gate: a
    shared copy path lets one gate's `target/` leak into the next gate's
    baseline, which is the harness manufacturing a green rather than
    observing one.
    """
    row = {
        "gate": gate.name,
        "status": "?",
        "detail": "",
        "baseline_rc": None,
        "broken_rc": None,
        "seconds": 0.0,
    }
    t0 = time.time()
    print(f"\n--- {gate.name}")
    if gate.breaks is None:
        row["status"] = "UNTESTED"
        row["detail"] = (
            "no nominated break. A gate nobody has seen go red is "
            "indistinguishable from a gate that works (US-1040)."
        )
        return row

    copy_root = slot / "container" / "fapico2"
    copy_root.mkdir(parents=True, exist_ok=True)
    copy_repo(copy_root)
    missing = materialise_container(slot / "container", gate.container_files)

    base_rc, base_out = run_gate(copy_root, gate, timeout)
    row["baseline_rc"] = base_rc
    print(f"  baseline exit {base_rc}: {first_lines(base_out)}")

    if base_rc != 0 and gate.waiver is not None and missing:
        ok, detail = gate.waiver.verify(base_rc, base_out)
        row["broken_rc"] = base_rc
        row["status"] = "WAIVED-VERIFIED" if ok else "WAIVER-STALE"
        row["detail"] = detail
        row["seconds"] = time.time() - t0
        return row
    if base_rc != 0:
        row["status"] = "BASELINE-RED"
        row["detail"] = (
            "the gate is red on an UNMODIFIED copy, so a red after the break "
            "would prove nothing. This is either a real red in the tree or a "
            "harness path assumption that no longer holds; both must be "
            "resolved, not absorbed."
        )
        row["seconds"] = time.time() - t0
        return row

    for b in gate.breaks:
        b.apply(copy_root)

    broken_rc, broken_out = run_gate(copy_root, gate, timeout)
    row["broken_rc"] = broken_rc
    print(f"  broken   exit {broken_rc}: {first_lines(broken_out)}")
    if broken_rc == 0:
        row["status"] = "BREAK-INEFFECTIVE"
        row["detail"] = (
            "the nominated break left the gate GREEN. Either the break is not "
            "the defect the gate exists to catch, or the gate cannot see it."
        )
    else:
        row["status"] = "MUTATED"
        row["detail"] = gate.breaks[0].why
    row["seconds"] = time.time() - t0
    return row


def summarise(rows: list[dict]) -> tuple[int, int, int]:
    covered = sum(1 for r in rows if r["status"] in ("MUTATED", "WAIVED-VERIFIED"))
    return covered, len(rows), sum(1 for r in rows if r["status"] == "MUTATED")


# ---------------------------------------------------------------------------
# US-1042: are the gates reachable from a docs-only change?
# ---------------------------------------------------------------------------
#
# The skeptic pass this story comes from found a repository where the check job
# was gated on `docs_only != 'true'`, and where GitHub counts a *skipped*
# required check as *satisfied* — so a docs-only pull request merged with no
# assurance signal at all, and nothing red. fapico2's workflows do not carry
# that exact condition today; what they do carry is a worse and quieter shape
# of the same risk, which the first run of this check found: eight of the
# seventeen gate scripts are not invoked by ANY workflow, so a docs-only change
# skips them, and so does every other change.
#
# This is asserted by SIMULATION, not by grepping the YAML. The harness parses
# the workflow files, evaluates every job's and every step's `if:` for a given
# set of changed paths, and then asks which gate scripts the steps that would
# actually run invoke. Two properties of the implementation matter:
#
#   * an `if:` the evaluator does not understand is a hard ERROR, never a
#     silent "assume it runs". A simulation that defaults to permissive is the
#     same false green this whole story exists to catch, one level up;
#   * the parser cross-checks that it saw every `- ` step item in the file, so
#     a step it silently dropped cannot make a gate look unreachable — or
#     reachable — by accident.
#
# There is no PyYAML dependency (the house rule for everything in this
# directory is stdlib only), so the parser models the small subset of YAML the
# workflows use: two-space mappings, `- ` sequences, `|`/`>` block scalars, and
# quoted scalars. Anything else raises.

WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# Gates deliberately not wired into CI, each with the reason. Kept as data so
# the report prints them on every run rather than leaving them in a comment.
#
#   check_wrapup.py reads `parents[3]` — the CONTAINER repository (git/pico) —
#   and one of the two documents it gates
#   (`docs/tasks/EPIC-merged-firmware.md`) is not part of this repository. CI
#   checks fapico2 out standalone at $GITHUB_WORKSPACE/fapico2, so that file
#   does not exist and the gate is red there for a reason that has nothing to
#   do with the tree. Running it would turn every CI run permanently red, which
#   is a different way of the same failure. It is still mutation-covered by
#   this harness (see the Waiver in the table above), and the exclusion below
#   is printed rather than buried.
CI_EXCLUSIONS: dict[str, str] = {
    "check_wrapup.py": (
        "container-scoped: gates a document in git/pico, which a standalone "
        "CI checkout does not contain. Mutation-covered locally by this "
        "harness; not runnable in CI without vendoring a second repository."
    ),
}


class WorkflowError(Exception):
    """The workflow files are not in the shape this simulator models."""


def _yaml_lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        out.append((indent, raw.strip()))
    return out


def _parse_yaml(text: str) -> dict:
    """Parse the workflow subset. Raises WorkflowError on anything unexpected."""
    lines = _yaml_lines(text)

    def parse_mapping(block, i, indent):
        out: dict = {}
        while i < len(block) and block[i][0] == indent:
            head = _split_key(block[i][1])
            if head is None:
                raise WorkflowError(
                    f"not a `key: value` line at indent {indent}: {block[i][1]!r}"
                )
            key, value = head
            i += 1
            if value in ("|", "|-", "|+", ">", ">-", ">+"):
                body: list[str] = []
                while i < len(block) and block[i][0] > indent:
                    body.append(block[i][1])
                    i += 1
                out[key] = "\n".join(body)
            elif value == "":
                if i < len(block) and block[i][0] > indent:
                    out[key], i = parse(block, i, block[i][0])
                else:
                    out[key] = None
            else:
                # Strip the quoting: a value written `- name: "Foo bar"` must
                # compare equal to one written `- name: Foo bar`, or every
                # assertion over step names is a coin flip on the author's
                # quoting style.
                out[key] = (
                    value[1:-1] if len(value) > 1 and value[:1] in "'\"" and value[-1:] == value[:1]
                    else value
                )
        if i < len(block) and block[i][0] > indent:
            raise WorkflowError(
                f"unexpected deeper block after {block[i - 1][1]!r}: {block[i][1]!r}"
            )
        return out, i

    def parse(block, i, indent):
        if i >= len(block) or block[i][0] != indent:
            raise WorkflowError(f"expected a block at indent {indent}, line {i + 1}")
        if not block[i][1].startswith("- "):
            return parse_mapping(block, i, indent)
        seq = []
        while i < len(block) and block[i][0] == indent and block[i][1].startswith("- "):
            item = block[i][1][2:]
            head = _split_key(item)
            if head is None:
                # A bare sequence scalar (`- 'docs/**'`), possibly quoted.
                # The quotes are YAML syntax, not part of the value: keeping
                # them makes every `paths-ignore` pattern fail to match, and a
                # filter that silently matches nothing is a filter that has
                # been switched off.
                seq.append(item[1:-1] if item[:1] in "'\"" and item[-1:] == item[:1] else item)
                i += 1
                continue
            # `- key: value` opens a mapping whose remaining keys sit two
            # columns in, with the dash line acting as its first entry. The
            # dash line is re-indented so ONE parser handles both forms — a
            # second, near-identical parser is how a gate and its own copy of
            # the rules drift apart.
            inline: list[tuple[int, str]] = [(indent + 2, item)]
            j = i + 1
            while j < len(block) and block[j][0] > indent:
                inline.append(block[j])
                j += 1
            value, _ = parse_mapping(inline, 0, indent + 2)
            seq.append(value)
            i = j
        return seq, i

    if not lines or lines[0][0] != 0:
        raise WorkflowError("workflow does not start at indent 0")
    doc, _ = parse(lines, 0, 0)
    return doc


def _steps_in_text(text: str) -> int:
    """`- ` items that sit under a `steps:` key — the raw step count."""
    lines = [(len(ln) - len(ln.lstrip(" ")), ln.strip())
             for ln in text.splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    n = 0
    for i, (indent, body) in enumerate(lines):
        if body != "steps:":
            continue
        j = i + 1
        while j < len(lines) and lines[j][0] > indent:
            if lines[j][0] == indent + 2 and lines[j][1].startswith("- "):
                n += 1
            j += 1
    return n


def _split_key(text: str) -> tuple[str, str] | None:
    if ":" not in text:
        return None
    key, _, value = text.partition(":")
    key = key.strip().strip("'\"")
    if not key or " " in key:
        return None
    return key, value.strip()


# --- the condition evaluator ----------------------------------------------

import re as _re  # noqa: E402  (kept local to the section that needs it)

_TOKEN = _re.compile(
    r"""\s*(?:
        (?P<str>'(?:[^']|'')*')
      | (?P<op>==|!=|<=|>=|&&|\|\||[!()<>])
      | (?P<num>\d+)
      | (?P<ident>[A-Za-z_][A-Za-z0-9_.]*)
    )""",
    _re.X,
)

# The functions GitHub's `if:` expressions use in these workflows, and the ones
# a plausible future edit would add. Anything outside this set is an ERROR.
_FUNCS = {
    "always": lambda ctx: True,
    "success": lambda ctx: not ctx.get("_failed", False),
    "failure": lambda ctx: bool(ctx.get("_failed", False)),
    "cancelled": lambda ctx: False,
    "hashFiles": lambda ctx, arg: arg in ctx.get("_paths", set()),
    "startsWith": lambda ctx, a, b: str(a).startswith(str(b)),
    "endsWith": lambda ctx, a, b: str(a).endswith(str(b)),
    "contains": lambda ctx, a, b: str(b) in str(a),
}


def _tokenize(expr: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(expr):
        if expr[i].isspace():
            i += 1
            continue
        m = _TOKEN.match(expr, i)
        if not m or m.end() == i:
            raise WorkflowError(f"cannot tokenize condition at {expr[i:][:30]!r}")
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        i = m.end()
    return out


def eval_condition(expr: str | None, ctx: dict) -> bool:
    """Evaluate a GitHub `if:` expression. `None` means 'no condition' -> True.

    Unrecognised syntax raises. The default is deliberately NOT "runs": a
    simulator that assumes the permissive answer for anything it cannot parse
    would report every gate as reachable and pass, which is the false green
    this story exists to remove.
    """
    if expr is None or not str(expr).strip():
        return True
    text = str(expr).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    if text.startswith("${{") or text.endswith("}}"):
        raise WorkflowError(f"malformed ${{{{ }}}} wrapper in {expr!r}")
    toks = _tokenize(text)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else (None, None)

    def take():
        nonlocal pos
        t = toks[pos]
        pos += 1
        return t

    def primary():
        kind, val = take()
        if kind == "op" and val == "(":
            v = parse_or()  # noqa: F821 - nested mutually-recursive defs
            k2, v2 = take()
            if not (k2 == "op" and v2 == ")"):
                raise WorkflowError(f"unbalanced parenthesis in {expr!r}")
            return v
        if kind == "str":
            return val[1:-1].replace("''", "'")
        if kind == "num":
            return int(val)
        if kind == "ident":
            if peek() == ("op", "("):
                take()
                args = []
                if peek() != ("op", ")"):
                    while True:
                        args.append(primary())
                        if peek() == ("op", ","):
                            take()
                            continue
                        break
                k2, v2 = take()
                if not (k2 == "op" and v2 == ")"):
                    raise WorkflowError(f"unbalanced call in {expr!r}")
                fn = _FUNCS.get(val)
                if fn is None:
                    raise WorkflowError(
                        f"the simulator does not model the function {val}() in "
                        f"{expr!r}. Refusing to guess: add it to _FUNCS or "
                        f"narrow the condition."
                    )
                try:
                    return fn(ctx, *args)
                except TypeError as exc:
                    raise WorkflowError(f"bad call to {val}() in {expr!r}: {exc}")
            if val == "true":
                return True
            if val == "false":
                return False
            if val in ctx:
                return ctx[val]
            raise WorkflowError(
                f"the simulator has no value for `{val}` in {expr!r}. Refusing "
                f"to guess: add it to the context or narrow the condition."
            )
        raise WorkflowError(f"unexpected token {val!r} in {expr!r}")

    def parse_cmp():
        left = primary()
        kind, val = peek()
        if kind == "op" and val in ("==", "!=", "<", ">", "<=", ">="):
            take()
            right = primary()
            if val == "==":
                return left == right
            if val == "!=":
                return left != right
            a, b = _as_num(left, right, expr)
            return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[val]
        return left

    def parse_not():
        if peek() == ("op", "!"):
            take()
            return not parse_not()
        return parse_cmp()

    def parse_and():
        v = parse_not()
        while peek() == ("op", "&&"):
            take()
            v = bool(v) and bool(parse_not())
        return v

    def parse_or():
        v = parse_and()
        while peek() == ("op", "||"):
            take()
            v = bool(v) or bool(parse_not())
        return v

    def _as_num(a, b, src):
        try:
            return int(a), int(b)
        except (TypeError, ValueError):
            raise WorkflowError(f"cannot order-compare in {src!r}")

    result = parse_or()
    if pos != len(toks):
        raise WorkflowError(f"trailing tokens in {expr!r}")
    return bool(result)


# --- the simulation --------------------------------------------------------


class Step:
    def __init__(self, job: str, name: str, cond: str | None, body: str):
        self.job, self.name, self.cond, self.body = job, name, cond, body


def _workflow_paths(on: dict) -> tuple[list[str] | None, list[str] | None]:
    """(`paths`, `paths-ignore`) from an `on:` block, as glob-lite patterns.

    Both levels matter and both exist: a filter can sit directly under `on:`
    or under the individual event (`on.pull_request.paths-ignore`). Reading
    only the top level would miss the far more common per-event form, which
    is exactly the shape a docs-only skip is written in.
    """
    paths = on.get("paths")
    ignore = on.get("paths-ignore")
    for _, event in (on or {}).items():
        if not isinstance(event, dict):
            continue
        if paths is None and event.get("paths") is not None:
            paths = event.get("paths")
        if ignore is None and event.get("paths-ignore") is not None:
            ignore = event.get("paths-ignore")
    return (
        _as_list(paths) if paths is not None else None,
        _as_list(ignore) if ignore is not None else None,
    )


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None:
        return []
    text = str(value).strip()
    if text.startswith("[") and text.endswith("]"):
        return [v.strip().strip("'\"") for v in text[1:-1].split(",") if v.strip()]
    return [text]


def _glob(path: str, pattern: str) -> bool:
    import fnmatch
    return fnmatch.fnmatch(path, pattern)


def collect_steps(changed: set[str], ctx: dict) -> tuple[list[Step], list[str]]:
    """Parse every workflow and return (steps that would run, notes)."""
    if not WORKFLOW_DIR.is_dir():
        raise WorkflowError(f"{WORKFLOW_DIR} missing")
    files = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    if not files:
        raise WorkflowError(f"no workflow files under {WORKFLOW_DIR}")
    steps: list[Step] = []
    notes: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        doc = _parse_yaml(text)
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            raise WorkflowError(f"{path.name}: no `jobs:` mapping parsed")
        # Cross-check: every `- ` item under a `steps:` key must have become a
        # parsed step, so a step the parser dropped cannot silently change the
        # answer. Counting every `- ` in the file would not do — a `paths:`
        # list is one too, and the check would fire on a workflow whose every
        # step parsed correctly.
        raw_steps = _steps_in_text(text)
        parsed_steps = sum(len(j.get("steps") or []) for j in jobs.values())
        if raw_steps != parsed_steps:
            raise WorkflowError(
                f"{path.name}: parsed {parsed_steps} step(s) but the file has "
                f"{raw_steps} `- ` item(s) under jobs — the parser lost one, and "
                f"a lost step would make a gate look unreachable (or reachable) "
                f"by accident."
            )
        on = doc.get("on") or {}
        if not isinstance(on, dict):
            on = {}
        paths, ignore = _workflow_paths(on)
        if paths is not None and not any(_glob(p, pat) for p in changed for pat in paths):
            notes.append(f"{path.name}: not triggered — `on.paths` excludes this change set")
            continue
        if ignore is not None and all(_glob(p, pat) for p in changed for pat in ignore):
            notes.append(f"{path.name}: not triggered — `on.paths-ignore` covers this change set")
            continue
        for jname, job in jobs.items():
            if not eval_condition(job.get("if"), dict(ctx, _failed=False)):
                notes.append(f"{path.name}:{jname}: job skipped by if: {job.get('if')}")
                continue
            for st in job.get("steps") or []:
                cond = st.get("if")
                if not eval_condition(cond, dict(ctx, _failed=False)):
                    notes.append(
                        f"{path.name}:{jname}/{st.get('name')}: step skipped by if: {cond}"
                    )
                    continue
                body = st.get("run")
                if body:
                    steps.append(Step(f"{path.name}:{jname}", str(st.get("name")), cond, body))
    return steps, notes


def gates_invoked(steps: list[Step]) -> set[str]:
    found: set[str] = set()
    for step in steps:
        for name in _re.findall(r"tests/scripts/(check_[A-Za-z0-9_]+\.py)", step.body):
            found.add(name)
    return found


def all_gate_scripts() -> set[str]:
    return {p.name for p in SCRIPT_DIR.glob("check_*.py")}


# Three change sets that must all reach the full gate set:
#   1. docs only,
#   2. docs plus a gate script (the story's own subject),
#   3. device source.
CHANGE_SETS = {
    "docs-only": {"docs/size-report.md", "docs/erase-budget.md", "docs/bootsel.md"},
    "docs-plus-gate-script": {
        "docs/size-report.md",
        "tests/scripts/check_persist_gate.py",
    },
    "docs-plus-ci-workflow": {
        "docs/hardware-matrix.md",
        ".github/workflows/ci.yml",
    },
    "device-source": {"firmware/src/main.rs", "platform/src/trng.rs"},
}


def check_gates_run_on_docs_only() -> tuple[list[str], bool]:
    """Return (failures, ok) for the US-1042 reachability assertion."""
    failures: list[str] = []
    scripts = all_gate_scripts()
    required = scripts - set(CI_EXCLUSIONS)
    for label, changed in CHANGE_SETS.items():
        ctx = {
            "github.event_name": "pull_request",
            "github.ref": "refs/heads/main",
            # A GitHub expression compares STRINGLY, and a non-empty string
            # is truthy — so `if: ${{ docs_only }}` is true for 'false' too.
            # Modelling `docs_only` as a Python bool would quietly miss exactly
            # the condition this story is about, which is why it is the string
            # 'true' / 'false' here.
            "docs_only": "true" if all(c.startswith("docs/") for c in changed) else "false",
            # The sibling pytest harness repo is checked out by the workflows
            # themselves, so `hashFiles` over it is satisfied in the simulated
            # world; the gates under test are not gated on it either way.
            "_paths": {"pico-fido2/tests/requirements.txt"},
        }
        steps, notes = collect_steps(changed, ctx)
        invoked = gates_invoked(steps)
        missing = sorted(required - invoked)
        if missing:
            failures.append(
                f"[{label}] {len(missing)} gate script(s) are not invoked by any "
                f"step that would run: {', '.join(missing)}"
            )
        else:
            print(f"  [{label}] all {len(required)} required gates run "
                  f"({len(invoked)} gate script(s) invoked in total)")
    return failures, not failures


# ---------------------------------------------------------------------------
# US-1043: is the reproducible-build / flash-budget ratchet actually wired?
# ---------------------------------------------------------------------------
#
# The ratchet is a shell step, not a gate script, so nothing in the mutation
# table can reach it. It gets its own structural assertion here, on the PARSED
# step model rather than on the raw YAML: a step that has drifted (lost its
# second build, lost its `cmp`, grown an `if:`) fails here instead of quietly
# becoming a build that nobody checks twice.

BUDGET_ENV_VAR = "FIRMWARE_FLASH_BUDGET_KIB"


def check_ram_ceiling_is_derived_and_biting() -> list[str]:
    """The US-1010 RAM ceiling must be `RAM − CHAIN_CEILING`, and it must bite.

    Two properties, both load-bearing, neither of which the gate run itself
    demonstrates (on a healthy build the RAM check never fires, which is
    indistinguishable from a check that cannot fail — the exact defect class
    this harness exists to catch):

    1. **Derived, not invented.** ``RAM_CEILING`` must be the board's SRAM
       minus the stack ceiling the other gate enforces, taken from the same two
       sources. A round number chosen for looks would pass the healthy build
       and mean nothing.
    2. **Biting.** The `bss` figure the rejected 32-entry secure store
       actually produced must exceed it. That build is recorded in
       ``docs/known-gate-divergences.md`` SF-1 as +36,288 B of bss on a
       freshly nuked flash: it booted nowhere, and the only reason it was found
       was that a human flashed it. A ceiling that would have passed that
       build is not a ceiling.
    """
    failures: list[str] = []
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        import check_size_report as csr
    except Exception as exc:  # noqa: BLE001 — a refusal to guess is a FAIL
        return [f"check_size_report.py would not import: {exc!r}"]

    ram_origin, ram_total, _script = csr.ram_bytes()
    ceiling = ram_total - csr.CHAIN_CEILING
    if ram_origin != 0x2000_0000:
        failures.append(
            f"the generated memory.x puts RAM at {ram_origin:#010x}; the RP2350 map is "
            f"contiguous from 0x20000000 on every part in this family, so a different "
            f"origin means this check's model of the address map is wrong"
        )
    if csr.CHAIN_CEILING != 96 * 1024:
        failures.append(
            f"the RAM ceiling is derived from CHAIN_CEILING = {csr.CHAIN_CEILING}, which is "
            f"not the 98,304 B check_boot_chain.py has enforced since US-956 — if that "
            f"number moved deliberately, re-derive this check's expectation too"
        )
    if ceiling <= 0 or ceiling >= ram_total:
        failures.append(
            f"the derived RAM ceiling ({ceiling}) is not a real bound on {ram_total} B of "
            f"SRAM; a ceiling that admits every byte gates nothing"
        )

    # The historical regression, from SF-1. If this number stops exceeding the
    # ceiling the ceiling is too loose to be worth having.
    recorded_bss = 420_476          # Berkeley bss at the 24-entry tip
    dark_boot_growth = 36_288       # SF-1: the 32-entry build, hardware-rejected
    dark_boot_bss = recorded_bss + dark_boot_growth
    if dark_boot_bss <= ceiling:
        failures.append(
            f"the 32-entry build's recorded bss ({dark_boot_bss} B = {recorded_bss} + "
            f"{dark_boot_growth}) would PASS the derived ceiling ({ceiling} B). That build "
            f"dark-locked a freshly nuked board (SF-1), so the ceiling is too loose to catch "
            f"the regression it was added for — tighten it or record why the 24-entry tip's "
            f"bss figure is wrong."
        )

    # …and the current build must actually sit inside it, with the headroom
    # the PASS line claims.
    current_bss = None
    doc = REPO_ROOT / "docs" / "size-report.md"
    if doc.exists():
        m = _re.search(r"\*\*`\.bss` = ([\d,]+) B\*\*", doc.read_text(encoding="utf-8"))
        if m:
            current_bss = int(m.group(1).replace(",", ""))
    if current_bss is not None:
        if current_bss > ceiling:
            failures.append(
                f"docs/size-report.md records bss {current_bss} B, already over the derived "
                f"ceiling {ceiling} B — check_size_report.py would be failing on this tree"
            )
        elif ceiling - current_bss > 40_000:
            failures.append(
                f"the RAM ceiling leaves {ceiling - current_bss} B of headroom over the "
                f"recorded bss — that is a gate with nothing to say, not a ratchet. "
                f"check_size_report.py's own PASS line prints the figure; keep them in step."
            )
    return failures


def check_repro_ratchet_wired() -> list[str]:
    """Return a list of failures (empty == the ratchet is wired and unconditional)."""
    failures: list[str] = []
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        doc = _parse_yaml(path.read_text(encoding="utf-8"))
        env = doc.get("env") or {}
        budget = env.get(BUDGET_ENV_VAR)
        if budget is None:
            continue
        if not str(budget).isdigit() or int(budget) <= 0:
            failures.append(
                f"{path.name}: {BUDGET_ENV_VAR} = {budget!r} is not a positive "
                f"integer of KiB — a budget nobody can compare against is not a "
                f"ratchet."
            )
        found = 0
        for jname, job in (doc.get("jobs") or {}).items():
            for st in job.get("steps") or []:
                body = st.get("run") or ""
                if BUDGET_ENV_VAR not in body and "NOT reproducible" not in body:
                    continue
                found += 1
                where = f"{path.name}:{jname}/{st.get('name')}"
                if st.get("if"):
                    failures.append(
                        f"{where}: the ratchet step is conditioned on "
                        f"`{st['if']}` — a build check that a change set can skip "
                        f"is a build check that does not run."
                    )
                for needle, why in (
                    ("cargo build", "no build at all"),
                    ("CARGO_TARGET_DIR", "the second build reuses the first build's target "
                                         "directory, so it is not an independent build"),
                    # The GUARD, not the command: `cmp ... || true` still
                    # contains the command, and a comparison whose failure is
                    # swallowed is exactly the drift this check exists for.
                    ('if ! cmp -s "$ELF" "$REPRO_ELF"; then',
                     "the two ELFs are not compared under a guard that exits "
                     "non-zero — `cmp ... || true` would satisfy a substring "
                     "check while comparing nothing"),
                    (BUDGET_ENV_VAR, "the budget constant is not read by the step that declares it"),
                    # The UF2 comparison, matched up to the end of its line: a
                    # bare `cmp` under `set -e` already fails the step, and
                    # appending `|| true` to it is the only way to neuter it.
                    ("cmp /tmp/fapico2-a.uf2 /tmp/fapico2-b.uf2\n",
                     "the two flashable images are not compared, or the "
                     "comparison's failure is swallowed"),
                    ('if [ "$SHIPPING" -gt "$BUDGET_BYTES" ]; then',
                     "the shipping image is never compared against the budget "
                     "under a guard that exits non-zero"),
                ):
                    if needle not in body:
                        failures.append(f"{where}: {why} (missing {needle!r}).")
        if found != 1:
            failures.append(
                f"{path.name}: {found} step(s) use {BUDGET_ENV_VAR}, expected exactly "
                f"one. Two copies of a ratchet is two ceilings to keep in step; none "
                f"is no ratchet."
            )
    if not any(BUDGET_ENV_VAR in str(v) for v in _all_env_values()):
        failures.append(
            f"no workflow defines {BUDGET_ENV_VAR} — US-1043's flash-budget "
            f"ratchet is not wired into CI at all."
        )
    return failures


def _all_env_values():
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        yield (path.name, (_parse_yaml(path.read_text(encoding="utf-8")).get("env") or {}))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", action="append", default=[],
                    help="run only this gate (repeatable)")
    ap.add_argument("--list", action="store_true", help="list the entries and exit")
    ap.add_argument("--workflows-only", action="store_true",
                    help="run only the US-1042 reachability simulation")
    ap.add_argument("--no-workflows", action="store_true",
                    help="skip the US-1042 reachability simulation")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="per-gate wall-clock ceiling in seconds")
    ap.add_argument("--keep", action="store_true",
                    help="do not delete the temp tree (for debugging a break)")
    args = ap.parse_args(argv[1:])

    selected = GATES
    if args.only:
        wanted = set(args.only)
        unknown = wanted - {g.name for g in GATES}
        if unknown:
            print(f"unknown gate(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        selected = tuple(g for g in GATES if g.name in wanted)

    if args.list:
        for g in selected:
            mark = "break" if g.breaks else "NO BREAK"
            extra = " (waiver)" if g.waiver else ""
            print(f"{g.name:38s} {mark}{extra}  {g.note}")
        return 0

    failed = False

    # --- US-1042: reachability, first, because it is instant ---------------
    if not args.no_workflows and (args.workflows_only or not args.only):
        print(f"\n=== US-1042: are the gates reachable from a docs-only change? ===")
        print(f"workflows: {', '.join(sorted(p.name for p in WORKFLOW_DIR.glob('*.y*ml')))}")
        for name, reason in sorted(CI_EXCLUSIONS.items()):
            print(f"  [EXCLUDED from CI] {name} — {reason}")
        try:
            wf_failures, ok = check_gates_run_on_docs_only()
        except WorkflowError as exc:
            wf_failures = [f"the simulator refuses to guess: {exc}"]
            ok = False
        try:
            wf_failures += check_repro_ratchet_wired()
            ok = ok and not wf_failures
        except WorkflowError as exc:
            wf_failures.append(f"the ratchet check refuses to guess: {exc}")
            ok = False
        try:
            wf_failures += check_ram_ceiling_is_derived_and_biting()
            ok = ok and not wf_failures
        except WorkflowError as exc:
            wf_failures.append(f"the RAM-ceiling check refuses to guess: {exc}")
            ok = False
        for f in wf_failures:
            print(f"  FAIL: {f}")
        print("  " + ("RESULT: PASS (every gate runs on a docs-only change, the "
                     "US-1043 ratchet is wired and unconditional, and the US-1010 "
                     "RAM ceiling is derived and bites)"
                     if ok else "RESULT: FAIL"))
        failed = failed or not ok
        if args.workflows_only:
            return 1 if failed else 0

    # --- US-1040/US-1041: the mutation table -------------------------------
    print(f"\nUS-1040/US-1041 gate mutation harness ({REPO_ROOT})")
    print(f"{len(selected)} gate(s) selected; each is run twice, on a copy.")

    workspace = Path(tempfile.mkdtemp(prefix="fapico2-gate-mutation-"))
    rows: list[dict] = []
    try:
        for n, gate in enumerate(selected):
            slot = workspace / f"{n:02d}-{gate.name.removesuffix('.py')}"
            try:
                rows.append(check_gate(gate, slot, args.timeout))
            except HarnessError as exc:
                rows.append({
                    "gate": gate.name,
                    "status": "HARNESS-ERROR",
                    "detail": str(exc),
                    "baseline_rc": None,
                    "broken_rc": None,
                    "seconds": 0.0,
                })
    finally:
        if not args.keep:
            shutil.rmtree(workspace, ignore_errors=True)
        else:
            print(f"\ntemp tree kept at {workspace}")

    print("\n=== gate mutation results ===")
    width = max(len(r["gate"]) for r in rows)
    for r in rows:
        print(f"  {r['status']:16s} {r['gate']:<{width}s} "
              f"baseline={r['baseline_rc']} broken={r['broken_rc']} "
              f"({r['seconds']:.1f}s)")
        if r["status"] != "MUTATED":
            print(f"      {r['detail']}")

    covered, total, mutated = summarise(rows)
    waived = sum(1 for r in rows if r["status"] == "WAIVED-VERIFIED")
    print(f"\nmutation-covered: {covered}/{total} "
          f"({mutated} by a nominated break, {waived} by a verified waiver)")

    bad = [r for r in rows if r["status"] not in ("MUTATED", "WAIVED-VERIFIED")]
    if bad:
        print(f"\nRESULT: FAIL ({len(bad)} gate(s) are not mutation-covered: "
              + ", ".join(f"{r['gate']}={r['status']}" for r in bad) + ")")
        failed = True
    else:
        print("\nRESULT: PASS (every gate is mutation-covered — each has been "
              "observed to go red on a nominated break, or is covered by a "
              "waiver that was itself checked)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
