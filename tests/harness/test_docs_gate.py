"""US-164 docs gate: the README's PicoForge single-reader caveat must survive.

The story's RED test (``EPIC-fapico2-picoforge-compatibility.md``, US-164).
The constraint it protects is a **client-side** one — PicoForge takes the
first PC/SC reader and never iterates — so no firmware change can ever clear
it. That makes the README section the *only* place a user on a multi-reader
host can learn why they get ``Rescue Applet not found on device. Is it in
FIDO mode?`` from a token that is present and healthy, and what to do about
it. A later README rewrite that drops the caveat strands them with no way to
tell a client bug from a device fault, which is exactly the outcome this
gate exists to prevent.

The checks live in ``tests/scripts/check_picoforge_compat_docs.py`` (the house
shape for a docs gate — stdlib only, runnable from a shell as well as pytest)
and are imported rather than duplicated, so the two entry points can never
drift: this test and ``python3 tests/scripts/check_picoforge_compat_docs.py``
assert the same facts.

Two failure shapes are covered, and the second is the one that matters:

  * the section is gone;
  * the section keeps its heading and loses its substance — a rewritten
    section that still says "PicoForge compatibility" and no longer says why
    the error is misleading or that the firmware cannot fix it. Per-fact
    checks catch that; a heading-presence check would not, and neither would
    a "the words are still somewhere in the file" check, which is why the
    script slices the real section instead of matching the whole README.

Every failure names the fact that went missing and the section it belongs in.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# tests/harness/test_docs_gate.py -> parents[2] == fapico2/. Resolve the repo
# from the test file, never from the CWD: this suite is invoked from
# run_tests.sh, from tests/, and by hand, and the README must be the same file
# in all three.
REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"
GATE_SCRIPT = REPO_ROOT / "tests" / "scripts" / "check_picoforge_compat_docs.py"


def _load_gate():
    """Import the standalone gate module by path (it is not on sys.path)."""
    spec = importlib.util.spec_from_file_location(
        "check_picoforge_compat_docs", GATE_SCRIPT
    )
    if spec is None or spec.loader is None:  # pragma: no cover - setup error
        raise RuntimeError(f"cannot load docs gate script: {GATE_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_readme_documents_single_reader_constraint():
    """RED (pre-US-164): README.md has no *PicoForge compatibility* section at
    all, so nothing tells a multi-reader user that the failure is the client's
    and not the token's.

    GREEN: the section exists and carries every fact the story requires — the
    ``readers.next()`` behaviour with its client ``file:line`` citations, the
    wrong-card / ``6A82`` / ``Err``-not-``None`` outcome, the four-connects-
    per-LED-slot amplification, the client-side mitigation, the explicit "not
    fixable from the firmware" statement, the ``libccid_Info.plist`` cross-
    reference, and the borrowed RS-Key AAGUID note.
    """
    gate = _load_gate()
    assert README.is_file(), (
        f"US-164 docs gate: {README} is missing, so the PicoForge "
        "single-reader caveat cannot be documented at all."
    )

    text = README.read_text(encoding="utf-8")
    section = gate.read_section(text)
    assert section is not None, (
        "US-164: README.md no longer has a '## PicoForge compatibility' "
        "section.\n"
        "  missing fact: the single-reader caveat has nowhere to live.\n"
        "  belongs in:  a '## PicoForge compatibility' section in README.md, "
        "recording that PicoForge takes readers.next() off list_readers() and "
        "never iterates, that a foreign reader enumerated first answers 6A82 "
        "and makes try_rescue() return Err rather than None, that the "
        "mitigation is client-side, and that this is NOT fixable from the "
        "firmware."
    )

    findings = gate.check(text)
    assert not findings, (
        "US-164: README.md's '## PicoForge compatibility' section lost its "
        "substance — the caveat must not be hollowed out.\n"
        + "\n".join(f"  - {f}" for f in findings)
    )

    # The heading alone is not the caveat. A pointer stub satisfies every
    # per-fact regex only if the facts are present, but a future rewriter
    # could satisfy them with one clause each; the word floor makes a gutted
    # section fail on its own terms, with a message that says so.
    words = len(section.split())
    assert words >= gate.MIN_WORDS, (
        f"US-164: the '## PicoForge compatibility' section is only {words} "
        f"words (floor {gate.MIN_WORDS}). A heading plus a pointer to the "
        "upstream client is not the caveat — restore the full text: the "
        "reader-next() behaviour, the wrong-card 6A82 / Err-not-None outcome, "
        "the four-connects-per-LED-slot amplification, the client-side "
        "mitigation, the 'not fixable from the firmware' statement, the "
        "libccid_Info.plist cross-reference, and the borrowed AAGUID note."
    )
