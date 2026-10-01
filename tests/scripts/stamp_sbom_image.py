#!/usr/bin/env python3
"""Record the shipping image's digest in the SBOM that ships beside it.

WHY THIS IS A SCRIPT AND NOT A STEP IN THE WORKFLOW
----------------------------------------------------
`check_artefact_agreement.py` (US-1064) refuses a release whose SBOM does not
carry `cdx:fapico2:uf2:sha256` — the digest of the UF2 itself. The committed
`supply-chain/sbom.cdx.json` cannot carry it, and must not try: the SBOM says
what the image is BUILT FROM, and that set is a property of the source tree,
so it belongs in git and is checked by `check_sbom.py` on every push. The
image's digest is a property of one build, so it belongs to the build, and is
stamped into the COPY that travels with the artefacts.

That is also the reason the committed SBOM is left byte-identical by this
script: if stamping reached back into `supply-chain/`, every release would
dirty the tree and `check_sbom.py` would start failing on a file that was
never wrong.

WHY OVERWRITING AN EXISTING DIGEST IS A REFUSAL
------------------------------------------------
Re-running a release is normal; re-running it with a DIFFERENT image is a
different release wearing the same tag. Silently overwriting would let the
second image inherit the first image's SBOM, which is exactly the class of
drift US-1043's staleness gate exists to end. Stamping the same digest twice
is a no-op, so the workflow stays re-runnable.

USAGE
-----
    python3 tests/scripts/stamp_sbom_image.py --image dist/fapico2.uf2 \\
                                              --sbom dist/sbom.cdx.json
"""

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

IMAGE_DIGEST_KEY = "cdx:fapico2:uf2:sha256"
UF2_NAME = "fapico2.uf2"


class Refusal(Exception):
    """A named check failed. The message is the finding."""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stamp(image: Path, sbom: Path) -> str:
    """Record `image`'s sha256 in `sbom`. Returns the digest recorded."""
    if not image.is_file():
        raise Refusal(
            f"the image {image} does not exist. There is no digest to record, "
            f"and an SBOM that describes no image is not evidence of one."
        )
    if not sbom.is_file():
        raise Refusal(
            f"the SBOM {sbom} does not exist. The committed "
            f"supply-chain/sbom.cdx.json is the input; a release without one "
            f"attached is the US-1062 red."
        )
    try:
        doc = json.loads(sbom.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise Refusal(f"{sbom} is not valid JSON: {exc}") from exc

    digest = sha256_file(image)
    metadata = doc.setdefault("metadata", {})
    properties = metadata.setdefault("properties", [])
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name") == IMAGE_DIGEST_KEY:
            existing = str(prop.get("value", "")).strip().lower()
            if existing == digest:
                return digest  # idempotent re-run
            if not re.fullmatch(r"[0-9a-f]{64}", existing):
                raise Refusal(
                    f"{sbom} already carries {IMAGE_DIGEST_KEY}={existing!r}, "
                    f"which is not a sha256. Refusing rather than replacing it: "
                    f"a malformed digest is evidence that something else wrote "
                    f"this file."
                )
            raise Refusal(
                f"{sbom} already records {IMAGE_DIGEST_KEY}={existing}, but "
                f"{image.name} hashes to {digest}.\n"
                f"  Two different images cannot both be described by one SBOM. "
                f"This is either a stale artefact directory or a tag that was "
                f"re-cut; re-run the build so the SBOM is copied fresh, or "
                f"delete the stale copy."
            )
    properties.append({"name": IMAGE_DIGEST_KEY, "value": digest})
    sbom.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return digest


def self_test() -> list[str]:
    """Stamp a real file, and refuse the two cases that must be refused."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        image = root / UF2_NAME
        image.write_bytes(b"\x00" * 2048 + b"fapico2")
        want = sha256_file(image)

        def fresh_sbom() -> Path:
            p = root / "sbom.cdx.json"
            p.write_text(json.dumps({
                "bomFormat": "CycloneDX", "specVersion": "1.5",
                "metadata": {"component": {"name": "fapico2-firmware"},
                             "properties": [{"name": "cdx:rustc:sbom:target:all_targets",
                                             "value": "all_targets"}]},
            }, indent=2) + "\n", encoding="utf-8")
            return p

        # 1. the happy path, and that the pre-existing property survives.
        sbom = fresh_sbom()
        got = stamp(image, sbom)
        doc = json.loads(sbom.read_text(encoding="utf-8"))
        names = [p["name"] for p in doc["metadata"]["properties"]]
        if got != want:
            problems.append(f"stamped {got}, expected {want}")
        if "cdx:rustc:sbom:target:all_targets" not in names:
            problems.append("stamping dropped a pre-existing SBOM property")
        if IMAGE_DIGEST_KEY not in names:
            problems.append("stamping did not record the image digest")

        # 2. idempotent: a second run on the same image is a no-op.
        try:
            if stamp(image, sbom) != want:
                problems.append("a re-run on the same image changed the answer")
        except Refusal as exc:
            problems.append(f"a re-run on the same image was refused: {exc}")

        # 3. a different image must NOT overwrite a recorded digest.
        other = root / "other.uf2"
        other.write_bytes(b"a different image entirely")
        try:
            stamp(other, sbom)
            problems.append("a second, different image was stamped over a "
                            "recorded digest")
        except Refusal:
            pass

        # 4. a malformed digest is evidence, not something to replace.
        bad = fresh_sbom()
        d = json.loads(bad.read_text(encoding="utf-8"))
        d["metadata"]["properties"].append({"name": IMAGE_DIGEST_KEY, "value": "nope"})
        bad.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
        try:
            stamp(image, bad)
            problems.append("a malformed recorded digest was silently replaced")
        except Refusal:
            pass

        # 5. no image at all.
        try:
            stamp(root / "absent.uf2", fresh_sbom())
            problems.append("a missing image was stamped as if it existed")
        except Refusal:
            pass
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image", help=f"the shipping image (usually dist/{UF2_NAME})")
    ap.add_argument("--sbom", help="the SBOM to stamp, in the artefact directory")
    args = ap.parse_args(argv[1:])

    if not (args.image and args.sbom):
        print("Stamp the image digest into the release SBOM (self-test when no "
              "paths are given)")
        problems = self_test()
        print("  ACCEPT  stamp        — the image digest is recorded, other "
              "properties survive")
        print("  ACCEPT  re-run       — stamping the same image twice is a no-op")
        print("  REFUSE  other-image  — a second image cannot overwrite a "
              "recorded digest")
        print("  REFUSE  bad-digest   — a malformed recorded digest is evidence, "
              "not something to replace")
        print("  REFUSE  no-image     — there is no digest to record")
        if problems:
            print()
            for p in problems:
                print(f"  FAIL: {p}")
            print("\nRESULT: FAIL")
            return 1
        print("\nRESULT: PASS")
        return 0

    image, sbom = Path(args.image), Path(args.sbom)
    try:
        digest = stamp(image, sbom)
    except Refusal as exc:
        print(f"  REFUSED: {exc}")
        print("\nRESULT: FAIL")
        return 1
    print(f"  {IMAGE_DIGEST_KEY} = {digest}")
    print(f"  recorded in {sbom} ({(sbom.stat().st_size)} B)")
    print("\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
