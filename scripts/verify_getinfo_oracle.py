#!/usr/bin/env python3
"""US-1611 / US-1612 — measure the getInfo encrypted-state oracle on hardware.

Polls ``authenticatorGetInfo`` N times over CTAPHID with no state-changing
command in between and reports how many distinct IV halves and how many
distinct ciphertext halves each encrypted-state field produced.

Before US-1609 the answer was 10/10 IVs and **1/10 ciphertexts**: the plaintext
is an HMAC over the signature counter, so a repeating ciphertext is a free
oracle for assertion activity on a device that requires a PIN. After the fix
both halves must be N/N.

Run it before and after flashing; the two captures are the evidence US-1611
and US-1612 record.

    scripts/verify_getinfo_oracle.py            # 10 polls, human summary
    scripts/verify_getinfo_oracle.py -n 20      # more polls
    scripts/verify_getinfo_oracle.py --json out.json

Exit codes
----------
    0  no oracle: every ciphertext distinct (the fixed behaviour)
    1  the oracle is present: two polls returned an identical ciphertext
    2  the device or the client stack could not be reached

Why a script and not a test
---------------------------
It needs a real board: the emulator runs the **host** twin (``app.rs``), which
never had the defect, so a green ``cargo test`` says nothing about whether the
shipped image is fixed. That asymmetry is the whole reason this is a script —
and it is worth knowing before trusting either result alone.
"""

from __future__ import annotations

import argparse
import json
import sys

try:
    from fido2.ctap2 import Ctap2
    from fido2.hid import list_devices
except ImportError:  # pragma: no cover - environment problem, not a result
    print("fido2 is not importable; run this with the test venv's interpreter",
          file=sys.stderr)
    raise SystemExit(2)

#: One AES block, and the field is two of them (IV ‖ ciphertext).
#: CTAP 2.2 §5.1.2; `tests/getinfo.rs` asserts the same lengths host-side.
BLOCK = 16
FIELD = 2 * BLOCK


def poll(device, n: int) -> list[dict]:
    """`n` consecutive unauthenticated getInfo calls, nothing in between."""
    out = []
    with device as handle:
        ctap = Ctap2(handle)
        for _ in range(n):
            out.append(ctap.get_info())
    return out


def halves(value: bytes, name: str) -> tuple[bytes, bytes]:
    if len(value) != FIELD:
        # A wrong length is a different defect and must not be scored as
        # "the oracle" or "no oracle" — it is reported as itself.
        raise SystemExit(
            f"{name} is {len(value)} bytes, expected {FIELD}; "
            "this is a shape defect, not an oracle measurement"
        )
    return value[:BLOCK], value[BLOCK:]


def report(label: str, values: list[bytes]) -> dict:
    ivs, cts = set(), set()
    for v in values:
        iv, ct = halves(v, label)
        ivs.add(iv)
        cts.add(ct)
    return {
        "field": label,
        "samples": len(values),
        "distinct_ivs": len(ivs),
        "distinct_ciphertexts": len(cts),
        "raw": [v.hex() for v in values],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-n", "--polls", type=int, default=10,
                    help="consecutive unauthenticated getInfo calls (default 10)")
    ap.add_argument("--json", metavar="PATH", help="also write the full capture")
    args = ap.parse_args()

    try:
        device = next(iter(list_devices()))
    except StopIteration:
        print("no CTAPHID device found — is the board plugged in?",
              file=sys.stderr)
        return 2

    infos = poll(device, args.polls)
    first = infos[0]

    cred = report("encCredStoreState (0x1E)", [i.enc_cred_store_state for i in infos])
    ident = report("encIdentifier (0x19)", [i.enc_identifier for i in infos])

    print(f"device : {first.versions}  aaguid {first.aaguid.hex()}")
    print(f"PIN    : clientPin={first.options.get('clientPin')} "
          f"alwaysUv={first.options.get('alwaysUv')} "
          f"makeCredUvNotRqd={first.options.get('makeCredUvNotRqd')}")
    print(f"polls  : {args.polls} consecutive unauthenticated getInfo calls\n")
    for r in (cred, ident):
        print(f"{r['field']}: distinct IVs {r['distinct_ivs']}/{r['samples']}, "
              f"distinct ciphertexts {r['distinct_ciphertexts']}/{r['samples']}")

    for r in (cred, ident):
        if r["distinct_ciphertexts"] < r["samples"]:
            print(f"\nORACLE PRESENT in {r['field']}: "
                  f"{r['samples'] - r['distinct_ciphertexts']} of {r['samples']} "
                  "ciphertexts repeated. An unauthenticated reader can tell "
                  "'no assertion happened' from 'an assertion happened'.",
                  file=sys.stderr)
            return 1

    print("\nNo oracle: every ciphertext distinct, on a device that "
          f"reports clientPin={first.options.get('clientPin')}.")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({
                "polls": args.polls,
                "versions": first.versions,
                "aaguid": first.aaguid.hex(),
                "options": {k: v for k, v in first.options.items()},
                "enc_cred_store_state": cred,
                "enc_identifier": ident,
            }, fh, indent=2)
        print(f"capture written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())