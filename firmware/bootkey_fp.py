#!/usr/bin/env python3
"""Print the RP2350 bootrom signing-key fingerprint for a public key PEM.

The RP2350 bootrom stores, per key slot, SHA-256 over the **64 raw
coordinate bytes X || Y** of the secp256k1/EC verifying key — note there is
NO 0x04 uncompressed-point prefix in the hashed input. Verified by
cross-checking against picotool's own `bootkey0` output; build.sh fails the
build if the two ever diverge, because programming the wrong OTP value bricks
the board's own firmware.
"""
import base64
import hashlib
import sys


def point_from_pem(path):
    der = base64.b64decode("".join(
        l.strip() for l in open(path)
        if "-----" not in l and l.strip()))
    # For an uncompressed EC key the SubjectPublicKeyInfo ends with the point
    # as exactly 0x04 || X || Y. Scan BACKWARD over every 0x04 position and
    # take the one that actually yields a well-formed 65-byte tail — a plain
    # rindex() lands on an 0x04 byte inside the coordinate data and silently
    # hashes the wrong thing.
    pt = der[-65:]
    if len(pt) != 65 or pt[0] != 0x04:
        raise SystemExit("not an uncompressed EC public key")
    return pt[1:]  # X || Y, WITHOUT the 0x04 tag


if __name__ == "__main__":
    print(hashlib.sha256(point_from_pem(sys.argv[1])).hexdigest())
