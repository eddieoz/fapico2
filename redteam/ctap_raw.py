"""Shared plumbing for the fapico2 red-team probes.

`redteam_main()` gives every script one verdict convention, so a gate can run
them:

    exit 0  attack refused — the device held
    exit 1  EXPLOITED / partial compromise / defect observed — the signal
    exit 2  environment error (device absent, transport failure) — not a verdict

Also centralizes the hidraw path so `FA_HIDRAW` is honoured everywhere (the
QUALITY_AUDIT G3 ghost).
"""
import os, sys

DEV = os.environ.get("FA_HIDRAW", "/dev/hidraw8")


def redteam_main(title, attack, device_factory):
    """Run one `attack(device)` callable and translate its verdict to an exit code.

    `attack` returns (verdict, detail) with verdict in {"EXPLOITED",
    "partial", "refused"} — anything else raises through.
    """
    print("=== %s ===" % title)
    try:
        dev = device_factory()
    except Exception as e:
        print("  ENV ERROR: %s" % e)
        print("  (set FA_HIDRAW to the board's hidraw node; CCID needs pcscd)")
        return 2
    try:
        verdict, detail = attack(dev)
    except Exception as e:
        print("  ENV ERROR during attack: %s: %s" % (type(e).__name__, e))
        return 2
    print("  %-9s %s" % (verdict.upper(), detail))
    return 0 if verdict == "refused" else 1
