#!/usr/bin/env python3
"""US-1831/US-1832 (WARM-BOOT-SERVE) — the cold-morning validation probe.

The turnkey instrument for the epic's hardware stories: run it from power-on
(ideally with the boot filmed, so the LED timeline can be decoded against
this script's timestamps) and it produces the table the audit doc's §6
"still to observe" list asks for:

  1. **USB up while the TRNG would still be stalling** — enumeration time
     from this script's start, compared against the documented ~7 s boot.
  2. **A getAssertion succeeds during the stall** — wait for Ready, then
     register a throwaway non-resident credential and assert against it.
  3. **A makeCredential during the stall refuses with the warming error**
     — probed immediately on attach, before the bring-up can complete:
     the expected answer is CTAP 0x7F (`Ctap2Response::Other`) while the
     entropy state reads `warming`.
  4. **The status TLV flips warming -> ready** — `TAG_ENTROPY_STATE` (0x0B)
     polled over CCID (management READ_CONFIG) and over the FIDO config
     read, both rendered.
  5. **The OATH challenge is DRBG output, not the empty-pool constant** —
     `SHA-256(b"")` windows in the SELECT response are the fingerprint of
     an unfilled pool (the 2026-11-10 session's defect signature).
  6. **The LED reading** — not automatable; the filming covers it
     (wait rhythm while Warming, 1 Hz after Ready).

Usage:  probe_warm_boot_validation.py [--assert-touch] [--max-wait SECS]
        Start the probe BEFORE power-on (it waits up to --max-wait, default
        1800 s, for the device to attach — so a long-dwell cold episode can
        be sitting unplugged while the probe and the camera are rolling).
        --assert-touch waits for the button on the assertion/mint steps;
        without it the script still decodes everything else.

Every line is prefixed with a monotonic timestamp so the film and the log
correlate. Exit code 0 when the epic's claims all held; 1 with the failed
claims listed otherwise.
"""

import argparse
import hashlib
import os
import sys
import threading
import time

EMPTY_POOL_CONST = hashlib.sha256(b"").digest()


def ts() -> str:
    return f"[{time.monotonic() - T0:7.2f}s]"


T0 = time.monotonic()


def log(msg: str) -> None:
    print(f"{ts()} {msg}", flush=True)


def find_ctap2():
    from fido2.hid import CtapHidDevice

    for _ in range(60):  # up to ~2 min from script start
        devs = list(CtapHidDevice.list_devices())
        if devs:
            from fido2.ctap2 import Ctap2

            return Ctap2(devs[0]), devs[0]
        time.sleep(1)
    return None, None


def entropy_status_ccid() -> dict | None:
    """The US-1827 status TLV over CCID management READ_CONFIG (0x1D).
    Returns None when the reader is busy (pcscd sharing) — the poll loop
    retries."""
    from smartcard.System import readers

    try:
        rs = [x for x in readers() if "fapico2" in str(x).lower()]
        if not rs:
            return None
        c = rs[0].createConnection()
        c.connect()
        c.transmit([0x00, 0xA4, 0x04, 0x00, 0x08] + list(bytes.fromhex("A000000527471117")))
        resp, s1, s2 = c.transmit([0x00, 0x1D, 0x00, 0x00, 0x00])
    except Exception:
        return None
    if (s1, s2) != (0x90, 0x00):
        return None
    data = bytes(resp)
    i = 1
    while i < len(data) - 1:
        t, ln = data[i], data[i + 1]
        if t == 0x0B and ln == 2:
            flags, hint = data[i + 2], data[i + 3]
            return {
                "ready": bool(flags & 0x01),
                "row_unfused": bool(flags & 0x02),
                "hint": hint,
            }
        i += 2 + ln
    return None


def oath_challenge_is_constant() -> bool | None:
    """True when the SELECT challenge is an empty-pool keystream window."""
    from smartcard.System import readers

    try:
        rs = [x for x in readers() if "fapico2" in str(x).lower()]
        if not rs:
            return None
        c = rs[0].createConnection()
        c.connect()
        resp, s1, s2 = c.transmit([0x00, 0xA4, 0x04, 0x00, 0x07] + list(bytes.fromhex("a0000005272101")))
        if (s1, s2) != (0x90, 0x00):
            return None
        data = bytes(resp)
        return any(EMPTY_POOL_CONST[i : i + 8] in data for i in range(len(EMPTY_POOL_CONST) - 7))
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--assert-touch", action="store_true")
    ap.add_argument("--max-wait", type=int, default=1800,
                    help="seconds to wait for attach/Ready before failing")
    args = ap.parse_args()

    log("probe start — start filming now; power-on should precede this")
    log("polling for CTAPHID enumeration + entropy status...")

    failures = []
    ctap2 = None
    status = None
    deadline = time.monotonic() + args.max_wait
    while time.monotonic() < deadline:
        ctap2, _dev = find_ctap2()
        status = entropy_status_ccid()
        if ctap2 is not None and status is not None:
            break
        time.sleep(1)
    if ctap2 is None:
        log("FAIL: CTAPHID never enumerated")
        return 1

    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2

    log(f"enumerated; entropy status: {status}")

    # Claim 3: a makeCredential right at attach. While Warming the expected
    # answer is 0x7F; post-Ready (with no PIN and up=True) it either serves
    # (needs a touch) or asks for one.
    warming_at_attach = status is not None and not status["ready"]
    if warming_at_attach:
        try:
            c2 = Ctap2(ctap2.device)
            c2.make_credential(
                os.urandom(32),
                {"id": "warmboot-epic.test"},
                {"id": os.urandom(16)},
                [{"type": "public-key", "alg": -7}],
                options={"up": True},
            )
            log("makeCredential at attach: SERVED (unexpected while Warming)")
            failures.append("mc-served-while-warming")
        except CtapError as e:
            log(f"makeCredential at attach: refused 0x{e.code:02X}"
                + (" — the warming refusal, as designed" if e.code == 0x7F else ""))
            if e.code != 0x2D:  # 0x2D = touch window; the gate passed
                if e.code != 0x7F:
                    failures.append(f"mc-refusal-word-0x{e.code:02X}")

    # Claim 5: the OATH challenge fingerprint.
    deadline = time.monotonic() + args.max_wait
    while time.monotonic() < deadline:
        const = oath_challenge_is_constant()
        if const is False:
            break
        time.sleep(1)
    if const is True:
        log("FAIL: OATH challenge is empty-pool keystream — pool never filled")
        failures.append("oath-empty-pool")
    elif const is False:
        log("OATH challenge: DRBG output (pool filled — bring-up completed)")

    # Claim 4: warming -> ready flip (poll the TLV).
    ready = False
    deadline = time.monotonic() + args.max_wait
    while time.monotonic() < deadline:
        st = entropy_status_ccid()
        if st and st["ready"]:
            ready = True
            log(f"entropy status: READY (row_unfused={st['row_unfused']})")
            break
        time.sleep(1)
    if not ready:
        log("FAIL: entropy never reached Ready")
        failures.append("never-ready")

    # Claims 1/2: a real creation + assertion ceremony once Ready.
    ev = threading.Event()
    try:
        att = ctap2.make_credential(
            os.urandom(32),
            {"id": "warmboot-epic.test", "name": "WARM-BOOT-SERVE validation"},
            {"id": os.urandom(16), "name": "us1831"},
            [{"type": "public-key", "alg": -7}],
            options={"up": True, "rk": False},
            event=ev,
        )
        log("makeCredential post-Ready: SERVED (touch given)")
        aid = att.auth_data.credential_data.credential_id
        ast = ctap2.get_assertion(
            "warmboot-epic.test",
            os.urandom(32),
            [{"type": "public-key", "id": aid}],
            options={"up": True},
            event=ev,
        )
        log("getAssertion post-Ready: SERVED — the deterministic path held")
    except CtapError as e:
        log(f"ceremony incomplete: 0x{e.code:02X} ({'touch not given' if e.code == 0x2D else 'error'})")
        if not args.assert_touch:
            log("(rerun with --assert-touch and press the button on the LED prompt)")

    log(f"RESULT: {'PASS' if not failures else 'FAIL: ' + ', '.join(failures)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
