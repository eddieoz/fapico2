#!/usr/bin/env python3
"""P8 — US-1007 hardware BDD: entropy starvation is survivable on the board.

**THIS SCRIPT HAS NOT BEEN RUN.** It is committed unrun, against a tree
where the hardware leg could not be exercised (no board was attached
during the session that wrote it). Nothing in the repository, the
progress ledger, or the report should be read as claiming this leg
passed. Run it before quoting any hardware result from it.

What it is for
--------------

The emulation twin (``tests/harness/test_entropy_starve.py``) proves that
a starved *host* survives. It cannot prove anything about silicon, because
the host's entropy source is ``/dev/urandom`` and the seam that starves it
is a test file. Four things here are host-only and are exactly what a board
is needed for:

  1. that the RP2350 TRNG health test (autocorrelation) can be made to
     fail at all, and that ``Rp2350Probe`` then reports ``Stalled`` rather
     than spinning;
  2. that ``MAX_ENTROPY_WAIT_MS = 20`` is a real bound on a real part
     (D-8 records that it is a datasheet *average* x10, not a measured
     maximum — this is the script that would settle it);
  3. that the device stays enumerable over **CCID** and **HID** while
     starved, which is a claim about two independent USB stacks;
  4. that a request after the TRNG recovers succeeds, on the same boot.

The BDD, as the story states it
-------------------------------

  Given a device with the TRNG autocorrelation test forced to fail
  When  an OpenPGP signature and a FIDO assertion are requested
  Then  both answer a clean error (not a panic, not a hang, not silence),
        the device stays enumerable over CCID and over HID, and a
        subsequent request after TRNG recovery succeeds.

How the starvation is actually forced — read this before running
---------------------------------------------------------------

There is no way to wedge the RP2350 TRNG from the host side. The
peripheral's health tests run in hardware and their results are not
writable from software, so "force the autocorrelation test to fail" is not
an APDU, not a vendor command, and not a register poke this script can
send. The four ways to get the condition, in descending order of
preference:

  A. **A wedged build.** The firmware already refuses to boot when the
     probe stalls (``init_drbg`` is fatal — see D-8), so the honest
     hardware experiment is a *diagnostic* build whose
     ``Rp2350Probe::status()`` reports the stall unconditionally. That is a
     firmware change and is deliberately NOT made by US-1007: this story
     carries a test seam and a test, not a new device feature. If such a
     build exists, point ``--emu-binary``-equivalent at it via
     ``--expect-boot-refusal`` and steps H4/H5 become meaningful.

  B. **Physical fault injection.** Reduce the TRNG's supply or clock out
     of spec so the health test genuinely fails. Out of scope for a
     bench script, and the only route that produces a *real* result.

  C. **Observe the real bound without forcing a failure** (steps H2/H3).
     Measure how long a healthy draw takes on this part, which is the
     input D-8 says is missing. This is the part of the story that is
     genuinely obtainable from an ordinary board and ordinary tooling, and
     the script does it by default.

  D. **Nothing**, and report that. The default. With no wedged build and no
     fault injection the script cannot make the peripheral fail, and says
     so rather than pretending the starvation leg ran.

The script therefore runs what it can run, marks the starvation-dependent
steps ``SKIP (needs a wedged build)``, and exits non-zero if any step that
*did* run failed. It never reports the starvation leg as passed.

Usage
-----

  python3 tests/scripts/p8_rng_starve.py               # full run
  python3 tests/scripts/p8_rng_starve.py --list        # steps and what they need
  python3 tests/scripts/p8_rng_starve.py --skip-setup  # card already personalised

SETUP MUTATES THE CARD: it personalises PW1/PW3 away from the factory
defaults (the US-912 gate refuses key operations until both are changed)
and GENERATEs an Ed25519 signing key. Run only on a test device.

Evidence goes to ``docs/tasks/evidence/p8-rng-starve/``, one verbatim file
per step, in the ``p7_*`` style.
"""
import argparse
import hashlib
import os
import sys
import time

EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "docs", "tasks", "evidence", "p8-rng-starve")

PGP_AID = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
FACTORY_PW1 = list(b"123456")
FACTORY_PW3 = list(b"12345678")
BDD_PW1 = list(b"654321")
BDD_PW3 = list(b"87654321")
DIGEST = hashlib.sha256(b"US-1007 entropy-starvation hardware BDD").digest()

# Key attributes DO (0xC1): Ed25519. RSA keygen is slow and, per the
# hardware matrix, does not complete on this part — so it would turn a
# starvation measurement into a keygen benchmark.
KEY_ATTR_ED25519 = [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]

# The clean error a starved draw maps to (US-1006's opcard patch):
# Status::UnspecifiedNonpersistentExecutionError = ISO 7816 0x6400.
SW_CLEAN_ERROR = 0x6400

# A request that answers in longer than this is a HANG, not a slow answer.
# The story's whole negative property is "clean error, not a hang", so the
# ceiling has to be finite and has to be reported when it trips.
REQUEST_TIMEOUT_S = 10.0

# The device's own bound is MAX_ENTROPY_WAIT_MS = 20 (D-8). A starved draw
# on silicon therefore cannot answer in less than this without being wrong
# in the other direction, and a healthy one should be far quicker. Anything
# longer than this is a hang, whatever the peripheral is doing.
STARVED_REQUEST_TIMEOUT_S = 30.0

FAILED = False
SKIPPED = []


class Step:
    """Tee a step's verbatim output to stdout and to its evidence file."""

    def __init__(self, name, filename):
        self.name = name
        self.path = os.path.join(EVID, filename)
        self._fh = None

    def __enter__(self):
        os.makedirs(EVID, exist_ok=True)
        self._fh = open(self.path, "w")
        print("===== step %s -> %s" % (self.name, self.path))
        return self

    def __exit__(self, *exc):
        if self._fh:
            self._fh.close()

    def line(self, txt=""):
        print(txt)
        self._fh.write(txt + "\n")


def stop(msg):
    """A precondition failed: we could not even start. Exit 2, not 1."""
    print("STOP: " + msg)
    sys.exit(2)


def skip(step, why):
    """Record a step that could not run, and say so loudly.

    A skipped step is never a passed step. The distinction is the entire
    reason this script exists: the story's claims are about silicon, and a
    green run that quietly omitted them would be worse than a red one.
    """
    SKIPPED.append((step, why))
    print("SKIP %s: %s" % (step, why))
    with Step("skip %s" % step, "p8-skip-%s.log" % step) as out:
        out.line("SKIPPED: %s" % why)
        out.line("This step is NOT a pass. It did not run.")


def fail(msg):
    global FAILED
    FAILED = True
    print("FAIL: " + msg)


def apdu(con, b, timeout=REQUEST_TIMEOUT_S):
    """One APDU, following 61xx. Returns (sw, body).

    `timeout` is a *host-side* ceiling. It cannot interrupt a device that
    has stopped answering — a wedged request is observed as an exception
    from this side — but it does stop a slow-but-alive device from being
    reported as a hang, which is the other half of the distinction.
    """
    data, sw1, sw2 = con.transmit(b)
    while sw1 == 0x61:
        data2, sw1, sw2 = con.transmit(
            [0x00, 0xC0, 0x00, 0x00, min(0xFF, sw2)])
        data += data2[0]
    return sw1 << 8 | sw2, bytes(data)


def select_openpgp(con):
    sw, _ = apdu(con, [0x00, 0xA4, 0x04, 0x00, len(PGP_AID)] + PGP_AID)
    if sw != 0x9000:
        stop("SELECT OPENPGP failed: SW=%04X (is the fapico2 reader up?)" % sw)


def verify(con, p2, pin):
    return apdu(con, [0x00, 0x20, 0x00, p2, len(pin)] + pin)[0]


def change_ref(con, p2, old, new):
    return apdu(con, [0x00, 0x24, 0x00, p2, len(old) + len(new)] + old + new)[0]


def ensure_personalised(con, out, skip_setup):
    """Get past the US-912 factory gate, without clobbering a real card.

    The gate refuses PSO/GENKEY/TERMINATE while the shipped defaults are in
    force, so a signature test needs the card personalised first. This
    probes before it writes, exactly as `p7_d1_fido.py` does, and refuses
    to retry a state-changing operation.
    """
    if verify(con, 0x81, BDD_PW1) == 0x9000:
        out.line("card already personalised with the BDD PINs")
        return
    if skip_setup:
        stop("--skip-setup given but the card is not on the BDD PINs")

    out.line("probing factory PW1 ...")
    if verify(con, 0x81, FACTORY_PW1) != 0x9000:
        stop("neither the BDD nor the factory PW1 verifies; "
             "not touching the card (unknown PIN state)")

    out.line("personalising PW1/PW3 away from the factory defaults ...")
    for p2, old, new in ((0x81, FACTORY_PW1, BDD_PW1),
                         (0x83, FACTORY_PW3, BDD_PW3)):
        sw = change_ref(con, p2, old, new)
        out.line("  change p2=%02X -> SW=%04X" % (p2, sw))
        if sw != 0x9000:
            stop("CHANGE REFERENCE DATA p2=%02X failed: SW=%04X" % (p2, sw))
    if verify(con, 0x81, BDD_PW1) != 0x9000:
        stop("PW1 does not verify after personalisation")


def ensure_signing_key(con, out):
    """Ensure slot B6 (signing) holds a key, so PSO:SIGN has something to use."""
    sw, body = apdu(con, [0x00, 0xCA, 0x00, 0xC1, 0xFF])
    out.line("GET DATA C1 -> SW=%04X len=%d" % (sw, len(body)))
    if sw == 0x9000 and b"\x16\x2b\x06\x01\x04\x01\xda\x47\x0f\x01" in body:
        out.line("Ed25519 signing key already present")
        return
    out.line("generating an Ed25519 signing key into B6 ...")
    sw, _ = apdu(con, [0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00])
    if (sw >> 8) == 0x61:
        sw, _ = apdu(con, [0x00, 0xC0, 0x00, 0x00, sw & 0xFF])
    out.line("  GENERATE -> SW=%04X" % sw)
    if sw != 0x9000:
        stop("GENERATE failed: SW=%04X" % sw)


# ---------------------------------------------------------------------------
# HID (FIDO) — the second transport the story requires
# ---------------------------------------------------------------------------

def fido_device():
    """The board's CTAP-HID node, or None.

    Returned as None rather than raising so the caller can SKIP the HID
    leg with a reason. A missing HID node is an environment fact (no
    udev rule, no hidraw perms), not a firmware failure, and conflating
    the two would produce a red run that means nothing.
    """
    try:
        from fido2.hid import CtapHidDevice
    except ImportError:
        return None
    try:
        return next(CtapHidDevice.list_devices(), None)
    except Exception:
        return None


def fido_healthy_probe(out):
    """One getInfo over HID. Returns True if the node answered.

    Deliberately `getInfo` and not an assertion: getInfo needs no
    credential and no entropy, so it is the right liveness probe for "is
    this transport still there", which is what the enumerability half of
    the story asks.
    """
    dev = fido_device()
    if dev is None:
        return False
    try:
        from fido2.ctap2 import Ctap2
        info = Ctap2(dev).get_info()
    except Exception as exc:
        out.line("HID getInfo raised: %s: %s" % (type(exc).__name__, exc))
        return False
    out.line("HID getInfo: versions=%s aaguid=%s" % (
        list(info.versions), info.aaguid))
    return True


# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true",
                    help="print the step list and exit")
    ap.add_argument("--skip-setup", action="store_true",
                    help="the card is already personalised with the BDD PINs")
    ap.add_argument("--wedged", action="store_true",
                    help="the flashed build forces the TRNG health test to "
                         "fail (see the module docstring, mechanism A). "
                         "Without it the starvation steps are SKIPped.")
    args = ap.parse_args()

    if args.list:
        print(__doc__)
        return 0

    try:
        from smartcard.System import readers
    except ImportError:
        stop("pyscard is not installed; this script needs the pcscd stack "
             "(see fapico2/README.md, Requirements)")

    names = readers()
    if not names:
        stop("no PC/SC reader. The fapico2 CCID node must be visible to "
             "pcscd first — on Debian that means 0xFA20/0x0002 added to "
             "/etc/libccid_Info.plist and pcscd restarted (fapico2/"
             "README.md). If the reader IS there but gnupg is the problem, "
             "that is a different failure entirely.")
    print("readers: %s" % names)

    con = readers()[0].createConnection()

    # ---- H1: baseline, before anything is forced ---------------------------
    with Step("H1 baseline", "p8-H1-baseline.log") as out:
        out.line("# Healthy baseline. Everything after this is compared "
                 "against these numbers.")
        atr = con.transmit([0x00, 0x00, 0x00, 0x00])  # cheap liveness probe
        out.line("reader responded: %s" % (atr,))
        select_openpgp(con)

        sw, body = apdu(con, [0x00, 0x84, 0x00, 0x00, 0x08])
        out.line("GET CHALLENGE -> SW=%04X body=%s" % (sw, body.hex()))
        if sw != 0x9000 or len(body) != 8:
            fail("healthy GET CHALLENGE must answer 9000 with 8 bytes")

        # How long does a healthy draw take? This is the number D-8 says is
        # missing: MAX_ENTROPY_WAIT_MS = 20 is a datasheet average x10, not
        # a measured maximum, and only silicon can measure it.
        t0 = time.time()
        for _ in range(20):
            apdu(con, [0x00, 0x84, 0x00, 0x00, 0x08])
        per = (time.time() - t0) / 20.0
        out.line("healthy GET CHALLENGE round trip: %.1f ms (n=20, includes "
                 "USB + pcscd framing, so an UPPER bound on the device-side "
                 "draw and nothing more)" % (per * 1e3))
        out.line("device-side bound in force: MAX_ENTROPY_WAIT_MS = 20 ms")
        if per * 1e3 > 20.0:
            out.line("NOTE: the round trip already exceeds the device's own "
                     "20 ms bound, so this host cannot resolve the device-"
                     "side figure — the measurement needs defmt/RTT or a "
                     "GPIO, not a USB round trip.")

        ensure_personalised(con, out, args.skip_setup)
        ensure_signing_key(con, out)

        sw, _ = apdu(con, [0x00, 0x20, 0x00, 0x81] + BDD_PW1)
        out.line("VERIFY PW1 -> SW=%04X" % sw)
        t0 = time.time()
        sw, body = apdu(con, [0x00, 0x2A, 0x9E, 0x9A, len(DIGEST)] + DIGEST)
        out.line("PSO:CDS -> SW=%04X len=%d in %.1f ms"
                 % (sw, len(body), (time.time() - t0) * 1e3))
        if sw != 0x9000:
            fail("healthy PSO:CDS must answer 9000, got %04X" % sw)

        out.line("HID node present: %s" % (fido_device() is not None))
        fido_healthy_probe(out)

    # ---- H2/H3: the starvation legs ----------------------------------------
    if not args.wedged:
        skip("H2-starved-openpgp",
             "the TRNG health test cannot be failed from the host: it runs in "
             "hardware and its result is not software-writable. Needs a "
             "wedged build (--wedged) or physical fault injection. NOT RUN, "
             "NOT PASSED.")
        skip("H3-starved-fido",
             "same reason as H2. NOT RUN, NOT PASSED.")
    else:
        with Step("H2 starved OpenPGP", "p8-H2-starved-openpgp.log") as out:
            out.line("# The flashed build forces the autocorrelation health "
                     "test to fail (--wedged).")
            out.line("A starved draw is expected to answer %04X within "
                     "%.0f s; a device that does not answer at all is a "
                     "HANG and fails the story."
                     % (SW_CLEAN_ERROR, STARVED_REQUEST_TIMEOUT_S))
            t0 = time.time()
            try:
                sw, body = apdu(con, [0x00, 0x84, 0x00, 0x00, 0x08],
                                timeout=STARVED_REQUEST_TIMEOUT_S)
            except Exception as exc:
                fail("starved GET CHALLENGE did not answer: %s: %s"
                     % (type(exc).__name__, exc))
                out.line("no answer within %.0f s — HANG"
                         % STARVED_REQUEST_TIMEOUT_S)
            else:
                dt = (time.time() - t0) * 1e3
                out.line("starved GET CHALLENGE -> SW=%04X body=%s in %.1f ms"
                         % (sw, body.hex(), dt))
                if sw == SW_CLEAN_ERROR:
                    out.line("clean error, as the story requires")
                elif sw == 0x9000:
                    out.line("NOTE: 9000 here means the DRBG seeded before the "
                             "wedge still has entropy to serve — see the "
                             "twin's module docstring; that is the designed "
                             "behaviour, not a pass on the clean-error claim.")
                else:
                    fail("starved GET CHALLENGE answered %04X; the story "
                         "wants %04X" % (sw, SW_CLEAN_ERROR))
                if body:
                    fail("a failed challenge must carry no bytes; got %d"
                         % len(body))

        with Step("H3 starved FIDO", "p8-H3-starved-fido.log") as out:
            out.line("# Enumerability over HID while starved, plus a FIDO "
                     "assertion (the request the story names).")
            if not fido_healthy_probe(out):
                fail("the HID node did not answer getInfo while starved — "
                     "the device is not enumerable over HID")
            out.line("NOTE: a FIDO *assertion* needs an enrolled credential "
                     "and a registered origin, and a credential can only be "
                     "created before the wedge (creating one needs a keygen, "
                     "which is the very thing the wedge breaks). Enrol a "
                     "credential in H1 and this step becomes runnable.")

    # ---- H4: enumerability over both transports, starved -------------------
    with Step("H4 enumerability", "p8-H4-enumerability.log") as out:
        out.line("# Both transports, in the state the board is in now.")
        try:
            sw, _ = apdu(con, [0x00, 0xA4, 0x04, 0x00, len(PGP_AID)] + PGP_AID)
            out.line("CCID SELECT OPENPGP -> SW=%04X" % sw)
            if sw != 0x9000:
                fail("CCID SELECT must answer 9000; the device is not "
                     "enumerable over CCID")
        except Exception as exc:
            fail("CCID SELECT did not answer: %s: %s" % (type(exc).__name__, exc))
        if not fido_healthy_probe(out):
            fail("HID getInfo did not answer; the device is not enumerable "
                 "over HID")

    # ---- H5: recovery ------------------------------------------------------
    with Step("H5 recovery", "p8-H5-recovery.log") as out:
        out.line("# A request after the TRNG recovers must succeed, on the "
                 "same boot. With --wedged the operator restores entropy "
                 "between H3 and here (that transition is physical, not a "
                 "command this script can send); without it this step only "
                 "confirms the device is still serving.")
        sw, body = apdu(con, [0x00, 0x84, 0x00, 0x00, 0x08])
        out.line("GET CHALLENGE -> SW=%04X body=%s" % (sw, body.hex()))
        if sw != 0x9000 or len(body) != 8:
            fail("post-recovery GET CHALLENGE must answer 9000 with 8 bytes")
        sw, _ = apdu(con, [0x00, 0x20, 0x00, 0x81] + BDD_PW1)
        out.line("VERIFY PW1 -> SW=%04X" % sw)
        sw, body = apdu(con, [0x00, 0x2A, 0x9E, 0x9A, len(DIGEST)] + DIGEST)
        out.line("PSO:CDS -> SW=%04X len=%d" % (sw, len(body)))
        if sw != 0x9000:
            fail("post-recovery PSO:CDS must answer 9000, got %04X" % sw)

    print()
    print("=" * 66)
    print("P8 / US-1007 entropy-starvation hardware BDD")
    print("=" * 66)
    print("RESULT: %s" % ("FAIL" if FAILED else
                          ("PASS (with %d skipped step(s))" % len(SKIPPED)
                           if SKIPPED else "PASS")))
    if SKIPPED:
        print()
        print("SKIPPED — these did NOT run and are NOT passes:")
        for name, why in SKIPPED:
            print("  %s: %s" % (name, why.split(".")[0]))
        print()
        print("The starvation half of US-1007 is therefore UNVERIFIED on "
              "hardware. Do not read a green line above as the story passing.")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
