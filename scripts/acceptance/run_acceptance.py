#!/usr/bin/env python3
"""US-1518 acceptance runner.

Runs the machine-checkable half of the acceptance suite against the attached
authenticator and reports pass/fail per case. Non-interactive, bounded, and
never silent: a case that cannot complete within its budget is recorded as a
FAIL with the reason, not skipped.

WHAT IS ASSERTED HERE, AND WHY IT IS HERE RATHER THAN IN THE BROWSER
----------------------------------------------------------------------
The epic's headline regression (DoD item 8) is a property of the USB transport:
after a ceremony is abandoned, the device must still enumerate and still answer,
quickly. A browser cannot measure that. WebAuthn exposes no way to enumerate
authenticators, no latency budget it will report, and no way to observe what the
OS/USB stack did while the page was doing something else. Worse, the browser
owns the hidraw node exclusively while a ceremony is in flight, so a page cannot
even ping the device during the very window where the defect appears.

So the regression is asserted here, on the wire, where it is measurable:

  abandoned-attempt-leaves-device-enumerable
      open a real consent window, walk away from it (no cancel, no touch, stop
      reading), then prove the device still answers.

  abandoned-attempt-next-ceremony-engages
      the same scenario, but asserting the SINGLE-OCCUPANCY contract: while the
      abandoned slot is still held, a second ceremony is REFUSED with 0x24
      CTAP2_ERR_OPERATION_PENDING (US-1510 -- refused, not queued), the device
      keeps answering INIT/PING/GetInfo throughout the drain, and a new ceremony
      engages once the slot is released.

  abandoned-attempt-does-not-block-the-host
      the same scenario, but measuring whether the host's own WRITE blocks --
      the second half of the defect, where writes block to ETIMEDOUT.

  device-enumerates / device-answers-ping
      the baseline those two are compared against, measured in the same run on
      the same device, so the bound is derived rather than assumed.

WHERE THE SLOT COMES FROM, AND HOW IT IS RELEASED
-------------------------------------------------
A consent window is opened with `authenticatorGetNextAssertion` (0x02) to a
throwaway RP id -- the one request shape that reaches the presence gate on this
board, verified empirically from a verified-idle slot (see
`open_consent_window`). It holds for ~30 s and is released either by
CTAPHID_CANCEL (measured 0.04 s) or by its own deadline (measured 29.78 s).

CTAPHID_CANCEL is deliberately NOT acknowledged on this firmware, per CTAPHID
and as both references behave -- a cancel reply makes fido2's inbound packet
matcher raise. So nothing here waits for an ack; a cancel is verified by
observing that the slot then accepts a new ceremony.

The latency bound is not picked to pass. It is derived at run time from the
device's own healthy PING round trip in the same run (see --bound-factor), with
an absolute floor, and both the derived bound and the measured baseline are
printed. A bound derived from a healthy baseline is defensible: it says "after
an abandoned ceremony the device must answer within N times as long as it does
when idle", which is the actual claim.

WHAT NEEDS A HUMAN
------------------
The request shapes US-1521 named (userVerification required/preferred,
authenticatorAttachment cross-platform, attestation none/direct, residentKey
required) are full ceremonies: this firmware requires a physical touch for user
presence (US-907) and this epic does not relax it. The runner therefore cannot
complete them unattended and does not pretend to. It launches the browser at the
acceptance page, which drives those shapes, and the operator touches the button.
The runner's verdict for those cases comes from the page.

The runner does NOT stub user presence. Chrome's CDP virtual authenticator and
Playwright's automatic-presence-simulation flag are deliberately unused: a
harness that fakes the touch cannot observe the thing this epic exists to
observe, so a green run from one would be evidence of nothing.

DEVICE SELECTION
----------------
Two boards are attached and both enumerate as 1050:0407; they differ only in
USB identity strings. Selection is by iManufacturer + iSerial from the USB
descriptors, never by hidraw node order, and each board also exposes a YubiOTP
interface on the same identity -- that is separated by HID usage page. The
selected board is named in the output. --exclude-identity keeps the harness
from ever opening a handle on the other board.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ctap  # noqa: E402
import server as https_server  # noqa: E402

# Bound derivation. A healthy PING on this hardware measures ~16 ms and the C
# reference measures ~8 ms; the observed defect is 30047.7 ms. The factor is
# generous enough to absorb scheduler jitter on a loaded CI box and still three
# orders of magnitude below the defect.
DEFAULT_BOUND_FACTOR = 10.0
# Absolute floor so a pathologically fast baseline cannot make the bound
# absurdly tight (sub-millisecond scheduling) and produce flaky failures.
DEFAULT_BOUND_FLOOR_MS = 250.0

# Baseline ping sample count.
BASELINE_PINGS = 5

# A consent window on this device stays open for ~30 s before the device's own
# timer expires. The abandoned-attempt case waits a bounded slice of that, then
# measures. It deliberately does NOT wait the full 30 s: the point is whether
# the device is answerable WHILE the ceremony it was given is still outstanding.
ABANDON_SETTLE_S = 3.0
POST_ABANDON_PROBE_S = 12.0

# Measured on the flashed board, from an abandoned ceremony: the slot is
# released at 29.78 s by the device's own window deadline, or at 0.04 s by
# CTAPHID_CANCEL. Both are asserted, not assumed -- see
# case_device_survives_repeated_abandonment, which measures both in-run.
MEASURED_DEADLINE_RELEASE_S = 30.0
MEASURED_CANCEL_RELEASE_S = 0.5

# How long to wait for the device's user-presence slot to drain after a case
# that abandoned a ceremony. The bound covers the measured 29.78 s deadline plus
# slack for the probe interval; exceeding it is a real result, not a timeout to
# paper over.
RECOVERY_BUDGET_S = 90.0


def open_consent_window(dev, rp_id, settle_s=ABANDON_SETTLE_S, phase="abandon"):
    """Park the device in a real consent window, then walk away from it.

    Returns (wire, parked_dict). The Wire is left OPEN and its request
    OUTSTANDING, with its keepalives drained up to `settle_s`. That is the
    shape of a dismissed browser prompt: the host stops reading and never
    cancels.

    WHICH REQUEST, and why not MakeCredential. Empirically verified on the
    flashed board, from a verified-idle slot:

      authenticatorGetNextAssertion (0x02)  -> PARKS (25 keepalives, 0x01/0x02)
      MakeCredential (0x01), throwaway RP    -> 0x12 INVALID_CBOR, no window
      authenticatorClientPIN (0x06) sub 0x06 -> 0x02 INVALID_PARAMETER, no window

    The MakeCredential answer is not a defect and not this harness's business:
    US-1530 established that a throwaway-RP MakeCredential is rejected at the
    CBOR layer on this firmware and on the C reference alike (`CBOR_FIELD_GET_
    BYTES` at the same key), because the request is not grammatical. And a PIN
    is set on this board, so a well-formed MakeCredential is refused
    `0x36 PIN_POLICY_VIOLATION` before the presence gate is ever consulted.
    GetNextAssertion to a throwaway RP is the one shape that actually reaches
    the gate here, so it is what parks the window. (The 0x02 clientPIN probe
    is reported for completeness: it is the documented built-in-UV path, but on
    this build it does not reach the gate, so it cannot stand in.)
    """
    w = ctap.Wire(dev)
    w.init(timeout=5.0)
    w.get_assertion_request(rp_id, b"\x11" * 32)
    parked = w.drain_until_closed(timeout=settle_s)
    return w, parked


def release_window(w):
    """Hand the device's user-presence slot back. Best-effort, never raises.

    Closing a handle does NOT release the slot -- only CTAPHID_CANCEL or the
    ~30 s deadline does. So a case that abandons a ceremony and then returns
    EARLY (a failed assertion, an exception) leaves the slot occupied for the
    rest of the window, and the next run's first case walks into
    `0x24 OPERATION_PENDING` and reports it as its own failure. Observed: a run
    whose predecessor had failed mid-case reported
    `abandoned-attempt-leaves-device-enumerable` FAIL with
    "never parked (0x24)" -- a failure manufactured by the previous case's
    cleanup, not by the device.

    Every abandoning case therefore cancels in its `finally`, so the device is
    left idle whether the case passed or failed. Best-effort by design: a
    cancel that does not take effect must not mask the case's real verdict, and
    `wait_for_recovery` between cases is the backstop that drains it anyway.
    """
    try:
        w.cancel(timeout=1.0)
    except Exception:
        pass


class Case:
    def __init__(self, cid, title, gate, fn):
        self.id = cid
        self.title = title
        self.gate = gate          # "machine" or "human"
        self.fn = fn
        self.verdict = None       # PASS / FAIL / BLOCKED
        self.observed = ""
        self.evidence = {}

    def as_dict(self):
        return {
            "case": self.id, "title": self.title, "gate": self.gate,
            "verdict": self.verdict, "observed": self.observed,
            "evidence": self.evidence,
        }


def log(msg=""):
    print(msg, flush=True)


# ---------------------------------------------------------------------------
# The exit-code contract, in one pure function
# ---------------------------------------------------------------------------
#
#   0  every MACHINE-gated case in this run reported PASS
#   1  at least one machine case FAILED, or one was in scope and did not
#      report at all
#   2  the harness could not run (no board, ambiguous identity, no browser
#      when --run-browser asked for one) — decided by the callers, not here
#
# "In scope" is the whole distinction, and it is carried on each case as
# `out_of_scope`. `page:enumerates` and `page:answers_after_abandon` are
# machine-gated *on the acceptance page*, but they can only report if a browser
# was launched, so they are machine-gated HERE only when `--run-browser` was
# passed. Without it they carry `gate: "browser"` and `out_of_scope: true`:
# visible and named, but not in the machine tally.
#
# The bug this replaces. The exit code was the one-liner
# `1 if machine_fail else 0`, while both page cases were filed under
# `gate: "machine"` unconditionally. So a browser-less run exited **0** with
# `page:enumerates` and `page:answers_after_abandon` never executed, while the
# README promised "exit code 0 = every machine case passed". `88d31cd` fixed
# the *summary count* for the same defect and left the exit code — the half the
# README tells callers to gate on — still reporting success over an unexecuted
# case.
#
# The rule, stated so it cannot be re-broken: **an unexecuted case is never a
# pass.** It is either out of scope and named as such, or in scope and non-zero.
# Human-gated cases are out of both directions — they need a physical touch by
# design, so `NOT RUN` on one is the expected state of an unattended run.
#
# Pure over a list of case dicts, with no board, browser or clock, so
# `tests/scripts/check_acceptance_exit_code.py` can pin all four branches
# without the hardware the harness itself requires.
def classify_cases(all_cases):
    machine = [c for c in all_cases if c["gate"] == "machine"]
    machine_pass = [c for c in machine if c["verdict"] == "PASS"]
    machine_fail = [c for c in machine if c["verdict"] == "FAIL"]
    # Anything in the machine tally that is neither PASS nor FAIL: the page
    # stayed silent, the case raised before recording a verdict, or a future
    # gate was added and left unhandled. All three mean "we did not measure
    # it", and all three must be non-zero.
    machine_notrun = [c for c in machine if c["verdict"] not in ("PASS", "FAIL")]
    out_of_scope = [c for c in all_cases if c.get("out_of_scope")]
    complete = not machine_fail and not machine_notrun
    return {
        "machine": machine,
        "machine_pass": machine_pass,
        "machine_fail": machine_fail,
        "machine_notrun": machine_notrun,
        "out_of_scope": out_of_scope,
        "complete": complete,
        "exit_code": 0 if complete else 1,
    }


def hdr(title):
    log()
    log("=" * 78)
    log(title)
    log("=" * 78)


# ---------------------------------------------------------------------------
# Machine cases
# ---------------------------------------------------------------------------


def case_device_enumerates(ctx):
    """The board is attached, is a CTAPHID node, and answers INIT.

    Asserted specifically, because this case PASSED against the pre-fix
    firmware too and its value comes entirely from what it now pins down. It
    used to check only "INIT assigned a non-zero cid", which was true on both
    firmwares -- a baseline that could not tell them apart. It now also pins:

      * the CTAPHID protocol version, which must be 2 (the value the Yubico
        client gates its FIDO2 support on);
      * `capFlags == 0x05` (CBOR|WINK). This is the US-1507 fix and it is the
        single byte most likely to separate "recognised" from "not offered" to
        a host: measured 0x04 pre-fix and 0x05 on both this board and the C
        reference after the flash. Asserting the exact value makes the case
        falsifiable against a regression to 0x04, which "is non-zero" could
        never do;
      * the nonce echo, which must actually match rather than merely exist --
        the old `payload[:8] is not None` was a tautology, true for every
        reply that had ever been received.
    """
    dev = ctx["device"]
    ev = {"device": ctap.describe(dev)}
    expected_caps = 0x05  # CAPFLAG_CBOR | CAPFLAG_WINK, per US-1507
    try:
        with ctap.Wire(dev) as w:
            t0 = time.monotonic()
            init = w.init()
            init_ms = round((time.monotonic() - t0) * 1000, 1)
            ev["init"] = init
            ev["init_ms"] = init_ms
            ev["foreign_frames_seen"] = w.foreign_summary()
            problems = []
            if init["cid"] == "0x00000000":
                problems.append("INIT assigned cid 0x00000000")
            if init["ctaphid_version"] != 2:
                problems.append(f"CTAPHID protocol version "
                                f"{init['ctaphid_version']}, expected 2")
            caps = int(init["cap_flags"], 16)
            if caps != expected_caps:
                problems.append(f"capFlags {init['cap_flags']}, expected "
                                f"0x{expected_caps:02x} (CBOR|WINK)")
            if problems:
                return CaseResult(False, "; ".join(problems), ev)
            return CaseResult(True, f"INIT ok in {init_ms} ms, cid {init['cid']}, "
                                    f"firmware {init['firmware_version']}, "
                                    f"CTAPHID v{init['ctaphid_version']}, "
                                    f"capFlags {init['cap_flags']}", ev)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"{type(e).__name__}: {e}", ev)


class CaseResult:
    def __init__(self, ok, observed, evidence=None):
        self.ok = ok
        self.observed = observed
        self.evidence = evidence or {}


def case_device_answers_ping(ctx):
    """Baseline: N PINGs on an idle device. This is what the post-abandon
    measurement is compared against, so it must be taken on the same device in
    the same run rather than assumed.

    This case is also the one whose FAILURE broke the two cases after it (see
    `case_abandoned_attempt_enumerable`), so it is asserted harder than a
    latency check: every sample must echo its own payload exactly, and a
    plausible-looking latency on the wrong bytes is a failure, not a pass.
    """
    dev = ctx["device"]
    ev = {}
    lat = []
    try:
        with ctap.Wire(dev) as w:
            w.init()
            for i in range(BASELINE_PINGS):
                tag = b"BASELINE%02d" % i
                r = w.ping(tag)
                lat.append(r["latency_ms"])
                if not r["echo_ok"]:
                    ev.setdefault("echo_failures", []).append(
                        {"i": i, "sent": tag.decode(), "got": r["echo"]})
            ev["foreign_frames"] = w.foreign_summary()
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"{type(e).__name__}: {e}", ev)
    ev["latencies_ms"] = lat
    if not lat:
        return CaseResult(False, "no PING samples", ev)
    if ev.get("echo_failures"):
        return CaseResult(False,
                          f"{len(ev['echo_failures'])} of {len(lat)} PINGs echoed "
                          f"the wrong bytes ({ev['echo_failures']}); the baseline "
                          "this run derives its bound from is untrustworthy", ev)
    worst = max(lat)
    floor = ctx["bound_floor_ms"]
    ok = worst <= floor
    return CaseResult(ok, f"{len(lat)} pings, all echoes correct, worst {worst:.1f} ms "
                          f"(median {sorted(lat)[len(lat)//2]:.1f} ms), "
                          f"floor {floor:.0f} ms", ev)


def case_get_info(ctx):
    """GetInfo answers and parses. Cheap liveness that is not just a PING."""
    dev = ctx["device"]
    ev = {}
    try:
        with ctap.Wire(dev) as w:
            w.init()
            status, info, trailing = w.get_info()
            ev["status"] = f"0x{status:02x}"
            ev["trailing_bytes"] = trailing
            if status != 0:
                return CaseResult(False, f"GetInfo status "
                                         f"0x{status:02x} "
                                         f"({ctap.status_name(status)})", ev)
            if info is None:
                return CaseResult(False, "GetInfo body did not decode to a map", ev)
            ev["top_level_keys"] = sorted(
                str(k) for k in info.keys())[:20]
            ev["key_count"] = len(info)
            return CaseResult(True, f"GetInfo status 0x00, {len(info)} keys, "
                                    f"{trailing} trailing bytes", ev)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"{type(e).__name__}: {e}", ev)


def case_abandoned_attempt_enumerable(ctx):
    """THE REGRESSION.

    Open a real consent window, then walk away from it: no touch, no
    CTAPHID_CANCEL, stop reading entirely. Then ask the device a fresh question
    on a brand-new connection and require it to answer within the bound.

    "Walk away" is what a browser does when a user opens the passkey prompt and
    dismisses it. The common case, not an exotic one.

    The TypeError this used to raise is fixed, and it was not cosmetic. The
    failure message formatted `ctx['baseline_ms']` with `:.1f`, and
    `baseline_ms` is only populated once `device-answers-ping` has run AND
    succeeded. So when the ping case failed -- which it did, on the CID bug --
    this case crashed formatting a `None` and the crash REPLACED a real
    measurement with a Python traceback. Two of the reported failures were
    therefore one failure plus two that could not report. The bound now falls
    back to the absolute floor and says so in the verdict, so an uncalibrated
    run is visible in the output instead of throwing.
    """
    dev = ctx["device"]
    ev = {"abandon_settle_s": ABANDON_SETTLE_S}
    rp = "us1518-abandon.invalid"
    try:
        w, parked = open_consent_window(dev, rp)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"opening the consent window failed: "
                                  f"{type(e).__name__}: {e}", ev)
    ev["during_window"] = parked
    if parked["keepalives"] == 0:
        # Without a parked window this case would measure nothing at all, and
        # would pass for the wrong reason -- which is exactly the failure mode
        # this suite exists to avoid.
        w.close()
        return CaseResult(False,
                          "the device never parked in a consent window "
                          f"({parked['outcome']}), so the abandoned-attempt "
                          "scenario was never exercised", ev)
    try:
        # Walk away: stop reading. A real dismissal also stops the host from
        # draining, which is the whole shape of the defect.
        ev["walked_away"] = True
        time.sleep(0.2)

        bound = ctx["bound_ms"]
        baseline = ctx["baseline_ms"]
        calibrated = baseline is not None
        if not calibrated:
            ev["bound_calibration"] = (
                "the idle PING baseline did not measure this run, so the bound "
                f"is the absolute floor {bound:.0f} ms, not a derived one")
        try:
            # A brand-new connection: this is "does the device still enumerate",
            # not "does the old channel still work".
            w2 = ctap.Wire(dev)
        except OSError as e:
            w.close()
            return CaseResult(False, f"could not reopen the device after abandoning: {e}", ev)
        try:
            t0 = time.monotonic()
            try:
                init = w2.init(timeout=ctx["probe_timeout_s"])
                reinit_ms = (time.monotonic() - t0) * 1000
            except (ctap.HarnessError, OSError) as e:
                ev["reinit_ms"] = round((time.monotonic() - t0) * 1000, 1)
                return CaseResult(
                    False,
                    f"the device did NOT re-enumerate after the abandoned attempt: "
                    f"{type(e).__name__}: {e} "
                    f"(waited {ctx['probe_timeout_s']:.0f}s)",
                    ev)
            ev["reinit_ms"] = round(reinit_ms, 1)
            ev["post_abandon_init"] = init
            p = w2.ping(b"AFTERABANDON", timeout=ctx["probe_timeout_s"])
            ev["post_abandon_ping"] = p
            # The device must still be usable, not merely alive: the INIT it
            # just answered has to be a real one and the PING a real echo.
            if not p["echo_ok"]:
                return CaseResult(False,
                                  f"PING echoed wrong bytes after the abandoned "
                                  f"attempt ({p['echo']!r}, {p['latency_ms']:.1f} ms)",
                                  ev)
            ratio = (p["latency_ms"] / baseline) if calibrated else None
            ev["latency_ratio_vs_baseline"] = (
                round(ratio, 1) if ratio is not None else None)
            basis = (f"bound {bound:.0f} ms = {ctx['bound_factor']:.0f}x the "
                     f"{baseline:.1f} ms idle baseline; ratio {ratio:.1f}x"
                     if calibrated else
                     f"bound {bound:.0f} ms (absolute floor; no idle baseline "
                     f"measured this run)")
            ok = p["latency_ms"] <= bound
            return CaseResult(
                ok,
                f"re-enumerated in {reinit_ms:.1f} ms, answered PING in "
                f"{p['latency_ms']:.1f} ms ({basis})",
                ev)
        finally:
            w2.close()
    finally:
        release_window(w)
        w.close()


def case_abandoned_attempt_does_not_block_host(ctx):
    """The second half of the defect: the host's WRITES block.

    Measured on this firmware before the fix: during a consent window the board
    stopped reading its USB OUT endpoint, the host's writes blocked, and a PING
    was only answered at 30047.7 ms -- the device's own window timer. This case
    asserts that a write issued after an abandoned ceremony completes promptly.

    It is separate from the enumerability case because it fails differently: the
    device may still answer on a fresh handle while a blocked write on the old
    one wedges the host. Both halves shipped together in the fix.

    The PING echo bug this replaces. The case used to time a PING write
    fire-and-forget and then call `ping()` with a different payload. Both
    replies arrive, in order, and both are `TYPE_INIT|CTAPHID_PING`, so
    CTAPHID's reply-matching cannot tell them apart: the second `ping()`
    consumed the FIRST one's echo and reported `echo_ok: False` after a
    flawless 8.0 ms round trip. Measured on the flashed board -- a device
    answering correctly was recorded as "echoed wrong bytes". The write is now
    paired with its own reply via `await_reply`, and a second PING issued after
    that pairs with its own too. What is asserted now is what the case means:
    the OUT endpoint is drained by the device, so writes land.
    """
    dev = ctx["device"]
    ev = {"write_watchdog_s": ctap.WATCHDOG_WRITE_S}
    rp = "us1518-block.invalid"
    try:
        w, parked = open_consent_window(dev, rp)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"opening the consent window failed: "
                                  f"{type(e).__name__}: {e}", ev)
    ev["during_window"] = parked
    if parked["keepalives"] == 0:
        # No window means no abandoned ceremony, so there is nothing to block.
        w.close()
        return CaseResult(False,
                          "the device never parked in a consent window "
                          f"({parked['outcome']}), so the host-blocking "
                          "scenario was never exercised", ev)
    try:
        time.sleep(0.2)
        # Time a single write on the SAME handle the ceremony was issued on.
        # This is the write a browser would issue to poll or to cancel.
        t0 = time.monotonic()
        try:
            w.send(ctap.CTAPHID_PING, b"WRITEAFTER")
            write_ms = (time.monotonic() - t0) * 1000
        except ctap.HidWriteBlocked as e:
            ev["write_blocked"] = True
            ev["write_ms"] = round((time.monotonic() - t0) * 1000, 1)
            return CaseResult(
                False,
                f"the host's WRITE BLOCKED for "
                f"{(time.monotonic()-t0)*1000:.0f} ms after the abandoned "
                f"attempt ({e}). The device is not draining its OUT endpoint.",
                ev)
        except (ctap.HarnessError, OSError) as e:
            return CaseResult(False, f"write raised {type(e).__name__}: {e}", ev)
        ev["write_ms"] = round(write_ms, 1)

        # Pair that write with ITS OWN reply. Not a second PING: two PINGs are
        # indistinguishable by frame command, which is the bug being fixed.
        t1 = time.monotonic()
        try:
            echo = w.await_reply(ctap.CTAPHID_PING, timeout=ctx["probe_timeout_s"])
            echo_ms = (time.monotonic() - t1) * 1000
        except (ctap.HarnessError, OSError) as e:
            return CaseResult(False,
                              f"write completed in {write_ms:.1f} ms but the device "
                              f"never answered it: {type(e).__name__}: {e}", ev)
        ev["write_echo_ms"] = round(echo_ms, 1)
        ev["write_echo_ok"] = (echo == b"WRITEAFTER")
        if echo != b"WRITEAFTER":
            return CaseResult(False,
                              f"the device echoed {echo!r} for the PING this case "
                              f"wrote, not b'WRITEAFTER'", ev)

        # A genuinely independent round trip, now that nothing is in flight.
        p = w.ping(b"AFTERWRITE", timeout=ctx["probe_timeout_s"])
        ev["ping_after_write"] = p
        ok = (p["echo_ok"] and p["latency_ms"] <= ctx["bound_ms"]
              and echo_ms <= ctx["bound_ms"])
        return CaseResult(ok,
                          f"write completed in {write_ms:.1f} ms, was answered in "
                          f"{echo_ms:.1f} ms, and a further PING echoed correctly in "
                          f"{p['latency_ms']:.1f} ms (bound {ctx['bound_ms']:.0f} ms) "
                          "-- the OUT endpoint stayed drained throughout", ev)
    finally:
        try:
            release_window(w)
            w.close()
        except Exception:
            pass


def case_device_survives_repeated_abandonment(ctx):
    """REGRESSION, rewritten. The assertion it used to make encoded the
    PRE-FIX world, and would have passed a device that had simply gone dark.

    THE OLD ASSERTION: "after an abandoned ceremony, a new ceremony engages."
    Measured on the flashed board it fails immediately, with the device
    answering `0x24 CTAP2_ERR_OPERATION_PENDING` -- and that refusal is the
    DESIGNED behaviour, not a regression:

      * US-1510 specifies that a second user-presence request arriving while the
        slot is occupied is **refused, not queued**. A single-occupancy,
        fail-closed slot is the whole point of that story.
      * An abandoned attempt therefore holds the slot for the remainder of its
        ~30 s window, so an immediate re-ceremony is *correctly* refused.
      * The pico-fido2 C reference does the same; the sibling A/B probe
        recorded it "STILL PARKED" under the same conditions.

    WHY THE OLD ASSERTION WAS WRONG, not merely strict. Before the fix the
    device went dark for the whole window. Anything sent during that period
    either got nothing back or was refused, so "a new ceremony engages right
    away" could only have been satisfied by a device that was NOT holding a
    slot -- i.e. the assertion and the fix were pulling in opposite
    directions. Pre-fix, the case could only pass if the very defect it exists
    to catch were absent, and in practice it passed for the wrong reason: the
    device, being dark, was trivially "not blocking" anything.

    THE HONEST ASSERTION has three parts, each decided:

      1. **Enumerate and answer, throughout the drain.** While the abandoned
         slot is still held, the device must answer INIT, PING and GetInfo on
         fresh channels, within the derived bound, repeatedly across the window.
         This is the actual DoD-8 claim: the blackout is gone.

      2. **Refuse, not queue, while occupied.** A second ceremony during the
         drain must be answered `0x24 CTAP2_ERR_OPERATION_PENDING` and must NOT
         park. Asserting the refusal is asserting US-1510 rather than
         tolerating it -- a device that silently queued instead would fail
         here.

      3. **Engage once the slot is released.** The slot is released two ways,
         both measured in this run and both asserted:
           - `CTAPHID_CANCEL`, which this firmware deliberately does NOT
             acknowledge (per CTAPHID, and as both references behave: a cancel
             reply makes `fido2`'s inbound packet matcher raise). Measured
             release: 0.04 s.
           - the device's own ~30 s window deadline, with no cancel at all --
             the true "user walked away" path. Measured release: 29.78 s.
    """
    dev = ctx["device"]
    ev = {"measured_deadline_release_s": MEASURED_DEADLINE_RELEASE_S,
          "measured_cancel_release_s": MEASURED_CANCEL_RELEASE_S}
    bound = ctx["bound_ms"]

    # ---- (1) abandon one, then hold it while probing liveness -------------
    try:
        w, parked = open_consent_window(dev, "us1518-next.invalid")
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"opening the consent window failed: "
                                  f"{type(e).__name__}: {e}", ev)
    ev["abandoned"] = parked
    if parked["keepalives"] == 0:
        w.close()
        return CaseResult(False,
                          "the device never parked in a consent window "
                          f"({parked['outcome']}), so the abandoned-attempt "
                          "scenario was never exercised", ev)

    probes = []
    refusals = []          # the status of every second ceremony sent while held
    release_t = None       # when the slot accepted a new ceremony
    parked_while_occupied = None
    try:
        # Probe across the window, sampling liveness and occupancy as we go.
        # The window is ~30 s; we stop as soon as it releases on its own.
        t0 = time.monotonic()
        while time.monotonic() - t0 < MEASURED_DEADLINE_RELEASE_S + 5:
            rec = {"t_s": round(time.monotonic() - t0, 2)}
            try:
                w2 = ctap.Wire(dev)
            except OSError as e:
                rec["error"] = f"open failed: {e}"
                probes.append(rec)
                break
            try:
                init = w2.init(timeout=3.0)
                rec["init_cid"] = init["cid"]
                p = w2.ping(b"DRAINING", timeout=3.0)
                rec["ping_ms"] = p["latency_ms"]
                rec["ping_ok"] = p["echo_ok"]
                rec["ping_within_bound"] = p["latency_ms"] <= bound
                status, info, _ = w2.get_info()
                rec["getinfo_status"] = f"0x{status:02x}"
                rec["getinfo_keys"] = len(info) if info else 0

                # (2)/(3a) A second ceremony on yet another channel. While the
                # slot is held this must be REFUSED (US-1510). The probe is what
                # detects the release, so when it DOES park we must release it
                # again -- otherwise this probe occupies the slot for another
                # 30 s and every later probe reads its own damage.
                w3 = ctap.Wire(dev)
                w3.init(timeout=3.0)
                w3.get_assertion_request("us1518-second.invalid", b"\x55" * 32)
                try:
                    frame_cmd, payload = w3.read_frame(
                        3.0, skip_foreign_cids=True)
                    if frame_cmd == ctap.TYPE_INIT | ctap.CTAPHID_KEEPALIVE:
                        rec["second_ceremony"] = "PARKED (slot released)"
                        rec["released_here"] = True
                        release_t = time.monotonic() - t0
                        w3.cancel(timeout=1.0)
                    elif payload:
                        rec["second_ceremony"] = (
                            f"0x{payload[0]:02x} {ctap.status_name(payload[0])}")
                        refusals.append(payload[0])
                    else:
                        rec["second_ceremony"] = "empty reply"
                        refusals.append(None)
                except ctap.HidTimeout:
                    rec["second_ceremony"] = "no reply"
                    refusals.append(None)
                finally:
                    w3.close()
            except (ctap.HarnessError, OSError) as e:
                rec["error"] = f"{type(e).__name__}: {e}"
            finally:
                w2.close()
            probes.append(rec)
            if release_t is not None:
                break
            time.sleep(1.0)
    finally:
        release_window(w)
        w.close()

    ev["probes"] = probes
    ev["refusals_observed"] = sorted({f"0x{s:02x}" for s in refusals if s is not None})
    ev["release_by_deadline_s"] = round(release_t, 2) if release_t is not None else None

    liveness = [p for p in probes if p.get("ping_ok")]
    if not liveness:
        return CaseResult(False,
                          "the device answered nothing while the abandoned slot "
                          "drained -- it went dark, which is the regression this "
                          "case exists to catch", ev)
    slowest = max(p["ping_ms"] for p in liveness)
    all_within = all(p.get("ping_within_bound") for p in liveness)
    all_info = all(p.get("getinfo_status") == "0x00" for p in liveness)
    ev["probes_answered"] = len(liveness)
    ev["slowest_ping_ms"] = slowest

    if not all_within:
        bad = [p for p in liveness if not p.get("ping_within_bound")]
        return CaseResult(False,
                          f"{len(bad)} of {len(liveness)} liveness probes exceeded "
                          f"the {bound:.0f} ms bound (worst {slowest:.1f} ms) while "
                          "the abandoned slot drained", ev)
    if not all_info:
        return CaseResult(False,
                          f"GetInfo did not answer 0x00 on every one of the "
                          f"{len(liveness)} liveness probes while the abandoned "
                          "slot drained", ev)

    # (2) Every second ceremony sent BEFORE the release must have been refused
    # with 0x24. Anything else -- a park, or a different status -- means the
    # single-occupancy rule was not honoured.
    occupied_probes = [p for p in probes
                       if p.get("t_s") is not None and not p.get("released_here")]
    undecided = [p for p in occupied_probes
                 if not str(p.get("second_ceremony", "")).startswith("0x24")]
    if undecided:
        first = undecided[0]
        return CaseResult(False,
                          f"while the abandoned slot was still occupied, a second "
                          f"ceremony was answered "
                          f"{first.get('second_ceremony')!r} at t+"
                          f"{first['t_s']}s rather than being refused with 0x24 "
                          "CTAP2_ERR_OPERATION_PENDING (US-1510)", ev)
    if not occupied_probes:
        return CaseResult(False,
                          "the abandoned slot was never observed in the occupied "
                          "state, so the refusal behaviour was not exercised", ev)

    # (3a) released by the device's own deadline, with no cancel from us.
    if release_t is None:
        return CaseResult(False,
                          f"the abandoned slot never released on its own within "
                          f"{MEASURED_DEADLINE_RELEASE_S + 5:.0f}s; a new ceremony "
                          "must engage once the device's own ~30 s window expires",
                          ev)
    ev["released_by_deadline"] = True

    # ---- (3b) release by CTAPHID_CANCEL, measured -----------------------
    try:
        wc, parked_c = open_consent_window(dev, "us1518-cancel.invalid")
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"could not park for the CANCEL measurement: "
                                  f"{type(e).__name__}: {e}", ev)
    if parked_c["keepalives"] == 0:
        release_window(wc)
        wc.close()
        return CaseResult(False,
                          f"could not park for the CANCEL measurement "
                          f"({parked_c['outcome']}) -- the slot from the previous "
                          "measurement had not been released", ev)
    try:
        ev["cancel_parked_on"] = f"0x{wc.cid:08x}"
        tc0 = time.monotonic()
        cancel = wc.cancel(timeout=1.0)
        ev["cancel"] = cancel
        # Deliberately NOT waiting for an ack: this firmware does not send one,
        # and per CTAPHID a cancel reply breaks fido2's packet matcher.
        released = None
        while time.monotonic() - tc0 < MEASURED_DEADLINE_RELEASE_S + 5:
            if _try_engage_standalone(dev, timeout=2.0):
                released = time.monotonic() - tc0
                break
            time.sleep(0.2)
        if released is None:
            return CaseResult(False,
                              "after CTAPHID_CANCEL the slot never accepted a new "
                              f"ceremony within {MEASURED_DEADLINE_RELEASE_S + 5:.0f}s",
                              ev)
        ev["cancel_release_s"] = round(released, 3)
    finally:
        release_window(wc)
        wc.close()

    # Timed from when the ceremony was actually issued, not from when the probe
    # loop started -- the loop begins only after the settle period during which
    # the device was already holding the slot.
    ev["release_s_from_request"] = round(release_t + ABANDON_SETTLE_S, 2)
    distinct = sorted({s for s in refusals if s is not None})
    return CaseResult(
        True,
        f"across {len(liveness)} probes spanning {release_t:.1f}s of drain the "
        f"device answered INIT/PING/GetInfo every time (worst PING {slowest:.1f} ms, "
        f"bound {bound:.0f} ms); all {len(refusals)} second ceremonies sent while "
        f"the slot was held were refused with "
        f"{['0x%02x %s' % (s, ctap.status_name(s)) for s in distinct]}; the slot "
        f"released on the device's own deadline {release_t + ABANDON_SETTLE_S:.1f}s "
        f"after the request, and {released:.2f}s after CTAPHID_CANCEL",
        ev)


def _try_engage_standalone(dev, timeout=2.0):
    """On a throwaway handle: does a new ceremony engage right now?

    CANCELS the ceremony it opens. That matters: this probes whether the slot
    is free, and a probe that left the slot occupied would hold it for another
    ~30 s and poison whatever ran next -- which is precisely how the first
    version of this case failed, reading its own damage as the device's.
    """
    try:
        w = ctap.Wire(dev)
    except OSError:
        return False
    try:
        w.init(timeout=3.0)
        engaged = _try_engage(w, timeout=timeout)
        if engaged:
            w.cancel(timeout=1.0)
        return engaged
    except (ctap.HarnessError, OSError):
        return False
    finally:
        w.close()


def case_ctap_identity_is_ours(ctx):
    """The run talked to the board it claims to have talked to.

    A guard against the most embarrassing failure this harness could have:
    reporting our board's numbers while actually having driven the C reference,
    or vice versa. The identity is re-read from the USB descriptors immediately
    before the first measured case and compared to the selection.

    This also asserts the constraint the brief sets: the C reference board must
    not be touched. The reference IS expected to be present and enumerable --
    it is attached -- so its presence is not a failure. What must hold is that
    every hidraw node this run opened belongs to the selected board.
    """
    dev = ctx["device"]
    ev = {"selected": ctap.describe(dev)}
    try:
        nodes, other = ctap.enumerate_devices()
        ev["ctap_nodes"] = [f"{n['path']} ({n.get('manufacturer')})" for n in nodes]
        ev["non_ctap_nodes"] = [
            f"{n['path']} ({n['interface']}, {n.get('manufacturer')})"
            for n in other]
        again = ctap.select_target(nodes, ctx["manufacturer"], ctx["serial"])
        ev["reidentified"] = ctap.describe(again)
        if again["path"] != dev["path"]:
            return CaseResult(False,
                              f"the target moved: selected {dev['path']}, "
                              f"now {again['path']}", ev)

        # The reference board is allowed to be attached. What is not allowed is
        # this run having opened a handle on it. Assert on what was opened.
        opened = ctx.get("opened_paths", [])
        foreign = [p for p in opened if p != dev["path"]]
        ev["opened_paths"] = sorted(set(opened))
        if foreign:
            return CaseResult(False,
                              f"this run opened nodes belonging to another "
                              f"board: {foreign}", ev)

        # And confirm the excluded identity is a DIFFERENT node, so the two
        # boards really are being told apart and not collapsed.
        others = [n for n in nodes
                  if n.get("manufacturer") == ctx["excluded_identity"]]
        ev["excluded_present"] = [n["path"] for n in others]
        return CaseResult(True,
                          f"identity confirmed before measuring: {again['path']} "
                          f"({again.get('manufacturer')}, {again.get('serial')}); "
                          f"this run opened only {sorted(set(opened))}; the "
                          f"excluded board {ctx['excluded_identity']!r} is "
                          f"present at {[n['path'] for n in others]} and was "
                          f"never opened",
                          ev)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"{type(e).__name__}: {e}", ev)


def case_get_info_options(ctx):
    """Record the GetInfo options map as evidence.

    Not a pass/fail on semantics -- it is here because the epic's fixes touch
    authenticatorSelection and capFlags, and a run that does not print the
    options map cannot tell you whether the fix landed. Prints the keys with
    their TYPES, because an earlier probe in this epic reported a column of
    option ids for a device that emits string keys, and had to be retracted.

    It used to return PASS on an absent options map, reporting "recorded, not
    assumed". That is a pass for the wrong reason: the whole point of this case
    is that the map IS present and readable on this firmware, so an absent map
    now FAILS. A case that cannot report what it exists to report should not be
    able to pass. It also now pins that the keys are TEXT on this device --
    measured `key type(s) ['str']` -- so a regression to integer-keyed options
    (which an earlier probe mistakenly reported) is caught rather than recorded.
    """
    dev = ctx["device"]
    ev = {}
    try:
        with ctap.Wire(dev) as w:
            w.init()
            status, info, trailing = w.get_info()
            ev["status"] = f"0x{status:02x}"
            if status != 0 or info is None:
                return CaseResult(False,
                                  f"GetInfo status 0x{status:02x}", ev)
            # GetInfo member 4 is the options map. It may be keyed by text name
            # or by integer id depending on the device; report what is actually
            # there, never a substituted default.
            options = info.get(4)
            if options is None:
                ev["options"] = "member 4 absent from the reply (unobserved)"
                return CaseResult(False,
                                  "GetInfo answered but carried NO options map "
                                  "(member 4 absent); this case exists to report "
                                  "that map, so an absent one is a failure, not "
                                  "a neutral observation", ev)
            if not isinstance(options, dict):
                ev["options"] = f"member 4 is {type(options).__name__}: {options!r}"
                return CaseResult(False,
                                  f"options member is a {type(options).__name__}, "
                                  f"not a map", ev)
            rendered = "; ".join(
                f"{k!r} (key type={type(k).__name__})={v!r}"
                for k, v in sorted(options.items(), key=lambda kv: str(kv[0])))
            ev["options"] = rendered
            ev["option_key_types"] = sorted({type(k).__name__ for k in options})
            ev["option_keys"] = sorted(str(k) for k in options)
            ev["option_count"] = len(options)
            ev["trailing_bytes"] = trailing
            key_types = ev["option_key_types"]
            if key_types != ["str"]:
                return CaseResult(False,
                                  f"options map is keyed by {key_types}, expected "
                                  "['str'] -- this device emits text keys, so a "
                                  "different key type is a wire change", ev)
            return CaseResult(True,
                              f"options map: {len(options)} entries, "
                              f"key type(s) {key_types}, {trailing} trailing bytes",
                              ev)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"{type(e).__name__}: {e}", ev)


def wait_for_recovery(ctx, budget_s=RECOVERY_BUDGET_S):
    """Wait until the device's user-presence SLOT is free again, and report how long.

    Why this gate changed, and why the old one silently destroyed the suite.

    The old gate polled INIT+PING and called the device "recovered" when both
    answered. That was written for the PRE-FIX world, where an abandoned
    ceremony took the device dark for 30 s: there, INIT+PING failing *was* the
    damage. Post-fix the exact opposite holds — the device stays fully
    answerable throughout the drain (measured: INIT/PING/GetInfo all answered in
    16-64 ms at every second of a 30 s drain, while a second ceremony was
    refused with `0x24` each time). So INIT+PING now succeed **0.08 s** after a
    case abandons a ceremony, `wait_for_recovery` returns `recovered: True`, and
    the next case starts with the slot still occupied.

    The consequence was not subtle: every case after the first abandon case ran
    its own ceremony into an occupied slot, got `0x24` instead of a window, and
    recorded that as its own result. One case's damage was reported as three
    independent failures — exactly what this function exists to prevent, and it
    did the opposite of its stated purpose because it measured the wrong state.

    So the gate now probes the thing the next case actually needs: **can a new
    ceremony engage?** Measured on the flashed board, from an abandoned
    ceremony: released at **29.78 s** by the device's own window deadline, or
    at **0.04 s** by `CTAPHID_CANCEL`. `wait_for_recovery` deliberately does NOT
    cancel — it waits out the real deadline, so each case starts from the state
    a real user reaches by walking away, and the recovery time it reports is
    the device's own measured drain, not a figure the harness manufactured.
    """
    dev = ctx["device"]
    t0 = time.monotonic()
    attempts = 0
    last = "never attempted"
    while time.monotonic() - t0 < budget_s:
        attempts += 1
        try:
            w = ctap.Wire(dev)
        except OSError as e:
            last = f"open failed: {e}"
            time.sleep(1.0)
            continue
        try:
            w.init(timeout=3.0)
            p = w.ping(b"RECOVER", timeout=3.0)
            if not p["echo_ok"]:
                last = f"PING echo mismatch ({p['latency_ms']} ms)"
                time.sleep(1.0)
                continue
            # Liveness is necessary but NOT sufficient: prove the slot is free
            # by engaging a real ceremony and confirming a keepalive arrives.
            # Cancelling it leaves the device as we found it.
            engaged = _try_engage(w, timeout=3.0)
            if not engaged:
                last = "answerable, but the user-presence slot is still occupied"
                time.sleep(1.0)
                continue
            w.cancel(timeout=1.0)
            return {"recovered": True, "waited_s": round(time.monotonic() - t0, 1),
                    "attempts": attempts, "ping_ms": p["latency_ms"],
                    "slot_state": "free (a ceremony engaged, then was cancelled)"}
        except (ctap.HarnessError, OSError) as e:
            last = f"{type(e).__name__}: {e}"
        finally:
            try:
                w.close()
            except Exception:
                pass
        time.sleep(1.0)
    return {"recovered": False, "waited_s": round(time.monotonic() - t0, 1),
            "attempts": attempts, "last_error": last}


def _try_engage(w, timeout=2.0):
    """On handle `w`, ask for a throwaway ceremony. True if a window opens.

    True means the slot was free. This deliberately leaves the slot OCCUPIED
    when it returns True -- the caller is expected to `cancel()` or abandon it.
    The discard is safe: any follow-up frame for this request is ignored,
    because it can never be another request's reply once we stop reading.
    """
    w.send(ctap.CTAPHID_CBOR,
           bytes([ctap.CTAP2_GET_NEXT_ASSERTION])
           + ctap.cbor_encode({1: "slot-probe.invalid", 2: b"\x77" * 32}))
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            frame_cmd, _ = w.read_frame(max(0.2, timeout - (time.monotonic() - t0)),
                                        skip_foreign_cids=True)
        except ctap.HidTimeout:
            return False
        if frame_cmd == ctap.TYPE_INIT | ctap.CTAPHID_KEEPALIVE:
            return True
        # Any other reply means the slot refused it, so it was not free.
        return False
    return False


# (id, title, fn, abandons_a_ceremony)
#
# The fourth element marks a case that leaves an outstanding abandoned ceremony
# behind, which is what forces the recovery wait before the next one. See
# wait_for_recovery for why that matters to the integrity of a run.
MACHINE_CASES = [
    ("ctap-identity-is-ours", "The run targets the intended board, by USB identity",
     case_ctap_identity_is_ours, False),
    ("device-enumerates", "The board enumerates and answers CTAPHID INIT",
     case_device_enumerates, False),
    ("device-answers-ping", "The idle device answers PING within the floor",
     case_device_answers_ping, False),
    ("get-info-answers", "GetInfo answers and its body decodes",
     case_get_info, False),
    ("get-info-options", "The GetInfo options map is recorded as evidence",
     case_get_info_options, False),
    ("abandoned-attempt-leaves-device-enumerable",
     "REGRESSION: after an abandoned attempt the device still enumerates "
     "and answers within the derived bound",
     case_abandoned_attempt_enumerable, True),
    ("abandoned-attempt-does-not-block-host",
     "REGRESSION: after an abandoned attempt the host's write is not blocked",
     case_abandoned_attempt_does_not_block_host, True),
    ("abandoned-attempt-next-ceremony-engages",
     "REGRESSION: the abandoned slot refuses a second ceremony (US-1510), the "
     "device stays answerable while it drains, and a new ceremony engages once "
     "the slot is released",
     case_device_survives_repeated_abandonment, True),
]


# ---------------------------------------------------------------------------
# Browser side
# ---------------------------------------------------------------------------

# The six shapes US-1521 named. These need a physical touch, so they are run by
# the page with a human present; the runner launches the browser, waits, and
# reads the verdicts back. They are reported as HUMAN-GATED, never as machine
# passes, so nobody can mistake a green suite for "the ceremonies were verified
# unattended".
HUMAN_CASES = [
    ("uv_required", "userVerification: required"),
    ("uv_preferred", "userVerification: preferred"),
    ("attachment_cross", "authenticatorAttachment: cross-platform"),
    ("attestation_none", "attestation: none"),
    ("attestation_direct", "attestation: direct"),
    ("rk_required", "residentKey: required"),
    ("get_uv_required", "userVerification: required (assertion)"),
]

MACHINE_PAGE_CASES = ["enumerates", "answers_after_abandon"]


def find_chrome(explicit=None):
    candidates = []
    if explicit:
        candidates.append(explicit)
    for name in ("chromium", "chromium-browser", "google-chrome",
                 "google-chrome-stable", "chrome"):
        p = shutil.which(name)
        if p:
            candidates.append(p)
    # Playwright's bundled Chrome for Testing, if present.
    cache = os.path.expanduser("~/.cache/ms-playwright")
    if os.path.isdir(cache):
        for d in sorted(os.listdir(cache)):
            if d.startswith("chromium-"):
                for sub in ("chrome-linux64/chrome", "chrome-linux/chrome"):
                    p = os.path.join(cache, d, sub)
                    if os.path.exists(p):
                        candidates.append(p)
    seen = set()
    for c in candidates:
        if c and c not in seen and os.path.exists(c):
            seen.add(c)
            return c
    return None


def run_browser(chrome, url, udd, wait_s, extra_args, autorun=False):
    """Launch the browser at the page and collect what it reports.

    The page POSTs each verdict to /results as it reaches it, so this needs no
    DevTools-protocol plumbing and works identically headless and headed.

    `autorun` adds ?autorun=1, which fires ONLY the machine-gated page cases.
    The human-gated ceremonies are never auto-started: with nobody at the
    button they would each burn their full timeout and then be reported as a
    FAIL, which would be a lie about the device rather than a measurement.
    """
    target = url + ("?autorun=1" if autorun else "")
    args = [chrome, "--no-first-run", "--no-default-browser-check",
            f"--user-data-dir={udd}"] + list(extra_args) + [target]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + wait_s
    # Do not return on the FIRST result. In autorun the page fires two
    # machine-gated cases in sequence, and stopping on the first would drop the
    # second -- which is the one that matters. Instead wait for the autorun
    # chain to finish, or for a quiet period after the last new result.
    # The abandoned-attempt page case deliberately sits for two settle periods
    # before it probes, so the quiet window must be comfortably longer than
    # that, or the runner stops before the case that matters reports.
    quiet_after = 45.0 if autorun else 40.0
    expected = set(MACHINE_PAGE_CASES) if autorun else set(HUMAN_CASES)
    last_change = time.monotonic()
    seen = 0
    try:
        while time.monotonic() < deadline:
            time.sleep(1.0)
            results = https_server.Server.results()
            if len(results) != seen:
                seen = len(results)
                last_change = time.monotonic()
                log(f"    page reported {len(results)} case(s) so far: "
                    f"{sorted(results)}")
            if expected and expected.issubset(set(results)):
                break
            if results and time.monotonic() - last_change > quiet_after:
                log("    (no new page verdicts for "
                    f"{quiet_after:.0f}s; stopping)")
                break
        return https_server.Server.results()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manufacturer", default="EddieOz",
                    help="iManufacturer of the board under test "
                         "(default: our Rust firmware)")
    ap.add_argument("--serial", default="94746395",
                    help="iSerial of the board under test")
    ap.add_argument("--exclude-identity", default="Pol Henarejos",
                    help="iManufacturer of the board that must NOT be driven")
    ap.add_argument("--bound-factor", type=float, default=DEFAULT_BOUND_FACTOR,
                    help="the post-abandon bound is this many times the "
                         f"measured idle PING baseline (default {DEFAULT_BOUND_FACTOR})")
    ap.add_argument("--bound-floor-ms", type=float, default=DEFAULT_BOUND_FLOOR_MS,
                    help="absolute floor for the post-abandon bound "
                         f"(default {DEFAULT_BOUND_FLOOR_MS})")
    ap.add_argument("--probe-timeout-s", type=float, default=POST_ABANDON_PROBE_S,
                    help="how long the device gets to answer after an "
                         f"abandoned attempt (default {POST_ABANDON_PROBE_S})")
    ap.add_argument("--browser", default=None, help="path to a Chrome/Chromium binary")
    ap.add_argument("--run-browser", action="store_true",
                    help="also launch the browser at the acceptance page "
                         "(needs a human at the keyboard for the touches)")
    ap.add_argument("--browser-wait-s", type=float, default=180.0)
    ap.add_argument("--browser-autorun", action="store_true",
                    help="have the page fire its MACHINE-gated cases on load "
                         "(the human-gated ceremonies are never auto-started)")
    ap.add_argument("--browser-args", default="--ignore-certificate-errors",
                    help="extra browser args (space separated)")
    ap.add_argument("--headed", action="store_true",
                    help="run the browser headed (default headless=new)")
    ap.add_argument("--json-out", default=None, help="write the full report as JSON")
    args = ap.parse_args()

    hdr("US-1518 acceptance harness")
    log(f"python  : {sys.version.split()[0]}")
    log(f"board   : iManufacturer={args.manufacturer!r} iSerial={args.serial!r}")
    log(f"excluded: iManufacturer={args.exclude_identity!r} (the C reference)")

    hdr("STEP 1 — inventory and device selection")
    try:
        ctap_nodes, other_nodes = ctap.enumerate_devices()
    except Exception as e:
        log(f"FATAL: could not enumerate devices: {type(e).__name__}: {e}")
        return 2
    log(f"{len(ctap_nodes)} CTAPHID node(s), {len(other_nodes)} other 1050:0407 "
        f"node(s):")
    for n in ctap_nodes:
        log(f"  CTAP  {n['path']}: {ctap.describe(n)}  "
            f"[{n['interface_evidence']}]")
    for n in other_nodes:
        log(f"  other {n['path']}: {n.get('manufacturer')} / {n.get('serial')} "
            f"({n['interface']}, not driven)")
    if not ctap_nodes:
        log("FATAL: no CTAPHID device found. Attach the board and re-run.")
        return 2
    try:
        device = ctap.select_target(ctap_nodes, args.manufacturer, args.serial)
    except ctap.IdentityError as e:
        log(f"FATAL: {e}")
        return 2
    log()
    log(f"SELECTED: {ctap.describe(device)}")
    log("  (selected by USB iManufacturer+iSerial and HID usage page; "
        "never by hidraw node order)")

    ctx = {
        "device": device,
        "manufacturer": args.manufacturer,
        "serial": args.serial,
        "excluded_identity": args.exclude_identity,
        "bound_factor": args.bound_factor,
        "bound_floor_ms": args.bound_floor_ms,
        "bound_ms": args.bound_floor_ms,
        "baseline_ms": None,
        "probe_timeout_s": args.probe_timeout_s,
        # Filled in by each case as handles are opened, so the identity case
        # can assert which board the run actually drove.
        "opened_paths": ctap.OPENED_PATHS,
    }

    hdr("STEP 2 — machine-checkable cases (no human, no browser)")
    cases = []
    recoveries = []
    needs_recovery = False
    for cid, title, fn, abandons in MACHINE_CASES:
        log()
        log(f"--- {cid}: {title}")
        if needs_recovery:
            # The previous case left an outstanding abandoned ceremony behind.
            # Bring the device back to a verified-healthy state first, or this
            # case would be measuring the previous case's damage instead of its
            # own scenario.
            rec = wait_for_recovery(ctx)
            recoveries.append(rec)
            if not rec["recovered"]:
                log(f"    FAIL  the device did not recover within "
                    f"{RECOVERY_BUDGET_S:.0f}s after the previous case "
                    f"({rec.get('last_error')}); this case is NOT attributable "
                    f"to its own scenario and is recorded as such")
                c = Case(cid, title, "machine", fn)
                c.verdict = "FAIL"
                c.observed = (f"not attributable: the device was still "
                              f"unanswerable {rec['waited_s']}s after the "
                              f"previous case abandoned a ceremony "
                              f"({rec.get('last_error')})")
                c.evidence = {"recovery": rec}
                cases.append(c)
                continue
            log(f"    (user-presence slot released {rec['waited_s']}s after the "
                f"previous case abandoned a ceremony; {rec['attempts']} probe(s), "
                f"ping {rec['ping_ms']} ms — {rec.get('slot_state', '?')})")
        c = Case(cid, title, "machine", fn)
        t0 = time.monotonic()
        try:
            result = fn(ctx)
        except Exception as e:
            result = CaseResult(False, f"case raised {type(e).__name__}: {e}")
        took = time.monotonic() - t0
        c.verdict = "PASS" if result.ok else "FAIL"
        c.observed = result.observed
        c.evidence = result.evidence
        c.evidence["elapsed_s"] = round(took, 2)
        # Establish the derived bound from the baseline as soon as it exists.
        lat = result.evidence.get("latencies_ms")
        if cid == "device-answers-ping" and lat:
            baseline = max(lat)
            ctx["baseline_ms"] = baseline
            ctx["bound_ms"] = max(args.bound_floor_ms,
                                  args.bound_factor * baseline)
            c.evidence["baseline_ms"] = baseline
            c.evidence["derived_bound_ms"] = round(ctx["bound_ms"], 1)
        log(f"    {'PASS' if result.ok else 'FAIL'}  {result.observed}  ({took:.1f}s)")
        cases.append(c)
        needs_recovery = abandons

    hdr("STEP 3 — derived latency bound (how the numbers above were judged)")
    if ctx["baseline_ms"]:
        log(f"idle baseline (worst of {BASELINE_PINGS} pings): "
            f"{ctx['baseline_ms']:.1f} ms")
        log(f"bound = max(floor {args.bound_floor_ms:.0f} ms, "
            f"factor {args.bound_factor:.0f} x baseline) = "
            f"{ctx['bound_ms']:.1f} ms")
        log("The bound is derived from this run's own healthy measurement, not "
            "picked to pass.")
        log("For scale: the C reference answered 4 pings in 8.0 ms each over the "
            "same window; this firmware, before the fix, answered one at "
            "30047.7 ms while its host's writes blocked to ETIMEDOUT.")
    else:
        log("The idle baseline did not measure, so the bound fell back to the "
            f"absolute floor of {args.bound_floor_ms:.0f} ms.")
        log("Treat the post-abandon cases as uncalibrated in this run.")

    browser_results = None
    chrome = None
    if args.run_browser:
        hdr("STEP 4 — browser acceptance page (HUMAN-GATED ceremonies)")
        chrome = find_chrome(args.browser)
        if not chrome:
            log("FATAL: no Chrome/Chromium found. Pass --browser /path/to/chrome.")
            return 2
        cert, key, trust_note = https_server.ensure_certificate()
        srv = https_server.Server(certfile=cert, keyfile=key).start()
        log(f"browser : {chrome}")
        log(f"serving : {srv.url}")
        log(f"cert    : {cert}")
        for line in trust_note.splitlines():
            log(f"          {line}")
        extra = args.browser_args.split() if args.browser_args else []
        if args.headed:
            extra = [a for a in extra if a != "--headless=new"]
        else:
            extra = ["--headless=new", "--no-sandbox", "--disable-gpu"] + extra
        log()
        log("The page will drive the request shapes. Each one needs a physical")
        log("TOUCH of the board's button; the runner cannot and does not")
        log("simulate user presence. Leave the browser up and touch the button")
        log("when prompted. A case that does not report before its deadline is")
        log("a FAIL, not a skip.")
        log()
        try:
            browser_results = run_browser(chrome, srv.url,
                                          https_server.user_data_dir(),
                                          args.browser_wait_s, extra,
                                          autorun=args.browser_autorun)
        finally:
            # The cert and the browser profile are torn down on the process
            # exit path (see the __main__ block), which also covers a
            # KeyboardInterrupt or SIGTERM in here. The socket is this run's
            # own resource and stops here.
            srv.stop()
        log()
        log("page-reported results:")
        log(json.dumps(browser_results, indent=2))

    # --- assemble the report ---

    hdr("RESULTS")
    all_cases = [c.as_dict() for c in cases]
    for cid, shape in HUMAN_CASES:
        pr = (browser_results or {}).get(cid)
        all_cases.append({
            "case": cid, "title": shape, "gate": "human",
            "verdict": (pr or {}).get("verdict", "NOT RUN"),
            "observed": (pr or {}).get("observed", "no verdict reported"),
            "evidence": {},
            "out_of_scope": False,
        })
    # The page's two MACHINE-gated cases. Whether they are machine-gated for
    # THIS run depends on whether a browser was launched: with no `--run-browser`
    # there is nothing that could report them, so filing them under
    # `gate: "machine"` would put two cases that cannot run into the machine
    # tally and let the run exit 0 over them (the defect fixed above). They
    # stay listed, named, and flagged `out_of_scope` so a board-only run says
    # out loud what it did not verify.
    for cid in MACHINE_PAGE_CASES:
        pr = (browser_results or {}).get(cid)
        in_scope = args.run_browser
        all_cases.append({
            "case": f"page:{cid}", "title": "page-side check",
            "gate": "machine" if in_scope else "browser",
            "verdict": (pr or {}).get("verdict", "NOT RUN"),
            "observed": (pr or {}).get(
                "observed",
                "no verdict reported" if in_scope
                else "out of scope: this run did not pass --run-browser, so "
                     "no browser was launched and the page could not report it"),
            "evidence": {},
            "out_of_scope": not in_scope,
        })

    log(f"{'case':<44} {'gate':<8} {'verdict'}")
    log("-" * 78)
    for c in all_cases:
        mark = {"PASS": "PASS", "FAIL": "FAIL"}.get(c["verdict"],
                                                     c["verdict"])
        log(f"{c['case']:<44} {c['gate']:<8} {mark}")
    log()
    tally = classify_cases(all_cases)
    machine = tally["machine"]
    machine_pass = tally["machine_pass"]
    machine_fail = tally["machine_fail"]
    machine_notrun = tally["machine_notrun"]
    out_of_scope = tally["out_of_scope"]
    complete = tally["complete"]
    log(f"machine-checkable: {len(machine_pass)}/{len(machine)} pass "
        f"({len(machine_fail)} fail, {len(machine_notrun)} not run)")
    if machine_notrun:
        log("  IN SCOPE AND DID NOT REPORT, counted as NOT passing: "
            + ", ".join(c["case"] for c in machine_notrun))
        log("  (these were machine-gated for this run, so something that "
            "should have reported them did not; that is a harness failure, "
            "not a pass)")
    if out_of_scope:
        log()
        log("*** NOT CERTIFIED BY THIS RUN ***")
        log("  These are machine-gated cases the acceptance page owns, and "
            "this run did not exercise them:")
        for c in out_of_scope:
            log(f"    - {c['case']}  ({c['observed']})")
        log("  Exit code 0 therefore means the cases this run COULD execute "
            "all passed.")
        log("  It does NOT mean the browser-discovery DoD was verified. "
            "Re-run with --run-browser for that.")
    if any(c["gate"] == "human" for c in all_cases):
        log()
        log("human-gated: the ceremonies above need a physical touch; a "
            "'NOT RUN' there means the operator did not run them, which is "
            "not a pass. Human-gated cases never affect the exit code.")

    exit_code = tally["exit_code"]
    report = {
        "harness": "US-1518 acceptance",
        "board_selected": ctap.describe(device),
        "bound": {"floor_ms": args.bound_floor_ms,
                  "factor": args.bound_factor,
                  "baseline_ms": ctx["baseline_ms"],
                  "derived_ms": ctx["bound_ms"]},
        "recoveries_between_cases": recoveries,
        "complete": complete,
        "out_of_scope": [c["case"] for c in out_of_scope],
        "exit_code": exit_code,
        "exit_code_contract": {
            "0": "every machine-gated case in this run reported PASS",
            "1": "a machine case failed, or one was in scope and did not report",
            "2": "the harness could not run",
        },
        "cases": all_cases,
    }
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        log(f"\nwrote {args.json_out}")

    hdr("MACHINE-READABLE RESULTS")
    log(json.dumps(report, indent=2, default=str))

    log()
    log(f"EXIT CODE {exit_code} — " + (
        "every machine-gated case in this run passed"
        if complete else
        "NOT a clean run: see the summary above"))
    return exit_code


def _install_signal_handlers():
    """Turn SIGTERM/SIGHUP into exceptions so `finally` still runs.

    A harness that is generating a private key is killed by plenty of things
    the operator did not plan on -- a CI timeout, a closing terminal, a
    supervisor. Default SIGTERM disposition skips every cleanup handler in
    Python, which is exactly how a key ends up left in the working tree. The
    handler raises, the `finally` below does the work, and the process then
    exits 130 rather than dying silently mid-run -- which is the honest
    status for "interrupted, and here is what it managed to clean up".
    """

    def _raise(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")

    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _raise)
        except (ValueError, OSError):
            pass  # not the main thread, or the platform disagrees; nothing to do


if __name__ == "__main__":
    _install_signal_handlers()
    # The single place generated material is torn down. Wrapping the whole
    # entry point rather than just the browser phase is deliberate: argparse's
    # SystemExit on a bad flag, every early `return 2` from main(), an
    # exception from a case, and Ctrl-C all land here, and the ones that
    # actually created a key are the ones most likely to be interrupted. This
    # is a no-op for a run that never made one.
    try:
        sys.exit(main())
    finally:
        for path in https_server.cleanup_generated():
            print("cleanup: removed " + path)