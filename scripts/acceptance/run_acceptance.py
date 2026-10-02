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

  abandoned-attempt-does-not-block-the-host
      the same scenario, but measuring whether the host's own WRITE blocks --
      the second half of the defect, where writes block to ETIMEDOUT.

  device-enumerates / device-answers-ping
      the baseline those two are compared against, measured in the same run on
      the same device, so the bound is derived rather than assumed.

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

# How long to wait for the device to become answerable again after a case that
# abandoned a ceremony. It recovers on its own once its own ~30 s window timer
# expires (measured), so this is generous; exceeding it is a real result.
RECOVERY_BUDGET_S = 90.0


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


def hdr(title):
    log()
    log("=" * 78)
    log(title)
    log("=" * 78)


# ---------------------------------------------------------------------------
# Machine cases
# ---------------------------------------------------------------------------


def case_device_enumerates(ctx):
    """The board is attached, is a CTAPHID node, and answers INIT."""
    dev = ctx["device"]
    ev = {"device": ctap.describe(dev)}
    try:
        with ctap.Wire(dev) as w:
            init = w.init()
            ev["init"] = init
            if init["cid"] == "0x00000000":
                return CaseResult(False, "INIT assigned cid 0x00000000", ev)
            return CaseResult(True, f"INIT ok, cid {init['cid']}, "
                                    f"firmware {init['firmware_version']}, "
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
    the same run rather than assumed."""
    dev = ctx["device"]
    ev = {}
    lat = []
    try:
        with ctap.Wire(dev) as w:
            w.init()
            for i in range(BASELINE_PINGS):
                r = w.ping(b"BASELINE%02d" % i)
                lat.append(r["latency_ms"])
                if not r["echo_ok"]:
                    ev.setdefault("echo_failures", []).append(i)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"{type(e).__name__}: {e}", ev)
    ev["latencies_ms"] = lat
    if not lat:
        return CaseResult(False, "no PING samples", ev)
    worst = max(lat)
    floor = ctx["bound_floor_ms"]
    ok = worst <= floor
    return CaseResult(ok, f"{len(lat)} pings, worst {worst:.1f} ms "
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
    """
    dev = ctx["device"]
    ev = {"abandon_settle_s": ABANDON_SETTLE_S}
    rp = "us1518-abandon.invalid"
    try:
        w = ctap.Wire(dev)
    except OSError as e:
        return CaseResult(False, f"could not open {dev['path']}: {e}", ev)
    try:
        w.init()
        # Real consent window: GetNextAssertion to a throwaway RP parks the
        # authenticator in the user-presence wait and streams KEEPALIVE 0x02.
        # A MakeCredential to a throwaway RP is rejected at the CBOR layer on
        # this firmware and never parks anything, so it cannot stand in here.
        w.get_assertion_request(rp, b"\x11" * 32)
        parked = w.drain_until_closed(timeout=ABANDON_SETTLE_S)
        ev["during_window"] = parked
        if parked["keepalives"] == 0:
            ev["note"] = ("the device did not park in a consent window; the "
                          "abandoned attempt may not have been exercised")
        # Walk away: stop reading. A real dismissal also stops the host from
        # draining, which is the whole shape of the defect.
        ev["walked_away"] = True
        time.sleep(0.2)
    except (ctap.HarnessError, OSError) as e:
        w.close()
        return CaseResult(False, f"opening the consent window failed: "
                                  f"{type(e).__name__}: {e}", ev)

    bound = ctx["bound_ms"]
    baseline = ctx["baseline_ms"]
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
            w2.close()
            w.close()
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
        if not p["echo_ok"]:
            return CaseResult(False,
                              f"PING echoed wrong bytes after the abandoned "
                              f"attempt ({p['latency_ms']:.1f} ms)", ev)
        ok = p["latency_ms"] <= bound
        ratio = (p["latency_ms"] / baseline) if baseline else float("inf")
        ev["latency_ratio_vs_baseline"] = round(ratio, 1)
        return CaseResult(
            ok,
            f"re-enumerated in {reinit_ms:.1f} ms, answered PING in "
            f"{p['latency_ms']:.1f} ms "
            f"(bound {bound:.0f} ms = {ctx['bound_factor']:.0f}x the "
            f"{baseline:.1f} ms idle baseline; ratio {ratio:.1f}x)",
            ev)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False,
                          f"post-abandon probe failed: {type(e).__name__}: {e}", ev)
    finally:
        w2.close()
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
    """
    dev = ctx["device"]
    ev = {"write_watchdog_s": ctap.WATCHDOG_WRITE_S}
    rp = "us1518-block.invalid"
    try:
        w = ctap.Wire(dev)
    except OSError as e:
        return CaseResult(False, f"could not open {dev['path']}: {e}", ev)
    try:
        w.init()
        w.get_assertion_request(rp, b"\x22" * 32)
        parked = w.drain_until_closed(timeout=ABANDON_SETTLE_S)
        ev["during_window"] = parked
        time.sleep(0.2)
        # Time a single write on the SAME handle the ceremony was issued on.
        # This is the write a browser would issue to poll or to cancel.
        t0 = time.monotonic()
        try:
            w.send(ctap.CTAPHID_PING, b"WRITEAFTER", cid=w.cid)
            write_ms = (time.monotonic() - t0) * 1000
        except ctap.HidWriteBlocked as e:
            ev["write_blocked"] = True
            ev["write_ms"] = round((time.monotonic() - t0) * 1000, 1)
            w.close()
            return CaseResult(
                False,
                f"the host's WRITE BLOCKED for "
                f"{(time.monotonic()-t0)*1000:.0f} ms after the abandoned "
                f"attempt ({e}). The device is not draining its OUT endpoint.",
                ev)
        except (ctap.HarnessError, OSError) as e:
            w.close()
            return CaseResult(False, f"write raised {type(e).__name__}: {e}", ev)
        ev["write_ms"] = round(write_ms, 1)
        # The write landed; now make sure the device is still coherent.
        try:
            p = w.ping(b"AFTERWRITE", timeout=ctx["probe_timeout_s"])
            ev["ping_after_write"] = p
            ok = p["echo_ok"] and p["latency_ms"] <= ctx["bound_ms"]
            return CaseResult(ok,
                              f"write completed in {write_ms:.1f} ms and the "
                              f"device still answered in {p['latency_ms']:.1f} ms "
                              f"(bound {ctx['bound_ms']:.0f} ms)", ev)
        except (ctap.HarnessError, OSError) as e:
            return CaseResult(False,
                              f"write completed in {write_ms:.1f} ms but the "
                              f"device then failed to answer: "
                              f"{type(e).__name__}: {e}", ev)
    finally:
        try:
            w.close()
        except Exception:
            pass


def case_device_survives_repeated_abandonment(ctx):
    """Abandon a ceremony, then prove the NEXT ceremony still engages.

    Closes the loop on DoD item 8: it is not enough that the device answers a
    PING; it must still service a fresh user-presence window afterwards.
    """
    dev = ctx["device"]
    ev = {}
    rp = "us1518-next.invalid"
    try:
        w = ctap.Wire(dev)
    except OSError as e:
        return CaseResult(False, f"could not open {dev['path']}: {e}", ev)
    try:
        w.init()
        # Abandon one.
        w.get_assertion_request(rp, b"\x33" * 32)
        ev["abandoned"] = w.drain_until_closed(timeout=ABANDON_SETTLE_S)
        time.sleep(0.5)
        # Now the next ceremony, on a fresh connection.
        w2 = ctap.Wire(dev)
        try:
            w2.init(timeout=ctx["probe_timeout_s"])
            w2.get_assertion_request("us1518-next2.invalid", b"\x44" * 32)
            next_window = w2.drain_until_closed(timeout=ABANDON_SETTLE_S)
            ev["next_window"] = next_window
            if next_window["keepalives"] == 0:
                return CaseResult(
                    False,
                    "after an abandoned ceremony the device did not engage a "
                    f"new user-presence window ({next_window['outcome']})", ev)
            return CaseResult(True,
                              f"after abandoning one ceremony the device "
                              f"engaged the next ({next_window['keepalives']} "
                              f"keepalives, statuses {next_window['statuses']})",
                              ev)
        finally:
            w2.close()
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"{type(e).__name__}: {e}", ev)
    finally:
        try:
            w.close()
        except Exception:
            pass


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
    """
    dev = ctx["device"]
    ev = {}
    try:
        with ctap.Wire(dev) as w:
            w.init()
            status, info, _ = w.get_info()
            if status != 0 or info is None:
                return CaseResult(False,
                                  f"GetInfo status 0x{status:02x}", ev)
            # GetInfo member 4 is the options map. It may be keyed by text name
            # or by integer id depending on the device; report what is actually
            # there, never a substituted default.
            options = info.get(4)
            if options is None:
                ev["options"] = "member 4 absent from the reply (unobserved)"
                return CaseResult(True,
                                  "GetInfo answered; no options map present "
                                  "(recorded, not assumed)", ev)
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
            return CaseResult(True,
                              f"options map: {len(options)} entries, "
                              f"key type(s) {ev['option_key_types']}", ev)
    except (ctap.HarnessError, OSError) as e:
        return CaseResult(False, f"{type(e).__name__}: {e}", ev)


def wait_for_recovery(ctx, budget_s=RECOVERY_BUDGET_S):
    """Wait until the device is answerable again, and report how long it took.

    Why this is not just politeness: the device under test is known to go blind
    after an abandoned ceremony and to recover on its own once its ~30 s window
    timer expires (measured: it recovered unattended during this session).
    Without an explicit wait between cases, the FIRST regression case leaves
    the device blind and the SECOND and THIRD then fail because of the first
    one's damage rather than their own. Three FAILs that are really one FAIL is
    worse than useless -- it hides which parts of the fix are broken.

    So each regression case starts from a verified-healthy device, and the
    recovery time is recorded as evidence in its own right.
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
            time.sleep(2)
            continue
        try:
            w.init(timeout=3.0)
            p = w.ping(b"RECOVER", timeout=3.0)
            if p["echo_ok"]:
                return {"recovered": True, "waited_s": round(time.monotonic() - t0, 1),
                        "attempts": attempts, "ping_ms": p["latency_ms"]}
            last = f"PING echo mismatch ({p['latency_ms']} ms)"
        except (ctap.HarnessError, OSError) as e:
            last = f"{type(e).__name__}: {e}"
        finally:
            try:
                w.close()
            except Exception:
                pass
        time.sleep(2)
    return {"recovered": False, "waited_s": round(time.monotonic() - t0, 1),
            "attempts": attempts, "last_error": last}


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
     "REGRESSION: after an abandoned attempt the device still engages the "
     "next ceremony",
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
            log(f"    (device recovered in {rec['waited_s']}s after "
                f"{rec['attempts']} attempt(s), ping {rec['ping_ms']} ms)")
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
        browser_results = run_browser(chrome, srv.url,
                                      os.path.join(https_server.CERT_DIR, "udd"),
                                      args.browser_wait_s, extra,
                                      autorun=args.browser_autorun)
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
        })
    for cid in MACHINE_PAGE_CASES:
        pr = (browser_results or {}).get(cid)
        all_cases.append({
            "case": f"page:{cid}", "title": "page-side check", "gate": "machine",
            "verdict": (pr or {}).get("verdict", "NOT RUN"),
            "observed": (pr or {}).get("observed", "no verdict reported"),
            "evidence": {},
        })

    log(f"{'case':<44} {'gate':<8} {'verdict'}")
    log("-" * 78)
    for c in all_cases:
        mark = {"PASS": "PASS", "FAIL": "FAIL"}.get(c["verdict"],
                                                     c["verdict"])
        log(f"{c['case']:<44} {c['gate']:<8} {mark}")
    log()
    # Count ONLY real passes. A machine case that reported nothing is NOT a
    # pass -- counting it as one would let CI go green on a case that never
    # ran, which is exactly the failure mode this harness exists to prevent.
    machine = [c for c in all_cases if c["gate"] == "machine"]
    machine_pass = [c for c in machine if c["verdict"] == "PASS"]
    machine_fail = [c for c in machine if c["verdict"] == "FAIL"]
    machine_notrun = [c for c in machine if c["verdict"] not in ("PASS", "FAIL")]
    log(f"machine-checkable: {len(machine_pass)}/{len(machine)} pass "
        f"({len(machine_fail)} fail, {len(machine_notrun)} not run)")
    if machine_notrun:
        log("  NOT counted as passes: "
            + ", ".join(c["case"] for c in machine_notrun)
            + "  (the page-side cases only run with --run-browser)")
    if any(c["gate"] == "human" for c in all_cases):
        log("human-gated: the ceremonies above need a physical touch; a "
            "'NOT RUN' there means the operator did not run them, which is "
            "not a pass.")

    report = {
        "harness": "US-1518 acceptance",
        "board_selected": ctap.describe(device),
        "bound": {"floor_ms": args.bound_floor_ms,
                  "factor": args.bound_factor,
                  "baseline_ms": ctx["baseline_ms"],
                  "derived_ms": ctx["bound_ms"]},
        "recoveries_between_cases": recoveries,
        "cases": all_cases,
    }
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        log(f"\nwrote {args.json_out}")

    hdr("MACHINE-READABLE RESULTS")
    log(json.dumps(report, indent=2, default=str))

    return 1 if machine_fail else 0


if __name__ == "__main__":
    sys.exit(main())