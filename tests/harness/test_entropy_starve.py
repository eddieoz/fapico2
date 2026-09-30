"""US-1007 — entropy starvation is survivable (the emulation twin).

The story asks for one **live** device, observed four times: an OpenPGP
request that needs randomness and a FIDO request that needs randomness,
both while the TRNG is forced to fail, answer a **clean error** (not a
panic, not a hang, not silence); the device stays **enumerable over CCID
and HID**; and a request after recovery succeeds.

None of that is expressible on a host without a seam — the host entropy
source reads ``/dev/urandom``, which is correct and unkillable, and
"starve, then recover" is a transition of a *running* process, which a
process-start environment variable cannot express. The seam is
``platform/src/entropy_starve.rs``: a control file whose **existence** is
the live state, ``cfg``-gated to the emulation feature and a non-``arm``
target, and policed by ``tests/scripts/check_rng_path.py``.


What the twin asserts, and the two properties it cannot
--------------------------------------------------------

**Green, and the substance of the story** — a starved device is still a
device, and it comes back:

* the injection is **live** (a differential: the same request succeeds
  healthy and does not while starved — without this, every other test here
  would also pass against an inert seam);
* the device stays enumerable over **both** transports while starved
  (CCID ``SELECT`` *and* HID ``getInfo`` — two independent transport
  stacks, so this is not one transport answering twice);
* entropy **recovery needs no restart** — removing the control file is
  enough and subsequent requests succeed;
* the OpenPGP request path keeps serving **real** randomness while the
  peripheral is starved. That is not a consolation prize; see below.

**The two properties the story asks for that this tree does not have.**
One is now green; one is still recorded as a finding.

*FIXED — a starved FIDO keygen now answers a clean, bounded error.* This
landed as an ``xfail`` with the finding written out: ``crypto.rs``'s RNG
adapters implemented ``try_fill_bytes`` as ``self.fill_bytes(dest); Ok(())``
— infallible by construction, so a starved draw was reported as **success**
with an untouched buffer, and ``p256::SecretKey::random`` then
rejection-sampled that constant buffer forever. The draw is now fallible and
the rejection is capped at ``KEYGEN_MAX_ATTEMPTS``; the test asserts the
CTAP catch-all comes back in microseconds. The diagnosis is kept in the
test's own docstring rather than deleted, because it is the reason the
assertion is shaped the way it is.

*STILL OPEN — a device already starved at power-on never enumerates.*
``FidoApp::with_keystore`` still calls the **infallible**
``crypto::generate_p256_keypair`` unconditionally, so the unbounded sampler
still runs during host construction, before any transport exists. This is
the boot path, not the request path: ``generate_p256_keypair`` has 45
callers and no fallible return, so bounding it is a signature change across
the whole tree and was not made here. The device does not take this path —
``main.rs`` uses the store-backed ``FidoApp::boot`` — but "the device does
not" is **not** the same as "the device is safe", and see the D-9 amendment:
the device's own boot and request paths have their own unbounded samplers,
which this change bounded (``device_core.rs``) but did not remove.

Why the OpenPGP leg answers 9000 rather than a clean error
-----------------------------------------------------------

This is the load-bearing measurement of the whole story, and it is a
**property of the design US-1005 landed**, not a gap in it.

trussed's ``Service`` does not hand the platform RNG to callers. It keeps
its own ChaCha8 DRBG, and ``Service::rng()`` draws from the platform
**once**, the first time it is needed, then serves every later draw from
that generator. ``trussed-0.2.0/src/service.rs:705-775`` says so in its
own comments ("We do not [mix in new entropy] on each DRBG draw to avoid
excessive flash writes"), and the measurement agrees exactly: with the
seam instrumented, a full healthy → starved → recovered session issues
**one** platform draw, at boot, and **none** afterwards — so every
starved ``GET CHALLENGE`` is answered from DRBG output and every one
succeeds.

That is the *intended* behaviour of the Phase 1 outcome. A peripheral
going away is not "no entropy": a DRBG seeded from good entropy is
designed to outlive exactly that. The request path only answers ``6400``
when the **generator** cannot re-seed — which is a different fault at a
different layer, and is what ``apps/openpgp/tests/rng_stall.rs`` pins at
the library level with a constructed stalled platform. This twin does not
duplicate that test; it establishes what the *running device* does, and
the answer is that peripheral starvation is invisible to it.

So the story's OpenPGP leg, read literally ("a request that needs
randomness answers a clean error while the TRNG is failed"), is not a
property this firmware has or should have. Read as the epic means it —
"entropy starvation is survivable" — it holds, and the tests below are the
evidence. The literal reading is recorded in the report as the one place
the BDD and the design disagree.


Ports
-----

Private relay + emulator, disjoint from every sibling (see the port map in
``ccid_relay.py``): CCID dial-in 36218 / client 36219, HID 36217. Its own
keystore/partition/piv paths under ``tmp_path``, so it inherits no state
from the shared ``run_tests.sh`` emulator.

These are fixed private ports on purpose, and that is what makes releasing
them a contract rather than a courtesy: ``run_tests.sh`` runs each suite
directory in its own ``pytest`` invocation, so a suite that leaves an
emulator bound breaks the *next* invocation instead of its own. Every path
out of [`_device`] — pass, assertion, or the starved-power-on startup
failure — reaps the emulator and the relay. See that function for the bug
this replaced.
"""

import contextlib
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fido2.cbor import encode as cbor_encode

from harness.test_restart import Emu

REPO = Path(__file__).resolve().parents[2]

# Private ports for this suite (see the map in tests/harness/ccid_relay.py).
RELAY_CCID_PORT = 36218    # the emulator dials in here (FAPICO2_CCID_PORT)
RELAY_CLIENT_PORT = 36219  # this test connects here
HID_PORT = 36217

OPENPGP_AID = bytes.fromhex("D27600012401")

SW_OK = 0x9000

# Per-request wall-clock ceiling. Distinguishing "hung" from "answered" is
# half of what this file is for, so the ceiling has to be short enough to
# fail a spin quickly and long enough that a healthy p256 operation is
# never the thing that trips it.
REQUEST_TIMEOUT_S = 8

# How long a healthy emulator gets to boot before the harness calls it dead.
BOOT_TIMEOUT_S = 10

# CTAP 2.1's catch-all status, which a starved FIDO keygen answers with.
# Not "any non-zero": a panic, a transport error or a truncated frame would
# all satisfy `!= 0x00` without being the property the story asks for.
CTAP2_ERR_OTHER = 0x7F

# A refused keygen must be immediate. The rejection sampler is capped at
# KEYGEN_MAX_ATTEMPTS draws, so the honest answer is microseconds; this is
# orders of magnitude above that and orders below REQUEST_TIMEOUT_S, which
# makes it a claim about the *shape* of the answer — "it came back" is
# already enforced by `_call`, which raises `_Halt` if it did not.
BOUNDED_KEYGEN_SECONDS = 1.0

# Mirrors `crypto::KEYGEN_MAX_ATTEMPTS` in apps/fido/src/crypto.rs. Named
# here so the failure message can say what the ceiling is, and because the
# two must not drift: a Rust-side change to the cap should make a starved
# keygen slower than this bound rather than silently redefine it.
KEYGEN_MAX_ATTEMPTS = 8


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("CCID connection closed")
        buf += chunk
    return bytes(buf)


def _ccid(sock, apdu):
    """One [u16 BE length] framed APDU exchange; returns the raw response."""
    sock.sendall(struct.pack(">H", len(apdu)) + apdu)
    (length,) = struct.unpack(">H", _recv_exact(sock, 2))
    return _recv_exact(sock, length)


def _sw(resp):
    return (resp[-2] << 8) | resp[-1]


class _Halt(Exception):
    """A request did not answer inside its deadline.

    Deliberately its own type. A starved device that merely *fails to
    answer* is the negative property this suite must be able to name, and a
    bare ``socket.timeout`` escaping into pytest output is indistinguishable
    from a broken harness — which is exactly the confusion the story is
    about.
    """


def _call(label, fn, *args):
    """Run `fn`, turning a timeout into a named `_Halt` failure.

    The single place the suite draws the "hung vs answered" line, drawn
    explicitly rather than by letting a socket timeout escape.
    """
    try:
        return fn(*args)
    except socket.timeout as exc:
        raise _Halt(
            f"{label}: no answer within {REQUEST_TIMEOUT_S}s — the device HUNG. "
            "A starved request must answer a clean error, not stop answering."
        ) from exc


class _Starved:
    """The starvation control file.

    Existence is the live state: absent -> healthy, present -> starved. The
    process is never restarted to change it, which is the point — "starve,
    observe, recover" is a transition of a running device, and a
    process-start variable has exactly one value for a whole process life.
    """

    def __init__(self, path: Path):
        self.path = path

    def starve(self):
        self.path.write_text("1")

    def recover(self):
        self.path.unlink(missing_ok=True)


def _wait_relay_line(proc, needle, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        if needle in line:
            return
    raise AssertionError(f"ccid relay did not report {needle!r} within {timeout}s")


class _Relay:
    def __init__(self):
        self.proc = subprocess.Popen(
            [sys.executable, str(REPO / "tests" / "harness" / "ccid_relay.py"),
             "--ccid-port", str(RELAY_CCID_PORT),
             "--client-port", str(RELAY_CLIENT_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _wait_relay_line(self.proc, "READY", timeout=10)

    def stop(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except (subprocess.TimeoutExpired, OSError):
            self.proc.kill()
        self.proc = None


class _Device:
    """A running emulator plus its two client connections.

    Constructed healthy and starved *afterwards*, because a device started
    already starved never finishes booting (see
    `test_a_starved_device_can_still_boot`).

    Lifetime is owned by [`_device`], not by `__enter__`/`__exit__` — see
    that function for why startup has to be inside the `try`.
    """

    def __init__(self, tmp_path: Path, starve: _Starved, relay: _Relay):
        self.starve = starve
        self.relay = relay
        self.emu = Emu(
            tmp_path / "starve_keystore.cbor",
            hid_port=HID_PORT,
            partition_path=tmp_path / "starve_partition.bin",
            piv_path=tmp_path / "starve_piv.cbor",
        )
        self.cc = None

    def _start(self):
        self.emu.start()
        self.relay.proc.stdout.readline()  # emulator connected
        self.cc = socket.create_connection(
            ("127.0.0.1", RELAY_CLIENT_PORT), timeout=5
        )
        self.cc.settimeout(REQUEST_TIMEOUT_S)
        self.relay.proc.stdout.readline()  # test client connected

    def _stop(self):
        if self.cc is not None:
            try:
                self.cc.close()
            except OSError:
                pass
            self.cc = None
        # SIGTERM first — the emulator flushes its keystore on the way out —
        # then SIGKILL. The escalation is not decoration. `Emu.stop` waits 5 s
        # and re-raises `TimeoutExpired` if the child ignored the signal,
        # which is exactly what a wedged emulator does; without the
        # escalation the process survives, keeps HID_PORT bound, and the
        # *next* run of this suite (or `run_tests.sh`'s next suite) fails on
        # a port collision that has nothing to do with the code under test.
        proc = self.emu.proc
        try:
            self.emu.stop(signal.SIGTERM)
        except subprocess.TimeoutExpired:
            if proc is not None:
                proc.kill()
                proc.wait(timeout=10)
        self.emu.sock = None

    # -- CCID ----------------------------------------------------------

    def select_openpgp(self):
        apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(OPENPGP_AID)]) + OPENPGP_AID
        return _ccid(self.cc, apdu)

    def get_challenge(self):
        """GET CHALLENGE, 8 bytes (OpenPGP card spec 7.2.8)."""
        return _ccid(self.cc, bytes([0x00, 0x84, 0x00, 0x00, 0x08]))

    # -- HID -----------------------------------------------------------

    def fido_get_info(self):
        return self.emu.ctap(0x04, b"")

    def fido_get_assertion(self):
        return self.emu.ctap(0x02, cbor_encode({1: "example.com", 2: b"\x5a" * 32}))

    def fido_make_credential(self):
        return self.emu.ctap(0x01, cbor_encode({
            1: b"\x11" * 32,
            2: {"id": "example.com", "name": "RP"},
            3: {"id": b"user", "name": "A User"},
            4: [{"type": "public-key", "alg": -7}],
            7: {"rk": True},
        }))


@contextlib.contextmanager
def _device(tmp_path, starve, relay):
    """A private emulator + relayed CCID client, alive for the block.

    The house pattern for a suite-owned emulator is ``_redteam_device`` in
    ``test_redteam.py``: one ``try/finally`` that owns the whole lifetime,
    **startup included**. That placement is the fix, not a style choice.

    The previous shape put startup in ``__enter__`` and teardown in
    ``__exit__``, and Python does not call ``__exit__`` when ``__enter__``
    raises. So whenever the emulator failed to come up — which is exactly
    what the starved-power-on case does, since the FIDO host construction
    path never finishes — the spawned process was orphaned, spinning at
    100% CPU and holding HID_PORT. The *next* run then timed out talking to
    that orphan instead of its own, and the suite failed for a reason that
    had nothing to do with the code under test: it passed only on a host
    where no earlier run had leaked. Four green runs, then four reds,
    depending on nothing but history.

    Covering startup also covers every other exit path for free: a failed
    assertion, a `_Halt` timeout, or a ``pytest.fail`` inside the block all
    unwind through the same ``finally``. What it cannot cover is a *pytest*
    timeout that kills the worker outright — no user-space ``finally``
    survives that, which is why no such timeout is configured for this
    suite.
    """
    dev = _Device(tmp_path, starve, relay)
    try:
        dev._start()
        yield dev
    finally:
        dev._stop()


@pytest.fixture()
def starve_file(tmp_path, monkeypatch):
    """Point the emulator at a control file that does not exist yet.

    ``FAPICO2_ENTROPY_STARVE_FILE`` is read once at first use and names the
    *path*; the file's existence is the live switch. So the device boots
    healthy here and can be starved and recovered later, in-process.
    """
    path = tmp_path / "entropy_starve"
    monkeypatch.setenv("FAPICO2_ENTROPY_STARVE_FILE", str(path))
    monkeypatch.setenv("FAPICO2_CCID_PORT", str(RELAY_CCID_PORT))
    monkeypatch.setenv("FAPICO2_KEYSTORE", str(tmp_path / "starve_keystore.cbor"))
    monkeypatch.setenv(
        "FAPICO2_SECURE_PARTITION", str(tmp_path / "starve_partition.bin")
    )
    monkeypatch.setenv("FAPICO2_PIV_KEYSTORE", str(tmp_path / "starve_piv.cbor"))
    return _Starved(path)


@pytest.fixture()
def relay():
    r = _Relay()
    try:
        yield r
    finally:
        r.stop()


# ---------------------------------------------------------------------------
# 1. The injection is real
# ---------------------------------------------------------------------------


def test_the_injection_is_live(starve_file, relay, tmp_path):
    """Starvation changes what the device does. Without this, everything
    below would also pass against an inert seam.

    The observable is a differential on one request, `makeCredential`: it
    succeeds when healthy and answers a CTAP error when starved. That is
    the only request in the suite whose *behaviour* the seam is expected to
    change (see the module docstring for why the OpenPGP path's is
    unchanged by design) — so it is the only honest liveness witness, and
    it is witnessed differentially rather than by inspecting a buffer.

    This witness used to be `pytest.raises(_Halt)`: starvation was detected
    by the request failing to come back. That was accurate when the spin was
    the behaviour, and it made the suite *depend* on the defect — a fix that
    made the starved keygen answer would have broken the liveness check that
    justified the rest of the file. The differential is unchanged in kind
    (same request, same seam, different outcome) and now points at the
    fixed behaviour.
    """
    with _device(tmp_path, starve_file, relay) as dev:
        assert dev.fido_make_credential()[0] == 0x00, "healthy keygen must work"

        starve_file.starve()
        starved = _call("starved makeCredential", dev.fido_make_credential)
        assert starved[0] != 0x00, (
            "starvation must change what the device does — if a starved "
            "keygen still succeeds, the seam is inert and every other test "
            "in this file is vacuous"
        )


# ---------------------------------------------------------------------------
# 2. Enumerable over BOTH transports while starved
# ---------------------------------------------------------------------------


def test_starved_device_stays_enumerable_over_ccid_and_hid(
    starve_file, relay, tmp_path
):
    """A starved device is still a device.

    Enumerability is what separates "one request failed" from "the card is
    gone". CCID `SELECT` and HID `getInfo` are the two a client enumerates
    with, and they exercise two independent transport stacks (the CCID
    relay/socket path and the CTAP-HID frame path), so passing both is not
    one transport answering twice.
    """
    with _device(tmp_path, starve_file, relay) as dev:
        starve_file.starve()

        ccid_resp = _call("starved CCID SELECT", dev.select_openpgp)
        assert _sw(ccid_resp) == SW_OK, (
            "a starved device must still answer SELECT over CCID — entropy "
            "starvation is not a dead card"
        )

        hid_resp = _call("starved HID getInfo", dev.fido_get_info)
        assert hid_resp[0] == 0x00, (
            f"a starved device must still answer getInfo over HID; "
            f"CTAP status 0x{hid_resp[0]:02x}"
        )
        # And CCID is still usable afterwards, which "enumerable" does not
        # on its own: a transport that answered once and then wedged has
        # not stayed enumerable.
        assert _sw(_call("CCID SELECT (repeat)", dev.select_openpgp)) == SW_OK


# ---------------------------------------------------------------------------
# 3. The OpenPGP path keeps serving real randomness
# ---------------------------------------------------------------------------


def test_openpgp_requests_still_succeed_while_starved(starve_file, relay, tmp_path):
    """A starved peripheral is not a starved generator.

    The honest reading of "entropy starvation is survivable" for this
    firmware: trussed's ChaCha8 DRBG was seeded from good entropy at boot
    and serves every later draw, so a peripheral that stops producing is
    invisible to the request path. Asserted as *served*, with a positive
    check that the bytes are fresh rather than a replay — a card quietly
    answering from a stale buffer would satisfy a bare status-word check
    and fail this one.

    The complementary property — that a request answers ``6400`` when the
    *generator* cannot re-seed — belongs to
    ``apps/openpgp/tests/rng_stall.rs``, which pins it at the library
    level. Not duplicated here.
    """
    with _device(tmp_path, starve_file, relay) as dev:
        assert _sw(dev.select_openpgp()) == SW_OK

        healthy = _call("healthy GET CHALLENGE", dev.get_challenge)
        assert _sw(healthy) == SW_OK
        assert len(healthy) - 2 == 8, "a healthy challenge is 8 bytes"

        starve_file.starve()
        starved = _call("starved GET CHALLENGE", dev.get_challenge)
        # Read the assertion as a negative, because that is what it is: NO
        # clean error is observed here, and none is expected. The story's
        # literal wording ("a request needing randomness answers a clean
        # error") is NOT what this test proves, and a reader must not come
        # away thinking it was. What it proves is the opposite property — a
        # DRBG seeded at boot is *unaffected* by peripheral starvation, and
        # serves fresh bytes. The clean-error case belongs to
        # `rng_stall.rs`, at the library level, where the generator itself
        # is stalled rather than the peripheral feeding it.
        assert _sw(starved) == SW_OK, (
            f"a DRBG seeded at boot keeps serving; a starved peripheral must "
            f"not stop the request path (got {_sw(starved):04X})"
        )
        assert len(starved) - 2 == 8
        assert starved[:8] != healthy[:8], (
            "the starved challenge must be fresh bytes, not a replay of the "
            "buffer filled before the starve"
        )
        # Repeated starvation must be stable, not progressively worse.
        assert _sw(_call("starved GET CHALLENGE (repeat)", dev.get_challenge)) == SW_OK


# ---------------------------------------------------------------------------
# 4. Recovery, without a restart
# ---------------------------------------------------------------------------


def test_requests_succeed_again_after_entropy_recovers(
    starve_file, relay, tmp_path
):
    """Starve, observe, recover — and the SAME process serves throughout.

    No restart anywhere in this test, which is the whole reason the seam is
    a polled control file and not an environment variable: a
    process-start variable can say "starved" or "healthy" but not the
    transition between them, and the transition is the entire second half
    of the story.
    """
    with _device(tmp_path, starve_file, relay) as dev:
        dev.select_openpgp()
        before = _call("healthy GET CHALLENGE", dev.get_challenge)
        assert _sw(before) == SW_OK

        starve_file.starve()
        assert _sw(_call("starved GET CHALLENGE", dev.get_challenge)) == SW_OK

        starve_file.recover()
        after = _call("recovered GET CHALLENGE", dev.get_challenge)
        assert _sw(after) == SW_OK, (
            "a request after recovery must succeed — a device that cannot "
            "come back is not survivable, it is merely still present"
        )
        assert len(after) - 2 == 8
        assert after[:8] != before[:8], "the device must not replay a challenge"

        # Both transports again, so recovery is not CCID-only.
        assert _call("recovered HID getInfo", dev.fido_get_info)[0] == 0x00
        assert _sw(_call("recovered CCID SELECT", dev.select_openpgp)) == SW_OK


# ---------------------------------------------------------------------------
# 5. RED — the two properties the story asks for that this tree lacks
# ---------------------------------------------------------------------------


def test_starved_fido_keygen_answers_a_clean_error(starve_file, relay, tmp_path):
    """The FIDO leg of the story: a request needing randomness must answer.

    makeCredential is the FIDO request that genuinely needs fresh entropy.
    getAssertion over an existing credential signs with a key already in
    the keystore and consumes none — which is why the enumerability test
    above can assert through it and mean nothing about the seam.

    **This test was an xfail when the story landed, and the marker is
    deliberately gone.** The finding it recorded was real and it is now
    fixed: `apps/fido/src/crypto.rs` draws keygen material through
    `try_fill_bytes` and caps the curve crates' rejection at
    `KEYGEN_MAX_ATTEMPTS`, so a starved source answers instead of spinning.
    The defect's own diagnosis is worth keeping, because it is the reason
    the assertion below is shaped the way it is:

    the old `TrngAdapter::try_fill_bytes` was `self.fill_bytes(dest);
    Ok(())` — an unconditional success reporting a refused draw as fresh
    bytes. `p256::SecretKey::random` is a rejection sampler over exactly
    that draw, so a starved source (every draw the same untouched buffer)
    made the sampler reject forever and the request never returned.

    # What "clean" and "bounded" mean here, and how they are checked
    #
    * *Clean* — a specific CTAP status, not merely "not success". Asserting
      only `!= 0x00` would also be satisfied by a panic, a transport error
      or a truncated frame, none of which is the property. The code is
      `0x7F Other`, the CTAP 2.1 catch-all, chosen over a
      policy-sounding code precisely so a client knows to retry.
    * *Bounded* — enforced structurally, by `_call`'s deadline. The call
      goes through `_call`, so a regression to the spin cannot hang this
      test: it raises `_Halt` at `REQUEST_TIMEOUT_S` and the assertion
      below never runs. The `elapsed` assertion then pins the *shape* of
      the answer — microseconds, not "merely under the ceiling" — so a fix
      that merely got slower would not pass.
    """
    with _device(tmp_path, starve_file, relay) as dev:
        assert dev.fido_make_credential()[0] == 0x00, "healthy keygen first"

        starve_file.starve()
        start = time.monotonic()
        resp = _call("starved makeCredential", dev.fido_make_credential)
        elapsed = time.monotonic() - start

        assert resp[0] == CTAP2_ERR_OTHER, (
            "a starved keygen must answer the CTAP catch-all 0x7F, and must "
            f"not fabricate a credential from a constant key; got status "
            f"0x{resp[0]:02x}"
        )
        assert elapsed < BOUNDED_KEYGEN_SECONDS, (
            "the refusal must be immediate, not merely eventually: a starved "
            f"keygen took {elapsed:.3f}s. The rejection sampler is capped at "
            f"{KEYGEN_MAX_ATTEMPTS} draws, so the honest answer is "
            "microseconds; anything near the ceiling is the spin returning."
        )
        assert _call("post-starve getInfo", dev.fido_get_info)[0] == 0x00, (
            "the device must still be there after a refused keygen"
        )

        # And the refused request left nothing behind: once entropy is back,
        # the same request succeeds on the same process, with no restart.
        starve_file.recover()
        assert dev.fido_make_credential()[0] == 0x00, (
            "a refused keygen must not wedge the request path — after "
            "recovery the same makeCredential must succeed"
        )


@pytest.mark.xfail(
    strict=False,
    reason=(
        "FINDING (US-1007), STILL OPEN after the keygen fix: a device already "
        "starved at power-on never enumerates. FidoApp::with_keystore calls "
        "the INFALLIBLE crypto::generate_p256_keypair unconditionally, so "
        "p256's rejection sampler still runs before any transport exists; the "
        "emulator never finishes construction and never answers CTAPHID INIT. "
        "The fix deliberately did not touch this: generate_p256_keypair has 45 "
        "callers and no fallible return, so bounding it is a signature change "
        "across the whole tree, not a keygen change.\n"
        "  NOT the same as 'the device is safe', which is how this read when "
        "the story landed. The device does not take the with_keystore path "
        "(main.rs uses the store-backed FidoApp::boot), and init_drbg refuses "
        "fatally when the peripheral is dead AT BOOT (D-8). But that argument "
        "does not cover a generator that seeds successfully and later fails, "
        "and the device's own boot path draws from it unconditionally: "
        "boot_in_place calls attestation::provision on every boot, and "
        "device_app.rs still derives the hkey through SecretKey::random on "
        "both the new and the fresh-partition arm. Those boot samplers remain "
        "unbounded. The device REQUEST paths, which are the ones a live "
        "request can reach, were bounded by this change (device_core.rs) and "
        "are not what this xfail is about. D-9 records the full split."
    ),
)
def test_a_starved_device_can_still_boot(starve_file, relay, tmp_path):
    """Starvation present at power-on must not prevent enumeration."""
    starve_file.starve()
    with _device(tmp_path, starve_file, relay) as dev:
        assert _sw(_call("starved-boot SELECT", dev.select_openpgp)) == SW_OK
        assert _call("starved-boot getInfo", dev.fido_get_info)[0] == 0x00
