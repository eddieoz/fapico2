#!/usr/bin/env python3
"""Power-cycle persistence acceptance for the fapico2 FIDO2 firmware (US-428).

Sibling of scripts/token2_validate.py: drives the physical token over USB
CTAP-HID with python-fido2's Ctap2 transport, which runs in strict
canonical CBOR mode by default — every response is re-encoded and compared
against its canonical form, and any deviation raises ValueError. That is
exactly the property Chromium enforces.

What this proves on real hardware (SECURE-PERSIST epic acceptance):

(a) a set PIN survives a power cycle — getInfo keeps showing
    clientPin: true after every cycle, and the key-agreement key behind
    pinAuth tokens is restored from the secure partition (the pre-cycle
    PIN token must still be accepted);
(b) a resident credential registered before the power cycle can still be
    asserted after it — getAssertion with the recorded credential id in
    the allowList answers the same credential id, with the UP flag set
    and a signature that verifies under the strict canonical parse.

Both are the durable-before-ack invariant plus boot-from-store, observed
from the host side: a success reply is only accepted by this script after
the state it depends on has survived the reboot.

Flow (single invocation; it pauses for the manual power cycles):

0. Discover the device (retry loop; VID:PID fa20:0002), connect. The
   Ctap2 constructor runs the getInfo handshake under strict parsing.
1. getInfo — print the state (clientPin, residentKeys, pinUvAuthToken,
   pinUvProtocols).
2. Scenario (a) setup: if no PIN is set, set_pin(--pin) (SetPin has no
   user-presence requirement), then require getInfo to show
   clientPin: true.
3. Scenario (b) setup: makeCredential(rk=True, up=True). Probed WITHOUT
   pinUvAuth first — with a PIN set the firmware answers PUAT_REQUIRED
   (0x36); that is expected here, not a failure, and the script retries
   with pinUvAuth = PIN-token HMAC for the command's clientDataHash
   (the token is obtained up front, which also verifies --pin when a
   PIN was already set). Records the credential id and public key.
   User presence is auto-satisfied by the current firmware build (no
   physical touch).
4. Per cycle i of --cycles: banner "POWER CYCLE i: unplug and replug the
   token, then press Enter" -> input() -> re-discover (retry loop; the
   token re-enumerates a few seconds after replug) -> reconnect ->
   - getInfo: clientPin must still be true                  (scenario a)
   - getAssertion (allowList = recorded credential id): same
     credential id, UP flag set, signature verifies — all under
     strict canonical parsing                              (scenario b)
     Probed without pinUvAuth first; on PIN_INVALID (0x31) /
     PUAT_REQUIRED (0x36) it retries with the pre-cycle token.
5. PASS: N consecutive power cycles survived; exit 0.

Scenario (c) — the Chrome www.token2.com login repeated post-cycle — is
manual (checklist in docs/token2-hardware-validation.md).

Usage:
    ~/Projects/git/pico/pico-fido2/.test-venv/bin/python \
        scripts/token2_persistence.py [--rp-id www.token2.com] \
        [--cycles 2] [--pin 1234]

Exit codes: 0 = every cycle passed every assertion; 1 = an assertion
mismatch (the persistence regression signal, with detail); 2 =
environment problem (no library, no device, discovery timeout, abort).
"""

import argparse
import hashlib
import os
import sys
import time

RP_DEFAULT = "www.token2.com"
VID, PID = 0xFA20, 0x0002
DISCOVER_TIMEOUT_S = 60.0
DISCOVER_POLL_S = 2.0

try:
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.base import AuthenticatorData, CtapError
    from fido2.ctap2.pin import ClientPin
    from fido2.hid import CtapHidDevice
except ImportError as e:  # checked in main() -> exit 2
    FIDO2_IMPORT_ERROR = e
    Ctap2 = AuthenticatorData = CtapError = ClientPin = CtapHidDevice = None


def env_fail(msg: str) -> None:
    print(f"environment: {msg}")
    sys.exit(2)


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def _clear_hidraw_failure_cache() -> None:
    # fido2's Linux backend caches /dev/hidraw* paths that failed to open
    # (fido2.hid.linux._failed_cache) and skips them until the path
    # disappears and reappears. A replugged token often reuses the same
    # path, so without clearing the cache the discovery retry loop would
    # go blind to it for the rest of the run. Private API; used only to
    # keep the retry loop honest.
    try:
        from fido2.hid import linux
        linux._failed_cache.clear()
    except (ImportError, AttributeError):
        pass


def discover(timeout_s: float = DISCOVER_TIMEOUT_S):
    """Return the fa20:0002 CTAP-HID device, or None after timeout_s.

    list_devices() opens a connection for every CTAP descriptor; a
    mid-replug re-enumeration can make open_connection raise, in which
    case this round finds nothing and we simply retry.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        _clear_hidraw_failure_cache()
        try:
            devs = list(CtapHidDevice.list_devices())
        except Exception:
            devs = []
        token = None
        for dev in devs:
            if dev.descriptor.vid == VID and dev.descriptor.pid == PID:
                token = dev
                break
            try:
                dev.close()
            except Exception:
                pass
        if token is not None:
            return token
        if time.monotonic() >= deadline:
            return None
        time.sleep(DISCOVER_POLL_S)


def connect(dev):
    """Ctap2 with strict canonical CBOR (the default; explicit here).

    The constructor performs the getInfo handshake under the same strict
    parse, so a non-canonical handshake is already a failure.
    """
    try:
        return Ctap2(dev, strict_cbor=True)
    except ValueError as e:
        fail(f"getInfo handshake answered with non-canonical CBOR: {e}")
    except CtapError as e:
        env_fail(f"getInfo handshake failed with CTAP 0x{e.code:02X} "
                 f"({e})")
    except OSError as e:
        # ConnectionError is an OSError; a drop mid-(re)plug handshake is
        # an environment problem, not an assertion failure.
        env_fail(f"the token dropped during the getInfo handshake: {e}")


def refresh_info(ctap):
    """Re-issue getInfo and replace the constructor-cached copy.

    Ctap2 caches the constructor's getInfo in a private attribute that
    its `info` property exposes, and fido2 2.x has no public refresh
    method — but set_pin changes the cached options, so we update the
    attribute directly.
    """
    info = ctap.get_info()
    ctap._info = info
    return info


def set_pin(ctap, pin: str) -> None:
    # SetPin has no user-presence requirement — no touch.
    print("   (no touch needed — SetPin has no user-presence requirement)")
    try:
        ClientPin(ctap).set_pin(pin)
    except ValueError as e:
        # protocol negotiation or a non-canonical clientPin response
        fail(f"set_pin failed: {e}")
    except CtapError as e:
        fail(f"set_pin failed with CTAP 0x{e.code:02X} ({e})")
    except OSError as e:
        # a transport drop mid-setup is an environment problem, not an
        # assertion failure (ConnectionError is an OSError)
        env_fail(f"the token disconnected during set_pin ({e}) — replug "
                 f"it and re-run the script")


def pin_token_for(ctap, pin: str):
    """Fetch a PIN token; this also verifies the PIN.

    Returns (token, protocol): token is the 32-byte PIN/UV token and
    protocol the negotiated PinProtocol object. The raw token is never
    sent to the token — each command derives its own pinUvAuth as
    protocol.authenticate(token, clientDataHash) (CTAP2: the token is
    the HMAC key, bound per-command to the clientDataHash).
    """
    try:
        cp = ClientPin(ctap)
    except ValueError as e:
        fail(f"clientPin set but no supported PIN/UV protocol: {e}")
    try:
        token = cp.get_pin_token(pin)
    except CtapError as e:
        if e.code in (
            CtapError.ERR.PIN_INVALID,      # 0x31 — PIN rejected (wrong --pin?)
            CtapError.ERR.PIN_BLOCKED,      # 0x32 — retries exhausted
            CtapError.ERR.PIN_AUTH_INVALID,  # 0x33 — token/key mismatch
        ):
            fail(
                f"PIN rejected by the token (CTAP 0x{e.code:02X}): the token "
                f"was configured with a different PIN — pass it via --pin"
            )
        fail(f"get_pin_token failed with CTAP 0x{e.code:02X} ({e})")
    except ValueError as e:
        # can come from the protocol crypto in get_pin_token (encrypt /
        # validate), not only the strict CBOR parser
        fail(f"PIN token derivation failed (protocol crypto or "
             f"non-canonical clientPin response): {e}")
    except OSError as e:
        # a transport drop mid-setup is an environment problem, not an
        # assertion failure (ConnectionError is an OSError)
        env_fail(f"the token disconnected during the PIN token fetch "
                 f"({e}) — replug it and re-run the script")
    return token, cp.protocol


def _with_token_error_detail(op: str, e, after_cycle: bool) -> str:
    """FAIL detail for a CtapError from the with-PIN-token retry.

    0x31/0x33 are the persistence regression signal: the PIN token was
    rejected because the state it was derived from no longer matches
    what the token holds. Name which state; anything else is a generic
    with-token failure.
    """
    if e.code in (CtapError.ERR.PIN_AUTH_INVALID,  # 0x33
                  CtapError.ERR.PIN_INVALID):      # 0x31
        token_what = "pre-cycle" if after_cycle else "freshly derived"
        if e.code == CtapError.ERR.PIN_AUTH_INVALID:
            why = ("the key-agreement key behind the PIN token did not "
                   "survive the power cycle" if after_cycle else
                   "the key-agreement key is inconsistent — the token was "
                   "derived seconds earlier")
        else:
            why = ("the PIN state changed (did not survive the power "
                   "cycle)" if after_cycle else
                   "the PIN was verified seconds earlier but is now "
                   "rejected")
        return (f"{op} (with PIN token) rejected the {token_what} PIN "
                f"token (CTAP 0x{e.code:02X}) — {why}")
    return f"{op} (with PIN token) failed (CTAP 0x{e.code:02X} ({e}))"


def make_resident_credential(ctap, rp_id: str, token, proto):
    """makeCredential(rk=True): probe without pinUvAuth, retry with the
    PIN token on 0x31/0x36 (expected with a PIN set — not a failure)."""
    cdh = hashlib.sha256(b"token2-persistence registration").digest()
    rp = {"id": rp_id, "name": rp_id}
    user = {"id": os.urandom(32), "name": "token2-persistence"}
    key_params = [{"type": "public-key", "alg": -7}]  # ES256
    options = {"up": True, "rk": True}
    print("   (user presence: auto-satisfied by this firmware build — no touch needed)")
    try:
        return ctap.make_credential(cdh, rp, user, key_params, options=options)
    except CtapError as e:
        if e.code in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PUAT_REQUIRED):
            if token is None:
                fail(f"makeCredential demanded pinUvAuth (0x{e.code:02X}) "
                     f"although no PIN is set — unexpected firmware state")
            print(f"   CTAP 0x{e.code:02X} (pinUvAuth required) — retrying "
                  f"with the PIN token")
            print("   (user presence: auto-satisfied by this firmware build — no touch needed)")
            try:
                return ctap.make_credential(
                    cdh, rp, user, key_params, options=options,
                    pin_uv_param=proto.authenticate(token, cdh),
                    pin_uv_protocol=proto.VERSION,
                )
            except ValueError as ve:
                fail(f"makeCredential (with PIN token) response is "
                     f"non-canonical: {ve}")
            except CtapError as e:
                fail(_with_token_error_detail("makeCredential", e,
                                              after_cycle=False))
            except OSError as e:
                # a transport drop mid-setup is an environment problem,
                # not an assertion failure (ConnectionError is an OSError)
                env_fail(f"the token disconnected during makeCredential "
                         f"(with PIN token) ({e}) — replug it and re-run "
                         f"the script")
        fail(f"makeCredential failed with CTAP 0x{e.code:02X} ({e})")
    except ValueError as e:
        fail(f"makeCredential response is non-canonical: {e}")
    except OSError as e:
        # a transport drop mid-setup is an environment problem, not an
        # assertion failure (ConnectionError is an OSError)
        env_fail(f"the token disconnected during makeCredential ({e}) — "
                 f"replug it and re-run the script")


def get_resident_assertion(ctap, rp_id: str, cdh: bytes, cred_id: bytes,
                           token, proto):
    """getAssertion(allowList=[cred_id]): probe without pinUvAuth, retry
    with the token on 0x31/0x36."""
    allow_list = [{"id": cred_id, "type": "public-key"}]
    print("   (user presence: auto-satisfied by this firmware build — no touch needed)")
    try:
        resp = ctap.get_assertion(rp_id, cdh, allow_list=allow_list)
    except CtapError as e:
        if e.code in (CtapError.ERR.PIN_INVALID, CtapError.ERR.PUAT_REQUIRED):
            if token is None:
                fail(f"getAssertion demanded pinUvAuth (0x{e.code:02X}) "
                     f"although no PIN is set — unexpected firmware state")
            print(f"   CTAP 0x{e.code:02X} (pinUvAuth required) — retrying "
                  f"with the PIN token")
            print("   (user presence: auto-satisfied by this firmware build — no touch needed)")
            try:
                resp = ctap.get_assertion(
                    rp_id, cdh, allow_list=allow_list,
                    pin_uv_param=proto.authenticate(token, cdh),
                    pin_uv_protocol=proto.VERSION,
                )
            except ValueError as ve:
                fail(f"getAssertion (with PIN token) response is "
                     f"non-canonical: {ve}")
            except CtapError as e:
                fail(_with_token_error_detail("getAssertion", e,
                                              after_cycle=True))
            except TypeError as te:
                # The success response parsed, but the CTAP-optional
                # credential member was missing — python-fido2 types it
                # required (AssertionResponse.credential has no default),
                # so the dataclass construction raises a bare TypeError.
                fail(f"getAssertion (with PIN token) response is missing "
                     f"the credential field (CTAP-optional, but "
                     f"python-fido2 types it required — bare TypeError: "
                     f"{te})")
        else:
            fail(f"getAssertion failed with CTAP 0x{e.code:02X} ({e})")
    except ValueError as e:
        fail(f"getAssertion response is non-canonical: {e}")
    if isinstance(resp, list):
        resp = resp[0]
    return resp


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rp-id", default=RP_DEFAULT,
                    help=f"relying party id (default {RP_DEFAULT})")
    ap.add_argument("--cycles", type=int, default=2,
                    help="number of power cycles (default 2; EPIC DoD is >= 2)")
    ap.add_argument("--pin", default="1234",
                    help="token PIN (default 1234; required to match if the "
                         "token already has a PIN set)")
    args = ap.parse_args()
    if args.cycles < 1:
        env_fail("--cycles must be >= 1")

    if CtapHidDevice is None:
        env_fail(f"python-fido2 not importable ({FIDO2_IMPORT_ERROR}); "
                 f"use the project venv: "
                 f"~/Projects/git/pico/pico-fido2/.test-venv/bin/python")

    # 0. discover + connect
    print(f"0. discover device     (fa20:0002; retrying up to "
          f"{DISCOVER_TIMEOUT_S:.0f}s)")
    dev = discover()
    if dev is None:
        env_fail(f"no CTAP-HID device with id fa20:0002 found within "
                 f"{DISCOVER_TIMEOUT_S:.0f}s — is the token plugged in and "
                 f"flashed? (lsusb)")
    print(f"   device: {dev}")
    ctap = connect(dev)

    # 1. getInfo state
    try:
        info = refresh_info(ctap)
    except ValueError as e:
        fail(f"getInfo response is non-canonical: {e}")
    except CtapError as e:
        env_fail(f"getInfo failed with CTAP 0x{e.code:02X} ({e})")
    pin_set = bool(info.options.get("clientPin"))
    print("1. getInfo             OK (strict canonical parse)")
    print(f"   versions: {', '.join(info.versions)}")
    print(f"   options: clientPin={'set' if pin_set else 'unset'}, "
          f"residentKeys={info.options.get('residentKeys')}, "
          f"pinUvAuthToken={info.options.get('pinUvAuthToken')}")
    print(f"   pinUvProtocols: {info.pin_uv_protocols}")

    # 2. scenario (a) setup: make sure a PIN is set
    if not pin_set:
        print("2. set PIN             (no PIN set yet — scenario (a) setup)")
        set_pin(ctap, args.pin)
        try:
            info = refresh_info(ctap)
        except ValueError as e:
            fail(f"getInfo after set_pin is non-canonical: {e}")
        except CtapError as e:
            env_fail(f"getInfo after set_pin failed with CTAP "
                     f"0x{e.code:02X} ({e})")
        if not info.options.get("clientPin"):
            fail("getInfo still shows clientPin unset after set_pin")
        print("   OK — getInfo now shows clientPin=true")
        pin_set = True
    else:
        print("2. set PIN             already set — the PIN is verified by the "
              "token fetch below")

    token = proto = None
    if pin_set:
        # The same token is reused across the cycle loop on purpose: it is
        # derived from the key-agreement key, so if that key did not
        # survive a power cycle the pre-cycle token is rejected and
        # scenario (b) fails.
        token, proto = pin_token_for(ctap, args.pin)
        print(f"   PIN OK (protocol v{proto.VERSION}); token cached for the "
              f"cycle loop")

    # 3. scenario (b) setup: register a resident credential
    print(f"3. makeCredential      (rpId={args.rp_id}, rk=True — resident "
          f"credential)")
    att = make_resident_credential(ctap, args.rp_id, token, proto)
    cred_id = att.auth_data.credential_data.credential_id
    pub_key = att.auth_data.credential_data.public_key
    print(f"   OK (strict canonical parse) — credential id "
          f"{cred_id[:16].hex()}… ({len(cred_id)} bytes)")

    # 4. the power-cycle loop
    for i in range(1, args.cycles + 1):
        print(f"\nPOWER CYCLE {i}/{args.cycles}: unplug and replug the "
              f"token, then press Enter")
        input()
        try:
            dev.close()
        except Exception:
            pass
        dev = discover()
        if dev is None:
            env_fail(f"the token did not re-enumerate after power cycle "
                     f"{i} (replug it and re-run the script)")
        print(f"   re-discovered: {dev}")
        ctap = connect(dev)
        try:
            info = refresh_info(ctap)
        except ValueError as e:
            fail(f"cycle {i}: getInfo response is non-canonical: {e}")
        except CtapError as e:
            env_fail(f"cycle {i}: getInfo failed with CTAP "
                     f"0x{e.code:02X} ({e})")
        except OSError as e:
            env_fail(f"cycle {i}: the token disconnected during getInfo "
                     f"({e}) — replug it and re-run the script")
        if not info.options.get("clientPin"):
            fail(f"cycle {i}: clientPin is no longer set after a power "
                 f"cycle — the PIN state did not survive (scenario (a) "
                 f"failure)")
        print(f"   cycle {i}/{args.cycles}: clientPin still set            "
              f"PASS (scenario (a))")

        cdh = hashlib.sha256(f"token2-persistence cycle {i}".encode()).digest()
        try:
            resp = get_resident_assertion(ctap, args.rp_id, cdh, cred_id,
                                          token, proto)
        except OSError as e:
            env_fail(f"cycle {i}: the token disconnected during "
                     f"getAssertion ({e}) — replug it and re-run the "
                     f"script")
        if resp.credential.get("id") != cred_id:
            fail(f"cycle {i}: the assertion used credential "
                 f"{(resp.credential.get('id') or b'')[:16].hex()}… — not "
                 f"the resident credential registered before the cycles "
                 f"({cred_id[:16].hex()}…) — scenario (b) failure")
        if not resp.auth_data.flags & AuthenticatorData.FLAG.UP:
            fail(f"cycle {i}: user presence flag missing on the "
                 f"assertion (UP is auto-satisfied by the firmware)")
        try:
            resp.verify(cdh, pub_key)
        except Exception as e:
            fail(f"cycle {i}: assertion signature does not verify under "
                 f"the attested public key: {e}")
        print(f"   cycle {i}/{args.cycles}: same credential + valid sig    "
              f"PASS (scenario (b))  (UP set, counter="
              f"{resp.auth_data.counter})")

    # 5. final
    print(f"\nPASS: {args.cycles} consecutive power cycles survived")
    print("   the PIN state and the resident credential survived every")
    print("   power cycle, and every response parsed under strict")
    print("   canonical CBOR (the property Chromium enforces).")
    print("   Scenario (c) — the Chrome www.token2.com login repeated")
    print("   post-cycle — is manual; see docs/token2-hardware-validation.md")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(2)
    except EOFError:
        print("\ninput closed during a power-cycle pause")
        sys.exit(2)
