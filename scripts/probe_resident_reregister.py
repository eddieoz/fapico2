#!/usr/bin/env python3
"""Hardware probe for US-1720: resident-credential re-registration key drift.

The defect (docs/audits/2026-10-30-wrong-key-assertion-drift.md, section 1):
fapico2 derives resident credential IDs deterministically from
(rp_id, user.id) -- SHA-256("fapico2-resident-id" || SHA-256(rp_id) || user.id)
-- but mints a fresh TRNG private key for every registration, stores both
records (no dedupe on the region backend), and serves allow-listed assertions
from the FIRST record in index order, i.e. the OLDEST same-ID one.  So after
re-registering the same (rp, user.id) resident credential, every assertion
pinned to that credential ID verifies under the FIRST registration's key --
a key the relying party never registered.

This probe demonstrates it on a live board, with no application in between:

  1. find the board over CTAPHID (or --device PATH);
  2. clientPIN handshake for --pin (refuses politely if no PIN is set --
     it never sets one; per AGENTS.md section 4 a PIN-set board requires both
     token and touch for every MC/GA anyway);
  3. two authenticatorMakeCredential calls, same rp, same user.id,
     rk=true, empty exclude list; records each attested public key;
  4. derives the expected credential ID in-script and compares it with both
     registrations' IDs (they must all be byte-equal -- that equality is the
     deterministic-ID precondition for the whole defect);
  5. two getAssertion calls pinning that ID via allowCredentials; verifies
     each assertion signature under EACH registration's key and reports
     which key it verifies under;
  6. credMgmt metadata: totalCredentials for the rp vs distinct enumerated
     credential IDs (duplicates <=> totalCredentials > distinct).

Outcome is REPORTED, never asserted: the probe prints `DRIFT: assertion N
verified under registration M's key` for any assertion that verifies under a
non-newest registration's key, `NO-DRIFT` otherwise.  Both are valid probe
outcomes; nonzero exit is reserved for genuine errors (no device, no PIN).

Opcodes are this family's dialect, NOT CTAP 2.1's: makeCredential 0x01,
getInfo 0x04, clientPIN 0x06, credMgmt 0x0A (python-fido2 2.2.1 Ctap2.CMD --
AGENTS.md section 2).  pinUvAuthParam = HMAC-SHA256(token, clientDataHash),
the message python-fido2's own Fido2Client uses for both MC and GA
(fido2/client/__init__.py:850,1006).  Everything is framed through the
library's own Ctap2/ClientPin/CredentialManagement encoders -- hand-rolled
CBOR in this family has produced false results before.

`--selftest` runs the pure-computation parts (ID derivation vector from the
analysis doc, ECDSA verify round-trip against locally generated keypairs with
synthetic authData) with no device attached.

HAZARD: this probe REGISTERS two resident credentials and deletes nothing.
It is read-mostly, but run it on a bench board -- never on a board holding
real passkeys.  The default user.id is the analysis doc's (keccak256("Safe
Owner")); change it with --user-id to keep repeat runs separable.

Usage:  probe_resident_reregister.py --pin 123456 [--rp localhost]
        [--user-id HEX] [--device /dev/hidraw8]
        probe_resident_reregister.py --selftest
"""
import argparse
import hashlib
import sys
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

try:
    # cryptography >= 50 moved Prehashed into asymmetric.utils.
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
except ImportError:  # pragma: no cover - older cryptography
    from cryptography.hazmat.primitives.hashes import Prehashed
from fido2 import ctap
from fido2.cose import ES256
from fido2.ctap2 import ClientPin, CredentialManagement, Ctap2
from fido2.ctap2.base import AssertionResponse, AttestationResponse
from fido2.ctap2.pin import PinProtocolV1
from fido2.hid import CtapHidDevice, open_device

# rp and user are plain dicts on purpose (same reason as probe_mc_uv_ab.py):
# PublicKeyCredentialUserEntity types `id` as str and base64-encodes it, which
# puts a CBOR *text string* where CTAP2 6.1.2 requires bytes; the authenticator
# correctly answers INVALID_CBOR and the probe would report a device fault
# that is not there.

# Fixed clientDataHash.  CTAP2 never sees clientDataJSON -- the client layer
# hashes it and the wire carries only the 32-byte hash.  b"\xaa"*32 matches
# probe_mc_uv_ab.py so pinUvAuthParam (HMAC over exactly this hash) and any
# captured traffic line up between the two probes.
CLIENT_DATA_HASH = b"\xaa" * 32

RP_ID_DEFAULT = "localhost"

# keccak256("Safe Owner") -- the user.id of the original failure report
# (analysis doc section 1).  Making it the default means an unmodified run
# reproduces the report's exact credential ID on a bench board.
USER_ID_DEFAULT_HEX = "eff5a3041317ca36bc0f7af6d3940cce529e44412748add83c4d1a8f6bb449e6"

# The derived credential ID for (rp="localhost", USER_ID_DEFAULT) -- pinned
# by --selftest against the analysis doc's section-1 computation.
EXPECTED_DERIVED_ID_HEX = "3b810ef7e868adf706e0692fc5720a314e4ec58c314df74d425939632abced0a"

# The firmware's domain separator: device_core.rs:1381-1390.
RESIDENT_ID_DOMAIN = b"fapico2-resident-id"

N_REGISTRATIONS = 2
N_ASSERTIONS = 2

CTAP2_ERRORS = {
    0x00: "SUCCESS", 0x01: "INVALID_COMMAND", 0x02: "INVALID_PARAMETER",
    0x03: "INVALID_LENGTH", 0x11: "CBOR_UNEXPECTED_TYPE", 0x12: "INVALID_CBOR",
    0x14: "MISSING_PARAMETER", 0x15: "LIMIT_EXCEEDED",
    0x24: "OPERATION_PENDING", 0x25: "OPERATION_TIMED_OUT",
    0x2B: "UNSUPPORTED_OPTION", 0x2C: "INVALID_OPTION", 0x2D: "KEEPALIVE_CANCEL",
    0x2E: "NO_CREDENTIALS", 0x2F: "USER_ACTION_TIMEOUT", 0x30: "NOT_ALLOWED",
    0x31: "PIN_INVALID", 0x32: "PIN_BLOCKED", 0x33: "PIN_AUTH_INVALID",
    0x34: "PIN_AUTH_BLOCKED", 0x35: "PIN_NOT_SET", 0x36: "PUAT_REQUIRED",
    0x37: "PIN_POLICY_VIOLATION", 0x39: "REQUEST_TOO_LARGE",
    0x3A: "ACTION_TIMEOUT", 0x3B: "UP_REQUIRED", 0x3C: "UV_BLOCKED",
    0x3E: "INVALID_SUBCOMMAND", 0x3F: "UV_INVALID",
    0x40: "UNAUTHORIZED_PERMISSION",
}


def show_exc(exc):
    code = getattr(exc, "code", None)
    if code is None:
        return f"{type(exc).__name__}: {exc}"
    return f"0x{code:02x} {CTAP2_ERRORS.get(code, code)}"


class ProbeError(Exception):
    """A genuine probe-environment error (no device, no PIN). Exits nonzero."""


# ---------------------------------------------------------------- pure parts

def derive_resident_id(rp_id, user_id):
    """The firmware's resident credential ID derivation.

    device_core.rs:1381-1390:
        SHA-256("fapico2-resident-id" || SHA-256(rp_id) || user_handle)
    """
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    return hashlib.sha256(RESIDENT_ID_DOMAIN + rp_id_hash + user_id).digest()


def verify_assertion_signature(auth_data, signature, cose_key, client_data_hash):
    """Verify an assertion the way an RP would: ECDSA P-256 over
    SHA-256(authData || clientDataHash), under the given COSE key.

    Returns True/False -- never raises.

    Signature encoding: an authenticator signs raw r||s (64 bytes, WebAuthn),
    but cryptography's ECDSA verify -- which ES256.verify ends in -- wants
    DER, so the raw form is converted first.  A signature that already
    arrives DER-encoded (len != 64) is passed through untouched; the
    selftest exercises both the raw path and the cross-key failure.
    """
    try:
        if len(signature) == 64:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            signature = encode_dss_signature(r, s)
        cose_key.verify(auth_data + client_data_hash, signature)
        return True
    except Exception:  # noqa: BLE001 - verification failure is a finding
        return False


def selftest():
    """Pure-computation proof, no device.  Returns exit code 0/1."""
    ok = True

    # 1. The derivation vector from the analysis doc (section 1).  This pins
    #    the domain separator, the hash order, and the keccak-vs-sha3 trap.
    user_id = bytes.fromhex(USER_ID_DEFAULT_HEX)
    got = derive_resident_id("localhost", user_id)
    ok &= _check("derivation vector (analysis doc)",
                 got.hex() == EXPECTED_DERIVED_ID_HEX,
                 f"got {got.hex()} want {EXPECTED_DERIVED_ID_HEX}")

    # Negative control: a different rp must not derive the same ID.
    ok &= _check("negative control (rp differs)",
                 derive_resident_id("example.com", user_id) != got, "-")

    # 2. ECDSA verify round-trip against locally generated keypairs, using
    #    the exact helper the device path uses.  Synthetic authData: 32-byte
    #    rpIdHash, flags UP|UV|AT (0x45), 4-byte big-endian signCount of 1.
    #    The signature is made over the digest exactly as a device does:
    #    digest = SHA-256(authData || clientDataHash), prehashed input --
    #    signing with ec.ECDSA(SHA256) directly would hash the digest a
    #    second time and the verification would rightly fail.
    auth_data = (
        hashlib.sha256(b"localhost").digest()
        + b"\x45"
        + (1).to_bytes(4, "big")
    )

    key_a = ec.generate_private_key(ec.SECP256R1())
    key_b = ec.generate_private_key(ec.SECP256R1())
    cose_a = ES256.from_cryptography_key(key_a.public_key())
    cose_b = ES256.from_cryptography_key(key_b.public_key())

    digest = hashlib.sha256(auth_data + CLIENT_DATA_HASH).digest()
    sig_der = key_a.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(sig_der)
    sig_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    ok &= _check("verify under signing key -> True",
                 verify_assertion_signature(auth_data, sig_raw, cose_a,
                                            CLIENT_DATA_HASH), "-")
    ok &= _check("verify under wrong key -> False",
                 not verify_assertion_signature(auth_data, sig_raw, cose_b,
                                                CLIENT_DATA_HASH), "-")
    ok &= _check("tampered authData -> False",
                 not verify_assertion_signature(auth_data[:-1] + b"\x00",
                                                sig_raw, cose_a,
                                                CLIENT_DATA_HASH), "-")
    ok &= _check("tampered clientDataHash -> False",
                 not verify_assertion_signature(auth_data, sig_raw, cose_a,
                                                b"\xbb" * 32), "-")

    # 3. The library-shaped path too: verify an AssertionResponse-like
    #    object's fields line up with the helper (fields exist and the
    #    digest construction matches what AssertionResponse.verify uses:
    #    auth_data + client_param hashed inside ES256.verify).
    try:
        ar_fields = [f.name for f in __import__("dataclasses").fields(AssertionResponse)]
        att_fields = [f.name for f in __import__("dataclasses").fields(AttestationResponse)]
        ok &= _check("library response shapes present",
                     {"auth_data", "signature"} <= set(ar_fields)
                     and {"auth_data"} <= set(att_fields),
                     f"assertion={ar_fields} attestation={att_fields}")
    except Exception as exc:  # noqa: BLE001
        ok &= _check("library response shapes present", False, str(exc))

    print("SELFTEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def _check(label, cond, detail):
    print(f"  [{'ok' if cond else 'FAIL'}] {label}" + (f"  ({detail})" if detail and not cond else ""))
    return cond


# ------------------------------------------------------------ hardware parts

class TouchPrompt:
    """Print once per blocking call when the board signals user presence is
    needed (CTAPHID keepalive status UPNEEDED=2); count like the other
    probes do.  Per AGENTS.md section 4, every MC and GA needs a touch."""

    def __init__(self, label):
        self.label = label
        self.count = 0
        self._prompted = False

    def __call__(self, status):
        self.count += 1
        if status == ctap.STATUS.UPNEEDED and not self._prompted:
            self._prompted = True
            print(f"  -> {self.label}: touch the button")


def find_device(path=None):
    """Find the board over CTAPHID: --device PATH, else first enumerated."""
    if path:
        return open_device(path), path
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        raise ProbeError(
            "no CTAPHID device found; pass --device /dev/hidrawN explicitly"
        )
    dev = devs[0]
    path = getattr(getattr(dev, "descriptor", None), "path", None) or "?"
    return dev, path


def client_pin_token(ctap2, pin, rp_id):
    """The real clientPIN handshake (ECDH key agreement + PIN check), per
    probe_clientpin_legs.py.  The board must already have a PIN; this probe
    never sets one.  Requests MC|GA|credMgmt permissions bound to the rp,
    the way a real client does (the firmware reads permissions from CBOR
    keys 9/10 while python-fido2 sends 7/8 -- known divergence, recorded in
    probe_clientpin_legs.py; both legs mint regardless, so the token works
    for all three verbs here either way)."""
    cp = ClientPin(ctap2, PinProtocolV1())

    try:
        retries, _power_cycle = cp.get_pin_retries()
        print(f"  PIN set, retries remaining: {retries}")
    except ctap.CtapError as exc:
        if getattr(exc, "code", None) == 0x35:  # PIN_NOT_SET
            raise ProbeError(
                "board has no PIN set.  This probe refuses to run without one "
                "(it will not set a PIN, and a PIN-set board is the realistic "
                "condition for the defect -- AGENTS.md section 4)."
            ) from None
        raise ProbeError(f"getPinRetries failed: {show_exc(exc)}") from None

    perms = (
        ClientPin.PERMISSION.MAKE_CREDENTIAL
        | ClientPin.PERMISSION.GET_ASSERTION
        | ClientPin.PERMISSION.CREDENTIAL_MGMT
    )
    try:
        token = cp.get_pin_token(pin, permissions=perms, permissions_rpid=rp_id)
    except ctap.CtapError as exc:
        raise ProbeError(f"getPinToken failed: {show_exc(exc)}") from None
    protocol = PinProtocolV1()
    return token, protocol


def register(ctap2, token, protocol, rp_id, user_id, label):
    """One authenticatorMakeCredential, rk=true, empty exclude list.
    Returns the attested credential data (id + public key)."""
    keepalive = TouchPrompt(label)
    resp = ctap2.make_credential(
        CLIENT_DATA_HASH,
        {"id": rp_id, "name": f"US-1720 probe rp {rp_id}"},
        {"id": user_id, "name": "US-1720 probe user",
         "displayName": "US-1720 probe user"},
        key_params=[{"type": "public-key", "alg": -7}],
        exclude_list=[],
        options={"rk": True},  # residentKey: preferred, as a browser maps it
        pin_uv_param=protocol.authenticate(token, CLIENT_DATA_HASH),
        pin_uv_protocol=protocol.VERSION,
        on_keepalive=keepalive,
    )
    cd = resp.auth_data.credential_data
    return cd.credential_id, cd.public_key, keepalive.count


def assert_pinned(ctap2, token, protocol, rp_id, cred_id, label):
    """One getAssertion with the credential ID pinned via allowCredentials.
    Returns the AssertionResponse."""
    keepalive = TouchPrompt(label)
    resp = ctap2.get_assertion(
        rp_id,
        CLIENT_DATA_HASH,
        allow_list=[{"type": "public-key", "id": cred_id}],
        pin_uv_param=protocol.authenticate(token, CLIENT_DATA_HASH),
        pin_uv_protocol=protocol.VERSION,
        on_keepalive=keepalive,
    )
    return resp, keepalive.count


def credmgmt_report(ctap2, token, protocol, rp_id, expected_id):
    """credMgmt metadata: the device's own totalCredentials claim vs the
    distinct IDs actually enumerated for the rp.  totalCredentials is read
    from enumerate_creds_begin's response (CTAP2 preview key 9, python-fido2
    CredentialManagement.RESULT.TOTAL_CREDENTIALS -- the dialect everyone
    classifies as, AGENTS.md section 2) and printed as the primary number;
    the number of entries actually enumerated is printed alongside, and if
    key 9 is absent the counted number is used with its source named.
    Duplicates (same ID listed more than once) are the storage-side half of
    the defect -- analysis doc section 1 item 3."""
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    try:
        cm = CredentialManagement(ctap2, protocol, token)
    except ValueError as exc:
        print(f"  credMgmt unavailable: {exc}")
        return
    try:
        meta = cm.get_metadata()
        existing = meta.get(CredentialManagement.RESULT.EXISTING_CRED_COUNT)
        remaining = meta.get(CredentialManagement.RESULT.MAX_REMAINING_COUNT)
        print(f"  metadata (device-wide): existingCredCount={existing} "
              f"maxRemainingCount={remaining}")
    except ctap.CtapError as exc:
        print(f"  getMetadata failed: {show_exc(exc)}")

    try:
        first = cm.enumerate_creds_begin(rp_id_hash)
    except ctap.CtapError as exc:
        if getattr(exc, "code", None) == 0x2E:  # NO_CREDENTIALS
            print(f"  device reports no credentials for rp {rp_id!r} (0x2E)")
            return
        print(f"  enumerateCredsBegin({rp_id}) failed: {show_exc(exc)}")
        return

    total_claimed = first.get(CredentialManagement.RESULT.TOTAL_CREDENTIALS)
    creds = [first]
    try:
        if total_claimed is None:
            # No key 9 in the begin response: walk until the device refuses
            # (enumerateCredsNext errors at end-of-list in every dialect).
            while True:
                creds.append(cm.enumerate_creds_next())
        else:
            for _ in range(int(total_claimed) - 1):
                creds.append(cm.enumerate_creds_next())
    except ctap.CtapError as exc:
        print(f"  NOTE: enumerateCredsNext stopped early ({show_exc(exc)}).")

    # python-fido2 2.x parses the preview key 7 as a descriptor MAP
    # ({'id': bytes, 'type': 'public-key'}), not raw bytes -- bytes(dict)
    # is the TypeError that bit the first hardware run.
    def _cred_id(c):
        raw = c.get(CredentialManagement.RESULT.CREDENTIAL_ID) or b""
        return bytes(raw.get("id")) if isinstance(raw, dict) else bytes(raw)

    ids = [_cred_id(c) for c in creds]
    distinct = {i for i in ids}
    print(f"  enumerated {len(creds)} credential(s) for rp {rp_id!r}:")
    for i in ids:
        marker = "   <= derived ID" if i == expected_id else ""
        print(f"    {i.hex()}{marker}")
    if total_claimed is not None:
        print(f"  totalCredentials={total_claimed} (device, "
              f"enumerate_creds_begin key 9)  enumerated={len(creds)}  "
              f"distinctIDs={len(distinct)}")
        if int(total_claimed) != len(creds):
            print("  NOTE: device total != enumerated count -- the device "
                  "claims more than it served.")
    else:
        print(f"  totalCredentials={len(creds)} (counted; the device's "
              f"begin response carried no key 9)  "
              f"distinctIDs={len(distinct)}")
    if len(distinct) < len(creds):
        print("  NOTE: duplicates present -- the append-without-dedup half "
              "of the defect (analysis doc section 1 item 3).")


def probe(args):
    dev, path = find_device(args.device)
    with dev:
        print(f"=== board {path}")
        ctap2 = Ctap2(dev)
        print(f"  getInfo options: {ctap2.info.options}")
        # python-fido2 names the field `pin_uv_protocols` (2.x); older sketches
        # say `pin_uv_auth_protocols`, which is a wire-key name, not the attr.
        protocols = getattr(ctap2.info, "pin_uv_protocols", None)
        print(f"  versions: {ctap2.info.versions}  "
              f"pinUvAuthProtocols: {protocols}")

        token, protocol = client_pin_token(ctap2, args.pin, args.rp)

        user_id = bytes.fromhex(args.user_id)
        expected_id = derive_resident_id(args.rp, user_id)
        print(f"\n  derived credential ID for (rp={args.rp!r}, user.id):")
        print(f"    {expected_id.hex()}")

        print("\n*** HARDWARE SAFETY: this probe REGISTERS two resident "
              "credentials and deletes nothing.")
        print("*** Run it on a bench board -- never on a board holding "
              "real passkeys. ^C to abort now.")
        time.sleep(2)

        # -- step 3: two registrations, same rp, same user.id, rk=true ----
        reg_ids, reg_keys = [], []
        for n in range(1, N_REGISTRATIONS + 1):
            label = f"makeCredential {n}/{N_REGISTRATIONS}"
            cred_id, pub_key, keepalives = register(
                ctap2, token, protocol, args.rp, user_id, label)
            reg_ids.append(cred_id)
            reg_keys.append(pub_key)
            print(f"\n  registration {n}: {label} ok (keepalives={keepalives})")
            print(f"    credential ID : {cred_id.hex()}")
            print(f"    attested key  : {pub_key}")

        # -- step 4: ID comparison, explicit -----------------------------
        print("\n  credential ID comparison:")
        same_to_each_other = reg_ids[0] == reg_ids[1]
        same_to_derivation = reg_ids[0] == expected_id
        print(f"    registration 1 == registration 2 : {same_to_each_other}")
        print(f"    registration 1 == derived ID     : {same_to_derivation}")
        print(f"    registration 2 == derived ID     : {reg_ids[1] == expected_id}")
        if same_to_each_other and same_to_derivation:
            print("    -> deterministic-ID precondition holds: every "
                  "registration for this (rp, user.id) mints the SAME ID.")
        else:
            print("    -> IDs are NOT deterministic on this board; the drift "
                  "precondition does not hold here (still a valid reading).")

        # -- step 5: pinned assertions, verified under each key ----------
        drift = False
        anomalies = 0
        for n in range(1, N_ASSERTIONS + 1):
            label = f"getAssertion {n}/{N_ASSERTIONS} (pinned ID)"
            resp, keepalives = assert_pinned(
                ctap2, token, protocol, args.rp, reg_ids[0], label)
            print(f"\n  assertion {n}: {label} ok (keepalives={keepalives})")
            resp_id = bytes(resp.credential["id"]) if resp.credential else None
            if resp_id is not None:
                print(f"    response credential ID: {resp_id.hex()} "
                      f"{'(== pinned)' if resp_id == reg_ids[0] else '(MISMATCH)'}")
            print(f"    authData flags: 0x{resp.auth_data.flags:02x}  "
                  f"signCount: {resp.auth_data.counter}")

            verified_under = []
            for m, key in enumerate(reg_keys, start=1):
                hit = verify_assertion_signature(
                    bytes(resp.auth_data), resp.signature, key,
                    CLIENT_DATA_HASH)
                print(f"    verifies under registration {m}'s key: "
                      f"{'YES' if hit else 'no'}")
                if hit:
                    verified_under.append(m)
            if not verified_under:
                anomalies += 1
                print(f"    ANOMALY: assertion {n} verified under NEITHER "
                      "registration's key -- inspect by hand.")
            # Newest registration is N_REGISTRATIONS; any older key serving
            # the pinned assertion is the drift -- but only when the keys
            # actually differ.  On post-epic firmware (US-1721) both
            # registrations attest the SAME deterministic key, so "under
            # registration 1's key" is trivially "under the newest
            # registration's key" -- that is NO-DRIFT, and printing DRIFT
            # would mislabel the fix as the bug.
            keys_identical = len(reg_keys) == N_REGISTRATIONS and all(
                bytes(reg_keys[0][-2]) == bytes(k[-2])
                and bytes(reg_keys[0][-3]) == bytes(k[-3])
                for k in reg_keys[1:]
            )
            if keys_identical and len(reg_keys) == 2 and verified_under:
                print("    NOTE: both registrations attest the SAME key "
                      "(deterministic derivation, US-1721) -- serving it "
                      "under either registration is the same key.")
            for m in verified_under:
                if m != N_REGISTRATIONS and not keys_identical:
                    print(f"  DRIFT: assertion {n} verified under "
                          f"registration {m}'s key")
                    drift = True

        # -- step 6: credMgmt metadata -----------------------------------
        print("\n  credMgmt:")
        credmgmt_report(ctap2, token, protocol, args.rp, expected_id)

        print()
        # Verdict precedence: DRIFT (a recorded, non-newest key served) >
        # INCONCLUSIVE (an unknown key served) > NO-DRIFT.  A clean NO-DRIFT
        # must not swallow an anomaly, and a DRIFT already under-reports
        # nothing, so it keeps the stronger label even with anomalies.
        if drift:
            print("RESULT: DRIFT -- a pinned assertion was served under a "
                  "key that registration did not attest (analysis doc "
                  "section 1: oldest same-ID record serves).")
        elif anomalies:
            print("RESULT: INCONCLUSIVE -- an assertion verified under "
                  "NEITHER registration's key, so an unknown key served it: "
                  "a same-ID credential left by a previous probe run (or "
                  "any earlier registration for this rp/user.id) would do "
                  "exactly this, because the oldest record serves.  Read "
                  "the ANOMALY lines and the credMgmt enumeration above "
                  "before drawing conclusions.")
        else:
            print("RESULT: NO-DRIFT -- every pinned assertion verified "
                  "under the newest registration's key (or under no "
                  "recorded key).")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="US-1720 hardware probe: resident re-registration key "
                    "drift.  Registers the same (rp, user.id) twice, pins "
                    "the credential ID, and reports which registration's "
                    "key each assertion verifies under.  REPORTS, never "
                    "asserts; nonzero exit only for genuine errors.")
    parser.add_argument("--rp", default=RP_ID_DEFAULT,
                        help=f"relying party ID (default: {RP_ID_DEFAULT!r})")
    parser.add_argument("--user-id", default=USER_ID_DEFAULT_HEX,
                        metavar="HEX",
                        help="user.id as hex (default: keccak256(\"Safe "
                             "Owner\") from the analysis doc)")
    parser.add_argument("--pin", default=None,
                        help="device PIN (board must already have one set; "
                             "the probe never sets a PIN)")
    parser.add_argument("--device", default=None, metavar="PATH",
                        help="CTAPHID device path (default: first "
                             "enumerated CTAPHID device)")
    parser.add_argument("--selftest", action="store_true",
                        help="run the pure-computation selftest (ID "
                             "derivation vector + ECDSA round-trip) with "
                             "no device")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    if not args.pin:
        parser.error("--pin is required for a hardware run "
                     "(or use --selftest)")
    if len(args.user_id) % 2:
        parser.error("--user-id hex must have an even length")
    try:
        bytes.fromhex(args.user_id)
    except ValueError:
        parser.error(f"--user-id is not valid hex: {args.user_id!r}")

    try:
        probe(args)
    except ProbeError as exc:
        print(f"PROBE ERROR: {exc}", file=sys.stderr)
        return 1
    except ctap.CtapError as exc:
        print(f"PROBE ERROR: device answered {show_exc(exc)}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - a probe reports, never crashes
        print(f"PROBE ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
