"""US-1845 — the bypass-accounting matrix over the CCID emulator.

The emulator registers Nostr over CCID only (AGENTS.md §8): the vendor-HID
arm is not exercised here — that is `nostr_probe.py`'s job on the board
(US-1847), because a green emulator suite says nothing about that arm.
Everything below drives the applet's own dialect through the dispatcher:

arm → N grant-free operations → GET_AUDIT reads
`budget ‖ n ‖ age_ms ‖ records` → the spent session's next operation goes
back through the touch → LOCK closes the read with the session.

Two emulator instances carry the matrix. The **auto-ack** one answers every
press, so the whole state machine is driven end to end; the **deny** one
(`FAPICO2_NOSTR_PRESENCE=deny`) proves the sessionless rows. The budget is
the cap's observable over CCID: the auto-ack cannot distinguish a consulted
grant from a skipped one, but the *budget* can — the next operation past
the budget, going
through the touch path, burns nothing and writes no record.

The expiry is not exercised over CCID: the emulator's clock is real wall
time and a 10-minute sleep is not a CI test. The deadline arithmetic is
pinned by the host suite (`apps/nostr/tests/bypass_accounting.rs`, the
fake clock), which is the same code the emulator runs.

GET_INFO layout: `applet_ver(2) ‖ caps(2) ‖ max_plaintext(2) ‖
n_identities(1) ‖ flags(1)` — caps bit 5 = CAP_BYPASS_ACCOUNTING, flags
bit 3 = FLAG_TOUCH_BYPASS. GET_AUDIT v0.3 body: `budget(1) ‖ n(1) ‖
age_ms(4 BE) ‖ n × { op(1), idx(1), ts(4 BE), digest(16) }` — 22 bytes
per record, from offset 6. `age_ms` is the session's sampled age
(US-1849): the device clock is monotonic-since-boot, so a raw stamp
could never be related to host wall time, but an age sampled at read
time anchors a client-side countdown.
"""

import hashlib

import pytest

from nostr_ccid import (
    FLAG_MIGRATION_PENDING,
    INS_GET_INFO,
    INS_IMPORT_KEY,
    INS_LOCK,
    INS_SET_PIN,
    INS_SIGN,
    INS_VERIFY_PIN,
    NostrEmu,
    SW_OK,
    SW_PIN_NOT_SET,
    SW_PIN_SESSION_REQUIRED,
    SW_TOUCH_REQUIRED,
    apdu,
)

INS_GET_AUDIT = 0x20
INS_SET_TOUCH_POLICY = 0x1F

CAP_BYPASS_ACCOUNTING = 0x0020
FLAG_TOUCH_BYPASS = 0x08

OP_SIGN = 0x00
OP_NIP44_ENC = 0x01
OP_NIP44_DEC = 0x02

SCALAR = bytes([0x03]) + bytes(31)
PIN = b"731742"
DIGEST = bytes(32)

RECORD_LEN = 22


def read_info(emu):
    data, _ = emu.send(apdu(INS_GET_INFO))
    caps = (data[2] << 8) | data[3]
    flags = data[7]
    return caps, flags


def parse_audit_body(data):
    budget = data[0]
    n = data[1]
    age_ms = int.from_bytes(data[2:6], "big")
    records = []
    for i in range(n):
        b = data[6 + i * RECORD_LEN : 6 + (i + 1) * RECORD_LEN]
        records.append(
            {
                "op": b[0],
                "idx": b[1],
                "ts_ms": int.from_bytes(b[2:6], "big"),
                "digest": bytes(b[6:22]),
            }
        )
    return budget, age_ms, records


def verified_board(emu):
    """Import the identity, set the PIN, open the session."""
    _, sw = emu.send(apdu(INS_IMPORT_KEY, p1=0, data=SCALAR))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_OK


def arm(emu):
    _, sw = emu.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_OK, "the consent press lands"


@pytest.fixture()
def emu(tmp_path):
    with NostrEmu("keymgmt", tmp_path) as e:
        assert e.select()[1] == SW_OK
        yield e


# ---------------------------------------------------------------------------
# Advertisement and gating
# ---------------------------------------------------------------------------


def test_get_info_advertises_bypass_accounting(emu):
    caps, flags = read_info(emu)
    assert caps & CAP_BYPASS_ACCOUNTING, "the accounting exists on this firmware"
    assert not flags & FLAG_TOUCH_BYPASS, "a fresh boot has the flag down"


def test_a_closed_session_is_refused(emu):
    _, sw = emu.send(apdu(INS_IMPORT_KEY, p1=0, data=SCALAR))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_SET_PIN, p1=0, data=PIN))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_GET_AUDIT))
    assert sw == SW_PIN_SESSION_REQUIRED, "a sessionless host learns nothing, not even the budget"


def test_a_pin_less_board_answers_honestly_empty(emu):
    data, sw = emu.send(apdu(INS_GET_AUDIT))
    assert sw == SW_OK
    budget, age_ms, records = parse_audit_body(bytes(data))
    assert budget == 0
    assert age_ms == 0, "no session, no age"
    assert records == [], "nothing to audit"


def test_lock_closes_the_read_along_with_the_session(emu):
    verified_board(emu)
    arm(emu)
    emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    _, sw = emu.send(apdu(INS_LOCK))
    assert sw == SW_OK
    _, sw = emu.send(apdu(INS_GET_AUDIT))
    assert sw == SW_PIN_SESSION_REQUIRED, "the read died with the session"


# ---------------------------------------------------------------------------
# The ring over the wire
# ---------------------------------------------------------------------------


def test_an_open_session_reads_budget_and_records(emu):
    verified_board(emu)
    arm(emu)
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_OK
    data, sw = emu.send(apdu(INS_GET_AUDIT))
    assert sw == SW_OK
    budget, age_ms, records = parse_audit_body(bytes(data))
    assert budget == 254, "one operation spent of 255 (US-1855)"
    assert len(data) == 6 + len(records) * RECORD_LEN, "the v0.3 6-byte header"
    assert len(records) == 1
    r = records[0]
    assert r["op"] == OP_SIGN
    assert r["idx"] == 0
    assert r["digest"] == hashlib.sha256(DIGEST).digest()[:16], "the sighash's digest"
    assert r["ts_ms"] > 0, "the emulator's virtual clock stamped it"
    assert age_ms < 600_000, "the age of a live session, inside the window"


def test_the_cap_is_observable_over_ccid(emu):
    verified_board(emu)
    arm(emu)
    # A distinct payload per operation: the overwrite-oldest assertion
    # below must be able to FAIL — identical digests would make it a ghost
    # (satisfiable by any record, pinning nothing).
    for i in range(255):
        _, sw = emu.send(apdu(INS_SIGN, p1=0, data=bytes([i % 256]) * 32))
        assert sw == SW_OK, "the whole budget runs grant-free"
    data, sw = emu.send(apdu(INS_GET_AUDIT))
    budget, age_ms, records = parse_audit_body(bytes(data))
    assert budget == 0, "the session is spent"
    assert age_ms == 0, "the spent session's age reads as gone"
    assert len(records) == 16, "the ring holds its depth, oldest overwritten"

    # The next operation goes back through the touch path: on the auto-ack
    # emulator it still answers SW_OK (the press is granted), but it burns
    # nothing and writes no record — the budget is the observable.
    _, sw = emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    assert sw == SW_OK, "the press is granted on the auto-ack"
    data, sw = emu.send(apdu(INS_GET_AUDIT))
    budget, age_ms, records = parse_audit_body(bytes(data))
    assert budget == 0, "the touched op past the budget burned nothing"
    assert age_ms == 0, "and its age stays gone"
    assert len(records) == 16, "and wrote no record"
    # The ring's newest record is still the 255th operation's — the touched
    # op wrote nothing, and every older record has been overwritten away.
    assert records[-1]["digest"] == hashlib.sha256(bytes([254]) * 32).digest()[:16]
    assert records[0]["digest"] != hashlib.sha256(bytes([254]) * 32).digest()[:16]


def test_re_arming_resets_the_budget(emu):
    verified_board(emu)
    arm(emu)
    for _ in range(10):
        emu.send(apdu(INS_SIGN, p1=0, data=DIGEST))
    data, _ = emu.send(apdu(INS_GET_AUDIT))
    budget, _, _ = parse_audit_body(bytes(data))
    assert budget == 245, "ten operations spent of 255"
    arm(emu)
    data, _ = emu.send(apdu(INS_GET_AUDIT))
    budget, _, _ = parse_audit_body(bytes(data))
    assert budget == 255, "arming is the reset"


# ---------------------------------------------------------------------------
# The deny board: sessionless rows
# ---------------------------------------------------------------------------


@pytest.fixture()
def deny(tmp_path):
    # The auto-ack instance seeds the region file (identity + PIN); the
    # deny instance reopens it with the session closed — VERIFY is
    # touch-free, so the deny instance opens its own session.
    with NostrEmu("keymgmt", tmp_path) as e:
        assert e.select()[1] == SW_OK
        _, sw = e.send(apdu(INS_IMPORT_KEY, p1=0, data=SCALAR))
        assert sw == SW_OK
        _, sw = e.send(apdu(INS_SET_PIN, p1=0, data=PIN))
        assert sw == SW_OK
    with NostrEmu("deny", tmp_path, presence="deny") as e:
        assert e.select()[1] == SW_OK
        yield e


def test_the_deny_board_reads_an_honestly_empty_ring(deny):
    # The bypass cannot be armed under a denied presence source (the consent
    # press is refused), so the deny board's ring is empty — and the read
    # itself works once the (touch-free) VERIFY opens the session.
    _, sw = deny.send(apdu(INS_VERIFY_PIN, data=PIN))
    assert sw == SW_OK, "VERIFY is touch-free: the deny board can open a session"
    _, sw = deny.send(apdu(INS_SET_TOUCH_POLICY, p1=1))
    assert sw == SW_TOUCH_REQUIRED, "the consent press is denied — no arm"
    _, sw = deny.send(apdu(INS_GET_AUDIT))
    assert sw == SW_OK
    budget, age_ms, records = parse_audit_body(bytes(deny.send(apdu(INS_GET_AUDIT))[0]))
    assert budget == 0, "no press, no bypass"
    assert age_ms == 0, "no session, no age"
    assert records == [], "no records either"
