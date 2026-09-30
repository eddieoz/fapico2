"""US-153 (PicoForge-COMPAT): GENERATE over CCID, and the same-session VERIFY it
depends on.

The reference client's generate path (`picoforge/src/hal/io.rs:846-856`) is
three APDUs in one session: VERIFY PW3, PUT DATA the slot's algorithm
attribute, GENERATE. It documents, in three places
(`transport/ccid.rs:1-8`, `hal/io.rs:789-799`,
`applets/openpgp.rs:9-10`), that it relies on SELECT clearing the security
status to keep the first and the last together. This file drives the same
sequence over the real CCID relay and records what the card actually does,
which is **not** that:

* GENERATE is refused ``6985`` while the *factory* PINs are in force, and
  "in force" is the OR of two flags — PW1 **and** PW3 must both be moved off
  the shipped defaults (``vendor/opcard/src/command.rs:497-506``,
  ``state.rs:1349-1351``). The client prompts for the admin PIN on this
  path, so a user who changes only PW3 is stuck at ``6985`` with no
  diagnostic. The ``pin_gate_lifted`` fixture in the ROOT conftest moves
  both, which is the whole reason the client's own `change_pin` calls
  cannot be swapped for PW3-only.
* With the gate lifted but no VERIFY in the session, GENERATE answers
  ``6982`` (``state.rs:1948-1950``) — the status the client's session
  discipline is actually about.
* The PW3 latch **survives a re-SELECT of the same AID**.
  ``select()`` (``command.rs:346-361``) clears only ``cur_do`` and
  ``keyrefs``, and the dispatcher takes its same-app branch
  (``platform/src/dispatch.rs:163-165``), which never calls ``deselect()``.
  It *is* dropped by an applet switch, because that path does
  (``dispatch.rs:168-170`` → ``OpenPgpApp::deselect`` → ``Card::reset``).

The `card` fixture is the session-scoped, emulator-backed one from the ROOT
conftest (tests/conftest.py); it is not redefined here — see
tests/openpgp/conftest.py for why redefining it shadows the emulator. The
``pin_gate_lifted_once`` fixture used here also comes from that root
conftest: it moves both PINs off the factory defaults and wipes back to a
factory card afterwards, so a test that touches the PINs must take it rather
than rolling its own (a card left personalised is the classic way this suite
poisons its own next module).

The GENERATE framing is the client's own ``00 47 80 00 02 <crt> 00 00`` —
short Lc *and* a trailing Le of 0, neither a clean case 3 nor a clean case
2. It parses because the OpenPGP app runs the `iso7816` crate rather than a
hand-rolled parser, unlike the OATH/OTP applets where US-132 had to fix
exactly that shape. The twin over the in-process dispatcher is
`apps/openpgp/tests/picoforge_generate.rs`; this file is the same contract
over the wire, and the 61xx/GET RESPONSE chain is exercised here because the
client reaches the reply through ``transceive_full``.
"""

from openpgp_card import iso7816_compose

# PW1 / PW3 after `lift_factory_pin_gate` has run (tests/conftest.py).
GATE_PW3 = b"86429753"
# The shipped defaults, needed to prove the gate is a real precondition here
# and not a formality.
FACTORY_PW3 = b"12345678"

# CRT per slot: signature, decryption, authentication (openpgp.rs:426-432).
CRT_SIGN, CRT_DEC, CRT_AUT = 0xB6, 0xB8, 0xA4
# ECDSA / ECDH + the P-256 curve OID — the client's `ec(..)` closure, which
# substitutes ECDH on the decryption slot only. The wider attribute/curve
# matrix belongs to tests/openpgp/test_openpgp_picoforge_algo.py.
_ALGO_ECDSA, _ALGO_ECDH = 0x13, 0x12
_OID_P256 = b"\x2a\x86\x48\xce\x3d\x03\x01\x07"
# The OATH AID: a second applet on the same device, so the latch boundary can
# be observed from the wire and not only over the in-process dispatcher.
_OATH_AID = b"\xa0\x00\x00\x05\x27\x21\x01"


def _send(card, apdu):
    return card._OpenPGP_Card__reader.send_cmd(apdu)


def _generate(card, crt=CRT_SIGN):
    """The client's GENERATE, byte for byte: ``00 47 80 00 02 <crt> 00 00``.

    Short Lc ``02``, the CRT, the specification control byte ``00``, and the
    trailing short Le ``00``. The reply is reassembled over the ``61xx`` /
    GET RESPONSE chain, because ``transceive_full`` follows it and a card
    that answered a short body with 9000 would break the session.
    """
    resp = _send(card, bytes([0x00, 0x47, 0x80, 0x00, 0x02, crt, 0x00, 0x00]))
    body, sw = resp[:-2], resp[-2:]
    while sw[0] == 0x61:
        chunk = _send(card, iso7816_compose(0xC0, 0x00, 0x00, b"", le=sw[1] or 256))
        body, sw = body + chunk[:-2], chunk[-2:]
    return body, (sw[0] << 8) | sw[1]


def _put_attr(card, tag, on_dec_slot):
    """PUT DATA the algorithm attribute, the way the client does on the same
    session as the GENERATE. Admin-gated, so it answers 6982 until PW3 has
    been verified."""
    algo = _ALGO_ECDH if on_dec_slot else _ALGO_ECDSA
    resp = _send(card, iso7816_compose(0xDA, 0x00, tag, bytes([algo]) + _OID_P256))
    return (resp[-2] << 8) | resp[-1]


def _public_key_mpi(body):
    """Strict ``7F49`` parse: returns the single ``86`` MPI payload.

    Both lengths are *declared* and must account for the rest of the message.
    The client's only caller discards the body (``io.rs:852``), so a
    malformed-but-9000 reply is invisible to it and would surface one key
    import later. The MPI payload itself is the curve's own serialization, so
    its size is deliberately not asserted here.
    """
    assert len(body) >= 5, "GENERATE reply is too short to be a 7F49: %s" % body.hex()
    assert body[:2] == b"\x7f\x49", "reply is not a 7F49: %s" % body.hex()
    declared = body[2]
    assert 3 + declared == len(body), (
        "7F49 declares %d bytes but the body carries %d: %s"
        % (declared, len(body) - 3, body.hex())
    )
    value = body[3:]
    assert value[0] == 0x86, "7F49 does not open with an 86 MPI: %s" % value.hex()
    mpi_len = value[1]
    assert 2 + mpi_len == len(value), (
        "86 MPI declares %d bytes but carries %d: %s"
        % (mpi_len, len(value) - 2, value.hex())
    )
    assert mpi_len > 0, "7F49 carries a zero-length MPI"
    return value[2:]


def test_verify_then_generate_same_session(require_live_card, pin_gate_lifted_once):
    """The client's whole generate flow, in the order it runs it.

    The factory-PIN gate is already lifted by the fixture, so the only thing
    standing between here and a key is the PW3 VERIFY on this session.
    """
    card = pin_gate_lifted_once

    # The factory-PIN gate is already lifted by the fixture, so the only
    # thing standing between here and a key is the PW3 VERIFY on this
    # session. The factory-gate refusal itself is pinned in-process by
    # apps/openpgp/tests/picoforge_generate.rs, which can put a card back to
    # factory without disturbing the module-scoped fixtures the rest of this
    # suite shares.
    #
    # The fixture leaves PW3 *verified* — `lift_factory_pin_gate` verifies in
    # order to change the PIN — so the latch has to be dropped before this can
    # be an assertion about an unauthorised GENERATE at all. VERIFY with P1=0xFF
    # is the card's own "forget this verification"
    # (vendor/opcard/src/command.rs:399-407).
    _send(card, iso7816_compose(0x20, 0xFF, 0x83, b""))
    _, sw = _generate(card)
    assert sw == 0x6982, "unverified GENERATE must be 6982, got %04X" % sw

    card.cmd_verify(3, GATE_PW3)
    assert _put_attr(card, 0xC1, False) == 0x9000, "PUT DATA C1 must be 9000"

    for crt, tag, on_dec in ((CRT_SIGN, 0xC1, False), (CRT_DEC, 0xC2, True), (CRT_AUT, 0xC3, False)):
        assert _put_attr(card, tag, on_dec) == 0x9000, "PUT DATA %02X" % tag
        body, sw = _generate(card, crt)
        assert sw == 0x9000, "GENERATE %02X must be 9000, got %04X %s" % (crt, sw, body.hex())
        point = _public_key_mpi(body)
        # P-256 was just PUT, so the MPI is the SEC1 uncompressed form: 0x04
        # followed by x‖y. A card that answered the default algorithm's
        # 32-octet Ed25519 point here would be silently serving the wrong
        # curve for the attribute that was just written.
        assert len(point) == 65, "CRT %02X: P-256 point is %d octets" % (crt, len(point))
        assert point[0] == 0x04, "CRT %02X: not an uncompressed point" % crt


def test_the_pw3_latch_outlives_a_reselect_of_the_same_aid(require_live_card, pin_gate_lifted_once):
    """The security-posture divergence, observed over the wire.

    The client states in three places that it depends on SELECT clearing the
    security status. It does not: ``select()`` clears only ``cur_do`` and
    ``keyrefs`` (``vendor/opcard/src/command.rs:346-361``), and the
    dispatcher's same-app branch (``platform/src/dispatch.rs:163-165``) never
    calls ``deselect()``. So a VERIFY'd session stays authorised across any
    number of re-SELECTs of the OpenPGP AID.
    """
    card = pin_gate_lifted_once
    card.cmd_verify(3, GATE_PW3)
    _, sw = _generate(card)
    assert sw == 0x9000, "precondition: VERIFY must authorise GENERATE, got %04X" % sw

    for round_ in range(3):
        card.cmd_select_openpgp()
        _, sw = _generate(card)
        assert sw == 0x9000, "round %d: re-SELECT dropped the latch (%04X)" % (round_, sw)


def test_the_pw3_latch_does_not_outlive_an_applet_switch(require_live_card, pin_gate_lifted_once):
    """The other half of the boundary, and the one that makes the above a
    security property rather than an unbounded one.

    Selecting a different applet runs ``deselect()`` on the app being left
    (``platform/src/dispatch.rs:168-170``), which for OpenPGP is a
    ``Card::reset()`` (``apps/openpgp/src/device_shell.rs:614-619``) and drops
    the volatile admin latch. Coming back to the OpenPGP AID therefore finds
    a card that must be VERIFY'd again.
    """
    card = pin_gate_lifted_once
    card.cmd_verify(3, GATE_PW3)
    _, sw = _generate(card)
    assert sw == 0x9000, "precondition: VERIFY must authorise GENERATE, got %04X" % sw

    resp = _send(card, iso7816_compose(0xA4, 0x04, 0x00, _OATH_AID))
    assert resp[-2:] == b"\x90\x00", "SELECT of the OATH applet failed: %s" % resp.hex()
    card.cmd_select_openpgp()

    _, sw = _generate(card)
    assert sw == 0x6982, "an applet switch must drop the PW3 latch, got %04X" % sw

    # The old factory admin PIN is not the one that latches now, which is
    # what makes this a security boundary and not bookkeeping.
    resp = _send(card, iso7816_compose(0x20, 0x00, 0x83, FACTORY_PW3))
    assert resp[-2:] != b"\x90\x00", "the factory admin PIN verified on a personalised card"
    card.cmd_verify(3, GATE_PW3)
    assert _generate(card)[1] == 0x9000, "re-VERIFY must restore the latch"
