"""US-150 (PicoForge-COMPAT): the data objects the reference client reads off
a card it has only just SELECTed — the "applet info" screen, before any PIN is
touched.

The client reads five of them, and its expectations are not the ones a reader
of the OpenPGP card spec would assume:

* ``0x4F`` (Application Identifier) is decoded as **packed BCD**: the serial
  field ``AID[10..14]`` is read digit-per-nibble with no validity check, so a
  nibble above 9 renders as a garbage decimal. The card must therefore only
  ever *draw* serials whose every nibble is 0-9.
* ``0x6E`` (Application Related Data) is read with a ``find(..).unwrap_or(&self)``
  shape tolerance, because some cards answer with the template already
  unwrapped. A non-9000 here is fatal to the client, so the status word is
  pinned as tightly as the body.
* ``0x65`` (Cardholder Related Data) is walked as TLVs for ``5B``/``5F2D``/``5F35``.
* ``0x5E`` (Login Data) and ``0x5F50`` (URL) are read **raw, with no TLV
  unwrap** — the reply must be the bare value, not the value re-wrapped in its
  own tag. An unset DO answers 9000 with an empty body.

The `card` fixture is the session-scoped emulator-backed one from the ROOT
conftest (tests/conftest.py); it is not redefined here — see
tests/openpgp/conftest.py for why redefining it shadows the emulator.
"""

from openpgp_card import iso7816_compose

# The OpenPGP AID prefix of `0x4F`: RID + PIX + version (spec §4.2.1).
_AID_PREFIX = b"\xd2\x76\x00\x01\x24\x01\x03\x04"
# The serial field inside it, as a byte range rather than a slice of the TLV.
_SERIAL = slice(10, 14)


def _send(card, apdu):
    return card._OpenPGP_Card__reader.send_cmd(apdu)


def _get_data(card, tag):
    """GET DATA (INS 0xCA) for `tag`, returning ``(body, sw)``.

    The tag goes in P1-P2 (``00 CA 00 5E`` for 5E, ``00 CA 5F 50`` for 5F50),
    per spec §7.1. The body is reassembled across the ``61XX``/GET RESPONSE
    chain, because the Application Related Data is far longer than one Le.
    """
    tagh, tagl = tag >> 8, tag & 0xFF
    resp = _send(card, iso7816_compose(0xCA, tagh, tagl, b"", le=254))
    body, sw = resp[:-2], resp[-2:]
    while sw[0] == 0x61:
        chunk = _send(card, iso7816_compose(0xC0, 0x00, 0x00, b"", le=sw[1] or 256))
        body, sw = body + chunk[:-2], chunk[-2:]
    return body, (sw[0] << 8) | sw[1]


def _tlvs(body):
    """Yield ``(tag_bytes, value)`` over a BER-TLV run, strictly.

    Strict because these DOs are read by a client that walks them
    field-by-field: a length that overruns its own buffer is a parse failure
    on the client even when the card returned 9000.
    """
    offset = 0
    while offset < len(body):
        start = offset
        offset += 1
        if body[start] & 0x1F == 0x1F:  # multi-byte tag
            while body[offset] & 0x80:
                offset += 1
            offset += 1
        tag = body[start:offset]
        length = body[offset]
        offset += 1
        if length & 0x80:
            width = length & 0x7F
            length = int.from_bytes(body[offset:offset + width], "big")
            offset += width
        assert offset + length <= len(body), "TLV %s overruns the body" % tag.hex()
        yield tag, body[offset:offset + length]
        offset += length


def test_selection_data_objects_match(live_card):
    # 0x4F: present, the AID the client knows, and a serial it can render.
    aid, sw = _get_data(live_card, 0x4F)
    assert sw == 0x9000, "GET DATA 4F: %04X" % sw
    assert len(aid) >= 14, "0x4F is too short to hold a serial: %d bytes" % len(aid)
    assert aid.startswith(_AID_PREFIX), "0x4F is not the OpenPGP 3.4 AID: %s" % aid.hex()
    serial = aid[_SERIAL]
    for index, byte in enumerate(serial):
        assert (
            byte >> 4 <= 9 and byte & 0x0F <= 9
        ), "serial byte %d (0x%02X) is not packed BCD; the client prints it as garbage" % (
            index,
            byte,
        )

    # 0x6E: 9000 or the client gives up, and the two DOs it descends into must
    # be in there (4F for the identity, 73 for the discretionary DOs).
    app_data, sw = _get_data(live_card, 0x6E)
    assert sw == 0x9000, "GET DATA 6E: %04X (fatal to the client)" % sw
    tags = {tag for tag, _ in _tlvs(app_data)}
    assert b"\x4f" in tags, "0x6E carries no 4F: %s" % app_data[:32].hex()
    assert b"\x73" in tags, "0x6E carries no 73: %s" % app_data[:32].hex()

    # 0x65: name, language and the sex/PIN-status byte, as TLVs.
    holder, sw = _get_data(live_card, 0x65)
    assert sw == 0x9000, "GET DATA 65: %04X" % sw
    holder_tags = {tag for tag, _ in _tlvs(holder)}
    for tag in (b"\x5b", b"\x5f\x2d", b"\x5f\x35"):
        assert tag in holder_tags, "0x65 carries no %s: %s" % (tag.hex(), holder.hex())

    # ...and the 5F35 *value*, which the previous assertion could not reach.
    # A factory card sends 0x30, "not known" -- the OpenPGP card spec's
    # "unspecified" encoding, and opcard's own default (Sex::NotKnown = 0x30).
    # The client's docstring at openpgp.rs:119 lists only 0x31 male, 0x32
    # female and 0x39 "not announced"; 0x39 is the ISO 7816 "not announced"
    # encoding, a *different* thing from 0x30 "not known". The client passes
    # the byte through verbatim, so 0x30 reaches the UI unlabelled -- that is
    # a gap in the client's three-value docstring, not a card defect, and it
    # is on the EPIC's upstream list. Asserting the served value is what makes
    # that claim checkable instead of asserted: if the card ever starts
    # sending 0x39 or a byte outside the encoding set, this fails loudly.
    sex = dict(_tlvs(holder))[b"\x5f\x35"]
    assert len(sex) == 1, "5F35 must be one byte, got %d: %s" % (len(sex), sex.hex())
    assert sex[0] in (0x30, 0x31, 0x32, 0x39), (
        "5F35 is outside the card-spec encoding set: %02X" % sex[0]
    )
    assert sex[0] != 0x39, (
        "0x39 is the ISO 7816 'not announced' encoding; a card with no sex "
        "asserted must send 0x30 'not known', and this is what PicoForge's UI "
        "would mislabel if we sent 0x39 for an unset value"
    )

    # 0x5E / 0x5F50: read raw by the client, so the reply must be the bare
    # value. A factory card has neither set, which is the 9000 + empty body
    # case; the populated round trip is pinned by the suite's own
    # card_test_personalize_card_1.py (test_login / test_url), which asserts
    # the same bare shape for a written value.
    login, sw = _get_data(live_card, 0x5E)
    assert sw == 0x9000, "GET DATA 5E: %04X" % sw
    assert not login.startswith(b"\x5e"), "0x5E is wrapped in its own tag: %s" % login.hex()

    url, sw = _get_data(live_card, 0x5F50)
    assert sw == 0x9000, "GET DATA 5F50: %04X" % sw
    assert not url.startswith(b"\x5f\x50"), "0x5F50 is wrapped in its own tag: %s" % url.hex()
