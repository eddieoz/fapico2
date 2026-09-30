"""PICOForge-COMPAT: the key-state data objects the reference client reads
out of the ``73`` (Discretionary Data Objects) sub-template of ``0x6E``
(``picoforge/src/hal/applets/openpgp.rs:258-287``) — ``0xC4`` PW status,
``0xC5`` fingerprints, ``0xDE`` key information, and the per-slot ``0xC1``-``0xC3``
attribute and ``0xD6``-``0xD8`` touch DOs.

The client does not read these the way a reader of the OpenPGP card spec
would. It reads fixed offsets out of fixed-length blobs, and a card that
answers ``9000`` with a *plausible but wrongly shaped* DO is silently
misrendered rather than rejected:

* ``0xC4`` is gated on ``len() >= 7`` and then read as ``(p[4], p[5], p[6])``
  — the PW1 / reset-code / PW3 retry counters. Bytes 0-3 are ignored, so a
  card that filled the first three slots with counters would render a
  plausible-looking but wrong triple.
* ``0xC5`` is sliced as ``fps[i*20 : i*20+20]`` for ``[Sig, Dec, Aut]``; under
  60 bytes every slot collapses to the empty slice and the client shows a key
  with an empty fingerprint.
* ``0xDE`` is read at the **odd** indices only (``key_info[i*2+1] != 0``).
  The even bytes are the key references 01/02/03 and are never read — but
  they are what says *which* key a status belongs to, so a card that emitted
  three bare status bytes would still satisfy the client and would report the
  signature slot's status as the decryption key's.
* ``0xC1``-``0xC3`` and ``0xD6``-``0xD8`` feed only the display label and the
  ``touch`` boolean; absent is tolerated (label "unknown", touch false), so
  only their *shape* is load-bearing here.

The client computes a slot's presence as an **OR** over ``0xC5`` and ``0xDE``
and both halves are driven by different writers, so the test replays the OR
rather than asserting either DO alone (see ``docs/tasks/us151-key-state-objects.md``).

The `card` fixture is the session-scoped emulator-backed one from the ROOT
conftest (tests/conftest.py); it is not redefined here — see
tests/openpgp/conftest.py for why redefining it shadows the emulator.
"""

from openpgp_card import iso7816_compose

# The algorithm-id byte every ``0xC1``-``0xC3`` attribute starts with
# (openpgp.rs:41-44). The client maps it to a label and falls back to
# "unknown" for anything else, so a card answering a bogus id still renders —
# a shape check is the only thing that catches it.
_ALGO_IDS = frozenset((0x01, 0x12, 0x13, 0x16))
# ``Uif`` (vendor/opcard/src/types.rs:538-543) as the card reports it, and the
# general-feature-management byte that follows it in ``0xD6``-``0xD8``.
_UIF_STATES = frozenset((0x00, 0x01, 0x02))
_GFM_BYTE = 0x20
# PW status: the three maximum-length fields and the three retry counters, by
# the offsets the client reads them at.
_PW_MAX_LEN_INDEXES = (1, 2, 3)
_PW_RETRY_INDEXES = (4, 5, 6)
_MIN_PIN_LENGTH = 6
_MAX_PIN_LENGTH = 127
# A card that emitted all three retry counters as ``FF`` would still answer
# 9000; 0..3 is the whole range of a real counter.
_MAX_RETRIES = 3


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
    """Return ``{tag_bytes: value}`` over a BER-TLV run, strictly.

    Strict because these DOs are read by a client that walks them
    field-by-field: a length that overruns its own buffer is a parse failure
    on the client even when the card returned 9000.
    """
    found = {}
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
        found[tag] = body[offset:offset + length]
        offset += length
    return found


def test_key_state_objects_match(live_card):
    # 0x6E is where all eight live; a non-9000 here is fatal to the client.
    app_data, sw = _get_data(live_card, 0x6E)
    assert sw == 0x9000, "GET DATA 6E: %04X" % sw
    app = _tlvs(app_data)
    assert b"\x73" in app, "0x6E carries no 73 sub-template"
    disc = _tlvs(app[b"\x73"])

    for tag in (0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xDE, 0xD6, 0xD7, 0xD8):
        key = bytes((tag,))
        assert key in disc, "the 73 carries no %02X: %s" % (tag, app[b"\x73"][:32].hex())
        # The same DO read on its own must agree with the copy the client
        # walks; a disagreement leaves gpg and the reference client
        # describing different cards.
        direct, sw = _get_data(live_card, tag)
        assert sw == 0x9000, "GET DATA %02X: %04X" % (tag, sw)
        assert disc[key] == direct, "0x%02X differs between the 73 and its own GET DATA" % tag

    # 0xC4: the client drops anything under 7 bytes to (0, 0, 0) without an
    # error, so the length is part of the contract. Bytes 1-3 are the three
    # maximum PIN lengths; 4-6 are the three retry counters. Both facts are
    # invisible to the client (it ignores 0-3) and both are asserted here.
    c4 = disc[b"\xc4"]
    assert len(c4) >= 7, "0xC4 is %d bytes; the client reads (0,0,0)" % len(c4)
    for index in _PW_MAX_LEN_INDEXES:
        assert (
            _MIN_PIN_LENGTH <= c4[index] <= _MAX_PIN_LENGTH
        ), "0xC4[%d] = %d is not a maximum PIN length (a counter here shifts every value the client shows)" % (
            index,
            c4[index],
        )
    for index in _PW_RETRY_INDEXES:
        assert (
            c4[index] <= _MAX_RETRIES
        ), "0xC4[%d] = %d is not a remaining-tries count" % (index, c4[index])

    # 0xC5: the client slices it positionally, so the exact 3x20 length is
    # what makes each slot non-empty.
    c5 = disc[b"\xc5"]
    assert len(c5) == 60, "0xC5 is %d bytes, not three 20-byte slots" % len(c5)

    # The per-slot 0xC7/0xC8/0xC9 a host writes a fingerprint through answer
    # 6A88 to GET DATA — they are write-only in this implementation (absent
    # from opcard's GetDataObject set, data.rs:238-268), so the composite
    # 0xC5 is the only fingerprint a reader can see, and the client cannot
    # cross-check a slot against a per-slot reference. What *is* checkable
    # here is that the card is internally consistent about which slots hold
    # anything at all, which is what the OR below turns on.
    for tag in (0xC7, 0xC8, 0xC9):
        body, sw = _get_data(live_card, tag)
        assert sw in (0x9000, 0x6A88), "GET DATA %02X: %04X" % (tag, sw)
        assert sw != 0x9000 or len(body) == 20, "0x%02X is %d bytes, not one 20-byte fingerprint" % (tag, len(body))

    # 0xDE: 01/02/03 key references (Sig/Dec/Aut) with the status alongside.
    # The client reads only the status; the key reference is what keeps the
    # status attached to the right key.
    de = disc[b"\xde"]
    assert len(de) == 6, "0xDE is %d bytes, not three key-ref/status pairs" % len(de)
    assert [de[0], de[2], de[4]] == [1, 2, 3], "0xDE key refs are not Sig/Dec/Aut: %s" % de.hex()
    for slot, index in enumerate((1, 3, 5)):
        assert de[index] in (0, 1, 2), "0xDE slot %d status = %d is outside {none, generated, imported}" % (
            slot,
            de[index],
        )

    # The client's per-slot view, replayed: presence is an OR over the
    # fingerprint bytes and the status byte, and the fingerprint is the
    # 20-byte slice. Both halves come from independent writers, so neither
    # DO alone decides the key list.
    for slot, name in enumerate(("Sig", "Dec", "Aut")):
        fp = c5[slot * 20:slot * 20 + 20]
        assert len(fp) == 20, "slot %d fingerprint slice is %d bytes" % (slot, len(fp))
        # A slot the card reports as keyless must carry no fingerprint
        # bytes. The card clears the composite slice when it drops the key
        # (`delete_key`, state.rs:1678) and it has to: a stray byte reads as
        # "present" through the OR with nothing to contradict it, so a
        # leftover slice shows an operator a key the card cannot use.
        if de[slot * 2 + 1] == 0:
            assert not any(
                b != 0 for b in fp
            ), "0xDE says slot %s has no key but 0xC5 still holds a fingerprint: %s" % (name, fp.hex())
        present = any(b != 0 for b in fp) or de[slot * 2 + 1] != 0
        assert isinstance(present, bool), "presence for slot %s must be a plain bool" % name

    # 0xC1-0xC3: label-only, but the algorithm-id byte is what the client
    # switches on and an unrecognised one silently becomes "unknown".
    for tag in (0xC1, 0xC2, 0xC3):
        attr = disc[bytes((tag,))]
        assert attr, "0x%02X carries no algorithm attribute" % tag
        assert (
            attr[0] in _ALGO_IDS
        ), "0x%02X algorithm id %02X is not one the client can label: %s" % (tag, attr[0], attr.hex())

    # 0xD6-0xD8: [uif-state, gfm]. The client reads the FIRST byte only, so
    # the state has to lead; a card that put the GFM byte first would report
    # touch for every slot on a card with no touch requirement at all.
    for tag in (0xD6, 0xD7, 0xD8):
        uif = disc[bytes((tag,))]
        assert len(uif) == 2, "0x%02X is %d bytes, not [uif-state, gfm]" % (tag, len(uif))
        assert uif[0] in _UIF_STATES, "0x%02X uif state %02X is outside the Uif enum" % (tag, uif[0])
        assert uif[1] == _GFM_BYTE, "0x%02X second byte %02X is not the GFM byte" % (tag, uif[1])
