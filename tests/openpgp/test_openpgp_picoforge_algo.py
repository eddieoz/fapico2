"""US-152 (PICOForge-COMPAT): the algorithm attributes the reference client
writes to C1/C2/C3, round-tripped over the real CCID + emulator path.

The client builds an attribute as ``<algo id><curve OID>`` and PUTs it to the
slot DO before GENERATE, then reads the same DO back to label the key. Two
things about that exchange are worth a wire-level pin:

* **The client never sends the ``FF`` form.** It emits the bare
  ``<id><OID>`` spelling (``13 2A 86 48 CE 3D 03 01 07``); the card answers
  with the public-key form, the same bytes plus an ``FF`` import nibble. A
  host that PUT the ``FF`` spelling would still pass an FF-only test, so the
  bytes driven here are the ones the client actually builds — reconstructed
  from the client's own OID list and its own ``ec(id, oid)`` closure rather
  than transcribed, so the ECDSA/ECDH slot split cannot be a property of this
  file rather than of the client.
* **The DEC slot is not ECDH-only.** The ECDSA→ECDH substitution lives inside
  that closure, so the RSA choices emit ``01 08 00 00 20 00`` on all three
  slots alike and the encryption slot accepts one. That the card then
  *generates* an RSA decryption key is the firmware-level half of the claim
  and is pinned in apps/openpgp/tests/picoforge_algo.rs; what this layer
  fixes is the round trip a host sees before it ever gets there.

`card` is the session-scoped emulator-backed fixture from the ROOT conftest
(tests/conftest.py) and is deliberately not redefined here — see
tests/openpgp/conftest.py. The US-912 factory-PIN gate fixtures come from the
same file: algorithm attributes are admin-authorized, and lifting the gate
restores a factory card afterwards so the algorithm DOs this test writes are
back to their defaults for the modules that run after it.
"""

from openpgp_card import iso7816_compose

# First byte of an attribute: the algorithm id.
ALGO_RSA = 0x01
ALGO_ECDH = 0x12
ALGO_ECDSA = 0x13
ALGO_EDDSA = 0x16

# Curve OIDs, as the client lists them.
OID_P256 = bytes([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
OID_P384 = bytes([0x2B, 0x81, 0x04, 0x00, 0x22])
OID_P521 = bytes([0x2B, 0x81, 0x04, 0x00, 0x23])
OID_SECP256K1 = bytes([0x2B, 0x81, 0x04, 0x00, 0x0A])
OID_BP256R1 = bytes([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07])
OID_BP384R1 = bytes([0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B])
OID_ED25519 = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01])
OID_X25519 = bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01])

# The Brainpool P-512r1 OID: the client's family prefix with the 0x0D size
# nibble. The client has no entry for it and the card has no bp512 backend, so
# it is the one curve in this OID family that is refused from both sides.
OID_BP512R1 = OID_BP256R1[:8] + bytes([0x0D])

# The client's ten generate-menu entries, as (label, choice, curve-or-None).
CHOICES = [
    ("RSA-2048", 0, None),
    ("RSA-3072", 1, None),
    ("RSA-4096", 2, None),
    ("ECC P-256", 3, OID_P256),
    ("ECC P-384", 4, OID_P384),
    ("ECC P-521", 5, OID_P521),
    ("secp256k1", 6, OID_SECP256K1),
    ("brainpoolP256r1", 7, OID_BP256R1),
    ("brainpoolP384r1", 8, OID_BP384R1),
    ("Ed25519 / Cv25519", 9, None),
]

# The algorithm-attribute DO per slot, named as the client names the slots.
SLOTS = (("C1/sign", 0xC1), ("C2/dec", 0xC2), ("C3/aut", 0xC3))

_RSA_BITS = {0: 2048, 1: 3072, 2: 4096}

_CURVE_OIDS = {
    3: OID_P256,
    4: OID_P384,
    5: OID_P521,
    6: OID_SECP256K1,
    7: OID_BP256R1,
    8: OID_BP384R1,
}


def _attribute(choice, slot_tag):
    """The bytes the client PUTs for `choice` on the slot DO `slot_tag`.

    The client's ``ec(..)`` closure is reproduced exactly: the EC id is
    ``0x12`` on the encryption slot and ``0x13`` on the other two, and the
    25519 entry splits between Cv25519 (ECDH) on encryption and Ed25519
    (EdDSA) elsewhere. The RSA arms sit *outside* that closure, which is why
    they come out identical on all three slots.
    """
    on_dec = slot_tag == 0xC2
    if choice in _RSA_BITS:
        # <id> <modulus bits BE> <exponent bits BE> <import format>
        bits = _RSA_BITS[choice]
        return bytes([ALGO_RSA, bits >> 8, bits & 0xFF, 0x00, 0x20, 0x00])
    if choice == 9:
        return bytes([ALGO_ECDH if on_dec else ALGO_EDDSA,
                      *(OID_X25519 if on_dec else OID_ED25519)])
    return bytes([ALGO_ECDH if on_dec else ALGO_ECDSA, *_CURVE_OIDS[choice]])


def _expected_read_back(sent):
    """What GET DATA must answer after a PUT of `sent`.

    The card stores the parsed algorithm, not the bytes, and answers from its
    own canonical encoding: the public-key form for every EC and 25519
    variant — the sent bytes plus the ``FF`` import nibble — and the standard
    ``N,E`` spelling for RSA, which is already what the client sent.
    """
    return sent if sent[0] == ALGO_RSA else sent + b"\xff"


def _send(card, apdu):
    return card._OpenPGP_Card__reader.send_cmd(apdu)


def _sw(response):
    return (response[-2] << 8) | response[-1]


def _get_data(card, tag):
    """GET DATA (INS 0xCA) for `tag`, returning ``(body, sw)``.

    The tag goes in P1-P2 (``00 CA 00 C1 00``), per spec §7.1. The body is
    reassembled across the ``61XX``/GET RESPONSE chain: the ``FA`` algorithm
    DO is 30 records and does not fit one Le.
    """
    resp = _send(card, iso7816_compose(0xCA, 0x00, tag, b"", le=254))
    body, sw = resp[:-2], (resp[-2] << 8) | resp[-1]
    while sw & 0xFF00 == 0x6100:
        chunk = _send(card, iso7816_compose(0xC0, 0x00, 0x00, b"", le=sw & 0xFF or 256))
        body, sw = body + chunk[:-2], (chunk[-2] << 8) | chunk[-1]
    return body, sw


def _put_data(card, tag, attr):
    """PUT DATA (INS 0xDA) of an algorithm attribute, returning the SW.

    Short Lc and **no Le** byte: the reference client composes it this way and
    an APDU carrying a trailing Le is a different command to the card's
    parser. Built through ``iso7816_compose`` with ``le`` left unset rather
    than by hand so that stays true.
    """
    return _sw(_send(card, iso7816_compose(0xDA, 0x00, tag, attr)))


def test_algorithm_attribute_roundtrip(require_live_card, pin_gate_lifted_once):
    card = pin_gate_lifted_once
    # The gate fixture has verified PW3, which is what the attribute DOs are
    # authorized against (`write_perm` -> Admin).

    # 1. Every attribute the client's menu can produce is accepted on all
    #    three slot DOs and reads back in the card's canonical spelling.
    #
    #    **One entry is held out**: the client *does* offer Brainpool P-384r1
    #    (choice 8), and the card deliberately does not serve it — US-966
    #    deferred that curve (-166,056 B of ``text``), and it is refused
    #    ``6A80`` at PUT DATA and absent from ``GET DATA FA``. Holding it out
    #    here is not a way to stop testing it: the refusal itself is asserted
    #    immediately below, and in the Rust twin
    #    ``apps/openpgp/tests/picoforge_algo.rs``, which also pins that the
    #    refusal leaves the stored attribute untouched.
    for label, choice, _curve in CHOICES:
        if choice == 8:
            continue
        for slot_name, tag in SLOTS:
            attr = _attribute(choice, tag)
            sw = _put_data(card, tag, attr)
            assert sw == 0x9000, (
                "client choice %d (%s) on %s: PUT DATA %s must answer 9000, got %04X"
                % (choice, label, slot_name, attr.hex(), sw)
            )
            stored, sw = _get_data(card, tag)
            assert sw == 0x9000, "GET DATA %02X after PUT must answer 9000, got %04X" % (
                tag, sw)
            assert stored == _expected_read_back(attr), (
                "client choice %d (%s) on %s: the card must read back the algorithm the "
                "client named, in its own spelling. PUT %s, got %s"
                % (choice, label, slot_name, attr.hex(), stored.hex())
            )

    # 1b. The deferred entry, asserted as refused rather than skipped. A test
    #     that simply omitted it would pass just as happily if the card started
    #     serving it again for a reason nobody noticed.
    for slot_name, tag in SLOTS:
        sw = _put_data(card, tag, _attribute(8, tag))
        assert sw == 0x6A80, (
            "Brainpool P-384r1 is deferred (US-966) and must be refused 6A80 on %s; got %04X"
            % (slot_name, sw)
        )

    # 2. The encryption slot's RSA round trip specifically, called out because
    #    it is the one the "DEC is always ECDH" reading gets wrong: the client
    #    emits the same six bytes for it as for the signature slot, and the
    #    card stores them on C2. The firmware half — that GENERATE on this slot
    #    then yields an RSA key — is apps/openpgp/tests/picoforge_algo.rs.
    rsa_2k = _attribute(0, 0xC2)
    assert rsa_2k == bytes([0x01, 0x08, 0x00, 0x00, 0x20, 0x00])
    assert _put_data(card, 0xC2, rsa_2k) == 0x9000
    stored, sw = _get_data(card, 0xC2)
    assert sw == 0x9000 and stored == rsa_2k, (
        "C2 must read back the RSA-2048 attribute: %s" % stored.hex()
    )

    # 3. P-512r1 fails closed in the spelling a client would send, and leaves
    #    the slot on its previous attribute rather than wedging it. The client
    #    cannot request it (no menu entry carries the 0x0D OID) and the card
    #    has no bp512 backend, so this is a boundary to hold, not a gap.
    for label, choice, _curve in CHOICES:
        for slot_name, tag in SLOTS:
            assert _attribute(choice, tag)[1:] != OID_BP512R1, (
                "client choice %d (%s) must not offer Brainpool P-512r1" % (choice, label)
            )
    before = {}
    for _slot_name, tag in SLOTS:
        before[tag], sw = _get_data(card, tag)
        assert sw == 0x9000, "GET DATA %02X baseline must answer 9000, got %04X" % (tag, sw)
    for slot_name, tag in SLOTS:
        attr = bytes([_attribute(9, tag)[0], *OID_BP512R1])
        sw = _put_data(card, tag, attr)
        assert sw == 0x6A80, (
            "Brainpool P-512r1 on %s (%s) must fail closed with 6A80, got %04X"
            % (slot_name, attr.hex(), sw)
        )
        stored, sw = _get_data(card, tag)
        assert sw == 0x9000 and stored == before[tag], (
            "a refused PUT must leave %s on its previous attribute: %s -> %s"
            % (slot_name, before[tag].hex(), stored.hex())
        )
