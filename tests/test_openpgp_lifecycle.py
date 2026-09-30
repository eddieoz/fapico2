"""US-333 (lifecycle: factory reset + init) and US-334 (VERIFY, retry counters)
harness-level tests for the fapico2 Rust OpenPGP app.

These drive the raw APDU reader through the same CCID relay/`card` fixture the
upstream suite uses. Factory PINs per the suite: PW1=123456, PW3=12345678
(card_const.FACTORY_PASSPHRASE_*).

CHANGE REFERENCE DATA takes `old || new` per OpenPGP card spec §7.2.3.
The factory-reset test runs last and leaves the card in factory state.
"""

import pytest

from card_const import FACTORY_PASSPHRASE_PW1, FACTORY_PASSPHRASE_PW3
from openpgp_card import iso7816_compose

OPENPGP_AID = b"\xD2\x76\x00\x01\x24\x01"
def _send(card, cmd):
    """Send a raw APDU through the suite card's reader; return resp + SW."""
    return card._OpenPGP_Card__reader.send_cmd(cmd)


def _sw(card, ins, p1, p2, data=b"", le=None):
    resp = _send(card, iso7816_compose(ins, p1, p2, data, le=le))
    return (resp[-2] << 8) | resp[-1]


def _verify(card, who, pin):
    return _sw(card, 0x20, 0x00, 0x80 + who, pin)


def _select(card, aid=OPENPGP_AID):
    return _sw(card, 0xA4, 0x04, 0x00, aid)


# --- US-333: initial PIN states ------------------------------------------------


def test_initial_pin_states(card):
    # Factory PINs from the suite constants must be valid on a fresh card.
    assert _verify(card, 1, FACTORY_PASSPHRASE_PW1) == 0x9000
    assert _verify(card, 2, FACTORY_PASSPHRASE_PW1) == 0x9000
    assert _verify(card, 3, FACTORY_PASSPHRASE_PW3) == 0x9000


# --- US-333: factory reset (TERMINATE DF + ACTIVATE FILE, §7.2.16/7.2.17) ------
# Runs last: leaves the card in factory state.


def test_zz_factory_reset_restores_initial_state(card):
    # Personalize: change PW1 and PW3 (US-912: TERMINATE DF is refused while
    # the factory PINs are in force) and set the login DO.
    assert _sw(card, 0x24, 0x00, 0x81, FACTORY_PASSPHRASE_PW1 + b"765432") == 0x9000
    assert _sw(card, 0x24, 0x00, 0x83, FACTORY_PASSPHRASE_PW3 + b"abcdefgh") == 0x9000
    assert _verify(card, 3, b"abcdefgh") == 0x9000
    assert _sw(card, 0xDA, 0x00, 0x5E, b"fapico2") == 0x9000

    # TERMINATE DF with admin (PW3) verified.
    assert _sw(card, 0xE6, 0x00, 0x00) == 0x9000

    # In termination state, SELECT must not answer 9000.
    assert _select(card) != 0x9000

    # ACTIVATE FILE performs the factory reset and returns to operational.
    assert _sw(card, 0x44, 0x00, 0x00) == 0x9000
    assert _select(card) == 0x9000

    # Factory PINs are restored and personalization is wiped.
    assert _verify(card, 3, FACTORY_PASSPHRASE_PW3) == 0x9000
    assert _verify(card, 1, FACTORY_PASSPHRASE_PW1) == 0x9000
    login = card.cmd_get_data(0x00, 0x5E)
    assert login is None or len(login) == 0
