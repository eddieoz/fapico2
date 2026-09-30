"""US-334 harness-level tests: VERIFY PW1/PW3, retry counters (63CX),
retry-counter DO (0xC4), RESET RETRY COUNTER, CHANGE REFERENCE DATA.

Factory PINs per the suite: PW1=123456, PW3=12345678.
CHANGE REFERENCE DATA takes `old || new` per OpenPGP card spec §7.2.3.
"""

from card_const import FACTORY_PASSPHRASE_PW1, FACTORY_PASSPHRASE_PW3
from openpgp_card import iso7816_compose

from test_openpgp_lifecycle import _sw, _verify  # noqa: F401

# --- US-334: VERIFY, retry counters, reset retry counter ------------------------


def test_wrong_pin_reports_retry_counter(card):
    # 63CX with X = attempts remaining after the failed try.
    assert _verify(card, 3, b"00000000") == 0x63C2
    assert _verify(card, 3, b"00000000") == 0x63C1
    # Correct PIN still works and resets the counter.
    assert _verify(card, 3, FACTORY_PASSPHRASE_PW3) == 0x9000
    # Empty VERIFY (check) now reports success since already validated.
    assert _sw(card, 0x20, 0x00, 0x83) == 0x9000


def test_retry_counter_do_reflects_attempts(card):
    c4 = card.cmd_get_data(0x00, 0xC4)
    assert c4 is not None and len(c4) >= 7
    assert c4[6] == 0x03
    assert _verify(card, 3, b"00000000") == 0x63C2
    c4 = card.cmd_get_data(0x00, 0xC4)
    assert c4[6] == 0x02
    assert _verify(card, 3, FACTORY_PASSPHRASE_PW3) == 0x9000
    c4 = card.cmd_get_data(0x00, 0xC4)
    assert c4[6] == 0x03


def test_reset_retry_counter_with_admin(card):
    assert _verify(card, 3, FACTORY_PASSPHRASE_PW3) == 0x9000
    assert _verify(card, 1, b"000000") == 0x63C2
    # RESET RETRY COUNTER mode 0x02 (data = PW1), with PW3 verified.
    assert _sw(card, 0x2C, 0x02, 0x81, FACTORY_PASSPHRASE_PW1) == 0x9000
    assert _verify(card, 1, FACTORY_PASSPHRASE_PW1) == 0x9000


def test_change_reference_data_pw1_and_pw3(card):
    # CHANGE REFERENCE DATA: old || new (§7.2.3).
    assert _sw(card, 0x24, 0x00, 0x81, FACTORY_PASSPHRASE_PW1 + b"654321") == 0x9000
    assert _verify(card, 1, b"654321") == 0x9000
    # Restore factory PW1 via admin change.
    assert _sw(card, 0x24, 0x00, 0x81, b"654321" + FACTORY_PASSPHRASE_PW1) == 0x9000
    assert _verify(card, 1, FACTORY_PASSPHRASE_PW1) == 0x9000

    assert _sw(card, 0x24, 0x00, 0x83, FACTORY_PASSPHRASE_PW3 + b"abcdefgh") == 0x9000
    assert _verify(card, 3, b"abcdefgh") == 0x9000
    assert _sw(card, 0x24, 0x00, 0x83, b"abcdefgh" + FACTORY_PASSPHRASE_PW3) == 0x9000
    assert _verify(card, 3, FACTORY_PASSPHRASE_PW3) == 0x9000
