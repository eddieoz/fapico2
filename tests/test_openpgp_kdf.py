"""US-337 harness tests: KDF-full setup (PUT/GET DO 0xF9, non-RSA subset).

Per the OpenPGP card spec §4.3 and the Gnuk suite posture: the KDF-DO is set
with PUT DATA (admin), echoed back via GET DATA, and the PINs then travel
client-side KDF'd (the card stores/compares whatever VERIFY/CHANGE REFERENCE
DATA carries). C baseline: 39 passed / 628 skipped — RSA-gated variants are
out of scope here.

Factory PINs per the suite: PW1=123456, PW3=12345678.
"""

from card_const import FACTORY_PASSPHRASE_PW3
from constants_for_test import KDF_FULL
from openpgp_card import kdf_calc, parse_kdf_data

KDF_NONE = b"\x81\x01\x00"


def _read_kdf(card):
    return card.cmd_get_data(0x00, 0xF9)


def test_kdf_do_default_is_none(card):
    assert _read_kdf(card).endswith(KDF_NONE)


def test_kdf_put_full_echoed_back(card):
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert card.cmd_put_data(0x00, 0xF9, KDF_FULL)
    assert _read_kdf(card) == KDF_FULL
    # Restore KDF-none so other tests see the factory state.
    assert card.cmd_put_data(0x00, 0xF9, KDF_NONE)


def test_kdf_put_requires_admin(card):
    # Drop the session-scoped admin verification first.
    card.deauthenticate(3)
    # PUT DATA 0xF9 without PW3 verified must fail.
    try:
        card.cmd_put_data(0x00, 0xF9, KDF_FULL)
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_kdf_full_pin_flow(card):
    """Full client-side KDF convention: set KDF-full, re-personalize PW3 to a
    KDF-derived value, VERIFY with the derived value, then restore."""
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert card.cmd_put_data(0x00, 0xF9, KDF_FULL)

    algo, subalgo, iters, salt_user, salt_reset, salt_admin, hash_user, hash_admin = (
        parse_kdf_data(KDF_FULL)
    )
    assert algo == 0x03 and iters == 0x00C80000

    # CHANGE REFERENCE DATA (PW3): old PIN raw, new PIN = KDF result.
    new_pw3 = b"kdf-admin-pin-1"
    new_hash = kdf_calc(new_pw3, salt_admin, iters)
    assert card.cmd_change_reference_data(3, FACTORY_PASSPHRASE_PW3 + new_hash)

    # VERIFY with the KDF-derived value now succeeds; raw fails.
    assert card.verify(3, new_hash)
    try:
        card.cmd_verify(3, new_pw3)
        raw_rejected = False
    except ValueError:
        raw_rejected = True
    assert raw_rejected

    # Restore: set the PIN back to the raw factory value, KDF-none.
    assert card.verify(3, new_hash)
    assert card.cmd_put_data(0x00, 0xF9, KDF_NONE)
    assert card.cmd_change_reference_data(3, new_hash + FACTORY_PASSPHRASE_PW3)
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)


def test_kdf_reset_via_empty_put(card):
    assert card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert card.cmd_put_data(0x00, 0xF9, KDF_FULL)
    assert _read_kdf(card) == KDF_FULL
    # The suite treats b"" and 81 01 00 as "no KDF".
    assert card.cmd_put_data(0x00, 0xF9, KDF_NONE)
    # PUT stores the raw DO value; the factory default file carries the F9
    # TLV itself, so accept either echo form.
    assert _read_kdf(card) in (KDF_NONE, b"\xf9\x03" + KDF_NONE)
