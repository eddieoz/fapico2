"""
card_test_ki_pko_dsc.py - test personalizing card

Copyright (C) 2021  g10 Code GmbH
Author: NIIBE Yutaka <gniibe@fsij.org>

This file is a part of Gnuk, a GnuPG USB Token implementation.

Gnuk is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Gnuk is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

# US-966 (2026-09-27) — this module is now permanently skipped.
#
# Brainpool P-384r1 was served by this firmware between US-944 and US-966 and
# is **deferred to a follow-up release**: OpenPGP card spec v3.4 §4.4.3.10 only
# requires that "at least one of this curves shall be supported" (NIST
# P-256/384/521 already satisfies that, and P-384r1 is never singled out), RFC
# 8734 deprecated Brainpool for TLS 1.3 "because they had little usage … not
# endorsed by the IETF", and no OpenPGP-card user of P-384r1 was found while
# GnuPG and OpenSC disagree about carrying the curve at all.
#
# P-384r1 is NOT being deferred for being broken. The 14.47 s failure in the
# US-954 hardware run is a host-side PC/SC transaction ceiling: it recurs
# identically for RSA-4096 GENERATE while a *longer* 8.19 s NIST-P-384
# GENERATE succeeds. P-384r1 signing was never measured.
#
# The `check_brainpoolp384r1` fixture below reads the card's own FA DO, so once
# the post-US-966 image is flashed this module skips on its own — the same
# mechanism that has always skipped the P-512r1 modules. A skip here is the
# expected result, not a device or pcscd problem. The files are kept, as the
# P-512r1 ones are, so a later release that re-admits P-384r1 has its hardware
# coverage already in place. The host-side assertion that the curve is refused
# lives in `apps/openpgp/tests/advertise_serve.rs` (`DEFERRED`) and
# `apps/openpgp/tests/dispatch.rs` (`NEVER_SERVED`).
#
import pytest
from card_const import KEY_ATTRIBUTES_ECDH_BRAINPOOLP384R1
from brainpoolp384r1_keys import brainpoolp384r1_pk

@pytest.fixture(scope="module",autouse=True)
def check_brainpoolp384r1(card):
    if not KEY_ATTRIBUTES_ECDSA_BRAINPOOLP384R1 in card.supported_key_attrlist[0]:
        pytest.skip("Test for brainpoolP384r1", allow_module_level=True)

@pytest.fixture(scope="module")
def pk(card):
    print("Select brainpoolP384r1 for testing key import")
    return brainpoolp384r1_pk

from card_test_0_set_attr import *
from card_test_1_import_keys import *
from card_test_2_pkop import *
from card_test_3_ds_counter2 import *
