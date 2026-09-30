"""US-181 (`PICOForge-COMPAT`) — ISO 7816-4 command chaining for a >255-byte body.

The named RED test for EPIC Phase J, US-181:
`put_data_over_255_bytes_chains`.

**The bug this covers.** PicoForge fragments a body longer than
`CHAIN_CHUNK = 255` into `cla | 0x10` fragments, requires `9000` from every
one, and then sends the tail as an ordinary APDU
(`picoforge/src/hal/transport/ccid.rs:115-144`). It uses that for PIV `PUT
DATA` / `IMPORT` and for the OpenPGP import. Before this story the device
**accepted a fragment and then refused it**: `iso7816` 0.2.0 resolves chains
on the send side only, so `TryFrom<&[u8]> for CommandView` parsed
`cla|0x10 … Lc=0xFF … 255 bytes` as a plain case-3S body with `lc = 255` and
gave opcard a truncated TLV, which opcard's TLV reader turns into an error
(`vendor/opcard/src/tlv.rs:32-34`). Fail-closed, but a hard compatibility
break: a large certificate could not be imported at all.

**What is asserted, and what is deliberately not.** The write succeeding is
the point. The round-trip is the point. That a *malformed* chain is refused
is asserted too — but at the status-word level only, because the finer
fail-closed rules (per-fragment, per-header-field) are unit-tested without a
card in `platform/tests/apdu_chain.rs`, which is where a rule with four cases
belongs. Duplicating them here would be a second place for them to drift.

**Private relay.** See `tests/harness/chaining_ccid.py` for why this file does
not use the shared `run_openpgp_tests.sh` relay: it writes card state, and it
carries its own stale-port guard because it must be safe under a bare
`pytest tests/openpgp/` too.

pytest does not rebuild the emulator. Run

    cargo build -p fapico2-firmware --bin fapico2-emulation \\
        --no-default-features --features emulation \\
        --target x86_64-unknown-linux-gnu

first (this is what `run_openpgp_tests.sh` does).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_HARNESS = Path(__file__).resolve().parents[1] / "harness"
if str(_HARNESS) not in sys.path:
    sys.path.insert(0, str(_HARNESS))

from chaining_ccid import (  # noqa: E402
    CHAIN_CHUNK,
    FACTORY_PW3,
    INS_PUT_DATA,
    TAG_CARDHOLDER_CERT,
    ChainingEmu,
    do_tlv,
    select_openpgp,
    send_chained,
    verify_pw3,
)

#: 512 bytes of value: two full 255-byte fragments plus a 7-byte tail, i.e.
#: three APDUs on the wire where the pre-fix firmware expected one. A large
#: cardholder certificate is the realistic case (EPIC US-181) and this is the
#: size that makes it one.
CERT_LEN = 512


@pytest.fixture(scope="module")
def emu(tmp_path_factory):
    with ChainingEmu(tmp_path_factory.mktemp("us181")) as e:
        yield e


@pytest.fixture
def openpgp(emu):
    """A selected, PW3-verified OpenPGP card."""
    _, sw = emu.send(select_openpgp())
    assert sw == 0x9000, f"SELECT failed: {sw:04X}"
    _, sw = emu.send(verify_pw3())
    assert sw == 0x9000, (
        f"VERIFY PW3 failed: {sw:04X} — the cardholder certificate is an "
        f"Admin-permission DO (opcard command/data.rs:926-930), so the write "
        f"needs PW3 verified first. With a private keystore the factory PW3 "
        f"({FACTORY_PW3!r}) is in force."
    )
    return emu


def test_put_data_over_255_bytes_chains(openpgp):
    """The EPIC's named test: a 512-byte `PUT DATA` must survive the chain.

    Three separate claims, in the order the client would hit them:

    1. **Every fragment answers `9000`.** Not a formality — `send_chained`
       returns `Err` on the first fragment that is not
       (`picoforge/src/hal/transport/ccid.rs:129-131`), so a card answering
       anything else makes the client abandon the write.
    2. **The tail answers `9000`**, i.e. the reassembled body parsed as a
       valid DO.
    3. **The object round-trips** byte-for-byte through `GET DATA`. Without
       this a card could answer `9000` to everything and store nothing, which
       is precisely the silent-corruption failure the story says must not
       happen.
    """
    emu = openpgp
    value = bytes((i * 7 + 11) % 256 for i in range(CERT_LEN))
    body = do_tlv(TAG_CARDHOLDER_CERT, value)
    # P1/P2 carry the DO tag, *not* the data field — `Tag::from(command)` is
    # `Self::from((command.p1, command.p2))` (`vendor/opcard/src/types.rs:604`)
    # — and the `7F 21 …` TLV repeats it as the first bytes of the body. A
    # reader would reasonably send `00 DA 00 00` and get `6A88` (unknown DO),
    # which looks like a chaining bug and is not.
    p1, p2 = TAG_CARDHOLDER_CERT

    # The wire shape the client produces, asserted so a change in the
    # transcription is visible rather than silent: 255 + 255 + a 7-byte tail.
    apdus = send_chained(INS_PUT_DATA, p1, p2, body)
    assert len(apdus) == 3, [a[:5].hex() for a in apdus]
    assert apdus[0][0] & 0x10 and apdus[1][0] & 0x10, "fragments carry CLA b4"
    assert not apdus[2][0] & 0x10, "the tail is an ordinary APDU"
    assert [len(a) - 5 for a in apdus[:2]] == [CHAIN_CHUNK, CHAIN_CHUNK]

    sws = emu.send_chained(INS_PUT_DATA, p1, p2, body)
    assert sws == [0x9000, 0x9000, 0x9000], (
        f"every fragment must answer 9000, got {[f'{s:04X}' for s in sws]}"
    )

    # `GET DATA` returns the **whole DO**, tag and length included, not the
    # bare value — so the round-trip is against the encoded DO, and the
    # header is asserted rather than skipped. A card that stored the value
    # and lost the tag would otherwise pass.
    got = emu.get_data(TAG_CARDHOLDER_CERT)
    assert got == body, (
        f"the object did not round-trip: {len(got)} bytes back, "
        f"{len(body)} sent"
    )
    assert got[:5] == bytes([0x7F, 0x21, 0x82, 0x02, 0x00]), (
        f"DO header not preserved: {got[:5].hex()}"
    )


def test_a_body_of_exactly_255_bytes_never_chains(openpgp):
    """The boundary below the chain, from the client's own loop.

    `send_chained` is `while data.len() - i > CHAIN_CHUNK` with a
    `len <= CHAIN_CHUNK` short circuit (`ccid.rs:116-121`), so a 255-byte
    *body* is one ordinary APDU. Pinned because an off-by-one the other way
    would put an empty fragment on the wire, and an applet that answered
    anything but `9000` to it would break a write that never needed chaining.
    """
    emu = openpgp
    p1, p2 = TAG_CARDHOLDER_CERT
    value = bytes(range(CHAIN_CHUNK))
    body = do_tlv(TAG_CARDHOLDER_CERT, value)
    assert len(body) > CHAIN_CHUNK, "this test is about the short path, not this one"
    # Trim the value so the whole body is exactly one chunk.
    value = value[: CHAIN_CHUNK - (len(body) - CHAIN_CHUNK)]
    body = do_tlv(TAG_CARDHOLDER_CERT, value)
    apdus = send_chained(INS_PUT_DATA, p1, p2, body)
    assert len(apdus) == 1, "255 bytes or fewer is a single unchained APDU"
    assert not apdus[0][0] & 0x10

    _, sw = emu.send(apdus[0])
    assert sw == 0x9000, f"unchained PUT DATA answered {sw:04X}"
    assert emu.get_data(TAG_CARDHOLDER_CERT) == body


def test_a_broken_chain_is_refused_and_stores_nothing(emu):
    """Fail-closed, end to end: a truncated chain writes nothing.

    The first fragment of a 512-byte body, then **no** terminator, then a
    completely different command. Two things must hold:

    * the fragment still answers `9000` — it is a legal fragment, and the
      client is entitled to that; and
    * the `GET DATA` that follows gets its own empty body back, **not** the
      abandoned fragment. This is the corruption case the story is really
      about, and it is why the accumulator drops a chain whose terminator
      does not match rather than flushing it.
    """
    _, sw = emu.send(select_openpgp())
    assert sw == 0x9000, f"SELECT failed: {sw:04X}"

    value = bytes(CERT_LEN)
    body = do_tlv(TAG_CARDHOLDER_CERT, value)
    # A re-SELECT between the fragment and the unrelated command: that is the
    # documented client recovery ("my chain went wrong, start over"), and
    # the chain must be gone afterwards.
    _, sw = emu.send(send_chained(INS_PUT_DATA, *TAG_CARDHOLDER_CERT, body)[0])
    assert sw == 0x9000, f"a well-formed fragment must answer 9000, got {sw:04X}"

    _, sw = emu.send(select_openpgp())
    assert sw == 0x9000

    # A `GET DATA` on the DO we were writing. It must not see the fragment's
    # bytes; the previous test stored a 255-byte object there, so compare
    # against that rather than asserting emptiness.
    before = emu.get_data(TAG_CARDHOLDER_CERT)
    _, sw = emu.send(send_chained(INS_PUT_DATA, *TAG_CARDHOLDER_CERT, body)[0])
    assert sw == 0x9000
    _, sw = emu.send(bytes([0x00, 0xCA, TAG_CARDHOLDER_CERT[0], TAG_CARDHOLDER_CERT[1], 0x00]))
    assert sw & 0xFF00 == 0x6100 or sw == 0x9000, f"GET DATA answered {sw:04X}"
    after = emu.get_data(TAG_CARDHOLDER_CERT)
    assert after == before, (
        "an abandoned chain's bytes reached a later GET DATA — the accumulator "
        "flushed instead of discarding"
    )
    assert value[:CHAIN_CHUNK] not in after, (
        "the abandoned fragment's payload was stored or served"
    )


def test_an_over_long_chain_is_refused_rather_than_truncated(emu):
    """The bound, on the wire.

    A chain whose body would exceed the accumulator's maximum is refused with
    `6700`, and the tail that follows is then a command in its own right (so
    the card is still usable). This is the memory-exhaustion-surface rule: a
    card that reassembled without a bound would let anyone with a reader
    choose how much memory the card commits per exchange.

    The bound itself — 4101 bytes — is derived in
    `platform::apdu_chain::MAX_CHAINED_BODY` and unit-tested there. Here the
    only claim is the *behaviour*: over the bound is `6700`, not a silently
    truncated write.
    """
    _, sw = emu.send(select_openpgp())
    assert sw == 0x9000
    _, sw = emu.send(verify_pw3())
    assert sw == 0x9000

    from chaining_ccid import CLA_ISO, write_apdu  # noqa: E402  (local import: client-side constants)

    # 17 full fragments = 4335 bytes of DO value, past the 4101-byte bound.
    # `send_chained` is not used here: it would stop at the client's own
    # limit rather than the device's, and the point is the device's limit.
    for i in range(16):
        _, sw = emu.send(
            write_apdu(INS_PUT_DATA, *TAG_CARDHOLDER_CERT, bytes([(i + j) % 256 for j in range(CHAIN_CHUNK)]), chained=True)
        )
        assert sw == 0x9000, f"fragment {i} answered {sw:04X}"
    # The 17th crosses the bound and must be refused.
    _, sw = emu.send(write_apdu(INS_PUT_DATA, *TAG_CARDHOLDER_CERT, bytes(CHAIN_CHUNK), chained=True))
    assert sw == 0x6700, (
        f"a chain past the bound must be refused with 6700, got {sw:04X}. "
        f"Not 6Cxx: 6Cxx makes transceive_paged re-send the same fragment "
        f"(ccid.rs:90-96) and the card cannot tell a resend from a new one, so "
        f"the bytes would land in the accumulator twice."
    )
    # The card is still alive and the chain is gone.
    _, sw = emu.send(bytes([CLA_ISO, 0xCA, 0x5F, 0x52, 0x00]))
    assert sw in (0x9000, 0x6A82, 0x6D00), f"card unusable after refusal: {sw:04X}"
    assert len(emu.get_data(TAG_CARDHOLDER_CERT)) < 4110, (
        "a refused chain left its payload on the card"
    )
