"""CCID/PC-SC APDU driver for redteam use — every applet via SELECT AID."""
from smartcard.System import readers
from smartcard.util import toBytes

FIDO_AID = "A0000006472F0001"          # CTAP2 U2F/CTAP1 over CCID (historical)
MGMT_AID = "A000000527471117"          # management (pico dialect)
OATH_AID = "A0000005272101"            # YKOATH (7 bytes)
OATH_AID8 = "A000000527210101"         # Yubico Java 8-byte form
OTP_INS_APDU = None                    # OTP goes over HID, not CCID
PGP_AID = "D276000124010304000000000000000000"
RESCUE_AID = "A0583FC19B7E4F21"
PIV_AID = "A00000030800001000"


class Card:
    def __init__(self):
        rs = readers()
        self.reader = rs[0]
        self.conn = self.reader.createConnection()
        self.conn.connect()

    def select(self, aid_hex, lc=None):
        aid = toBytes(aid_hex)
        if lc is None:
            lc = len(aid)
        apdu = [0x00, 0xA4, 0x04, 0x00, lc] + aid + [0]
        resp, sw1, sw2 = self.conn.transmit(apdu)
        return bytes(resp), sw1 * 256 + sw2

    def apdu(self, cla, ins, p1=0, p2=0, data=b"", le=None):
        d = list(data) if data else []
        if le is None:
            apdu = [cla, ins, p1, p2, len(d)] + d
        elif le == 0:
            apdu = [cla, ins, p1, p2, len(d)] + d + [0]
        else:
            apdu = [cla, ins, p1, p2, len(d)] + d + [le]
        resp, sw1, sw2 = self.conn.transmit(apdu)
        return bytes(resp), sw1 * 256 + sw2

    def disconnect(self):
        try:
            self.conn.disconnect()
        except Exception:
            pass
