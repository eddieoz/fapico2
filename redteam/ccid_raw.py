"""Direct CCID driver over libusb — no pcscd, no sharing violations.

Implements the PC_to_RDR_Apdu / RDR_to_PC_DataBlock messages the bulk CCID
interface expects. Interface 0 of 1050:0407 is CCID (bInterfaceClass 11).
"""
import usb.core
import usb.util
import struct

PC_TO_RDR_ICC_POWER_ON = 0x62
PC_TO_RDR_APDU = 0x6F
RDR_TO_PC_DATA_BLOCK = 0x80
RDR_RESP = {
    0x00: "ok", 0x01: "card reset", 0x02: "card removed", 0x03: "card inserted",
    0x80: "data block", 0xFF: "unknown", 0x11: "active protocol T0", 0x12: "active protocol T1",
}
ABORT = 0x6C
IFD_GUARD = 0x00


class CCID:
    def __init__(self, vid=0x1050, pid=0x0407, iface=0):
        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        if self.dev is None:
            raise RuntimeError("device not found")
        cfg = self.dev.get_active_configuration()
        self.iface_num = iface
        for alt in cfg:
            if alt.bInterfaceNumber == iface:
                self.intf = alt
        self.ep_out = usb.util.find_descriptor(self.intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        self.ep_in = usb.util.find_descriptor(self.intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
        self.bInterfaceClass = self.intf.bInterfaceClass
        self.seq = 0
        self.bulkin = 65535

    def _xfer(self, msg, timeout=5000):
        self.seq = (self.seq + 1) & 0xFF
        body = bytes([self.seq, 0, 0, 0]) + msg
        n = self.dev.write(self.ep_out.bEndpointAddress, body, timeout)
        return self._read_msg(timeout)

    def _read_msg(self, timeout=5000):
        data = self.dev.read(self.ep_in.bEndpointAddress, self.bulkin, timeout)
        if len(data) < 10:
            raise RuntimeError("short CCID message: %s" % data.hex())
        bMsgType = data[5]
        if bMsgType == RDR_TO_PC_DATA_BLOCK:
            wDataLength = struct.unpack("<H", data[7:9])[0]
            return bMsgType, data[9:9 + wDataLength]
        return bMsgType, data[10:]

    def power_on(self):
        st, payload = self._xfer(bytes([PC_TO_RDR_ICC_POWER_ON, 0, 0, 0, 0]))
        return st, payload

    def apdu(self, cla, ins, p1=0, p2=0, data=b"", le=None):
        """Returns (resp_bytes, sw) where sw is 2-byte status or None on error."""
        d = bytes(data)
        # bLength = apdu length including CLA..LE
        le_byte = b""
        if le is not None:
            le_byte = bytes([le if le else 0x00])
        apdu = bytes([cla, ins, p1, p2, len(d)]) + d + le_byte
        # CCID bLength is 1 byte in the message, but modern cards need
        # PC_to_RDR_Apdu with a 2-byte extended length; the short form caps
        # at 255 which covers everything we send.
        msg = struct.pack("<HI", PC_TO_RDR_APDU, 0)[:2]  # placeholder to keep struct import used
        msg = bytes([PC_TO_RDR_APDU, 0, 0, 0, 0, 0x00, 0x00, len(apdu)]) + apdu
        st, payload = self._xfer(msg)
        if st != RDR_TO_PC_DATA_BLOCK:
            return None, st
        # payload: SW1 SW2 then data (short form) — device sends SW last
        if len(payload) >= 2:
            sw = payload[-1] << 8 | payload[-2]
            return payload[:-2], sw
        return payload, None

    def close(self):
        usb.util.dispose_resources(self.dev)