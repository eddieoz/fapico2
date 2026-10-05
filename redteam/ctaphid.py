"""Raw CTAPHID driver for redteam use — talks directly to hidraw8.

Bypasses python-fido2 so we can send malformed/unexpected frames.
"""
import os, struct, time

DEV = os.environ.get("FA_HIDRAW", "/dev/hidraw8")
REPORT = 64

TYPE_INIT = 0x80
PING = TYPE_INIT | 0x01
MSG = TYPE_INIT | 0x03
INIT = TYPE_INIT | 0x06
WINK = TYPE_INIT | 0x08
CBOR = TYPE_INIT | 0x10
CANCEL = TYPE_INIT | 0x11
ERROR = TYPE_INIT | 0x3F
VENDOR = TYPE_INIT | 0x40


class CTAPHID:
    def __init__(self, path=DEV):
        self.fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        # drain any stale reports so we don't read a previous session's response
        import select
        end = time.time() + 0.5
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if not r:
                break
            try:
                os.read(self.fd, 64)
            except (BlockingIOError, OSError):
                break

    def _read_frame(self, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            try:
                data = os.read(self.fd, 65)
                return data[1:] if len(data) == 65 else data
            except BlockingIOError:
                time.sleep(0.005)
        raise TimeoutError("no response within %.1fs" % timeout)

    def _write(self, frame):
        # this hidraw interface wants a report-id 0 prefix (65-byte reports)
        os.write(self.fd, b"\x00" + frame + b"\x00" * (REPORT - len(frame)))

    def init(self, nonce=b"\x42" * 8, chan=0xFFFFFFFF):
        self._write(struct.pack(">IBH", chan, INIT, len(nonce)) + nonce)
        resp = self._read_frame()
        chan, cmd, ln = struct.unpack(">I", resp[:4])[0], resp[4], struct.unpack(">H", resp[5:7])[0]
        payload = resp[7:7 + ln]
        # fapico2 layout: nonce(8) + new_cid(4) + ifaceVer(1) + fw(3) + caps(1)
        self.cid = struct.unpack(">I", payload[8:12])[0]
        self.proto = payload[12]
        self.fw = tuple(payload[13:16])
        self.caps = payload[16]
        return chan, cmd, payload

    def _send_seq(self, chan, cmd, payload):
        # init frame
        ln = len(payload)
        if ln <= 64 - 7:
            self._write(struct.pack(">IBH", chan, cmd, ln) + payload)
        else:
            first = payload[:64 - 7]
            self._write(struct.pack(">IBH", chan, cmd, ln) + first)
            off = 64 - 7
            seq = 0
            while off < ln:
                chunk = payload[off:off + 64 - 5]
                self._write(struct.pack(">IB", chan, 0x80 | seq) + chunk)
                off += len(chunk)
                seq += 1

    def _recv(self, chan, timeout=10.0):
        f = self._read_frame(timeout)
        c = struct.unpack(">I", f[:4])[0]
        if c != chan:
            raise RuntimeError("unexpected channel %08x (want %08x) cmd=%02x" % (c, chan, f[4]))
        ln = struct.unpack(">H", f[5:7])[0]
        data = f[7:]
        seq = 0
        while len(data) < ln:
            cont = self._read_frame(timeout)
            contc = struct.unpack(">I", cont[:4])[0]
            if contc != chan:
                raise RuntimeError("cont channel mismatch %08x" % contc)
            if cont[4] not in (0x80 | seq, seq):
                # fapico2 deviates from CTAPHID here: cont frames carry the
                # bare sequence byte (0x00,0x01,..) instead of 0x80|seq.
                raise RuntimeError("cont seq mismatch got %02x want %02x" % (cont[4], 0x80 | seq))
            data += cont[5:]
            seq += 1
        return data[:ln]

    def ping(self, chan, payload=b"A" * 32):
        self._send_seq(chan, PING, payload)
        return self._recv(chan)

    def wink(self, chan):
        self._write(struct.pack(">IBH", chan, WINK, 0))
        return self._recv(chan, timeout=2.0)

    def cbor(self, chan, payload, timeout=30.0):
        """payload = opcode + cbor body. returns status byte + data."""
        self._send_seq(chan, CBOR, payload)
        return self._recv(chan, timeout)

    def msg(self, chan, apdu, timeout=10.0):
        self._send_seq(chan, MSG, apdu)
        return self._recv(chan, timeout)

    def cancel(self, chan):
        self._write(struct.pack(">IBH", chan, CANCEL, 0))

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass
