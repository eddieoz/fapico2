"""Reassembly test with a CORRECTLY extracted CID: does the device accept
multi-frame messages (continuation packets) at all, and with which seq bit?
"""
import os, struct, time, select, sys
sys.path.insert(0, "/home/eddieoz/Projects/git/pico/fapico2/redteam")

DEV = "/dev/hidraw8"
fd = os.open(DEV, os.O_RDWR | os.O_NONBLOCK)

def drain(t=0.4):
    out = []
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                d = os.read(fd, 65)
                if len(d) == 65: d = d[1:]
                out.append(d)
            except (BlockingIOError, OSError):
                break
    return out

def w(f):
    os.write(fd, b"\x00" + f.ljust(64, b"\x00")[:64])

def init():
    w(struct.pack(">IBH", 0xFFFFFFFF, 0x86, 8) + b"\x00" * 8)
    r = drain(0.6)
    assert r, "no INIT reply"
    payload = r[0][7:]
    return struct.unpack(">I", payload[8:12])[0]

def big_ping(cid, data, seq_hi):
    """Send a multi-frame PING; seq_hi = 0x80 or 0xC0 continuation marker."""
    w(struct.pack(">IBH", cid, 0x81, len(data)) + data[:57])
    off, seq = 57, 0
    while off < len(data):
        w(struct.pack(">IB", cid, seq_hi | seq) + data[off:off + 59])
        off += 59
        seq += 1

drain(0.3)
print("=== multi-frame PING reassembly ===")
for n in (100, 300, 7609):
    # CTAPHID continuation packets: bit 7 CLEAR, sequence in bits 0-6.
    for label, hi in (("cont 0x00|seq", 0x00), ("cont 0x40|seq", 0x40)):
        cid = init()
        data = bytes(range(1, 60)) * ((n // 59) + 2)
        data = data[:n]
        big_ping(cid, data, hi)
        r = drain(1.0)
        if not r:
            print("  len %-5d %-9s -> no reply" % (n, label))
            continue
        # reassemble the reply the same tolerant way
        parts, ln = [], None
        i = 0
        parts.append(r[0][7:])
        ln = struct.unpack(">H", r[0][5:7])[0]
        seq = 0
        for x in r[1:]:
            parts.append(x[5:])
        body = b"".join(parts)
        # verify the echo matched what we sent
        echoed = body[:len(data)] == data
        err = body[0] if len(body) else -1
        print("  len %-5d %-9s -> frames=%d body=%dB echo_match=%s first=%02x"
              % (n, label, len(r), len(body), echoed, err))

os.close(fd)