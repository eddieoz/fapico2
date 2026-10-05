"""YubiOTP HID feature-report probe via hidraw ioctl.

The YK4 protocol is not a bulk/OUT write: ykman sends each request as a HID
*feature report* (HIDIOCSFEATURE) and reads the answer with HIDIOCGFEATURE.
hidraw exposes those as ioctls, which need no libusb interface claim.

  HIDIOCSFEATURE(dir=WRITE, 'H', 0x06, len)
  HIDIOCGFEATURE(dir=READ,  'H', 0x07, len)
"""
import fcntl, os, struct, sys, time

def ioc(direction, typ, nr, size):
    # _IOC(dir,type,nr,size); dir 1=write 2=read on Linux
    IOC_NRBITS, IOC_TYPEBITS, IOC_SIZEBITS, IOC_DIRBITS = 8, 8, 14, 2
    IOC_NRSHIFT = 0
    IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
    IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
    IOC_DIRSHIFT = IOC_SIZESHIFT + IOC_SIZEBITS
    return (direction << IOC_DIRSHIFT) | (ord(typ) << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)

SFEAT = ioc(1, 'H', 0x06, 0)
GFEAT = ioc(2, 'H', 0x07, 0)

def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc

def probe(path):
    print("\n=== %s ===" % path)
    fd = os.open(path, os.O_RDWR)
    try:
        for feat, name in ((0x13, "CAPABILITIES (device info)"),
                           (0x15, "SET_DEVICE_INFO"),
                           (0x01, "SERIAL"),
                           (0x11, "CHALLENGE_OTP"),
                           (0x1B, "SCAN_MAP"),
                           (0x0B, "SCAN_CONFIG"),
                           (0x03, "CONFIG_1"),
                           (0x04, "CONFIG_2"),
                           (0x0D, "?"),
                           (0x00, "?")):
            # GET_REPORT feature
            buf = bytearray(9)
            buf[0] = feat
            try:
                fcntl.ioctl(fd, GFEAT, bytes(buf), True)
                print("  GET  feat %02X %-24s -> %s" % (feat, name, bytes(buf).hex()))
            except OSError as e:
                print("  GET  feat %02X %-24s -> err %s" % (feat, name, str(e)[:40]))
    finally:
        os.close(fd)

for p in ("/dev/hidraw9", "/dev/hidraw8"):
    try:
        probe(p)
    except Exception as e:
        print("%s: %s" % (p, e))

print("\n=== CRC check on a captured 8-byte payload (YubiKey residue 0xF0B8) ===")
sample = bytes.fromhex("0011223344556677")
print("  crc16(%s) = %04X" % (sample.hex(), crc16(sample)))