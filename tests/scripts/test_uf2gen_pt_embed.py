#!/usr/bin/env python3
"""US-413 S-413-2 host test: uf2gen.py must embed the PICOBIN partition
table into the produced Rust UF2 (marker 0xffffded3 + item 0x0a) so the
bootrom can still resolve the C data partition after the cutover.

Builds a minimal synthetic ELF, runs firmware/uf2gen.py on it, unwraps
the resulting UF2 into a flash image, and decodes the embedded PT block.
Stdlib only; run directly or via pytest/unittest.
"""
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
UF2GEN = REPO / "firmware" / "uf2gen.py"

FLASH_BASE = 0x10000000
PICOBIN_MARKER = 0xFFFFDED3
PICOBIN_ITEM_PARTITION_TABLE = 0x0A


def build_minimal_elf() -> bytes:
    """ELF32 LE with one PT_LOAD at 0x10000000 (2 pages) and a `Reset`
    symbol — the minimum uf2gen.py accepts."""
    text = bytes(range(256)) * 2  # 512 bytes at 0x10000000
    ehsize, phentsize, shentsize = 52, 32, 40
    phoff = ehsize
    text_off = phoff + phentsize
    symtab_off = text_off + len(text)
    strtab_off = symtab_off + 16  # one 16-byte Elf32_Sym
    sym: tuple = (1, 0x10000101, 0, 2, 0, 1)  # name, value, size, info, other, shndx
    strtab = b"\x00Reset\x00"
    shoff = strtab_off + len(strtab)
    shnum = 4  # NULL, .text PROGBITS, SYMTAB, STRTAB

    eh = struct.pack(
        "<4s5B7xHHIIIIIHHHHHH",
        b"\x7fELF", 1, 1, 1, 0, 0,  # ELF32, LE, v1, SysV
        2, 40,                      # e_type EXEC, e_machine ARM
        1,                          # e_version
        0x10000101,                 # e_entry (Reset, thumb)
        phoff,                      # e_phoff
        shoff,                      # e_shoff
        0,                          # e_flags
        ehsize, phentsize, 1, shentsize, shnum, 0,
    )
    ph = struct.pack("<8I", 1, text_off, 0x10000000, FLASH_BASE, len(text), 0, 0, 0)
    syment = struct.pack("<IIIBBH", *sym)
    # Elf32_Shdr: name, type, flags, addr, offset, size, link, info,
    # addralign, entsize.
    sh = b""
    sh += struct.pack("<10I", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)          # NULL
    sh += struct.pack("<10I", 0, 1, 6, FLASH_BASE, text_off, len(text), 0, 0, 4, 0)  # .text PROGBITS ALLOC EXECINSTR
    sh += struct.pack("<10I", 0, 2, 0, 0, symtab_off, 16, 3, 1, 4, 16)  # SYMTAB, link->strtab
    sh += struct.pack("<10I", 0, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0)  # STRTAB
    return eh + ph + text + syment + strtab + sh

def unwrap_uf2_to_flash(data: bytes) -> dict[int, bytes]:
    """Map UF2 blocks (family RP2350_ARM_S, non-absolute) to addr->256B."""
    pages = {}
    for off in range(0, len(data), 512):
        magic0, magic1, flags, addr, n, seq, total, fam = struct.unpack_from("<8I", data, off)
        if magic0 != 0x0A324655:
            continue
        if flags & 0x00008000:  # absolute preamble block
            continue
        assert fam == 0xE48BFF59, f"unexpected family {fam:#x}"
        pages[addr] = data[off + 32 : off + 32 + 256]
    return pages


class TestUf2genPtEmbed(unittest.TestCase):
    def test_uf2_contains_picobin_pt_block(self):
        with tempfile.TemporaryDirectory() as td:
            elf = Path(td) / "synthetic.elf"
            uf2 = Path(td) / "synthetic.uf2"
            elf.write_bytes(build_minimal_elf())
            r = subprocess.run(
                [sys.executable, str(UF2GEN), str(elf), str(uf2)],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr or r.stdout)
            pages = unwrap_uf2_to_flash(uf2.read_bytes())
        self.assertTrue(pages, "no payload blocks in UF2")

        # Scan the reconstructed flash image for the PT block.
        blob = b"".join(pages[a] for a in sorted(pages))
        marker = struct.pack("<I", PICOBIN_MARKER)
        idx = blob.find(marker)
        self.assertGreaterEqual(idx, 0, "PICOBIN marker not present in UF2")
        hdr = struct.unpack_from("<I", blob, idx + 4)[0]
        self.assertEqual(hdr & 0xFF, PICOBIN_ITEM_PARTITION_TABLE,
                         f"first item after marker is {hdr & 0xFF:#x}, not the partition table")
        count = (hdr >> 24) & 0x0F
        self.assertEqual(count, 3, "pt.json defines exactly 3 partitions")

        # Decode partition 1 ("PicoKeys Data") from the item words:
        # item header, unpartitioned flags, then per partition:
        # [location, flags] (+ optional id/families/name words).
        def part_loc(pi: int) -> int:
            j = idx + 8  # past marker + header, at unpartitioned word
            j += 4  # unpartitioned flags
            for p in range(count):
                loc = struct.unpack_from("<I", blob, j)[0]
                flags = struct.unpack_from("<I", blob, j + 4)[0]
                j += 8
                if flags & 0x1:
                    j += 8  # 64-bit id
                j += 4 * ((flags >> 7) & 0x3)  # extra families
                if flags & 0x1000:
                    name_len = blob[j] & 0xFF
                    j += 4 * (1 + name_len // 4)
                if p == pi:
                    return loc
            raise AssertionError(f"partition {pi} not found")

        # The block in the Rust UF2 must be the verbatim pt.json encoding:
        # data partition = sectors 258..1023 (0x102000..0x400000).
        loc = part_loc(1)
        first, last = loc & 0x1FFF, (loc >> 13) & 0x1FFF
        self.assertEqual((first * 4096, (last + 1) * 4096), (0x102000, 0x400000))

        # Reference bytes: the block extracted from the C image must appear
        # byte-identical in the Rust UF2.
        ref = (REPO / "firmware" / "picobin_pt.bin").read_bytes()
        self.assertIn(ref, blob, "firmware/picobin_pt.bin not embedded verbatim")


if __name__ == "__main__":
    unittest.main()
