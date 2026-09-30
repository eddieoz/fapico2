#!/usr/bin/env python3
"""Convert the fapico2 release ELF into an RP2350 UF2 image (US-389).

`elf2uf2-rs` (2.2.0, latest) hardcodes the RP2040 family ID (0xe48bff56),
which the Pico 2's BOOTSEL rejects, so this script emits the RP2350 Arm
Secure family ID (0xe48bff59, pico-sdk `RP2350_ARM_S_FAMILY_ID`). stdlib
only — no picotool dependency.

Usage: uf2gen.py <input.elf> <output.uf2>

UF2 format: pico-sdk `struct uf2_block`
(src/common/boot_uf2_headers/include/boot/uf2.h) — 512-byte blocks
carrying 476 payload bytes; every loadable flash segment is emitted
block-sequential at its load address (p_paddr), matching `picotool uf2
convert`.

Erratum RP2350-E10 (US-391): an RP2350 will not boot a UF2-flashed Arm
image unless the file starts with picotool's "absolute block" — an
ABSOLUTE-family (0xe48bff57) block of 0xEF bytes targeting the end of
flash (default 0x10ffff00) carrying the RP2_IGNORE_BLOCK extension flag.
`picotool uf2 convert` prepends
it to every RP2350 UF2; the reference implementation is `gen_abs_block()`
in raspberrypi/picotool elf2uf2/elf2uf2.cpp. Without it the bootrom
writes the image but never leaves BOOTSEL — verified on hardware (Pico 2,
US-391): our abs-block-less images stayed in BOOTSEL while the
picotool-generated C release image (which carries the block) booted.

Reset-vector entry (US-391 / S-391-13): the RP2350 ImageDef block
(embassy-rp's 20-byte `.start_block`) carries NO entry point, so the
bootrom jumps to `.vector_table[1]`. E2b (S-391-4) verified on hardware
that the bootrom honors VT[1] — patching that word changed the observed
entry point, refuting the "bootrom jumps to start of .text" claim. As
linked, VT[1] already holds cortex-m-rt's `Reset` (thumb bit set); this
script verifies the symbol exists and rewrites VT[1] to it — a
canonicalization that fails loudly if the entry symbol is ever missing.
(The earlier post-link patch to a custom replacement reset handler was
removed with the bisect scaffolding in S-391-13.)
"""

import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

UF2_MAGIC_START0 = 0x0A324655  # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_FLAG_FAMILY_PRESENT = 0x00002000
UF2_FLAG_EXTENSION_FLAGS_PRESENT = 0x00008000
RP2350_ARM_S_FAMILY_ID = 0xE48BFF59
ABSOLUTE_FAMILY_ID = 0xE48BFF57
UF2_EXTENSION_RP2_IGNORE_BLOCK = 0x9957E304
# picotool's default `--abs-block` location (end-of-flash marker; the
# IGNORE_BLOCK extension makes the write itself a no-op on any flash size).
ABS_BLOCK_LOC = 0x10FFFF00

# Flash window the BOOTSEL accepts for the RP2350-Arm family (4 MiB QSPI).
FLASH_BASE = 0x10000000
FLASH_END = 0x14000000


def elf_symbol_address(data, name):
    """Address of `name` in the ELF32 symtab, or None.

    Only what the reset-vector canonicalization needs: SHT_SYMTAB + its
    linked strtab, linear scan (the firmware symtab is small)."""
    e_shoff = struct.unpack_from("<I", data, 0x20)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
    e_shnum = struct.unpack_from("<H", data, 0x30)[0]
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        # Elf32_Shdr: sh_type@4, sh_offset@16, sh_size@20, sh_link@24,
        # sh_entsize@36.
        sh_type = struct.unpack_from("<I", data, off + 4)[0]
        sh_offset, sh_size, sh_link = struct.unpack_from("<III", data, off + 16)
        sh_entsize = struct.unpack_from("<I", data, off + 36)[0]
        shdrs.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    for i, (sh_type, sh_offset, sh_size, sh_link, sh_entsize) in enumerate(shdrs):
        if sh_type != 2:  # SHT_SYMTAB
            continue
        if sh_entsize != 16:  # Elf32_Sym
            continue
        str_off = shdrs[sh_link][1]
        wanted = name.encode() + b"\x00"
        for j in range(sh_size // sh_entsize):
            e = sh_offset + j * sh_entsize
            st_name, st_value = struct.unpack_from("<II", data, e)
            if data[str_off + st_name : str_off + st_name + len(wanted)] == wanted:
                return st_value
    return None


def elf_load_segments(data):
    """Yield (load_addr, bytes) for every PT_LOAD segment with file content
    inside the flash window."""
    if data[:4] != b"\x7fELF":
        raise SystemExit("not an ELF file")
    if data[4] != 1:
        raise SystemExit("not a 32-bit ELF (thumbv8m output is ELF32)")
    if data[5] != 1:
        raise SystemExit("not little-endian")
    e_phoff = struct.unpack_from("<I", data, 0x1C)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
    e_phnum = struct.unpack_from("<H", data, 0x2C)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        # ELF32 phdr: p_type, p_offset, p_vaddr, p_paddr (load address),
        # p_filesz.
        p_type, p_offset, _p_vaddr, p_paddr, p_filesz = struct.unpack_from(
            "<IIIII", data, off
        )[0:5]
        if p_type != 1 or p_filesz == 0:  # PT_LOAD with content only
            continue
        if not (FLASH_BASE <= p_paddr < FLASH_END):
            continue  # RAM-only segments are not flashed
        yield p_paddr, data[p_offset : p_offset + p_filesz]


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    elf_path, uf2_path = sys.argv[1], sys.argv[2]
    with open(elf_path, "rb") as f:
        data = f.read()

    chunks = [(addr, seg) for addr, seg in elf_load_segments(data)]
    if not chunks:
        raise SystemExit("no loadable flash segments found in the ELF")

    # One 256-byte payload page per touched flash page. Each segment is
    # blitted into its exact [addr, addr+len) range by page overlap — a
    # segment that starts mid-page (e.g. .rodata at 0x10007C1C right after
    # .text) must NOT zero the page head, and a 256-byte slice of a
    # mid-page segment spans two pages (found on hardware, US-391: the old
    # zero-prefix clobber silently zeroed the .text/.rodata tails of the
    # flashed image).
    pages = {}
    for addr, seg in chunks:
        start, end = addr, addr + len(seg)
        for page_addr in range(start & ~255, ((end - 1) & ~255) + 1, 256):
            ov_start = max(page_addr, start)
            ov_end = min(page_addr + 256, end)
            if ov_start >= ov_end:
                continue
            src = ov_start - start
            dst = ov_start - page_addr
            if page_addr not in pages:
                pages[page_addr] = bytearray(256)
            pages[page_addr][dst : dst + (ov_end - ov_start)] = seg[
                src : src + (ov_end - ov_start)
            ]

    # picotool workaround (see elf2uf2.cpp): the bootrom uses the block
    # number for its 4 KiB erase-sector accounting, so every touched erase
    # sector must be covered by consecutive 256-byte pages. picotool fills
    # the gap with all-zero "dummy" pages — every page below the image's
    # highest page address (the last sector may stay partial, exactly as in
    # the known-good C release image).
    SECTOR = 4096
    last_page = max(pages)
    for sector in sorted({a // SECTOR for a in pages}):
        for page in range(sector * SECTOR, (sector + 1) * SECTOR, 256):
            if page < last_page:
                pages.setdefault(page, b"\x00" * 256)

    # PICOBIN partition-table embed (US-413 S-413-2): the bootrom resolves
    # the C data partition by scanning flash for a partition-table block
    # (marker 0xffffded3, item 0x0a); the C firmware ships one inside its
    # image, which vanishes when the Rust image replaces it. Embed the
    # byte-exact pt.json encoding (extracted from the C reference image,
    # bootrom-proven on this board; data partition 0x102000..0x400000) on
    # the first page boundary after the image. Must precede the sector
    # gap-fill above? No: it is added after it, so re-run the fill for the
    # PT's own sector below.
    with open(os.path.join(_HERE, "picobin_pt.bin"), "rb") as f:
        pt_blob = f.read()
    pt_addr = last_page + 256
    for off in range(0, len(pt_blob), 256):
        pages[pt_addr + off] = pt_blob[off : off + 256].ljust(256, b"\x00")
    for sector in sorted({a // SECTOR for a in pages}):
        for page in range(sector * SECTOR, (sector + 1) * SECTOR, 256):
            if page < max(pages):
                pages.setdefault(page, b"\x00" * 256)
    print(
        f"picobin PT: {len(pt_blob)} bytes embedded at {pt_addr:#x} "
        "(C data partition 0x102000..0x400000, US-413 S-413-2)"
    )

    # Reset-vector canonicalization (see module docstring): the bootrom
    # jumps to .vector_table[1] (FLASH_BASE + 4). As linked that word
    # already holds `Reset` (thumb bit set); rewrite it to the symbol's
    # address so the shipped image provably enters via the standard
    # cortex-m-rt path, failing loudly if the symbol is missing.
    RESET_VECTOR = FLASH_BASE + 4
    reset_addr = elf_symbol_address(data, "Reset")
    if reset_addr is None:
        raise SystemExit(
            "symbol Reset not found in the ELF; refusing to emit a "
            "UF2 whose reset vector is missing"
        )
    page_addr, off = RESET_VECTOR & ~255, RESET_VECTOR & 255
    page = pages.get(page_addr)
    if not isinstance(page, bytearray):
        raise SystemExit("vector-table page missing from the flash image")
    old = struct.unpack_from("<I", page, off)[0]
    struct.pack_into("<I", page, off, reset_addr | 1)
    print(f"reset vector: {old:#x} -> {reset_addr | 1:#x} (Reset, canonical entry — bootrom honors VT[1] per S-391-4)")

    blocks = sorted(pages.items())

    out = bytearray()

    # Erratum RP2350-E10: picotool's leading "absolute block". Byte-identical
    # to `gen_abs_block(ABS_BLOCK_LOC)` in picotool elf2uf2.cpp —
    # ABSOLUTE family, 256 bytes of 0xEF at the end-of-flash marker address,
    # RP2_IGNORE_BLOCK extension flag (so the write is a no-op), its own
    # sequence (block_no 0, num_blocks 2). The payload blocks below follow
    # with their own sequence, exactly as in picotool's output.
    out += struct.pack(
        "<IIIIIIII",
        UF2_MAGIC_START0,
        UF2_MAGIC_START1,
        UF2_FLAG_FAMILY_PRESENT | UF2_FLAG_EXTENSION_FLAGS_PRESENT,
        ABS_BLOCK_LOC,
        256,
        0,
        2,
        ABSOLUTE_FAMILY_ID,
    )
    out += b"\xef" * 256
    out += struct.pack("<I", UF2_EXTENSION_RP2_IGNORE_BLOCK)
    out += b"\x00" * (476 - 256 - 4)
    out += struct.pack("<I", UF2_MAGIC_END)

    nblocks = len(blocks)
    for seq, (addr, chunk) in enumerate(blocks):
        # Standard UF2 block layout: 8 header words (32 bytes; family id in
        # the header when the flag is set, matching picotool output) + 476
        # bytes data + magic end (4 bytes) = 512.
        out += struct.pack(
            "<IIIIIIII",
            UF2_MAGIC_START0,
            UF2_MAGIC_START1,
            UF2_FLAG_FAMILY_PRESENT,
            addr,
            256,
            seq,
            nblocks,
            RP2350_ARM_S_FAMILY_ID,
        )
        out += chunk.ljust(476, b"\x00")
        out += struct.pack("<I", UF2_MAGIC_END)

    with open(uf2_path, "wb") as f:
        f.write(out)
    # 1 absolute preamble block + the payload stream (num_blocks counts the
    # payload stream only, matching picotool / the C reference image).
    print(f"{uf2_path}: {nblocks + 1} blocks (1 absolute preamble + {nblocks} ARM_S payload), {len(out)} bytes")


if __name__ == "__main__":
    main()
