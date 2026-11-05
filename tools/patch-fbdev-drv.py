#!/usr/bin/env python3
"""Patch Debian fbdev_drv.so for AxonOS (no KMS / incomplete PCI sysfs).

1. xf86ClaimFbSlot -> xf86ClaimNoSlot (PCI slot counters block fbdev otherwise).
2. DriverRec.PciProbe -> NULL (fbdev_open_pci glob on graphics/fb*/dev fails here).
"""
import struct
import sys

PCI_PROBE_RELA_OFF = 0x6408
PCI_PROBE_FUNC = 0x2A50
DT_NULL = 0
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_RELACOUNT = 0x6FFFFFF9


def patch_claim_slot(data: bytearray) -> bool:
    old, new = b"xf86ClaimFbSlot", b"xf86ClaimNoSlot"
    if old not in data:
        return False
    i = 0
    changed = False
    while True:
        j = data.find(old, i)
        if j < 0:
            break
        data[j : j + len(old)] = new
        changed = True
        i = j + len(new)
    return changed


def patch_pci_probe_null(data: bytearray) -> bool:
    # RELATIVE writes load_base + addend. An addend of zero is NOT NULL.
    # Turn the relocation into R_X86_64_NONE and clear its on-disk target.
    # glibc optimizes the first DT_RELACOUNT entries without checking their
    # types; this is the final entry in that prefix, so shorten it as well.
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a little-endian ELF64 shared object")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    loads = []
    dynamic = None
    for i in range(phnum):
        p = phoff + i * phentsize
        kind = struct.unpack_from("<I", data, p)[0]
        off, va, filesz = struct.unpack_from("<QQ8xQ", data, p + 8)
        if kind == 1:
            loads.append((va, off, filesz))
        elif kind == 2:
            dynamic = (off, filesz)
    def file_offset(va, size):
        for base, off, filesz in loads:
            if base <= va and va + size <= base + filesz:
                return off + va - base
        raise ValueError("ELF address is not backed by file data")
    if dynamic is None:
        raise ValueError("missing ELF dynamic section")
    tags = {}
    for pos in range(dynamic[0], dynamic[0] + dynamic[1], 16):
        tag, value = struct.unpack_from("<QQ", data, pos)
        if tag == DT_NULL:
            break
        tags[tag] = (pos, value)
    if any(tag not in tags for tag in (DT_RELA, DT_RELASZ, DT_RELAENT, DT_RELACOUNT)):
        raise ValueError("missing ELF relocation metadata")
    rela_va = tags[DT_RELA][1]
    rela_size = tags[DT_RELASZ][1]
    rela_ent = tags[DT_RELAENT][1]
    count = tags[DT_RELACOUNT][1]
    if rela_ent != 24 or rela_size % rela_ent or count > rela_size // rela_ent:
        raise ValueError("unexpected ELF relocation layout")
    rela = file_offset(rela_va, rela_size)
    target = file_offset(PCI_PROBE_RELA_OFF, 8)
    matches = []
    for i in range(rela_size // rela_ent):
        pos = rela + i * rela_ent
        offset, info, addend = struct.unpack_from("<QQq", data, pos)
        if offset == PCI_PROBE_RELA_OFF:
            matches.append((i, pos, info, addend))
    if len(matches) != 1:
        raise ValueError("expected exactly one PciProbe relocation")
    index, pos, info, addend = matches[0]
    if info == 0 and index >= count and struct.unpack_from("<Q", data, target)[0] == 0:
        return False
    if info != 8 or addend not in (0, PCI_PROBE_FUNC) or index + 1 != count:
        raise ValueError("unexpected PciProbe relocation or DT_RELACOUNT")
    struct.pack_into("<Q", data, target, 0)
    struct.pack_into("<Q", data, pos + 8, 0)  # R_X86_64_NONE
    struct.pack_into("<Q", data, tags[DT_RELACOUNT][0] + 8, count - 1)
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} fbdev_drv.so", file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "rb") as f:
        data = bytearray(f.read())

    c1 = patch_claim_slot(data)
    c2 = patch_pci_probe_null(data)
    if not c1 and not c2:
        print(f"patch-fbdev-drv: nothing to do ({path})")
        return 0

    with open(path, "wb") as f:
        f.write(data)
    parts = []
    if c1:
        parts.append("ClaimNoSlot")
    if c2:
        parts.append("PciProbe=NULL")
    print(f"patch-fbdev-drv: {path}: " + ", ".join(parts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
