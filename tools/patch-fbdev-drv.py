#!/usr/bin/env python3
"""Patch Debian fbdev_drv.so for AxonOS (no KMS / incomplete PCI sysfs).

1. xf86ClaimFbSlot -> xf86ClaimNoSlot (PCI slot counters block fbdev otherwise).
2. DriverRec.PciProbe -> NULL (fbdev_open_pci glob on graphics/fb*/dev fails here).
"""
import struct
import sys

PCI_PROBE_RELA_OFF = 0x6408
PCI_PROBE_FUNC = 0x2A50


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
    needle = struct.pack("<QQq", PCI_PROBE_RELA_OFF, 8, PCI_PROBE_FUNC)
    pos = data.find(needle)
    if pos < 0:
        return False
    struct.pack_into("<q", data, pos + 16, 0)
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
