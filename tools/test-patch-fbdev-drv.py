#!/usr/bin/env python3
"""The fbdev PCI callback must remain NULL after ELF relative relocation."""
import importlib.util
from pathlib import Path
import struct

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("patch_fbdev", root / "tools/patch-fbdev-drv.py")
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


def fixture(addend):
    data = bytearray(0x7000)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 2)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 6, 0, 0, 0, len(data), len(data), 0x1000)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 6, 0x400, 0x400, 0, 0x60, 0x60, 8)
    for i, pair in enumerate(((7, 0x500), (8, 48), (9, 24),
                              (0x6FFFFFF9, 2), (0, 0))):
        struct.pack_into("<QQ", data, 0x400 + i * 16, *pair)
    struct.pack_into("<QQq", data, 0x500, 0x6000, 8, 0x1234)
    struct.pack_into("<QQq", data, 0x518, 0x6408, 8, addend)
    struct.pack_into("<Q", data, 0x6408, 0x2A50)
    return data


for old_addend in (0, patch.PCI_PROBE_FUNC):
    data = fixture(old_addend)
    assert patch.patch_pci_probe_null(data)
    assert struct.unpack_from("<Q", data, 0x438)[0] == 1
    assert struct.unpack_from("<QQq", data, 0x518)[1] == 0
    assert struct.unpack_from("<Q", data, 0x6408)[0] == 0
    # Model glibc's RELACOUNT fast path followed by generic relocations.
    base = 0x7F0000000000
    for i in range(2):
        offset, kind, addend = struct.unpack_from("<QQq", data, 0x500 + i * 24)
        if i < struct.unpack_from("<Q", data, 0x438)[0] or kind == 8:
            struct.pack_into("<Q", data, offset, base + addend)
    assert struct.unpack_from("<Q", data, 0x6408)[0] == 0
    assert not patch.patch_pci_probe_null(data)

bad = fixture(0)
struct.pack_into("<Q", bad, 0x438, 1)
try:
    patch.patch_pci_probe_null(bad)
except ValueError:
    pass
else:
    raise AssertionError("unexpected RELACOUNT must be rejected")

print("PASS: fbdev PciProbe stays NULL after RELACOUNT relocations")
