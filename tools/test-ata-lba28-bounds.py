#!/usr/bin/env python3
"""Exercise the ATA PIO address check without touching a disk."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "drv/disk/ata.c").read_text()
start = source.index("static int ata_lba28_valid(")
end = source.index("\n}\n", start) + 3
program = r'''
#include <assert.h>
#include <stdint.h>
''' + source[start:end] + r'''
int main(void) {
    assert(ata_lba28_valid(0, 1));
    assert(ata_lba28_valid(0, 1u << 28));
    assert(ata_lba28_valid((1u << 28) - 1, 1));
    assert(!ata_lba28_valid((1u << 28) - 1, 2));
    assert(!ata_lba28_valid(1u << 28, 1));
    assert(!ata_lba28_valid(0, 0));
    assert(!ata_lba28_valid(1, UINT32_MAX));
    return 0;
}
'''
assert source.count("if (!ata_lba28_valid(lba, sectors)) return -1;") == 2
with tempfile.TemporaryDirectory(prefix="axon-ata-lba-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: ATA PIO rejects overflowing 28-bit read and write requests")
