#!/usr/bin/env python3
"""Test ATA PIO post-data completion and error handling."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "drv/disk/ata.c").read_text()
start = source.index("static int ata_write_completed(")
end = source.index("\n}\n", start) + 3
assert "if (ata_write_completed(dev->io_base, dev->ctrl_base) != 0)" in source
program = r'''
#include <assert.h>
#include <stdint.h>
#define ATA_SR_BSY 0x80
#define ATA_SR_DRQ 0x08
#define ATA_SR_DF 0x20
#define ATA_SR_ERR 0x01
#define ATA_REG_STATUS(base) ((base) + 7)
static uint8_t status;
static int timeout, delays;
static void ata_io_delay(uint16_t ctrl) { (void)ctrl; delays++; }
static int ata_wait_ready(uint16_t io, uint16_t ctrl, int ms) {
    (void)io; (void)ctrl; (void)ms; return timeout ? -1 : 0;
}
static uint8_t inb(uint16_t port) { (void)port; return status; }
''' + source[start:end] + r'''
int main(void) {
    status = 0x40; assert(ata_write_completed(0x1f0, 0x3f6) == 0 && delays == 1);
    status = 0x41; assert(ata_write_completed(0x1f0, 0x3f6) == -1);
    status = 0x60; assert(ata_write_completed(0x1f0, 0x3f6) == -1);
    status = 0x48; assert(ata_write_completed(0x1f0, 0x3f6) == -1);
    status = 0xff; assert(ata_write_completed(0x1f0, 0x3f6) == -1);
    status = 0; assert(ata_write_completed(0x1f0, 0x3f6) == -1);
    timeout = 1; status = 0x40; assert(ata_write_completed(0x1f0, 0x3f6) == -1);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-ata-completion-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: ATA write completion rejects timeout and error statuses")
