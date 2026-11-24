#!/usr/bin/env python3
"""Run the SCSI core's real read/write paths against a fake transport."""
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "drv/disk/scsi_core.c").read_text()

def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]

program = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#define SCSI_CDB_MAX_LEN 16
#define SCSI_SECTOR_SIZE 512
#define SCSI_READ_10 0x28
#define SCSI_WRITE_10 0x2a
#define SCSI_DATA_IN 1
#define SCSI_DATA_OUT 2
typedef struct { int (*execute_command)(void *, const uint8_t *, int, void *, size_t, int); } scsi_transport_ops_t;
typedef struct { void *transport_priv; const scsi_transport_ops_t *ops; uint32_t sector_count; } scsi_lun_t;
static scsi_lun_t test_lun;
static int calls, fail_on;
static int execute(void *priv, const uint8_t *cdb, int cdb_len, void *buffer, size_t len, int dir) {
    (void)priv; assert(cdb_len == 10 && buffer && len);
    assert((dir == SCSI_DATA_IN && cdb[0] == SCSI_READ_10) ||
           (dir == SCSI_DATA_OUT && cdb[0] == SCSI_WRITE_10));
    calls++; return calls == fail_on ? -1 : 0;
}
static const scsi_transport_ops_t ops = {execute};
static scsi_lun_t *scsi_lun_by_disk_id(int id) { return id == 0 ? &test_lun : NULL; }
''' + "".join(function(s) for s in ("static void cdb_read_10(", "static void cdb_write_10(",
                                      "static int scsi_disk_read(", "static int scsi_disk_write(")) + r'''
int main(void) {
    uint8_t buffer[129 * 512] = {0};
    test_lun.ops = &ops; test_lun.sector_count = UINT32_MAX;
    assert(scsi_disk_read(0, UINT32_MAX - 1, buffer, 2) == -1 && !calls);
    assert(scsi_disk_write(0, UINT32_MAX - 1, buffer, UINT32_MAX) == -1 && !calls);
    assert(scsi_disk_read(0, 0, NULL, 1) == -1 && !calls);
    assert(scsi_disk_write(0, 0, buffer, 129) == 0 && calls == 2);
    calls = 0; fail_on = 2;
    assert(scsi_disk_read(0, 0, buffer, 129) == -1 && calls == 2);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-scsi-io-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: SCSI rejects overflow and propagates transport failures")
