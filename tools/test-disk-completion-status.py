#!/usr/bin/env python3
"""Reject error completion statuses from NVMe and VMware PVSCSI."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
nvme = (root / "drv/disk/nvme.c").read_text()
pvscsi = (root / "drv/disk/pvscsi.c").read_text()

def function(source, signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]

assert "!nvme_status_ok(done.status)" in nvme
assert "!pvscsi_scsi_status_ok(cmp->scsiStatus)" in pvscsi
program = "#include <stdint.h>\n#include <assert.h>\n" + "".join([
    function(nvme, "static inline uint16_t nvme_status_code("),
    function(nvme, "static inline uint16_t nvme_status_sct("),
    function(nvme, "static int nvme_status_ok("),
    function(pvscsi, "static int pvscsi_scsi_status_ok("),
]) + r'''
int main(void) {
    assert(nvme_status_ok(0) && nvme_status_ok(1)); /* phase bit */
    assert(!nvme_status_ok(2));                    /* status code */
    assert(!nvme_status_ok(1u << 9));              /* status type */
    assert(pvscsi_scsi_status_ok(0));
    assert(!pvscsi_scsi_status_ok(2));             /* CHECK CONDITION */
    assert(!pvscsi_scsi_status_ok(8));             /* BUSY */
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="axon-disk-status-") as tmp:
    c, exe = Path(tmp) / "test.c", Path(tmp) / "test"
    c.write_text(program)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=undefined", str(c), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
print("PASS: NVMe and PVSCSI error statuses are not successful completions")
