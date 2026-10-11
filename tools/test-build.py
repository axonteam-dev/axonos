#!/usr/bin/env python3
"""Check fresh, parallel and switched configuration without building the kernel."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="axon-build-") as tmp:
    build = Path(tmp) / "build"
    def configure(config="config.cfg"):
        subprocess.run(["make", "-C", str(root), "-j8", "config",
                        f"BUILD_DIR={build}", f"CONFIG_FILE={config}"], check=True)

    configure()
    header = build / "include/generated/autoconf.h"
    conf = build / "include/config/auto.conf"
    assert "#define FAT32_SUPPORT 1" in header.read_text()
    times = (header.stat().st_mtime_ns, conf.stat().st_mtime_ns)
    configure()
    assert times == (header.stat().st_mtime_ns, conf.stat().st_mtime_ns)
    configure("config.production.cfg")
    assert "#define AXON_PRODUCTION 1" in header.read_text()
    configure()
    assert "#define AXON_PRODUCTION 1" not in header.read_text()
    header.unlink()
    configure()
    assert header.is_file()
    bad = Path(tmp) / "bad.cfg"
    bad.write_text("this is invalid\n")
    result = subprocess.run(["bash", str(root / "scripts/genconfig.sh"),
                             str(bad), str(build / "include")])
    assert result.returncode != 0
    flags = build / "build.flags"
    def update_flags(options):
        subprocess.run(["make", "-C", str(root), str(flags),
                        f"BUILD_DIR={build}", f"OPTFLAGS={options}"], check=True)
    update_flags("-g")
    timestamp = flags.stat().st_mtime_ns
    update_flags("-g")
    assert flags.stat().st_mtime_ns == timestamp
    update_flags("-O0 -g0")
    assert "-O0 -g0" in flags.read_text()
print("PASS: fresh/parallel config, stable timestamps, config switch, missing header, invalid input")
