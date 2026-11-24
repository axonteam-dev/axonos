#!/usr/bin/env python3
"""Kconfig import, dependency validation and legacy header compatibility."""
from pathlib import Path
import os
import fcntl
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time

root = Path(__file__).resolve().parents[1]
env = os.environ.copy()
with tempfile.TemporaryDirectory(prefix="axon-kconfig-test-") as tmp:
    tmp = Path(tmp)
    build = tmp / "build"
    config = build / ".config"
    legacy = root / "config.cfg"
    subprocess.run(["make", f"BUILD_DIR={build}", "olddefconfig"],
                   cwd=root, env=env, check=True)
    conf = build / "host-kconfig" / "conf"
    mconf = build / "host-kconfig" / "mconf"
    cmd = [sys.executable, str(root / "scripts/kconfig.py"),
           "olddefconfig", str(config), str(legacy), str(conf), str(mconf)]
    subprocess.run(cmd, cwd=root, env=env, check=True)
    legacy_out, new_out = tmp / "legacy", tmp / "new"
    subprocess.run([sys.executable, str(root / "scripts/genconfig.py"),
                    str(legacy), str(legacy_out)], check=True)
    subprocess.run([sys.executable, str(root / "scripts/genconfig.py"), "--kconfig",
                    str(config), str(new_out)], check=True)
    def definitions(path):
        return {line for line in path.read_text().splitlines() if line.startswith("#define ")}
    assert definitions(legacy_out / "generated/autoconf.h") == definitions(
        new_out / "generated/autoconf.h")

    # Exercise the actual lxdialog frontend in a pseudo-terminal. No input is
    # sent until the menu has rendered, so the keys cannot be lost at startup.
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    term_env = dict(env, TERM="xterm")
    proc = subprocess.Popen(["make", f"BUILD_DIR={build}", "menuconfig"], cwd=root,
                            env=term_env, stdin=slave, stdout=slave, stderr=slave,
                            start_new_session=True)
    os.close(slave)
    output = b""
    sent = False
    deadline = time.monotonic() + 45
    try:
        while proc.poll() is None and time.monotonic() < deadline:
            if select.select([master], [], [], 1)[0]:
                try:
                    output += os.read(master, 65536)
                except OSError:
                    break
            if not sent and b"Axon kernel configuration" in output:
                os.write(master, b"\x1b\x1b")
                sent = True
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
            raise AssertionError("native menuconfig did not exit")
        assert proc.returncode == 0 and sent
        assert b"\x1b[44m" in output, "menu did not render blue in an xterm"
        assert (build / "host-kconfig/frontend/config/auto.conf").is_file()
        assert (build / "host-kconfig/frontend/generated/autoconf.h").is_file()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)

    # Existing unknown settings must not be silently erased.
    text = config.read_text() + "CONFIG_NOT_AN_AXON_OPTION=y\n"
    config.write_text(text)
    result = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode and "unknown symbol" in result.stderr
    assert config.read_text() == text

    # Do not import legacy module requests as built-in code.
    bad = tmp / "bad.cfg"
    bad.write_text("FAT32_SUPPORT=m\n")
    missing = tmp / "missing" / ".config"
    result = subprocess.run([sys.executable, str(root / "scripts/kconfig.py"),
                             "olddefconfig", str(missing), str(bad), str(conf), str(mconf)],
                            cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode and "modules are not implemented" in result.stderr
    assert not missing.exists()

    # Explicit invalid dependency must not be converted silently.
    bad.write_text("AXON_EXPERIMENTAL_HIGH_USER_FRAMES=y\n")
    result = subprocess.run([sys.executable, str(root / "scripts/kconfig.py"),
                             "olddefconfig", str(missing), str(bad), str(conf), str(mconf)],
                            cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode and "violates Kconfig dependencies" in result.stderr
    assert not missing.exists()

    # A handwritten .config cannot silently pretend a module was built.
    bad.write_text("CONFIG_FAT32_SUPPORT=m\n")
    result = subprocess.run([sys.executable, str(root / "scripts/genconfig.py"),
                             "--kconfig", str(bad), str(tmp / "bad-out")],
                            cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode and "loadable modules are not implemented" in result.stderr
print("PASS: Kconfig imports legacy options and protects existing configuration")
