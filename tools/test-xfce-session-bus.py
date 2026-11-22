#!/usr/bin/env python3
"""Starting XFCE inside an existing X server must use one session bus."""
import os
from pathlib import Path
import subprocess
import tempfile

tools = Path(__file__).resolve().parent
original = '''#!/bin/sh
if command -v dbus-update-activation-environment >/dev/null 2>&1; then
  if command -v systemctl >/dev/null 2>&1 && systemctl --user list-jobs >/dev/null 2>&1; then
    systemd_arg='--systemd'
  fi
  dbus-update-activation-environment $systemd_arg \\
    DESKTOP_SESSION
fi
exec xfce4-session "$@"
'''

with tempfile.TemporaryDirectory(prefix="axon-xfce-bus-", dir="/tmp/opencode") as tmp:
    root = Path(tmp)
    script = root / "etc/xdg/xfce4/xinitrc"
    script.parent.mkdir(parents=True)
    script.write_text(original)
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/timeout").symlink_to("/usr/bin/timeout")
    patch = ["python3", str(tools / "patch-xfce-xinitrc.py"), str(root)]
    subprocess.run(patch, check=True)
    transformed = script.read_text()
    subprocess.run(patch, check=True)
    assert script.read_text() == transformed
    subprocess.run(["sh", "-n", str(script)], check=True)

    bindir = root / "bin"
    bindir.mkdir()

    def tool(name, text):
        path = bindir / name
        path.write_text("#!/bin/sh\n" + text)
        path.chmod(0o755)
        return path

    tool("systemctl", "exit 1\n")
    tool("dbus-update-activation-environment",
         'printf "%s\\n" "$DBUS_SESSION_BUS_ADDRESS" > "$TEST_DIR/update-bus"\n')
    tool("xfce4-session",
         'printf "%s\\n" "${DBUS_SESSION_BUS_ADDRESS-unset}" "$@" > "$TEST_DIR/session"\n')
    bus = tool("dbus-run-session",
               'printf "started\\n" >> "$TEST_DIR/bus-count"\n'
               '[ "$1" = -- ] || exit 90\nshift\n'
               'export DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/test-bus\n'
               'exec "$@"\n')
    env = dict(os.environ, PATH=str(bindir), TEST_DIR=tmp)
    env.pop("DBUS_SESSION_BUS_ADDRESS", None)

    subprocess.run(["/bin/sh", str(script), "one", "two words"], env=env,
                   check=True, timeout=5)
    assert (root / "bus-count").read_text().splitlines() == ["started"]
    assert (root / "session").read_text().splitlines() == [
        "unix:path=/tmp/test-bus", "one", "two words"]
    assert (root / "update-bus").read_text().strip() == "unix:path=/tmp/test-bus"

    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/tmp/existing"
    subprocess.run(["/bin/sh", str(script), "keep"], env=env, check=True, timeout=5)
    assert (root / "bus-count").read_text().splitlines() == ["started"]
    assert (root / "session").read_text().splitlines() == ["unix:path=/tmp/existing", "keep"]
    assert (root / "update-bus").read_text().strip() == "unix:path=/tmp/existing"

    bus.unlink()
    env.pop("DBUS_SESSION_BUS_ADDRESS")
    subprocess.run(["/bin/sh", str(script), "fallback"], env=env, check=True, timeout=5)
    assert (root / "session").read_text().splitlines() == ["unset", "fallback"]

print("PASS: XFCE activation and session share a bus without replacing an existing bus")
