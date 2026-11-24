#!/usr/bin/env python3
"""Exercise the transformed XFCE startup script with real timeout processes."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile

tools = Path(__file__).resolve().parent
original = '''#!/bin/sh
if command -v dbus-update-activation-environment >/dev/null 2>&1; then
  if command -v systemctl >/dev/null 2>&1 && systemctl --user list-jobs >/dev/null 2>&1; then # user session is running
    systemd_arg='--systemd'
  fi

  dbus-update-activation-environment $systemd_arg \\
    DESKTOP_SESSION \\
    XDG_RUNTIME_DIR
fi
exec xfce4-session
'''

with tempfile.TemporaryDirectory(dir="/tmp/opencode", prefix="xfce-timeout-test-") as tmp:
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
    assert "python3 \"$ROOT/tools/patch-xfce-xinitrc.py\" \"$ROOTFS\"" in (tools / "build-glibc-iso.sh").read_text()
    # Keep the production command structure and real timeout, but shorten delays.
    script.write_text(transformed.replace("-k 2s 5s", "-k 0.2s 0.2s"))
    subprocess.run(["sh", "-n", str(script)], check=True)
    bindir = root / "bin"
    bindir.mkdir()
    for name in ("systemctl", "dbus-update-activation-environment"):
        executable = bindir / name
        executable.write_text('''#!/bin/sh
name=${0##*/}
printf '%s\\n' "$*" > "$TEST_DIR/$name.args"
eval "mode=\\${${name%%-*}_mode}"
if [ "$mode" = hang ]; then
  echo $$ > "$TEST_DIR/$name.pid"
  trap '' TERM
  while :; do :; done
fi
[ "$mode" != fail ]
''')
        executable.chmod(0o755)
    session = bindir / "xfce4-session"
    session.write_text('#!/bin/sh\necho session-started\n')
    session.chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:/usr/bin:/bin", TEST_DIR=tmp)
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/tmp/existing-session"
    runtime = root / "runtime"
    (runtime / "systemd").mkdir(parents=True)
    manager = socket.socket(socket.AF_UNIX)
    manager.bind(str(runtime / "systemd/private"))
    env["XDG_RUNTIME_DIR"] = str(runtime)
    for probe, update in (("ok", "ok"), ("fail", "fail"), ("hang", "hang")):
        env.update(systemctl_mode=probe, dbus_mode=update)
        result = subprocess.run(["sh", str(script)], env=env, text=True,
                                capture_output=True, timeout=5, check=True)
        assert "session-started" in result.stdout
        assert (root / "systemctl.args").read_text().strip() == "--user list-jobs"
        args = (root / "dbus-update-activation-environment.args").read_text().split()
        assert args == (["--systemd"] if probe == "ok" else []) + ["BROWSER", "DESKTOP_SESSION", "XDG_RUNTIME_DIR"]
        assert ("systemctl user probe" in result.stderr) == (probe != "ok")
        assert ("D-Bus activation environment" in result.stderr) == (update != "ok")
        if probe == "hang":
            for name in ("systemctl", "dbus-update-activation-environment"):
                pid = int((root / f"{name}.pid").read_text())
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise AssertionError(f"{name} survived timeout: {pid}")
    manager.close()
    (runtime / "systemd/private").unlink()
    (root / "systemctl.args").unlink()
    env.update(systemctl_mode="hang", dbus_mode="ok")
    result = subprocess.run(["sh", str(script)], env=env, text=True,
                            capture_output=True, timeout=2, check=True)
    assert "session-started" in result.stdout
    assert not (root / "systemctl.args").exists()
    script.write_text("unexpected upstream script\n")
    assert subprocess.run(patch, capture_output=True).returncode != 0
    assert script.read_text() == "unexpected upstream script\n"
print("PASS: XFCE activation calls are bounded and session startup continues")
