#!/usr/bin/env python3
"""Exercise the ISO builder's generated xinitrc with and without a runtime dir."""
import ast
import os
from pathlib import Path
import subprocess
import tempfile

builder = (Path(__file__).resolve().parents[1] / "tools/build-glibc-iso.sh").read_text()
start = builder.index('(root / "root/.xinitrc").write_text(')
end = builder.index('\n(root / "root/.xinitrc").chmod', start)
expression = builder[start:end].split('.write_text(', 1)[1][:-1]
xinitrc = ast.literal_eval('(' + expression + ')')

with tempfile.TemporaryDirectory(prefix="axon-xinitrc-test-", dir="/tmp/opencode") as tmp:
    root = Path(tmp)
    (root / "dbus-launch").write_text('#!/bin/sh\nprintf "%s\\n" "$XDG_RUNTIME_DIR"\n')
    (root / "dbus-launch").chmod(0o755)
    script = root / "xinitrc"
    script.write_text(xinitrc)
    env = dict(os.environ, PATH=f"{root}:/usr/bin:/bin")
    env.pop("XDG_RUNTIME_DIR", None)
    created = Path(subprocess.check_output(["sh", str(script)], env=env, text=True).strip())
    try:
        assert created.is_dir() and created.stat().st_mode & 0o777 == 0o700
        assert created != Path('/tmp')
        env["XDG_RUNTIME_DIR"] = str(root)
        assert subprocess.check_output(["sh", str(script)], env=env, text=True).strip() == str(root)
    finally:
        created.rmdir()
print("PASS: xinitrc uses a private fallback runtime dir and preserves an existing one")
