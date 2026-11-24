#!/usr/bin/env python3
"""Check that Xorg and XFCE diagnostics use separate startup stages."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='axon-xcheck-', dir='/tmp/opencode') as tmp:
    path = Path(tmp)
    for name in ('dbus-run-session',):
        tool = path / name
        tool.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGS_FILE"\n')
        tool.chmod(0o755)
    env = dict(os.environ, PATH=f'{tmp}:' + os.environ['PATH'], ARGS_FILE=str(path / 'args'), TMPDIR=tmp)
    env.pop('DISPLAY', None)
    assert 'exec /opt/axonos-x11/run-xterm.sh' in (root / 'tools/ax-xcheck.sh').read_text()
    script = root / 'tools/ax-xfce-check.sh'
    assert subprocess.run(['sh', str(script)], env=env, capture_output=True).returncode == 2
    env['DISPLAY'] = ':0'
    subprocess.run(['sh', str(script)], env=env, check=True)
    assert (path / 'args').read_text().splitlines() == ['--', 'startxfce4']
print('PASS: Xorg and XFCE diagnostic sessions start separately')
