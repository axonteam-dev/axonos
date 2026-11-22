#!/usr/bin/env python3
"""Known bundle launchers can be updated; unknown edits must be preserved."""
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='axon-launchers-', dir='/tmp/opencode') as tmp:
    stage = Path(tmp) / 'root'
    launchers = stage / 'opt/axonos-x11'
    launchers.mkdir(parents=True)
    bundle = Path(tmp) / 'bundle.tar.gz'
    names = ('run-xterm.sh', 'run-client.sh')
    with tarfile.open(bundle, 'w:gz') as tar:
        for name in names:
            data = ('old ' + name).encode()
            (launchers / name).write_bytes(data)
            info = tarfile.TarInfo('axonos-x11/' + name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    command = ['python3', str(root / 'tools/install-xterm-launchers.py'), str(stage), str(bundle)]
    subprocess.run(command, check=True)
    subprocess.run(command, check=True)  # idempotent for an already updated cache
    original_first = (launchers / names[0]).read_bytes()
    (launchers / names[1]).write_text('user changes')
    assert subprocess.run(command, capture_output=True).returncode != 0
    assert (launchers / names[0]).read_bytes() == original_first
    assert (launchers / names[1]).read_text() == 'user changes'
print('PASS: launcher updates preserve unknown modifications')
