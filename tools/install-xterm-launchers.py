#!/usr/bin/env python3
"""Install known X11 launcher replacements without overwriting unknown edits."""
import sys
import tarfile
from pathlib import Path

root, bundle = map(Path, sys.argv[1:])
scripts = Path(__file__).resolve().parent / 'x11-bundle'
with tarfile.open(bundle, 'r:gz') as archive:
    for name in ('run-xterm.sh', 'run-client.sh'):
        member = archive.getmember('axonos-x11/' + name)
        stream = archive.extractfile(member)
        if stream is None:
            raise SystemExit(f'not a regular bundle launcher: {name}')
        original = stream.read()
        target = root / 'opt/axonos-x11' / name
        replacement = (scripts / name).read_bytes()
        if target.is_symlink() or not target.is_file():
            raise SystemExit(f'unsafe or missing launcher: {target}')
        if target.read_bytes() not in (original, replacement):
            raise SystemExit(f'refusing to overwrite modified launcher: {target}')
    # Validate both files before changing either.
    for name in ('run-xterm.sh', 'run-client.sh'):
        target = root / 'opt/axonos-x11' / name
        target.write_bytes((scripts / name).read_bytes())
        target.chmod(0o755)
