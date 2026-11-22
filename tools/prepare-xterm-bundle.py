#!/usr/bin/env python3
"""Create an updated X11 bundle without overwriting its prebuilt input."""

import argparse
import copy
import gzip
import io
from pathlib import Path
import tarfile


SCRIPTS = Path(__file__).resolve().parent / 'x11-bundle'
REPLACEMENTS = {
    'axonos-x11/run-xterm.sh': SCRIPTS / 'run-xterm.sh',
    'axonos-x11/run-client.sh': SCRIPTS / 'run-client.sh',
}
REQUIRED_EXECUTABLES = set(REPLACEMENTS) | {
    'axonos-x11/bin/xinit',
    'axonos-x11/bin/xterm',
    'axonos-x11/lib/ld-linux-x86-64.so.2',
}


def prepare(source, destination):
    replacements = {name: path.read_bytes() for name, path in REPLACEMENTS.items()}
    with tarfile.open(source, 'r:gz') as archive:
        members = archive.getmembers()
        for name in REQUIRED_EXECUTABLES:
            matches = [member for member in members if member.name == name]
            if len(matches) != 1 or not matches[0].isfile() or not matches[0].mode & 0o111:
                raise ValueError(f'expected one executable regular file: {name}')

        # An exclusive create protects the original bundle and any prior output.
        with destination.open('xb') as output:
            try:
                with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode='w') as updated:
                        for member in members:
                            if member.name in replacements:
                                data = replacements[member.name]
                                new_member = copy.copy(member)
                                new_member.size = len(data)
                                new_member.pax_headers = new_member.pax_headers.copy()
                                new_member.pax_headers.pop('size', None)
                                updated.addfile(new_member, io.BytesIO(data))
                            else:
                                contents = archive.extractfile(member) if member.isfile() else None
                                updated.addfile(member, contents)
            except BaseException:
                # Only remove the partial file created by this invocation.
                output.close()
                destination.unlink()
                raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='original axonos-xterm-xinit.tar.gz')
    parser.add_argument('destination', type=Path, help='new archive; must not already exist')
    args = parser.parse_args()
    try:
        prepare(args.source, args.destination)
    except (OSError, ValueError, tarfile.TarError) as exc:
        parser.exit(1, f'prepare-xterm-bundle: {exc}\n')


if __name__ == '__main__':
    main()
