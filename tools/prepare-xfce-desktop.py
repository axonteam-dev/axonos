#!/usr/bin/env python3
"""Seed the default root desktop without changing an existing XDG choice."""
import os
from pathlib import Path
import sys


def prepare(root):
    if not (root / 'etc/debian_version').is_file():
        raise SystemExit(f'not a Debian root: {root}')

    # Use directory descriptors and do not follow symlinks in the home or
    # config path. A cached staging root can contain deliberate user state.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            home_fd = os.open('root', flags, dir_fd=root_fd)
        except OSError as error:
            print(f'XFCE desktop: leaving unusual /root unchanged: {error}', file=sys.stderr)
            return

        try:
            try:
                config_fd = os.open('.config', flags, dir_fd=home_fd)
            except FileNotFoundError:
                config_fd = None
            except OSError as error:
                print(f'XFCE desktop: leaving unusual /root/.config unchanged: {error}', file=sys.stderr)
                return

            if config_fd is not None:
                try:
                    try:
                        os.stat('user-dirs.dirs', dir_fd=config_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        # Includes dangling symlinks and non-regular files. Do
                        # not guess what a user-configured desktop should be.
                        return
                finally:
                    os.close(config_fd)

            try:
                os.mkdir('Desktop', 0o755, dir_fd=home_fd)
            except FileExistsError:
                # Leave existing directories, files, and symlinks untouched.
                return
        finally:
            os.close(home_fd)
    finally:
        os.close(root_fd)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(f'usage: {sys.argv[0]} ROOTFS')
    prepare(Path(sys.argv[1]))
