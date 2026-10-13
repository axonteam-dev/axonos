#!/usr/bin/env python3
"""Merge an overlay with symlinks interpreted inside the guest root, not the host."""
import argparse
from pathlib import Path, PurePosixPath
import shutil


def guest_path(root, relative, follow_leaf):
    pending = list(PurePosixPath(relative).parts)
    resolved = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part in ("", ".", "/"):
            continue
        if part == "..":
            if resolved:
                resolved.pop()
            continue
        candidate = root.joinpath(*resolved, part)
        if candidate.is_symlink() and (pending or follow_leaf):
            links += 1
            if links > 40:
                raise ValueError(f"guest symlink loop: {relative}")
            target = candidate.readlink()
            if target.is_absolute():
                resolved = []
            pending = list(PurePosixPath(target).parts) + pending
        else:
            resolved.append(part)
    return root.joinpath(*resolved)


def merge(source, destination):
    source, destination = source.resolve(), destination.resolve()
    if not source.is_dir() or not destination.is_dir():
        raise ValueError("source and destination must be existing directories")
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError("source and destination trees must not overlap")
    for entry in sorted(source.rglob("*"), key=lambda p: (len(p.parts), str(p))):
        relative = entry.relative_to(source)
        is_directory = not entry.is_symlink() and entry.is_dir()
        target = guest_path(destination, str(relative), follow_leaf=is_directory)
        target.parent.mkdir(parents=True, exist_ok=True)
        if is_directory:
            target.mkdir(exist_ok=True)
            continue
        if not entry.is_symlink() and not entry.is_file():
            raise ValueError(f"unsupported overlay node: {entry}")
        if target.is_symlink():
            target.unlink()  # Replace the link itself, never its host-side target.
        elif target.exists() and not target.is_file():
            raise ValueError(f"refusing to replace a guest directory: {target}")
        elif target.is_file():
            # Extracted config/library files may be read-only. Replace the
            # staging inode rather than opening it for write (also avoids
            # changing another name if the base contains hardlinks).
            target.unlink()
        if entry.is_symlink():
            if target.exists():
                target.unlink()
            target.symlink_to(entry.readlink())
        else:
            shutil.copy2(entry, target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    merge(args.source, args.destination)
