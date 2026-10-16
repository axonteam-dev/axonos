#!/usr/bin/env python3
"""Drop stale APK records for OpenSSL packages whose library files are broken."""
from pathlib import Path
import sys


LIBS = {
    "libcrypto3": "/lib/libcrypto.so.3",
    "libssl3": "/lib/libssl.so.3",
}
ALIASES = (
    "/lib/libcrypto.so.3",
    "/lib/libssl.so.3",
    "/usr/lib/libcrypto.so.3",
    "/usr/lib/libssl.so.3",
)


def is_broken(path: Path) -> bool:
    if not path.is_symlink():
        return not path.exists()
    try:
        path.resolve(strict=True)
    except (OSError, RuntimeError):
        return True
    return False


def repair(root: Path) -> list[str]:
    db = root / "lib/apk/db/installed"
    if not db.is_file():
        return []

    stale = {
        package for package, relpath in LIBS.items()
        if is_broken(root / relpath.lstrip("/"))
    }
    if not stale:
        return []

    stanzas = db.read_text().strip().split("\n\n")
    kept = []
    removed = set()
    for stanza in stanzas:
        package = next((line[2:] for line in stanza.splitlines()
                        if line.startswith("P:")), None)
        if package in stale:
            removed.add(package)
        else:
            kept.append(stanza)
    if removed:
        db.write_text("\n\n".join(kept) + "\n")

    for relpath in ALIASES:
        path = root / relpath.lstrip("/")
        if path.is_symlink() and is_broken(path):
            path.unlink()
    return sorted(removed)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {sys.argv[0]} EXTRACTED_INITFS_ROOT")
    changed = repair(Path(sys.argv[1]))
    print("removed stale APK package records: " +
          (", ".join(changed) if changed else "none"))
