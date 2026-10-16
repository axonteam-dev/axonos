#!/usr/bin/env python3
"""Test migration of APK records that claim broken OpenSSL libraries."""
import importlib.util
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "repair_apk_openssl", root / "tools/repair-apk-openssl-state.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(prefix="axon-apk-openssl-") as tmp:
    tree = Path(tmp)
    db = tree / "lib/apk/db/installed"
    db.parent.mkdir(parents=True)
    db.write_text(
        "C:one\nP:alpine-base\nV:1\n\n"
        "C:two\nP:libcrypto3\nV:3\n\n"
        "C:three\nP:libssl3\nV:3\n\n"
        "C:four\nP:openrc\nV:1\n"
    )
    (tree / "lib").mkdir(exist_ok=True)
    (tree / "usr/lib").mkdir(parents=True)
    (tree / "lib/libcrypto.so.3").symlink_to("../../lib/libcrypto.so.3")
    (tree / "lib/libssl.so.3").symlink_to("../../lib/libssl.so.3")
    (tree / "usr/lib/libcrypto.so.3").symlink_to("../../lib/libcrypto.so.3")
    (tree / "usr/lib/libssl.so.3").symlink_to("../../lib/libssl.so.3")

    assert module.repair(tree) == ["libcrypto3", "libssl3"]
    remaining = db.read_text()
    assert "P:alpine-base" in remaining and "P:openrc" in remaining
    assert "P:libcrypto3" not in remaining and "P:libssl3" not in remaining
    assert not (tree / "lib/libcrypto.so.3").is_symlink()
    assert not (tree / "lib/libssl.so.3").is_symlink()
    assert module.repair(tree) == []

print("PASS: stale APK OpenSSL records and dangling links are repaired")
