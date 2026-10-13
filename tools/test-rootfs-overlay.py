#!/usr/bin/env python3
"""Check guest-root symlink resolution without writing through host aliases."""
from pathlib import Path
import runpy
import tempfile

code = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/merge-rootfs-overlay.py"))
with tempfile.TemporaryDirectory(prefix="axon-overlay-") as tmp:
    root = Path(tmp) / "guest"; root.mkdir()
    overlay = Path(tmp) / "overlay"; overlay.mkdir()
    (root / "usr/lib64").mkdir(parents=True)
    (root / "lib64").symlink_to("/usr/lib64")
    (overlay / "lib64").mkdir()
    (overlay / "lib64/loader").write_text("guest loader")
    (overlay / "etc/init.d").mkdir(parents=True)
    (overlay / "etc/init.d/networking").write_text("service")
    (overlay / "etc/init.d/networking").chmod(0o755)
    (overlay / "etc/runlevels/boot").mkdir(parents=True)
    (overlay / "etc/runlevels/boot/networking").symlink_to("../../init.d/networking")
    host = Path(tmp) / "host"; host.mkdir()
    (host / "config").write_text("host untouched")
    (root / "etc").mkdir()
    (root / "etc/config").symlink_to(host / "config")
    (overlay / "etc/config").write_text("guest replacement")
    (root / "etc/readonly").write_text("old config")
    (root / "etc/readonly").chmod(0o444)
    (overlay / "etc/readonly").write_text("new config")
    code["merge"](overlay, root)
    assert (root / "lib64").is_symlink()
    assert (root / "usr/lib64/loader").read_text() == "guest loader"
    assert (host / "config").read_text() == "host untouched"
    assert not (root / "etc/config").is_symlink()
    assert (root / "etc/config").read_text() == "guest replacement"
    assert (root / "etc/readonly").read_text() == "new config"
    assert (root / "etc/runlevels/boot/networking").readlink() == Path("../../init.d/networking")
    assert (root / "etc/init.d/networking").stat().st_mode & 0o111
    (root / "loop").symlink_to("/loop")
    try:
        code["guest_path"](root, "loop/file", True)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted a symlink loop")
print("PASS: rootfs overlay resolves absolute guest aliases and never writes through host links")
