#!/usr/bin/env python3
"""Host-only tests for the verified OpenSSH overlay installer's archive handling."""
import io
from pathlib import Path
import runpy
import tarfile
import tempfile

root = Path(__file__).resolve().parents[1]
code = runpy.run_path(str(root / "tools/install-openssh-rootfs.py"))
compare = code["version_compare"]
for low, high in [("1.0~rc1", "1.0"), ("1.0-1", "1.0-2"),
                  ("1:10.0p1-7+deb13u1", "1:10.0p1-7+deb13u2"),
                  ("9:1.0", "10:0.1"), ("2.41-12", "2.41-12+deb13u4")]:
    assert compare(low, high) < 0 and compare(high, low) > 0
assert compare("1.01", "1.1") == 0
assert compare("1.0", "1.0-0") == 0
fields = next(code["paragraphs"]("Codename: trixie\nSHA256:\n abc 42 main/Packages.xz\n\n"))
assert fields["Codename"] == "trixie" and "abc 42" in fields["SHA256"]


def archive(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as tar:
        for name, content, link in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            if link is not None:
                member.type = tarfile.SYMTYPE; member.linkname = link
                tar.addfile(member)
            else:
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
    return data.getvalue()


with tempfile.TemporaryDirectory(prefix="axon-openssh-rootfs-") as tmp:
    dest = Path(tmp) / "root"; dest.mkdir()
    (dest / "etc/ssh").mkdir(parents=True)
    config = dest / "etc/ssh/sshd_config"
    config.write_text("administrator policy\n")
    data = archive([
        ("./usr/sbin/sshd", b"server", None),
        ("./etc/ssh/sshd_config", b"package default", None),
        ("./etc/passwd", b"do not copy accounts", None),
        ("./usr/lib/example.so.1", b"library", None),
        ("./usr/lib/example.so", b"", "example.so.1"),
    ])
    code["unpack_selected"](data, dest)
    assert config.read_text() == "administrator policy\n"
    assert not (dest / "etc/passwd").exists()
    assert (dest / "usr/sbin/sshd").read_bytes() == b"server"
    assert (dest / "usr/lib/example.so").is_symlink()
    for name in ["../escape", "/usr/sbin/outside"]:
        try:
            code["unpack_selected"](archive([(name, b"bad", None)]), dest)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted unsafe archive path")
    outside = Path(tmp) / "outside"; outside.mkdir()
    try:
        code["unpack_selected"](archive([
            ("usr/lib/escape", b"", str(outside)),
            ("usr/lib/escape/bad", b"bad", None),
        ]), dest)
    except ValueError:
        pass
    else:
        raise AssertionError("wrote through a directory symlink")
    assert not (outside / "bad").exists()
print("PASS: OpenSSH overlay preserves policy/accounts; rejects archive escapes; compares Debian versions")
