#!/usr/bin/env python3
"""Install verified Debian Trixie OpenSSH runtime files without maintainer scripts.

Never installs packages on the host, starts daemons, generates host keys, or
overwrites an existing destination file. Intended for an initfs overlay tree.
"""
import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

KEYS = {
    "archive-key-12.asc": "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8",
    "archive-key-12-security.asc": "05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0",
    "archive-key-13.asc": "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
    "archive-key-13-security.asc": "5E04A1E3223A19A20706E20F9904613D4CCE68C6",
    "release-13.asc": "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
}
REPOS = [("https://deb.debian.org/debian", "trixie"),
         ("https://security.debian.org/debian-security", "trixie-security")]
SKIP = {"debconf", "debconf-2.0", "adduser", "ucf", "init-system-helpers",
        "runit-helper", "systemd", "systemd-sysv", "libpam-systemd"}


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def paragraphs(text):
    for paragraph in text.split("\n\n"):
        fields = {}
        key = None
        for line in paragraph.splitlines():
            if line.startswith(" ") and key:
                fields[key] += "\n" + line[1:]
            elif ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.lstrip(" ")
        if fields:
            yield fields


def version_key_parts(version):
    epoch, sep, rest = version.partition(":")
    epoch, rest = (int(epoch), rest) if sep else (0, version)
    upstream, sep, revision = rest.rpartition("-")
    return epoch, upstream if sep else rest, revision if sep else "0"


def version_compare(left, right):
    def order(ch):
        if ch == "~": return -1
        if not ch or ch.isdigit(): return 0
        return ord(ch) if ch.isalpha() else ord(ch) + 256

    def compare_part(a, b):
        while a or b:
            while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
                x, y = order(a[:1]), order(b[:1])
                if x != y: return 1 if x > y else -1
                a, b = a[1:], b[1:]
            a, b = a.lstrip("0"), b.lstrip("0")
            ma, mb = re.match(r"\d*", a)[0], re.match(r"\d*", b)[0]
            if len(ma) != len(mb): return 1 if len(ma) > len(mb) else -1
            if ma != mb: return 1 if ma > mb else -1
            a, b = a[len(ma):], b[len(mb):]
        return 0

    ea, ua, ra = version_key_parts(left)
    eb, ub, rb = version_key_parts(right)
    if ea != eb: return 1 if ea > eb else -1
    return compare_part(ua, ub) or compare_part(ra, rb)


def payload(deb):
    if deb[:8] != b"!<arch>\n":
        raise ValueError("not a Debian ar archive")
    offset = 8
    while offset + 60 <= len(deb):
        header = deb[offset:offset + 60]
        if header[58:60] != b"`\n":
            raise ValueError("invalid ar header")
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58])
        data = deb[offset + 60:offset + 60 + size]
        if len(data) != size:
            raise ValueError("truncated ar member")
        if name.startswith("data.tar."):
            return data
        offset += 60 + size + (size % 2)
    raise ValueError("missing data archive")


def selected(path):
    return (path.startswith(("usr/lib/", "usr/lib64/", "lib/", "lib64/",
                             "etc/ssh/", "etc/pam.d/", "etc/security/",
                             "usr/share/openssh/", "usr/share/pam-configs/")) or
            path in {"usr/sbin/sshd", "usr/sbin/unix_chkpwd", "usr/sbin/unix_update",
                     "usr/bin/ssh-keygen", "usr/bin/ssh", "usr/bin/scp", "usr/bin/sftp"})


def make_parents(dest, target):
    current = dest
    for part in target.parent.relative_to(dest).parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"refusing to write through directory symlink: {current}")
        current.mkdir(exist_ok=True)


def unpack_selected(data, dest):
    # Debian uses xz/gzip data archives here; tarfile validates their streams.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            rel = PurePosixPath(name)
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError(f"unsafe package path: {name}")
            if not selected(name) or member.isdir():
                continue
            target = dest / name
            if target.exists() or target.is_symlink():
                continue
            make_parents(dest, target)
            if member.isfile():
                with archive.extractfile(member) as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out)
                target.chmod(member.mode & 0o777)
            elif member.issym():
                target.symlink_to(member.linkname)
            else:
                raise ValueError(f"unsupported package member: {name}")


def install(dest, cache, extra_packages=()):
    dest.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="openssh-verify-", dir=cache) as tmp:
        work = Path(tmp)
        home = work / "gnupg"
        home.mkdir(mode=0o700)
        keyring = work / "archive.gpg"
        for name, fingerprint in KEYS.items():
            key = work / name
            key.write_bytes(fetch("https://ftp-master.debian.org/keys/" + name))
            listing = subprocess.check_output(["gpg", "--homedir", str(home),
                "--batch", "--with-colons", "--show-keys", str(key)], text=True)
            fingerprints = [line.split(":")[9] for line in listing.splitlines()
                            if line.startswith("fpr:")]
            if not fingerprints or fingerprints[0] != fingerprint:
                raise ValueError("archive key fingerprint mismatch")
            with keyring.open("ab") as out:
                subprocess.run(["gpg", "--homedir", str(home), "--batch",
                                "--output", "-", "--dearmor", str(key)], stdout=out, check=True)
        packages = {}
        for base, suite in REPOS:
            signed = work / "InRelease"
            release = work / "Release"
            signed.write_bytes(fetch(f"{base}/dists/{suite}/InRelease"))
            subprocess.run(["gpgv", "--homedir", str(home), "--keyring", str(keyring),
                            str(signed)], check=True)
            # gpgv verifies cleartext signatures but does not emit the payload.
            clear = signed.read_text().split("\n\n", 1)[1].split(
                "\n-----BEGIN PGP SIGNATURE-----", 1)[0]
            release.write_text("\n".join(line.removeprefix("- ")
                                         for line in clear.splitlines()))
            fields = next(paragraphs(release.read_text()))
            if fields.get("Codename") != suite:
                raise ValueError("signed repository codename mismatch")
            if "Valid-Until" in fields and datetime.now(timezone.utc) > parsedate_to_datetime(fields["Valid-Until"]):
                raise ValueError("signed repository metadata has expired")
            if suite.endswith("-security") and "Valid-Until" not in fields:
                raise ValueError("security repository metadata lacks expiration")
            index_path = "main/binary-amd64/Packages.xz"
            checksums = {line.split()[2]: (line.split()[0], int(line.split()[1]))
                         for line in fields["SHA256"].splitlines() if line.strip()}
            expected, length = checksums[index_path]
            index = fetch(f"{base}/dists/{suite}/{index_path}")
            if len(index) != length or hashlib.sha256(index).hexdigest() != expected:
                raise ValueError("package index checksum mismatch")
            for item in paragraphs(lzma.decompress(index).decode()):
                item["base"] = base
                old = packages.get(item["Package"])
                if not old or version_compare(item["Version"], old["Version"]) > 0:
                    packages[item["Package"]] = item
        queue = ["openssh-server", "openssh-client", "openssh-sftp-server",
                 "libpam-modules", "libpam-runtime", *extra_packages]
        done = set()
        manifest = []
        stage = work / "stage"
        stage.mkdir()
        while queue:
            name = queue.pop(0)
            if name in done or name in SKIP:
                continue
            done.add(name)
            item = packages[name]
            manifest.append({key: item[key] for key in
                             ("Package", "Version", "SHA256", "Filename", "base")})
            for key in ("Pre-Depends", "Depends"):
                for group in item.get(key, "").split(","):
                    choices = [re.split(r"[\s(:]", alt.strip(), maxsplit=1)[0]
                               for alt in group.split("|") if alt.strip()]
                    dependency = next((p for p in choices if p in packages), None)
                    if dependency and dependency not in done:
                        queue.append(dependency)
            filename = PurePosixPath(item["Filename"])
            if filename.is_absolute() or ".." in filename.parts:
                raise ValueError("unsafe package URL")
            deb = cache / filename.name
            if not deb.exists() or hashlib.sha256(deb.read_bytes()).hexdigest() != item["SHA256"]:
                content = fetch(item["base"] + "/" + str(filename))
                if hashlib.sha256(content).hexdigest() != item["SHA256"]:
                    raise ValueError(f"package checksum mismatch: {name}")
                deb.write_bytes(content)
            print(f"openssh-rootfs: {name} {item['Version']}", flush=True)
            unpack_selected(payload(deb.read_bytes()), stage)
        for src in sorted(stage.rglob("*")):
            rel = src.relative_to(stage)
            dst = dest / rel
            if src.is_dir() or dst.exists() or dst.is_symlink():
                continue
            make_parents(dest, dst)
            if src.is_symlink():
                dst.symlink_to(src.readlink())
            else:
                shutil.copy2(src, dst)
        # Debian usr-merge paths must also resolve in the non-merged initfs.
        libs = dest / "usr/lib/x86_64-linux-gnu"
        if libs.exists():
            for src in libs.rglob("*"):
                if src.is_dir():
                    continue
                dst = dest / "lib/x86_64-linux-gnu" / src.relative_to(libs)
                if not dst.exists() and not dst.is_symlink():
                    make_parents(dest, dst)
                    dst.symlink_to(os.path.relpath(src, dst.parent))
        loader = dest / "lib64/ld-linux-x86-64.so.2"
        if not loader.exists() and not loader.is_symlink():
            loader.parent.mkdir(parents=True, exist_ok=True)
            loader.symlink_to("../usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
        config = dest / "etc/ssh/sshd_config"
        template = dest / "usr/share/openssh/sshd_config"
        if not config.exists():
            config.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(template, config)
        # pam-auth-update normally creates these during package configuration.
        # Use the standard Unix primary stack, without touching passwords or
        # replacing administrator-authored PAM rules in an existing tree.
        common = {
            "common-auth": "auth [success=1 default=ignore] pam_unix.so\nauth requisite pam_deny.so\nauth required pam_permit.so\n",
            "common-account": "account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\naccount requisite pam_deny.so\naccount required pam_permit.so\n",
            "common-password": "password [success=1 default=ignore] pam_unix.so obscure yescrypt\npassword requisite pam_deny.so\npassword required pam_permit.so\n",
            "common-session": "session required pam_unix.so\n",
            "common-session-noninteractive": "session required pam_unix.so\n",
        }
        for name, content in common.items():
            pam = dest / "etc/pam.d" / name
            if not pam.exists():
                pam.parent.mkdir(parents=True, exist_ok=True)
                pam.write_text("# Unix PAM stack for the AxonOS OpenSSH overlay.\n" + content)
        provenance = dest / "usr/share/axonos" / (
            "runtime-extra-packages.json" if extra_packages else "openssh-packages.json")
        if not provenance.exists():
            provenance.parent.mkdir(parents=True, exist_ok=True)
            provenance.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"openssh-rootfs: runtime installed in {dest}; no host keys generated")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--cache", type=Path, default=Path("/tmp/opencode/openssh-debs"))
    parser.add_argument("--extra-package", action="append", default=[],
                        help="also install a verified package's runtime files/dependencies")
    args = parser.parse_args()
    install(args.destination.resolve(), args.cache.resolve(), args.extra_package)
