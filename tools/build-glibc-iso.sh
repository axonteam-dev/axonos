#!/usr/bin/env bash
# Build the default Debian/glibc initfs and ISO without modifying the source initfs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT/build/axonos.iso}"
KERNEL="${2:-$ROOT/build/axonos.elf}"
SOURCE_SFS="$ROOT/iso/boot/initfs.sfs"

for cmd in python3 unshare chroot unsquashfs mksquashfs grub-mkrescue strings; do
    command -v "$cmd" >/dev/null || {
        echo "build-glibc-iso: missing required command: $cmd" >&2
        exit 1
    }
done
[[ -f "$SOURCE_SFS" ]] || { echo "build-glibc-iso: missing $SOURCE_SFS" >&2; exit 1; }
[[ -f "$KERNEL" ]] || { echo "build-glibc-iso: missing kernel ELF $KERNEL (run make kernel first)" >&2; exit 1; }

WORK="$(mktemp -d /tmp/opencode/axon-glibc.XXXXXX)"
RESTORE_RESOLV=0
cleanup() {
    if [[ "$RESTORE_RESOLV" == 1 ]]; then
        rm -f "$ROOTFS/etc/resolv.conf"
        ln -s ../run/systemd/resolve/resolv.conf "$ROOTFS/etc/resolv.conf"
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
ROOTFS="$WORK/rootfs"
ROOTFS_EPHEMERAL=0
CACHE_ROOTFS=/tmp/opencode/debian-trixie-cache
# Reuse the persistent Trixie rootfs cache used by the local ISO workflow.
# Without this, every plain `make iso` downloads Debian layers and reinstalls
# hundreds of packages after the kernel's LZ4 line, which looks like a hang.
if [[ -z "${GLIBC_ROOTFS:-}" && -f "$CACHE_ROOTFS/etc/debian_version" ]]; then
    GLIBC_ROOTFS="$CACHE_ROOTFS"
    echo "build-glibc-iso: reusing cached Debian rootfs"
fi
if [[ -n "${GLIBC_ROOTFS:-}" ]]; then
    ROOTFS="$(realpath "$GLIBC_ROOTFS")"
    [[ -f "$ROOTFS/etc/debian_version" ]] || {
        echo "build-glibc-iso: GLIBC_ROOTFS is not a Debian root: $ROOTFS" >&2
        exit 1
    }
else
ROOTFS_EPHEMERAL=1
mkdir -p "$ROOTFS"

# Fetch the official Debian Trixie slim OCI image directly; Docker/Podman is not
# required. Layer digests are verified before extraction.
echo "build-glibc-iso: no Debian cache; fetching base image and installing packages (first build may take several minutes)"
python3 - "$ROOTFS" <<'PY'
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import tarfile
import urllib.parse
import urllib.request
import sys

root = Path(sys.argv[1])
def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {},
                                 method="GET")
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read()

scope = urllib.parse.quote("repository:library/debian:pull", safe="")
token_data = json.loads(get(
    f"https://auth.docker.io/token?service=registry.docker.io&scope={scope}"))
token = token_data.get("token") or token_data["access_token"]
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": ", ".join((
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )),
}
registry = "https://registry-1.docker.io/v2/library/debian"
index = json.loads(get(f"{registry}/manifests/trixie-slim", headers))
if "manifests" in index:
    manifest_ref = next(
        item["digest"] for item in index["manifests"]
        if item.get("platform", {}).get("os") == "linux" and
           item.get("platform", {}).get("architecture") == "amd64")
    manifest = json.loads(get(f"{registry}/manifests/{manifest_ref}", headers))
else:
    manifest = index

def remove_path(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)

def safe_member(member, destination):
    # Debian packages legitimately use root-absolute symlinks. Rebase those
    # within the rootfs so extraction cannot follow them into the host tree.
    if member.issym() and member.linkname.startswith("/"):
        target = PurePosixPath(member.linkname)
        target_parts = tuple(part for part in target.parts if part not in ("/", "", "."))
        if ".." in target_parts:
            raise tarfile.FilterError(f"unsafe absolute symlink: {member.name} -> {member.linkname}")
        target_name = "/" + "/".join(target_parts)
        parent_name = "/" + "/".join(PurePosixPath(member.name).parent.parts)
        member.linkname = posixpath.relpath(target_name, parent_name)
    return tarfile.data_filter(member, destination)

for number, layer in enumerate(manifest["layers"]):
    digest = layer["digest"]
    archive = root.parent / f"debian-layer-{number}.tar.gz"
    h = hashlib.sha256()
    blob_request = urllib.request.Request(
        f"{registry}/blobs/{digest}",
        headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(blob_request, timeout=180) as src, \
         archive.open("wb") as dst:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            dst.write(chunk)
    if f"sha256:{h.hexdigest()}" != digest:
        raise SystemExit(f"OCI layer digest mismatch: {digest}")

    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            name = PurePosixPath(member.name)
            parts = tuple(part for part in name.parts if part not in ("", "."))
            if not parts or ".." in parts:
                continue
            parent = root.joinpath(*parts[:-1])
            leaf = parts[-1]
            if leaf == ".wh..wh..opq":
                if parent.is_dir():
                    for child in parent.iterdir():
                        remove_path(child)
                continue
            if leaf.startswith(".wh."):
                remove_path(parent / leaf[4:])
                continue
            member.name = str(PurePosixPath(*parts))
            tf.extract(member, root, filter=safe_member)
    archive.unlink()

print("Fetched and verified Debian Trixie amd64 base image")
PY

# Package scripts must not start services inside the staging root. Disable apt's
# _apt setuid sandbox because this bootstrap runs in an unprivileged userns.
printf '#!/bin/sh\nexit 101\n' > "$ROOTFS/usr/sbin/policy-rc.d"
chmod 755 "$ROOTFS/usr/sbin/policy-rc.d"
# Rootless chroot cannot chown the D-Bus launcher to messagebus. Systemd
# activation uses dbus.service, so this legacy helper stays root-owned and
# non-setuid in the image. Register the override before dbus.postinst runs.
unshare -Ur chroot "$ROOTFS" /usr/bin/dpkg-statoverride --add root root 0755 \
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
APT=(unshare -Ur chroot "$ROOTFS" /usr/bin/apt-get
     -o APT::Sandbox::User=root -o APT::Sandbox::Seccomp=false)
DEBIAN_FRONTEND=noninteractive LC_ALL=C "${APT[@]}" update
DEBIAN_FRONTEND=noninteractive LC_ALL=C "${APT[@]}" -y --no-install-recommends install \
    ca-certificates systemd systemd-sysv systemd-resolved e2fsprogs xfce4 \
    xserver-xorg-core xserver-xorg-video-fbdev xserver-xorg-input-evdev \
    xinit xauth x11-xserver-utils xfonts-base xkb-data console-setup-linux \
    dbus dbus-x11 pm-utils at-spi2-core net-tools util-linux \
    openbox tint2 pcmanfm dialog perl libterm-readline-perl-perl
DEBIAN_FRONTEND=noninteractive LC_ALL=C "${APT[@]}" check
rm -f "$ROOTFS/usr/sbin/policy-rc.d"
"${APT[@]}" clean
fi

# The packaged /etc/resolv.conf points into /run, which exists only in the
# booted guest. Temporarily use the host resolver while apt runs in the chroot;
# restore the runtime symlink even if the build fails.
prepare_host_resolver() {
    if [[ -L "$ROOTFS/etc/resolv.conf" ]]; then
        rm -f "$ROOTFS/etc/resolv.conf"
        RESTORE_RESOLV=1
        cp -L /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
    fi
}
prepare_host_resolver

# A cached Debian staging root may predate the dbus package addition. The
# dbus-daemon package alone provides dbus.socket, but not dbus.service.
if [[ ! -f "$ROOTFS/usr/lib/systemd/system/dbus.service" ]]; then
    printf '#!/bin/sh\nexit 101\n' > "$ROOTFS/usr/sbin/policy-rc.d"
    chmod 755 "$ROOTFS/usr/sbin/policy-rc.d"
    unshare -Ur chroot "$ROOTFS" /usr/bin/dpkg-statoverride --add root root 0755 \
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    DEBIAN_FRONTEND=noninteractive LC_ALL=C unshare -Ur chroot "$ROOTFS" \
        /usr/bin/apt-get -o APT::Sandbox::User=root -o APT::Sandbox::Seccomp=false \
        -y --no-install-recommends install dbus
    rm -f "$ROOTFS/usr/sbin/policy-rc.d"
fi
if grep -q '^Status: install ok half-configured$' "$ROOTFS/var/lib/dpkg/status"; then
    if ! unshare -Ur chroot "$ROOTFS" /usr/bin/dpkg-statoverride --list \
        /usr/lib/dbus-1.0/dbus-daemon-launch-helper | grep -q .; then
        unshare -Ur chroot "$ROOTFS" /usr/bin/dpkg-statoverride --add root root 0755 \
            /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    fi
    unshare -Ur chroot "$ROOTFS" /usr/bin/env \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        /usr/bin/dpkg --configure -a
fi
[[ -f "$ROOTFS/usr/lib/systemd/system/dbus.service" ]] || {
    echo "build-glibc-iso: dbus.service missing after installing dbus" >&2
    exit 1
}
rm -f "$ROOTFS/usr/sbin/policy-rc.d"

# Cached roots built before DHCP DNS support do not contain the resolver.
if [[ ! -x "$ROOTFS/usr/lib/systemd/systemd-resolved" ]]; then
    printf '#!/bin/sh\nexit 101\n' > "$ROOTFS/usr/sbin/policy-rc.d"
    chmod 755 "$ROOTFS/usr/sbin/policy-rc.d"
    DEBIAN_FRONTEND=noninteractive LC_ALL=C unshare -Ur chroot "$ROOTFS" \
        /usr/bin/apt-get -o APT::Sandbox::User=root -o APT::Sandbox::Seccomp=false update
    DEBIAN_FRONTEND=noninteractive LC_ALL=C unshare -Ur chroot "$ROOTFS" \
        /usr/bin/apt-get -o APT::Sandbox::User=root -o APT::Sandbox::Seccomp=false \
        -y --no-install-recommends install systemd-resolved
    rm -f "$ROOTFS/usr/sbin/policy-rc.d"
    # The Debian postinst may have switched the chroot to the stub symlink.
    prepare_host_resolver
fi
[[ -x "$ROOTFS/usr/lib/systemd/systemd-resolved" ]] || {
    echo "build-glibc-iso: systemd-resolved missing after installation" >&2
    exit 1
}

# Cached images may lack debconf's interactive frontends. Install them in both
# cached and freshly bootstrapped roots rather than suppressing debconf prompts.
if [[ ! -x "$ROOTFS/usr/bin/dialog" ]] || ! unshare -Ur chroot "$ROOTFS" \
    /usr/bin/perl -MTerm::ReadLine -e 1 >/dev/null 2>&1; then
    printf '#!/bin/sh\nexit 101\n' > "$ROOTFS/usr/sbin/policy-rc.d"
    chmod 755 "$ROOTFS/usr/sbin/policy-rc.d"
    DEBIAN_FRONTEND=noninteractive LC_ALL=C unshare -Ur chroot "$ROOTFS" \
        /usr/bin/apt-get -o APT::Sandbox::User=root -o APT::Sandbox::Seccomp=false \
        -y --no-install-recommends install dialog perl libterm-readline-perl-perl
    rm -f "$ROOTFS/usr/sbin/policy-rc.d"
fi

# Fresh and cached roots both need the real XFCE power probe and AT-SPI service.
bash "$ROOT/tools/prepare-xfce-services.sh" "$ROOTFS"

# Retain the static glibc BusyBox only as a rescue shell; systemd is PID 1.
mkdir -p "$ROOTFS/usr/bin"
unsquashfs -cat "$SOURCE_SFS" usr/bin/busybox > "$ROOTFS/usr/bin/busybox"
chmod 0755 "$ROOTFS/usr/bin/busybox"
if readelf -l "$ROOTFS/usr/bin/busybox" 2>/dev/null | grep 'Requesting program interpreter' >/dev/null; then
    echo "build-glibc-iso: source BusyBox is dynamic; refusing a musl/glibc mix" >&2
    exit 1
fi
if ! strings "$ROOTFS/usr/bin/busybox" | grep 'GLIBC_TUNABLES' >/dev/null; then
    echo "build-glibc-iso: static BusyBox is not verified as glibc-built" >&2
    exit 1
fi

# apk and opkg are static package managers retained from the source userland.
# Their binaries do not pull musl into the Debian/glibc runtime.
PKG_TOOLS="$WORK/alpine-tools"
unsquashfs -d "$PKG_TOOLS" "$SOURCE_SFS" \
    usr/local/bin/apk usr/bin/opkg etc/apk etc/opkg var/lib/opkg >/dev/null
for binary in usr/local/bin/apk usr/bin/opkg; do
    [[ -x "$PKG_TOOLS/$binary" ]] || {
        echo "build-glibc-iso: missing static package manager $binary in source initfs" >&2
        exit 1
    }
done
install -D -m 0755 "$PKG_TOOLS/usr/local/bin/apk" "$ROOTFS/usr/local/bin/apk"
install -D -m 0755 "$PKG_TOOLS/usr/bin/opkg" "$ROOTFS/usr/bin/opkg"
mkdir -p "$ROOTFS/etc/apk" "$ROOTFS/etc/opkg" "$ROOTFS/var/lib/opkg"
cp -a "$PKG_TOOLS/etc/apk/." "$ROOTFS/etc/apk/"
cp -a "$PKG_TOOLS/etc/opkg/." "$ROOTFS/etc/opkg/"
cp -a "$PKG_TOOLS/var/lib/opkg/." "$ROOTFS/var/lib/opkg/"
# Do not let Alpine's default world set imply that its base/musl runtime is
# installed in this Debian image; apk remains available for explicit use.
: > "$ROOTFS/etc/apk/world"
# Initialize apk's own database without importing Alpine packages or fetching
# indexes. apk update needs /lib/apk/db before it can create its lock file.
if [[ ! -f "$ROOTFS/lib/apk/db/installed" ]]; then
    unshare -Ur "$ROOTFS/usr/local/bin/apk" --root "$ROOTFS" \
        --initdb --no-network add
fi

# Debian intentionally does not ship BusyBox applet links. Restore only the
# applets absent from Debian, never replace native Debian commands or import
# Alpine's musl-linked binaries. Include /usr/sbin as well as /usr/bin.
python3 - "$SOURCE_SFS" "$ROOTFS" <<'PY'
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import sys

root = Path(sys.argv[2])
listing = subprocess.check_output(["unsquashfs", "-ll", sys.argv[1]], text=True)
for line in listing.splitlines():
    if not line.startswith("l") or " -> " not in line:
        continue
    source, target = line.split(" -> ", 1)
    name = source.split()[-1].removeprefix("squashfs-root/")
    if not name.startswith(("usr/bin/", "usr/sbin/", "bin/", "sbin/")):
        continue
    resolved = posixpath.normpath(posixpath.join("/", posixpath.dirname(name), target)) if not target.startswith("/") else posixpath.normpath(target)
    if resolved not in ("/usr/bin/busybox", "/bin/busybox"):
        continue
    dest = root / name
    if dest.exists() or dest.is_symlink():
        continue
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Absolute path works even when Debian /bin is a symlink to /usr/bin.
    dest.symlink_to("/usr/bin/busybox")
PY

# AxonOS /dev/kmsg is a raw byte stream, not Linux's structured kmsg records.
# Use the supported syslog(2) path so util-linux does not parse each character
# as its own record. Keep color enabled on the regular dmesg command.
install -d "$ROOTFS/usr/local/bin"
cat > "$ROOTFS/usr/local/bin/dmesg" <<'EOF'
#!/bin/sh
exec /usr/bin/dmesg --syslog --color=always "$@"
EOF
chmod 0755 "$ROOTFS/usr/local/bin/dmesg"

# AxonOS boot integration: Debian systemd is PID 1; BusyBox is only a static
# rescue applet. All dynamic userland uses Debian glibc.
python3 - "$ROOTFS" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
(root / "linuxrc").unlink(missing_ok=True)
(root / "linuxrc").symlink_to("/usr/bin/busybox")
(root / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
(root / "etc/systemd/system/default.target").unlink(missing_ok=True)
(root / "etc/systemd/system/default.target").symlink_to("multi-user.target")
getty_override = root / "etc/systemd/system/getty@tty1.service.d/override.conf"
getty_override.parent.mkdir(parents=True, exist_ok=True)
getty_override.write_text("""[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I 38400 linux
""")
for vt in range(1, 13):
    getty_link = root / f"etc/systemd/system/getty.target.wants/getty@tty{vt}.service"
    getty_link.parent.mkdir(parents=True, exist_ok=True)
    getty_link.unlink(missing_ok=True)
    getty_link.symlink_to("/usr/lib/systemd/system/getty@.service")
for rel, target in (
    ("etc/systemd/system/multi-user.target.wants/systemd-networkd.service",
     "/usr/lib/systemd/system/systemd-networkd.service"),
    # The packaged D-Bus activation file requests this unit name when no
    # org.freedesktop.network1 owner is present. `systemctl enable` normally
    # creates the Alias= symlink, but this image enables networkd manually.
    ("etc/systemd/system/dbus-org.freedesktop.network1.service",
     "/usr/lib/systemd/system/systemd-networkd.service"),
    ("etc/systemd/system/sysinit.target.wants/systemd-resolved.service",
     "/usr/lib/systemd/system/systemd-resolved.service"),
    ("etc/systemd/system/dbus-org.freedesktop.resolve1.service",
     "/usr/lib/systemd/system/systemd-resolved.service"),
):
    link = root / rel
    link.parent.mkdir(parents=True, exist_ok=True)
    link.unlink(missing_ok=True)
    link.symlink_to(target)
network = root / "etc/systemd/network"
network.mkdir(parents=True, exist_ok=True)
(network / "20-ethernet.network").write_text(
    "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\nIPv6AcceptRA=yes\nConfigureWithoutCarrier=yes\n")

# Debian systemd 257 imports optional service credentials through a kernel API
# AxonOS does not implement yet. Clear those optional directives; this image has
# no credential payloads. AxonOS devfs supplies /dev; networkd still needs udev
# link initialization, so udevd remains enabled independently of /dev handling.
units = root / "usr/lib/systemd/system"
for unit in units.rglob("*.service"):
    if unit.is_symlink() or not unit.is_file():
        continue
    if "ImportCredential=" not in unit.read_text(errors="replace"):
        continue
    name = unit.relative_to(units).as_posix()
    dropin = root / "etc/systemd/system" / (name + ".d/90-axon-no-credentials.conf")
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text("""[Service]
ImportCredential=
LoadCredential=
SetCredential=
LoadCredentialEncrypted=
SetCredentialEncrypted=
""")
for name in (
    # Kernel boot already creates /run/lock; re-mounting it triggers the
    # unsupported session-keyring setup in mount(8).
    "run-lock.mount",
    # Lease persistence is not needed for DHCP in this bootable initfs; keep
    # networkd itself enabled and let its BusName gate service readiness.
    "systemd-networkd-persistent-storage.service",
    # The journal lives in the boot image's writable runtime layer; the
    # packaged 90s flush-to-var job stalls boot on this kernel. Journald stays
    # enabled with volatile storage below.
    "systemd-journal-flush.service",
    # The initfs boots from SquashFS and contains no LVM tooling; ext4/LVM
    # online metadata scrubbing has nothing to inspect in this image.
    "e2scrub_reap.service",
    "e2scrub_all.service",
    "e2scrub_all.timer",
    # Legacy SysV initctl FIFO is not used by the systemd image.
    "systemd-initctl.socket",
    # Optional credential loading is not needed in this image.
    "systemd-udev-load-credentials.service",
):
    mask = root / "etc/systemd/system" / name
    if mask.exists() or mask.is_symlink():
        mask.unlink()
    mask.symlink_to("/dev/null")

# Older cached roots were built with udev masked. Unmask the daemon and its
# sockets/trigger: systemd-networkd waits for udev link initialization before
# applying matching .network files. Devfs continues to provide /dev.
for name in (
    "systemd-udevd.service",
    "systemd-udevd-control.socket",
    "systemd-udevd-kernel.socket",
    "systemd-udev-trigger.service",
):
    mask = root / "etc/systemd/system" / name
    if mask.is_symlink() and str(mask.readlink()) == "/dev/null":
        mask.unlink()

# The packaged udevd unit creates mount and UTS namespaces. AxonOS cannot yet
# provide those service sandbox namespaces; systemd exits with 226/NAMESPACE
# before udevd can publish NIC initialization, leaving networkd stuck pending.
udevd_compat = root / "etc/systemd/system/systemd-udevd.service.d/85-axon-compat.conf"
udevd_compat.parent.mkdir(parents=True, exist_ok=True)
udevd_compat.write_text("""[Service]
PrivateMounts=no
ProtectHostname=no
""")

# AxonOS currently has a 2048-entry per-process fd table. Debian defaults for
# logind/journald exceed that kernel limit (524288), so cap those services at
# the supported value instead of letting prlimit64 fail during early boot.
for name in (
    "systemd-logind.service",
    "systemd-journald.service",
    "systemd-journald@.service",
):
    unit = root / "usr/lib/systemd/system" / name
    if not unit.is_file():
        continue
    dropin = root / "etc/systemd/system" / (name + ".d/90-axon-rlimit.conf")
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text("[Service]\nLimitNOFILE=2048:2048\n")

# logind's Debian hardening uses mount/UTS/time namespaces and cgroup BPF,
# which this kernel does not yet implement. Drop only those sandbox features;
# retain logind, its capability bounds, syscall filter, and notify protocol.
logind_compat = root / "etc/systemd/system/systemd-logind.service.d/85-axon-compat.conf"
logind_compat.parent.mkdir(parents=True, exist_ok=True)
logind_compat.write_text("""[Service]
PrivateTmp=no
ProtectSystem=no
ProtectHome=no
ProtectClock=no
ProtectControlGroups=no
ProtectHostname=no
ProtectKernelLogs=no
ProtectKernelModules=no
IPAddressDeny=
""")

# D-Bus's audit ambient capability is unnecessary in this image. Keep
# Debian's AmbientCapabilities for networkd now that capsets, securebits,
# keep-caps and ambient-capability prctl operations are implemented.
for name in ("dbus.service",):
    dropin = root / "etc/systemd/system" / (name + ".d/90-axon-ambient.conf")
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text("[Service]\nAmbientCapabilities=\n")

# Remove the temporary root-run workaround from an older cached staging root.
# The kernel creates /run/systemd/netif with the packaged service UID/GID.
for name in ("systemd-networkd.service", "systemd-networkd-persistent-storage.service"):
    dropin = root / "etc/systemd/system" / (name + ".d/90-axon-root-network.conf")
    dropin.unlink(missing_ok=True)
    ambient = root / "etc/systemd/system" / (name + ".d/90-axon-ambient.conf")
    ambient.unlink(missing_ok=True)
    unit = root / "usr/lib/systemd/system" / name
    if unit.is_file():
        text = unit.read_text()
        text = text.replace("User=root\n", "User=systemd-network\n")
        text = text.replace("Group=root\n", "")
        unit.write_text(text)

# AxonOS still lacks enough mount-namespace operations for networkd's Debian
# ProtectSystem/ProtectProc sandbox. Disable only namespace-dependent features
# so networkd can configure eth0. Use Type=dbus so systemd does not report
# networkd ready until it owns the D-Bus name used by networkctl.
networkd_compat = root / "etc/systemd/system/systemd-networkd.service.d/85-axon-compat.conf"
networkd_compat.parent.mkdir(parents=True, exist_ok=True)
networkd_compat.write_text("""[Service]
Type=dbus
ProtectSystem=no
ProtectHome=no
ProtectProc=default
ProtectControlGroups=no
ProtectKernelLogs=no
ProtectKernelModules=no
ProtectClock=no
PrivateDevices=no
PrivateTmp=no
""")

# Use resolved's upstream DNS file directly. AxonOS does not yet provide a
# complete local DNS stub, but networkd's DHCP DNS and search domains remain
# dynamic via sd-network's inotify monitor.
resolved_compat = root / "etc/systemd/system/systemd-resolved.service.d/85-axon-compat.conf"
resolved_compat.parent.mkdir(parents=True, exist_ok=True)
resolved_compat.write_text("""[Service]
Type=simple
PrivateDevices=no
PrivateTmp=no
ProtectClock=no
ProtectControlGroups=no
ProtectHome=no
ProtectKernelLogs=no
ProtectKernelModules=no
ProtectKernelTunables=no
ProtectSystem=no
ImportCredential=
LoadCredential=
SetCredential=
LoadCredentialEncrypted=
SetCredentialEncrypted=
""")
resolved_config = root / "etc/systemd/resolved.conf.d/90-axon-no-stub.conf"
resolved_config.parent.mkdir(parents=True, exist_ok=True)
resolved_config.write_text("[Resolve]\nDNSStubListener=no\nLLMNR=no\nMulticastDNS=no\n")

# Journald initializes the runtime journal, but it remains in activating even
# with Type=exec. Use Type=simple for both the regular and namespaced journal
# services: this avoids both the READY=1 notification and the exec-status-pipe
# handshake. Patch packaged units as well as drop-ins to make the setting
# unambiguous for the image's systemd manager.
for name in ("systemd-journald.service", "systemd-journald@.service"):
    unit = root / "usr/lib/systemd/system" / name
    if unit.is_file():
        text = unit.read_text()
        text = text.replace("Type=notify\n", "Type=simple\n", 1)
        text = text.replace("Type=exec\n", "Type=simple\n", 1)
        unit.write_text(text)
    journald_compat = root / "etc/systemd/system" / (name + ".d/85-axon-compat.conf")
    journald_compat.parent.mkdir(parents=True, exist_ok=True)
    journald_compat.write_text("[Service]\nType=simple\n")

journald_storage = root / "etc/systemd/journald.conf.d/85-axon-storage.conf"
journald_storage.parent.mkdir(parents=True, exist_ok=True)
journald_storage.write_text("[Journal]\nStorage=volatile\n")

# Keep the boot console to systemd's [ OK ] / [FAILED] status lines. This
# suppresses daemon debug/error chatter and service stdout/stderr on the tty.
for name in (
    "systemd-journald.service", "systemd-sysusers.service", "dbus.service",
    "systemd-networkd.service", "systemd-logind.service", "systemd-udevd.service",
):
    dropin = root / "etc/systemd/system" / (name + ".d/95-axon-console.conf")
    dropin.parent.mkdir(parents=True, exist_ok=True)
    text = """[Service]
StandardOutput=null
StandardError=null
RestartSec=30s
"""
    if name in ("systemd-networkd.service", "systemd-udevd.service"):
        # Keep network daemon diagnostics in journald without flooding the tty.
        text += "Environment=SYSTEMD_LOG_TARGET=journal SYSTEMD_LOG_LEVEL=info SYSTEMD_LOG_COLOR=1 SYSTEMD_COLORS=1\n"
        if name == "systemd-networkd.service":
            text += "Restart=no\n"
    else:
        text += "Environment=SYSTEMD_LOG_TARGET=null SYSTEMD_LOG_LEVEL=emerg SYSTEMD_LOG_COLOR=1 SYSTEMD_COLORS=1\n"
    if name == "dbus.service":
        text += """ExecStart=
ExecStart=/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --nosyslog
"""
    dropin.write_text(text)

# /dev/console aliases tty1, which already has a dedicated getty.
console_getty = root / "etc/systemd/system/console-getty.service"
console_getty.unlink(missing_ok=True)
console_getty.symlink_to("/dev/null")

# The kernel console does not yet support OSC 8 hyperlinks. Avoid printing
# their control sequences literally in systemctl status and related tools.
profile = root / "etc/profile.d/90-axon-terminal.sh"
profile.parent.mkdir(parents=True, exist_ok=True)
profile.write_text("""export SYSTEMD_URLIFY=0
export SYSTEMD_PAGER=cat
# Temporary post-X diagnostics: print automatically, even if input stopped.
_axon_x_diagnostics() {
    printf '\\n--- X diagnostic: startx status %s ---\\n' "$_axon_x_status"
    grep '(EE)' /var/log/Xorg.0.log 2>/dev/null | tail -12
    tail -18 /var/log/Xorg.0.log 2>/dev/null
    dmesg | grep 'xdiag' | tail -35
}
startx() {
    command startx "$@"
    _axon_x_status=$?
    _axon_x_diagnostics
    return "$_axon_x_status"
}
startxfce4() {
    command startxfce4 "$@"
    _axon_x_status=$?
    _axon_x_diagnostics
    return "$_axon_x_status"
}
""")

(root / "etc/X11").mkdir(parents=True, exist_ok=True)
(root / "etc/X11/xorg.conf").write_text("""Section \"ServerFlags\"
    Option \"AutoAddDevices\" \"false\"
    Option \"AutoEnableDevices\" \"false\"
    Option \"AutoAddGPU\" \"false\"
    Option \"DontVTSwitch\" \"true\"
    Option \"DontZap\" \"false\"
EndSection

Section \"Module\"
    Disable \"glx\"
    Disable \"dri\"
    Disable \"dri2\"
    Disable \"dri3\"
    Disable \"glamoregl\"
    Load \"shadow\"
EndSection

# Temporary compatibility: SysV SHM attach is not yet Linux-complete.
Section \"Extensions\"
    Option \"MIT-SHM\" \"Disable\"
EndSection

Section \"InputDevice\"
    Identifier \"Keyboard0\"
    Driver \"evdev\"
    Option \"Device\" \"/dev/input/event0\"
    Option \"GrabDevice\" \"false\"
    Option \"XkbRules\" \"evdev\"
    Option \"XkbModel\" \"pc105\"
    Option \"XkbLayout\" \"us\"
EndSection

Section \"InputDevice\"
    Identifier \"Mouse0\"
    Driver \"evdev\"
    Option \"Device\" \"/dev/input/event1\"
    Option \"GrabDevice\" \"false\"
EndSection

Section \"Device\"
    Identifier \"FB0\"
    Driver \"fbdev\"
    Option \"fbdev\" \"/dev/fb0\"
    Option \"ShadowFB\" \"true\"
    Option \"HWCursor\" \"false\"
EndSection

Section \"Monitor\"
    Identifier \"Monitor0\"
EndSection

Section \"Screen\"
    Identifier \"Screen0\"
    Device \"FB0\"
    Monitor \"Monitor0\"
EndSection

Section \"ServerLayout\"
    Identifier \"Layout0\"
    Screen 0 \"Screen0\"
    InputDevice \"Keyboard0\" \"CoreKeyboard\"
    InputDevice \"Mouse0\" \"CorePointer\"
EndSection
""")
(root / "root/.xinitrc").parent.mkdir(parents=True, exist_ok=True)
(root / "root/.xinitrc").write_text(
    "#!/bin/sh\nexport XDG_SESSION_TYPE=x11\n"
    "if [ -z \"$XDG_RUNTIME_DIR\" ]; then\n"
    "    XDG_RUNTIME_DIR=$(mktemp -d /tmp/axonos-runtime-XXXXXXXXXX) || exit 1\n"
    "    export XDG_RUNTIME_DIR\n"
    "fi\n"
    "exec dbus-launch --exit-with-session startxfce4\n")
(root / "root/.xinitrc").chmod(0o755)
(root / "usr/share/fonts").mkdir(parents=True, exist_ok=True)
font = root / "usr/share/consolefonts/Uni2-Terminus16.psf.gz"
if not font.is_file():
    raise SystemExit("build-glibc-iso: console font package did not provide Uni2-Terminus16.psf.gz")
(root / "usr/share/fonts/console.psf").write_bytes(__import__("gzip").decompress(font.read_bytes()))
(root / "etc/hostname").write_text("localhost\n")
machine_id = root / "etc/machine-id"
machine_id.chmod(0o644)
machine_id.write_text("")
shadow = root / "etc/shadow"
shadow.chmod(0o640)
lines = shadow.read_text().splitlines()
lines = ["root::1:0:99999:7:::" if line.startswith("root:") else line
         for line in lines]
shadow.write_text("\n".join(lines) + "\n")
(root / "usr/lib/xorg/modules/drivers/modesetting_drv.so").unlink(missing_ok=True)
PY

# Keep the packaged XFCE startup sequence, share one session bus, and bound
# activation calls that can block the desktop. Fail closed on an unknown script.
python3 "$ROOT/tools/patch-xfce-xinitrc.py" "$ROOTFS"

# Keep the fully provisioned rootfs for subsequent `make iso` invocations.
if [[ "$ROOTFS_EPHEMERAL" == 1 && ! -e "$CACHE_ROOTFS" ]]; then
    mv "$ROOTFS" "$CACHE_ROOTFS"
    ROOTFS="$CACHE_ROOTFS"
    echo "build-glibc-iso: cached Debian rootfs at $CACHE_ROOTFS"
fi

FBDEV="$ROOTFS/usr/lib/xorg/modules/drivers/fbdev_drv.so"
[[ -f "$FBDEV" ]] && python3 "$ROOT/tools/patch-fbdev-drv.py" "$FBDEV"
if find "$ROOTFS" \( -name 'ld-musl-x86_64.so.1' -o -name 'libc.musl-x86_64.so.1' \) -print -quit | grep . >/dev/null; then
    echo "build-glibc-iso: musl runtime remains in the staged root" >&2
    exit 1
fi
unshare -Ur chroot "$ROOTFS" /usr/lib/systemd/systemd --version >/dev/null
unshare -Ur chroot "$ROOTFS" /usr/sbin/mke2fs -V >/dev/null 2>&1
for binary in /usr/lib/systemd/systemd /usr/sbin/mke2fs /usr/lib/xorg/Xorg; do
    ldd_output="$(unshare -Ur chroot "$ROOTFS" /usr/bin/ldd "$binary" 2>&1)"
    if grep 'not found' <<<"$ldd_output" >/dev/null; then
        echo "build-glibc-iso: unresolved glibc library in $binary" >&2
        exit 1
    fi
done

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"
bash "$ROOT/tools/prepare-xfce-assets.sh" "$ROOTFS"
# xfdesktop 4.20.1 queries the desktop folder before it can create it.
python3 "$ROOT/tools/prepare-xfce-desktop.py" "$ROOTFS"
install -d "$ROOTFS/usr/local/bin"
install -m 755 "$ROOT/tools/ax-xfce-check.sh" "$ROOTFS/usr/local/bin/ax-xfce-check"
# The image ships the Debian/glibc archive only. Remove stale custom X11/Xeyes
# test bundles from the cached root so they cannot leak into the ISO.
rm -rf "$ROOTFS/opt/axonos-x11" "$ROOTFS/opt/axonos-xterm-xinit.tar.gz" \
       "$ROOTFS/opt/axonos-xeyes" "$ROOTFS/opt/axonos-xeyes.tar.gz" \
       "$ROOTFS/usr/local/bin/ax-xcheck"
SFS_OUT="${OUTPUT%.iso}.sfs"
# No host DNS settings are copied into the image. resolved creates this target
# after boot and refreshes it whenever networkd publishes DHCP changes.
rm -f "$ROOTFS/etc/resolv.conf"
ln -s ../run/systemd/resolve/resolv.conf "$ROOTFS/etc/resolv.conf"
RESTORE_RESOLV=0
# The rootless cache is owned by the invoking user. Map it to root in the
# image while preserving the dedicated APT sandbox ownership via pseudo files.
mkdir -p "$ROOTFS/var/lib/apt/lists/partial" "$ROOTFS/var/cache/apt/archives/partial"
APT_UID="$(awk -F: '$1 == "_apt" { print $3; exit }' "$ROOTFS/etc/passwd")"
APT_GID="$(awk -F: '$1 == "_apt" { print $4; exit }' "$ROOTFS/etc/passwd")"
[[ "$APT_UID" =~ ^[0-9]+$ && "$APT_GID" =~ ^[0-9]+$ ]] || {
    echo "build-glibc-iso: missing _apt account" >&2
    exit 1
}
unshare -Ur mksquashfs "$ROOTFS" "$SFS_OUT" -comp gzip -b 131072 -noappend \
    -p "var/lib/apt/lists/partial m 0700 $APT_UID $APT_GID" \
    -p "var/cache/apt/archives/partial m 0700 $APT_UID $APT_GID" \
    -processors "$(nproc 2>/dev/null || echo 2)" >/dev/null

ISO_TREE="$WORK/iso"
cp -a "$ROOT/iso" "$ISO_TREE"
cp "$KERNEL" "$ISO_TREE/boot/axonos.elf"
cp "$SFS_OUT" "$ISO_TREE/boot/initfs.sfs"
python3 - "$ISO_TREE/boot/grub/grub.cfg" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
lines = []
for line in s.splitlines():
    if line.lstrip().startswith("multiboot2 /boot/axonos.elf") and "axon.init=systemd" not in line:
        line += " axon.init=systemd"
    lines.append(line)
p.write_text("\n".join(lines) + "\n")
PY
ISO_TMP="$WORK/axonos-glibc.iso"
grub-mkrescue -o "$ISO_TMP" "$ISO_TREE"
mv -f "$ISO_TMP" "$OUTPUT"
echo "build-glibc-iso: wrote $OUTPUT"
echo "build-glibc-iso: Debian Trixie + glibc + systemd + apk + opkg + colored dmesg + e2fsprogs + Xfce"
