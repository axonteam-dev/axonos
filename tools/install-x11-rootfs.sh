#!/usr/bin/env bash
# Install a fbdev-only X11 userspace into $HOME/rootfs (Debian Trixie ABI).
# Copies files from the host dpkg database; downloads missing .debs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-${HOME}/rootfs}"
ARCHIVES="${DEST}/var/cache/apt/archives"
mkdir -p "$DEST" "$ARCHIVES/partial" "$DEST/var/lib/dpkg/info" \
         "$DEST/etc/X11/xorg.conf.d" "$DEST/root" "$DEST/tmp/.X11-unix" \
         "$DEST/usr/share/X11" "$DEST/etc/X11/xkb"

log() { printf 'x11-rootfs: %s\n' "$*"; }

SEEDS=(
    xserver-xorg-core
    xserver-xorg-video-fbdev
    xserver-xorg-input-evdev
    xinit
    xterm
    twm
    x11-xserver-utils
    xfonts-base
    xfonts-utils
    xkb-data
    x11-common
    xserver-common
    x11-xkb-utils
    fonts-dejavu-core
    fonts-dejavu-mono
    fontconfig-config
    libfontconfig1
    libxft2
    libudev1
    libmtdev1
    libevdev2
    xauth
)

python3 - "$DEST" "${SEEDS[@]}" <<'PY'
import os, re, shutil, subprocess, sys

dest = sys.argv[1]
seeds = sys.argv[2:]

skip = {
    "xserver-xorg", "xserver-xorg-video-all", "xserver-xorg-input-all",
    "xserver-xorg-video-intel", "xserver-xorg-video-vesa",
    "xserver-xorg-video-vmware", "xserver-xorg-video-qxl",
    "xserver-xorg-video-nouveau", "xserver-xorg-video-amdgpu",
    "xserver-xorg-video-radeon", "xserver-xorg-video-modesetting",
    "xserver-xorg-input-libinput", "xserver-xorg-input-wacom",
    "libgl1-mesa-dri", "libglx-mesa0", "mesa-vulkan-drivers",
    "mesa-libgallium", "libegl-mesa0", "libgl1", "libegl1", "libgbm1",
    "libglx0", "libglvnd0", "libepoxy0", "libwayland-server0",
    "libwayland-client0", "libllvm19", "libdrm-amdgpu1", "libdrm-intel1",
    "libelf1t64", "libsensors5", "libsensors-config", "libz3-4", "libxml2",
    "libedit2", "libffi8", "cpp", "cpp-14", "cpp-x86-64-linux-gnu",
    "cpp-14-x86-64-linux-gnu", "libisl23", "libmpc3", "libmpfr6", "libgmp10",
    "systemd", "systemd-sysv", "udev", "dbus",
    "xorg-video-abi-25", "xorg-video-abi-24", "lsb-base", "perlapi-5.40.0",
    "perlapi-5.40.1", "debconf", "keyboard-configuration",
    "liblocale-gettext-perl", "perl-base",
}

skip_copy_pfx = (
    "/usr/share/doc/", "/usr/share/man/", "/usr/share/lintian/",
    "/usr/share/info/", "/usr/share/bug/",
    "/lib/systemd/", "/usr/lib/systemd/",
    "/usr/lib/udev/", "/lib/udev/",
)

def query_s(pkg):
    try:
        return subprocess.check_output(["dpkg-query", "-s", pkg], text=True,
                                       stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return None

def depends(st):
    names = []
    for line in st.splitlines():
        if line.startswith("Depends:") or line.startswith("Pre-Depends:"):
            for part in line.split(":", 1)[1].split(","):
                alt = part.split("|")[0].strip()
                name = re.split(r"[\s(:]", alt, maxsplit=1)[0]
                if name:
                    names.append(name)
    return names

have, order, missing, status = set(), [], [], []
queue = list(seeds)
while queue:
    pkg = queue.pop(0)
    if pkg in have or pkg in skip:
        continue
    st = query_s(pkg)
    if not st:
        missing.append(pkg)
        have.add(pkg)
        continue
    have.add(pkg)
    order.append(pkg)
    status.append(st.rstrip() + "\n")
    for dep in depends(st):
        if dep not in have and dep not in skip:
            queue.append(dep)

print("PACKAGES", " ".join(order), flush=True)
print("MISSING", " ".join(missing), flush=True)

skip_copy_exact = {"/.", "/"}

def copy_pkg(pkg):
    try:
        files = subprocess.check_output(["dpkg-query", "-L", pkg], text=True,
                                        stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return 0
    n = 0
    for line in files.splitlines():
        src = line.rstrip("\n")
        if not src or src in skip_copy_exact:
            continue
        if any(src.startswith(p) for p in skip_copy_pfx):
            continue
        if src.startswith("/etc/init.d/") or src.startswith("/etc/systemd/"):
            continue
        dst = dest + src
        if os.path.isdir(src) and not os.path.islink(src):
            os.makedirs(dst, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.islink(src) or os.path.isfile(src):
            if os.path.lexists(dst) or os.path.exists(dst):
                if os.path.isdir(dst) and not os.path.islink(dst):
                    continue
                os.remove(dst)
            shutil.copy(src, dst, follow_symlinks=False)
            n += 1
    info_src = f"/var/lib/dpkg/info/{pkg}"
    info_dst_dir = os.path.join(dest, "var/lib/dpkg/info")
    os.makedirs(info_dst_dir, exist_ok=True)
    parent = "/var/lib/dpkg/info"
    if os.path.isdir(parent):
        for name in os.listdir(parent):
            if name == pkg or name.startswith(pkg + ":"):
                s = os.path.join(parent, name)
                d = os.path.join(info_dst_dir, name)
                if os.path.isfile(s):
                    shutil.copy2(s, d)
    return n

copied = 0
for pkg in order:
    copied += copy_pkg(pkg)
    print(f"copied {pkg}", flush=True)

status_path = os.path.join(dest, "var/lib/dpkg/status")
os.makedirs(os.path.dirname(status_path), exist_ok=True)
existing = ""
if os.path.isfile(status_path):
    existing = open(status_path).read()
# Append X packages not already recorded.
have_status = set()
cur = None
for line in existing.splitlines():
    if line.startswith("Package:"):
        cur = line.split(":", 1)[1].strip()
        have_status.add(cur)
with open(status_path, "a") as fh:
    if existing and not existing.endswith("\n\n"):
        fh.write("\n")
    for st in status:
        pkg = None
        for line in st.splitlines():
            if line.startswith("Package:"):
                pkg = line.split(":", 1)[1].strip()
                break
        if pkg and pkg in have_status:
            continue
        fh.write(st)
        if not st.endswith("\n"):
            fh.write("\n")
        fh.write("\n")

missing_path = os.path.join(dest, "var/tmp/x11-missing-pkgs.txt")
os.makedirs(os.path.dirname(missing_path), exist_ok=True)
open(missing_path, "w").write("\n".join(missing) + ("\n" if missing else ""))
print(f"COPIED_FILES {copied}", flush=True)
print(f"MISSING_FILE {missing_path}", flush=True)
PY

MISSING_FILE="$DEST/var/tmp/x11-missing-pkgs.txt"
if [[ -s "$MISSING_FILE" ]]; then
    log "downloading missing packages"
    # shellcheck disable=SC2046
    ( cd "$ARCHIVES" && apt-get download $(tr '\n' ' ' < "$MISSING_FILE") )
    shopt -s nullglob
    for deb in "$ARCHIVES"/*.deb; do
        log "unpack $(basename "$deb")"
        dpkg-deb -x "$deb" "$DEST"
        pkg="$(dpkg-deb -f "$deb" Package)"
        {
            echo "Package: $pkg"
            echo "Status: install ok installed"
            dpkg-deb -f "$deb" | grep -E '^(Package|Status|Version|Architecture|Depends|Pre-Depends|Provides|Replaces|Conflicts|Breaks|Essential|Priority|Section|Installed-Size|Maintainer|Description|Homepage|Original-Maintainer):' | grep -v '^Package:' || true
            echo "Version: $(dpkg-deb -f "$deb" Version)"
            echo "Architecture: $(dpkg-deb -f "$deb" Architecture)"
            echo "Depends: $(dpkg-deb -f "$deb" Depends || true)"
            echo
        } >> "$DEST/var/lib/dpkg/status"
    done
fi

# xorg.conf: fbdev + evdev only. AutoAdd* off so libinput/udev/modesetting stay out.
mkdir -p "$DEST/etc/X11"
cat > "$DEST/etc/X11/xorg.conf" <<'EOF'
Section "ServerFlags"
    Option "AutoAddDevices" "false"
    Option "AutoEnableDevices" "false"
    Option "AutoAddGPU" "false"
    Option "DontVTSwitch" "true"
    Option "DontZap" "false"
EndSection

Section "Module"
    Disable "glx"
    Disable "dri"
    Disable "dri2"
    Disable "dri3"
    Disable "glamoregl"
    Load "shadow"
EndSection

Section "InputDevice"
    Identifier "Keyboard0"
    Driver "evdev"
    Option "Device" "/dev/input/event0"
    Option "GrabDevice" "false"
    Option "XkbRules" "evdev"
    Option "XkbModel" "pc105"
    Option "XkbLayout" "us"
EndSection

Section "InputDevice"
    Identifier "Mouse0"
    Driver "evdev"
    Option "Device" "/dev/input/event1"
    Option "GrabDevice" "false"
EndSection

Section "Device"
    Identifier "FB0"
    Driver "fbdev"
    Option "fbdev" "/dev/fb0"
    Option "ShadowFB" "true"
    Option "HWCursor" "false"
EndSection

Section "Monitor"
    Identifier "Monitor0"
EndSection

Section "Screen"
    Identifier "Screen0"
    Device "FB0"
    Monitor "Monitor0"
EndSection

Section "ServerLayout"
    Identifier "Layout0"
    Screen 0 "Screen0"
    InputDevice "Keyboard0" "CoreKeyboard"
    InputDevice "Mouse0" "CorePointer"
EndSection
EOF

cat > "$DEST/root/.xinitrc" <<'EOF'
#!/bin/sh
export DISPLAY="${DISPLAY:-:0}"
xterm -geometry 80x24+40+40 &
exec twm
EOF
chmod 755 "$DEST/root/.xinitrc"

cat > "$DEST/usr/bin/startx.axon" <<'EOF'
#!/bin/sh
# AxonOS: Xorg + fbdev, no systemd/udev.
export HOME="${HOME:-/root}"
export USER="${USER:-root}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}"
mkdir -p /tmp/.X11-unix /tmp/.ICE-unix "$XDG_RUNTIME_DIR"
chmod 1777 /tmp/.X11-unix /tmp/.ICE-unix 2>/dev/null || true
cd "$HOME" || cd /root || true
if [ -x /usr/bin/xinit ]; then
    exec /usr/bin/xinit "$HOME/.xinitrc" -- /usr/lib/xorg/Xorg :0 vt1 -config /etc/X11/xorg.conf -nolisten tcp -noreset
fi
exec /usr/lib/xorg/Xorg :0 vt1 -config /etc/X11/xorg.conf -nolisten tcp
EOF
chmod 755 "$DEST/usr/bin/startx.axon"
ln -sfn startx.axon "$DEST/usr/bin/startx" 2>/dev/null || true

# Fontconfig cache is host-specific; xterm can use core X fonts from xfonts-base.
mkdir -p "$DEST/usr/share/fonts/X11" "$DEST/etc/fonts"
if [[ -d /etc/fonts ]]; then
    cp -a /etc/fonts/. "$DEST/etc/fonts/" 2>/dev/null || true
fi

rm -f "$DEST/usr/lib/xorg/Xorg.wrap"
# xserver-xorg-core ships this; PCI probe would prefer it over fbdev and then
# die on our stub /dev/dri/card0 (ENODEV) → "no screens found".
rm -f "$DEST/usr/lib/xorg/modules/drivers/modesetting_drv.so"
# AxonOS: no KMS; libfbdevhw PCI probe glob fails on our sysfs → disable it.
FBDEV_SO="$DEST/usr/lib/xorg/modules/drivers/fbdev_drv.so"
if [[ -f "$FBDEV_SO" ]]; then
    python3 "$ROOT/tools/patch-fbdev-drv.py" "$FBDEV_SO"
fi

log "done dest=$DEST size=$(du -sh "$DEST" | awk '{print $1}')"
if [[ -x "$DEST/usr/lib/xorg/Xorg" ]]; then
    log "Xorg ok"
else
    log "WARNING: $DEST/usr/lib/xorg/Xorg missing"
fi
if [[ -x "$DEST/usr/bin/xterm" ]]; then
    log "xterm ok"
else
    log "WARNING: xterm missing"
fi
if [[ -e "$DEST/usr/lib/xorg/modules/drivers/fbdev_drv.so" ]]; then
    log "fbdev_drv.so ok"
else
    log "WARNING: fbdev_drv.so missing"
fi
if [[ -e "$DEST/usr/lib/xorg/modules/input/evdev_drv.so" ]]; then
    log "evdev_drv.so ok"
else
    log "WARNING: evdev_drv.so missing (was downloaded?)"
fi
