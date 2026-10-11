#!/usr/bin/env bash
# Copy the shared-library closure of host /usr/bin/apt into an AxonOS initfs
# squashfs (Debian paths: /lib/x86_64-linux-gnu). Does not use ldd(1).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SFS="${1:-$ROOT/iso/boot/initfs.sfs}"
HOST_APT="${HOST_APT:-/usr/bin/apt}"

if [[ ! -f "$SFS" ]]; then
    echo "inject-apt-libs: missing $SFS" >&2
    exit 1
fi
if [[ ! -f "$HOST_APT" ]]; then
    echo "inject-apt-libs: host apt not found ($HOST_APT)" >&2
    exit 1
fi
if ! command -v unsquashfs >/dev/null || ! command -v mksquashfs >/dev/null; then
    echo "inject-apt-libs: need unsquashfs and mksquashfs" >&2
    exit 1
fi

WORKDIR="$ROOT/build/initfs-apt-libs.$$"
mkdir -p "$ROOT/build"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

python3 - "$HOST_APT" "$WORKDIR/manifest.txt" <<'PY'
import os, subprocess, sys

apt, manifest = sys.argv[1], sys.argv[2]
search = ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64"]

def readelf_d(path):
    return subprocess.check_output(["readelf", "-d", path], text=True, stderr=subprocess.DEVNULL)

def tags(path, tag):
    out = []
    for line in readelf_d(path).splitlines():
        if tag in line and "[" in line:
            out.append(line.split("[", 1)[1].split("]", 1)[0])
    return out

def interp(path):
    try:
        out = subprocess.check_output(["readelf", "-l", path], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return None
    for line in out.splitlines():
        if "Requesting program interpreter:" in line:
            return line.split(":", 1)[1].strip()
    return None

def resolve(soname):
    if soname.startswith("/"):
        return os.path.realpath(soname) if os.path.exists(soname) else None
    for d in search:
        p = os.path.join(d, soname)
        if os.path.isfile(p) or os.path.islink(p):
            return os.path.realpath(p)
    return None

seen = set()
queue = [os.path.realpath(apt)]
rows = []

while queue:
    f = os.path.realpath(queue.pop(0))
    if f in seen:
        continue
    seen.add(f)
    ip = interp(f)
    if ip:
        r = resolve(ip) or (os.path.realpath(ip) if os.path.exists(ip) else None)
        if r:
            queue.append(r)
    try:
        sonames = tags(f, "SONAME")
        needed = tags(f, "NEEDED")
    except subprocess.CalledProcessError:
        continue
    soname = sonames[0] if sonames else os.path.basename(f)
    if os.path.basename(f) != os.path.basename(apt):
        rows.append((f, soname))
    for n in needed:
        r = resolve(n)
        if r:
            queue.append(r)
        else:
            print(f"inject-apt-libs: unresolved {n} (from {f})", file=sys.stderr)
            sys.exit(1)

with open(manifest, "w") as fh:
    for real, soname in rows:
        fh.write(f"{real}\t{soname}\n")
PY

echo "inject-apt-libs: unsquashing $SFS"
unsquashfs -d "$WORKDIR/root" "$SFS" >/dev/null
LIBDIR="$WORKDIR/root/lib/x86_64-linux-gnu"
USRDIR="$WORKDIR/root/usr/lib/x86_64-linux-gnu"
mkdir -p "$LIBDIR" "$USRDIR"

copied=0
skipped=0
while IFS=$'\t' read -r real soname; do
    [[ -z "$real" ]] && continue
    base="$(basename "$real")"
    dest="$LIBDIR/$base"
    if [[ -e "$dest" || -L "$LIBDIR/$soname" ]]; then
        skipped=$((skipped + 1))
        # Still ensure SONAME is visible under both Debian search paths.
        if [[ ! -e "$LIBDIR/$soname" && ! -L "$LIBDIR/$soname" ]]; then
            ln -sfn "$base" "$LIBDIR/$soname"
        fi
        if [[ ! -e "$USRDIR/$soname" && ! -L "$USRDIR/$soname" ]]; then
            ln -sfn "../../../lib/x86_64-linux-gnu/$soname" "$USRDIR/$soname"
        fi
        continue
    fi
    cp -a "$real" "$dest"
    chmod a+r "$dest" 2>/dev/null || true
    if [[ "$soname" != "$base" ]]; then
        ln -sfn "$base" "$LIBDIR/$soname"
    fi
    ln -sfn "../../../lib/x86_64-linux-gnu/$soname" "$USRDIR/$soname"
    echo "  + /lib/x86_64-linux-gnu/$soname  ($base)"
    copied=$((copied + 1))
done < "$WORKDIR/manifest.txt"

echo "inject-apt-libs: copied=$copied skipped-existing=$skipped"
echo "inject-apt-libs: packing squashfs"
rm -f "$SFS"
mksquashfs "$WORKDIR/root" "$SFS" -comp gzip -b 131072 -noappend -processors "$(nproc 2>/dev/null || echo 2)" >/dev/null
echo "inject-apt-libs: wrote $SFS ($(du -h "$SFS" | awk '{print $1}'))"
