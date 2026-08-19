#!/usr/bin/env bash
# Populate a Debian-shaped apt+dpkg tree so GNU apt can update/install.
# Default destination: $HOME/rootfs (existing tree is kept, busybox dpkg is replaced).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-${HOME}/rootfs}"

if [[ ! -d "$DEST" ]]; then
    mkdir -p "$DEST"
fi

log() { printf 'apt-rootfs: %s\n' "$*"; }

is_busybox_link() {
    local p="$1"
    [[ -L "$p" ]] || return 1
    local t
    t="$(readlink "$p")"
    [[ "$t" == *busybox* ]]
}

install_file() {
    local src="$1"
    local dst="$2"
    if [[ ! -e "$src" && ! -L "$src" ]]; then
        log "skip missing $src"
        return 0
    fi
    mkdir -p "$(dirname "$dst")"
    if [[ -e "$dst" || -L "$dst" ]]; then
        if is_busybox_link "$dst"; then
            rm -f "$dst"
        elif [[ -f "$dst" && ! -L "$dst" && -f "$src" && ! -L "$src" ]]; then
            rm -f "$dst"
        elif [[ -L "$dst" ]]; then
            rm -f "$dst"
        fi
    fi
    cp -a "$src" "$dst"
}

install_host() {
    local src="$1"
    install_file "$src" "$DEST$src"
}

# --- directory skeleton (apt update dies without these) ---
while read -r d; do
    [[ -z "$d" ]] && continue
    mkdir -p "$DEST$d"
done <<'DIRS'
/etc/apt/apt.conf.d
/etc/apt/auth.conf.d
/etc/apt/keyrings
/etc/apt/preferences.d
/etc/apt/sources.list.d
/etc/apt/trusted.gpg.d
/etc/dpkg/dpkg.cfg.d
/etc/default
/usr/lib/locale
/usr/lib/apt/methods
/usr/lib/apt/solvers
/usr/lib/apt/planners
/usr/share/dpkg
/usr/share/apt
/usr/share/keyrings
/var/lib/apt/lists/partial
/var/lib/apt/mirrors/partial
/var/lib/apt/periodic
/var/cache/apt/archives/partial
/var/lib/dpkg/info
/var/lib/dpkg/updates
/var/lib/dpkg/triggers
/var/lib/dpkg/alternatives
/var/lib/dpkg/parts
/var/log/apt
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu
/usr/bin
/usr/sbin
/root
DIRS

# --- GNU dpkg / apt / compressors / sqv (replace BusyBox applets) ---
for f in \
    /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config \
    /usr/bin/apt-cdrom /usr/bin/apt-mark \
    /usr/bin/dpkg /usr/bin/dpkg-deb /usr/bin/dpkg-query /usr/bin/dpkg-divert \
    /usr/bin/dpkg-statoverride /usr/bin/dpkg-trigger /usr/bin/dpkg-split \
    /usr/bin/dpkg-maintscript-helper /usr/bin/dpkg-realpath \
    /usr/sbin/start-stop-daemon \
    /usr/bin/sqv \
    /usr/bin/gpgv \
    /usr/bin/tar /usr/bin/xz /usr/bin/xzcat /usr/bin/zstd /usr/bin/lz4 \
    /usr/bin/bzip2 /usr/bin/bunzip2
 do
    install_host "$f"
done

# dpkg refuses to unpack unless ldconfig is on PATH (libc-bin static-pie).
mkdir -p "$DEST/usr/sbin" "$DEST/sbin" "$DEST/etc/ld.so.conf.d"
if [[ -e /usr/sbin/ldconfig ]]; then
    install_file /usr/sbin/ldconfig "$DEST/usr/sbin/ldconfig"
elif [[ -e /sbin/ldconfig ]]; then
    install_file /sbin/ldconfig "$DEST/usr/sbin/ldconfig"
fi
if [[ -e $DEST/usr/sbin/ldconfig && ! -e $DEST/sbin/ldconfig ]]; then
    ln -s ../usr/sbin/ldconfig "$DEST/sbin/ldconfig"
fi
if [[ -f /etc/ld.so.conf ]]; then
    install_host /etc/ld.so.conf
else
    printf 'include /etc/ld.so.conf.d/*.conf\n' > "$DEST/etc/ld.so.conf"
fi
if [[ -f /etc/ld.so.conf.d/libc.conf ]]; then
    install_host /etc/ld.so.conf.d/libc.conf
else
    printf '%s\n' '# libc default configuration' '/usr/local/lib' \
        > "$DEST/etc/ld.so.conf.d/libc.conf"
fi
if [[ -f /etc/ld.so.conf.d/x86_64-linux-gnu.conf ]]; then
    install_host /etc/ld.so.conf.d/x86_64-linux-gnu.conf
else
    printf '%s\n' '# Multiarch support' \
        '/usr/local/lib/x86_64-linux-gnu' \
        '/lib/x86_64-linux-gnu' \
        '/usr/lib/x86_64-linux-gnu' \
        > "$DEST/etc/ld.so.conf.d/x86_64-linux-gnu.conf"
fi

# Debian glibc uses C.UTF-8 when LANG is unset. SquashFS path walk does not
# follow intermediate directory symlinks, so C.UTF-8 must be a real directory
# (not C.UTF-8 -> C.utf8) or fnmatch intern's LC_COLLATE offsets as pointers.
if [[ -d /usr/lib/locale/C.utf8 ]]; then
    mkdir -p "$DEST/usr/lib/locale"
    rm -rf "$DEST/usr/lib/locale/C.utf8" "$DEST/usr/lib/locale/C.UTF-8"
    cp -a /usr/lib/locale/C.utf8 "$DEST/usr/lib/locale/C.utf8"
    cp -a /usr/lib/locale/C.utf8 "$DEST/usr/lib/locale/C.UTF-8"
    log "locale C.utf8+C.UTF-8 ($(du -sh /usr/lib/locale/C.utf8 | awk '{print $1}'))"
fi
if [[ -f /etc/locale.alias ]]; then
    install_host /etc/locale.alias
fi
mkdir -p "$DEST/usr/share/locale" "$DEST/etc/default"
if [[ ! -e $DEST/usr/share/locale/locale.alias && -e $DEST/etc/locale.alias ]]; then
    ln -s /etc/locale.alias "$DEST/usr/share/locale/locale.alias"
fi
printf 'LANG=C\nLC_ALL=C\n' > "$DEST/etc/default/locale"
printf 'LANG=C\nLC_ALL=C\n' > "$DEST/etc/environment"
mkdir -p "$DEST/root" "$DEST/etc/profile.d"
# BusyBox login clearenv(); LANG only survives if the login shell sources this.
cat > "$DEST/etc/profile" <<'EOF'
export PATH=/opt/bin:/opt/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=linux
export USER=root
export LOGNAME=root
export HOME=/root
export LANG=C
export LC_ALL=C
export PS1='\[\033[1;31m\]\u\033[0m@\h \033[1;37m\w\033[0m \$ '
export OPENSSL_CONF=/etc/ssl/openssl.cnf
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_DIR=/etc/ssl/certs
for _f in /etc/profile.d/*.sh; do
    [ -r "$_f" ] && . "$_f"
done
unset _f
EOF
cat > "$DEST/root/.profile" <<'EOF'
export LANG=C
export LC_ALL=C
export PS1='\[\033[1;31m\]\u\033[0m@\h \033[1;37m\w\033[0m \$ '
EOF
printf 'export LANG=C\nexport LC_ALL=C\n' > "$DEST/etc/profile.d/locale.sh"

# gzip lives at /bin/gzip on Debian (usr-merged). Keep BusyBox /bin/gzip; put GNU at /usr/bin.
if [[ -e /usr/bin/gzip ]]; then
    install_host /usr/bin/gzip
elif [[ -e /bin/gzip ]]; then
    install_file /bin/gzip "$DEST/usr/bin/gzip"
fi

# --- apt methods / helpers ---
mkdir -p "$DEST/usr/lib/apt"
cp -a /usr/lib/apt/. "$DEST/usr/lib/apt/"
rm -rf "$DEST/usr/lib/apt/apt.systemd.daily" \
       "$DEST/usr/lib/systemd" 2>/dev/null || true
# Debian apt prefers methods/sqv when /usr/bin/sqv exists. Sequoia+libgmp on
# the 140KiB trixie InRelease (EdDSA) has been an unreliable verifier here;
# gpgv (libgcrypt) is apt's documented fallback and matches Debian without sqv.
rm -f "$DEST/usr/lib/apt/methods/sqv"

mkdir -p "$DEST/usr/lib/dpkg/methods"
if [[ -d /usr/lib/dpkg/methods/apt ]]; then
    cp -a /usr/lib/dpkg/methods/apt "$DEST/usr/lib/dpkg/methods/"
fi

# --- dpkg architecture tables (must be the Debian files, not empty touch) ---
cp -a /usr/share/dpkg/. "$DEST/usr/share/dpkg/"
mkdir -p "$DEST/usr/share/apt"
if [[ -d /usr/share/apt ]]; then
    cp -a /usr/share/apt/. "$DEST/usr/share/apt/"
fi

# --- keyrings ---
if [[ -d /usr/share/keyrings ]]; then
    find /usr/share/keyrings -maxdepth 1 \( -name 'debian-archive-*' -o -name 'debian-archive-keyring.*' \) \
        -exec cp -a {} "$DEST/usr/share/keyrings/" \;
fi
if [[ -d /etc/apt/trusted.gpg.d ]]; then
    find /etc/apt/trusted.gpg.d -maxdepth 1 -name 'debian-archive-*' \
        -exec cp -a {} "$DEST/etc/apt/trusted.gpg.d/" \;
fi

# --- dpkg.cfg ---
if [[ -f /etc/dpkg/dpkg.cfg ]]; then
    install_host /etc/dpkg/dpkg.cfg
else
    printf '# dpkg config for AxonOS\n' > "$DEST/etc/dpkg/dpkg.cfg"
fi
if [[ -f /etc/apt/apt.conf.d/01autoremove ]]; then
    install_host /etc/apt/apt.conf.d/01autoremove
fi

# AxonOS: no _apt user, no seccomp sandbox, GNU tools live in /usr/bin.
cat > "$DEST/etc/apt/apt.conf.d/00axonos" <<'EOF'
APT::Architecture "amd64";
APT::Architectures "amd64";
APT::Sandbox::User "root";
APT::Sandbox::Seccomp "false";
Dir::Bin::dpkg "/usr/bin/dpkg";
Dir::Bin::gzip "/usr/bin/gzip";
Dir::Bin::bzip2 "/usr/bin/bzip2";
Dir::Bin::xz "/usr/bin/xz";
Dir::Bin::lz4 "/usr/bin/lz4";
Dir::Bin::zstd "/usr/bin/zstd";
Dir::Bin::lzma "/usr/bin/xz";
Dir::Bin::gpgv "/usr/bin/gpgv";
APT::Key::GPGVCommand "/usr/bin/gpgv";
Acquire::Languages "none";
Acquire::ForceIPv4 "true";
Acquire::ForceIPv6 "false";
Acquire::EnableSrvRecords "false";
Acquire::Connect::AddrConfig "false";
Acquire::Connect::IDN "false";
Acquire::http::Timeout "20";
Acquire::https::Timeout "20";
Acquire::Retries "5";
Dir::Cache "/var/cache/apt/";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Cache-Start "33554432";
APT::Cache-Grow "16777216";
APT::Cache-Limit "134217728";
Dpkg::Use-Pty "false";
DPkg::Inhibit-Shutdown "false";
DPkg::FlushSTDIN "false";
DPkg::Path "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
Acquire::http::Pipeline-Depth "0";
EOF

# Debian 13 (trixie) — same ABI as the host apt binary.
cat > "$DEST/etc/apt/sources.list.d/debian.sources" <<'EOF'
Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main contrib non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main contrib non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
EOF

# Fresh dpkg database — do NOT copy the host's full status (thousands of pkgs).
# Seed the Depends-closure of packages whose files already live in the tree so
# `apt install hello` does not unpack Debian libc6, and so seeded packages are
# not "broken" (libssl3t64 → openssl-provider-legacy).
: > "$DEST/var/lib/dpkg/status"
: > "$DEST/var/lib/dpkg/available"
# Previous usrmerge left ../../../lib/... SONAME cycles under /usr/lib.
for gnu in "$DEST/lib/x86_64-linux-gnu" "$DEST/usr/lib/x86_64-linux-gnu"; do
    [[ -d "$gnu" ]] || continue
    find "$gnu" -maxdepth 1 -type l -print0 2>/dev/null | while IFS= read -r -d '' l; do
        if [[ ! -e "$l" ]]; then
            rm -f "$l"
        fi
    done
done
python3 - "$DEST" <<'PY'
import os, re, subprocess, sys

dest = sys.argv[1]
roots = [
    "libc6", "libgcc-s1", "gcc-14-base", "libstdc++6",
    "liblzma5", "zlib1g", "libzstd1", "libmd0", "libxxhash0",
    "libunistring5", "libidn2-0", "libcrypt1",
    "libnsl2", "libtirpc3", "libtirpc-common",
    "libssl3t64", "libssl3", "openssl-provider-legacy",
]
skip_copy_pfx = (
    "/usr/share/doc/", "/usr/share/man/", "/usr/share/lintian/",
    "/usr/share/locale/", "/usr/share/info/",
)

def query_s(pkg):
    try:
        return subprocess.check_output(["dpkg-query", "-s", pkg], text=True,
                                       stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def depends(st):
    names = []
    for line in st.splitlines():
        if line.startswith("Depends:") or line.startswith("Pre-Depends:"):
            for part in line.split(":", 1)[1].split(","):
                name = re.split(r"[\s(]", part.strip(), maxsplit=1)[0]
                if name:
                    names.append(name)
    return names

seen = []
queue = list(roots)
have = set()
while queue:
    pkg = queue.pop(0)
    if pkg in have:
        continue
    st = query_s(pkg)
    if not st:
        continue
    have.add(pkg)
    seen.append((pkg, st))
    for dep in depends(st):
        if dep not in have:
            queue.append(dep)

status_path = os.path.join(dest, "var/lib/dpkg/status")
with open(status_path, "w") as fh:
    for pkg, st in seen:
        text = st.rstrip() + "\n\n"
        fh.write(text)

copied = 0
# libc/libgcc/libstdc++ are already planted by the ELF-closure copy.
# Do not dump libc6 gconv modules (ISO-2022-CN.so NEEDED libGB.so, not in DEST).
skip_copy_pkg = {
    "libc6", "libgcc-s1", "gcc-14-base", "libstdc++6",
}
for pkg, _ in seen:
    if pkg in skip_copy_pkg:
        continue
    try:
        listing = subprocess.check_output(["dpkg", "-L", pkg], text=True,
                                          stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        continue
    for src in listing.splitlines():
        if not src or src == "/":
            continue
        if src.startswith(skip_copy_pfx):
            continue
        if not os.path.isfile(src) and not os.path.islink(src):
            continue
        dst = dest + src
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.lexists(dst) and os.path.islink(dst):
            # Keep BusyBox applets at /bin.
            try:
                tgt = os.readlink(dst)
            except OSError:
                tgt = ""
            if "busybox" in tgt:
                continue
            os.remove(dst)
        copy = ["cp", "-aL", src, dst] if (
            src.startswith("/lib/") or src.startswith("/usr/lib/") or os.path.islink(src)
        ) else ["cp", "-a", src, dst]
        subprocess.check_call(copy)
        copied += 1

print(f"dpkg-status-seed pkgs={len(seen)} files={copied}")
for pkg, _ in seen:
    print(f"  {pkg}")
PY
printf 'amd64\n' > "$DEST/var/lib/dpkg/arch-native"
printf 'apt apt\n' > "$DEST/var/lib/dpkg/cmethopt"
: > "$DEST/var/lib/dpkg/diversions"
: > "$DEST/var/lib/dpkg/statoverride"
: > "$DEST/var/lib/dpkg/lock"
: > "$DEST/var/lib/dpkg/lock-frontend"
chmod 640 "$DEST/var/lib/dpkg/lock" "$DEST/var/lib/dpkg/lock-frontend" || true

# --- shared-library closure of every ELF we just planted ---
python3 - "$DEST" <<'PY'
import os, subprocess, sys

dest = sys.argv[1]
search = ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64"]
libdir = os.path.join(dest, "lib/x86_64-linux-gnu")
usrdir = os.path.join(dest, "usr/lib/x86_64-linux-gnu")
os.makedirs(libdir, exist_ok=True)
os.makedirs(usrdir, exist_ok=True)

def drop_bad_link(path):
    if not os.path.islink(path):
        return
    try:
        os.stat(path)
    except OSError:
        os.remove(path)

for d in (libdir, usrdir):
    try:
        names = os.listdir(d)
    except OSError:
        continue
    for name in names:
        drop_bad_link(os.path.join(d, name))

def readelf_d(path):
    return subprocess.check_output(["readelf", "-d", path], text=True, stderr=subprocess.DEVNULL)

def tags(path, tag):
    out = []
    try:
        text = readelf_d(path)
    except subprocess.CalledProcessError:
        return out
    for line in text.splitlines():
        if tag in line and "[" in line:
            out.append(line.split("[", 1)[1].split("]", 1)[0])
    return out

def interp(path):
    try:
        text = subprocess.check_output(["readelf", "-l", path], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return None
    for line in text.splitlines():
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

def is_elf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False

scan_dirs = [
    "usr/bin",
    "usr/sbin",
    "usr/lib/apt",
    "usr/lib/dpkg",
    "lib/x86_64-linux-gnu",
    "usr/lib/x86_64-linux-gnu",
]
roots = []
for rel in scan_dirs:
    base = os.path.join(dest, rel)
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                continue
            if is_elf(p):
                roots.append(p)

seen = set()
queue = list(roots)
copied = 0
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
    needed = tags(f, "NEEDED")
    sonames = tags(f, "SONAME")
    # Copy this file into libdir if it is a host library (not already under dest).
    if f.startswith("/lib/") or f.startswith("/usr/lib/"):
        base = os.path.basename(f)
        soname = sonames[0] if sonames else base
        dest_file = os.path.join(libdir, base)
        if os.path.islink(dest_file):
            os.remove(dest_file)
        if not os.path.isfile(dest_file):
            subprocess.check_call(["cp", "-aL", f, dest_file])
            copied += 1
            print(f"  + /lib/x86_64-linux-gnu/{base}")
        if soname != base:
            # Same-directory SONAME. ../../../lib/... breaks after /lib -> usr/lib.
            for link in (os.path.join(libdir, soname), os.path.join(usrdir, soname)):
                if os.path.islink(link) or (os.path.lexists(link) and not os.path.isfile(link)):
                    try:
                        os.stat(link)
                    except OSError:
                        os.remove(link)
                if os.path.islink(link) and not os.path.exists(link):
                    os.remove(link)
                if not os.path.lexists(link):
                    os.symlink(base, link)
    for n in needed:
        r = resolve(n)
        if r:
            queue.append(r)
        else:
            print(f"unresolved {n} from {f}", file=sys.stderr)
            sys.exit(1)

print(f"copied-libs={copied} elf-roots={len(roots)}")
PY

# Debian trixie refuses unmerged /bin vs /usr/bin (different inodes).
# Keep GNU tools in /usr/*; move leftover BusyBox applets, then symlink.
merge_usr_tree() {
    local src="$1"
    local dst="$2"
    mkdir -p "$dst"
    local f
    shopt -s nullglob
    for f in "$src"/*; do
        [[ -e "$f" || -L "$f" ]] || continue
        local base
        base="$(basename "$f")"
        if [[ -d "$f" && ! -L "$f" ]]; then
            merge_usr_tree "$f" "$dst/$base"
        elif [[ -L "$dst/$base" ]]; then
            # Prefer a real file (or a working symlink) over a dangling
            # ../../../lib/... leftover from the unmerged layout.
            if [[ ! -e "$dst/$base" ]] || [[ -f "$f" && ! -L "$f" ]]; then
                rm -f "$dst/$base"
                mv "$f" "$dst/$base"
            fi
        elif [[ ! -e "$dst/$base" && ! -L "$dst/$base" ]]; then
            mv "$f" "$dst/$base"
        fi
    done
}

merge_usr_dir() {
    local abs="$1"
    local rel="$2"
    local src="$DEST$abs"
    local dst="$DEST/$rel"
    mkdir -p "$dst"
    if [[ -L "$src" ]]; then
        return 0
    fi
    if [[ ! -d "$src" ]]; then
        if [[ ! -e "$src" ]]; then
            ln -s "$rel" "$src"
        fi
        return 0
    fi
    merge_usr_tree "$src" "$dst"
    rm -rf "$src"
    ln -s "$rel" "$src"
    log "usrmerge $abs -> $rel"
}

merge_usr_dir /lib usr/lib
if [[ -e "$DEST/lib64" || -L "$DEST/lib64" || -d "$DEST/usr/lib64" ]]; then
    merge_usr_dir /lib64 usr/lib64
fi
merge_usr_dir /sbin usr/sbin
merge_usr_dir /bin usr/bin

# Rewrite leftover ../../../lib/x86_64-linux-gnu/SONAME links to same-dir
# names, and copy any still-missing objects from the host (ld-linux, libc).
repair_gnu_lib_links() {
    local dir="$DEST/usr/lib/x86_64-linux-gnu"
    local host=""
    local f base tgt
    [[ -d "$dir" ]] || return 0
    if [[ -d /usr/lib/x86_64-linux-gnu ]]; then
        host=/usr/lib/x86_64-linux-gnu
    elif [[ -d /lib/x86_64-linux-gnu ]]; then
        host=/lib/x86_64-linux-gnu
    fi
    shopt -s nullglob
    for f in "$dir"/*; do
        [[ -L "$f" ]] || continue
        [[ -e "$f" ]] && continue
        base="$(basename "$f")"
        tgt="$(readlink "$f")"
        tgt="${tgt##*/}"
        if [[ -n "$tgt" && -e "$dir/$tgt" ]]; then
            rm -f "$f"
            ln -s "$tgt" "$f"
            continue
        fi
        if [[ -n "$host" && -e "$host/$base" ]]; then
            rm -f "$f"
            cp -aL "$host/$base" "$f" 2>/dev/null || cp -a "$host/$base" "$f"
        fi
    done
    mkdir -p "$DEST/usr/lib64"
    if [[ ! -e "$DEST/usr/lib64/ld-linux-x86-64.so.2" ]]; then
        if [[ -e "$dir/ld-linux-x86-64.so.2" ]]; then
            ln -s "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" \
                "$DEST/usr/lib64/ld-linux-x86-64.so.2"
        elif [[ -e /lib64/ld-linux-x86-64.so.2 ]]; then
            cp -aL /lib64/ld-linux-x86-64.so.2 "$DEST/usr/lib64/ld-linux-x86-64.so.2"
        elif [[ -e /usr/lib64/ld-linux-x86-64.so.2 ]]; then
            cp -aL /usr/lib64/ld-linux-x86-64.so.2 "$DEST/usr/lib64/ld-linux-x86-64.so.2"
        fi
    fi
    if [[ ! -e "$DEST/usr/lib64/ld-linux-x86-64.so.2" ]]; then
        log "ERROR: missing ld-linux-x86-64.so.2 after usrmerge"
        exit 1
    fi
}
repair_gnu_lib_links

log "populated $DEST"
log "dpkg=$(file -b "$DEST/usr/bin/dpkg" | cut -c1-60)"
log "sources=$DEST/etc/apt/sources.list.d/debian.sources"
