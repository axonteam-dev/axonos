#!/usr/bin/env python3
"""Exercise staged xfdesktop under Xvfb without writing to the staged root.

Usage: python3 tools/test-xfdesktop-sandbox.py DEBIAN_ROOTFS XVFB_BINARY

The rootfs must contain xfdesktop, dbus-run-session and Python. XVFB_BINARY
must be compatible with its libraries. No packages are installed by this test.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

HELPER = Path(__file__).resolve().with_name('prepare-xfce-desktop.py')

SANDBOX = r'''#!/bin/sh
set -eu
ulimit -c 0
case "$1" in
    missing) test ! -e /root/Desktop ;;
    prepared)
        /usr/bin/python3 /tmp/prepare-xfce-desktop.py /
        test -d /root/Desktop
        ;;
    custom|custom-missing|disabled)
        mkdir -p /root/.config
        if [ "$1" = custom ] || [ "$1" = custom-missing ]; then
            if [ "$1" = custom ]; then mkdir -p '/root/Custom Desktop'; fi
            printf 'XDG_DESKTOP_DIR="$HOME/Custom Desktop"\n' > /root/.config/user-dirs.dirs
        else
            printf 'XDG_DESKTOP_DIR="$HOME/"\n' > /root/.config/user-dirs.dirs
        fi
        cp /root/.config/user-dirs.dirs /tmp/expected-config
        /usr/bin/python3 /tmp/prepare-xfce-desktop.py /
        test ! -e /root/Desktop
        cmp /tmp/expected-config /root/.config/user-dirs.dirs
        ;;
    *) exit 2 ;;
esac
mkdir -p /tmp/runtime
chmod 700 /tmp/runtime
export XDG_RUNTIME_DIR=/tmp/runtime DISPLAY=:66
/tmp/Xvfb :66 -screen 0 800x600x24 -nolisten tcp -ac > /tmp/xvfb.log 2>&1 &
xvfb=$!
trap 'kill "$xvfb" 2>/dev/null || true' EXIT
i=0
until [ -S /tmp/.X11-unix/X66 ]; do
    if ! kill -0 "$xvfb" 2>/dev/null || [ "$i" -ge 50 ]; then
        cat /tmp/xvfb.log
        exit 1
    fi
    i=$((i + 1))
    sleep 0.1
done
/usr/bin/dbus-run-session -- /bin/sh /tmp/xfdesktop-session.sh "$1"
'''

SESSION = r'''#!/bin/sh
set -eu
runs=1
if [ "$1" = missing ] || [ "$1" = custom-missing ]; then runs=2; fi
i=1
while [ "$i" -le "$runs" ]; do
    status=0
    /usr/bin/timeout -k 1s 4s /usr/bin/xfdesktop --disable-wm-check > /tmp/xfdesktop.log 2>&1 || status=$?
    if [ "$status" -ne 124 ]; then
        echo "xfdesktop exited unexpectedly: $status"
        cat /tmp/xfdesktop.log
        exit 1
    fi
    critical=0
    if grep -Fq "xfdesktop_regular_file_icon_new: assertion 'G_IS_FILE_INFO(file_info)' failed" /tmp/xfdesktop.log; then
        critical=1
    fi
    echo "XFCE_TEST run=$i critical=$critical"
    if [ "$1" = missing ]; then
        test -d /root/Desktop
    fi
    if [ "$1" = custom-missing ]; then
        test -d '/root/Custom Desktop'
    fi
    i=$((i + 1))
done
if [ "$1" = custom ] || [ "$1" = custom-missing ] || [ "$1" = disabled ]; then
    test ! -e /root/Desktop
    cmp /tmp/expected-config /root/.config/user-dirs.dirs
fi
'''


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    rootfs, xvfb = (Path(arg).resolve() for arg in sys.argv[1:])
    if not (rootfs / 'etc/debian_version').is_file() or not xvfb.is_file():
        raise SystemExit('expected a Debian rootfs and an existing Xvfb binary')

    scenarios = {
        'missing': ['XFCE_TEST run=1 critical=1', 'XFCE_TEST run=2 critical=0'],
        'prepared': ['XFCE_TEST run=1 critical=0'],
        'custom': ['XFCE_TEST run=1 critical=0'],
        'custom-missing': ['XFCE_TEST run=1 critical=1', 'XFCE_TEST run=2 critical=0'],
        'disabled': ['XFCE_TEST run=1 critical=0'],
    }
    with tempfile.TemporaryDirectory(dir='/tmp/opencode', prefix='xfdesktop-test-') as temp:
        temp = Path(temp)
        sandbox = temp / 'sandbox.sh'
        session = temp / 'session.sh'
        sandbox.write_text(SANDBOX)
        session.write_text(SESSION)
        for scenario, expected in scenarios.items():
            command = [
                'bwrap', '--unshare-all', '--die-with-parent', '--uid', '0', '--gid', '0',
                '--ro-bind', str(rootfs), '/', '--proc', '/proc', '--dev', '/dev',
                '--tmpfs', '/tmp', '--tmpfs', '/run', '--tmpfs', '/root',
                '--ro-bind', str(xvfb), '/tmp/Xvfb',
                '--ro-bind', str(HELPER), '/tmp/prepare-xfce-desktop.py',
                '--ro-bind', str(sandbox), '/tmp/xfdesktop-sandbox.sh',
                '--ro-bind', str(session), '/tmp/xfdesktop-session.sh',
                '--clearenv', '--setenv', 'PATH', '/usr/sbin:/usr/bin:/sbin:/bin',
                '--setenv', 'HOME', '/root', '--setenv', 'LC_ALL', 'C',
                '--setenv', 'NO_AT_BRIDGE', '1', '--chdir', '/',
                '/bin/sh', '/tmp/xfdesktop-sandbox.sh', scenario,
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=40)
            observed = [line for line in result.stdout.splitlines() if line.startswith('XFCE_TEST ')]
            if result.returncode or observed != expected:
                raise SystemExit(f'{scenario} failed ({result.returncode}):\n'
                                 f'{result.stdout}\n{result.stderr}')
            print(f'{scenario}: ' + ', '.join(observed))


if __name__ == '__main__':
    main()
