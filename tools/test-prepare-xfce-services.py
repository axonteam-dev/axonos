#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent
SCRIPT = TOOLS / 'prepare-xfce-services.sh'


class ServicesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp/opencode')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'root'
        self.write('etc/debian_version', '13')
        (self.root / 'usr/sbin').mkdir(parents=True)
        bindir = self.base / 'bin'
        bindir.mkdir()
        mock = bindir / 'unshare'
        mock.write_text('''#!/bin/sh
set -eu
root=$3
case "$4" in
  /usr/bin/dpkg-query)
    [ -f "$root/installed" ] || exit 1
    printf 'install ok installed'
    ;;
  /usr/bin/apt-get)
    printf '%s\\n' "$*" >> "$MOCK_LOG"
    [ -e "$root/usr/sbin/policy-rc.d" ] || exit 9
    [ "${MOCK_FAIL:-0}" != 1 ] || exit 8
    mkdir -p "$root/usr/bin" "$root/usr/libexec" "$root/usr/share/dbus-1/services"
    touch "$root/installed" "$root/usr/bin/pm-is-supported" "$root/usr/libexec/at-spi-bus-launcher"
    chmod +x "$root/usr/bin/pm-is-supported" "$root/usr/libexec/at-spi-bus-launcher"
    if [ "${MOCK_BAD:-0}" != 1 ]; then
      printf 'Name=org.a11y.Bus\\nExec=/usr/libexec/at-spi-bus-launcher\\n' > "$root/usr/share/dbus-1/services/org.a11y.Bus.service"
    fi
    ;;
  *) exit 2 ;;
esac
''')
        mock.chmod(0o755)
        self.log = self.base / 'apt.log'
        self.env = dict(os.environ, PATH=str(bindir) + ':' + os.environ['PATH'], MOCK_LOG=str(self.log))

    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def run_helper(self, **env):
        return subprocess.run(['bash', str(SCRIPT), str(self.root)],
                              env=dict(self.env, **env), capture_output=True, text=True)

    def test_install_and_idempotence(self):
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertFalse((self.root / 'usr/sbin/policy-rc.d').exists())
        self.assertIn('install --reinstall pm-utils at-spi2-core', self.log.read_text())
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(len(self.log.read_text().splitlines()), 1)
        (self.root / 'usr/bin/pm-is-supported').unlink()
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(len(self.log.read_text().splitlines()), 2)

    def test_preserves_existing_policy(self):
        self.write('usr/sbin/policy-rc.d', 'existing')
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual((self.root / 'usr/sbin/policy-rc.d').read_text(), 'existing')

    def test_failed_install_cleans_policy(self):
        self.assertNotEqual(self.run_helper(MOCK_FAIL='1').returncode, 0)
        self.assertFalse((self.root / 'usr/sbin/policy-rc.d').exists())

    def test_incomplete_install_fails_validation(self):
        result = self.run_helper(MOCK_BAD='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('validation failed', result.stderr)
        self.assertFalse((self.root / 'usr/sbin/policy-rc.d').exists())

    def test_integrated_in_image_build(self):
        build = (TOOLS / 'build-glibc-iso.sh').read_text()
        self.assertIn('dbus dbus-x11 pm-utils at-spi2-core', build)
        self.assertIn('bash "$ROOT/tools/prepare-xfce-services.sh" "$ROOTFS"', build)


if __name__ == '__main__':
    unittest.main()
