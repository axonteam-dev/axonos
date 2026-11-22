#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('prepare-xfce-assets.sh')
LOADER = 'usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader_svg.so'
CACHE = 'usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache'


class AssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp/opencode')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'root'
        self.write('etc/debian_version', '13')
        self.write('usr/share/mime/mime.cache', 'mime')
        self.write('usr/share/backgrounds/xfce/xfce-blue.jpg', 'jpg')
        (self.root / 'usr/sbin').mkdir(parents=True)
        bin_dir = self.base / 'bin'
        bin_dir.mkdir()
        mock = bin_dir / 'unshare'
        mock.write_text('#!/bin/sh\nset -e\nroot="$3"\nmkdir -p "$root/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders"\ntouch "$root/' + LOADER + '"\nprintf \'"/' + LOADER + '"\\n\' > "$root/' + CACHE + '"\n')
        mock.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bin_dir) + ':' + os.environ['PATH'])

    def write(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def run_helper(self):
        return subprocess.run(['bash', str(SCRIPT), str(self.root)], env=self.env,
                              capture_output=True, text=True)

    def test_repair_and_idempotence(self):
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertFalse((self.root / 'usr/sbin/policy-rc.d').exists())
        self.assertEqual(self.run_helper().returncode, 0)

    def test_preserves_existing_policy(self):
        self.write('usr/sbin/policy-rc.d', 'existing')
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual((self.root / 'usr/sbin/policy-rc.d').read_text(), 'existing')

    def test_missing_mime_fails(self):
        (self.root / 'usr/share/mime/mime.cache').unlink()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('MIME database', result.stderr)


if __name__ == '__main__':
    unittest.main()
