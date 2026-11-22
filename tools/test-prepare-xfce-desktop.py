#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent
SCRIPT = TOOLS / 'prepare-xfce-desktop.py'


class DesktopTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/tmp/opencode')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'rootfs'
        self.home = self.root / 'root'
        self.home.mkdir(parents=True)
        (self.root / 'etc').mkdir()
        (self.root / 'etc/debian_version').write_text('13\n')

    def run_helper(self):
        return subprocess.run(['python3', str(SCRIPT), str(self.root)],
                              capture_output=True, text=True)

    def test_default_created_idempotently(self):
        self.assertEqual(self.run_helper().returncode, 0)
        desktop = self.home / 'Desktop'
        self.assertTrue(desktop.is_dir())
        item = desktop / 'keep'
        item.write_text('user data')
        os.chmod(desktop, 0o700)
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(item.read_text(), 'user data')
        self.assertEqual(desktop.stat().st_mode & 0o777, 0o700)

    def test_no_desktop_setting_in_existing_config_directory(self):
        (self.home / '.config').mkdir()
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertTrue((self.home / 'Desktop').is_dir())

    def test_configured_or_disabled_desktop_untouched(self):
        for contents in ('XDG_DESKTOP_DIR="$HOME/Custom Desktop"\n',
                         'XDG_DESKTOP_DIR="$HOME/"\n',
                         '# other user settings\n'):
            with self.subTest(contents=contents):
                path = self.home / '.config/user-dirs.dirs'
                if not path.parent.exists():
                    path.parent.mkdir()
                path.write_text(contents)
                self.assertEqual(self.run_helper().returncode, 0)
                self.assertEqual(path.read_text(), contents)
                self.assertFalse((self.home / 'Desktop').exists())

    def test_existing_desktop_file_untouched(self):
        desktop = self.home / 'Desktop'
        desktop.write_text('keep')
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(desktop.read_text(), 'keep')

    def test_existing_desktop_symlinks_untouched(self):
        desktop = self.home / 'Desktop'
        desktop.symlink_to(self.base / 'missing')
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertTrue(desktop.is_symlink())
        self.assertEqual(os.readlink(desktop), str(self.base / 'missing'))
        self.assertFalse((self.base / 'missing').exists())

        desktop.unlink()
        target = self.base / 'existing'
        target.mkdir()
        desktop.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(os.readlink(desktop), str(target))
        self.assertEqual(list(target.iterdir()), [])

    def test_dangling_user_dirs_symlink_is_a_choice(self):
        config = self.home / '.config'
        config.mkdir()
        user_dirs = config / 'user-dirs.dirs'
        user_dirs.symlink_to(self.base / 'missing')
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertTrue(user_dirs.is_symlink())
        self.assertFalse((self.home / 'Desktop').exists())

    def test_symlinked_or_non_directory_config_untouched(self):
        target = self.base / 'outside'
        target.mkdir()
        config = self.home / '.config'
        config.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertFalse((self.home / 'Desktop').exists())
        self.assertEqual(list(target.iterdir()), [])
        config.unlink()
        config.symlink_to(self.base / 'missing', target_is_directory=True)
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertTrue(config.is_symlink())
        self.assertFalse((self.home / 'Desktop').exists())
        config.unlink()
        config.write_text('keep')
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(config.read_text(), 'keep')
        self.assertFalse((self.home / 'Desktop').exists())

    def test_symlinked_home_untouched(self):
        self.home.rmdir()
        target = self.base / 'outside'
        target.mkdir()
        self.home.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(list(target.iterdir()), [])

    def test_non_debian_root_rejected(self):
        (self.root / 'etc/debian_version').unlink()
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertFalse((self.home / 'Desktop').exists())

    def test_iso_build_runs_helper_before_packing(self):
        build = (TOOLS / 'build-glibc-iso.sh').read_text()
        call = 'python3 "$ROOT/tools/prepare-xfce-desktop.py" "$ROOTFS"'
        self.assertIn(call, build)
        self.assertLess(build.index(call), build.index('mksquashfs "$ROOTFS"'))


if __name__ == '__main__':
    unittest.main()
