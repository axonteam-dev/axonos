#!/usr/bin/env python3
"""Host-only tests for the X11 bundle's executable library-path boundary."""

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent
SCRIPTS = TOOLS / 'x11-bundle'
PREPARE = TOOLS / 'prepare-xterm-bundle.py'
HOST_LOADER = Path('/lib64/ld-linux-x86-64.so.2')

MOCK = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void record(const char *stage, int argc, char **argv) {
    char path[4096];
    const char *dir = getenv("TEST_LOG");
    if (!dir) exit(90);
    snprintf(path, sizeof(path), "%s/%s.env", dir, stage);
    FILE *out = fopen(path, "wb");
    if (!out) exit(91);
    for (char **p = environ; *p; p++) fwrite(*p, 1, strlen(*p) + 1, out);
    if (fclose(out)) exit(92);
    snprintf(path, sizeof(path), "%s/%s.args", dir, stage);
    out = fopen(path, "wb");
    if (!out) exit(93);
    for (int i = 0; i < argc; i++) fwrite(argv[i], 1, strlen(argv[i]) + 1, out);
    if (fclose(out)) exit(94);
}

#if defined(XINIT) || defined(XTERM)
extern const char *probe(void);
static void record_probe(const char *stage) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s.probe", getenv("TEST_LOG"), stage);
    FILE *out = fopen(path, "w");
    if (!out) exit(95);
    fputs(probe(), out);
    if (fclose(out)) exit(96);
}
#endif

int main(int argc, char **argv) {
#ifdef XINIT
    record("xinit", argc, argv);
    record_probe("xinit");
    int split = 1;
    while (split < argc && strcmp(argv[split], "--")) split++;
    if (split + 2 >= argc) return 97;
    pid_t child = fork();
    if (child == -1) return 98;
    if (child == 0) {
        execv(argv[split + 1], &argv[split + 1]);
        _exit(99);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 100;
    if (setenv("DISPLAY", argv[split + 2], 1)) return 101;
    argv[split] = NULL;
    execv(argv[1], &argv[1]);
    return 102;
#elif defined(XTERM)
    record("xterm", argc, argv);
    record_probe("xterm");
    const char *early_exit = getenv("TEST_XTERM_EXIT");
    if (early_exit) return atoi(early_exit);
    int command = 1;
    while (command < argc && strcmp(argv[command], "-e")) command++;
    if (command + 2 != argc || strcmp(argv[command + 1], "/bin/sh")) return 103;
    const char *script =
        "if [ \"${LD_LIBRARY_PATH+x}\" = x ]; then "
        "printf 'set\\0%s' \"$LD_LIBRARY_PATH\" > \"$TEST_LOG/shell.ld\"; "
        "else printf unset > \"$TEST_LOG/shell.ld\"; fi; "
        "/usr/bin/env -0 > \"$TEST_LOG/child.env\"";
    char *args[] = {argv[command + 1], "-c", (char *) script, NULL};
    execv(args[0], args);
    return 104;
#else
    record("xorg", argc, argv);
    return 0;
#endif
}
'''


def read_nul(path):
    return path.read_bytes().rstrip(b'\0').split(b'\0')


def read_env(path):
    return dict(item.split(b'=', 1) for item in read_nul(path) if b'=' in item)


def archive_file(archive, name, data, mode=0o755):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = 123456789
    archive.addfile(info, io.BytesIO(data))


class BundlePackagingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='axon-x11-pack-', dir='/tmp/opencode')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'original.tar.gz'
        self.destination = self.base / 'updated.tar.gz'
        with tarfile.open(self.source, 'w:gz') as archive:
            for name in ('run-xterm.sh', 'run-client.sh', 'bin/xinit', 'bin/xterm',
                         'lib/ld-linux-x86-64.so.2'):
                archive_file(archive, 'axonos-x11/' + name, ('original ' + name).encode())
            archive_file(archive, 'axonos-x11/lib/libc.so.6', b'library', 0o644)
            archive_file(archive, 'axonos-x11/SHA256SUMS', b'original checksums', 0o644)
            symlink = tarfile.TarInfo('axonos-x11/lib/link')
            symlink.type = tarfile.SYMTYPE
            symlink.linkname = 'libc.so.6'
            archive.addfile(symlink)

    def run_prepare(self, source=None, destination=None):
        return subprocess.run([sys.executable, str(PREPARE), str(source or self.source),
                               str(destination or self.destination)], capture_output=True, text=True)

    def test_replaces_only_launchers_and_preserves_input(self):
        original = self.source.read_bytes()
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.source.read_bytes(), original)
        with tarfile.open(self.source) as before, tarfile.open(self.destination) as after:
            self.assertEqual(before.getnames(), after.getnames())
            for old, new in zip(before.getmembers(), after.getmembers()):
                self.assertEqual((old.name, old.mode, old.mtime, old.type, old.linkname),
                                 (new.name, new.mode, new.mtime, new.type, new.linkname))
                if old.isfile():
                    contents = after.extractfile(new).read()
                    if old.name in ('axonos-x11/run-xterm.sh', 'axonos-x11/run-client.sh'):
                        self.assertEqual(contents, (SCRIPTS / Path(old.name).name).read_bytes())
                    else:
                        self.assertEqual(contents, before.extractfile(old).read())
        # Reprocessing yields the same gzip/tar bytes, while refusing an existing output.
        second = self.base / 'second.tar.gz'
        self.assertEqual(self.run_prepare(self.destination, second).returncode, 0)
        self.assertEqual(self.destination.read_bytes(), second.read_bytes())
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertNotEqual(self.run_prepare(destination=self.source).returncode, 0)
        self.assertEqual(self.source.read_bytes(), original)

    def test_rejects_missing_or_duplicate_required_file(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                bad = self.base / f'bad-{duplicate}.tar.gz'
                output = self.base / f'bad-{duplicate}-out.tar.gz'
                with tarfile.open(bad, 'w:gz') as archive:
                    if duplicate:
                        for name in ('run-xterm.sh', 'run-client.sh', 'bin/xinit', 'bin/xterm',
                                     'lib/ld-linux-x86-64.so.2', 'run-xterm.sh'):
                            archive_file(archive, 'axonos-x11/' + name, b'original')
                result = self.run_prepare(bad, output)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('expected one executable regular file', result.stderr)
                self.assertFalse(output.exists())

    @unittest.skipUnless(HOST_LOADER.exists(), 'requires x86-64 glibc')
    def test_prebuilt_bundle_if_available(self):
        source = TOOLS.parent / 'build/axonos-xterm-xinit.tar.gz'
        if not source.is_file():
            self.skipTest('prebuilt local bundle is not present')
        source_digest = hashlib.sha256(source.read_bytes()).digest()
        result = self.run_prepare(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), source_digest)
        with tarfile.open(source) as before, tarfile.open(self.destination) as after:
            self.assertEqual(before.getnames(), after.getnames())
            for old, new in zip(before.getmembers(), after.getmembers()):
                self.assertEqual((old.name, old.mode, old.type, old.linkname),
                                 (new.name, new.mode, new.type, new.linkname))
                if old.isfile() and old.name not in (
                        'axonos-x11/run-xterm.sh', 'axonos-x11/run-client.sh'):
                    self.assertEqual(hashlib.sha256(before.extractfile(old).read()).digest(),
                                     hashlib.sha256(after.extractfile(new).read()).digest())
            checksums = after.extractfile('axonos-x11/SHA256SUMS').read().decode()
            for line in checksums.splitlines():
                expected, name = line.split(None, 1)
                actual = hashlib.sha256(after.extractfile('axonos-x11/' + name).read()).hexdigest()
                self.assertEqual(actual, expected, name)
            after.extractall(self.base / 'unpacked', filter='data')
        bundle = self.base / 'unpacked/axonos-x11'
        loader = bundle / 'lib/ld-linux-x86-64.so.2'
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'LD_AUDIT'):
            env.pop(name, None)
        env['LD_LIBRARY_PATH'] = '/does-not-exist'
        command = [str(loader), '--library-path', str(bundle / 'lib')]
        for program in ('xinit', 'xterm'):
            listed = subprocess.run(command + ['--list', str(bundle / 'bin' / program)],
                                    env=env, capture_output=True, text=True, check=True)
            self.assertIn(f'libc.so.6 => {bundle}/lib/libc.so.6', listed.stdout)
        version = subprocess.run(command + [str(bundle / 'bin/xterm'), '-version'],
                                 env=env, capture_output=True, text=True, check=True)
        self.assertIn('XTerm(', version.stdout)


@unittest.skipUnless(shutil.which('cc') and HOST_LOADER.exists(), 'requires x86-64 glibc and cc')
class RuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="axon x11 'test-", dir='/tmp/opencode')
        cls.base = Path(cls.temp.name)
        cls.bundle = cls.base / 'bundle with spaces'
        cls.log = cls.base / 'log'
        cls.alternate = cls.base / 'caller libraries'
        for path in (cls.bundle / 'bin', cls.bundle / 'lib', cls.log, cls.alternate):
            path.mkdir(parents=True)
        (cls.bundle / 'lib/ld-linux-x86-64.so.2').symlink_to(HOST_LOADER)
        for name in ('run-xterm.sh', 'run-client.sh'):
            shutil.copyfile(SCRIPTS / name, cls.bundle / name)
            (cls.bundle / name).chmod(0o755)
        for path, value in ((cls.bundle / 'lib', 'bundle'), (cls.alternate, 'caller')):
            source = cls.base / f'{value}.c'
            source.write_text(f'const char *probe(void) {{ return "{value}"; }}\n')
            subprocess.run(['cc', '-shared', '-fPIC', '-o', str(path / 'liblaunchprobe.so'),
                            str(source)], check=True)
        mock = cls.base / 'mock.c'
        mock.write_text(MOCK)
        for program, define in (('xinit', 'XINIT'), ('xterm', 'XTERM'), ('xorg', 'XORG')):
            command = ['cc', '-Wall', '-Wextra', '-Werror', f'-D{define}', str(mock),
                       '-o', str(cls.bundle / 'bin' / program)]
            if program != 'xorg':
                command += [f'-L{cls.bundle / "lib"}', '-llaunchprobe']
            subprocess.run(command, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def environment(self, value):
        env = os.environ.copy()
        for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT', 'BASH_ENV', 'ENV'):
            env.pop(name, None)
        env.update(TEST_LOG=str(self.log), XORG=str(self.bundle / 'bin/xorg'),
                   DISPLAY=':88', XAUTHORITY='/original auth',
                   AXONOS_SAVED_LD_LIBRARY_PATH='caller sentinel $HOME\nsecond line')
        if value is not None:
            env['LD_LIBRARY_PATH'] = value
        return env

    def assert_environment(self, path, value):
        env = read_env(path)
        if value is None:
            self.assertNotIn(b'LD_LIBRARY_PATH', env)
        else:
            self.assertEqual(env[b'LD_LIBRARY_PATH'], os.fsencode(value))
        self.assertEqual(env[b'XAUTHORITY'], b'/original auth')
        self.assertEqual(env[b'AXONOS_SAVED_LD_LIBRARY_PATH'], b'caller sentinel $HOME\nsecond line')
        return env

    def assert_shell_and_child(self, value):
        self.assertEqual((self.log / 'shell.ld').read_bytes(),
                         b'unset' if value is None else b'set\0' + os.fsencode(value))
        self.assert_environment(self.log / 'child.env', value)

    def test_new_server_and_existing_server(self):
        values = (None, '', f"{self.alternate}:/absent space;'$(false)\nmore",
                  str(self.bundle / 'lib'))
        for value in values:
            with self.subTest(ld_library_path=value):
                env = self.environment(value)
                result = subprocess.run([str(self.bundle / 'run-xterm.sh'), ':42'],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                for stage in ('xinit', 'xorg', 'xterm'):
                    observed = self.assert_environment(self.log / f'{stage}.env', value)
                    if stage == 'xterm':
                        self.assertEqual(observed[b'DISPLAY'], b':42')
                for stage in ('xinit', 'xterm'):
                    self.assertEqual((self.log / f'{stage}.probe').read_text(), 'bundle')
                self.assertEqual(read_nul(self.log / 'xinit.args')[1:], [
                    os.fsencode(self.bundle / 'lib/ld-linux-x86-64.so.2'), b'--library-path',
                    os.fsencode(self.bundle / 'lib'), os.fsencode(self.bundle / 'bin/xterm'),
                    b'-ut', b'-geometry', b'80x24', b'-e', b'/bin/sh', b'--',
                    os.fsencode(self.bundle / 'bin/xorg'), b':42', b'-nolisten', b'tcp', b'-ac'])
                self.assertEqual(read_nul(self.log / 'xorg.args')[1:],
                                 [b':42', b'-nolisten', b'tcp', b'-ac'])
                self.assertEqual(read_nul(self.log / 'xterm.args')[1:],
                                 [b'-ut', b'-geometry', b'80x24', b'-e', b'/bin/sh'])
                self.assert_shell_and_child(value)

                result = subprocess.run([str(self.bundle / 'run-client.sh')],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                observed = self.assert_environment(self.log / 'xterm.env', value)
                self.assertEqual(observed[b'DISPLAY'], b':88')
                self.assertEqual((self.log / 'xterm.probe').read_text(), 'bundle')
                self.assert_shell_and_child(value)

    def test_checks_and_default_display(self):
        env = self.environment(None)
        result = subprocess.run([str(self.bundle / 'run-xterm.sh')], env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(read_nul(self.log / 'xorg.args')[1], b':1')
        env['XORG'] = str(self.base / 'nonexistent')
        result = subprocess.run([str(self.bundle / 'run-xterm.sh')], env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Xorg not found', result.stderr)
        for value in (None, ''):
            if value is None:
                env.pop('DISPLAY', None)
            else:
                env['DISPLAY'] = value
            result = subprocess.run([str(self.bundle / 'run-client.sh')], env=env,
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('DISPLAY is not set', result.stderr)
        env.update(DISPLAY=':1', TEST_XTERM_EXIT='42')
        result = subprocess.run([str(self.bundle / 'run-client.sh')], env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 42)


if __name__ == '__main__':
    unittest.main()
