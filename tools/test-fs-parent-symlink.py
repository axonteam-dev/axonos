#!/usr/bin/env python3
"""Check dentry mutations resolve parent symlinks but preserve the leaf."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "fs/fs.c").read_text()
start = source.index("int fs_resolve_parent_path(")
function = source[start:source.index("\n}\n", start) + 3]
fixture = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define kmalloc malloc
#define kfree free

static char *duplicate(const char *s) {
    size_t n = strlen(s) + 1;
    char *copy = malloc(n);
    if (copy) memcpy(copy, s, n);
    return copy;
}

static char *fs_resolve_symlinks(const char *path) {
    if (strcmp(path, "/bin") == 0) return duplicate("/usr/bin");
    if (strcmp(path, "/missing") == 0) return NULL;
    return duplicate(path);
}

static char *fs_normalize_abs_path(const char *path) {
    return duplicate(path);
}
'''
tests = r'''
int main(void) {
    char out[512];
    assert(fs_resolve_parent_path("/bin/sh", out, sizeof(out)) == 0);
    assert(strcmp(out, "/usr/bin/sh") == 0);
    /* Do not follow a leaf symlink when unlinking or replacing it. */
    assert(fs_resolve_parent_path("/bin", out, sizeof(out)) == 0);
    assert(strcmp(out, "/bin") == 0);
    assert(fs_resolve_parent_path("/usr/bin/sh", out, sizeof(out)) == 0);
    assert(strcmp(out, "/usr/bin/sh") == 0);
    assert(fs_resolve_parent_path("/missing/name", out, sizeof(out)) == 0);
    assert(strcmp(out, "/missing/name") == 0);
    puts("PASS: parent symlinks resolve; leaf symlinks remain intact");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-parent-link-") as tmp:
    src, binary = Path(tmp) / "test.c", Path(tmp) / "test"
    src.write_text(fixture + function + tests)
    subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
