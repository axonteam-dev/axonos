#!/usr/bin/env python3
"""Ensure optimized kernel C cannot silently clobber userspace SIMD registers."""
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="axon-codegen-") as tmp:
    build = Path(tmp) / "build"
    subprocess.run(["make", "-s", "-C", str(root), "config", f"BUILD_DIR={build}"], check=True)
    rule = 'print-codegen-flags:\n\t@printf "%s\\n" "$(CC) $(CFLAGS)"'
    flags = subprocess.check_output(["make", "-s", "--no-print-directory", "-C", str(root),
                                    "--eval=" + rule, "print-codegen-flags",
                                    f"BUILD_DIR={build}"], text=True)
    compiler = shlex.split(flags)
    assert "-mgeneral-regs-only" in compiler
    source = Path(tmp) / "simd.c"
    source.write_text("void copy_words(unsigned long *dst, const unsigned long *src) {\n"
                      "    for (int i = 0; i < 128; i++) dst[i] = src[i];\n}\n")
    obj = Path(tmp) / "simd.o"
    subprocess.run(compiler + ["-O2", "-c", str(source), "-o", str(obj)], cwd=root, check=True)
    disassembly = subprocess.check_output(["objdump", "-d", str(obj)], text=True)
    assert not re.search(r"\b(?:[xyz]mm|mm)[0-9]+\b", disassembly)
print("PASS: actual kernel flags prohibit compiler-generated SIMD at -O2")
