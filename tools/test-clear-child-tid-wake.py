#!/usr/bin/env python3
"""Exit paths must use Linux's shared-key wake for clear_child_tid."""
from pathlib import Path
import re

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
calls = re.findall(
    r"futex_syscall\s*\(\s*\(uintptr_t\)cur->clear_child_tid\s*,\s*"
    r"([^,]+),\s*1\s*,\s*NULL\s*,\s*0\s*,\s*0\s*\)", source)
assert len(calls) == 3, calls
assert all(op.strip() == "1" for op in calls), calls
print("PASS: all clear_child_tid exit wakes use the shared futex key")
