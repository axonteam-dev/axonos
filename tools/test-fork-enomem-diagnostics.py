#!/usr/bin/env python3
"""Ensure fork ENOMEM diagnostics identify the failed allocation stage."""
from pathlib import Path

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
start = source.index("static void fork_log_enomem(")
end = source.index("\nstatic uint64_t do_linux_fork(", start)
logger = source[start:end]
for field in ("stage=%s", "heap_free=%llu", "heap_largest=%llu", "pmm_free_pages=%llu"):
    assert field in logger
fork = source[end:source.index("\n", source.index("fork_inherit_fd_table(child, cur);", end))]
for stage in ("heap-watermark", "thread-create", "retain-mm", "duplicate-mm",
              "clone-vma", "process-create", "clone-namespace"):
    assert f'fork_log_enomem(cur, "{stage}")' in fork, stage
print("PASS: fork ENOMEM reports allocation stage and allocator state")
