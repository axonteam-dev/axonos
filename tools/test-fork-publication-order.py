#!/usr/bin/env python3
"""Keep a new fork child blocked until clone metadata has been installed."""
from pathlib import Path

source = (Path(__file__).resolve().parents[1] /
          "syscall/dispatch/syscall_dispatch.c").read_text()
fork_start = source.index("static uint64_t do_linux_fork(")
clone_start = source.index("static uint64_t kernel_clone(", fork_start)
clone_end = source.index("\n/* Linux resource numbers", clone_start)
fork = source[fork_start:clone_start]
clone = source[clone_start:clone_end]
assert "fork_wake_up_new_task(cur, child, 1)" in fork
assert clone.index("fork_store_child_tid(") < clone.index("thread_unblock_fork_child(")
assert clone.index("CLONE_PARENT_SETTID") < clone.index("thread_unblock_fork_child(")
assert clone.index("child->user_fs_base = args->tls") < clone.index("thread_unblock_fork_child(")
print("PASS: fork child publication follows clone metadata setup")
