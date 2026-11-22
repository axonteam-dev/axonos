#!/usr/bin/env python3
"""PID 1 fallback must not globally tear down live tasks' VMAs."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
elf = (root / "core/elf.c").read_text()
start = elf.index("static int kernel_execve_into_mm(", elf.index("int kernel_execve_init_from_path("))
body = elf[start:elf.index("int r = elf_load_from_path_info(", start)]
assert "exec_reset_shared_user_space(elf_bprm_thread()," in body
assert "exec_reset_shared_user_space(thread_get_current_user()," not in body

teardown = (root / "mm/user_as.c").read_text()
start = teardown.index("void user_as_teardown_for_exec(")
body = teardown[start:teardown.index("/* Legacy shared-CR3 boot path", start)]
assert "if (user_as_has_private_mm(tcur))" in body
assert "user_vma_remove_all_for_tid(tid)" in body
assert "return;" in body
print("PASS: boot/fallback selects private image owner before VMA teardown")
