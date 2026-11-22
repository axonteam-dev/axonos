#!/usr/bin/env python3
"""Static integration guards; these are not a ring-3 or QEMU test."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
init = (root / "core/entry/init.c").read_text()
mm = (root / "core/mm.c").read_text()
elf = (root / "core/elf.c").read_text()
boot = (root / "mem/direct_map_boot.c").read_text()

start = init.index("void start_kernel(")
init = init[start:]
assert init.index("paging_init();") < init.index("direct_map_boot_install(")
assert init.index("direct_map_boot_install(") < init.index('asm volatile("sti")')
assert init.index("direct_map_boot_install(") < init.index("thread_init();")
assert init.index("direct_map_boot_install(") < init.index("smp_boot_aps();")
assert "#if defined(AXON_EXPERIMENTAL_DIRECT_MAP) && AXON_EXPERIMENTAL_DIRECT_MAP" in init
assert "if (!(efer & (1ULL << 11))) return -1;" in boot
assert "cr4 & (1ULL << 12)" in boot
assert boot.index("direct_map_build(") < boot.index("direct_map_publish(")
assert boot.index("direct_map_publish(") < boot.index("paging_flush_tlb();")

clone = mm[mm.index("mm_t *mm_clone_from("):mm.index("int mm_demote_user_identity(")]
assert "memcpy(new_l4, src_l4, (size_t)PAGE_SIZE_4K);" in clone
alloc = mm[mm.index("mm_t *mm_alloc(void)"):mm.index("int mm_switch(")]
assert "mm_clone_from(mm_kernel())" in alloc
assert "mm_demote_user_identity(m)" in alloc
demote = mm[mm.index("int mm_demote_user_identity("):mm.index("mm_t *mm_alloc(void)")]
assert "uint64_t hi = (uint64_t)USER_STACK_TOP;" in demote
assert "mm_t *new_mm = mm_alloc();" in elf
assert "child = mm_alloc();" in mm
print("PASS: opt-in boot ordering and PML4 inheritance source contracts")
