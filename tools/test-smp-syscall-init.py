#!/usr/bin/env python3
"""Each CPU needs syscall MSRs without repeating global device setup."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
dispatch = (root / "syscall/dispatch/syscall_dispatch.c").read_text()
smp = (root / "cpu/smp/smp.c").read_text()

start = dispatch.index("void syscall_init_cpu(void) {")
end = dispatch.index("\n}", start)
body = dispatch[start:end]
for msr in ("MSR_EFER", "MSR_STAR", "MSR_LSTAR", "MSR_FMASK"):
    assert msr in body
assert "keyring_init" not in body
assert "kmalloc" not in body
assert "syscall_init_cpu();" in dispatch[dispatch.index("void syscall_init(void) {"):]
assert "syscall_init_cpu();" in smp[smp.index("void smp_ap_entry(void) {"):]
entry = smp[smp.index("void smp_ap_entry(void) {"):]
ready = entry.index("__atomic_or_fetch(&smp_started_mask")
for setup in ("idt_load_cpu();", "gdt_ltr_for_cpu(", "fpu_init_cpu();",
              "syscall_init_cpu();", "apic_ap_enable_local();"):
    assert entry.index(setup) < ready, setup
assert ready < entry.index("__atomic_load_n(&smp_boot_done")
assert entry.index("__atomic_load_n(&smp_boot_done") < entry.index("__atomic_or_fetch(&smp_online_mask")
print("PASS: syscall MSRs initialized independently on BSP and AP")
