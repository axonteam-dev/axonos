#!/usr/bin/env python3
"""Guard the opt-in scheduler ordering experiment and its production fallback."""
from pathlib import Path

source = (Path(__file__).resolve().parents[1] / "core/entry/init.c").read_text()
start = source.index("void start_kernel(")
boot = source[start:]
early = boot.index("#if defined(AXON_EXPERIMENTAL_EARLY_SCHED)")
sti = boot.index('asm volatile("sti")', early)
early_branch = boot[early:sti]
assert early_branch.index("smp_finalize_topology(") < early_branch.index("thread_init();")
assert "#endif" in early_branch
late = boot[sti:]
assert late.count("#if !defined(AXON_EXPERIMENTAL_EARLY_SCHED)") == 2
assert late.count("smp_finalize_topology(") == 1
assert late.count("\n        thread_init();") == 1
print("PASS: early scheduler is opt-in and topology precedes thread setup")
