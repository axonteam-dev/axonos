#!/usr/bin/env python3
"""Ensure the scheduler releases its lock only after leaving the old stack."""
from pathlib import Path

asm = (Path(__file__).resolve().parents[1] / "cpu/thread/context.S").read_text()
start = asm.index("context_switch_with_prev:")
end = asm.index("\n.global context_switch\n", start)
body = asm[start:end]
save = body.index("movq %rsp, 0x80(%rdi)")
switch = body.index("movq 0x80(%r12), %rsp")
unlock = body.index("call thread_schedule_prev_saved")
restore = body.index("movq %r13, %rsp")
assert save < switch < unlock < restore
assert "andq $-16, %rsp" in body[switch:unlock]
print("PASS: context switch releases scheduler lock on incoming stack")
