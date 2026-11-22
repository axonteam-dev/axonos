#!/usr/bin/env python3
"""Ensure AP real-mode LGDT addresses the descriptor through trampoline CS."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = root / "cpu/smp/ap_trampoline.asm"
with tempfile.TemporaryDirectory(prefix="axon-ap-trampoline-") as tmp:
    binary = Path(tmp) / "trampoline.bin"
    subprocess.run(["nasm", "-f", "bin", str(source), "-o", str(binary)], check=True)
    dis = subprocess.check_output(["ndisasm", "-b", "16", "-o", "0x10000",
                                   str(binary)], text=True)
    lgdt = next(line for line in dis.splitlines() if "lgdt" in line)
    assert "[cs:" in lgdt, lgdt
    assert "dword [cs:" in lgdt, lgdt
print("PASS: AP loads 32-bit GDT descriptor through real-mode CS")
