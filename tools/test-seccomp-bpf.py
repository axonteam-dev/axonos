#!/usr/bin/env python3
"""Exercise classic-BPF seccomp validation, filter stacking and inheritance."""
from pathlib import Path
import subprocess
import tempfile
import sys

root = Path(__file__).resolve().parents[1]
source = (root / "core/seccomp.c").read_text()

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define kmalloc malloc
#define kfree free
''' + source + r'''
int main(void) {
    enum { LD_W_ABS=0x20, JMP_JEQ_K=0x15, RET_K=0x06 };
    const uint32_t ALLOW=0x7fff0000u, ERRNO=0x00050000u;
    process_t parent={0}, child={0};
    /* Deny openat(257), permit other syscalls. */
    axon_bpf_insn_t deny_openat[] = {
        {LD_W_ABS,0,0,0},
        {JMP_JEQ_K,0,1,257},
        {RET_K,0,0,ERRNO|13},
        {RET_K,0,0,ALLOW},
    };
    assert(seccomp_filter_install(&parent, deny_openat, 4) == 0);
    uint64_t args[6]={0};
    assert(seccomp_filter_evaluate(&parent,257,0,args)==(ERRNO|13));
    assert(seccomp_filter_evaluate(&parent,0,0,args)==ALLOW);
    seccomp_process_inherit((struct process *)&child,(const struct process *)&parent);
    assert(seccomp_filter_evaluate(&child,257,0,args)==(ERRNO|13));

    /* A second filter is ANDed with the first: deny syscall 0 as EPERM. */
    axon_bpf_insn_t deny_read[] = {
        {LD_W_ABS,0,0,0},
        {JMP_JEQ_K,0,1,0},
        {RET_K,0,0,ERRNO|1},
        {RET_K,0,0,ALLOW},
    };
    assert(seccomp_filter_install(&parent, deny_read, 4) == 0);
    assert(seccomp_filter_evaluate(&parent,0,0,args)==(ERRNO|1));
    assert(seccomp_filter_evaluate(&parent,257,0,args)==(ERRNO|13));
    assert(seccomp_filter_evaluate(&child,0,0,args)==ALLOW);

    /* Reject backward/out-of-range jumps and unsupported return actions. */
    axon_bpf_insn_t bad_jump[]={{0x05,0,0,100},{RET_K,0,0,ALLOW}};
    assert(seccomp_filter_install(&child,bad_jump,2)==-22);
    axon_bpf_insn_t bad_action[]={{RET_K,0,0,0x7fc00000u}};
    assert(seccomp_filter_install(&child,bad_action,1)==-22);

    /* systemd composes more than sixteen independent policy filters. Linux
     * limits aggregate path instructions (32K), not an arbitrary 16-filter cap. */
    process_t many={0};
    axon_bpf_insn_t allow[]={{RET_K,0,0,ALLOW}};
    for (int i=0;i<32;i++) assert(seccomp_filter_install(&many,allow,1)==0);
    assert(seccomp_filter_evaluate(&many,1,0,args)==ALLOW);
    seccomp_process_release((struct process *)&many);

    axon_bpf_insn_t full[4096];
    for (size_t i=0;i<4096;i++) full[i]=(axon_bpf_insn_t){RET_K,0,0,ALLOW};
    process_t budget={0};
    for (int i=0;i<8;i++) assert(seccomp_filter_install(&budget,full,4096)==0);
    assert(seccomp_filter_install(&budget,allow,1)==-7); /* aggregate > 32768 */
    seccomp_process_release((struct process *)&budget);

    seccomp_process_release((struct process *)&parent);
    seccomp_process_release((struct process *)&child);
    puts("PASS: seccomp classic-BPF deny/allow, filter stacking, fork inheritance and verifier");
}
'''

with tempfile.TemporaryDirectory(prefix="axon-seccomp-", dir="/tmp/opencode") as tmp:
    path = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    path.write_text(fixture)
    subprocess.run(["cc", "-I", str(Path(__file__).resolve().parents[1] / "inc"),
                    "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
