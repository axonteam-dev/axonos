#!/usr/bin/env python3
"""Exercise actual signal argument assignments through the final syscall epilogue."""
from pathlib import Path
import subprocess
import tempfile

source=(Path(__file__).resolve().parents[1]/"syscall/dispatch/syscall_dispatch.c").read_text()


def function(signature):
    start=source.index(signature)
    return source[start:source.index("\n}\n",start)+3]


begin=source.index("        frame[8]  = (uint64_t)sig;")
end=source.index("        frame[13] = handler;",begin)
arguments=source[begin:end]
program=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define SA_SIGINFO 4
#define RT_SIGFRAME_INFO_OFF 320
#define RT_SIGFRAME_UC_OFF 8
typedef struct {
    int ring;
    uint64_t saved_user_rdi,saved_user_rsi,saved_user_rdx;
    uint64_t *saved_syscall_frame,*syscall_frame_kbuf;
    int sigreturn_restore_gprs;
    uint64_t sigreturn_rcx,sigreturn_r11;
} thread_t;
static thread_t *current;
static thread_t *thread_current(void) { return current; }
static thread_t *thread_get_current_user(void) { return current; }
'''+function("void syscall_finalize_user_frame(")+function("void syscall_prepare_iret_frame(")+r'''
static void deliver_args(thread_t *cur,uint64_t *frame,int sig,uint64_t frame_start,int flags) {
    struct { int flags; } sa={flags};
'''+arguments+r'''
}
int main(void) {
    uint64_t area[25]={0}, saved[16]={0}; uint64_t *frame=area+5;
    thread_t t={.ring=3,.saved_user_rdx=2,.saved_syscall_frame=frame,.syscall_frame_kbuf=saved};
    current=&t; frame[12]=2; /* Go's interrupted FUTEX_WAIT val */
    uint64_t interrupted_rdx=t.saved_user_rdx;
    deliver_args(&t,frame,2,0x5fffe000,SA_SIGINFO);
    frame[4]=0x202;frame[13]=0xe43000;frame[15]=0x5fffe000;
    assert(interrupted_rdx==2); /* already stored in ucontext before handler args */
    syscall_finalize_user_frame(frame);
    assert(frame[8]==2&&frame[9]==0x5fffe140&&frame[12]==0x5fffe008);
    assert(saved[12]==0x5fffe008);
    syscall_prepare_iret_frame(frame,area);
    assert(area[12]==0x5fffe008); /* real third handler argument, not the old futex value */
    assert(area[15]==0xe43000&&area[18]==0x5fffe000);
    uint64_t ordinary[16]={0};t.saved_syscall_frame=ordinary;t.saved_user_rdx=17;t.saved_user_rsi=18;
    deliver_args(&t,ordinary,10,0x5fff0000,0);
    syscall_finalize_user_frame(ordinary);
    assert(ordinary[8]==10&&ordinary[12]==17&&t.saved_user_rsi==18);
    puts("PASS: SA_SIGINFO ucontext/si pointers survive epilogue reconciliation; interrupted context stays distinct");
}
'''
with tempfile.TemporaryDirectory(prefix="axon-siginfo-") as tmp:
    c=Path(tmp)/"test.c";binary=Path(tmp)/"test";c.write_text(program)
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                    "-fsanitize=undefined",str(c),"-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
