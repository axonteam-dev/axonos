/* Call a three-argument function on a temporary SysV-aligned kernel stack.
 * The old stack pointer lives in callee-saved r12 across scheduling. */
.text
.globl boot_exec_call_on_stack
.type boot_exec_call_on_stack, @function
boot_exec_call_on_stack:
    pushq %r12
    movq %rsp, %r12
    movq %rcx, %rax
    movq %r8, %rsp
    andq $-16, %rsp
    call *%rax
    movq %r12, %rsp
    popq %r12
    ret
.size boot_exec_call_on_stack, .-boot_exec_call_on_stack
.section .note.GNU-stack,"",@progbits
