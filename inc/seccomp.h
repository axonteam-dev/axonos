#pragma once

#include <stddef.h>
#include <stdint.h>

struct process;
struct seccomp_filter;

/* x86_64 classic-BPF instruction layout, matching Linux struct sock_filter. */
typedef struct {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
} axon_bpf_insn_t;

struct seccomp_filter *seccomp_filter_get(struct seccomp_filter *filter);
void seccomp_filter_put(struct seccomp_filter *filter);
void seccomp_process_inherit(struct process *child, const struct process *parent);
void seccomp_process_release(struct process *process);
int seccomp_filter_install(struct process *process,
                           const axon_bpf_insn_t *instructions, size_t count);
uint32_t seccomp_filter_evaluate(const struct process *process, uint32_t syscall_nr,
                                 uint64_t instruction_pointer,
                                 const uint64_t args[6]);
