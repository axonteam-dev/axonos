#pragma once

struct thread;

/* Per-CPU FPU/SSE/AVX bring-up (CR0/CR4/XCR0). Safe to call more than once. */
void fpu_init_cpu(void);
int fpu_thread_init(struct thread *thread);
void fpu_thread_destroy(struct thread *thread);
void fpu_thread_fork(struct thread *parent, struct thread *child);
void fpu_switch(struct thread *prev, struct thread *next);
