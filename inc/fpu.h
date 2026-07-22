#pragma once

/* Per-CPU FPU/SSE/AVX bring-up (CR0/CR4/XCR0). Safe to call more than once. */
void fpu_init_cpu(void);
