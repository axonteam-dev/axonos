#pragma once
#include <stdint.h>

struct vt_mode_k {
    char mode, waitv;
    short relsig, acqsig, frsig;
};

int vt_get_mode(int index, struct vt_mode_k *mode);
int vt_set_mode(int index, const struct vt_mode_k *mode, uint64_t pid);
int vt_request_switch(int index);
int vt_release(int index, int action, uint64_t pid);
void vt_request_switch_irq(int index);
void vt_worker(void);
