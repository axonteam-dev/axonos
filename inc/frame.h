#ifndef FRAME_H
#define FRAME_H

#include <stdint.h>

void frame_init(void);
void *frame_alloc(void);
void *frame_alloc_zero(void);
int frame_adopt(uint64_t pa);
int frame_retain(uint64_t pa);
void frame_release(uint64_t pa);
unsigned frame_refcount(uint64_t pa);

#endif
