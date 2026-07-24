#pragma once

#include <stdint.h>

/*
 * Process-local virtual-address layout.  These addresses are deliberately
 * independent of a thread id: separate mm_t instances make the same virtual
 * stack and TLS locations safe for unrelated processes, matching Linux fork
 * and exec semantics.
 */
#define USER_IMAGE_BASE       ((uintptr_t)0x00400000ULL)
#define USER_MMAP_BASE        ((uintptr_t)0x08000000ULL)
#define USER_MMAP_TOP         ((uintptr_t)0x30000000ULL)
#define USER_STACK_TOP_LAYOUT ((uintptr_t)0x40000000ULL)
#define USER_STACK_SIZE_LAYOUT ((uintptr_t)(8 * 1024 * 1024))
#define USER_TLS_SIZE_LAYOUT   ((uintptr_t)(2 * 1024 * 1024))
#define USER_STACK_BASE_LAYOUT (USER_STACK_TOP_LAYOUT - USER_STACK_SIZE_LAYOUT)
#define USER_TLS_BASE_LAYOUT   (USER_STACK_BASE_LAYOUT - USER_TLS_SIZE_LAYOUT)
