#include <spinlock.h>

void acquire(spinlock_t *lock)
{
    while (__sync_lock_test_and_set(&lock->lock, 1))
        ;
}

void release(spinlock_t *lock)
{
    __sync_lock_release(&lock->lock);
}

int try_acquire(spinlock_t *lock)
{
    return (__sync_lock_test_and_set(&lock->lock, 1) == 0) ? 1 : 0;
}

void acquire_irqsave(spinlock_t *lock, unsigned long *rflags)
{
    unsigned long f;

    asm volatile(
        "pushfq\n\t"
        "pop %0\n\t"
        "cli"
        : "=r"(f)
        :
        : "memory");
    *rflags = f;
    while (__sync_lock_test_and_set(&lock->lock, 1))
        asm volatile("pause" ::: "memory");
}

void release_irqrestore(spinlock_t *lock, unsigned long rflags)
{
    __sync_lock_release(&lock->lock);
    asm volatile("push %0; popfq" :: "r"(rflags) : "memory", "cc");
}

void restore_irqflags(unsigned long rflags)
{
    asm volatile("push %0; popfq" :: "r"(rflags) : "memory", "cc");
}
