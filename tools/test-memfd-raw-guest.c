/* Freestanding x86-64 guest test; also runs on Linux without a C library.
 * cc -nostdlib -static -fno-stack-protector -O2 ... -o test-memfd */
typedef unsigned long u64;
typedef long s64;

static s64 call6(s64 nr, u64 a, u64 b, u64 c, u64 d, u64 e, u64 f)
{
    register u64 r10 __asm__("r10") = d;
    register u64 r8 __asm__("r8") = e;
    register u64 r9 __asm__("r9") = f;
    s64 result;
    __asm__ volatile("syscall" : "=a"(result) :
        "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
        "rcx", "r11", "memory");
    return result;
}
#define SC(n,a,b,c,d,e,f) call6(n,(u64)(a),(u64)(b),(u64)(c),(u64)(d),(u64)(e),(u64)(f))

static void finish(int ok)
{
    static const char pass[] = "PASS: guest memfd create, fd flags, I/O, mmap and close\n";
    static const char fail[] = "FAIL: guest memfd syscall or semantics\n";
    const char *message = ok ? pass : fail;
    u64 len = ok ? sizeof(pass)-1 : sizeof(fail)-1;
    SC(1, 1, message, len, 0, 0, 0);
    SC(60, ok ? 0 : 1, 0, 0, 0, 0, 0);
    for (;;) {}
}

void _start(void)
{
    static const char name[] = "axon-memfd-test";
    static const char data[] = "shared-image";
    char out[sizeof(data)];
    s64 fd = SC(319, name, 1, 0, 0, 0, 0);
    if (fd < 0) finish(0);
    if (SC(72, fd, 1, 0, 0, 0, 0) != 1 ||
        SC(72, fd, 1034, 0, 0, 0, 0) != 1 ||
        SC(77, fd, 4096, 0, 0, 0, 0) != 0 ||
        SC(18, fd, data, sizeof(data), 0, 0, 0) != (s64)sizeof(data) ||
        SC(17, fd, out, sizeof(out), 0, 0, 0) != (s64)sizeof(out))
        finish(0);
    for (u64 i=0; i<sizeof(data); ++i)
        if (out[i] != data[i]) finish(0);
    s64 map = SC(9, 0, 4096, 3, 1, fd, 0);
    if (map < 0) finish(0);
    ((volatile char *)(u64)map)[100] = 'Z';
    s64 second = SC(9, 0, 4096, 1, 1, fd, 0);
    if (second < 0 || ((const volatile char *)(u64)second)[100] != 'Z')
        finish(0);
    if (SC(3, fd, 0, 0, 0, 0, 0) != 0) finish(0);
    for (u64 i=0; i<sizeof(data); ++i)
        if (((const char *)(u64)map)[i] != data[i]) finish(0);
    if (SC(11, second, 4096, 0, 0, 0, 0) != 0 ||
        SC(11, map, 4096, 0, 0, 0, 0) != 0 ||
        SC(319, name, 0x80000000u, 0, 0, 0, 0) != -22)
        finish(0);
#ifdef AXON_PARTIAL_SEALS_TEST
    /* AxonOS supports creation with ALLOW_SEALING, but must never claim that
     * it applied a seal until write/mmap enforcement is implemented. */
    fd = SC(319, name, 3, 0, 0, 0, 0);
    if (fd < 0 || SC(72, fd, 1034, 0, 0, 0, 0) != 0 ||
        SC(72, fd, 1033, 1, 0, 0, 0) != -95 ||
        SC(3, fd, 0, 0, 0, 0, 0) != 0)
        finish(0);
#endif
    finish(1);
}
