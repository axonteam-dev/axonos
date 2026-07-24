/*
 * AxonOS userspace regression harness (static ELF).
 * Build: gcc -O2 -static -Wall -Wextra -o axon-harness tools/axon-harness.c
 * Install: cp axon-harness /path/to/initfs/usr/sbin/axon-harness
 */
#include <stdint.h>
#include <stddef.h>

static int g_pass, g_fail, g_skip;
static int g_verbose = 1;

static long sys0(long n) {
	long ret;
	__asm__ volatile ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
	return ret;
}
static long sys1(long n, long a1) {
	long ret;
	__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}
static long sys2(long n, long a1, long a2) {
	long ret;
	__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
	return ret;
}
static long sys3(long n, long a1, long a2, long a3) {
	long ret;
	__asm__ volatile ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3)
		: "rcx", "r11", "memory");
	return ret;
}
static long sys6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
	long ret;
	register long r10 asm("r10") = a4;
	register long r8 asm("r8") = a5;
	register long r9 asm("r9") = a6;
	__asm__ volatile ("syscall"
		: "=a"(ret)
		: "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
		: "rcx", "r11", "memory");
	return ret;
}

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_fork 57
#define SYS_vfork 58
#define SYS_execve 59
#define SYS_exit 60
#define SYS_wait4 61
#define SYS_getpid 39
#define SYS_brk 12
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_mprotect 10
#define SYS_gettid 186
#define SYS_clone3 435
#define SYS_nanosleep 35
#define SYS_getppid 110
#define SYS_pipe2 293

struct timespec_h { long tv_sec; long tv_nsec; };

#define MAP_PRIVATE 0x02
#define MAP_SHARED 0x01
#define MAP_ANONYMOUS 0x20
#define PROT_READ 1
#define PROT_WRITE 2
#define O_RDONLY 0
#define ENOENT 2
#define ECHILD 10
#define ENOEXEC 8
#define ENOMEM 12

static void uwrite(const char *s) {
	const char *p = s;
	while (*p) p++;
	sys3(SYS_write, 1, (long)s, (long)(p - s));
}

static void uwrite_hex64(const char *pfx, unsigned long long v) {
	char buf[32];
	char *e = buf + sizeof(buf);
	*--e = '\n';
	if (!v) *--e = '0';
	while (v && e > buf) { *--e = "0123456789abcdef"[v & 15]; v >>= 4; }
	uwrite(pfx);
	while (*e) sys3(SYS_write, 1, (long)e++, 1);
}

static void uwrite_errno(const char *pfx, long rc) {
	uwrite_hex64(pfx, (unsigned long long)rc);
}

static int streq(const char *a, const char *b) {
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

static int filter_match(const char *name, const char *flt) {
	if (!flt || !flt[0]) return 1;
	return streq(name, flt);
}

static void pass(const char *name) {
	g_pass++;
	uwrite("PASS ");
	uwrite(name);
	uwrite("\n");
}

static void fail(const char *name, const char *detail) {
	g_fail++;
	uwrite("FAIL ");
	uwrite(name);
	if (detail && detail[0]) {
		uwrite(" — ");
		uwrite(detail);
	}
	uwrite("\n");
}

static void skip(const char *name, const char *why) {
	g_skip++;
	uwrite("SKIP ");
	uwrite(name);
	if (why && why[0]) {
		uwrite(" — ");
		uwrite(why);
	}
	uwrite("\n");
}

static volatile int g_fork_probe;

static void test_basic_syscalls(void) {
	long pid = sys0(SYS_getpid);
	if (pid > 0) pass("getpid positive");
	else fail("getpid positive", "pid<=0");
}

static void test_brk_grow(void) {
	long b0 = sys1(SYS_brk, 0);
	long b1 = sys1(SYS_brk, b0 + 0x20000);
	if (b1 == b0 + 0x20000) pass("brk grow 128KiB");
	else fail("brk grow 128KiB", "brk did not advance");
	*(volatile char *)(uintptr_t)b0 = 42;
	if (*(volatile char *)(uintptr_t)b0 == 42) pass("brk store/load");
	else fail("brk store/load", "byte mismatch");
}

static void test_mmap_anon(void) {
	long p = sys6(SYS_mmap, 0, 0x10000, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p > 0 && p < 0x10000000L) pass("mmap anon 64KiB");
	else { fail("mmap anon 64KiB", "bad addr"); return; }
	*(volatile int *)(uintptr_t)p = 0x12345678;
	if (*(volatile int *)(uintptr_t)p == 0x12345678) pass("mmap R/W");
	else fail("mmap R/W", "store failed");
	if (sys2(SYS_munmap, p, 0x10000) == 0) pass("munmap anon");
	else fail("munmap anon", "syscall failed");
}

static void test_mmap_large(void) {
	long sz = 4L * 1024 * 1024;
	long p = sys6(SYS_mmap, 0, sz, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p > 0) {
		*(volatile char *)(uintptr_t)p = 1;
		*(volatile char *)(uintptr_t)(p + sz - 4096) = 2;
		pass("mmap 4MiB touch ends");
		sys2(SYS_munmap, p, sz);
	} else fail("mmap 4MiB", "ENOMEM or bad addr");
}

static void test_munmap_removes_pte(void) {
	const long len = 3L * 4096;
	long map = sys6(SYS_mmap, 0, len, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map <= 0) {
		skip("munmap removes PTE", "mmap failed");
		return;
	}
	volatile int *first = (volatile int *)(uintptr_t)map;
	volatile int *middle = (volatile int *)(uintptr_t)(map + 4096);
	volatile int *last = (volatile int *)(uintptr_t)(map + 8192);
	*first = 0x1111;
	*middle = 0x2222;
	*last = 0x3333;
	if (sys2(SYS_munmap, map + 4096, 4096) != 0) {
		fail("munmap removes PTE", "partial munmap failed");
		(void)sys2(SYS_munmap, map, len);
		return;
	}
	if (*first != 0x1111 || *last != 0x3333) {
		fail("munmap preserves neighbours", "adjacent page changed");
		(void)sys2(SYS_munmap, map, len);
		return;
	}
	long child = sys0(SYS_fork);
	if (child < 0) {
		fail("munmap removes PTE", "fork failed");
		(void)sys2(SYS_munmap, map, len);
		return;
	}
	if (child == 0) {
		volatile int value = *middle;
		(void)value;
		sys1(SYS_exit, 0);
	}
	int status = 0;
	(void)sys3(SYS_wait4, child, (long)(uintptr_t)&status, 0);
	if ((status & 0x7f) == 11)
		pass("munmap removes PTE");
	else
		fail("munmap removes PTE", "unmapped page remained readable");
	(void)sys2(SYS_munmap, map, 4096);
	(void)sys2(SYS_munmap, map + 8192, 4096);
}

static void test_mprotect(void) {
	long p = sys6(SYS_mmap, 0, 0x2000, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p <= 0) { skip("mprotect", "mmap failed"); return; }
	if (sys3(SYS_mprotect, p, 0x2000, PROT_READ) == 0) pass("mprotect RO");
	else fail("mprotect RO", "syscall error");
	if (sys3(SYS_mprotect, p, 0x2000, PROT_READ | PROT_WRITE) == 0) pass("mprotect RW restore");
	else fail("mprotect RW restore", "syscall error");
	sys2(SYS_munmap, p, 0x2000);
}

static void test_fork_readonly_mprotect_cow(void) {
	long map = sys6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map <= 0) {
		skip("fork RO then mprotect COW", "mmap failed");
		return;
	}
	volatile int *p = (volatile int *)(uintptr_t)map;
	*p = 0x13579bdf;
	if (sys3(SYS_mprotect, map, 4096, PROT_READ) != 0) {
		fail("fork RO then mprotect COW", "initial mprotect failed");
		(void)sys2(SYS_munmap, map, 4096);
		return;
	}
	long child = sys0(SYS_fork);
	if (child < 0) {
		fail("fork RO then mprotect COW", "fork failed");
		(void)sys2(SYS_munmap, map, 4096);
		return;
	}
	if (child == 0) {
		if (sys3(SYS_mprotect, map, 4096,
		         PROT_READ | PROT_WRITE) != 0)
			sys1(SYS_exit, 2);
		*p = 0x2468ace0;
		sys1(SYS_exit, 0);
	}
	int status = 0;
	(void)sys3(SYS_wait4, child, (long)(uintptr_t)&status, 0);
	if (sys3(SYS_mprotect, map, 4096, PROT_READ | PROT_WRITE) == 0 &&
	    status == 0 && *p == 0x13579bdf)
		pass("fork RO then mprotect COW");
	else
		fail("fork RO then mprotect COW", "private page was shared");
	(void)sys2(SYS_munmap, map, 4096);
}

static void test_fork_basic(void) {
	g_fork_probe = 0;
	long pid = sys0(SYS_fork);
	if (pid < 0) {
		fail("fork", "syscall failed");
		uwrite_errno("  rc=0x", pid);
		return;
	}
	if (pid == 0) { g_fork_probe = 77; sys1(SYS_exit, 0); }
	int status = 0;
	long w = sys3(SYS_wait4, pid, (long)(uintptr_t)&status, 0);
	if (w == pid && g_fork_probe == 0) pass("fork/wait child exit");
	else fail("fork/wait", "parent state wrong");
}

static void test_pipe_eof_after_fork(void) {
	int fds[2] = { -1, -1 };
	if (sys2(SYS_pipe2, (long)(uintptr_t)fds, 0) != 0) {
		fail("pipe EOF after fork", "pipe2 failed");
		return;
	}
	long pid = sys0(SYS_fork);
	if (pid == 0) {
		static const char payload[] = "ok";
		(void)sys1(SYS_close, fds[0]);
		(void)sys3(SYS_write, fds[1], (long)(uintptr_t)payload, 2);
		(void)sys1(SYS_close, fds[1]);
		sys1(SYS_exit, 0);
		for (;;) { }
	}
	if (pid < 0) {
		(void)sys1(SYS_close, fds[0]);
		(void)sys1(SYS_close, fds[1]);
		fail("pipe EOF after fork", "fork failed");
		return;
	}
	(void)sys1(SYS_close, fds[1]);
	char buf[4] = { 0, 0, 0, 0 };
	long n1 = sys3(SYS_read, fds[0], (long)(uintptr_t)buf, sizeof(buf));
	long n2 = sys3(SYS_read, fds[0], (long)(uintptr_t)buf, sizeof(buf));
	(void)sys1(SYS_close, fds[0]);
	long status = 0;
	(void)sys3(SYS_wait4, pid, (long)(uintptr_t)&status, 0);
	if (n1 == 2 && n2 == 0 && buf[0] == 'o' && buf[1] == 'k')
		pass("pipe EOF after fork");
	else
		fail("pipe EOF after fork", "expected payload followed by EOF");
}

static volatile unsigned int g_isolation_magic = 0xBEEF0001U;

static void test_fork_memory_isolation(void) {
	g_isolation_magic = 0xBEEF0001U;
	long pid = sys0(SYS_fork);
	if (pid < 0) {
		fail("fork isolation", "fork failed");
		uwrite_errno("  rc=0x", pid);
		return;
	}
	if (pid == 0) { g_isolation_magic = 0xCAFEBABEU; sys1(SYS_exit, 0); }
	int st = 0;
	(void)sys3(SYS_wait4, pid, (long)(uintptr_t)&st, 0);
	if (g_isolation_magic == 0xBEEF0001U) pass("fork memory isolation");
	else fail("fork memory isolation", "parent saw child write");
}

static void test_parent_child_linkage(void) {
	int pipefd[2] = { -1, -1 };
	if (sys2(SYS_pipe2, (long)(uintptr_t)pipefd, 0) != 0) {
		skip("parent child linkage", "pipe2 unavailable");
		return;
	}
	long parent = sys0(SYS_getpid);
	long child = sys0(SYS_fork);
	if (child == 0) {
		long ppid = sys0(SYS_getppid);
		(void)sys3(SYS_write, pipefd[1], (long)(uintptr_t)&ppid, sizeof(ppid));
		sys1(SYS_exit, 0);
	}
	long seen = 0;
	(void)sys3(SYS_read, pipefd[0], (long)(uintptr_t)&seen, sizeof(seen));
	int status = 0;
	long waited = sys3(SYS_wait4, child, (long)(uintptr_t)&status, 0);
	sys1(SYS_close, pipefd[0]);
	sys1(SYS_close, pipefd[1]);
	if (child > 0 && waited == child && seen == parent)
		pass("parent child PID linkage");
	else
		fail("parent child PID linkage", "getppid/wait mismatch");
}

static void test_wait_wnohang_zombie(void) {
	long child = sys0(SYS_fork);
	if (child == 0) {
		struct timespec_h ts = { 0, 20000000L };
		(void)sys2(SYS_nanosleep, (long)(uintptr_t)&ts, 0);
		sys1(SYS_exit, 23);
	}
	int status = 0;
	long first = sys3(SYS_wait4, child, (long)(uintptr_t)&status, 1);
	long second = sys3(SYS_wait4, child, (long)(uintptr_t)&status, 0);
	if (first == 0 && second == child && status == (23 << 8))
		pass("wait4 WNOHANG zombie retention");
	else
		fail("wait4 WNOHANG zombie retention", "unexpected wait result");
}

static void test_fork_brk_mmap_cow(void) {
	long brk0 = sys1(SYS_brk, 0);
	long brk1 = sys1(SYS_brk, brk0 + 4096);
	long map = sys6(SYS_mmap, 0, 0x2000, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (brk1 != brk0 + 4096 || map <= 0) {
		skip("fork brk/mmap COW", "allocation failed");
		return;
	}
	volatile int *bp = (volatile int *)(uintptr_t)brk0;
	volatile int *mp = (volatile int *)(uintptr_t)map;
	*bp = 0x11223344;
	*mp = 0x55667788;
	long child = sys0(SYS_fork);
	if (child == 0) {
		*bp = 1;
		*mp = 2;
		sys1(SYS_exit, 0);
	}
	int status = 0;
	(void)sys3(SYS_wait4, child, (long)(uintptr_t)&status, 0);
	if (*bp == 0x11223344 && *mp == 0x55667788)
		pass("fork brk/mmap COW");
	else
		fail("fork brk/mmap COW", "parent mapping changed");
	(void)sys2(SYS_munmap, map, 0x2000);
}

static void test_map_shared_visibility(void) {
	long map = sys6(SYS_mmap, 0, 0x1000, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (map <= 0) {
		skip("MAP_SHARED fork visibility", "mmap failed");
		return;
	}
	volatile int *p = (volatile int *)(uintptr_t)map;
	*p = 7;
	long child = sys0(SYS_fork);
	if (child == 0) {
		*p = 99;
		sys1(SYS_exit, 0);
	}
	int status = 0;
	(void)sys3(SYS_wait4, child, (long)(uintptr_t)&status, 0);
	if (*p == 99) pass("MAP_SHARED fork visibility");
	else fail("MAP_SHARED fork visibility", "child write not visible");
	(void)sys2(SYS_munmap, map, 0x1000);
}

static void test_vfork_exit_order(void) {
	long child = sys0(SYS_vfork);
	if (child == 0)
		sys1(SYS_exit, 17);
	int status = 0;
	long waited = sys3(SYS_wait4, child, (long)(uintptr_t)&status, 0);
	if (child > 0 && waited == child && status == (17 << 8))
		pass("vfork parent release on exit");
	else
		fail("vfork parent release on exit", "ordering/status mismatch");
}

static void test_fork_stress(void) {
	int ok = 1;
	for (int i = 0; i < 8; i++) {
		long pid = sys0(SYS_fork);
		if (pid < 0) {
			uwrite_errno("  stress fork rc=0x", pid);
			ok = 0;
			break;
		}
		if (pid == 0) sys1(SYS_exit, (long)i);
		int st = 0;
		if (sys3(SYS_wait4, pid, (long)(uintptr_t)&st, 0) != pid) ok = 0;
	}
	if (ok) pass("fork stress 8x");
	else fail("fork stress 8x", "fork/wait chain failed");
}

static void test_nested_fork(void) {
	long child = sys0(SYS_fork);
	if (child < 0) { fail("nested fork", "first fork failed"); return; }
	if (child == 0) {
		long grandchild = sys0(SYS_fork);
		if (grandchild < 0) sys1(SYS_exit, 90);
		if (grandchild == 0) sys1(SYS_exit, 31);
		int gst = 0;
		long gw = sys3(SYS_wait4, grandchild, (long)(uintptr_t)&gst, 0);
		sys1(SYS_exit, (gw == grandchild && gst == (31 << 8)) ? 0 : 91);
	}
	int st = 0;
	long w = sys3(SYS_wait4, child, (long)(uintptr_t)&st, 0);
	if (w == child && st == 0) pass("nested fork/wait");
	else fail("nested fork/wait", "grandchild lifecycle failed");
}

static void test_fork_stack_cow(void) {
	volatile unsigned long stack_words[1024];
	for (int i = 0; i < 1024; i++) stack_words[i] = 0x10000000UL + (unsigned long)i;
	long child = sys0(SYS_fork);
	if (child < 0) { fail("fork stack COW", "fork failed"); return; }
	if (child == 0) {
		for (int i = 0; i < 1024; i += 17) stack_words[i] ^= 0xffffffffUL;
		sys1(SYS_exit, 0);
	}
	int st = 0;
	(void)sys3(SYS_wait4, child, (long)(uintptr_t)&st, 0);
	int ok = 1;
	for (int i = 0; i < 1024; i++)
		if (stack_words[i] != 0x10000000UL + (unsigned long)i) { ok = 0; break; }
	if (ok) pass("fork stack COW");
	else fail("fork stack COW", "parent stack changed");
}

static void test_fork_large_mmap_cow(void) {
	const long sz = 4L * 1024 * 1024;
	long map = sys6(SYS_mmap, 0, sz, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map <= 0) { skip("fork large mmap COW", "mmap failed"); return; }
	volatile int *first = (volatile int *)(uintptr_t)map;
	volatile int *last = (volatile int *)(uintptr_t)(map + sz - 4096);
	*first = 0x1122;
	*last = 0x3344;
	long child = sys0(SYS_fork);
	if (child < 0) {
		fail("fork large mmap COW", "fork failed");
		(void)sys2(SYS_munmap, map, sz);
		return;
	}
	if (child == 0) {
		*first = 1;
		*last = 2;
		sys1(SYS_exit, 0);
	}
	int st = 0;
	(void)sys3(SYS_wait4, child, (long)(uintptr_t)&st, 0);
	if (*first == 0x1122 && *last == 0x3344) pass("fork large mmap COW");
	else fail("fork large mmap COW", "parent mapping changed");
	(void)sys2(SYS_munmap, map, sz);
}

static void test_wait_echild(void) {
	int st = 0;
	long rc = sys3(SYS_wait4, -1, (long)(uintptr_t)&st, 1);
	if (rc == -ECHILD) pass("wait4 ECHILD");
	else fail("wait4 ECHILD", "unexpected result");
}

static void test_stack_alignment(void) {
	uintptr_t sp;
	__asm__ volatile ("mov %%rsp, %0" : "=r"(sp));
	/* Inside a called function RSP≡8 (mod 16); aligned for the next call when (rsp+8)%16==0. */
	if (((sp + 8) & 0xF) == 0) pass("stack 16-byte aligned");
	else {
		fail("stack 16-byte aligned", "misaligned RSP");
		uwrite_hex64("  rsp=0x", (unsigned long long)sp);
		uwrite_hex64("  (rsp+8)&f=0x", (unsigned long long)((sp + 8) & 0xF));
	}
}

static void test_gettid(void) {
	long a = sys0(SYS_gettid);
	long b = sys0(SYS_getpid);
	if (a > 0) pass("gettid");
	else fail("gettid", "bad value");
	if (a == b) pass("gettid==getpid (single-thread)");
	else skip("gettid==getpid", "may differ with threads");
}

struct clone3_args {
	uint64_t flags;
	uint64_t pidfd;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t exit_signal;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t tls;
	uint64_t set_tid;
	uint64_t cgroup;
};

static void test_clone3_thread(void) {
	static volatile int thread_done;
	static volatile int thread_ok;
	enum { CHILD_STK = 65536 };
	/* mmap stack avoids overlapping the process stack slot (clone3 stack copy heuristics). */
	long stk = sys6(SYS_mmap, 0, CHILD_STK, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stk < 0) {
		skip("clone3 thread", "mmap child stack failed");
		uwrite_hex64("  rc=0x", (unsigned long long)stk);
		return;
	}
	/* Linux clone3: stack = lowest address; kernel sets RSP = stack+size. */
	uintptr_t stack_lo = (uintptr_t)stk;
	stack_lo = (stack_lo + 0xFULL) & ~(uintptr_t)0xFULL;
	struct clone3_args cl = { 0 };
	cl.flags = 0x00000100ULL;
	cl.stack = stack_lo;
	cl.stack_size = CHILD_STK - (stack_lo - (uintptr_t)stk);
	long tid = sys2(SYS_clone3, (long)(uintptr_t)&cl, (long)sizeof(cl));
	if (tid < 0) {
		skip("clone3 thread", "clone3 failed");
		uwrite_hex64("  rc=0x", (unsigned long long)tid);
		return;
	}
	if (tid == 0) {
		thread_ok = 1;
		thread_done = 1;
		sys1(SYS_exit, 0);
	}
	for (int spin = 0; spin < 5000 && !thread_done; spin++) {
		struct timespec_h ts = { 0, 1000000L };
		(void)sys2(SYS_nanosleep, (long)(uintptr_t)&ts, 0);
	}
	if (thread_ok && thread_done) pass("clone3 thread");
	else {
		fail("clone3 thread", "child did not run");
		uwrite_hex64("  done=", (unsigned long long)thread_done);
		uwrite_hex64("  ok=", (unsigned long long)thread_ok);
	}
	(void)sys2(SYS_munmap, stk, CHILD_STK);
}

static void test_open_read(void) {
	long fd = sys2(SYS_open, (long)(uintptr_t)"/usr/sbin/axon-harness", O_RDONLY);
	if (fd >= 0) {
		char buf[4];
		long n = sys3(SYS_read, fd, (long)(uintptr_t)buf, 4);
		sys1(SYS_close, fd);
		if (n == 4 && buf[0] == 0x7f && buf[1] == 'E') pass("open/read ELF magic");
		else fail("open/read ELF magic", "bad header");
	} else skip("open/read self", "not installed yet");
}

static void test_execve_missing_dynamic_loader(void) {
	const char *argv[] = { "/lib/no-such-ld-linux-x86-64.so.2", 0 };
	const char *envp[] = { 0 };
	long r = sys3(SYS_execve, (long)(uintptr_t)argv[0],
		(long)(uintptr_t)argv, (long)(uintptr_t)envp);
	if (r == (long)-ENOENT) pass("execve missing dynamic loader");
	else {
		fail("execve missing dynamic loader", "unexpected errno");
		uwrite_hex64("  rc=0x", (unsigned long long)r);
	}
}

static void test_execve_enoent(void) {
	static volatile unsigned long preserved;
	unsigned long stack_cookie = 0x1234abcdUL;
	preserved = 0xfeedbeefUL;
	const char *argv[] = { "/no/such/file", 0 };
	const char *envp[] = { 0 };
	long r = sys3(SYS_execve, (long)(uintptr_t)argv[0], (long)(uintptr_t)argv, (long)(uintptr_t)envp);
	if (r == (long)-ENOENT && preserved == 0xfeedbeefUL &&
	    stack_cookie == 0x1234abcdUL)
		pass("failed exec preserves image");
	else
		fail("failed exec preserves image", "errno or memory changed");
}

static void run_one(const char *name, void (*fn)(void), const char *flt) {
	if (!filter_match(name, flt)) return;
	if (g_verbose) { uwrite("RUN  "); uwrite(name); uwrite("\n"); }
	fn();
}

int main(int argc, char **argv) {
	const char *flt = 0;
	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "-v")) {
			g_verbose = 1;
		} else if (streq(argv[i], "-q")) {
			g_verbose = 0;
		} else if (argv[i][0] != '-') {
			flt = argv[i];
		}
	}
	uwrite("AxonOS axon-harness\n");
	run_one("basic", test_basic_syscalls, flt);
	run_one("brk", test_brk_grow, flt);
	run_one("mmap", test_mmap_anon, flt);
	run_one("mmap-large", test_mmap_large, flt);
	run_one("munmap-pte", test_munmap_removes_pte, flt);
	run_one("mprotect", test_mprotect, flt);
	run_one("fork-ro-mprotect-cow", test_fork_readonly_mprotect_cow, flt);
	run_one("fork", test_fork_basic, flt);
	run_one("pipe-eof", test_pipe_eof_after_fork, flt);
	run_one("parent-link", test_parent_child_linkage, flt);
	run_one("wait-zombie", test_wait_wnohang_zombie, flt);
	run_one("isolation", test_fork_memory_isolation, flt);
	run_one("fork-cow", test_fork_brk_mmap_cow, flt);
	run_one("map-shared", test_map_shared_visibility, flt);
	run_one("vfork", test_vfork_exit_order, flt);
	run_one("fork-stress", test_fork_stress, flt);
	run_one("nested-fork", test_nested_fork, flt);
	run_one("fork-stack-cow", test_fork_stack_cow, flt);
	run_one("fork-large-cow", test_fork_large_mmap_cow, flt);
	run_one("wait-echild", test_wait_echild, flt);
	run_one("stack", test_stack_alignment, flt);
	run_one("tid", test_gettid, flt);
	run_one("clone3", test_clone3_thread, flt);
	run_one("open", test_open_read, flt);
	run_one("execve-enoent", test_execve_enoent, flt);
	run_one("execve-dyn", test_execve_missing_dynamic_loader, flt);
	uwrite("\nSummary: PASS=");
	/* minimal decimal print */
	{
		char n[16]; int v = g_pass, i = 0;
		if (!v) n[i++] = '0';
		while (v) { n[i++] = (char)('0' + (v % 10)); v /= 10; }
		while (i--) sys3(SYS_write, 1, (long)(uintptr_t)&n[i], 1);
	}
	uwrite(" FAIL=");
	{
		char n[16]; int v = g_fail, i = 0;
		if (!v) n[i++] = '0';
		while (v) { n[i++] = (char)('0' + (v % 10)); v /= 10; }
		while (i--) sys3(SYS_write, 1, (long)(uintptr_t)&n[i], 1);
	}
	uwrite("\n");
	return g_fail ? 1 : 0;
}
