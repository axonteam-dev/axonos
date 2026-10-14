# Docker loader checks

The reported Alpine `docker-engine 29.8.2-r0` daemon is a 98,731,592-byte
ET_DYN PIE with PT_INTERP `/lib/ld-musl-x86_64.so.1`. Its DT_RELASZ is
10,302,864 bytes (429,280 relative relocations), larger than the kernel's
2 MiB static relocation buffer limit.

The kernel incorrectly attempted the main executable's dynamic relocations
before entering musl, causing `elf: RELA/IRELATIVE apply failed`. Like Linux,
PT_INTERP executables now leave these relocations to the interpreter. This
also avoids calling their userspace IFUNC resolvers in kernel mode. The
existing no-interpreter/static path is unchanged; this is not a larger
allocation limit or suppressed loader failure.

`tools/test-elf-interpreter-relocations.py` compiles the real relocation
dispatch and verifies that an interpreted PIE with dockerd's table size
performs no kernel relocation reads/allocations/applications. It also checks
interpreted ET_EXEC and the retained static path. The Alpine binary was only
downloaded/extracted for read-only ELF inspection, never executed on the host.

Manual guest checks (no QEMU automation):

```sh
dockerd --version
dockerd --debug
```

The ELF correction does not establish working containers. Docker additionally
depends on namespaces, cgroups, mounts/storage drivers, networking and security
syscalls; unsupported features must fail honestly rather than fabricate
isolation. The separate APK ca-certificates/glib trigger ENOENT failures in the
reported installation are not proven to be caused by this relocation issue.

## Go runtime, signals and scheduling

The subsequent Ctrl-C fault occurs in Go's `runtime.sighandler` (the inspected
PIE's faulting virtual address matches the dump after subtracting its 4 MiB
load bias). A confirmed syscall-return bug replaced the SA_SIGINFO handler's
RDX/ucontext pointer with the interrupted futex's saved third argument. Signal
delivery now synchronizes handler RDI/RSI/RDX with the saved snapshot after
constructing the interrupted ucontext, so final register reconciliation cannot
overwrite the handler arguments. `test-siginfo-epilogue.py` executes that path.

The futex backend no longer ignores timeouts. It supports relative WAIT and
absolute WAIT_BITSET deadlines, bitset-selective wake, per-mm private keys and
physical backing keys for shared waits. The value is checked under the wake/
queue lock; blocking is published before dropping it. Wake, timeout, EINTR,
requeue and task reaping remove the correct waiter, avoiding stale scheduler
TIDs waking a later task. Unsupported PI operations remain ENOSYS.

Private expedited membarrier QUERY/REGISTER/EXECUTE is supported with a real
mfence under the scheduler's current userspace-BSP-only policy. Registration
belongs to the mm, not the thread. Global/core-sync commands are not advertised.
Cross-CPU rendezvous is required before enabling userspace execution on APs.

Raw sched_getaffinity now returns the copied byte count and the actual available
userspace CPU mask, not zero and the physical SMP mask. It makes one bounded
mask copy rather than one kernel uaccess operation per padding byte. Go thus
sizes GOMAXPROCS according to available CPUs. AP-only masks are rejected.

Scheduler slot lookup and targeted block/wake paths now use O(1) table indexing
with TID validation instead of full table scans. Group operations and runnable
selection still scan where needed; IRQ quantum and timeout intervals are not
arbitrarily reduced. Host tests cover these operation-count and lifecycle
properties, not a claim of maximum guest throughput or complete Docker support.
