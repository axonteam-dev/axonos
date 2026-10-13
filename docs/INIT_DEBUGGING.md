# Init runtime fixes and manual boot checks

## Boot-info copy overwriting initfs

The guest's compressed block CRC was `1e7b6cd7`, while the local image and the
image extracted from the built ISO both had `9223f76f`. That establishes a
difference in the guest input, not an Adler32 workaround or a libc/rseq bug.

`preserve_multiboot_info()` previously copied GRUB's tags to the fixed physical
address `0x01000000` **before** relocating the initfs module. A 60 MiB module
loaded near 1 MiB covers this address. The copy therefore overwrites compressed
file data, and the later initfs relocation preserves the corrupted bytes.
Checking only the `hsqs` magic cannot detect that interior corruption.

The copy now uses an aligned 2 MiB buffer in the stub's own BSS. GRUB reserves
that buffer through the ELF segment's `p_memsz`; it is not an unreserved scratch
address. The actual built buffer at `[0x822f000, 0x842f000)` was checked to lie
entirely inside a PT_LOAD memory range (addresses vary with the build).
`tools/test-boot-info-preservation.py` demonstrates the old collision in a host
low-memory fixture and verifies that the new copy leaves every module byte
unchanged, including overlapping boot-info copies. It starts no VM.

The bootstrap stack is also increased from 16 KiB to 128 KiB: the early
SquashFS metadata buffer and nested miniz decoder alone exceed 16 KiB before
scheduled kernel stacks are available. Manual guest validation is still needed.

## Init task and pipe lifecycle

The init loader must restore the kernel caller's original mm **before** making
the init task runnable. The compressed boot stub's stack is around 128 MiB,
inside the user mmap window; keeping init's mm on the kernel caller lets ld.so
unmap or replace that stack. Switching back after a fatal init fault then raises
a double fault in `context_switch_with_prev`. Fatal task teardown now switches
to the permanent kernel root, not an arbitrary other process's mm.

The systemd executable is also recognized as a PID 1 candidate. Exception entry
clears DF and aligns the stack before calling C, preserving the interrupt frame.
Fault lookup includes inherited mm-scoped VMAs, rather than only tid records.

Pipe readers and writers publish their waiter and mark themselves blocked under
the pipe lock. Previously a peer could wake them between unlock and block, after
which the reader/writer would sleep forever. This can stall OpenRC's dependency
generation pipeline. Writes with no reader now fail before modifying the ring.

Host-only verification:

```bash
make test
./compile -j4
```

No automated guest boot is needed for these host regressions. Boot the rebuilt
`build/axonos.iso` manually using both existing GRUB entries. Check that systemd
runs as PID 1 without a double fault and OpenRC advances beyond
`Caching service dependencies` through the boot/default runlevels to a console.

These checks still require a real guest run; a successful build or host test
does not prove that systemd's full Linux ABI requirements are satisfied.
If the initial systemd page fault remains, capture the full output including
`fs-read:`, `squashfs:`, `zlib-inflate:`, `filemap-fault:`, `fault-vma:` and
`user-pf-fatal:`. These identify the backing
library, file offset, permissions and fault address without guessing from a
build-specific RIP. For an OpenRC stall, capture a debug build's output:

```bash
./compile -j4 CFLAGS_EXTRA=-DDEVEL_DEBUG=1
```

Keep `build/axonos.payload.elf` from that same build for symbolization. The earlier
`AXON_BOOT_OPENRC_EXEC` smoke-test marker only means exec loading began; it is
not evidence that OpenRC reached a runlevel or a console.

SquashFS metadata/data blocks are now decoded under the kernel direct map:
the borrowed image pointer denotes physical identity memory, not a process VA.
`tools/test-squashfs-read.py` reads libc (including the reported `0xca000`
offset), systemd and OpenRC from the actual local initfs using the kernel reader
and miniz, with a mock CR3 guard that asserts every decode uses the kernel root.
It also verifies restoration of the caller root on read failure. This host test
does not reproduce real guest page tables or prove the guest EIO is resolved.

## Deeper analysis of the reported libc block failure

The guest reports a Deflate failure on libc block 6: compressed position
`0xef0e6f`, length 67,458, consumed 48,556 and produced 91,919 of 131,072
bytes. Status `-1` is not the Adler32 mismatch status (`-2`). The same block
from the current initfs has CRC32 `9223f76f` and SHA256
`f6ce2b1b5c0fcee7e893031f4816697322b22c0342b7f88ef408852e146c910d`.
Both Python zlib and the actual linked kernel miniz/string/heap objects decode
it successfully. Repeat that stronger host check after rebuilding:

```bash
python3 tools/test-squashfs-read.py --kernel-objects build
```

This rules out a malformed local block and several host/kernel implementation
differences, but does not establish where the guest's memory/state differs.
On failure the kernel now prints the compressed input CRC and miniz coroutine
state. A different CRC from the same build's host result proves different input
bytes. A matching CRC shifts attention to decoder state, mappings, stack or
concurrent memory corruption. Do not disable checksum/error checks to boot.

A separate confirmed ABI bug was compiler-generated SSE in the syscall path
(484 SIMD-register instructions in the previous object). Syscall/exception entry
did not preserve that use of userspace SIMD state; task-switch XSAVE is not a
substitute for preserving it across a syscall. Kernel C now uses
`-mgeneral-regs-only`, TSC frequency logging uses integer arithmetic, and the
unused floating-point `ftos` implementation is removed. `make test` checks the
actual flags at `-O2`; the rebuilt kernel payload was also disassembled and
checked for SIMD-register instructions. Explicit FPU context-save/restore
assembly remains enabled for userspace.

## OpenRC dependency-generator stall

The image's OpenRC executable uses `/lib/ld-musl-x86_64.so.1`; `/usr/bin/sh`
is a symlink to static BusyBox. OpenRC 0.54 runs `/lib/rc/sh/gendepends.sh`
through musl `popen()`. Musl creates the output pipe and a separate CLOEXEC
error pipe, starts `/bin/sh` using `clone(CLONE_VM|CLONE_VFORK|SIGCHLD)`, and
waits for EOF on the error pipe after exec. OpenRC then consumes generator
output and calls `pclose()/waitpid()`.

Detailed lifecycle/syscall logs are now opt-in: append `init.trace=1` to the
kernel command line in GRUB (press `e`, edit the `multiboot2` line, boot with
Ctrl-X). Before service startup, `init-spawn:` allows 32 parent and 20
descendant records; after startup it allows 16 records per PID. This avoids
spending the entire allowance on the dependency generator. Up to three
`init-pipe:` writer snapshots are also available.
The expected startup sequence is `spawn-clone`, `vfork-wait`, `child-enter`,
`exec-start`, `exec-ready`, `vfork-release`, `vfork-resume`, then `pipe-eof` on
the musl error pipe. Scheduling can interleave the records.

`pipe-read-wait` on the output pipe names its live writer descriptors in the
following `init-pipe:` lines. No writer descriptors with two remaining endpoint
objects points to a reference leak; a blocked writer names the task to inspect.
`waitpid-block` identifies a child wait instead of a pipe wait. Thread states
are READY=0, RUNNING=1, BLOCKED=2, TERMINATED=3 and SLEEPING=4.

These messages diagnose the remaining hang. They do not treat a partial boot
as success, fabricate EOF, or bypass dependency generation.

Once `Caching service dependencies` shows `[ ok ]`, generation and `pclose()`
have completed. The next trace is armed when OpenRC opens the generated
`/run/openrc/deptree` for reading: `openrc-stage:` marks this point and up to 24
paired `openrc-step: enter/leave` records identify subsequent syscalls. An enter
without its matching leave can identify a blocking syscall; the syscall number
and saved user RIP identify the path to investigate. A completed read followed
by no further syscalls can instead indicate a userspace loop.

`rt_sigreturn` also had a control-slot mismatch for IRQ-delivered signals:
the assembly return path consumes RCX as RIP and R11 as RFLAGS, but the restore
code filled them from interrupted general-purpose RCX/R11. It now uses the
ucontext's RIP/EFLAGS fields. `tools/test-sigreturn-control.py` exercises both
IRQ-style frames (different RCX/RIP and R11/EFLAGS) and syscall-style frames.
This is a verified return-path correction, not proof that the remaining
OpenRC stall is fixed.

## Current service-start checks (OpenRC and systemd)

The later guest logs show child exit teardown completing, parents becoming
READY, and `wait4` returning the expected child PID. They do not establish an
exit teardown failure. A separate wait4 scan-before-block wakeup window was
fixed by publishing BLOCKED and rechecking waitable zombies before yielding;
`tools/test-wait4-wakeup.py` covers the deterministic interleavings.

cgroupfs previously rejected writing PID `0` to `cgroup.procs`. Linux defines
this as moving the calling process, and OpenRC explicitly writes `0`. It now
resolves the caller and performs removal/insertion with the cgroup lock held
through the whole migration, keeping ancestor counters and membership lists
consistent. Malformed/overflowed PIDs, removed destinations, and full
destinations fail without removing the process from its old group.
`tools/test-cgroup-migration.py` exercises the actual parser and migration code.
This correction is shared infrastructure, not evidence of a complete systemd
boot or full Linux cgroup-controller compatibility.

Default diagnostics are compact:

- `init-read:` records the real path, file offsets, byte count, and EOF/error.
  Byte-at-a-time reads are sampled at powers of two, with a total 128-record
  cap; they are not themselves proof of a loop. Successful reads now go to the
  kernel log ring only unless `init.trace=1` is enabled. Errors still reach the
  console.
- `init-wait:` pairs entry/return of waits for OpenRC services and systemd PID 1.
  These routine records likewise stay in the ring unless verbose tracing is on.
- `init-stall:` is a snapshot after five seconds without syscall progress,
  limited to three reports until the task makes progress again. It is produced
  by a BSP kernel monitor, so exhausted per-syscall log budgets cannot hide the
  last syscall. `active=1` means the syscall has not returned; `active=0` means
  the last syscall returned. `last-read` is context, not necessarily the file
  involved in the current wait. Legitimate idle/event waits can produce these
  records too; they are diagnostic snapshots, not automatic failure verdicts.
  Descendant matching now follows up to 16 parents, including the full
  OpenRC → openrc-run → shell → ifup → udhcpc → lease hook → ip chain.
  Normal fork children are registered before publication too: `last-n=-1`
  means that the monitored child has not entered a syscall yet.
  `init-wait-child:` also snapshots the exact requested child of a waitpid
  issuer, regardless of ancestry or whether that child entered a syscall. It
  includes thread state, parent/waiter slots and exit status; `state=-1` means
  no matching thread was found, not that the child successfully exited.

Verbose boot tracing writes hundreds of lines synchronously to the console and
can materially slow boot. Leave `init.trace=1` off when measuring performance.
`tools/test-init-trace.py` checks token parsing and bounded read sampling.

Boot both ISO entries manually and capture `init-read:`, `init-wait:`, and
`init-stall:` if either still stops. Optional systemd kmod/BPF warnings are not
by themselves a blocking error. Do not change the reported kernel version or
fake successful optional-feature support to silence them.

## Confirmed cgroup.events EOF stall

The later OpenRC trace identifies `/sys/fs/cgroup/openrc.dmesg/cgroup.events`:
the shell reads it byte-by-byte through fd 0, with `ppoll` before each read.
After consuming the snapshot, it stays inside syscall 271 (`ppoll`). The generic
file readiness path incorrectly required `pos < size`. Linux regular-file
readiness includes EOF: a read that immediately returns zero does not block.
The fallback now reports the requested IN/OUT/RDNORM/WRNORM bits regardless of
position. `tools/test-poll-regular-eof.py` compiles the actual fallback and
compares it to host Linux poll/ppoll before, at and beyond EOF, on empty files
and on a directory.

The epoll translation separately conflated PRI with IN in both directions.
It now preserves them independently; `tools/test-epoll-priority.py` compares
the actual translation against Linux epoll on a pipe containing ordinary data.
That data must not be reported as a priority event.

cgroup.events now tracks populated transitions separately from ordinary
readability. A changed generation produces ERR/PRI readiness; reading from
offset zero refreshes the snapshot and acknowledges the generation. Moving
between groups does not spuriously notify a common ancestor whose populated
state remains unchanged. Membership changes and task entry/exit update the
generation under the cgroup lock. `tools/test-cgroup-events.py` covers fresh
rewinds, EOF readiness, priority changes and acknowledgement.

PID 1's inherited umask also previously started at zero. The bootstrap task now
uses Linux's initial 0022, kernel tasks inherit it, and user task creation keeps
an explicitly changed parent mask. This addresses the mechanism behind newly
generated world-writable files without special-casing systemd-generated units.

The reported systemd screen shows advancing reads of many unit files, not a
blocked syscall. Synchronously displaying these diagnostic records can dominate
boot time on the framebuffer console. Routine records are now ring-only by
default; the stall monitor remains on the console. These fixes require manual
boot verification of both entries and are not a claim of full Linux parity.

## Startup metadata work

Repeated SquashFS directory scans used to copy a whole cached metadata block
(up to 8192 bytes) for each small dirent/inode slice. The metadata stream reader
now copies only the requested slice on a cache hit, holding the direct-map
guard for the complete operation and restoring it on errors. A bounded
256-entry positive directory-entry cache avoids re-scanning immutable lower-fs
directories for hot names. It does not cache overlay paths or read/decode
failures, and mount-local storage prevents cross-image reuse.

`tools/test-squashfs-metadata-cache.py` checks actual copy volume: 1000 warm
8-byte reads copy 8000 bytes rather than approximately 8.2 MB. It also covers
cross-block reads, skipped bytes, failures, root restoration, repeated positive
lookups and uncached misses. This is an operation-count improvement, not a
measured guest boot-time claim. Compare the same guest's time to login after
rebuilding; leave verbose init tracing off.

## READY child while networking waits

The DHCP trace now shows a lease followed by udhcpc waiting for a live READY
shell child, not a dead child waiting to be reaped. The scheduler had a separate
accounting hole: `thread_schedule_prev_saved` charges only RUNNING outgoing
tasks, while sleep/block functions change the state before that callback. A
short sleep can also expire in the inline timeout scan before selection, making
the same uncharged task READY again and letting it win forever over a child
with a higher virtual runtime.

Sleep and current-task block paths now charge the same weighted dispatch unit
used by the existing CFS-like scheduler before changing state. External blocks,
idle tasks and repeated/idempotent blocks are not charged; the outgoing callback
does not double-charge blocked tasks. Timed blocking also rejects terminated
tasks rather than reviving them.

`tools/test-scheduler-block-accounting.py` exercises the actual sleep/block and
outgoing accounting functions with a modeled inline-expiry selection: the READY
child is selected after five dispatches instead of being permanently outranked.
This is not a full SMP/scheduler timing test or proof that the reported DHCP
stall is resolved. `init-wait-child:` now includes CPU binding, vfork state,
virtual runtime and saved kernel RIP to distinguish remaining eligibility
issues on manual retest.

A subsequent trace shows that the child's virtual runtime increases, with
`bound=-1` and `vfork=0`. That does not confirm complete scheduler starvation.
The displayed `rip` is the saved syscall return site, not a live instruction
sample, and `context.rip` is not populated by the context-switch assembly.
PIT and LAPIC ticks now record separate last user/kernel IRQ RIPs for user
tasks; `init-wait-child:` displays them as `irq-user` and `irq-kernel`. These
last-known samples may be stale, but can locate a userspace loop or kernel
path without changing syscall-return registers. Host sampling tests do not
substitute for a guest boot.

## Confirmed boot-time replacement of userspace configuration

The initfs contained the expected DHCP hook and an `sshd` passwd entry, but the
kernel boot code replaced both before PID 1. It truncated passwd to a single
root entry, rewrote group/shadow/gshadow, and unlinked/replaced the DHCP hook.
The replacement hook ran `while route del default gw 0.0.0.0 ...`; SIOCDELRT
always returned success, even after the first deletion. This explains the
missing hook phase messages, repeated short-lived route processes and the SSH
privilege-separation account error. Earlier READY/vruntime observations alone
did not identify this root cause.

Boot fallbacks for passwd/group/shadow/gshadow, NSS, fstab and the DHCP hook now
use `boot_seed_file_if_missing`: existing inodes are left unchanged, including
empty files and dangling symlinks. Only genuinely absent files are seeded;
fallback shadow/gshadow files are private and do not create passwordless root.
Packaged password hashes and group IDs are preserved.

SIOCDELRT and RTM_DELROUTE now share a checked default-route deletion helper:
an absent or nonmatching gateway returns ESRCH without mutation. Route dumps
stop advertising a default gateway after it is deleted; non-default deletion
does not accidentally clear the stored default. The fallback deletion loop
therefore terminates. Host regressions exercise file preservation and the
actual deletion helper. Guest boot remains necessary to verify DHCP and SSH.

## Complete signal-return register image

Separating the saved control RIP/RFLAGS from ucontext RCX/R11 was not sufficient
while the assembly still used RCX/R11 themselves to construct IRETQ: an
IRQ-delivered signal could return to the right instruction with corrupted
general-purpose RCX/R11. Ordinary SYSCALL is allowed to clobber them, but Linux
rt_sigreturn restores the entire interrupted register image.

The syscall epilogue now reserves a separate five-word IRETQ frame below the
live frame, preserving CALL alignment and restoring all 15 GPRs independently.
The per-task rt_sigreturn marker supplies interrupted RCX/R11 without replacing
the control RIP/RFLAGS. Pending signal delivery uses those restored GPRs when
constructing another ucontext. The stack_t members inside ucontext also now
use Linux's sp/flags/padding/size order. Host tests cover overlapping frame
movement, distinct IRQ RCX/RIP and R11/RFLAGS values, RAX, selectors, stack and
the unchanged normal-syscall register image. Guest validation is still needed.
