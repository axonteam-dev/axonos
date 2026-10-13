# systemd startup compatibility

The systemd 257 startup warnings have separate causes. Do not suppress the
log level or change uname's release merely to make them disappear.

## Implemented corrections

- `/proc/sys/fs/file-max` is a root-writable global open-file-description
  limit, backed by actual accounting. Duplicate references are not counted
  again; the final release removes the count. Unprivileged new descriptions
  above the limit fail with ENFILE; privileged/kernel opens can exceed it to
  allow recovery, as with Linux's privileged file allocation.
- `/proc/sys/fs/nr_open` is present, readable, writable and listed in its
  directory. Values below 64 or above the physical fd-table capacity return
  EINVAL, with no state change. RLIMIT_NOFILE hard-limit changes above this
  ceiling return EPERM.
- Process and thread fd tables now both have 2048 actual slots. The previous
  advertised hard limit of 1048576 did not match the 1024-entry tables. The
  default soft limit remains 1024; the hard ceiling reflects real capacity.
  Ordinary fd allocation also observes the process soft limit. systemd's
  INT_MAX/rounding/halving probe reaches this real ceiling without falsely
  claiming that billions of descriptors can be allocated.
- File-limit sysctl writes validate decimal input, overflow, permissions and
  supported ranges; unsupported/malformed writes are not generic EIO failures.
- The warning is **kbrequest**, not keyring: systemd uses
  `ioctl(KDSIGACCEPT, SIGWINCH)` on its keyboard console. Registration now
  records the caller's process identity and signal. Alt-Up delivers that signal
  to the live registered process, rather than just returning success. Invalid
  signals, SIGKILL and unprivileged registration are rejected.

Host regressions cover sysctl parsing, state changes, object/reference
accounting, EMFILE/ENFILE, systemd's halving loop, and kbrequest registration
and signal dispatch. They do not replace a guest boot or keyboard test.

## Optional runtime libraries and remaining kernel features

The rootfs overlay now includes authenticated Debian Trixie `libkmod2` and
`libbpf1` runtime files and dependencies. Reproduce with:

```sh
python3 tools/install-openssh-rootfs.py "$HOME/rootfs" \
    --extra-package libkmod2 --extra-package libbpf1
~/compilerootfs.sh
./compile -j4 iso
```

Repository signatures and package SHA256 checks are retained. Existing account,
PAM and SSH policy files are not overwritten. Extra-package provenance is in
`usr/share/axonos/runtime-extra-packages.json` inside the overlay.

Installing these libraries fixes missing userspace dependencies; it does **not**
implement Linux module loading, the BPF verifier/interpreter, cgroup-BPF hooks
or autofs. Those capabilities may still produce unsupported-feature messages.
AxonOS continues to report its own `4.1.0-axonos` release; systemd's Linux 5.4
baseline warning remains until there is a justified compatibility baseline,
not just a different version string. Full Linux parity is not claimed.

## PID 1 waiting in waitid

The next guest trace stopped in syscall 247 (`waitid`), not in the BPF probe.
Its scan/arm/block sequence still had the exit-before-block lost-wakeup window
already addressed in wait4. It now publishes BLOCKED, rechecks both thread
zombies and process-only zombies (or the disappearance of all matching children),
and yields only if it remains blocked. The process selection is recorded for
the monitor, which can now show the child for P_ALL/P_PGID without relinking
processes as a side effect of observation.

WNOHANG with no event clears siginfo, returned events include the child's UID,
and invalid P_PID/P_PGID identifiers are rejected. The waitid regression
executes the actual dispatch code, including the simulated exit-before-block
race and WNOWAIT behavior. A guest retest is still needed: a live helper can
also legitimately keep PID 1 in a blocking waitid.
