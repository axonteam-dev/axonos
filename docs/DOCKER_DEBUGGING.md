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
