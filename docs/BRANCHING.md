# Branch plan

This is the branch layout for AxonOS server development. Not gospel — update it when reality disagrees.

## Trunk

```
main      stable. boots in QEMU, builds clean, no 400MB blobs in git
develop   integration branch. features merge here first
```

`main` only moves forward from `develop` when someone has actually booted the result and nothing obvious is on fire.

Release branches (`release/0.2` etc.) only when we need to freeze something. We're not there yet.

## How features are named

```
feature/<subsystem>-<what>
feature/<subsystem>-<what>/<dev>-<task>
fix/<subsystem>-<what>
refactor/<subsystem>-<what>
experiment/<whatever>     # does not merge. playground.
```

Examples that make sense here:
- `feature/net-loopback`
- `feature/net-loopback/alice-bind-fix`
- `fix/disk-ahci-timeout`
- `refactor/syscall-split-sockets`

Examples that don't:
- `feature/stuff`
- `miha-changes`
- `wip`

## Phase 1 — make it a real server

These are the branches that matter first. Everything else can wait.

### `feature/headless-boot`

Skip fbcon and boot logo when booting with serial console. Server in a rack doesn't have a monitor.

Touches: `core/entry/kernel.c`, maybe `drv/video/`

No dependencies. Good first branch for someone new.

### `feature/disk-irq-io`

AHCI and NVMe currently poll. Works in QEMU, won't scale. Move block I/O to interrupt-driven path.

Touches: `drv/disk/`, `cpu/thread/iothread.c`

Blocks: everything storage-related below.

### `feature/ext2-write` → `feature/ext4-fs`

ext2 is read-only. FAT32 is read-only. Root is ramfs — dies on reboot. Need a writable persistent FS.

Start with making ext2 write-capable (smaller diff), then ext4 if ext2 gets too painful.

Touches: `fs/virt/ext2.c` or new `fs/ext4/`

Needs: `feature/disk-irq-io` at minimum

### `feature/net-loopback`

Right now `127.0.0.1` returns `ECONNREFUSED`. That's... not great for an OS that wants to run sshd or nginx.

Touches: `syscall/net/`, socket cases in `syscall/dispatch/syscall_dispatch.c`

No hard dependencies, but socket changes mean coordinate with whoever else is in syscall land.

### `feature/virtio-net` / `feature/virtio-blk`

e1000 works in QEMU but cloud VMs expect virtio. New drivers under `drv/`.

Needs: `drv/bus/pci.c` (already there)

Can be two branches, two people, minimal overlap.

## Phase 2 — run actual daemons

### `feature/net-epoll`

A lot of server software uses epoll. We don't have it. Stub returns ENOSYS.

Touches: `syscall/dispatch/syscall_dispatch.c` mostly

### `feature/syscall-flock`

Currently a no-op. Package managers and databases care about this.

Touches: `syscall/dispatch/syscall_dispatch.c`

### `feature/net-inotify`

Same story. Daemons watch files. We pretend we don't know what that means.

Touches: `syscall/dispatch/syscall_dispatch.c`, maybe `fs/`

### `feature/sec-crypto-random`

`getrandom()` is a PRNG. Password hashing is djb2. Fine for a demo, not for SSH or TLS.

Touches: `syscall/dispatch/`, `core/user.c`

## Phase 3 — isolation

Only start these once Phase 1–2 things actually work. No point in cgroups if you can't persist data or bind localhost.

### `feature/cgroups-v1`
### `feature/namespaces-pid`
### `feature/namespaces-net`
### `feature/namespaces-mount`

All new code, mostly `core/`. Net namespace depends on loopback existing for real.

## Phase 4 — cloud / hypervisor

Longer term. Don't let anyone spend three weeks on KVM while loopback is still broken.

### `feature/virtio-pci` — shared virtio transport
### `feature/kvm-hypervisor` — actually running VMs
### `feature/guest-virtio-full` — wire up net + blk virtio as guest

## Branches we deliberately keep separate

Desktop and dev-QEMU comfort stuff. Fine to work on, not on the server track:

| Branch | What's in it |
|--------|-------------|
| `feature/drv-video-*` | fbcon, VMware SVGA, Cirrus, boot logo |
| `feature/drv-input-ps2` | keyboard/mouse |
| `feature/desktop-extras` | tetris, snake, whatever else |

Merge to `develop` only if it doesn't bloat the boot path for headless. Or keep a `desktop` fork. TBD.

## Dependency graph (the part people ignore then regret)

```
boot + mem + smp
    └── threading
            └── syscalls
                    └── exec/initfs → userspace actually runs

pci
    └── disk drivers
            └── writable FS

e1000 (or virtio-net)
    └── dhcp/dns/tcp
            └── socket syscalls
                    └── loopback (currently missing)
                            └── localhost daemons actually work
```

Critical path to "it's a server OS":
1. headless boot
2. disk irq + writable fs
3. loopback
4. epoll + flock
5. real random + passwords

Everything else is gravy or desktop fluff.

## Who owns what

Not formal ownership, just "talk to this person before rewriting their area."

| Area | Directory | Pain level |
|------|-----------|------------|
| Syscalls | `syscall/` | extreme — coordinate |
| Net stack | `net/`, `drv/net/` | high |
| Block storage | `drv/disk/` | high |
| FS / VFS | `fs/` | medium |
| SMP / sched | `cpu/` | medium — breaks everything if wrong |
| Boot | `boot/` | low — fairly isolated |
| Video/input | `drv/video/`, `drv/input/` | low priority for servers |

## Merge rules (informal but enforced by peer pressure)

1. One feature per branch. Don't sneak ext4 changes into a loopback PR.
2. `net/` backend changes and socket syscall changes go in the **same** PR. Splitting them guarantees a broken middle state.
3. Branch must build: `make clean && make iso`
4. Say what you tested. "Works on my machine" with no details is weak.
5. Delete feature branches after merge. Nobody needs 40 stale `feature/net-loopback/bob-attempt-3` branches in the remote.

## Creating a new feature branch

```bash
git checkout develop
git pull origin develop
git checkout -b feature/net-loopback
git push -u origin feature/net-loopback
```

Then each person branches off that:

```bash
git checkout -b feature/net-loopback/yourname-whatever
```

PR flow: `yourname-whatever` → `feature/net-loopback` → `develop` → `main`

Not: `yourname-whatever` → `main`. We learned that one already.
