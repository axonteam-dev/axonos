If you're here, you probably already know this is a kernel, not a web app. Good. Less time explaining what a page fault is. xd

Before you write code: build it. Boot it. Break it. Fix it. Then open a PR.

```bash
make archive   # pulls initfs on first run — needs network
make iso       # use sudo if iso/boot is root-owned from an old build
make run       # QEMU, needs ../disk.img — run make disk once if missing
```

If `make` left files owned by root:

```bash
sudo ./docs/fix_permissions.sh
```

If your change doesn't survive `make clean && make iso`, it's not ready. We dont have CI yet (working on it), so youre the CI for now.

**Don't commit build output.** `build/`, `iso/boot/initfs.cpio`, `iso/boot/axonos.elf` stay local. Already in `.gitignore`. If you accidentally add a 400MB iso again, well all have a bad day.

Read [docs/BRANCHING.md](docs/BRANCHING.md) for the full picture. Short version:

- `main` — boots, doesn't embarrass us
- `develop` — where features land before they touch main
- `feature/<name>` — one feature, one branch
- `feature/<name>/<yourname>-<task>` — your actual work

Don't push directly to `main`. Seriously. Even if you have access.

### Working on a feature with other people

The shared `feature/foo` branch is a merge target, not a group chat. Nobody should be force-pushing WIP into it at 2am.

Do this instead:

```bash
git fetch origin
git checkout feature/net-loopback
git pull --rebase origin feature/net-loopback
git checkout -b feature/net-loopback/yourname-bind-localhost
# ... work ...
git push -u origin feature/net-loopback/yourname-bind-localhost
# open PR into feature/net-loopback, not main
```

Keep PRs small. Two days max. If your branch is a week old, rebase will hurt and it'll be your fault.

Write messages like you're explaining to a teammate what you did:

Good:
```
net: make 127.0.0.1 actually work

bind() was returning ECONNREFUSED for loopback because we
literally didn't have one. Added a fake lo device in net/.
```

Bad:
```
feat: implement comprehensive loopback networking subsystem
```

One logical change per commit when you can. Squash fixups before merge.

## Pull requests

- Link the issue if there is one
- Say how you tested it (`make run`, ping something, mounted a disk — whatever applies)
- If you didn't test on real hardware, say so. QEMU-only is fine, just be honest
- Screenshots only if it's a visual thing. This is mostly a headless server OS. Nobody needs a photo of dmesg

Review isn't about style nitpicks. Does it work? Does it break SMP? Does it leak pages? That's what we're looking at.

Match what's already there. See [docs/CODING_STYLE.md](docs/CODING_STYLE.md) — GNU layout, return type on the same line as the function name (`void foo()`, not split across lines).

- Kernel C: no libc, no floating point, check return values
- Data structures before clever control flow; max ~3 indentation levels in new code
- New syscalls: prefer a new file under `syscall/dispatch/`; avoid growing the monolithic switch when you can split cleanly
- New drivers under `drv/`, new FS code under `fs/`
- Headers in `inc/`
- Don't change syscall ABI or errno values without explicit reason and tests

If you add a `TODO`, make it specific. `TODO: fix later` is not a TODO, it's a confession.

AxonOS is aimed at servers. That means:

- persistent storage that survives reboot
- networking that doesn't fall over when a daemon binds to localhost
- headless boot over serial
- security that isn't djb2 passwords (yes, we know)

Framebuffer polish, PS/2 mouse quirks, boot logo tweaks — fine, but that's not the priority. Put those on separate branches if you care.

## Getting stuck

Open an issue. Half-finished PR with a note is better than two weeks of silence. We can see the code either way.

If you're not sure which branch to use, check BRANCHING.md or ask in the issue. Guessing `feature/ext4-fs` when you meant `feature/ext2-write` wastes everyone's time.

## AI tools

If you use Windsurf or similar: fine, but **you** own the code. Read what it generated. Test it. Don't dump 500 lines of plausible-looking nonsense into Axon source code.

Also: turn off "add co-author to commits" in your agent settings. We don't need bot accounts showing up in the contributors list.

# we hope you understood the game, so go ahead!