# Building AxonOS

AxonOS uses GNU Make (version 4.3 or newer), like the Linux kernel. The executable
`configure` and `compile` files are Bash scripts, not binaries to compile. CMake
is not required. Python 3 generates the configuration headers.

On Debian/Ubuntu:

```bash
sudo apt-get install build-essential nasm lz4 python3 grub-pc-bin grub-common xorriso mtools openssl ca-certificates wget
./configure
./compile
```

The default output is `build/axonos.iso`. The tracked `iso/boot/initfs.sfs` is
used without downloading a root filesystem. If it is missing, `make archive`
uses a local initfs image and otherwise fails with an explicit error. There is
no automatic download of unverified archives. Converting a CPIO image currently
requires Docker or Podman (see `tools/mkinitfs-squashfs.sh`).

```bash
./compile kernel                         # kernel only, no root filesystem
./compile -j4                           # override default parallelism
./configure CONFIG_FILE=config.production.cfg
./compile CONFIG_FILE=config.production.cfg OPTFLAGS='-O0 -g0'
./compile BUILD_DIR=build-custom kernel  # separate build outputs
make test-build                         # configuration regression tests
make test                               # all available host regression tests
```

Pass the same `CONFIG_FILE` and `BUILD_DIR` to both scripts: configure does not
save command-line options. Configuration and compiler flag changes trigger
rebuilds automatically. `make clean` removes the selected build directory.

GitHub Actions builds a fresh kernel, switches to production configuration,
builds an ISO, and uploads artifacts. It does not publish releases or claim a
successful guest boot. `make test-boot` is an optional local QEMU smoke test;
its default milestone only confirms that loading the OpenRC executable began.
