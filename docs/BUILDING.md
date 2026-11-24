# Building AxonOS

AxonOS uses GNU Make (version 4.3 or newer), like the Linux kernel. The executable
`configure` and `compile` files are Bash scripts, not binaries to compile. CMake
is not required. Python 3 generates the configuration headers.

### Kernel configuration

The existing `config.cfg` remains the default until a Kconfig file is created
for the selected `BUILD_DIR`. The interactive frontend is Linux's original
`mconf`/lxdialog, built locally as a host tool; it requires a C compiler and
ncurses development headers, not kconfiglib or network access. For example:

```bash
make menuconfig
make -j8 kernel
```

On first use, `menuconfig` imports `config.cfg` into `build/.config` without
modifying the original. Later kernel builds use `build/.config` automatically.
`make olddefconfig` updates an existing Kconfig file non-interactively; both
commands use the bundled host tools. Use the same `BUILD_DIR` for configuration and
build. To use a legacy file explicitly, pass `CONFIG_FILE=config.cfg` or
`CONFIG_FILE=config.production.cfg`. Unknown legacy settings and `m` values
cause import to stop instead of silently changing the configuration.

Kconfig currently exposes built-in boolean settings only. **Loadable modules and
Linux module compatibility are not implemented.** Selecting an experimental
option does not mean it is safe: SMP, high-memory paths and Intel framebuffer
takeover remain experimental. The graphical menu requires an interactive
terminal; ordinary `make kernel` with an existing configuration does not require
ncurses. Some historical settings have no current kernel consumer and are
explicitly labelled as having no effect in the menu. This initial Kconfig
integration does not yet omit all disabled drivers from the linked image.
The bundled Kconfig host tools retain their GPL-2.0 licenses and are not linked
into the Axon kernel; see `third_party/kconfig/README.axonos`.

On Debian/Ubuntu:

```bash
sudo apt-get install build-essential nasm lz4 python3 libncurses-dev pkg-config grub-pc-bin grub-common xorriso mtools openssl ca-certificates wget
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
