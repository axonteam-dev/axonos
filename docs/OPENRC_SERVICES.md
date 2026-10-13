# OpenRC SSH and networking overlay

The prepared `~/rootfs` tree extends the existing initfs; it is not a standalone
bootable rootfs. It retains the existing accounts, passwords, inittab and basic
OpenRC services.

Enabled runlevel entries:

- `etc/runlevels/boot/networking` → `../../init.d/networking`
- `etc/runlevels/default/sshd` → `../../init.d/sshd`

`/etc/network/interfaces` enables loopback and DHCP on `eth0`. The BusyBox
DHCP hook configures addresses, routes and DNS, including classless static
routes. Renewals do not read stdin or flush an unchanged address. `ifup` uses
the existing initfs BusyBox client, which retains its daemon for lease renewal.
The DHCP stanza explicitly selects `/usr/share/udhcpc/default.script` using
BusyBox's `script` option. Its generated udhcpc command was checked with the
actual initfs BusyBox in mapping-disabled dry-run mode and a private PATH;
no host interfaces were configured.
Networking provides OpenRC's `net` dependency; SSH requires it.
If loopback already has 127.0.0.1/8, the service brings the link up without
trying to add the same address again. It still reports real interface failures.

The DHCP hook emits bounded `udhcpc-hook:` phase messages for address setup,
routes, DNS and completion. Obtaining a lease alone does not prove the hook
finished or that OpenRC considers networking started.

OpenSSH runs in the foreground under OpenRC's background/pidfile management.
Before starting, the service creates its runtime directories, generates missing
guest host keys with `ssh-keygen -A`, and validates `sshd_config`. Reload also
validates the configuration before sending SIGHUP.

The default Debian OpenSSH policy is retained: port 22, PAM enabled, no empty
passwords, and root login by public key rather than password. No user keys or
host private keys are copied from the build host. Add an authorized key in the
guest if root SSH access is desired. For a stable SSH identity across reboots,
persist `/etc/ssh` on guest storage; a volatile initfs overlay loses newly
generated keys when it reboots.

`etc/nsswitch.conf` explicitly selects local `files` lookups for passwd, group
and shadow so the Debian glibc SSH/PAM runtime uses the guest's account files
alongside the musl/BusyBox base. The existing `sshd` account is retained; missing
privilege-separation users are not worked around by running unprivileged SSH
children as root or disabling privilege separation.

## Reinstalling the runtime

```sh
python3 tools/install-openssh-rootfs.py "$HOME/rootfs"
```

This downloads Debian Trixie and security repository metadata over HTTPS,
checks pinned archive-key fingerprints, verifies InRelease signatures and
index/package SHA256 hashes, and extracts the runtime dependency closure.
Expired security metadata is rejected. It does not install packages on the
host or execute maintainer scripts. Existing destination files are preserved.
Package provenance is recorded in
`usr/share/axonos/openssh-packages.json` inside the destination.

The runtime installer is not a replacement for dpkg's package database and
does not enable runlevels on a fresh arbitrary destination. The service files,
network configuration and runlevel entries described above must also be
present. The base initfs supplies BusyBox, OpenRC, `hostname` and `localmount`.

To use these changes in a guest, merge the overlay into the extracted initfs,
repack it and rebuild the ISO. Merely running `./compile iso` does not merge
`~/rootfs` into an already existing `iso/boot/initfs.sfs`.

On the prepared host, `~/compilerootfs.sh` performs this merge using
`tools/merge-rootfs-overlay.py`. Absolute `/lib64`-style aliases resolve inside
the staging guest tree, not through the host filesystem. Before packing, it
requires executable `fsck`, `root`, `localmount`, `hostname`, `networking` and
`sshd` scripts. A service file with mode 0644 is ignored by OpenRC even if its
contents are valid; it can therefore cause misleading "non existent service"
dependency errors. The prepared overlay's OpenRC scripts now have execute bits.

## Guest checks

```sh
rc-status
rc-service networking status
ip -4 addr show dev eth0
ip route
cat /etc/resolv.conf
rc-service sshd status
```

From another machine: `ssh USER@GUEST_IP`. VM NAT may require forwarding a host
port to guest port 22; no host firewall or VM networking configuration is
changed by the installer. SSH authentication and network operations still
require validation in AxonOS; host configuration/ELF checks do not prove kernel
ABI compatibility. No QEMU boot is part of these checks.
