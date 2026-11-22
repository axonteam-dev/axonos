#!/usr/bin/env python3
"""Keep the packaged XFCE startup sequence and prepare its session bus."""
from pathlib import Path
import sys

root = Path(sys.argv[1])
path = root / "etc/xdg/xfce4/xinitrc"
if not (root / "usr/bin/timeout").is_file():
    raise SystemExit("build-glibc-iso: /usr/bin/timeout is required for XFCE startup")

text = path.read_text()
marker = "# Axon bounded activation setup"
if marker not in text:
    probe = "systemctl --user list-jobs >/dev/null 2>&1"
    update = "  dbus-update-activation-environment $systemd_arg \\\n"
    anchor = "if command -v dbus-update-activation-environment >/dev/null 2>&1; then\n"
    if any(text.count(part) != 1 for part in (probe, update, anchor)):
        raise SystemExit("build-glibc-iso: unrecognized XFCE xinitrc activation setup")
    helper = '''# Axon bounded activation setup
# A stalled bus or user manager must not prevent the desktop from starting.
axon_systemctl_probe() {
  if /usr/bin/timeout -k 2s 5s systemctl --user list-jobs >/dev/null 2>&1; then
    return 0
  else
    axon_status=$?
    echo "xfce xinitrc: warning: systemctl user probe failed or timed out (status $axon_status)" >&2
    return 1
  fi
}
axon_dbus_update() {
  if /usr/bin/timeout -k 2s 5s dbus-update-activation-environment "$@"; then
    return 0
  else
    axon_status=$?
    echo "xfce xinitrc: warning: D-Bus activation environment update failed or timed out (status $axon_status)" >&2
    return 0
  fi
}
'''
    text = text.replace(probe, "axon_systemctl_probe", 1)
    text = text.replace(update, "  axon_dbus_update $systemd_arg \\\n", 1)
    text = text.replace(anchor, helper + anchor, 1)

bus_marker = "# Axon shared XFCE session bus"
if bus_marker not in text:
    shebang = "#!/bin/sh\n"
    if not text.startswith(shebang):
        raise SystemExit("build-glibc-iso: unrecognized XFCE xinitrc interpreter")
    bus_setup = '''# Axon shared XFCE session bus
# startxfce4 can be launched from an existing X session without a bus.
# Run the whole startup sequence under one bus, including activation and
# every desktop component. Preserve a bus supplied by the login session.
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && command -v dbus-run-session >/dev/null 2>&1; then
  exec dbus-run-session -- /bin/sh "$0" "$@"
fi

'''
    text = shebang + bus_setup + text[len(shebang):]
path.write_text(text)
