#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
timeout_s="${AXON_BOOT_TIMEOUT:-600}"
milestone="${AXON_BOOT_MILESTONE:-AXON_BOOT_OPENRC_EXEC}"
log="${AXON_BOOT_LOG:-$(mktemp)}"
qemu_pid=""

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

make -C "$root" iso

args=(
    -cdrom "$root/build/axonos.iso"
    -m 1024M
    -smp 1
    -boot d
    -display none
    -monitor none
    -serial none
    -debugcon stdio
    -global isa-debugcon.iobase=0xe9
    -no-reboot
    -no-shutdown
)
if [[ -f "$root/../disk.img" ]]; then
    args+=( -drive "file=$root/../disk.img,format=raw,if=ide" )
fi

qemu-system-x86_64 "${args[@]}" >"$log" 2>&1 &
qemu_pid=$!

failure='wait4.*ECHILD|init-wait repair|requeue stale-running|kernel panic|PANIC|#PF|page fault|general protection|triple fault|SYSCALL-NOCUR'
for ((second = 0; second < timeout_s; second++)); do
    if grep -Eiq "$failure" "$log"; then
        echo "headless boot failed; log: $log" >&2
        exit 1
    fi
    if grep -Eiq "$milestone" "$log"; then
        echo "headless boot reached milestone '$milestone'"
        exit 0
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        wait "$qemu_pid" || true
        echo "QEMU exited before milestone '$milestone'; log: $log" >&2
        exit 1
    fi
    sleep 1
done

echo "headless boot timed out after ${timeout_s}s; log: $log" >&2
exit 1
