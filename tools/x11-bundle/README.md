# X11 diagnostic bundle launchers

The local ISO workflow consumes a prebuilt, ignored
`build/axonos-xterm-xinit.tar.gz`. It has no checked-in generator. Create a
separate archive with the corrected launchers using:

```sh
python3 tools/prepare-xterm-bundle.py build/axonos-xterm-xinit.tar.gz \
    build/axonos-xterm-xinit-fixed.tar.gz
python3 tools/test-xterm-bundle.py
```

The output must not already exist. The input is never overwritten. The tool
replaces only the two executable launchers, retaining the other archive
members, including `SHA256SUMS` for the existing binaries and libraries.

The ISO builder still names the original archive. It must be integrated with
the fixed archive (or install these launchers over the extracted copies) before
the boot image uses them. In particular, its existing cached-root check compares
the prebuilt archive with the copy in `/opt` and deliberately refuses a
different bundle. Do not silently overwrite or remove that cached root or its
archive; use a fresh staging root, or explicitly coordinate updating both the
cached bundle and the extracted launchers. Installing only the launchers
leaves the separately stored original tarball unchanged.

`tools/ax-xfce-check.sh` independently unsets `LD_LIBRARY_PATH` as a safeguard
for the old launcher. It therefore does not preserve an explicitly supplied
caller path, even with the fixed bundle. If that helper must preserve the path
too, remove its unset only when the fixed runner is deployed alongside it.

Each launcher invokes the bundled glibc loader with `--library-path` for
`xinit` and/or `xterm`. This selects bundle libraries for those processes
without exporting the path. Xorg, the terminal shell, and programs started
from that shell instead receive the caller's original `LD_LIBRARY_PATH`,
including the distinction between unset and empty. An explicitly supplied
caller path is not sanitized; the caller remains responsible for its contents.
The existing X resources and terminal settings are still exported as before.

Directly invoking a dynamic loader can make `/proc/PID/exe` identify the loader
rather than the application, which may affect features that re-execute
`/proc/self/exe` or kernel traces filtered by process name. In the current
AxonOS ELF loader, directly executing this `ET_DYN` binary without `PT_INTERP`
can also take the no-interpreter relocation and image-cache path, unlike the
usual interpreter load. The host tests exercise actual glibc loading and mock
process handoffs, but do not verify this diagnostic session on AxonOS or in a
VM.
