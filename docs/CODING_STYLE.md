# Coding style

AxonOS uses **GNU C layout** with one deliberate exception: the return type stays on the **same line** as the function name.

```c
void syscall_init(void)
{
    ...
}

static int copy_from_user(void *dst, const void *src, size_t n)
{
    ...
}
```

Not this:

```c
void
syscall_init (void)
{
```

## Formatting

- **Indent:** 4 spaces. No tabs in kernel C (host tools like `tools/axon-harness.c` may differ).
- **Braces:** opening `{` on its own line for functions; same line for `if`/`for`/`while` when the body is one statement or fits cleanly.
- **Spacing:** space after keywords (`if (`, `for (`); no space before `(` in function calls.
- **Lines:** keep under ~100 columns when reasonable; break long argument lists, not the return type.
- **Headers:** `inc/foo.h` for public API; `syscall/internal/` for syscall-private cross-module declarations.

## Comments

Write for the next person, not for the compiler.

- **Keep:** non-obvious invariants, hardware quirks, ABI constraints, “why we do this weird thing”.
- **Drop:** file banners that only repeat the path, `Author:` lines, changelog noise in source, commented-out dead code.
- No `TODO: fix later`. Name the bug or the syscall.

## Design (Torvalds rules, adapted for a kernel)

1. **Data structures first.** Get the structs and ownership right; the code often writes itself. Bad code around good data beats the reverse.
2. **Fewer special cases.** Prefer one straight path over a forest of `if (legacy)` branches. Push complexity into data, not control flow.
3. **Three levels of indentation.** If you're nesting deeper, extract a `static` helper or restructure. Giant `switch` arms are the main exception while `syscall/dispatch/` is still being split.
4. **Small functions.** One job, one screen (~40–60 lines). `syscall_dispatch.c` is the known monolith — new syscalls go in focused files under `syscall/dispatch/`, not deeper into the big switch file.
5. **Don't break user space.** Syscall numbers, struct layouts seen by glibc/busybox, and errno values are ABI. Refactors are behavior-preserving unless you're explicitly versioning something.

## What we don't do

- Mass reformatting for its own sake in a driver you're not touching.
- “Cleanup” that changes syscall behavior or error codes without tests.
- libc in the kernel, floating point in kernel paths, or ignoring error returns.

## Check before PR

```bash
make clean && make BUILD_DIR=.build -j$(nproc)   # or make iso if you have permissions
```

If you only changed style in a file, say so in the PR — reviewers still care that the binary didn't change semantics.
