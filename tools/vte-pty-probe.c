/* Test the real libvte PTY constructor without Python or an X session. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

typedef struct { unsigned domain; int code; char *message; } GError;
static int (*spawn_finish)(void *, void *, int *, GError **);
static void (*loop_quit)(void *);
static int spawn_ok;

static void spawned(void *pty, void *result, void *loop) {
    GError *error = NULL;
    int pid = -1;
    spawn_ok = spawn_finish(pty, result, &pid, &error);
    printf("VTE_SPAWN_%s pid=%d error=%s\n", spawn_ok ? "OK" : "FAILED",
           pid, error && error->message ? error->message : "none");
    fflush(stdout);
    loop_quit(loop);
}

int main(void) {
    void *lib = dlopen("libvte-2.91.so.0", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "VTE_DLOPEN_FAILED: %s\n", dlerror());
        return 1;
    }
    void *(*new_pty)(int, void *, GError **) = dlsym(lib, "vte_pty_new_sync");
    int (*get_fd)(void *) = dlsym(lib, "vte_pty_get_fd");
    if (!new_pty || !get_fd) return 2;
    GError *error = NULL;
    void *pty = new_pty(0, NULL, &error);
    if (!pty) {
        fprintf(stderr, "VTE_PTY_FAILED: %s\n",
                error && error->message ? error->message : "unknown");
        return 3;
    }
    int fd = get_fd(pty);
    printf("VTE_PTY_OK fd=%d\n", fd);
    fflush(stdout);
    if (fd < 0) return 4;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps))
            fputs(line, stdout);
        fclose(maps);
        fflush(stdout);
    }
    Dl_info info = {0};
    if (dladdr((void *)(uintptr_t)0x8096388, &info))
        printf("VTE_DEBUG_RETURN object=%s base=%p symbol=%s\n",
               info.dli_fname, info.dli_fbase,
               info.dli_sname ? info.dli_sname : "?");
    void (*spawn)(void *, const char *, char **, char **, int, void *,
                  void *, void *, int, void *, void (*)(void *, void *, void *),
                  void *) = dlsym(lib, "vte_pty_spawn_async");
    spawn_finish = dlsym(lib, "vte_pty_spawn_finish");
    void *(*loop_new)(void *, int) = dlsym(lib, "g_main_loop_new");
    void (*loop_run)(void *) = dlsym(lib, "g_main_loop_run");
    loop_quit = dlsym(lib, "g_main_loop_quit");
    if (!spawn || !spawn_finish || !loop_new || !loop_run || !loop_quit) return 5;
    void *loop = loop_new(NULL, 0);
    char *argv[] = {"/bin/sh", "-c", "echo VTE_SPAWN_CHILD_OK > /tmp/vte-spawn-marker", NULL};
    spawn(pty, NULL, argv, NULL, 0, NULL, NULL, NULL, 30000, NULL, spawned, loop);
    loop_run(loop);
    return spawn_ok ? 0 : 6;
}
