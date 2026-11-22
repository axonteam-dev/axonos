/* Temporary xeyes diagnostic. Loaded into the X client only, not Xorg. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

typedef struct _XDisplay Display;
typedef unsigned long Window;

static void trace(const char *text, int a, int b, int c) {
    char line[160];
    int n = snprintf(line, sizeof(line), "%s %d %d %d\n", text, a, b, c);
    int fd = open("/tmp/xeyes-trace.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        if (n > 0 && (unsigned)n < sizeof(line)) {
            ssize_t written = write(fd, line, (unsigned)n);
            (void)written;
        }
        close(fd);
    }
}

int XISelectEvents(Display *d, Window w, void *masks, int count) {
    typedef int (*fn_t)(Display *, Window, void *, int);
    fn_t fn = (fn_t)dlsym(RTLD_NEXT, "XISelectEvents");
    if (!fn) { trace("XISelectEvents-missing", 0, 0, 0); return -1; }
    int rc = fn(d, w, masks, count);
    trace("XISelectEvents", rc, count, 0);
    return rc;
}

int XQueryPointer(Display *d, Window w, Window *root, Window *child,
                  int *root_x, int *root_y, int *win_x, int *win_y,
                  unsigned int *mask) {
    typedef int (*fn_t)(Display *, Window, Window *, Window *, int *, int *, int *, int *, unsigned int *);
    fn_t fn = (fn_t)dlsym(RTLD_NEXT, "XQueryPointer");
    if (!fn) { trace("XQueryPointer-missing", 0, 0, 0); return 0; }
    static unsigned count;
    unsigned sample = count++;
    if (sample < 200) trace("XQueryPointer-begin", (int)sample, 0, 0);
    int rc = fn(d, w, root, child, root_x, root_y, win_x, win_y, mask);
    if (sample < 200) trace("XQueryPointer", rc, rc ? *root_x : 0, rc ? *root_y : 0);
    return rc;
}
