#!/usr/bin/env python3
"""Create a real libvte PTY without starting X; run inside the guest."""
import ctypes
import sys


class GError(ctypes.Structure):
    _fields_ = [("domain", ctypes.c_uint), ("code", ctypes.c_int),
                ("message", ctypes.c_char_p)]


vte = ctypes.CDLL("libvte-2.91.so.0")
gobject = ctypes.CDLL("libgobject-2.0.so.0")
glib = ctypes.CDLL("libglib-2.0.so.0")
vte.vte_pty_new_sync.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                ctypes.POINTER(ctypes.POINTER(GError))]
vte.vte_pty_new_sync.restype = ctypes.c_void_p
vte.vte_pty_get_fd.argtypes = [ctypes.c_void_p]
vte.vte_pty_get_fd.restype = ctypes.c_int
gobject.g_object_unref.argtypes = [ctypes.c_void_p]
glib.g_error_free.argtypes = [ctypes.POINTER(GError)]
error = ctypes.POINTER(GError)()
pty = vte.vte_pty_new_sync(0, None, ctypes.byref(error))
if not pty:
    message = error.contents.message.decode(errors="replace") if error else "unknown"
    print(f"VTE_PTY_FAILED: {message}", flush=True)
    if error:
        glib.g_error_free(error)
    sys.exit(1)
fd = vte.vte_pty_get_fd(pty)
print(f"VTE_PTY_OK fd={fd}", flush=True)
gobject.g_object_unref(pty)
sys.exit(0 if fd >= 0 else 1)
