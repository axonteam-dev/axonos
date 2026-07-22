/*
 * Minimal libnss_files.so.2 for static glibc on AxonOS.
 * Built -nostdlib / no NEEDED libc — static busybox can dlopen this without
 * pulling shared libc.so.6 (which fatals: "error while loading shared libraries").
 * Lookups return NOTFOUND; passwd/group data stays in the static busybox builtins
 * when the module offers no match, or callers fall through.
 */
typedef enum {
	NSS_STATUS_TRYAGAIN = -2,
	NSS_STATUS_UNAVAIL = -1,
	NSS_STATUS_NOTFOUND = 0,
	NSS_STATUS_SUCCESS = 1,
	NSS_STATUS_RETURN = 2
} nss_status;

#define STUB_NF(name) \
	nss_status name(void) { return NSS_STATUS_NOTFOUND; }

/* Common glibc NSS entry points — keep signatures loose (varargs-safe via void). */
STUB_NF(_nss_files_getpwnam_r)
STUB_NF(_nss_files_getpwuid_r)
STUB_NF(_nss_files_getpwent_r)
STUB_NF(_nss_files_setpwent)
STUB_NF(_nss_files_endpwent)
STUB_NF(_nss_files_getgrnam_r)
STUB_NF(_nss_files_getgrgid_r)
STUB_NF(_nss_files_getgrent_r)
STUB_NF(_nss_files_setgrent)
STUB_NF(_nss_files_endgrent)
STUB_NF(_nss_files_getspnam_r)
STUB_NF(_nss_files_getspent_r)
STUB_NF(_nss_files_setspent)
STUB_NF(_nss_files_endspent)
STUB_NF(_nss_files_gethostbyname_r)
STUB_NF(_nss_files_gethostbyname2_r)
STUB_NF(_nss_files_gethostbyname3_r)
STUB_NF(_nss_files_gethostbyname4_r)
STUB_NF(_nss_files_gethostbyaddr_r)
STUB_NF(_nss_files_gethostent_r)
STUB_NF(_nss_files_sethostent)
STUB_NF(_nss_files_endhostent)
STUB_NF(_nss_files_getservbyname_r)
STUB_NF(_nss_files_getservbyport_r)
STUB_NF(_nss_files_getservent_r)
STUB_NF(_nss_files_getprotobyname_r)
STUB_NF(_nss_files_getprotobynumber_r)
STUB_NF(_nss_files_getnetbyname_r)
STUB_NF(_nss_files_getnetbyaddr_r)
