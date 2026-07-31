#include <utsname_host.h>
#include <string.h>

/* Match historical shell prompt / gethostname default for this ISO image. */
static char g_hostname[UTS_NODENAME_MAX] = "axoniso";
static char g_domainname[UTS_NODENAME_MAX] = "local";

void uts_hostname_init(void) {
	/* defaults already set */
}

const char *uts_hostname_get(void) {
	return g_hostname;
}

const char *uts_domainname_get(void) {
	return g_domainname;
}

static int uts_set_name(char *dst, size_t dstsz, const char *buf, size_t len) {
	size_t n;
	if (!buf || dstsz == 0)
		return -1;
	n = len;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == '\0'))
		n--;
	if (n >= dstsz)
		n = dstsz - 1;
	if (n > 0)
		memcpy(dst, buf, n);
	dst[n] = '\0';
	return 0;
}

int uts_hostname_set(const char *buf, size_t len) {
	return uts_set_name(g_hostname, sizeof(g_hostname), buf, len);
}

int uts_domainname_set(const char *buf, size_t len) {
	return uts_set_name(g_domainname, sizeof(g_domainname), buf, len);
}
