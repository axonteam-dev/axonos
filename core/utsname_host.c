#include <utsname_host.h>
#include <ns.h>
#include <string.h>

void uts_hostname_init(void) {
	/* UTS strings live in the init UTS namespace (core/ns.c). */
}

const char *uts_hostname_get(void) {
	return ns_uts_nodename();
}

const char *uts_domainname_get(void) {
	return ns_uts_domainname();
}

int uts_hostname_set(const char *buf, size_t len) {
	return ns_uts_set_nodename(buf, len);
}

int uts_domainname_set(const char *buf, size_t len) {
	return ns_uts_set_domainname(buf, len);
}
