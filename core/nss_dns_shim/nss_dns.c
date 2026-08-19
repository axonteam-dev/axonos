/*
 * Minimal glibc NSS "dns" module: hostname -> IPv4 via SYS_resolve (1000).
 *
 * Built -nostdlib / no NEEDED libc — static busybox can dlopen this (same
 * constraint as libnss_files). Dynamic apt/glibc uses the same DSO.
 */
typedef unsigned int uint32_t;
typedef unsigned long size_t;

typedef enum {
	NSS_STATUS_TRYAGAIN = -2,
	NSS_STATUS_UNAVAIL = -1,
	NSS_STATUS_NOTFOUND = 0,
	NSS_STATUS_SUCCESS = 1
} nss_status;

struct hostent {
	char *h_name;
	char **h_aliases;
	int h_addrtype;
	int h_length;
	char **h_addr_list;
};

/* glibc nss_dns getaddrinfo tuple (x86_64 layout). */
struct gaih_addrtuple {
	struct gaih_addrtuple *next;
	char *name;
	int family;
	uint32_t addr[4];
	uint32_t scopeid;
};

#define AF_UNSPEC 0
#define AF_INET   2
#define AF_INET6  10

#define HOST_NOT_FOUND  1
#define NO_RECOVERY     3
#define NETDB_INTERNAL  -1
#define NETDB_SUCCESS   0

#define EIO    5
#define ENOENT 2
#define ERANGE 34

#define SYS_resolve 1000

static inline long sys2(long n, long a1, long a2)
{
	long ret;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(n), "D"(a1), "S"(a2)
	                 : "rcx", "r11", "memory");
	return ret;
}

static size_t xstrlen(const char *s)
{
	size_t n = 0;
	if (!s)
		return 0;
	while (s[n])
		n++;
	return n;
}

static void xmemcpy(void *d, const void *s, size_t n)
{
	size_t i;
	char *dd = (char *)d;
	const char *ss = (const char *)s;
	for (i = 0; i < n; i++)
		dd[i] = ss[i];
}

static void xmemset(void *d, int c, size_t n)
{
	size_t i;
	char *dd = (char *)d;
	for (i = 0; i < n; i++)
		dd[i] = (char)c;
}

static void fill_v4mapped_addr(unsigned char out[16], uint32_t ip_be)
{
	xmemset(out, 0, 16);
	out[10] = 0xff;
	out[11] = 0xff;
	xmemcpy(out + 12, &ip_be, 4);
}

static int resolve_ip(const char *name, uint32_t *ip_be, int *errnop, int *h_errnop)
{
	long r;

	if (!name || !name[0] || !ip_be || !errnop || !h_errnop)
		return -1;
	*ip_be = 0;
	r = sys2(SYS_resolve, (long)name, (long)ip_be);
	if (r < 0) {
		int e = (int)(-r);
		*errnop = e;
		if (e == EIO || e == ENOENT)
			*h_errnop = HOST_NOT_FOUND;
		else
			*h_errnop = NO_RECOVERY;
		return -1;
	}
	*errnop = 0;
	*h_errnop = NETDB_SUCCESS;
	return 0;
}

nss_status _nss_dns_gethostbyname3_r(const char *name, int af, struct hostent *result,
                                     char *buffer, size_t buflen, int *errnop,
                                     int *h_errnop, int *ttlp, char **canon);

nss_status _nss_dns_gethostbyname2_r(const char *name, int af, struct hostent *result,
                                     char *buffer, size_t buflen, int *errnop,
                                     int *h_errnop)
{
	if (!name || !name[0]) {
		if (h_errnop)
			*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}
	return _nss_dns_gethostbyname3_r(name, af, result, buffer, buflen, errnop, h_errnop, 0, 0);
}

nss_status _nss_dns_gethostbyname_r(const char *name, struct hostent *result,
                                    char *buffer, size_t buflen, int *errnop,
                                    int *h_errnop)
{
	if (!name || !name[0]) {
		if (h_errnop)
			*h_errnop = HOST_NOT_FOUND;
		return NSS_STATUS_NOTFOUND;
	}
	return _nss_dns_gethostbyname3_r(name, AF_INET, result, buffer, buflen, errnop, h_errnop, 0, 0);
}

nss_status _nss_dns_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat,
                                     char *buffer, size_t buflen, int *errnop,
                                     int *h_errnop, int *ttlp)
{
	uint32_t ip_be;
	struct gaih_addrtuple *t4;

	if (!name || !pat || !buffer || !errnop || !h_errnop)
		return NSS_STATUS_UNAVAIL;

	*pat = 0;
	if (ttlp)
		*ttlp = 0;

	if (resolve_ip(name, &ip_be, errnop, h_errnop) != 0) {
		if (*h_errnop == HOST_NOT_FOUND)
			return NSS_STATUS_NOTFOUND;
		return NSS_STATUS_UNAVAIL;
	}

	if (buflen < sizeof(struct gaih_addrtuple)) {
		*errnop = ERANGE;
		*h_errnop = NETDB_INTERNAL;
		return NSS_STATUS_TRYAGAIN;
	}

	/* IPv4 only: this kernel has no IPv6 stack. A v4-mapped AF_INET6
	 * tuple makes apt/glibc Happy-Eyeballs poll an IPv6 connect forever. */
	t4 = (struct gaih_addrtuple *)buffer;
	xmemset(t4, 0, sizeof(*t4));
	t4->next = 0;
	t4->name = 0;
	t4->family = AF_INET;
	t4->addr[0] = ip_be;
	t4->scopeid = 0;
	*pat = t4;
	*errnop = 0;
	*h_errnop = NETDB_SUCCESS;
	return NSS_STATUS_SUCCESS;
}

nss_status _nss_dns_gethostbyname3_r(const char *name, int af, struct hostent *result,
                                     char *buffer, size_t buflen, int *errnop,
                                     int *h_errnop, int *ttlp, char **canon)
{
	uint32_t ip_be;
	size_t nl, off_addr, addr_len, need;
	int out_af;
	char **addrlist;
	char **aliases;

	if (af != AF_INET && af != AF_INET6 && af != AF_UNSPEC)
		return NSS_STATUS_NOTFOUND;
	if (!name || !result || !buffer || !errnop || !h_errnop)
		return NSS_STATUS_UNAVAIL;
	if (canon)
		*canon = 0;
	if (ttlp)
		*ttlp = 0;

	if (resolve_ip(name, &ip_be, errnop, h_errnop) != 0) {
		if (*h_errnop == HOST_NOT_FOUND)
			return NSS_STATUS_NOTFOUND;
		return NSS_STATUS_UNAVAIL;
	}

	nl = xstrlen(name) + 1;
	out_af = (af == AF_INET6) ? AF_INET6 : AF_INET;
	addr_len = (out_af == AF_INET6) ? 16u : 4u;
	off_addr = (nl + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
	need = off_addr + addr_len + sizeof(char *) * 2 + sizeof(char *) * 2;

	if (buflen < need) {
		*errnop = ERANGE;
		*h_errnop = NETDB_INTERNAL;
		return NSS_STATUS_TRYAGAIN;
	}

	xmemcpy(buffer, name, nl);
	if (out_af == AF_INET6)
		fill_v4mapped_addr((unsigned char *)(buffer + off_addr), ip_be);
	else
		xmemcpy(buffer + off_addr, &ip_be, 4);

	addrlist = (char **)(buffer + off_addr + addr_len);
	aliases = addrlist + 2;
	aliases[0] = 0;
	addrlist[0] = buffer + off_addr;
	addrlist[1] = 0;

	xmemset(result, 0, sizeof(*result));
	result->h_name = buffer;
	result->h_aliases = aliases;
	result->h_addrtype = out_af;
	result->h_length = (int)addr_len;
	result->h_addr_list = addrlist;

	*errnop = 0;
	*h_errnop = NETDB_SUCCESS;
	return NSS_STATUS_SUCCESS;
}
