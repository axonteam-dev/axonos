/*
 * Minimal libnss_files.so.2 for static glibc on AxonOS.
 *
 * Built -nostdlib / no NEEDED libc — static busybox can dlopen this without
 * pulling shared libc.so.6 (which fatals: "error while loading shared libraries").
 *
 * Parses /etc/passwd and /etc/group via raw syscalls so getpwuid/getpwnam
 * (bash/ash PS1, whoami, id) resolve root instead of "I have no name!".
 */
typedef unsigned long size_t;
typedef long ssize_t;
typedef int uid_t;
typedef int gid_t;

typedef enum {
	NSS_STATUS_TRYAGAIN = -2,
	NSS_STATUS_UNAVAIL = -1,
	NSS_STATUS_NOTFOUND = 0,
	NSS_STATUS_SUCCESS = 1,
	NSS_STATUS_RETURN = 2
} nss_status;

struct passwd {
	char *pw_name;
	char *pw_passwd;
	uid_t pw_uid;
	gid_t pw_gid;
	char *pw_gecos;
	char *pw_dir;
	char *pw_shell;
};

struct group {
	char *gr_name;
	char *gr_passwd;
	gid_t gr_gid;
	char **gr_mem;
};

#define SYS_read   0
#define SYS_open   2
#define SYS_close  3
#define O_RDONLY   0
#define ERANGE     34
#define ENOENT     2

static inline long sys3(long n, long a1, long a2, long a3)
{
	long ret;
	__asm__ volatile("syscall"
	                 : "=a"(ret)
	                 : "a"(n), "D"(a1), "S"(a2), "d"(a3)
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

static int xstrcmp(const char *a, const char *b)
{
	if (!a || !b)
		return a ? 1 : (b ? -1 : 0);
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}

static char *xmemcpy(char *d, const char *s, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		d[i] = s[i];
	return d;
}

static int parse_u32(const char *s, unsigned *out)
{
	unsigned v = 0;
	int any = 0;
	if (!s || !out)
		return -1;
	while (*s >= '0' && *s <= '9') {
		v = v * 10u + (unsigned)(*s - '0');
		s++;
		any = 1;
	}
	if (!any || *s != '\0')
		return -1;
	*out = v;
	return 0;
}

/* Split line into up to max fields on ':'. Mutates line. */
static int split_colon(char *line, char **fields, int max)
{
	int n = 0;
	char *p = line;
	if (!line || !fields || max <= 0)
		return 0;
	fields[n++] = p;
	while (*p && n < max) {
		if (*p == ':') {
			*p = '\0';
			fields[n++] = p + 1;
		}
		p++;
	}
	return n;
}

static ssize_t read_file(const char *path, char *buf, size_t cap)
{
	long fd;
	ssize_t total = 0;
	if (!path || !buf || cap < 2)
		return -1;
	fd = sys3(SYS_open, (long)path, O_RDONLY, 0);
	if (fd < 0)
		return -1;
	for (;;) {
		long n = sys3(SYS_read, fd, (long)(buf + total), (long)(cap - 1 - (size_t)total));
		if (n <= 0)
			break;
		total += (ssize_t)n;
		if ((size_t)total >= cap - 1)
			break;
	}
	(void)sys3(SYS_close, fd, 0, 0);
	if (total < 0)
		return -1;
	buf[total] = '\0';
	return total;
}

static char *buf_copy(char **cursor, char *end, const char *src)
{
	size_t n;
	char *out;
	if (!cursor || !*cursor || !end || !src)
		return 0;
	n = xstrlen(src) + 1;
	if (*cursor + n > end)
		return 0;
	out = *cursor;
	xmemcpy(out, src, n);
	*cursor += n;
	return out;
}

static nss_status fill_passwd(struct passwd *pwd, char *buffer, size_t buflen,
                              int *errnop, char *f0, char *f1, char *f2, char *f3,
                              char *f4, char *f5, char *f6)
{
	char *cur;
	char *end;
	unsigned uid, gid;
	if (!pwd || !buffer || buflen < 8 || !errnop)
		return NSS_STATUS_UNAVAIL;
	if (parse_u32(f2, &uid) != 0 || parse_u32(f3, &gid) != 0)
		return NSS_STATUS_NOTFOUND;
	cur = buffer;
	end = buffer + buflen;
	pwd->pw_name = buf_copy(&cur, end, f0 ? f0 : "");
	pwd->pw_passwd = buf_copy(&cur, end, f1 ? f1 : "x");
	pwd->pw_gecos = buf_copy(&cur, end, f4 ? f4 : "");
	pwd->pw_dir = buf_copy(&cur, end, f5 ? f5 : "/");
	pwd->pw_shell = buf_copy(&cur, end, f6 ? f6 : "/bin/sh");
	if (!pwd->pw_name || !pwd->pw_passwd || !pwd->pw_gecos ||
	    !pwd->pw_dir || !pwd->pw_shell) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}
	pwd->pw_uid = (uid_t)uid;
	pwd->pw_gid = (gid_t)gid;
	*errnop = 0;
	return NSS_STATUS_SUCCESS;
}

static nss_status lookup_passwd(int by_uid, uid_t uid, const char *name,
                                struct passwd *pwd, char *buffer, size_t buflen,
                                int *errnop)
{
	char file[4096];
	char line[512];
	ssize_t n;
	size_t i = 0;
	if (!pwd || !buffer || !errnop)
		return NSS_STATUS_UNAVAIL;
	n = read_file("/etc/passwd", file, sizeof(file));
	if (n <= 0) {
		*errnop = ENOENT;
		return NSS_STATUS_NOTFOUND;
	}
	while (i < (size_t)n) {
		size_t len = 0;
		char *fields[7];
		int nf;
		while (i + len < (size_t)n && file[i + len] != '\n')
			len++;
		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		xmemcpy(line, file + i, len);
		line[len] = '\0';
		i += len + (i + len < (size_t)n ? 1 : 0);
		if (!line[0] || line[0] == '#')
			continue;
		nf = split_colon(line, fields, 7);
		if (nf < 7)
			continue;
		if (by_uid) {
			unsigned u;
			if (parse_u32(fields[2], &u) != 0 || (uid_t)u != uid)
				continue;
		} else {
			if (!name || xstrcmp(fields[0], name) != 0)
				continue;
		}
		return fill_passwd(pwd, buffer, buflen, errnop,
		                   fields[0], fields[1], fields[2], fields[3],
		                   fields[4], fields[5], fields[6]);
	}
	*errnop = ENOENT;
	return NSS_STATUS_NOTFOUND;
}

nss_status _nss_files_getpwuid_r(uid_t uid, struct passwd *pwd,
                                 char *buffer, size_t buflen, int *errnop)
{
	return lookup_passwd(1, uid, 0, pwd, buffer, buflen, errnop);
}

nss_status _nss_files_getpwnam_r(const char *name, struct passwd *pwd,
                                 char *buffer, size_t buflen, int *errnop)
{
	return lookup_passwd(0, 0, name, pwd, buffer, buflen, errnop);
}

static nss_status fill_group(struct group *gr, char *buffer, size_t buflen,
                             int *errnop, char *name, char *passwd, char *gid_s,
                             char *mem_csv)
{
	char *cur;
	char *end;
	char **mem;
	unsigned gid;
	int nmem = 0;
	int i;
	char *p;
	if (!gr || !buffer || buflen < 16 || !errnop)
		return NSS_STATUS_UNAVAIL;
	if (parse_u32(gid_s, &gid) != 0)
		return NSS_STATUS_NOTFOUND;
	cur = buffer;
	end = buffer + buflen;
	/* Count members */
	if (mem_csv && mem_csv[0]) {
		nmem = 1;
		for (p = mem_csv; *p; p++)
			if (*p == ',')
				nmem++;
	}
	/* pointer table + NULL at end */
	if (cur + (size_t)(nmem + 1) * sizeof(char *) > end) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}
	mem = (char **)(void *)cur;
	cur += (size_t)(nmem + 1) * sizeof(char *);
	gr->gr_name = buf_copy(&cur, end, name ? name : "");
	gr->gr_passwd = buf_copy(&cur, end, passwd ? passwd : "x");
	if (!gr->gr_name || !gr->gr_passwd) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}
	gr->gr_gid = (gid_t)gid;
	gr->gr_mem = mem;
	i = 0;
	if (nmem > 0) {
		char *m = mem_csv;
		for (;;) {
			char *comma = m;
			while (*comma && *comma != ',')
				comma++;
			if (*comma)
				*comma = '\0';
			mem[i] = buf_copy(&cur, end, m);
			if (!mem[i]) {
				*errnop = ERANGE;
				return NSS_STATUS_TRYAGAIN;
			}
			i++;
			if (!*comma)
				break;
			m = comma + 1;
		}
	}
	mem[i] = 0;
	*errnop = 0;
	return NSS_STATUS_SUCCESS;
}

static nss_status lookup_group(int by_gid, gid_t gid, const char *name,
                               struct group *gr, char *buffer, size_t buflen,
                               int *errnop)
{
	char file[2048];
	char line[256];
	ssize_t n;
	size_t i = 0;
	if (!gr || !buffer || !errnop)
		return NSS_STATUS_UNAVAIL;
	n = read_file("/etc/group", file, sizeof(file));
	if (n <= 0) {
		*errnop = ENOENT;
		return NSS_STATUS_NOTFOUND;
	}
	while (i < (size_t)n) {
		size_t len = 0;
		char *fields[4];
		int nf;
		while (i + len < (size_t)n && file[i + len] != '\n')
			len++;
		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		xmemcpy(line, file + i, len);
		line[len] = '\0';
		i += len + (i + len < (size_t)n ? 1 : 0);
		if (!line[0] || line[0] == '#')
			continue;
		nf = split_colon(line, fields, 4);
		if (nf < 3)
			continue;
		if (by_gid) {
			unsigned g;
			if (parse_u32(fields[2], &g) != 0 || (gid_t)g != gid)
				continue;
		} else {
			if (!name || xstrcmp(fields[0], name) != 0)
				continue;
		}
		return fill_group(gr, buffer, buflen, errnop,
		                  fields[0], fields[1], fields[2],
		                  nf >= 4 ? fields[3] : "");
	}
	*errnop = ENOENT;
	return NSS_STATUS_NOTFOUND;
}

nss_status _nss_files_getgrgid_r(gid_t gid, struct group *gr,
                                 char *buffer, size_t buflen, int *errnop)
{
	return lookup_group(1, gid, 0, gr, buffer, buflen, errnop);
}

nss_status _nss_files_getgrnam_r(const char *name, struct group *gr,
                                 char *buffer, size_t buflen, int *errnop)
{
	return lookup_group(0, 0, name, gr, buffer, buflen, errnop);
}

/* Enumeration / remaining DB types: still NOTFOUND (unused by whoami/PS1). */
#define STUB_NF(name) \
	nss_status name(void) { return NSS_STATUS_NOTFOUND; }

STUB_NF(_nss_files_getpwent_r)
STUB_NF(_nss_files_setpwent)
STUB_NF(_nss_files_endpwent)
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
