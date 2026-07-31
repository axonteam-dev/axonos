/* Shared nodename / domainname for uname(2), gethostname(2), /proc/sys/kernel/*. */
#pragma once

#include <stddef.h>

#define UTS_NODENAME_MAX 64

void uts_hostname_init(void);
const char *uts_hostname_get(void);
const char *uts_domainname_get(void);
/* Copy without trailing newline; returns 0 or -1. */
int uts_hostname_set(const char *buf, size_t len);
int uts_domainname_set(const char *buf, size_t len);
