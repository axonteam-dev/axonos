#pragma once

/*
 * Forced in via -include: pulls generated autoconf.h and maps option names
 * onto the legacy AXON_* / DEVEL_* / NET_* macros still used in the tree.
 *
 * New code: #ifdef FAT32_SUPPORT (names match config.cfg as written).
 */

#include <generated/autoconf.h>

#ifdef AXON_PRODUCTION
# undef AXON_PRODUCTION
# define AXON_PRODUCTION 1
#elif !defined(AXON_PRODUCTION)
# define AXON_PRODUCTION 0
#endif

#ifdef DEVEL_DEBUG
# undef DEVEL_DEBUG
# define DEVEL_DEBUG 1
#elif !defined(DEVEL_DEBUG)
# define DEVEL_DEBUG 0
#endif

#ifdef AXON_FORK_DEBUG
# undef AXON_FORK_DEBUG
# define AXON_FORK_DEBUG 1
#elif !defined(AXON_FORK_DEBUG)
# define AXON_FORK_DEBUG DEVEL_DEBUG
#endif

#if AXON_PRODUCTION
# undef DEVEL_DEBUG
# define DEVEL_DEBUG 0
# undef AXON_FORK_DEBUG
# define AXON_FORK_DEBUG 0
#endif

#ifdef NET_TCP_TRACE
# undef NET_TCP_TRACE
# define NET_TCP_TRACE 1
#elif !defined(NET_TCP_TRACE)
# define NET_TCP_TRACE 0
#endif

#ifdef AXON_WGET_DNS_TRACE
# undef AXON_WGET_DNS_TRACE
# define AXON_WGET_DNS_TRACE 1
#elif !defined(AXON_WGET_DNS_TRACE)
# define AXON_WGET_DNS_TRACE 0
#endif

#ifdef KBD_DEBUG
# undef KBD_DEBUG
# define KBD_DEBUG 1
#elif !defined(KBD_DEBUG)
# define KBD_DEBUG 0
#endif

#ifdef QEMU_LOG
# define QEMU_LOG_ENABLE 1
#endif

#ifdef KERNEL_LOG_TIME
# define KERNEL_LOG_TIME 1
#endif
