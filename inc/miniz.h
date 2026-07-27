/* Minimal miniz.h for tinfl-only kernel builds. */
#pragma once

#ifndef MINIZ_NO_STDIO
#define MINIZ_NO_STDIO
#endif
#ifndef MINIZ_NO_TIME
#define MINIZ_NO_TIME
#endif
#ifndef MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_APIS
#endif
#ifndef MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#endif
#ifndef MINIZ_NO_DEFLATE_APIS
#define MINIZ_NO_DEFLATE_APIS
#endif
#ifndef MINIZ_NO_ZLIB_APIS
#define MINIZ_NO_ZLIB_APIS
#endif
#ifndef MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#endif
#ifndef MINIZ_USE_UNALIGNED_LOADS_AND_STORES
#define MINIZ_USE_UNALIGNED_LOADS_AND_STORES 1
#endif
#ifndef MINIZ_LITTLE_ENDIAN
#define MINIZ_LITTLE_ENDIAN 1
#endif
#ifndef MINIZ_HAS_64BIT_REGISTERS
#define MINIZ_HAS_64BIT_REGISTERS 1
#endif

#include <miniz_export.h>
#include <miniz_common.h>
/* tinfl.h is included by miniz_tinfl.c / consumers explicitly */
