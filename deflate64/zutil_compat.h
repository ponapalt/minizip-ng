/* zutil_compat.h -- minimal zutil.h compatibility for infback9
 * Copyright (C) 2025 - minizip-ng project
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

#ifndef ZUTIL_COMPAT_H
#define ZUTIL_COMPAT_H

#include <stdlib.h>
#include <string.h>
#include "zlib.h"

/* Memory allocation macros */
#define ZALLOC(strm, items, size) \
    (*((strm)->zalloc))((strm)->opaque, (items), (size))
#define ZFREE(strm, addr) \
    (*((strm)->zfree))((strm)->opaque, (voidpf)(addr))

/* Memory operation macros */
#define zmemcpy memcpy
#define zmemzero(dest, len) memset(dest, 0, len)

/* Debug trace macros - disabled by default */
#ifndef ZLIB_DEBUG
#  define Tracev(x)
#  define Tracevv(x)
#else
#  include <stdio.h>
#  define Tracev(x) do { if (z_verbose >= 0) fprintf x; } while (0)
#  define Tracevv(x) do { if (z_verbose > 0) fprintf x; } while (0)
   extern int z_verbose;
#endif

#endif /* ZUTIL_COMPAT_H */
