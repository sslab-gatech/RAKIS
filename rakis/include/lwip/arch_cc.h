#ifndef RAKIS_LWIP_ARCH_CC_H
#define RAKIS_LWIP_ARCH_CC_H

#ifndef	SSIZE_MAX
# if __WORDSIZE == 64 || __WORDSIZE32_SIZE_ULONG
#  define SSIZE_MAX	LONG_MAX
# else
#  define SSIZE_MAX	INT_MAX
# endif
#endif

#if defined(RAKIS_FUZZ)
#include "rakis/fuzz/log.h"
#elif !defined(RAKIS_VERIFICATION)
#include "log.h"
#endif

#define LWIP_PLATFORM_DIAG(x) log_debug x
#define LWIP_PLATFORM_ASSERT(x) do { \
  log_error("Assertion \"%s\" failed at line %d in %s\n", x, __LINE__, __FILE__); \
  for(;;); \
} while(0)

#define LWIP_ERRNO_STDINCLUDE 1
#define LWIP_NO_CTYPE_H 1

#define SA_FAMILY_T_DEFINED 1
#define GSNE_USE_SYS_SOCK_TYPES 1

#define LWIP_DEBUG                0
#define SOCKETS_DEBUG             0

#endif
