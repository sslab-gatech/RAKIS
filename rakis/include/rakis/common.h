#ifndef _RAKIS_COMMON_H
#define _RAKIS_COMMON_H

#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define u64 __u64
#define u32 __u32
#define u16 __u16
#define u8  __u8

#ifndef UNIX_PATH_MAX
#define RAKIS_UNIX_PATH_MAX 108
#else
#define RAKIS_UNIX_PATH_MAX UNIX_PATH_MAX
#endif

#ifndef IFNAMSIZ
#define RAKIS_IFNAMSIZ 16
#else
#define RAKIS_IFNAMSIZ IFNAMSIZ
#endif

#ifndef NS_INADDRSZ
#define NS_INADDRSZ 4
#endif

#define RAKIS_INLINE static inline __attribute__((__always_inline__))

#endif
