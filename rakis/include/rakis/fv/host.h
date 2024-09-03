#ifndef RAKIS_VERIFICATION_H
#define RAKIS_VERIFICATION_H

#ifndef RAKIS_VERIFICATION
#error "This file should not be included unless for klee verification compilation"
#endif

#include "rakis/common.h"
#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/mman.h>
#include <linux/un.h>
#include <net/if.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

// capabilities
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#define _LINUX_CAPABILITY_U32S_3    2

#define CAP_NET_RAW 13
#define CAP_BPF			39

typedef enum {
  CAP_EFFECTIVE = 0,                 /* Specifies the effective flag */
  CAP_PERMITTED = 1,                 /* Specifies the permitted flag */
  CAP_INHERITABLE = 2                /* Specifies the inheritable flag */
} cap_flag_t;

typedef struct __user_cap_header_struct {
  u32 version;
  int pid;
} *cap_user_header_t;

typedef struct __user_cap_data_struct {
  u32 effective;
  u32 permitted;
  u32 inheritable;
} *cap_user_data_t;

struct rakis__cap_struct {
  struct __user_cap_header_struct head;
  union {
    struct __user_cap_data_struct set;
    u32 flat[3];
  } u[_LINUX_CAPABILITY_U32S_3];
};

#define raise_cap(x,set)   u[(x)>>5].flat[set]       |=  (1<<((x)&31))
#define lower_cap(x,set)   u[(x)>>5].flat[set]       &= ~(1<<((x)&31))
typedef struct rakis__cap_struct *cap_t;

#define offsetofend(TYPE, MEMBER) \
  (offsetof(TYPE, MEMBER)	+ sizeof((((TYPE *)0)->MEMBER)))

#ifdef RAKIS_SYMBOLIC
#define log_error(args...)
#define log_debug(args...)
#define log_always(args...)
#else
#define log_error(args...) printf(args); fflush(stdout);
#define log_debug(args...) printf(args); fflush(stdout);
#define log_always(args...) printf(args); fflush(stdout);
#endif

#define DO_SYSCALL(name, args...)  syscall(__NR_##name, ##args)

#define PAGE_SIZE       (1ul << 12)

#define ALIGN_DOWN_POW2(val, alignment) ((val) - ((val) & ((alignment) - 1)))
#define ALIGN_UP_POW2(val, alignment)   ALIGN_DOWN_POW2((val) + (alignment) - 1, alignment)
#define IS_ALIGNED(val, alignment)     ((val) % (alignment) == 0)

#define MIN(a, b)               \
    ({                          \
        __typeof__(a) _a = (a); \
        __typeof__(b) _b = (b); \
        _a < _b ? _a : _b;      \
    })

#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, y) do { (x) = (y); } while (0)

#define __ntohs ntohs
#define __htons htons
#define __htonl htonl

#define sgx_is_valid_untrusted_ptr(ptr, sz, ag) true
#endif

