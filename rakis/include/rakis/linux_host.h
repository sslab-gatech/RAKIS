#ifndef _RAKIS_LINUX_HOST_H
#define _RAKIS_LINUX_HOST_H

#include "rakis/common.h"
#include <linux/mman.h>
#include <stddef.h>

// Types & defs specific to linux

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

// BPF
enum bpf_cmd {
  BPF_MAP_CREATE,
  BPF_MAP_LOOKUP_ELEM,
  BPF_MAP_UPDATE_ELEM,
  BPF_MAP_DELETE_ELEM,
};

enum {
  BPF_ANY		= 0, /* create new element or update existing */
  BPF_NOEXIST	= 1, /* create new element if it didn't exist */
  BPF_EXIST	= 2, /* update existing element */
  BPF_F_LOCK	= 4, /* spin_lock-ed map_lookup/map_update */
};

union bpf_attr {
  struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
    u32	map_fd;
    __aligned_u64	key;
    union {
      __aligned_u64 value;
      __aligned_u64 next_key;
    };
    u64	flags;
  };
};

#define offsetofend(TYPE, MEMBER) \
  (offsetof(TYPE, MEMBER)	+ sizeof((((TYPE *)0)->MEMBER)))

// if_nametoindex
#define SIOCGIFINDEX	0x8933		/* name -> if_index mapping	*/
struct ifreq {
  char ifr_name[RAKIS_IFNAMSIZ]; /* Interface name */
  union {
    int ifr_ifindex;
  };
};

// unix sockets
#ifndef CMSG_DATA
#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif

#define CMSG_DATA(cmsg)         ((unsigned char*)((struct cmsghdr*)(cmsg) + 1))
#define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr(mhdr, cmsg)
#define CMSG_FIRSTHDR(mhdr)                                   \
  ((size_t)(mhdr)->msg_controllen >= sizeof(struct cmsghdr) \
   ? (struct cmsghdr*)(mhdr)->msg_control               \
   : (struct cmsghdr*)0)
#define CMSG_ALIGN(len) ALIGN_UP(len, sizeof(size_t))
#define CMSG_SPACE(len) (CMSG_ALIGN(len) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_LEN(len)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif

#endif
