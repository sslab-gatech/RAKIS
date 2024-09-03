#ifndef RAKIS_PKTBPOOL_H
#define RAKIS_PKTBPOOL_H
#include "lwip/pbuf.h"
#include "rakis/common.h"
#include "stack/rakis_spinlock.h"

#ifdef RAKIS_VERIFICATION
#define PKTBPOOL_SIZEPOOL_COUNT 2
#define PKTBPOOL_SIZEPOOL_FILL_COUNT 2
#else
#define PKTBPOOL_SIZEPOOL_COUNT 10
#define PKTBPOOL_SIZEPOOL_FILL_COUNT 16
#endif

struct pktbpool{
  struct pktbsizepool{
    u16 size;
    struct pktb* free_list;
    struct rakis_spinlock lock;
  } sizepools[PKTBPOOL_SIZEPOOL_COUNT];

  u32 slot_size_increment;
};

struct pktb{
  struct pbuf_custom lcpbuf;
  struct pktbsizepool* sizepool;
  struct pktb* next;
  u8 payload[];
};

void pktb_free(struct pbuf* lpbuf);
struct pktb* pktb_malloc(struct pktbpool* pool, u32 len);
struct pktbpool* pktbpool_create(u32 slot_size_increment);
#endif
