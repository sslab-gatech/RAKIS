#include "rakis/pktbpool.h"
#include "rakis/stack/rakis_misc.h"

#if defined (RAKIS_VERIFICATION)
#include "rakis/fv/host.h"
#define fill_pktbsizepool(a)
#else
#ifndef RAKIS_FUZZ
#include "libos_utils.h"
#endif
// these functions are removed in sec/verification
// and replaced with malloc and free as it will cause
// path explosion

RAKIS_INLINE
void fill_pktbsizepool(struct pktbsizepool* pktbsizepool){
  RAKIS_STAT_DURATION_START(pktbpool_alloc_fill_duration);

  for (size_t j = 0; j < PKTBPOOL_SIZEPOOL_FILL_COUNT; ++j) {
    struct pktb* pktb = malloc(pktbsizepool->size + sizeof(struct pktb));
    if (pktb == NULL) {
      break;
    }

    pktb->sizepool = pktbsizepool;
    pktb->next = pktbsizepool->free_list;
    pktbsizepool->free_list = pktb;
  }

  RAKIS_STAT_DURATION_END(pktbpool_alloc_fill_duration);
}

RAKIS_INLINE
struct pktbsizepool* find_closest_sizepool(struct pktbpool* pool, u32 size) {
  // if size is smaller than the smallest sizepool, use smallest sizepool
  size = (size < pool->slot_size_increment) ? pool->slot_size_increment : size;

  u32 size_less_min = size - pool->slot_size_increment;
  u32 index = (size_less_min) / pool->slot_size_increment;
  if ((size_less_min % pool->slot_size_increment) != 0) {
    index++;
  }

  if (index >= PKTBPOOL_SIZEPOOL_COUNT) {
    return NULL;
  }

  return &pool->sizepools[index];
}
#endif

RAKIS_INLINE
void pktb_init(struct pktb* pktb, u32 len, struct pktbsizepool* sizepool, struct pktb* next) {
  pktb->sizepool = sizepool;
  pktb->next = next;
  pktb->lcpbuf.custom_free_function = pktb_free;
  struct pbuf* p = pbuf_alloced_custom(len, &pktb->lcpbuf, pktb->payload);
  LWIP_ASSERT("creating pbuf for rakis packet failed", p != NULL);
  LWIP_ASSERT("creating pbuf for rakis packet failed", p->payload == pktb->payload);
}

void pktb_free(struct pbuf* pbuf){
  struct pktb* pktb = (struct pktb*)pbuf;
  struct pktbsizepool* sizepool = pktb->sizepool;
  if (sizepool == NULL) {
    // this condition is always true in klee verification
    // as we use malloc and free instead of pktbpool
    free(pktb);
    RAKIS_STAT_INC(pktbpool_free_null);
    return;
  }

  RAKIS_STAT_INC(pktbpool_free_pool);
  RAKIS_SLOCK(&sizepool->lock, &RAKIS_GET_THREAD_STRG(rakis_stats.pktbpool_lock));
  pktb->next = sizepool->free_list;
  sizepool->free_list = pktb;
  RAKIS_SUNLOCK(&sizepool->lock, &RAKIS_GET_THREAD_STRG(rakis_stats.pktbpool_lock));
}

struct pktb* pktb_malloc(struct pktbpool* pool, u32 len){
  RAKIS_STAT_DURATION_START(pktbpool_alloc_duration);

#ifndef RAKIS_VERIFICATION
  struct pktbsizepool* sizepool = find_closest_sizepool(pool, len);
#else
  // force to use malloc/free in klee verification
  // to avoid path explosion
  struct pktbsizepool* sizepool = NULL;
#endif

  if (sizepool == NULL) {
    RAKIS_STAT_INC(pktbpool_alloc_too_large);

    // use malloc
    struct pktb* pktb = malloc(len + sizeof(struct pktb));
    if (pktb == NULL) {
      return NULL;
    }

    pktb_init(pktb, len, NULL, NULL);
    return pktb;
  }

  RAKIS_SLOCK(&sizepool->lock, &RAKIS_GET_THREAD_STRG(rakis_stats.pktbpool_lock));

  if (sizepool->free_list == NULL) {
    RAKIS_STAT_INC(pktbpool_alloc_fill_count);
    fill_pktbsizepool(sizepool);

  }else{
    RAKIS_STAT_INC(pktbpool_alloc_nofill_count);
  }

  struct pktb* pktb = sizepool->free_list;
  if (pktb == NULL) {
    RAKIS_SUNLOCK(&sizepool->lock, &RAKIS_GET_THREAD_STRG(rakis_stats.pktbpool_lock));
    return NULL;
  }

  sizepool->free_list = pktb->next;
  RAKIS_SUNLOCK(&sizepool->lock, &RAKIS_GET_THREAD_STRG(rakis_stats.pktbpool_lock));

  pktb_init(pktb, len, sizepool, NULL);
  RAKIS_STAT_DURATION_END(pktbpool_alloc_duration);
  return pktb;
}

struct pktbpool* pktbpool_create(u32 slot_size_increment){
  struct pktbpool* pool = malloc(sizeof(struct pktbpool));
  if (pool == NULL) {
    return NULL;
  }
  pool->slot_size_increment = slot_size_increment;

  for (size_t i = 0; i < PKTBPOOL_SIZEPOOL_COUNT; ++i) {
    pool->sizepools[i].size = (i+1) * pool->slot_size_increment;
    pool->sizepools[i].free_list = NULL;
    fill_pktbsizepool(&pool->sizepools[i]);

    rakis_spinlock_init(&pool->sizepools[i].lock);
  }

  return pool;
}
