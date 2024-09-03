#ifndef RAKIS_PKTQ_H_
#define RAKIS_PKTQ_H_
#include "rakis/common.h"
#include "rakis/stack/rakis_spinlock.h"

struct pktq{
  struct rakis_spinlock prod_lock;
  struct rakis_spinlock cons_lock;

  u32  size;
  u32  mask;

  u32  prod_cached_prod;
  u32  prod_cached_cons;
  u32  producer;

  u32  cons_cached_prod;
  u32  cons_cached_cons;
  u32  consumer;
  struct pbuf* ring[];
};


void pktq_enqueue_override_pbuf_unlocked(struct pktq* pktq, struct pbuf* pbuf_new);
void pktq_free_queue_pbufs_unlocked(struct pktq* pktq);
bool pktq_new(struct pktq** pktq, size_t pktq_size);

RAKIS_INLINE
void pktq_enqueue_commit_prod_locked(struct pktq* q, struct pbuf* pbuf){
  q->ring[q->prod_cached_prod & q->mask] = pbuf;
  q->prod_cached_prod++;
}

RAKIS_INLINE
void pktq_enqueue_push_prod_locked(struct pktq* q){
  __atomic_store_n(&q->producer, q->prod_cached_prod, __ATOMIC_RELEASE);
}

RAKIS_INLINE
u32 pktq_can_enqueue_prod_locked(struct pktq* q){
  u32 free_entries = q->prod_cached_cons - q->prod_cached_prod;
  if (free_entries > 0) {
    return free_entries;
  }

  q->prod_cached_cons  = __atomic_load_n(&q->consumer, __ATOMIC_ACQUIRE);
  q->prod_cached_cons += q->size;

  free_entries = q->prod_cached_cons - q->prod_cached_prod;
  return free_entries;
}

RAKIS_INLINE
struct pbuf* pktq_dequeue_peek_cons_locked(struct pktq* q){
  return q->ring[q->cons_cached_cons & q->mask];
}

RAKIS_INLINE
struct pbuf* pktq_dequeue_commit_cons_locked(struct pktq* q){
  struct pbuf* pbuf = q->ring[q->cons_cached_cons & q->mask];
  q->cons_cached_cons++;
  return pbuf;
}

RAKIS_INLINE
void pktq_dequeue_push_cons_locked(struct pktq* q){
  __atomic_store_n(&q->consumer, q->cons_cached_cons, __ATOMIC_RELEASE);
}

RAKIS_INLINE
u32 pktq_can_dequeue_cons_locked(struct pktq* q){
  u32 avail_entries = q->cons_cached_prod - q->cons_cached_cons;

  if (avail_entries == 0) {
    q->cons_cached_prod = __atomic_load_n(&q->producer, __ATOMIC_ACQUIRE);
    avail_entries = q->cons_cached_prod - q->cons_cached_cons;
  }

  return avail_entries;
}
#endif
