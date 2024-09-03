#include "lwip/pbuf.h"
#include "rakis/pktq.h"
#include "rakis/stack/rakis_misc.h"

#if defined (RAKIS_VERIFICATION)
#include "rakis/fv/host.h"
#elif !defined (RAKIS_FUZZ)
#include "libos_utils.h"
#endif

void pktq_enqueue_override_pbuf_unlocked(struct pktq* pktq, struct pbuf* pbuf_new){
  RAKIS_SLOCK(&pktq->prod_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_prod_lock));

  // if the queue is full, we take the consumer lock and drop the oldest packet
  if (pktq_can_enqueue_prod_locked(pktq) == 0) {
    RAKIS_SLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));

    // now we are holding two locks
    // we check again because maybe the consumer values changed while we were waiting for the lock
    if (pktq_can_enqueue_prod_locked(pktq) == 0) {
      RAKIS_STAT_INC(pktq_enqueue_drop);

      if (pktq_can_dequeue_cons_locked(pktq) > 0) {
        struct pbuf* p = (struct pbuf*) pktq_dequeue_commit_cons_locked(pktq);
        pbuf_free(p);
        pktq_dequeue_push_cons_locked(pktq);
      }

      // update the producer's consumer values after dropping the packet
      pktq_can_enqueue_prod_locked(pktq);
    }

    RAKIS_SUNLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
  }

  pktq_enqueue_commit_prod_locked(pktq, pbuf_new);
  pktq_enqueue_push_prod_locked(pktq);

  RAKIS_SUNLOCK(&pktq->prod_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_prod_lock));
}

void pktq_free_queue_pbufs_unlocked(struct pktq* pktq){
  RAKIS_SLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
  do {
    u32 remaining_packets = pktq_can_dequeue_cons_locked(pktq);
    if (remaining_packets == 0) {
      break;
    }

    for (u32 i = 0; i < remaining_packets; i++) {
      struct pbuf* p = (struct pbuf*) pktq_dequeue_commit_cons_locked(pktq);
      pbuf_free(p);
    }
  } while (true);
  pktq_dequeue_push_cons_locked(pktq);
  RAKIS_SUNLOCK(&pktq->cons_lock, &RAKIS_GET_THREAD_STRG(rakis_stats.sockets_pktq_cons_lock));
  free(pktq);
}

bool pktq_new(struct pktq** pktq, size_t pktq_size){
  struct pktq* q = malloc(sizeof(struct pktq) + pktq_size * sizeof(void*));
  if (q == NULL) {
    return false;
  }

  q->prod_lock.lock = SPINLOCK_UNLOCKED;
  q->cons_lock.lock = SPINLOCK_UNLOCKED;
  q->size = pktq_size;
  q->mask = pktq_size - 1;

  q->prod_cached_prod = 0;
  q->prod_cached_cons = q->size;
  q->producer = 0;

  q->cons_cached_prod = 0;
  q->cons_cached_cons = 0;
  q->consumer = 0;

  *pktq = q;
  return true;
}


