#include "lwip/pbuf.h"
#include "rakis/if_xdp.h"
#include "rakis/pktbpool.h"
#include "rakis/rakis_memcpy.h"
#include "rakis/rakis_ring.h"
#include "rakis/stack/rakis_misc.h"
#include "rakis/xsk.h"

#ifdef RAKIS_VERIFICATION
#include "rakis/fv/host.h"
#define RAKIS_XSK_PKTQ_SIZE           2
#else
#include "libos_utils.h"
#define RAKIS_XSK_PKTQ_SIZE           128
#endif

#define RAKIS_XSK_UMEM_OOF         UINT64_MAX
#define RAKIS_XSK_UMEM_BK_RESERVED UINT64_MAX - 1

#define FRAME_SZ(__XSK) (__XSK->cfg->frame_size)
#define UMEM_SZ(__XSK) (__XSK->cfg->umem_size)
#define UMEM_FRAMES_NUM(__XSK) (UMEM_SZ(__XSK) / FRAME_SZ(__XSK))
#define FREE_FRAMES_NUM(__XSK) (__XSK->frame_allocator.umem_free_frames_num)
#define FRAME_BK2UMEM(__XSK, __IDX) (__XSK->frame_allocator.umem_frames_booked_map[__IDX])
#define FRAME_OWNER(__XSK, __IDX) (__XSK->frame_allocator.umem_frames_owner_map[__IDX])
#define FRAME_MASKED(__XSK, __FR) ((__FR) & __XSK->frame_mask)
#define FRAME_OWNER_CHECK(__XSK, __FIDX, __OWNER) (FRAME_OWNER(__XSK, \
                                                    FRAME_MASKED(__XSK, __FIDX) / FRAME_SZ(__XSK)) == __OWNER)

struct rakis_xsk{
  struct rakis_spinlock allocator_lock;

  int   fd;
  u32   qid;
  int   bpf_map_fd;
  u64   frame_mask;
  void *umem_area;

  struct rakis_spinlock fill_lock;
  struct rakis_ring_prod fill_ring;

  struct rakis_spinlock compl_lock;
  struct rakis_ring_cons compl_ring;

  struct rakis_spinlock tx_lock;
  struct rakis_ring_prod tx_ring;

  struct rakis_spinlock rx_lock;
  struct rakis_ring_cons rx_ring;

  struct pktbpool      *pktbpool;
  struct pktq          *pktq;
  struct rakis_xsk_cfg *cfg;
  struct rakis_netif   *rakis_netif;

  struct frame_allocator{
    u64  umem_free_frames_num;
    u64 *umem_frames_booked_map;

    enum rakis_umem_frame_owner{
      RAKIS_XSK_UMEM_OWNER_FREE = 1,
      RAKIS_XSK_UMEM_OWNER_TX   = 2,
      RAKIS_XSK_UMEM_OWNER_RX   = 3
    } *umem_frames_owner_map;
  } frame_allocator;
};


#if defined(RAKIS_VERIFICATION) && defined(RAKIS_SYMBOLIC)
static inline void rakis_fv_xsk_verify_umem_frame_offset(struct rakis_xsk* xsk, u64 frame_offset){
  // verify that the frame is within the umem area
  klee_assert(frame_offset >= 0);
  klee_assert(frame_offset < UMEM_SZ(xsk));

  u64 frame_aligned = frame_offset & xsk->frame_mask;
  klee_assert(frame_offset == frame_aligned);
}

static inline void rakis_fv_xsk_verify_umem_frame_abs(struct rakis_xsk* xsk, void* frame, u32 size){
  // verify that the frame is within the umem area
  klee_assert(frame >= 0);
  klee_assert(size > 0);
  klee_assert((frame >= xsk->umem_area) &&
      ((frame + size) <= (xsk->umem_area + xsk->cfg->umem_size)));

  // verify that we are writing within one frame
  u64 umem_offset = frame - xsk->umem_area;
  u64 umem_start = umem_offset & xsk->frame_mask;
  u64 umem_end = (umem_offset + size - 1) & xsk->frame_mask;
  klee_assert(umem_start == umem_end);
}

#define RAKIS_XSK_CREATE_RING_GETTER(__PC, __R) \
  struct rakis_ring_##__PC* rakis_xsk_get_##__PC##_##__R##_ring(struct rakis_xsk* xsk){ \
    return &xsk->__R##_ring; \
  }

RAKIS_XSK_CREATE_RING_GETTER(prod, fill);
RAKIS_XSK_CREATE_RING_GETTER(cons, compl);
RAKIS_XSK_CREATE_RING_GETTER(prod, tx);
RAKIS_XSK_CREATE_RING_GETTER(cons, rx);
#else
#define rakis_fv_xsk_verify_umem_frame_abs(a, b, c)
#define rakis_fv_xsk_verify_umem_frame_offset(a, b)
#endif

RAKIS_INLINE
bool validate_umem_frame_offset(struct rakis_xsk* xsk, u64 offset){
  // within umem range
  if(offset < UMEM_SZ(xsk)){
    return true;
  }

  return false;
}

RAKIS_INLINE
bool validate_umem_frame_bound(struct rakis_xsk* xsk, u64 offset, u32 len){
  // they must be the same if the len is within chunk size
  if (FRAME_MASKED(xsk, offset) != FRAME_MASKED(xsk, offset + len - 1)) {
    return false;
  }

  // now just check that the offset is valid offset
  return validate_umem_frame_offset(xsk, offset);
}

RAKIS_INLINE
u8* xsk_get_umem_abs_addr(struct rakis_xsk* xsk, u64 addr){
  assert(validate_umem_frame_offset(xsk, addr));
  u8 *umem_addr = (u8*) xsk->umem_area;
  umem_addr += addr;
  return umem_addr;
}

RAKIS_INLINE
void xsk_frame_free(struct rakis_xsk* xsk, u64 frame, enum rakis_umem_frame_owner old_owner){
  u64 num_frames = UMEM_FRAMES_NUM(xsk);
  u64 frame_idx = FREE_FRAMES_NUM(xsk);

  // sanity checks
  assert(FREE_FRAMES_NUM(xsk) < num_frames);
  assert(FRAME_BK2UMEM(xsk, frame_idx) == RAKIS_XSK_UMEM_BK_RESERVED);
  assert(validate_umem_frame_offset(xsk, frame));
  assert(old_owner != RAKIS_XSK_UMEM_OWNER_FREE);

  frame = FRAME_MASKED(xsk, frame);
  u64 owner_idx = frame / FRAME_SZ(xsk);
  enum rakis_umem_frame_owner owner_check = FRAME_OWNER(xsk, owner_idx);
  assert(old_owner == owner_check);

  // insert the frame into bucket to be allocated later
  rakis_fv_xsk_verify_umem_frame_offset(xsk, frame);
  FRAME_BK2UMEM(xsk, frame_idx) = frame;
  FRAME_OWNER(xsk, owner_idx) = RAKIS_XSK_UMEM_OWNER_FREE;
  FREE_FRAMES_NUM(xsk)++;
}

RAKIS_INLINE
u64 xsk_frame_alloc(struct rakis_xsk* xsk, enum rakis_umem_frame_owner new_owner){
  // out-of-frames to give
  if (FREE_FRAMES_NUM(xsk) == 0){
    return RAKIS_XSK_UMEM_OOF;
  }

  // decrement the number of free frames
  FREE_FRAMES_NUM(xsk)--;

  // take the top frame
  u64 frame_idx = FREE_FRAMES_NUM(xsk);
  u64 frame = FRAME_BK2UMEM(xsk, frame_idx);

  // sanity checks
  assert(frame != RAKIS_XSK_UMEM_BK_RESERVED);
  assert(FRAME_MASKED(xsk, frame) == frame);
  assert(validate_umem_frame_offset(xsk, frame));
  assert(new_owner != RAKIS_XSK_UMEM_OWNER_FREE);

  u64 owner_idx = frame / xsk->cfg->frame_size;
  enum rakis_umem_frame_owner old_owner = FRAME_OWNER(xsk, owner_idx);
  assert(old_owner == RAKIS_XSK_UMEM_OWNER_FREE);

  // mark the taken frame as reserved and update the stats
  FRAME_BK2UMEM(xsk, frame_idx) = RAKIS_XSK_UMEM_BK_RESERVED;
  FRAME_OWNER(xsk, owner_idx) = new_owner;

  rakis_fv_xsk_verify_umem_frame_offset(xsk, frame);
  return frame;
}

RAKIS_INLINE
int rakis_xsk_init_frame_allocator(struct rakis_xsk* xsk){
  FREE_FRAMES_NUM(xsk) = UMEM_FRAMES_NUM(xsk);

  // allocate the frame booker map
  xsk->frame_allocator.umem_frames_booked_map = calloc(UMEM_FRAMES_NUM(xsk), sizeof(u64));
  if (!xsk->frame_allocator.umem_frames_booked_map) {
    log_error("calloc failed for umem frame allocator booker map");
    return -1;
  }

  // allocate the frame owner map
  xsk->frame_allocator.umem_frames_owner_map = calloc(UMEM_FRAMES_NUM(xsk), sizeof(u64));
  if (!xsk->frame_allocator.umem_frames_owner_map) {
    log_error("calloc failed for umem frame allocator owner map");
    return -1;
  }

  // initially, all frames are free
  for (u32 i =0; i < UMEM_FRAMES_NUM(xsk); i++) {
    FRAME_BK2UMEM(xsk, i) = i * FRAME_SZ(xsk);
    FRAME_OWNER(xsk, i) = RAKIS_XSK_UMEM_OWNER_FREE;
  }

  return 0;
}

RAKIS_INLINE
void xsk_fill_routine(struct rakis_xsk* xsk){
  u32 ensured_frames,
        fr_free, idx_fr, alloc_free;
  struct rakis_ring_prod *fr;

  RAKIS_STAT_DURATION_START(xsk_fill_duration);

  fr = &xsk->fill_ring;

  RAKIS_SLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
  alloc_free = FREE_FRAMES_NUM(xsk);
  if (alloc_free == 0) {
    // our frame allocator is empty
    RAKIS_SUNLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
    RAKIS_STAT_INC(xsk_fill_empty_alloc);
    return;
  }

  fr_free = rakis_ring_prod_free_num(fr, alloc_free);
  if (fr_free == 0) {
    // we do not need to ensure any frames, fill ring is full
    RAKIS_SUNLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
    RAKIS_STAT_INC(xsk_fill_full_ring);
    return;
  }

  ensured_frames = MIN(fr_free, alloc_free);
  rakis_ring_prod_reserve(fr, ensured_frames, &idx_fr);

  // allocate frames and write them in the ring
  while(ensured_frames > 0){
    u64 frame = xsk_frame_alloc(xsk, RAKIS_XSK_UMEM_OWNER_RX);

    u64 *addrs = rakis_ring_prod_get_elem(fr, idx_fr++);
    WRITE_ONCE(*addrs, frame);

    ensured_frames--;
    RAKIS_STAT_INC(xsk_fill_prod_frames);
  }

  RAKIS_SUNLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
  rakis_ring_prod_submit(fr);

  RAKIS_STAT_DURATION_END(xsk_fill_duration);
}

RAKIS_INLINE
void xsk_compl_routine(struct rakis_xsk* xsk){
  u32 completed, idx_cr;
  struct rakis_ring_cons* cr;

  RAKIS_STAT_DURATION_START(xsk_compl_duration);

  cr = &xsk->compl_ring;
  completed = rakis_ring_cons_avail_num(cr);
  if (completed == 0) {
    // no frames ready to claim
    RAKIS_STAT_INC(xsk_compl_empty_ring);
    return;
  }

  rakis_ring_cons_peek(cr, completed, &idx_cr);

  RAKIS_SLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
  for (u32 i = 0; i < completed; i++){
    u64 *addrs = rakis_ring_cons_get_elem(cr, idx_cr++);

    u64 v = RAKIS_COPY_UNTRUSTED_VALUE(addrs);
    if (!validate_umem_frame_offset(xsk, v) ||
        !FRAME_OWNER_CHECK(xsk, v, RAKIS_XSK_UMEM_OWNER_TX)) {

      RAKIS_STAT_INC(xsk_compl_invalid_frame);
      continue;
    }

    xsk_frame_free(xsk, v, RAKIS_XSK_UMEM_OWNER_TX);
    RAKIS_STAT_INC(xsk_compl_cons_frames);
  }

  RAKIS_SUNLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
  rakis_ring_cons_release(cr);

  RAKIS_STAT_DURATION_END(xsk_compl_duration);
}

RAKIS_INLINE
void xsk_rx_routine(struct rakis_xsk* xsk){
  u32 rcvd = 0, idx_rx = 0;
  struct rakis_ring_cons *rx;
  struct pktq* pktq;
  u8 *umem_abs;

  RAKIS_STAT_DURATION_START(xsk_rx_duration);

  rx = &xsk->rx_ring;
  pktq = xsk->pktq;

  RAKIS_SLOCK(&pktq->prod_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_prod_lock)));
  u32 can_recv = pktq_can_enqueue_prod_locked(xsk->pktq);
  if (can_recv == 0) {
    // our queue is full, we cannot receive any more packets
    RAKIS_STAT_INC(xsk_rx_full_pktq);
    RAKIS_SUNLOCK(&pktq->prod_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_prod_lock)));
    return;
  }

  rcvd = rakis_ring_cons_avail_num(rx);
  if (rcvd == 0) {
    // no frames ready to be received
    RAKIS_STAT_INC(xsk_rx_empty_ring);
    RAKIS_SUNLOCK(&pktq->prod_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_prod_lock)));
    return;
  }

  RAKIS_STAT_DURATION_START(pkt_avg_process_duration);
  u32 recv_batch = MIN(can_recv, rcvd);
  rakis_ring_cons_peek(rx, recv_batch, &idx_rx);

  RAKIS_SLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
  for (u32 i = 0; i < recv_batch; i++) {
    struct xdp_desc *descs = rakis_ring_cons_get_elem(rx, idx_rx++);

    u64 addr_tmp = RAKIS_COPY_UNTRUSTED_VALUE(&descs->addr);
    u32 len_tmp  = RAKIS_COPY_UNTRUSTED_VALUE(&descs->len);

    if (len_tmp == 0 ||
        !validate_umem_frame_bound(xsk, addr_tmp, len_tmp) ||
        !FRAME_OWNER_CHECK(xsk, addr_tmp, RAKIS_XSK_UMEM_OWNER_RX)) {
      continue;

      RAKIS_STAT_INC(xsk_rx_invalid_frame);
    }

    umem_abs = xsk_get_umem_abs_addr(xsk, addr_tmp);
    rakis_fv_xsk_verify_umem_frame_abs(xsk, umem_abs, len_tmp);

    struct pktb* pktb = pktb_malloc(xsk->pktbpool, len_tmp);
    if (pktb != NULL) {
      rakis_memcpy__untrusted(pktb->payload, umem_abs, len_tmp);
      pktq_enqueue_commit_prod_locked(pktq, (struct pbuf*)pktb);
    }

    xsk_frame_free(xsk, addr_tmp, RAKIS_XSK_UMEM_OWNER_RX);

    RAKIS_STAT_INC(xsk_rx_recv_frame);
  }

  RAKIS_SUNLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
  pktq_enqueue_push_prod_locked(pktq);
  RAKIS_SUNLOCK(&pktq->prod_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_pktq_prod_lock)));
  rakis_ring_cons_release(rx);

  RAKIS_STAT_DURATION_END(xsk_rx_duration);
}

u32 rakis_xsk_send(struct rakis_xsk* xsk, struct pbuf* p){
  struct rakis_ring_prod *tx;
  struct xdp_desc *desc;
  unsigned int idx_tx;
  u8 *umem_abs;
  u64 frame_offset;
  u32 len, sent;

  len = p->tot_len;
  if (len == 0) {
    return 0;
  }

  tx = &xsk->tx_ring;
  u32 pkt_sz = (u32)len + XDP_PACKET_HEADROOM;
  if (pkt_sz > FRAME_SZ(xsk)) {
    return 0;
  }

  RAKIS_SLOCK(&xsk->tx_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_tx_lock)));
  u32 can_send = rakis_ring_prod_free_num(tx, 1);
  if (can_send == 0) {
    RAKIS_SUNLOCK(&xsk->tx_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_tx_lock)));
    return 0;
  }

  RAKIS_SLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
  frame_offset = xsk_frame_alloc(xsk, RAKIS_XSK_UMEM_OWNER_TX);
  RAKIS_SUNLOCK(&xsk->allocator_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_alloc_lock)));
  if (frame_offset == RAKIS_XSK_UMEM_OOF) {
    RAKIS_SUNLOCK(&xsk->tx_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_tx_lock)));
    return 0;
  }

  rakis_ring_prod_reserve(tx, 1, &idx_tx);
  desc = rakis_ring_prod_get_elem(tx, idx_tx);
  frame_offset += XDP_PACKET_HEADROOM;
  umem_abs = xsk_get_umem_abs_addr(xsk, frame_offset);
  rakis_fv_xsk_verify_umem_frame_abs(xsk, umem_abs, len);

  WRITE_ONCE(desc->addr, frame_offset);
  WRITE_ONCE(desc->len,  len);
  WRITE_ONCE(desc->options, 0);

  sent = pbuf_copy_partial(p, umem_abs, len, 0);
  rakis_ring_prod_submit(tx);
  RAKIS_SUNLOCK(&xsk->tx_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_tx_lock)));
  return sent;
}

void rakis_xsk_tick(struct rakis_xsk* xsk){
  RAKIS_STAT_DURATION_START(xsk_tick_duration);

  if (RAKIS_STRYLOCK(&xsk->fill_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_fill_lock)))) {
    xsk_fill_routine(xsk);
    RAKIS_SUNLOCK(&xsk->fill_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_fill_lock)));
  }

  if (RAKIS_STRYLOCK(&xsk->compl_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_compl_lock)))) {
    xsk_compl_routine(xsk);
    RAKIS_SUNLOCK(&xsk->compl_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_compl_lock)));
  }

  if (RAKIS_STRYLOCK(&xsk->rx_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_rx_lock)))) {
    xsk_rx_routine(xsk);
    RAKIS_SUNLOCK(&xsk->rx_lock, &(RAKIS_GET_THREAD_STRG(rakis_stats.xsk_rx_lock)));
  }

  RAKIS_STAT_DURATION_END(xsk_tick_duration);

  rakis_fv_sym_prod_ring(&xsk->fill_ring);
  rakis_fv_sym_prod_ring(&xsk->tx_ring);
  rakis_fv_sym_cons_ring(&xsk->compl_ring);
  rakis_fv_sym_cons_ring(&xsk->rx_ring);
}

#ifdef RAKIS_VERIFICATION
int rakis_xsk_get_fd(struct rakis_xsk* xsk){
  return xsk->fd;
}
#endif

void* rakis_xsk_get_pktq(struct rakis_xsk* xsk){
  return xsk->pktq;
}

void* rakis_xsk_get_lwip(struct rakis_xsk* xsk){
  return xsk->rakis_netif->lwip_netif;
}

struct rakis_xsk* rakis_xsk_get_xsk(struct rakis_xsk* xsks, int n){
  return &xsks[n];
}

struct rakis_xsk* rakis_xsk_alloc_xsks(int n){
  return calloc(n, sizeof(struct rakis_xsk));
}

int rakis_new_xsk(
    struct rakis_xsk_cfg* xsk_cfg,
    struct rakis_xsk_pal* xsk_pal,
    struct rakis_netif* rakis_netif,
    struct rakis_xsk* xsk){

  xsk->allocator_lock.lock = SPINLOCK_UNLOCKED;
  xsk->fill_lock.lock      = SPINLOCK_UNLOCKED;
  xsk->compl_lock.lock     = SPINLOCK_UNLOCKED;
  xsk->tx_lock.lock        = SPINLOCK_UNLOCKED;
  xsk->rx_lock.lock        = SPINLOCK_UNLOCKED;

  xsk->fd          = xsk_pal->xsk_fd;
  xsk->qid         = xsk_cfg->qid;
  xsk->bpf_map_fd  = xsk_pal->xsk_bpf_map_fd;
  xsk->frame_mask  = ~((u64)xsk_cfg->frame_size - 1);
  xsk->umem_area   = xsk_pal->umem_area;
  xsk->cfg         = xsk_cfg;
  xsk->rakis_netif = rakis_netif;

  init_rakis_ring_prod(&xsk->fill_ring,
      xsk_cfg->fill_ring_size,
      sizeof(u64),
      xsk_pal->fill_ring.producer,
      xsk_pal->fill_ring.consumer,
      xsk_pal->fill_ring.ring);

  init_rakis_ring_cons(&xsk->compl_ring,
      xsk_cfg->compl_ring_size,
      sizeof(u64),
      xsk_pal->compl_ring.producer,
      xsk_pal->compl_ring.consumer,
      xsk_pal->compl_ring.ring);

  init_rakis_ring_prod(&xsk->tx_ring,
      xsk_cfg->tx_ring_size,
      sizeof(struct xdp_desc),
      xsk_pal->tx_ring.producer,
      xsk_pal->tx_ring.consumer,
      xsk_pal->tx_ring.ring);

  init_rakis_ring_cons(&xsk->rx_ring,
      xsk_cfg->rx_ring_size,
      sizeof(struct xdp_desc),
      xsk_pal->rx_ring.producer,
      xsk_pal->rx_ring.consumer,
      xsk_pal->rx_ring.ring);


  if(rakis_xsk_init_frame_allocator(xsk) < 0){
    log_error("RAKIS Failed to initialize frame allocator for xsk socket");
    return -1;
  }

  if(!pktq_new(&xsk->pktq, RAKIS_XSK_PKTQ_SIZE)){
    log_error("RAKIS Failed to initialize incoming packets queue for xsk socket");
    return -1;
  }

  struct pktbpool* pktbpool = pktbpool_create(200);
  if(pktbpool == NULL){
    log_error("RAKIS Failed to initialize pktb pool for xsk socket");
    return -1;
  }
  xsk->pktbpool = pktbpool;

  return 0;
}
