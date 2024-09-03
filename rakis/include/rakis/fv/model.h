#ifndef RAKIS_FV_H
#define RAKIS_FV_H
#ifdef RAKIS_SYMBOLIC
#include "klee/klee.h"
#include "rakis/xsk.h"
#include "rakis/if_xdp.h"
#include "rakis/verified_structs.h"

#include <stdlib.h>
#include <err.h>

static inline void rakis_fv_model_monitor_memory(struct rakis_config* rakis_config, struct rakis_pal* rakis_pal){
  // even though we never use the monitor in this code, we need to at least
  // allocate it so that the initialization checker code passes
  // we also symbolize incase it was used in a wrong way i.e. dereferenced
  rakis_pal->rakis_monitor = malloc(sizeof(struct rakis_monitor_pal));
  if (!rakis_pal->rakis_monitor) {
    err(EXIT_FAILURE, "ERROR allocating rakis_monitor");
  }

  klee_make_symbolic(rakis_pal->rakis_monitor, sizeof(struct rakis_monitor_pal), "rakis_monitor");
}

static inline void rakis_fv_model_xsk_memory(struct rakis_config* rakis_config, struct rakis_netif_pal* rakis_netif_pal){
  struct rakis_xsk_cfg* rakis_xsk_cfg = &rakis_config->netifs_cfg[0].xsks_cfg[0];

  // model fds as ints
  struct rakis_xsk_pal* xsk_pal = &rakis_netif_pal->xsks[0];
  rakis_netif_pal->ifindex = klee_int("ifindex");
  xsk_pal->xsk_fd          = klee_int("xsk_fd"),
  xsk_pal->xsk_bpf_map_fd  = klee_int("xsk_bpf_map_fd");

  // umem
  // we symbolize it all except the mmap returned address
  xsk_pal->umem_area = malloc(rakis_xsk_cfg->umem_size);
  if (!xsk_pal->umem_area){
    err(EXIT_FAILURE, "ERROR allocating UMEM buffer");
  }
  klee_make_symbolic(xsk_pal->umem_area, rakis_xsk_cfg->umem_size, "umem area");

#define RAKIS_SYMBOLIZE_XSK_RING_OFFSET(___R, ___VAL) \
  {\
    int off_sym = klee_int(#___R "_ring_" #___VAL "_offset"); \
    void* ptr_sym = xsk_pal->___R##_ring.mmap_addr + off_sym; \
    xsk_pal->___R##_ring.___VAL = ptr_sym; \
  }

#define RAKIS_SYMBOLIZE_XSK_RING(__R, __slot_sz) \
  {\
    u32 sz = rakis_xsk_cfg->__R##_ring_size * __slot_sz + offsetof(struct xdp_ring, ring); \
    struct rakis_xsk_ring_pal* rr = &xsk_pal->__R##_ring;\
    void* mm = malloc(sz); \
    if (!mm){ \
      err(EXIT_FAILURE, "ERROR malloc the " #__R " ring"); \
    } \
    rr->mmap_addr = mm; \
    rr->mmap_size = sz; \
    /* then we symbolize it all except the mmap returned address */ \
    klee_make_symbolic(rr->mmap_addr, rr->mmap_size, #__R " ring"); \
    int mmap_size = klee_int(#__R "_ring_mmap_size"); \
    rr->mmap_size = mmap_size; \
    RAKIS_SYMBOLIZE_XSK_RING_OFFSET(__R, producer); \
    RAKIS_SYMBOLIZE_XSK_RING_OFFSET(__R, consumer); \
    RAKIS_SYMBOLIZE_XSK_RING_OFFSET(__R, flags); \
    RAKIS_SYMBOLIZE_XSK_RING_OFFSET(__R, ring); \
  }

  RAKIS_SYMBOLIZE_XSK_RING(fill, sizeof(u64));
  RAKIS_SYMBOLIZE_XSK_RING(compl, sizeof(u64));
  RAKIS_SYMBOLIZE_XSK_RING(tx, sizeof(struct xdp_desc));
  RAKIS_SYMBOLIZE_XSK_RING(rx, sizeof(struct xdp_desc));
}

static inline void rakis_fv_model_io_uring_memory(struct rakis_config* rakis_config, struct rakis_io_uring_pal* rakis_io_uring){
  size_t io_uring_entries_num = rakis_config->io_urings_cfg.entries_num;

  // model fds as ints
  rakis_io_uring->fd = klee_int("io_uring_fd");

#define RAKIS_SYMBOLIZE_IO_URING_RING_OFFSET(___R, ___VAL) \
  {\
    int off_sym = klee_int(#___R "_ring_" #___VAL "_offset"); \
    void* ptr_sym = rakis_io_uring->___R.mmap_addr + off_sym; \
    rakis_io_uring->___R.___VAL = ptr_sym; \
  }

  {
    // model the sqring
    struct rakis_io_uring_sqring_pal* sq = &rakis_io_uring->sqring;

    size_t sq_off_array = sizeof(struct io_rings) + io_uring_entries_num * 2 * sizeof(struct io_uring_cqe);
    size_t sqring_alloc_size = sq_off_array + io_uring_entries_num * sizeof(unsigned);
    void* mm = malloc(sqring_alloc_size);
    if (!mm){
      err(EXIT_FAILURE, "ERROR malloc the sqring");
    }
    sq->mmap_addr = mm;
    sq->mmap_size = sqring_alloc_size;
    klee_make_symbolic(sq->mmap_addr, sq->mmap_size, "sqring");

    int mmap_size = klee_int("sqring_mmap_size");
    sq->mmap_size = mmap_size;
    RAKIS_SYMBOLIZE_IO_URING_RING_OFFSET(sqring, producer);
    RAKIS_SYMBOLIZE_IO_URING_RING_OFFSET(sqring, consumer);

    size_t sqe_arr_sz = io_uring_entries_num * sizeof(struct io_uring_sqe);
    void* sqe_mm = malloc(sqe_arr_sz);
    if (!sqe_mm){
      err(EXIT_FAILURE, "ERROR malloc the sqring sqes");
    }
    sq->sqes = sqe_mm;
    klee_make_symbolic(sq->sqes, sqe_arr_sz, "sqring sqes");
  }

  {
    // model the cqring
    struct rakis_io_uring_cqring_pal* cq = &rakis_io_uring->cqring;

    size_t cqring_alloc_size = offsetof(struct io_rings, cqes) + io_uring_entries_num * sizeof(struct io_uring_cqe) * 2;
    void* mm = malloc(cqring_alloc_size);
    if (!mm){
      err(EXIT_FAILURE, "ERROR malloc the cqring");
    }
    cq->mmap_addr = mm;
    cq->mmap_size = cqring_alloc_size;
    klee_make_symbolic(cq->mmap_addr, cq->mmap_size, "cqring");

    int mmap_size = klee_int("cqring_mmap_size");
    cq->mmap_size = mmap_size;
    RAKIS_SYMBOLIZE_IO_URING_RING_OFFSET(cqring, producer);
    RAKIS_SYMBOLIZE_IO_URING_RING_OFFSET(cqring, consumer);
    RAKIS_SYMBOLIZE_IO_URING_RING_OFFSET(cqring, cqes);
  }
}
#endif
#endif
