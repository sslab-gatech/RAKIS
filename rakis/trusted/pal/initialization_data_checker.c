#include "rakis/if_xdp.h"
#include "rakis/linux_io_uring.h"
#include "rakis/pal.h"
#include "rakis/rakis.h"
#include "rakis/verified_structs.h"

#ifdef RAKIS_VERIFICATION
#include "rakis/fv/host.h"
#else
#include "pal.h"
#endif

#ifdef RAKIS_SGX_HOST
#include "enclave_api.h"
#endif

struct rakis_untrusted_mem_region{
  void* start;
  size_t size;

  struct rakis_untrusted_mem_region* next;
} *overlap_check_head = NULL;

static inline int check_overlap_region(void* start, size_t size){
  struct rakis_untrusted_mem_region* new_node = malloc(sizeof(struct rakis_untrusted_mem_region));
  new_node->start = start;
  new_node->size = size;
  new_node->next = NULL;

  struct rakis_untrusted_mem_region* current = overlap_check_head;
  struct rakis_untrusted_mem_region* prev = NULL;

  while(current != NULL){
    if((new_node->start >= current->start && new_node->start < current->start + current->size) ||
       (new_node->start + new_node->size > current->start && new_node->start + new_node->size <= current->start + current->size)){
      free(new_node);
      return -1;
    }

    // this check keeps the list sorted
    if(new_node->start < current->start){
      break;
    }

    prev = current;
    current = current->next;
  }

  if(prev == NULL){
    overlap_check_head = new_node;
  }else{
    prev->next = new_node;
  }
  new_node->next = current;

  return 0;
}

static inline int check_untrusted_memory_region(void* start, size_t size){
  if(size == 0){
    return -1;
  }

  if(start == NULL){
    return -1;
  }

  if(check_overlap_region(start, size) < 0){
    return -1;
  }

#ifdef RAKIS_SGX_HOST
  if(!sgx_is_valid_untrusted_ptr(start, size, __alignof__(size))){
    return -1;
  }
#endif

  return 0;
}

static inline int check_monitor_initialization_data(struct rakis_monitor_pal* rakis_monitor_pal){
  if(check_untrusted_memory_region(rakis_monitor_pal, sizeof(struct rakis_monitor_pal)) < 0){
    return -1;
  }

  return 0;
}

static inline int check_xsk_initialization_data(struct rakis_xsk_cfg* rakis_xsk_cfg, struct rakis_xsk_pal* rakis_xsk_pal){

  if (rakis_xsk_pal->xsk_fd <= 0) {
    return -1;
  }

  if (rakis_xsk_pal->xsk_bpf_map_fd <= 0) {
    return -1;
  }

  if (check_untrusted_memory_region(rakis_xsk_pal->umem_area, rakis_xsk_cfg->umem_size) < 0) {
    return -1;
  }

#define VERIFY_XDP_RING(__R, __DESC_SIZE) \
{ \
  struct rakis_xsk_ring_pal *__ring = &rakis_xsk_pal->__R; \
  u32   mmap_sz__t = rakis_xsk_cfg->__R##_size * __DESC_SIZE  + offsetof(struct xdp_ring, ring);\
  u32   mmap_sz__u = __ring->mmap_size; \
  void* mmap_start = __ring->mmap_addr; \
  \
  if ((mmap_sz__u != mmap_sz__t) || \
      (check_untrusted_memory_region(mmap_start, mmap_sz__t) < 0) || \
      (__ring->producer != (mmap_start + offsetof(struct xdp_ring, producer))) || \
      (__ring->consumer != (mmap_start + offsetof(struct xdp_ring, consumer))) || \
      (__ring->flags != (mmap_start + offsetof(struct xdp_ring, flags))) || \
      (__ring->ring != (mmap_start + offsetof(struct xdp_ring, ring))) \
    ){ \
    \
    return -1;\
  }\
}

  VERIFY_XDP_RING(fill_ring,  sizeof(u64));
  VERIFY_XDP_RING(compl_ring, sizeof(u64));
  VERIFY_XDP_RING(rx_ring,    sizeof(struct xdp_desc));
  VERIFY_XDP_RING(tx_ring,    sizeof(struct xdp_desc));

  return 0;
}

static inline int check_netifs_initialization_data(struct rakis_config* rakis_config, struct rakis_netif_pal* rakis_netifs_pal){
  for (u32 i = 0; i < rakis_config->netifs_num; i++) {
    struct rakis_netif_pal* rakis_netif_pal = &rakis_netifs_pal[i];
    struct rakis_netif_cfg* rakis_netif_cfg = &rakis_config->netifs_cfg[i];

    if (rakis_netif_pal->ifindex <= 0) {
      return -1;
    }

    for (u32 i =0; i < rakis_netif_cfg->xsks_num; i++) {
      if (check_xsk_initialization_data(&rakis_netif_cfg->xsks_cfg[i], &rakis_netifs_pal->xsks[i]) < 0){
        return -1;
      }
    }
  }

  return 0;
}

static inline int check_io_uring_initialization_data(struct rakis_io_uring_cfg* rakis_io_uring_cfg, struct rakis_io_uring_pal* rakis_io_uring_pal){

  if (rakis_io_uring_pal->fd <= 0) {
    return -1;
  }

  // verifying sqring
  {
    size_t sq_off_array = sizeof(struct io_rings) +
      rakis_io_uring_cfg->entries_num * 2 * sizeof(struct io_uring_cqe);
    size_t mmap_sz__t = sq_off_array + rakis_io_uring_cfg->entries_num * sizeof(unsigned);
    if (mmap_sz__t != rakis_io_uring_pal->sqring.mmap_size) {
      return -1;
    }

    if (check_untrusted_memory_region(rakis_io_uring_pal->sqring.mmap_addr, mmap_sz__t) < 0) {
      return -1;
    }

    if (rakis_io_uring_pal->sqring.producer != ( rakis_io_uring_pal->sqring.mmap_addr +
          offsetof(struct io_rings, sq) + offsetof(struct io_uring, tail))) {
      return -1;
    }

    if (rakis_io_uring_pal->sqring.consumer != ( rakis_io_uring_pal->sqring.mmap_addr +
          offsetof(struct io_rings, sq) + offsetof(struct io_uring, head))) {
      return -1;
    }

    if (check_untrusted_memory_region(rakis_io_uring_pal->sqring.sqes, rakis_io_uring_cfg->entries_num * sizeof(struct io_uring_sqe)) < 0) {
      return -1;
    }
  }

  // verifying cqring
  {
    size_t mmap_size_t = offsetof(struct io_rings, cqes) + rakis_io_uring_cfg->entries_num * sizeof(struct io_uring_cqe) * 2;
    if (mmap_size_t != rakis_io_uring_pal->cqring.mmap_size) {
      return -1;
    }

    if (check_untrusted_memory_region(rakis_io_uring_pal->cqring.mmap_addr, mmap_size_t) < 0) {
      return -1;
    }

    if (rakis_io_uring_pal->cqring.producer != ( rakis_io_uring_pal->cqring.mmap_addr +
          offsetof(struct io_rings, cq) + offsetof(struct io_uring, tail))) {
      return -1;
    }

    if (rakis_io_uring_pal->cqring.consumer != ( rakis_io_uring_pal->cqring.mmap_addr +
          offsetof(struct io_rings, cq) + offsetof(struct io_uring, head))) {
      return -1;
    }

    if (rakis_io_uring_pal->cqring.cqes != ( rakis_io_uring_pal->cqring.mmap_addr +
          offsetof(struct io_rings, cqes))) {
      return -1;
    }
  }

  return 0;
}

static inline int check_io_urings_initialization_data(struct rakis_config* rakis_config, struct rakis_io_uring_pal* rakis_io_urings_pal){
  for (u32 i =0; i < rakis_config->io_urings_cfg.io_urings_num; i++) {
    if(check_io_uring_initialization_data(&rakis_config->io_urings_cfg, &rakis_io_urings_pal[i]) < 0){
      return -1;
    }
  }
  return 0;
}

int rakis_initialization_data_checker(struct rakis_config* rakis_config, struct rakis_pal* rakis_pal){
  int ret = 0;

  ret = check_monitor_initialization_data(rakis_pal->rakis_monitor);
  if (ret < 0) {
    goto out;
  }

  ret = check_netifs_initialization_data(rakis_config, rakis_pal->netifs);
  if (ret < 0) {
    goto out;
  }

  ret = check_io_urings_initialization_data(rakis_config, rakis_pal->io_urings);
  if (ret < 0) {
    goto out;
  }

out:
  // free the check list
  while(overlap_check_head != NULL){
    struct rakis_untrusted_mem_region* tmp = overlap_check_head;
    overlap_check_head = overlap_check_head->next;
    free(tmp);
  }
  return ret;
}

