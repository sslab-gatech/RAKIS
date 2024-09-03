#ifndef RAKIS_PAL_H
#define RAKIS_PAL_H
#include "rakis/common.h"
#include "rakis/rakis.h"

struct rakis_xsk_ring_pal{
  u32   mmap_size;
  void *mmap_addr;
  u32  *producer;
  u32  *consumer;
  u32  *flags;
  void *ring;
};

struct rakis_pal{
  struct rakis_monitor_pal{
    // TODO: separate def and impl. of this struct to different compilation units
    // to insure that it is not used in trusted context
    bool ready_flag;
    bool terminate_flag;

    struct rakis_monitored_fd_pal{
      int fd;

      enum{
        RAKIS_MONITORED_FD_TYPE_EMPTY = 0,
        RAKIS_MONITORED_FD_TYPE_XSK,
        RAKIS_MONITORED_FD_TYPE_IOURING,
      } type;

      union{
        struct rakis_xsk_monitor_pal{
          bool needs_wakeup;
          u32  tx_cached;
          u32 *tx_prod;
          u32 *fq_ring_flags;
          u32 *tx_ring_flags;
        } xsk_monitor;

        struct rakis_io_uring_monitor_pal{
          u32 sq_cached;
          u32 *sq_prod;
        } io_uring_monitor;
      };
    } *fd_monitors;
  } *rakis_monitor;

  struct rakis_netif_pal{
    int ifindex;
    struct rakis_xsk_pal{
      u8  *umem_area;
      int xsk_fd;
      int xsk_bpf_map_fd;
      struct rakis_xsk_ring_pal fill_ring;
      struct rakis_xsk_ring_pal compl_ring;
      struct rakis_xsk_ring_pal rx_ring;
      struct rakis_xsk_ring_pal tx_ring;
    } *xsks;
  } *netifs;

  struct rakis_io_uring_pal{
    int fd;

    struct rakis_io_uring_sqring_pal{
      u32   mmap_size;
      void *mmap_addr;
      u32  *producer;
      u32  *consumer;
      struct io_uring_sqe *sqes;
    } sqring;

    struct rakis_io_uring_cqring_pal{
      u32   mmap_size;
      void *mmap_addr;
      u32  *producer;
      u32  *consumer;
      struct io_uring_cqe *cqes;
    } cqring;
  } *io_urings;
};

int rakis_initialization_data_checker(struct rakis_config* rakis_config, struct rakis_pal* rakis_pal);
#endif
