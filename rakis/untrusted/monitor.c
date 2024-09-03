#include "linux_socket.h"
#include "pal.h"
#include "rakis/if_xdp.h"
#include "rakis/linux_host.h"
#include "rakis/monitor.h"
#include "rakis/rakis.h"
#include <linux/time.h>

static void monitor_xsk(int xsk_fd, struct rakis_xsk_monitor_pal* rakis_xsk_monitor_pal){
  // we only need to call recv if:
  // -- When using needs_wakeup setting, only if flag risen by kernel.
  // -- When not using needs_wakeup, we call recv all the time.
  bool nudge_recv = rakis_xsk_monitor_pal->needs_wakeup ?
                    (*rakis_xsk_monitor_pal->fq_ring_flags & XDP_RING_NEED_WAKEUP)
                    : true;
  if (nudge_recv) {
    int ret = DO_SYSCALL(recvfrom, xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    if (ret < 0) {
      log_error("Error receiving from XDP socket: (ret: %d)", ret);
    }
  }

  // we call send if there are pending tx packets AND:
  // -- When using needs_wakeup setting, only if flag risen by kernel.
  // -- When not using needs_wakeup, we call send
  bool nudge_send = rakis_xsk_monitor_pal->needs_wakeup ?
                    *rakis_xsk_monitor_pal->tx_ring_flags & XDP_RING_NEED_WAKEUP
                    : true;
  if (nudge_send) {

    // check if there are pending packets to be sent
    u32 new_tx = RAKIS_GET_ATOMIC(rakis_xsk_monitor_pal->tx_prod);
    if(new_tx != rakis_xsk_monitor_pal->tx_cached) {
      rakis_xsk_monitor_pal->tx_cached = new_tx;
      int ret = DO_SYSCALL(sendto, xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
      if (ret < 0) {
        log_error("Error sending to XDP socket: (ret: %d)", ret);
      }
    }
  }
}

static void monitor_io_uring(int iouring_fd, struct rakis_io_uring_monitor_pal* rakis_io_uring_monitor_pal){
  u32 new_sq = RAKIS_GET_ATOMIC(rakis_io_uring_monitor_pal->sq_prod);
  if(new_sq > rakis_io_uring_monitor_pal->sq_cached) {
    u32 to_submit = new_sq - rakis_io_uring_monitor_pal->sq_cached;
    int ret = DO_SYSCALL(io_uring_enter, iouring_fd, to_submit, to_submit, 0, 0);
    if (ret < 0) {
      log_error("Error submiting to io_uring: (ret: %d)", ret);
    }
    rakis_io_uring_monitor_pal->sq_cached = new_sq;
  }
}

void rakis_monitor_start(struct rakis_monitor_pal* rakis_monitor_pal){
  log_debug("RAKIS monitor started");
  RAKIS_SET_ATOMIC(&rakis_monitor_pal->ready_flag, true);

#ifdef RAKIS_STAT
  u64 tm=0,cnt = 0;
#endif

  while (true) {

#ifdef RAKIS_STAT
    struct timespec tsc={0,0};
    DO_SYSCALL(clock_gettime, CLOCK_MONOTONIC, (long)&tsc, 0);
    u64 start = tsc.tv_sec * 1000000000 + tsc.tv_nsec;
#endif

    for (uint32_t i = 0; i < RAKIS_KFPS_NUM; i++) {
      struct rakis_monitored_fd_pal* current_fd = &rakis_monitor_pal->fd_monitors[i];
      switch (current_fd->type) {
        case RAKIS_MONITORED_FD_TYPE_EMPTY:
          break;

        case RAKIS_MONITORED_FD_TYPE_XSK:
          monitor_xsk(current_fd->fd, &current_fd->xsk_monitor);
          continue;

        case RAKIS_MONITORED_FD_TYPE_IOURING:
          monitor_io_uring(current_fd->fd, &current_fd->io_uring_monitor);
          continue;
      }
      break;
    }

#ifdef RAKIS_STAT
    DO_SYSCALL(clock_gettime, CLOCK_MONOTONIC, (long)&tsc, 0);
    u64 end = tsc.tv_sec * 1000000000 + tsc.tv_nsec;
    tm += (end - start);
    cnt++;
#endif

    if(RAKIS_IS_ATOMIC_EQ(&rakis_monitor_pal->terminate_flag, true)){

#ifdef RAKIS_STAT
      log_debug("Rakis monitor average time per iteration: %llu", tm/cnt);
#endif

      log_debug("RAKIS monitor is exiting..");
      RAKIS_SET_ATOMIC(&rakis_monitor_pal->ready_flag, false);
      return;
    }
  }
}
