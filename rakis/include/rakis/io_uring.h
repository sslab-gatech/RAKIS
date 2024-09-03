#ifndef _RAKIS_IO_URING_H
#define _RAKIS_IO_URING_H

#ifdef RAKIS_VERIFICATION
#include <sys/socket.h>
#else
#include "linux_socket.h"
#endif

#include "rakis/linux_io_uring.h"
#include "rakis/pal.h"
#include "rakis/rakis.h"
#include "rakis/rakis_ring.h"

#include <linux/poll.h>
#include <stdint.h>

struct rakis_io_uring;

struct rakis_io_uring_pool{
  uint32_t size;
  struct rakis_io_uring* rakis_io_urings;
};

#ifdef RAKIS_VERIFICATION
// in klee verification, we use a global variable to represent the pool and
// the current io_uring
extern struct rakis_io_uring*     g_rakis_io_uring;
extern struct rakis_io_uring_pool g_rakis_io_uring_pool;
#endif

int rakis_io_uring_poll(struct pollfd* fds, size_t nfds, struct __kernel_timespec* timeout_us, bool* wakeup);
int rakis_io_uring_recv(int fd, struct msghdr* msghdr);
int rakis_io_uring_send(int fd, struct msghdr* msghdr);
int rakis_io_uring_read(int fd, void* buf, size_t count, long offset);
int rakis_io_uring_write(int fd, const void* buf, size_t count, long offset);
int rakis_init_pal_io_urings(struct rakis_io_uring_cfg* rakis_io_uring_cfg, struct rakis_pal* rakis_pal);
#endif
