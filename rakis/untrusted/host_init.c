#include "rakis/host_init.h"
#include "rakis/if_xdp.h"
#include "rakis/linux_io_uring.h"
#include <unistd.h>

#ifdef RAKIS_VERIFICATION
#include "rakis/fv/host.h"
#else
#include "linux_socket.h"
#include "pal.h"
#include "rakis/linux_host.h"
#endif

/*
 * Acquiring & dropping capabilities
 */
/*{{{*/
static int rakis_acquire_capabilities(void) {
  cap_t caps = calloc(1, sizeof(*caps));
  caps->head.version = _LINUX_CAPABILITY_VERSION_3;
  caps->head.pid = 0;

  if (DO_SYSCALL(capget, &caps->head, &caps->u[0].set) == -1) {
    log_error("capget failed on acquiring capabilities");
    return -1;
  }

  caps->raise_cap(CAP_NET_RAW, CAP_EFFECTIVE);
  caps->raise_cap(CAP_BPF, CAP_EFFECTIVE);

  if (DO_SYSCALL(capset, &caps->head, &caps->u[0].set) == -1) {
    log_error("capset failed on acquiring capabilities");
    return -1;
  }
  free(caps);
  return 0;
}

static int rakis_drop_capabilities(void) {
  cap_t caps = calloc(1, sizeof(*caps));
  caps->head.version = _LINUX_CAPABILITY_VERSION_3;
  caps->head.pid = 0; // self

  if (DO_SYSCALL(capget, &caps->head, &caps->u[0].set) == -1) {
    log_error("capget failed on dropping capabilities");
    return -1;
  }

  caps->lower_cap(CAP_NET_RAW, CAP_EFFECTIVE);
  caps->lower_cap(CAP_BPF, CAP_EFFECTIVE);

  if (DO_SYSCALL(capset, &caps->head, &caps->u[0].set) == -1) {
    log_error("capset failed on dropping capabilities");
    return -1;
  }
  free(caps);
  return 0;
}
/*}}}*/

/*
 * BPF maps update & delete
 */
/*{{{*/
static int rakis_bpf_map_delete_elem(int fd, const void *key){
  const size_t attr_sz = offsetofend(union bpf_attr, flags);
  union bpf_attr attr;
  int ret;

  memset(&attr, 0, attr_sz);
  attr.map_fd = fd;
  attr.key = (u64) (unsigned long)(key);

  ret = DO_SYSCALL(bpf, BPF_MAP_DELETE_ELEM, &attr, attr_sz);
  return ret;
}

static int rakis_bpf_map_update_elem(int fd, const void *key, const void *value,
    u64 flags){
  const size_t attr_sz = offsetofend(union bpf_attr, flags);
  union bpf_attr attr;
  int ret;

  memset(&attr, 0, attr_sz);
  attr.map_fd = fd;
  attr.key = (u64) key;
  attr.value = (u64) value;
  attr.flags = flags;

  ret = DO_SYSCALL(bpf, BPF_MAP_UPDATE_ELEM, &attr, attr_sz);
  return ret;
}
/*}}}*/

/*
 * if_nametoindex implementation
 */
/*{{{*/
static unsigned int rakis_if_nametoindex(const char *ifname){
  struct ifreq ifr;
  size_t name_len = strnlen(ifname, RAKIS_IFNAMSIZ);
  if(name_len == RAKIS_IFNAMSIZ){
    return 0;
  }
  memset(&ifr, 0, sizeof(struct ifreq));
  memcpy(ifr.ifr_name, ifname, name_len);
  int fd = DO_SYSCALL(socket, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return 0;
  if (DO_SYSCALL(ioctl , fd, SIOCGIFINDEX, &ifr) < 0) {
    DO_SYSCALL(close, fd);
    return 0;
  }
  DO_SYSCALL(close, fd);
  return ifr.ifr_ifindex;
}
/*}}}*/

/*
 * Obtaining XSK bpf map file descriptor
 */
/*{{{*/
static int rakis_recv_xsks_map_fd(int ctrl_sock_fd){
  char cms[CMSG_SPACE(sizeof(int))];
  struct cmsghdr *cmsg;
  struct msghdr msg;
  struct iovec iov;
  int value;
  int len;

  iov.iov_base = &value;
  iov.iov_len = sizeof(int);

  msg.msg_name = 0;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  msg.msg_control = (void*)cms;
  msg.msg_controllen = sizeof(cms);

  len = DO_SYSCALL(recvmsg, ctrl_sock_fd, &msg, 0);

  if (len <= 0)
    return -1;

  cmsg = CMSG_FIRSTHDR(&msg);
  int fd = *(int *)CMSG_DATA(cmsg);

  return fd;
}

static int rakis_get_xsks_map_fd(char* ctrl_server_path){
  struct sockaddr_un server;
  int ctrl_sock_fd;

  ctrl_sock_fd = DO_SYSCALL(socket, AF_UNIX, SOCK_STREAM, 0);
  if (ctrl_sock_fd < 0){
    log_error("Error on creating unix socket to control process at %s", ctrl_server_path);
    return -1;
  }

  memset(&server, 0, sizeof(server));
  server.sun_family = AF_UNIX;

  size_t unix_server_path_len = strnlen(ctrl_server_path, sizeof(server.sun_path));
  if(unix_server_path_len == sizeof(server.sun_path)){
    log_error("control server path too long (%s)", ctrl_server_path);
    goto socket_err;
  }

  memcpy(server.sun_path, ctrl_server_path, unix_server_path_len);

  int conn = DO_SYSCALL(connect, ctrl_sock_fd, (struct sockaddr *)&server, sizeof(struct sockaddr_un));
  if (conn < 0) {
    log_error("Error on connecting to control process at %s", ctrl_server_path);
    goto socket_err;
  }

  return rakis_recv_xsks_map_fd(ctrl_sock_fd);

socket_err:
  DO_SYSCALL(close, ctrl_sock_fd);
  return -1;
}
/*}}}*/

/*
 * XDP socket init & deinit
 */
/*{{{*/
static void rakis_xsk_mmap_offsets_v1(struct xdp_mmap_offsets *off){
  struct xdp_mmap_offsets_v1 off_v1;

  /* getsockopt on a kernel <= 5.3 has no flags fields.
   * Copy over the offsets to the correct places in the >=5.4 format
   * and put the flags where they would have been on that kernel.
   */
  memcpy(&off_v1, off, sizeof(off_v1));

  off->rx.producer = off_v1.rx.producer;
  off->rx.consumer = off_v1.rx.consumer;
  off->rx.desc = off_v1.rx.desc;
  off->rx.flags = off_v1.rx.consumer + sizeof(u32);

  off->tx.producer = off_v1.tx.producer;
  off->tx.consumer = off_v1.tx.consumer;
  off->tx.desc = off_v1.tx.desc;
  off->tx.flags = off_v1.tx.consumer + sizeof(u32);

  off->fr.producer = off_v1.fr.producer;
  off->fr.consumer = off_v1.fr.consumer;
  off->fr.desc = off_v1.fr.desc;
  off->fr.flags = off_v1.fr.consumer + sizeof(u32);

  off->cr.producer = off_v1.cr.producer;
  off->cr.consumer = off_v1.cr.consumer;
  off->cr.desc = off_v1.cr.desc;
  off->cr.flags = off_v1.cr.consumer + sizeof(u32);
}

static int rakis_xsk_get_mmap_offsets(int fd, struct xdp_mmap_offsets *off){
  __socklen_t optlen;
  int err;

  optlen = sizeof(*off);
  err = DO_SYSCALL(getsockopt, fd, SOL_XDP, XDP_MMAP_OFFSETS, off, &optlen);
  if (err)
    return err;

  if (optlen == sizeof(*off))
    return 0;

  if (optlen == sizeof(struct xdp_mmap_offsets_v1)) {
    rakis_xsk_mmap_offsets_v1(off);
    return 0;
  }

  return -1;
}

static int rakis_init_one_xsk(struct rakis_netif_cfg* rakis_netif_cfg, struct rakis_xsk_cfg* rakis_xsk_cfg,
    struct rakis_netif_pal* rakis_netif_pal, struct rakis_xsk_pal* rakis_xsk_pal){

  assert(rakis_netif_cfg);
  assert(rakis_netif_pal);
  assert(rakis_xsk_cfg);
  assert(rakis_xsk_pal);

  struct sockaddr_xdp sxdp = {};
  struct xdp_mmap_offsets off;
  struct xdp_umem_reg mr;
  u32 mmap_sz;
  long mmap_ret;
  int ret;

  // create the socket
  ret = DO_SYSCALL(socket, AF_XDP, SOCK_RAW, 0);
  if (ret < 0) {
    log_error("ERROR creating AF_XDP socket");
    return -1;
  }
  rakis_xsk_pal->xsk_fd = ret;

  // allocate umem buffer
  mmap_ret = DO_SYSCALL(mmap, NULL, rakis_xsk_cfg->umem_size,
      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mmap_ret == -1){
    log_error("ERROR allocating UMEM buffer");
    return -1;
  }
  rakis_xsk_pal->umem_area = (void*)mmap_ret;

  // registering the umem for the XDP socket
  memset(&mr, 0, sizeof(mr));
  mr.addr = (uintptr_t)rakis_xsk_pal->umem_area;
  mr.len = rakis_xsk_cfg->umem_size;
  mr.chunk_size = rakis_xsk_cfg->frame_size;
  mr.headroom = 0;
  mr.flags = 0;
  ret = DO_SYSCALL(setsockopt, rakis_xsk_pal->xsk_fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));
  if (ret){
    log_error("ERROR registering the UMEM buffer for XSK socket. Make sure you have enough memlock ulimits.");
    return -1;
  }

#define RAKIS_CREATE_XDP_RING(__r, __R) \
  ret = DO_SYSCALL(setsockopt, rakis_xsk_pal->xsk_fd, SOL_XDP, XDP_##__R##_RING, \
      &rakis_xsk_cfg->__r##_ring_size, \
      sizeof(rakis_xsk_cfg->__r##_ring_size)); \
  if (ret){ \
    log_error("ERROR creating the " #__r " ring"); \
    return -1; \
  }

  RAKIS_CREATE_XDP_RING(fill,  UMEM_FILL);
  RAKIS_CREATE_XDP_RING(compl, UMEM_COMPLETION);
  RAKIS_CREATE_XDP_RING(rx,    RX);
  RAKIS_CREATE_XDP_RING(tx,    TX);

  // get the rings mmap offsets
  ret = rakis_xsk_get_mmap_offsets(rakis_xsk_pal->xsk_fd, &off);
  if (ret){
    log_error("ERROR getting the mmap offsets for the rx & tx rings");
    return -1;
  }

#define RAKIS_MMAP_XDP_RING(__rr, __r, __slot_ty, __OFFSET) \
  mmap_sz = off.__rr.desc + rakis_xsk_cfg->__r##_ring_size * sizeof(__slot_ty); \
  mmap_ret = DO_SYSCALL(mmap, NULL, mmap_sz, \
      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, rakis_xsk_pal->xsk_fd, \
      __OFFSET); \
  if (mmap_ret == -1){ \
    log_error("ERROR mmaping the " #__r " ring"); \
    return -1; \
  } \
  rakis_xsk_pal->__r##_ring.mmap_addr = (void*)mmap_ret; \
  rakis_xsk_pal->__r##_ring.mmap_size = mmap_sz; \
  rakis_xsk_pal->__r##_ring.producer  = (void*)mmap_ret + off.__rr.producer; \
  rakis_xsk_pal->__r##_ring.consumer  = (void*)mmap_ret + off.__rr.consumer; \
  rakis_xsk_pal->__r##_ring.ring      = (void*)mmap_ret + off.__rr.desc; \
  rakis_xsk_pal->__r##_ring.flags     = (void*)mmap_ret + off.__rr.flags;

  RAKIS_MMAP_XDP_RING(fr, fill, u64, XDP_UMEM_PGOFF_FILL_RING);
  RAKIS_MMAP_XDP_RING(cr, compl, u64, XDP_UMEM_PGOFF_COMPLETION_RING);
  RAKIS_MMAP_XDP_RING(rx, rx, struct xdp_desc, XDP_PGOFF_RX_RING);
  RAKIS_MMAP_XDP_RING(tx, tx, struct xdp_desc, XDP_PGOFF_TX_RING);

  // preparing the socket address for binding
  sxdp.sxdp_family = PF_XDP;
  sxdp.sxdp_ifindex = rakis_netif_pal->ifindex;
  sxdp.sxdp_queue_id = rakis_xsk_cfg->qid;
  sxdp.sxdp_flags  = (rakis_xsk_cfg->zero_copy) ? XDP_ZEROCOPY : XDP_COPY;
  sxdp.sxdp_flags |= (rakis_xsk_cfg->needs_wakeup) ? XDP_USE_NEED_WAKEUP : 0;

  // binding to socket
  ret = DO_SYSCALL(bind, rakis_xsk_pal->xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
  if (ret){
    log_error("Error binding to XDP socket at %d:%s:%d", rakis_netif_pal->ifindex,
        rakis_netif_cfg->interface_name, rakis_xsk_cfg->qid);
    return -1;
  }

  // placing our xdp socket in xdp program map
  // first we contact the control process to give us an fd to the bpf map
  ret = rakis_get_xsks_map_fd(rakis_xsk_cfg->ctrl_prcs_path);
  if (ret < 0) {
    log_error("Error getting xsk_fd from control process at %s for XDP socket at %d:%s:%d",
        rakis_xsk_cfg->ctrl_prcs_path, rakis_netif_pal->ifindex, rakis_netif_cfg->interface_name, rakis_xsk_cfg->qid);
    return -1;
  }
  rakis_xsk_pal->xsk_bpf_map_fd = ret;

  // now we issue a bpf syscall to update the map with our socket & qid
  ret = rakis_bpf_map_update_elem(rakis_xsk_pal->xsk_bpf_map_fd, &rakis_xsk_cfg->qid, &rakis_xsk_pal->xsk_fd, 0);
  if (ret) {
    log_error("Error on updating bpf map for xdp program with socket fd received from %s", rakis_xsk_cfg->ctrl_prcs_path);
    return -1;
  }

  log_debug("RAKIS: Initiated one XDP socket at %d:%s:%d successfully!", rakis_netif_pal->ifindex,
      rakis_netif_cfg->interface_name, rakis_xsk_cfg->qid);
  return 0;
}

// static void rakis_xdp_deinit_one_sock(struct xdp_sock_cfg* xdp_sock_cfg,
//     struct xdp__untrusted_data* xdp_sock){
//
//   int ret;
//   struct xdp_mmap_offsets off;
//
//   if(!xdp_sock->xsk_fd)
//     return;
//
//   // removing our xdp socket from xdp program map
//   // now we issue a bpf syscall to update the map and delete our socket & qid
//   // dont care about the outcome of this
//   if (xdp_sock->xsk_bpf_map_fd) {
//     rakis_bpf_map_delete_elem(xdp_sock->xsk_bpf_map_fd, &xdp_sock->xsk_fd);
//   }
//
//   // get the rings mmap offsets before closing the socket
//   ret = rakis_xsk_get_mmap_offsets(xdp_sock->xsk_fd, &off);
//
//   // munmap rings
//   if (!ret){
//     if(xdp_sock->fill_ring.ring)
//       DO_SYSCALL(munmap, xdp_sock->fill_ring.mmap_addr, xdp_sock->fill_ring.mmap_size);
//
//     if (xdp_sock->compl_ring.ring)
//       DO_SYSCALL(munmap, xdp_sock->compl_ring.mmap_addr, xdp_sock->compl_ring.mmap_size);
//
//     // munmap the rx ring
//     if(xdp_sock->rx_ring.ring)
//       DO_SYSCALL(munmap, xdp_sock->rx_ring.mmap_addr, xdp_sock->rx_ring.mmap_size);
//
//     // munmap the tx ring
//     if (xdp_sock->tx_ring.ring)
//       DO_SYSCALL(munmap, xdp_sock->tx_ring.mmap_addr, xdp_sock->tx_ring.mmap_size);
//   }
//
//   // deallocate umem buffer
//   if(!xdp_sock->umem_area)
//     DO_SYSCALL(munmap, xdp_sock->umem_area, xdp_sock_cfg->umem_size);
//
//   DO_SYSCALL(close, xdp_sock->xsk_fd);
// }
/*}}}*/

static struct rakis_monitored_fd_pal*
find_empty_fd_monitor_entry(struct rakis_monitored_fd_pal* fd_array){
  // find the first free entry in the monitors array

  int i=0;
  struct rakis_monitored_fd_pal* entry = fd_array;
  while (i < RAKIS_KFPS_NUM && entry->type != RAKIS_MONITORED_FD_TYPE_EMPTY) {
    i++;
    entry++;
  }

  if(i == RAKIS_KFPS_NUM || entry->type != RAKIS_MONITORED_FD_TYPE_EMPTY){
    log_error("There is too many KFPs, increase the KFPs limit");
    return NULL;
  }

  return entry;
}

static int rakis_init_one_netif(struct rakis_netif_cfg* rakis_netif_cfg,
    struct rakis_netif_pal* rakis_netif_pal,
    struct rakis_monitored_fd_pal* fd_array){
  int ret;

  ret = rakis_if_nametoindex(rakis_netif_cfg->interface_name);
  if (!ret) {
    log_error("Could not get the interface index for interface (%s)", rakis_netif_cfg->interface_name);
    return -1;
  }
  rakis_netif_pal->ifindex = ret;

  for (u32 i=0; i<rakis_netif_cfg->xsks_num; i++) {
    ret = rakis_init_one_xsk(rakis_netif_cfg, &rakis_netif_cfg->xsks_cfg[i],
        rakis_netif_pal, &rakis_netif_pal->xsks[i]);
    if (ret < 0) {
      log_error("Failed to init xsk[%d] in interface [%s]", i, rakis_netif_cfg->interface_name);
      return ret;
    }

    struct rakis_monitored_fd_pal* entry = find_empty_fd_monitor_entry(fd_array);
    if (!entry) {
      return -1;
    }

    entry->fd = rakis_netif_pal->xsks[i].xsk_fd;
    entry->type = RAKIS_MONITORED_FD_TYPE_XSK;
    entry->xsk_monitor.fq_ring_flags = rakis_netif_pal->xsks[i].fill_ring.flags;
    entry->xsk_monitor.tx_ring_flags = rakis_netif_pal->xsks[i].tx_ring.flags;
    entry->xsk_monitor.tx_prod       = rakis_netif_pal->xsks[i].tx_ring.producer;
    entry->xsk_monitor.tx_cached     = 0;
    entry->xsk_monitor.needs_wakeup = rakis_netif_cfg->xsks_cfg[i].needs_wakeup;
  }

  return 0;
}

static int rakis_iouring_init__untrusted(struct rakis_io_uring_cfg* rakis_io_uring_cfg,
    struct rakis_monitor_pal* rakis_monitor_pal,
    struct rakis_io_uring_pal* rakis_io_uring_pal){
  int fd;
  long mmap_ret;

  struct io_uring_params p;
  memset(&p, 0, sizeof(p));
  p.cq_entries = rakis_io_uring_cfg->entries_num * 2;
  p.sq_entries = rakis_io_uring_cfg->entries_num;
  p.flags      = IORING_SETUP_CQSIZE;

  // io_uring fd
  fd = DO_SYSCALL(io_uring_setup, rakis_io_uring_cfg->entries_num, &p);
  if (fd < 0){
    return fd;
  }
  rakis_io_uring_pal->fd = fd;

  if (p.cq_entries != rakis_io_uring_cfg->entries_num * 2 ||
      p.sq_entries != rakis_io_uring_cfg->entries_num) {
    log_error("Host OS allocated different io_uring entries number");
    return -1;
  }

  // sq ring
  size_t mmap_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
  mmap_ret = DO_SYSCALL(mmap, 0, mmap_sz, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_POPULATE,
      fd, IORING_OFF_SQ_RING);
  if (mmap_ret == -1){
    log_error("ERROR MMaping SQ ring");
    return -1;
  }

  struct rakis_io_uring_sqring_pal* sqring = &rakis_io_uring_pal->sqring;
  sqring->mmap_addr    = (void*)mmap_ret;
  sqring->mmap_size    = mmap_sz;
  sqring->producer     = (void*)(mmap_ret + p.sq_off.tail);
  sqring->consumer     = (void*)(mmap_ret + p.sq_off.head);

  // we directly map the sqring to sqe so that we avoid any management later
  u32* sqring_ring = (void*)(mmap_ret + p.sq_off.array);
  for (u32 index = 0; index < rakis_io_uring_cfg->entries_num; index++)
    sqring_ring[index] = index;

  // sqe array
  mmap_sz = p.sq_entries * sizeof(struct io_uring_sqe);
  mmap_ret = DO_SYSCALL(mmap, 0, mmap_sz, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_POPULATE, fd,
      IORING_OFF_SQES);
  if (mmap_ret == -1){
    log_error("ERROR MMaping SQ ring entries array");
    return -1;
  }
  sqring->sqes = (struct io_uring_sqe*)mmap_ret;

  // cq ring
  mmap_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
  mmap_ret = DO_SYSCALL(mmap, 0, mmap_sz, PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_POPULATE, fd,
      IORING_OFF_CQ_RING);
  if (mmap_ret == -1){
    log_error("ERROR MMaping CQ ring");
    return -1;
  }

  struct rakis_io_uring_cqring_pal* cqring = &rakis_io_uring_pal->cqring;
  cqring->mmap_addr    = (void*)mmap_ret;
  cqring->mmap_size    = mmap_sz;
  cqring->producer     = (void*)(mmap_ret + p.cq_off.tail);
  cqring->consumer     = (void*)(mmap_ret + p.cq_off.head);
  cqring->cqes         = (void*)(mmap_ret + p.cq_off.cqes);

  struct rakis_monitored_fd_pal* entry = find_empty_fd_monitor_entry(rakis_monitor_pal->fd_monitors);
  if (!entry) {
    return -1;
  }

  entry->fd = rakis_io_uring_pal->fd;
  entry->type = RAKIS_MONITORED_FD_TYPE_IOURING;
  entry->io_uring_monitor.sq_cached = 0;
  entry->io_uring_monitor.sq_prod = rakis_io_uring_pal->sqring.producer;
  return 0;
}

int rakis_host_init(struct rakis_config* rakis_config, struct rakis_pal* rakis_pal){
  int ret, cap_drop_ret=0;

  rakis_pal->rakis_monitor = calloc(1, sizeof(struct rakis_monitor_pal));
  if (!rakis_pal->rakis_monitor) {
    log_error("Failed to allocate memory for rakis_monitor");
    return -1;
  }
  struct rakis_monitor_pal* rakis_monitor = rakis_pal->rakis_monitor;

  rakis_monitor->fd_monitors = calloc(RAKIS_KFPS_NUM, sizeof(struct rakis_monitored_fd_pal));
  if (!rakis_monitor->fd_monitors) {
    log_error("Failed to allocate memory for rakis_monitors array");
    return -1;
  }

  for (u32 i = 0; i<rakis_config->io_urings_cfg.io_urings_num; i++) {
    if(rakis_iouring_init__untrusted(&rakis_config->io_urings_cfg, rakis_monitor, &rakis_pal->io_urings[i]) < 0){
      log_error("Failed to init iouring");
      return -1;
    }
    log_debug("RAKIS: Initiated one io_uring successfully!");
  }

  ret = rakis_acquire_capabilities();
  if (ret < 0) {
    log_error("Failed to acquire capabilities");
    return -1;
  }

  for(u32 i=0; i<rakis_config->netifs_num; i++) {
    ret = rakis_init_one_netif(&rakis_config->netifs_cfg[i], &rakis_pal->netifs[i], rakis_monitor->fd_monitors);

    if (ret < 0){
      log_error("Failed to init netif [%s]", rakis_config->netifs_cfg[i].interface_name);
      goto err_out;
    }
  }

  cap_drop_ret = rakis_drop_capabilities();
  if (cap_drop_ret < 0) {
    log_error("Failed to drop capabilities");
    goto err_out;
  }

  return 0;

err_out:
  // (rakis) TODO: we should figure out the deinit routine...
  // this includes simply closing sockets after exeuction is finished
  // for now, we loudly fail for any error
  assert(0 && "Failed to init RAKIS");

  // if we are not here because of failuer in cap drop, we attempt to drop it
  if (cap_drop_ret == 0) {
    cap_drop_ret = rakis_drop_capabilities();
    if (cap_drop_ret < 0) {
      log_error("Failed to drop capabilities");
    }
  }

  return ret;
}
